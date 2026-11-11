package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var dockerProjectPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// These are variables so tests can replace the host-specific trust and lock
// boundaries without weakening production behavior.
var composeTrustCheck = trustComposeFiles
var dockerLockPath = "/run/hibp-docker.lock"

// DockerCheckResult reports image movement without restarting containers.
type DockerCheckResult struct {
	Action          string                `json:"action"`
	OK              bool                  `json:"ok"`
	Project         string                `json:"project"`
	DurationSeconds float64               `json:"duration_seconds"`
	Services        []DockerServiceUpdate `json:"services"`
	Output          string                `json:"output,omitempty"`
	Error           string                `json:"error,omitempty"`
}

type DockerServiceUpdate struct {
	Service          string `json:"service"`
	Image            string `json:"image"`
	BeforeID         string `json:"before_id,omitempty"`
	AfterID          string `json:"after_id,omitempty"`
	ContainerID      string `json:"container_id,omitempty"`
	ContainerImageID string `json:"container_image_id,omitempty"`
	Status           string `json:"status"`
}

// DockerApplyResult reports an explicit Compose up -d operation.
type DockerApplyResult struct {
	Action          string  `json:"action"`
	OK              bool    `json:"ok"`
	Project         string  `json:"project"`
	ExitCode        int     `json:"exit_code"`
	DurationSeconds float64 `json:"duration_seconds"`
	Output          string  `json:"output"`
	Error           string  `json:"error,omitempty"`
}

type composeProjectFile struct {
	Name        string `json:"Name"`
	Status      string `json:"Status"`
	ConfigFiles string `json:"ConfigFiles"`
}

func dockerCheck(ctx context.Context, args []string) (DockerCheckResult, error) {
	project, files, err := dockerProject(ctx, args)
	if err != nil {
		return DockerCheckResult{}, err
	}
	started := time.Now()
	result := DockerCheckResult{Action: "docker-check", Project: project, Services: []DockerServiceUpdate{}}
	lock, err := acquireDockerLock()
	if err != nil {
		return DockerCheckResult{}, err
	}
	defer releaseDockerLock(lock)

	configOutput, code, err := runDockerCompose(ctx, project, files, "config", "--format", "json")
	if err != nil || code != 0 {
		return DockerCheckResult{}, fmt.Errorf("read Compose config: %s", strings.TrimSpace(string(configOutput)))
	}
	var composeConfig struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if err := json.Unmarshal(configOutput, &composeConfig); err != nil {
		return DockerCheckResult{}, fmt.Errorf("parse Compose config: %w", err)
	}
	images := make(map[string]string)
	serviceNames := make([]string, 0, len(composeConfig.Services))
	for service, definition := range composeConfig.Services {
		serviceNames = append(serviceNames, service)
		if strings.TrimSpace(definition.Image) != "" {
			images[service] = definition.Image
		}
	}
	sortStrings(serviceNames)
	before := make(map[string]string, len(images))
	for service, image := range images {
		before[service] = dockerImageID(ctx, image)
	}

	pullOutput, pullCode, pullErr := runDockerCompose(ctx, project, files, "pull", "--quiet", "--ignore-buildable")
	if pullErr != nil || pullCode != 0 {
		// Older Compose releases do not understand --ignore-buildable. Retry
		// without it; build-only services are still reported separately.
		pullOutput, pullCode, pullErr = runDockerCompose(ctx, project, files, "pull", "--quiet")
	}
	pullFailed := pullErr != nil || pullCode != 0
	if pullFailed {
		result.Error = strings.TrimSpace(string(pullOutput))
		if result.Error == "" && pullErr != nil {
			result.Error = pullErr.Error()
		}
	}
	result.Output = boundedText(pullOutput, 32*1024)

	after := make(map[string]string, len(images))
	for service, image := range images {
		after[service] = dockerImageID(ctx, image)
	}
	containers := dockerProjectContainers(ctx, project)

	for _, service := range serviceNames {
		image := images[service]
		update := DockerServiceUpdate{Service: service, Image: image}
		if image == "" {
			update.Status = "build-only"
			result.Services = append(result.Services, update)
			continue
		}
		update.BeforeID = before[service]
		update.AfterID = after[service]
		if container, ok := containers[service]; ok {
			update.ContainerID = container.ID
			update.ContainerImageID = container.ImageID
		}
		switch {
		case pullFailed:
			update.Status = "pull-failed"
		case update.BeforeID == "" && update.AfterID != "":
			update.Status = "new-image"
		case update.BeforeID != "" && update.AfterID != "" && update.BeforeID != update.AfterID:
			update.Status = "image-updated"
		case update.AfterID == "":
			update.Status = "pull-failed"
		case update.ContainerID == "":
			update.Status = "not-running"
		case update.ContainerImageID != update.AfterID:
			update.Status = "container-stale"
		default:
			update.Status = "up-to-date"
		}
		result.Services = append(result.Services, update)
	}
	result.OK = !pullFailed
	for _, service := range result.Services {
		if service.Status == "pull-failed" {
			result.OK = false
		}
	}
	result.DurationSeconds = time.Since(started).Seconds()
	return result, nil
}

func dockerApply(ctx context.Context, args []string) (DockerApplyResult, error) {
	project, files, err := dockerProject(ctx, args)
	if err != nil {
		return DockerApplyResult{}, err
	}
	started := time.Now()
	result := DockerApplyResult{Action: "docker-apply", Project: project}
	lock, err := acquireDockerLock()
	if err != nil {
		return DockerApplyResult{}, err
	}
	defer releaseDockerLock(lock)
	output, code, err := runDockerCompose(ctx, project, files, "up", "-d", "--pull", "never")
	result.ExitCode = code
	result.Output = boundedText(output, 64*1024)
	result.OK = err == nil && code == 0
	if err != nil {
		result.Error = err.Error()
	}
	if !result.OK && result.Error == "" {
		result.Error = "docker compose up failed"
	}
	result.DurationSeconds = time.Since(started).Seconds()
	return result, nil
}

func dockerProject(ctx context.Context, args []string) (string, []string, error) {
	if len(args) != 1 {
		return "", nil, errors.New("docker project name is required")
	}
	project := strings.TrimSpace(args[0])
	if !dockerProjectPattern.MatchString(project) {
		return "", nil, errors.New("invalid Docker project name")
	}
	output, code, err := runBinary(ctx, "docker", "compose", "ls", "--all", "--format", "json")
	if err != nil {
		return "", nil, fmt.Errorf("list Compose projects: %w", err)
	}
	if code != 0 {
		return "", nil, fmt.Errorf("list Compose projects: %s", strings.TrimSpace(string(output)))
	}
	var projects []composeProjectFile
	if err := json.Unmarshal(output, &projects); err != nil {
		return "", nil, fmt.Errorf("parse Compose projects: %w", err)
	}
	for _, candidate := range projects {
		if candidate.Name != project {
			continue
		}
		files, err := composeFiles(candidate.ConfigFiles)
		if err != nil {
			return "", nil, err
		}
		if err := composeTrustCheck(files); err != nil {
			return "", nil, err
		}
		return project, files, nil
	}
	return "", nil, fmt.Errorf("Compose project %q was not found", project)
}

func composeFiles(value string) ([]string, error) {
	seen := make(map[string]bool)
	var files []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if !filepath.IsAbs(item) {
			return nil, fmt.Errorf("Compose file path must be absolute: %s", item)
		}
		item = filepath.Clean(item)
		if seen[item] {
			continue
		}
		seen[item] = true
		files = append(files, item)
	}
	if len(files) == 0 {
		return nil, errors.New("Compose project has no config files")
	}
	return files, nil
}

func trustComposeFiles(files []string) error {
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			return fmt.Errorf("Compose file %s: %w", file, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("Compose file %s is not a regular file", file)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return fmt.Errorf("Compose file %s must be owned by root", file)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("Compose file %s must not be group/world-writable", file)
		}
		dir := filepath.Dir(file)
		for {
			dirInfo, err := os.Stat(dir)
			if err != nil {
				return fmt.Errorf("Compose directory %s: %w", dir, err)
			}
			dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
			if !ok || dirStat.Uid != 0 {
				return fmt.Errorf("Compose directory %s must be owned by root", dir)
			}
			if dirInfo.Mode().Perm()&0o022 != 0 && dirInfo.Mode()&os.ModeSticky == 0 {
				return fmt.Errorf("Compose directory %s must not be group/world-writable", dir)
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return nil
}

func runDockerCompose(ctx context.Context, project string, files []string, subcommand ...string) ([]byte, int, error) {
	args := []string{"compose", "-p", project}
	for _, file := range files {
		args = append(args, "-f", file)
	}
	args = append(args, subcommand...)
	return runBinary(ctx, "docker", args...)
}

func dockerImageID(ctx context.Context, image string) string {
	if image == "" {
		return ""
	}
	output, code, err := runBinary(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", image)
	if err != nil || code != 0 {
		return ""
	}
	return strings.TrimSpace(string(output))
}

type dockerProjectContainer struct {
	ID      string
	ImageID string
}

func dockerProjectContainers(ctx context.Context, project string) map[string]dockerProjectContainer {
	result := make(map[string]dockerProjectContainer)
	output, code, err := runBinary(ctx, "docker", "ps", "--filter", "label=com.docker.compose.project="+project, "--format", "{{.ID}}")
	if err != nil || code != 0 {
		return result
	}
	for _, id := range strings.Fields(string(output)) {
		if len(result) >= 100 {
			break
		}
		inspect, inspectCode, inspectErr := runBinary(ctx, "docker", "inspect", "--format",
			`{{.Image}} {{index .Config.Labels "com.docker.compose.service"}}`, id)
		if inspectErr != nil || inspectCode != 0 {
			continue
		}
		fields := strings.Fields(string(inspect))
		if len(fields) < 2 {
			continue
		}
		service := fields[len(fields)-1]
		result[service] = dockerProjectContainer{ID: id, ImageID: fields[0]}
	}
	return result
}

func acquireDockerLock() (*os.File, error) {
	file, err := os.OpenFile(dockerLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open Docker operation lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errors.New("another Docker operation is already in progress")
		}
		return nil, fmt.Errorf("lock Docker operation: %w", err)
	}
	return file, nil
}

func releaseDockerLock(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}

func boundedText(value []byte, limit int) string {
	if len(value) > limit {
		return string(value[:limit]) + "\n[output truncated]"
	}
	return string(value)
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
