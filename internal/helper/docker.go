package helper

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// DockerInventory is the read-only view shown under a managed host. It never
// includes container environment variables, command lines, secrets, or mounts.
type DockerInventory struct {
	CollectedAt    string            `json:"collected_at"`
	Available      bool              `json:"available"`
	DockerVersion  string            `json:"docker_version"`
	ComposeVersion string            `json:"compose_version"`
	Projects       []DockerProject   `json:"projects"`
	Containers     []DockerContainer `json:"containers"`
	Error          string            `json:"error,omitempty"`
}

type DockerProject struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	ConfigFiles string `json:"config_files"`
	WorkingDir  string `json:"working_dir"`
}

type DockerContainer struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Image     string `json:"image"`
	Project   string `json:"project"`
	Service   string `json:"service"`
	State     string `json:"state"`
	Status    string `json:"status"`
	Health    string `json:"health"`
	Ports     string `json:"ports"`
	CreatedAt string `json:"created_at"`
}

type dockerPSLine struct {
	ID        string `json:"ID"`
	Names     string `json:"Names"`
	Image     string `json:"Image"`
	Labels    string `json:"Labels"`
	State     string `json:"State"`
	Status    string `json:"Status"`
	Ports     string `json:"Ports"`
	CreatedAt string `json:"CreatedAt"`
}

type dockerComposeProject struct {
	Name        string `json:"Name"`
	Status      string `json:"Status"`
	ConfigFiles string `json:"ConfigFiles"`
}

func collectDockerInventory(ctx context.Context) (DockerInventory, error) {
	inventory := DockerInventory{
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
		Projects:    []DockerProject{},
		Containers:  []DockerContainer{},
	}
	if _, err := lookPath("docker"); err != nil {
		inventory.Error = "Docker CLI is not installed"
		return inventory, nil
	}
	inventory.Available = true
	if output, code, err := runBinary(ctx, "docker", "version", "--format", "{{.Server.Version}}"); err == nil && code == 0 {
		inventory.DockerVersion = strings.TrimSpace(string(output))
	} else if err != nil {
		inventory.Error = err.Error()
	}
	if output, code, err := runBinary(ctx, "docker", "compose", "version", "--short"); err == nil && code == 0 {
		inventory.ComposeVersion = strings.TrimSpace(string(output))
	}

	projects := make(map[string]DockerProject)
	if output, code, err := runBinary(ctx, "docker", "compose", "ls", "--all", "--format", "json"); err == nil && code == 0 {
		var listed []dockerComposeProject
		if err := json.Unmarshal(output, &listed); err == nil {
			for _, project := range listed {
				projects[project.Name] = DockerProject{
					Name:        project.Name,
					Status:      project.Status,
					ConfigFiles: project.ConfigFiles,
				}
			}
		}
	}

	output, code, err := runBinary(ctx, "docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}")
	if err != nil {
		inventory.Error = err.Error()
		return inventory, nil
	}
	if code != 0 {
		inventory.Error = strings.TrimSpace(string(output))
		return inventory, nil
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var parsed dockerPSLine
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			continue
		}
		labels := parseDockerLabels(parsed.Labels)
		projectName := labels["com.docker.compose.project"]
		service := labels["com.docker.compose.service"]
		configFiles := labels["com.docker.compose.project.config_files"]
		workingDir := labels["com.docker.compose.project.working_dir"]
		if projectName != "" {
			project, ok := projects[projectName]
			if !ok {
				project = DockerProject{Name: projectName}
			}
			if project.ConfigFiles == "" {
				project.ConfigFiles = configFiles
			}
			if project.WorkingDir == "" {
				project.WorkingDir = workingDir
			}
			if project.Status == "" {
				project.Status = parsed.State
			}
			projects[projectName] = project
		}
		inventory.Containers = append(inventory.Containers, DockerContainer{
			ID:        parsed.ID,
			Name:      parsed.Names,
			Image:     parsed.Image,
			Project:   projectName,
			Service:   service,
			State:     parsed.State,
			Status:    parsed.Status,
			Health:    dockerHealth(parsed.Status),
			Ports:     parsed.Ports,
			CreatedAt: parsed.CreatedAt,
		})
		if len(inventory.Containers) >= 2000 {
			break
		}
	}
	for _, project := range projects {
		inventory.Projects = append(inventory.Projects, project)
	}
	sort.Slice(inventory.Projects, func(i, j int) bool { return inventory.Projects[i].Name < inventory.Projects[j].Name })
	sort.Slice(inventory.Containers, func(i, j int) bool {
		if inventory.Containers[i].Project != inventory.Containers[j].Project {
			return inventory.Containers[i].Project < inventory.Containers[j].Project
		}
		return inventory.Containers[i].Name < inventory.Containers[j].Name
	})
	return inventory, nil
}

func parseDockerLabels(raw string) map[string]string {
	labels := make(map[string]string)
	for _, pair := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		labels[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return labels
}

func dockerHealth(status string) string {
	lower := strings.ToLower(status)
	switch {
	case strings.Contains(lower, "(healthy)"):
		return "healthy"
	case strings.Contains(lower, "(unhealthy)"):
		return "unhealthy"
	case strings.Contains(lower, "(health: starting)"):
		return "starting"
	default:
		return ""
	}
}
