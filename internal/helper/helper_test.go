package helper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/RogerBergling/hibp/internal/buildinfo"
)

func TestParseOSRelease(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/os-release"
	content := "ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\nID_LIKE=debian\n"
	if err := writeTestFile(path, content); err != nil {
		t.Fatal(err)
	}
	info, err := readOSRelease(path)
	if err != nil {
		t.Fatal(err)
	}
	if info["ID"] != "ubuntu" || info["VERSION_ID"] != "24.04" {
		t.Fatalf("unexpected os-release: %#v", info)
	}
}

func TestParseUptime(t *testing.T) {
	if got := parseUptime("12345.67 999.00"); got != 12345 {
		t.Fatalf("expected 12345, got %d", got)
	}
	if got := parseUptime("bad"); got != 0 {
		t.Fatalf("expected 0, got %d", got)
	}
}

func TestCountPackages(t *testing.T) {
	apt := "Inst curl [1.0] (1.1 Ubuntu:24.04)\nInst vim [2.0] (2.1 Ubuntu:24.04)\nConf curl\n"
	if got := countPackages("apt", apt); got != 2 {
		t.Fatalf("expected 2 apt updates, got %d", got)
	}
	pacman := "curl 1.0 -> 1.1\nvim 2.0 -> 2.1\n"
	if got := countPackages("pacman", pacman); got != 2 {
		t.Fatalf("expected 2 pacman updates, got %d", got)
	}
}

func TestCheckActionUsesFixedCommand(t *testing.T) {
	restoreLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "apt-get" {
			return "/usr/bin/apt-get", nil
		}
		return "", errors.New("not found")
	})
	defer restoreLook()
	var gotName string
	var gotArgs []string
	restoreRun := SetRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		gotName = name
		gotArgs = args
		return []byte("Inst curl [1.0] (1.1)\n"), 0, nil
	})
	defer restoreRun()

	output, code, err := checkUpdates(context.Background())
	if err != nil || code != 0 {
		t.Fatalf("check failed: %v code=%d", err, code)
	}
	if !strings.HasSuffix(gotName, "apt-get") || strings.Join(gotArgs, " ") != "-s upgrade" {
		t.Fatalf("unexpected command: %s %v", gotName, gotArgs)
	}
	if !strings.Contains(output, "Inst curl") {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestUnknownActionRejected(t *testing.T) {
	if err := Run(context.Background(), "shell", &strings.Builder{}); err == nil {
		t.Fatal("expected unknown action to fail")
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func TestRebootUsesSystemdNoBlock(t *testing.T) {
	restoreLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "systemctl" {
			return "/usr/bin/systemctl", nil
		}
		return "", errors.New("not found")
	})
	defer restoreLook()
	var gotName string
	var gotArgs []string
	restoreRun := SetRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		gotName = name
		gotArgs = args
		return []byte("reboot requested"), 0, nil
	})
	defer restoreRun()

	var output strings.Builder
	if err := Run(context.Background(), "reboot", &output); err != nil {
		t.Fatal(err)
	}
	if gotName != "/usr/bin/systemctl" || strings.Join(gotArgs, " ") != "reboot --no-block" {
		t.Fatalf("unexpected command: %s %v", gotName, gotArgs)
	}
	if !strings.Contains(output.String(), `"action":"reboot"`) || !strings.Contains(output.String(), `"ok":true`) {
		t.Fatalf("unexpected result: %s", output.String())
	}
}

func TestRebootFallsBackToShutdown(t *testing.T) {
	restoreLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "systemctl" {
			return "", errors.New("not found")
		}
		if name == "shutdown" {
			return "/sbin/shutdown", nil
		}
		return "", errors.New("not found")
	})
	defer restoreLook()
	var gotName string
	var gotArgs []string
	restoreRun := SetRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		gotName = name
		gotArgs = args
		return []byte("shutdown requested"), 0, nil
	})
	defer restoreRun()

	var output strings.Builder
	if err := Run(context.Background(), "reboot", &output); err != nil {
		t.Fatal(err)
	}
	if gotName != "/sbin/shutdown" || strings.Join(gotArgs, " ") != "-r now" {
		t.Fatalf("unexpected command: %s %v", gotName, gotArgs)
	}
}

func TestDockerInventoryParsing(t *testing.T) {
	restoreLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "docker" {
			return "/usr/bin/docker", nil
		}
		return "", errors.New("not found")
	})
	defer restoreLook()
	restoreRun := SetRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		if name != "/usr/bin/docker" {
			t.Fatalf("unexpected binary: %s", name)
		}
		switch strings.Join(args, " ") {
		case "version --format {{.Server.Version}}":
			return []byte("27.0.0\n"), 0, nil
		case "compose version --short":
			return []byte("2.30.0\n"), 0, nil
		case "compose ls --all --format json":
			return []byte(`[{"Name":"web","Status":"running(2)","ConfigFiles":"/opt/web/compose.yaml"}]`), 0, nil
		case "ps -a --no-trunc --format {{json .}}":
			return []byte(`{"ID":"abc","Names":"web-1","Image":"nginx:1.27","Labels":"com.docker.compose.project=web,com.docker.compose.service=frontend","State":"running","Status":"Up 2 hours (healthy)","Ports":"0.0.0.0:80->80/tcp","CreatedAt":"2026-11-11 06:00:00 +0000 UTC"}` + "\n" +
				`{"ID":"def","Names":"standalone","Image":"redis:7","Labels":"","State":"exited","Status":"Exited (0) 1 hour ago","Ports":"","CreatedAt":"2026-11-11 06:00:00 +0000 UTC"}` + "\n"), 0, nil
		default:
			t.Fatalf("unexpected docker command: %v", args)
		}
		return nil, 0, nil
	})
	defer restoreRun()

	inventory, err := collectDockerInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !inventory.Available || inventory.DockerVersion != "27.0.0" || inventory.ComposeVersion != "2.30.0" {
		t.Fatalf("unexpected Docker metadata: %+v", inventory)
	}
	if len(inventory.Projects) != 1 || inventory.Projects[0].Name != "web" {
		t.Fatalf("unexpected projects: %+v", inventory.Projects)
	}
	if len(inventory.Containers) != 2 {
		t.Fatalf("unexpected containers: %+v", inventory.Containers)
	}
	var composeContainer *DockerContainer
	for index := range inventory.Containers {
		if inventory.Containers[index].Project == "web" {
			composeContainer = &inventory.Containers[index]
		}
	}
	if composeContainer == nil || composeContainer.Service != "frontend" || composeContainer.Health != "healthy" {
		t.Fatalf("unexpected compose container: %+v", inventory.Containers)
	}
}

func TestSystemInfoAndMetrics(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only collector")
	}
	info, err := collectSystemInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.Hostname == "" || info.CPU.Cores == 0 || info.Memory.TotalBytes == 0 {
		t.Fatalf("incomplete system info: %+v", info)
	}
	metrics, err := collectMetrics(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if metrics.CollectedAt == "" || metrics.MemoryPercent <= 0 {
		t.Fatalf("incomplete metrics: %+v", metrics)
	}
}

func TestDockerCheckAndApply(t *testing.T) {
	restoreLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "docker" {
			return "/usr/bin/docker", nil
		}
		return "", errors.New("not found")
	})
	defer restoreLook()
	oldTrust := composeTrustCheck
	composeTrustCheck = func([]string) error { return nil }
	defer func() { composeTrustCheck = oldTrust }()
	oldLock := dockerLockPath
	dockerLockPath = filepath.Join(t.TempDir(), "docker.lock")
	defer func() { dockerLockPath = oldLock }()

	imageCalls := 0
	restoreRun := SetRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		if name != "/usr/bin/docker" {
			t.Fatalf("unexpected binary: %s", name)
		}
		joined := strings.Join(args, " ")
		switch {
		case joined == "compose ls --all --format json":
			return []byte(`[{"Name":"web","Status":"running(2)","ConfigFiles":"/opt/web/compose.yaml"}]`), 0, nil
		case strings.Contains(joined, "config --format json"):
			return []byte(`{"services":{"frontend":{"image":"nginx:1.27"},"worker":{"build":{"context":"."}}}}`), 0, nil
		case strings.Contains(joined, "image inspect") && strings.Contains(joined, "nginx:1.27"):
			imageCalls++
			if imageCalls == 1 {
				return []byte("sha256:old\n"), 0, nil
			}
			return []byte("sha256:new\n"), 0, nil
		case strings.Contains(joined, "pull --quiet --ignore-buildable"):
			return []byte("pulled\n"), 0, nil
		case strings.Contains(joined, "ps --filter"):
			return []byte("abc\n"), 0, nil
		case strings.Contains(joined, "inspect --format"):
			return []byte("sha256:new frontend\n"), 0, nil
		case strings.Contains(joined, "up -d --pull never"):
			return []byte("up ok\n"), 0, nil
		default:
			t.Fatalf("unexpected docker command: %s", joined)
		}
		return nil, 0, nil
	})
	defer restoreRun()

	check, err := dockerCheck(context.Background(), []string{"web"})
	if err != nil {
		t.Fatal(err)
	}
	if !check.OK || len(check.Services) != 2 {
		t.Fatalf("unexpected check result: %+v", check)
	}
	var frontend *DockerServiceUpdate
	var worker *DockerServiceUpdate
	for index := range check.Services {
		switch check.Services[index].Service {
		case "frontend":
			frontend = &check.Services[index]
		case "worker":
			worker = &check.Services[index]
		}
	}
	if frontend == nil || frontend.Status != "image-updated" {
		t.Fatalf("unexpected frontend status: %+v", frontend)
	}
	if worker == nil || worker.Status != "build-only" {
		t.Fatalf("unexpected worker status: %+v", worker)
	}

	apply, err := dockerApply(context.Background(), []string{"web"})
	if err != nil {
		t.Fatal(err)
	}
	if !apply.OK || apply.ExitCode != 0 || apply.Project != "web" {
		t.Fatalf("unexpected apply result: %+v", apply)
	}
	if _, err := dockerCheck(context.Background(), []string{"bad project"}); err == nil {
		t.Fatal("invalid project name accepted")
	}
}

func TestFactsIncludeHelperBuildIdentity(t *testing.T) {
	restoreLook := SetLookPathForTest(func(string) (string, error) {
		return "", errors.New("not found")
	})
	defer restoreLook()
	old := buildinfo.Current
	buildinfo.Current = buildinfo.Info{
		Version: "0.6.3", BuildNumber: "42", BuildCommit: "abc123def456",
		BuildDate: "2026-11-11T12:00:00Z", BuildTarget: "linux/amd64", BuildType: "release",
	}
	defer func() { buildinfo.Current = old }()
	facts, err := collectFacts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if facts.Agent != buildinfo.Current {
		t.Fatalf("helper build = %+v, want %+v", facts.Agent, buildinfo.Current)
	}
}

func TestDockerUpdateAllUpdatesOnlyChangedProjects(t *testing.T) {
	restoreLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "docker" {
			return "/usr/bin/docker", nil
		}
		return "", errors.New("not found")
	})
	defer restoreLook()
	oldTrust := composeTrustCheck
	composeTrustCheck = func([]string) error { return nil }
	defer func() { composeTrustCheck = oldTrust }()
	oldLock := dockerLockPath
	dockerLockPath = filepath.Join(t.TempDir(), "docker.lock")
	defer func() { dockerLockPath = oldLock }()

	imageCalls := map[string]int{}
	applyCalls := 0
	restoreRun := SetRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		if name != "/usr/bin/docker" {
			t.Fatalf("unexpected binary: %s", name)
		}
		joined := strings.Join(args, " ")
		switch {
		case joined == "compose ls --all --format json":
			return []byte(`[{"Name":"web","Status":"running(1)","ConfigFiles":"/opt/web/compose.yaml"},{"Name":"db","Status":"running(1)","ConfigFiles":"/opt/db/compose.yaml"}]`), 0, nil
		case strings.Contains(joined, "-p web") && strings.Contains(joined, "config --format json"):
			return []byte(`{"services":{"frontend":{"image":"nginx:1.27"}}}`), 0, nil
		case strings.Contains(joined, "-p db") && strings.Contains(joined, "config --format json"):
			return []byte(`{"services":{"db":{"image":"postgres:16"}}}`), 0, nil
		case strings.Contains(joined, "image inspect"):
			image := "unknown"
			for _, candidate := range []string{"nginx:1.27", "postgres:16"} {
				if strings.Contains(joined, candidate) {
					image = candidate
				}
			}
			imageCalls[image]++
			if image == "nginx:1.27" && imageCalls[image] == 1 {
				return []byte("sha256:web-old\n"), 0, nil
			}
			if image == "nginx:1.27" {
				return []byte("sha256:web-new\n"), 0, nil
			}
			return []byte("sha256:db-same\n"), 0, nil
		case strings.Contains(joined, "pull --quiet --ignore-buildable"):
			return []byte("pulled\n"), 0, nil
		case strings.Contains(joined, "ps --filter"):
			if strings.Contains(joined, "project=web") {
				return []byte("web-container\n"), 0, nil
			}
			return []byte("db-container\n"), 0, nil
		case strings.Contains(joined, "inspect --format"):
			if strings.Contains(joined, "web-container") {
				return []byte("sha256:web-new frontend\n"), 0, nil
			}
			return []byte("sha256:db-same db\n"), 0, nil
		case strings.Contains(joined, "up -d --pull never"):
			applyCalls++
			return []byte("up ok\n"), 0, nil
		default:
			t.Fatalf("unexpected docker command: %s", joined)
		}
		return nil, 0, nil
	})
	defer restoreRun()

	result, err := dockerUpdateAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Updated != 1 || result.Skipped != 1 || result.Failed != 0 {
		t.Fatalf("unexpected update-all result: %+v", result)
	}
	if applyCalls != 1 {
		t.Fatalf("expected one compose up, got %d", applyCalls)
	}
	actions := map[string]string{}
	for _, project := range result.Projects {
		actions[project.Name] = project.Action
	}
	if actions["web"] != "updated" || actions["db"] != "no-change" {
		t.Fatalf("unexpected project actions: %+v", actions)
	}
}
