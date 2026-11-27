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

func TestParseTimedatectlTimeSyncStatus(t *testing.T) {
	status := timeSyncStatus{OK: true, Source: "timedatectl"}
	parseTimedatectlStatus(`       Server: 10.0.0.1 (ntp.example)
 Poll interval: 34min 8s (min: 32s; max 34min 8s)
       Offset: +123.4ms
        Delay: 1.2ms
       Jitter: 300us
     Stratum: 2
  Leap status: normal
`, &status)
	if !status.OK || !status.OffsetKnown || status.Stratum != 2 {
		t.Fatalf("unexpected timedatectl status: %+v", status)
	}
	if status.OffsetSeconds < 0.1233 || status.OffsetSeconds > 0.1235 {
		t.Fatalf("unexpected offset: %f", status.OffsetSeconds)
	}
}

func TestParseChronyTimeSyncStatus(t *testing.T) {
	status := parseChronyTracking(`Reference ID    : 10.0.0.1 (ntp.example)
Stratum         : 3
System time     : 0.00123456 seconds slow of NTP time
Last offset     : +0.00120000 seconds
RMS offset      : 0.00150000 seconds
Leap status     : Normal
`)
	if !status.OK || !status.OffsetKnown || status.Stratum != 3 {
		t.Fatalf("unexpected chrony status: %+v", status)
	}
	if status.OffsetSeconds < 0.00123 || status.OffsetSeconds > 0.00124 {
		t.Fatalf("unexpected chrony offset: %f", status.OffsetSeconds)
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
	args := strings.Join(gotArgs, " ")
	if !strings.HasSuffix(gotName, "apt-get") || (args != "-s upgrade" && args != "-s full-upgrade") {
		t.Fatalf("unexpected command: %s %v", gotName, gotArgs)
	}
	if !strings.Contains(output, "Inst curl") {
		t.Fatalf("unexpected output: %q", output)
	}
}

func TestAptCheckRefreshesListsBeforeSimulation(t *testing.T) {
	restoreLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "apt-get" {
			return "/usr/bin/apt-get", nil
		}
		return "", errors.New("not found")
	})
	defer restoreLook()
	var calls [][]string
	restoreRun := SetRunnerForTest(func(_ context.Context, _ string, args ...string) ([]byte, int, error) {
		calls = append(calls, append([]string(nil), args...))
		return []byte("Inst curl [1.0] (1.1)\n"), 0, nil
	})
	defer restoreRun()

	if _, _, err := checkCommand(context.Background(), "apt", false); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected update + simulation, got %v", calls)
	}
	if strings.Join(calls[0], " ") != "update" {
		t.Fatalf("expected apt-get update first, got %v", calls[0])
	}
	if len(calls[1]) < 2 || calls[1][0] != "-s" {
		t.Fatalf("expected apt-get simulation, got %v", calls[1])
	}
}

func TestUnknownActionRejected(t *testing.T) {
	if err := Run(context.Background(), "shell", &strings.Builder{}); err == nil {
		t.Fatal("expected unknown action to fail")
	}
}

func TestReadCheckmkRunbookRequestValidatesFields(t *testing.T) {
	request, err := readRunbookRequestFrom(strings.NewReader(`{"checkmk":{"hostname":"web01","server":"checkmk:8000","site":"Bergling","user":"cmkadmin","password":"password1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if request.Checkmk == nil || request.Checkmk.Hostname != "web01" || request.Checkmk.Server != "checkmk:8000" {
		t.Fatalf("unexpected Checkmk request: %+v", request.Checkmk)
	}

	request, err = readRunbookRequestFrom(strings.NewReader(`{"checkmk":{"server":"checkmk","site":"Bergling","user":"cmkadmin","password":"password1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if request.Checkmk == nil || request.Checkmk.Hostname == "" {
		t.Fatal("expected an empty hostname to resolve to the target hostname")
	}

	request, err = readRunbookRequestFrom(strings.NewReader(`{"checkmk":{"hostname":"$HOSTNAME","server":"checkmk","site":"Bergling","user":"cmkadmin","password":"password1"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if request.Checkmk == nil || request.Checkmk.Hostname == "" || request.Checkmk.Hostname == "$HOSTNAME" {
		t.Fatal("expected $HOSTNAME to resolve to the target hostname")
	}

	invalid := []string{
		`{"checkmk":{"hostname":"bad host","server":"checkmk","site":"Bergling","user":"cmkadmin","password":"password1"}}`,
		`{"checkmk":{"server":"checkmk:bad","site":"Bergling","user":"cmkadmin","password":"password1"}}`,
		`{"checkmk":{"server":"checkmk:70000","site":"Bergling","user":"cmkadmin","password":"password1"}}`,
		`{"checkmk":{"server":"checkmk","site":"bad site","user":"cmkadmin","password":"password1"}}`,
		`{"checkmk":{"server":"checkmk","site":"Bergling","user":"bad user","password":"password1"}}`,
		`{"checkmk":{"server":"checkmk","site":"Bergling","user":"cmkadmin","password":""}}`,
		`{"checkmk":{"server":"checkmk","site":"Bergling","user":"cmkadmin","password":"line\nbreak"}}`,
		`{"checkmk":{"server":"checkmk","site":"Bergling","user":"cmkadmin","password":"password1","extra":"x"}}`,
	}
	for _, payload := range invalid {
		if _, err := readRunbookRequestFrom(strings.NewReader(payload)); err == nil {
			t.Fatalf("expected invalid Checkmk request to be rejected: %s", payload)
		}
	}
}

func TestCheckmkRegisterRunsFixedCommandAndAnswersPrompt(t *testing.T) {
	restoreLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "cmk-agent-ctl" {
			return "/usr/bin/cmk-agent-ctl", nil
		}
		return "", errors.New("not found")
	})
	defer restoreLook()
	var gotName, gotInput string
	var gotArgs []string
	restoreRun := SetInputRunnerForTest(func(_ context.Context, name, input string, args ...string) ([]byte, int, error) {
		gotName = name
		gotInput = input
		gotArgs = append([]string(nil), args...)
		return []byte("Registered web01. password1 accepted.\n"), 0, nil
	})
	defer restoreRun()

	result := runCheckmkRegister(context.Background(), CheckmkRegisterRequest{
		Hostname: "web01", Server: "checkmk:8000", Site: "Bergling",
		User: "cmkadmin", Password: "password1",
	})
	if !result.OK || result.ExitCode != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Action != "cmk-agent-ctl register" {
		t.Fatalf("unexpected action: %q", result.Action)
	}
	wantCommand := "cmk-agent-ctl register --hostname web01 --server checkmk:8000 --site Bergling --user cmkadmin --password ********"
	if result.Command != wantCommand {
		t.Fatalf("unexpected command preview: %q", result.Command)
	}
	if strings.Contains(result.Command, "password1") {
		t.Fatalf("password leaked into command preview: %q", result.Command)
	}
	if gotName != "/usr/bin/cmk-agent-ctl" {
		t.Fatalf("unexpected binary: %s", gotName)
	}
	wantArgs := "register --hostname web01 --server checkmk:8000 --site Bergling --user cmkadmin --password password1"
	if strings.Join(gotArgs, " ") != wantArgs {
		t.Fatalf("unexpected arguments: %v", gotArgs)
	}
	if gotInput != "y\n" {
		t.Fatalf("expected certificate confirmation on stdin, got %q", gotInput)
	}
	if strings.Contains(result.Output, "password1") || !strings.Contains(result.Output, "[redacted]") {
		t.Fatalf("password was not redacted from output: %q", result.Output)
	}
}

func TestCheckmkRegisterReportsMissingBinaryAndFailure(t *testing.T) {
	restoreLook := SetLookPathForTest(func(string) (string, error) {
		return "", errors.New("not found")
	})
	result := runCheckmkRegister(context.Background(), CheckmkRegisterRequest{
		Hostname: "web01", Server: "checkmk", Site: "Bergling",
		User: "cmkadmin", Password: "password1",
	})
	restoreLook()
	if result.OK || result.ExitCode != 127 || !strings.Contains(result.Error, "not installed") {
		t.Fatalf("unexpected missing-binary result: %+v", result)
	}

	restoreLook = SetLookPathForTest(func(string) (string, error) {
		return "/usr/bin/cmk-agent-ctl", nil
	})
	defer restoreLook()
	restoreRun := SetInputRunnerForTest(func(context.Context, string, string, ...string) ([]byte, int, error) {
		return []byte("certificate rejected\n"), 1, nil
	})
	defer restoreRun()
	result = runCheckmkRegister(context.Background(), CheckmkRegisterRequest{
		Hostname: "web01", Server: "checkmk", Site: "Bergling",
		User: "cmkadmin", Password: "password1",
	})
	if result.OK || result.ExitCode != 1 || !strings.Contains(result.Error, "exited with code 1") {
		t.Fatalf("unexpected failure result: %+v", result)
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

func TestRebootFallsBackWhenSystemctlFails(t *testing.T) {
	restoreLook := SetLookPathForTest(func(name string) (string, error) {
		switch name {
		case "systemctl":
			return "/usr/bin/systemctl", nil
		case "shutdown":
			return "/sbin/shutdown", nil
		default:
			return "", errors.New("not found")
		}
	})
	defer restoreLook()
	var gotName string
	restoreRun := SetRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		gotName = name
		if name == "/usr/bin/systemctl" {
			return []byte("systemctl failed"), 1, nil
		}
		return []byte("shutdown requested"), 0, nil
	})
	defer restoreRun()

	var output strings.Builder
	if err := Run(context.Background(), "reboot", &output); err != nil {
		t.Fatal(err)
	}
	if gotName != "/sbin/shutdown" {
		t.Fatalf("expected shutdown fallback, got %s", gotName)
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

func TestCompareKernelVersions(t *testing.T) {
	if compareKernelVersions("6.9.0", "6.12.0") >= 0 {
		t.Fatal("6.9.0 should sort before 6.12.0")
	}
	if compareKernelVersions("6.12.0-1", "6.12.0-2") >= 0 {
		t.Fatal("6.12.0-1 should sort before 6.12.0-2")
	}
	if compareKernelVersions("6.12.0", "6.12.0") != 0 {
		t.Fatal("equal versions should compare equal")
	}
}

func TestAptUpgradeActionForKali(t *testing.T) {
	if got := aptUpgradeActionFor("kali", "debian"); got != "full-upgrade" {
		t.Fatalf("Kali should use full-upgrade, got %q", got)
	}
	if got := aptUpgradeActionFor("ubuntu", "debian"); got != "upgrade" {
		t.Fatalf("Ubuntu should keep upgrade, got %q", got)
	}
	if got := aptUpgradeActionFor("debian", ""); got != "upgrade" {
		t.Fatalf("Debian should keep upgrade, got %q", got)
	}
}

func TestParseCleanupPackages(t *testing.T) {
	apt := "The following packages will be REMOVED:\n  libfoo1 libbar2\n  oldkernel\n0 upgraded, 0 newly installed, 3 to remove and 0 not upgraded.\n"
	if got := parseAptAutoremove(apt); strings.Join(got, ",") != "libfoo1,libbar2,oldkernel" {
		t.Fatalf("unexpected apt orphans: %v", got)
	}
	dnf := "Last metadata expiration check: 0:01:00 ago.\nInstalled Packages\nfoo.x86_64 1.0-1.fc41 @System\nbar.noarch 2.0-1.fc41 @System\n"
	if got := parseDNFList(dnf); strings.Join(got, ",") != "foo,bar" {
		t.Fatalf("unexpected dnf orphans: %v", got)
	}
	if got := parseDNFPackages("foo\nbar\n"); strings.Join(got, ",") != "foo,bar" {
		t.Fatalf("unexpected dnf repoquery orphans: %v", got)
	}
	zypper := "S | Repository | Name | Version | Arch\n--+------------+------+---------+-----\ni+ | @System | keepme | 1.0 | x86_64\ni  | @System | dropme | 2.0 | x86_64\n"
	if got := parseZypperUnneeded(zypper); strings.Join(got, ",") != "dropme" {
		t.Fatalf("unexpected zypper orphans: %v", got)
	}
	pacman := "libfoo\nlibbar\n"
	if got := parsePacmanOrphans(pacman); strings.Join(got, ",") != "libfoo,libbar" {
		t.Fatalf("unexpected pacman orphans: %v", got)
	}
}

func TestCleanupCheckUsesFixedCommands(t *testing.T) {
	tests := []struct {
		name     string
		binary   string
		output   string
		code     int
		wantArgs string
		want     int
	}{
		{name: "apt", binary: "apt-get", output: "The following packages will be REMOVED:\n  libfoo1\n0 upgraded.\n", wantArgs: "-s autoremove", want: 1},
		{name: "dnf", binary: "dnf", output: "foo\nbar\n", wantArgs: "-q repoquery --unneeded --installed --qf %{name}", want: 2},
		{name: "zypper", binary: "zypper", output: "S | Repository | Name | Version | Arch\n--+--+--+--+--\ni | @System | dropme | 2.0 | x86_64\n", wantArgs: "-q --non-interactive --no-refresh packages --unneeded", want: 1},
		{name: "pacman", binary: "pacman", output: "libfoo\n", code: 0, wantArgs: "-Qdtq", want: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			restoreLook := SetLookPathForTest(func(name string) (string, error) {
				if name == tc.binary {
					return "/usr/bin/" + name, nil
				}
				return "", errors.New("not found")
			})
			defer restoreLook()
			var gotArgs []string
			restoreRun := SetRunnerForTest(func(_ context.Context, _ string, args ...string) ([]byte, int, error) {
				gotArgs = append([]string(nil), args...)
				return []byte(tc.output), tc.code, nil
			})
			defer restoreRun()

			result, err := cleanupCheck(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !result.Supported || !result.OK || result.Count != tc.want {
				t.Fatalf("unexpected result: %+v", result)
			}
			if strings.Join(gotArgs, " ") != tc.wantArgs {
				t.Fatalf("expected %q, got %q", tc.wantArgs, strings.Join(gotArgs, " "))
			}
		})
	}
}

func TestCleanupApplyUsesComputedNames(t *testing.T) {
	restoreLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "pacman" {
			return "/usr/bin/pacman", nil
		}
		return "", errors.New("not found")
	})
	defer restoreLook()
	var calls [][]string
	restoreRun := SetRunnerForTest(func(_ context.Context, _ string, args ...string) ([]byte, int, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(calls) == 1 {
			return []byte("libfoo\nlibbar\n"), 0, nil
		}
		return []byte("removed\n"), 0, nil
	})
	defer restoreRun()

	result, err := cleanupApply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || len(result.Packages) != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(calls) < 2 || strings.Join(calls[1], " ") != "-R --noconfirm -- libfoo libbar" {
		t.Fatalf("unexpected apply command: %v", calls)
	}
}

func TestCleanupUnsupportedPackageManager(t *testing.T) {
	restoreLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "apk" {
			return "/sbin/apk", nil
		}
		return "", errors.New("not found")
	})
	defer restoreLook()
	result, err := cleanupCheck(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Supported || !result.OK || len(result.Packages) != 0 {
		t.Fatalf("expected unsupported apk result, got %+v", result)
	}
}

func TestCleanupApplyZypperUsesComputedNames(t *testing.T) {
	restoreLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "zypper" {
			return "/usr/bin/zypper", nil
		}
		return "", errors.New("not found")
	})
	defer restoreLook()
	var calls [][]string
	restoreRun := SetRunnerForTest(func(_ context.Context, _ string, args ...string) ([]byte, int, error) {
		calls = append(calls, append([]string(nil), args...))
		if len(calls) == 1 {
			return []byte("S | Repository | Name | Version | Arch\n--+--+--+--+--\ni | @System | dropme | 2.0 | x86_64\ni+ | @System | keepme | 1.0 | x86_64\n"), 0, nil
		}
		return []byte("removed\n"), 0, nil
	})
	defer restoreRun()

	result, err := cleanupApply(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || len(result.Packages) != 1 || result.Packages[0] != "dropme" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(calls) < 2 || strings.Join(calls[1], " ") != "--non-interactive remove --clean-deps -- dropme" {
		t.Fatalf("unexpected apply command: %v", calls)
	}
}
