package helper

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
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
