package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestValidatePackageFilenameAndHeader(t *testing.T) {
	cases := []struct {
		name   string
		format string
		header []byte
	}{
		{"agent.deb", "deb", []byte("!<arch>\n")},
		{"agent.rpm", "rpm", []byte{0xed, 0xab, 0xee, 0xdb}},
		{"agent.pkg.tar.zst", "pkg.tar.zst", []byte{0x28, 0xb5, 0x2f, 0xfd}},
		{"agent.apk", "apk", []byte{0x1f, 0x8b}},
	}
	for _, tc := range cases {
		format, err := ValidatePackageFilename(tc.name)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if format != tc.format {
			t.Fatalf("%s: expected %s, got %s", tc.name, tc.format, format)
		}
		if err := ValidatePackageHeader(tc.format, tc.header); err != nil {
			t.Fatalf("%s header: %v", tc.name, err)
		}
	}
	for _, name := range []string{"agent.exe", "../agent.deb", "agent", "agent.deb/../evil"} {
		if _, err := ValidatePackageFilename(name); err == nil {
			t.Fatalf("expected %q to be rejected", name)
		}
	}
	if err := ValidatePackageHeader("deb", []byte("not a deb")); err == nil {
		t.Fatal("expected invalid deb header to fail")
	}
}

func TestValidateInstallEnvironment(t *testing.T) {
	if err := ValidateInstallEnvironment(map[string]string{"WAZUH_MANAGER": "10.0.0.5"}); err != nil {
		t.Fatalf("expected safe variable to pass: %v", err)
	}
	for _, env := range []map[string]string{
		{"LD_PRELOAD": "/tmp/evil.so"},
		{"PATH": "/tmp"},
		{"SUDO_ASKPASS": "/tmp/evil"},
		{"BASH_FUNC_evil": "() { id; }"},
		{"NODE_OPTIONS": "--require /tmp/evil.js"},
		{"lowercase": "value"},
		{"SAFE": "line\nbreak"},
	} {
		if err := ValidateInstallEnvironment(env); err == nil {
			t.Fatalf("expected %#v to be rejected", env)
		}
	}
}

func TestInstallPackageCommandUsesFixedArguments(t *testing.T) {
	restoreLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "apt-get" {
			return "/usr/bin/apt-get", nil
		}
		return "", errors.New("not found")
	})
	defer restoreLook()
	var gotName string
	var gotArgs []string
	var gotEnv []string
	restoreRun := SetPackageRunnerForTest(func(_ context.Context, env []string, name string, args ...string) ([]byte, int, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		gotEnv = append([]string(nil), env...)
		return []byte("installed"), 0, nil
	})
	defer restoreRun()

	result := installPackageFile(context.Background(), "deb", "/tmp/hibp-package.deb", InstallPackageRequest{
		Filename: "agent.deb", SHA256: strings.Repeat("a", 64),
		Env: map[string]string{"WAZUH_MANAGER": "10.0.0.5"},
	})
	if !result.OK || result.Error != "" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if gotName != "apt-get" {
		t.Fatalf("unexpected command: %s", gotName)
	}
	if !contains(gotArgs, "install") || !contains(gotArgs, "/tmp/hibp-package.deb") {
		t.Fatalf("unexpected arguments: %v", gotArgs)
	}
	if !contains(gotEnv, "WAZUH_MANAGER=10.0.0.5") || !contains(gotEnv, "DEBIAN_FRONTEND=noninteractive") {
		t.Fatalf("missing environment: %v", gotEnv)
	}
}

func TestInstallRejectsInvalidPackageHeader(t *testing.T) {
	body, err := json.Marshal(InstallPackageRequest{
		Filename: "agent.deb", SHA256: strings.Repeat("0", 64),
		Package: []byte("not a debian archive"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err = installPackage(context.Background(), bytes.NewReader(body), &out)
	if err == nil || !strings.Contains(err.Error(), "Debian package") {
		t.Fatalf("expected header validation error, got %v", err)
	}
}

func TestInstallRejectsHashMismatch(t *testing.T) {
	body, err := json.Marshal(InstallPackageRequest{
		Filename: "agent.deb", SHA256: strings.Repeat("0", 64),
		Package: []byte("!<arch>\npackage"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := installPackage(context.Background(), bytes.NewReader(body), &out); err == nil {
		t.Fatal("expected hash mismatch to fail")
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
