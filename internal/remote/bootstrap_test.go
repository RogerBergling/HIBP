package remote

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestValidateSudoUsername(t *testing.T) {
	valid := []string{"roger", "hibp_svc", "user.name", "user-name", "u123", strings.Repeat("a", 64)}
	for _, username := range valid {
		if err := validateSudoUsername(username); err != nil {
			t.Fatalf("expected %q to be valid: %v", username, err)
		}
	}

	invalid := []string{"", "ALL", "all", "All", "root user", "foo;bar", "%admin", "-user", ".user", "user,other", strings.Repeat("a", 65)}
	for _, username := range invalid {
		if err := validateSudoUsername(username); err == nil {
			t.Fatalf("expected %q to be rejected", username)
		}
	}
}

func TestSudoersContentIsRestricted(t *testing.T) {
	content := sudoersContent("roger")
	if strings.Contains(content, "NOPASSWD: ALL") {
		t.Fatal("sudoers content must not grant unrestricted passwordless sudo")
	}
	for _, action := range []string{"facts", "check", "apply", "reboot", "reboot-check"} {
		want := "roger ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper " + action
		if !strings.Contains(content, want) {
			t.Fatalf("missing restricted rule for %s in:\n%s", action, content)
		}
	}
	lines := strings.Split(strings.TrimSpace(content), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected one comment and five rules, got %d lines:\n%s", len(lines), content)
	}
}

func TestArchitectureMatches(t *testing.T) {
	var matching, other string
	switch runtime.GOARCH {
	case "amd64":
		matching, other = "x86_64", "aarch64"
	case "arm64":
		matching, other = "aarch64", "x86_64"
	case "arm":
		matching, other = "armv7l", "x86_64"
	default:
		matching, other = runtime.GOARCH, "mips64"
	}
	if !architectureMatches(matching) {
		t.Fatalf("expected %q to match controller architecture %s", matching, runtime.GOARCH)
	}
	if architectureMatches(other) {
		t.Fatalf("expected %q not to match controller architecture %s", other, runtime.GOARCH)
	}
}

func TestInstallHelperRejectsUnsafeInputBeforeConnecting(t *testing.T) {
	if _, err := InstallHelper(context.Background(), Target{Username: "ALL"}, nil, []byte("binary"), ""); err == nil {
		t.Fatal("expected username ALL to be rejected")
	}
	if _, err := InstallHelper(context.Background(), Target{Username: "roger"}, nil, nil, ""); err == nil {
		t.Fatal("expected empty binary to be rejected")
	}
}

type fakeRunner struct {
	commands []string
	inputs   []string
	handle   func(command, input string) (string, int, error)
}

func (f *fakeRunner) run(_ context.Context, _ Target, _ *HostKey, command, input string, _ time.Duration) (string, int, error) {
	f.commands = append(f.commands, command)
	f.inputs = append(f.inputs, input)
	if f.handle != nil {
		return f.handle(strings.TrimPrefix(command, bootstrapPath+" "), input)
	}
	return "", 0, nil
}

func (f *fakeRunner) find(prefix string) (string, string, bool) {
	for index, command := range f.commands {
		if strings.HasPrefix(strings.TrimPrefix(command, bootstrapPath+" "), prefix) {
			return strings.TrimPrefix(command, bootstrapPath+" "), f.inputs[index], true
		}
	}
	return "", "", false
}

func controllerUname() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "arm":
		return "armv7l"
	default:
		return runtime.GOARCH
	}
}

func bootstrapHandler(t *testing.T, uname string) func(command, input string) (string, int, error) {
	t.Helper()
	return func(command, input string) (string, int, error) {
		switch {
		case command == "uname -m":
			return uname + "\n", 0, nil
		case command == "sudo -n -p '' true", command == "sudo -S -p '' true":
			return "", 0, nil
		case strings.HasSuffix(command, " version"):
			return "hibp test\n", 0, nil
		case strings.HasPrefix(command, "mkdir -m 700 "):
			return "", 0, nil
		case strings.HasPrefix(command, "cat > "):
			return "", 0, nil
		case strings.Contains(command, "install -D -m 0755"):
			return "", 0, nil
		case strings.Contains(command, "install -m 0440 -o root -g root"):
			return "", 0, nil
		case strings.Contains(command, "visudo -c -f"):
			return "parsed OK\n", 0, nil
		case strings.Contains(command, "mv -f"):
			return "", 0, nil
		case strings.Contains(command, "hibp-helper facts"):
			return `{"os_pretty_name":"Test Linux"}`, 0, nil
		case strings.Contains(command, "rm -rf "), strings.Contains(command, "rm -f "):
			return "", 0, nil
		default:
			return "", 0, fmt.Errorf("unexpected command %q", command)
		}
	}
}

func TestInstallHelperSuccessSequence(t *testing.T) {
	binary := []byte("fake-hibp-binary")
	fake := &fakeRunner{handle: bootstrapHandler(t, controllerUname())}
	output, err := installHelper(context.Background(), Target{Username: "roger"}, nil, binary, "secret", fake.run)
	if err != nil {
		t.Fatal(err)
	}
	if output != `{"os_pretty_name":"Test Linux"}` {
		t.Fatalf("unexpected output %q", output)
	}

	for _, command := range fake.commands {
		if !strings.HasPrefix(command, bootstrapPath+" ") {
			t.Fatalf("bootstrap command did not use the trusted PATH: %q", command)
		}
	}
	for _, prefix := range []string{
		"sudo -S -p '' true",
		"sudo -S -p '' install -D -m 0755 ",
		"/usr/local/libexec/hibp/.hibp-helper.",
		"sudo -S -p '' mv -f /usr/local/libexec/hibp/.hibp-helper.",
		"sudo -S -p '' install -m 0440 -o root -g root ",
		"sudo -S -p '' visudo -c -f /etc/sudoers.d/.hibp-helper.",
		"sudo -S -p '' mv -f /etc/sudoers.d/.hibp-helper.",
		"sudo -n -p '' /usr/local/libexec/hibp/hibp-helper facts",
	} {
		if _, _, ok := fake.find(prefix); !ok {
			t.Fatalf("missing command %q in:\n%s", prefix, strings.Join(fake.commands, "\n"))
		}
	}

	var uploads []string
	for index, command := range fake.commands {
		normalized := strings.TrimPrefix(command, bootstrapPath+" ")
		if strings.HasPrefix(normalized, "cat > ") {
			uploads = append(uploads, fake.inputs[index])
		}
		if strings.Contains(command, "secret") {
			t.Fatalf("sudo password leaked into command: %q", command)
		}
		if strings.HasPrefix(command, "sudo -S ") && fake.inputs[index] != "secret\n" {
			t.Fatalf("sudo password was not sent over stdin for %q: %q", command, fake.inputs[index])
		}
	}
	if len(uploads) != 2 {
		t.Fatalf("expected two uploads, got %d", len(uploads))
	}
	if uploads[0] != string(binary) {
		t.Fatal("helper binary upload did not preserve bytes")
	}
	if !strings.Contains(uploads[1], "roger ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper facts") {
		t.Fatalf("unexpected sudoers upload:\n%s", uploads[1])
	}
}

func TestInstallHelperRequiresSudoPassword(t *testing.T) {
	base := bootstrapHandler(t, controllerUname())
	fake := &fakeRunner{handle: func(command, input string) (string, int, error) {
		if command == "sudo -n -p '' true" {
			return "sudo: interactive authentication is required", 1, nil
		}
		return base(command, input)
	}}
	_, err := installHelper(context.Background(), Target{Username: "roger"}, nil, []byte("binary"), "", fake.run)
	if !errors.Is(err, ErrSudoPasswordRequired) {
		t.Fatalf("expected ErrSudoPasswordRequired, got %v", err)
	}
	for _, command := range fake.commands {
		if strings.Contains(command, "mkdir ") || strings.Contains(command, "cat > ") {
			t.Fatalf("upload started before sudo auth was confirmed: %q", command)
		}
	}
}

func TestInstallHelperRejectsInvalidSudoPassword(t *testing.T) {
	base := bootstrapHandler(t, controllerUname())
	fake := &fakeRunner{handle: func(command, input string) (string, int, error) {
		if command == "sudo -S -p '' true" {
			return "Sorry, try again.", 1, nil
		}
		return base(command, input)
	}}
	_, err := installHelper(context.Background(), Target{Username: "roger"}, nil, []byte("binary"), "wrong", fake.run)
	if !errors.Is(err, ErrSudoPasswordInvalid) {
		t.Fatalf("expected ErrSudoPasswordInvalid, got %v", err)
	}
}

func TestInstallHelperRejectsArchitectureMismatch(t *testing.T) {
	fake := &fakeRunner{handle: bootstrapHandler(t, "definitely-not-"+runtime.GOARCH)}
	_, err := installHelper(context.Background(), Target{Username: "roger"}, nil, []byte("binary"), "", fake.run)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected architecture mismatch, got %v", err)
	}
	for _, command := range fake.commands {
		if strings.HasPrefix(command, "mkdir ") || strings.HasPrefix(command, "cat > ") {
			t.Fatalf("upload started despite architecture mismatch: %q", command)
		}
	}
}

func TestInstallHelperFailsWhenNOPASSWDDoesNotWork(t *testing.T) {
	base := bootstrapHandler(t, controllerUname())
	fake := &fakeRunner{handle: func(command, input string) (string, int, error) {
		if command == "sudo -n -p '' /usr/local/libexec/hibp/hibp-helper facts" {
			return "sudo: a password is required", 1, nil
		}
		return base(command, input)
	}}
	_, err := installHelper(context.Background(), Target{Username: "roger"}, nil, []byte("binary"), "secret", fake.run)
	if err == nil || !strings.Contains(err.Error(), "NOPASSWD rule did not work") {
		t.Fatalf("expected NOPASSWD verification failure, got %v", err)
	}
}

func TestInstallHelperRejectsUnrunnableCandidateBeforeReplacingHelper(t *testing.T) {
	base := bootstrapHandler(t, controllerUname())
	fake := &fakeRunner{handle: func(command, input string) (string, int, error) {
		if strings.HasSuffix(command, " version") {
			return "error while loading shared libraries: libsqlcipher.so.0", 127, nil
		}
		return base(command, input)
	}}
	_, err := installHelper(context.Background(), Target{Username: "roger"}, nil, []byte("binary"), "secret", fake.run)
	if err == nil || !strings.Contains(err.Error(), "cannot run on the target") {
		t.Fatalf("expected preflight failure, got %v", err)
	}
	for _, command := range fake.commands {
		if strings.Contains(command, "mv -f /usr/local/libexec/hibp/.hibp-helper.") {
			t.Fatalf("candidate was moved into place despite preflight failure: %q", command)
		}
	}
}

func TestInstallHelperExplainsUnrunnableBinary(t *testing.T) {
	base := bootstrapHandler(t, controllerUname())
	fake := &fakeRunner{handle: func(command, input string) (string, int, error) {
		if command == "sudo -n -p '' /usr/local/libexec/hibp/hibp-helper facts" {
			return "error while loading shared libraries: libsqlcipher.so.0", 127, nil
		}
		return base(command, input)
	}}
	_, err := installHelper(context.Background(), Target{Username: "roger"}, nil, []byte("binary"), "secret", fake.run)
	if err == nil || !strings.Contains(err.Error(), "cannot run on the target") {
		t.Fatalf("expected runnable-binary error, got %v", err)
	}
}
