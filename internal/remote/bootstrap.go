package remote

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// ErrSudoPasswordRequired means the bootstrap attempt needs a sudo password.
var ErrSudoPasswordRequired = errors.New("sudo requires a password for helper installation")

// ErrSudoPasswordInvalid means the supplied sudo password was rejected.
var ErrSudoPasswordInvalid = errors.New("sudo password was rejected during helper installation")

var sudoUserPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

// bootstrapPath keeps bootstrap commands on trusted system paths instead of
// inheriting a PATH that the SSH account may be able to influence.
const bootstrapPath = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"

func bootstrapCommand(command string) string {
	return bootstrapPath + " " + command
}

func validateSudoUsername(username string) error {
	if !sudoUserPattern.MatchString(username) {
		return fmt.Errorf("unsupported SSH username for sudoers: %q", username)
	}
	if strings.EqualFold(username, "ALL") {
		return errors.New("SSH username ALL is not allowed for helper installation")
	}
	return nil
}

type runFunc func(ctx context.Context, target Target, expected *HostKey, command, input string, timeout time.Duration) (string, int, error)

// InstallHelper uploads this binary to the fixed helper path, installs a
// restricted sudoers rule, validates it, and runs a facts check. It requires
// SSH access and either passwordless sudo or a sudo password supplied by the
// caller. The sudo password is sent only over SSH stdin.
func InstallHelper(ctx context.Context, target Target, expected *HostKey, binary []byte, sudoPassword string) (string, error) {
	return installHelper(ctx, target, expected, binary, sudoPassword, RunWithInput)
}

func installHelper(ctx context.Context, target Target, expected *HostKey, binary []byte, sudoPassword string, run runFunc) (string, error) {
	if len(binary) == 0 {
		return "", errors.New("helper binary is empty")
	}
	if len(binary) > 100<<20 {
		return "", errors.New("helper binary is too large (maximum 100 MiB)")
	}
	if err := validateSudoUsername(target.Username); err != nil {
		return "", err
	}

	uname, code, err := run(ctx, target, expected, bootstrapCommand("uname -m"), "", 15*time.Second)
	if err != nil {
		return "", fmt.Errorf("detect target architecture: %w", err)
	}
	if code != 0 {
		return "", fmt.Errorf("detect target architecture: %s", strings.TrimSpace(uname))
	}
	if !architectureMatches(strings.TrimSpace(uname)) {
		return "", fmt.Errorf("controller architecture %s does not match target architecture %s", runtime.GOARCH, strings.TrimSpace(uname))
	}

	// Validate sudo before uploading a multi-megabyte binary. With no supplied
	// password this detects that sudo needs one; with a supplied password it
	// rejects a wrong password before any files are transferred.
	preflight, code, err := runSudo(ctx, target, expected, "true", sudoPassword, 30*time.Second, run)
	if err != nil {
		return "", fmt.Errorf("check sudo: %w", err)
	}
	if code != 0 {
		if sudoPassword == "" && looksLikeSudoAuthFailure(preflight) {
			return "", ErrSudoPasswordRequired
		}
		if looksLikeSudoPasswordInvalid(preflight) {
			return "", ErrSudoPasswordInvalid
		}
		return "", fmt.Errorf("sudo is not available for helper installation: %s", strings.TrimSpace(preflight))
	}

	suffix, err := randomSuffix()
	if err != nil {
		return "", err
	}
	dir := "/tmp/hibp-bootstrap-" + suffix
	helperPath := dir + "/hibp-helper"
	sudoersPath := dir + "/hibp-sudoers"
	helperTemp := "/usr/local/libexec/hibp/.hibp-helper." + suffix
	sudoersTemp := "/etc/sudoers.d/.hibp-helper." + suffix

	if _, code, err := run(ctx, target, expected, bootstrapCommand("mkdir -m 700 "+dir), "", 15*time.Second); err != nil {
		return "", fmt.Errorf("create bootstrap directory: %w", err)
	} else if code != 0 {
		return "", errors.New("could not create the target bootstrap directory")
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _, _ = run(cleanupCtx, target, expected, bootstrapCommand("rm -rf "+dir), "", 20*time.Second)
		// Temporary files are renamed into place on success. Remove them if
		// setup failed early. sudo ignores dot-named files in sudoers.d, so a
		// leftover rule would be harmless, but removing it is tidier.
		_, _, _ = runSudo(cleanupCtx, target, expected, "rm -f "+helperTemp+" "+sudoersTemp, sudoPassword, 20*time.Second, run)
	}()

	if err := upload(ctx, target, expected, helperPath, binary, run); err != nil {
		return "", err
	}
	if err := upload(ctx, target, expected, sudoersPath, []byte(sudoersContent(target.Username)), run); err != nil {
		return "", err
	}

	runStep := func(step string) error {
		output, code, err := runSudo(ctx, target, expected, step, sudoPassword, 2*time.Minute, run)
		if err != nil {
			return err
		}
		if code != 0 {
			if sudoPassword == "" && looksLikeSudoAuthFailure(output) {
				return ErrSudoPasswordRequired
			}
			if looksLikeSudoPasswordInvalid(output) {
				return ErrSudoPasswordInvalid
			}
			return fmt.Errorf("helper setup failed: %s", strings.TrimSpace(output))
		}
		return nil
	}

	// Install the candidate binary next to the final path and run it as the
	// unprivileged SSH account before replacing a working helper. This catches
	// dynamically linked or otherwise unrunnable binaries early.
	if err := runStep("install -D -m 0755 " + helperPath + " " + helperTemp); err != nil {
		return "", err
	}
	versionOutput, code, err := run(ctx, target, expected, bootstrapCommand(helperTemp+" version"), "", 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("check uploaded helper: %w", err)
	}
	if code != 0 {
		return "", fmt.Errorf("uploaded helper cannot run on the target (use the static release build): %s", strings.TrimSpace(versionOutput))
	}

	// Validate the new rule while it still has a dot in its name. sudo skips
	// files in /etc/sudoers.d whose names contain dots, so the temporary file
	// cannot affect existing sudoers parsing, and the final rename is atomic.
	steps := []string{
		"mv -f " + helperTemp + " /usr/local/libexec/hibp/hibp-helper",
		"install -m 0440 -o root -g root " + sudoersPath + " " + sudoersTemp,
		"visudo -c -f " + sudoersTemp,
		"mv -f " + sudoersTemp + " /etc/sudoers.d/hibp-helper",
	}
	for _, step := range steps {
		if err := runStep(step); err != nil {
			return "", err
		}
	}

	// Verification must use sudo -n, not the supplied password: the point of
	// bootstrap is to establish a passwordless helper rule.
	output, code, err := run(ctx, target, expected, bootstrapCommand("sudo -n -p '' /usr/local/libexec/hibp/hibp-helper facts"), "", 2*time.Minute)
	if err != nil {
		return "", fmt.Errorf("verify helper: %w", err)
	}
	if code != 0 {
		lower := strings.ToLower(output)
		if strings.Contains(lower, "error while loading shared libraries") || strings.Contains(lower, "no such file or directory") {
			return "", fmt.Errorf("helper was installed but cannot run on the target: %s", strings.TrimSpace(output))
		}
		if looksLikeSudoAuthFailure(output) {
			return "", fmt.Errorf("helper was installed, but the NOPASSWD rule did not work: %s", strings.TrimSpace(output))
		}
		return "", fmt.Errorf("helper verification failed: %s", strings.TrimSpace(output))
	}
	return output, nil
}

func upload(ctx context.Context, target Target, expected *HostKey, path string, data []byte, run runFunc) error {
	output, code, err := run(ctx, target, expected, bootstrapCommand("cat > "+path), string(data), 5*time.Minute)
	if err != nil {
		return fmt.Errorf("upload %s: %w", path, err)
	}
	if code != 0 {
		return fmt.Errorf("upload %s: %s", path, strings.TrimSpace(output))
	}
	return nil
}

func runSudo(ctx context.Context, target Target, expected *HostKey, command, sudoPassword string, timeout time.Duration, run runFunc) (string, int, error) {
	if sudoPassword == "" {
		return run(ctx, target, expected, bootstrapCommand("sudo -n -p '' "+command), "", timeout)
	}
	return run(ctx, target, expected, bootstrapCommand("sudo -S -p '' "+command), sudoPassword+"\n", timeout)
}

func sudoersContent(username string) string {
	return fmt.Sprintf(`# Managed by HIBP. This rule is limited to the fixed helper actions.
%s ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper facts
%s ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper check
%s ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper apply
%s ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper reboot
%s ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper reboot-check
%s ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper system-info
%s ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper metrics
%s ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper docker-list
%s ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper docker-check *
%s ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper docker-apply *
%s ALL=(root) NOPASSWD: /usr/local/libexec/hibp/hibp-helper docker-update-all
`, username, username, username, username, username, username, username, username, username, username, username)
}

func architectureMatches(uname string) bool {
	switch runtime.GOARCH {
	case "amd64":
		return uname == "x86_64" || uname == "amd64"
	case "arm64":
		return uname == "aarch64" || uname == "arm64"
	case "arm":
		return strings.HasPrefix(uname, "armv7") || uname == "arm"
	default:
		return uname == runtime.GOARCH
	}
}

func randomSuffix() (string, error) {
	buffer := make([]byte, 8)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func looksLikeSudoAuthFailure(output string) bool {
	lower := strings.ToLower(output)
	for _, needle := range []string{
		"interactive authentication is required",
		"a password is required",
		"authentication required but not attempted",
		"authentication failed, try again",
		"no tty present",
		"no askpass program specified",
		"a terminal is required",
		"must have a tty",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func looksLikeSudoPasswordInvalid(output string) bool {
	lower := strings.ToLower(output)
	for _, needle := range []string{
		"sorry, try again",
		"incorrect password",
		"incorrect password attempt",
		"authentication failure",
		"authentication failed",
	} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}
