package helper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// MaxPackageSize is the maximum uploaded package size accepted by the helper.
// The controller applies the same limit before creating a job.
const MaxPackageSize = 100 << 20

// InstallPackageRequest is the JSON contract for install-package. The package
// bytes are transported as base64 inside JSON on stdin so the controller never
// has to place a root-installable file in an unprivileged directory.
type InstallPackageRequest struct {
	Filename string            `json:"filename"`
	SHA256   string            `json:"sha256"`
	Env      map[string]string `json:"env,omitempty"`
	Package  []byte            `json:"package"`
}

// PackageInstallResult is the JSON result of install-package.
type PackageInstallResult struct {
	Action         string `json:"action"`
	OK             bool   `json:"ok"`
	ExitCode       int    `json:"exit_code"`
	PackageManager string `json:"package_manager"`
	Package        string `json:"package"`
	SHA256         string `json:"sha256"`
	Output         string `json:"output"`
	Error          string `json:"error,omitempty"`
}

var packageNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]{0,127}$`)
var envKeyPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
var envValuePattern = regexp.MustCompile(`^[\x20-\x7E]*$`)

var blockedInstallEnv = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true,
	"ENV": true, "BASH_ENV": true, "IFS": true, "TMPDIR": true, "TMP": true, "TEMP": true,
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true,
	"PYTHONPATH": true, "PYTHONHOME": true, "PERL5LIB": true, "PERL5OPT": true,
	"RUBYLIB": true, "RUBYOPT": true, "NODE_PATH": true,
	"SSH_AUTH_SOCK": true, "SUDO_ASKPASS": true, "SUDO_EDITOR": true, "SUDO_USER": true,
	"APT_CONFIG": true, "DPKG_MAINTSCRIPT_PACKAGE": true, "DPKG_ROOT": true,
}

func blockedInstallEnvKey(key string) bool {
	if blockedInstallEnv[key] {
		return true
	}
	for _, prefix := range []string{
		"LD_", "SUDO_", "BASH_FUNC_", "GIT_", "GCONV_",
		"PYTHON", "JAVA_", "JDK_", "NODE_", "PERL", "RUBY",
	} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// ValidateInstallEnvironment rejects environment variables that can subvert a
// root package-manager process. It is deliberately a small, reviewable policy.
func ValidateInstallEnvironment(env map[string]string) error {
	if len(env) > 32 {
		return errors.New("at most 32 installer environment variables are allowed")
	}
	for key, value := range env {
		if !envKeyPattern.MatchString(key) {
			return fmt.Errorf("invalid installer environment variable name %q", key)
		}
		if blockedInstallEnvKey(key) {
			return fmt.Errorf("installer environment variable %q is not allowed", key)
		}
		if len(value) > 1024 || !envValuePattern.MatchString(value) {
			return fmt.Errorf("installer environment value for %q must be at most 1024 printable ASCII characters without newlines", key)
		}
	}
	return nil
}

// ValidatePackageFilename accepts a base filename with a supported package
// extension and returns the format identifier.
func ValidatePackageFilename(name string) (string, error) {
	raw := strings.TrimSpace(name)
	if raw == "" || strings.ContainsAny(raw, `/\`) {
		return "", errors.New("invalid package filename")
	}
	base := filepath.Base(raw)
	if base == "" || base == "." || base == ".." {
		return "", errors.New("invalid package filename")
	}
	if len(base) > 200 {
		return "", errors.New("package filename is too long")
	}
	lower := strings.ToLower(base)
	format := ""
	switch {
	case strings.HasSuffix(lower, ".deb"):
		format = "deb"
	case strings.HasSuffix(lower, ".rpm"):
		format = "rpm"
	case strings.HasSuffix(lower, ".pkg.tar.zst"):
		format = "pkg.tar.zst"
	case strings.HasSuffix(lower, ".apk"):
		format = "apk"
	default:
		return "", errors.New("unsupported package extension; use .deb, .rpm, .pkg.tar.zst, or .apk")
	}
	if !packageNamePattern.MatchString(strings.TrimSuffix(base, filepath.Ext(base))) {
		return "", errors.New("package filename contains unsupported characters")
	}
	return format, nil
}

// ValidatePackageHeader checks a small file header against the declared format.
func ValidatePackageHeader(format string, header []byte) error {
	switch format {
	case "deb":
		if len(header) < 8 || string(header[:8]) != "!<arch>\n" {
			return errors.New("file is not a valid Debian package archive")
		}
	case "rpm":
		if len(header) < 4 || header[0] != 0xed || header[1] != 0xab || header[2] != 0xee || header[3] != 0xdb {
			return errors.New("file is not a valid RPM package")
		}
	case "pkg.tar.zst":
		if len(header) < 4 || header[0] != 0x28 || header[1] != 0xb5 || header[2] != 0x2f || header[3] != 0xfd {
			return errors.New("file is not a valid zstd-compressed pacman package")
		}
	case "apk":
		if len(header) < 2 || header[0] != 0x1f || header[1] != 0x8b {
			return errors.New("file is not a valid gzip-compressed apk package")
		}
	default:
		return errors.New("unsupported package format")
	}
	return nil
}

func installPackage(ctx context.Context, in io.Reader, out io.Writer) error {
	limited := io.LimitReader(in, MaxPackageSize*2)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var request InstallPackageRequest
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("decode install-package request: %w", err)
	}
	if len(request.Package) == 0 {
		return errors.New("package data is empty")
	}
	if len(request.Package) > MaxPackageSize {
		return fmt.Errorf("package is larger than the %d MiB limit", MaxPackageSize>>20)
	}
	format, err := ValidatePackageFilename(request.Filename)
	if err != nil {
		return err
	}
	if err := ValidateInstallEnvironment(request.Env); err != nil {
		return err
	}
	if len(request.SHA256) != 64 {
		return errors.New("sha256 must be 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(request.SHA256); err != nil {
		return errors.New("sha256 is not valid hexadecimal")
	}
	header := request.Package
	if len(header) > 8 {
		header = header[:8]
	}
	if err := ValidatePackageHeader(format, header); err != nil {
		return err
	}
	sum := sha256.Sum256(request.Package)
	actual := hex.EncodeToString(sum[:])
	if !strings.EqualFold(actual, request.SHA256) {
		return errors.New("package SHA-256 does not match the request")
	}

	extension := "." + format
	temp, err := os.CreateTemp("", "hibp-package-*"+extension)
	if err != nil {
		return fmt.Errorf("create package temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("secure package temporary file: %w", err)
	}
	if _, err := temp.Write(request.Package); err != nil {
		return fmt.Errorf("write package temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close package temporary file: %w", err)
	}

	result := installPackageFile(ctx, format, tempPath, request)
	result.Package = request.Filename
	result.SHA256 = actual
	if encodeErr := json.NewEncoder(out).Encode(result); encodeErr != nil {
		return encodeErr
	}
	// Package-manager failures are part of the JSON result. Returning nil here
	// keeps the helper's stdout a clean JSON document for the controller.
	return nil
}

func installPackageFile(ctx context.Context, format, path string, request InstallPackageRequest) PackageInstallResult {
	pm := detectPackageManager()
	result := PackageInstallResult{
		Action: "install-package", PackageManager: pm, Package: request.Filename, SHA256: request.SHA256,
	}
	command, args, fixedEnv, err := packageInstallCommand(pm, format, path)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	env := mergeInstallEnv(fixedEnv, request.Env)
	output, code, runErr := packageRunner(ctx, env, command, args...)
	result.Output = string(output)
	result.ExitCode = code
	if runErr != nil {
		result.Error = runErr.Error()
		return result
	}
	result.OK = code == 0
	if !result.OK && result.Error == "" {
		result.Error = fmt.Sprintf("package manager exited with code %d", code)
	}
	return result
}

func packageInstallCommand(packageManager, format, path string) (string, []string, map[string]string, error) {
	switch format {
	case "deb":
		if packageManager != "apt" {
			return "", nil, nil, fmt.Errorf("a .deb package requires apt; target uses %s", packageManager)
		}
		return "apt-get", []string{
			"-y",
			"-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold",
			"install", path,
		}, map[string]string{"DEBIAN_FRONTEND": "noninteractive"}, nil
	case "rpm":
		switch packageManager {
		case "dnf":
			return "dnf", []string{"-y", "--setopt=localpkg_gpgcheck=1", "install", path}, nil, nil
		case "zypper":
			return "zypper", []string{"--non-interactive", "install", path}, nil, nil
		default:
			return "", nil, nil, fmt.Errorf("an .rpm package requires dnf or zypper; target uses %s", packageManager)
		}
	case "pkg.tar.zst":
		if packageManager != "pacman" {
			return "", nil, nil, fmt.Errorf("a .pkg.tar.zst package requires pacman; target uses %s", packageManager)
		}
		return "pacman", []string{"-U", "--noconfirm", path}, nil, nil
	case "apk":
		if packageManager != "apk" {
			return "", nil, nil, fmt.Errorf("an .apk package requires apk; target uses %s", packageManager)
		}
		return "apk", []string{"add", path}, nil, nil
	default:
		return "", nil, nil, errors.New("unsupported package format")
	}
}

func mergeInstallEnv(fixed, user map[string]string) []string {
	values := map[string]string{
		"HOME":   "/root",
		"PATH":   "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL": "C",
		"LANG":   "C",
	}
	for key, value := range fixed {
		values[key] = value
	}
	for key, value := range user {
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}

type packageEnvRunner func(ctx context.Context, env []string, name string, args ...string) ([]byte, int, error)

var packageRunner packageEnvRunner = defaultPackageEnvRunner

// SetPackageRunnerForTest replaces the package-install runner.
func SetPackageRunnerForTest(fn packageEnvRunner) func() {
	old := packageRunner
	packageRunner = fn
	return func() { packageRunner = old }
}

func defaultPackageEnvRunner(ctx context.Context, env []string, name string, args ...string) ([]byte, int, error) {
	path, err := lookPath(name)
	if err != nil {
		return nil, 127, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = "/"
	cmd.Env = env
	var output limitedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err = cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
			err = nil
		} else if errors.Is(err, context.DeadlineExceeded) {
			return output.Bytes(), 124, err
		} else if errors.Is(err, exec.ErrNotFound) {
			return output.Bytes(), 127, err
		} else {
			return output.Bytes(), 1, err
		}
	}
	return output.Bytes(), code, err
}
