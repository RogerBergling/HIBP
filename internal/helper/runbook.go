package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	runbookUnitPattern    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9@_.:-]{0,127}$`)
	runbookPackagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:-]{0,127}$`)

	runbookCheckmkHostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)
	runbookCheckmkSitePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	runbookCheckmkUserPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}$`)
)

// CheckmkRegisterRequest is the typed input for the checkmk-register action.
// The password is sent only in the helper request and is never persisted in a
// controller job payload.
type CheckmkRegisterRequest struct {
	Hostname string `json:"hostname,omitempty"`
	Server   string `json:"server"`
	Site     string `json:"site"`
	User     string `json:"user"`
	Password string `json:"password"`
}

type RunbookRequest struct {
	Unit     string                  `json:"unit,omitempty"`
	Packages []string                `json:"packages,omitempty"`
	Checkmk  *CheckmkRegisterRequest `json:"checkmk,omitempty"`
}

func readRunbookRequest() (RunbookRequest, error) {
	return readRunbookRequestFrom(os.Stdin)
}

func readRunbookRequestFrom(reader io.Reader) (RunbookRequest, error) {
	var request RunbookRequest
	decoder := json.NewDecoder(io.LimitReader(reader, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return RunbookRequest{}, fmt.Errorf("invalid runbook request: %w", err)
	}
	request.Unit = strings.TrimSpace(request.Unit)
	cleaned := make([]string, 0, len(request.Packages))
	for _, pkg := range request.Packages {
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			continue
		}
		if !runbookPackagePattern.MatchString(pkg) {
			return RunbookRequest{}, fmt.Errorf("invalid package name %q", pkg)
		}
		cleaned = append(cleaned, pkg)
	}
	request.Packages = cleaned
	if request.Unit != "" && !runbookUnitPattern.MatchString(request.Unit) {
		return RunbookRequest{}, fmt.Errorf("invalid systemd unit %q", request.Unit)
	}
	if request.Checkmk != nil {
		normalized, err := normalizeCheckmkRegister(*request.Checkmk)
		if err != nil {
			return RunbookRequest{}, err
		}
		request.Checkmk = &normalized
	}
	return request, nil
}

func normalizeCheckmkRegister(request CheckmkRegisterRequest) (CheckmkRegisterRequest, error) {
	request.Hostname = strings.TrimSpace(request.Hostname)
	request.Server = strings.TrimSpace(request.Server)
	request.Site = strings.TrimSpace(request.Site)
	request.User = strings.TrimSpace(request.User)

	if request.Hostname == "" || request.Hostname == "%HOSTNAME" || request.Hostname == "$HOSTNAME" {
		hostname, err := os.Hostname()
		if err != nil {
			return CheckmkRegisterRequest{}, fmt.Errorf("resolve target hostname: %w", err)
		}
		request.Hostname = strings.TrimSpace(hostname)
	}
	request.Hostname = strings.TrimSuffix(request.Hostname, ".")
	if !runbookCheckmkHostPattern.MatchString(request.Hostname) {
		return CheckmkRegisterRequest{}, fmt.Errorf("invalid Checkmk hostname %q", request.Hostname)
	}
	if err := validateCheckmkServer(request.Server); err != nil {
		return CheckmkRegisterRequest{}, err
	}
	if !runbookCheckmkSitePattern.MatchString(request.Site) {
		return CheckmkRegisterRequest{}, fmt.Errorf("invalid Checkmk site %q", request.Site)
	}
	if !runbookCheckmkUserPattern.MatchString(request.User) {
		return CheckmkRegisterRequest{}, fmt.Errorf("invalid Checkmk user %q", request.User)
	}
	if !validCheckmkPassword(request.Password) {
		return CheckmkRegisterRequest{}, errors.New("invalid Checkmk password")
	}
	return request, nil
}

func validateCheckmkServer(value string) error {
	host, port, hasPort := strings.Cut(strings.TrimSpace(value), ":")
	if strings.Contains(port, ":") || !runbookCheckmkHostPattern.MatchString(host) {
		return fmt.Errorf("invalid Checkmk server %q", value)
	}
	if !hasPort {
		return nil
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("invalid Checkmk server port in %q", value)
	}
	return nil
}

func validCheckmkPassword(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func serviceRunbook(ctx context.Context, action string) (Result, error) {
	request, err := readRunbookRequest()
	if err != nil {
		return Result{Action: action, Error: err.Error()}, err
	}
	if request.Unit == "" {
		return Result{Action: action, Error: "unit is required"}, errors.New("unit is required")
	}
	output, code, err := runBinary(ctx, "systemctl", action, request.Unit)
	if err != nil {
		return Result{Action: action, ExitCode: code, Output: strings.TrimSpace(string(output)), Error: err.Error()}, nil
	}
	return Result{Action: action, OK: code == 0, ExitCode: code, Output: strings.TrimSpace(string(output))}, nil
}

const checkmkRegisterDisplayAction = "cmk-agent-ctl register"

func checkmkRegisterRunbook(ctx context.Context) (Result, error) {
	request, err := readRunbookRequest()
	if err != nil {
		return Result{Action: checkmkRegisterDisplayAction, Error: err.Error()}, err
	}
	if request.Checkmk == nil {
		err := errors.New("checkmk settings are required")
		return Result{Action: checkmkRegisterDisplayAction, Error: err.Error()}, err
	}
	return runCheckmkRegister(ctx, *request.Checkmk), nil
}

func runCheckmkRegister(ctx context.Context, request CheckmkRegisterRequest) Result {
	normalized, err := normalizeCheckmkRegister(request)
	if err != nil {
		return Result{Action: checkmkRegisterDisplayAction, Error: err.Error()}
	}
	command := "cmk-agent-ctl register" +
		" --hostname " + normalized.Hostname +
		" --server " + normalized.Server +
		" --site " + normalized.Site +
		" --user " + normalized.User +
		" --password ********"
	path, err := lookPath("cmk-agent-ctl")
	if err != nil {
		return Result{
			Action: checkmkRegisterDisplayAction, Command: command, ExitCode: 127,
			Error: "cmk-agent-ctl is not installed on the target",
		}
	}

	// Answer the certificate confirmation from stdin. Passing stdin to the
	// child means the answer is consumed when cmk-agent-ctl reaches its prompt,
	// after the registration request has started.
	output, code, runErr := commandInputRunner(ctx, path, "y\n",
		"register",
		"--hostname", normalized.Hostname,
		"--server", normalized.Server,
		"--site", normalized.Site,
		"--user", normalized.User,
		"--password", normalized.Password,
	)
	result := Result{
		Action: checkmkRegisterDisplayAction, Command: command, ExitCode: code,
		Output: redactRunbookSecret(strings.TrimSpace(string(output)), normalized.Password),
	}
	if runErr != nil {
		result.Error = redactRunbookSecret(runErr.Error(), normalized.Password)
		return result
	}
	result.OK = code == 0
	if !result.OK {
		result.Error = fmt.Sprintf("cmk-agent-ctl exited with code %d", code)
	}
	return result
}

func redactRunbookSecret(value, secret string) string {
	if secret == "" {
		return value
	}
	return strings.ReplaceAll(value, secret, "[redacted]")
}

func packageRunbook(ctx context.Context, operation, phase string) (Result, error) {
	request, err := readRunbookRequest()
	if err != nil {
		return Result{Action: operation + " " + phase, Error: err.Error()}, err
	}
	if len(request.Packages) == 0 {
		return Result{Action: operation + " " + phase, Error: "at least one package is required"}, errors.New("at least one package is required")
	}
	manager := detectPackageManager()
	path, args, ok := packageRunbookCommand(manager, operation, phase, request.Packages)
	action := operation + " " + phase
	if !ok {
		return Result{Action: action, Error: "unsupported package manager: " + manager}, nil
	}
	output, code, err := runBinary(ctx, path, args...)
	result := Result{Action: action, ExitCode: code, Output: strings.TrimSpace(string(output))}
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}
	result.OK = code == 0
	if phase == "preview" && code != 0 && manager != "apt" && manager != "zypper" && manager != "pacman" && manager != "apk" {
		// dnf --assumeno returns non-zero after printing the transaction.
		result.OK = true
		result.Error = ""
	}
	return result, nil
}

func packageRunbookCommand(manager, operation, phase string, packages []string) (string, []string, bool) {
	switch manager {
	case "apt":
		if phase == "preview" {
			args := []string{"-s", operation}
			args = append(args, packages...)
			return "apt-get", args, true
		}
		args := []string{operation, "-y"}
		args = append(args, packages...)
		return "apt-get", args, true
	case "dnf":
		if phase == "preview" {
			args := []string{operation, "--assumeno"}
			args = append(args, packages...)
			return "dnf", args, true
		}
		args := []string{operation, "-y"}
		args = append(args, packages...)
		return "dnf", args, true
	case "zypper":
		args := []string{"--non-interactive"}
		if phase == "preview" {
			args = append(args, "--dry-run")
		}
		args = append(args, operation)
		args = append(args, packages...)
		return "zypper", args, true
	case "pacman":
		if operation == "remove" {
			if phase == "preview" {
				args := []string{"-Rns", "--print"}
				args = append(args, packages...)
				return "pacman", args, true
			}
			args := []string{"-Rns", "--noconfirm"}
			args = append(args, packages...)
			return "pacman", args, true
		}
		if phase == "preview" {
			args := []string{"-S", "--print"}
			args = append(args, packages...)
			return "pacman", args, true
		}
		args := []string{"-S", "--noconfirm"}
		args = append(args, packages...)
		return "pacman", args, true
	case "apk":
		if operation == "remove" {
			if phase == "preview" {
				args := []string{"del", "--simulate"}
				args = append(args, packages...)
				return "apk", args, true
			}
			args := []string{"del"}
			args = append(args, packages...)
			return "apk", args, true
		}
		if phase == "preview" {
			args := []string{"add", "--simulate"}
			args = append(args, packages...)
			return "apk", args, true
		}
		args := []string{"add"}
		args = append(args, packages...)
		return "apk", args, true
	default:
		return "", nil, false
	}
}

func writeRunbookResult(out io.Writer, result Result, err error) error {
	if err != nil {
		result.OK = false
		result.Error = err.Error()
	}
	return json.NewEncoder(out).Encode(result)
}
