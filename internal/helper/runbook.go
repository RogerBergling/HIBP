package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

var (
	runbookUnitPattern    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9@_.:-]{0,127}$`)
	runbookPackagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._:-]{0,127}$`)
)

type RunbookRequest struct {
	Unit     string   `json:"unit,omitempty"`
	Packages []string `json:"packages,omitempty"`
}

func readRunbookRequest() (RunbookRequest, error) {
	var request RunbookRequest
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 64<<10))
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
	return request, nil
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
