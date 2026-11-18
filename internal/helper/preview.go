package helper

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// PackageChange is one package action in a dry-run transaction.
type PackageChange struct {
	Name         string `json:"name"`
	Action       string `json:"action"` // upgrade, install, remove, downgrade, reinstall
	OldVersion   string `json:"old_version,omitempty"`
	NewVersion   string `json:"new_version,omitempty"`
	Repository   string `json:"repository,omitempty"`
	Architecture string `json:"architecture,omitempty"`
}

// PreviewResult is the JSON contract for the preview action. It is read-only:
// it resolves the package manager transaction but does not apply it.
type PreviewResult struct {
	Action         string          `json:"action"`
	OK             bool            `json:"ok"`
	PackageManager string          `json:"package_manager"`
	Packages       []PackageChange `json:"packages"`
	Counts         map[string]int  `json:"counts"`
	RebootRequired bool            `json:"reboot_required"`
	ExitCode       int             `json:"exit_code"`
	Output         string          `json:"output"`
	Warnings       []string        `json:"warnings,omitempty"`
	Error          string          `json:"error,omitempty"`
}

func previewUpdates(ctx context.Context) PreviewResult {
	packageManager := detectPackageManager()
	result := PreviewResult{
		Action:         "preview",
		PackageManager: packageManager,
		Packages:       []PackageChange{},
		Counts:         map[string]int{},
	}
	var (
		changes  []PackageChange
		output   string
		code     int
		warnings []string
		err      error
	)
	switch packageManager {
	case "apt":
		changes, output, code, warnings, err = previewApt(ctx)
	case "dnf":
		changes, output, code, warnings, err = previewDNF(ctx)
	case "zypper":
		changes, output, code, warnings, err = previewZypper(ctx)
	case "pacman":
		changes, output, code, warnings, err = previewPacman(ctx)
	case "apk":
		changes, output, code, warnings, err = previewAPK(ctx)
	default:
		err = fmt.Errorf("unsupported package manager %q", packageManager)
	}
	if changes != nil {
		result.Packages = changes
	}
	result.Counts = packageActionCounts(result.Packages)
	result.Output = output
	result.ExitCode = code
	result.Warnings = warnings
	result.RebootRequired, _ = rebootRequired(ctx)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.OK = previewExitOK(packageManager, code, output)
	if !result.OK && result.Error == "" {
		result.Error = fmt.Sprintf("package manager exited with code %d", code)
	}
	return result
}

func packageActionCounts(changes []PackageChange) map[string]int {
	counts := map[string]int{
		"upgrade": 0, "install": 0, "remove": 0, "downgrade": 0, "reinstall": 0,
	}
	for _, change := range changes {
		if _, ok := counts[change.Action]; ok {
			counts[change.Action]++
		}
	}
	return counts
}

func previewExitOK(packageManager string, code int, output string) bool {
	switch packageManager {
	case "apt", "zypper", "apk":
		return code == 0
	case "dnf":
		if code == 0 {
			return true
		}
		lower := strings.ToLower(output)
		return code == 1 && (strings.Contains(lower, "operation aborted") ||
			strings.Contains(lower, "nothing to do") ||
			strings.Contains(lower, "transaction summary"))
	case "pacman":
		return code == 0 || code == 1
	default:
		return false
	}
}

var (
	aptInstPattern = regexp.MustCompile(`^Inst\s+(\S+)(?:\s+\[([^\]]+)\])?\s+\(([^)\s]+)(?:\s+([^)]*))?\)`)
	aptRemvPattern = regexp.MustCompile(`^Remv\s+(\S+)(?:\s+\[([^\]]+)\])?`)
)

func previewApt(ctx context.Context) ([]PackageChange, string, int, []string, error) {
	updateOutput, _, _ := runBinary(ctx, "apt-get", "update")
	output, code, err := runBinary(ctx, "apt-get", "-s", aptUpgradeAction())
	var combined strings.Builder
	if len(updateOutput) > 0 {
		combined.Write(updateOutput)
		if updateOutput[len(updateOutput)-1] != '\n' {
			combined.WriteByte('\n')
		}
	}
	combined.Write(output)
	text := combined.String()
	return parseAptPreview(text), text, code, nil, err
}

func parseAptPreview(output string) []PackageChange {
	var changes []PackageChange
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Inst ") {
			match := aptInstPattern.FindStringSubmatch(line)
			if len(match) == 0 {
				continue
			}
			change := PackageChange{Name: match[1], Action: "install", NewVersion: match[3]}
			if match[2] != "" {
				change.Action = "upgrade"
				change.OldVersion = match[2]
			}
			if len(match) > 4 {
				change.Repository, change.Architecture = parseAptRepoArch(match[4])
			}
			changes = appendUniqueChange(changes, change)
			continue
		}
		if strings.HasPrefix(line, "Remv ") {
			match := aptRemvPattern.FindStringSubmatch(line)
			if len(match) == 0 {
				continue
			}
			changes = appendUniqueChange(changes, PackageChange{
				Name: match[1], Action: "remove", OldVersion: match[2],
			})
		}
	}
	return changes
}

func parseAptRepoArch(value string) (string, string) {
	value = strings.TrimSpace(value)
	architecture := ""
	if open := strings.LastIndex(value, "["); open >= 0 && strings.HasSuffix(value, "]") {
		architecture = strings.TrimSpace(value[open+1 : len(value)-1])
		value = strings.TrimSpace(value[:open])
	}
	return strings.TrimSpace(value), architecture
}

func previewDNF(ctx context.Context) ([]PackageChange, string, int, []string, error) {
	installed, installedErr := dnfInstalledVersions(ctx)
	output, code, err := runBinary(ctx, "dnf", "-q", "--refresh", "--assumeno", "--color=never", "upgrade")
	changes := parseDNFPreview(string(output), installed)
	var warnings []string
	if installedErr != nil {
		warnings = append(warnings, "Could not read installed package versions; upgrade source versions may be blank.")
	}
	if len(changes) == 0 && strings.Contains(strings.ToLower(string(output)), "upgrad") {
		warnings = append(warnings, "The DNF transaction output could not be parsed into package rows; review the raw output.")
	}
	return changes, string(output), code, warnings, err
}

func dnfInstalledVersions(ctx context.Context) (map[string]string, error) {
	output, code, err := runBinary(ctx, "dnf", "-q", "repoquery", "--installed", "--qf", "%{name} %{version}-%{release}")
	if err != nil || code != 0 {
		return map[string]string{}, err
	}
	versions := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && safePackageName(fields[0]) {
			versions[fields[0]] = fields[1]
		}
	}
	return versions, nil
}

func parseDNFPreview(output string, installed map[string]string) []PackageChange {
	var changes []PackageChange
	action := ""
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		switch {
		case strings.Contains(lower, "upgrading:"):
			action = "upgrade"
			continue
		case strings.Contains(lower, "installing:"):
			action = "install"
			continue
		case strings.Contains(lower, "installing dependencies:"):
			action = "install"
			continue
		case strings.Contains(lower, "removing:"):
			action = "remove"
			continue
		case strings.Contains(lower, "removing dependent packages:"):
			action = "remove"
			continue
		case strings.Contains(lower, "downgrading:"):
			action = "downgrade"
			continue
		case strings.Contains(lower, "reinstalling:"):
			action = "reinstall"
			continue
		case strings.HasPrefix(lower, "transaction summary"):
			action = ""
			continue
		}
		if action == "" || strings.HasPrefix(lower, "package ") ||
			strings.HasPrefix(lower, "=====") || strings.HasPrefix(lower, "size ") ||
			strings.HasPrefix(lower, "state ") || strings.HasPrefix(lower, "replacing ") ||
			strings.HasPrefix(lower, "obsoleting ") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 {
			continue
		}
		name := fields[0]
		architecture := fields[1]
		if dot := strings.LastIndex(name, "."); dot > 0 && isRPMArch(name[dot+1:]) {
			architecture = name[dot+1:]
			name = name[:dot]
		}
		version := fields[2]
		repository := ""
		if len(fields) > 3 {
			repository = fields[3]
		}
		if !safePackageName(name) {
			continue
		}
		change := PackageChange{
			Name: name, Action: action, NewVersion: version,
			Architecture: architecture, Repository: repository,
		}
		if old := installed[name]; old != "" {
			change.OldVersion = old
		}
		if action == "remove" {
			change.NewVersion = ""
			if change.OldVersion == "" {
				change.OldVersion = version
			}
		}
		changes = appendUniqueChange(changes, change)
	}
	return changes
}

func previewZypper(ctx context.Context) ([]PackageChange, string, int, []string, error) {
	output, code, err := runBinary(ctx, "zypper", "-q", "--non-interactive", "--no-refresh", "--dry-run", "update")
	changes := parseZypperPreview(string(output))
	var warnings []string
	if len(changes) == 0 && strings.Contains(strings.ToLower(string(output)), "going to be") {
		warnings = append(warnings, "The zypper transaction output could not be parsed into package rows; review the raw output.")
	}
	return changes, string(output), code, warnings, err
}

func parseZypperPreview(output string) []PackageChange {
	var changes []PackageChange
	action := ""
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			action = ""
			continue
		}
		lower := strings.ToLower(trimmed)
		switch {
		case strings.Contains(lower, "going to be upgraded"):
			action = "upgrade"
			continue
		case strings.Contains(lower, "going to be installed"):
			action = "install"
			continue
		case strings.Contains(lower, "going to be removed"):
			action = "remove"
			continue
		case strings.Contains(lower, "going to be downgraded"):
			action = "downgrade"
			continue
		case strings.Contains(lower, "going to be reinstalled"):
			action = "reinstall"
			continue
		}
		if action == "" || strings.HasPrefix(lower, "the following") ||
			strings.HasPrefix(lower, "loading repository") ||
			strings.HasPrefix(lower, "reading installed") ||
			strings.HasPrefix(lower, "no updates") {
			continue
		}
		change, ok := parseZypperPackageLine(trimmed, action)
		if ok {
			changes = appendUniqueChange(changes, change)
		}
	}
	return changes
}

func parseZypperPackageLine(line, action string) (PackageChange, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return PackageChange{}, false
	}
	name := fields[0]
	if !safePackageName(name) {
		return PackageChange{}, false
	}
	change := PackageChange{Name: name, Action: action}
	if strings.Contains(line, "->") {
		parts := strings.SplitN(line, "->", 2)
		left := strings.Fields(parts[0])
		right := strings.Fields(parts[1])
		if len(left) > 0 {
			change.OldVersion = left[len(left)-1]
		}
		if len(right) > 0 {
			change.NewVersion = right[0]
		}
	} else if strings.Contains(line, "|") {
		fields = strings.Split(line, "|")
		if len(fields) >= 2 {
			change.Name = strings.TrimSpace(fields[0])
			versions := strings.Fields(strings.TrimSpace(fields[1]))
			if len(versions) > 0 {
				change.NewVersion = versions[0]
			}
		}
		if len(fields) >= 3 {
			versions := strings.Fields(strings.TrimSpace(fields[2]))
			if len(versions) > 0 {
				change.NewVersion = versions[0]
			}
		}
	} else if len(fields) > 1 {
		change.NewVersion = fields[1]
	}
	if change.NewVersion == "" && len(fields) > 1 {
		change.NewVersion = fields[1]
	}
	if action == "remove" {
		change.NewVersion = ""
		if change.OldVersion == "" && len(fields) > 1 {
			change.OldVersion = fields[len(fields)-1]
		}
	}
	return change, true
}

func previewPacman(ctx context.Context) ([]PackageChange, string, int, []string, error) {
	updatesOutput, _, _ := runBinary(ctx, "pacman", "-Qu")
	targetsOutput, code, err := runBinary(ctx, "pacman", "-Syu", "--print", "--print-format", "%n %v")
	var combined strings.Builder
	if len(updatesOutput) > 0 {
		combined.Write(updatesOutput)
		if updatesOutput[len(updatesOutput)-1] != '\n' {
			combined.WriteByte('\n')
		}
	}
	combined.Write(targetsOutput)
	text := combined.String()
	changes := parsePacmanPreview(text)
	warnings := []string{"Pacman dry-run does not expose every transaction removal; review the raw output before applying."}
	return changes, text, code, warnings, err
}

func parsePacmanPreview(output string) []PackageChange {
	installed := map[string]PackageChange{}
	var targets []string
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "::") ||
			strings.HasPrefix(trimmed, "warning:") || strings.HasPrefix(trimmed, "error:") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 3 || !strings.Contains(trimmed, "->") {
			if len(fields) == 2 && safePackageName(fields[0]) {
				targets = append(targets, fields[0]+"\x00"+fields[1])
			}
			continue
		}
		arrow := -1
		for i, field := range fields {
			if field == "->" {
				arrow = i
				break
			}
		}
		if arrow <= 0 || arrow+1 >= len(fields) || !safePackageName(fields[0]) {
			continue
		}
		installed[fields[0]] = PackageChange{
			Name: fields[0], OldVersion: fields[arrow-1], NewVersion: fields[arrow+1],
		}
	}
	var changes []PackageChange
	for _, entry := range targets {
		parts := strings.SplitN(entry, "\x00", 2)
		if len(parts) != 2 {
			continue
		}
		name, version := parts[0], parts[1]
		if old, ok := installed[name]; ok {
			changes = appendUniqueChange(changes, PackageChange{
				Name: name, Action: "upgrade", OldVersion: old.OldVersion, NewVersion: version,
			})
		} else {
			changes = appendUniqueChange(changes, PackageChange{
				Name: name, Action: "install", NewVersion: version,
			})
		}
	}
	return changes
}

var apkPreviewPattern = regexp.MustCompile(`\(\d+/\d+\)\s+(Upgrading|Installing|Purging|Removing|Downgrading|Reinstalling)\s+(\S+)\s+\(([^)]*)\)`)

func previewAPK(ctx context.Context) ([]PackageChange, string, int, []string, error) {
	output, code, err := runBinary(ctx, "apk", "upgrade", "--simulate")
	changes := parseAPKPreview(string(output))
	var warnings []string
	if len(changes) == 0 && strings.Contains(strings.ToLower(string(output)), "upgrading") {
		warnings = append(warnings, "The apk transaction output could not be parsed into package rows; review the raw output.")
	}
	return changes, string(output), code, warnings, err
}

func parseAPKPreview(output string) []PackageChange {
	var changes []PackageChange
	for _, match := range apkPreviewPattern.FindAllStringSubmatch(output, -1) {
		action := strings.ToLower(match[1])
		switch action {
		case "upgrading":
			action = "upgrade"
		case "installing":
			action = "install"
		case "purging", "removing":
			action = "remove"
		case "downgrading":
			action = "downgrade"
		case "reinstalling":
			action = "reinstall"
		}
		change := PackageChange{Name: match[2], Action: action}
		version := strings.TrimSpace(match[3])
		if strings.Contains(version, "->") {
			parts := strings.SplitN(version, "->", 2)
			change.OldVersion = strings.TrimSpace(parts[0])
			change.NewVersion = strings.TrimSpace(parts[1])
		} else {
			change.NewVersion = version
		}
		if action == "remove" {
			change.OldVersion = change.NewVersion
			change.NewVersion = ""
		}
		changes = appendUniqueChange(changes, change)
	}
	return changes
}

func appendUniqueChange(changes []PackageChange, value PackageChange) []PackageChange {
	for _, existing := range changes {
		if existing.Name == value.Name && existing.Action == value.Action {
			return changes
		}
	}
	return append(changes, value)
}
