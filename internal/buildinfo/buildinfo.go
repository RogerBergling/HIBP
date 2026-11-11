// Package buildinfo describes the running HIBP controller and helper build.
package buildinfo

import "strings"

// Info is the build identity injected at link time with -ldflags.
type Info struct {
	Version     string `json:"version"`
	BuildNumber string `json:"build_number"`
	BuildCommit string `json:"build_commit"`
	BuildDate   string `json:"build_date"`
	BuildTarget string `json:"build_target"`
	BuildType   string `json:"build_type"`
}

// Current is set by cmd/hibp from the linker values. The helper and server use
// the same value, which lets the controller show the build installed on each
// target.
var Current = Info{
	Version:     "0.1.0-dev",
	BuildNumber: "dev",
	BuildCommit: "unknown",
	BuildDate:   "unknown",
	BuildTarget: "unknown",
	BuildType:   "unknown",
}

// VersionLabel returns the version with a single leading "v".
func VersionLabel(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return ""
	}
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}

// Compact returns the version, build number, and commit.
func (i Info) Compact() string {
	parts := make([]string, 0, 3)
	if label := VersionLabel(i.Version); label != "" {
		parts = append(parts, label)
	}
	if i.BuildNumber != "" {
		parts = append(parts, "build "+i.BuildNumber)
	}
	if i.BuildCommit != "" {
		parts = append(parts, "commit "+i.BuildCommit)
	}
	return strings.Join(parts, " · ")
}

// String returns the full build identity.
func (i Info) String() string {
	parts := make([]string, 0, 6)
	if label := VersionLabel(i.Version); label != "" {
		parts = append(parts, label)
	}
	if i.BuildNumber != "" {
		parts = append(parts, "build "+i.BuildNumber)
	}
	if i.BuildCommit != "" {
		parts = append(parts, "commit "+i.BuildCommit)
	}
	if i.BuildDate != "" {
		parts = append(parts, i.BuildDate)
	}
	if i.BuildTarget != "" {
		parts = append(parts, i.BuildTarget)
	}
	if i.BuildType != "" {
		parts = append(parts, i.BuildType)
	}
	return strings.Join(parts, " · ")
}
