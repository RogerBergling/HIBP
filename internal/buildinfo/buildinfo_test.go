package buildinfo

import "testing"

func TestInfoIdentity(t *testing.T) {
	info := Info{
		Version:     "0.6.2",
		BuildNumber: "1234",
		BuildCommit: "abc123def456",
		BuildDate:   "2026-11-11T12:00:00Z",
		BuildTarget: "linux/amd64",
		BuildType:   "release",
	}
	if got, want := info.Compact(), "v0.6.2 · build 1234 · commit abc123def456"; got != want {
		t.Fatalf("Compact() = %q, want %q", got, want)
	}
	if got, want := info.String(), "v0.6.2 · build 1234 · commit abc123def456 · 2026-11-11T12:00:00Z · linux/amd64 · release"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}

func TestVersionLabelDoesNotDoublePrefix(t *testing.T) {
	if got := VersionLabel("v0.6.2"); got != "v0.6.2" {
		t.Fatalf("VersionLabel(v0.6.2) = %q", got)
	}
	if got := VersionLabel("0.6.2"); got != "v0.6.2" {
		t.Fatalf("VersionLabel(0.6.2) = %q", got)
	}
}
