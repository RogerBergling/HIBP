package helper

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseAptPreview(t *testing.T) {
	output := `Reading package lists...
Inst libc6 [2.35-0ubuntu3.8] (2.35-0ubuntu3.9 Ubuntu:24.04/noble [amd64])
Inst newpkg (1.0-1 Debian:12/bookworm [amd64])
Remv oldpkg [0.9-1]
Conf libc6 (2.35-0ubuntu3.9 Ubuntu:24.04/noble [amd64])
`
	changes := parseAptPreview(output)
	if len(changes) != 3 {
		t.Fatalf("expected 3 changes, got %+v", changes)
	}
	if changes[0].Name != "libc6" || changes[0].Action != "upgrade" || changes[0].OldVersion != "2.35-0ubuntu3.8" || changes[0].NewVersion != "2.35-0ubuntu3.9" {
		t.Fatalf("unexpected upgrade: %+v", changes[0])
	}
	if changes[1].Name != "newpkg" || changes[1].Action != "install" || changes[1].NewVersion != "1.0-1" {
		t.Fatalf("unexpected install: %+v", changes[1])
	}
	if changes[2].Name != "oldpkg" || changes[2].Action != "remove" || changes[2].OldVersion != "0.9-1" {
		t.Fatalf("unexpected remove: %+v", changes[2])
	}
	counts := packageActionCounts(changes)
	if counts["upgrade"] != 1 || counts["install"] != 1 || counts["remove"] != 1 {
		t.Fatalf("unexpected counts: %+v", counts)
	}
}

func TestParseDNFPreview(t *testing.T) {
	output := `Dependencies resolved.
================================================================================
 Package          Arch   Version       Repository  Size
================================================================================
Upgrading:
 foo              x86_64 1.2-1.el9     baseos      1.2 M
Installing dependencies:
 bar              noarch 2.0-1.el9     appstream   10 k
Removing:
 baz              x86_64 0.9-1.el9     @System     1.0 M

Transaction Summary
================================================================================
Upgrade  1 Package
Install  1 Package
Remove   1 Package
Operation aborted.
`
	changes := parseDNFPreview(output, map[string]string{
		"foo": "1.1-1.el9",
		"baz": "0.9-1.el9",
	})
	if len(changes) != 3 {
		t.Fatalf("expected 3 changes, got %+v", changes)
	}
	if changes[0].Name != "foo" || changes[0].Action != "upgrade" || changes[0].OldVersion != "1.1-1.el9" || changes[0].NewVersion != "1.2-1.el9" {
		t.Fatalf("unexpected upgrade: %+v", changes[0])
	}
	if changes[1].Name != "bar" || changes[1].Action != "install" || changes[1].NewVersion != "2.0-1.el9" {
		t.Fatalf("unexpected install: %+v", changes[1])
	}
	if changes[2].Name != "baz" || changes[2].Action != "remove" || changes[2].OldVersion != "0.9-1.el9" {
		t.Fatalf("unexpected remove: %+v", changes[2])
	}
}

func TestParseZypperPreview(t *testing.T) {
	output := `Loading repository data...
Reading installed packages...
The following 2 packages are going to be upgraded:
  foo  1.0-1 -> 1.1-1
  bar  2.0-1 -> 2.1-1
The following package is going to be installed:
  baz  3.0-1
The following package is going to be REMOVED:
  old  0.9-1
`
	changes := parseZypperPreview(output)
	if len(changes) != 4 {
		t.Fatalf("expected 4 changes, got %+v", changes)
	}
	if changes[0].Name != "foo" || changes[0].Action != "upgrade" || changes[0].OldVersion != "1.0-1" || changes[0].NewVersion != "1.1-1" {
		t.Fatalf("unexpected upgrade: %+v", changes[0])
	}
	if changes[2].Name != "baz" || changes[2].Action != "install" || changes[2].NewVersion != "3.0-1" {
		t.Fatalf("unexpected install: %+v", changes[2])
	}
	if changes[3].Name != "old" || changes[3].Action != "remove" || changes[3].OldVersion != "0.9-1" {
		t.Fatalf("unexpected remove: %+v", changes[3])
	}
}

func TestParsePacmanPreview(t *testing.T) {
	output := `foo 1.0-1 -> 1.1-1
bar 2.0-1 -> 2.1-1
foo 1.1-1
bar 2.1-1
baz 3.0-1
`
	changes := parsePacmanPreview(output)
	if len(changes) != 3 {
		t.Fatalf("expected 3 changes, got %+v", changes)
	}
	if changes[0].Name != "foo" || changes[0].Action != "upgrade" || changes[0].OldVersion != "1.0-1" || changes[0].NewVersion != "1.1-1" {
		t.Fatalf("unexpected upgrade: %+v", changes[0])
	}
	if changes[2].Name != "baz" || changes[2].Action != "install" || changes[2].NewVersion != "3.0-1" {
		t.Fatalf("unexpected install: %+v", changes[2])
	}
}

func TestParseAPKPreview(t *testing.T) {
	output := `(1/3) Upgrading foo (1.0-r0 -> 1.1-r0)
(2/3) Installing bar (2.0-r0)
(3/3) Purging baz (0.9-r0)
`
	changes := parseAPKPreview(output)
	if len(changes) != 3 {
		t.Fatalf("expected 3 changes, got %+v", changes)
	}
	if changes[0].Name != "foo" || changes[0].Action != "upgrade" || changes[0].OldVersion != "1.0-r0" || changes[0].NewVersion != "1.1-r0" {
		t.Fatalf("unexpected upgrade: %+v", changes[0])
	}
	if changes[1].Name != "bar" || changes[1].Action != "install" || changes[1].NewVersion != "2.0-r0" {
		t.Fatalf("unexpected install: %+v", changes[1])
	}
	if changes[2].Name != "baz" || changes[2].Action != "remove" || changes[2].OldVersion != "0.9-r0" {
		t.Fatalf("unexpected remove: %+v", changes[2])
	}
}

func TestPreviewExitOK(t *testing.T) {
	if !previewExitOK("dnf", 1, "Transaction Summary\nOperation aborted.") {
		t.Fatal("expected an aborted DNF preview to count as a successful dry run")
	}
	if previewExitOK("dnf", 1, "Error: repo failed") {
		t.Fatal("expected a DNF failure to be rejected")
	}
	if !previewExitOK("apt", 0, "") || previewExitOK("apt", 100, "") {
		t.Fatal("unexpected apt exit handling")
	}
}

func TestPreviewUpdatesWiresAPTAction(t *testing.T) {
	oldLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "apt-get" {
			return "/usr/bin/apt-get", nil
		}
		return "", ErrNotFoundForTest
	})
	defer oldLook()
	oldRunner := SetRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		if name != "/usr/bin/apt-get" {
			t.Fatalf("unexpected command: %s", name)
		}
		if len(args) > 0 && args[0] == "update" {
			return []byte("Reading package lists...\n"), 0, nil
		}
		return []byte("Inst libc6 [2.35-0ubuntu3.8] (2.35-0ubuntu3.9 Ubuntu:24.04/noble [amd64])\nRemv oldpkg [0.9-1]\n"), 0, nil
	})
	defer oldRunner()
	result := previewUpdates(context.Background())
	if !result.OK || result.PackageManager != "apt" || len(result.Packages) != 2 {
		t.Fatalf("unexpected preview: %+v", result)
	}
	if result.Counts["upgrade"] != 1 || result.Counts["remove"] != 1 {
		t.Fatalf("unexpected counts: %+v", result.Counts)
	}
}

func TestPreviewUpdatesFullUsesFullUpgrade(t *testing.T) {
	oldLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "apt-get" {
			return "/usr/bin/apt-get", nil
		}
		return "", ErrNotFoundForTest
	})
	defer oldLook()
	oldRunner := SetRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, int, error) {
		if name != "/usr/bin/apt-get" {
			t.Fatalf("unexpected command: %s", name)
		}
		if len(args) > 0 && args[0] == "update" {
			return []byte("Reading package lists...\n"), 0, nil
		}
		if len(args) != 2 || args[0] != "-s" || args[1] != "full-upgrade" {
			t.Fatalf("expected apt-get -s full-upgrade, got %v", args)
		}
		return []byte("Inst libc6 [2.35-0ubuntu3.8] (2.35-0ubuntu3.9 Ubuntu:24.04/noble [amd64])\nRemv oldpkg [0.9-1]\n"), 0, nil
	})
	defer oldRunner()
	result := previewUpdatesWithMode(context.Background(), true)
	if !result.OK || result.Action != "preview-full" || result.PackageManager != "apt" || len(result.Packages) != 2 {
		t.Fatalf("unexpected full preview: %+v", result)
	}
	if aptUpgradeActionForMode(true) != "full-upgrade" {
		t.Fatal("full mode did not select apt-get full-upgrade")
	}
}

func TestFullUpgradeWiringForCheckAndApply(t *testing.T) {
	oldLook := SetLookPathForTest(func(name string) (string, error) {
		if name == "apt-get" {
			return "/usr/bin/apt-get", nil
		}
		return "", ErrNotFoundForTest
	})
	defer oldLook()
	var calls [][]string
	oldRunner := SetRunnerForTest(func(_ context.Context, _ string, args ...string) ([]byte, int, error) {
		calls = append(calls, append([]string(nil), args...))
		return []byte("Inst curl [1.0] (1.1)\n"), 0, nil
	})
	defer oldRunner()

	if _, _, err := checkUpdatesWithMode(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || strings.Join(calls[1], " ") != "-s full-upgrade" {
		t.Fatalf("unexpected check calls: %v", calls)
	}
	calls = nil
	if _, _, err := applyUpdatesWithMode(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[1][0] != "-y" || calls[1][len(calls[1])-1] != "full-upgrade" {
		t.Fatalf("unexpected apply calls: %v", calls)
	}
}

var ErrNotFoundForTest = errors.New("not found")
