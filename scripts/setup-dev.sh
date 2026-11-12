#!/bin/sh
# One-command development bootstrap for HIBP.
#
# - Uses Go from PATH when it is available.
# - Otherwise downloads Go into $GO_DIR (default: $HOME/.local) and uses it.
# - Checks for a C compiler and make.
# - Runs `make build`.
#
# This is for contributors building from source. End users should install a
# prebuilt release with scripts/install.sh instead.

set -eu

GO_VERSION="${GO_VERSION:-1.27.4}"
GO_DIR="${GO_DIR:-$HOME/.local}"
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

usage() {
    cat <<'EOF'
Bootstrap a HIBP development build.

Environment:
  GO_VERSION  Go version to download when Go is missing (default: 1.27.4)
  GO_DIR      Directory used for a local Go install (default: $HOME/.local)

The script runs `make build` at the end.
EOF
}

case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    "") ;;
    *) echo "error: unknown option: $1" >&2; usage >&2; exit 2 ;;
esac

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required command not found: $1" >&2
        exit 1
    fi
}

need curl
need tar

case "$(uname -s)" in
    Linux) ;;
    *) echo "error: this bootstrap supports Linux only" >&2; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "error: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

if command -v go >/dev/null 2>&1; then
    GO_BIN=$(command -v go)
    echo "Using Go from PATH: $GO_BIN"
else
    need mkdir
    mkdir -p "$GO_DIR"
    if [ ! -x "$GO_DIR/go/bin/go" ]; then
        echo "Downloading Go ${GO_VERSION} into ${GO_DIR}…"
        curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz" \
            | tar -xz -C "$GO_DIR"
    fi
    GO_BIN="$GO_DIR/go/bin/go"
    echo "Using local Go: $GO_BIN"
fi

if ! command -v make >/dev/null 2>&1; then
    echo "error: make is required" >&2
    echo "Install build-essential (Debian/Ubuntu), gcc/make (Fedora/SUSE), or base-devel (Arch)." >&2
    exit 1
fi
if ! command -v gcc >/dev/null 2>&1; then
    echo "error: a C compiler is required for CGO/SQLCipher" >&2
    echo "Install build-essential (Debian/Ubuntu), gcc (Fedora/SUSE), or base-devel (Arch)." >&2
    exit 1
fi

cd "$ROOT"
make build GO="$GO_BIN"

echo
echo "Build complete: ${ROOT}/dist/hibp"
echo "Run: ./dist/hibp server --db \"\$HOME/.local/share/hibp/hibp.db\" --create"
