#!/bin/sh
# Install a prebuilt HIBP release. No Go installation is required.
#
# Usage:
#   sh install.sh
#   sh install.sh --version v0.6.8
#   sh install.sh --prefix "$HOME/.local/bin"
#
# Environment:
#   HIBP_REPO    GitHub repository (default: RogerBergling/HIBP)
#   HIBP_VERSION Release tag, or "latest" (default: latest)
#   HIBP_PREFIX  Install directory (default: $HOME/.local/bin)
#
# The script verifies the release archive against the published SHA256SUMS
# before installing it.

set -eu

REPO="${HIBP_REPO:-RogerBergling/HIBP}"
VERSION="${HIBP_VERSION:-latest}"
PREFIX="${HIBP_PREFIX:-$HOME/.local/bin}"

usage() {
    cat <<'EOF'
Install HIBP from a prebuilt GitHub release.

Options:
  --version TAG   Install a specific release tag (for example v0.6.8)
  --prefix DIR    Install into DIR (default: $HOME/.local/bin)
  -h, --help      Show this help

Environment:
  HIBP_REPO       GitHub repository (default: RogerBergling/HIBP)
  HIBP_VERSION    Release tag, or "latest" (default: latest)
  HIBP_PREFIX     Install directory (default: $HOME/.local/bin)
EOF
}

need() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required command not found: $1" >&2
        exit 1
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || { echo "error: --version needs a value" >&2; exit 2; }
            VERSION="$2"
            shift 2
            ;;
        --prefix)
            [ "$#" -ge 2 ] || { echo "error: --prefix needs a value" >&2; exit 2; }
            PREFIX="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "$(uname -s)" in
    Linux) ;;
    *) echo "error: HIBP releases currently support Linux only" >&2; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "error: unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

need curl
need tar
need sha256sum
need install

if [ "$VERSION" = "latest" ]; then
    need sed
    if ! RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null); then
        echo "error: no published GitHub release found for ${REPO}." >&2
        echo "Build from source instead: make bootstrap" >&2
        echo "Or publish a release by pushing a v* tag; see README.md." >&2
        exit 1
    fi
    TAG=$(printf '%s\n' "$RELEASE_JSON" \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | head -n 1)
    if [ -z "$TAG" ]; then
        echo "error: could not determine the latest release for ${REPO}." >&2
        echo "Build from source instead: make bootstrap" >&2
        exit 1
    fi
else
    case "$VERSION" in
        v*) TAG="$VERSION" ;;
        *) TAG="v$VERSION" ;;
    esac
fi

ASSET="hibp-${TAG}-linux-${ARCH}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${TAG}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "Downloading ${ASSET}…"
if ! curl -fsSL "${BASE}/${ASSET}" -o "${TMP}/${ASSET}" 2>/dev/null; then
    echo "error: release asset not found: ${BASE}/${ASSET}" >&2
    echo "Check the release tag and architecture (${ARCH})." >&2
    exit 1
fi
if ! curl -fsSL "${BASE}/SHA256SUMS" -o "${TMP}/SHA256SUMS" 2>/dev/null; then
    echo "error: SHA256SUMS not found for release ${TAG}" >&2
    exit 1
fi

if ! grep -E "[[:space:]]${ASSET}$" "${TMP}/SHA256SUMS" >/dev/null 2>&1; then
    echo "error: ${ASSET} is missing from SHA256SUMS" >&2
    exit 1
fi
(
    cd "$TMP"
    grep -E "[[:space:]]${ASSET}$" SHA256SUMS | sha256sum -c -
)

tar -xzf "${TMP}/${ASSET}" -C "$TMP"
if [ ! -f "${TMP}/hibp" ]; then
    echo "error: release archive does not contain the hibp binary" >&2
    exit 1
fi

mkdir -p "$PREFIX"
install -m 0755 "${TMP}/hibp" "${PREFIX}/hibp"

echo "Installed ${PREFIX}/hibp"
"${PREFIX}/hibp" version

case ":${PATH}:" in
    *":${PREFIX}:"*) ;;
    *) echo "Add ${PREFIX} to PATH, or run ${PREFIX}/hibp directly." ;;
esac

echo
echo "Next:"
echo "  ${PREFIX}/hibp server --db \"\$HOME/.local/share/hibp/hibp.db\" --create"
echo "Then open http://localhost:8443/ and create the admin account + MFA."
