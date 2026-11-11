#!/bin/sh
# Start HIBP in a persistent terminal session for interactive database unlock.
#
# Run as root (the script drops to the service account for the server process)
# or as the service account itself:
#
#   sudo HIBP_CREATE=1 sh scripts/start-interactive.sh   # first run
#   sudo sh scripts/start-interactive.sh                 # after reboot
#
# The passphrase is entered in the tmux/screen session, never in argv or the
# environment. tmux is preferred; screen is used when tmux is unavailable.

set -eu

HIBP_USER="${HIBP_USER:-hibp}"
HIBP_BIN="${HIBP_BIN:-/usr/local/bin/hibp}"
HIBP_DB="${HIBP_DB:-/var/lib/hibp/hibp.db}"
HIBP_LISTEN="${HIBP_LISTEN:-127.0.0.1:8443}"
HIBP_KEY_DIR="${HIBP_KEY_DIR:-/etc/hibp/ssh}"
HIBP_SSH_CONFIG="${HIBP_SSH_CONFIG:-/etc/hibp/ssh/config}"
HIBP_SESSION="${HIBP_SESSION:-hibp}"
HIBP_HOME="${HIBP_HOME:-/var/lib/hibp}"

if [ ! -x "$HIBP_BIN" ]; then
    echo "error: HIBP binary is not executable: $HIBP_BIN" >&2
    exit 1
fi

if [ "$(id -u)" -eq 0 ]; then
    if ! id "$HIBP_USER" >/dev/null 2>&1; then
        echo "error: service user does not exist: $HIBP_USER" >&2
        exit 1
    fi
    if command -v runuser >/dev/null 2>&1; then
        RUNNER="runuser -u $HIBP_USER -- env HOME=$HIBP_HOME"
    elif command -v sudo >/dev/null 2>&1; then
        RUNNER="sudo -u $HIBP_USER -H env HOME=$HIBP_HOME"
    else
        echo "error: root needs runuser or sudo to drop to $HIBP_USER" >&2
        exit 1
    fi
else
    if [ "$(id -un)" != "$HIBP_USER" ]; then
        echo "error: run as root or as the $HIBP_USER service account" >&2
        exit 1
    fi
    RUNNER="env HOME=$HIBP_HOME"
fi

server_command="$RUNNER $HIBP_BIN server --db $HIBP_DB --listen $HIBP_LISTEN --key-dir $HIBP_KEY_DIR --ssh-config $HIBP_SSH_CONFIG"
if [ "${HIBP_CREATE:-0}" = "1" ]; then
    server_command="$server_command --create"
fi

if command -v tmux >/dev/null 2>&1; then
    if tmux has-session -t "$HIBP_SESSION" 2>/dev/null; then
        echo "HIBP session already exists: $HIBP_SESSION"
    else
        tmux new-session -d -s "$HIBP_SESSION" "$server_command"
        echo "Started HIBP in tmux session: $HIBP_SESSION"
    fi
    if [ -n "${TMUX:-}" ]; then
        echo "Attach from outside tmux with: tmux attach -t $HIBP_SESSION"
        exit 0
    fi
    exec tmux attach -t "$HIBP_SESSION"
fi

if command -v screen >/dev/null 2>&1; then
    if screen -list 2>/dev/null | grep -q "[.]${HIBP_SESSION}[[:space:]]"; then
        echo "HIBP session already exists: $HIBP_SESSION"
    else
        screen -dmS "$HIBP_SESSION" sh -c "$server_command"
        echo "Started HIBP in screen session: $HIBP_SESSION"
    fi
    if [ -n "${STY:-}" ]; then
        echo "Attach from outside screen with: screen -r $HIBP_SESSION"
        exit 0
    fi
    exec screen -r "$HIBP_SESSION"
fi

echo "error: neither tmux nor screen is installed" >&2
echo "Install tmux (preferred) or screen, then retry." >&2
exit 1
