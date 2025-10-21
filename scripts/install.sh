#!/usr/bin/env bash

set -euo pipefail

APP_NAME="mbox-reader"
REPO_OWNER="allquixotic"
REPO_NAME="mbox_reader"
DEFAULT_BRANCH="main"

LOG_PREFIX="[$APP_NAME installer]"
SDKMAN_DIR="${SDKMAN_DIR:-$HOME/.sdkman}"
BRANCH="${BRANCH:-$DEFAULT_BRANCH}"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/${BRANCH}"
INSTALL_ROOT="${INSTALL_ROOT:-$HOME/.local/share/$APP_NAME}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
SCRIPT_DEST="$INSTALL_ROOT/mbox_reader.main.kts"
SHIM_PATH="$BIN_DIR/$APP_NAME"

log() {
  printf '%s %s\n' "$LOG_PREFIX" "$*" >&2
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "Missing required command: $1"
    exit 1
  fi
}

require_cmd curl
require_cmd mkdir

mkdir -p "$INSTALL_ROOT" "$BIN_DIR"

if [ ! -s "$SDKMAN_DIR/bin/sdkman-init.sh" ]; then
  log "Installing SDKMAN! into $SDKMAN_DIR"
  curl -fsSL "https://get.sdkman.io" | bash
else
  log "SDKMAN! already present in $SDKMAN_DIR"
fi

# shellcheck source=/dev/null
source "$SDKMAN_DIR/bin/sdkman-init.sh"

export SDKMAN_NON_INTERACTIVE=1

if [ ! -d "$SDKMAN_DIR/candidates/java/25-tem" ]; then
  log "Installing Temurin Java 25 via SDKMAN!"
  sdk install java 25-tem
else
  log "Temurin Java 25 already installed"
fi

if [ ! -d "$SDKMAN_DIR/candidates/kotlin/2.2.20" ]; then
  log "Installing Kotlin 2.2.20 via SDKMAN!"
  sdk install kotlin 2.2.20
else
  log "Kotlin 2.2.20 already installed"
fi

JAVA_HOME="$SDKMAN_DIR/candidates/java/25-tem"
KOTLIN_HOME="$SDKMAN_DIR/candidates/kotlin/2.2.20"

if [ ! -x "$KOTLIN_HOME/bin/kotlin" ]; then
  log "Kotlin executable not found at $KOTLIN_HOME/bin/kotlin"
  exit 1
fi

tmp_script="$(mktemp "${TMPDIR:-/tmp}/mbox_reader.XXXXXX")"
trap 'rm -f "$tmp_script"' EXIT

log "Downloading mbox_reader.main.kts from $RAW_BASE"
curl -fsSL "$RAW_BASE/mbox_reader.main.kts" -o "$tmp_script"
mv "$tmp_script" "$SCRIPT_DEST"
chmod 644 "$SCRIPT_DEST"

cat >"$SHIM_PATH" <<EOF
#!/usr/bin/env bash
set -euo pipefail
SDKMAN_DIR="\${SDKMAN_DIR:-$SDKMAN_DIR}"
JAVA_HOME="\$SDKMAN_DIR/candidates/java/25-tem"
KOTLIN_HOME="\$SDKMAN_DIR/candidates/kotlin/2.2.20"
if [ ! -x "\$KOTLIN_HOME/bin/kotlin" ]; then
  echo "mbox-reader: Kotlin 2.2.20 is not installed. Re-run the installer." >&2
  exit 1
fi
export JAVA_HOME
exec "\$KOTLIN_HOME/bin/kotlin" -script "$SCRIPT_DEST" "\$@"
EOF

chmod 755 "$SHIM_PATH"

if ! command -v "$APP_NAME" >/dev/null 2>&1; then
  if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    log "Add $BIN_DIR to your PATH to use '$APP_NAME' command."
  fi
fi

log "Installation complete. Launch with: $APP_NAME"
