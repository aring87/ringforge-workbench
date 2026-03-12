#!/usr/bin/env bash
set -euo pipefail

RULES_DIR="${1:-tools/capa-rules}"
PIN_TAG="${CAPA_RULES_TAG:-v9.3.1}"  # set a known-good tag; change when you want updates

mkdir -p "$(dirname "$RULES_DIR")"

if [[ -d "$RULES_DIR/.git" ]]; then
  echo "[*] Updating existing capa-rules repo in $RULES_DIR"
  git -C "$RULES_DIR" fetch --tags --quiet
  git -C "$RULES_DIR" checkout --quiet "$PIN_TAG"
else
  echo "[*] Cloning capa-rules into $RULES_DIR"
  git clone --quiet https://github.com/mandiant/capa-rules.git "$RULES_DIR"
  git -C "$RULES_DIR" checkout --quiet "$PIN_TAG"
fi

echo "[+] capa rules ready: $RULES_DIR ($(git -C "$RULES_DIR" describe --tags --always))"