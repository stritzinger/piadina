#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH

set -euo pipefail

: "${TOP_BUILDDIR:?TOP_BUILDDIR is required}"

PIADINA_BIN="$TOP_BUILDDIR/piadina/piadina"
AZDORA_BIN="$TOP_BUILDDIR/azdora/azdora"

if [[ ! -x "$PIADINA_BIN" ]]; then
    echo "ERROR: piadina binary not found at $PIADINA_BIN" >&2
    exit 1
fi

if [[ ! -x "$AZDORA_BIN" ]]; then
    echo "ERROR: azdora binary not found at $AZDORA_BIN" >&2
    exit 1
fi

WORKDIR="$(mktemp -d /tmp/piadina_force_extractXXXXXX)"
PAYLOAD_DIR="$WORKDIR/payload"
SFX_BIN="$WORKDIR/piadina_sfx"

cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

mkdir -p "$PAYLOAD_DIR/bin"
cat > "$PAYLOAD_DIR/bin/app.sh" <<'EOF'
#!/usr/bin/env sh
echo "ORIGINAL"
EOF
chmod +x "$PAYLOAD_DIR/bin/app.sh"

"$AZDORA_BIN" \
    --launcher "$PIADINA_BIN" \
    --payload "$PAYLOAD_DIR" \
    --output "$SFX_BIN" \
    --meta ENTRY_POINT=bin/app.sh

run_sfx() {
    local expected_status="$1"; shift
    "$SFX_BIN" --launcher-log-level=info "$@" 2>&1
    return $?
}

OUTPUT1=$(run_sfx 0) || true
if [[ $? -ne 0 ]]; then
    echo "ERROR: first run failed" >&2
    echo "$OUTPUT1" >&2
    exit 1
fi

PAYLOAD_ROOT=$(echo "$OUTPUT1" | sed -n 's|.*payload ready at \([^ ]*\).*|\1|p' | tail -n 1)
if [[ -z "$PAYLOAD_ROOT" || ! -d "$PAYLOAD_ROOT" ]]; then
    echo "ERROR: failed to determine payload root" >&2
    echo "$OUTPUT1" >&2
    exit 1
fi

if ! grep -q "ORIGINAL" "$PAYLOAD_ROOT/bin/app.sh"; then
    echo "ERROR: initial payload content mismatch" >&2
    exit 1
fi

echo "MUTATED" > "$PAYLOAD_ROOT/bin/app.sh"
touch "$PAYLOAD_ROOT/SENTINEL"

OUTPUT2=$(run_sfx 0 --launcher-force-extract) || true
if [[ $? -ne 0 ]]; then
    echo "ERROR: force extract run failed" >&2
    echo "$OUTPUT2" >&2
    exit 1
fi

if ! echo "$OUTPUT2" | grep -q "force extracting payload"; then
    echo "ERROR: missing force extract log" >&2
    echo "$OUTPUT2" >&2
    exit 1
fi

if ! grep -q "ORIGINAL" "$PAYLOAD_ROOT/bin/app.sh"; then
    echo "ERROR: payload not restored after force extract" >&2
    echo "$OUTPUT2" >&2
    exit 1
fi

if [[ -e "$PAYLOAD_ROOT/SENTINEL" ]]; then
    echo "ERROR: sentinel not removed after force extract" >&2
    echo "$OUTPUT2" >&2
    exit 1
fi

OUTPUT3=$(run_sfx 0) || true
if [[ $? -ne 0 ]]; then
    echo "ERROR: third run failed" >&2
    echo "$OUTPUT3" >&2
    exit 1
fi

if ! echo "$OUTPUT3" | grep -q "reusing existing payload at $PAYLOAD_ROOT"; then
    echo "ERROR: reuse log missing on third run" >&2
    echo "$OUTPUT3" >&2
    exit 1
fi

if ! grep -q "ORIGINAL" "$PAYLOAD_ROOT/bin/app.sh"; then
    echo "ERROR: payload content changed after reuse run" >&2
    echo "$OUTPUT3" >&2
    exit 1
fi

echo "PASS: force extract refreshes mutated cache and reuse works"
