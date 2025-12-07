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

WORKDIR="$(mktemp -d /tmp/piadina_extract_reuseXXXXXX)"
PAYLOAD_DIR="$WORKDIR/payload"
SFX_BIN="$WORKDIR/piadina_sfx"

cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

mkdir -p "$PAYLOAD_DIR/bin"
cat > "$PAYLOAD_DIR/bin/app.sh" <<'EOF'
#!/usr/bin/env sh
ORIG_ARGS="$*"
PRINT_ENV=0
EXIT_CODE=0
ARGS="$@"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --print-env)
            PRINT_ENV=1
            ;;
        --exit)
            if [ "$#" -ge 2 ]; then
                EXIT_CODE="$2"
                shift
            fi
            ;;
    esac
    shift
done
echo "ARGS:${ORIG_ARGS}"
if [ "$PRINT_ENV" -eq 1 ]; then
    echo "FOO=${FOO:-}"
    echo "BAR=${BAR:-}"
fi
exit "$EXIT_CODE"
EOF
chmod +x "$PAYLOAD_DIR/bin/app.sh"

"$AZDORA_BIN" \
    --launcher "$PIADINA_BIN" \
    --payload "$PAYLOAD_DIR" \
    --output "$SFX_BIN" \
    --meta ENTRY_POINT=bin/app.sh \
    --meta ENTRY_ARGS[]="--print-env" \
    --meta ENV.FOO="foo_meta" \
    --meta ENV.BAR="bar_meta"

run_once() {
    local name="$1"; shift
    local expected_status="$1"; shift

    local output status
    output=$("$SFX_BIN" --launcher-log-level=info "$@" 2>&1)
    status=$?

    if [[ "$status" -ne "$expected_status" ]]; then
        echo "ERROR ($name): launcher exit $status (expected $expected_status)" >&2
        echo "$output" >&2
        exit 1
    fi

    echo "$output"
}

OUTPUT1=$(run_once "first run" 0)

PAYLOAD_ROOT=$(echo "$OUTPUT1" | sed -n 's|.*payload ready at \([^ ]*\).*|\1|p' | tail -n 1)
if [[ -z "$PAYLOAD_ROOT" || ! -d "$PAYLOAD_ROOT" ]]; then
    echo "ERROR: failed to determine payload root" >&2
    echo "$OUTPUT1" >&2
    exit 1
fi

if ! echo "$OUTPUT1" | grep -q "FOO=foo_meta"; then
    echo "ERROR: missing env FOO in output" >&2
    echo "$OUTPUT1" >&2
    exit 1
fi
if ! echo "$OUTPUT1" | grep -q "BAR=bar_meta"; then
    echo "ERROR: missing env BAR in output" >&2
    echo "$OUTPUT1" >&2
    exit 1
fi
if ! echo "$OUTPUT1" | grep -q "ARGS:--print-env"; then
    echo "ERROR: entry args not echoed" >&2
    echo "$OUTPUT1" >&2
    exit 1
fi

OUTPUT2=$(run_once "reuse run" 7 -- --exit 7)

if ! echo "$OUTPUT2" | grep -q "reusing existing payload at $PAYLOAD_ROOT"; then
    echo "ERROR: reuse log not found" >&2
    echo "$OUTPUT2" >&2
    exit 1
fi
if ! echo "$OUTPUT2" | grep -q "ARGS:--print-env --exit 7"; then
    echo "ERROR: argv not propagated with CLI args" >&2
    echo "$OUTPUT2" >&2
    exit 1
fi

echo "PASS: extraction and reuse with env/args"
