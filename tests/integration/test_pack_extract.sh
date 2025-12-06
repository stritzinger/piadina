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

WORKDIR="$(mktemp -d /tmp/azdora_integration_workXXXXXX)"
PAYLOAD_DIR="$WORKDIR/payload"
SFX_BIN="$WORKDIR/piadina_sfx"
EXTRACT_DIR=""

cleanup() {
    rm -rf "$WORKDIR"
    if [[ -n "$EXTRACT_DIR" && -d "$EXTRACT_DIR" ]]; then
        rm -rf "$EXTRACT_DIR"
    fi
}
trap cleanup EXIT

mkdir -p "$PAYLOAD_DIR/subdir"
echo "hello from integration payload" > "$PAYLOAD_DIR/hello.txt"
echo "nested file content" > "$PAYLOAD_DIR/subdir/nested.txt"

"$AZDORA_BIN" \
    --launcher "$PIADINA_BIN" \
    --payload "$PAYLOAD_DIR" \
    --output "$SFX_BIN" \
    --meta ENTRY_POINT=bin/app

RUN_OUTPUT=$("$SFX_BIN" --launcher-log-level=info 2>&1)
RUN_STATUS=$?
if [[ "$RUN_STATUS" -ne 0 ]]; then
    echo "ERROR: launcher exit code $RUN_STATUS" >&2
    echo "Output:" >&2
    echo "$RUN_OUTPUT" >&2
    exit 1
fi

EXTRACT_DIR="$(echo "$RUN_OUTPUT" | sed -n 's|.*extracting archive to \([^ ]*\).*|\1|p' | tail -n 1)"

if [[ -z "$EXTRACT_DIR" || ! -d "$EXTRACT_DIR" ]]; then
    echo "ERROR: failed to detect extraction directory" >&2
    echo "Output:" >&2
    echo "$RUN_OUTPUT" >&2
    exit 1
fi

if [[ "$(cat "$EXTRACT_DIR/hello.txt")" != "hello from integration payload" ]]; then
    echo "ERROR: extracted hello.txt content mismatch" >&2
    exit 1
fi

if [[ "$(cat "$EXTRACT_DIR/subdir/nested.txt")" != "nested file content" ]]; then
    echo "ERROR: extracted nested.txt content mismatch" >&2
    exit 1
fi

echo "PASS: pack and extract end-to-end"
