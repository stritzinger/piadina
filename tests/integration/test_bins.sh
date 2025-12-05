#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH

set -euo pipefail

: "${TOP_BUILDDIR:?TOP_BUILDDIR is required}"

PIADINA_BIN="$TOP_BUILDDIR/piadina/piadina"
AZDORA_BIN="$TOP_BUILDDIR/azdora/azdora"

echo "=== Testing binary existence ==="

if [ ! -x "$PIADINA_BIN" ]; then
    echo "FAIL: piadina binary missing at $PIADINA_BIN" >&2
    exit 1
fi

if [ ! -x "$AZDORA_BIN" ]; then
    echo "FAIL: azdora binary missing at $AZDORA_BIN" >&2
    exit 1
fi

echo "PASS: Both binaries exist"

echo ""
echo "=== Testing piadina --launcher-help ==="
if "$PIADINA_BIN" --launcher-help 2>&1 | grep -q "Piadina Self-Extracting Launcher"; then
    echo "PASS: --launcher-help works"
else
    echo "FAIL: --launcher-help output unexpected" >&2
    exit 1
fi

echo ""
echo "=== Testing piadina --launcher-version ==="
if "$PIADINA_BIN" --launcher-version 2>&1 | grep -q "Piadina launcher"; then
    echo "PASS: --launcher-version works"
else
    echo "FAIL: --launcher-version output unexpected" >&2
    exit 1
fi

echo ""
echo "=== Testing piadina test process launch (without footer) ==="
# The plain binary should fail footer validation but still launch test process
OUTPUT=$("$PIADINA_BIN" 2>&1) || true
if echo "$OUTPUT" | grep -q "test process launched successfully"; then
    echo "PASS: Test process launched"
else
    echo "FAIL: Test process did not launch" >&2
    echo "Output: $OUTPUT" >&2
    exit 1
fi

echo ""
echo "=== Testing exit code forwarding ==="
# Test that the launcher returns 0 when test process succeeds
if "$PIADINA_BIN" 2>/dev/null; then
    echo "PASS: Exit code 0 forwarded correctly"
else
    echo "FAIL: Expected exit code 0" >&2
    exit 1
fi

echo ""
echo "=== Testing error exit codes ==="
# Test invalid option returns usage error (111)
set +e
"$PIADINA_BIN" --launcher-invalid 2>/dev/null
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 111 ]; then
    echo "PASS: Invalid option returns exit code 111"
else
    echo "FAIL: Expected exit code 111, got $EXIT_CODE" >&2
    exit 1
fi

# Test print-footer on unpacked binary returns footer error (112)
set +e
"$PIADINA_BIN" --launcher-print-footer 2>/dev/null
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 112 ]; then
    echo "PASS: print-footer on unpacked binary returns exit code 112"
else
    echo "FAIL: Expected exit code 112, got $EXIT_CODE" >&2
    exit 1
fi

echo ""
echo "=== Testing piadina --launcher-print-metadata on unpacked binary ==="
set +e
"$PIADINA_BIN" --launcher-print-metadata 2>/dev/null
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 112 ]; then
    echo "PASS: print-metadata on unpacked binary returns exit code 112"
else
    echo "FAIL: Expected exit code 112, got $EXIT_CODE" >&2
    exit 1
fi

echo ""
echo "=== Testing azdora basic execution ==="
"$AZDORA_BIN" >/dev/null
echo "PASS: Azdora runs"

echo ""
echo "=== All integration tests passed ==="
