#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH

set -euo pipefail

: "${TOP_BUILDDIR:?TOP_BUILDDIR is required}"

PIADINA_BIN="$TOP_BUILDDIR/piadina/piadina"
AZDORA_BIN="$TOP_BUILDDIR/azdora/azdora"
READ_ELF="${READ_ELF:-readelf}"

if [[ ! -x "$PIADINA_BIN" ]]; then
    echo "ERROR: piadina binary not found at $PIADINA_BIN" >&2
    exit 1
fi

if [[ ! -x "$AZDORA_BIN" ]]; then
    echo "ERROR: azdora binary not found at $AZDORA_BIN" >&2
    exit 1
fi

if [[ ! -x "$(command -v "$READ_ELF")" ]]; then
    echo "SKIP: readelf not available" >&2
    exit 77
fi

if [[ ! -r /lib64/ld-linux-x86-64.so.2 ]]; then
    echo "SKIP: expected loader /lib64/ld-linux-x86-64.so.2 not present" >&2
    exit 77
fi

WORKDIR="$(mktemp -d /tmp/piadina_patchelf_workXXXXXX)"
PAYLOAD_DIR="$WORKDIR/payload"
SFX_BIN="$WORKDIR/piadina_sfx"
EXTRACT_DIR=""
LONG_DIR="$WORKDIR/very/long/path/for/interp/$(printf 'p%.0s' {1..80})"
LD1="$LONG_DIR/ld-linux-x86-64.so.2"
LD2="/tmp/ld2.so"

cleanup() {
    rm -rf "$WORKDIR"
    if [[ -n "$EXTRACT_DIR" && -d "$EXTRACT_DIR" ]]; then
        rm -rf "$EXTRACT_DIR"
    fi
    rm -f "$LD1" "$LD2"
}
trap cleanup EXIT

mkdir -p "$PAYLOAD_DIR/bin" "$(dirname "$LD1")"

HELLO_SRC="$WORKDIR/hello.c"
cat > "$HELLO_SRC" <<'EOF'
#include <stdio.h>
int main(void) {
    puts("hello-elf-1");
    return 0;
}
EOF

HELLO2_SRC="$WORKDIR/hello2.c"
cat > "$HELLO2_SRC" <<'EOF'
#include <stdio.h>
int main(void) {
    puts("hello-elf-2");
    return 0;
}
EOF

# Use an intentionally long interpreter path so the patch must grow .interp.
LONG_INTERP="/lib64/ld-linux-x86-64.so.2.extra"
gcc -o "$PAYLOAD_DIR/bin/hello1" "$HELLO_SRC" -Wl,--dynamic-linker
gcc -o "$PAYLOAD_DIR/bin/hello2" "$HELLO2_SRC" -Wl,--dynamic-linker,"$LONG_INTERP"

cp /lib64/ld-linux-x86-64.so.2 "$LD1"
cp /lib64/ld-linux-x86-64.so.2 "$LD2"

"$AZDORA_BIN" \
    --launcher "$PIADINA_BIN" \
    --payload "$PAYLOAD_DIR" \
    --output "$SFX_BIN" \
    --meta ENTRY_POINT=bin/hello1 \
    --meta PATCHELF_SET_INTERPRETER[]=bin/hello1:$LD1 \
    --meta PATCHELF_SET_INTERPRETER[]=bin/hello2:$LD2

RUN_OUTPUT=$("$SFX_BIN" --launcher-verbose 2>&1)
RUN_STATUS=$?
if [[ "$RUN_STATUS" -ne 0 ]]; then
    echo "ERROR: launcher exit code $RUN_STATUS" >&2
    echo "$RUN_OUTPUT" >&2
    exit 1
fi

EXTRACT_DIR="$(echo "$RUN_OUTPUT" | sed -n 's|.*payload ready at \([^ ]*\).*|\1|p' | tail -n 1)"
if [[ -z "$EXTRACT_DIR" || ! -d "$EXTRACT_DIR" ]]; then
    echo "ERROR: failed to detect extraction directory" >&2
    echo "$RUN_OUTPUT" >&2
    exit 1
fi

INTERP1_LINE=$("$READ_ELF" -l "$EXTRACT_DIR/bin/hello1" | grep 'Requesting program interpreter' || true)
if [[ "$INTERP1_LINE" != *"$LD1"* ]]; then
    echo "ERROR: interpreter not patched for hello1, got: $INTERP1_LINE" >&2
    echo "$RUN_OUTPUT" >&2
    exit 1
fi

INTERP2_LINE=$("$READ_ELF" -l "$EXTRACT_DIR/bin/hello2" | grep 'Requesting program interpreter' || true)
if [[ "$INTERP2_LINE" != *"$LD2"* ]]; then
    echo "ERROR: interpreter not patched for hello2, got: $INTERP2_LINE" >&2
    echo "$RUN_OUTPUT" >&2
    exit 1
fi

HELLO_OUT=$("$EXTRACT_DIR/bin/hello1")
if [[ "$HELLO_OUT" != "hello-elf-1" ]]; then
    echo "ERROR: patched hello1 failed to run (output: $HELLO_OUT)" >&2
    echo "$RUN_OUTPUT" >&2
    exit 1
fi

HELLO_OUT2=$("$EXTRACT_DIR/bin/hello2")
if [[ "$HELLO_OUT2" != "hello-elf-2" ]]; then
    echo "ERROR: patched hello2 failed to run (output: $HELLO_OUT2)" >&2
    echo "$RUN_OUTPUT" >&2
    exit 1
fi

mv "$LD1" "$LD1.gone"
if "$EXTRACT_DIR/bin/hello1" 2>/tmp/hello1_fail.log; then
    echo "ERROR: hello1 still ran after interpreter $LD1 was removed" >&2
    cat /tmp/hello1_fail.log >&2 || true
    exit 1
fi
rm -f /tmp/hello1_fail.log

mv "$LD2" "$LD2.gone"
if "$EXTRACT_DIR/bin/hello2" 2>/tmp/hello2_fail.log; then
    echo "ERROR: hello2 still ran after interpreter $LD2 was removed" >&2
    cat /tmp/hello2_fail.log >&2 || true
    exit 1
fi
rm -f /tmp/hello2_fail.log

echo "PASS: patchelf_set_interpreter patched interpreters for multiple binaries and they run"
