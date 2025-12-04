#!/usr/bin/env bash
# Test script to verify that binaries are statically linked when expected.
# This test only runs when STATIC_BUILD=yes is passed via the environment.
set -euo pipefail

: "${TOP_BUILDDIR:?TOP_BUILDDIR is required}"
: "${STATIC_BUILD:=no}"

PIADINA_BIN="$TOP_BUILDDIR/piadina/piadina"
AZDORA_BIN="$TOP_BUILDDIR/azdora/azdora"

# Function to check if a binary is statically linked
is_statically_linked() {
    local binary="$1"
    local ldd_output

    if ! [ -x "$binary" ]; then
        echo "ERROR: Binary not found or not executable: $binary" >&2
        return 1
    fi

    # Use ldd to check dynamic dependencies
    ldd_output=$(ldd "$binary" 2>&1) || true

    # A statically linked binary will show "not a dynamic executable" or
    # "statically linked" message
    if echo "$ldd_output" | grep -qE "(not a dynamic executable|statically linked)"; then
        return 0
    fi

    # If ldd shows library dependencies, it's dynamically linked
    if echo "$ldd_output" | grep -qE "lib.*\.so"; then
        return 1
    fi

    # Default: assume static if no shared libs found
    return 0
}

echo "Static build test:"
echo "  STATIC_BUILD=$STATIC_BUILD"
echo "  PIADINA_BIN=$PIADINA_BIN"
echo "  AZDORA_BIN=$AZDORA_BIN"

if [ "$STATIC_BUILD" = "yes" ]; then
    echo ""
    echo "Verifying binaries are statically linked..."

    failed=0

    echo -n "  Checking piadina... "
    if is_statically_linked "$PIADINA_BIN"; then
        echo "OK (static)"
    else
        echo "FAILED (dynamically linked)"
        echo "  ldd output:"
        ldd "$PIADINA_BIN" 2>&1 | sed 's/^/    /'
        failed=1
    fi

    echo -n "  Checking azdora... "
    if is_statically_linked "$AZDORA_BIN"; then
        echo "OK (static)"
    else
        echo "FAILED (dynamically linked)"
        echo "  ldd output:"
        ldd "$AZDORA_BIN" 2>&1 | sed 's/^/    /'
        failed=1
    fi

    if [ $failed -eq 1 ]; then
        echo ""
        echo "ERROR: Static build verification failed!"
        echo "       Binaries were expected to be statically linked but are not."
        exit 1
    fi

    echo ""
    echo "Static linkage verification passed."

else
    echo ""
    echo "Dynamic build mode - skipping static linkage verification."
    echo "  (Use STATIC_BUILD=yes to enable this test)"

    # Still verify binaries exist and run
    for bin in "$PIADINA_BIN" "$AZDORA_BIN"; do
        if ! [ -x "$bin" ]; then
            echo "ERROR: Binary not found: $bin" >&2
            exit 1
        fi
    done

    echo "Binaries exist and are executable."
fi

exit 0
