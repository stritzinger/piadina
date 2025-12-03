#!/usr/bin/env bash
set -euo pipefail

: "${TOP_BUILDDIR:?TOP_BUILDDIR is required}"

PIADINA_BIN="$TOP_BUILDDIR/piadina/piadina"
AZDORA_BIN="$TOP_BUILDDIR/azdora/azdora"

if [ ! -x "$PIADINA_BIN" ]; then
    echo "piadina binary missing at $PIADINA_BIN" >&2
    exit 1
fi

if [ ! -x "$AZDORA_BIN" ]; then
    echo "azdora binary missing at $AZDORA_BIN" >&2
    exit 1
fi

"$PIADINA_BIN" >/dev/null
"$AZDORA_BIN" >/dev/null
