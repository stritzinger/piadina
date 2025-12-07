#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH

set -euo pipefail

print_usage() {
    cat <<'EOF'
Piadina Testing Command
Usage: entry.sh [--print-env] [--exit N] [--help] [--] [extra args...]

Options:
  --print-env    Print a compact view of selected env vars.
  --exit N       Exit with status N (default 0).
  --help         Show this help and exit.

All additional arguments are echoed back for testing.
EOF
}

PRINT_ENV=0
PRINT_ARGS=0
EXIT_CODE=0
ARGS=""
SCRIPT="$0"

while [ $# -gt 0 ]; do
    case "$1" in
        --print-env) PRINT_ENV=1 ;;
        --print-args) PRINT_ARGS=1 ;;
        --exit)
            if [ $# -ge 2 ]; then
                EXIT_CODE="$2"
                shift
            fi
            ;;
        --help) print_usage; exit 0 ;;
        --) shift; break ;;
        *) ;;
    esac
    ARGS="$ARGS $1"
    shift
done

echo "Piadina Testing Command"

if [ "$PRINT_ARGS" -eq 1 ]; then
    echo "Args: $SCRIPT$ARGS $*"
fi

if [ "$PRINT_ENV" -eq 1 ]; then
    env
fi

exit "$EXIT_CODE"
