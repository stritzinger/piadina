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

WORKDIR="$(mktemp -d /tmp/piadina_overrides_workXXXXXX)"
PAYLOAD_DIR="$WORKDIR/payload"
SFX_BIN="$WORKDIR/piadina_sfx"

cleanup() {
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

mkdir -p "$PAYLOAD_DIR/bin"
cat > "$PAYLOAD_DIR/bin/app" <<'EOF'
#!/usr/bin/env sh
echo "hello"
EOF
chmod +x "$PAYLOAD_DIR/bin/app"

# Build SFX with templated CACHE_ROOT and PAYLOAD_ROOT
"$AZDORA_BIN" \
    --launcher "$PIADINA_BIN" \
    --payload "$PAYLOAD_DIR" \
    --output "$SFX_BIN" \
    --meta CACHE_ROOT="{HOME}/.piadina/cache_tpl" \
    --meta PAYLOAD_ROOT="{CACHE_ROOT}/payload_tpl" \
    --meta ENTRY_POINT=bin/app \
    --meta ENTRY_ARGS[]="--arg={PAYLOAD_ROOT}" \
    --meta ENTRY_ARGS_POST[]="--post={PAYLOAD_ROOT}" \
    --meta ENV.DEST="{PAYLOAD_ROOT}"

run_case() {
    local name="$1"
    local home_dir="$2"
    local env_cache="$3"
    local cli_cache="$4"
    local expected_root="$5"

    rm -rf "$expected_root"

    local output status
    if [[ -n "$cli_cache" ]]; then
        output=$(
            HOME="$home_dir" PIADINA_CACHE_ROOT="$env_cache" \
                "$SFX_BIN" --launcher-log-level=debug \
                --launcher-cache-root="$cli_cache" 2>&1
        )
        status=$?
    else
        output=$(
            HOME="$home_dir" PIADINA_CACHE_ROOT="$env_cache" \
                "$SFX_BIN" --launcher-log-level=debug 2>&1
        )
        status=$?
    fi

    if [[ $status -ne 0 ]]; then
        echo "ERROR ($name): launcher exit $status" >&2
        echo "$output" >&2
        exit 1
    fi

    local extract_dir
    extract_dir=$(echo "$output" | sed -n 's|.*payload ready at \([^ ]*\).*|\1|p' | tail -n 1)
    if [[ -z "$extract_dir" ]]; then
        echo "ERROR ($name): could not parse extraction dir" >&2
        echo "$output" >&2
        exit 1
    fi

    if [[ "$extract_dir" != "$expected_root" ]]; then
        echo "ERROR ($name): extraction dir mismatch" >&2
        echo "  expected: $expected_root" >&2
        echo "  actual:   $extract_dir" >&2
        echo "$output" >&2
        exit 1
    fi

    if [[ ! -f "$extract_dir/bin/app" ]]; then
        echo "ERROR ($name): payload not extracted to expected root" >&2
        echo "$output" >&2
        exit 1
    fi

    # Context print should show resolved payload_root and args containing it
    if ! echo "$output" | grep -q "payload_root: *$expected_root"; then
        echo "ERROR ($name): context print missing payload_root $expected_root" >&2
        echo "$output" >&2
        exit 1
    fi
    if ! echo "$output" | grep -q "\\[0\\]: --arg=$expected_root"; then
        echo "ERROR ($name): entry_args not substituted" >&2
        echo "$output" >&2
        exit 1
    fi
    if ! echo "$output" | grep -q "\\[0\\]: --post=$expected_root"; then
        echo "ERROR ($name): entry_args_post not substituted" >&2
        echo "$output" >&2
        exit 1
    fi
    if ! echo "$output" | grep -q "DEST=$expected_root"; then
        echo "ERROR ($name): ENV DEST not substituted" >&2
        echo "$output" >&2
        exit 1
    fi
}

HOME_META="$WORKDIR/home_meta"
HOME_ENV="$WORKDIR/home_env"
HOME_CLI="$WORKDIR/home_cli"

EXPECTED_META="$HOME_META/.piadina/cache_tpl/payload_tpl"
EXPECTED_ENV="$WORKDIR/cache_env/payload_tpl"
EXPECTED_CLI="$WORKDIR/cache_cli/payload_tpl"

mkdir -p "$HOME_META" "$HOME_ENV" "$HOME_CLI"

run_case "metadata defaults" "$HOME_META" "" "" "$EXPECTED_META"
run_case "env override" "$HOME_ENV" "$WORKDIR/cache_env" "" "$EXPECTED_ENV"
run_case "cli override" "$HOME_CLI" "$WORKDIR/cache_env2" "$WORKDIR/cache_cli" "$EXPECTED_CLI"

echo "PASS: cache/payload overrides and templating"
