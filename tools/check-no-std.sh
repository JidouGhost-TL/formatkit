#!/usr/bin/env bash
# Build every `no_std` + `alloc` crate without its `std` feature.
#
# Each library crate except `formatkit-corpus` and `formatkit-corpus-test` has a
# default `std` feature. For each one, and for every combination of its other
# optional features that does not imply `std`, this runs
#
#   cargo check -p <crate> --no-default-features [--features ...] --target thumbv7em-none-eabi
#
# so nothing from `std` can leak in through the crate or its dependencies. It
# also runs clippy on the host without default features, which catches
# `std`-only code that the bare-metal target would merely skip.
#
# Needs `rustup target add thumbv7em-none-eabi`.
#
# usage: tools/check-no-std.sh [crate...]

set -euo pipefail
cd "$(dirname "$0")/.."

TARGET=${NO_STD_TARGET:-thumbv7em-none-eabi}

# crate -> space-separated feature sets ("" = no optional features). Features that
# enable `std` (`formatkit-codec/lzma`, `formatkit/corpus`) are left out.
declare -A SETS=(
    [formatkit-core]='"" shift-jis libm shift-jis,libm'
    [formatkit-layout]='""'
    [formatkit-catalog]='""'
    [formatkit-runtime]='""'
    [formatkit-pixel]='""'
    [formatkit-codec]='"" dds'
    [formatkit-archive]='""'
    [formatkit-patch]='""'
    [formatkit-gltf]='"" png libm png,libm'
    [formatkit]='"" archive pixel codec patch gltf archive,pixel,codec,patch,gltf'
)
ORDER=(formatkit-core formatkit-layout formatkit-catalog formatkit-runtime formatkit-pixel
    formatkit-codec formatkit-archive formatkit-patch formatkit-gltf formatkit)

if ! rustup target list --installed 2>/dev/null | grep -qx "$TARGET"; then
    echo "error: $TARGET is not installed (rustup target add $TARGET)" >&2
    exit 2
fi

if (($# > 0)); then crates=("$@"); else crates=("${ORDER[@]}"); fi

fail=0
for crate in "${crates[@]}"; do
    [[ -n ${SETS[$crate]+x} ]] || { echo "error: unknown no_std crate $crate" >&2; exit 2; }
    eval "sets=(${SETS[$crate]})"
    for features in "${sets[@]}"; do
        args=(-p "$crate" --no-default-features)
        [[ -z $features ]] || args+=(--features "$features")
        label="$crate [${features:-no optional features}]"
        if cargo check --locked -q "${args[@]}" --target "$TARGET"; then
            echo "ok   $label ($TARGET)"
        else
            echo "FAIL $label ($TARGET)" >&2
            fail=1
        fi
    done
    if cargo clippy --locked -q -p "$crate" --no-default-features -- -D warnings; then
        echo "ok   $crate [host clippy, no default features]"
    else
        echo "FAIL $crate [host clippy, no default features]" >&2
        fail=1
    fi
done

exit $fail
