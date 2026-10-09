#!/usr/bin/env bash
# One bounded, low-priority real-corpus run per user across consumer workspaces.
set -euo pipefail

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
    echo 'usage: FORMATKIT_CORPUS_DIR=/path/to/corpus tools/run-corpus-safe.sh CARGO_TEST_ARGS...'
    echo 'Run from the consumer workspace; timeout defaults to 1800 seconds.'
    exit 0
fi
if (($# == 0)) || [[ -z ${FORMATKIT_CORPUS_DIR:-} ]]; then
    echo 'error: specify FORMATKIT_CORPUS_DIR and Cargo test arguments' >&2
    exit 64
fi
if [[ ! -d $FORMATKIT_CORPUS_DIR ]]; then
    echo 'error: FORMATKIT_CORPUS_DIR is not a directory' >&2
    exit 66
fi
for arg in "$@"; do
    if [[ $arg == -- ]]; then
        echo "error: the safe runner owns test arguments after '--'" >&2
        exit 64
    fi
done
timeout_seconds=${FORMATKIT_CORPUS_TIMEOUT_SECONDS:-1800}
if [[ ! $timeout_seconds =~ ^[1-9][0-9]*$ ]]; then
    echo 'error: FORMATKIT_CORPUS_TIMEOUT_SECONDS must be positive' >&2
    exit 64
fi

lock_path=${XDG_RUNTIME_DIR:-/tmp}/formatkit-corpus-${UID}.lock
exec 9>>"$lock_path"
if ! flock -n 9; then
    echo "error: another corpus run owns $lock_path" >&2
    exit 75
fi
printf 'pid=%s\n' "$$" >"$lock_path"
child_pid=
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    if [[ -n $child_pid ]] && kill -0 "$child_pid" 2>/dev/null; then
        kill -TERM -- "-$child_pid" 2>/dev/null || true
        for _ in {1..50}; do
            kill -0 "$child_pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL -- "-$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    : >"$lock_path"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM
export CARGO_BUILD_JOBS=1 FORMATKIT_CORPUS_RUNNER_LOCKED=1
setsid timeout --signal=TERM --kill-after=10s "${timeout_seconds}s" \
    nice -n 10 ionice -c 3 cargo test "$@" -- --test-threads=1 --nocapture &
child_pid=$!
set +e
wait "$child_pid"
status=$?
child_pid=
exit "$status"
