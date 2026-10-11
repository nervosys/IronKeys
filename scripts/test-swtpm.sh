#!/bin/bash
# Run the TPM 2.0 provider's tests against a fresh swtpm software TPM.
# Needs swtpm and swtpm-tools (swtpm_setup) and cargo. The TPM's state lives
# in a temporary directory removed on exit. Auth values in the tests are
# public test data.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
cleanup() {
    [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT
mkdir "$work/state"
swtpm_setup --tpm2 --tpmstate "$work/state" >/dev/null
port="${SWTPM_PORT:-2331}"
swtpm socket --tpm2 --tpmstate "dir=$work/state" --flags startup-clear \
    --server "type=tcp,port=$port" --ctrl "type=tcp,port=$((port + 1))" \
    --daemon --pid "file=$work/swtpm.pid"
pid=$(cat "$work/swtpm.pid")
export IRONKEYS_TEST_TPM="swtpm:port=$port"
# The device test returns early without that variable; require that it ran.
# One thread: the tests share one TPM.
RUST_TEST_THREADS=1 cargo test --locked --features tpm2 -p ironkeys -- --exact \
    tpm2::tests::a_tpm_key_signs_and_agrees_and_is_bound_to_its_auth_and_role --nocapture
RUST_TEST_THREADS=1 cargo test --locked -p ironkeys-tpm2 --features device
