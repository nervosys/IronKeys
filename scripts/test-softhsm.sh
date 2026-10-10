#!/bin/bash
# Run the PKCS#11 provider's tests against a fresh SoftHSM token.
# Needs softhsm2 (softhsm2-util and libsofthsm2.so) and cargo.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/tokens"
cat > "$work/softhsm2.conf" <<CONF
directories.tokendir = $work/tokens
objectstore.backend = file
log.level = ERROR
CONF
export SOFTHSM2_CONF="$work/softhsm2.conf"
softhsm2-util --init-token --free --label ironkeys-test --pin 123456 --so-pin 12345678 >/dev/null
module=""
for candidate in /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib64/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so; do
    if [ -f "$candidate" ]; then module=$candidate; break; fi
done
[ -n "$module" ] || { echo "libsofthsm2.so not found" >&2; exit 1; }
export IRONKEYS_TEST_PKCS11_MODULE="$module"
export IRONKEYS_TEST_PKCS11_SERIAL=$(softhsm2-util --show-slots | awk '/Serial number:/ {print $3; exit}')
export IRONKEYS_TEST_PKCS11_PIN=123456
# The token test returns early without these variables; require that it ran.
cargo test --locked --features pkcs11,software -p ironkeys -- --exact \
    pkcs11::tests::a_token_key_signs_and_agrees_without_leaving_the_token --nocapture
cargo test --locked -p ironkeys-pkcs11
