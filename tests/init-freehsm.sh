#!/bin/bash

# set paths
freehsm_paths="$FREEHSM_LIB \
	$BUILD_PATH/freehsm/libfreehsm.so \
	/usr/local/lib/libfreehsm.so \
	/usr/lib64/pkcs11/libfreehsm.so \
	/usr/lib/pkcs11/libfreehsm.so"

for LIB in $freehsm_paths; do
	echo "Testing $LIB"
	if [[ -f $LIB ]]; then
		export P11LIB=$LIB
		echo "Setting P11LIB=$LIB"
		break
	fi
done
if [[ -z "$P11LIB" ]]; then
	echo "Warning: Could not find the FreeHSM PKCS#11 module"
fi

# A build from source is not signed, so the module skips its integrity check
# and serves every mechanism from OpenSSL's default provider. "permissive" lets
# it run the ones NIST has not approved (RSA-PKCS, SHA-1, ...), as the tests
# expect of a software token.
export FHSM_INTEGRITY_ALLOW_UNSIGNED=1
export FHSM_MODE=permissive

function initialize_token() {
	# FreeHSM refuses a token directory that others can read
	TMPPDIR="${FREEHSM_TMPDIR:-freehsm.tmp}"
	if [ -d "${TMPPDIR}" ]; then
		rm -fr "${TMPPDIR}"
	fi
	mkdir -p "${TMPPDIR}/tokens"
	chmod -R 700 "${TMPPDIR}"
	export FHSM_TOKENS_DIR=$(realpath "$TMPPDIR/tokens")
	export TOKENCONFIGVARS="export FHSM_TOKENS_DIR=$FHSM_TOKENS_DIR FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_MODE=permissive"
	export TOKENLABEL="FreeHSM Token"

	# init token
	$PKCS11_TOOL --module "${P11LIB}" --init-token \
		--label "${TOKENLABEL}" --so-pin "${PIN}"
	# set pin
	$PKCS11_TOOL --module "${P11LIB}" --so-pin "${PIN}" \
		--login --login-type so --init-pin --pin "${PIN}"

	export PUB_ARGS=("--module=${P11LIB}" "--token-label=${TOKENLABEL}")
	export PRIV_ARGS=("${PUB_ARGS[@]}" "--login" "--pin=${PIN}")
}

function token_cleanup() {
	rm -fr "${TMPPDIR}"
	sleep 1
}
