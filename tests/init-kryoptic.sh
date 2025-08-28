#!/bin/bash

# set paths
kryoptic_paths="$BUILD_PATH/kryoptic/target/debug/libkryoptic_pkcs11.so"

for LIB in $kryoptic_paths; do
	echo "Testing $LIB"
	if [[ -f $LIB ]]; then
		export P11LIB=$LIB
		echo "Setting P11LIB=$LIB"
		break
	fi
done
if [[ -z "$P11LIB" ]]; then
	echo "Warning: Could not find the Kryoptic PKCS#11 module"
fi

function initialize_token() {
	TMPPDIR="$BUILD_PATH/kryoptic/tmp"
	export TOKDIR="$TMPPDIR/tokens"
	if [ -d "${TMPPDIR}" ]; then
		rm -fr "${TMPPDIR}"
	fi
	mkdir -p "${TMPPDIR}"
	mkdir "${TOKDIR}"

	export KRYOPTIC_CONF="${KRYOPTIC_CONF:-$TOKDIR/kryoptic.sql}"
	export TOKENCONFIGVARS="export KRYOPTIC_CONF=$TOKDIR/kryoptic.sql"
	export TOKENLABEL="Kryoptic Token"

	# init token
	$PKCS11_TOOL --module "${P11LIB}" --init-token \
		--label "${TOKENLABEL}" --so-pin "${PIN}"
	# set pin
	$PKCS11_TOOL --module "${P11LIB}" --so-pin "${PIN}" \
		--login --login-type so --init-pin --pin "${PIN}"

	export PUB_ARGS=("--module=${P11LIB}" "--token-label=${TOKENLABEL}")
	export PRIV_ARGS=("${PUB_ARGS[@]}" "--login" "--pin=${PIN}")
	export PRIV_ARGS_KRYOPTIC=("${PRIV_ARGS[@]}")
}

function token_cleanup() {
	rm -fr "${TMPPDIR}"
	sleep 1
}
