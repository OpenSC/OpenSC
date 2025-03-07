#!/bin/bash

# set paths
KRYOPTIC_PWD="$BUILD_PATH/kryoptic/target/debug/libkryoptic_pkcs11.so"
if test -f "$KRYOPTIC_PWD" ; then
	echo "Using kryoptic path $KRYOPTIC_PWD"
	P11LIB="$KRYOPTIC_PWD"
else
	echo "Kryoptic not found"
	exit 0
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
}

function token_cleanup() {
	rm -fr "${TMPPDIR}"
	sleep 1
}
