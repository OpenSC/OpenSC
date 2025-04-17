#!/bin/bash

softokn_paths="/usr/lib64/libsoftokn3.so \
	/usr/lib/x86_64-linux-gnu/libsoftokn3.so"

for LIB in $softokn_paths; do
	echo "Testing $LIB"
	if [[ -f $LIB ]]; then
		export P11LIB=$LIB
		echo "Setting P11LIB=$LIB"
		break
	fi
done
if [[ -z "$P11LIB" ]]; then
	echo "Warning: Could not find the Softokn PKCS#11 module"
fi

function initialize_token() {
	TMPPDIR="$BUILD_PATH/softokn"
	export TOKDIR="$TMPPDIR/tokens"
	if [ -d "${TMPPDIR}" ]; then
		rm -fr "${TMPPDIR}"
	fi
	mkdir "${TMPPDIR}"
	mkdir "${TOKDIR}"

	TOKENLABEL="NSS Certificate DB"
	PINVALUE="12345678"
	PINFILE="${TMPPDIR}/pinfile.txt"
	echo ${PINVALUE} > "${PINFILE}"

	certutil -N -d $TOKDIR -f $PINFILE

	export NSS_LIB_PARAMS=configDir=$TMPPDIR/tokens
	export PUB_ARGS=("--module=${P11LIB}" "--token-label=${TOKENLABEL}")
	export PRIV_ARGS=("${PUB_ARGS[@]}" "--login" "--pin=${PINVALUE}")
	export PRIV_ARGS_SOFTOKN=("${PRIV_ARGS[@]}")
}

function token_cleanup() {
	rm -fr "${TMPPDIR}"
	sleep 1
}
