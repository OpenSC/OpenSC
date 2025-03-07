#!/bin/bash

softokn_paths=(
    "/usr/lib64/libsoftokn3.so" # Fedora
    "/usr/lib/x86_64-linux-gnu/libsoftokn3.so" # Ubuntu
)
P11LIB=""
for lib in "${softokn_paths[@]}"; do
    if [ -f "$lib" ]; then
        echo "Using softokn path $lib"
        P11LIB="$lib"
        break
    fi
done
if [ -z "$P11LIB" ]; then
    echo "Unable to find softokn PKCS#11 library"
    exit 1
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
	export PKCS11_TOOL="pkcs11-tool"
	export PUB_ARGS=("--module=${P11LIB}" "--token-label=${TOKENLABEL}")
	export PRIV_ARGS=("${PUB_ARGS[@]}" "--login" "--pin=${PINVALUE}")
}

function token_cleanup() {
	rm -fr "${TMPPDIR}"
	sleep 1
}
