#!/bin/bash

SOURCE_PATH=${SOURCE_PATH:-..}


softhsm_paths="/usr/local/lib/softhsm/libsofthsm2.so \
	/usr/lib/softhsm/libsofthsm2.so \
	/usr/lib64/pkcs11/libsofthsm2.so \
	/usr/lib/i386-linux-gnu/softhsm/libsofthsm2.so \
	/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"

for LIB in $softhsm_paths; do
	echo "Testing $LIB"
	if [[ -f $LIB ]]; then
		export P11LIB=$LIB
		echo "Setting P11LIB=$LIB"
		break
	fi
done
if [[ -z "$P11LIB" ]]; then
	echo "Warning: Could not find the SoftHSM PKCS#11 module"
fi

function initialize_token() {
	echo "directories.tokendir = $(realpath .tokens)" > .softhsm2.conf
	if [ -d ".tokens" ]; then
		rm -rf ".tokens"
	fi
	mkdir ".tokens"

	export SOFTHSM2_CONF=$(realpath ".softhsm2.conf")
	softhsm2-util --init-token --slot 0 --label "SC test" --so-pin="$SOPIN" --pin="$PIN"

	export PUB_ARGS=("--module=${P11LIB}")
	export PRIV_ARGS=("${PUB_ARGS[@]}" "--login" "--pin=${PIN}")
	export PRIV_ARGS_SOFTHSM=("${PRIV_ARGS[@]}")
}

function token_cleanup() {
	rm .softhsm2.conf
	rm -rf ".tokens"
	sleep 1
}
