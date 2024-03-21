#!/bin/bash

#
# To be sourced to the test scripts to run the OpenSC tools under valgrind
#
if [ "$1" == "valgrind" -o "$2" == "valgrind" ]; then
	# the glib raises dozens of memory related issues so we will rebuild opensc without notify support
	./configure --disable-notify
	make clean && make -j 4 V=1

	# suppression file contains supressions for softhsm providing us with uninitialized mechanism flags
	# https://github.com/opendnssec/SoftHSMv2/commit/f94aaffc879ade97a51b8e1308af42f86be1885f
	export VALGRIND="valgrind -q --error-exitcode=1 --leak-check=full --keep-debuginfo=yes --trace-children=yes --gen-suppressions=all --suppressions=$PWD/tests/opensc.supp"
	# this should help us getting better traces as some of pcsclite and avoid false positives
	export LD_PRELOAD="/usr/lib/x86_64-linux-gnu/libpcsclite.so.1"
fi
