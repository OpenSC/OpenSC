#!/bin/bash

#
# To be sourced to the test scripts to run the OpenSC tools under valgrind
#
if [ "$1" == "valgrind" -o "$2" == "valgrind" ]; then
	# the glib raises dozens of memory related issues so we will rebuild opensc without notify support
	./configure --disable-notify
	make clean && make -j 4 V=1

	# suppression file contains supressions for the notification support which leaks memory
	# The other option would  be to build without the notification support.
	# export VALGRIND="valgrind --error-exitcode=1 --leak-check=full --keep-debuginfo=yes --suppressions=$PWD/tests/opensc.supp"
	export VALGRIND="valgrind -q --error-exitcode=1 --leak-check=full --keep-debuginfo=yes --trace-children=yes --gen-suppressions=all"
	# this should help us getting better traces as some of pcsclite and avoid false positives
	export LD_PRELOAD="/usr/lib/x86_64-linux-gnu/libpcsclite.so.1"
fi
