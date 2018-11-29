#!/bin/bash
SOURCE_PATH=../

# find all the manual pages in src/tools
TOOLS=`find "${SOURCE_PATH}/doc/tools" -name "*.1.xml" | sed -E -e "s|.*/([a-z0-9-]*).*|\1|"`
ALL=1

for T in $TOOLS; do
	SWITCHES=$( ${SOURCE_PATH}/src/tools/${T} --help 2>&1 \
		    | grep -v "unrecognized option '--help'" \
		    | awk '{if (match($0,"--[a-zA-Z0-9-]*",a) != 0) print a[0]}
		           {if (match($0," -[a-zA-Z0-9]",a) != 0) print a[0]}' )

	for S in $SWITCHES; do
		grep -q -- "$S" ${SOURCE_PATH}/doc/tools/${T}.1.xml || { echo "${T}: missing switch $S"; ALL=0; };
	done
done
if [ "$ALL" = 0 ]; then
	echo "Not all the switches in help are documented in manual pages"
	exit 1;
fi
