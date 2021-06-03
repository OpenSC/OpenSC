#!/bin/bash -x
SOURCE_PATH=${SOURCE_PATH:-../}

# find all the manual pages in doc/tools
TOOLS=`find "${SOURCE_PATH}/doc/tools" -name "*.1.xml" | sed -E -e "s|.*/([a-z0-9-]*).*|\1|" | grep -v goid-tool`
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
	exit 1
fi

RES=0
# find all tools in src/tools (files without extension)
TOOLS=`find "${SOURCE_PATH}/src/tools" -maxdepth 1 -type f ! -name "*.*" | sed -E -e "s|.*/([a-z0-9-]*).*|\1|" | grep -v -- -example`
for T in $TOOLS; do
	if [[ ! -f "${SOURCE_PATH}/doc/tools/$T.1.xml" ]]; then
		echo "Missing manual page for '$T'"
		RES=1
	fi
done

exit $RES
