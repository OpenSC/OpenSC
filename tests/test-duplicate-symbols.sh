#!/bin/bash

if [ -z "$MESON_BUILD_ROOT" ]; then
	SOURCE_PATH=${SOURCE_PATH:-..}
	EXPORTS=`find "${SOURCE_PATH}" -name "*exports"`
else
	EXPORTS=`find "${MESON_BUILD_ROOT}" -name "*symbols"`
fi

ERRORS=0
for E in $EXPORTS; do
	DUPES=`sort $E | uniq -d`
	NUM_DUPES=`echo -n "$DUPES" | wc -l`
	if [ $NUM_DUPES -gt 0 ]; then
		echo "There are $NUM_DUPES duplicate symbols in '$E': $DUPES"
		ERRORS=1
	fi
done

if [[ "$ERRORS" = 1 ]]; then
	echo "There are duplicate symbols"
	exit 1
fi

exit $ERRORS
