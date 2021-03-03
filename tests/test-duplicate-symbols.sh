#!/bin/bash
SOURCE_PATH=../

EXPORTS=`find "${SOURCE_PATH}" -name "*exports"`

ERRORS=0
for E in $EXPORTS; do
	NUM_DUPES=`sort $E | uniq -d | wc -l`
	if [[ "$NUM_DUPES" != 0 ]]; then
		echo "There are duplicate symbols in '$E'"
		ERRORS=1
	fi
done

if [[ "$ERRORS" = 1 ]]; then
	echo "There are duplicate symbols"
	exit 1
fi

exit $ERRORS
