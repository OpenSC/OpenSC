SUFFIX=$1
if [ -n "$SUFFIX" ]; then
	REL="opensc-*$SUFFIX/_build/sub/"
fi

echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
for F in ${REL}tests/*.log ${REL}src/tests/unittests/*.log; do
	echo "::group::$F"
	cat $F
	echo "::endgroup::"
done
echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"

