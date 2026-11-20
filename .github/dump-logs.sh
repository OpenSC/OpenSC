SUFFIX=$1
if [ -n "$SUFFIX" ]; then
	REL="opensc-*$SUFFIX/_build/sub/"
fi

echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
for F in ${REL}tests/*.log ${REL}src/tests/unittests/*.log; do
	[ -f "$F" ] || continue
	TRS="${F%.log}.trs"
	RES=""
	if [ -f "$TRS" ]; then
		RES=$(awk '/^:global-test-result:/ { print $2; exit }' "$TRS")
		if [ -z "$RES" ]; then
			if grep -q -E '^:test-result:[[:blank:]]*(FAIL|ERROR)' "$TRS"; then
				RES="FAIL"
			else
				RES=$(awk '/^:test-result:/ { print $2; exit }' "$TRS")
			fi
		fi
	fi

	if [ -n "$RES" ]; then
		echo "::group::[$RES] $F"
	else
		echo "::group::$F"
	fi

	if [ "$RES" = "FAIL" ] || [ "$RES" = "ERROR" ] || [ "$RES" = "XPASS" ]; then
		cat "$F"
	else
		tail -n50 "$F"
	fi
	echo "::endgroup::"
done
echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
