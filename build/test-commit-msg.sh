#!/bin/bash
TEMPFILE=commit_test
\ls -1 $* | egrep -v "\.orig|\.20" | while read FILE; do
	cp $FILE $TEMPFILE
	sh ./build/commit-msg $TEMPFILE 2>&1 | grep -q "^error:"
	OK=$?

	EXPECT=$(echo $FILE | cut -d. -f2)
	case $OK$EXPECT in
	1ok*) echo "$FILE: PASS (was allowed)" ;;
	0ok*) echo "$FILE: FAIL (not allowed)" ;;
	0*) echo "$FILE: PASS (found error)";;
	*) echo "$FILE: FAIL (no error)" ;;
	esac
done

rm -f $TEMPFILE
