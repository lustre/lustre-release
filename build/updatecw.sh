#!/bin/bash
# Update existing Sun copyright notices to Oracle copyright notices
# Does not add copyright notices to files that are missing them
#
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

TMP=${TMP:-/tmp}
TMPFILE=$(mktemp $TMP/updatecopy.XXXXXX)
NOW=$(date +%Y)

SUNCOPY="Copyright.*Sun Micro.*"
ORACOPY="Copyright.*Oracle.*"
LECDATE="2010-02-15"
 
git ls-files build ldiskfs libcfs lnet lustre snmp |grep -v ${0##*/} | while read FILE; do
    # Pick only files that have changed since LECDATE
    if [ -n "$(git log -n1 --since=$LECDATE  $FILE)" ]; then
	OLDCOPY="$(egrep "$SUNCOPY|$ORACOPY" $FILE | sed 's/.*Copy/Copy/')"
	if [ -z "$OLDCOPY" ]; then
	    case $FILE in
    		*.[ch]) echo "$FILE: no Copyright" && continue ;;
		*) continue ;;
	    esac
	else
	# skip files that already have a copyright for this year
	    echo "$OLDCOPY" | grep -q "$NOW.*Oracle" && continue
	fi

	# Get commit dates
	git log --follow --pretty=format:%ci $FILE | cut -d- -f1 > $TMPFILE
	NEWYEAR=$(head -1 $TMPFILE)
	OLDYEAR=$(tail -1 $TMPFILE)
	rm $TMPFILE

	[ $NEWYEAR == $OLDYEAR ] && YEAR="$NEWYEAR" || YEAR="$OLDYEAR, $NEWYEAR"

	NEWCOPY="Copyright (c) $YEAR, Oracle and/or its affiliates. All rights reserved."

        # If the copyright isn't different (excluding whitespace), don't change it.
	[ "$OLDCOPY" == "$NEWCOPY" ] && continue

	[ ! -w $FILE ] && echo "Unable to write to $FILE" && exit 1

	echo "$FILE: Copyright $YEAR"
	sed -e "s#$ORACOPY#$NEWCOPY#" -e "s#$SUNCOPY#$NEWCOPY#" $FILE > $FILE.tmp
	cp $FILE.tmp $FILE	# preserve owner/mode
	rm $FILE.tmp
    fi
done
