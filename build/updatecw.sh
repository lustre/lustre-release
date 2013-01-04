#!/bin/bash
# Adds Whamcloud copyright notices to files modified by Whamcloud.
# Does not add copyright notices to files that are missing them
#
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2012, Intel Corporation.
#
TMP=${TMP:-/tmp}
TMPFILE=$(mktemp $TMP/updatecopy.XXXXXX)
EXCFILE=$(mktemp $TMP/excludecopy.XXXXXX)
NOW=$(date +%Y)
DIRS=${DIRS:-"build ldiskfs libcfs lnet lustre snmp lustre-iokit"}
#Commits to exclude
EXCLUDE=${EXCLUDE:-'e3a7c58aebafce40323db54bf6056029e5af4a70\n
65701b4a30efdb695776bcf690a2b3cabc928da1\n
f2a9374170e4522b9d2ac3b7096cf2912339d480\n
3f90f344ae059b30e7d23e4fe554a985eb827b02\n
320e014a2c93cb905637d178269b80847cb8d277\n
cd8c65642f1c36b56ae74a0414a1f1f27337a662'}

XYRACOPY="Copyright.*Xyratex Technology Limited"
ORACOPY1="Copyright.*Oracle.*"
ORACOPY2="Use is subject to license terms."
#Copyright we rewrite to the current version
WHAMCOPY=${WHAMCOPY:-"Copyright.*Whamcloud,* Inc."}
INTREPCOPY=${INTREPCOPY:-"Copyright.*Intel, Inc."}
INTREPCOPY2=${INTREPCOPY2:-"Copyright.*Intel Corporation$"}
#The current copyright
INTCOPY=${INTCOPY:-"Copyright.*Intel Corporation."}

#Emails we assume ownership of
AUTH_WHAM=${AUTH_WHAM:-".*@whamcloud.com"}
AUTH_INT=${AUTH_INT:-".*@intel.com"}

#Post Oracle date
START=${START:-"2010-06-01"}
ECHOE=${ECHOE:-"echo -e"}
[ "$($ECHOE foo)" = "-e foo" ] && ECHOE=echo

echo -e $EXCLUDE > $EXCFILE

git ls-files $DIRS | grep -v ${0##*/} | while read FILE; do
#FILE=lustre/mdt/mdt_hsm.c
#FILE=lustre/include/lustre_quota.h
 	if [ "$FILE" == 'build/updatecw.sh' ]; then
		echo $FILE": *** EDIT MANUALLY ***"
		continue
	fi

	NEEDCOPY=false
	# Pick only files that have changed since START
	git log --follow --since=$START --author=$AUTH_WHAM --author=$AUTH_INT\
		--pretty=format:"%ai %H" $FILE | grep -v -f $EXCFILE |
		cut -d- -f1 > $TMPFILE
	# Skip files not modified by $AUTHOR
	[ -s "$TMPFILE" ] || continue

	OLDCOPY="$(egrep -e "$XYRACOPY|$ORACOPY1|$ORACOPY2|$WHAMCOPY|$INTCOPY"\
			-e "$INTREPCOPY|$INTREPCOPY2" $FILE|tail -n1 | tr / .)"

	if [ -z "$OLDCOPY" ]; then
		case $FILE in
			*.[ch]) echo "$FILE: ** INSPECT  **" && continue ;;
			*) continue ;;
		esac
	fi
	OLDCOPY=$(egrep "$WHAMCOPY|$INTCOPY|$INTREPCOPY|$INTREPCOPY2"\
							$FILE|tail -n1|tr / .)

	if [ -z "$(egrep "$INTCOPY|$INTREPCOPY|$INTERCOPY2|$WHAMCOPY"\
							<<<"$OLDCOPY")" ];
	then
		NEEDCOPY=true
		OLDCOPY="$(egrep "$XYRACOPY|$ORACOPY1|$ORACOPY2" $FILE |
							tail -n1 | tr / .)"
	elif [ -n "$(grep -e "$INTCOPY" <<<"$OLDCOPY")" ]; then
		# Skip files that already have a copyright for this year
		echo "$OLDCOPY" | grep -q "$NOW" && continue
	fi

	# Get commit dates
	NEWYEAR=$(head -1 $TMPFILE)
	OLDYEAR=$(tail -1 $TMPFILE)

	if [ "$NEWYEAR" -lt "$OLDYEAR" ]; then
		echo "$FILE: ** YEAR INVERSION: INSPECT  **"
		continue;
	fi

	[ $NEWYEAR == $OLDYEAR ] && YEAR="$NEWYEAR" || YEAR="$OLDYEAR, $NEWYEAR"
	COMMENT=$(echo "$OLDCOPY" | sed -e "s/^\( *[^A-Z]*\) [A-Z].*/\1/")
	NEWCOPY=$(sed -e "s/^/$COMMENT /" -e "s/\.\*/ (c) $YEAR, /" <<<$INTCOPY)

	# '.\"' as a COMMENT isn't escaped correctly
	if [ "$COMMENT" == ".\\\"" ]; then # add " to fix vim
		echo "$FILE: *** EDIT MANUALLY ***"
		continue
	fi

	# If copyright is unchanged (excluding whitespace), we're done
	[ "$OLDCOPY" == "$NEWCOPY" ] && continue

	[ ! -w $FILE ] && echo "Unable to write to $FILE" && exit 1

	if $NEEDCOPY; then
		echo "$FILE: Copyright $YEAR (new Copyright added)"
		# Add a new copyright line after the existing copyright.
		# Using a temporary file is ugly, but I couldn't get
		# newlines into the substitution pattern for some reason,
		# and this is not a performance-critical process.
		$ECHOE "${COMMENT}\n${NEWCOPY}" > $TMPFILE
		sed -e "/$OLDCOPY/r $TMPFILE" $FILE > $FILE.tmp
	else
		echo "$FILE: Copyright $YEAR"
		# Replace the old copyright line with a new copyright
		sed -e "s/.*$INTREPCOPY/$NEWCOPY/" -e "s/.*$INTCOPY/$NEWCOPY/"\
		   -e "s/.*$INTREPCOPY2/$NEWCOPY/" -e "s/.*$WHAMCOPY/$NEWCOPY/"\
							$FILE > $FILE.tmp
	fi
	[ -s $FILE.tmp ] && cp $FILE.tmp $FILE
	rm $FILE.tmp
#exit
done
rm $TMPFILE
