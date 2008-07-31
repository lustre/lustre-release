#!/bin/bash
# diffatt.sh - generate inspection template for attachment
if [ -z "$1" ]; then
	cat - 1>&2 <<- USAGE
	usage: $0 [-k] {attachment} [attachment ...]
	   -k:  keep attachment(s) for editing (delete otherwise)
	   attachment is an attachment number or a local patch filename
	USAGE
	exit 1
fi

export LANG=C
BUGZILLA=https://bugzilla.lustre.org/attachment.cgi
TMP=${TMP:-/tmp}

[ "$1" = "-k" ] && KEEP=yes && shift

FILE=$(mktemp -t)

for ATT in $*; do
	DO_KEEP=$KEEP
	if [ -f "$ATT" ]; then
		PATCH=$ATT
		BUG=N
		DO_KEEP=yes
	else
		BUG=$(wget --no-check-certificate -O - \
			$BUGZILLA?id=$ATT\&action=edit 2> /dev/null |
			perl -nle 'print $1 if /Details for Bug (\d+)/' -)
		PATCH=$TMP/att$ATT.patch
		wget --no-check-certificate -O $PATCH \
			$BUGZILLA?id=$ATT 2> /dev/null
	fi

	grep "not authorized" $PATCH && continue

	diffstat $PATCH | tee $FILE
	LOC=$(awk '/insertion/ { print $4 }' $FILE)
	[ -z "$LOC" ] && LOC=$(awk '/deletion/ { print $4 }' $FILE)

	# if it isn't a patch, just count all of the lines
	[ -z "$LOC" ] && $(grep -q "0 files changed" $FILE) &&
		LOC=$(cat $PATCH | wc -l)

	tee -a $PATCH <<- EOF
		Inspection Type: CODE
		Defect Count: N
		Size: $LOC LOC
		Developer: @sun.com
		Inspector: $USER@sun.com
		Inspection duration: N min
		Bug: $BUG
		Date: $(date +%Y-%m-%d)
	EOF

	[ "$DO_KEEP" = "yes" ] || rm $PATCH
done
