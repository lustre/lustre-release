#!/bin/bash
# Adds Intel copyright notices to files modified by Intel.
# Does not add copyright notices to files that are missing them.
#
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2012, 2014, Intel Corporation.
#
TMP=${TMP:-/tmp}
TMPFILE=$(mktemp $TMP/updatecopy.XXXXXX)
EXCFILE=$(mktemp $TMP/excludecopy.XXXXXX)
THISYEAR=$(date +%Y)
DIRS=${*:-"build ldiskfs libcfs lnet lustre lustre-iokit snmp"}

#Old copyright messages we might need to find
OLDCOPY1="Copyright.*"
OLDCOPY2="Use is subject to license terms."
#The current copyright
INTCOPY=${INTCOPY:-"Copyright.*Intel Corporation"}

#Emails we assume ownership of
AUTH_WHAM=${AUTH_WHAM:-".*@whamcloud.com"}
AUTH_INT=${AUTH_INT:-".*@intel.com"}

#Post Oracle date
START=${START:-"2010-06-01"}
ECHOE=${ECHOE:-"echo -e"}
[ "$($ECHOE foo)" = "-e foo" ] && ECHOE=echo

#Commits to exclude (whitespace, copyright, prefix, revert, delete only, etc)
cat << EXCLUDE_END > $EXCFILE
003df3c38fe74a092f75569793edd6ec5a387d5c
01def2b635ff0b7bacde158d9124334c42cd5d2b
08aa217ce49aba1ded52e0f7adb8a607035123fd
11db1a551172f596d1d284e8496530f9ce24ac81
14d162c5438de959d0ea01fb1b40a7c5dfa764d1
1f1d3a376d488d715dd1b0c94d5b66ea05c1e6ca
27bc60aa7cb3c567fd3150cc55a133d60cec2405
2841be335687840cf98961e6c6cde6ee9312e4d7
317ebf88af58e9d9235c90f84b112e931ae69b43
320e014a2c93cb905637d178269b80847cb8d277
3f90f344ae059b30e7d23e4fe554a985eb827b02
4df63615669a69b51c752cc4e416f705f8a56197
5d37670e8507563db556879041c7992936aefa56
60e07b972114df24105a3a1bfa7365892f72a4a7
65701b4a30efdb695776bcf690a2b3cabc928da1
98060d83459ba10409f295898f0ec917f938b4d3
b1e595c09e1b07a6840142b3ae015b8a5a8affeb
b529a917a48cb0873f2898348b25a1074d7e9429
b5a7260ae8f96c3ff9a9948dacc4f17a46943d00
c2c14f31da5f69770d3a46627c81335f5b8d7821
cd8c65642f1c36b56ae74a0414a1f1f27337a662
e3a7c58aebafce40323db54bf6056029e5af4a70
e5f552b70dccbd2fdf21ec7b7053a01bcbe062c2
e64d9101cc8ebc61924d6e9db6d7ab3cfa94767c
f2a9374170e4522b9d2ac3b7096cf2912339d480
fc1475ebdd64cd8eccc603d629ac6b4dcd222445
EXCLUDE_END
[ -n "$EXCLUDE" ] && echo "$EXCLUDE" >> $EXCFILE

HASHFILE=$TMP/hash_list
> $TMP/hash_list
git ls-files $DIRS | while read FILE; do
	FILE=$FILE # just so FILE shows up in "sh -vx" output
	case "$FILE" in
	*/list.h)
		# file is copied from upstream kernel
		continue ;;
	*/liblustreapi.h)
		# file just includes lustreapi.h, copyrights are in there
		continue ;;
	*/*.patch|*/*.series)
		# patches can't add copyrights easily
		continue ;;
	*/lustre_dlm_flags.h)
		# file is automatically generated
		continue ;;
	*/.gitignore)
		continue ;;
	esac

	OLDCOPY=$(egrep "$INTCOPY" $FILE | tail -n1)
	# Skip files that already have a copyright for this year
	[ -n "$(egrep -e $THISYEAR <<<"$OLDCOPY")" ] && continue

	ADDCOPY=false
	# Pick only files that have changed since $START
	# %ai author dates holds has bad data, use %ci instead
	# Exclude revert commits and the patch being reverted.
	git log --follow --since=$START --pretty=format:"%ci %ae %H" $FILE |
		grep -v -f $EXCFILE | egrep -e "$AUTH_INT|$AUTH_WHAM" |
		while read YYYY TTTT TZZZ AUTHOR HASH; do
			REVERT=$(git show -s $HASH |
				 awk '/This reverts commit/ { print $4 }')
			if [ -n "$REVERT" ]; then
				echo $HASH >> $EXCFILE
				tr -d . <<<$REVERT >> $EXCFILE
				continue
			fi
			echo "$YYYY $TTTT $TZZZ $AUTHOR $HASH"
		done > $TMPFILE.2
	grep -v -f $EXCFILE $TMPFILE.2 > $TMPFILE

	# Skip files not modified by $AUTHOR
	[ -s "$TMPFILE" ] || continue

	if [ -z "$(egrep -e "$OLDCOPY1" $FILE)" ]; then
		case $FILE in
		*.[ch])
			echo "$FILE: ** NO COPYRIGHT. INSPECT  **"
			continue ;;
		*)
			continue ;;
		esac
	fi

	if [ -z "$(grep "$INTCOPY" <<<"$OLDCOPY")" ]; then
		ADDCOPY=true
		OLDCOPY="$(egrep "$OLDCOPY1|$OLDCOPY2" $FILE| tail -n1| tr / .)"
	fi
	if [ -n "$(grep "Commissariat" <<<"$OLDCOPY")"]; then
		INSPECT="** INSPECT **"
	else
		INSPECT=""
	fi

	# Get commit dates
	NEWYEAR=$(head -1 $TMPFILE | cut -d- -f 1)
	OLDYEAR=$(tail -1 $TMPFILE | cut -d- -f 1)

	if [ "$NEWYEAR" -lt "$OLDYEAR" ]; then
		echo "$FILE: ** YEAR INVERSION: INSPECT  **"
		continue;
	fi

	[ $NEWYEAR == $OLDYEAR ] && YEAR="$NEWYEAR" || YEAR="$OLDYEAR, $NEWYEAR"
	# The man page comment .\" needs to be escaped, and the '\' reinforced
	COMMENT=$(sed -e 's/^\( *[\*#\.\"\\]*\) *[A-Z(].*/\1/' -e 's/\\/\\\\/' \
		  <<<"$OLDCOPY")
	NEWCOPY=$(sed -e"s/^/$COMMENT /" -e"s/\.\*/ (c) $YEAR, /" -e's/\.*$//' \
		  <<<"$INTCOPY").

	# '.\"' as a COMMENT in a man page isn't escaped correctly
	#case "$FILE" in
	#*/*.[1-9])
	#	echo "$FILE: *** EDIT MANUALLY ***"
	#	continue ;;
	#esac

	# If copyright is unchanged (excluding whitespace), we're done
	[ "$OLDCOPY" == "$NEWCOPY" ] && continue

	# Log all changes this year, to help find "noisy" patches
	awk '/'$THISYEAR'-/ { print $5 }' $TMPFILE >> $HASHFILE

	[ ! -w $FILE ] && echo "$FILE: *** can't write, EDIT MANUALLY ***" &&
		continue

	if $ADDCOPY; then
		echo "$FILE: Copyright $YEAR (new Copyright added) $INSPECT"
		# Add a new copyright line after the existing copyright.
		# Using a temporary file is ugly, but I couldn't get
		# newlines into the substitution pattern for some reason,
		# and this is not a performance-critical process.
		$ECHOE "${COMMENT}\n${NEWCOPY}" > $TMPFILE
		# The man page comment .\" (currently .") needs '\' added back
		sed -e "/$OLDCOPY/r $TMPFILE"
		    -e 's/^\."/.\\"/' $FILE > $FILE.tmp
	else
		echo "$FILE: Copyright $YEAR $INSPECT"
		# Replace the old copyright line with a new copyright
		# The man page comment .\" (currently .") needs '\' added back
		sed -e "s/.*$INTCOPY.*/$NEWCOPY/" \
		    -e 's/^\."/.\\"/' $FILE > $FILE.tmp
	fi
	[ -s $FILE.tmp ] && cp $FILE.tmp $FILE && rm -f $FILE.tmp
#exit
done
if [ -s $HASHFILE ]; then
	echo "commits causing the most changes"
	sort $HASHFILE | uniq -c | sort -nr | head -20
fi
rm -f $TMPFILE $TMPFILE.2
