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
AUTHOR=${AUTHOR:-$AUTH_INT|$AUTH_WHAM}

START=${START:-"2010-06-01"}	# Post Oracle date
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
b6332b5c0dfe28d6b574e206ae651262337a8309
5acebd778f7427e8221e2cd6e463c76649f83ad3
2b294992edce5af7b79d4300ed3aa1ea6a8db850
21d716e6c16424d9deb646456758ebbaa9c70fec
3c1f519956598b0106bd639f0ccae30ce745eb54
faeb94fe81e4646b3121c263521d30e0e83fa71f
3b84a1ee5213563945225854a50e9037bb9646db
c6aab2ca77831852db22b7dc39baed4d06405b7e
26b8238659974959780cd49de92595b4b0bdf89f
7817e4c785d075aae76b635dcf799064590833b0
930dca7253bc2531bffa15dc763db1081cdf32d8
d843591c30d63bf54024e21b48dec92eb0ec9f68
1738e70fe6aaf1e07b78a6b89eb11ea115135e69
353ef58b1d2394c4721a340e2463b07d4069d99c
b0638b322b8c8adb2cf5f6189efd17ad70f3af2c
83ae3e2e5b9713822ea4889d832915e791801d90
315f6e0237b676a7512a4d2fa5765ad57483676e
7b63a5dab65cde131627bf22d16d6e13cf259686
6eda93c7b5f65324bdc831100a17c0bef1a3c078
355a283fce6998f5b5621adc9697d98d0fb72dfe
e2d2fbc07bf8f45e19d8f3127c3a7088351126d6
89e685e154daba096c8388e39e279c6e6b342940
4c3858b3c88d2a2f443d348945229f5995f3e1dd
d5d5b349f23e769ae4c6307a295c532856af9c21
be4372fddbada6d026f4188a7e88c6a11d0a83d4
bb6dbca9c2c9bdcd33663d6449b27a671fcaf902
65e067d5d90270d4237a7271008561a4b432b94d
3151aa574e2c9bd3343dad11577cba3c55c16dca
bca975c7fa261ffb926e8a18d5869b886c65f447
8fdb46e476f0f54025fd9ff85c274f2ed86315f0
8f1c8dbe2389e1ef1e1d3387e343fb9a1bb84198
8daba6a7381a2fb8cc933f7e9486f60e659465d4
2bac2cd8f7bf7f31b92e976d500d89b958ab1788
95f85ba9ed5df66a0385755be62254322fc447e1
8f27184b14a192848429e52ac234805c324e1f7a
3dc94d835dc3adf871c3603fc91c08bdd36701ff
25670bb8c21deb64cfbb277bdeeab6e7ee39aa0e
f4b93dff9a8f4a59976ea864c4e3c2c42faa5770
aab1d832130ee5c181cf7e0e5aa555244d150b00
32bd5051a518c57e35f51b7f3c7f739b5ef91b25
9fdef0896b78d85312269e97962d9818b395f57a
fdd5596593050d22feef05ecba6ba53c65cb3397
4817574ad5a31d6dbafc2bd0dfc2b6a33851ea11
55f2a237320f23cb59df23518f5a72698d4f251c
06c83e0109b2e934ac8cbcdcb2a22f184fe546f5
315f6e0237b676a7512a4d2fa5765ad57483676e
63a296c31a51cf8ac29f6e339e5686192da14769
6c0fa97869b568a7af2d21e7e4ed2b440b7dfa27
97da796bd3d9b98f6b65ecce493044a3e7404607
9bf46408b3c2c8b7f939d7000a9e8df38c3fd6ed
eebeee9afa368d62b9a0813652a4c14430bd8e35
ff4357229efe87781e65382c20d3d718ecc3114d
beca050380b592477153fe16b79b7b6bb3aacbf2
6c47e7f99f5fa8884751ac549a45dd3c0b81e7f1
9d06de39731ae16d030cda672ae771496d4f0952
0b1ad400c8f64575292a7ff54a8ce872a124b19e
b1ff338ede34421acfc2cdbfe0dbe7b293ebd3b2
f28cc25929c4e8a111e96b2205a0433542b35e84
2112bc0e8b54832c303008cfe53957b8a0019407
bbee5d1ae941a208d7a07d0348e835ab58ca90ce
dd6623e657032bf34e70446a6d72851c70d605d9
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
		grep -v -f $EXCFILE | egrep -e "$AUTHOR" |
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
	awk '/'$THISYEAR'-/ { print $5 }' $TMPFILE | cut -c1-12 >> $HASHFILE

	[ ! -w $FILE ] && echo "$FILE: *** can't write, EDIT MANUALLY ***" &&
		continue

	if $ADDCOPY; then
		echo "$FILE: $NEWCOPY (newly added) ** INSPECT **"
		# Add a new copyright line after the existing copyright.
		# Using a temporary file is ugly, but I couldn't get
		# newlines into the substitution pattern for some reason,
		# and this is not a performance-critical process.
		$ECHOE "${COMMENT}\n${NEWCOPY}" > $TMPFILE
		# The man page comment .\" (currently .") needs '\' added back
		sed -e "/$OLDCOPY/r $TMPFILE" \
		    -e 's/^\."/.\\"/' $FILE > $FILE.tmp
	else
		if grep -q "Commissariat" <<<"$OLDCOPY"; then
			INSPECT="** INSPECT **"
		else
			INSPECT=""
		fi
		echo "$FILE: $NEWCOPY $INSPECT"
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
	sort $HASHFILE | uniq -c | sort -nr | head -30 | while read CNT HASH; do
		echo $CNT $(git show --oneline --no-patch $HASH)
	done

fi
rm -f $TMPFILE $TMPFILE.2
