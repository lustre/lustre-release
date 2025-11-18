#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

#
# Folders/ which did not had any warnings to begin with
#
# conf/ contrib/ ec/ include/ kernel_patches/ kunit/ scripts/ tests/
#

folder_lst0="fid/ fld/ fld/ ldlm/ llite/ lfsck/ lmv/ lod/ lov/ mdc/ mdd/ mdt/  \
             mgc/ mgs/ obdclass/ obdecho/ ofd/ osc/ osd-ldiskfs/ osd-zfs/ osp/ \
             ptlrpc/ quota/ target/ utils/"
folder_lst1="lnet/lnet"

KERNEL_DOC=${KERNEL_DOC:-kernel-doc}

BIN="$0"
BINPATH="$(dirname "$(readlink -f "$BIN")")"

TOTAL=0

show_usage()
{
	echo "Usage:"
	echo "$BIN [file.c]"
	echo "Eg: $BIN ./lustre/llite/file.c # for single file (complete path)"
	echo "Eg: $BIN # for all pre-defined folder"
	echo
	echo "Pre-defined folders:"
	echo "$folder_lst0 $folder_lst1"
	exit
}

get_kern_doc_warning()
{
	if (( $# == 3 )); then
		[[ -f "$3" ]] || show_usage

		warn=$($BINPATH/$KERNEL_DOC -v -none ${3} 2>&1 |
		       grep -c warning)
		echo "$3:$warn"
		(( TOTAL += warn ))
	else
		for f in $1; do
			warn=$($BINPATH/$KERNEL_DOC -v -none ${2}/$f/*.c 2>&1 |
			       grep -c warning)
			echo "$warn:$f"
			(( TOTAL += warn ))
		done
	fi
}

#
# main
#
(( $# < 2 )) || show_usage

if (( $# == 1 )); then
	get_kern_doc_warning "$folder_lst0" "$BINPATH/../../lustre/" $1
else
	get_kern_doc_warning "$folder_lst0" "$BINPATH/../../lustre/"
	get_kern_doc_warning "$folder_lst1" "$BINPATH/../../"
fi

echo "$TOTAL : Total"
