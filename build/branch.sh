#!/bin/bash -e 
CVS=${CVS:-cvs}

progname=${0##*/}

if [ $# -lt 2 -o $# -gt 3 ]; then
    echo "This creates a new branch in CVS. Usage: $progname parent child <dir>"
    exit
fi

parent=$1
child=$2
CHILD=`echo $child | sed -e "s/^b_//" | tr "[a-z]" "[A-Z]"`
dir=${3:-.}
if [ ! -d $dir ]; then
    echo >&2 "${progname}: directory '$dir' does not exist."
    exit 1
fi
module=$(basename `cat $dir/CVS/Repository`)

if [ "$module" = "lustre" ]; then
    echo >&2 "${progname}: You probably want to branch lustre or lnet."
    echo >&2 "${progname}: Try using ${0} $parent $child lustre"
    exit 1
fi

case $parent in
  HEAD) : ;;
  b_*|b1*) : ;;
  *) parent="b_$parent" ;;
esac
case $child in
  HEAD) : ;;
  b_*|b1*) : ;;
  *) child="b_$child"
esac

#if [ "$parent" != "HEAD" -a -f $dir/CVS/Tag ]; then
	# put in separate condition as bash evaluates all conditions unlike C
#	if [ "`cat $dir/CVS/Tag`" != "T$parent" ]; then
#		echo "This script must be run within the $parent branch"
#		exit 1
#	fi
#fi

echo parent: $parent CHILD: $CHILD child: $child date: $date

echo -n "tagging $parent as '${CHILD}_BASE' ...."
$CVS rtag -r $parent ${CHILD}_BASE $module
echo "done"
echo -n "branching $child at ${CHILD}_BASE' ...."
$CVS rtag -b -r ${CHILD}_BASE $child $module
echo -n "updating $dir to $child ...."
$CVS update -r $child $dir
echo "done"
