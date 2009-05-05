#!/bin/bash -e 

CONFLICTS=cvs-merge-conflicts
CVS="cvs -z3"

if [ -f .mergeinfo ] ; then
    echo ".mergeinfo exists - clean up first"
    exit 
fi

if [ -f $CONFLICTS ] ; then
    echo "$CONFLICTS exists - clean up first"
    exit 
fi

if [ $# -lt 2 -o $# -gt 3 ]; then
    echo "This is phase 1 of merging branches. Usage: $0 parent child dir"
    exit
fi

parent=$1
PARENT=`echo $parent | sed -e "s/^b_//" | tr "[a-z]" "[A-Z]"`
child=$2
CHILD=`echo $child | sed -e "s/^b_//" | tr "[a-z]" "[A-Z]"`
date=`date +%Y%m%d_%H%M`

dir=${3:-.}
module=$(basename $(<$dir/CVS/Repository))

if [ "$module" = "lustre" ] ; then
    echo >&2 "${progname}: You probably want to merge lustre or portals, not the whole tree."
    echo >&2 "${progname}: Try using ${0} $parent $child lustre"
    exit 1
fi


case $parent in
  HEAD) : ;;
  b_*|b[1-4]*) : ;;
  *) parent="b_$parent" ;;
esac
case $child in
  HEAD) : ;;
  b_*|b[1-4]*) : ;;
  *) child="b_$child"
esac

if [ "$child" != "HEAD" -a "`cat $dir/CVS/Tag 2> /dev/null`" != "T$child" ]; then
	echo "This script must be run within the $child branch"
	exit 1
fi

TEST_FILE=${TEST_FILE:-ChangeLog} # does this need to be smarter?
[ $dir = "build" ] && TEST_FILE=lbuild
check_tag() {
	[ -z "$1" ] && echo "check_tag() missing arg" && exit3
	[ "$1" = "HEAD" ] && return
	$CVS log $dir/$TEST_FILE 2> /dev/null | grep -q "	$1: " && return
	echo "$0: tag $1 not found in $dir/$TEST_FILE"
	exit 2
}

check_tag $parent
check_tag ${CHILD}_BASE

cat << EOF > .mergeinfo
parent=$parent
PARENT=$PARENT
child=$child
CHILD=$CHILD
date=$date
dir=$dir
module=$module
CONFLICTS=$CONFLICTS
OPERATION=Merge
OPERWHERE=from
EOF

echo PARENT: $PARENT parent: $parent CHILD: $CHILD child: $child date: $date

echo -n "tagging $parent as '${PARENT}_${CHILD}_UPDATE_PARENT_$date' ...."
$CVS rtag -r $parent ${PARENT}_${CHILD}_UPDATE_PARENT_$date $module
echo "done"
echo -n "tagging $child as '${PARENT}_${CHILD}_UPDATE_CHILD_$date' ...."
$CVS rtag -r $child ${PARENT}_${CHILD}_UPDATE_CHILD_$date $module
echo "done"

# Apply all of the changes to your local tree:
echo "Updating: -j ${CHILD}_BASE -j ${PARENT}_${CHILD}_UPDATE_PARENT_$date ...."
$CVS update -j ${CHILD}_BASE -j ${PARENT}_${CHILD}_UPDATE_PARENT_$date -dP $dir
echo "done"

echo -n "Recording conflicts in $CONFLICTS ..."
$CVS update | awk '/^C/ { print $2 }' > $CONFLICTS
if [ -s $CONFLICTS ] ; then
    echo "Conflicts found, fix before committing."
    cat $CONFLICTS
else 
    echo "No conflicts found"
    rm -f $CONFLICTS
fi
echo "done"

echo "Build, test, commit and then run merge2.sh (no arguments)"
