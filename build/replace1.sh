#!/bin/sh -e 

progname=${0##*/}

CONFLICTS=cvs-merge-conflicts
CVS=cvs

if [ -f .mergeinfo ] ; then
    echo ".mergeinfo exists - clean up first"
    exit 
fi

if [ -f $CONFLICTS ] ; then
    echo "$CONFLICTS exists - clean up first"
    exit 
fi

if [ $# -lt 2 -o $# -gt 3 ]; then
    echo "This is phase 1 of replacing branches. Usage: $0 parent(old) child(new) [dir]"
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
    echo >&2 "${progname}: You probably want to land lustre or lnet, not the whole tree."
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

if [ "$parent" != "HEAD" -a "`cat $dir/CVS/Tag 2> /dev/null`" != "T$parent" ]; then
        echo "${progname}: this script must be run within the $parent branch"
	exit 1
fi

TEST_FILE=${TEST_FILE:-ChangeLog} # does this need to be smarter?
check_tag() {
	[ -z "$1" ] && echo "check_tag() missing arg" && exit3
	[ "$1" = "HEAD" ] && return
	$CVS log ${dir%%/*}/$TEST_FILE 2> /dev/null | grep -q "	$1: " && return
	echo "${progname}: tag $1 not found in $dir/$TEST_FILE"
	exit 2
}

check_tag $child
check_tag ${CHILD}_BASE

cat << EOF > ".mergeinfo"
parent=$parent
PARENT=$PARENT
child=$child
CHILD=$CHILD
date=$date
module=$module
dir=$dir
CONFLICTS=$CONFLICTS
OPERATION=Replace
OPERWHERE=onto
EOF

echo PARENT $PARENT parent $parent CHILD $CHILD child $child date $date

# Update your tree to the PARENT branch; HEAD is not really a branch, so you
# need to update -A instead of update -r HEAD, or the commit will fail. -p
echo -n "Updating to $parent ...."
if [ $parent == "HEAD" ]; then
  $CVS update -AdP $dir
else
  $CVS update -r $parent -dP $dir
fi
echo "done"

# Tag parent before merge
echo -n "Tagging as ${PARENT}_${CHILD}_REPLACE_PARENT_$date ..."
$CVS tag ${PARENT}_${CHILD}_REPLACE_PARENT_$date $dir
echo "done"

# Tag child before merge
echo -n "Create land point on ${child} ${PARENT}_${CHILD}_REPLACE_CHILD_$date ..."
$CVS tag -r ${child} ${PARENT}_${CHILD}_REPLACE_CHILD_$date $dir
echo "done"

# In case someone tries to re-land later
echo -n "Preserve old base tag ${CHILD}_BASE as ${CHILD}_BASE_PREV ..."
$CVS tag -F -r ${CHILD}_BASE ${CHILD}_BASE_PREV $dir
echo "done"

# Apply all of the changes to your local tree:
echo -n "Updating as -j $parent -j $child ..."
$CVS update -j $parent -j $child $dir
echo "done"

echo -n "Recording conflicts in $CONFLICTS ..."
$CVS update | awk '/^C/ { print $2 }' > $CONFLICTS
if [ -s $CONFLICTS ] ; then
    echo "Conflicts found, fix before committing."
    cat $CONFLICTS
fi

$CVS diff --brief -r $CHILD $dir >> $CONFLICTS  
if [ -s $CONFLICTS ] ; then
    echo "Danger! The child branch $CHILD differs from the updated branch $dir"
    cat $CONFLICTS
else 
    echo "No conflicts found"
    rm -f $CONFLICTS
fi

echo "done"

echo "Build, test, commit and then run replace2.sh (no arguments)"
