#!/bin/sh -e 
CVS=${CVS:-cvs}

if [ $# != 2 ]; then
    echo "This creates a new branch in CVS. Usage: $0 parent child"
    exit
fi

parent=$1
child=$2
CHILD=`echo $child | sed -e "s/^b_//" | tr "[a-z]" "[A-Z]"`
module=lustre

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

if [ "$parent" != "HEAD" -a "`cat CVS/Tag`" != "T$parent" ]; then
	echo "This script must be run within the $parent branch"
	exit 1
fi

echo parent: $parent CHILD: $CHILD child: $child date: $date

echo -n "tagging $parent as '${CHILD}_BASE' ...."
$CVS rtag -r $parent ${CHILD}_BASE $module
echo "done"
echo -n "branching $child at ${CHILD}_BASE' ...."
$CVS rtag -b -r ${CHILD}_BASE $child $module
echo -n "updating to $child ...."
$CVS update -r $child
echo "done"
