#!/bin/bash

die() {
	echo -e $* >&2
	echo aborting.. >&2
	exit 1
}

canon() {
	cd $1
	CANON=$PWD
	cd -
}

canon $(dirname $0)
MYDIR=$CANON

while [ ${#*} -gt 1 ]; do
        case "$1" in
                -t)
                        shift;
                        TREE=$1
                        ;;
                -s)
                        shift;
                        SERIES=$1
                        ;;
                *)
			die "unknown argument $1"
                        break;
                        ;;
        esac
        shift;
done

[ -z "$TREE" -o -z "$SERIES" ] && die "I need a tree and series:\n\t$0 -t kernel_dir -s series_name"
[ ! -d $TREE ] && die "kernel tree '$TREE' isn't a directory"
SERIES=$(basename $SERIES)
[ ! -f $MYDIR/series/$SERIES ] && die "no series file '$SERIES'"

canon $TREE
TREE=$CANON

# patch scripts wants a relative path from the linux tree to
# its patch pile :(

MY=$(echo $MYDIR | sed -e 's_^/__')
TR=$(echo $TREE | sed -e 's_^/__')

while true ; do
	M=$(echo $MY | cut -d/ -f 1)
	T=$(echo $TR | cut -d/ -f 1)

	if [ $M != $T ]; then
		break;
	fi

	MY=$(echo $MY | cut -d/ -f 2-)
	TR=$(echo $TR | cut -d/ -f 2-)
done

[ $MY == $MYDIR ] && die "bad! $MY == $MYDIR" 

REVERSE=$(revpath $TR)${MY}
ABSINO=$(stat $MYDIR | awk '($3 == "Inode:") {print $4}')
REVINO=`(cd $TREE ; stat $REVERSE | awk '($3 == "Inode:") {print $4}')`

[ $ABSINO != $REVINO ] && die "inodes differ, my reverse path is bad?"

echo export PATCHSCRIPTS_LIBDIR=$REVERSE

cd $TREE
ln -sf $REVERSE/series/$SERIES series

PATH_ELEMENTS=$(echo $PATH | sed -e 's/:/ /g')

NEW_PATH=$MYDIR/scripts

for p in $PATH_ELEMENTS; do
	if echo $p | grep kernel_patches/scripts > /dev/null 2>&1 ; then
		continue;
	fi
	NEW_PATH="$NEW_PATH:$p"
done

echo export PATH=$NEW_PATH

echo "'$TREE' successfully setup" >&2
