#!/bin/bash

MAX_FILES=${MAX_FILES:-20}
DIR=${DIR:-$1}
DIR=${DIR:-"/mnt/lustre/racer"}
if ! [ -d "$DIR" -o -d "`basename $DIR`" ]; then
	echo "$0: '$DIR' and '`basename $DIR`' are not directories"
	exit 1
fi
DURATION=${DURATION:-$((60*5))}

NUM_THREADS=${NUM_THREADS:-$2}
NUM_THREADS=${NUM_THREADS:-3}

[ -e $DIR ] || mkdir $DIR

racer_cleanup()
{
    killall file_create.sh 
    killall dir_create.sh
    killall file_rm.sh 
    killall file_rename.sh 
    killall file_link.sh 
    killall file_symlink.sh 
    killall file_list.sh 
    killall file_concat.sh
    trap 0
}

echo "Running $0 for $DURATION seconds. CTRL-C to exit"
trap "
    echo \"Cleaning up\" 
    racer_cleanup
    exit 0
" 2

cd `dirname $0`
for N in `seq 1 $NUM_THREADS`; do
	./file_create.sh $DIR $MAX_FILES &
	./dir_create.sh $DIR $MAX_FILES &
	./file_rename.sh $DIR $MAX_FILES &
	./file_link.sh $DIR $MAX_FILES &
	./file_symlink.sh $DIR $MAX_FILES &
	./file_concat.sh $DIR $MAX_FILES &
	./file_list.sh $DIR &
	./file_rm.sh $DIR $MAX_FILES &
done

sleep $DURATION;
racer_cleanup
# Check our to see whether our test DIR is still available.
df $DIR
RC=$?
if [ $RC -eq 0 ]; then
    echo "We survived $0 for $DURATION seconds."
fi
exit $RC
