#!/bin/bash
#set -x

DIR="$1"
MAX_FILES=${MAX_FILES:-20}
DURATION=${DURATION:-$((60*5))}

NUM_THREADS=${NUM_THREADS:-$2}
NUM_THREADS=${NUM_THREADS:-3}

RACER_MAX_CLEANUP_WAIT=${RACER_MAX_CLEANUP_WAIT:-$DURATION}

mkdir -p $DIR

RACER_PROGS="file_create dir_create file_rm file_rename file_link file_symlink \
file_list file_concat file_exec file_chown file_chmod file_mknod file_truncate \
file_delxattr file_getxattr file_setxattr"

# allow e.g. RACER_EXTRA=dir_create:5,file_link:10 to launch extra tasks
for PROG in ${RACER_EXTRA//,/ }; do
	prog=(${PROG/:/ })
	count=${prog[1]:-1}
	for ((i = 0; i < count; i++)); do
		RACER_PROGS+=" ${prog[0]}"
	done
done

if $RACER_ENABLE_REMOTE_DIRS || $RACER_ENABLE_STRIPED_DIRS; then
	RACER_PROGS+=' dir_remote'
fi

if $RACER_ENABLE_MIGRATION; then
	RACER_PROGS+=' dir_migrate'
fi

racer_cleanup()
{
	echo "racer cleanup"
	for P in $RACER_PROGS; do
		killall -q $P.sh
	done
	trap 0

	local TOT_WAIT=0
	local SHORT_WAIT=5

	local rc
	while [[ $TOT_WAIT -le $RACER_MAX_CLEANUP_WAIT ]]; do
		rc=0
		echo sleeping $SHORT_WAIT sec ...
		sleep $SHORT_WAIT
		# this only checks whether processes exist
		for P in $RACER_PROGS; do
			killall -0 $P.sh
			[[ $? -eq 0 ]] && (( rc+=1 ))
		done

		# Kill dd processes to speedup cleanup
		local pids=$(ps uax | grep "$DIR" | grep dd | grep -v grep |
				awk '{print $2}')
		for pid in $pids; do
			kill $pid
		done

		if [[ $rc -eq 0 ]]; then
			echo there should be NO racer processes:
			ps uww -C "${RACER_PROGS// /.sh,}.sh"
			return 0
		fi
		(( TOT_WAIT+=SHORT_WAIT ))
		echo -n "Waited $TOT_WAIT, rc=$rc "
		(( SHORT_WAIT+=SHORT_WAIT ))
	done
	ps uww -C "${RACER_PROGS// /.sh,}.sh"
	return 1
}

RC=0

echo "Running $0 for $DURATION seconds. CTRL-C to exit"
trap "
	echo \"Cleaning up\" 
	racer_cleanup
	exit 0
" INT TERM

cd `dirname $0`
for N in `seq 1 $NUM_THREADS`; do
	for P in $RACER_PROGS; do
		./$P.sh $DIR $MAX_FILES &
	done
done

sleep $DURATION
racer_cleanup || RC=$?

# Check our to see whether our test DIR is still available.
df $DIR
(( RC+=$? ))
[ $RC -eq 0 ] && echo "We survived $0 for $DURATION seconds."
exit $RC
