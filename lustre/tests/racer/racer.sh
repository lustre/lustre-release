#!/usr/bin/bash
#set -x

DIR="$1"
MAX_FILES=${MAX_FILES:-20}
DURATION=${DURATION:-$((60*5))}

NUM_THREADS=${NUM_THREADS:-$2}
NUM_THREADS=${NUM_THREADS:-3}

RACER_MAX_CLEANUP_WAIT=${RACER_MAX_CLEANUP_WAIT:-$DURATION}

mkdir -p $DIR
# need to specify mountpoint directly if 'fuser -M' is used
MNT=$(stat -c %m $DIR)

if [[ -z "$RACER_PROGS" ]]; then
	RACER_PROGS="file_create dir_create file_rm file_rename file_link"
	RACER_PROGS+=" file_symlink file_list file_concat file_exec file_chown"
	RACER_PROGS+=" file_chmod file_mknod file_truncate file_delxattr"
	RACER_PROGS+=" file_getxattr file_setxattr"

	if $RACER_ENABLE_REMOTE_DIRS || $RACER_ENABLE_STRIPED_DIRS; then
		RACER_PROGS+=" dir_remote"
	fi

	if $RACER_ENABLE_MIGRATION; then
		RACER_PROGS+=" dir_migrate"
	fi

	if $RACER_ENABLE_FALLOCATE; then
		RACER_PROGS+=' file_fallocate'
	fi
fi
RACER_PROGS=${RACER_PROGS//[,+]/ }

# allow e.g. RACER_EXTRA=dir_create:5,file_link:10 or
# RACER_EXTRA=dir_create:5+file_link:10 to launch extra tasks
for PROG in ${RACER_EXTRA//[,+]/ }; do
	prog=(${PROG/:/ })
	count=${prog[1]:-1}
	for ((i = 0; i < count; i++)); do
		RACER_PROGS+=" ${prog[0]}"
	done
done

racer_cleanup()
{
	echo "racer cleanup"
	for P in $RACER_PROGS; do
		killall -q $P.sh
	done
	trap 0

	local short_wait=5
	local start=$SECONDS
	local end=$((start + $RACER_MAX_CLEANUP_WAIT))

	while (( $SECONDS <= $end )); do
		local rc=0

		echo "sleeping $short_wait sec ..."
		sleep $short_wait
		# this only checks whether processes exist
		for P in $RACER_PROGS; do
			killall -0 $P.sh
			(( $? == 0 )) && (( rc+=1 ))
		done

		# Kill dd processes to speedup cleanup
		local pids=$(ps uax | grep "$DIR" | grep dd | grep -v grep |
			     awk '{print $2}')
		for pid in $pids; do
			kill $pid
		done

		# killall only signals the worker scripts ($P.sh) but not
		# commands started by them, which may now be orphans.
		# Kill leftover users of the racer mount here.
		# Do not kill everything on system if $DIR is now root.
		[[ "$MNT" != "/" ]] &&
			timeout $short_wait fuser -M -k -m "$MNT"

		if (( $rc == 0 )); then
			echo "there should be NO racer processes:"
			ps uww -C "${RACER_PROGS// /.sh,}.sh"
			return 0
		fi
		echo -n "Waited $((SECONDS - start)): rc=$rc "
	done
	ps uww -C "${RACER_PROGS// /.sh,}.sh"
	return 1
}

RC=0

echo "Running $0 for $DURATION seconds. CTRL-C to exit"
trap "
	echo 'Cleaning up'
	racer_cleanup
	exit 0
" INT TERM

cd $(dirname $0)
for ((N = 1; N <= $NUM_THREADS; N++)); do
	for P in $RACER_PROGS; do
		RACER_MIGRATE_STRIPE_MAX=$RACER_MIGRATE_STRIPE_MAX \
		./$P.sh $DIR $MAX_FILES &
	done
done

sleep $DURATION
racer_cleanup || RC=$?

# Check our to see whether our test DIR is still available.
df $DIR
(( RC+=$? ))
(( $RC == 0 )) && echo "We survived $0 for $DURATION seconds."
exit $RC
