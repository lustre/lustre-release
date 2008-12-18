#!/bin/sh
set -e

#
# Runs create.pl and rename.pl on two mountpoints with increasing load, varying
# debug levels.  Assumes that the node is already setup with llmount2.sh
#

SRCDIR="`dirname $0`"
CREATE=$SRCDIR/create.pl
RENAME=$SRCDIR/rename.pl

TIME=${TIME:-/usr/bin/time}

display_elapsed_time() {
    PREVIOUS_TS=$CURRENT_TS
    CURRENT_TS=`date +%s`
    BLOCK_ELAPSED=`expr $CURRENT_TS - $PREVIOUS_TS`
    TOTAL_ELAPSED=`expr $CURRENT_TS - $START_TS`

    echo " "
    echo "Elapsed time (block): ${BLOCK_ELAPSED} seconds"
    echo "Elapsed time (TOTAL): ${TOTAL_ELAPSED} seconds"
    echo " "
}    

debug_client_on()
{
	lctl set_param -n debug=-1
}

debug_client_off()
{
	lctl set_param -n debug=0x3f0400
}

MNT=${MNT:-/mnt/lustre}

# Get our initial timestamps.
START_TS=`date +%s`
CURRENT_TS=$START_TS
PREVIOUS_TS=$START_TS

debug_client_on
echo "create.pl, 2 mounts, 1 thread, 10 ops, debug on"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=10
echo "create.pl, 2 mounts, 1 thread, 100 ops, debug on"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=100 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 1 thread, 10 ops, debug on"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=10 --use_mcreate=0
echo "create.pl --use_mcreate=0, 2 mounts, 1 thread, 100 ops, debug on"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=100 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 1 thread, 10 ops, debug on"
$TIME perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=10
echo "rename.pl, 2 mounts, 1 thread, 100 ops, debug on"
$TIME perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=100 --silent

display_elapsed_time

debug_client_off
echo "create.pl, 2 mounts, 1 thread, 1000 ops, debug off"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=1000 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 1 thread, 1000 ops, debug off"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=1000 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 1 thread, 1000 ops, debug off"
$TIME perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=1000 --silent

display_elapsed_time

debug_client_on
echo "create.pl, 2 mounts, 2 threads, 100 ops, debug on"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=100 --num_threads=2 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 2 threads, 100 ops, debug on"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=100 --num_threads=2 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 2 thread, 1000 ops, debug on"
$TIME perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=1000 --num_threads=2 --silent

display_elapsed_time

debug_client_off
echo "create.pl, 2 mounts, 2 threads, 2000 ops, debug off"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=2 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 2 threads, 2000 ops, debug off"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=2 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 2 threads, 2000 ops, debug off"
$TIME perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=2 --silent

display_elapsed_time

debug_client_on
echo "create.pl, 2 mounts, 4 threads, 100 ops, debug on"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=100 --num_threads=4 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 4 threads, 100 ops, debug on"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=100 --num_threads=4 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 4 threads, 2000 ops, debug on"
$TIME perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=4 --silent

display_elapsed_time

debug_client_off
echo "create.pl, 2 mounts, 4 threads, 2000 ops, debug off"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=4 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 4 threads, 2000 ops, debug off"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=4 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 4 threads, 2000 ops, debug off"
$TIME perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=4 --silent

display_elapsed_time

debug_client_on
echo "create.pl, 2 mounts, 8 threads, 500 ops, debug on"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=500 --num_threads=8 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 8 threads, 500 ops, debug on"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=500 --num_threads=8 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 8 threads, 2000 ops, debug on"
$TIME perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=8 --silent

display_elapsed_time

debug_client_off
echo "create.pl, 2 mounts, 8 threads, 2000 ops, debug off"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=8 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 8 threads, 2000 ops, debug off"
$TIME perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=8 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 8 threads, 2000 ops, debug off"
$TIME perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=8 --silent

display_elapsed_time
