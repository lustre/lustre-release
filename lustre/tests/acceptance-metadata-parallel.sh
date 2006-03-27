#!/bin/sh
set -e

#########################################################################
# Runs create.pl on a single mountpoint and directory with increasing
# load across multiple clients.
#########################################################################

LUSTRE=${LUSTRE:-`dirname $0`/..}
LTESTDIR=${LTESTDIR:-$LUSTRE/../ltest}
PATH=$LUSTRE/utils:$LUSTRE/tests:$PATH
 
RLUSTRE=${RLUSTRE:-$LUSTRE}
RPWD=${RPWD:-$PWD}
 
. $LUSTRE/tests/test-framework.sh

TIME=${TIME:-/usr/bin/time}
PDSH=${PDSH:-"pdsh -S -w"}
MOUNTPT=${MOUNTPT:-"/mnt/lustre"}

CREATE=$LUSTRE/tests/create.pl
RENAME=$LUSTRE/tests/rename.pl

[ -z "$CLIENTS" ] && exit 1
#CLIENTS=`comma_list $CLIENTS`

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

set_debug_level() 
{
    $PDSH $CLIENTS "echo $1 > /proc/sys/lnet/debug"
}

debug_client_on()
{
    set_debug_level -1
}

debug_client_partial()
{
    set_debug_level 0x3f0400
}

debug_client_off()
{
    set_debug_level 0
}

# Get our initial timestamps.
START_TS=`date +%s`
CURRENT_TS=$START_TS
PREVIOUS_TS=$START_TS

debug_client_off

echo "create.pl, 1 mount, 1 thread, 1000 ops"
$TIME $PDSH $CLIENTS "umask 0022 && cd $RLUSTRE/tests && perl $CREATE --mountpt=${MOUNTPT} --num_mounts=-1 --iterations=1000 --silent"
#echo "create.pl --mcreate=0, 1 mount, 1 thread, 1000 ops, debug off"
#$TIME $PDSH $CLIENTS "umask 0022 && cd $RLUSTRE/tests && perl $CREATE --mountpt=${MOUNTPT} --num_mounts=-1 --iterations=1000 --use_mcreate=0 --silent"
wait
#echo "rename.pl, 1 mount, 1 thread, 1000 ops, debug off"
#$TIME $PDSH $CLIENTS "umask 0022 && cd $RLUSTRE/tests && perl $RENAME --mountpt=${MOUNTPT} --num_mounts=-1 --iterations=1000 --silent"

display_elapsed_time

echo "create.pl, 1 mount, 2 threads, 2000 ops, debug off"
$TIME $PDSH $CLIENTS "umask 0022 && cd $RLUSTRE/tests && perl $CREATE --mountpt=${MOUNTPT} --num_mounts=-1 --iterations=2000 --num_threads=2 --silent"
#echo "create.pl --mcreate=0, 1 mount, 2 threads, 2000 ops, debug off"
#$TIME $PDSH $CLIENTS "umask 0022 && cd $RLUSTRE/tests && perl $CREATE --mountpt=${MOUNTPT} --num_mounts=-1 --iterations=2000 --num_threads=2 --use_mcreate=0  --silent"
wait
#echo "rename.pl, 1 mount, 2 threads, 2000 ops, debug off"
#$TIME $PDSH $CLIENTS "umask 0022 && cd $RLUSTRE/tests && perl $RENAME --mountpt=${MOUNTPT} --num_mounts=-1 --iterations=2000 --num_threads=2 --silent#

display_elapsed_time

echo "create.pl, 1 mount, 4 threads, 2000 ops, debug off"
$TIME $PDSH $CLIENTS "umask 0022 && cd $RLUSTRE/tests && perl $CREATE --mountpt=${MOUNTPT} --num_mounts=-1 --iterations=2000 --num_threads=4  --silent"
#echo "create.pl --mcreate=0, 1 mount, 4 threads, 2000 ops, debug off"
#$TIME $PDSH $CLIENTS "umask 0022 && cd $RLUSTRE/tests && perl $CREATE --mountpt=${MOUNTPT} --num_mounts=-1 --iterations=2000 --num_threads=4  --use_mcreate=0 --silent"
wait
#echo "rename.pl, 1 mount, 4 threads, 2000 ops, debug off"
#$TIME $PDSH $CLIENTS "umask 0022 && cd $RLUSTRE/tests && perl $RENAME --mountpt=${MOUNTPT} --num_mounts=-1 --iterations=2000 --num_threads=4 --silent"

display_elapsed_time

echo "create.pl, 1 mount, 8 threads, 2000 ops, debug off"
$TIME $PDSH $CLIENTS "umask 0022 && cd $RLUSTRE/tests && perl $CREATE --mountpt=${MOUNTPT} --num_mounts=-1 --iterations=2000 --num_threads=8  --silent"
#echo "create.pl --mcreate=0, 1 mount, 8 threads, 2000 ops, debug off"
#$TIME $PDSH $CLIENTS "umask 0022 && cd $RLUSTRE/tests && perl $CREATE --mountpt=${MOUNTPT} --num_mounts=-1 --iterations=2000 --num_threads=8  --use_mcreate=0 --silent"
wait
#echo "rename.pl, 1 mount, 8 threads, 2000 ops, debug off"
#$TIME $PDSH $CLIENTS "umask 0022 && cd $RLUSTRE/tests && perl $RENAME --mountpt=${MOUNTPT} --num_mounts=-1 --iterations=2000 --num_threads=8 --silent"

display_elapsed_time
