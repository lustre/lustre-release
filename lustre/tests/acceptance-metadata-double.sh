#!/bin/sh
set -e

#
# Runs create.pl and rename.pl on two mountpoints with increasing load, varying
# debug levels.  Assumes that the node is already setup with llmount2.sh
#

SRCDIR="`dirname $0`"
CREATE=$SRCDIR/create.pl
RENAME=$SRCDIR/rename.pl

debug_client_on()
{
	echo -1 > /proc/sys/portals/debug
}

debug_client_off()
{
	echo 0 > /proc/sys/portals/debug
}

MNT=${MNT:-/mnt/lustre}

debug_client_on
echo "create.pl, 2 mounts, 1 thread, 10 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=10
echo "create.pl, 2 mounts, 1 thread, 100 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=100 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 1 thread, 10 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=10 --use_mcreate=0
echo "create.pl --use_mcreate=0, 2 mounts, 1 thread, 100 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=100 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 1 thread, 10 ops, debug on"
perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=10
echo "rename.pl, 2 mounts, 1 thread, 100 ops, debug on"
perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=100 --silent

debug_client_off
echo "create.pl, 2 mounts, 1 thread, 1000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=1000 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 1 thread, 1000 ops, debug off"
perl $CREATE --silent --use_mcreate=0 -- $MNT 2 1000
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=1000 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 1 thread, 1000 ops, debug off"
perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=1000 --silent

debug_client_on
echo "create.pl, 2 mounts, 2 threads, 100 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=100 --num_threads=2 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 2 threads, 100 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=100 --num_threads=2 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 2 thread, 1000 ops, debug on"
perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=1000 --num_threads=2 --silent

debug_client_off
echo "create.pl, 2 mounts, 2 threads, 2000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=2 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 2 threads, 2000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=2 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 2 threads, 2000 ops, debug off"
perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=2 --silent

debug_client_on
echo "create.pl, 2 mounts, 4 threads, 100 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=100 --num_threads=4 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 4 threads, 100 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=100 --num_threads=4 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 4 threads, 2000 ops, debug on"
perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=4 --silent

debug_client_off
echo "create.pl, 2 mounts, 4 threads, 2000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=4 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 4 threads, 2000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=4 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 4 threads, 2000 ops, debug off"
perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=4 --silent

debug_client_on
echo "create.pl, 2 mounts, 8 threads, 500 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=500 --num_threads=8 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 8 threads, 500 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=500 --num_threads=8 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 8 threads, 2000 ops, debug on"
perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=8 --silent

debug_client_off
echo "create.pl, 2 mounts, 8 threads, 2000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=8 --silent
echo "create.pl --use_mcreate=0, 2 mounts, 8 threads, 2000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=8 --use_mcreate=0 --silent
echo "rename.pl, 2 mounts, 8 threads, 2000 ops, debug off"
perl $RENAME --mountpt=${MNT} --num_mounts=2 --iterations=2000 --num_threads=8 --silent
