#!/bin/sh
set -e

#
# Runs create.pl and rename.pl on a single mountpoint with increasing
# load, varying debug levels
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
echo "create.pl, 1 mount, 1 thread, 10 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=10
echo "create.pl, 1 mount, 1 thread, 100 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=100 --silent
echo "create.pl --mcreate=0, 1 mount, 1 thread, 10 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=10 --use_mcreate=0
echo "create.pl --mcreate=0, 1 mount, 1 thread, 100 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=100 --use_mcreate=0 --silent
echo "rename.pl, 1 mount, 1 thread, 10 ops, debug on"
perl $RENAME --mountpt=${MNT} --num_mounts=-1 --iterations=10
echo "rename.pl, 1 mount, 1 thread, 100 ops, debug on"
perl $RENAME --mountpt=${MNT} --num_mounts=-1 --iterations=100 --silent

debug_client_off
echo "create.pl, 1 mount, 1 thread, 1000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=1000 --silent
echo "create.pl --mcreate=0, 1 mount, 1 thread, 1000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=1000 --use_mcreate=0 --silent
echo "rename.pl, 1 mount, 1 thread, 1000 ops, debug off"
perl $RENAME --mountpt=${MNT} --num_mounts=-1 --iterations=1000 --silent

debug_client_on
echo "create.pl, 1 mount, 2 threads, 100 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=100 --num_threads=2 --silent
echo "create.pl --mcreate=0, 1 mount, 2 threads, 100 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=100 --num_threads=2 --use_mcreate=0 --silent
echo "rename.pl, 1 mount, 2 thread, 1000 ops, debug on"
perl $RENAME --mountpt=${MNT} --num_mounts=-1 --iterations=1000 --num_threads=2 --silent

debug_client_off
echo "create.pl, 1 mount, 2 threads, 2000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=2000 --num_threads=2 --silent
echo "create.pl --mcreate=0, 1 mount, 2 threads, 2000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=2000 --num_threads=2 --use_mcreate=0  --silent
wait
echo "rename.pl, 1 mount, 2 threads, 2000 ops, debug off"
perl $RENAME --mountpt=${MNT} --num_mounts=-1 --iterations=2000 --num_threads=2 --silent

debug_client_on
echo "create.pl, 1 mount, 4 threads, 100 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=100 --num_threads=4 --silent
echo "create.pl --mcreate=0, 1 mount, 4 threads, 100 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=100 --num_threads=4 --use_mcreate=0 --silent
echo "rename.pl, 1 mount, 4 threads, 2000 ops, debug on"
perl $RENAME --mountpt=${MNT} --num_mounts=-1 --iterations=2000 --num_threads=4 --silent

debug_client_off
echo "create.pl, 1 mount, 4 threads, 2000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=2000 --num_threads=4  --silent
echo "create.pl --mcreate=0, 1 mount, 4 threads, 2000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=2000 --num_threads=4  --use_mcreate=0 --silent
echo "rename.pl, 1 mount, 4 threads, 2000 ops, debug off"
perl $RENAME --mountpt=${MNT} --num_mounts=-1 --iterations=2000 --num_threads=4 --silent

debug_client_on
echo "create.pl, 1 mount, 8 threads, 500 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=500 --num_threads=8  --silent
echo "create.pl --mcreate=0, 1 mount, 8 threads, 500 ops, debug on"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=500 --num_threads=8  --use_mcreate=0 --silent
echo "rename.pl, 1 mount, 8 threads, 2000 ops, debug on"
perl $RENAME --mountpt=${MNT} --num_mounts=-1 --iterations=2000 --num_threads=8 --silent

debug_client_off
echo "create.pl, 1 mount, 8 threads, 2000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=2000 --num_threads=8  --silent
echo "create.pl --mcreate=0, 1 mount, 8 threads, 2000 ops, debug off"
perl $CREATE --mountpt=${MNT} --num_mounts=-1 --iterations=2000 --num_threads=8  --use_mcreate=0 --silent
echo "rename.pl, 1 mount, 8 threads, 2000 ops, debug off"
perl $RENAME --mountpt=${MNT} --num_mounts=-1 --iterations=2000 --num_threads=8 --silent

sh rundbench 1
sh rundbench 2
sh rundbench 4
sh rundbench 8
sh rundbench 16
sh rundbench 32
