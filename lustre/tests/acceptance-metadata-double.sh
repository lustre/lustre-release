#!/bin/sh
set -e

#
# Runs create.pl and rename.pl on two mountpoints with increasing load, varying
# debug levels.  Assumes that the node is already setup with llmount2.sh
#

SRCDIR="`dirname $0`"
CREATE=$SRCDIR/create.pl

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
perl $CREATE -- $MNT 2 10
echo "create.pl, 2 mounts, 1 thread, 100 ops, debug on"
perl $CREATE --silent -- $MNT 2 100
echo "create.pl --mcreate=0, 2 mounts, 1 thread, 10 ops, debug on"
perl $CREATE --mcreate=0 -- $MNT 2 10
echo "create.pl --mcreate=0, 2 mounts, 1 thread, 100 ops, debug on"
perl $CREATE --mcreate=0 --silent -- $MNT 2 100
echo "rename.pl, 2 mounts, 1 thread, 10 ops, debug on"
perl rename.pl --count=2 $MNT 10
echo "rename.pl, 2 mounts, 1 thread, 100 ops, debug on"
perl rename.pl --count=2 --silent $MNT 100

debug_client_off
echo "create.pl, 2 mounts, 1 thread, 1000 ops, debug off"
perl $CREATE --silent -- $MNT 2 1000
echo "create.pl --mcreate=0, 2 mounts, 1 thread, 1000 ops, debug off"
perl $CREATE --silent --mcreate=0 -- $MNT 2 1000
echo "rename.pl, 2 mounts, 1 thread, 1000 ops, debug off"
perl rename.pl --count=2 --silent $MNT 1000

debug_client_on
echo "create.pl, 2 mounts, 2 threads, 100 ops, debug on"
perl $CREATE --silent -- $MNT 2 100 &
perl $CREATE --silent -- $MNT 2 100 &
wait
echo "create.pl --mcreate=0, 2 mounts, 2 threads, 100 ops, debug on"
perl $CREATE --silent --mcreate=0 -- $MNT 2 100 &
perl $CREATE --silent --mcreate=0 -- $MNT 2 100 &
wait
echo "rename.pl, 2 mounts, 2 thread, 1000 ops, debug on"
perl rename.pl --count=2 --silent $MNT 1000 &
perl rename.pl --count=2 --silent $MNT 1000 &
wait

debug_client_off
echo "create.pl, 2 mounts, 2 threads, 2000 ops, debug off"
perl $CREATE --silent -- $MNT 2 2000 &
perl $CREATE --silent -- $MNT 2 2000 &
wait
echo "create.pl --mcreate=0, 2 mounts, 2 threads, 2000 ops, debug off"
perl $CREATE --silent --mcreate=0 -- $MNT 2 2000 &
perl $CREATE --silent --mcreate=0 -- $MNT 2 2000 &
wait
echo "rename.pl, 2 mounts, 2 threads, 2000 ops, debug off"
perl rename.pl --count=2 --silent $MNT 2000 &
perl rename.pl --count=2 --silent $MNT 2000 &
wait

debug_client_on
echo "create.pl, 2 mounts, 4 threads, 100 ops, debug on"
for i in `seq 1 4`; do
  perl $CREATE --silent -- $MNT 2 100 &
done
wait
echo "create.pl --mcreate=0, 2 mounts, 4 threads, 100 ops, debug on"
for i in `seq 1 4`; do
  perl $CREATE --silent --mcreate=0 -- $MNT 2 100 &
done
wait
echo "rename.pl, 2 mounts, 4 threads, 2000 ops, debug on"
for i in `seq 1 4`; do
  perl rename.pl --count=2 --silent $MNT 2000 &
done
wait

debug_client_off
echo "create.pl, 2 mounts, 4 threads, 2000 ops, debug off"
for i in `seq 1 4`; do
  perl $CREATE --silent -- $MNT 2 2000 &
done
wait
echo "create.pl --mcreate=0, 2 mounts, 4 threads, 2000 ops, debug off"
for i in `seq 1 4`; do
  perl $CREATE --silent --mcreate=0 -- $MNT 2 2000 &
done
wait
echo "rename.pl, 2 mounts, 4 threads, 2000 ops, debug off"
for i in `seq 1 4`; do
  perl rename.pl --count=2 --silent $MNT 2000 &
done
wait

debug_client_on
echo "create.pl, 2 mounts, 8 threads, 500 ops, debug on"
for i in `seq 1 8`; do
  perl $CREATE --silent -- $MNT 2 500 &
done
wait
echo "create.pl --mcreate=0, 2 mounts, 8 threads, 500 ops, debug on"
for i in `seq 1 8`; do
  perl $CREATE --silent --mcreate=0 -- $MNT 2 500 &
done
wait
echo "rename.pl, 2 mounts, 8 threads, 2000 ops, debug on"
for i in `seq 1 8`; do
  perl rename.pl --count=2 --silent $MNT 2000 &
done
wait

debug_client_off
echo "create.pl, 2 mounts, 8 threads, 2000 ops, debug off"
for i in `seq 1 8`; do
  perl $CREATE --silent -- $MNT 2 2000 &
done
wait
echo "create.pl --mcreate=0, 2 mounts, 8 threads, 2000 ops, debug off"
for i in `seq 1 8`; do
  perl $CREATE --silent --mcreate=0 -- $MNT 2 2000 &
done
wait
echo "rename.pl, 2 mounts, 8 threads, 2000 ops, debug off"
for i in `seq 1 8`; do
  perl rename.pl --count=2 --silent $MNT 2000 &
done
wait
