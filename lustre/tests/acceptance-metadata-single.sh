#!/bin/sh
set -e

#
# Runs create.pl and rename.pl on a single mountpoint with increasing
# load, varying debug levels
#

SRCDIR="`dirname $0`/"
. $SRCDIR/common.sh

MNT=${MNT:-/mnt/lustre}

debug_client_on
echo "create.pl, 1 mount, 1 thread, 10 ops, debug on"
perl create.pl -- $MNT -1 10
echo "create.pl, 1 mount, 1 thread, 100 ops, debug on"
perl create.pl --silent -- $MNT -1 100
echo "rename.pl, 1 mount, 1 thread, 10 ops, debug on"
perl rename.pl $MNT 10
echo "rename.pl, 1 mount, 1 thread, 100 ops, debug on"
perl rename.pl --silent $MNT 100

debug_client_off
echo "create.pl, 1 mount, 1 thread, 1000 ops, debug off"
perl create.pl --silent -- $MNT -1 1000
echo "rename.pl, 1 mount, 1 thread, 1000 ops, debug off"
perl rename.pl --silent $MNT 1000

debug_client_on
echo "create.pl, 1 mount, 2 threads, 100 ops, debug on"
perl create.pl --silent -- $MNT -1 100 &
perl create.pl --silent -- $MNT -1 100 &
wait
echo "rename.pl, 1 mount, 2 thread, 1000 ops, debug on"
perl rename.pl --silent $MNT 1000 &
perl rename.pl --silent $MNT 1000 &
wait

debug_client_off
echo "create.pl, 1 mount, 2 threads, 2000 ops, debug off"
perl create.pl --silent -- $MNT -1 2000 &
perl create.pl --silent -- $MNT -1 2000 &
wait
echo "rename.pl, 1 mount, 2 threads, 2000 ops, debug off"
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
wait

debug_client_on
echo "create.pl, 1 mount, 4 threads, 100 ops, debug on"
perl create.pl --silent -- $MNT -1 100 &
perl create.pl --silent -- $MNT -1 100 &
perl create.pl --silent -- $MNT -1 100 &
perl create.pl --silent -- $MNT -1 100 &
wait
echo "rename.pl, 1 mount, 4 threads, 2000 ops, debug on"
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
wait

debug_client_off
echo "create.pl, 1 mount, 4 threads, 2000 ops, debug off"
perl create.pl --silent -- $MNT -1 2000 &
perl create.pl --silent -- $MNT -1 2000 &
perl create.pl --silent -- $MNT -1 2000 &
perl create.pl --silent -- $MNT -1 2000 &
wait
echo "rename.pl, 1 mount, 4 threads, 2000 ops, debug off"
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
wait

debug_client_on
echo "create.pl, 1 mount, 8 threads, 100 ops, debug on"
perl create.pl --silent -- $MNT -1 100 &
perl create.pl --silent -- $MNT -1 100 &
perl create.pl --silent -- $MNT -1 100 &
perl create.pl --silent -- $MNT -1 100 &
perl create.pl --silent -- $MNT -1 100 &
perl create.pl --silent -- $MNT -1 100 &
perl create.pl --silent -- $MNT -1 100 &
perl create.pl --silent -- $MNT -1 100 &
wait
echo "rename.pl, 1 mount, 4 threads, 2000 ops, debug on"
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
wait

debug_client_off
echo "create.pl, 1 mount, 8 threads, 2000 ops, debug off"
perl create.pl --silent -- $MNT -1 2000 &
perl create.pl --silent -- $MNT -1 2000 &
perl create.pl --silent -- $MNT -1 2000 &
perl create.pl --silent -- $MNT -1 2000 &
perl create.pl --silent -- $MNT -1 2000 &
perl create.pl --silent -- $MNT -1 2000 &
perl create.pl --silent -- $MNT -1 2000 &
perl create.pl --silent -- $MNT -1 2000 &
wait
echo "rename.pl, 1 mount, 4 threads, 2000 ops, debug off"
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
perl rename.pl --silent $MNT 2000 &
wait
