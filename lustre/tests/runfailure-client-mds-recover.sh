#!/bin/sh

echo `date` creating /mnt/lustre/foo
echo 0x80000107 > /proc/sys/lustre/fail_loc
touch /mnt/lustre/foo &
ps axww | grep touch
echo "touch program suspended and hanging -- sleeping 5 secs"
sleep 5
ls -l /mnt/lustre/foo

echo 0x0000107 > /proc/sys/lustre/fail_loc
touch /mnt/lustre/bar &
ps axww | grep touch
echo "touch program will have repeated failures sleeping 10"

sleep 10

echo 0 > /proc/sys/lustre/fail_loc
echo "failure cleared"
sleep 5
ls -l /mnt/lustre/bar
