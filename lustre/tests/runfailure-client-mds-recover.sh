#!/bin/sh
SRCDIR=.

. common.sh

reconnect () { 

$OBDCTL <<EOF
name2dev RPCDEV
newconn
quit
EOF

}

echo 
echo "Test 5 reopen a file:" `date` "creating and writing/mnt/lustre/foo"
echo
rm -rf /mnt/lustre/*
./openme /mnt/lustre/foo3 & 
./writeme /mnt/lustre/iogoeson & 
sleep 1
ls -l /mnt/lustre
echo 0x80000107 > /proc/sys/lustre/fail_loc
mknod /mnt/lustre/dev c 10 240 &
echo "MDS dropped create request -- sleep 4 secs - watch for timeout"
sleep 4
reconnect
sleep 1
echo "did things recover? check for file foo, bar, check log for reopen."
ls -l /mnt/lustre
echo "Test 5 done"

exit

echo 
echo "Test 1 drop request:" `date` "creating /mnt/lustre/foo"
echo
rm -rf /mnt/lustre/*
echo 0x80000107 > /proc/sys/lustre/fail_loc
touch /mnt/lustre/foo &
ps axww | grep touch
echo "MDS dropped create request -- sleep 4 secs - watch for timeout"
sleep 4
reconnect
sleep 1
echo "did things recover? check for file foo."
ls -l /mnt/lustre


echo
echo "Test 2 test delay queue:" `date` "creating /mnt/lustre/foo"
echo
rm -rf /mnt/lustre/*
mkdir /mnt/lustre/a
echo 0x80000107 > /proc/sys/lustre/fail_loc
touch /mnt/lustre/foo &
ps axww | grep touch
echo "MDS dropped create request -- sleep 4 secs - watch for timeout"
sleep 4
touch /mnt/lustre/a/f &
reconnect
sleep 1
echo "did things recover? check for file foo and a/f"
ls -l /mnt/lustre
ls -l /mnt/lustre/a

echo
echo "Test 4 dropped reply:" `date` "creating /mnt/lustre/foo2"
echo
rm -rf /mnt/lustre/*
echo 0x80000119 > /proc/sys/lustre/fail_loc
touch /mnt/lustre/foo2 &
ps axww | grep touch
echo "MDS dropped create request -- sleep 4 secs - watch for timeout"
sleep 4
reconnect
echo failure cleared
sleep 1
echo "did things recover? check for file foo2"
ls -l /mnt/lustre



exit

echo
echo "Test 3: Multiple failures"
echo
echo 0x0000107 > /proc/sys/lustre/fail_loc
touch /mnt/lustre/bar &
ps axww | grep touch
echo "touch program will have repeated failures sleeping 10"
sleep 10
echo 0 > /proc/sys/lustre/fail_loc
reconnect
sleep 1
echo "failure cleared"
echo "did things recover? Check for file bar"
ls -l /mnt/lustre/bar


