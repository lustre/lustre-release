#!/bin/bash

set -e

PATH=$PATH:.

CHECKSTAT=${CHECKSTAT:-"checkstat -v"}
MOUNT1=${MOUNT1:-/mnt/lustre1}
MOUNT2=${MOUNT2:-/mnt/lustre2}
DIRNAME=${DIRNAME:-"ls-timing"}
DIRSIZE=${DIRSIZE:-200}
export NAME=${NAME:-mount2}

error () { 
    echo FAIL
    exit 1
}

pass() { 
    echo PASS
}
echo "Mounting..."
mount | grep $MOUNT1 || sh llmount.sh

echo -n "Preparing test directory with $DIRSIZE files..."
rm -rf "$MOUNT1/$DIRNAME"
rm -rf "$MOUNT2/$DIRNAME"
mkdir -p "$MOUNT1/$DIRNAME"
[ -d "$MOUNT2/$DIRNAME" ] || error
createmany -o $MOUNT1/$DIRNAME/file 0 $DIRSIZE &> /dev/null
echo "done"

echo -n "Cached ls: "
time ls -lr $MOUNT1/$DIRNAME 1> /dev/null

echo -n "Uncached ls: "
time ls -lr $MOUNT2/$DIRNAME 1> /dev/null


fsx $MOUNT1/$DIRNAME/fsx.file &>/dev/null &
fsxpid=$!

echo -n "Cached busy ls:"
time ls -lr $MOUNT1/$DIRNAME 1> /dev/null

echo -n "Uncached busy ls: "
time ls -lr $MOUNT2/$DIRNAME 1> /dev/null

kill $fsxpid

exit
