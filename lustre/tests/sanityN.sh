#!/bin/bash

export NAME=$NAME
clean() {
        echo -n "cleanup..."
        sh llmount2-hackcleanup.sh > /dev/null
}

CLEAN=clean
start() {
        echo -n "mounting..."
        sh llmount2-hack.sh > /dev/null
        echo -n "mounted"
}
START=start

error () { 
    echo $1
    exit 1
}

echo -n "test 1: check create on 2 mtpt's..."
touch /mnt/lustre1/f1
[ -f /mnt/lustre2/f1 ] || error "test 1 failure" 
echo "pass"

echo "test 2: check attribute updates on 2 mtpt's..."
chmod a+x /mnt/lustre2/f1
[ -x /mnt/lustre1/f1 ] || error "test 2 failure"
echo "pass"

echo "test 3: check after remount attribute updates on 2 mtpt's..."
chmod a-x /mnt/lustre2/f1
$CLEAN
$START

[ ! -x /mnt/lustre1/f1 ] || error "test 3 failure"
echo "pass"

$CLEAN
$START

exit
