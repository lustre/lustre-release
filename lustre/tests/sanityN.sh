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

echo -n "test 2: check attribute updates on 2 mtpt's..."
chmod a+x /mnt/lustre2/f1
[ -x /mnt/lustre1/f1 ] || error "test 2 failure"
echo "pass"

echo -n "test 3: check after remount attribute updates on 2 mtpt's..."
chmod a-x /mnt/lustre2/f1
$CLEAN
$START

[ ! -x /mnt/lustre1/f1 ] || error "test 3 failure"
echo "pass"

echo -n "test 4: symlink on one mtpt, readlink on another..."
( cd /mnt/lustre1 ; ln -s this/is/good lnk )

[ "Xthis/is/good" = X`perl -e 'print readlink("/mnt/lustre2/lnk");'` ] || error  "test 4 fails"
echo "pass"

echo -n "test 5: fstat validation on multiple mount points..."
./multifstat /mnt/lustre1/fstatfile /mnt/lustre2/fstatfile || error "test 5 fails"
echo "pass"

$CLEAN
$START



exit
