#! /bin/sh
#
# Extremely minimal regression test set for clio.
#

MOUNT=${MOUNT:-"/mnt/lustre"}

function cmpcheck() {
    find /etc/ -type f | while read ;do
        f=$REPLY
        echo -n .
        cmp $f $MOUNT/$f
    done
}

cp -vax /etc $MOUNT                                   || exit 1
cmpcheck

export OSTCOUNT=2
#export LOV="27c 27d 27e 27f 27g 27j 27k 27l 27m 27s 27t 27w 34f 51d 56 56g 56h"
#export JOIN="75a 75b 57c 75d 75e 75f 75g"
#export CHKSUM="77a 77d 77e 77f"
#export DIO="69 77d 77e 77f 78 119a 119b 119c"
#export EXCEPT="69 78 118a 129 $JOIN $CHKSUM $DIO"
#export EXCEPT="77f"
export SLOW="yes"

sh sanity.sh
#umount $MOUNT                                        || exit 2
