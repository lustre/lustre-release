#!/bin/bash

MDSDEV=smfs OSTDEV=smfs FSTYPE=smfs MDS_MOUNT_OPTS="" OST_MOUNT_OPTS="" \
OSTSIZE=100000 MDSSIZE=100000 MDS_BACKFSTYPE=ext3 OST_BACKFSTYPE=ext3 \
MDS_BACKDEV=/tmp/mds1-$(hostname) OST_BACKDEV=/tmp/ost1-$(hostname) sh llmount.sh
