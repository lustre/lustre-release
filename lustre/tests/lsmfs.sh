#!/bin/bash
# this is framework that sets env for SMFS before exec scripts
FSTYPE=smfs MDS_MOUNT_OPTS="" OST_MOUNT_OPTS="" \
MDS_BACKFSTYPE=ldiskfs OST_BACKFSTYPE=ldiskfs \
MDSDEV=/tmp/mds1-$(hostname) OSTDEV=/tmp/ost1-$(hostname) sh $1
