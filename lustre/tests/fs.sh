#! /bin/bash

insmod loop
dd if=/dev/zero of=/tmp/fs bs=1024 count=10000
losetup /dev/loop0 /tmp/fs
mke2fs -b 4096 /dev/loop0
