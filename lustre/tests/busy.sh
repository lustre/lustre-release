#!/bin/bash

 mkdir /mnt/lustre/d22
 mkdir /mnt/lustre/d22/etc
 ./mcreate /mnt/lustre/d22/etc/foo
 ls -ld /mnt/lustre/etc
 ls -ld /mnt/lustre/d22/etc
