#!/bin/bash

dmesg -n 1

#sh llmount.sh
../utils/lctl <<eof
device 2
probe 2
eof

dmesg -c > /dev/null

dmesg -n 7
#echo 0x300811 > /proc/sys/portals/debug

START=:  CLEAN=: ONLY="99a 99b 99c" sh sanity.sh
