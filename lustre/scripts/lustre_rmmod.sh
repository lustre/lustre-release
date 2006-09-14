#!/bin/sh
#
# remove all lustre modules.  Won't succeed if they're in use, or if you
# manually did a 'lctl network up'.
###############################################################################

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

lctl modules | awk '{ print $2 }' | xargs rmmod >/dev/null 2>&1
# do it again, in case we tried to unload the lnd's too early
lsmod | grep lnet > /dev/null && lctl modules | awk '{ print $2 }' | xargs rmmod
