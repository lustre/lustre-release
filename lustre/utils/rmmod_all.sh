#!/bin/sh

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

lctl modules | awk '{ print $2 }' | xargs rmmod >/dev/null 2>&1 
# do it again, in case we tried to unload ksocklnd too early
lctl modules | awk '{ print $2 }' | xargs rmmod
