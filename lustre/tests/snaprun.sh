#!/bin/sh
# Utility script to test several features of a snapshot filesystem
# Assumes that snapshot has already been configured
OBDDIR="`dirname $0`/.."
. $OBDDIR/demos/config.sh

qrun ls $MNTOBD
qrun chown bin.bin $MNTOBD
qrun ls -ld $MNTOBD
qrun ls -ld $MNTSNAP
qrun cp /etc/hosts $MNTOBD
qrun ls $MNTOBD
qrun ls $MNTSNAP

# More complicated because we can't pass ">>" as an argument easily
echo -n "Run 'echo today >> $MNTOBD/hello' [Y/n]" ; read JUNK
case $JUNK in
    n*|N*) echo "not run" ;;
    *)	plog log "echo today >> $MNTOBD/hello"
	echo "today" >> $MNTOBD/hello ;;
esac

qrun cat $MNTOBD/hello
qrun cat $MNTSNAP/hello
qrun cat $MNTOBD/link
qrun cat $MNTSNAP/link
qrun rm $MNTOBD/goodbye
qrun ls $MNTOBD
qrun ls $MNTSNAP
qrun cat $MNTSNAP/goodbye
