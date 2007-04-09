#!/bin/bash

# This script will create a Lustre .xml configuration consisting
# of echo client/servers for use with the obdfilter-survey test

#######################################################################
# Customisation variables
#######################################################################

config=$(basename $0 .sh).xml

SERVERS=${SERVERS:-$(uname -n)}

NETS=${NETS:-tcp}

LMC=lmc
VERBOSE=1
BATCH=/tmp/lmc-batch.$$

#######################################################################
# some helpers: actual config below
#######################################################################

h2elan () {
     echo $1 | sed 's/[^0-9]*//g'
}

_LMC="${LMC} -m $config"

_lmc () {
     if [ $VERBOSE ]; then echo "$@"; fi
     if [ -n "$BATCH" ]; then
	echo "$@" >> $BATCH
     else
	$_LMC "$@"
     fi
}

config_end () {
     [ -n "$BATCH" ] && $_LMC --batch $BATCH
     cleanup
}

cleanup () {
     [ -n "$BATCH" ] && rm -f $BATCH
}

ABORT_ON="ERR QUIT INT HUP"

abort () {
     trap - EXIT $ABORT_ON
     echo "Error/Interrupt creating $config"
     cleanup
     exit 1
}

trap config_end EXIT
trap abort      $ABORT_ON

[ -f $config ] && rm $config

####################################################################
# the actual config
####################################################################

# client net
_lmc --node client --add net --nettype lnet --nid '*'

for srv in $SERVERS; do
     for net in $NETS; do
	case $net in
	    elan*) nid=`h2elan $srv`;;
	    gm*)   nid=`gmnalnid -n $srv`;;
	    *)     nid=$srv;;
	esac
	_lmc --node $srv --add net --nettype lnet --nid ${nid}@${net}
     done

     _lmc --node $srv --add ost --ost ost_$srv --osdtype=obdecho

     _lmc --node client --add echo_client --ost ost_$srv
done
