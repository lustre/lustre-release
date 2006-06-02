#!/bin/sh

# Given one or more Lustre objects, create a mon configuration file
# naming the mon watches based on the Lustre object names 
# For each Lustre object, the script will create two mon watches
# The first watch sets a trap, and the second watch clears the 
# trap if Lustre is healthy.

# This may be more fun in Perl due to the need to support a list
# of objects

# (plus we could use a Perl format for this goop)

MONBASEDIR=${MONBASEDIR:-/usr/local/lib/mon}
MONCFGDIR=${MONCFGDIR:-/etc/mon}
TD=`date +%y_%m%d_%S`
TMPMONCFG=${TD}-mon.cfg
# Determines how often we will check Lustre health
CHECKINTERVAL="3m"
# Determines how quickly we must clear the trap
TRAPINTERVAL="6m"
ALERTSCRIPT=${ALERTSCRIPT:-"fail_lustre.alert"}
TRAPSCRIPT=${TRAPSCRIPT:-"lustre.mon.trap"}

# We will assume all inputs are Lustre objects
# file locations and timeouts correct to taste
# Correct to taste
print_header() {
    cat >> $TMPMONCFG <<-EOF
	cfbasedir     = $MONCFGDIR
	alertdir      = $MONBASEDIR/alert.d
	mondir        = $MONBASEDIR/mon.d
	statedir      = $MONBASEDIR/state.d
	logdir        = $MONBASEDIR/log.d
	dtlogfile     = $MONBASEDIR/log.d/downtime.log
	maxprocs      = 20 
	histlength    = 100 
	randstart     = 60s
	authtype      = getpwnam
EOF
}

# Tabs should be preserved in the config file
# $1 object name
# we do not set a period, it is assumed monitor is always active

print_trap_rec() {
    cat >> $TMPMONCFG <<EOF
#
watch ${1}-obj
    service ${1}_ser
    description triggers heartbeat failure if trap springs on $1
    traptimeout $TRAPINTERVAL
    period 
	alert $ALERTSCRIPT

# end ${1}-obj

EOF

}

print_trap_send() {
    cat >> $TMPMONCFG <<EOF
#
watch ${1}-mon
    service ${1}_mon_ser
    description clears trap for $1
    interval $CHECKINTERVAL
    monitor $TRAPSCRIPT ${1}-obj ${1}_ser ${1}
    period
	alert $ALERTSCRIPT
# end ${1}-mon
EOF

}

usage() {
    echo "$0 -n <node> -n <node> -o <Lustre object> -o <Lustre object>...."
    echo "Creates the /etc/mon/mon.cf file to monitor Lustre objects"
    exit 1
}


# Start of script

if [ $# -eq 0 ];then
    usage
fi

# This script should work for any number of hosts
# 
HOSTCNT=0
OBJCNT=0

declare -a HOSTS
declare -a OBJS

while getopts "n:o:" opt; do
    case $opt in 
	n) HOSTS[HOSTCNT]=$OPTARG
	    HOSTCNT=$(( HOSTCNT + 1 ))
	    ;;
	o) OBJS[OBJCNT]=$OPTARG
	    OBJCNT=$(( OBJCNT + 1 ))
	    ;;
	*) usage
	    ;;
    esac
done

echo "Found $HOSTCNT hosts"
echo "Found $OBJCNT Lustre objects"

# First create the host groups
# we assume 
# each object will have two watches defined
# each object hostgroup will have all objects

# Create the file with the declared goop
print_header

for obj in ${OBJS[@]}
do
    echo "hostgroup ${obj}-obj ${HOSTS[@]}" >> $TMPMONCFG
    echo "hostgroup ${obj}-mon ${HOSTS[@]}" >> $TMPMONCFG
    echo "#" >> $TMPMONCFG
done
    
# create the monitors

for obj in ${OBJS[@]}
do
    print_trap_send $obj
    print_trap_rec $obj
done

echo "Mon config completed - new mon config is $TMPMONCFG"
exit 0