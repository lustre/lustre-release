#!/bin/sh
export PATH=$PATH:/sbin:/usr/sbin

[ -d /r ] && R=/r

# check if running in source directory
# will probably need to create variable for each module.
if [ -f $SRCDIR/Makefile.am ]; then
	USEDEV=yes
	PORTALS=$SRCDIR/../../portals
	LUSTRE=$SRCDIR/..

	PTLCTL=$PORTALS/linux/utils/ptlctl
	DBGCTL=$PORTALS/linux/utils/debugctl
	ACCEPTOR=$PORTALS/linux/utils/acceptor

	OBDCTL=$LUSTRE/utils/obdctl
else
	USEDEV=no
	# should have configure set the paths here
	BINDIR=/usr/sbin
	PORTALS=/lib/modules
	LUSTRE=/lib/modules

	PTLCTL=$BINDIR/ptlctl
	DBGCTL=$BINDIR/debugctl
	ACCEPTOR=$BINDIR/acceptor
	OBDCTL=$BINDIR/obdctl
fi

LOOPNUM=0; export LOOPNUM
if [ -b /dev/loop0 ]; then
	LOOP=/dev/loop
elif [ -b /dev/loop/0 ]; then
	LOOP=/dev/loop/
else
	echo "Cannot find /dev/loop0 or /dev/loop/0" 1>&2 && exit -1
fi

do_insmod() {
	MODULE=$1
	BASE=`echo $MODULE | sed -e "s^.*/^^" -e "s/\.o$//"`

	lsmod | grep -q "\<$BASE\>" && return 0
	[ "$MODULE" ] || fail "usage: $0 <module>"

	if [ "$USEDEV" = "yes" ]; then
		[ -f $MODULE ] || echo "$0: module '$MODULE' not found" 1>&2
		insmod $MODULE
	else
		modprobe $BASE
	fi
}

do_rmmod() {
	MODULE=$1
	[ "$MODULE" ] || fail "usage: $0 <module>"
	lsmod | grep -q $MODULE || return 0
	rmmod $MODULE || lsmod | sed "s/^/$MODULE failed: /"
}

# Return the next unused loop device on stdout and in the $LOOPDEV
# environment variable.
next_loop_dev() {
	NEXT=
	while [ -b ${LOOP}${LOOPNUM} ]; do
		LOOPDEV=${LOOP}${LOOPNUM}
		losetup ${LOOPDEV} > /dev/null 2>&1 || NEXT=${LOOPDEV}
		LOOPNUM=`expr ${LOOPNUM} + 1`
		[ "$NEXT" ] && echo ${NEXT} && break
	done
}

# Create a new filesystem.  If we are using a loopback device, we check
# for existing "template" filesystems instead of creating a new one,
# because it is _much_ faster to gunzip the empty filesystem instead of
# creating a new one from scratch.  Conversely, if we are creating a
# filesystem on a device we use mkfs, because that only writes sparsely
# to the device.  The empty filesystems are also highly compressed (1000:1)
# so they don't take too much space.
#
new_fs_usage() {
	echo "new_fs <fstype> {device | file} [size]" 1>&2
	exit -1
}
new_fs () {
 	EFILE="$1_$3.gz"
	MKFS="mkfs.$1"
	MKFSOPT="-b 4096"

	[ "$1" = "ext3" ] && MKFS="mkfs.ext2 -j"
	if [ "$1" = "extN" ]; then
		MKFS="mkfs.ext2 -j"
		EFILE="ext3_$3.gz"
	fi

	if [ -b "$2" ]; then
		[ $# -lt 2 -o $# -gt 3 ] && new_fs_usage

		PM="/proc/mounts"
		[ -r "$PM" ] || PM="/etc/mtab"

		grep "$2 " $PM 1>&2 && echo "$0: $2 is in $PM!" 1>&2 && exit -1

		$MKFS $MKFSOPT $2 $3 || exit -1
		LOOPDEV=$2	# Not really a loop device
	else
		[ $# -ne 3 ] && new_fs_usage

		if [ -r "$EFILE" ]; then
			echo "using prepared filesystem $EFILE for $2"
			zcat "$EFILE" > $2 || exit -1
			sync
		else
			echo "creating new sparse filesystem on $2"
			dd if=/dev/zero of=$2 bs=1k seek=$3 count=1 1>&2 || exit -1
			$MKFS $MKFSOPT -F $2 1>&2 || exit -1
		fi
		LOOPDEV=`next_loop_dev`
		losetup ${LOOPDEV} $2 1>&2 || exit -1
	fi

	# Enable hash-indexed directories for extN filesystems
#	[ "$1" = "extN" ] && echo "feature FEATURE_C5" | debugfs -w $2
}

# Set up to use an existing filesystem.  We take the same parameters as
# new_fs, even though we only use the <fstype> and <file> parameters, to
# make it easy to convert between new_fs and old_fs in testing scripts.
old_fs () {
	[ -e $2 ] || exit -1

	if [ -b "$2" ]; then
		LOOPDEV=$2	# Not really a loop device
	else
		LOOPDEV=`next_loop_dev`
		losetup ${LOOPDEV} $2 1>&2 || exit -1
	fi
}

list_mods() {
	$DBGCTL modules > $R/tmp/ogdb
	echo "The GDB module script is in $R/tmp/ogdb"
	[ "$DEBUG_WAIT" = "yes" ] && echo -n "Press ENTER to continue" && read
	return 0
}

# start acceptor for a given network and port.
# not all networks need an acceptor
start_acceptor() {
	case $NETWORK in
	elan)   [ "$PORT" ] && fail "$0: NETWORK is elan but PORT is set"
		;;
	tcp)    [ "$PORT" ] || fail "$0: NETWORK is tcp but PORT is not set"
		$ACCEPTOR $PORT
		;;
	*) 	fail "$0: unknown NETWORK '$NETWORK'" ;;
	esac

}

# We need at least one setup file to be given.  It can be passed on
# the command-line, or it can be found in the home directory, or it
# can even be sourced into the current shell environment.
setup_opts() {
	DEF=/etc/lustre/lustre.cfg
	if [ "$#" = 0 -a -r $DEF ]; then
		. $DEF && SETUP=y
	fi

	for CFG in "$@" ; do
		case $CFG  in
		*.cfg) [ -r "$CFG" ] && . $CFG && SETUP=y ;;
		*) echo "unknown option '$CFG'" 1>&2
		esac
	done

	if [ "$SETUP" != "y" ]; then
		echo "error: no config file on command-line and no $DEF" 1>&2
		exit -1
	fi
	
	[ -z "$MDS_RSH" ] && MDS_RSH="eval"
	[ -z "$OST_RSH" ] && OST_RSH="eval"
	[ -z "$OSC_RSH" ] && OSC_RSH="eval"
}

setup_variables() {
	[ -z "$OSTNODE" ] && OSTNODE=$SERVER
	[ -z "$MDSNODE" ] && MDSNODE=$SERVER
	[ -z "$DLM" ] && DLM=$SERVER
}

setup_portals() {
	setup_variables

	if grep -q portals /proc/modules; then
		echo "$0: portals already appears to be set up, skipping"
		return 0
	fi

	if [ -z "$NETWORK" -o -z "$LOCALHOST" -o -z "$SERVER" ]; then
		echo "$0: NETWORK or LOCALHOST or SERVER is not set" 1>&2
		exit -1
	fi

	[ -c /dev/portals ] || mknod /dev/portals c 10 240

  	do_insmod $PORTALS/linux/oslib/portals.o || exit -1

	case $NETWORK in
	elan)  do_insmod $PORTALS/linux/qswnal/kqswnal.o || exit -1
		    ;;
	tcp)   do_insmod $PORTALS/linux/socknal/ksocknal.o || exit -1
		   ;;
	*) 	fail "$0: unknown NETWORK '$NETWORK'" ;;
	esac

	start_acceptor

	$PTLCTL <<- EOF
	setup $NETWORK
	mynid $LOCALHOST
	connect $MDSNODE $PORT
	add_uuid $MDSNODE
	connect $OSTNODE $PORT
	add_uuid $OSTNODE
	connect $DLM $PORT
	add_uuid $DLM
	add_uuid self
	quit
EOF
}

setup_lustre() {
	[ -c /dev/obd ] || mknod /dev/obd c 10 241

	do_insmod $LUSTRE/obdclass/obdclass.o || exit -1
	do_insmod $LUSTRE/ptlrpc/ptlrpc.o || exit -1
	do_insmod $LUSTRE/ldlm/ldlm.o || exit -1
	do_insmod $LUSTRE/extN/extN.o || \
		echo "info: can't load extN.o module, not fatal if using ext3"
	do_insmod $LUSTRE/mds/mds.o || exit -1
	#do_insmod $LUSTRE/mds/mds_ext2.o || exit -1
	#do_insmod $LUSTRE/mds/mds_ext3.o || exit -1
	do_insmod $LUSTRE/mds/mds_extN.o || \
		echo "info: can't load mds_extN.o module, needs extN.o"
	do_insmod $LUSTRE/obdecho/obdecho.o || exit -1
	#do_insmod $LUSTRE/obdext2/obdext2.o || exit -1
	do_insmod $LUSTRE/obdfilter/obdfilter.o || exit -1
	do_insmod $LUSTRE/ost/ost.o || exit -1
	do_insmod $LUSTRE/osc/osc.o || exit -1
	do_insmod $LUSTRE/mdc/mdc.o || exit -1
		do_insmod $LUSTRE/lov/lov.o || exit -1
	do_insmod $LUSTRE/llite/llite.o || exit -1

	echo "$R/tmp/lustre-log" > /proc/sys/portals/debug_path

	if $OBDCTL name2dev RPCDEV > /dev/null 2>&1; then
		echo "$0: RPCDEV is already configured, skipping"
		return 0
	fi
	list_mods

	$OBDCTL <<- EOF || return $?
	newdev
	attach ptlrpc RPCDEV
	setup
	quit
	EOF

	[ -d /mnt/lustre ] || mkdir /mnt/lustre
}

setup_ldlm() {
	[ "$SETUP_LDLM" = "y" ] || return 0

	[ -c /dev/portals ] || mknod /dev/portals c 10 240

	$OBDCTL <<- EOF || return $?
	newdev
	attach ldlm LDLMDEV
	setup
	quit
	EOF
}

find_devno() {
	if [ -z "$1" ]; then
		echo "usage: $0 <devname>" 1>&2
		return -1
	fi

	$OBDCTL name2dev $1
}

setup_mds() {
	[ "$SETUP_MDS" = "y" ] || return 0

	if [ -z "$MDSFS" -o -z "$MDSDEV" ]; then
		echo "error: setup_mds: MDSFS or MDSDEV unset" 1>&2
		return -1
	fi

	[ "$1" ] && DO_FS=$1
	if [ "$DO_FS" != "new_fs" -a "$DO_FS" != "old_fs" ]; then
		echo "usage: setup_mds {new_fs|old_fs}" 1>&2
		return -1
	fi

	if $OBDCTL name2dev MDSDEV > /dev/null 2>&1; then
		echo "$0: MDSDEV is already configured"
		return 0
	fi

	$DO_FS ${MDSFS} ${MDSDEV} ${MDSSIZE}
	MDS=${LOOPDEV}

	$OBDCTL <<- EOF || return $?
	newdev
	attach mds MDSDEV MDSUUID  
	setup ${MDS} ${MDSFS}
	quit
	EOF
}

setup_mds_lov() { 

	[ "$SETUP_MDS" = "y" ] || return 0

	if [ -z "$LOVUUID" ]; then
		echo "No LOV configured"
			return
	fi

	$OBDCTL <<- EOF || return $?
	name2dev MDSDEV
	connect 
	lovconfig ${LOVUUID} 1 4096 0 OSCUUID
	disconnect
	quit
	EOF
}


setup_ost() {
	[ "$SETUP_OST" = "y" ] || return 0

	if [ -z "$OSTTYPE" ]; then
		echo "error: setup_ost: OSTTYPE unset" 1>&2
		return -1
	fi

	case $OSTTYPE in
	obdecho)	OBD=
			OBDARG=
			NEED_FS=n
		;;
	obdext2)	OBDARG=
			NEED_FS=y
		;;
	obdfilter)	OBDARG=$OSTFS
			NEED_FS=y
		;;
	*)	echo "error: setup_ost: unknown OSTTYPE '$OSTTYPE'" 1>&2
		return -1
		;;
	esac

	if $OBDCTL name2dev OBDDEV > /dev/null 2>&1; then
		echo "$0: OBDDEV is already configured"
		return 0
	fi

	if [ "$NEED_FS" = "y" ]; then
		[ "$1" ] && DO_FS=$1
		if [ -z "$OSTFS" -o -z "$OSTDEV" ]; then
			echo "error: setup_ost: OSTFS or OSTDEV unset" 1>&2
			return -1
		fi

		if [ "$DO_FS" != "new_fs" -a "$DO_FS" != "old_fs" ]; then
			echo "usage: setup_ost {new_fs|old_fs}" 1>&2
			return -1
		fi

		$DO_FS ${OSTFS} ${OSTDEV} ${OSTSIZE}
		OBD=${LOOPDEV}
	fi

	$OBDCTL <<- EOF || return $?
	newdev
	attach ${OSTTYPE} OBDDEV OBDUUID
	setup ${OBD} ${OBDARG}
	quit
	EOF

	$OBDCTL <<- EOF || return $?
	newdev
	attach ost OSTDEV OSTUUID
	setup \$OBDDEV
	quit
	EOF
}

setup_server() {
	#setup_mds $1 && setup_mds_lov $1 && setup_ost $1
	setup_mds $1 && setup_ost $1
}

setup_osc() {
	set -vx
	[ "$SETUP_OSC" != "y" ] && return 0
	[ "$OSC_NAMES" ] || OSC_NAMES=OSCDEV

	for THEOSC in $OSC_NAMES ; do 
		if $OBDCTL name2dev $THEOSC > /dev/null 2>&1; then
			echo "$0: OSCDEV is already configured"
			continue
		fi

		$OBDCTL <<- EOF || return $rc
		newdev
		attach osc $THEOSC ${THEOSC}-UUID
		setup OBDUUID $OSTNODE
		quit
		EOF
	done
}

setup_mdc() {
	set -vx
	[ "$SETUP_MDC" != "y" ] && return 0
	[ "$MDC_NAMES" ] || MDC_NAMES=MDCDEV

	for THEMDC in $MDC_NAMES ; do 
		if $OBDCTL name2dev $THEMDC > /dev/null 2>&1; then
			echo "$0: MDCDEV is already configured"
			continue
		fi

		$OBDCTL <<- EOF || return $?
		newdev
		attach mdc $THEMDC ${THEMDC}-UUID
		setup MDSUUID $MDSNODE
		quit
		EOF
	done
}

setup_lov () { 
	[ "$SETUP_MDC" != "y" ] && return 0

	if [ -z "$LOVUUID" ]; then
		echo "No LOV configured"
		return
	fi

	$OBDCTL <<- EOF || return $?
	newdev
	attach lov LOVNAME  ${LOVUUID}
	setup  MDCDEV-UUID
	quit
	EOF
}        


setup_mount() {
	set -vx
	[ "$SETUP_MOUNT" != "y" ] && return 0
	[ "$MDC_NAMES" ] || MDC_NAMES=MDCDEV
	[ "$OSC_NAMES" ] || OSC_NAMES=OSCDEV
	[ -z "$MOUNT_LIST" -a "$OSCMT" ] && MOUNT_LIST="MT" && MT="$OSCMT OSCDEV MDCDEV"

	[ "$MOUNT_LIST" ] || fail "error: $0: MOUNT_LIST unset"

	for THEMOUNT in $MOUNT_LIST; do
	    eval "echo \$$THEMOUNT" | while read MTPT THEOSC THEMDC; do
		if mount | grep -q $MTPT; then
		    echo "$0: $MTPT is already mounted"
		    return 0
		fi

		[ ! -d $MTPT ] && mkdir $MTPT
		echo mount -t lustre_lite -o ost=${THEOSC}-UUID,mds=${THEMDC}-UUID none $MTPT
		mount -t lustre_lite -o ost=${THEOSC}-UUID,mds=${THEMDC}-UUID none $MTPT
	    done
	done
}

setup_client() {
	# setup_osc && setup_mdc && setup_lov  && setup_mount
	setup_osc && setup_mdc && setup_mount
}

DEBUG_ON="echo 0xffffffff > /proc/sys/portals/debug"
DEBUG_OFF="echo 0 > /proc/sys/portals/debug"

debug_server_off() {
	[ "$MDS_RSH" ] && echo "Turn OFF debug on MDS" && $MDS_RSH "$DEBUG_OFF"
	[ "$OST_RSH" ] && echo "Turn OFF debug on OST" && $OST_RSH "$DEBUG_OFF"
}

debug_server_on() {
	[ "$MDS_RSH" ] && echo "Turn ON debug on MDS" && $MDS_RSH "$DEBUG_ON"
	[ "$OST_RSH" ] && echo "Turn ON debug on OST" && $OST_RSH "$DEBUG_ON"
}

debug_client_off() {
	echo "Turning OFF debug on client" && $OSC_RSH "$DEBUG_OFF"
}

debug_client_on() {
	echo "Turning ON debug on client" && $OSC_RSH "$DEBUG_ON"
}

cleanup_portals() {
	[ -z "$NETWORK" ] && NETWORK=tcp

	setup_variables

	$PTLCTL <<- EOF
	setup $NETWORK
	disconnect
	del_uuid self
	del_uuid $MDSNODE
	del_uuid $OSTNODE
	del_uuid $DLM
	quit
	EOF

	do_rmmod ldlm
	do_rmmod ptlrpc
	do_rmmod obdclass

	#do_rmmod kqswnal
	do_rmmod ksocknal
	do_rmmod kptlrouter

	do_rmmod portals
}

cleanup_lustre() {
	killall acceptor

	do_rmmod llite
	do_rmmod lov
	do_rmmod mdc
	do_rmmod osc

	do_rmmod mds_extN
	do_rmmod mds_ext3
	do_rmmod mds_ext2
	do_rmmod mds
	do_rmmod ost
	do_rmmod obdecho
	do_rmmod obdfilter
	do_rmmod obdext2
	do_rmmod extN

	losetup -d ${LOOP}0
	losetup -d ${LOOP}1
	losetup -d ${LOOP}2
}

cleanup_ldlm() {
	[ "$SETUP" -a -z "$SETUP_LDLM" ] && return 0

	LDLMDEVNO=`find_devno LDLMDEV`
	if [ "$LDLMDEVNO" ]; then
		$OBDCTL <<- EOF
		device $LDLMDEVNO
		cleanup
		detach
		quit
		EOF
	fi
}

cleanup_mds() {
	[ "$SETUP" -a -z "$SETUP_MDS" ] && return 0

	MDSDEVNO=`find_devno MDSDEV`
	if [ "$MDSDEVNO" ]; then
		$OBDCTL <<- EOF
		device $MDSDEVNO
		cleanup
		detach
		quit
		EOF
	fi
}

cleanup_ost() {
	[ "$SETUP" -a -z "$SETUP_OST" ] && return 0

	OSTDEVNO=`find_devno OSTDEV`
	if [ "$OSTDEVNO" ]; then
		$OBDCTL <<- EOF
		device $OSTDEVNO
		cleanup
		detach
		quit
		EOF
	fi

	OBDDEVNO=`find_devno OBDDEV`
	if [ "$OBDDEVNO" ]; then
		$OBDCTL <<- EOF
		device $OBDDEVNO
		cleanup
		detach
		quit
		EOF
	fi
}

cleanup_server() {
	cleanup_ost && cleanup_mds
}

cleanup_mount() {
	set -vx
	[ "$SETUP_MOUNT" != "y" ] && return 0
	[ "$MDC_NAMES" ] || MDC_NAMES=MDCDEV
	[ "$OSC_NAMES" ] || OSC_NAMES=OSCDEV
	[ -z "$MOUNT_LIST" -a "$OSCMT" ] && MOUNT_LIST="MT" && MT="$OSCMT OSCDEV MDCDEV"

	[ "$MOUNT_LIST" ] || fail "error: $0: MOUNT_LIST unset"

	for THEMOUNT in $MOUNT_LIST; do
		eval "echo \$$THEMOUNT" | while read MTPT THEOSC THEMDC; do
			if [ "`mount | grep $MTPT`" ]; then
				umount $MTPT || fail "unable to unmount $MTPT"
			fi
		done
	done
}

cleanup_osc() {
	[ "$SETUP" -a -z "$SETUP_OSC" ] && return 0
	[ "$OSC_NAMES" ] || OSC_NAMES=OSCDEV

	for THEOSC in $OSC_NAMES ; do 
		OSCDEVNO=`find_devno $THEOSC`
		if [ "$OSCDEVNO" ]; then
			$OBDCTL <<- EOF
			device $OSCDEVNO
			cleanup
			detach
			quit
			EOF
		fi
	done
}

cleanup_mdc() {
	[ "$SETUP" -a -z "$SETUP_MDC" ] && return 0
	[ "$MDC_NAMES" ] || MDC_NAMES=MDCDEV

	for THEMDC in $MDC_NAMES ; do 
		MDCDEVNO=`find_devno $THEMDC`
		if [ "$MDCDEVNO" ]; then
			$OBDCTL <<- EOF
			device $MDCDEVNO
			cleanup
			detach
			quit
			EOF
		fi
	done
}

cleanup_rpc() {
	RPCDEVNO=`find_devno RPCDEV`
	if [ "$RPCDEVNO" ]; then
		$OBDCTL <<- EOF
		device $RPCDEVNO
		cleanup
		detach
		quit
		EOF
	fi
}

cleanup_client() {
	cleanup_mount && cleanup_osc && cleanup_mdc && cleanup_rpc
}

fail() { 
	echo "ERROR: $1" 1>&2
	[ $2 ] && RC=$2 || RC=1
	exit $RC
}
