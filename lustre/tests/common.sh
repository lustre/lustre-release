#!/bin/sh
export PATH=$PATH:/sbin:/usr/sbin

[ -d /r ] && R=/r

PORTALS=$SRCDIR/../../portals
LUSTRE=$SRCDIR/../../obd

PTLCTL=$PORTALS/linux/utils/ptlctl
DBGCTL=$PORTALS/linux/utils/debugctl
ACCEPTOR=$PORTALS/linux/utils/acceptor

OBDCTL=$LUSTRE/utils/obdctl

LOOPNUM=0; export LOOPNUM
if [ -b /dev/loop0 ]; then
	LOOP=/dev/loop
elif [ -b /dev/loop/0 ]; then
	LOOP=/dev/loop/
else
	echo "Cannot find /dev/loop0 or /dev/loop/0" 1>&2 && exit -1
fi

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
new_fs () {
 	EFILE="$1_$3.gz"
	MKFS="mkfs.$1"
	MKFSOPT="-b 4096"

	[ "$1" = "ext3" ] && MKFS="mkfs.ext2 -j"

	if [ -b "$2" ]; then
		[ $# -lt 2 -o $# -gt 3 ] && \
			echo "usage: $0 <fstype> <file> [size]" 1>&2 && exit -1

		PM="/proc/mounts"
		[ -r "$PM" ] || PM="/etc/mtab"

		grep "$2 " $PM 1>&2 && echo "$0: $2 is in $PM!" 1>&2 && exit -1

		$MKFS $MKFSOPT $2 $3 || exit -1
		LOOPDEV=$2	# Not really a loop device
	else
		[ $# -ne 3 ] && \
			echo "usage: $0 <fstype> <file> <size>" 1>&2 && exit -1

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
}

# Set up to use an existing filesystem.  We take the same parameters as
# new_fs, even though we only use the <file> parameter, to make it easy
# to convert between new_fs and old_fs in testing scripts.
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
	echo "The GDB module script is in /tmp/ogdb"
	[ "$DEBUG_WAIT" = "yes" ] && echo -n "Press ENTER to continue" && read
}

# We need at least one setup file to be given.  It can be passed on
# the command-line, or it can be found in the home directory, or it
# can even be sourced into the current shell environment.
setup_opts() {
	DEF=$HOME/.lustretestrc
	[ -r $DEF ] && . $DEF && SETUP=y

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

do_insmod() {
	MODULE=$LUSTRE/$1

	[ "$MODULE" ] || fail "usage: $0 <module>"
	[ -f $MODULE ] || fail "$0: module '$MODULE' not found"

	lsmod | grep -q `basename $MODULE` || insmod $MODULE || exit -1
}

setup_portals() {
	if [ -z "$NETWORK" -o -z "$LOCALHOST" -o -z "$SERVER" ]; then
		echo "$0: NETWORK or LOCALHOST or SERVER is not set" 1>&2
		exit -1
	fi

	if [ "$LOCALHOST" == "$SERVER" ]; then
		DLM=localhost
	else
		DLM=$SERVER
	fi

	[ -c /dev/portals ] || mknod /dev/portals c 10 240

	insmod $PORTALS/linux/oslib/portals.o || exit -1

	case $NETWORK in
	elan)	[ "$PORT" ] && fail "$0: NETWORK is elan but PORT is set"
		insmod $PORTALS/linux/qswnal/kqswnal.o
		;;
	tcp)	[ "$PORT" ] || fail "$0: NETWORK is tcp but PORT is not set"
		insmod $PORTALS/linux/socknal/ksocknal.o || exit -1
		$ACCEPTOR $PORT
		;;
	*) 	fail "$0: unknown NETWORK '$NETWORK'" ;;
	esac

	$PTLCTL <<- EOF
	setup $NETWORK
	mynid $LOCALHOST
	connect $SERVER $PORT
	add_uuid self
	add_uuid mds
	add_uuid ost
	connect $DLM $PORT
	add_uuid ldlm
	quit
	EOF
}

setup_lustre() {
	[ -c /dev/obd ] || mknod /dev/obd c 10 241

	do_insmod class/obdclass.o
	do_insmod rpc/ptlrpc.o
	do_insmod ldlm/ldlm.o
	do_insmod mds/mds.o
	do_insmod obdecho/obdecho.o
	do_insmod ext2obd/obdext2.o
	do_insmod filterobd/obdfilter.o
	do_insmod ost/ost.o
	do_insmod osc/osc.o
	do_insmod mdc/mdc.o
	do_insmod llight/llite.o

	list_mods

	$OBDCTL <<- EOF || return $rc
	newdev
	attach ptlrpc RPCDEV
	setup
	quit
	EOF

	[ -d /mnt/lustre ] || mkdir /mnt/lustre
}

setup_ldlm() {
	[ -c /dev/portals ] || mknod /dev/portals c 10 240

	insmod $PORTALS/linux/oslib/portals.o || exit -1

	do_insmod class/obdclass.o
	do_insmod rpc/ptlrpc.o
	do_insmod ldlm/ldlm.o

	DEBUG_WAIT=yes
	list_mods
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

	$DO_FS ${MDSFS} ${MDSDEV} ${MDSSIZE}
	MDS=${LOOPDEV}

	$OBDCTL <<- EOF
	newdev
	attach mds MDSDEV
	setup ${MDS} ${MDSFS}
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

	$OBDCTL <<- EOF
	newdev
	attach ${OSTTYPE} OBDDEV
	setup ${OBD} ${OBDARG}
	newdev
	attach ost OSTDEV
	setup \$OBDDEV
	quit
	EOF
}

setup_server() {
	setup_mds $1 && setup_ost $1
}

setup_osc() {
	[ "$SETUP_OSC" != "y" ] && return 0

	$OBDCTL <<- EOF || return $rc
	newdev
	attach osc OSCDEV
	setup -1
	quit
	EOF
}

setup_mount() {
	[ "$SETUP_MOUNT" != "y" ] && return 0

	[ "$OSCMT" ] || fail "error: $0: OSCMT unset"

	[ ! -d $OSCMT ] && mkdir $OSCMT
	mount -t lustre_lite -o device=`find_devno OSCDEV` none $OSCMT
}

setup_client() {
	setup_osc && setup_mount
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
	$PTLCTL <<- EOF
	setup tcp
	disconnect
	del_uuid self
	del_uuid mds
	del_uuid ost
	del_uuid ldlm
	quit
	EOF

	rmmod kqswnal
	rmmod ksocknal
	rmmod portals
}

cleanup_lustre() {
	killall acceptor

	losetup -d ${LOOP}0
	losetup -d ${LOOP}1
	losetup -d ${LOOP}2

	rmmod llite
	rmmod mdc

	rmmod mds
	rmmod ost
	rmmod osc
	rmmod obdecho
	rmmod obdfilter
	rmmod obdext2

	rmmod ldlm
	rmmod ptlrpc
	rmmod obdclass
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
	[ "$SETUP" -a -z "$SETUP_MOUNT" ] && return 0

	[ "$OSCMT" ] || OSCMT=/mnt/lustre
	if [ "`mount | grep $OSCMT`" ]; then
		umount $OSCMT || fail "unable to unmount $OSCMT"
	fi
}

cleanup_osc() {
	[ "$SETUP" -a -z "$SETUP_OSC" ] && return 0

	OSCDEVNO=`find_devno OSCDEV`
	if [ "$OSCDEVNO" ]; then
		$OBDCTL <<- EOF
		device $OSCDEVNO
		cleanup
		detach
		quit
		EOF
	fi
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
	cleanup_mount && cleanup_osc && cleanup_rpc
}

fail() { 
    echo "ERROR: $1" 1>&2
    [ $2 ] && RC=$2 || RC=1
    exit $RC
}
