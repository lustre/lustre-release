#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT=""
[ "$SLOW" = "no" ] && EXCEPT_SLOW=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}

. $LUSTRE/tests/test-framework.sh
CLEANUP=${CLEANUP:-:}
SETUP=${SETUP:-:}
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

FAIL_ON_ERROR=false

check_and_setup_lustre

# $RUNAS_ID may get set incorrectly somewhere else
if [[ $UID -eq 0 && $RUNAS_ID -eq 0 ]]; then
	skip_env "\$RUNAS_ID set to 0, but \$UID is also 0!" && exit
fi
check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

build_test_filter

DOM="yes"
DOM_SIZE=${DOM_SIZE:-"1M"}
OSC="mdc"

rm -rf $DIR/*

NORM=$DIR/norm
DOM=$DIR/dom
STATS=${STATS:-"yes"}

# 1 stripe for normal files
mkdir -p $NORM
lfs setstripe -c 1 $NORM

if [ "x$DNE" == "xyes" ] ; then
	lfs setdirstripe -i 0 -c 2 $DOM
else
	mkdir -p $DOM
fi

lfs setstripe -E ${DOM_SIZE} -L mdt -E EOF $DOM

# total number of files
FNUM=16384
# number of threads
NUM=4

clear_stats() {
	local cli=$1

	$LCTL set_param -n ${cli}.*.${cli}_stats=0
	$LCTL set_param -n ${cli}.*.rpc_stats=0
	$LCTL set_param -n ${cli}.*.stats=0
	$LCTL set_param -n llite.*.read_ahead_stats=0
	$LCTL set_param -n llite.*.unstable_stats=0
}

collect_stats() {
	local cli=$1

	sync;sync

	if [ "x$STATS" != "xyes" ] ; then
		return 0
	fi

	$LCTL get_param ${cli}.*.${cli}_stats
	$LCTL get_param ${cli}.*.rpc_stats
	# for OSC get both OSC and MDC stats
	if [ $cli == "osc" ] ; then
		$LCTL get_param mdc.*.stats
	fi
	$LCTL get_param ${cli}.*.stats
	$LCTL get_param ${cli}.*.unstable_stats
	$LCTL get_param ${cli}.*.${cli}_cached_mb
	$LCTL get_param llite.*.read_ahead_stats
}

setup_test() {
	local cli=$1

	cancel_lru_locks $cli
	### drop all debug
	$LCTL set_param -n debug=0
	clear_stats $cli
}

run_cmd() {
	local cmd=$1

	setup_test $OSC
	if ! grep -qw "$MOUNT" /proc/mounts ; then
		echo "!!!!! Lustre is not mounted !!!!!, aborting"
		return 0
	fi

	echo "##### $cmd #####"
	echo "##### $(date +'%F %H:%M:%S'): START"
	eval $cmd
	echo "##### $(date +'%F %H:%M:%S'): GETSTATS"
	collect_stats $OSC
	echo "##### $(date +'%F %H:%M:%S'): STOP"
	remount_client $DIR

}

run_MDtest() {
	if ! which mdtest > /dev/null 2>&1 ; then
		echo "Mdtest is not installed, skipping"
		return 0
	fi

	local mdtest=$(which mdtest)

	local TDIR=${1:-$MOUNT}
	local th_num=$((FNUM * 2 / NUM))

	for bsize in 4096 ; do
		run_cmd "mpirun -np $NUM $mdtest \
			 -i 3 -I $th_num -F -z 1 -b 1 -L -u -w $bsize -d $TDIR"
	done
	rm -rf $TDIR/*
	return 0
}

run_smalliomany() {
	if [ ! -f createmany ] ; then
		echo "Createmany is not installed, skipping"
		return 0
	fi

	if [ ! -f smalliomany ] ; then
		echo "Smalliomany is not installed, skipping"
		return 0
	fi

	local TDIR=${1:-$DIR}
	local count=$FNUM

	local MIN=$((count * 16))
	[ $MDSSIZE -le $MIN ] && count=$((MDSSIZE / 16))

	run_cmd "./createmany -o $TDIR/file- $count | grep 'total'"

	if [ -f statmany ]; then
		run_cmd "./statmany -s $TDIR/file- $count $((count * 5)) | \
			grep 'total'"
	fi

	for opc in w a r ; do
		run_cmd "./smalliomany -${opc} $TDIR/file- $count 300 | \
			grep 'total'"
	done

	run_cmd "./unlinkmany $TDIR/file- $count | grep 'total'"
	return 0
}

run_IOR() {
	if ! which IOR > /dev/null 2>&1 ; then
		echo "IOR is not installed, skipping"
		return 0
	fi

	local IOR=$(which IOR)
	local iter=$((FNUM / NUM))

	if [ "x$DIO" == "xyes" ] ; then
		direct="-B"
	else
		direct=""
	fi

	local TDIR=${1:-$MOUNT}

	for bsize in 4 ; do
		segments=$((128 / bsize))

		run_cmd "mpirun -np $NUM $IOR \
			-a POSIX -b ${bsize}K -t ${bsize}K -o $TDIR/ -k \
			-s $segments -w -r -i $iter -F -E -z -m -Z $direct"
		# check READ performance only (no cache)
		run_cmd "mpirun -np $NUM $IOR \
			-a POSIX -b ${bsize}K -t ${bsize}K -o $TDIR/ -X 42\
			-s $segments -r -i $iter -F -E -z -m -Z $direct"
	done
	rm -rf $TDIR/*
	return 0
}

run_dbench() {
	if ! which dbench > /dev/null 2>&1 ; then
		echo "Dbench is not installed, skipping"
		return 0
	fi

	if [ "x$DNE" == "xyes" ] ; then
		echo "dbench uses subdirs, skipping for DNE setup"
		return 0
	fi

	local TDIR=${1:-$MOUNT}

	run_cmd "dbench -D $TDIR $NUM | egrep -v 'warmup|execute'"
	rm -rf $TDIR/*
	return 0
}

run_smallfile() {
	if ! which unzip > /dev/null 2>&1 ; then
		echo "No unzip is installed, skipping"
		return 0;
	fi

	if [ "x$DIO" == "xyes" ] ; then
		echo "smallfile has no DIRECT IO mode, skipping"
		return 0
	fi

	if [ "x$DNE" == "xyes" ] ; then
		echo "smallfile uses subdirs, skipping for DNE setup"
		return 0
	fi

	local host_set=$(hostname)

	### since smallfile is not installed system wide, get it right now
	[ -f master.zip ] || \
		wget https://github.com/bengland2/smallfile/archive/master.zip
	unzip -uo master.zip
	cd ./smallfile-master

	if ! ls ./smallfile_cli.py > /dev/null 2>&1 ; then
		echo "No smallfile test found, skipping"
		cd ..
		return 0
	fi

	local TDIR=${1:-$MOUNT}
	local thrds=$NUM
	local fsize=64 # in Kbytes
	local total=$FNUM # files in test
	local fnum=$((total / NUM))

	SYNC_DIR=${MOUNT}/sync
	mkdir -p $SYNC_DIR

	SMF="./smallfile_cli.py --pause 10 --host-set $host_set \
	     --response-times Y --threads $thrds --file-size $fsize \
	     --files $fnum --top $TDIR --network-sync-dir $SYNC_DIR \
	     --file-size-distribution exponential"

	run_cmd "$SMF --operation create"

	for oper in read append overwrite ; do
		for bsize in 8 ; do
			run_cmd "$SMF --record-size $bsize --operation $oper"
		done
	done
	run_cmd "$SMF --operation delete"

	rm -rf $TDIR/*
	cd ..
	return 0
}

test_smallio() {
	OSC="mdc"
	run_smalliomany $DOM
	echo "### Data-on-MDT files, no IO lock on open ###"
	do_facet $SINGLEMDS lctl set_param -n mdt.*.dom_lock=0
	OSC="mdc"
	run_smalliomany $DOM
	do_facet $SINGLEMDS lctl set_param -n mdt.*.dom_lock=1
	OSC="osc"
	run_smalliomany $NORM
}
run_test smallio "Performance comparision: smallio"

test_mdtest() {
	OSC="mdc"
	run_MDtest $DOM
	echo "### Data-on-MDT files, NO IO lock on open ###"
	do_facet $SINGLEMDS lctl set_param -n mdt.*.dom_lock=0
	OSC="mdc"
	run_MDtest $DOM
	do_facet $SINGLEMDS lctl set_param -n mdt.*.dom_lock=1
	echo "### Normal files, $OSTCOUNT OSTs ###"
	OSC="osc"
	run_MDtest $NORM
}
run_test mdtest "Performance comparision: mdtest"

test_IOR() {
	OSC="mdc"
	run_IOR $DOM
	echo "### Data-on-MDT files, no IO lock on open ###"
	do_facet $SINGLEMDS lctl set_param -n mdt.*.dom_lock=0
	OSC="mdc"
	run_IOR $DOM
	do_facet $SINGLEMDS lctl set_param -n mdt.*.dom_lock=1
	OSC="osc"
	run_IOR $NORM
}
run_test IOR "Performance comparision: IOR"

test_dbench() {
	OSC="mdc"
	run_dbench $DOM
	echo "### Data-on-MDT files, no IO lock on open ###"
	do_facet $SINGLEMDS lctl set_param -n mdt.*.dom_lock=0
	OSC="mdc"
	run_dbench $DOM
	do_facet $SINGLEMDS lctl set_param -n mdt.*.dom_lock=1
	OSC="osc"
	run_dbench $NORM
}
run_test dbench "Performance comparision: dbench"

test_smf() {
	OSC="mdc"
	run_smallfile $DOM
	echo "### Data-on-MDT files, no IO lock on open ###"
	do_facet $SINGLEMDS lctl set_param -n mdt.*.dom_lock=0
	OSC="mdc"
	run_smallfile $DOM
	do_facet $SINGLEMDS lctl set_param -n mdt.*.dom_lock=1
	OSC="osc"
	run_smallfile $NORM

}
run_test smf "Performance comparision: smallfile"

complete $SECONDS
check_and_cleanup_lustre
exit_status
