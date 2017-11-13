#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT=${ALWAYS_EXCEPT:-"$DOM_PERFORMANCE_EXCEPT"}
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

[ "$SLOW" = "no" ] && EXCEPT_SLOW=""

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}

. $LUSTRE/tests/test-framework.sh

init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

SAVED_FAIL_ON_ERROR=$FAIL_ON_ERROR
FAIL_ON_ERROR=false

SAVED_DEBUG=$($LCTL get_param -n debug 2> /dev/null)

check_and_setup_lustre

build_test_filter

DP_DNE=${DP_DNE:-"no"}
DP_DIO=${DP_DIO:-"no"}

DOM_SIZE=${DOM_SIZE:-"1M"}
DP_OSC="mdc"

rm -rf $DIR/*

DP_NORM=$DIR/dp_norm
DP_DOM=$DIR/dp_dom
DP_STATS=${DP_STATS:-"no"}

# total number of files
DP_FNUM=${DP_FNUM:-16384}
# number of threads
DP_NUM=${DP_NUM:-4}

# 1 stripe for normal files
mkdir -p $DP_NORM
$LFS setstripe -c 1 $DP_NORM ||
	error "Cannot create test directory for ordinary files"

if [ "x$DP_DNE" == "xyes" ] ; then
	$LFS setdirstripe -i 0 -c 2 $DP_DOM ||
		error "Cannot create striped directory"
else
	mkdir -p $DP_DOM
fi

$LFS setstripe -E ${DOM_SIZE} -L mdt -E EOF $DP_DOM ||
	error "Cannot create test directory for dom files"

dp_clear_stats() {
	local cli=$1

	$LCTL set_param -n osc.*.stats=0
	$LCTL set_param -n mdc.*.stats=0
	$LCTL set_param -n ${cli}.*.${cli}_stats=0
	$LCTL set_param -n ${cli}.*.rpc_stats=0
	$LCTL set_param -n llite.*.read_ahead_stats=0
	$LCTL set_param -n llite.*.unstable_stats=0
}

dp_collect_stats() {
	local cli=$1

	sync;sync
	echo ----- MDC RPCs: $(calc_stats mdc.*.stats req_active)
	echo ----- OSC RPCs: $(calc_stats osc.*.stats req_active)

	if [ "x$DP_STATS" != "xyes" ] ; then
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

dp_setup_test() {
	local cli=$1

	cancel_lru_locks $cli
	### drop all debug
	$LCTL set_param -n debug=0
	dp_clear_stats $cli
}

dp_run_cmd() {
	local cmd=$1
	local cmdlog=$TMP/dp_cmd.log
	local rc

	dp_setup_test $DP_OSC
	if ! grep -qw "$MOUNT" /proc/mounts ; then
		echo "!!!!! Lustre is not mounted !!!!!, aborting"
		return 0
	fi

	echo "## $cmd" | awk '{ if (NR==1) {gsub(/[ \t\r\n]+/, " "); \
				gsub(/\|.*$/, ""); print }}'
	echo "## $(date +'%F %H:%M:%S'): START"
	eval $cmd 2>&1 | tee $cmdlog || true

	rc=${PIPESTATUS[0]}
	if [ $rc -eq 0 ] && grep -q "p4_error:" $cmdlog ; then
		rc=1
	fi

	dp_collect_stats $DP_OSC
	remount_client $DIR > /dev/null
	return $rc
}

run_MDtest() {
	if ! which mdtest > /dev/null 2>&1 ; then
		echo "Mdtest is not installed, skipping"
		return 0
	fi

	local mdtest=$(which mdtest)

	local TDIR=${1:-$MOUNT}
	local th_num=$((DP_FNUM * 2 / DP_NUM))
	local bsizes="8192"

	[ "$SLOW" = "yes" ] && bsizes="4096 16384"

	for bsize in $bsizes ; do
		dp_run_cmd "mpirun -np $DP_NUM $mdtest -i 3 -I $th_num -F \
			-z 1 -b 1 -L -u -w $bsize -R -d $TDIR"
		if [ ${PIPESTATUS[0]} != 0 ]; then
			error "MDtest failed, aborting"
		fi
	done

	rm -rf $TDIR/*
	return 0
}

run_SmallIO() {
	if [ ! -f createmany ] ; then
		echo "Createmany is not installed, skipping"
		return 0
	fi

	if [ ! -f smalliomany ] ; then
		echo "Smalliomany is not installed, skipping"
		return 0
	fi

	local TDIR=${1:-$DIR}
	local count=$DP_FNUM

	local MIN=$((count * 16))
	[ $MDSSIZE -le $MIN ] && count=$((MDSSIZE / 16))

	dp_run_cmd "./createmany -o $TDIR/file- $count | grep 'total:'"
	if [ ${PIPESTATUS[0]} != 0 ]; then
		error "File creation failed, aborting"
	fi

	if [ -f statmany ]; then
		dp_run_cmd "./statmany -s $TDIR/file- $count $((count * 5)) |
			grep 'total:'"
		if [ ${PIPESTATUS[0]} != 0 ]; then
			error "File stat failed, aborting"
		fi

	fi

	for opc in w a r ; do
		dp_run_cmd "./smalliomany -${opc} $TDIR/file- $count 300 |
			grep 'total:'"
		if [ ${PIPESTATUS[0]} != 0 ]; then
			error "SmallIO -${opc} failed, aborting"
		fi

	done

	dp_run_cmd "./unlinkmany $TDIR/file- $count | grep 'total:'"
	if [ ${PIPESTATUS[0]} != 0 ]; then
		error "SmallIO failed, aborting"
	fi

	return 0
}

run_IOR() {
	if ! which IOR > /dev/null 2>&1 ; then
		echo "IOR is not installed, skipping"
		return 0
	fi

	local IOR=$(which IOR)
	local iter=$((DP_FNUM / DP_NUM))
	local direct=""

	if [ "x$DP_DIO" == "xyes" ] ; then
		direct="-B"
	fi

	local TDIR=${1:-$MOUNT}
	local bsizes="8"
	[ "$SLOW" = "yes" ] && bsizes="4 16"

	for bsize in $bsizes ; do
		segments=$((128 / bsize))

		dp_run_cmd "mpirun -np $DP_NUM $IOR \
			-a POSIX -b ${bsize}K -t ${bsize}K -o $TDIR/ -k \
			-s $segments -w -r -i $iter -F -E -z -m -Z $direct"
		if [ ${PIPESTATUS[0]} != 0 ]; then
			error "IOR write test for ${bsize}K failed, aborting"
		fi

		# check READ performance only (no cache)
		dp_run_cmd "mpirun -np $DP_NUM $IOR \
			-a POSIX -b ${bsize}K -t ${bsize}K -o $TDIR/ -X 42\
			-s $segments -r -i $iter -F -E -z -m -Z $direct"
		if [ ${PIPESTATUS[0]} != 0 ]; then
			error "IOR read test for ${bsize}K failed, aborting"
		fi

	done
	rm -rf $TDIR/*
	return 0
}

run_Dbench() {
	if ! which dbench > /dev/null 2>&1 ; then
		echo "Dbench is not installed, skipping"
		return 0
	fi

	if [ "x$DP_DNE" == "xyes" ] ; then
		echo "dbench uses subdirs, skipping for DNE setup"
		return 0
	fi

	local TDIR=${1:-$MOUNT}

	dp_run_cmd "dbench -D $TDIR $DP_NUM | egrep -v 'warmup|execute'"
	if [ ${PIPESTATUS[0]} != 0 ]; then
		error "Dbench failed, aborting"
	fi

	rm -rf $TDIR/*
	return 0
}

run_FIO() {
	# https://github.com/axboe/fio/archive/fio-2.8.zip
	if ! which fio > /dev/null 2>&1 ; then
		echo "No FIO installed, skipping"
		return 0
	fi

	local fnum=128 # per thread
	local total=$((fnum * DP_NUM)) # files in all threads
	local loops=$((DP_FNUM / total)) # number of loops
	local direct=""
	local output=""

	if [ $loops -eq 0 ] ; then
		loops=1
	fi

	if [ "x$DP_DIO" == "xyes" ] ; then
		direct="--direct=1"
	else
		direct="--buffered=1 --bs_unaligned=1"
	fi

	if [ "x$DP_STATS" != "xyes" ] ; then
		output="--minimal"
	fi

	local TDIR=${1:-$MOUNT}
	base_cmd="fio --name=smallio --ioengine=posixaio $output \
		  --iodepth=$((DP_NUM * 4)) --directory=$TDIR \
		  --nrfiles=$fnum --openfiles=10000 \
		  --numjobs=$DP_NUM --filesize=64k --lockfile=readwrite"

	dp_run_cmd "$base_cmd --create_only=1" > /dev/null
	if [ ${PIPESTATUS[0]} != 0 ]; then
		error "FIO file creation failed, aborting"
	fi

	local bsizes="8"
	[ "$SLOW" = "yes" ] && bsizes="4 16"

	for bsize in $bsizes ; do
		dp_run_cmd "$base_cmd --bs=${bsize}k --rw=randwrite $direct \
			 --file_service_type=random --randrepeat=1 \
			 --norandommap --group_reporting=1 --loops=$loops |
			awk -F\; '{printf \"WRITE: BW %dKiB/sec, IOPS %d, \
					lat (%d/%d/%d)usec\n\",\
					\$48, \$49, \$53, \$57, \$81}'"
		if [ ${PIPESTATUS[0]} != 0 ]; then
			error "FIO write test with ${bsize}k failed, aborting"
		fi

		dp_run_cmd "$base_cmd --bs=${bsize}k --rw=randread $direct \
			 --file_service_type=random --randrepeat=1 \
			 --norandommap --group_reporting=1 --loops=$loops |
			awk -F\; '{printf \"READ : BW %dKiB/sec, IOPS %d, \
					lat (%d/%d/%d)usec\n\",\
					\$7, \$8, \$12, \$16, \$40}'"
		if [ ${PIPESTATUS[0]} != 0 ]; then
			error "FIO read test with ${bsize}k failed, aborting"
		fi
	done
	rm -rf $TDIR/*
	return 0
}

dp_test_run() {
	local test=$1
	local facets=$(get_facets MDS)
	local nodes=$(comma_list $(mdts_nodes))
	local p="$TMP/$TESTSUITE-$TESTNAME.parameters"

	save_lustre_params $facets "mdt.*.dom_lock" >> $p

	printf "\n##### $test: DoM files, IO lock on open\n"
	do_nodes $nodes "lctl set_param -n mdt.*.dom_lock=1"
	DP_OSC="mdc"
	run_${test} $DP_DOM

	printf "\n##### $test: DoM files, no IO lock on open\n"
	do_nodes $nodes "lctl set_param -n mdt.*.dom_lock=0"
	DP_OSC="mdc"
	run_${test} $DP_DOM

	printf "\n##### $test: OST files\n"
	DP_OSC="osc"
	run_${test} $DP_NORM

	restore_lustre_params < $p
}

test_smallio() {
	dp_test_run SmallIO
}
run_test smallio "Performance comparision: smallio"

test_mdtest() {
	dp_test_run MDtest
}
run_test mdtest "Performance comparision: mdtest"

test_IOR() {
	dp_test_run IOR
}
run_test IOR "Performance comparision: IOR"

test_dbench() {
	dp_test_run Dbench
}
run_test dbench "Performance comparision: dbench"

test_fio() {
	dp_test_run FIO
}
run_test fio "Performance comparision: FIO"

FAIL_ON_ERROR=$SAVED_FAIL_ON_ERROR
$LCTL set_param -n debug="$SAVED_DEBUG"

complete $SECONDS
check_and_cleanup_lustre
exit_status
