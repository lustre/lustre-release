#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
init_logging

ALWAYS_EXCEPT="$DOM_PERFORMANCE_EXCEPT"
build_test_filter

SAVED_FAIL_ON_ERROR=$FAIL_ON_ERROR
FAIL_ON_ERROR=false

SAVED_DEBUG=$($LCTL get_param -n debug 2> /dev/null)

. $LUSTRE/tests/functions.sh
check_and_setup_lustre

clients=${CLIENTS:-$HOSTNAME}
generate_machine_file $clients $MACHINEFILE ||
	error "Failed to generate machine file"

DP_DIO=${DP_DIO:-"no"}

DOM_SIZE=${DOM_SIZE:-"1M"}
DP_OSC="mdc"

DP_NORM=$DIR/dp_norm
DP_DOM=$DIR/dp_dom
DP_DOM_DNE=$DIR/dp_dne
DP_STATS=${DP_STATS:-"no"}

if $DO_CLEANUP; then
	rm -rf $DIR/*
else
	rm -rf $DP_NORM $DP_DOM $DP_DOM_DNE
fi

# total number of files
DP_FNUM=${DP_FNUM:-16384}
# number of threads
DP_NUM=${DP_NUM:-4}

# 1 stripe for normal files
mkdir -p $DP_NORM
$LFS setstripe -c 2 $DP_NORM ||
	error "Cannot create test directory for ordinary files"

if [[ $MDSCOUNT -gt 1 ]] ; then
	$LFS setdirstripe -i 0 -c $MDSCOUNT $DP_DOM_DNE ||
		error_noexit "Cannot create striped directory"
	$LFS setstripe -E ${DOM_SIZE} -L mdt -E EOF $DP_DOM_DNE ||
		error_noexit "Cannot create test directory for dom files"
fi

mkdir -p $DP_DOM
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
	### drop all debug except critical
	$LCTL set_param -n debug="error warning console emerg"
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
		skip_env "Mdtest is not installed, skipping"
	fi

	local mdtest=$(which mdtest)

	local TDIR=${1:-$MOUNT}
	local th_num=$((DP_FNUM * 2 / DP_NUM))
	local bsizes="8192"

	chmod 0777 $TDIR

	[ "$SLOW" = "yes" ] && bsizes="4096 32768"

	for bsize in $bsizes ; do
		dp_run_cmd "mpi_run -np $DP_NUM $mdtest -i 3 -I $th_num -F \
			-z 1 -b 1 -L -u -w $bsize -R -d $TDIR"
		if [ ${PIPESTATUS[0]} != 0 ]; then
			error "MDtest failed, aborting"
		fi
	done

	rm -rf $TDIR/*
	return 0
}

run_SmallIO() {
	local TDIR=${1:-$DIR}
	local count=$DP_FNUM

	local MIN=$((count * 16))
	local mdssize=$(mdssize_from_index $TDIR 0)
	[ $mdssize -le $MIN ] && count=$((mdssize / 16))

	dp_run_cmd "createmany -o $TDIR/file- $count | grep 'total:'"
	if [ ${PIPESTATUS[0]} != 0 ]; then
		error "File creation failed, aborting"
	fi

	dp_run_cmd "statmany -s $TDIR/file- $count $((count * 5)) |
		grep 'total:'"
	if [ ${PIPESTATUS[0]} != 0 ]; then
		error "File stat failed, aborting"
	fi

	for opc in w a r ; do
		dp_run_cmd "smalliomany -${opc} $TDIR/file- $count 300 |
			grep 'total:'"
		if [ ${PIPESTATUS[0]} != 0 ]; then
			error "SmallIO -${opc} failed, aborting"
		fi

	done

	dp_run_cmd "unlinkmany $TDIR/file- $count | grep 'total:'"
	if [ ${PIPESTATUS[0]} != 0 ]; then
		error "SmallIO failed, aborting"
	fi

	return 0
}

run_IOR() {
	if ! which IOR > /dev/null 2>&1 ; then
		skip_env "IOR is not installed, skipping"
	fi

	# Requires at least 20GB (roughly)
	(( MDSSIZE >= 20000000 )) || skip "Require MDS of at least 20GB"

	local IOR=$(which IOR)
	local iter=$((DP_FNUM / DP_NUM))
	local direct=""

	if [ "x$DP_DIO" == "xyes" ] ; then
		direct="-B"
	fi

	local TDIR=${1:-$MOUNT}

	chmod 0777 $TDIR

	# for DoM large files (beyond the DoM size) use
	# DOM_SIZE=1M :
	#     bsize="4096 " - 4Mb
	#     nsegments=$((128 * 1024))
	# DOM_SIZE=64k :
	#     bsize="1024 " - 1Mb
	#     nsegments=$((32 * 1024))
	local bsizes=${BSIZES:-"4 32"}
	local nsegments=${NSEGMENTS:-128}
	[ "$SLOW" = "no" ] && bsizes="8"

	for bsize in $bsizes ; do
		segments=$((nsegments / bsize))

		dp_run_cmd "mpi_run -np $DP_NUM $IOR \
			-a POSIX -b ${bsize}K -t ${bsize}K -o $TDIR/ -k \
			-s $segments -w -r -i $iter -F -E -z -m -Z $direct" |
			awk '($1 !~ /^(write|read|access)$/) || NF>12 {print}'
		if [ ${PIPESTATUS[0]} != 0 ]; then
			error "IOR write test for ${bsize}K failed, aborting"
		fi

		# check READ performance only (no cache)
		dp_run_cmd "mpi_run -np $DP_NUM $IOR \
			-a POSIX -b ${bsize}K -t ${bsize}K -o $TDIR/ -X 42\
			-s $segments -r -i $iter -F -E -z -m -Z $direct" |
			awk '($1 !~ /^(read|access|remove)$/) || NF>12 {print}'
		if [ ${PIPESTATUS[0]} != 0 ]; then
			error "IOR read test for ${bsize}K failed, aborting"
		fi

	done
	rm -rf $TDIR/*
	return 0
}

run_Dbench() {
	if ! which dbench > /dev/null 2>&1 ; then
		skip_env "Dbench is not installed, skipping"
	fi

	local TDIR=${1:-$MOUNT}

	if [ "x$DP_DOM_DNE" == "x$TDIR" ] ; then
		echo "dbench uses subdirs, skipping for DNE dir"
		return 0
	fi

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
		skip_env "No FIO installed, skipping"
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
	[ "$SLOW" = "yes" ] && bsizes="4 32"

	for bsize in $bsizes ; do
		local write_cmd="$base_cmd --bs=${bsize}k --rw=randwrite \
			$direct --file_service_type=random --randrepeat=1 \
			 --norandommap --group_reporting=1 --loops=$loops"
		if [ "x$DP_STATS" != "xyes" ] ; then
			dp_run_cmd "$write_cmd | awk -F\; '{printf \"WRITE: \
				BW %dKiB/sec, IOPS %d, lat (%d/%d/%d)usec\n\", \
				\$48, \$49, \$53, \$57, \$81}'"
		else
			dp_run_cmd "$write_cmd"
		fi
		if [ ${PIPESTATUS[0]} != 0 ]; then
			error "FIO write test with ${bsize}k failed, aborting"
		fi

		local read_cmd="$base_cmd --bs=${bsize}k --rw=randread \
			$direct --file_service_type=random --randrepeat=1 \
			 --norandommap --group_reporting=1 --loops=$loops"
		if [ "x$DP_STATS" != "xyes" ] ; then
			dp_run_cmd "$read_cmd | awk -F\; '{printf \"READ : \
				BW %dKiB/sec, IOPS %d, lat (%d/%d/%d)usec\n\", \
				\$7, \$8, \$12, \$16, \$40}'"
		else
			dp_run_cmd "$read_cmd"
		fi
		if [ ${PIPESTATUS[0]} != 0 ]; then
			error "FIO read test with ${bsize}k failed, aborting"
		fi
	done
	rm -rf $TDIR/*
	return 0
}

run_compbench() {
	local compilebench
	if [ x$cbench_DIR = x ]; then
		compilebench=$(which compilebench 2> /dev/null)
	else
		cd $cbench_DIR
		[ -x compilebench ] ||
			skip_env "compilebench is missing in $cbench_DIR"
		compilebench=compilebench
	fi

	[ x$compilebench != x ] ||
		skip_env "Compilebench is not installed, skipping"

	local TDIR=${1:-$MOUNT}

	dp_run_cmd "$compilebench -D $TDIR -i 2 -r 2 --makej"
	if [ ${PIPESTATUS[0]} != 0 ]; then
		error "Compilebench failed, aborting"
	fi

	rm -rf $TDIR/*
}

dp_test_run() {
	local test=$1
	local facets=$(get_facets MDS)
	local nodes=$(comma_list $(mdts_nodes))
	local p="$TMP/$TESTSUITE-$TESTNAME.parameters"

	save_lustre_params $facets "mdt.*.dom_lock" >> $p

	printf "\n##### $test: DoM files\n"
	do_nodes $nodes "lctl set_param -n mdt.*.dom_lock=1"
	DP_OSC="mdc"
	run_${test} $DP_DOM

	if [ -d $DP_DOM_DNE ] ; then
		printf "\n##### $test: DoM files + DNE\n"
		DP_OSC="mdc"
		run_${test} $DP_DOM_DNE
	fi

	printf "\n##### $test: OST files\n"
	DP_OSC="osc"
	run_${test} $DP_NORM

	restore_lustre_params < $p
	rm -f $p
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

test_compbench() {
	dp_test_run compbench
}
run_test compbench "Performance comparision: compilebench"

FAIL_ON_ERROR=$SAVED_FAIL_ON_ERROR
$LCTL set_param -n debug="$SAVED_DEBUG"

complete $SECONDS
check_and_cleanup_lustre
exit_status
