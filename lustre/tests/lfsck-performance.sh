#!/bin/bash

set -e

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT="$LFSCK_PERFORMANCE_EXCEPT"
[ "$SLOW" = "no" ] && EXCEPT_SLOW=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

[ $(facet_fstype $SINGLEMDS) != ldiskfs ] &&
	skip "lfsck performance only for ldiskfs" && exit 0

require_dsh_mds || exit 0

[ "$SLOW" = "no" ] &&
	skip "skip lfsck performance test under non-SLOW mode" && exit 0

NTHREADS=${NTHREADS:-0}
UNIT=${UNIT:-1048576}
MINCOUNT=${MINCOUNT:-8192}
MAXCOUNT=${MAXCOUNT:-32768}
MINCOUNT_REPAIR=${MINCOUNT_REPAIR:-8192}
MAXCOUNT_REPAIR=${MAXCOUNT_REPAIR:-32768}
BASE_COUNT=${BASE_COUNT:-1048576}
FACTOR=${FACTOR:-2}
INCFACTOR=${INCFACTOR:-25} #percent

RCMD="do_facet ${SINGLEMDS}"
RLCTL="${RCMD} ${LCTL}"
MDT_DEV="${FSNAME}-MDT0000"
MDT_DEVNAME=$(mdsdevname ${SINGLEMDS//mds/})
START_NAMESPACE="${RLCTL} lfsck_start -M ${MDT_DEV} -t namespace"
STOP_LFSCK="${RLCTL} lfsck_stop -M ${MDT_DEV}"
SHOW_NAMESPACE="${RLCTL} get_param -n mdd.${MDT_DEV}.lfsck_namespace"
MNTOPTS_NOSCRUB="-o user_xattr,noscrub"
remote_mds && ECHOCMD=${RCMD} || ECHOCMD="eval"

if [ ${NTHREADS} -eq 0 ]; then
	CPUCORE=$(${RCMD} cat /proc/cpuinfo | grep "processor.*:" | wc -l)
	NTHREADS=$((CPUCORE * 2))
fi

lfsck_attach() {
	${ECHOCMD} "${LCTL} <<-EOF
		attach echo_client lfsck-MDT0000 lfsck-MDT0000_UUID
		setup ${MDT_DEV} mdd
	EOF"
}

lfsck_detach() {
	${ECHOCMD} "${LCTL} <<-EOF
		device lfsck-MDT0000
		cleanup
		detach
	EOF"
}

lfsck_create() {
	local echodev=$(${RLCTL} dl | grep echo_client|awk '{print $1}')
	local j

	${ECHOCMD} "${LCTL} <<-EOF
		cfg_device ${echodev}
		test_mkdir ${tdir}
	EOF"

	for ((j = 1; j < ${threads}; j++)); do
		${ECHOCMD} "${LCTL} <<-EOF
			cfg_device ${echodev}
			test_mkdir ${tdir}${j}
		EOF"
	done

	${ECHOCMD} "${LCTL} <<-EOF
		cfg_device ${echodev}
		--threads ${threads} 0 ${echodev} test_create \
		-d ${tdir} -D ${threads} -b ${lbase} -c 0 -n ${usize}
	EOF"
}

lfsck_cleanup() {
	do_rpc_nodes $(facet_active_host $SINGLEMDS) unload_modules
	formatall
}

lfsck_create_nfiles() {
	local total=$1
	local lbase=$2
	local threads=$3
	local linkea=$4
	local ldir="/test-${lbase}"
	local cycle=0
	local count=${UNIT}

	while true; do
		[ ${count} -eq 0 -o  ${count} -gt ${total} ] && count=${total}
		local usize=$((count / NTHREADS))
		[ ${usize} -eq 0 ] && break
		local tdir=${ldir}-${cycle}-

		echo "[cycle: ${cycle}] [threads: ${threads}]"\
		     "[files: ${count}] [basedir: ${tdir}]"
		start ${SINGLEMDS} $MDT_DEVNAME $MNTOPTS_NOSCRUB ||
			error "Fail to start MDS!"
		#define OBD_FAIL_FID_IGIF	0x1504
		[ ! -z $linkea ] && ${RLCTL} set_param fail_loc=0x1504

		lfsck_attach
		lfsck_create
		lfsck_detach

		[ ! -z $linkea ] && ${RLCTL} set_param fail_loc=0x0
		stop ${SINGLEMDS} || error "Fail to stop MDS!"

		total=$((total - usize * NTHREADS))
		[ ${total} -eq 0 ] && break
		lbase=$((lbase + usize))
		cycle=$((cycle + 1))
	done
}

build_test_filter

test_0() {
	local BCOUNT=0
	local i

	stopall
	do_rpc_nodes $(facet_active_host $SINGLEMDS) load_modules_local
	reformat_external_journal
	add ${SINGLEMDS} $(mkfs_opts ${SINGLEMDS} ${MDT_DEVNAME}) --backfstype \
		ldiskfs --reformat ${MDT_DEVNAME} $(mdsvdevname 1) > /dev/null ||
		error "Fail to reformat the MDS!"

	for ((i = $MINCOUNT; i <= $MAXCOUNT; i = $((i * FACTOR)))); do
		local nfiles=$((i - BCOUNT))

		echo "+++ start to create for ${i} files set at: $(date) +++"
		lfsck_create_nfiles ${nfiles} ${BCOUNT} ${NTHREADS} ||
			error "Fail to create files!"
		echo "+++ end to create for ${i} files set at: $(date) +++"

		BCOUNT=${i}
		start ${SINGLEMDS} $MDT_DEVNAME $MNTOPTS_NOSCRUB > /dev/null ||
			error "Fail to start MDS!"

		echo "start lfsck_namespace for ${i} files set at: $(date)"
		$START_NAMESPACE || error "Fail to start lfsck_namespace!"

		while true; do
			local STATUS=$($SHOW_NAMESPACE |
					awk '/^status/ { print $2 }')
			[ "$STATUS" == "completed" ] && break
			sleep 3 # check status every 3 seconds
		done

		echo "end lfsck_namespace for ${i} files set at: $(date)"
		SPEED=$($SHOW_NAMESPACE |
			awk '/^average_speed_phase1/ { print $2 }')
		echo "lfsck_namespace speed is ${SPEED}/sec"
		stop ${SINGLEMDS} > /dev/null || error "Fail to stop MDS!"
	done
}
run_test 0 "lfsck performance test (routine case) without load"

test_1() {
	local BCOUNT=0
	local i

	stopall
	do_rpc_nodes $(facet_active_host $SINGLEMDS) load_modules_local
	reformat_external_journal
	add ${SINGLEMDS} $(mkfs_opts ${SINGLEMDS} ${MDT_DEVNAME}) --backfstype \
		ldiskfs --reformat ${MDT_DEVNAME} $(mdsvdevname 1) > /dev/null ||
		error "Fail to reformat the MDS!"

	for ((i = $MINCOUNT_REPAIR; i <= $MAXCOUNT_REPAIR;
	      i = $((i * FACTOR)))); do
		local nfiles=$((i - BCOUNT))

		echo "+++ start to create for ${i} files set at: $(date) +++"
		lfsck_create_nfiles ${nfiles} ${BCOUNT} ${NTHREADS} ||
			error "Fail to create files!"
		echo "+++ end to create for ${i} files set at: $(date) +++"

		BCOUNT=${i}
		local stime=$(date +%s)
		echo "backup/restore ${i} files start at: $(date)"
		mds_backup_restore $SINGLEMDS || error "Fail to backup/restore!"
		echo "backup/restore ${i} files end at: $(date)"
		local etime=$(date +%s)
		local delta=$((etime - stime))
		[ $delta -gt 0 ] || delta=1
		echo "backup/restore ${i} files used ${delta} seconds"
		echo "backup/restore speed is $((i / delta))/sec"

		start ${SINGLEMDS} $MDT_DEVNAME $MNTOPTS_NOSCRUB > /dev/null ||
			error "Fail to start MDS!"

		echo "start lfsck_namespace for ${i} files set at: $(date)"
		$START_NAMESPACE || error "Fail to start lfsck_namespace!"

		while true; do
			local STATUS=$($SHOW_NAMESPACE |
					awk '/^status/ { print $2 }')
			[ "$STATUS" == "completed" ] && break
			sleep 3 # check status every 3 seconds
		done

		echo "end lfsck_namespace for ${i} files set at: $(date)"
		local SPEED=$($SHOW_NAMESPACE |
			      awk '/^average_speed_phase1/ { print $2 }')
		echo "lfsck_namespace speed is ${SPEED}/sec"
		stop ${SINGLEMDS} > /dev/null || error "Fail to stop MDS!"
	done
}
run_test 1 "lfsck performance test (backup/restore) without load"

test_2() {
	local i

	for ((i = $MINCOUNT_REPAIR; i <= $MAXCOUNT_REPAIR;
	      i = $((i * FACTOR)))); do
		stopall
		do_rpc_nodes $(facet_active_host $SINGLEMDS) load_modules_local
		reformat_external_journal
		add ${SINGLEMDS} $(mkfs_opts ${SINGLEMDS} ${MDT_DEVNAME}) \
			--backfstype ldiskfs --reformat ${MDT_DEVNAME} \
			$(mdsvdevname 1) > /dev/null ||
			error "Fail to reformat the MDS!"

		echo "+++ start to create for ${i} files set at: $(date) +++"
		lfsck_create_nfiles ${i} 0 ${NTHREADS} 1 ||
			error "Fail to create files!"
		echo "+++ end to create for ${i} files set at: $(date) +++"

		start ${SINGLEMDS} $MDT_DEVNAME $MNTOPTS_NOSCRUB > /dev/null ||
			error "Fail to start MDS!"

		echo "start lfsck_namespace for ${i} files set at: $(date)"
		$START_NAMESPACE || error "Fail to start lfsck_namespace!"

		while true; do
			local STATUS=$($SHOW_NAMESPACE |
					awk '/^status/ { print $2 }')
			[ "$STATUS" == "completed" ] && break
			sleep 3 # check status every 3 seconds
		done

		echo "end lfsck_namespace for ${i} files set at: $(date)"
		local SPEED=$($SHOW_NAMESPACE |
			      awk '/^average_speed_phase1/ { print $2 }')
		echo "lfsck_namespace speed is ${SPEED}/sec"
		stop ${SINGLEMDS} > /dev/null || error "Fail to stop MDS!"
	done
}
run_test 2 "lfsck performance test (simulate upgrade from 1.8) without load"

test_3() {
	[ $MDSSIZE -lt 4000000 ] &&
		skip "MDT device is too small, expect at last 4GB" && exit 0

	[ $BASE_COUNT -lt 1048576 ] && BASE_COUNT=1048576
	[ $INCFACTOR -gt 25 ] && INCFACTOR=25

	local inc_count=$((BASE_COUNT * INCFACTOR / 100))
	local BCOUNT=0
	local i

	stopall
	do_rpc_nodes $(facet_active_host $SINGLEMDS) load_modules_local
	reformat_external_journal
	add ${SINGLEMDS} $(mkfs_opts ${SINGLEMDS} ${MDT_DEVNAME}) --backfstype \
		ldiskfs --reformat ${MDT_DEVNAME} $(mdsvdevname 1) > /dev/null ||
		error "Fail to reformat the MDS!"

	for ((i = $inc_count; i <= $BASE_COUNT; i = $((i + inc_count)))); do
		local nfiles=$((i - BCOUNT))

		echo "+++ start to create for ${i} files set at: $(date) +++"
		lfsck_create_nfiles ${nfiles} ${BCOUNT} ${NTHREADS} ||
			error "Fail to create files!"
		echo "+++ end to create for ${i} files set at: $(date) +++"
		BCOUNT=${i}
	done

	start ${SINGLEMDS} $MDT_DEVNAME $MNTOPTS_NOSCRUB > /dev/null ||
		error "Fail to start MDS!"

	echo "start lfsck_namespace for ${BASE_COUNT} files set at: $(date)"
	$START_NAMESPACE || error "Fail to start lfsck_namespace!"

	while true; do
		local STATUS=$($SHOW_NAMESPACE |
				awk '/^status/ { print $2 }')
		[ "$STATUS" == "completed" ] && break
		sleep 3 # check status every 3 seconds
	done

	echo "end lfsck_namespace for ${BASE_COUNT} files set at: $(date)"
	local FULL_SPEED=$($SHOW_NAMESPACE |
		      awk '/^average_speed_phase1/ { print $2 }')
	echo "lfsck_namespace full_speed is ${FULL_SPEED}/sec"
	stop ${SINGLEMDS} > /dev/null || error "Fail to stop MDS!"
	local inc_speed=$((FULL_SPEED * INCFACTOR / 100))
	local j

	for ((j = $inc_speed; j < $FULL_SPEED; j = $((j + inc_speed)))); do
		start ${SINGLEMDS} $MDT_DEVNAME $MNTOPTS_NOSCRUB > /dev/null ||
			error "Fail to start MDS!"

		$STOP_LFSCK > /dev/null 2>&1
		echo "start lfsck_namespace with speed ${j} at: $(date)"
		$START_NAMESPACE --reset -s ${j} ||
			error "Fail to start lfsck_namespace with speed ${j}!"
		# lfsck_namespace will be paused when MDS stop,
		# and will be restarted automatically when mount up again.
		stop ${SINGLEMDS} > /dev/null || error "Fail to stop MDS!"

		local nfiles=$(((i - BCOUNT) / 2))

		echo "+++ start to create for ${i} files set at: $(date) +++"
		lfsck_create_nfiles ${nfiles} ${BCOUNT} ${NTHREADS} ||
			error "Fail to create files!"
		echo "+++ end to create for ${i} files set at: $(date) +++"
		BCOUNT=${i}
		i=$((i + inc_count))
	done

	start ${SINGLEMDS} $MDT_DEVNAME $MNTOPTS_NOSCRUB > /dev/null ||
		error "Fail to start MDS!"

	$STOP_LFSCK /dev/null 2>&1
	echo "start lfsck_namespace with full speed at: $(date)"
	$START_NAMESPACE --reset -s 0 ||
		error "Fail to start lfsck_namespace with full speed!"
	stop ${SINGLEMDS} > /dev/null || error "Fail to stop MDS!"

	local nfiles=$(((i - BCOUNT) / 2))

	echo "+++ start to create for ${i} files set at: $(date) +++"
	lfsck_create_nfiles ${nfiles} ${BCOUNT} ${NTHREADS} ||
		error "Fail to create files!"
	echo "+++ end to create for ${i} files set at: $(date) +++"
}
run_test 3 "lfsck performance test (routine case) without load"

# cleanup the system at last
lfsck_cleanup
complete $SECONDS
exit_status
