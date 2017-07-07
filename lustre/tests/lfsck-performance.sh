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

require_dsh_mds || exit 0
require_dsh_ost || exit 0

[ "$SLOW" = "no" ] &&
	skip "skip lfsck performance test under non-SLOW mode" && exit 0

NTHREADS=${NTHREADS:-0}
UNIT=${UNIT:-8192}
MINCOUNT=${MINCOUNT:-4096}
MAXCOUNT=${MAXCOUNT:-8192}
MINCOUNT_REPAIR=${MINCOUNT_REPAIR:-4096}
MAXCOUNT_REPAIR=${MAXCOUNT_REPAIR:-8192}
BASE_COUNT=${BASE_COUNT:-8192}
FACTOR=${FACTOR:-2}
INCFACTOR=${INCFACTOR:-25} #percent
MINSUBDIR=${MINSUBDIR:-1}
MAXSUBDIR=${MAXSUBDIR:-2}
TOTSUBDIR=${TOTSUBDIR:-2}
WTIME=${WTIME:-86400}

RCMD="do_facet ${SINGLEMDS}"
RLCTL="${RCMD} ${LCTL}"
MDT_DEV="${FSNAME}-MDT0000"
MDT_DEVNAME=$(mdsdevname ${SINGLEMDS//mds/})
START_NAMESPACE="${RLCTL} lfsck_start -M ${MDT_DEV} -t namespace"
STOP_LFSCK="${RLCTL} lfsck_stop -M ${MDT_DEV} -A"
SHOW_NAMESPACE="${RLCTL} get_param -n mdd.${MDT_DEV}.lfsck_namespace"
MNTOPTS_NOSCRUB="-o user_xattr,noscrub"
remote_mds && ECHOCMD=${RCMD} || ECHOCMD="eval"

if [ ${NTHREADS} -eq 0 ]; then
	CPUCORE=$(${RCMD} cat /proc/cpuinfo | grep "processor.*:" | wc -l)
	NTHREADS=$((CPUCORE * 2))
fi

lfsck_attach() {
	${RCMD} "modprobe obdecho"

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
	format_mdt $(facet_number $SINGLEMDS)

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
run_test 0 "lfsck namespace performance (routine case) without load"

test_1() {
	[ $(facet_fstype $SINGLEMDS) != ldiskfs ] &&
		skip "not implemented for ZFS" && return

	local BCOUNT=0
	local i

	stopall
	do_rpc_nodes $(facet_active_host $SINGLEMDS) load_modules_local
	format_mdt $(facet_number $SINGLEMDS)

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
run_test 1 "lfsck namespace performance (backup/restore) without load"

test_2() {
	local i

	for ((i = $MINCOUNT_REPAIR; i <= $MAXCOUNT_REPAIR;
	      i = $((i * FACTOR)))); do
		stopall
		do_rpc_nodes $(facet_active_host $SINGLEMDS) load_modules_local
		format_mdt $(facet_number $SINGLEMDS)

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
run_test 2 "lfsck namespace performance (upgrade from 1.8) without load"

test_3() {
	[ $INCFACTOR -gt 25 ] && INCFACTOR=25

	local inc_count=$((BASE_COUNT * INCFACTOR / 100))
	local BCOUNT=0
	local i

	stopall
	do_rpc_nodes $(facet_active_host $SINGLEMDS) load_modules_local
	format_mdt $(facet_number $SINGLEMDS)

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
run_test 3 "lfsck namespace impact on create performance"

show_layout() {
	local idx=$1

	do_facet mds${idx} \
		"$LCTL get_param -n mdd.$(facet_svc mds${idx}).lfsck_layout"
}

layout_test_one() {
	echo "***** Start layout LFSCK on all devices at: $(date) *****"
	$RLCTL lfsck_start -M ${MDT_DEV} -t layout -A -r || return 21

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" $WTIME || {
		show_layout 1
		return 22
	}
	echo "***** End layout LFSCK on all devices at: $(date) *****"

	for n in $(seq $MDSCOUNT); do
		show_layout ${n}

		local SPEED=$(show_layout ${n} |
			      awk '/^average_speed_phase1/ { print $2 }')
		echo
		echo "lfsck_layout speed on MDS_${n} is $SPEED objs/sec"
		echo
	done
}

layout_gen_one() {
	local idx1=$1
	local idx2=$2
	local mntpt="/mnt/lustre_lfsck_${idx1}_${idx2}"
	local basedir="$mntpt/$tdir/$idx1/$idx2"

	mkdir -p $mntpt || {
		error_noexit "(11) Fail to mkdir $mntpt"
		return 11
	}

	mount_client $mntpt || {
		error_noexit "(12) Fail to mount $mntpt"
		return 12
	}

	mkdir $basedir || {
		umount_client $mntpt
		error_noexit "(13) Fail to mkdir $basedir"
		return 13
	}

	echo "&&&&& Start create $UNIT files under $basedir at: $(date) &&&&&"
	createmany -o ${basedir}/f $UNIT || {
		umount_client $mntpt
		error_noexit "(14) Fail to gen $UNIT files under $basedir"
		return 14
	}
	echo "&&&&& End create $UNIT files under $basedir at: $(date) &&&&&"

	umount_client $mntpt
}

layout_gen_set() {
	local cnt=$1

	echo "##### Start generate test set for subdirs=$cnt at: $(date) #####"
	for ((k = 0; k < $MDSCOUNT; k++)); do
		$LFS mkdir -i ${k} $LFSCKDIR/${k} || return 10

		for ((l = 1; l <= $cnt; l++)); do
			layout_gen_one ${k} ${l} &
		done
	done

	wait
	echo "##### End generate test set for subdirs=$cnt at: $(date) #####"
}

t4_test() {
	local saved_mdscount=$MDSCOUNT
	local saved_ostcount=$OSTCOUNT

	echo "stopall"
	stopall > /dev/null || error "(1) Fail to stopall"

	LFSCKDIR="$DIR/$tdir"
	MDSCOUNT=1
	for ((i = 1; i <= $saved_ostcount; i = $((i * 2)))); do
		OSTCOUNT=${i}

		echo "+++++ Start cycle ostcount=$OSTCOUNT at: $(date) +++++"
		echo

		for ((j = $MINSUBDIR; j <= $MAXSUBDIR; j = $((j * FACTOR)))); do
			echo "formatall"
			formatall > /dev/null ||
				error "(2) Fail to formatall, subdirs=${j}"

			echo "setupall"
			setupall > /dev/null ||
				error "(3) Fail to setupall, subdirs=${j}"

			mkdir $LFSCKDIR ||
				error "(4) mkdir $LFSCKDIR, subdirs=${j}"

			$LFS setstripe -c ${OSTCOUNT} -i 0 $LFSCKDIR ||
				error "(5) setstripe on $LFSCKDIR, subdirs=${j}"

			local RC=0
			layout_gen_set ${j} || RC=$?
			[ $RC -eq 0 ] ||
				error "(6) generate set $RC, subdirs=${j}"

			RC=0
			layout_test_one || RC=$?
			[ $RC -eq 0 ] ||
				error "(7) LFSCK failed with $RC, subdirs=${j}"
		done

		echo "stopall"
		stopall > /dev/null || error "(8) Fail to stopall, subdirs=${j}"

		echo
		echo "----- Stop cycle ostcount=$OSTCOUNT at: $(date) -----"
	done

	MDSCOUNT=$saved_mdscount
	OSTCOUNT=$saved_ostcount
}

test_4a() {
	t4_test
}
run_test 4a "Single MDS lfsck layout performance (routine case) without load"

test_4b() {
	echo "Inject failure stub to simulate dangling reference"
	#define OBD_FAIL_LFSCK_DANGLING 0x1610
	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param fail_loc=0x1610

	t4_test
}
run_test 4b "Single MDS lfsck layout performance (repairing case) without load"

t5_test() {
	local saved_mdscount=$MDSCOUNT

	echo "stopall"
	stopall > /dev/null || error "(1) Fail to stopall"

	LFSCKDIR="$DIR/$tdir"
	for ((i = 1; i <= $saved_mdscount; i++)); do
		MDSCOUNT=${i}

		echo "+++++ Start cycle mdscount=$MDSCOUNT at: $(date) +++++"
		echo

		for ((j = $MINSUBDIR; j <= $MAXSUBDIR; j = $((j * FACTOR)))); do
			echo "formatall"
			formatall > /dev/null ||
				error "(2) Fail to formatall, subdirs=${j}"

			echo "setupall"
			setupall > /dev/null ||
				error "(3) Fail to setupall, subdirs=${j}"

			mkdir $LFSCKDIR ||
				error "(4) mkdir $LFSCKDIR, subdirs=${j}"

			$LFS setstripe -c ${OSTCOUNT} -i 0 $LFSCKDIR ||
				error "(5) setstripe on $LFSCKDIR, subdirs=${j}"

			local RC=0
			layout_gen_set ${j} || RC=$?
			[ $RC -eq 0 ] ||
				error "(6) generate set $RC, subdirs=${j}"

			RC=0
			layout_test_one || RC=$?
			[ $RC -eq 0 ] ||
				error "(7) LFSCK failed with $RC, subdirs=${j}"
		done

		echo "stopall"
		stopall > /dev/null || error "(8) Fail to stopall"

		echo
		echo "----- Stop cycle mdscount=$MDSCOUNT at: $(date) -----"
	done

	MDSCOUNT=$saved_mdscount
}

test_5a() {
	t5_test
}
run_test 5a "lfsck layout performance (routine case) without load for DNE"

test_5b() {
	echo "Inject failure stub to simulate dangling reference"
	#define OBD_FAIL_LFSCK_DANGLING 0x1610
	do_nodes $(comma_list $(osts_nodes)) $LCTL set_param fail_loc=0x1610

	t5_test
}
run_test 5b "lfsck layout performance (repairing case) without load for DNE"

lfsck_fast_create() {
	local total=$1
	local lbase=$2
	local threads=$3
	local ldir="/test-${lbase}"
	local cycle=0
	local count=$UNIT

	while true; do
		[ $count -eq 0 -o  $count -gt ${total} ] && count=$total
		local usize=$((count / NTHREADS))
		[ ${usize} -eq 0 ] && break
		local tdir=${ldir}-${cycle}-

		echo "[cycle: $cycle] [threads: $threads]"\
		     "[files: $count] [basedir: $tdir]"

		lfsck_create

		total=$((total - usize * NTHREADS))
		[ $total -eq 0 ] && break
		lbase=$((lbase + usize))
		cycle=$((cycle + 1))
	done
}

lfsck_detach_error() {
	lfsck_detach
	error "$@"
}

test_6() {
	[ $INCFACTOR -gt 25 ] && INCFACTOR=25

	echo "stopall"
	stopall > /dev/null || error "(1) Fail to stopall"

	local saved_mdscount=$MDSCOUNT

	LFSCKDIR="$DIR/$tdir"
	MDSCOUNT=1
	echo "formatall"
	formatall > /dev/null || error "(2) Fail to formatall"

	echo "setupall"
	setupall > /dev/null || error "(3) Fail to setupall"

	mkdir $LFSCKDIR || error "(4) Fail to mkdir $LFSCKDIR"

	$LFS setstripe -c ${OSTCOUNT} -i 0 $LFSCKDIR ||
		error "(5) Fail to setstripe on $LFSCKDIR"

	local RC=0
	layout_gen_set $TOTSUBDIR || RC=$?
	[ $RC -eq 0 ] ||
		error "(6) Fail to generate set $RC, subdirs=$TOTSUBDIR"

	echo
	echo "***** Start layout LFSCK on single MDS at: $(date) *****"
	$RLCTL lfsck_start -M ${MDT_DEV} -t layout -r ||
		error "(7) Fail to start layout LFSCK"

	wait_update_facet $SINGLEMDS "$LCTL get_param -n \
		mdd.${MDT_DEV}.lfsck_layout |
		awk '/^status/ { print \\\$2 }'" "completed" $WTIME || {
		show_layout 1
		error "(8) layout LFSCK cannot finished in time"
	}
	echo "***** End layout LFSCK on single MDS at: $(date) *****"

	local SPEED=$(show_layout 1 |
		      awk '/^average_speed_phase1/ { print $2 }')
	echo "lfsck_layout full_speed is $SPEED objs/sec"

	local inc_count=$((BASE_COUNT * INCFACTOR / 100))
	local nfiles=$((inc_count / 2))

	lfsck_attach
	for ((m = 0, n = $INCFACTOR; n < 100;
	      m = $((m + inc_count)), n = $((n + INCFACTOR)))); do
		local sl=$((SPEED * n / 100))

		$STOP_LFSCK > /dev/null 2>&1
		echo
		echo "start lfsck_layout with speed ${sl} at: $(date)"
		$RLCTL lfsck_start -M ${MDT_DEV} -t layout -r -s ${sl} ||
			lfsck_detach_error \
			"(9) Fail to start lfsck_layout with speed ${sl}"

		echo "&&&&& Start create files set from ${m} at: $(date) &&&&&"
		lfsck_fast_create $nfiles ${m} $NTHREADS ||
			lfsck_detach_error "(10) Fail to create files"
		echo "&&&&& End create files set from ${m} at: $(date) &&&&&"
	done

	$STOP_LFSCK > /dev/null 2>&1
	echo
	echo "start lfsck_layout with full speed at: $(date)"
	$RLCTL lfsck_start -M ${MDT_DEV} -t layout -r -s 0 ||
		lfsck_detach_error \
		"(11) Fail to start lfsck_layout with full speed"

	echo "&&&&& start to create files set from ${m} at: $(date) &&&&&"
	lfsck_fast_create $nfiles ${m} $NTHREADS ||
		lfsck_detach_error "(12) Fail to create files"
	echo "&&&&& end to create files set from ${m} at: $(date) &&&&&"

	m=$((m + inc_count))
	$STOP_LFSCK > /dev/null 2>&1
	echo
	echo "create without lfsck_layout run back-ground"
	echo "&&&&& start to create files set from ${m} at: $(date) &&&&&"
	lfsck_fast_create $nfiles ${m} $NTHREADS ||
		lfsck_detach_error "(13) Fail to create files"
	echo "&&&&& end to create files set from ${m} at: $(date) &&&&&"

	lfsck_detach
	echo
	echo "stopall"
	stopall > /dev/null || error "(14) Fail to stopall"

	MDSCOUNT=$saved_mdscount
}
run_test 6 "lfsck layout impact on create performance"

show_namespace() {
	local idx=$1

	do_facet mds${idx} \
		"$LCTL get_param -n mdd.$(facet_svc mds${idx}).lfsck_namespace"
}

namespace_test_one() {
	echo "***** Start namespace LFSCK on all devices at: $(date) *****"
	$RLCTL lfsck_start -M ${MDT_DEV} -t namespace -A -r || return 21

	for n in $(seq $MDSCOUNT); do
		wait_update_facet mds${n} "$LCTL get_param -n \
			mdd.$(facet_svc mds${n}).lfsck_namespace |
			awk '/^status/ { print \\\$2 }'" "completed" $WTIME || {
			show_namespace ${n}
			return 22
		}
	done
	echo "***** End namespace LFSCK on all devices at: $(date) *****"

	for n in $(seq $MDSCOUNT); do
		show_namespace ${n}

		local SPEED=$(show_namespace ${n} |
			      awk '/^average_speed_total/ { print $2 }')
		echo
		echo "lfsck_namespace speed on MDS_${n} is $SPEED objs/sec"
		echo
	done
}

namespace_gen_one() {
	local idx1=$1
	local idx2=$2
	local idx3=$(((idx1 + 1) % MDSCOUNT))
	local base_mntpt="/mnt/lustre_lfsck_${idx1}"
	local show_dir="$LFSCKDIR/${idx1}/${idx2}"
	local work_dir="${base_mntpt}_0/$tdir/${idx1}/${idx2}"

	mkdir $show_dir || return 20

	local count=$((UNIT * 78 / 100)) # 78% regular files
	local sub_count=$((count / NTHREADS))
	echo "Creating $count regular files under $show_dir at: $(date)"
	for ((m = 0; m < $NTHREADS; m++)); do
		local sub_dir="${base_mntpt}_${m}/$tdir/${idx1}/${idx2}"

		createmany -o ${sub_dir}/f_${m}_ $sub_count > /dev/null &
	done

	wait || {
		error_noexit "(21) Fail to gen regular files under $show_dir"
		return 21
	}

	count=$((UNIT * 3 / 100)) # 3% local sub-dirs
	echo "Creating $count local sub-dirs under $show_dir at: $(date)"
	createmany -d $work_dir/d_l_ $count > /dev/null || {
		error_noexit "(22) Fail to gen local sub-dir under $show_dir"
		return 22
	}

	# 3% * 5 = 15% regular files under local sub-dirs
	echo "Creating 5 regular files under each local sub-dir at: $(date)"
	for ((m = 0; m < $count; m++)); do
		createmany -o $work_dir/d_l_${m}/f_l_ 5 > /dev/null || {
			error_noexit \
			"(23) Fail to gen regular under $work_dir/d_l_${m}"
			return 23
		}
	done

	count=$((UNIT * 4 / 1000)) # 0.4% multiple hard-links
	echo "Creating $count multiple hard-links under $show_dir at: $(date)"
	for ((m = 0; m < $count; m++)); do
		ln $work_dir/f_0_${m} $work_dir/f_m_${m} || {
			error_noexit \
			"(24) Fail to hardlink to $work_dir/f_0_${m}"
			return 24
		}
	done

	count=$((UNIT * 3 / 1000)) # 0.3% remote sub-dirs
	echo "Creating $count remote sub-dirs under $show_dir, and 4 regular" \
		"files under each remote sub-dir at: $(date)"
	for ((m = 0; m < $count; m++)); do
		$LFS mkdir -i ${idx3} $work_dir/d_r_${m} || {
			error_noexit \
			"(25) Fail to remote mkdir $work_dir/d_r_${m}"
			return 25
		}

		# 0.3% * 4 = 1.2% regular files under remote sub-dirs
		createmany -o $work_dir/d_r_${m}/f_r_ 4 > /dev/null || {
			error_noexit \
			"(26) Fail to gen regular under $work_dir/d_r_${m}"
			return 26
		}
	done

	# 0.3% 2-striped sub-dirs + 0.6% shards of the 2-striped sub-dirs
	count=$((UNIT * 3 / 1000))
	echo "Creating $count 2-striped sub-dirs under $show_dir," \
		"and 4 regular files under each striped sub-dir at: $(date)"
	for ((m = 0; m < $count; m++)); do
		$LFS setdirstripe -i ${idx1} -c 2 -t all_char \
			$work_dir/d_s_${m} || {
			error_noexit \
			"(27) Fail to make striped-dir $work_dir/d_s_${m}"
			return 27
		}

		# 0.3% * 4 = 1.2% regular files under striped sub-dirs
		createmany -o $work_dir/d_s_${m}/f_s_ 4 > /dev/null || {
			error_noexit \
			"(28) Fail to gen regular under $work_dir/d_s_${m}"
			return 28
		}
	done
}

namespace_gen_mdt() {
	local mdt_idx=$1
	local dir_cnt=$2
	local base_mntpt="/mnt/lustre_lfsck_${mdt_idx}"

	$LFS mkdir -i ${mdt_idx} $LFSCKDIR/${mdt_idx} || return 10

	for ((m = 0; m < $NTHREADS; m++)); do
		local mntpt="${base_mntpt}_${m}"

		mkdir -p $mntpt || {
			umount ${base_mntpt}_*
			error_noexit "(11) Fail to mkdir $mntpt"
			return 11
		}

		mount_client $mntpt || {
			umount ${base_mntpt}_*
			error_noexit "(12) Fail to mount $mntpt"
			return 12
		}
	done

	for ((l = 0; l < $dir_cnt; l++)); do
		namespace_gen_one ${mdt_idx} ${l}
	done

	umount ${base_mntpt}_*
}

namespace_gen_set() {

	local cnt=$1

	echo "##### Start generate test set for subdirs=$cnt at: $(date) #####"
	for ((k = 0; k < $MDSCOUNT; k++)); do
		namespace_gen_mdt ${k} ${cnt} &
	done
	wait
	echo "##### End generate test set for subdirs=$cnt at: $(date) #####"
}

t7_test() {
	local local_loc=$1
	local saved_mdscount=$MDSCOUNT

	[ $MDSCOUNT -le 8 ] ||
		error "Too much MDT, test data set on each MDT may be unbalance"

	echo "stopall"
	stopall > /dev/null || error "(1) Fail to stopall"

	LFSCKDIR="$DIR/$tdir"
	for ((i = 2; i <= $saved_mdscount; i = $((i + 2)))); do
		MDSCOUNT=${i}

		echo "+++++ Start cycle mdscount=$MDSCOUNT at: $(date) +++++"
		echo

		for ((j = $MINSUBDIR; j <= $MAXSUBDIR;
		      j = $((j + MINSUBDIR)))); do
			echo "formatall"
			formatall > /dev/null ||
				error "(2) Fail to formatall, subdirs=${j}"

			echo "setupall"
			setupall > /dev/null ||
				error "(3) Fail to setupall, subdirs=${j}"

			mkdir $LFSCKDIR ||
				error "(4) mkdir $LFSCKDIR, subdirs=${j}"

			$LFS setstripe -c 1 -i -1 $LFSCKDIR ||
				error "(5) Fail to setstripe on $LFSCKDIR"

			do_nodes $(comma_list $(mdts_nodes)) \
				$LCTL set_param fail_loc=$local_loc

			local RC=0
			namespace_gen_set ${j} || RC=$?
			[ $RC -eq 0 ] ||
				error "(6) generate set $RC, subdirs=${j}"

			RC=0
			namespace_test_one || RC=$?
			[ $RC -eq 0 ] ||
				error "(7) LFSCK failed with $RC, subdirs=${j}"

			do_nodes $(comma_list $(mdts_nodes)) \
				$LCTL set_param fail_loc=0
		done

		echo "stopall"
		stopall > /dev/null || error "(8) Fail to stopall"

		echo
		echo "----- Stop cycle mdscount=$MDSCOUNT at: $(date) -----"
	done

	MDSCOUNT=$saved_mdscount
}

test_7a() {
	t7_test 0
}
run_test 7a "namespace LFSCK performance (routine check) without load for DNE"

test_7b() {
	echo "Inject failure stub to simulate the case of lost linkEA"
	#define OBD_FAIL_LFSCK_NO_LINKEA	0x161d
	t7_test 0x161d
}
run_test 7b "namespace LFSCK performance (repairing lost linkEA) for DNE"

test_7c() {
	echo "Inject failure stub to simulate the case of bad FID-in-dirent"
	#define OBD_FAIL_FID_INDIR      0x1501
	t7_test 0x1501
}
run_test 7c "namespace LFSCK performance (repairing bad FID-in-dirent) for DNE"

test_8() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	[ $INCFACTOR -gt 25 ] && INCFACTOR=25

	echo "stopall"
	stopall > /dev/null || error "(1) Fail to stopall"

	local saved_mdscount=$MDSCOUNT

	LFSCKDIR="$DIR/$tdir"
	MDSCOUNT=2
	echo "formatall"
	formatall > /dev/null || error "(2) Fail to formatall"

	echo "setupall"
	setupall > /dev/null || error "(3) Fail to setupall"

	mkdir $LFSCKDIR || error "(4) Fail to mkdir $LFSCKDIR"

	$LFS setstripe -c 1 -i 0 $LFSCKDIR ||
		error "(5) Fail to setstripe on $LFSCKDIR"

	local RC=0
	namespace_gen_set $TOTSUBDIR || RC=$?
	[ $RC -eq 0 ] ||
		error "(6) Fail to generate set $RC, subdirs=$TOTSUBDIR"

	echo
	echo "***** Start namespace LFSCK at: $(date) *****"
	$RLCTL lfsck_start -M ${MDT_DEV} -t namespace -A -r ||
		error "(7) Fail to start namespace LFSCK"

	for n in $(seq $MDSCOUNT); do
		wait_update_facet mds${n} "$LCTL get_param -n \
			mdd.$(facet_svc mds${n}).lfsck_namespace |
			awk '/^status/ { print \\\$2 }'" "completed" $WTIME || {
			show_namespace ${n}
			error "(8) namespace LFSCK cannot finished in time"
		}
	done
	echo "***** End namespace LFSCK at: $(date) *****"

	local SPEED=$(show_namespace 1 |
		      awk '/^average_speed_phase1/ { print $2 }')
	echo "lfsck_namespace full_speed is $SPEED objs/sec"
	echo

	local inc_count=$((BASE_COUNT * INCFACTOR / 100))
	local nfiles=$((inc_count / 2))
	local m=0

	lfsck_attach

	local stime=$(date +%s)
	lfsck_fast_create $nfiles ${m} $NTHREADS ||
		lfsck_detach_error "(9) Fail to create files"
	local etime=$(date +%s)
	echo "created $nfiles without lfsck_namespace run back-ground used" \
		"$((etime - stime)) seconds"
	echo

	for ((m = nfiles, n = $INCFACTOR; n < 100;
	      m = $((m + inc_count)), n = $((n + INCFACTOR)))); do
		local sl=$((SPEED * n / 100))

		$STOP_LFSCK > /dev/null 2>&1
		echo "start lfsck_namespace with speed ${sl} at: $(date)"
		$RLCTL lfsck_start -M ${MDT_DEV} -t namespace -A -r -s ${sl} ||
			lfsck_detach_error \
			"(10) Fail to start lfsck_namespace with speed ${sl}"

		stime=$(date +%s)
		lfsck_fast_create $nfiles ${m} $NTHREADS ||
			lfsck_detach_error "(11) Fail to create files"
		etime=$(date +%s)
		echo "created $nfiles with namespace LFSCK run with the" \
			"speed limit of ${n}% of full speed used" \
			"$((etime - stime)) seconds"
		echo
	done

	$STOP_LFSCK > /dev/null 2>&1
	echo "start lfsck_namespace with full speed at: $(date)"
	$RLCTL lfsck_start -M ${MDT_DEV} -t namespace -A -r -s 0 ||
		lfsck_detach_error \
		"(12) Fail to start lfsck_namespace with full speed"

	stime=$(date +%s)
	lfsck_fast_create $nfiles ${m} $NTHREADS ||
		lfsck_detach_error "(13) Fail to create files"
	etime=$(date +%s)
	echo "created $nfiles with namespace LFSCK run with full speed used" \
		"$((etime - stime)) seconds"
	echo

	$STOP_LFSCK > /dev/null 2>&1

	lfsck_detach

	echo "stopall"
	stopall > /dev/null || error "(14) Fail to stopall"

	MDSCOUNT=$saved_mdscount
}
run_test 8 "lfsck namespace impact on create performance"

# cleanup the system at last
lfsck_cleanup
complete $SECONDS
exit_status
