#!/bin/bash

set -e

ONLY=${ONLY:-"$*"}
ALWAYS_EXCEPT="$SCRUB_PERFORMANCE_EXCEPT"
[ "$SLOW" = "no" ] && EXCEPT_SLOW=""
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

[ $(facet_fstype $SINGLEMDS) != ldiskfs ] &&
	skip "OI scrub performance only for ldiskfs" && exit 0
[[ $(lustre_version_code $SINGLEMDS) -lt $(version_code 2.2.90) ]] &&
	skip "Need MDS version at least 2.2.90" && exit 0
require_dsh_mds || exit 0
[ "$SLOW" = "no" ] && skip "skip scrub performance test under non-SLOW mode"


NTHREADS=${NTHREADS:-0}
UNIT=${UNIT:-1048576}
BACKUP=${BACKUP:-0}
MINCOUNT=${MINCOUNT:-8192}
MAXCOUNT=${MAXCOUNT:-32768}
FACTOR=${FACTOR:-2}

RCMD="do_facet ${SINGLEMDS}"
RLCTL="${RCMD} ${LCTL}"
MDT_DEV="${FSNAME}-MDT0000"
MDT_DEVNAME=$(mdsdevname ${SINGLEMDS//mds/})
SHOW_SCRUB="${RLCTL} get_param -n osd-ldiskfs.${MDT_DEV}.oi_scrub"
remote_mds && ECHOCMD=${RCMD} || ECHOCMD="eval"

if [ ${NTHREADS} -eq 0 ]; then
	CPUCORE=$(${RCMD} cat /proc/cpuinfo | grep "processor.*:" | wc -l)
	NTHREADS=$((CPUCORE * 2))
fi

stopall
do_rpc_nodes $(facet_active_host $SINGLEMDS) load_modules_local
reformat_external_journal ${SINGLEMDS}
add ${SINGLEMDS} $(mkfs_opts ${SINGLEMDS} ${MDT_DEVNAME}) --backfstype ldiskfs \
	--reformat ${MDT_DEVNAME} $(mdsvdevname 1) > /dev/null || exit 2

scrub_attach() {
	${ECHOCMD} "${LCTL} <<-EOF
		attach echo_client scrub-MDT0000 scrub-MDT0000_UUID
		setup ${MDT_DEV} mdd
	EOF"
}

scrub_detach() {
	${ECHOCMD} "${LCTL} <<-EOF
		device scrub-MDT0000
		cleanup
		detach
	EOF"
}

scrub_create() {
	local echodev=$(${RLCTL} dl | grep echo_client|awk '{print $1}')
	local j

	${ECHOCMD} "${LCTL} <<-EOF
		cfg_device ${echodev}
		test_mkdir ${tdir}
	EOF"

	for ((j=1; j<${threads}; j++)); do
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

scrub_cleanup() {
	do_rpc_nodes $(facet_active_host $SINGLEMDS) unload_modules
	formatall
}

scrub_create_nfiles() {
	local total=$1
	local lbase=$2
	local threads=$3
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
		start ${SINGLEMDS} $MDT_DEVNAME $MDS_MOUNT_OPTS ||
			error "Fail to start MDS!"
		scrub_attach
		scrub_create
		scrub_detach
		stop ${SINGLEMDS} || error "Fail to stop MDS!"

		total=$((total - usize * NTHREADS))
		[ ${total} -eq 0 ] && break
		lbase=$((lbase + usize))
		cycle=$((cycle + 1))
	done
}

build_test_filter

test_0() {
	local BASECOUNT=0
	local i

	for ((i=$MINCOUNT; i<=$MAXCOUNT; i=$((i * FACTOR)))); do
		local nfiles=$((i - BASECOUNT))
		local stime=$(date +%s)

		echo "+++ start to create for ${i} files set at: $(date) +++"
		scrub_create_nfiles ${nfiles} ${BASECOUNT} ${NTHREADS} ||
			error "Fail to create files!"
		echo "+++ end to create for ${i} files set at: $(date) +++"
		local etime=$(date +%s)
		local delta=$((etime - stime))
		[ $delta -gt 0 ] || delta=1
		echo "create ${nfiles} files used ${delta} seconds"
		echo "create speed is $((nfiles / delta))/sec"

		BASECOUNT=${i}
		if [ ${BACKUP} -ne 0 ]; then
			stime=$(date +%s)
			echo "backup/restore ${i} files start at: $(date)"
			mds_backup_restore $SINGLEMDS ||
				error "Fail to backup/restore!"
			echo "backup/restore ${i} files end at: $(date)"
			etime=$(date +%s)
			delta=$((etime - stime))
			[ $delta -gt 0 ] || delta=1
			echo "backup/restore ${i} files used ${delta} seconds"
			echo "backup/restore speed is $((i / delta))/sec"
		else
			mds_remove_ois $SINGLEMDS ||
				error "Fail to remove/recreate!"
		fi

		echo "--- start to rebuild OI for $i files set at: $(date) ---"
		start ${SINGLEMDS} $MDT_DEVNAME $MDS_MOUNT_OPTS > /dev/null ||
			error "Fail to start MDS!"

		while true; do
			local STATUS=$($SHOW_SCRUB |
					awk '/^status/ { print $2 }')
			[ "$STATUS" == "completed" ] && break
			sleep 3 # check status every 3 seconds
		done

		echo "--- end to rebuild OI for ${i} files set at: $(date) ---"
		local RTIME=$($SHOW_SCRUB | awk '/^run_time/ { print $2 }')
		echo "rebuild OI for ${i} files used ${RTIME} seconds"
		local SPEED=$($SHOW_SCRUB | awk '/^average_speed/ { print $2 }')
		echo "rebuild speed is ${SPEED}/sec"
		stop ${SINGLEMDS} > /dev/null || error "Fail to stop MDS!"
	done
}
run_test 0 "OI scrub performance test"

# cleanup the system at last
scrub_cleanup
complete $SECONDS
exit_status
