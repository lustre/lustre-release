#!/bin/bash
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#

set -e

ONLY=${ONLY:-"$*"}

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env "$@"
init_logging

# bug number for skipped test:
ALWAYS_EXCEPT="$SANITY_COMPR_EXCEPT"

build_test_filter

FAIL_ON_ERROR=false

check_and_setup_lustre

# $RUNAS_ID may get set incorrectly somewhere else
if [[ $UID -eq 0 && $RUNAS_ID -eq 0 ]]; then
	skip_env "\$RUNAS_ID set to 0, but \$UID is also 0!" && exit
fi
check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

save_layout_restore_at_exit $MOUNT
# Set file system with different layout
COMPR_EXTRA_LAYOUT=${COMPR_EXTRA_LAYOUT:-"-E EOF -c 1"}
$LFS setstripe $COMPR_EXTRA_LAYOUT $MOUNT

test_sanity()
{
	always_except LU-16928 56wb

	SANITY_EXCEPT=$ALWAYS_EXCEPT bash sanity.sh
	return 0
}
run_test sanity "Run sanity with PFL layout"

test_sanityn()
{
	bash sanityn.sh
	return 0
}
run_test sanityn "Run sanityn with PFL layout"

test_1000() {
	local filefrag_op=$(filefrag -l 2>&1 | grep "invalid option")
	[[ -z "$filefrag_op" ]] || skip_env "filefrag missing logical ordering"

	local blocks=128
	local dense=$(do_facet ost1 lctl get_param -n \
			      osd*.*OST0000*.extents_dense)
	[[ -n $dense ]] || skip "no dense writes supported"

	local osts=$(comma_list $(osts_nodes))
	do_nodes $osts $LCTL set_param osd*.*.extents_dense=0 ||
		error "cannot enable dense extent allocation"
	stack_trap "do_nodes $osts $LCTL set_param osd*.*.extents_dense=$dense"

	local tf=$DIR/$tfile
	stack_trap "rm -f $tf"
	log "create file with dense=0"

	$LFS setstripe -c 1 -i 0 $tf
	for ((i=0; i<$blocks; i++)); do
		dd if=/dev/zero of=$tf bs=32k seek=$((i*2)) count=1 \
			oflag=direct >&/dev/null conv=notrunc ||
				error "can't dd (sparse)"
	done
	filefrag -sv $tf
	local nonr=0
	while read EX LS LE PS PE LEN DEV FLAGS; do
		[[ "$EX" == "ext:" || "$EX" =~ "File" ]] && continue
		[[ "$EX" == "0:" ]] && PREV=${PE%:} && ((nonr+=1)) && continue
		(( ${PS%%.*} == PREV + 1 )) || ((nonr+=1))
		PREV=${PE%:}
	done < <(filefrag -v $tf)
	(( nonr > 0 )) || error "no extents?"
	rm -f $tf
	wait_delete_completed

	do_nodes $osts $LCTL set_param osd*.*.extents_dense=1 ||
		error "cannot enable dense extent allocation"
	#define OBD_FAIL_OSC_MARK_COMPRESSED    0x419
	$LCTL set_param fail_loc=0x419
	log "create file with dense=1"

	$LFS setstripe -c 1 -i 0 $tf
	for ((i=0; i<$blocks; i++)); do
		dd if=/dev/zero of=$tf bs=32k seek=$((i*2)) count=1 \
			oflag=direct conv=notrunc >&/dev/null ||
				error "can't dd (dense)"
	done
	filefrag -sv $tf
	local nr=0
	while read EX LS LE PS PE LEN DEV FLAGS; do
		[[ "$EX" == "ext:" || "$EX" =~ "File" ]] && continue
		[[ "$EX" == "0:" ]] && PREV=${PE%:} && ((nr+=1)) && continue
		(( ${PS%%.*} == PREV + 1 )) || ((nr+=1))
		PREV=${PE%:}
	done < <(filefrag -v $tf)
	(( nr > 0 )) || error "no extents?"

	echo "dense ($nr) should have fewer extents ($nonr)"
	(( (nonr / nr) > 3 )) ||
		error "dense ($nr) should have less extents ($nonr)"
	$LCTL set_param fail_loc=0

	local tmpfile=$(mktemp)
	stack_trap "rm -f $tmpfile"
	echo "generate temp file $tmpfile"
	dd if=/dev/urandom of=$tmpfile bs=32k count=$((blocks*2)) iflag=fullblock ||
		error "can't generate temporary file"
	dd if=$tmpfile of=$tf bs=32k conv=notrunc
	cancel_lru_locks osc

	stop ost1 || error "(2) Fail to stop ost1"
	run_e2fsck $(facet_host ost1) $(ostdevname 1) "-y" ||
		error "(3) Fail to run e2fsck error"
	start ost1 $(ostdevname 1) $OST_MOUNT_OPTS ||
		error "(4) Fail to start ost1"

	cmp $tmpfile $tf || error "data mismatch"
}
run_test 1000 "compressed vs uncompressed allocation"

test_fsx() {
	[[ "$ost1_FSTYPE" == "ldiskfs" ]] || skip "need ldiskfs backend"
	local osts=$(comma_list $(osts_nodes))

	local dense=$(do_facet ost1 lctl get_param -n \
			      osd*.*OST0000*.extents_dense)
	[[ -n $dense ]] || skip "no dense writes supported"
	do_nodes $osts $LCTL set_param osd*.*.extents_dense=1 ||
		error "cannot enable dense extent allocation"
	stack_trap "do_nodes $osts $LCTL set_param osd*.*.extents_dense=$dense"

#define OBD_FAIL_OSD_MARK_COMPRESSED	 	0x2302
	do_nodes $osts $LCTL set_param fail_loc=0x2302 ||
		error "cannot force dense writes"
	stack_trap "do_nodes $osts $LCTL set_param fail_loc=0"

	fsx_STRIPEPARAMS="-E eof -c -1" ONLY=fsx FSX_COUNT=2500 SLOW=yes bash sanity-benchmark.sh

	$DEBUG_ON
}
run_test fsx "verify dense writes with fsx on ldiskfs"

complete_test $SECONDS
check_and_cleanup_lustre
declare -a logs=($ONLY)
logs=("${logs[@]/#/$TMP/}")
exit_status "$(echo "${logs[@]/%/.log}")"
