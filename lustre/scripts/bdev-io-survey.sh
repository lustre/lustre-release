#!/bin/bash

# for now all the units are in 'k', but we could introduce some helpers
# would be nice to run tests in the background and trap signals and kill
#
#  todo:
#	make sure devices aren't in use before going to town
#	really use threads with iozone
#	look into what sgp_dd is really doing, update arguments
# 	rename config/prepare/setup/cleanup/finish/teardown
# 	do something with sf and fpp iterating
#	discard first vmstat line
#

HOSTNAME=`hostname`
# a temp dir that is setup and torn down for each script run
tmpdir=""
# so we can kill background processes as the test cleans up
declare -a cleanup_pids
# to unmount mounts in our tmpdir before removing it
declare -a cleanup_mounts
# global for completing the table.  XXX this is a wart that could go
cur_y="0"
# a global which funcs use to get at the blocks[] array
last_block=-1
# prefix to run oprofile or readprofile
oprofile=""
readprofile=""

# defaults for some options:
min_threads=1
max_threads=4
possible_tests="sgp_dd ext2_iozone echo_filter"
run_tests="$possible_tests"
echo_module=""

# optional output directory
output_dir=""
 
die() {
        echo $* 1>&2
        exit 1
}
rm_or_die() {
        for path in $*; do
                [ -e $path ] || continue;
                [ -f $path ] || die "needed to remove non-file $path"
                rm -f $path || die "couldn't remove $path"
        done
}
save_output() {
	[ ! -z "$output_dir" ] && mv -f $1 $output_dir/$2
}
cleanup() {
	# only cleanup test runs if we have block devices
	if [ $last_block != -1 ]; then
		for pid in ${cleanup_pids[*]}; do
			kill $pid
		done
		cleanup_echo_filter
		for a in ${cleanup_mounts[*]}; do
			umount -f $a
		done
	fi

        [ ${#tmpdir} == 18 ] && [ -d $tmpdir ] && rm -rf $tmpdir
}
trap cleanup EXIT

pid_now_running() {
	local pid=$1
	cleanup_pids[$pid]=$pid
}
pid_has_stopped() {
	local pid=$1
	unset cleanup_pids[$pid]
}
                                                                                
commas() {
	echo $* | sed -e 's/ /,/g'
}
do_bc_scale() {
	local scale=$1
	shift
        echo "scale=$scale; $*" | bc
}
do_bc() {
	do_bc_scale 10 $*
}
mean_stddev() {
	local points=$*

	local avg=0
	local num=0
	for p in $points; do
		avg=`do_bc $avg + $p`
		num=`do_bc $num + 1`
	done
	case $num in
		0) echo '??' ; return ;;
		1) echo "$avg:0" ; return ;;
	esac

	avg=`do_bc $avg / $num`
	local tmp=0
	for p in $points; do
	        local dev=`do_bc \($p - $avg\) \^ 2`
	        tmp=`do_bc $tmp + $dev`
	done
	tmp=`do_bc_scale 1 sqrt \( $tmp / \($num - 1\) \)`
	avg=`do_bc_scale 1 $avg / 1`
	echo "$avg:$tmp"
}

usage() {
        echo $*
        echo "       -b <block device to profile>"
        echo "       -d <summary output directory>"
        echo "       -l <max io len>"
        echo "       -t <minimum number of threads per device>"
        echo "       -T <maximum number of threads per device>"
        echo "       -r <tests to run>"
        exit;
}

# some cute code for handling tables whose columns fit
set_max() {
        local target=$1
        local val=$2
                                                                                
        if [ $val -gt ${!target:-0} ]; then
                eval $target=$val
        fi
}
table_set() {
        local name="_table_$1"
        local col=$2
        local row=$3
        local val=$4
        local num
                                                                                
        eval ${name}_${row}_${col}="'$val'"
                                                                                
        set_max ${name}_${col}_longest ${#val}
        set_max ${name}_num_col $(($col + 1))
        set_max ${name}_num_row $(($row + 1))
}
                                                                                
table_get() {
        local name="_table_$1"
        local col=$2
        local row=$3
        tmp="${name}_${row}_${col}"
        echo ${!tmp}
}
                                                                                
table_dump() {
        local name="_table_$1"
        local num_col;
        local num_row;
        local fmt="";
        local tmp
        local sep
                                                                                
        tmp="${name}_num_col"
        num_col="${!tmp:-0}"
        tmp="${name}_num_row"
        num_row="${!tmp:-0}"
                                                                                
        # iterate through the columns to find the longest
                                                                                
        sep=" "
        for x in `seq 0 $num_col`; do
                tmp="${name}_${x}_longest"
                tmp=${!tmp:-0}
                [ $tmp -eq 0 ] && continue
                                                                                
                [ $x -eq $((num_col - 1)) ] && sep='\n'
                                                                                
                fmt="$fmt%-${tmp}s$sep"
        done
                                                                                
        # nothing in the table to print
        [ -z "$fmt" ] && return
                                                                                
        for y in `seq 0 $num_row`; do
                local row=""
                for x in `seq 0 $num_col`; do
                                                                                
                        # skip this element if the column is empty
                        tmp="${name}_${x}_longest"
                        [ ${!tmp:-0} -eq 0 ] && continue
                                                                                
                        # fill this cell with the value or '' for printf
                        tmp="${name}_${y}_${x}"
                        row="$row'${!tmp:-""}' "
                done
                eval printf "'$fmt'" $row
        done
}

######################################################################
# the sgp_dd tests
sgp_dd_banner() {
	echo sgp_dd using dio=1 and thr=
}
sgp_dd_config() {
	# it could be making sure that the block dev
	# isn't in use by something else
	local nothing=0
}
sgp_dd_prepare() {
	if ! which sgp_dd; then
		echo "can't find sgp_dd binary"
		return 1
	fi
	return 0
}
sgp_dd_setup() {
	# it could be making sure that the block dev
	# isn't in use by something else
	local nothing=0
}
sgp_dd_start() {
	local threads=$1
	local iosize=$2
	local wor=$3
	local i=$4
	local ifof;
	local bdev=${blocks[$i]};

	case "$wor" in
		[wo]) ifof="if=/dev/zero of=$bdev" ;;
		r) ifof="if=$bdev of=/dev/null" ;;
		*) die "asked to do io with $wor?"
	esac
	echo sgp_dd $ifof bs=$iosize"k" count=$(($io_len / $iosize)) time=1 \
			dio=1 thr=$threads
}
sgp_dd_result() {
	local output=$1

	awk '($(NF) == "MB/sec") {print $(NF-1)}' < $output
}
sgp_dd_cleanup() {
	# got me
	local nothing=0
}
sgp_dd_finish() {
	# got me
	local nothing=0
}
sgp_dd_teardown() {
	# got me
	local nothing=0
}

######################################################################
# the iozone tests
ext2_iozone_banner() {
	echo "iozone -I on a clean ext2 fs"
}
ext2_iozone_config() {
	local nothing=0
}
ext2_iozone_prepare() {
	local index=$1
	local bdev=${blocks[$index]}
	local mntpnt=$tmpdir/mount_$index

	if ! which iozone; then
		echo "iozone binary not found in PATH"
		return 1
	fi
	if ! iozone -i 0 -w -+o -s 1k -r 1k -f /dev/null > /dev/null; then
		echo "iozone doesn't support -+o"
		return 1
	fi
	if ! which mke2fs; then
		echo "mke2fs binary not found in PATH"
		return 1
	fi

	if ! mkdir -p $mntpnt ; then
		echo "$mntpnt isn't a directory?"
	fi

	echo making ext2 filesystem on $bdev
	if ! mke2fs -b 4096 $bdev; then
		echo "mke2fs failed"
		return 1;
	fi

	if ! mount -t ext2 $bdev $mntpnt; then 
		echo "couldn't mount $bdev on $mntpnt"
		return 1;
	fi

	cleanup_mounts[$index]="$mntpnt"
	return 0
}
ext2_iozone_setup() {
	local id=$1
	local wor=$2
	local f="$tmpdir/mount_$id/iozone"

	case "$wor" in
		w) rm -f $f ;;
		[or]) ;;
		*) die "asked to do io with $wor?"
	esac
}
ext2_iozone_start() {
	local threads=$1
	local iosize=$2
	local wor=$3
	local id=$4
	local args;
	local f="$tmpdir/mount_$id/iozone"

	case "$wor" in
		[wo]) args="-i 0 -w" ;;
		r) args="-i 1" ;;
		*) die "asked to do io with $wor?"
	esac

	echo iozone "$args -r ${iosize}k -s $(($io_len / $threads))k \
			-t $threads -+o -x -I -f $f"
}
ext2_iozone_result() {
	local output=$1
	local wor=$2
	local string
	local field

	case "$wor" in
		[wo]) string="writers" 
		   field=7 
			;;
		r) string="readers" 
		   field=6
			;;
		*) die "asked to do io with $wor?"
	esac

	do_bc_scale 1 `awk '($1 == "Parent" && $'$field' == "'$string'") \
			{print $'$(($field + 2))'}' $output` / 1024
}
ext2_iozone_cleanup() {
	# the final read w/o -w removed the file
	local nothing=0
}
ext2_iozone_finish() {
	local index=$1
	local mntpnt=$tmpdir/mount_$index

	umount -f $mntpnt
	unset cleanup_mounts[$index]
}
ext2_iozone_teardown() {
	local nothing=0
}

######################################################################
# the lctl test_brw via the echo_client on top of the filter

# the echo_client setup is nutty enough to warrant its own clenaup
running_config=""
running_module=""
declare -a running_names
declare -a running_oids

cleanup_echo_filter() {
	local i

	for i in `seq 0 $last_block`; do
		[ -z "${running_oids[$i]}" ] && continue
		lctl --device "\$"echo_$i destroy ${running_oids[$i]} \
			$running_threads
	done
	unset running_oids

	for n in ${running_names[*]}; do
# I can't believe leading whitespace matters here.
lctl << EOF
cfg_device $n
cleanup
detach
quit
EOF
	done
	unset running_names

	for m in $running_module; do
		rmmod $m
	done
	running_module=""

	[ ! -z "$running_config" ] && lconf --cleanup $running_config
	running_config=""
}

echo_filter_banner() {
	echo "test_brw on the echo_client on the filter" 
}
echo_filter_config() {
	local index=$1
	local bdev=${blocks[$index]}
	local config="$tmpdir/config.xml"

	if ! which lmc; then
		echo "lmc binary not found in PATH"
		return 1
	fi
	if ! which lconf; then
		echo "lconf binary not found in PATH"
		return 1
	fi
	if ! which lctl; then
		echo "lctl binary not found in PATH"
		return 1
	fi

	if [ $index = 0 ]; then
		if ! lmc -m $config --add net \
			--node $HOSTNAME --nid $HOSTNAME --nettype tcp; then
			echo "error adding $HOSTNAME net node"
			return 1
		fi
	fi

	if ! lmc -m $config --add ost --ost ost_$index --node $HOSTNAME \
			--fstype ext3 --dev $bdev --journal_size 400; then
		echo "error adding $bdev to config with lmc"
		return 1
	fi

	# it would be nice to be able to ask lmc to setup an echo client
	# to the filter here.  --add echo_client assumes osc
}
echo_filter_prepare() {
	local index=$1
	local bdev=${blocks[$index]}
	local config="$tmpdir/config.xml"
	local name="echo_$index"
	local uuid="echo_$index_uuid"

	if [ $index = 0 ]; then
		if ! lconf --reformat $config; then
			echo "error setting up with lconf"
			return 1;
		fi
		running_config="$config"

		echo 0 > /proc/sys/lnet/debug
		echo 0 > /proc/sys/lnet/subsystem_debug

		if ! grep -q '^obdecho\>' /proc/modules; then
			local m
			if ! modprobe obdecho; then
				if [ ! -z "$echo_module" ]; then
					if ! insmod $echo_module; then
						echo "err: insmod $echo_module"
						return 1;
					else
						m="$echo_module"
					fi
				else
					echo "err: modprobe $obdecho"
					return 1;
				fi
			else
				m=obdecho
			fi
			running_module=`basename $m | cut -d'.' -f 1`
		fi
	fi

lctl << EOF
        newdev
        attach echo_client $name $uuid
        setup ost_$index
        quit
EOF
	if [  $? != 0 ]; then
		echo "error setting up echo_client $name against ost_$index"
		return 1
	fi
	running_names[$index]=$name
}
echo_filter_setup() {
	local id=$1
	local wor=$2
	local threads=$3
	local name="echo_$id"
	local oid

	case "$wor" in
		w) ;;
		[or]) return ;;
		*) die "asked to do io with $wor?"
	esac

	running_threads=$threads
	oid=`lctl --device "\$"$name create $threads | \
		awk '/ #1 is object id/ { print $6 }'`
	# XXX need to deal with errors
	running_oids[$id]=$oid
}
echo_filter_start() {
	local threads=$1
	local iosize=$2
	local wor=$3
	local id=$4
	local rw

	local name="echo_$id"
	local len_pages=$(($io_len / $(($page_size / 1024)) / $threads ))
	local size_pages=$(($iosize / $(($page_size / 1024)) ))

	case "$wor" in
		[wo]) rw="w" ;;
		r) rw="r" ;;
		*) die "asked to do io with $wor?"
	esac

	echo lctl --threads $threads v "\$"$name \
		test_brw 1 $rw v $len_pages t${running_oids[$id]} p$size_pages
}
echo_filter_result() {
	local output=$1
	local total=0
	local mbs

	for mbs in `awk '($8=="MB/s):"){print substr($7,2)}' < $output`; do
		total=$(do_bc $total + $mbs)
	done
	do_bc_scale 2 $total / 1
}
echo_filter_cleanup() {
	local id=$1
	local wor=$2
	local threads=$3
	local name="echo_$id"

	case "$wor" in
		[wo]) return ;;
		r) ;;
		*) die "asked to do io with $wor?"
	esac

	lctl --device "\$"$name destroy ${running_oids[$id]} $threads
	unset running_oids[$id]
}
echo_filter_finish() {
	local index=$1
	# leave real work for _teardown
}
echo_filter_teardown() {
	cleanup_echo_filter
}

######################################################################
# the iteration that drives the tests

test_one() {
	local test=$1
	local my_x=$2
	local threads=$3
	local iosize=$4
	local wor=$5
	local vmstat_pid
	local vmstat_log="$tmpdir/vmstat.log"
	local opref="$test-$threads-$iosize-$wor"
	local -a iostat_pids
	# sigh.  but this makes it easier to dump into the tables
	local -a read_req_s
	local -a mb_s
	local -a write_req_s
	local -a sects_req
	local -a queued_reqs
	local -a service_ms

	for i in `seq 0 $last_block`; do
		${test}_setup $i $wor $threads
	done

	echo $test with $threads threads

	$oprofile opcontrol --start

	# start up vmstat and record its pid
        nice -19 vmstat 1 > $vmstat_log 2>&1 &
	[ $? = 0 ] || die "vmstat failed"
	vmstat_pid=$!
	pid_now_running $vmstat_pid

	# start up each block device's iostat
	for i in `seq 0 $last_block`; do
		nice -19 iostat -x ${blocks[$i]} 1 | awk \
			'($1 == "'${blocks[$i]}'"){print $0; fflush()}' \
			> $tmpdir/iostat.$i &
		local pid=$!
		pid_now_running $pid
		iostat_pids[$i]=$pid
	done

	$oprofile opcontrol --reset
	$readprofile -r

	# start all the tests.  each returns a pid to wait on
	pids=""
	for i in `seq 0 $last_block`; do
		local cmd=`${test}_start $threads $iosize $wor $i`
		echo "$cmd" >> $tmpdir/commands
		$cmd > $tmpdir/$i 2>&1 &
		local pid=$!
		pids="$pids $pid"
		pid_now_running $pid
	done

	echo -n waiting on pids $pids:
	for p in $pids; do
		wait $p
		echo -n .
		pid_has_stopped $p
	done

	# stop vmstat and all the iostats
	kill $vmstat_pid
	pid_has_stopped $vmstat_pid
	for i in `seq 0 $last_block`; do
		local pid=${iostat_pids[$i]}
		[ -z "$pid" ] && continue

		kill $pid
		unset iostat_pids[$i]
		pid_has_stopped $pid
	done

	$readprofile | sort -rn > $tmpdir/readprofile

	$oprofile opcontrol --shutdown
	$oprofile opreport > $tmpdir/oprofile
	echo >> $tmpdir/oprofile
	$oprofile opreport -c -l | head -20 >> $tmpdir/oprofile

	save_output $tmpdir/oprofile $opref.oprofile
	save_output $tmpdir/readprofile $opref.readprofile

	# collect the results of vmstat and iostat
	cpu=$(mean_stddev $(awk \
	      '(NR > 3 && NF == 16 && $16 != "id" )	\
		{print 100 - $16}' < $vmstat_log) )
	save_output $vmstat_log $opref.vmstat

	for i in `seq 0 $last_block`; do
		read_req_s[$i]=$(mean_stddev $(awk \
		      '(NR > 1)	{print $4}' < $tmpdir/iostat.$i) )
		write_req_s[$i]=$(mean_stddev $(awk \
		      '(NR > 1)	{print $5}' < $tmpdir/iostat.$i) )
		sects_req[$i]=$(mean_stddev $(awk \
		      '(NR > 1)	{print $10}' < $tmpdir/iostat.$i) )
		queued_reqs[$i]=$(mean_stddev $(awk \
		      '(NR > 1)	{print $11}' < $tmpdir/iostat.$i) )
		service_ms[$i]=$(mean_stddev $(awk \
		      '(NR > 1)	{print $13}' < $tmpdir/iostat.$i) )

		save_output $tmpdir/iostat.$i $opref.iostat.$i
	done

	# record each index's test results and sum them
	thru=0
	for i in `seq 0 $last_block`; do
		local t=`${test}_result $tmpdir/$i $wor`
		save_output $tmpdir/$i $opref.$i
		echo test returned "$t"
		mb_s[$i]="$t"
		# some tests return mean:stddev per device, filter out stddev
		thru=$(do_bc $thru + $(echo $t | sed -e 's/:.*$//g'))
	done

	for i in `seq 0 $last_block`; do
		${test}_cleanup $i $wor $threads
	done

	# tabulate the results
	echo $test did $thru mb/s with $cpu
	table_set $test $my_x $cur_y `do_bc_scale 2 $thru / 1`
	table_set $test $(($my_x + 1)) $cur_y $cpu

	for i in `seq 0 $last_block`; do
		cur_y=$(($cur_y + 1))
		table_set $test $(($my_x)) $cur_y ${mb_s[$i]}
		table_set $test $(($my_x + 1)) $cur_y ${read_req_s[$i]}
		table_set $test $(($my_x + 2)) $cur_y ${write_req_s[$i]}
		table_set $test $(($my_x + 3)) $cur_y ${sects_req[$i]}
		table_set $test $(($my_x + 4)) $cur_y ${queued_reqs[$i]}
		table_set $test $(($my_x + 5)) $cur_y ${service_ms[$i]}
	done

	cur_y=$(($cur_y + 1))
}

test_iterator() {
	local test=$1
	local thr=$min_threads
	local cleanup=""
	local rc=0
	local i
	
	for i in `seq 0 $last_block`; do
		if ! ${test}_config $i; then
			echo "couldn't config $test for bdev ${blocks[$i]}"
			echo "skipping $test for all block devices"
			cleanup=$(($i - 1))
			rc=1;
			break
		fi
	done

	for i in `seq 0 $last_block`; do
		# don't prepare if _config already failed
		[ ! -z "$cleanup" ] && break
		if ! ${test}_prepare $i; then
			echo "couldn't prepare $test for bdev ${blocks[$i]}"
			echo "skipping $test for all block devices"
			cleanup=$(($i - 1))
			rc=1;
			break
		fi
	done

	while [ -z "$cleanup" -a $thr -lt $(($max_threads + 1)) ]; do
		for iosize in 128 512; do
			table_set $test 0 $cur_y $thr
			table_set $test 1 $cur_y $iosize

			for wor in w o r; do
				table_set $test 2 $cur_y $wor
				test_one $test 3 $thr $iosize $wor
			done
		done
		thr=$(($thr + $thr))
	done

	[ -z "$cleanup" ] && cleanup=$last_block

	if [ "$cleanup" != -1 ]; then
		for i in `seq $cleanup 0`; do
			${test}_finish $i
		done
	fi

	${test}_teardown

	return $rc;
}

while getopts ":d:b:l:t:T:r:e:" opt; do
        case $opt in
                e) echo_module=$OPTARG                 ;;
                b) block=$OPTARG                 ;;
                d) output_dir=$OPTARG                 ;;
                l) io_len=$OPTARG			;;
                r) run_tests=$OPTARG			;;
                t) min_threads=$OPTARG			;;
                T) max_threads=$OPTARG			;;
                \?) usage
        esac
done

page_size=`getconf PAGE_SIZE` || die '"getconf PAGE_SIZE" failed'

[ ! -z "$echo_module" -a ! -f "$echo_module" ] && \
	die "obdecho module $echo_module is not a file"

if [ -z "$io_len" ]; then
	io_len=`awk '($1 == "MemTotal:"){print $2}' < /proc/meminfo`
	[ -z "$io_len" ] && die "couldn't determine the amount of memory"
fi

if [ ! -z "$output_dir" ]; then
	if [ ! -e "$output_dir" ]; then
		 mkdir -p "$output_dir" || die  "error creating $output_dir"
	fi
	[ ! -d "$output_dir" ] && die "$output_dir isn't a directory"
fi

block=`echo $block | sed -e 's/,/ /g'`
[ -z "$block" ] && usage "need block devices"

run_tests=`echo $run_tests | sed -e 's/,/ /g'`
[ -z "$run_tests" ] && usage "need to specify tests to run with -r"
for t in $run_tests; do
	if ! echo $possible_tests | grep -q $t ; then
		die "$t isn't one of the possible tests: $possible_tests"
	fi
done

if which opcontrol; then
        echo generating oprofile results
        oprofile=""
else
        echo not using oprofile
        oprofile=": "
fi

if which readprofile; then
	map="/boot/System.map-`uname -r`"
	if [ -f /proc/profile -a -f "$map" ]; then
		echo generating profiles with 'readprofile'
		readprofile="readprofile -m $map"
	fi
fi
if [ -z "$readprofile" ]; then
	echo not using readprofile
	readprofile=": "
fi

[ $min_threads -gt $max_threads ] && \
	die "min threads $min_threads must be <= min_threads $min_threads"

for b in $block; do
	[ ! -e $b ] && die "block device file $b doesn't exist"
	[ ! -b $b ] && die "$b isn't a block device"
	dd if=$b of=/dev/null bs=8192 count=1 || \
		die "couldn't read 8k from $b, is it alive?"
	[ ! -b $b ] && die "$b isn't a block device"
	last_block=$(($last_block + 1))
	blocks[$last_block]=$b
done	

tmpdir=`mktemp -d /tmp/.surveyXXXXXX` || die "couldn't create tmp dir"

echo each test will operate on $io_len"k"

test_results=""

for t in $run_tests; do

	table_set $t 0 0 "T"
	table_set $t 1 0 "L"
	table_set $t 2 0 "m"
	table_set $t 3 0 "A"
	table_set $t 4 0 "C"
	table_set $t 3 1 "MB"
	table_set $t 4 1 "rR"
	table_set $t 5 1 "wR"
	table_set $t 6 1 "SR"
	table_set $t 7 1 "Q"
	table_set $t 8 1 "ms"
	cur_y=2;

	if ! test_iterator $t; then
		continue;
	fi
	test_results="$test_results $t"
done

save_output $tmpdir/commands commands

[ ! -z "$test_results" ] && (
	echo
	echo "T = number of concurrent threads per device"
	echo "L = base io operation length, in KB"
	echo "m = IO method: read, write, or over-write"
	echo "A = aggregate throughput from all devices"
	echo "C = percentage CPU used, both user and system"
	echo "MB/s = per-device throughput"
	echo "rR = read requests issued to the device per second"
	echo "wR = write requests issued to the device per second"
	echo "SR = sectors per request; sectors tend to be 512 bytes"
	echo "Q = the average number of requests queued on the device"
	echo "ms = the average ms taken by the device to service a req"
	echo
	echo "foo:bar represents a mean of foo with a stddev of bar"
)

for t in $test_results; do
	${t}_banner
	table_dump $t
done
