#!/bin/sh
#
# this runs prep/commit against filters and generates a
# table of their write timings.  it needs the names
# of the filters it will run against and needs the
# obdecho module loaded.  it spews a lot of junk
# as it goes, only the last bit is really interesting; 
# tee it to a log file.
#
# ex: FILTER_NAMES="ost1 ost2" sh ./filter_survey.sh
#
SRCDIR="`dirname $0`/"
export PATH=$SRCDIR/../utils:/sbin:/usr/sbin::$PATH

tmp_dir=""
echo_base="f_s_$$"
echo_objs=""

die() {
	echo $* 1>&2
	exit 1
}

cleanup() {
	[ ! -z "$tmp_dir" ] && [ -d $tmp_dir ] && rm -rf $tmp_dir
	[ -z "$echo_objs" ] && exit 0
	for obj in $echo_objs; do
		echo cleaning up $obj
# I can't believe leading whitespace matters here.
lctl << EOF
device $obj
cleanup
detach
quit
EOF
	done
}
trap cleanup EXIT

not_a_filter() {
	lctl device_list | awk "/obdfilter $1/ {exit 1}"
	return $?
}

# holy crap are these confusing
sep1="||||"
sep2="||"
sep3=""
sep4="||||"

#
# build up echo_clients attached to the given filters and record
# their names and obj numbers for later use and teardown
#
last_filter="-1"
[ -z "$FILTER_NAMES" ] && die "please specify filter names to run against"
for fn in $FILTER_NAMES; do
	if not_a_filter $fn; then
		die "'$fn' isn't the name of an obdfilter device"
	fi
	en="${echo_base}_$fn"
lctl << EOF
	newdev
	attach echo_client $en ${en}_uuid
	setup $fn
	probe
	quit
EOF
	[ $? -eq 0 ] || die "error setting up echo_client (is obdecho loaded?)"

	obj=`lctl device_list | awk "/echo_client $en/ {print "'$1}'`
	[ -z "$obj" ] && die "couldn't find my echo_client's object number"
	echo setup echo_client name $en as object $obj
	echo_objs="$echo_objs $obj"

	last_filter=$(($last_filter + 1))
	echo_names[$last_filter]=$en

	# build up the seperators we'll use in generating the wiki
	sep1="$sep1||||"
	sep2="$sep2||"
	sep3="$sep3||"
	sep4="$sep4||"
done


doit() {
        $*
}
nop() {
        local nothing;
}
if which opcontrol; then
        echo generating oprofile results
        oprofile=doit
else
        echo not using oprofile
        oprofile=nop
fi
 
tmp_dir=`mktemp -d /tmp/echo_client_survey_XXXXXX` || die "mktemp failed"

TOT_PAGES=${TOT_PAGES:-524288}

throughput() {
	local threads="$1"
	local pages="$2"
	local time="$3"
	local tp=`echo 'scale=2; '$threads' * '$pages' * 4096 / ('$time' * 1024 * 1024)' | bc`
	echo $tp
}

wait_for_idle_io() {
	echo "waiting idle io via vmstat"
	vmstat 1 | awk '
        ($10 == 0 && $11 == 0) {
                idle++;
                if (idle == 3) {
                        print "idle for 3 seconds, must be done"
                        exit
                }
        }
        (NR == 13) {
                "deletion took longer than 10s, bailing";
                exit
        } '
}

#
# sorry for the wild indenting.  get a wide terminal, its 2003.
#
num_rows="0"
num_summary_rows="0"
for order_threads in `seq 0 3`; do 
	nthreads=$(echo "2^$order_threads" | bc)

	for stride in 16 64 128; do 
		span="<|$(($nthreads +1))>"
		row="||$span $nthreads||$span $stride||"
		sum_row="||$nthreads||$stride||"

		for t in `seq 1 $nthreads`; do
			thread_row[$t]="||"
		done

		for obj_per_thread in y n; do
			if [ $obj_per_thread == "y" ]; then
				offset_prefix=""
				objid_prefix="t";
			else 
				offset_prefix="t"
				objid_prefix="";
			fi

			# create the objects that this write/rewrite run
			# will be using
			for i in `seq 0 $last_filter`; do
				oid=`lctl --device "\$"${echo_names[$i]} create $nthreads | \
					awk '/1 is object id/ { print $6 }'`
				[ -z "$oid" ] && die "error creating object"
				oids[$i]=$oid
			done

			# iterate through write and rewrite
			for a in 1 2; do
				total_maxtime="0.0"
				pids=""

				$oprofile opcontrol --start				

				echo 'nice -19 vmstat 5' > $tmp_dir/vmstat-log
				nice -19 vmstat 5 >> $tmp_dir/vmstat-log &
				vmstat_pid="$!"

				$oprofile opcontrol --reset

				# start a test_brw thread in the background
				# for each given filter
				for i in `seq 0 $last_filter`; do
					lctl --threads $nthreads v "\$"${echo_names[$i]} \
						test_brw ${offset_prefix}1 w v \
						$TOT_PAGES ${objid_prefix}${oids[$i]} p$stride | \
							tee $tmp_dir/$i &
					pids="$pids $!"
				done
				echo ------ waiting for $nthreads obj per thread $obj_per_thread rw: $a ----
				for p in $pids; do 
					wait $p
				done
				$oprofile opcontrol --shutdown
				echo ------ finished $nthreads obj per thread $obj_per_thread rw: $a ----
				kill $vmstat_pid
				cat $tmp_dir/vmstat-log
				rm $tmp_dir/vmstat-log

			        $oprofile opreport
				$oprofile opreport -c -l

				for t in `seq 1 $nthreads`; do
					thread_row[$t]="${thread_row[$t]} ||"
				done
				row_tmp=""
				for i in `seq 0 $last_filter`; do
					maxtime="0.0"
					for t in `seq 1 $nthreads`; do
						f="$tmp_dir/$i"
						MS=`grep "test_brw-$t" $f | \
						   awk '($8=="MB/s):"){print $6, substr($7,2);}'`
						thread_row[$t]="${thread_row[$t]}$MS||"
						time=`echo $MS | cut -d s -f 1`
						if [ `echo "$time > $maxtime" | bc` -eq "1" ]; then
							maxtime=$time;
						fi
					done
					tp=`throughput $nthreads $TOT_PAGES $maxtime`
					row_tmp="${row_tmp}<#ffffe0>$tp $maxtime||"
					sum_row="${sum_row}$tp||"

					if [ `echo "$maxtime > $total_maxtime" | bc` -eq "1" ]; then
						total_maxtime=$maxtime;
					fi
				done
				tp=`throughput $(($nthreads * $(($last_filter +1)))) $TOT_PAGES $total_maxtime`
				row="${row}<#ffffe0>${tp} $total_maxtime||${row_tmp}"
			done

			# destroy the objects from this run and wait for
			# their destruction to complete 
			for i in `seq 0 $last_filter`; do
				lctl --device "\$"${echo_names[$i]} destroy ${oids[$i]} $nthreads
			done
			wait_for_idle_io
		done

		num_rows=$(($num_rows + 1))
		rows[$num_rows]="$row"

		num_summary_rows=$(($num_summary_rows + 1))
		summary[$num_summary_rows]="$sum_row"

		for t in `seq 1 $nthreads`; do
			num_rows=$(($num_rows + 1))
			rows[$num_rows]="${thread_row[$t]}"
		done
	done
done

echo done.

bg='<rowbgcolor="#eoeoff"'
echo "||$bg|2>threads writing $TOT_PAGES pages||<|2>pages per prep/commit${sep1}oid per thread${sep1}shared oid||"
echo "$sep2$bg>write${sep2}re-write${sep2}write${sep2}re-write||"
for r in `seq 1 $num_rows`; do
	echo ${rows[$r]}
done

echo summary table

echo "||$bg|2>threads||<|2>pages ${sep4}oid/thread${sep4}shared oid||"
echo "$sep3$bg>write${sep3}re-write${sep3}write${sep3}re-write||"
for r in `seq 1 $num_summary_rows`; do
	echo ${summary[$r]}
done
