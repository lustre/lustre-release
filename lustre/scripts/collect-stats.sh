#!/bin/bash

die() {
        echo $* 1>&2
        exit 1
}
cleanup_lock=""
cleanup() {
        [ ! -z "$cleanup_lock" ] && rmdir $cleanup_lock
}
trap cleanup EXIT

usage() {
        echo "  -d dir  (required)"
        echo "          Specifies the top level directory that all hosts share"
        echo "          and collects stats under.  Each host will use a "
        echo "          subdirectory named after its hostname."
        echo
        echo "          If the host directory doesn't exist, stats collection"
        echo "          begins by clearing accumulators in /proc and launching"
        echo "          background tasks."
	echo
        echo "          If the host directory exists, the script stops "
	echo "		background processes and collects the results.  A host"
        echo "          directory can not be reused once it has collected"
        echo "          stats."
        echo "  -h"
        echo "		Shows this help message."
        echo
        echo "Example:"
        echo " [on all nodes] $0 -d /tmp/collection"
        echo " (time passes while a load is run)"
        echo " [on all nodes] $0 -d /tmp/collection"
        echo " tree /tmp/collection"
        echo
        exit
}

[ ${#*} == 0 ] && usage

while getopts ":d:" opt; do
        case $opt in
                d) topdir=$OPTARG                 ;;
                \?) usage
        esac
done

if [ ! -e $topdir ]; then
	mkdir -p $topdir || die "couldn't create dir $topdir"
fi

[ ! -d $topdir ] && die "$topdir isn't a directory"

mydir="$topdir/`hostname`"
lock="$topdir/.`hostname`-lock"

mkdir $lock || "another script is working on $mydir, exiting."
cleanup_lock="$lock"

clear_files() {
	for f in $1; do
		[ ! -f $f ] && continue
		echo 0 > $f
	done
}

dump_files() {
	dirglob=$1
	shift
	for d in $dirglob; do
		[ ! -d $d ] && continue
		log="$mydir/`basename $d`"
		> $log
		for f in $*; do
			[ ! -f $d/$f ] && continue
			echo "----------------- $f" >> $log
			( cd $d && cat $f ) >> $log
		done
	done
}

# find filter dirs, sigh.
num_filter_dirs=0
for f in /proc/fs/lustre/obdfilter/*; do
	[ ! -d $f ] && continue;
	num_filter_dirs=$((num_filter_dirs + 1))
	filter_dirs="$filter_dirs,`basename $f`"
done
if [ $num_filter_dirs == "1" ]; then
	tmp=`echo $filter_dirs | sed -e 's/,//g'`
	filter_dirs="/proc/fs/lustre/obdfilter/$tmp"
fi
if [ $num_filter_dirs -gt "1" ]; then
	filter_dirs="/proc/fs/lustre/obdfilter/{$filter_dirs}"
fi

save_proc_files() {
	cd /proc
	for f in $*; do
		save=`echo $f | sed -e 's@/@_@g'`
		[ ! -f $f ] && continue
		cat $f > $mydir/$save
	done
	cd -
}

launch() {
	touch $mydir/pids

	if ! which $1 > /dev/null 2>&1; then
		return
	fi

	cd $mydir
	$* > $1.log 2>&1 &
	PID=$!
	if [ $? = 0 ]; then
		echo $PID >> pids
		echo "launched '$*' as pid $PID"
	else
		echo "'$*' failed"
		rm $1.log
	fi
	cd -
}


start_collection() {
	echo "starting collection in $mydir"
	mkdir $mydir || die "couldn't create dir $mydir"

	echo clearing files in /proc/fs/lustre
	clear_files '/proc/fs/lustre/osc/*MNT*/rpc_stats'
	clear_files '/proc/fs/lustre/llite/*/read_ahead_stats'
	[ ! -z "$filter_dirs" ] && clear_files "$filter_dirs/brw_stats"

	launch vmstat 2
	launch iostat -x 2


	date > $mydir/started
}


stop_collection() {
	pids="$mydir/pids"

	[ -e $mydir/finished ] && die "$mydir already contains collected files"
	[ ! -e $mydir/started ] && die "$mydir hasn't started collection?"

	echo "collecting files for $mydir"
	dump_files '/proc/fs/lustre/osc/*MNT*' max_dirty_mb max_pages_per_rpc \
			max_rpcs_in_flight cur_grant_bytes rpc_stats
	dump_files '/proc/fs/lustre/llite/*' read_ahead max_read_ahead_mb \
		read_ahead_stats
	[ ! -z "$filter_dirs" ] && dump_files $filter_dirs \
				readcache_max_filesize tot_granted \
				brw_stats

	for pid in `cat $pids`; do
		echo killing pid $pid
		kill $pid
	done
	rm $pids

	save_proc_files cpuinfo meminfo slabinfo

	if which lspci > /dev/null 2>&1; then
		lspci > $mydir/lspci 2>&1
	fi

	date > $mydir/finished
	echo DONE
}

if [ -e $mydir ]; then
	stop_collection
else
	start_collection
fi
