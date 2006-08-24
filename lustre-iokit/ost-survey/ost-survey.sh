#!/bin/bash

# This script is to be run on a client machine and will test all the 
# OSTs to determine which is the fastest and slowest
# The current test method 
# Create a directory for each OST
# Use 'lfs setstripe' to set the Lustre striping such that IO goes to 
# only one OST
# Use 'dd' to write a file of a specified size
# Use 'dd' to read a file of a specified size
# Compute the average 
# Find the slowest OST


declare -a rTime=()          # Time to read some data
declare -a wTime=()          # Time to write some data
declare -a rMBs=()           # Read speed
declare -a wMBs=()           # Write speed

# GLOBALS
OSTS=0                       # Number of OSTS we will loop over
OFILE=testdummy              #  File name to use
BSIZE=1024                   # size of blocks to be written 
MNT=''                       # Location of Lustre file system
DIR="tmpdir"                 # Name used to create a series of tmp directories
VERBOSE=1                    # Set this to get verbose output ( TODO - use getopts? )

# Usage
if [ $# -ne 2 ]; then
   echo "Usage: $0 <size of test file in KB> <Lustre directory>"
   exit 1
fi


test_preq () {
    # check for a mounted Lustre filesystem
    MNT=`grep lustre /proc/mounts | awk '{print $2}'`
    if [ -z $MNT ]; then
	echo "Mounted Lustre filesystem not found"
	exit 1
    fi
    
    # Check for Lustre utilites in PATH
    # Check for dd
}

ost_count () {
  # We assume that all devices with 'osc' in the string are OSTs
  OSTS=`lctl dl | grep -c osc`
}

make_dummy () {
# Create a file full of zeros
    echo "make dummy"
    local DIR=$1
    local SIZE=$2
    mkdir -p $MNT/$DIR
    dd if=/dev/zero of=$MNT/$DIR/$OFILE count=$SIZE bs=$BSIZE 2> /dev/null
    
}

output_all_data () {
    echo "$OSTS OST devices found"
    local CNT=0
    while [ $CNT -lt $OSTS ]; do
	echo "Ost index $CNT Read speed ${rMBs[$CNT]} Write speed ${wMBs[$CNT]}"
	echo "Ost index $CNT Read time ${rTime[$CNT]} Write time ${wTime[$CNT]}"
	CNT=$(( $CNT + 1 ))
    done
}
run_test () {
    local DIR=$1
    local SIZE=$2
    local INX=$3
    local ACTION=$4
    
    if [ ! -f $MNT/$DIR/$OFILE ] && [ $ACTION == 'read' ]; then
	make_dummy $DIR $SIZE
    fi

    t0=`date +%s.%N`
    if [ $ACTION == 'read' ]; then 
	OUTS=`dd if=$MNT/$DIR/$OFILE of=/dev/null count=$SIZE bs=$BSIZE 2> /dev/null`
    elif [ $ACTION == 'write' ]; then 
	OUTS=`dd of=$MNT/$DIR/$OFILE if=/dev/zero count=$SIZE bs=$BSIZE 2> /dev/null`
    else
	echo "Action not read||write"
	exit 1
    fi
    t1=`date +%s.%N`

    tdelta=`awk "BEGIN {printf \"%7.2f\", $t1 - $t0; exit}"`
    sdelta=$(( $SIZE * $BSIZE ))
    delta=`awk "BEGIN {printf \"%7.2f\", ($SIZE * $BSIZE / ( $t1 - $t0 )) / ( 1024 * 1024 ) ; exit}"`
    
    if [ $ACTION == 'read' ]; then 
	rTime[$INX]=$tdelta
	rMBs[$INX]=$delta
    else 
	wTime[$INX]=$tdelta
	wMBs[$INX]=$delta
    fi
}

display_average () {
    local CNT=0
    local OP=$1
    while [ $CNT -lt $OSTS ]; do
	if [ $OP == "read" ]; then
	    echo "${rMBs[$CNT]} $OP"
	elif [ $OP == "write" ]; then
	    echo "${wMBs[$CNT]} $OP"
	else
	    echo "Bad param"
            exit 1
	fi
	CNT=$(( $CNT + 1 ))
    done |  awk '{ c++; t+= $1; op = $2 }; END { printf "Average %s Speed: %7.2f\n", op, t/c }'

}

find_min () {
    local CNT=0
    local OP=$1
    while [ $CNT -lt $OSTS ]; do
	if [ $OP == "read" ]; then
	    echo "${rMBs[$CNT]} $CNT $OP"
	elif [ $OP == "write" ]; then 
	    echo "${wMBs[$CNT]} $CNT $OP"
	else
	    echo "Bad param"
            exit 1
	fi
	    CNT=$(( $CNT + 1 ))
    done | awk '{
	if (NR == 1) { min = $1; indx = $2; op = $3 } 
	else if (min > $1){  min = $1; indx = $ 2; op = $3}
    } 
    END {printf "%s - Worst OST indx %d %7.2f MB/s\n", op, indx, min}'
}

find_max () {
    local CNT=0
    local OP=$1
    while [ $CNT -lt $OSTS ]; do
	if [ $OP == "read" ]; then
	    echo "${rMBs[$CNT]} $CNT $OP"
	elif [ $OP == "write" ]; then 
	    echo "${wMBs[$CNT]} $CNT $OP"
	else
	    echo "Bad param"
            exit 1
	fi
	    CNT=$(( $CNT + 1 ))
    done | awk '{
	if (NR == 1) { max = $1; indx = $2; op = $3 } 
	else if (max < $1){  max = $1; indx = $ 2; op = $3 }
    } 
    END {printf "%s - Best OST indx %d %7.2f MB/s\n", op, indx, max}'
}
# Temp cleanup

CNT=0
MYSIZE=1024

test_preq
ost_count

while [ $CNT -lt $OSTS ]; do
    rm -rf $MNT/${DIR}${CNT}
    mkdir -p $MNT/${DIR}${CNT}
    lfs setstripe $MNT/${DIR}${CNT} 0 $CNT 1
    run_test ${DIR}${CNT} $MYSIZE $CNT write
    run_test ${DIR}${CNT} $MYSIZE $CNT read
    CNT=$(( $CNT + 1 ))
done

MAX_MB=0
MIN_T=999999999

display_average read
display_average write
find_min read
find_min write
find_max read
find_max write

CNT=0


if [ $VERBOSE ]; then
    output_all_data
fi

