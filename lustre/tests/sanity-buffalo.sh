#!/bin/sh

# sanity-buffalo.sh
#
# This script is used to report the results from a sanity run to buffalo.
#
# Assumptions: 
# - the target host on which you are running the test (be it
#   a real machine or a uml session) is accessible via DSH

export TMP=${TMP:-"/tmp"}
export LOG=${LOG:-"$TMP/sanity-buffalo.log"}
export DMESGLOG=${DMESGLOG:-"$TMP/sanity-buffalo-dmesg.log"}
export OUTPUT=${OUTPUT:-"$TMP/buffalo_mail"}
export DSH=${DSH:-"pdsh -S -w"}
export LUSTRE_SRC=${LUSTRE_SRC:-"$PWD/.."}
export LTESTDIR=${LTESTDIR:-"$PWD/../../ltest"}
export TARGET=${TARGET:-"uml"}
export SCP=${SCP:-"scp"}
#export NO_SHARED_FS=0

# Changeable buffalo config variables.

# The following RECIPIENTS string sends results to the buffalo-sandbox.
RECIPIENTS=${RECIPIENTS:-"buffalo-sandbox@clusterfs.com"}
# The following RECIPIENTS string sends results to buffalo proper.
# RECIPIENTS=${RECIPIENTS:-"buffalo_results@clusterfs.com"}

export TESTNAME=${TESTNAME:-"sanity-buffalo"}
export TESTDESC=${TESTDESC:-"Local test in $TARGET for correctness"}
export TESTGROUP=${TESTGROUP:-"correctness"}
export LUSTRE_TAG=${LUSTRE_TAG:-`cat $PWD/CVS/Tag | cut -c 2-`}
export TESTARCH=${TESTARCH:-`uname -r`}
export NETWORKTYPE=${NETWORKTYPE:-"tcp"}
export MACHINENAME=${MACHINENAME:-`hostname`}

usage() {

    echo "echo
Usage: sanity-buffalo.sh --sender=email_address [--config=config_name] [--test=test_name] [--extra-params=extra_parameters] [--target=hostname] [--help]"
    if [ x$1 = x-h ]
        then
        echo "

--sender=email_address
    Email address of the person running the test. (Required)

--config=config_name
    Config type to use for lustre setup. Any of the standard script names
    from lustre/tests are allowable:
    lov, local, mount2lov, local-large-inode (default)

--test=test_script
    Name of the test script to run. Default is \"sanity.sh\".   

--target=hostname
    The machine (or uml session) on which to run the test. 
    Defaults to \"uml\"

--extra-params=extra_parameters
    Extra parameters to pass to the test script.
    e.g. --extra-params=\"START=' ' CLEAN=' '\"
    NOTE: NAME=lov should not be set here, use --config

--help
    Display this usage message

"
        exit 0
    else
        exit 1
    fi
}

check_mail() {
    if [ -z "$SENDER" ] ; then
	echo "Please supply a valid email address for --sender"
	usage
    fi
}

check_config() {
    if [ -z "$CONFIG_NAME" ] ; then
        echo "Using default config: local-large-inode"
        CONFIG_NAME="local-large-inode"
    fi
}

check_test() {
    if [ -z "$TESTSCRIPT" ] ; then
	echo "Running default test: sanity.sh"
	TESTSCRIPT="sanity.sh"
    fi
}


do_prepare() {
    if [ -e $LOG ] ; then
	rm -fr $LOG
    fi
    dmesg -c > /dev/null
    $DSH $TARGET "dmesg -c > /dev/null" || exit 1
    return 0
}

run_test() {
    $DSH $TARGET "cd $LUSTRE_SRC/tests && PATH=/sbin:/usr/sbin:\$PATH NAME=$CONFIG_NAME sh llmount.sh 2>&1" | dshbak -c >> $LOG
    if ! [ $? = 0 ] ; then
        echo "Can not mount lustre on remoute machine: $TARGET "
        exit 2
    fi
    if [ $NO_SHARED_FS ]; then
	$SCP $TARGET:$LUSTRE_SRC/tests/${CONFIG_NAME}.xml $PWD/config.xml
	if ! [ $? = 0 ] ; then
	    echo "Can not get the config file from remoute machine: $TARGET "
	    exit 3
	fi
    fi

    COMMAND="cd $LUSTRE_SRC/tests && NAME=$CONFIG_NAME PATH=/sbin:/usr/sbin:\$PATH $EXTRA_PARAMS sh $TESTSCRIPT"
    echo >> $LOG;echo "COMMAND: $COMMAND" >> $LOG;echo >> $LOG

    $DSH $TARGET "$COMMAND 2>&1" | dshbak -c >> $LOG
    return $?
}

do_eval() {
    RC=$1

    if [ $RC -eq 0 ]; then
	RESULT="pass"
    else
	RESULT="fail"
    fi

    if [ "$RESULT" = "fail" ] ; then   
	$DSH $TARGET "dmesg" | dshbak -c >> $DMESGLOG
    fi
}

send_report() {
    . $LTESTDIR/acceptance/harness/config/common/buffalo.sh

    if [ $NO_SHARED_FS ]; then
	CONFIG="$PWD/config.xml"
    else
	CONFIG="${LUSTRE_SRC}/tests/${CONFIG_NAME}.xml"
    fi    
    CONFIGDESC=${CONFIGDESC:-"${TARGET}-${CONFIG_NAME}"}	   

    ### send buffalo reports
    echo "Sending buffalo report..."
    rm -fr $OUTPUT
    buffalo_format_result > $OUTPUT
    buffalo_format_config $CONFIG >> $OUTPUT
    buffalo_format_log $LOG >> $OUTPUT
    buffalo_format_dmesg $DMESGLOG >> $OUTPUT
    buffalo_send_report $OUTPUT
    rm -f $OUTPUT
    rm -f $DMESGLOG
    rm -f $LOG
    echo "done."
}

do_cleanup() {
    $DSH $TARGET "cd $LUSTRE_SRC/tests && NAME=$CONFIG_NAME sh llmountcleanup.sh 2>&1" | dshbak -c >> $LOG
    if ! [ $? = 0  ] ; then
	echo "failed to clean up lustre"
    fi	 
}

options=`getopt -o h --long extra-params:,target:,sender:,config:,test:,help -- "$@"`

if [ $? -ne 0 ] ; then
    usage
fi
eval set -- "$options"
while true
  do
  case "$1" in
      --config)
          CONFIG_NAME=$2
          shift 2         ;;
      --sender)
	  SENDER=$2
	  shift 2         ;;
      --target)
	  TARGET=$2
	  shift 2         ;; 
      --extra-params)
	  EXTRA_PARAMS=$2
	  shift 2         ;;
      --test)
	  TESTSCRIPT=$2    
          shift 2         ;; 
      --help)
          usage -h        ;;
      -h)
          usage -h        ;;
      --)
          shift
          break           ;;
  esac
done

if [ ! -d ${LUSTRE_SRC} ]; then
    echo "LUSTRE_SRC dir $LUSTRE_SRC doesn't exist"
    exit 1
fi

if [ ! -d ${LTESTDIR} ]; then
    echo "LTESTDIR dir $LTESTDIR doesn't exist"
    exit 2
fi

# Gather some buffalo variable before we run the test.
export KERNEL=`$DSH $TARGET uname -r | sed "s/^.*\ //g"`
export LUSTRE_BUILD=`${LUSTRE_SRC}/utils/lctl lustre_build_version 2>/dev/null|grep "^lctl" | awk '/^lctl/ {print $3}'`

check_mail && check_config && check_test

do_prepare
run_test
do_eval $?
do_cleanup

send_report

exit 0    


