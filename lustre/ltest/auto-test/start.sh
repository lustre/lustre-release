#!/bin/sh

# You NEED to configure these settings for your site
TESTUSER=someusername
KERNEL_SRC=/usr/src/linux-2.4
LCONF_OPS="-v --reformat"
MOUNT="/p/gm1"
SENDER="someone@place.com"
SENDMAIL="sendmail -t -f$SENDER"
RECIPIENTS=$SENDER
#RECIPIENTS="$SENDER, buffalo_results@lustre.org"
MACHINENAME=`hostname | sed -e 's/[0-9]\+//'`
#---------------------------------------------------------
test_list=${1-testlist}
config_list="configlist"
tag_list="taglist"
[ -e $test_list ] || exit 18
[ -e $config_list ] || exit 19
[ -e $tag_list ] || exit 20
BASEDIR=`pwd`
[ -d $BASEDIR/tmp ] || mkdir $BASEDIR/tmp || exit 21
chown $TESTUSER:$TESTUSER $BASEDIR/tmp || exit 22

export LUSTRE_TAG PORTALS_TAG LUSTRE_CONFIG KERNEL_SRC BASEDIR
export MOUNT TESTUSER SENDMAIL SENDER RECIPIENTS MACHINENAME
export PATH=$PATH:$BASEDIR/bin

lookup_hostnames() {
    ROUTERS=`grep -e '^ROUTERS\s*=\s*' $BASEDIR/configs/$LUSTRE_CONFIG |\
             sed -e 's/^ROUTERS\s*=\s*//' | sed -e 's/#.*//' |\
             sed -e 's/\s*$//'`
    OSTS=`grep -e '^OSTS\s*=\s*' $BASEDIR/configs/$LUSTRE_CONFIG |\
          sed -e 's/^OSTS\s*=\s*//' | sed -e 's/#.*//' |\
          sed -e 's/\s*$//'`
    MDS=`grep -e '^MDS\s*=\s*' $BASEDIR/configs/$LUSTRE_CONFIG |\
         sed -e 's/^MDS\s*=\s*//' | sed -e 's/#.*//' |\
         sed -e 's/\s*$//'`
    CLIENTS=`grep -e '^CLIENTS\s*=\s*' $BASEDIR/configs/$LUSTRE_CONFIG |\
             sed -e 's/^CLIENTS\s*=\s*//' | sed -e 's/#.*//' |\
             sed -e 's/\s*$//'`
    SINGLECLIENT=`$BASEDIR/unglobhosts.py -n 1 $CLIENTS`
    export CLIENTS SINGLECLIENT

    SERVERS=""
    if [ $ROUTERS != "" ] ; then
        SERVERS="$ROUTERS,"
    fi
    if [ $OSTS != "" ] ; then
        SERVERS="$SERVERS$OSTS,"
    fi
    SERVERS="$SERVERS$MDS"

    ALLNODES="$SERVERS,$CLIENTS"

    CONFIGDESC=`grep -e '^CONFIGDESC\s*=\s*' $BASEDIR/configs/$LUSTRE_CONFIG |\
             sed -e 's/^CONFIGDESC\s*=\s*//' | sed -e 's/#.*//'`
    export CONFIGDESC
}

# Source the start_lustre() and reboot_cluster() functions
. ./reboot_cluster.sh
. ./start_lustre.sh

for tag in `cat $tag_list`; do
    export LUSTRE_TAG=$tag
    export PORTALS_TAG=$tag

    su -c $BASEDIR/get_and_build_lustre.sh $TESTUSER || exit 1
    for config in `cat $config_list`; do
	LUSTRE_CONFIG=$config
    
	lookup_hostnames
	reboot_cluster || exit 3
	start_lustre || exit 4

	for run in `cat $test_list`; do
	    if [ $? -ne 0 ] ; then
		reboot_cluster || exit 3
		start_lustre || exit 4
	    fi
	    echo "Running $run"
	    su $TESTUSER --command="$BASEDIR/tests/$run"
	done
	reboot_cluster || exit 3
    done
done
