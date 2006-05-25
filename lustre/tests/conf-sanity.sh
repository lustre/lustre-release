#!/bin/bash
# requirement:
#	add uml1 uml2 uml3 in your /etc/hosts

# FIXME - there is no reason to use all of these different
#   return codes, espcially when most of them are mapped to something
#   else anyway.  The combination of test number and return code
#   figure out what failed.

set -e

ONLY=${ONLY:-"$*"}

# These tests don't apply to mountconf
MOUNTCONFSKIP="9 10 11 12 13 13b 14 15 18"

# bug number for skipped test:
ALWAYS_EXCEPT=" $CONF_SANITY_EXCEPT $MOUNTCONFSKIP"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

LUSTRE=${LUSTRE:-`dirname $0`/..}
RLUSTRE=${RLUSTRE:-$LUSTRE}
MOUNTLUSTRE=${MOUNTLUSTRE:-/sbin/mount.lustre}
MKFSLUSTRE=${MKFSLUSTRE:-/usr/sbin/mkfs.lustre}
HOSTNAME=`hostname`

. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/local.sh}

reformat() {
        formatall
}

gen_config() {
        reformat
        # The MGS must be started before the OSTs for a new fs, so start
        # and stop to generate the startup logs. 
	start_mds
	start_ost
	sleep 5
	stop_ost
	stop_mds
}

start_mds() {
	echo "start mds service on `facet_active_host mds`"
	start mds $MDSDEV $MDS_MOUNT_OPTS || return 94
}

stop_mds() {
	echo "stop mds service on `facet_active_host mds`"
	# These tests all use non-failover stop
	stop mds -f  || return 97
}

start_ost() {
	echo "start ost1 service on `facet_active_host ost1`"
	start ost1 `ostdevname 1` $OST_MOUNT_OPTS || return 95
}

stop_ost() {
	echo "stop ost1 service on `facet_active_host ost1`"
	# These tests all use non-failover stop
	stop ost1 -f  || return 98
}

start_ost2() {
	echo "start ost2 service on `facet_active_host ost2`"
	start ost2 `ostdevname 2` $OST_MOUNT_OPTS || return 92
}

stop_ost2() {
	echo "stop ost2 service on `facet_active_host ost2`"
	# These tests all use non-failover stop
	stop ost2 -f  || return 93
}

mount_client() {
	local MOUNTPATH=$1
	echo "mount lustre on ${MOUNTPATH}....."
	zconf_mount `hostname` $MOUNTPATH  || return 96
}

umount_client() {
	local MOUNTPATH=$1
	echo "umount lustre on ${MOUNTPATH}....."
	zconf_umount `hostname` $MOUNTPATH || return 97
}

manual_umount_client(){
	echo "manual umount lustre on ${MOUNT}...."
	do_facet client "umount -d $MOUNT"
}

setup() {
	start_ost
	start_mds
	mount_client $MOUNT
}

cleanup_nocli() {
	stop_mds || return 201
	stop_ost || return 202
	unload_modules || return 203
}

cleanup() {
 	umount_client $MOUNT || return 200
	cleanup_nocli || return $?
}

check_mount() {
	do_facet client "cp /etc/passwd $DIR/a" || return 71
	do_facet client "rm $DIR/a" || return 72
	# make sure lustre is actually mounted (touch will block, 
        # but grep won't, so do it after) 
        do_facet client "grep $MOUNT' ' /proc/mounts > /dev/null" || return 73
	echo "setup single mount lustre success"
}

check_mount2() {
	do_facet client "touch $DIR/a" || return 71	
	do_facet client "rm $DIR/a" || return 72	
	do_facet client "touch $DIR2/a" || return 73	
	do_facet client "rm $DIR2/a" || return 74	
	echo "setup double mount lustre success"
}

build_test_filter

if [ "$ONLY" == "setup" ]; then
	setup
	exit
fi

if [ "$ONLY" == "cleanup" ]; then
	cleanup
	exit
fi

#create single point mountpoint

gen_config


test_0() {
        setup
	check_mount || return 41
	cleanup || return $?
}
run_test 0 "single mount setup"

test_1() {
	start_ost
	echo "start ost second time..."
	setup
	check_mount || return 42
	cleanup || return $?
}
run_test 1 "start up ost twice (should return errors)"

test_2() {
	start_ost
	start_mds	
	echo "start mds second time.."
	start_mds
	mount_client $MOUNT
	check_mount || return 43
	cleanup || return $?
}
run_test 2 "start up mds twice"

test_3() {
	setup
	#mount.lustre returns an error if already in mtab
	mount_client $MOUNT && return $?
	check_mount || return 44
	cleanup || return $?
}
run_test 3 "mount client twice"

test_4() {
	setup
	touch $DIR/$tfile || return 85
	stop_ost -f
	cleanup
	eno=$?
	# ok for ost to fail shutdown
	if [ 202 -ne $eno ]; then
		return $eno;
	fi
	return 0
}
run_test 4 "force cleanup ost, then cleanup"

test_5() {
	setup
	touch $DIR/$tfile || return 1
	stop_mds -f || return 2

	# cleanup may return an error from the failed
	# disconnects; for now I'll consider this successful
	# if all the modules have unloaded.
 	umount -d $MOUNT &
	UMOUNT_PID=$!
	sleep 6
	echo "killing umount"
	kill -TERM $UMOUNT_PID
	echo "waiting for umount to finish"
	wait $UMOUNT_PID
	if grep " $MOUNT " /etc/mtab; then
		echo "test 5: mtab after failed umount"
		umount $MOUNT &
		UMOUNT_PID=$!
		sleep 2
		echo "killing umount"
		kill -TERM $UMOUNT_PID
		echo "waiting for umount to finish"
		wait $UMOUNT_PID
		grep " $MOUNT " /etc/mtab && echo "test 5: mtab after second umount" && return 11
	fi

	manual_umount_client
	# stop_mds is a no-op here, and should not fail
	cleanup_nocli || return $?
	# df may have lingering entry
	manual_umount_client
	# mtab may have lingering entry
	grep -v $MOUNT" " /etc/mtab > $TMP/mtabtemp
	mv $TMP/mtabtemp /etc/mtab
}
run_test 5 "force cleanup mds, then cleanup"

test_5b() {
	start_ost
	[ -d $MOUNT ] || mkdir -p $MOUNT
	grep " $MOUNT " /etc/mtab && echo "test 5b: mtab before mount" && return 10
	mount_client $MOUNT && return 1
	grep " $MOUNT " /etc/mtab && echo "test 5b: mtab after failed mount" && return 11
	umount_client $MOUNT	
	# stop_mds is a no-op here, and should not fail
	cleanup_nocli || return $?
	return 0
}
run_test 5b "mds down, cleanup after failed mount (bug 2712)"

test_5c() {
	start_ost
	start_mds
	[ -d $MOUNT ] || mkdir -p $MOUNT
	grep " $MOUNT " /etc/mtab && echo "test 5c: mtab before mount" && return 10
	mount -t lustre `facet_nid mgs`:/wrong.$FSNAME $MOUNT || :
	grep " $MOUNT " /etc/mtab && echo "test 5c: mtab after failed mount" && return 11
	umount_client $MOUNT
	cleanup_nocli  || return $?
}
run_test 5c "cleanup after failed mount (bug 2712)"

test_5d() {
	start_ost
	start_mds
	stop_ost -f
	grep " $MOUNT " /etc/mtab && echo "test 5d: mtab before mount" && return 10
	mount_client $MOUNT || return 1
	cleanup  || return $?
	grep " $MOUNT " /etc/mtab && echo "test 5d: mtab after unmount" && return 11
	return 0
}
run_test 5d "mount with ost down"

test_5e() {
	start_ost
	start_mds
        # give MDS a chance to connect to OSTs (bz 10476)
	sleep 5	

#define OBD_FAIL_PTLRPC_DELAY_SEND       0x506
	do_facet client "sysctl -w lustre.fail_loc=0x80000506"
	grep " $MOUNT " /etc/mtab && echo "test 5e: mtab before mount" && return 10
	mount_client $MOUNT || echo "mount failed (not fatal)"
	cleanup  || return $?
	grep " $MOUNT " /etc/mtab && echo "test 5e: mtab after unmount" && return 11
	return 0
}
run_test 5e "delayed connect, don't crash (bug 10268)"

test_6() {
	setup
	manual_umount_client
	mount_client ${MOUNT} || return 87
	touch $DIR/a || return 86
	cleanup  || return $?
}
run_test 6 "manual umount, then mount again"

test_7() {
	setup
	manual_umount_client
	cleanup_nocli || return $?
}
run_test 7 "manual umount, then cleanup"

test_8() {
	setup
	mount_client $MOUNT2
	check_mount2 || return 45
	umount_client $MOUNT2
	cleanup  || return $?
}
run_test 8 "double mount setup"

test_9() {
        # backup the old values of PTLDEBUG and SUBSYSTEM
        OLDPTLDEBUG=$PTLDEBUG
        OLDSUBSYSTEM=$SUBSYSTEM

        # generate new configuration file with lmc --ptldebug and --subsystem
        PTLDEBUG="trace"
        SUBSYSTEM="mdc"
        gen_config

        # check the result of lmc --ptldebug/subsystem
        start_ost
        start_mds
        CHECK_PTLDEBUG="`do_facet mds sysctl lnet.debug|cut -d= -f2`"
        if [ "$CHECK_PTLDEBUG" ] && [ $CHECK_PTLDEBUG -eq 1 ]; then
           echo "lmc --debug success"
        else
           echo "lmc --debug: want 1, have $CHECK_PTLDEBUG"
           return 1
        fi
	# again with the pdsh prefix
        CHECK_SUBSYS="`do_facet mds sysctl lnet.subsystem_debug|cut -d= -f2`"
        if [ "$CHECK_SUBSYS" ] && [ $CHECK_SUBSYS -eq 2 ]; then
           echo "lmc --subsystem success"
        else
           echo "lmc --subsystem: want 2, have $CHECK_SUBSYS"
           return 1
        fi
        cleanup || return $?

        # the new PTLDEBUG/SUBSYSTEM used for lconf --ptldebug/subsystem
        PTLDEBUG="inode+trace"
        SUBSYSTEM="mds+ost"

        # check lconf --ptldebug/subsystem overriding lmc --ptldebug/subsystem
        start_ost
        start_mds
        CHECK_PTLDEBUG="`do_facet mds sysctl lnet.debug | cut -d= -f2`"
        if [ "$CHECK_PTLDEBUG" ] && [ $CHECK_PTLDEBUG -eq 3 ]; then
           echo "lconf --debug success"
        else
           echo "lconf --debug: want 3, have $CHECK_PTLDEBUG"
           return 1
        fi
        CHECK_SUBSYS="`do_facet mds sysctl lnet.subsystem_debug | cut -d= -f2`"
        if [ "$CHECK_SUBSYS" ] && [ $CHECK_SUBSYS -eq 20 ]; then
           echo "lconf --subsystem success"
        else
           echo "lconf --subsystem: want 20, have $CHECK_SUBSYS"
           return 1
        fi
        cleanup || return $?

        # resume the old configuration
        PTLDEBUG=$OLDPTLDEBUG
        SUBSYSTEM=$OLDSUBSYSTEM
        gen_config
}

run_test 9 "test --ptldebug and --subsystem for lmc and lconf"

test_10() {
        echo "generate configuration with the same name for node and mds"
        OLDXMLCONFIG=$XMLCONFIG
        XMLCONFIG="broken.xml"
        [ -f "$XMLCONFIG" ] && rm -f $XMLCONFIG
        facet="mds"
        rm -f ${facet}active
        add_facet $facet
        echo "the name for node and mds is the same"
        do_lmc --add mds --node ${facet}_facet --mds ${facet}_facet \
            --dev $MDSDEV --size $MDSSIZE || return $?
        do_lmc --add lov --mds ${facet}_facet --lov lov1 --stripe_sz \
            $STRIPE_BYTES --stripe_cnt $STRIPES_PER_OBJ \
            --stripe_pattern 0 || return $?
        add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE
        facet="client"
        add_facet $facet --lustre_upcall $UPCALL
        do_lmc --add mtpt --node ${facet}_facet --mds mds_facet \
            --lov lov1 --path $MOUNT

        echo "mount lustre"
        start_ost
        start_mds
        mount_client $MOUNT
        check_mount || return 41
        cleanup || return $?

        echo "Success!"
        XMLCONFIG=$OLDXMLCONFIG
}
run_test 10 "mount lustre with the same name for node and mds"

test_11() {
        OLDXMLCONFIG=$XMLCONFIG
        XMLCONFIG="conf11.xml"

        [ -f "$XMLCONFIG" ] && rm -f $XMLCONFIG
        add_mds mds --dev $MDSDEV --size $MDSSIZE
        add_ost ost --dev $OSTDEV --size $OSTSIZE
        add_client client mds --path $MOUNT --ost ost_svc || return $?
        echo "Default lov config success!"

        [ -f "$XMLCONFIG" ] && rm -f $XMLCONFIG
        add_mds mds --dev $MDSDEV --size $MDSSIZE
        add_ost ost --dev $OSTDEV --size $OSTSIZE
        add_client client mds --path $MOUNT && return $?
        echo "--add mtpt with neither --lov nor --ost will return error"

        echo ""
        echo "Success!"
        XMLCONFIG=$OLDXMLCONFIG
}
run_test 11 "use default lov configuration (should return error)"

test_12() {
        OLDXMLCONFIG=$XMLCONFIG
        XMLCONFIG="batch.xml"
        BATCHFILE="batchfile"

        # test double quote
        [ -f "$XMLCONFIG" ] && rm -f $XMLCONFIG
        [ -f "$BATCHFILE" ] && rm -f $BATCHFILE
        echo "--add net --node $HOSTNAME --nid $HOSTNAME --nettype tcp" > $BATCHFILE
        echo "--add mds --node $HOSTNAME --mds mds1 --mkfsoptions \"-I 128\"" >> $BATCHFILE
        # --mkfsoptions "-I 128"
        do_lmc -m $XMLCONFIG --batch $BATCHFILE || return $?
        if [ `sed -n '/>-I 128</p' $XMLCONFIG | wc -l` -eq 1 ]; then
                echo "matched double quote success"
        else
                echo "matched double quote fail"
                return 1
        fi
        rm -f $XMLCONFIG
        rm -f $BATCHFILE
        echo "--add net --node $HOSTNAME --nid $HOSTNAME --nettype tcp" > $BATCHFILE
        echo "--add mds --node $HOSTNAME --mds mds1 --mkfsoptions \"-I 128" >> $BATCHFILE
        # --mkfsoptions "-I 128
        do_lmc -m $XMLCONFIG --batch $BATCHFILE && return $?
        echo "unmatched double quote should return error"

        # test single quote
        rm -f $BATCHFILE
        echo "--add net --node $HOSTNAME --nid $HOSTNAME --nettype tcp" > $BATCHFILE
        echo "--add mds --node $HOSTNAME --mds mds1 --mkfsoptions '-I 128'" >> $BATCHFILE
        # --mkfsoptions '-I 128'
        do_lmc -m $XMLCONFIG --batch $BATCHFILE || return $?
        if [ `sed -n '/>-I 128</p' $XMLCONFIG | wc -l` -eq 1 ]; then
                echo "matched single quote success"
        else
                echo "matched single quote fail"
                return 1
        fi
        rm -f $XMLCONFIG
        rm -f $BATCHFILE
        echo "--add net --node $HOSTNAME --nid $HOSTNAME --nettype tcp" > $BATCHFILE
        echo "--add mds --node $HOSTNAME --mds mds1 --mkfsoptions '-I 128" >> $BATCHFILE
        # --mkfsoptions '-I 128
        do_lmc -m $XMLCONFIG --batch $BATCHFILE && return $?
        echo "unmatched single quote should return error"

        # test backslash
        rm -f $BATCHFILE
        echo "--add net --node $HOSTNAME --nid $HOSTNAME --nettype tcp" > $BATCHFILE
        echo "--add mds --node $HOSTNAME --mds mds1 --mkfsoptions \-\I\ \128" >> $BATCHFILE
        # --mkfsoptions \-\I\ \128
        do_lmc -m $XMLCONFIG --batch $BATCHFILE || return $?
        if [ `sed -n '/>-I 128</p' $XMLCONFIG | wc -l` -eq 1 ]; then
                echo "backslash followed by a whitespace/letter success"
        else
                echo "backslash followed by a whitespace/letter fail"
                return 1
        fi
        rm -f $XMLCONFIG
        rm -f $BATCHFILE
        echo "--add net --node $HOSTNAME --nid $HOSTNAME --nettype tcp" > $BATCHFILE
        echo "--add mds --node $HOSTNAME --mds mds1 --mkfsoptions -I\ 128\\" >> $BATCHFILE
        # --mkfsoptions -I\ 128\
        do_lmc -m $XMLCONFIG --batch $BATCHFILE && return $?
        echo "backslash followed by nothing should return error"

        rm -f $BATCHFILE
        XMLCONFIG=$OLDXMLCONFIG
}
run_test 12 "lmc --batch, with single/double quote, backslash in batchfile"

test_13() {
        OLDXMLCONFIG=$XMLCONFIG
        XMLCONFIG="conf13-1.xml"

        # check long uuid will be truncated properly and uniquely
        echo "To generate XML configuration file(with long ost name): $XMLCONFIG"
        [ -f "$XMLCONFIG" ] && rm -f $XMLCONFIG
        do_lmc --add net --node $HOSTNAME --nid $HOSTNAME --nettype tcp
        do_lmc --add mds --node $HOSTNAME --mds mds1_name_longer_than_31characters
        do_lmc --add mds --node $HOSTNAME --mds mds2_name_longer_than_31characters
        if [ ! -f "$XMLCONFIG" ]; then
                echo "Error:no file $XMLCONFIG created!"
                return 1
        fi
        EXPECTEDMDS1UUID="e_longer_than_31characters_UUID"
        EXPECTEDMDS2UUID="longer_than_31characters_UUID_2"
        FOUNDMDS1UUID=`awk -F"'" '/<mds .*uuid=/' $XMLCONFIG | sed -n '1p' \
                       | sed "s/ /\n\r/g" | awk -F"'" '/uuid=/{print $2}'`
        FOUNDMDS2UUID=`awk -F"'" '/<mds .*uuid=/' $XMLCONFIG | sed -n '2p' \
                       | sed "s/ /\n\r/g" | awk -F"'" '/uuid=/{print $2}'`
	[ -z "$FOUNDMDS1UUID" ] && echo "MDS1 UUID empty" && return 1
	[ -z "$FOUNDMDS2UUID" ] && echo "MDS2 UUID empty" && return 1
        if ([ $EXPECTEDMDS1UUID = $FOUNDMDS1UUID ] && [ $EXPECTEDMDS2UUID = $FOUNDMDS2UUID ]) || \
           ([ $EXPECTEDMDS1UUID = $FOUNDMDS2UUID ] && [ $EXPECTEDMDS2UUID = $FOUNDMDS1UUID ]); then
                echo "Success:long uuid truncated successfully and being unique."
        else
                echo "Error:expected uuid for mds1 and mds2: $EXPECTEDMDS1UUID; $EXPECTEDMDS2UUID"
                echo "but:     found uuid for mds1 and mds2: $FOUNDMDS1UUID; $FOUNDMDS2UUID"
                return 1
        fi
        rm -f $XMLCONFIG
        XMLCONFIG=$OLDXMLCONFIG
}
run_test 13 "check new_uuid of lmc operating correctly"

test_13b() {
        OLDXMLCONFIG=$XMLCONFIG
        XMLCONFIG="conf13-1.xml"
        SECONDXMLCONFIG="conf13-2.xml"
        # check multiple invocations for lmc generate same XML configuration file
        rm -f $XMLCONFIG
        echo "Generate the first XML configuration file"
        gen_config
        echo "mv $XMLCONFIG to $SECONDXMLCONFIG"
        sed -e "s/mtime[^ ]*//" $XMLCONFIG > $SECONDXMLCONFIG || return $?
        echo "Generate the second XML configuration file"
        gen_config
	# don't compare .xml mtime, it will always be different
        if [ `sed -e "s/mtime[^ ]*//" $XMLCONFIG | diff - $SECONDXMLCONFIG | wc -l` -eq 0 ]; then
                echo "Success:multiple invocations for lmc generate same XML file"
        else
                echo "Error: multiple invocations for lmc generate different XML file"
                return 1
        fi

        rm -f $XMLCONFIG $SECONDXMLCONFIG
        XMLCONFIG=$OLDXMLCONFIG
}
run_test 13b "check lmc generates consistent .xml file"

test_14() {
        rm -f $XMLCONFIG

        # create xml file with --mkfsoptions for ost
        echo "create xml file with --mkfsoptions for ost"
        add_mds mds --dev $MDSDEV --size $MDSSIZE
        add_lov lov1 mds --stripe_sz $STRIPE_BYTES\
            --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
        add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE \
            --mkfsoptions "-Llabel_conf_14"
        add_client client mds --lov lov1 --path $MOUNT

        FOUNDSTRING=`awk -F"<" '/<mkfsoptions>/{print $2}' $XMLCONFIG`
        EXPECTEDSTRING="mkfsoptions>-Llabel_conf_14"
        if [ "$EXPECTEDSTRING" != "$FOUNDSTRING" ]; then
                echo "Error: expected: $EXPECTEDSTRING; found: $FOUNDSTRING"
                return 1
        fi
        echo "Success:mkfsoptions for ost written to xml file correctly."

        # mount lustre to test lconf mkfsoptions-parsing
        echo "mount lustre"
        start_ost
        start_mds
        mount_client $MOUNT || return $?
        if [ -z "`do_facet ost1 dumpe2fs -h $OSTDEV | grep label_conf_14`" ]; then
                echo "Error: the mkoptions not applied to mke2fs of ost."
                return 1
        fi
        cleanup
        echo "lconf mkfsoptions for ost success"

        gen_config
}
run_test 14 "test mkfsoptions of ost for lmc and lconf"

cleanup_15() {
	trap 0
	[ -f $MOUNTLUSTRE ] && echo "remove $MOUNTLUSTRE" && rm -f $MOUNTLUSTRE
	if [ -f $MOUNTLUSTRE.sav ]; then
		echo "return original $MOUNTLUSTRE.sav to $MOUNTLUSTRE"
		mv $MOUNTLUSTRE.sav $MOUNTLUSTRE
	fi
}

test_15() {
	echo "mount lustre on ${MOUNT} with $MOUNTLUSTRE....."
	if [ -f "$MOUNTLUSTRE" ]; then
		echo "save $MOUNTLUSTRE to $MOUNTLUSTRE.sav"
		mv $MOUNTLUSTRE $MOUNTLUSTRE.sav && trap cleanup_15 EXIT INT
		if [ -f $MOUNTLUSTRE ]; then
			echo "$MOUNTLUSTRE cannot be moved, skipping test"
			return 0
		fi
	fi
	[ ! `cp $(which llmount) $MOUNTLUSTRE` ] || return $?
	start_ost
	start_mds
	do_facet client "mkdir -p $MOUNT 2> /dev/null"
	# load llite module on the client if it isn't in /lib/modules
	do_facet client "$LCONF --nosetup --node client_facet $XMLCONFIG"
	do_facet client "mount -t lustre -o $MOUNTOPT \
		`facet_nid mds`:/mds_svc/client_facet $MOUNT" ||return $?
	echo "mount lustre on $MOUNT with $MOUNTLUSTRE: success"
	[ -d /r ] && $LCTL modules > /r/tmp/ogdb-`hostname`
	check_mount || return 41
	do_node `hostname` umount -d $MOUNT

	[ -f "$MOUNTLUSTRE" ] && rm -f $MOUNTLUSTRE
	echo "mount lustre on ${MOUNT} without $MOUNTLUSTRE....."
	do_node `hostname` mount -t lustre -o nettype=$NETTYPE,$MOUNTOPT \
		`facet_nid mds`:/mds_svc/client_facet $MOUNT &&return $?
	echo "mount lustre on $MOUNT without $MOUNTLUSTRE failed as expected"
	cleanup || return $?
	cleanup_15
}
run_test 15 "zconf-mount without /sbin/mount.lustre (should return error)"

test_16() {
        TMPMTPT="${MOUNT%/*}/conf16"

        if [ ! -f "$MDSDEV" ]; then
            echo "no $MDSDEV existing, so mount Lustre to create one"
	    setup
            check_mount || return 41
            cleanup || return $?
        fi

        echo "change the mode of $MDSDEV/OBJECTS,LOGS,PENDING to 555"
        do_facet mds "[ -d $TMPMTPT ] || mkdir -p $TMPMTPT;
                      mount -o loop -t ext3 $MDSDEV $TMPMTPT || return \$?;
                      chmod 555 $TMPMTPT/{OBJECTS,LOGS,PENDING} || return \$?;
                      umount -d $TMPMTPT || return \$?" || return $?

        echo "mount Lustre to change the mode of OBJECTS/LOGS/PENDING, then umount Lustre"
	setup
        check_mount || return 41
        cleanup || return $?

        echo "read the mode of OBJECTS/LOGS/PENDING and check if they has been changed properly"
        EXPECTEDOBJECTSMODE=`do_facet mds "debugfs -R 'stat OBJECTS' $MDSDEV 2> /dev/null" | grep 'Mode: ' | sed -e "s/.*Mode: *//" -e "s/ *Flags:.*//"`
        EXPECTEDLOGSMODE=`do_facet mds "debugfs -R 'stat LOGS' $MDSDEV 2> /dev/null" | grep 'Mode: ' | sed -e "s/.*Mode: *//" -e "s/ *Flags:.*//"`
        EXPECTEDPENDINGMODE=`do_facet mds "debugfs -R 'stat PENDING' $MDSDEV 2> /dev/null" | grep 'Mode: ' | sed -e "s/.*Mode: *//" -e "s/ *Flags:.*//"`

        if [ "$EXPECTEDOBJECTSMODE" = "0777" ]; then
                echo "Success:Lustre change the mode of OBJECTS correctly"
        else
                echo "Error: Lustre does not change mode of OBJECTS properly"
                return 1
        fi

        if [ "$EXPECTEDLOGSMODE" = "0777" ]; then
                echo "Success:Lustre change the mode of LOGS correctly"
        else
                echo "Error: Lustre does not change mode of LOGS properly"
                return 1
        fi

        if [ "$EXPECTEDPENDINGMODE" = "0777" ]; then
                echo "Success:Lustre change the mode of PENDING correctly"
        else
                echo "Error: Lustre does not change mode of PENDING properly"
                return 1
        fi
}
run_test 16 "verify that lustre will correct the mode of OBJECTS/LOGS/PENDING"

test_17() {
        if [ ! -f "$MDSDEV" ]; then
            echo "no $MDSDEV existing, so mount Lustre to create one"
	    setup
            check_mount || return 41
            cleanup || return $?
        fi

        echo "Remove mds config log"
        do_facet mds "debugfs -w -R 'unlink CONFIGS/$FSNAME-MDT0000' $MDSDEV || return \$?" || return $?

        start_ost
	start_mds && return 42
	gen_config
}
run_test 17 "Verify failed mds_postsetup won't fail assertion (2936) (should return errs)"

test_18() {
        [ -f $MDSDEV ] && echo "remove $MDSDEV" && rm -f $MDSDEV
        echo "mount mds with large journal..."
        OLDMDSSIZE=$MDSSIZE
        MDSSIZE=2000000
	#FIXME have to change MDS_MKFS_OPTS
        gen_config

        echo "mount lustre system..."
	setup
        check_mount || return 41

        echo "check journal size..."
        FOUNDJOURNALSIZE=`do_facet mds "debugfs -R 'stat <8>' $MDSDEV" | awk '/Size: / { print $NF; exit;}'`
        if [ "$FOUNDJOURNALSIZE" = "79691776" ]; then
                echo "Success:lconf creates large journals"
        else
                echo "Error:lconf not create large journals correctly"
                echo "expected journal size: 79691776(76M), found journal size: $FOUNDJOURNALSIZE"
                return 1
        fi

        cleanup || return $?

        MDSSIZE=$OLDMDSSIZE
        gen_config
}
run_test 18 "check lconf creates large journals"

test_19a() {
	start_mds || return 1
	stop_mds -f || return 2
}
run_test 19a "start/stop MDS without OSTs"

test_19b() {
	start_ost || return 1
	stop_ost -f || return 2
}
run_test 19b "start/stop OSTs without MDS"

test_20a() {
        start_mds
	start_ost
	stop_ost
	stop_mds
}
run_test 20a "start mds before ost, stop ost first"

test_20b() {
        start_ost
	start_mds
	stop_mds
	stop_ost
}
run_test 20b "start ost before mds, stop mds first"

test_20c() {
        start_ost
	start_mds
	start_ost2
	stop_ost
	stop_ost2
	stop_mds
}
run_test 20c "start mds between two osts, stop mds last"

test_21() {
        reformat
	start_mds
	echo Client mount before any osts are in the logs
	mount_client $MOUNT
	check_mount && return 41
	pass

	echo Client mount with ost in logs, but none running
	start_ost
	stop_ost
	mount_client $MOUNT
	# check_mount will block trying to contact ost
	umount_client $MOUNT
	pass

	echo Client mount with a running ost
	start_ost
	mount_client $MOUNT
	sleep 5	#bz10476
	check_mount || return 41
	pass

	cleanup
}
run_test 21 "start a client before osts (should return errs)"

test_22() {
        echo this test is not working yet
	return 0
        setup
        # failover mds
	stop mds   
	# force client so that recovering mds waits
	zconf_umount `hostname` $MOUNT -f
	# enter recovery on mds
	start_mds
	mount_client $MOUNT &
	local mount_pid=$?
	sleep 5
	local mount_lustre_pid=`ps -ef | grep mount.lustre | grep -v grep | awk '{print $2}'`
	ps -ef | grep mount
	echo mount pid is ${mount_pid}, mount.lustre pid is ${mount_lustre_pid}
	# why o why can't I kill these? Manual "ctrl-c" works...
	kill -2 ${mount_pid}
	ps -ef | grep mount
	kill -2 ${mount_lustre_pid}
	ps -ef | grep mount
	sleep 5
	exit 1 # the mount process is still running??
	stop_mds
	stop_ost
}
run_test 22 "interrupt client during recovery mount delay"


umount_client $MOUNT	
cleanup_nocli

equals_msg "Done"
