#!/bin/bash
# requirement:
#	add uml1 uml2 uml3 in your /etc/hosts

# FIXME - there is no reason to use all of these different
#   return codes, espcially when most of them are mapped to something
#   else anyway.  The combination of test number and return code
#   figure out what failed.

set -e

SRCDIR=`dirname $0`
PATH=$PWD/$SRCDIR:$SRCDIR:$SRCDIR/../utils:$PATH

LUSTRE=${LUSTRE:-`dirname $0`/..}
RLUSTRE=${RLUSTRE:-$LUSTRE}
MOUNTLUSTRE=${MOUNTLUSTRE:-/sbin/mount.lustre}

. $LUSTRE/tests/test-framework.sh

init_test_env $@

. ${CONFIG:=$LUSTRE/tests/cfg/local.sh}

gen_config() {
	rm -f $XMLCONFIG

	add_mds mds --dev $MDSDEV --size $MDSSIZE
	add_lov lov1 mds --stripe_sz $STRIPE_BYTES\
	    --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
	add_ost ost --lov lov1 --dev $OSTDEV --size $OSTSIZE
	add_client client mds --lov lov1 --path $MOUNT
}

gen_second_config() {
	rm -f $XMLCONFIG

	add_mds mds2 --dev $MDSDEV --size $MDSSIZE
	add_lov lov2 mds2 --stripe_sz $STRIPE_BYTES\
	    --stripe_cnt $STRIPES_PER_OBJ --stripe_pattern 0
	add_ost ost2 --lov lov2 --dev $OSTDEV --size $OSTSIZE
	add_client client mds2 --lov lov2 --path $MOUNT2
}

start_mds() {
	echo "start mds service on `facet_active_host mds`"
	start mds --reformat $MDSLCONFARGS  || return 94
}
stop_mds() {
	echo "stop mds service on `facet_active_host mds`"
	stop mds $@  || return 97
}

start_ost() {
	echo "start ost service on `facet_active_host ost`"
	start ost --reformat $OSTLCONFARGS  || return 95
}

stop_ost() {
	echo "stop ost service on `facet_active_host ost`"
	stop ost $@  || return 98
}

mount_client() {
	local MOUNTPATH=$1
	echo "mount lustre on ${MOUNTPATH}....."
	zconf_mount `hostname`  $MOUNTPATH  || return 96
}

umount_client() {
	local MOUNTPATH=$1
	echo "umount lustre on ${MOUNTPATH}....."
	zconf_umount `hostname`  $MOUNTPATH || return 97
}

manual_umount_client(){
	echo "manual umount lustre on ${MOUNTPATH}...."
	do_facet  client "umount $MOUNT"
}

setup() {
	start_ost
	start_mds
	mount_client $MOUNT
}

cleanup() {
 	umount_client $MOUNT || return 200
	stop_mds  || return 201
	stop_ost || return 202
	# catch case where these return just fine, but modules are still not unloaded
	/sbin/lsmod | grep -q portals
	if [ 1 -ne $? ]; then
		echo "modules still loaded..."
		return 203
	fi
}

check_mount() {
	do_facet client "touch $DIR/a" || return 71	
	do_facet client "rm $DIR/a" || return 72	
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

#create single point mountpoint

gen_config


test_0() {
	start_ost
	start_mds	
	mount_client $MOUNT
	check_mount || return 41
	cleanup || return $?
}
run_test 0 "single mount setup"

test_1() {
	start_ost
	echo "start ost second time..."
	start ost --reformat $OSTLCONFARGS
	start_mds	
	mount_client $MOUNT
	check_mount || return 42
	cleanup || return $?
}
run_test 1 "start up ost twice"

test_2() {
	start_ost
	start_mds	
	echo "start mds second time.."
	start mds --reformat $MDSLCONFARGS
	
	mount_client $MOUNT
	check_mount || return 43
	cleanup || return $?
}
run_test 2 "start up mds twice"

test_3() {
	setup
	mount_client $MOUNT

	check_mount || return 44
	
 	umount_client $MOUNT 	
	cleanup  || return $?
}
run_test 3 "mount client twice"

test_4() {
	setup
	touch $DIR/$tfile || return 85
	stop_ost --force
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
	stop_mds --force || return 2

	# cleanup may return an error from the failed
	# disconnects; for now I'll consider this successful
	# if all the modules have unloaded.
 	umount $MOUNT &
	UMOUNT_PID=$!
	sleep 2
	echo "killing umount"
	kill -TERM $UMOUNT_PID
	echo "waiting for umount to finish"
	wait $UMOUNT_PID

	# cleanup client modules
	$LCONF --cleanup --nosetup --node client_facet $XMLCONFIG > /dev/null
	
	# stop_mds is a no-op here, and should not fail
	stop_mds  || return 4
	stop_ost || return 5

	lsmod | grep -q portals && return 6
	return 0
}
run_test 5 "force cleanup mds, then cleanup"

test_5b() {
	start_ost
	start_mds
	stop_mds

	[ -d $MOUNT ] || mkdir -p $MOUNT
	$LCONF --nosetup --node client_facet $XMLCONFIG > /dev/null
	llmount $mds_HOST://mds_svc/client_facet $MOUNT  && exit 1

	# cleanup client modules
	$LCONF --cleanup --nosetup --node client_facet $XMLCONFIG > /dev/null
	
	# stop_mds is a no-op here, and should not fail
	stop_mds || return 2
	stop_ost || return 3

	lsmod | grep -q portals && return 3
	return 0

}
run_test 5b "mds down, cleanup after failed mount (bug 2712)"

test_5c() {
	start_ost
	start_mds

	[ -d $MOUNT ] || mkdir -p $MOUNT
	$LCONF --nosetup --node client_facet $XMLCONFIG > /dev/null
	llmount $mds_HOST://wrong_mds_svc/client_facet $MOUNT  && exit 1

	# cleanup client modules
	$LCONF --cleanup --nosetup --node client_facet $XMLCONFIG > /dev/null
	
	stop_mds || return 2
	stop_ost || return 3

	lsmod | grep -q portals && return 3
	return 0

}
run_test 5c "cleanup after failed mount (bug 2712)"

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
	cleanup || return $?
}
run_test 7 "manual umount, then cleanup"

test_8() {
	start_ost
	start_mds

	mount_client $MOUNT
	mount_client $MOUNT2

	check_mount2 || return 45
	umount $MOUNT
	umount_client $MOUNT2
	
	stop_mds
	stop_ost
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
        mount_client $MOUNT
        CHECK_PTLDEBUG="`cat /proc/sys/portals/debug`"
        if [ $CHECK_PTLDEBUG = "1" ]; then
           echo "lmc --debug success"
        else
           echo "lmc --debug: want 1, have $CHECK_PTLDEBUG"
           return 1
        fi
        CHECK_SUBSYSTEM="`cat /proc/sys/portals/subsystem_debug`"
        if [ $CHECK_SUBSYSTEM = "2" ]; then
           echo "lmc --subsystem success"
        else
           echo "lmc --subsystem: want 2, have $CHECK_SUBSYSTEM"
           return 1
        fi
        check_mount || return 41
        cleanup || return $?

        # the new PTLDEBUG/SUBSYSTEM used for lconf --ptldebug/subsystem
        PTLDEBUG="inode+trace"
        SUBSYSTEM="mds+ost"

        # check lconf --ptldebug/subsystem overriding lmc --ptldebug/subsystem
        start_ost
        start_mds
        CHECK_PTLDEBUG="`do_facet mds cat /proc/sys/portals/debug`"
        if [ $CHECK_PTLDEBUG = "3" ]; then
           echo "lconf --debug success"
        else
           echo "lconf --debug: want 3, have $CHECK_PTLDEBUG"
           return 1
        fi
        CHECK_SUBSYSTEM="`do_facet mds cat /proc/sys/portals/subsystem_debug`"
        if [ $CHECK_SUBSYSTEM = "20" ]; then
           echo "lconf --subsystem success"
        else
           echo "lconf --subsystem: want 20, have $CHECK_SUBSYSTEM"
           return 1
        fi
        mount_client $MOUNT
        check_mount || return 41
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
        echo "--add net --node  localhost --nid localhost.localdomain --nettype tcp" > $BATCHFILE
        echo "--add mds --node localhost --mds mds1 --mkfsoptions \"-I 128\"" >> $BATCHFILE
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
        echo "--add net --node  localhost --nid localhost.localdomain --nettype tcp" > $BATCHFILE
        echo "--add mds --node localhost --mds mds1 --mkfsoptions \"-I 128" >> $BATCHFILE
        # --mkfsoptions "-I 128
        do_lmc -m $XMLCONFIG --batch $BATCHFILE && return $?
        echo "unmatched double quote should return error"

        # test single quote
        rm -f $BATCHFILE
        echo "--add net --node  localhost --nid localhost.localdomain --nettype tcp" > $BATCHFILE
        echo "--add mds --node localhost --mds mds1 --mkfsoptions '-I 128'" >> $BATCHFILE
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
        echo "--add net --node  localhost --nid localhost.localdomain --nettype tcp" > $BATCHFILE
        echo "--add mds --node localhost --mds mds1 --mkfsoptions '-I 128" >> $BATCHFILE
        # --mkfsoptions '-I 128
        do_lmc -m $XMLCONFIG --batch $BATCHFILE && return $?
        echo "unmatched single quote should return error"

        # test backslash
        rm -f $BATCHFILE
        echo "--add net --node  localhost --nid localhost.localdomain --nettype tcp" > $BATCHFILE
        echo "--add mds --node localhost --mds mds1 --mkfsoptions \-\I\ \128" >> $BATCHFILE
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
        echo "--add net --node  localhost --nid localhost.localdomain --nettype tcp" > $BATCHFILE
        echo "--add mds --node localhost --mds mds1 --mkfsoptions -I\ 128\\" >> $BATCHFILE
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
        SECONDXMLCONFIG="conf13-2.xml"

        # check long uuid will be truncated properly and uniquely
        echo "To generate XML configuration file(with long ost name): $XMLCONFIG"
        [ -f "$XMLCONFIG" ] && rm -f $XMLCONFIG
        do_lmc --add net --node localhost --nid localhost.localdomain --nettype tcp
        do_lmc --add mds --node localhost --mds mds1_name_longer_than_31characters
        do_lmc --add mds --node localhost --mds mds2_name_longer_than_31characters
        if [ ! -f "$XMLCONFIG" ]; then
                echo "Error:no file $XMLCONFIG created!"
                return 1
        fi
        EXPECTEDMDS1UUID="e_longer_than_31characters_UUID"
        EXPECTEDMDS2UUID="longer_than_31characters_UUID_2"
        FOUNDMDS1UUID=`awk -F"'" '/<mds uuid=/{print $2}' $XMLCONFIG | sed -n '1p'`
        FOUNDMDS2UUID=`awk -F"'" '/<mds uuid=/{print $2}' $XMLCONFIG | sed -n '2p'`
        if [ $EXPECTEDMDS1UUID != $FOUNDMDS1UUID ]; then
                echo "Error:expected uuid for mds1: $EXPECTEDMDS1UUID; found: $FOUNDMDS1UUID"
                return 1
        fi
        if [ $EXPECTEDMDS2UUID != $FOUNDMDS2UUID ]; then
                echo "Error:expected uuid for mds2: $EXPECTEDMDS2UUID; found: $FOUNDMDS2UUID"
                return 1
        fi
        echo "Success:long uuid truncated successfully and being unique."

        # check multiple invocations for lmc generate same XML configuration file
        rm -f $XMLCONFIG
        echo "Generate the first XML configuration file"
        gen_config
        echo "mv $XMLCONFIG to $SECONDXMLCONFIG"
        mv $XMLCONFIG $SECONDXMLCONFIG || return $?
        echo "Generate the second XML configuration file"
        gen_config
        if [ `diff $XMLCONFIG $SECONDXMLCONFIG | wc -l` -eq 0 ]; then
                echo "Success:multiple invocations for lmc generate same XML file"
        else
                echo "Error: multiple invocations for lmc generate different XML file"
                return 1
        fi

        rm -f $XMLCONFIG
        rm -f $SECONDXMLCONFIG
        XMLCONFIG=$OLDXMLCONFIG
}
run_test 13 "check new_uuid of lmc operating correctly"

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
        if [ $EXPECTEDSTRING != $FOUNDSTRING ]; then
                echo "Error: expected: $EXPECTEDSTRING; found: $FOUNDSTRING"
                return 1
        fi
        echo "Success:mkfsoptions for ost written to xml file correctly."

        # mount lustre to test lconf mkfsoptions-parsing
        echo "mount lustre"
        start_ost
        start_mds
        mount_client $MOUNT || return $?
        if [ -z "`dumpe2fs -h $OSTDEV | grep label_conf_14`" ]; then
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
	start_ost
	start_mds
	echo "mount lustre on ${MOUNT} with $MOUNTLUSTRE....."
	if [ -f "$MOUNTLUSTRE" ]; then
		echo "save $MOUNTLUSTRE to $MOUNTLUSTRE.sav"
		mv $MOUNTLUSTRE $MOUNTLUSTRE.sav
	fi
	[ -f "$MOUNTLUSTRE" ] && echo "can't move $MOUNTLUSTRE" && return 40
	trap cleanup_15 EXIT INT
	[ ! `cp $LUSTRE/utils/llmount $MOUNTLUSTRE` ] || return $?
	do_node `hostname` mkdir -p $MOUNT 2> /dev/null
	# load llite module on the client if it isn't in /lib/modules
	do_node `hostname` lconf --nosetup --node client_facet $XMLCONFIG
	do_node `hostname` mount -t lustre -o nettype=$NETTYPE \
		`facet_active_host mds`:/mds_svc/client_facet $MOUNT ||return $?
	echo "mount lustre on $MOUNT with $MOUNTLUSTRE: success"
	[ -d /r ] && $LCTL modules > /r/tmp/ogdb-`hostname`
	check_mount || return 41
	do_node `hostname` umount $MOUNT

	[ -f "$MOUNTLUSTRE" ] && rm -f $MOUNTLUSTRE
	echo "mount lustre on ${MOUNT} without $MOUNTLUSTRE....."
	do_node `hostname` mount -t lustre -o nettype=$NETTYPE \
		`facet_active_host mds`:/mds_svc/client_facet $MOUNT &&return $?
	echo "mount lustre on $MOUNT without $MOUNTLUSTRE failed as expected"
	cleanup || return $?
	cleanup_15
}
run_test 15 "zconf-mount without /sbin/mount.lustre (should return error)"

test_16() {
        TMPMTPT="/mnt/conf16"
                                                                                                                             
        if [ ! -f "$MDSDEV" ]; then
            echo "no $MDSDEV existing, so mount Lustre to create one"
            start_ost
            start_mds
            mount_client $MOUNT
            check_mount || return 41
            cleanup || return $?
         fi
                                                                                                                             
        echo "change the mode of $MDSDEV/OBJECTS,LOGS,PENDING to 555"
        [ -d $TMPMTPT ] || mkdir -p $TMPMTPT
        mount -o loop -t ext3 $MDSDEV $TMPMTPT || return $?
        chmod 555 $TMPMTPT/OBJECTS || return $?
        chmod 555 $TMPMTPT/LOGS || return $?
        chmod 555 $TMPMTPT/PENDING || return $?
        umount $TMPMTPT || return $?
                                                                                                                             
        echo "mount Lustre to change the mode of OBJECTS/LOGS/PENDING, then umount Lustre"
        start_ost
        start_mds
        mount_client $MOUNT
        check_mount || return 41
        cleanup || return $?
                                                                                                                             
        echo "read the mode of OBJECTS/LOGS/PENDING and check if they has been changed properly"
        EXPECTEDOBJECTSMODE=`debugfs -R "stat OBJECTS" $MDSDEV 2> /dev/null | awk '/Mode: /{print $6}'`
        EXPECTEDLOGSMODE=`debugfs -R "stat LOGS" $MDSDEV 2> /dev/null | awk '/Mode: /{print $6}'`
        EXPECTEDPENDINGMODE=`debugfs -R "stat PENDING" $MDSDEV 2> /dev/null | awk '/Mode: /{print $6}'`

        if [ $EXPECTEDOBJECTSMODE = "0777" ]; then
                echo "Success:Lustre change the mode of OBJECTS correctly"
        else
                echo "Error: Lustre does not change the mode of OBJECTS properly"
                return 1
        fi
                                                                                                                             
        if [ $EXPECTEDLOGSMODE = "0777" ]; then
                echo "Success:Lustre change the mode of LOGS correctly"
        else
                echo "Error: Lustre does not change the mode of LOGS properly"
                return 1
        fi
                                                                                                                             
        if [ $EXPECTEDPENDINGMODE = "0777" ]; then
                echo "Success:Lustre change the mode of PENDING correctly"
        else
                echo "Error: Lustre does not change the mode of PENDING properly"
                return 1
        fi
}
run_test 16 "verify that lustre will correct the mode of OBJECTS/LOGS/PENDING"

test_17() {
        TMPMTPT="/mnt/conf17"

        if [ ! -f "$MDSDEV" ]; then
            echo "no $MDSDEV existing, so mount Lustre to create one"
            start_ost
            start_mds
            mount_client $MOUNT
            check_mount || return 41
            cleanup || return $?
        fi

        echo "Remove mds config log"
        [ -d $TMPMTPT ] || mkdir -p $TMPMTPT
        mount -o loop -t ext3 $MDSDEV $TMPMTPT || return $?
        rm -f $TMPMTPT/LOGS/mds_svc || return $?
        umount $TMPMTPT || return $?

        start_ost
	start mds $MDSLCONFARGS && return 42
        cleanup || return $?
}
run_test 17 "Verify failed mds_postsetup won't fail assertion (2936)"

test_18() {
        [ -f $MDSDEV ] && echo "remove $MDSDEV" && rm -f $MDSDEV
        echo "mount mds with large journal..."
        OLDMDSSIZE=$MDSSIZE
        MDSSIZE=2000000
        gen_config
                                                                                                                             
        echo "mount lustre system..."
        start_ost
        start_mds
        mount_client $MOUNT
        check_mount || return 41
                                                                                                                             
        echo "check journal size..."
        FOUNDJOURNALSIZE=`debugfs -R "stat <8>" $MDSDEV | awk '/Size: / { print $6; exit;}'`
        if [ $FOUNDJOURNALSIZE = "79691776" ]; then
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

equals_msg "Done"
