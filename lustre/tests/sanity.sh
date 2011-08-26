#!/bin/bash
# -*- mode: Bash; tab-width: 4; indent-tabs-mode: t; -*-
# vim:autoindent:shiftwidth=4:tabstop=4:
#
# Run select tests by setting ONLY, or as arguments to the script.
# Skip specific tests by setting EXCEPT.
#
# e.g. ONLY="22 23" or ONLY="`seq 32 39`" or EXCEPT="31"
set -e

ONLY=${ONLY:-"$*"}
# bug number for skipped test: 13297 2108 9789 3637 9789 3561 12622 5188
ALWAYS_EXCEPT="                27u   42a  42b  42c  42d  45   51d   68b  $SANITY_EXCEPT"
# UPDATE THE COMMENT ABOVE WITH BUG NUMBERS WHEN CHANGING ALWAYS_EXCEPT!

# Tests that fail on uml
CPU=`awk '/model/ {print $4}' /proc/cpuinfo`
#                                    buffer i/o errs             sock spc runas
[ "$CPU" = "UML" ] && EXCEPT="$EXCEPT 27m 27n 27o 27p 27q 27r 31d 54a  64b 99a 99b 99c 99d 99e 99f 101"

case `uname -r` in
2.4*) FSTYPE=${FSTYPE:-ext3} ;;
2.6*) FSTYPE=${FSTYPE:-ldiskfs} ;;
*) error "unsupported kernel" ;;
esac

SRCDIR=$(cd $(dirname $0); echo $PWD)
export PATH=$PATH:/sbin

TMP=${TMP:-/tmp}

CHECKSTAT=${CHECKSTAT:-"checkstat -v"}
CREATETEST=${CREATETEST:-createtest}
LFS=${LFS:-lfs}
SETSTRIPE=${SETSTRIPE:-"$LFS setstripe"}
GETSTRIPE=${GETSTRIPE:-"$LFS getstripe"}
LSTRIPE=${LSTRIPE:-"$LFS setstripe"}
LFIND=${LFIND:-"$LFS find"}
LVERIFY=${LVERIFY:-ll_dirstripe_verify}
LCTL=${LCTL:-lctl}
MCREATE=${MCREATE:-mcreate}
OPENFILE=${OPENFILE:-openfile}
OPENUNLINK=${OPENUNLINK:-openunlink}
READS=${READS:-"reads"}
MUNLINK=${MUNLINK:-munlink}
SOCKETSERVER=${SOCKETSERVER:-socketserver}
SOCKETCLIENT=${SOCKETCLIENT:-socketclient}
MEMHOG=${MEMHOG:-memhog}
DIRECTIO=${DIRECTIO:-directio}
ACCEPTOR_PORT=${ACCEPTOR_PORT:-988}
UMOUNT=${UMOUNT:-"umount -d"}
STRIPES_PER_OBJ=-1
CHECK_GRANT=${CHECK_GRANT:-"yes"}
GRANT_CHECK_LIST=${GRANT_CHECK_LIST:-""}

export NAME=${NAME:-local}

SAVE_PWD=$PWD

CLEANUP=${CLEANUP:-:}
SETUP=${SETUP:-:}
TRACE=${TRACE:-""}
LUSTRE=${LUSTRE:-$(cd $(dirname $0)/..; echo $PWD)}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/${NAME}.sh}
init_logging

[ "$SLOW" = "no" ] && EXCEPT_SLOW="24o 24v 27m 36f 36g 36h 51b 51c 60c 63 64b 68 71 73 77f 78 101 103 115 120g 124b"

FAIL_ON_ERROR=false

cleanup() {
	echo -n "cln.."
	pgrep ll_sa > /dev/null && { echo "There are ll_sa thread not exit!"; exit 20; }
	cleanupall ${FORCE} $* || { echo "FAILed to clean up"; exit 20; }
}
setup() {
	echo -n "mnt.."
        load_modules
	setupall || exit 10
	echo "done"
}

check_kernel_version() {
	WANT_VER=$1
	GOT_VER=$(lctl get_param -n version | awk '/kernel:/ {print $2}')
	case $GOT_VER in
	patchless|patchless_client) return 0;;
	*) [ $GOT_VER -ge $WANT_VER ] && return 0 ;;
	esac
	log "test needs at least kernel version $WANT_VER, running $GOT_VER"
	return 1
}

if [ "$ONLY" == "cleanup" ]; then
       sh llmountcleanup.sh
       exit 0
fi

check_and_setup_lustre

DIR=${DIR:-$MOUNT}
assert_DIR

MDT0=$($LCTL get_param -n mdc.*.mds_server_uuid | \
    awk '{gsub(/_UUID/,""); print $1}' | head -1)
LOVNAME=$($LCTL get_param -n llite.*.lov.common_name | tail -n 1)
OSTCOUNT=$($LCTL get_param -n lov.$LOVNAME.numobd)
STRIPECOUNT=$($LCTL get_param -n lov.$LOVNAME.stripecount)
STRIPESIZE=$($LCTL get_param -n lov.$LOVNAME.stripesize)
ORIGFREE=$($LCTL get_param -n lov.$LOVNAME.kbytesavail)
MAXFREE=${MAXFREE:-$((200000 * $OSTCOUNT))}

[ -f $DIR/d52a/foo ] && chattr -a $DIR/d52a/foo
[ -f $DIR/d52b/foo ] && chattr -i $DIR/d52b/foo
rm -rf $DIR/[Rdfs][0-9]*

# $RUNAS_ID may get set incorrectly somewhere else
[ $UID -eq 0 -a $RUNAS_ID -eq 0 ] && error "\$RUNAS_ID set to 0, but \$UID is also 0!"

check_runas_id $RUNAS_ID $RUNAS_GID $RUNAS

build_test_filter

if [ "${ONLY}" = "MOUNT" ] ; then
	echo "Lustre is up, please go on"
	exit
fi

echo "preparing for tests involving mounts"
EXT2_DEV=${EXT2_DEV:-$TMP/SANITY.LOOP}
touch $EXT2_DEV
mke2fs -j -F $EXT2_DEV 8000 > /dev/null
echo # add a newline after mke2fs.

umask 077

OLDDEBUG="`lctl get_param -n debug 2> /dev/null`"
lctl set_param debug=-1 2> /dev/null || true
test_0() {
	touch $DIR/$tfile
	$CHECKSTAT -t file $DIR/$tfile || error
	rm $DIR/$tfile
	$CHECKSTAT -a $DIR/$tfile || error
}
run_test 0 "touch .../$tfile ; rm .../$tfile ====================="

test_0b() {
	chmod 0755 $DIR || error
	$CHECKSTAT -p 0755 $DIR || error
}
run_test 0b "chmod 0755 $DIR ============================="

test_0c() {
    $LCTL get_param mdc.*.import | grep  "state: FULL" || error "import not FULL"
    $LCTL get_param mdc.*.import | grep  "target: $FSNAME-MDT" || error "bad target"
}
run_test 0c "check import proc ============================="

test_1a() {
	mkdir $DIR/d1
	mkdir $DIR/d1/d2
	mkdir $DIR/d1/d2 && error "we expect EEXIST, but not returned"
	$CHECKSTAT -t dir $DIR/d1/d2 || error
}
run_test 1a "mkdir .../d1; mkdir .../d1/d2 ====================="

test_1b() {
	rmdir $DIR/d1/d2
	rmdir $DIR/d1
	$CHECKSTAT -a $DIR/d1 || error
}
run_test 1b "rmdir .../d1/d2; rmdir .../d1 ====================="

test_2a() {
	mkdir $DIR/d2
	touch $DIR/d2/f
	$CHECKSTAT -t file $DIR/d2/f || error
}
run_test 2a "mkdir .../d2; touch .../d2/f ======================"

test_2b() {
	rm -r $DIR/d2
	$CHECKSTAT -a $DIR/d2 || error
}
run_test 2b "rm -r .../d2; checkstat .../d2/f ======================"

test_3a() {
	mkdir $DIR/d3
	$CHECKSTAT -t dir $DIR/d3 || error
}
run_test 3a "mkdir .../d3 ======================================"

test_3b() {
	if [ ! -d $DIR/d3 ]; then
		mkdir $DIR/d3
	fi
	touch $DIR/d3/f
	$CHECKSTAT -t file $DIR/d3/f || error
}
run_test 3b "touch .../d3/f ===================================="

test_3c() {
	rm -r $DIR/d3
	$CHECKSTAT -a $DIR/d3 || error
}
run_test 3c "rm -r .../d3 ======================================"

test_4a() {
	mkdir $DIR/d4
	$CHECKSTAT -t dir $DIR/d4 || error
}
run_test 4a "mkdir .../d4 ======================================"

test_4b() {
	if [ ! -d $DIR/d4 ]; then
		mkdir $DIR/d4
	fi
	mkdir $DIR/d4/d2
	$CHECKSTAT -t dir $DIR/d4/d2 || error
}
run_test 4b "mkdir .../d4/d2 ==================================="

test_5() {
	mkdir $DIR/d5
	mkdir $DIR/d5/d2
	chmod 0707 $DIR/d5/d2
	$CHECKSTAT -t dir -p 0707 $DIR/d5/d2 || error
}
run_test 5 "mkdir .../d5 .../d5/d2; chmod .../d5/d2 ============"

test_6a() {
	touch $DIR/f6a
	chmod 0666 $DIR/f6a || error
	$CHECKSTAT -t file -p 0666 -u \#$UID $DIR/f6a || error
}
run_test 6a "touch .../f6a; chmod .../f6a ======================"

test_6b() {
	[ $RUNAS_ID -eq $UID ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return
	if [ ! -f $DIR/f6a ]; then
		touch $DIR/f6a
		chmod 0666 $DIR/f6a
	fi
	$RUNAS chmod 0444 $DIR/f6a && error
	$CHECKSTAT -t file -p 0666 -u \#$UID $DIR/f6a || error
}
run_test 6b "$RUNAS chmod .../f6a (should return error) =="

test_6c() {
	[ $RUNAS_ID -eq $UID ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return
	touch $DIR/f6c
	chown $RUNAS_ID $DIR/f6c || error
	$CHECKSTAT -t file -u \#$RUNAS_ID $DIR/f6c || error
}
run_test 6c "touch .../f6c; chown .../f6c ======================"

test_6d() {
	[ $RUNAS_ID -eq $UID ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return
	if [ ! -f $DIR/f6c ]; then
		touch $DIR/f6c
		chown $RUNAS_ID $DIR/f6c
	fi
	$RUNAS chown $UID $DIR/f6c && error
	$CHECKSTAT -t file -u \#$RUNAS_ID $DIR/f6c || error
}
run_test 6d "$RUNAS chown .../f6c (should return error) =="

test_6e() {
	[ $RUNAS_ID -eq $UID ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return
	touch $DIR/f6e
	chgrp $RUNAS_ID $DIR/f6e || error
	$CHECKSTAT -t file -u \#$UID -g \#$RUNAS_ID $DIR/f6e || error
}
run_test 6e "touch .../f6e; chgrp .../f6e ======================"

test_6f() {
	[ $RUNAS_ID -eq $UID ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return
	if [ ! -f $DIR/f6e ]; then
		touch $DIR/f6e
		chgrp $RUNAS_ID $DIR/f6e
	fi
	$RUNAS chgrp $UID $DIR/f6e && error
	$CHECKSTAT -t file -u \#$UID -g \#$RUNAS_ID $DIR/f6e || error
}
run_test 6f "$RUNAS chgrp .../f6e (should return error) =="

test_6g() {
	[ $RUNAS_ID -eq $UID ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return
        mkdir $DIR/d6g || error
        chmod 777 $DIR/d6g || error
        $RUNAS mkdir $DIR/d6g/d || error
        chmod g+s $DIR/d6g/d || error
        mkdir $DIR/d6g/d/subdir
	$CHECKSTAT -g \#$RUNAS_GID $DIR/d6g/d/subdir || error
}
run_test 6g "Is new dir in sgid dir inheriting group?"

test_6h() { # bug 7331
	[ $RUNAS_ID -eq $UID ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return
	touch $DIR/f6h || error "touch failed"
	chown $RUNAS_ID:$RUNAS_GID $DIR/f6h || error "initial chown failed"
	$RUNAS -G$RUNAS_GID chown $RUNAS_ID:0 $DIR/f6h && error "chown worked"
	$CHECKSTAT -t file -u \#$RUNAS_ID -g \#$RUNAS_GID $DIR/f6h || error
}
run_test 6h "$RUNAS chown RUNAS_ID.0 .../f6h (should return error)"

test_7a() {
	mkdir $DIR/d7
	$MCREATE $DIR/d7/f
	chmod 0666 $DIR/d7/f
	$CHECKSTAT -t file -p 0666 $DIR/d7/f || error
}
run_test 7a "mkdir .../d7; mcreate .../d7/f; chmod .../d7/f ===="

test_7b() {
	if [ ! -d $DIR/d7 ]; then
		mkdir $DIR/d7
	fi
	$MCREATE $DIR/d7/f2
	echo -n foo > $DIR/d7/f2
	[ "`cat $DIR/d7/f2`" = "foo" ] || error
	$CHECKSTAT -t file -s 3 $DIR/d7/f2 || error
}
run_test 7b "mkdir .../d7; mcreate d7/f2; echo foo > d7/f2 ====="

test_8() {
	mkdir $DIR/d8
	touch $DIR/d8/f
	chmod 0666 $DIR/d8/f
	$CHECKSTAT -t file -p 0666 $DIR/d8/f || error
}
run_test 8 "mkdir .../d8; touch .../d8/f; chmod .../d8/f ======="

test_9() {
	mkdir $DIR/d9
	mkdir $DIR/d9/d2
	mkdir $DIR/d9/d2/d3
	$CHECKSTAT -t dir $DIR/d9/d2/d3 || error
}
run_test 9 "mkdir .../d9 .../d9/d2 .../d9/d2/d3 ================"

test_10() {
	mkdir $DIR/d10
	mkdir $DIR/d10/d2
	touch $DIR/d10/d2/f
	$CHECKSTAT -t file $DIR/d10/d2/f || error
}
run_test 10 "mkdir .../d10 .../d10/d2; touch .../d10/d2/f ======"

test_11() {
	mkdir $DIR/d11
	mkdir $DIR/d11/d2
	chmod 0666 $DIR/d11/d2
	chmod 0705 $DIR/d11/d2
	$CHECKSTAT -t dir -p 0705 $DIR/d11/d2 || error
}
run_test 11 "mkdir .../d11 d11/d2; chmod .../d11/d2 ============"

test_12() {
	mkdir $DIR/d12
	touch $DIR/d12/f
	chmod 0666 $DIR/d12/f
	chmod 0654 $DIR/d12/f
	$CHECKSTAT -t file -p 0654 $DIR/d12/f || error
}
run_test 12 "touch .../d12/f; chmod .../d12/f .../d12/f ========"

test_13() {
	mkdir $DIR/d13
	dd if=/dev/zero of=$DIR/d13/f count=10
	>  $DIR/d13/f
	$CHECKSTAT -t file -s 0 $DIR/d13/f || error
}
run_test 13 "creat .../d13/f; dd .../d13/f; > .../d13/f ========"

test_14() {
	mkdir $DIR/d14
	touch $DIR/d14/f
	rm $DIR/d14/f
	$CHECKSTAT -a $DIR/d14/f || error
}
run_test 14 "touch .../d14/f; rm .../d14/f; rm .../d14/f ======="

test_15() {
	mkdir $DIR/d15
	touch $DIR/d15/f
	mv $DIR/d15/f $DIR/d15/f2
	$CHECKSTAT -t file $DIR/d15/f2 || error
}
run_test 15 "touch .../d15/f; mv .../d15/f .../d15/f2 =========="

test_16() {
	mkdir $DIR/d16
	touch $DIR/d16/f
	rm -rf $DIR/d16/f
	$CHECKSTAT -a $DIR/d16/f || error
}
run_test 16 "touch .../d16/f; rm -rf .../d16/f ================="

test_17a() {
	mkdir -p $DIR/d17
	touch $DIR/d17/f
	ln -s $DIR/d17/f $DIR/d17/l-exist
	ls -l $DIR/d17
	$CHECKSTAT -l $DIR/d17/f $DIR/d17/l-exist || error
	$CHECKSTAT -f -t f $DIR/d17/l-exist || error
	rm -f $DIR/d17/l-exist
	$CHECKSTAT -a $DIR/d17/l-exist || error
}
run_test 17a "symlinks: create, remove (real) =================="

test_17b() {
	mkdir -p $DIR/d17
	ln -s no-such-file $DIR/d17/l-dangle
	ls -l $DIR/d17
	$CHECKSTAT -l no-such-file $DIR/d17/l-dangle || error
	$CHECKSTAT -fa $DIR/d17/l-dangle || error
	rm -f $DIR/d17/l-dangle
	$CHECKSTAT -a $DIR/d17/l-dangle || error
}
run_test 17b "symlinks: create, remove (dangling) =============="

test_17c() { # bug 3440 - don't save failed open RPC for replay
	mkdir -p $DIR/d17
	ln -s foo $DIR/d17/f17c
	cat $DIR/d17/f17c && error "opened non-existent symlink" || true
}
run_test 17c "symlinks: open dangling (should return error) ===="

test_17d() {
	mkdir -p $DIR/d17
	ln -s foo $DIR/d17/f17d
	touch $DIR/d17/f17d || error "creating to new symlink"
}
run_test 17d "symlinks: create dangling ========================"

test_17e() {
	mkdir -p $DIR/$tdir
	local foo=$DIR/$tdir/$tfile
	ln -s $foo $foo || error "create symlink failed"
	ls -l $foo || error "ls -l failed"
	ls $foo && error "ls not failed" || true
}
run_test 17e "symlinks: create recursive symlink (should return error) ===="

test_17f() {
	mkdir -p $DIR/d17f
	ln -s 1234567890/2234567890/3234567890/4234567890 $DIR/d17f/111
	ln -s 1234567890/2234567890/3234567890/4234567890/5234567890/6234567890 $DIR/d17f/222
	ln -s 1234567890/2234567890/3234567890/4234567890/5234567890/6234567890/7234567890/8234567890 $DIR/d17f/333
	ln -s 1234567890/2234567890/3234567890/4234567890/5234567890/6234567890/7234567890/8234567890/9234567890/a234567890/b234567890 $DIR/d17f/444
	ln -s 1234567890/2234567890/3234567890/4234567890/5234567890/6234567890/7234567890/8234567890/9234567890/a234567890/b234567890/c234567890/d234567890/f234567890 $DIR/d17f/555
	ln -s 1234567890/2234567890/3234567890/4234567890/5234567890/6234567890/7234567890/8234567890/9234567890/a234567890/b234567890/c234567890/d234567890/f234567890/aaaaaaaaaa/bbbbbbbbbb/cccccccccc/dddddddddd/eeeeeeeeee/ffffffffff/ $DIR/d17f/666
	ls -l  $DIR/d17f
}
run_test 17f "symlinks: long and very long symlink name ========================"

test_17g() {
        mkdir -p $DIR/$tdir
        LONGSYMLINK="$(dd if=/dev/zero bs=4095 count=1 | tr '\0' 'x')"
        ln -s $LONGSYMLINK $DIR/$tdir/$tfile
        ls -l $DIR/$tdir
}
run_test 17g "symlinks: really long symlink name ==============================="

test_17h() { #bug 17378
        mkdir -p $DIR/$tdir
        $SETSTRIPE $DIR/$tdir -c -1
#define OBD_FAIL_MDS_LOV_PREP_CREATE 0x141
        do_facet $SINGLEMDS lctl set_param fail_loc=0x80000141
        touch $DIR/$tdir/$tfile || true
}
run_test 17h "create objects: lov_free_memmd() doesn't lbug"

test_17i() { #bug 20018
        mkdir -p $DIR/$tdir
	local foo=$DIR/$tdir/$tfile
	ln -s $foo $foo || error "create symlink failed"
#define OBD_FAIL_MDS_READLINK_EPROTO     0x143
	do_facet $SINGLEMDS lctl set_param fail_loc=0x80000143
	ls -l $foo && error "error not detected"
	return 0
}
run_test 17i "don't panic on short symlink"

test_17k() { #bug 22301
        rsync --help | grep -q xattr ||
                skip_env "$(rsync --version| head -1) does not support xattrs"
        mkdir -p $DIR/{$tdir,$tdir.new}
        touch $DIR/$tdir/$tfile
        ln -s $DIR/$tdir/$tfile $DIR/$tdir/$tfile.lnk
        rsync -av -X $DIR/$tdir/ $DIR/$tdir.new ||
                error "rsync failed with xattrs enabled"
}
run_test 17k "symlinks: rsync with xattrs enabled ========================="

test_18() {
	touch $DIR/f
	ls $DIR || error
}
run_test 18 "touch .../f ; ls ... =============================="

test_19a() {
	touch $DIR/f19
	ls -l $DIR
	rm $DIR/f19
	$CHECKSTAT -a $DIR/f19 || error
}
run_test 19a "touch .../f19 ; ls -l ... ; rm .../f19 ==========="

test_19b() {
	ls -l $DIR/f19 && error || true
}
run_test 19b "ls -l .../f19 (should return error) =============="

test_19c() {
	[ $RUNAS_ID -eq $UID ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return
	$RUNAS touch $DIR/f19 && error || true
}
run_test 19c "$RUNAS touch .../f19 (should return error) =="

test_19d() {
	cat $DIR/f19 && error || true
}
run_test 19d "cat .../f19 (should return error) =============="

test_20() {
	touch $DIR/f
	rm $DIR/f
	log "1 done"
	touch $DIR/f
	rm $DIR/f
	log "2 done"
	touch $DIR/f
	rm $DIR/f
	log "3 done"
	$CHECKSTAT -a $DIR/f || error
}
run_test 20 "touch .../f ; ls -l ... ==========================="

test_21() {
	mkdir $DIR/d21
	[ -f $DIR/d21/dangle ] && rm -f $DIR/d21/dangle
	ln -s dangle $DIR/d21/link
	echo foo >> $DIR/d21/link
	cat $DIR/d21/dangle
	$CHECKSTAT -t link $DIR/d21/link || error
	$CHECKSTAT -f -t file $DIR/d21/link || error
}
run_test 21 "write to dangling link ============================"

test_22() {
	WDIR=$DIR/$tdir
	mkdir -p $WDIR
	chown $RUNAS_ID:$RUNAS_GID $WDIR
	(cd $WDIR || error "cd $WDIR failed";
	$RUNAS tar cf - /etc/hosts /etc/sysconfig/network | \
	$RUNAS tar xf -)
	ls -lR $WDIR/etc || error "ls -lR $WDIR/etc failed"
	$CHECKSTAT -t dir $WDIR/etc || error "checkstat -t dir failed"
	$CHECKSTAT -u \#$RUNAS_ID -g \#$RUNAS_GID $WDIR/etc || error "checkstat -u failed"
}
run_test 22 "unpack tar archive as non-root user ==============="

# was test_23
test_23a() {
	mkdir -p $DIR/$tdir
	local file=$DIR/$tdir/$tfile

	openfile -f O_CREAT:O_EXCL $file || error "$file create failed"
	openfile -f O_CREAT:O_EXCL $file &&
		error "$file recreate succeeded" || true
}
run_test 23a "O_CREAT|O_EXCL in subdir =========================="

test_23b() { # bug 18988
	mkdir -p $DIR/$tdir
	local file=$DIR/$tdir/$tfile

        rm -f $file
        echo foo > $file || error "write filed"
        echo bar >> $file || error "append filed"
        $CHECKSTAT -s 8 $file || error "wrong size"
        rm $file
}
run_test 23b "O_APPEND check =========================="

test_24a() {
	echo '== rename sanity =============================================='
	echo '-- same directory rename'
	mkdir $DIR/R1
	touch $DIR/R1/f
	mv $DIR/R1/f $DIR/R1/g
	$CHECKSTAT -t file $DIR/R1/g || error
}
run_test 24a "touch .../R1/f; rename .../R1/f .../R1/g ========="

test_24b() {
	mkdir $DIR/R2
	touch $DIR/R2/{f,g}
	mv $DIR/R2/f $DIR/R2/g
	$CHECKSTAT -a $DIR/R2/f || error
	$CHECKSTAT -t file $DIR/R2/g || error
}
run_test 24b "touch .../R2/{f,g}; rename .../R2/f .../R2/g ====="

test_24c() {
	mkdir $DIR/R3
	mkdir $DIR/R3/f
	mv $DIR/R3/f $DIR/R3/g
	$CHECKSTAT -a $DIR/R3/f || error
	$CHECKSTAT -t dir $DIR/R3/g || error
}
run_test 24c "mkdir .../R3/f; rename .../R3/f .../R3/g ========="

test_24d() {
	mkdir $DIR/R4
	mkdir $DIR/R4/{f,g}
	mrename $DIR/R4/f $DIR/R4/g
	$CHECKSTAT -a $DIR/R4/f || error
	$CHECKSTAT -t dir $DIR/R4/g || error
}
run_test 24d "mkdir .../R4/{f,g}; rename .../R4/f .../R4/g ====="

test_24e() {
	echo '-- cross directory renames --'
	mkdir $DIR/R5{a,b}
	touch $DIR/R5a/f
	mv $DIR/R5a/f $DIR/R5b/g
	$CHECKSTAT -a $DIR/R5a/f || error
	$CHECKSTAT -t file $DIR/R5b/g || error
}
run_test 24e "touch .../R5a/f; rename .../R5a/f .../R5b/g ======"

test_24f() {
	mkdir $DIR/R6{a,b}
	touch $DIR/R6a/f $DIR/R6b/g
	mv $DIR/R6a/f $DIR/R6b/g
	$CHECKSTAT -a $DIR/R6a/f || error
	$CHECKSTAT -t file $DIR/R6b/g || error
}
run_test 24f "touch .../R6a/f R6b/g; mv .../R6a/f .../R6b/g ===="

test_24g() {
	mkdir $DIR/R7{a,b}
	mkdir $DIR/R7a/d
	mv $DIR/R7a/d $DIR/R7b/e
	$CHECKSTAT -a $DIR/R7a/d || error
	$CHECKSTAT -t dir $DIR/R7b/e || error
}
run_test 24g "mkdir .../R7{a,b}/d; mv .../R7a/d .../R7b/e ======"

test_24h() {
	mkdir $DIR/R8{a,b}
	mkdir $DIR/R8a/d $DIR/R8b/e
	mrename $DIR/R8a/d $DIR/R8b/e
	$CHECKSTAT -a $DIR/R8a/d || error
	$CHECKSTAT -t dir $DIR/R8b/e || error
}
run_test 24h "mkdir .../R8{a,b}/{d,e}; rename .../R8a/d .../R8b/e"

test_24i() {
	echo "-- rename error cases"
	mkdir $DIR/R9
	mkdir $DIR/R9/a
	touch $DIR/R9/f
	mrename $DIR/R9/f $DIR/R9/a
	$CHECKSTAT -t file $DIR/R9/f || error
	$CHECKSTAT -t dir  $DIR/R9/a || error
	$CHECKSTAT -a $DIR/R9/a/f || error
}
run_test 24i "rename file to dir error: touch f ; mkdir a ; rename f a"

test_24j() {
	mkdir $DIR/R10
	mrename $DIR/R10/f $DIR/R10/g
	$CHECKSTAT -t dir $DIR/R10 || error
	$CHECKSTAT -a $DIR/R10/f || error
	$CHECKSTAT -a $DIR/R10/g || error
}
run_test 24j "source does not exist ============================"

test_24k() {
	mkdir $DIR/R11a $DIR/R11a/d
	touch $DIR/R11a/f
	mv $DIR/R11a/f $DIR/R11a/d
        $CHECKSTAT -a $DIR/R11a/f || error
        $CHECKSTAT -t file $DIR/R11a/d/f || error
}
run_test 24k "touch .../R11a/f; mv .../R11a/f .../R11a/d ======="

# bug 2429 - rename foo foo foo creates invalid file
test_24l() {
	f="$DIR/f24l"
	multiop $f OcNs || error
}
run_test 24l "Renaming a file to itself ========================"

test_24m() {
	f="$DIR/f24m"
	multiop $f OcLN ${f}2 ${f}2 || error "link ${f}2 ${f}2 failed"
	# on ext3 this does not remove either the source or target files
	# though the "expected" operation would be to remove the source
	$CHECKSTAT -t file ${f} || error "${f} missing"
	$CHECKSTAT -t file ${f}2 || error "${f}2 missing"
}
run_test 24m "Renaming a file to a hard link to itself ========="

test_24n() {
    f="$DIR/f24n"
    # this stats the old file after it was renamed, so it should fail
    touch ${f}
    $CHECKSTAT ${f}
    mv ${f} ${f}.rename
    $CHECKSTAT ${f}.rename
    $CHECKSTAT -a ${f}
}
run_test 24n "Statting the old file after renaming (Posix rename 2)"

test_24o() {
	check_kernel_version 37 || return 0
	mkdir -p $DIR/d24o
	rename_many -s random -v -n 10 $DIR/d24o
}
run_test 24o "rename of files during htree split ==============="

test_24p() {
	mkdir $DIR/R12{a,b}
	DIRINO=`ls -lid $DIR/R12a | awk '{ print $1 }'`
	mrename $DIR/R12a $DIR/R12b
	$CHECKSTAT -a $DIR/R12a || error
	$CHECKSTAT -t dir $DIR/R12b || error
	DIRINO2=`ls -lid $DIR/R12b | awk '{ print $1 }'`
	[ "$DIRINO" = "$DIRINO2" ] || error "R12a $DIRINO != R12b $DIRINO2"
}
run_test 24p "mkdir .../R12{a,b}; rename .../R12a .../R12b"

test_24q() {
	mkdir $DIR/R13{a,b}
	DIRINO=`ls -lid $DIR/R13a | awk '{ print $1 }'`
	multiop_bg_pause $DIR/R13b D_c || return 1
	MULTIPID=$!

	mrename $DIR/R13a $DIR/R13b
	$CHECKSTAT -a $DIR/R13a || error
	$CHECKSTAT -t dir $DIR/R13b || error
	DIRINO2=`ls -lid $DIR/R13b | awk '{ print $1 }'`
	[ "$DIRINO" = "$DIRINO2" ] || error "R13a $DIRINO != R13b $DIRINO2"
	kill -USR1 $MULTIPID
	wait $MULTIPID || error "multiop close failed"
}
run_test 24q "mkdir .../R13{a,b}; open R13b rename R13a R13b ==="

test_24r() { #bug 3789
	mkdir $DIR/R14a $DIR/R14a/b
	mrename $DIR/R14a $DIR/R14a/b && error "rename to subdir worked!"
	$CHECKSTAT -t dir $DIR/R14a || error "$DIR/R14a missing"
	$CHECKSTAT -t dir $DIR/R14a/b || error "$DIR/R14a/b missing"
}
run_test 24r "mkdir .../R14a/b; rename .../R14a .../R14a/b ====="

test_24s() {
	mkdir $DIR/R15a $DIR/R15a/b $DIR/R15a/b/c
	mrename $DIR/R15a $DIR/R15a/b/c && error "rename to sub-subdir worked!"
	$CHECKSTAT -t dir $DIR/R15a || error "$DIR/R15a missing"
	$CHECKSTAT -t dir $DIR/R15a/b/c || error "$DIR/R15a/b/c missing"
}
run_test 24s "mkdir .../R15a/b/c; rename .../R15a .../R15a/b/c ="
test_24t() {
	mkdir $DIR/R16a $DIR/R16a/b $DIR/R16a/b/c
	mrename $DIR/R16a/b/c $DIR/R16a && error "rename to sub-subdir worked!"
	$CHECKSTAT -t dir $DIR/R16a || error "$DIR/R16a missing"
	$CHECKSTAT -t dir $DIR/R16a/b/c || error "$DIR/R16a/b/c missing"
}
run_test 24t "mkdir .../R16a/b/c; rename .../R16a/b/c .../R16a ="

test_24u() { # bug12192
        multiop $DIR/$tfile C2w$((2048 * 1024))c || error
        $CHECKSTAT -s $((2048 * 1024)) $DIR/$tfile || error "wrong file size"
}
run_test 24u "create stripe file"

page_size() {
	getconf PAGE_SIZE
}

test_24v() {
	local NRFILES=100000
	local FREE_INODES=`lfs df -i|grep "filesystem summary" | awk '{print $5}'`
	[ $FREE_INODES -lt $NRFILES ] && \
		skip "not enough free inodes $FREE_INODES required $NRFILES" && \
		return

	mkdir -p $DIR/d24v
	createmany -m $DIR/d24v/$tfile $NRFILES

	cancel_lru_locks mdc
	lctl set_param mdc.*.stats clear

	ls $DIR/d24v >/dev/null || error "error in listing large dir"

	# LU-5 large readdir
	# DIRENT_SIZE = 32 bytes for sizeof(struct lu_dirent) +
	#               8 bytes for name(filename is mostly 5 in this test) +
	#               8 bytes for luda_type
	# take into account of overhead in lu_dirpage header and end mark in
	# each page, plus one in RPC_NUM calculation.
	DIRENT_SIZE=48
	RPC_SIZE=$(($(lctl get_param -n mdc.*.max_pages_per_rpc)*$(page_size)))
	RPC_NUM=$(((NRFILES * DIRENT_SIZE + RPC_SIZE - 1) / RPC_SIZE + 1))
	mds_readpage=`lctl get_param mdc.*.stats | \
				awk '/^mds_readpage/ {print $2}'`
	[ $mds_readpage -gt $RPC_NUM ] && \
		error "large readdir doesn't take effect"

	rm $DIR/d24v -rf
}
run_test 24v "list directory with large files (handle hash collision, bug: 17560)"

test_24w() { # bug21506
        SZ1=234852
        dd if=/dev/zero of=$DIR/$tfile bs=1M count=1 seek=4096 || return 1
        dd if=/dev/zero bs=$SZ1 count=1 >> $DIR/$tfile || return 2
        dd if=$DIR/$tfile of=$DIR/${tfile}_left bs=1M skip=4097 || return 3
        SZ2=`ls -l $DIR/${tfile}_left | awk '{print $5}'`
        [ "$SZ1" = "$SZ2" ] || \
                error "Error reading at the end of the file $tfile"
}
run_test 24w "Reading a file larger than 4Gb"

test_25a() {
	echo '== symlink sanity ============================================='

	mkdir $DIR/d25
	ln -s d25 $DIR/s25
	touch $DIR/s25/foo || error
}
run_test 25a "create file in symlinked directory ==============="

test_25b() {
	[ ! -d $DIR/d25 ] && test_25a
	$CHECKSTAT -t file $DIR/s25/foo || error
}
run_test 25b "lookup file in symlinked directory ==============="

test_26a() {
	mkdir $DIR/d26
	mkdir $DIR/d26/d26-2
	ln -s d26/d26-2 $DIR/s26
	touch $DIR/s26/foo || error
}
run_test 26a "multiple component symlink ======================="

test_26b() {
	mkdir -p $DIR/d26b/d26-2
	ln -s d26b/d26-2/foo $DIR/s26-2
	touch $DIR/s26-2 || error
}
run_test 26b "multiple component symlink at end of lookup ======"

test_26c() {
	mkdir $DIR/d26.2
	touch $DIR/d26.2/foo
	ln -s d26.2 $DIR/s26.2-1
	ln -s s26.2-1 $DIR/s26.2-2
	ln -s s26.2-2 $DIR/s26.2-3
	chmod 0666 $DIR/s26.2-3/foo
}
run_test 26c "chain of symlinks ================================"

# recursive symlinks (bug 439)
test_26d() {
	ln -s d26-3/foo $DIR/d26-3
}
run_test 26d "create multiple component recursive symlink ======"

test_26e() {
	[ ! -h $DIR/d26-3 ] && test_26d
	rm $DIR/d26-3
}
run_test 26e "unlink multiple component recursive symlink ======"

# recursive symlinks (bug 7022)
test_26f() {
	mkdir -p $DIR/$tdir
	mkdir $DIR/$tdir/$tfile        || error "mkdir $DIR/$tdir/$tfile failed"
	cd $DIR/$tdir/$tfile           || error "cd $DIR/$tdir/$tfile failed"
	mkdir -p lndir/bar1      || error "mkdir lndir/bar1 failed"
	mkdir $tfile             || error "mkdir $tfile failed"
	cd $tfile                || error "cd $tfile failed"
	ln -s .. dotdot          || error "ln dotdot failed"
	ln -s dotdot/lndir lndir || error "ln lndir failed"
	cd $DIR/$tdir                 || error "cd $DIR/$tdir failed"
	output=`ls $tfile/$tfile/lndir/bar1`
	[ "$output" = bar1 ] && error "unexpected output"
	rm -r $tfile             || error "rm $tfile failed"
	$CHECKSTAT -a $DIR/$tfile || error "$tfile not gone"
}
run_test 26f "rm -r of a directory which has recursive symlink ="

test_27a() {
	echo '== stripe sanity =============================================='
	mkdir -p $DIR/d27 || error "mkdir failed"
	$GETSTRIPE $DIR/d27
	$SETSTRIPE $DIR/d27/f0 -c 1 || error "lstripe failed"
	$CHECKSTAT -t file $DIR/d27/f0 || error "checkstat failed"
	pass
	log "== test_27a: write to one stripe file ========================="
	cp /etc/hosts $DIR/d27/f0 || error
}
run_test 27a "one stripe file =================================="

test_27c() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "skipping 2-stripe test" && return
	mkdir -p $DIR/d27
	$SETSTRIPE $DIR/d27/f01 -c 2 || error "lstripe failed"
	[ `$GETSTRIPE $DIR/d27/f01 | grep -A 10 obdidx | wc -l` -eq 4 ] ||
		error "two-stripe file doesn't have two stripes"
	pass
	log "== test_27c: write to two stripe file file f01 ================"
	dd if=/dev/zero of=$DIR/d27/f01 bs=4k count=4 || error "dd failed"
}
run_test 27c "create two stripe file f01 ======================="

test_27d() {
	mkdir -p $DIR/d27
	$SETSTRIPE -c0 -i-1 -s0 $DIR/d27/fdef || error "lstripe failed"
	$CHECKSTAT -t file $DIR/d27/fdef || error "checkstat failed"
	dd if=/dev/zero of=$DIR/d27/fdef bs=4k count=4 || error
}
run_test 27d "create file with default settings ================"

test_27e() {
	mkdir -p $DIR/d27
	$SETSTRIPE $DIR/d27/f12 -c 2 || error "lstripe failed"
	$SETSTRIPE $DIR/d27/f12 -c 2 && error "lstripe succeeded twice"
	$CHECKSTAT -t file $DIR/d27/f12 || error "checkstat failed"
}
run_test 27e "setstripe existing file (should return error) ======"

test_27f() {
	mkdir -p $DIR/d27
	$SETSTRIPE $DIR/d27/fbad -s 100 -i 0 -c 1 && error "lstripe failed"
	dd if=/dev/zero of=$DIR/d27/f12 bs=4k count=4 || error "dd failed"
	$GETSTRIPE $DIR/d27/fbad || error "lfs getstripe failed"
}
run_test 27f "setstripe with bad stripe size (should return error)"

test_27g() {
	mkdir -p $DIR/d27
	$MCREATE $DIR/d27/fnone || error "mcreate failed"
	pass
	log "== test 27h: lfs getstripe with no objects ===================="
	$GETSTRIPE $DIR/d27/fnone 2>&1 | grep "no stripe info" || error "has object"
	pass
	log "== test 27i: lfs getstripe with some objects =================="
	touch $DIR/d27/fsome || error "touch failed"
	$GETSTRIPE $DIR/d27/fsome | grep obdidx || error "missing objects"
}
run_test 27g "test lfs getstripe ==========================================="

test_27j() {
	mkdir -p $DIR/d27
	$SETSTRIPE $DIR/d27/f27j -i $OSTCOUNT && error "lstripe failed"||true
}
run_test 27j "setstripe with bad stripe offset (should return error)"

test_27k() { # bug 2844
	mkdir -p $DIR/d27
	FILE=$DIR/d27/f27k
	LL_MAX_BLKSIZE=$((4 * 1024 * 1024))
	[ ! -d $DIR/d27 ] && mkdir -p $DIR/d27
	$SETSTRIPE $FILE -s 67108864 || error "lstripe failed"
	BLKSIZE=`stat $FILE | awk '/IO Block:/ { print $7 }'`
	[ $BLKSIZE -le $LL_MAX_BLKSIZE ] || error "$BLKSIZE > $LL_MAX_BLKSIZE"
	dd if=/dev/zero of=$FILE bs=4k count=1
	BLKSIZE=`stat $FILE | awk '/IO Block:/ { print $7 }'`
	[ $BLKSIZE -le $LL_MAX_BLKSIZE ] || error "$BLKSIZE > $LL_MAX_BLKSIZE"
}
run_test 27k "limit i_blksize for broken user apps ============="

test_27l() {
	mkdir -p $DIR/d27
	mcreate $DIR/f27l || error "creating file"
	$RUNAS $SETSTRIPE $DIR/f27l -c 1 && \
		error "lstripe should have failed" || true
}
run_test 27l "check setstripe permissions (should return error)"

test_27m() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "$OSTCOUNT < 2 OSTs -- skipping" && return
	if [ $ORIGFREE -gt $MAXFREE ]; then
		skip "$ORIGFREE > $MAXFREE skipping out-of-space test on OST0"
		return
	fi
	mkdir -p $DIR/d27
	$SETSTRIPE $DIR/d27/f27m_1 -i 0 -c 1
	dd if=/dev/zero of=$DIR/d27/f27m_1 bs=1024 count=$MAXFREE && \
		error "dd should fill OST0"
	i=2
	while $SETSTRIPE $DIR/d27/f27m_$i -i 0 -c 1 ; do
		i=`expr $i + 1`
		[ $i -gt 256 ] && break
	done
	i=`expr $i + 1`
	touch $DIR/d27/f27m_$i
	[ `$GETSTRIPE $DIR/d27/f27m_$i | grep -A 10 obdidx | awk '{print $1}'| grep -w "0"` ] && \
		error "OST0 was full but new created file still use it"
	i=`expr $i + 1`
	touch $DIR/d27/f27m_$i
	[ `$GETSTRIPE $DIR/d27/f27m_$i | grep -A 10 obdidx | awk '{print $1}'| grep -w "0"` ] && \
		error "OST0 was full but new created file still use it"
	rm -r $DIR/d27
	sleep 15
}
run_test 27m "create file while OST0 was full =================="

sleep_maxage() {
        local DELAY=$(do_facet $SINGLEMDS lctl get_param -n lov.*.qos_maxage | head -n 1 | awk '{print $1 * 2}')
        sleep $DELAY
}

# OSCs keep a NOSPC flag that will be reset after ~5s (qos_maxage)
# if the OST isn't full anymore.
reset_enospc() {
	local OSTIDX=${1:-""}

	local list=$(comma_list $(osts_nodes))
	[ "$OSTIDX" ] && list=$(facet_host ost$((OSTIDX + 1)))

	do_nodes $list lctl set_param fail_loc=0
	sleep_maxage
}

exhaust_precreations() {
	local OSTIDX=$1
	local FAILLOC=$2
	local FAILIDX=${3:-$OSTIDX}

	mkdir -p $DIR/$tdir
	local MDSIDX=$(get_mds_dir "$DIR/$tdir")
	echo OSTIDX=$OSTIDX MDSIDX=$MDSIDX

	local OST=$(lfs osts | grep ${OSTIDX}": " | \
		awk '{print $2}' | sed -e 's/_UUID$//')
	local MDT_INDEX=$(lfs df | grep "\[MDT:$((MDSIDX - 1))\]" | awk '{print $1}' | \
			  sed -e 's/_UUID$//;s/^.*-//')

	# on the mdt's osc
	local mdtosc_proc1=$(get_mdtosc_proc_path mds${MDSIDX} $OST)
	local last_id=$(do_facet mds${MDSIDX} lctl get_param -n \
        osc.$mdtosc_proc1.prealloc_last_id)
	local next_id=$(do_facet mds${MDSIDX} lctl get_param -n \
        osc.$mdtosc_proc1.prealloc_next_id)

	local mdtosc_proc2=$(get_mdtosc_proc_path mds${MDSIDX})
	do_facet mds${MDSIDX} lctl get_param osc.$mdtosc_proc2.prealloc*

	mkdir -p $DIR/$tdir/${OST}
	$SETSTRIPE $DIR/$tdir/${OST} -i $OSTIDX -c 1
#define OBD_FAIL_OST_ENOSPC              0x215
	do_facet ost$((OSTIDX + 1)) lctl set_param fail_val=$FAILIDX
	do_facet ost$((OSTIDX + 1)) lctl set_param fail_loc=0x215
	echo "Creating to objid $last_id on ost $OST..."
	createmany -o $DIR/$tdir/${OST}/f $next_id $((last_id - next_id + 2))
	do_facet mds${MDSIDX} lctl get_param osc.$mdtosc_proc2.prealloc*
	do_facet ost$((OSTIDX + 1)) lctl set_param fail_loc=$FAILLOC
	sleep_maxage
}

exhaust_all_precreations() {
	local i
	for (( i=0; i < OSTCOUNT; i++ )) ; do
		exhaust_precreations $i $1 -1
	done
}

test_27n() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "too few OSTs" && return
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
	remote_ost_nodsh && skip "remote OST with nodsh" && return

	reset_enospc
	rm -f $DIR/$tdir/$tfile
	exhaust_precreations 0 0x80000215
	$SETSTRIPE -c -1 $DIR/$tdir
	touch $DIR/$tdir/$tfile || error
	$GETSTRIPE $DIR/$tdir/$tfile
	reset_enospc
}
run_test 27n "create file with some full OSTs =================="

test_27o() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "too few OSTs" && return
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
	remote_ost_nodsh && skip "remote OST with nodsh" && return

	reset_enospc
	rm -f $DIR/$tdir/$tfile
	exhaust_all_precreations 0x215

	touch $DIR/$tdir/$tfile && error "able to create $DIR/$tdir/$tfile"

	reset_enospc
	rm -rf $DIR/$tdir/*
}
run_test 27o "create file with all full OSTs (should error) ===="

test_27p() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "too few OSTs" && return
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
	remote_ost_nodsh && skip "remote OST with nodsh" && return

	reset_enospc
	rm -f $DIR/$tdir/$tfile
	mkdir -p $DIR/$tdir

	$MCREATE $DIR/$tdir/$tfile || error "mcreate failed"
	$TRUNCATE $DIR/$tdir/$tfile 80000000 || error "truncate failed"
	$CHECKSTAT -s 80000000 $DIR/$tdir/$tfile || error "checkstat failed"

	exhaust_precreations 0 0x80000215
	echo foo >> $DIR/$tdir/$tfile || error "append failed"
	$CHECKSTAT -s 80000004 $DIR/$tdir/$tfile || error "checkstat failed"
	$LFS getstripe $DIR/$tdir/$tfile

	reset_enospc
}
run_test 27p "append to a truncated file with some full OSTs ==="

test_27q() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "too few OSTs" && return
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
	remote_ost_nodsh && skip "remote OST with nodsh" && return

	reset_enospc
	rm -f $DIR/$tdir/$tfile

	$MCREATE $DIR/$tdir/$tfile || error "mcreate $DIR/$tdir/$tfile failed"
	$TRUNCATE $DIR/$tdir/$tfile 80000000 ||error "truncate $DIR/$tdir/$tfile failed"
	$CHECKSTAT -s 80000000 $DIR/$tdir/$tfile || error "checkstat failed"

	exhaust_all_precreations 0x215

	echo foo >> $DIR/$tdir/$tfile && error "append succeeded"
	$CHECKSTAT -s 80000000 $DIR/$tdir/$tfile || error "checkstat 2 failed"

	reset_enospc
}
run_test 27q "append to truncated file with all OSTs full (should error) ==="

test_27r() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "too few OSTs" && return
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
	remote_ost_nodsh && skip "remote OST with nodsh" && return

	reset_enospc
	rm -f $DIR/$tdir/$tfile
	exhaust_precreations 0 0x80000215

	$SETSTRIPE $DIR/$tdir/$tfile -i 0 -c 2 # && error

	reset_enospc
}
run_test 27r "stripe file with some full OSTs (shouldn't LBUG) ="

test_27s() { # bug 10725
	mkdir -p $DIR/$tdir
	local stripe_size=$((4096 * 1024 * 1024))	# 2^32
	local stripe_count=0
	[ $OSTCOUNT -eq 1 ] || stripe_count=2
	$SETSTRIPE $DIR/$tdir -s $stripe_size -c $stripe_count && \
		error "stripe width >= 2^32 succeeded" || true

}
run_test 27s "lsm_xfersize overflow (should error) (bug 10725)"

test_27t() { # bug 10864
        WDIR=`pwd`
        WLFS=`which lfs`
        cd $DIR
        touch $tfile
        $WLFS getstripe $tfile
        cd $WDIR
}
run_test 27t "check that utils parse path correctly"

test_27u() { # bug 4900
        [ "$OSTCOUNT" -lt "2" ] && skip_env "too few OSTs" && return
        remote_mds_nodsh && skip "remote MDS with nodsh" && return

#define OBD_FAIL_MDS_OSC_PRECREATE      0x139
        do_facet $SINGLEMDS lctl set_param fail_loc=0x139
        mkdir -p $DIR/$tdir
        createmany -o $DIR/$tdir/t- 1000
        do_facet $SINGLEMDS lctl set_param fail_loc=0

        TLOG=$DIR/$tfile.getstripe
        $GETSTRIPE $DIR/$tdir > $TLOG
        OBJS=`awk -vobj=0 '($1 == 0) { obj += 1 } END { print obj;}' $TLOG`
        unlinkmany $DIR/$tdir/t- 1000
        [ $OBJS -gt 0 ] && \
                error "$OBJS objects created on OST-0.  See $TLOG" || pass
}
run_test 27u "skip object creation on OSC w/o objects =========="

test_27v() { # bug 4900
        [ "$OSTCOUNT" -lt "2" ] && skip_env "too few OSTs" && return
        remote_mds_nodsh && skip "remote MDS with nodsh" && return
        remote_ost_nodsh && skip "remote OST with nodsh" && return

        exhaust_all_precreations 0x215
        reset_enospc

        mkdir -p $DIR/$tdir
        $SETSTRIPE $DIR/$tdir -c 1         # 1 stripe / file

        touch $DIR/$tdir/$tfile
        #define OBD_FAIL_TGT_DELAY_PRECREATE     0x705
        # all except ost1
        for (( i=0; i < OSTCOUNT; i++ )) ; do
                do_facet ost$i lctl set_param fail_loc=0x705
        done
        local START=`date +%s`
        createmany -o $DIR/$tdir/$tfile 32

        local FINISH=`date +%s`
        local TIMEOUT=`lctl get_param -n timeout`
        local PROCESS=$((FINISH - START))
        [ $PROCESS -ge $((TIMEOUT / 2)) ] && \
               error "$FINISH - $START >= $TIMEOUT / 2"
        sleep $((TIMEOUT / 2 - PROCESS))
        reset_enospc
}
run_test 27v "skip object creation on slow OST ================="

test_27w() { # bug 10997
        mkdir -p $DIR/$tdir || error "mkdir failed"
        $LSTRIPE $DIR/$tdir/f0 -s 65536 || error "lstripe failed"
        size=`$GETSTRIPE $DIR/$tdir/f0 -s`
        [ $size -ne 65536 ] && error "stripe size $size != 65536" || true
        gsdir=$($LFS getstripe -d $DIR/$tdir)
        [ $(echo $gsdir | grep -c stripe_count) -ne 1 ] && error "$LFS getstripe -d $DIR/$tdir failed"

        [ "$OSTCOUNT" -lt "2" ] && skip_env "skipping multiple stripe count/offset test" && return
        for i in `seq 1 $OSTCOUNT`; do
                offset=$(($i-1))
                $LSTRIPE $DIR/$tdir/f$i -c $i -i $offset || error "lstripe -c $i -i $offset failed"
                count=`$GETSTRIPE -c $DIR/$tdir/f$i`
                index=`$GETSTRIPE -o $DIR/$tdir/f$i`
                [ $count -ne $i ] && error "stripe count $count != $i" || true
                [ $index -ne $offset ] && error "stripe offset $index != $offset" || true
        done
}
run_test 27w "check lfs setstripe -c -s -i options ============="

test_27x() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "$OSTCOUNT < 2 OSTs" && return
	OFFSET=$(($OSTCOUNT - 1))
	OSTIDX=0
	local OST=$(lfs osts | awk '/'${OSTIDX}': / { print $2 }' | sed -e 's/_UUID$//')

	mkdir -p $DIR/$tdir
	$SETSTRIPE $DIR/$tdir -c 1	# 1 stripe per file
	do_facet ost$((OSTIDX + 1)) lctl set_param -n obdfilter.$OST.degraded 1
	sleep_maxage
	createmany -o $DIR/$tdir/$tfile $OSTCOUNT
	for i in `seq 0 $OFFSET`; do
		[ `$GETSTRIPE $DIR/$tdir/$tfile$i | grep -A 10 obdidx | awk '{print $1}' | grep -w "$OSTIDX"` ] &&
		error "OST0 was degraded but new created file still use it"
	done
	do_facet ost$((OSTIDX + 1)) lctl set_param -n obdfilter.$OST.degraded 0
}
run_test 27x "create files while OST0 is degraded"

test_27y() {
        [ "$OSTCOUNT" -lt "2" ] && skip_env "$OSTCOUNT < 2 OSTs -- skipping" && return
        remote_mds_nodsh && skip "remote MDS with nodsh" && return

        local mdtosc=$(get_mdtosc_proc_path $SINGLEMDS $FSNAME-OST0000)
        local last_id=$(do_facet $SINGLEMDS lctl get_param -n \
            osc.$mdtosc.prealloc_last_id)
        local next_id=$(do_facet $SINGLEMDS lctl get_param -n \
            osc.$mdtosc.prealloc_next_id)
        local fcount=$((last_id - next_id))
        [ $fcount -eq 0 ] && skip "not enough space on OST0" && return
        [ $fcount -gt $OSTCOUNT ] && fcount=$OSTCOUNT

        MDS_OSCS=`do_facet $SINGLEMDS lctl dl | awk '/[oO][sS][cC].*md[ts]/ { print $4 }'`
        OFFSET=$(($OSTCOUNT-1))
        OST=-1
        for OSC in $MDS_OSCS; do
                if [ $OST == -1 ]; then {
                        OST=`osc_to_ost $OSC`
                } else {
                        echo $OSC "is Deactivate:"
                        do_facet $SINGLEMDS lctl --device  %$OSC deactivate
                } fi
        done

        OSTIDX=$(lfs osts | grep ${OST} | awk '{print $1}' | sed -e 's/://')
        mkdir -p $DIR/$tdir
        $SETSTRIPE $DIR/$tdir -c 1      # 1 stripe / file

        do_facet ost$OSTIDX lctl set_param -n obdfilter.$OST.degraded 1
        sleep_maxage
        createmany -o $DIR/$tdir/$tfile $fcount
        do_facet ost$OSTIDX lctl set_param -n obdfilter.$OST.degraded 0

        for i in `seq 0 $OFFSET`; do
                [ `$GETSTRIPE $DIR/$tdir/$tfile$i | grep -A 10 obdidx | awk '{print $1}'| grep -w "$OSTIDX"` ] || \
                      error "files created on deactivated OSTs instead of degraded OST"
        done
        for OSC in $MDS_OSCS; do
                [ `osc_to_ost $OSC` != $OST  ] && {
                        echo $OSC "is activate"
                        do_facet $SINGLEMDS lctl --device %$OSC activate
                }
        done
}
run_test 27y "create files while OST0 is degraded and the rest inactive"

check_seq_oid()
{
        echo check file $1
        local old_ifs="$IFS"
        IFS=$'\t\n :'
        lmm=($($GETSTRIPE -v $1))

        IFS=$'[:]'
        fid=($($LFS path2fid $1))
        IFS="$old_ifs"

        # compare lmm_seq and lu_fid->f_seq
        [ ${lmm[4]} = ${fid[1]} ] || { error "SEQ mismatch"; return 1; }
        # compare lmm_object_id and lu_fid->oid
        [ ${lmm[6]} = ${fid[2]} ] || { error "OID mismatch"; return 2; }

        echo -e "\tseq ${fid[1]}, oid ${fid[2]} ver ${fid[3]}\n\tstripe count: ${lmm[8]}"

        [ "$FSTYPE" != "ldiskfs" ] && skip "can not check trusted.fid FSTYPE=$FSTYPE" && return 0

        # check the trusted.fid attribute of the OST objects of the file
        for (( i=0, j=19; i < ${lmm[8]}; i++, j+=4 )); do
                local obdidx=${lmm[$j]}
                local devnum=$((obdidx + 1))
                local objid=${lmm[$((j+1))]}
                local group=${lmm[$((j+3))]}
                local dev=$(ostdevname $devnum)
                local dir=${MOUNT%/*}/ost$devnum
                local mntpt=$(facet_mntpt ost$devnum)

                stop ost$devnum
                do_facet ost$devnum mount -t $FSTYPE $dev $dir $OST_MOUNT_OPTS ||
                        { error "mounting $dev as $FSTYPE failed"; return 3; }

                obj_filename=$(do_facet ost$devnum find $dir/O/$group -name $objid)
                local ff=$(do_facet ost$devnum $LL_DECODE_FILTER_FID $obj_filename)
                IFS=$'/= [:]'
                ff=($(echo $ff))
                IFS="$old_ifs"

                # compare lmm_seq and filter_fid->ff_parent.f_seq
                [ ${ff[11]} = ${lmm[4]} ] || { error "parent SEQ mismatch"; return 4; }
                # compare lmm_object_id and filter_fid->ff_parent.f_oid
                [ ${ff[12]} = ${lmm[6]} ] || { error "parent OID mismatch"; return 5; }
                let stripe=${ff[13]}
                [ $stripe -eq $i ] || { error "stripe mismatch"; return 6; }

                echo -e "\t\tost $obdidx, objid $objid, group $group"
                do_facet ost$devnum umount -d $mntpt
                start ost$devnum $dev $OST_MOUNT_OPTS
        done
}

test_27z() {
        mkdir -p $DIR/$tdir
        $SETSTRIPE $DIR/$tdir/$tfile-1 -c 1 -o 0 -s 1m ||
                { error "setstripe -c -1 failed"; return 1; }
        dd if=/dev/zero of=$DIR/$tdir/$tfile-1 bs=1M count=1 ||
                { error "dd 1 mb failed"; return 2; }
        $SETSTRIPE $DIR/$tdir/$tfile-2 -c -1 -o $(($OSTCOUNT - 1)) -s 1m ||
                { error "setstripe -c 1 failed"; return 3; }
        dd if=/dev/zero of=$DIR/$tdir/$tfile-2 bs=1M count=$OSTCOUNT ||
                { error "dd $OSTCOUNT mb failed"; return 4; }
        sync

        check_seq_oid $DIR/$tdir/$tfile-1 || return 5
        check_seq_oid $DIR/$tdir/$tfile-2 || return 6
}
run_test 27z "check SEQ/OID on the MDT and OST filesystems"

test_27A() { # b=19102
        local restore_size=`$GETSTRIPE -s $MOUNT`
        local restore_count=`$GETSTRIPE -c $MOUNT`
        local restore_offset=`$GETSTRIPE -o $MOUNT`
        $SETSTRIPE -c 0 -o -1 -s 0 $MOUNT
        local default_size=`$GETSTRIPE -s $MOUNT`
        local default_count=`$GETSTRIPE -c $MOUNT`
        local default_offset=`$GETSTRIPE -o $MOUNT`
        local dsize=$((1024 * 1024))
        [ $default_size -eq $dsize ] || error "stripe size $default_size != $dsize"
        [ $default_count -eq 1 ] || error "stripe count $default_count != 1"
        [ $default_offset -eq -1 ] || error "stripe offset $default_offset != -1"
        $SETSTRIPE -c $restore_count -o $restore_offset -s $restore_size $MOUNT
}
run_test 27A "check filesystem-wide default LOV EA values"

# createtest also checks that device nodes are created and
# then visible correctly (#2091)
test_28() { # bug 2091
	mkdir $DIR/d28
	$CREATETEST $DIR/d28/ct || error
}
run_test 28 "create/mknod/mkdir with bad file types ============"

test_29() {
	cancel_lru_locks mdc
	mkdir $DIR/d29
	touch $DIR/d29/foo
	log 'first d29'
	ls -l $DIR/d29

	declare -i LOCKCOUNTORIG=0
	for lock_count in $(lctl get_param -n ldlm.namespaces.*mdc*.lock_count); do
		let LOCKCOUNTORIG=$LOCKCOUNTORIG+$lock_count
	done
	[ $LOCKCOUNTORIG -eq 0 ] && echo "No mdc lock count" && return 1

	declare -i LOCKUNUSEDCOUNTORIG=0
	for unused_count in $(lctl get_param -n ldlm.namespaces.*mdc*.lock_unused_count); do
		let LOCKUNUSEDCOUNTORIG=$LOCKUNUSEDCOUNTORIG+$unused_count
	done

	log 'second d29'
	ls -l $DIR/d29
	log 'done'

	declare -i LOCKCOUNTCURRENT=0
	for lock_count in $(lctl get_param -n ldlm.namespaces.*mdc*.lock_count); do
		let LOCKCOUNTCURRENT=$LOCKCOUNTCURRENT+$lock_count
	done

	declare -i LOCKUNUSEDCOUNTCURRENT=0
	for unused_count in $(lctl get_param -n ldlm.namespaces.*mdc*.lock_unused_count); do
		let LOCKUNUSEDCOUNTCURRENT=$LOCKUNUSEDCOUNTCURRENT+$unused_count
	done

	if [ "$LOCKCOUNTCURRENT" -gt "$LOCKCOUNTORIG" ]; then
		lctl set_param -n ldlm.dump_namespaces ""
		error "CURRENT: $LOCKCOUNTCURRENT > $LOCKCOUNTORIG"
		$LCTL dk | sort -k4 -t: > $TMP/test_29.dk
		log "dumped log to $TMP/test_29.dk (bug 5793)"
		return 2
	fi
	if [ "$LOCKUNUSEDCOUNTCURRENT" -gt "$LOCKUNUSEDCOUNTORIG" ]; then
		error "UNUSED: $LOCKUNUSEDCOUNTCURRENT > $LOCKUNUSEDCOUNTORIG"
		$LCTL dk | sort -k4 -t: > $TMP/test_29.dk
		log "dumped log to $TMP/test_29.dk (bug 5793)"
		return 3
	fi
}
run_test 29 "IT_GETATTR regression  ============================"

test_30a() { # was test_30
	cp `which ls` $DIR || cp /bin/ls $DIR
	$DIR/ls / || error
	rm $DIR/ls
}
run_test 30a "execute binary from Lustre (execve) =============="

test_30b() {
	cp `which ls` $DIR || cp /bin/ls $DIR
	chmod go+rx $DIR/ls
	$RUNAS $DIR/ls / || error
	rm $DIR/ls
}
run_test 30b "execute binary from Lustre as non-root ==========="

test_30c() { # b=22376
	cp `which ls` $DIR || cp /bin/ls $DIR
	chmod a-rw $DIR/ls
	cancel_lru_locks mdc
	cancel_lru_locks osc
	$RUNAS $DIR/ls / || error
	rm -f $DIR/ls
}
run_test 30c "execute binary from Lustre without read perms ===="

test_31a() {
	$OPENUNLINK $DIR/f31 $DIR/f31 || error
	$CHECKSTAT -a $DIR/f31 || error
}
run_test 31a "open-unlink file =================================="

test_31b() {
	touch $DIR/f31 || error
	ln $DIR/f31 $DIR/f31b || error
	multiop $DIR/f31b Ouc || error
	$CHECKSTAT -t file $DIR/f31 || error
}
run_test 31b "unlink file with multiple links while open ======="

test_31c() {
	touch $DIR/f31 || error
	ln $DIR/f31 $DIR/f31c || error
	multiop_bg_pause $DIR/f31 O_uc || return 1
	MULTIPID=$!
	multiop $DIR/f31c Ouc
	kill -USR1 $MULTIPID
	wait $MULTIPID
}
run_test 31c "open-unlink file with multiple links ============="

test_31d() {
	opendirunlink $DIR/d31d $DIR/d31d || error
	$CHECKSTAT -a $DIR/d31d || error
}
run_test 31d "remove of open directory ========================="

test_31e() { # bug 2904
	check_kernel_version 34 || return 0
	openfilleddirunlink $DIR/d31e || error
}
run_test 31e "remove of open non-empty directory ==============="

test_31f() { # bug 4554
	set -vx
	mkdir $DIR/d31f
	$SETSTRIPE $DIR/d31f -s 1048576 -c 1
	cp /etc/hosts $DIR/d31f
	ls -l $DIR/d31f
	$GETSTRIPE $DIR/d31f/hosts
	multiop_bg_pause $DIR/d31f D_c || return 1
	MULTIPID=$!

	rm -rv $DIR/d31f || error "first of $DIR/d31f"
	mkdir $DIR/d31f
	$SETSTRIPE $DIR/d31f -s 1048576 -c 1
	cp /etc/hosts $DIR/d31f
	ls -l $DIR/d31f
	$GETSTRIPE $DIR/d31f/hosts
	multiop_bg_pause $DIR/d31f D_c || return 1
	MULTIPID2=$!

	kill -USR1 $MULTIPID || error "first opendir $MULTIPID not running"
	wait $MULTIPID || error "first opendir $MULTIPID failed"

	sleep 6

	kill -USR1 $MULTIPID2 || error "second opendir $MULTIPID not running"
	wait $MULTIPID2 || error "second opendir $MULTIPID2 failed"
	set +vx
}
run_test 31f "remove of open directory with open-unlink file ==="

test_31g() {
        echo "-- cross directory link --"
        mkdir $DIR/d31g{a,b}
        touch $DIR/d31ga/f
        ln $DIR/d31ga/f $DIR/d31gb/g
        $CHECKSTAT -t file $DIR/d31ga/f || error "source"
        [ `stat -c%h $DIR/d31ga/f` == '2' ] || error "source nlink"
        $CHECKSTAT -t file $DIR/d31gb/g || error "target"
        [ `stat -c%h $DIR/d31gb/g` == '2' ] || error "target nlink"
}
run_test 31g "cross directory link==============="

test_31h() {
        echo "-- cross directory link --"
        mkdir $DIR/d31h
        mkdir $DIR/d31h/dir
        touch $DIR/d31h/f
        ln $DIR/d31h/f $DIR/d31h/dir/g
        $CHECKSTAT -t file $DIR/d31h/f || error "source"
        [ `stat -c%h $DIR/d31h/f` == '2' ] || error "source nlink"
        $CHECKSTAT -t file $DIR/d31h/dir/g || error "target"
        [ `stat -c%h $DIR/d31h/dir/g` == '2' ] || error "target nlink"
}
run_test 31h "cross directory link under child==============="

test_31i() {
        echo "-- cross directory link --"
        mkdir $DIR/d31i
        mkdir $DIR/d31i/dir
        touch $DIR/d31i/dir/f
        ln $DIR/d31i/dir/f $DIR/d31i/g
        $CHECKSTAT -t file $DIR/d31i/dir/f || error "source"
        [ `stat -c%h $DIR/d31i/dir/f` == '2' ] || error "source nlink"
        $CHECKSTAT -t file $DIR/d31i/g || error "target"
        [ `stat -c%h $DIR/d31i/g` == '2' ] || error "target nlink"
}
run_test 31i "cross directory link under parent==============="


test_31j() {
        mkdir $DIR/d31j
        mkdir $DIR/d31j/dir1
        ln $DIR/d31j/dir1 $DIR/d31j/dir2 && error "ln for dir"
        link $DIR/d31j/dir1 $DIR/d31j/dir3 && error "link for dir"
        mlink $DIR/d31j/dir1 $DIR/d31j/dir4 && error "mlink for dir"
        mlink $DIR/d31j/dir1 $DIR/d31j/dir1 && error "mlink to the same dir"
	return 0
}
run_test 31j "link for directory==============="


test_31k() {
        mkdir $DIR/d31k
        touch $DIR/d31k/s
        touch $DIR/d31k/exist
        mlink $DIR/d31k/s $DIR/d31k/t || error "mlink"
        mlink $DIR/d31k/s $DIR/d31k/exist && error "mlink to exist file"
        mlink $DIR/d31k/s $DIR/d31k/s && error "mlink to the same file"
        mlink $DIR/d31k/s $DIR/d31k && error "mlink to parent dir"
        mlink $DIR/d31k $DIR/d31k/s && error "mlink parent dir to target"
        mlink $DIR/d31k/not-exist $DIR/d31k/foo && error "mlink non-existing to new"
        mlink $DIR/d31k/not-exist $DIR/d31k/s && error "mlink non-existing to exist"
	return 0
}
run_test 31k "link to file: the same, non-existing, dir==============="

test_31m() {
        mkdir $DIR/d31m
        touch $DIR/d31m/s
        mkdir $DIR/d31m2
        touch $DIR/d31m2/exist
        mlink $DIR/d31m/s $DIR/d31m2/t || error "mlink"
        mlink $DIR/d31m/s $DIR/d31m2/exist && error "mlink to exist file"
        mlink $DIR/d31m/s $DIR/d31m2 && error "mlink to parent dir"
        mlink $DIR/d31m2 $DIR/d31m/s && error "mlink parent dir to target"
        mlink $DIR/d31m/not-exist $DIR/d31m2/foo && error "mlink non-existing to new"
        mlink $DIR/d31m/not-exist $DIR/d31m2/s && error "mlink non-existing to exist"
	return 0
}
run_test 31m "link to file: the same, non-existing, dir==============="

test_32a() {
	echo "== more mountpoints and symlinks ================="
	[ -e $DIR/d32a ] && rm -fr $DIR/d32a
	mkdir -p $DIR/d32a/ext2-mountpoint
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32a/ext2-mountpoint || error
	$CHECKSTAT -t dir $DIR/d32a/ext2-mountpoint/.. || error
	$UMOUNT $DIR/d32a/ext2-mountpoint || error
}
run_test 32a "stat d32a/ext2-mountpoint/.. ====================="

test_32b() {
	[ -e $DIR/d32b ] && rm -fr $DIR/d32b
	mkdir -p $DIR/d32b/ext2-mountpoint
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32b/ext2-mountpoint || error
	ls -al $DIR/d32b/ext2-mountpoint/.. || error
	$UMOUNT $DIR/d32b/ext2-mountpoint || error
}
run_test 32b "open d32b/ext2-mountpoint/.. ====================="

test_32c() {
	[ -e $DIR/d32c ] && rm -fr $DIR/d32c
	mkdir -p $DIR/d32c/ext2-mountpoint
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32c/ext2-mountpoint || error
	mkdir -p $DIR/d32c/d2/test_dir
	$CHECKSTAT -t dir $DIR/d32c/ext2-mountpoint/../d2/test_dir || error
	$UMOUNT $DIR/d32c/ext2-mountpoint || error
}
run_test 32c "stat d32c/ext2-mountpoint/../d2/test_dir ========="

test_32d() {
	[ -e $DIR/d32d ] && rm -fr $DIR/d32d
	mkdir -p $DIR/d32d/ext2-mountpoint
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32d/ext2-mountpoint || error
	mkdir -p $DIR/d32d/d2/test_dir
	ls -al $DIR/d32d/ext2-mountpoint/../d2/test_dir || error
	$UMOUNT $DIR/d32d/ext2-mountpoint || error
}
run_test 32d "open d32d/ext2-mountpoint/../d2/test_dir ========="

test_32e() {
	[ -e $DIR/d32e ] && rm -fr $DIR/d32e
	mkdir -p $DIR/d32e/tmp
	TMP_DIR=$DIR/d32e/tmp
	ln -s $DIR/d32e $TMP_DIR/symlink11
	ln -s $TMP_DIR/symlink11 $TMP_DIR/../symlink01
	$CHECKSTAT -t link $DIR/d32e/tmp/symlink11 || error
	$CHECKSTAT -t link $DIR/d32e/symlink01 || error
}
run_test 32e "stat d32e/symlink->tmp/symlink->lustre-subdir ===="

test_32f() {
	[ -e $DIR/d32f ] && rm -fr $DIR/d32f
	mkdir -p $DIR/d32f/tmp
	TMP_DIR=$DIR/d32f/tmp
	ln -s $DIR/d32f $TMP_DIR/symlink11
	ln -s $TMP_DIR/symlink11 $TMP_DIR/../symlink01
	ls $DIR/d32f/tmp/symlink11  || error
	ls $DIR/d32f/symlink01 || error
}
run_test 32f "open d32f/symlink->tmp/symlink->lustre-subdir ===="

test_32g() {
	TMP_DIR=$DIR/$tdir/tmp
	mkdir -p $TMP_DIR $DIR/${tdir}2
	ln -s $DIR/${tdir}2 $TMP_DIR/symlink12
	ln -s $TMP_DIR/symlink12 $TMP_DIR/../symlink02
	$CHECKSTAT -t link $TMP_DIR/symlink12 || error
	$CHECKSTAT -t link $DIR/$tdir/symlink02 || error
	$CHECKSTAT -t dir -f $TMP_DIR/symlink12 || error
	$CHECKSTAT -t dir -f $DIR/$tdir/symlink02 || error
}
run_test 32g "stat d32g/symlink->tmp/symlink->lustre-subdir/${tdir}2"

test_32h() {
	rm -fr $DIR/$tdir $DIR/${tdir}2
	TMP_DIR=$DIR/$tdir/tmp
	mkdir -p $TMP_DIR $DIR/${tdir}2
	ln -s $DIR/${tdir}2 $TMP_DIR/symlink12
	ln -s $TMP_DIR/symlink12 $TMP_DIR/../symlink02
	ls $TMP_DIR/symlink12 || error
	ls $DIR/$tdir/symlink02  || error
}
run_test 32h "open d32h/symlink->tmp/symlink->lustre-subdir/${tdir}2"

test_32i() {
	[ -e $DIR/d32i ] && rm -fr $DIR/d32i
	mkdir -p $DIR/d32i/ext2-mountpoint
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32i/ext2-mountpoint || error
	touch $DIR/d32i/test_file
	$CHECKSTAT -t file $DIR/d32i/ext2-mountpoint/../test_file || error
	$UMOUNT $DIR/d32i/ext2-mountpoint || error
}
run_test 32i "stat d32i/ext2-mountpoint/../test_file ==========="

test_32j() {
	[ -e $DIR/d32j ] && rm -fr $DIR/d32j
	mkdir -p $DIR/d32j/ext2-mountpoint
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32j/ext2-mountpoint || error
	touch $DIR/d32j/test_file
	cat $DIR/d32j/ext2-mountpoint/../test_file || error
	$UMOUNT $DIR/d32j/ext2-mountpoint || error
}
run_test 32j "open d32j/ext2-mountpoint/../test_file ==========="

test_32k() {
	rm -fr $DIR/d32k
	mkdir -p $DIR/d32k/ext2-mountpoint
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32k/ext2-mountpoint
	mkdir -p $DIR/d32k/d2
	touch $DIR/d32k/d2/test_file || error
	$CHECKSTAT -t file $DIR/d32k/ext2-mountpoint/../d2/test_file || error
	$UMOUNT $DIR/d32k/ext2-mountpoint || error
}
run_test 32k "stat d32k/ext2-mountpoint/../d2/test_file ========"

test_32l() {
	rm -fr $DIR/d32l
	mkdir -p $DIR/d32l/ext2-mountpoint
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32l/ext2-mountpoint || error
	mkdir -p $DIR/d32l/d2
	touch $DIR/d32l/d2/test_file
	cat  $DIR/d32l/ext2-mountpoint/../d2/test_file || error
	$UMOUNT $DIR/d32l/ext2-mountpoint || error
}
run_test 32l "open d32l/ext2-mountpoint/../d2/test_file ========"

test_32m() {
	rm -fr $DIR/d32m
	mkdir -p $DIR/d32m/tmp
	TMP_DIR=$DIR/d32m/tmp
	ln -s $DIR $TMP_DIR/symlink11
	ln -s $TMP_DIR/symlink11 $TMP_DIR/../symlink01
	$CHECKSTAT -t link $DIR/d32m/tmp/symlink11 || error
	$CHECKSTAT -t link $DIR/d32m/symlink01 || error
}
run_test 32m "stat d32m/symlink->tmp/symlink->lustre-root ======"

test_32n() {
	rm -fr $DIR/d32n
	mkdir -p $DIR/d32n/tmp
	TMP_DIR=$DIR/d32n/tmp
	ln -s $DIR $TMP_DIR/symlink11
	ln -s $TMP_DIR/symlink11 $TMP_DIR/../symlink01
	ls -l $DIR/d32n/tmp/symlink11  || error
	ls -l $DIR/d32n/symlink01 || error
}
run_test 32n "open d32n/symlink->tmp/symlink->lustre-root ======"

test_32o() {
	rm -fr $DIR/d32o $DIR/$tfile
	touch $DIR/$tfile
	mkdir -p $DIR/d32o/tmp
	TMP_DIR=$DIR/d32o/tmp
	ln -s $DIR/$tfile $TMP_DIR/symlink12
	ln -s $TMP_DIR/symlink12 $TMP_DIR/../symlink02
	$CHECKSTAT -t link $DIR/d32o/tmp/symlink12 || error
	$CHECKSTAT -t link $DIR/d32o/symlink02 || error
	$CHECKSTAT -t file -f $DIR/d32o/tmp/symlink12 || error
	$CHECKSTAT -t file -f $DIR/d32o/symlink02 || error
}
run_test 32o "stat d32o/symlink->tmp/symlink->lustre-root/$tfile"

test_32p() {
    log 32p_1
	rm -fr $DIR/d32p
    log 32p_2
	rm -f $DIR/$tfile
    log 32p_3
	touch $DIR/$tfile
    log 32p_4
	mkdir -p $DIR/d32p/tmp
    log 32p_5
	TMP_DIR=$DIR/d32p/tmp
    log 32p_6
	ln -s $DIR/$tfile $TMP_DIR/symlink12
    log 32p_7
	ln -s $TMP_DIR/symlink12 $TMP_DIR/../symlink02
    log 32p_8
	cat $DIR/d32p/tmp/symlink12 || error
    log 32p_9
	cat $DIR/d32p/symlink02 || error
    log 32p_10
}
run_test 32p "open d32p/symlink->tmp/symlink->lustre-root/$tfile"

test_32q() {
	[ -e $DIR/d32q ] && rm -fr $DIR/d32q
	mkdir -p $DIR/d32q
        touch $DIR/d32q/under_the_mount
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32q
	ls $DIR/d32q/under_the_mount && error || true
	$UMOUNT $DIR/d32q || error
}
run_test 32q "stat follows mountpoints in Lustre (should return error)"

test_32r() {
	[ -e $DIR/d32r ] && rm -fr $DIR/d32r
	mkdir -p $DIR/d32r
        touch $DIR/d32r/under_the_mount
	mount -t ext2 -o loop $EXT2_DEV $DIR/d32r
	ls $DIR/d32r | grep -q under_the_mount && error || true
	$UMOUNT $DIR/d32r || error
}
run_test 32r "opendir follows mountpoints in Lustre (should return error)"

test_33() {
	rm -f $DIR/$tfile
	touch $DIR/$tfile
	chmod 444 $DIR/$tfile
	chown $RUNAS_ID $DIR/$tfile
	log 33_1
	$RUNAS $OPENFILE -f O_RDWR $DIR/$tfile && error || true
	log 33_2
}
run_test 33 "write file with mode 444 (should return error) ===="

test_33a() {
        rm -fr $DIR/d33
        mkdir -p $DIR/d33
        chown $RUNAS_ID $DIR/d33
        $RUNAS $OPENFILE -f O_RDWR:O_CREAT -m 0444 $DIR/d33/f33|| error "create"
        $RUNAS $OPENFILE -f O_RDWR:O_CREAT -m 0444 $DIR/d33/f33 && \
		error "open RDWR" || true
}
run_test 33a "test open file(mode=0444) with O_RDWR (should return error)"

test_33b() {
        rm -fr $DIR/d33
        mkdir -p $DIR/d33
        chown $RUNAS_ID $DIR/d33
        $RUNAS $OPENFILE -f 1286739555 $DIR/d33/f33 && error "create" || true
}
run_test 33b "test open file with malformed flags (No panic and return error)"

test_33c() {
        local ostnum
        local ostname
        local write_bytes
        local all_zeros

        all_zeros=:
        rm -fr $DIR/d33
        mkdir -p $DIR/d33
        # Read: 0, Write: 4, create/destroy: 2/0, stat: 1, punch: 0

        sync
        for ostnum in $(seq $OSTCOUNT); do
                # test-framework's OST numbering is one-based, while Lustre's
                # is zero-based
                ostname=$(printf "$FSNAME-OST%.4d" $((ostnum - 1)))
                # Parsing llobdstat's output sucks; we could grep the /proc
                # path, but that's likely to not be as portable as using the
                # llobdstat utility.  So we parse lctl output instead.
                write_bytes=$(do_facet ost$ostnum lctl get_param -n \
                        obdfilter/$ostname/stats |
                        awk '/^write_bytes/ {print $7}' )
                echo "baseline_write_bytes@$OSTnum/$ostname=$write_bytes"
                if (( ${write_bytes:-0} > 0 ))
                then
                        all_zeros=false
                        break;
                fi
        done

        $all_zeros || return 0

        # Write four bytes
        echo foo > $DIR/d33/bar
        # Really write them
        sync

        # Total up write_bytes after writing.  We'd better find non-zeros.
        for ostnum in $(seq $OSTCOUNT); do
                ostname=$(printf "$FSNAME-OST%.4d" $((ostnum - 1)))
                write_bytes=$(do_facet ost$ostnum lctl get_param -n \
                        obdfilter/$ostname/stats |
                        awk '/^write_bytes/ {print $7}' )
                echo "write_bytes@$OSTnum/$ostname=$write_bytes"
                if (( ${write_bytes:-0} > 0 ))
                then
                        all_zeros=false
                        break;
                fi
        done

        if $all_zeros
        then
                for ostnum in $(seq $OSTCOUNT); do
                        ostname=$(printf "$FSNAME-OST%.4d" $((ostnum - 1)))
                        echo "Check that write_bytes is present in obdfilter/*/stats:"
                        do_facet ost$ostnum lctl get_param -n \
                                obdfilter/$ostname/stats
                done
                error "OST not keeping write_bytes stats (b22312)"
        fi
}
run_test 33c "test llobdstat and write_bytes"

TEST_34_SIZE=${TEST_34_SIZE:-2000000000000}
test_34a() {
	rm -f $DIR/f34
	$MCREATE $DIR/f34 || error
	$GETSTRIPE $DIR/f34 2>&1 | grep -q "no stripe info" || error
	$TRUNCATE $DIR/f34 $TEST_34_SIZE || error
	$GETSTRIPE $DIR/f34 2>&1 | grep -q "no stripe info" || error
	$CHECKSTAT -s $TEST_34_SIZE $DIR/f34 || error
}
run_test 34a "truncate file that has not been opened ==========="

test_34b() {
	[ ! -f $DIR/f34 ] && test_34a
	$CHECKSTAT -s $TEST_34_SIZE $DIR/f34 || error
	$OPENFILE -f O_RDONLY $DIR/f34
	$GETSTRIPE $DIR/f34 2>&1 | grep -q "no stripe info" || error
	$CHECKSTAT -s $TEST_34_SIZE $DIR/f34 || error
}
run_test 34b "O_RDONLY opening file doesn't create objects ====="

test_34c() {
	[ ! -f $DIR/f34 ] && test_34a
	$CHECKSTAT -s $TEST_34_SIZE $DIR/f34 || error
	$OPENFILE -f O_RDWR $DIR/f34
	$GETSTRIPE $DIR/f34 2>&1 | grep -q "no stripe info" && error
	$CHECKSTAT -s $TEST_34_SIZE $DIR/f34 || error
}
run_test 34c "O_RDWR opening file-with-size works =============="

test_34d() {
	[ ! -f $DIR/f34 ] && test_34a
	dd if=/dev/zero of=$DIR/f34 conv=notrunc bs=4k count=1 || error
	$CHECKSTAT -s $TEST_34_SIZE $DIR/f34 || error
	rm $DIR/f34
}
run_test 34d "write to sparse file ============================="

test_34e() {
	rm -f $DIR/f34e
	$MCREATE $DIR/f34e || error
	$TRUNCATE $DIR/f34e 1000 || error
	$CHECKSTAT -s 1000 $DIR/f34e || error
	$OPENFILE -f O_RDWR $DIR/f34e
	$CHECKSTAT -s 1000 $DIR/f34e || error
}
run_test 34e "create objects, some with size and some without =="

test_34f() { # bug 6242, 6243
	SIZE34F=48000
	rm -f $DIR/f34f
	$MCREATE $DIR/f34f || error
	$TRUNCATE $DIR/f34f $SIZE34F || error "truncating $DIR/f3f to $SIZE34F"
	dd if=$DIR/f34f of=$TMP/f34f
	$CHECKSTAT -s $SIZE34F $TMP/f34f || error "$TMP/f34f not $SIZE34F bytes"
	dd if=/dev/zero of=$TMP/f34fzero bs=$SIZE34F count=1
	cmp $DIR/f34f $TMP/f34fzero || error "$DIR/f34f not all zero"
	cmp $TMP/f34f $TMP/f34fzero || error "$TMP/f34f not all zero"
	rm $TMP/f34f $TMP/f34fzero $DIR/f34f
}
run_test 34f "read from a file with no objects until EOF ======="

test_34g() {
	dd if=/dev/zero of=$DIR/$tfile bs=1 count=100 seek=$TEST_34_SIZE || error
	$TRUNCATE $DIR/$tfile $((TEST_34_SIZE / 2))|| error
	$CHECKSTAT -s $((TEST_34_SIZE / 2)) $DIR/$tfile || error "truncate failed"
	cancel_lru_locks osc
	$CHECKSTAT -s $((TEST_34_SIZE / 2)) $DIR/$tfile || \
		error "wrong size after lock cancel"

	$TRUNCATE $DIR/$tfile $TEST_34_SIZE || error
	$CHECKSTAT -s $TEST_34_SIZE $DIR/$tfile || \
		error "expanding truncate failed"
	cancel_lru_locks osc
	$CHECKSTAT -s $TEST_34_SIZE $DIR/$tfile || \
		error "wrong expanded size after lock cancel"
}
run_test 34g "truncate long file ==============================="

test_35a() {
	cp /bin/sh $DIR/f35a
	chmod 444 $DIR/f35a
	chown $RUNAS_ID $DIR/f35a
	$RUNAS $DIR/f35a && error || true
	rm $DIR/f35a
}
run_test 35a "exec file with mode 444 (should return and not leak) ====="

test_36a() {
	rm -f $DIR/f36
	utime $DIR/f36 || error
}
run_test 36a "MDS utime check (mknod, utime) ==================="

test_36b() {
	echo "" > $DIR/f36
	utime $DIR/f36 || error
}
run_test 36b "OST utime check (open, utime) ===================="

test_36c() {
	rm -f $DIR/d36/f36
	mkdir $DIR/d36
	chown $RUNAS_ID $DIR/d36
	$RUNAS utime $DIR/d36/f36 || error
}
run_test 36c "non-root MDS utime check (mknod, utime) =========="

test_36d() {
	[ ! -d $DIR/d36 ] && test_36c
	echo "" > $DIR/d36/f36
	$RUNAS utime $DIR/d36/f36 || error
}
run_test 36d "non-root OST utime check (open, utime) ==========="

test_36e() {
	[ $RUNAS_ID -eq $UID ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return
	mkdir -p $DIR/$tdir
	touch $DIR/$tdir/$tfile
	$RUNAS utime $DIR/$tdir/$tfile && \
		error "utime worked, expected failure" || true
}
run_test 36e "utime on non-owned file (should return error) ===="

subr_36fh() {
	local fl="$1"
	local LANG_SAVE=$LANG
	local LC_LANG_SAVE=$LC_LANG
	export LANG=C LC_LANG=C # for date language

	DATESTR="Dec 20  2000"
	mkdir -p $DIR/$tdir
	lctl set_param fail_loc=$fl
	date; date +%s
	cp /etc/hosts $DIR/$tdir/$tfile
	sync & # write RPC generated with "current" inode timestamp, but delayed
	sleep 1
	touch --date="$DATESTR" $DIR/$tdir/$tfile # setattr timestamp in past
	LS_BEFORE="`ls -l $DIR/$tdir/$tfile`" # old timestamp from client cache
	cancel_lru_locks osc
	LS_AFTER="`ls -l $DIR/$tdir/$tfile`"  # timestamp from OST object
	date; date +%s
	[ "$LS_BEFORE" != "$LS_AFTER" ] && \
		echo "BEFORE: $LS_BEFORE" && \
		echo "AFTER : $LS_AFTER" && \
		echo "WANT  : $DATESTR" && \
		error "$DIR/$tdir/$tfile timestamps changed" || true

	export LANG=$LANG_SAVE LC_LANG=$LC_LANG_SAVE
}

test_36f() {
	#define OBD_FAIL_OST_BRW_PAUSE_BULK 0x214
	subr_36fh "0x80000214"
}
run_test 36f "utime on file racing with OST BRW write =========="

test_36g() {
	remote_ost_nodsh && skip "remote OST with nodsh" && return
	local fmd_max_age
	local fmd_before
	local fmd_after

	mkdir -p $DIR/$tdir
	fmd_max_age=$(do_facet ost1 \
		"lctl get_param -n obdfilter.*.client_cache_seconds 2> /dev/null | \
		head -n 1")

	fmd_before=$(do_facet ost1 \
		"awk '/ll_fmd_cache/ {print \\\$2}' /proc/slabinfo")
	touch $DIR/$tdir/$tfile
	sleep $((fmd_max_age + 12))
	fmd_after=$(do_facet ost1 \
		"awk '/ll_fmd_cache/ {print \\\$2}' /proc/slabinfo")

	echo "fmd_before: $fmd_before"
	echo "fmd_after: $fmd_after"
	[ "$fmd_after" -gt "$fmd_before" ] && \
		echo "AFTER: $fmd_after > BEFORE: $fmd_before" && \
		error "fmd didn't expire after ping" || true
}
run_test 36g "filter mod data cache expiry ====================="

test_36h() {
	#define OBD_FAIL_OST_BRW_PAUSE_BULK2 0x227
	subr_36fh "0x80000227"
}
run_test 36h "utime on file racing with OST BRW write =========="

test_37() {
	mkdir -p $DIR/$tdir
	echo f > $DIR/$tdir/fbugfile
	mount -t ext2 -o loop $EXT2_DEV $DIR/$tdir
	ls $DIR/$tdir | grep "\<fbugfile\>" && error
	$UMOUNT $DIR/$tdir || error
	rm -f $DIR/$tdir/fbugfile || error
}
run_test 37 "ls a mounted file system to check old content ====="

test_38() {
	local file=$DIR/$tfile
	touch $file
	openfile -f O_DIRECTORY $file
	local RC=$?
	local ENOTDIR=20
	[ $RC -eq 0 ] && error "opened file $file with O_DIRECTORY" || true
	[ $RC -eq $ENOTDIR ] || error "error $RC should be ENOTDIR ($ENOTDIR)"
}
run_test 38 "open a regular file with O_DIRECTORY should return -ENOTDIR ==="

test_39() {
	touch $DIR/$tfile
	touch $DIR/${tfile}2
#	ls -l  $DIR/$tfile $DIR/${tfile}2
#	ls -lu  $DIR/$tfile $DIR/${tfile}2
#	ls -lc  $DIR/$tfile $DIR/${tfile}2
	sleep 2
	$OPENFILE -f O_CREAT:O_TRUNC:O_WRONLY $DIR/${tfile}2
	if [ ! $DIR/${tfile}2 -nt $DIR/$tfile ]; then
		echo "mtime"
		ls -l --full-time $DIR/$tfile $DIR/${tfile}2
		echo "atime"
		ls -lu --full-time $DIR/$tfile $DIR/${tfile}2
		echo "ctime"
		ls -lc --full-time $DIR/$tfile $DIR/${tfile}2
		error "O_TRUNC didn't change timestamps"
	fi
}
run_test 39 "mtime changed on create ==========================="

test_39b() {
	mkdir -p $DIR/$tdir
	cp -p /etc/passwd $DIR/$tdir/fopen
	cp -p /etc/passwd $DIR/$tdir/flink
	cp -p /etc/passwd $DIR/$tdir/funlink
	cp -p /etc/passwd $DIR/$tdir/frename
	ln $DIR/$tdir/funlink $DIR/$tdir/funlink2

	sleep 1
	echo "aaaaaa" >> $DIR/$tdir/fopen
	echo "aaaaaa" >> $DIR/$tdir/flink
	echo "aaaaaa" >> $DIR/$tdir/funlink
	echo "aaaaaa" >> $DIR/$tdir/frename

	local open_new=`stat -c %Y $DIR/$tdir/fopen`
	local link_new=`stat -c %Y $DIR/$tdir/flink`
	local unlink_new=`stat -c %Y $DIR/$tdir/funlink`
	local rename_new=`stat -c %Y $DIR/$tdir/frename`

	cat $DIR/$tdir/fopen > /dev/null
	ln $DIR/$tdir/flink $DIR/$tdir/flink2
	rm -f $DIR/$tdir/funlink2
	mv -f $DIR/$tdir/frename $DIR/$tdir/frename2

	for (( i=0; i < 2; i++ )) ; do
		local open_new2=`stat -c %Y $DIR/$tdir/fopen`
		local link_new2=`stat -c %Y $DIR/$tdir/flink`
		local unlink_new2=`stat -c %Y $DIR/$tdir/funlink`
		local rename_new2=`stat -c %Y $DIR/$tdir/frename2`

		[ $open_new2 -eq $open_new ] || error "open file reverses mtime"
		[ $link_new2 -eq $link_new ] || error "link file reverses mtime"
		[ $unlink_new2 -eq $unlink_new ] || error "unlink file reverses mtime"
		[ $rename_new2 -eq $rename_new ] || error "rename file reverses mtime"

		cancel_lru_locks osc
		if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
	done
}
run_test 39b "mtime change on open, link, unlink, rename  ======"

# this should be set to past
TEST_39_MTIME=`date -d "1 year ago" +%s`

# bug 11063
test_39c() {
	touch $DIR1/$tfile
	sleep 2
	local mtime0=`stat -c %Y $DIR1/$tfile`

	touch -m -d @$TEST_39_MTIME $DIR1/$tfile
	local mtime1=`stat -c %Y $DIR1/$tfile`
	[ "$mtime1" = $TEST_39_MTIME ] || \
		error "mtime is not set to past: $mtime1, should be $TEST_39_MTIME"

	local d1=`date +%s`
	echo hello >> $DIR1/$tfile
	local d2=`date +%s`
	local mtime2=`stat -c %Y $DIR1/$tfile`
	[ "$mtime2" -ge "$d1" ] && [ "$mtime2" -le "$d2" ] || \
		error "mtime is not updated on write: $d1 <= $mtime2 <= $d2"

	mv $DIR1/$tfile $DIR1/$tfile-1

	for (( i=0; i < 2; i++ )) ; do
		local mtime3=`stat -c %Y $DIR1/$tfile-1`
		[ "$mtime2" = "$mtime3" ] || \
			error "mtime ($mtime2) changed (to $mtime3) on rename"

		cancel_lru_locks osc
		if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
	done
}
run_test 39c "mtime change on rename ==========================="

# bug 21114
test_39d() {
	touch $DIR1/$tfile

	touch -m -d @$TEST_39_MTIME $DIR1/$tfile

	for (( i=0; i < 2; i++ )) ; do
		local mtime=`stat -c %Y $DIR1/$tfile`
		[ $mtime = $TEST_39_MTIME ] || \
			error "mtime($mtime) is not set to $TEST_39_MTIME"

		cancel_lru_locks osc
		if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
	done
}
run_test 39d "create, utime, stat =============================="

# bug 21114
test_39e() {
	touch $DIR1/$tfile
	local mtime1=`stat -c %Y $DIR1/$tfile`

	touch -m -d @$TEST_39_MTIME $DIR1/$tfile

	for (( i=0; i < 2; i++ )) ; do
		local mtime2=`stat -c %Y $DIR1/$tfile`
		[ $mtime2 = $TEST_39_MTIME ] || \
			error "mtime($mtime2) is not set to $TEST_39_MTIME"

		cancel_lru_locks osc
		if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
	done
}
run_test 39e "create, stat, utime, stat ========================"

# bug 21114
test_39f() {
	touch $DIR1/$tfile
	mtime1=`stat -c %Y $DIR1/$tfile`

	sleep 2
	touch -m -d @$TEST_39_MTIME $DIR1/$tfile

	for (( i=0; i < 2; i++ )) ; do
		local mtime2=`stat -c %Y $DIR1/$tfile`
		[ $mtime2 = $TEST_39_MTIME ] || \
			error "mtime($mtime2) is not set to $TEST_39_MTIME"

		cancel_lru_locks osc
		if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
	done
}
run_test 39f "create, stat, sleep, utime, stat ================="

# bug 11063
test_39g() {
	echo hello >> $DIR1/$tfile
	local mtime1=`stat -c %Y $DIR1/$tfile`

	sleep 2
	chmod o+r $DIR1/$tfile

	for (( i=0; i < 2; i++ )) ; do
		local mtime2=`stat -c %Y $DIR1/$tfile`
		[ "$mtime1" = "$mtime2" ] || \
			error "lost mtime: $mtime2, should be $mtime1"

		cancel_lru_locks osc
		if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
	done
}
run_test 39g "write, chmod, stat ==============================="

# bug 11063
test_39h() {
	touch $DIR1/$tfile
	sleep 1

	local d1=`date`
	echo hello >> $DIR1/$tfile
	local mtime1=`stat -c %Y $DIR1/$tfile`

	touch -m -d @$TEST_39_MTIME $DIR1/$tfile
	local d2=`date`
	if [ "$d1" != "$d2" ]; then
		echo "write and touch not within one second"
	else
		for (( i=0; i < 2; i++ )) ; do
			local mtime2=`stat -c %Y $DIR1/$tfile`
			[ "$mtime2" = $TEST_39_MTIME ] || \
				error "lost mtime: $mtime2, should be $TEST_39_MTIME"

			cancel_lru_locks osc
			if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
		done
	fi
}
run_test 39h "write, utime within one second, stat ============="

test_39i() {
	touch $DIR1/$tfile
	sleep 1

	echo hello >> $DIR1/$tfile
	local mtime1=`stat -c %Y $DIR1/$tfile`

	mv $DIR1/$tfile $DIR1/$tfile-1

	for (( i=0; i < 2; i++ )) ; do
		local mtime2=`stat -c %Y $DIR1/$tfile-1`

		[ "$mtime1" = "$mtime2" ] || \
			error "lost mtime: $mtime2, should be $mtime1"

		cancel_lru_locks osc
		if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
	done
}
run_test 39i "write, rename, stat =============================="

test_39j() {
	touch $DIR1/$tfile
	sleep 1

	multiop_bg_pause $DIR1/$tfile oO_RDWR:w2097152_c || error "multiop failed"
	local multipid=$!
	local mtime1=`stat -c %Y $DIR1/$tfile`

	mv $DIR1/$tfile $DIR1/$tfile-1

	kill -USR1 $multipid
	wait $multipid || error "multiop close failed"

	for (( i=0; i < 2; i++ )) ; do
		local mtime2=`stat -c %Y $DIR1/$tfile-1`
		[ "$mtime1" = "$mtime2" ] || \
			error "mtime is lost on close: $mtime2, should be $mtime1"

		cancel_lru_locks osc
		if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
	done
}
run_test 39j "write, rename, close, stat ======================="

test_39k() {
	touch $DIR1/$tfile
	sleep 1

	multiop_bg_pause $DIR1/$tfile oO_RDWR:w2097152_c || error "multiop failed"
	local multipid=$!
	local mtime1=`stat -c %Y $DIR1/$tfile`

	touch -m -d @$TEST_39_MTIME $DIR1/$tfile

	kill -USR1 $multipid
	wait $multipid || error "multiop close failed"

	for (( i=0; i < 2; i++ )) ; do
		local mtime2=`stat -c %Y $DIR1/$tfile`

		[ "$mtime2" = $TEST_39_MTIME ] || \
			error "mtime is lost on close: $mtime2, should be $TEST_39_MTIME"

		cancel_lru_locks osc
		if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
	done
}
run_test 39k "write, utime, close, stat ========================"

# this should be set to future
TEST_39_ATIME=`date -d "1 year" +%s`

test_39l() {
	local atime_diff=$(do_facet $SINGLEMDS lctl get_param -n mdd.*.atime_diff)

	mkdir -p $DIR/$tdir

	# test setting directory atime to future
	touch -a -d @$TEST_39_ATIME $DIR/$tdir
	local atime=$(stat -c %X $DIR/$tdir)
	[ "$atime" = $TEST_39_ATIME ] || \
		error "atime is not set to future: $atime, should be $TEST_39_ATIME"

	# test setting directory atime from future to now
	local d1=$(date +%s)
	ls $DIR/$tdir
	local d2=$(date +%s)

	cancel_lru_locks mdc
	atime=$(stat -c %X $DIR/$tdir)
	[ "$atime" -ge "$d1" -a "$atime" -le "$d2" ] || \
		error "atime is not updated from future: $atime, should be $d1<atime<$d2"

	do_facet $SINGLEMDS lctl set_param -n mdd.*.atime_diff=2
	sleep 3

	# test setting directory atime when now > dir atime + atime_diff
	d1=$(date +%s)
	ls $DIR/$tdir
	d2=$(date +%s)
	cancel_lru_locks mdc
	atime=$(stat -c %X $DIR/$tdir)
	[ "$atime" -ge "$d1" -a "$atime" -le "$d2" ] || \
		error "atime is not updated  : $atime, should be $d2"

	do_facet $SINGLEMDS lctl set_param -n mdd.*.atime_diff=60
	sleep 3

	# test not setting directory atime when now < dir atime + atime_diff
	ls $DIR/$tdir
	cancel_lru_locks mdc
	atime=$(stat -c %X $DIR/$tdir)
	[ "$atime" -ge "$d1" -a "$atime" -le "$d2" ] || \
		error "atime is updated to $atime, should remain $d1<atime<$d2"

	do_facet $SINGLEMDS lctl set_param -n mdd.*.atime_diff=$atime_diff
}
run_test 39l "directory atime update ==========================="

test_39m() {
	touch $DIR1/$tfile
	sleep 2
	local far_past_mtime=$(date -d "May 29 1953" +%s)
	local far_past_atime=$(date -d "Dec 17 1903" +%s)

	touch -m -d @$far_past_mtime $DIR1/$tfile
	touch -a -d @$far_past_atime $DIR1/$tfile

	for (( i=0; i < 2; i++ )) ; do
		local timestamps=$(stat -c "%X %Y" $DIR1/$tfile)
		[ "$timestamps" = "$far_past_atime $far_past_mtime" ] || \
			error "atime or mtime set incorrectly"

		cancel_lru_locks osc
		if [ $i = 0 ] ; then echo "repeat after cancel_lru_locks"; fi
	done
}
run_test 39m "test atime and mtime before 1970"

test_40() {
	dd if=/dev/zero of=$DIR/f40 bs=4096 count=1
	$RUNAS $OPENFILE -f O_WRONLY:O_TRUNC $DIR/f40 && error
	$CHECKSTAT -t file -s 4096 $DIR/f40 || error
}
run_test 40 "failed open(O_TRUNC) doesn't truncate ============="

test_41() {
	# bug 1553
	small_write $DIR/f41 18
}
run_test 41 "test small file write + fstat ====================="

count_ost_writes() {
        lctl get_param -n osc.*.stats |
            awk -vwrites=0 '/ost_write/ { writes += $2 } END { print writes; }'
}

# decent default
WRITEBACK_SAVE=500
DIRTY_RATIO_SAVE=40
MAX_DIRTY_RATIO=50
BG_DIRTY_RATIO_SAVE=10
MAX_BG_DIRTY_RATIO=25

start_writeback() {
	trap 0
	# in 2.6, restore /proc/sys/vm/dirty_writeback_centisecs,
	# dirty_ratio, dirty_background_ratio
	if [ -f /proc/sys/vm/dirty_writeback_centisecs ]; then
		sysctl -w vm.dirty_writeback_centisecs=$WRITEBACK_SAVE
		sysctl -w vm.dirty_background_ratio=$BG_DIRTY_RATIO_SAVE
		sysctl -w vm.dirty_ratio=$DIRTY_RATIO_SAVE
	else
		# if file not here, we are a 2.4 kernel
		kill -CONT `pidof kupdated`
	fi
}

stop_writeback() {
	# setup the trap first, so someone cannot exit the test at the
	# exact wrong time and mess up a machine
	trap start_writeback EXIT
	# in 2.6, save and 0 /proc/sys/vm/dirty_writeback_centisecs
	if [ -f /proc/sys/vm/dirty_writeback_centisecs ]; then
		WRITEBACK_SAVE=`sysctl -n vm.dirty_writeback_centisecs`
		sysctl -w vm.dirty_writeback_centisecs=0
		sysctl -w vm.dirty_writeback_centisecs=0
		# save and increase /proc/sys/vm/dirty_ratio
		DIRTY_RATIO_SAVE=`sysctl -n vm.dirty_ratio`
		sysctl -w vm.dirty_ratio=$MAX_DIRTY_RATIO
		# save and increase /proc/sys/vm/dirty_background_ratio
		BG_DIRTY_RATIO_SAVE=`sysctl -n vm.dirty_background_ratio`
		sysctl -w vm.dirty_background_ratio=$MAX_BG_DIRTY_RATIO
	else
		# if file not here, we are a 2.4 kernel
		kill -STOP `pidof kupdated`
	fi
}

# ensure that all stripes have some grant before we test client-side cache
setup_test42() {
	for i in `seq -f $DIR/f42-%g 1 $OSTCOUNT`; do
		dd if=/dev/zero of=$i bs=4k count=1
		rm $i
	done
}

# Tests 42* verify that our behaviour is correct WRT caching, file closure,
# file truncation, and file removal.
test_42a() {
	setup_test42
	cancel_lru_locks osc
	stop_writeback
	sync; sleep 1; sync # just to be safe
	BEFOREWRITES=`count_ost_writes`
        lctl get_param -n osc.*[oO][sS][cC][_-]*.cur_grant_bytes | grep "[0-9]"
        dd if=/dev/zero of=$DIR/f42a bs=1024 count=100
	AFTERWRITES=`count_ost_writes`
	[ $BEFOREWRITES -eq $AFTERWRITES ] || \
		error "$BEFOREWRITES < $AFTERWRITES"
	start_writeback
}
run_test 42a "ensure that we don't flush on close =============="

test_42b() {
	setup_test42
	cancel_lru_locks osc
	stop_writeback
        sync
        dd if=/dev/zero of=$DIR/f42b bs=1024 count=100
        BEFOREWRITES=`count_ost_writes`
        $MUNLINK $DIR/f42b || error "$MUNLINK $DIR/f42b: $?"
        AFTERWRITES=`count_ost_writes`
        if [ $BEFOREWRITES -lt $AFTERWRITES ]; then
                error "$BEFOREWRITES < $AFTERWRITES on unlink"
        fi
        BEFOREWRITES=`count_ost_writes`
        sync || error "sync: $?"
        AFTERWRITES=`count_ost_writes`
        if [ $BEFOREWRITES -lt $AFTERWRITES ]; then
                error "$BEFOREWRITES < $AFTERWRITES on sync"
        fi
        dmesg | grep 'error from obd_brw_async' && error 'error writing back'
	start_writeback
        return 0
}
run_test 42b "test destroy of file with cached dirty data ======"

# if these tests just want to test the effect of truncation,
# they have to be very careful.  consider:
# - the first open gets a {0,EOF}PR lock
# - the first write conflicts and gets a {0, count-1}PW
# - the rest of the writes are under {count,EOF}PW
# - the open for truncate tries to match a {0,EOF}PR
#   for the filesize and cancels the PWs.
# any number of fixes (don't get {0,EOF} on open, match
# composite locks, do smarter file size management) fix
# this, but for now we want these tests to verify that
# the cancellation with truncate intent works, so we
# start the file with a full-file pw lock to match against
# until the truncate.
trunc_test() {
        test=$1
        file=$DIR/$test
        offset=$2
	cancel_lru_locks osc
	stop_writeback
	# prime the file with 0,EOF PW to match
	touch $file
        $TRUNCATE $file 0
        sync; sync
	# now the real test..
        dd if=/dev/zero of=$file bs=1024 count=100
        BEFOREWRITES=`count_ost_writes`
        $TRUNCATE $file $offset
        cancel_lru_locks osc
        AFTERWRITES=`count_ost_writes`
	start_writeback
}

test_42c() {
        trunc_test 42c 1024
        [ $BEFOREWRITES -eq $AFTERWRITES ] && \
            error "beforewrites $BEFOREWRITES == afterwrites $AFTERWRITES on truncate"
        rm $file
}
run_test 42c "test partial truncate of file with cached dirty data"

test_42d() {
        trunc_test 42d 0
        [ $BEFOREWRITES -eq $AFTERWRITES ] || \
            error "beforewrites $BEFOREWRITES != afterwrites $AFTERWRITES on truncate"
        rm $file
}
run_test 42d "test complete truncate of file with cached dirty data"

test_42e() { # bug22074
	local TDIR=$DIR/${tdir}e
	local pagesz=$(page_size)
	local pages=16
	local files=$((OSTCOUNT * 500))	# hopefully 500 files on each OST
	local proc_osc0="osc.${FSNAME}-OST0000-osc-[^MDT]*"
	local max_dirty_mb
	local warmup_files

	mkdir -p $TDIR
	$LFS setstripe -c 1 $TDIR
	createmany -o $TDIR/f $files

	max_dirty_mb=$($LCTL get_param -n $proc_osc0/max_dirty_mb)

	# we assume that with $OSTCOUNT files, at least one of them will
	# be allocated on OST0.
	warmup_files=$((OSTCOUNT * max_dirty_mb))
	createmany -o $TDIR/w $warmup_files

	# write a large amount of data into one file and sync, to get good
	# avail_grant number from OST.
	for ((i=0; i<$warmup_files; i++)); do
		idx=$($LFS getstripe -i $TDIR/w$i)
		[ $idx -ne 0 ] && continue
		dd if=/dev/zero of=$TDIR/w$i bs="$max_dirty_mb"M count=1
		break
	done
	[ $i -gt $warmup_files ] && error "OST0 is still cold"
	sync
	$LCTL get_param $proc_osc0/cur_dirty_bytes
	$LCTL get_param $proc_osc0/cur_grant_bytes

	# create as much dirty pages as we can while not to trigger the actual
	# RPCs directly. but depends on the env, VFS may trigger flush during this
	# period, hopefully we are good.
	for ((i=0; i<$warmup_files; i++)); do
		idx=$($LFS getstripe -i $TDIR/w$i)
		[ $idx -ne 0 ] && continue
		dd if=/dev/zero of=$TDIR/w$i bs=1M count=1 2>/dev/null
	done
	$LCTL get_param $proc_osc0/cur_dirty_bytes
	$LCTL get_param $proc_osc0/cur_grant_bytes

	# perform the real test
	$LCTL set_param $proc_osc0/rpc_stats 0
	for ((;i<$files; i++)); do
		[ $($LFS getstripe -i $TDIR/f$i) -eq 0 ] || continue
		dd if=/dev/zero of=$TDIR/f$i bs=$pagesz count=$pages 2>/dev/null
	done
	sync
	$LCTL get_param $proc_osc0/rpc_stats

	$LCTL get_param $proc_osc0/rpc_stats |
		while read PPR RRPC RPCT RCUM BAR WRPC WPCT WCUM; do
			[ "$PPR" != "16:" ] && continue
			[ $WPCT -lt 85 ] && error "$pages-page write RPCs only $WPCT% < 85%"
			break # we only want the "pages per rpc" stat
		done
	rm -rf $TDIR
}
run_test 42e "verify sub-RPC writes are not done synchronously"

test_43() {
	mkdir -p $DIR/$tdir
	cp -p /bin/ls $DIR/$tdir/$tfile
	multiop $DIR/$tdir/$tfile Ow_c &
	pid=$!
	# give multiop a chance to open
	sleep 1

	$DIR/$tdir/$tfile && error || true
	kill -USR1 $pid
}
run_test 43 "execution of file opened for write should return -ETXTBSY"

test_43a() {
        mkdir -p $DIR/d43
	cp -p `which multiop` $DIR/d43/multiop || cp -p multiop $DIR/d43/multiop
        MULTIOP_PROG=$DIR/d43/multiop multiop_bg_pause $TMP/test43.junk O_c || return 1
        MULTIOP_PID=$!
        multiop $DIR/d43/multiop Oc && error "expected error, got success"
        kill -USR1 $MULTIOP_PID || return 2
        wait $MULTIOP_PID || return 3
        rm $TMP/test43.junk
}
run_test 43a "open(RDWR) of file being executed should return -ETXTBSY"

test_43b() {
        mkdir -p $DIR/d43
	cp -p `which multiop` $DIR/d43/multiop || cp -p multiop $DIR/d43/multiop
        MULTIOP_PROG=$DIR/d43/multiop multiop_bg_pause $TMP/test43.junk O_c || return 1
        MULTIOP_PID=$!
        $TRUNCATE $DIR/d43/multiop 0 && error "expected error, got success"
        kill -USR1 $MULTIOP_PID || return 2
        wait $MULTIOP_PID || return 3
        rm $TMP/test43.junk
}
run_test 43b "truncate of file being executed should return -ETXTBSY"

test_43c() {
	local testdir="$DIR/d43c"
	mkdir -p $testdir
	cp $SHELL $testdir/
	( cd $(dirname $SHELL) && md5sum $(basename $SHELL) ) | \
		( cd $testdir && md5sum -c)
}
run_test 43c "md5sum of copy into lustre========================"

test_44() {
	[  "$OSTCOUNT" -lt "2" ] && skip_env "skipping 2-stripe test" && return
	dd if=/dev/zero of=$DIR/f1 bs=4k count=1 seek=1023
	dd if=$DIR/f1 bs=4k count=1 > /dev/null
}
run_test 44 "zero length read from a sparse stripe ============="

test_44a() {
    local nstripe=`$LCTL lov_getconfig $DIR | grep default_stripe_count: | \
                         awk '{print $2}'`
    [ -z "$nstripe" ] && skip "can't get stripe info" && return
    [ "$nstripe" -gt "$OSTCOUNT" ] && skip "Wrong default_stripe_count: $nstripe (OSTCOUNT: $OSTCOUNT)" && return
    local stride=`$LCTL lov_getconfig $DIR | grep default_stripe_size: | \
                      awk '{print $2}'`
    if [ $nstripe -eq 0 -o $nstripe -eq -1 ] ; then
        nstripe=`$LCTL lov_getconfig $DIR | grep obd_count: | awk '{print $2}'`
    fi

    OFFSETS="0 $((stride/2)) $((stride-1))"
    for offset in $OFFSETS ; do
      for i in `seq 0 $((nstripe-1))`; do
        local GLOBALOFFSETS=""
        local size=$((((i + 2 * $nstripe )*$stride + $offset)))  # Bytes
	local myfn=$DIR/d44a-$size
	echo "--------writing $myfn at $size"
        ll_sparseness_write $myfn $size  || error "ll_sparseness_write"
        GLOBALOFFSETS="$GLOBALOFFSETS $size"
        ll_sparseness_verify $myfn $GLOBALOFFSETS \
                            || error "ll_sparseness_verify $GLOBALOFFSETS"

        for j in `seq 0 $((nstripe-1))`; do
            size=$((((j + $nstripe )*$stride + $offset)))  # Bytes
            ll_sparseness_write $myfn $size || error "ll_sparseness_write"
            GLOBALOFFSETS="$GLOBALOFFSETS $size"
        done
        ll_sparseness_verify $myfn $GLOBALOFFSETS \
                            || error "ll_sparseness_verify $GLOBALOFFSETS"
	rm -f $myfn
      done
    done
}
run_test 44a "test sparse pwrite ==============================="

dirty_osc_total() {
	tot=0
	for d in `lctl get_param -n osc.*.cur_dirty_bytes`; do
		tot=$(($tot + $d))
	done
	echo $tot
}
do_dirty_record() {
	before=`dirty_osc_total`
	echo executing "\"$*\""
	eval $*
	after=`dirty_osc_total`
	echo before $before, after $after
}
test_45() {
	f="$DIR/f45"
	# Obtain grants from OST if it supports it
	echo blah > ${f}_grant
	stop_writeback
	sync
	do_dirty_record "echo blah > $f"
	[ $before -eq $after ] && error "write wasn't cached"
	do_dirty_record "> $f"
	[ $before -gt $after ] || error "truncate didn't lower dirty count"
	do_dirty_record "echo blah > $f"
	[ $before -eq $after ] && error "write wasn't cached"
	do_dirty_record "sync"
	[ $before -gt $after ] || error "writeback didn't lower dirty count"
	do_dirty_record "echo blah > $f"
	[ $before -eq $after ] && error "write wasn't cached"
	do_dirty_record "cancel_lru_locks osc"
	[ $before -gt $after ] || error "lock cancellation didn't lower dirty count"
	start_writeback
}
run_test 45 "osc io page accounting ============================"

# in a 2 stripe file (lov.sh), page 1023 maps to page 511 in its object.  this
# test tickles a bug where re-dirtying a page was failing to be mapped to the
# objects offset and an assert hit when an rpc was built with 1023's mapped
# offset 511 and 511's raw 511 offset. it also found general redirtying bugs.
test_46() {
	f="$DIR/f46"
	stop_writeback
	sync
	dd if=/dev/zero of=$f bs=`page_size` seek=511 count=1
	sync
	dd conv=notrunc if=/dev/zero of=$f bs=`page_size` seek=1023 count=1
	dd conv=notrunc if=/dev/zero of=$f bs=`page_size` seek=511 count=1
	sync
	start_writeback
}
run_test 46 "dirtying a previously written page ================"

# test_47 is removed "Device nodes check" is moved to test_28

test_48a() { # bug 2399
	check_kernel_version 34 || return 0
	mkdir -p $DIR/d48a
	cd $DIR/d48a
	mv $DIR/d48a $DIR/d48.new || error "move directory failed"
	mkdir $DIR/d48a || error "recreate directory failed"
	touch foo || error "'touch foo' failed after recreating cwd"
	mkdir bar || error "'mkdir foo' failed after recreating cwd"
	if check_kernel_version 44; then
		touch .foo || error "'touch .foo' failed after recreating cwd"
		mkdir .bar || error "'mkdir .foo' failed after recreating cwd"
	fi
	ls . > /dev/null || error "'ls .' failed after recreating cwd"
	ls .. > /dev/null || error "'ls ..' failed after removing cwd"
	cd . || error "'cd .' failed after recreating cwd"
	mkdir . && error "'mkdir .' worked after recreating cwd"
	rmdir . && error "'rmdir .' worked after recreating cwd"
	ln -s . baz || error "'ln -s .' failed after recreating cwd"
	cd .. || error "'cd ..' failed after recreating cwd"
}
run_test 48a "Access renamed working dir (should return errors)="

test_48b() { # bug 2399
	check_kernel_version 34 || return 0
	mkdir -p $DIR/d48b
	cd $DIR/d48b
	rmdir $DIR/d48b || error "remove cwd $DIR/d48b failed"
	touch foo && error "'touch foo' worked after removing cwd"
	mkdir foo && error "'mkdir foo' worked after removing cwd"
	if check_kernel_version 44; then
		touch .foo && error "'touch .foo' worked after removing cwd"
		mkdir .foo && error "'mkdir .foo' worked after removing cwd"
	fi
	ls . > /dev/null && error "'ls .' worked after removing cwd"
	ls .. > /dev/null || error "'ls ..' failed after removing cwd"
	is_patchless || ( cd . && error "'cd .' worked after removing cwd" )
	mkdir . && error "'mkdir .' worked after removing cwd"
	rmdir . && error "'rmdir .' worked after removing cwd"
	ln -s . foo && error "'ln -s .' worked after removing cwd"
	cd .. || echo "'cd ..' failed after removing cwd `pwd`"  #bug 3517
}
run_test 48b "Access removed working dir (should return errors)="

test_48c() { # bug 2350
	check_kernel_version 36 || return 0
	#lctl set_param debug=-1
	#set -vx
	mkdir -p $DIR/d48c/dir
	cd $DIR/d48c/dir
	$TRACE rmdir $DIR/d48c/dir || error "remove cwd $DIR/d48c/dir failed"
	$TRACE touch foo && error "'touch foo' worked after removing cwd"
	$TRACE mkdir foo && error "'mkdir foo' worked after removing cwd"
	if check_kernel_version 44; then
		touch .foo && error "'touch .foo' worked after removing cwd"
		mkdir .foo && error "'mkdir .foo' worked after removing cwd"
	fi
	$TRACE ls . && error "'ls .' worked after removing cwd"
	$TRACE ls .. || error "'ls ..' failed after removing cwd"
	is_patchless || ( $TRACE cd . && error "'cd .' worked after removing cwd" )
	$TRACE mkdir . && error "'mkdir .' worked after removing cwd"
	$TRACE rmdir . && error "'rmdir .' worked after removing cwd"
	$TRACE ln -s . foo && error "'ln -s .' worked after removing cwd"
	$TRACE cd .. || echo "'cd ..' failed after removing cwd `pwd`" #bug 3415
}
run_test 48c "Access removed working subdir (should return errors)"

test_48d() { # bug 2350
	check_kernel_version 36 || return 0
	#lctl set_param debug=-1
	#set -vx
	mkdir -p $DIR/d48d/dir
	cd $DIR/d48d/dir
	$TRACE rmdir $DIR/d48d/dir || error "remove cwd $DIR/d48d/dir failed"
	$TRACE rmdir $DIR/d48d || error "remove parent $DIR/d48d failed"
	$TRACE touch foo && error "'touch foo' worked after removing parent"
	$TRACE mkdir foo && error "'mkdir foo' worked after removing parent"
	if check_kernel_version 44; then
		touch .foo && error "'touch .foo' worked after removing parent"
		mkdir .foo && error "'mkdir .foo' worked after removing parent"
	fi
	$TRACE ls . && error "'ls .' worked after removing parent"
	$TRACE ls .. && error "'ls ..' worked after removing parent"
	is_patchless || ( $TRACE cd . && error "'cd .' worked after recreate parent" )
	$TRACE mkdir . && error "'mkdir .' worked after removing parent"
	$TRACE rmdir . && error "'rmdir .' worked after removing parent"
	$TRACE ln -s . foo && error "'ln -s .' worked after removing parent"
	is_patchless || ( $TRACE cd .. && error "'cd ..' worked after removing parent" || true )
}
run_test 48d "Access removed parent subdir (should return errors)"

test_48e() { # bug 4134
	check_kernel_version 41 || return 0
	#lctl set_param debug=-1
	#set -vx
	mkdir -p $DIR/d48e/dir
	cd $DIR/d48e/dir
	$TRACE rmdir $DIR/d48e/dir || error "remove cwd $DIR/d48e/dir failed"
	$TRACE rmdir $DIR/d48e || error "remove parent $DIR/d48e failed"
	$TRACE touch $DIR/d48e || error "'touch $DIR/d48e' failed"
	$TRACE chmod +x $DIR/d48e || error "'chmod +x $DIR/d48e' failed"
	# On a buggy kernel addition of "touch foo" after cd .. will
	# produce kernel oops in lookup_hash_it
	touch ../foo && error "'cd ..' worked after recreate parent"
	cd $DIR
	$TRACE rm $DIR/d48e || error "rm '$DIR/d48e' failed"
}
run_test 48e "Access to recreated parent subdir (should return errors)"

test_50() {
	# bug 1485
	mkdir $DIR/d50
	cd $DIR/d50
	ls /proc/$$/cwd || error
}
run_test 50 "special situations: /proc symlinks  ==============="

test_51a() {	# was test_51
	# bug 1516 - create an empty entry right after ".." then split dir
	mkdir $DIR/d51
	touch $DIR/d51/foo
	$MCREATE $DIR/d51/bar
	rm $DIR/d51/foo
	createmany -m $DIR/d51/longfile 201
	FNUM=202
	while [ `ls -sd $DIR/d51 | awk '{ print $1 }'` -eq 4 ]; do
		$MCREATE $DIR/d51/longfile$FNUM
		FNUM=$(($FNUM + 1))
		echo -n "+"
	done
	echo
	ls -l $DIR/d51 > /dev/null || error
}
run_test 51a "special situations: split htree with empty entry =="

#export NUMTEST=70000
# FIXME: I select a relatively small number to do basic test.
# large number may give panic(). debugging on this is going on.
export NUMTEST=70
test_51b() {
	NUMFREE=`df -i -P $DIR | tail -n 1 | awk '{ print $4 }'`
	[ $NUMFREE -lt 21000 ] && \
		skip "not enough free inodes ($NUMFREE)" && \
		return

	check_kernel_version 40 || NUMTEST=31000
	[ $NUMFREE -lt $NUMTEST ] && NUMTEST=$(($NUMFREE - 50))

	mkdir -p $DIR/d51b
	createmany -d $DIR/d51b/t- $NUMTEST
}
run_test 51b "mkdir .../t-0 --- .../t-$NUMTEST ===================="

test_51bb() {
	[ $MDSCOUNT -lt 2 ] && skip "needs >= 2 MDTs" && return

	local ndirs=${TEST51BB_NDIRS:-10}
	local nfiles=${TEST51BB_NFILES:-100}

	local numfree=`df -i -P $DIR | tail -n 1 | awk '{ print $4 }'`

	[ $numfree -lt $(( ndirs * nfiles)) ] && \
		nfiles=$(( numfree / ndirs - 10 ))

	local dir=$DIR/d51bb
	mkdir -p $dir
	local savePOLICY=$(lctl get_param -n lmv.*.placement)
	lctl set_param -n lmv.*.placement=CHAR

	lfs df -i $dir
	local IUSED=$(lfs df -i $dir | grep MDT | awk '{print $3}')
	OLDUSED=($IUSED)

	declare -a dirs
	for ((i=0; i < $ndirs; i++)); do
		dirs[i]=$dir/$RANDOM
		echo Creating directory ${dirs[i]}
		mkdir -p ${dirs[i]}
		ls $dir
		echo Creating $nfiles in dir ${dirs[i]} ...
		echo "createmany -o ${dirs[i]}/$tfile- $nfiles"
		createmany -o ${dirs[i]}/$tfile- $nfiles
	done
	ls $dir

	sleep 1

	IUSED=$(lfs df -i $dir | grep MDT | awk '{print $3}')
	NEWUSED=($IUSED)

	local rc=0
	for ((i=0; i<${#NEWUSED[@]}; i++)); do
		echo "mds $i: inodes count OLD ${OLDUSED[$i]} NEW ${NEWUSED[$i]}"
		[ ${OLDUSED[$i]} -lt ${NEWUSED[$i]} ] || rc=$((rc + 1))
	done

	lctl set_param -n lmv.*.placement=$savePOLICY

	[ $rc -ne $MDSCOUNT ] || \
		error "Objects/inodes are not distributed over all mds servers"
}
run_test 51bb "mkdir createmany CMD $MDSCOUNT  ===================="


test_51c() {
	[ ! -d $DIR/d51b ] && skip "$DIR/51b missing" && \
		return

	unlinkmany -d $DIR/d51b/t- $NUMTEST
}
run_test 51c "rmdir .../t-0 --- .../t-$NUMTEST ===================="

test_51d() {
        [  "$OSTCOUNT" -lt "3" ] && skip_env "skipping test with few OSTs" && return
        mkdir -p $DIR/d51d
        createmany -o $DIR/d51d/t- 1000
        $LFS getstripe $DIR/d51d > $TMP/files
        for N in `seq 0 $((OSTCOUNT - 1))`; do
	    OBJS[$N]=`awk -vobjs=0 '($1 == '$N') { objs += 1 } END { print objs;}' $TMP/files`
	    OBJS0[$N]=`grep -A 1 idx $TMP/files | awk -vobjs=0 '($1 == '$N') { objs += 1 } END { print objs;}'`
	    log "OST$N has ${OBJS[$N]} objects, ${OBJS0[$N]} are index 0"
        done
        unlinkmany $DIR/d51d/t- 1000

        NLAST=0
        for N in `seq 1 $((OSTCOUNT - 1))`; do
	    [ ${OBJS[$N]} -lt $((${OBJS[$NLAST]} - 20)) ] && \
		error "OST $N has less objects vs OST $NLAST (${OBJS[$N]} < ${OBJS[$NLAST]}"
	    [ ${OBJS[$N]} -gt $((${OBJS[$NLAST]} + 20)) ] && \
		error "OST $N has less objects vs OST $NLAST (${OBJS[$N]} < ${OBJS[$NLAST]}"

	    [ ${OBJS0[$N]} -lt $((${OBJS0[$NLAST]} - 20)) ] && \
		error "OST $N has less #0 objects vs OST $NLAST (${OBJS0[$N]} < ${OBJS0[$NLAST]}"
	    [ ${OBJS0[$N]} -gt $((${OBJS0[$NLAST]} + 20)) ] && \
		error "OST $N has less #0 objects vs OST $NLAST (${OBJS0[$N]} < ${OBJS0[$NLAST]}"
	    NLAST=$N
        done
}
run_test 51d "check object distribution ===================="

test_52a() {
	[ -f $DIR/d52a/foo ] && chattr -a $DIR/d52a/foo
	mkdir -p $DIR/d52a
	touch $DIR/d52a/foo
	chattr +a $DIR/d52a/foo || error "chattr +a failed"
	echo bar >> $DIR/d52a/foo || error "append bar failed"
	cp /etc/hosts $DIR/d52a/foo && error "cp worked"
	rm -f $DIR/d52a/foo 2>/dev/null && error "rm worked"
	link $DIR/d52a/foo $DIR/d52a/foo_link 2>/dev/null && error "link worked"
	echo foo >> $DIR/d52a/foo || error "append foo failed"
	mrename $DIR/d52a/foo $DIR/d52a/foo_ren && error "rename worked"
	lsattr $DIR/d52a/foo | egrep -q "^-+a[-e]+ $DIR/d52a/foo" || error "lsattr"
	chattr -a $DIR/d52a/foo || error "chattr -a failed"
        cp -r $DIR/d52a /tmp/
	rm -fr $DIR/d52a || error "cleanup rm failed"
}
run_test 52a "append-only flag test (should return errors) ====="

test_52b() {
	[ -f $DIR/d52b/foo ] && chattr -i $DIR/d52b/foo
	mkdir -p $DIR/d52b
	touch $DIR/d52b/foo
	chattr +i $DIR/d52b/foo || error "chattr +i failed"
	cat test > $DIR/d52b/foo && error "cat test worked"
	cp /etc/hosts $DIR/d52b/foo && error "cp worked"
	rm -f $DIR/d52b/foo 2>/dev/null && error "rm worked"
	link $DIR/d52b/foo $DIR/d52b/foo_link 2>/dev/null && error  "link worked"
	echo foo >> $DIR/d52b/foo && error "echo worked"
	mrename $DIR/d52b/foo $DIR/d52b/foo_ren && error "rename worked"
	[ -f $DIR/d52b/foo ] || error
	[ -f $DIR/d52b/foo_ren ] && error
	lsattr $DIR/d52b/foo | egrep -q "^-+i[-e]+ $DIR/d52b/foo" || error "lsattr"
	chattr -i $DIR/d52b/foo || error "chattr failed"

	rm -fr $DIR/d52b || error
}
run_test 52b "immutable flag test (should return errors) ======="

test_53() {
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
	remote_ost_nodsh && skip "remote OST with nodsh" && return

	local param
	local ostname
	local mds_last
	local ost_last
	local ostnum

	# only test MDT0000
        local mdtosc=$(get_mdtosc_proc_path $SINGLEMDS)
        for value in $(do_facet $SINGLEMDS lctl get_param osc.$mdtosc.prealloc_last_id) ; do
                param=`echo ${value[0]} | cut -d "=" -f1`
                ostname=`echo $param | cut -d "." -f2 | cut -d - -f 1-2`
                mds_last=$(do_facet $SINGLEMDS lctl get_param -n $param)
                ostnum=$(echo $ostname | sed "s/${FSNAME}-OST//g" | awk '{print ($1+1)}' )
                ost_last=$(do_facet ost$ostnum lctl get_param -n obdfilter.$ostname.last_id | head -n 1)
                echo "$ostname.last_id=$ost_last ; MDS.last_id=$mds_last"
                if [ $ost_last != $mds_last ]; then
                    error "$ostname.last_id=$ost_last ; MDS.last_id=$mds_last"
                fi
        done
}
run_test 53 "verify that MDS and OSTs agree on pre-creation ===="

test_54a() {
        [ ! -f "$SOCKETSERVER" ] && skip_env "no socketserver, skipping" && return
        [ ! -f "$SOCKETCLIENT" ] && skip_env "no socketclient, skipping" && return
     	$SOCKETSERVER $DIR/socket
     	$SOCKETCLIENT $DIR/socket || error
      	$MUNLINK $DIR/socket
}
run_test 54a "unix domain socket test =========================="

test_54b() {
	f="$DIR/f54b"
	mknod $f c 1 3
	chmod 0666 $f
	dd if=/dev/zero of=$f bs=`page_size` count=1
}
run_test 54b "char device works in lustre ======================"

find_loop_dev() {
	[ -b /dev/loop/0 ] && LOOPBASE=/dev/loop/
	[ -b /dev/loop0 ] && LOOPBASE=/dev/loop
	[ -z "$LOOPBASE" ] && echo "/dev/loop/0 and /dev/loop0 gone?" && return

	for i in `seq 3 7`; do
		losetup $LOOPBASE$i > /dev/null 2>&1 && continue
		LOOPDEV=$LOOPBASE$i
		LOOPNUM=$i
		break
	done
}

test_54c() {
	tfile="$DIR/f54c"
	tdir="$DIR/d54c"
	loopdev="$DIR/loop54c"

	find_loop_dev
	[ -z "$LOOPNUM" ] && echo "couldn't find empty loop device" && return
	mknod $loopdev b 7 $LOOPNUM
	echo "make a loop file system with $tfile on $loopdev ($LOOPNUM)..."
	dd if=/dev/zero of=$tfile bs=`page_size` seek=1024 count=1 > /dev/null
	losetup $loopdev $tfile || error "can't set up $loopdev for $tfile"
	mkfs.ext2 $loopdev || error "mke2fs on $loopdev"
	mkdir -p $tdir
	mount -t ext2 $loopdev $tdir || error "error mounting $loopdev on $tdir"
	dd if=/dev/zero of=$tdir/tmp bs=`page_size` count=30 || error "dd write"
	df $tdir
	dd if=$tdir/tmp of=/dev/zero bs=`page_size` count=30 || error "dd read"
	$UMOUNT $tdir
	losetup -d $loopdev
	rm $loopdev
}
run_test 54c "block device works in lustre ====================="

test_54d() {
	f="$DIR/f54d"
	string="aaaaaa"
	mknod $f p
	[ "$string" = `echo $string > $f | cat $f` ] || error
}
run_test 54d "fifo device works in lustre ======================"

test_54e() {
	check_kernel_version 46 || return 0
	f="$DIR/f54e"
	string="aaaaaa"
	cp -aL /dev/console $f
	echo $string > $f || error
}
run_test 54e "console/tty device works in lustre ======================"

#The test_55 used to be iopen test and it was removed by bz#24037.
#run_test 55 "check iopen_connect_dentry() ======================"

test_56a() {	# was test_56
        rm -rf $DIR/d56
        $SETSTRIPE -d $DIR
        mkdir $DIR/d56
        mkdir $DIR/d56/dir
        NUMFILES=3
        NUMFILESx2=$(($NUMFILES * 2))
        for i in `seq 1 $NUMFILES` ; do
                touch $DIR/d56/file$i
                touch $DIR/d56/dir/file$i
        done

        # test lfs getstripe with --recursive
        FILENUM=`$GETSTRIPE --recursive $DIR/d56 | grep -c obdidx`
        [ $FILENUM -eq $NUMFILESx2 ] || error \
                "lfs getstripe --recursive $DIR/d56 wrong: found $FILENUM, expected $NUMFILESx2"
        FILENUM=`$GETSTRIPE $DIR/d56 | grep -c obdidx`
        [ $FILENUM -eq $NUMFILES ] || error \
                "lfs getstripe $DIR/d56 without --recursive wrong: found $FILENUM, expected $NUMFILES"
        echo "lfs getstripe --recursive passed."

        # test lfs getstripe with file instead of dir
        FILENUM=`$GETSTRIPE $DIR/d56/file1 | grep -c obdidx`
        [ $FILENUM  -eq 1 ] || error \
                 "lfs getstripe $DIR/d56/file1 wrong:found $FILENUM, expected 1"
        echo "lfs getstripe file passed."

        #test lfs getstripe with --verbose
        [ `$GETSTRIPE --verbose $DIR/d56 | grep -c lmm_magic` -eq $NUMFILES ] ||\
                error "lfs getstripe --verbose $DIR/d56 wrong: should find $NUMFILES lmm_magic info"
        [ `$GETSTRIPE $DIR/d56 | grep -c lmm_magic` -eq 0 ] || error \
                "lfs getstripe $DIR/d56 without --verbose wrong: should not show lmm_magic info"
        echo "lfs getstripe --verbose passed."

        #test lfs getstripe with --obd
        $GETSTRIPE --obd wrong_uuid $DIR/d56 2>&1 | grep -q "unknown obduuid" || \
                error "lfs getstripe --obd wrong_uuid should return error message"

        [  "$OSTCOUNT" -lt 2 ] && \
                skip_env "skipping other lfs getstripe --obd test" && return
        OSTIDX=1
        OBDUUID=$(lfs osts | grep ${OSTIDX}": " | awk '{print $2}')
        FILENUM=`$GETSTRIPE -ir $DIR/d56 | grep -x $OSTIDX | wc -l`
        FOUND=`$GETSTRIPE -r --obd $OBDUUID $DIR/d56 | grep obdidx | wc -l`
        [ $FOUND -eq $FILENUM ] || \
                error "lfs getstripe --obd wrong: found $FOUND, expected $FILENUM"
        [ `$GETSTRIPE -r -v --obd $OBDUUID $DIR/d56 | \
                sed '/^[	 ]*'${OSTIDX}'[	 ]/d' |\
                sed -n '/^[	 ]*[0-9][0-9]*[	 ]/p' | wc -l` -eq 0 ] || \
                error "lfs getstripe --obd wrong: should not show file on other obd"
        echo "lfs getstripe --obd passed."
}
run_test 56a "check lfs getstripe ===================================="

NUMFILES=3
NUMDIRS=3
setup_56() {
        LOCAL_NUMFILES=$1
        LOCAL_NUMDIRS=$2
        if [ ! -d "$DIR/${tdir}g" ] ; then
                mkdir -p $DIR/${tdir}g
                for i in `seq 1 $LOCAL_NUMFILES` ; do
                        touch $DIR/${tdir}g/file$i
                done
                for i in `seq 1 $LOCAL_NUMDIRS` ; do
                        mkdir $DIR/${tdir}g/dir$i
                        for j in `seq 1 $LOCAL_NUMFILES` ; do
                                touch $DIR/${tdir}g/dir$i/file$j
                        done
                done
        fi
}

setup_56_special() {
	LOCAL_NUMFILES=$1
	LOCAL_NUMDIRS=$2
	TDIR=$DIR/${tdir}g
	setup_56 $1 $2
	if [ ! -e "$TDIR/loop1b" ] ; then
		for i in `seq 1 $LOCAL_NUMFILES` ; do
			mknod $TDIR/loop${i}b b 7 $i
			mknod $TDIR/null${i}c c 1 3
			ln -s $TDIR/file1 $TDIR/link${i}l
		done
		for i in `seq 1 $LOCAL_NUMDIRS` ; do
			mknod $TDIR/dir$i/loop${i}b b 7 $i
			mknod $TDIR/dir$i/null${i}c c 1 3
			ln -s $TDIR/dir$i/file1 $TDIR/dir$i/link${i}l
		done
	fi
}

test_56g() {
        $LSTRIPE -d $DIR

        setup_56 $NUMFILES $NUMDIRS

        EXPECTED=$(($NUMDIRS + 2))
        # test lfs find with -name
        for i in `seq 1 $NUMFILES` ; do
                NUMS=`$LFIND -name "*$i" $DIR/${tdir}g | wc -l`
                [ $NUMS -eq $EXPECTED ] || error \
                        "lfs find -name \"*$i\" $DIR/${tdir}g wrong: found $NUMS, expected $EXPECTED"
        done
        echo "lfs find -name passed."
}
run_test 56g "check lfs find -name ============================="

test_56h() {
        $LSTRIPE -d $DIR

        setup_56 $NUMFILES $NUMDIRS

        EXPECTED=$((($NUMDIRS+1)*($NUMFILES-1)+$NUMFILES))
        # test lfs find with ! -name
        for i in `seq 1 $NUMFILES` ; do
                NUMS=`$LFIND ! -name "*$i" $DIR/${tdir}g | wc -l`
                [ $NUMS -eq $EXPECTED ] || error \
                        "lfs find ! -name \"*$i\" $DIR/${tdir}g wrong: found $NUMS, expected $EXPECTED"
        done
        echo "lfs find ! -name passed."
}
run_test 56h "check lfs find ! -name ============================="

test_56i() {
       tdir=${tdir}i
       mkdir -p $DIR/$tdir
       UUID=$(ostuuid_from_index 0 $DIR/$tdir)
       OUT=$($LFIND -obd $UUID $DIR/$tdir)
       [ "$OUT" ] && error "$LFIND returned directory '$OUT'" || true
}
run_test 56i "check 'lfs find -ost UUID' skips directories ======="

test_56j() {
	setup_56_special $NUMFILES $NUMDIRS

	EXPECTED=$((NUMDIRS+1))
	NUMS=`$LFIND -type d $DIR/${tdir}g | wc -l`
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find -type d $DIR/${tdir}g wrong: found $NUMS, expected $EXPECTED"
}
run_test 56j "check lfs find -type d ============================="

test_56k() {
	setup_56_special $NUMFILES $NUMDIRS

	EXPECTED=$(((NUMDIRS+1) * NUMFILES))
	NUMS=`$LFIND -type f $DIR/${tdir}g | wc -l`
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find -type f $DIR/${tdir}g wrong: found $NUMS, expected $EXPECTED"
}
run_test 56k "check lfs find -type f ============================="

test_56l() {
	setup_56_special $NUMFILES $NUMDIRS

	EXPECTED=$((NUMDIRS + NUMFILES))
	NUMS=`$LFIND -type b $DIR/${tdir}g | wc -l`
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find -type b $DIR/${tdir}g wrong: found $NUMS, expected $EXPECTED"
}
run_test 56l "check lfs find -type b ============================="

test_56m() {
	setup_56_special $NUMFILES $NUMDIRS

	EXPECTED=$((NUMDIRS + NUMFILES))
	NUMS=`$LFIND -type c $DIR/${tdir}g | wc -l`
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find -type c $DIR/${tdir}g wrong: found $NUMS, expected $EXPECTED"
}
run_test 56m "check lfs find -type c ============================="

test_56n() {
	setup_56_special $NUMFILES $NUMDIRS

	EXPECTED=$((NUMDIRS + NUMFILES))
	NUMS=`$LFIND -type l $DIR/${tdir}g | wc -l`
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find -type l $DIR/${tdir}g wrong: found $NUMS, expected $EXPECTED"
}
run_test 56n "check lfs find -type l ============================="

test_56o() {
	setup_56 $NUMFILES $NUMDIRS
	TDIR=$DIR/${tdir}g

	utime $TDIR/file1 > /dev/null || error "utime (1)"
	utime $TDIR/file2 > /dev/null || error "utime (2)"
	utime $TDIR/dir1 > /dev/null || error "utime (3)"
	utime $TDIR/dir2 > /dev/null || error "utime (4)"
	utime $TDIR/dir1/file1 > /dev/null || error "utime (5)"

	EXPECTED=5
	NUMS=`$LFIND -mtime +1 $TDIR | wc -l`
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find -mtime $TDIR wrong: found $NUMS, expected $EXPECTED"
}
run_test 56o "check lfs find -mtime for old files =========================="

test_56p() {
	[ $RUNAS_ID -eq $UID ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return

	TDIR=$DIR/${tdir}g
	rm -rf $TDIR

	setup_56 $NUMFILES $NUMDIRS

	chown $RUNAS_ID $TDIR/file* || error "chown $DIR/${tdir}g/file$i failed"
	EXPECTED=$NUMFILES
	NUMS="`$LFIND -uid $RUNAS_ID $TDIR | wc -l`"
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find -uid $TDIR wrong: found $NUMS, expected $EXPECTED"

	EXPECTED=$(( ($NUMFILES+1) * $NUMDIRS + 1))
	NUMS="`$LFIND ! -uid $RUNAS_ID $TDIR | wc -l`"
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find ! -uid $TDIR wrong: found $NUMS, expected $EXPECTED"

	echo "lfs find -uid and ! -uid passed."
}
run_test 56p "check lfs find -uid and ! -uid ==============================="

test_56q() {
	[ $RUNAS_ID -eq $UID ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return

	TDIR=$DIR/${tdir}g
        rm -rf $TDIR

	setup_56 $NUMFILES $NUMDIRS

	chgrp $RUNAS_GID $TDIR/file* || error "chown $DIR/${tdir}g/file$i failed"
	EXPECTED=$NUMFILES
	NUMS="`$LFIND -gid $RUNAS_GID $TDIR | wc -l`"
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find -gid $TDIR wrong: found $NUMS, expected $EXPECTED"

	EXPECTED=$(( ($NUMFILES+1) * $NUMDIRS + 1))
	NUMS="`$LFIND ! -gid $RUNAS_GID $TDIR | wc -l`"
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find ! -gid $TDIR wrong: found $NUMS, expected $EXPECTED"

	echo "lfs find -gid and ! -gid passed."
}
run_test 56q "check lfs find -gid and ! -gid ==============================="

test_56r() {
	setup_56 $NUMFILES $NUMDIRS
	TDIR=$DIR/${tdir}g

	EXPECTED=12
	NUMS=`$LFIND -size 0 -t f $TDIR | wc -l`
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find $TDIR -size 0 wrong: found $NUMS, expected $EXPECTED"
	EXPECTED=0
	NUMS=`$LFIND ! -size 0 -t f $TDIR | wc -l`
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find $TDIR ! -size 0 wrong: found $NUMS, expected $EXPECTED"
	echo "test" > $TDIR/56r && sync
	EXPECTED=1
	NUMS=`$LFIND -size 5 -t f $TDIR | wc -l`
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find $TDIR -size 5 wrong: found $NUMS, expected $EXPECTED"
	EXPECTED=1
	NUMS=`$LFIND -size +5 -t f $TDIR | wc -l`
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find $TDIR -size +5 wrong: found $NUMS, expected $EXPECTED"
	EXPECTED=13
	NUMS=`$LFIND -size +0 -t f $TDIR | wc -l`
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find $TDIR -size +0 wrong: found $NUMS, expected $EXPECTED"
	EXPECTED=0
	NUMS=`$LFIND ! -size -5 -t f $TDIR | wc -l`
	[ $NUMS -eq $EXPECTED ] || \
		error "lfs find $TDIR ! -size -5 wrong: found $NUMS, expected $EXPECTED"
}

run_test 56r "check lfs find -size works =========================="

test_57a() {
	# note test will not do anything if MDS is not local
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
	local MNTDEV="osd*.*MDT*.mntdev"
	DEV=$(do_facet $SINGLEMDS lctl get_param -n $MNTDEV)
	[ -z "$DEV" ] && error "can't access $MNTDEV"
	for DEV in $(do_facet $SINGLEMDS lctl get_param -n $MNTDEV); do
		do_facet $SINGLEMDS $DUMPE2FS -h $DEV > $TMP/t57a.dump || error "can't access $DEV"
		DEVISIZE=`awk '/Inode size:/ { print $3 }' $TMP/t57a.dump`
		[ "$DEVISIZE" -gt 128 ] || error "inode size $DEVISIZE"
		rm $TMP/t57a.dump
	done
}
run_test 57a "verify MDS filesystem created with large inodes =="

test_57b() {
	local dir=$DIR/d57b

	local FILECOUNT=100
	local FILE1=$dir/f1
	local FILEN=$dir/f$FILECOUNT

	rm -rf $dir || error "removing $dir"
	mkdir -p $dir || error "creating $dir"
	local num=$(get_mds_dir $dir)
	local mymds=mds$num

	echo "mcreating $FILECOUNT files"
	createmany -m $dir/f 1 $FILECOUNT || \
		error "creating files in $dir"

	# verify that files do not have EAs yet
	$GETSTRIPE $FILE1 2>&1 | grep -q "no stripe" || error "$FILE1 has an EA"
	$GETSTRIPE $FILEN 2>&1 | grep -q "no stripe" || error "$FILEN has an EA"

	sync
	sleep 1
	df $dir  #make sure we get new statfs data
	local MDSFREE=$(do_facet $mymds \
		lctl get_param -n osd*.*MDT000$((num -1)).kbytesfree)
	local MDCFREE=$(lctl get_param -n mdc.*MDT000$((num -1))-mdc-*.kbytesfree)
	echo "opening files to create objects/EAs"
	local FILE
	for FILE in `seq -f $dir/f%g 1 $FILECOUNT`; do
		$OPENFILE -f O_RDWR $FILE > /dev/null 2>&1 || error "opening $FILE"
	done

	# verify that files have EAs now
	$GETSTRIPE $FILE1 | grep -q "obdidx" || error "$FILE1 missing EA"
	$GETSTRIPE $FILEN | grep -q "obdidx" || error "$FILEN missing EA"

	sleep 1  #make sure we get new statfs data
	df $dir
	local MDSFREE2=$(do_facet $mymds \
		lctl get_param -n osd*.*MDT000$((num -1)).kbytesfree)
	local MDCFREE2=$(lctl get_param -n mdc.*MDT000$((num -1))-mdc-*.kbytesfree)
	if [ "$MDCFREE2" -lt "$((MDCFREE - 8))" ]; then
		if [ "$MDSFREE" != "$MDSFREE2" ]; then
			error "MDC before $MDCFREE != after $MDCFREE2"
		else
			echo "MDC before $MDCFREE != after $MDCFREE2"
			echo "unable to confirm if MDS has large inodes"
		fi
	fi
	rm -rf $dir
}
run_test 57b "default LOV EAs are stored inside large inodes ==="

test_58() {
    [ -z "$(which wiretest 2>/dev/null)" ] && skip_env "could not find wiretest" && return
    wiretest
}
run_test 58 "verify cross-platform wire constants =============="

test_59() {
	echo "touch 130 files"
	createmany -o $DIR/f59- 130
	echo "rm 130 files"
	unlinkmany $DIR/f59- 130
	sync
	sleep 2
        # wait for commitment of removal
}
run_test 59 "verify cancellation of llog records async ========="

TEST60_HEAD="test_60 run $RANDOM"
test_60a() {
        [ ! -f run-llog.sh ] && skip_env "missing subtest run-llog.sh" && return
	log "$TEST60_HEAD - from kernel mode"
	do_facet mgs sh run-llog.sh
}
run_test 60a "llog sanity tests run from kernel module =========="

test_60b() { # bug 6411
	dmesg > $DIR/$tfile
	LLOG_COUNT=`dmesg | awk "/$TEST60_HEAD/{marker = 1; from_marker = 0;}
				 /llog.test/ {
					 if (marker)
						 from_marker++
					 from_begin++
				 }
				 END {
					 if (marker)
						 print from_marker
					 else
						 print from_begin
				 }"`
	[ $LLOG_COUNT -gt 50 ] && error "CDEBUG_LIMIT not limiting messages ($LLOG_COUNT)"|| true
}
run_test 60b "limit repeated messages from CERROR/CWARN ========"

test_60c() {
	echo "create 5000 files"
	createmany -o $DIR/f60c- 5000
#define OBD_FAIL_MDS_LLOG_CREATE_FAILED  0x137
	lctl set_param fail_loc=0x80000137
	unlinkmany $DIR/f60c- 5000
	lctl set_param fail_loc=0
}
run_test 60c "unlink file when mds full"

test_60d() {
	SAVEPRINTK=$(lctl get_param -n printk)

	# verify "lctl mark" is even working"
	MESSAGE="test message ID $RANDOM $$"
	$LCTL mark "$MESSAGE" || error "$LCTL mark failed"
	dmesg | grep -q "$MESSAGE" || error "didn't find debug marker in log"

	lctl set_param printk=0 || error "set lnet.printk failed"
	lctl get_param -n printk | grep emerg || error "lnet.printk dropped emerg"
	MESSAGE="new test message ID $RANDOM $$"
	# Assume here that libcfs_debug_mark_buffer() uses D_WARNING
	$LCTL mark "$MESSAGE" || error "$LCTL mark failed"
	dmesg | grep -q "$MESSAGE" && error "D_WARNING wasn't masked" || true

	lctl set_param -n printk="$SAVEPRINTK"
}
run_test 60d "test printk console message masking"

test_61() {
	f="$DIR/f61"
	dd if=/dev/zero of=$f bs=`page_size` count=1
	cancel_lru_locks osc
	multiop $f OSMWUc || error
	sync
}
run_test 61 "mmap() writes don't make sync hang ================"

# bug 2330 - insufficient obd_match error checking causes LBUG
test_62() {
        f="$DIR/f62"
        echo foo > $f
        cancel_lru_locks osc
        lctl set_param fail_loc=0x405
        cat $f && error "cat succeeded, expect -EIO"
        lctl set_param fail_loc=0
}
# This test is now irrelevant (as of bug 10718 inclusion), we no longer
# match every page all of the time.
#run_test 62 "verify obd_match failure doesn't LBUG (should -EIO)"

# bug 2319 - oig_wait() interrupted causes crash because of invalid waitq.
test_63a() {	# was test_63
	MAX_DIRTY_MB=`lctl get_param -n osc.*.max_dirty_mb | head -n 1`
	lctl set_param -n osc.*.max_dirty_mb 0
	for i in `seq 10` ; do
		dd if=/dev/zero of=$DIR/f63 bs=8k &
		sleep 5
		kill $!
		sleep 1
	done

	lctl set_param -n osc.*.max_dirty_mb $MAX_DIRTY_MB
	rm -f $DIR/f63 || true
}
run_test 63a "Verify oig_wait interruption does not crash ======="

# bug 2248 - async write errors didn't return to application on sync
# bug 3677 - async write errors left page locked
test_63b() {
	debugsave
	lctl set_param debug=-1

	# ensure we have a grant to do async writes
	dd if=/dev/zero of=$DIR/$tfile bs=4k count=1
	rm $DIR/$tfile

	#define OBD_FAIL_OSC_BRW_PREP_REQ        0x406
	lctl set_param fail_loc=0x80000406
	multiop $DIR/$tfile Owy && \
		error "sync didn't return ENOMEM"
	sync; sleep 2; sync	# do a real sync this time to flush page
	lctl get_param -n llite.*.dump_page_cache | grep locked && \
		error "locked page left in cache after async error" || true
	debugrestore
}
run_test 63b "async write errors should be returned to fsync ==="

test_64a () {
	df $DIR
	lctl get_param -n osc.*[oO][sS][cC][_-]*.cur* | grep "[0-9]"
}
run_test 64a "verify filter grant calculations (in kernel) ====="

test_64b () {
        [ ! -f oos.sh ] && skip_env "missing subtest oos.sh" && return
	sh oos.sh $MOUNT
}
run_test 64b "check out-of-space detection on client ==========="

# bug 1414 - set/get directories' stripe info
test_65a() {
	mkdir -p $DIR/d65
	touch $DIR/d65/f1
	$LVERIFY $DIR/d65 $DIR/d65/f1 || error "lverify failed"
}
run_test 65a "directory with no stripe info ===================="

test_65b() {
	mkdir -p $DIR/d65
	$SETSTRIPE $DIR/d65 -s $(($STRIPESIZE * 2)) -i 0 -c 1 || error "setstripe"
	touch $DIR/d65/f2
	$LVERIFY $DIR/d65 $DIR/d65/f2 || error "lverify failed"
}
run_test 65b "directory setstripe $(($STRIPESIZE * 2)) 0 1 ==============="

test_65c() {
	if [ $OSTCOUNT -gt 1 ]; then
		mkdir -p $DIR/d65
    		$SETSTRIPE $DIR/d65 -s $(($STRIPESIZE * 4)) -i 1 \
			-c $(($OSTCOUNT - 1)) || error "setstripe"
		touch $DIR/d65/f3
		$LVERIFY $DIR/d65 $DIR/d65/f3 || error "lverify failed"
	fi
}
run_test 65c "directory setstripe $(($STRIPESIZE * 4)) 1 $(($OSTCOUNT - 1))"

test_65d() {
	mkdir -p $DIR/d65
	if [ $STRIPECOUNT -le 0 ]; then
        	sc=1
	elif [ $STRIPECOUNT -gt 160 ]; then
#LOV_MAX_STRIPE_COUNT is 160
        	[ $OSTCOUNT -gt 160 ] && sc=160 || sc=$(($OSTCOUNT - 1))
	else
        	sc=$(($STRIPECOUNT - 1))
	fi
	$SETSTRIPE $DIR/d65 -s $STRIPESIZE -c $sc || error "setstripe"
	touch $DIR/d65/f4 $DIR/d65/f5
	$LVERIFY $DIR/d65 $DIR/d65/f4 $DIR/d65/f5 || error "lverify failed"
}
run_test 65d "directory setstripe $STRIPESIZE -1 stripe_count =============="

test_65e() {
	mkdir -p $DIR/d65

	$SETSTRIPE $DIR/d65 || error "setstripe"
        $GETSTRIPE -v $DIR/d65 | grep "Default" || error "no stripe info failed"
	touch $DIR/d65/f6
	$LVERIFY $DIR/d65 $DIR/d65/f6 || error "lverify failed"
}
run_test 65e "directory setstripe defaults ======================="

test_65f() {
	mkdir -p $DIR/d65f
	$RUNAS $SETSTRIPE $DIR/d65f && error "setstripe succeeded" || true
}
run_test 65f "dir setstripe permission (should return error) ==="

test_65g() {
        mkdir -p $DIR/d65
        $SETSTRIPE $DIR/d65 -s $(($STRIPESIZE * 2)) -i 0 -c 1 || error "setstripe"
        $SETSTRIPE -d $DIR/d65 || error "setstripe"
        $GETSTRIPE -v $DIR/d65 | grep "Default" || \
		error "delete default stripe failed"
}
run_test 65g "directory setstripe -d ==========================="

test_65h() {
        mkdir -p $DIR/d65
        $SETSTRIPE $DIR/d65 -s $(($STRIPESIZE * 2)) -i 0 -c 1 || error "setstripe"
        mkdir -p $DIR/d65/dd1
        [ "`$GETSTRIPE -v $DIR/d65 | grep "^count"`" == \
          "`$GETSTRIPE -v $DIR/d65/dd1 | grep "^count"`" ] || error "stripe info inherit failed"
}
run_test 65h "directory stripe info inherit ===================="

test_65i() { # bug6367
        $SETSTRIPE $MOUNT -s 65536 -c -1
}
run_test 65i "set non-default striping on root directory (bug 6367)="

test_65ia() { # bug12836
	$LFS getstripe $MOUNT || error "getstripe $MOUNT failed"
}
run_test 65ia "getstripe on -1 default directory striping"

test_65ib() { # bug12836
	$LFS getstripe -v $MOUNT || error "getstripe -v $MOUNT failed"
}
run_test 65ib "getstripe -v on -1 default directory striping"

test_65ic() { # bug12836
	$LFS find -mtime -1 $MOUNT || error "find $MOUNT failed"
}
run_test 65ic "new find on -1 default directory striping"

test_65j() { # bug6367
	sync; sleep 1
	# if we aren't already remounting for each test, do so for this test
	if [ "$CLEANUP" = ":" -a "$I_MOUNTED" = "yes" ]; then
		cleanup || error "failed to unmount"
		setup
	fi
	$SETSTRIPE -d $MOUNT || error "setstripe failed"
}
run_test 65j "set default striping on root directory (bug 6367)="

test_65k() { # bug11679
        [ "$OSTCOUNT" -lt 2 ] && skip_env "too few OSTs" && return
        remote_mds_nodsh && skip "remote MDS with nodsh" && return

        echo "Check OST status: "
        MDS_OSCS=`do_facet $SINGLEMDS lctl dl | awk '/[oO][sS][cC].*md[ts]/ { print $4 }'`
        for OSC in $MDS_OSCS; do
                echo $OSC "is activate"
                do_facet $SINGLEMDS lctl --device %$OSC activate
        done
        do_facet client mkdir -p $DIR/$tdir
        for INACTIVE_OSC in $MDS_OSCS; do
                echo $INACTIVE_OSC "is Deactivate:"
                do_facet $SINGLEMDS lctl --device  %$INACTIVE_OSC deactivate
                for STRIPE_OSC in $MDS_OSCS; do
                        STRIPE_OST=`osc_to_ost $STRIPE_OSC`
                        STRIPE_INDEX=`do_facet $SINGLEMDS lctl get_param -n lov.*md*.target_obd |
                                      grep $STRIPE_OST | awk -F: '{print $1}' | head -n 1`

                [ -f $DIR/$tdir/${STRIPE_INDEX} ] && continue
                        echo "$SETSTRIPE $DIR/$tdir/${STRIPE_INDEX} -i ${STRIPE_INDEX} -c 1"
                        do_facet client $SETSTRIPE $DIR/$tdir/${STRIPE_INDEX} -i ${STRIPE_INDEX} -c 1
                        RC=$?
                        [ $RC -ne 0 ] && error "setstripe should have succeeded"
                done
                do_facet client rm -f $DIR/$tdir/*
                echo $INACTIVE_OSC "is Activate."
                do_facet $SINGLEMDS lctl --device  %$INACTIVE_OSC activate
        done
}
run_test 65k "validate manual striping works properly with deactivated OSCs"

test_65l() { # bug 12836
	mkdir -p $DIR/$tdir/test_dir
	$SETSTRIPE $DIR/$tdir/test_dir -c -1
	$LFS find -mtime -1 $DIR/$tdir >/dev/null
}
run_test 65l "lfs find on -1 stripe dir ========================"

# bug 2543 - update blocks count on client
test_66() {
	COUNT=${COUNT:-8}
	dd if=/dev/zero of=$DIR/f66 bs=1k count=$COUNT
	sync; sleep 1; sync
	BLOCKS=`ls -s $DIR/f66 | awk '{ print $1 }'`
	[ $BLOCKS -ge $COUNT ] || error "$DIR/f66 blocks $BLOCKS < $COUNT"
}
run_test 66 "update inode blocks count on client ==============="

LLOOP=
LLITELOOPLOAD=
cleanup_68() {
	trap 0
	if [ ! -z "$LLOOP" ]; then
		if swapon -s | grep -q $LLOOP; then
			swapoff $LLOOP || error "swapoff failed"
		fi

		$LCTL blockdev_detach $LLOOP || error "detach failed"
		rm -f $LLOOP
		unset LLOOP
	fi
	if [ ! -z "$LLITELOOPLOAD" ]; then
		rmmod llite_lloop
		unset LLITELOOPLOAD
	fi
	rm -f $DIR/f68*
}

meminfo() {
	awk '($1 == "'$1':") { print $2 }' /proc/meminfo
}

swap_used() {
	swapon -s | awk '($1 == "'$1'") { print $4 }'
}

# test case for lloop driver, basic function
test_68a() {
	[ "$UID" != 0 ] && skip_env "must run as root" && return
	llite_lloop_enabled || \
 		{ skip_env "llite_lloop module disabled" && return; }

	trap cleanup_68 EXIT

	if ! module_loaded llite_lloop; then
		if load_module llite/llite_lloop; then
			LLITELOOPLOAD=yes
		else
			skip_env "can't find module llite_lloop"
			return
		fi
	fi

	LLOOP=$TMP/lloop.`date +%s`.`date +%N`
	dd if=/dev/zero of=$DIR/f68a bs=4k count=1024
	$LCTL blockdev_attach $DIR/f68a $LLOOP || error "attach failed"

	directio rdwr $LLOOP 0 1024 4096 || error "direct write failed"
	directio rdwr $LLOOP 0 1025 4096 && error "direct write should fail"

	cleanup_68
}
run_test 68a "lloop driver - basic test ========================"

# excercise swapping to lustre by adding a high priority swapfile entry
# and then consuming memory until it is used.
test_68b() {  # was test_68
	[ "$UID" != 0 ] && skip_env "must run as root" && return
	lctl get_param -n devices | grep -q obdfilter && \
		skip "local OST" && return

	grep -q llite_lloop /proc/modules
	[ $? -ne 0 ] && skip "can't find module llite_lloop" && return

	[ -z "`$LCTL list_nids | grep -v tcp`" ] && \
		skip "can't reliably test swap with TCP" && return

	MEMTOTAL=`meminfo MemTotal`
	NR_BLOCKS=$((MEMTOTAL>>8))
	[[ $NR_BLOCKS -le 2048 ]] && NR_BLOCKS=2048

	LLOOP=$TMP/lloop.`date +%s`.`date +%N`
	dd if=/dev/zero of=$DIR/f68b bs=64k seek=$NR_BLOCKS count=1
	mkswap $DIR/f68b

	$LCTL blockdev_attach $DIR/f68b $LLOOP || error "attach failed"

	trap cleanup_68 EXIT

	swapon -p 32767 $LLOOP || error "swapon $LLOOP failed"

	echo "before: `swapon -s | grep $LLOOP`"
	$MEMHOG $MEMTOTAL || error "error allocating $MEMTOTAL kB"
	echo "after: `swapon -s | grep $LLOOP`"
	SWAPUSED=`swap_used $LLOOP`

	cleanup_68

	[ $SWAPUSED -eq 0 ] && echo "no swap used???" || true
}
run_test 68b "support swapping to Lustre ========================"

# bug5265, obdfilter oa2dentry return -ENOENT
# #define OBD_FAIL_OST_ENOENT 0x217
test_69() {
	remote_ost_nodsh && skip "remote OST with nodsh" && return

	f="$DIR/$tfile"
	$SETSTRIPE $f -c 1 -i 0

	$DIRECTIO write ${f}.2 0 1 || error "directio write error"

	do_facet ost1 lctl set_param fail_loc=0x217
	$TRUNCATE $f 1 # vmtruncate() will ignore truncate() error.
	$DIRECTIO write $f 0 2 && error "write succeeded, expect -ENOENT"

	do_facet ost1 lctl set_param fail_loc=0
	$DIRECTIO write $f 0 2 || error "write error"

	cancel_lru_locks osc
	$DIRECTIO read $f 0 1 || error "read error"

	do_facet ost1 lctl set_param fail_loc=0x217
	$DIRECTIO read $f 1 1 && error "read succeeded, expect -ENOENT"

	do_facet ost1 lctl set_param fail_loc=0
	rm -f $f
}
run_test 69 "verify oa2dentry return -ENOENT doesn't LBUG ======"

test_71() {
    mkdir -p $DIR/$tdir
    sh rundbench -C -D $DIR/$tdir 2 || error "dbench failed!"
}
run_test 71 "Running dbench on lustre (don't segment fault) ===="

test_72a() { # bug 5695 - Test that on 2.6 remove_suid works properly
	check_kernel_version 43 || return 0
	[ "$RUNAS_ID" = "$UID" ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return

        # Check that testing environment is properly set up. Skip if not
        FAIL_ON_ERROR=false check_runas_id_ret $RUNAS_ID $RUNAS_GID $RUNAS || {
                skip_env "User $RUNAS_ID does not exist - skipping"
                return 0
        }
	# We had better clear the $DIR to get enough space for dd
	rm -rf $DIR/*
	touch $DIR/f72
	chmod 777 $DIR/f72
	chmod ug+s $DIR/f72
	$RUNAS dd if=/dev/zero of=$DIR/f72 bs=512 count=1 || error
	# See if we are still setuid/sgid
	test -u $DIR/f72 -o -g $DIR/f72 && error "S/gid is not dropped on write"
	# Now test that MDS is updated too
	cancel_lru_locks mdc
	test -u $DIR/f72 -o -g $DIR/f72 && error "S/gid is not dropped on MDS"
	true
	rm -f $DIR/f72
}
run_test 72a "Test that remove suid works properly (bug5695) ===="

test_72b() { # bug 24226 -- keep mode setting when size is not changing
	local perm

	[ "$RUNAS_ID" = "$UID" ] && \
		skip_env "RUNAS_ID = UID = $UID -- skipping" && return
	[ "$RUNAS_ID" -eq 0 ] && \
		skip_env "RUNAS_ID = 0 -- skipping" && return

	# Check that testing environment is properly set up. Skip if not
	FAIL_ON_ERROR=false check_runas_id_ret $RUNAS_ID $RUNAS_ID $RUNAS || {
		skip_env "User $RUNAS_ID does not exist - skipping"
		return 0
	}
	touch $DIR/${tfile}-f{g,u}
	mkdir $DIR/${tfile}-d{g,u}
	chmod 770 $DIR/${tfile}-{f,d}{g,u}
	chmod g+s $DIR/${tfile}-{f,d}g
	chmod u+s $DIR/${tfile}-{f,d}u
	for perm in 777 2777 4777; do
		$RUNAS chmod $perm $DIR/${tfile}-fg && error "S/gid file allowed improper chmod to $perm"
		$RUNAS chmod $perm $DIR/${tfile}-fu && error "S/uid file allowed improper chmod to $perm"
		$RUNAS chmod $perm $DIR/${tfile}-dg && error "S/gid dir allowed improper chmod to $perm"
		$RUNAS chmod $perm $DIR/${tfile}-du && error "S/uid dir allowed improper chmod to $perm"
	done
	true
}
run_test 72b "Test that we keep mode setting if without file data changed (bug 24226)"

# bug 3462 - multiple simultaneous MDC requests
test_73() {
	mkdir $DIR/d73-1
	mkdir $DIR/d73-2
	multiop_bg_pause $DIR/d73-1/f73-1 O_c || return 1
	pid1=$!

	lctl set_param fail_loc=0x80000129
	multiop $DIR/d73-1/f73-2 Oc &
	sleep 1
	lctl set_param fail_loc=0

	multiop $DIR/d73-2/f73-3 Oc &
	pid3=$!

	kill -USR1 $pid1
	wait $pid1 || return 1

	sleep 25

	$CHECKSTAT -t file $DIR/d73-1/f73-1 || return 4
	$CHECKSTAT -t file $DIR/d73-1/f73-2 || return 5
	$CHECKSTAT -t file $DIR/d73-2/f73-3 || return 6

	rm -rf $DIR/d73-*
}
run_test 73 "multiple MDC requests (should not deadlock)"

test_74a() { # bug 6149, 6184
	#define OBD_FAIL_LDLM_ENQUEUE_OLD_EXPORT 0x30e
	#
	# very important to OR with OBD_FAIL_ONCE (0x80000000) -- otherwise it
	# will spin in a tight reconnection loop
	touch $DIR/f74a
	lctl set_param fail_loc=0x8000030e
	# get any lock that won't be difficult - lookup works.
	ls $DIR/f74a
	lctl set_param fail_loc=0
	true
	rm -f $DIR/f74a
}
run_test 74a "ldlm_enqueue freed-export error path, ls (shouldn't LBUG)"

test_74b() { # bug 13310
	#define OBD_FAIL_LDLM_ENQUEUE_OLD_EXPORT 0x30e
	#
	# very important to OR with OBD_FAIL_ONCE (0x80000000) -- otherwise it
	# will spin in a tight reconnection loop
	lctl set_param fail_loc=0x8000030e
	# get a "difficult" lock
	touch $DIR/f74b
	lctl set_param fail_loc=0
	true
	rm -f $DIR/f74b
}
run_test 74b "ldlm_enqueue freed-export error path, touch (shouldn't LBUG)"

test_74c() {
#define OBD_FAIL_LDLM_NEW_LOCK
	lctl set_param fail_loc=0x80000319
	touch $DIR/$tfile && error "Touch successful"
	true
}
run_test 74c "ldlm_lock_create error path, (shouldn't LBUG)"

num_inodes() {
	awk '/lustre_inode_cache/ {print $2; exit}' /proc/slabinfo
}

get_inode_slab_tunables() {
	awk '/lustre_inode_cache/ {print $9," ",$10," ",$11; exit}' /proc/slabinfo
}

set_inode_slab_tunables() {
	echo "lustre_inode_cache $1" > /proc/slabinfo
}

test_76() { # Now for bug 20433, added originally in bug 1443
	local SLAB_SETTINGS=`get_inode_slab_tunables`
	local CPUS=`getconf _NPROCESSORS_ONLN`
	# we cannot set limit below 1 which means 1 inode in each
	# per-cpu cache is still allowed
	set_inode_slab_tunables "1 1 0"
	cancel_lru_locks osc
	BEFORE_INODES=`num_inodes`
	echo "before inodes: $BEFORE_INODES"
	local COUNT=1000
	[ "$SLOW" = "no" ] && COUNT=100
	for i in `seq $COUNT`; do
		touch $DIR/$tfile
		rm -f $DIR/$tfile
	done
	cancel_lru_locks osc
	AFTER_INODES=`num_inodes`
	echo "after inodes: $AFTER_INODES"
	local wait=0
	while [ $((AFTER_INODES-1*CPUS)) -gt $BEFORE_INODES ]; do
		sleep 2
		AFTER_INODES=`num_inodes`
		wait=$((wait+2))
		echo "wait $wait seconds inodes: $AFTER_INODES"
		if [ $wait -gt 30 ]; then
			error "inode slab grew from $BEFORE_INODES to $AFTER_INODES"
		fi
	done
	set_inode_slab_tunables "$SLAB_SETTINGS"
}
run_test 76 "confirm clients recycle inodes properly ===="


export ORIG_CSUM=""
set_checksums()
{
	# Note: in sptlrpc modes which enable its own bulk checksum, the
	# original crc32_le bulk checksum will be automatically disabled,
	# and the OBD_FAIL_OSC_CHECKSUM_SEND/OBD_FAIL_OSC_CHECKSUM_RECEIVE
	# will be checked by sptlrpc code against sptlrpc bulk checksum.
	# In this case set_checksums() will not be no-op, because sptlrpc
	# bulk checksum will be enabled all through the test.

	[ "$ORIG_CSUM" ] || ORIG_CSUM=`lctl get_param -n osc.*.checksums | head -n1`
        lctl set_param -n osc.*.checksums $1
	return 0
}

export ORIG_CSUM_TYPE=""
CKSUM_TYPES=${CKSUM_TYPES:-"crc32 adler"}
set_checksum_type()
{
	[ "$ORIG_CSUM_TYPE" ] || \
		ORIG_CSUM_TYPE=`lctl get_param -n osc/*osc-[^mM]*/checksum_type |
                                sed 's/.*\[\(.*\)\].*/\1/g' | head -n1`
	lctl set_param -n osc.*osc-[^mM]*.checksum_type $1
	log "set checksum type to $1"
	return 0
}
F77_TMP=$TMP/f77-temp
F77SZ=8
setup_f77() {
	dd if=/dev/urandom of=$F77_TMP bs=1M count=$F77SZ || \
		error "error writing to $F77_TMP"
}

test_77a() { # bug 10889
	$GSS && skip "could not run with gss" && return
	[ ! -f $F77_TMP ] && setup_f77
	set_checksums 1
	dd if=$F77_TMP of=$DIR/$tfile bs=1M count=$F77SZ || error "dd error"
	set_checksums 0
	rm -f $DIR/$tfile
}
run_test 77a "normal checksum read/write operation ============="

test_77b() { # bug 10889
	$GSS && skip "could not run with gss" && return
	[ ! -f $F77_TMP ] && setup_f77
	#define OBD_FAIL_OSC_CHECKSUM_SEND       0x409
	lctl set_param fail_loc=0x80000409
	set_checksums 1
	dd if=$F77_TMP of=$DIR/f77b bs=1M count=$F77SZ conv=sync || \
		error "dd error: $?"
	lctl set_param fail_loc=0
	set_checksums 0
}
run_test 77b "checksum error on client write ===================="

test_77c() { # bug 10889
	$GSS && skip "could not run with gss" && return
	[ ! -f $DIR/f77b ] && skip "requires 77b - skipping" && return
	set_checksums 1
	for algo in $CKSUM_TYPES; do
		cancel_lru_locks osc
		set_checksum_type $algo
		#define OBD_FAIL_OSC_CHECKSUM_RECEIVE    0x408
		lctl set_param fail_loc=0x80000408
		cmp $F77_TMP $DIR/f77b || error "file compare failed"
		lctl set_param fail_loc=0
	done
	set_checksums 0
	set_checksum_type $ORIG_CSUM_TYPE
	rm -f $DIR/f77b
}
run_test 77c "checksum error on client read ==================="

test_77d() { # bug 10889
	$GSS && skip "could not run with gss" && return
	#define OBD_FAIL_OSC_CHECKSUM_SEND       0x409
	lctl set_param fail_loc=0x80000409
	set_checksums 1
	directio write $DIR/f77 0 $F77SZ $((1024 * 1024)) || \
		error "direct write: rc=$?"
	lctl set_param fail_loc=0
	set_checksums 0
}
run_test 77d "checksum error on OST direct write ==============="

test_77e() { # bug 10889
	$GSS && skip "could not run with gss" && return
	[ ! -f $DIR/f77 ] && skip "requires 77d - skipping" && return
	#define OBD_FAIL_OSC_CHECKSUM_RECEIVE    0x408
	lctl set_param fail_loc=0x80000408
	set_checksums 1
	cancel_lru_locks osc
	directio read $DIR/f77 0 $F77SZ $((1024 * 1024)) || \
		error "direct read: rc=$?"
	lctl set_param fail_loc=0
	set_checksums 0
}
run_test 77e "checksum error on OST direct read ================"

test_77f() { # bug 10889
	$GSS && skip "could not run with gss" && return
	set_checksums 1
	for algo in $CKSUM_TYPES; do
		cancel_lru_locks osc
		set_checksum_type $algo
		#define OBD_FAIL_OSC_CHECKSUM_SEND       0x409
		lctl set_param fail_loc=0x409
		directio write $DIR/f77 0 $F77SZ $((1024 * 1024)) && \
			error "direct write succeeded"
		lctl set_param fail_loc=0
	done
	set_checksum_type $ORIG_CSUM_TYPE
	set_checksums 0
}
run_test 77f "repeat checksum error on write (expect error) ===="

test_77g() { # bug 10889
	$GSS && skip "could not run with gss" && return
	remote_ost_nodsh && skip "remote OST with nodsh" && return

	[ ! -f $F77_TMP ] && setup_f77

	$SETSTRIPE $DIR/f77g -c 1 -i 0
	#define OBD_FAIL_OST_CHECKSUM_RECEIVE       0x21a
	do_facet ost1 lctl set_param fail_loc=0x8000021a
	set_checksums 1
	dd if=$F77_TMP of=$DIR/f77g bs=1M count=$F77SZ || \
		error "write error: rc=$?"
	do_facet ost1 lctl set_param fail_loc=0
	set_checksums 0
}
run_test 77g "checksum error on OST write ======================"

test_77h() { # bug 10889
	$GSS && skip "could not run with gss" && return
	remote_ost_nodsh && skip "remote OST with nodsh" && return

	[ ! -f $DIR/f77g ] && skip "requires 77g - skipping" && return
	cancel_lru_locks osc
	#define OBD_FAIL_OST_CHECKSUM_SEND          0x21b
	do_facet ost1 lctl set_param fail_loc=0x8000021b
	set_checksums 1
	cmp $F77_TMP $DIR/f77g || error "file compare failed"
	do_facet ost1 lctl set_param fail_loc=0
	set_checksums 0
}
run_test 77h "checksum error on OST read ======================="

test_77i() { # bug 13805
	$GSS && skip "could not run with gss" && return
	#define OBD_FAIL_OSC_CONNECT_CKSUM       0x40b
	lctl set_param fail_loc=0x40b
	remount_client $MOUNT
	lctl set_param fail_loc=0
	for VALUE in `lctl get_param osc.*osc-[^mM]*.checksum_type`; do
		PARAM=`echo ${VALUE[0]} | cut -d "=" -f1`
		algo=`lctl get_param -n $PARAM | sed 's/.*\[\(.*\)\].*/\1/g'`
		[ "$algo" = "crc32" ] || error "algo set to $algo instead of crc32"
	done
	remount_client $MOUNT
}
run_test 77i "client not supporting OSD_CONNECT_CKSUM =========="

test_77j() { # bug 13805
	$GSS && skip "could not run with gss" && return
	#define OBD_FAIL_OSC_CKSUM_ADLER_ONLY    0x40c
	lctl set_param fail_loc=0x40c
	remount_client $MOUNT
	lctl set_param fail_loc=0
	sleep 2 # wait async osc connect to finish
	for VALUE in `lctl get_param osc.*osc-[^mM]*.checksum_type`; do
                PARAM=`echo ${VALUE[0]} | cut -d "=" -f1`
		algo=`lctl get_param -n $PARAM | sed 's/.*\[\(.*\)\].*/\1/g'`
		[ "$algo" = "adler" ] || error "algo set to $algo instead of adler"
	done
	remount_client $MOUNT
}
run_test 77j "client only supporting ADLER32 ===================="

[ "$ORIG_CSUM" ] && set_checksums $ORIG_CSUM || true
rm -f $F77_TMP
unset F77_TMP

test_78() { # bug 10901
	remote_ost || { skip_env "local OST" && return; }

	NSEQ=5
	F78SIZE=$(($(awk '/MemFree:/ { print $2 }' /proc/meminfo) / 1024))
	echo "MemFree: $F78SIZE, Max file size: $MAXFREE"
	MEMTOTAL=$(($(awk '/MemTotal:/ { print $2 }' /proc/meminfo) / 1024))
	echo "MemTotal: $MEMTOTAL"
# reserve 256MB of memory for the kernel and other running processes,
# and then take 1/2 of the remaining memory for the read/write buffers.
    if [ $MEMTOTAL -gt 512 ] ;then
        MEMTOTAL=$(((MEMTOTAL - 256 ) / 2))
    else
        # for those poor memory-starved high-end clusters...
        MEMTOTAL=$((MEMTOTAL / 2))
    fi
	echo "Mem to use for directio: $MEMTOTAL"
	[ $F78SIZE -gt $MEMTOTAL ] && F78SIZE=$MEMTOTAL
	[ $F78SIZE -gt 512 ] && F78SIZE=512
	[ $F78SIZE -gt $((MAXFREE / 1024)) ] && F78SIZE=$((MAXFREE / 1024))
	SMALLESTOST=`lfs df $DIR |grep OST | awk '{print $4}' |sort -n |head -1`
	echo "Smallest OST: $SMALLESTOST"
	[ $SMALLESTOST -lt 10240 ] && \
		skip "too small OSTSIZE, useless to run large O_DIRECT test" && return 0

	[ $F78SIZE -gt $((SMALLESTOST * $OSTCOUNT / 1024 - 80)) ] && \
		F78SIZE=$((SMALLESTOST * $OSTCOUNT / 1024 - 80))

	[ "$SLOW" = "no" ] && NSEQ=1 && [ $F78SIZE -gt 32 ] && F78SIZE=32
	echo "File size: $F78SIZE"
	$SETSTRIPE $DIR/$tfile -c $OSTCOUNT || error "setstripe failed"
 	for i in `seq 1 $NSEQ`
 	do
 		FSIZE=$(($F78SIZE / ($NSEQ - $i + 1)))
 		echo directIO rdwr round $i of $NSEQ
  	 	$DIRECTIO rdwr $DIR/$tfile 0 $FSIZE 1048576||error "rdwr failed"
  	done

	rm -f $DIR/$tfile
}
run_test 78 "handle large O_DIRECT writes correctly ============"

test_79() { # bug 12743
	wait_delete_completed

        BKTOTAL=$(calc_osc_kbytes kbytestotal)
        BKFREE=$(calc_osc_kbytes kbytesfree)
        BKAVAIL=$(calc_osc_kbytes kbytesavail)

        STRING=`df -P $MOUNT | tail -n 1 | awk '{print $2","$3","$4}'`
        DFTOTAL=`echo $STRING | cut -d, -f1`
        DFUSED=`echo $STRING  | cut -d, -f2`
        DFAVAIL=`echo $STRING | cut -d, -f3`
        DFFREE=$(($DFTOTAL - $DFUSED))

        ALLOWANCE=$((64 * $OSTCOUNT))

        if [ $DFTOTAL -lt $(($BKTOTAL - $ALLOWANCE)) ] ||
           [ $DFTOTAL -gt $(($BKTOTAL + $ALLOWANCE)) ] ; then
                error "df total($DFTOTAL) mismatch OST total($BKTOTAL)"
        fi
        if [ $DFFREE -lt $(($BKFREE - $ALLOWANCE)) ] ||
           [ $DFFREE -gt $(($BKFREE + $ALLOWANCE)) ] ; then
                error "df free($DFFREE) mismatch OST free($BKFREE)"
        fi
        if [ $DFAVAIL -lt $(($BKAVAIL - $ALLOWANCE)) ] ||
           [ $DFAVAIL -gt $(($BKAVAIL + $ALLOWANCE)) ] ; then
                error "df avail($DFAVAIL) mismatch OST avail($BKAVAIL)"
        fi
}
run_test 79 "df report consistency check ======================="

test_80() { # bug 10718
        dd if=/dev/zero of=$DIR/$tfile bs=1M count=1 seek=1M
        sync; sleep 1; sync
        local BEFORE=`date +%s`
        cancel_lru_locks osc
        local AFTER=`date +%s`
        local DIFF=$((AFTER-BEFORE))
        if [ $DIFF -gt 1 ] ; then
                error "elapsed for 1M@1T = $DIFF"
        fi
        true
        rm -f $DIR/$tfile
}
run_test 80 "Page eviction is equally fast at high offsets too  ===="

test_81a() { # LU-456
        # define OBD_FAIL_OST_MAPBLK_ENOSPC    0x228
        # MUST OR with the OBD_FAIL_ONCE (0x80000000)
        do_facet ost0 lctl set_param fail_loc=0x80000228

        # write should trigger a retry and success
        $SETSTRIPE -i 0 -c 1 $DIR/$tfile
        multiop $DIR/$tfile oO_CREAT:O_RDWR:O_SYNC:w4096c
        RC=$?
        if [ $RC -ne 0 ] ; then
                error "write should success, but failed for $RC"
        fi
}
run_test 81a "OST should retry write when get -ENOSPC ==============="

test_81b() { # LU-456
        # define OBD_FAIL_OST_MAPBLK_ENOSPC    0x228
        # Don't OR with the OBD_FAIL_ONCE (0x80000000)
        do_facet ost0 lctl set_param fail_loc=0x228

        # write should retry several times and return -ENOSPC finally
        $SETSTRIPE -i 0 -c 1 $DIR/$tfile
        multiop $DIR/$tfile oO_CREAT:O_RDWR:O_SYNC:w4096c
        RC=$?
        ENOSPC=28
        if [ $RC -ne $ENOSPC ] ; then
                error "dd should fail for -ENOSPC, but succeed."
        fi
}
run_test 81b "OST should return -ENOSPC when retry still fails ======="


test_99a() {
        [ -z "$(which cvs 2>/dev/null)" ] && skip_env "could not find cvs" && \
	    return
	mkdir -p $DIR/d99cvsroot
	chown $RUNAS_ID $DIR/d99cvsroot
	local oldPWD=$PWD	# bug 13584, use $TMP as working dir
	cd $TMP

	$RUNAS cvs -d $DIR/d99cvsroot init || error
	cd $oldPWD
}
run_test 99a "cvs init ========================================="

test_99b() {
        [ -z "$(which cvs 2>/dev/null)" ] && skip_env "could not find cvs" && return
	[ ! -d $DIR/d99cvsroot ] && test_99a
	cd /etc/init.d
	# some versions of cvs import exit(1) when asked to import links or
	# files they can't read.  ignore those files.
	TOIGNORE=$(find . -type l -printf '-I %f\n' -o \
			! -perm +4 -printf '-I %f\n')
	$RUNAS cvs -d $DIR/d99cvsroot import -m "nomesg" $TOIGNORE \
		d99reposname vtag rtag
}
run_test 99b "cvs import ======================================="

test_99c() {
        [ -z "$(which cvs 2>/dev/null)" ] && skip_env "could not find cvs" && return
	[ ! -d $DIR/d99cvsroot ] && test_99b
	cd $DIR
	mkdir -p $DIR/d99reposname
	chown $RUNAS_ID $DIR/d99reposname
	$RUNAS cvs -d $DIR/d99cvsroot co d99reposname
}
run_test 99c "cvs checkout ====================================="

test_99d() {
        [ -z "$(which cvs 2>/dev/null)" ] && skip_env "could not find cvs" && return
	[ ! -d $DIR/d99cvsroot ] && test_99c
	cd $DIR/d99reposname
	$RUNAS touch foo99
	$RUNAS cvs add -m 'addmsg' foo99
}
run_test 99d "cvs add =========================================="

test_99e() {
        [ -z "$(which cvs 2>/dev/null)" ] && skip_env "could not find cvs" && return
	[ ! -d $DIR/d99cvsroot ] && test_99c
	cd $DIR/d99reposname
	$RUNAS cvs update
}
run_test 99e "cvs update ======================================="

test_99f() {
        [ -z "$(which cvs 2>/dev/null)" ] && skip_env "could not find cvs" && return
	[ ! -d $DIR/d99cvsroot ] && test_99d
	cd $DIR/d99reposname
	$RUNAS cvs commit -m 'nomsg' foo99
    rm -fr $DIR/d99cvsroot
}
run_test 99f "cvs commit ======================================="

test_100() {
	[ "$NETTYPE" = tcp ] || \
		{ skip "TCP secure port test, not useful for NETTYPE=$NETTYPE" && \
			return ; }

	remote_ost_nodsh && skip "remote OST with nodsh" && return
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
	remote_servers || \
		{ skip "useless for local single node setup" && return; }

	netstat -tna | ( rc=1; while read PROT SND RCV LOCAL REMOTE STAT; do
		[ "$PROT" != "tcp" ] && continue
		RPORT=$(echo $REMOTE | cut -d: -f2)
		[ "$RPORT" != "$ACCEPTOR_PORT" ] && continue

		rc=0
		LPORT=`echo $LOCAL | cut -d: -f2`
		if [ $LPORT -ge 1024 ]; then
			echo "bad: $PROT $SND $RCV $LOCAL $REMOTE $STAT"
			netstat -tna
			error_exit "local: $LPORT > 1024, remote: $RPORT"
		fi
	done
	[ "$rc" = 0 ] || error_exit "privileged port not found" )
}
run_test 100 "check local port using privileged port ==========="

function get_named_value()
{
    local tag

    tag=$1
    while read ;do
        line=$REPLY
        case $line in
        $tag*)
            echo $line | sed "s/^$tag//"
            break
            ;;
        esac
    done
}

export CACHE_MAX=`lctl get_param -n llite.*.max_cached_mb | head -n 1`
cleanup_101() {
	lctl set_param -n llite.*.max_cached_mb $CACHE_MAX
	trap 0
}

test_101() {
	local s
	local discard
	local nreads=10000
	[ "$CPU" = "UML" ] && nreads=1000
	local cache_limit=32

	lctl set_param -n osc.*-osc*.rpc_stats 0
	trap cleanup_101 EXIT
	lctl set_param -n llite.*.read_ahead_stats 0
	lctl set_param -n llite.*.max_cached_mb $cache_limit

	#
	# randomly read 10000 of 64K chunks from file 3x 32MB in size
	#
	echo "nreads: $nreads file size: $((cache_limit * 3))MB"
	$READS -f $DIR/$tfile -s$((cache_limit * 3192 * 1024)) -b65536 -C -n$nreads -t 180

	discard=0
        for s in `lctl get_param -n llite.*.read_ahead_stats | \
		get_named_value 'read but discarded' | cut -d" " -f1`; do
			discard=$(($discard + $s))
	done
	cleanup_101

	if [ $(($discard * 10)) -gt $nreads ] ;then
		lctl get_param osc.*-osc*.rpc_stats
		lctl get_param llite.*.read_ahead_stats
		error "too many ($discard) discarded pages"
	fi
	rm -f $DIR/$tfile || true
}
run_test 101 "check read-ahead for random reads ================"

setup_test101b() {
	mkdir -p $DIR/$tdir
	STRIPE_SIZE=1048576
	STRIPE_COUNT=$OSTCOUNT
	STRIPE_OFFSET=0

	trap cleanup_test101b EXIT
	# prepare the read-ahead file
	$SETSTRIPE $DIR/$tfile -s $STRIPE_SIZE -i $STRIPE_OFFSET -c $OSTCOUNT

	dd if=/dev/zero of=$DIR/$tfile bs=1024k count=100 2> /dev/null
}

cleanup_test101b() {
	trap 0
	rm -rf $DIR/$tdir
	rm -f $DIR/$tfile
}

calc_total() {
	awk 'BEGIN{total=0}; {total+=$1}; END{print total}'
}

ra_check_101() {
	local READ_SIZE=$1
	local STRIPE_SIZE=1048576
	local RA_INC=1048576
	local STRIDE_LENGTH=$((STRIPE_SIZE/READ_SIZE))
	local FILE_LENGTH=$((64*100))
	local discard_limit=$((((STRIDE_LENGTH - 1)*3/(STRIDE_LENGTH*OSTCOUNT))* \
			     (STRIDE_LENGTH*OSTCOUNT - STRIDE_LENGTH)))
	DISCARD=`$LCTL get_param -n llite.*.read_ahead_stats | \
			get_named_value 'read but discarded' | \
			cut -d" " -f1 | calc_total`

	if [ $DISCARD -gt $discard_limit ]; then
		lctl get_param llite.*.read_ahead_stats
		error "Too many ($DISCARD) discarded pages with size (${READ_SIZE})"
	else
		echo "Read-ahead success for size ${READ_SIZE}"
	fi
}

test_101b() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "skipping stride IO stride-ahead test" && return
	local STRIPE_SIZE=1048576
	local STRIDE_SIZE=$((STRIPE_SIZE*OSTCOUNT))
	local FILE_LENGTH=$((STRIPE_SIZE*100))
	local ITERATION=$((FILE_LENGTH/STRIDE_SIZE))
	# prepare the read-ahead file
	setup_test101b
	cancel_lru_locks osc
	for BIDX in 2 4 8 16 32 64 128 256
	do
		local BSIZE=$((BIDX*4096))
		local READ_COUNT=$((STRIPE_SIZE/BSIZE))
		local STRIDE_LENGTH=$((STRIDE_SIZE/BSIZE))
		local OFFSET=$((STRIPE_SIZE/BSIZE*(OSTCOUNT - 1)))
		$LCTL set_param -n llite.*.read_ahead_stats 0
		$READS -f $DIR/$tfile  -l $STRIDE_LENGTH -o $OFFSET \
			      -s $FILE_LENGTH -b $STRIPE_SIZE -a $READ_COUNT -n $ITERATION
		cancel_lru_locks osc
		ra_check_101 $BSIZE
	done
	cleanup_test101b
	true
}
run_test 101b "check stride-io mode read-ahead ================="

set_read_ahead() {
   lctl get_param -n llite.*.max_read_ahead_mb | head -n 1
   lctl set_param -n llite.*.max_read_ahead_mb $1 > /dev/null 2>&1
}

test_101d() {
    local file=$DIR/$tfile
    local size=${FILESIZE_101c:-500}
    local ra_MB=${READAHEAD_MB:-40}

    local space=$(df -P $DIR | tail -n 1 | awk '{ print $4 }')
    [ $space -gt $((size / 1024)) ] ||
        { skip "Need free space ${size}M, have $space" && return; }

    echo Creating ${size}M test file $file
    dd if=/dev/zero of=$file bs=1M count=$size
    echo Cancel LRU locks on lustre client to flush the client cache
    cancel_lru_locks osc

    echo Disable read-ahead
    local old_READAHEAD=$(set_read_ahead 0)

    echo Reading the test file $file with read-ahead disabled
    time_ra_OFF=$(do_and_time "dd if=$file of=/dev/null bs=1M count=$size")

    echo Cancel LRU locks on lustre client to flush the client cache
    cancel_lru_locks osc
    echo Enable read-ahead with ${ra_MB}MB
    set_read_ahead $ra_MB

    echo Reading the test file $file with read-ahead enabled
    time_ra_ON=$(do_and_time "dd if=$file of=/dev/null bs=1M count=$size")

    echo read-ahead disabled time read $time_ra_OFF
    echo read-ahead enabled  time read $time_ra_ON

    set_read_ahead $old_READAHEAD
    rm -f $file

    [ $time_ra_ON -lt $time_ra_OFF ] ||
        error "read-ahead enabled  time read (${time_ra_ON}s) is more than
               read-ahead disabled time read (${time_ra_OFF}s) filesize ${size}M"
}
run_test 101d "file read with and without read-ahead enabled  ================="

setup_test102() {
	mkdir -p $DIR/$tdir
	chown $RUNAS_ID $DIR/$tdir
	STRIPE_SIZE=65536
	STRIPE_OFFSET=1
	STRIPE_COUNT=$OSTCOUNT
	[ $OSTCOUNT -gt 4 ] && STRIPE_COUNT=4

	trap cleanup_test102 EXIT
	cd $DIR
	$1 $SETSTRIPE $tdir -s $STRIPE_SIZE -i $STRIPE_OFFSET -c $STRIPE_COUNT
	cd $DIR/$tdir
	for num in 1 2 3 4
	do
		for count in `seq 1 $STRIPE_COUNT`
		do
			for offset in `seq 0 $[$STRIPE_COUNT - 1]`
			do
				local stripe_size=`expr $STRIPE_SIZE \* $num`
				local file=file"$num-$offset-$count"
				$1 $SETSTRIPE $file -s $stripe_size -i $offset -c $count
			done
		done
	done

	cd $DIR
	$1 $TAR cf $TMP/f102.tar $tdir --xattrs
}

cleanup_test102() {
	trap 0
	rm -f $TMP/f102.tar
	rm -rf $DIR/d0.sanity/d102
}

test_102a() {
	local testfile=$DIR/xattr_testfile

	rm -f $testfile
        touch $testfile

	[ "$UID" != 0 ] && skip_env "must run as root" && return
	[ -z "`lctl get_param -n mdc.*-mdc-*.connect_flags | grep xattr`" ] && skip_env "must have user_xattr" && return

	[ -z "$(which setfattr 2>/dev/null)" ] && skip_env "could not find setfattr" && return

	echo "set/get xattr..."
        setfattr -n trusted.name1 -v value1 $testfile || error
        [ "`getfattr -n trusted.name1 $testfile 2> /dev/null | \
        grep "trusted.name1"`" == "trusted.name1=\"value1\"" ] || error

        setfattr -n user.author1 -v author1 $testfile || error
        [ "`getfattr -n user.author1 $testfile 2> /dev/null | \
        grep "user.author1"`" == "user.author1=\"author1\"" ] || error

	echo "listxattr..."
        setfattr -n trusted.name2 -v value2 $testfile || error
        setfattr -n trusted.name3 -v value3 $testfile || error
        [ `getfattr -d -m "^trusted" $testfile 2> /dev/null | \
        grep "trusted.name" | wc -l` -eq 3 ] || error


        setfattr -n user.author2 -v author2 $testfile || error
        setfattr -n user.author3 -v author3 $testfile || error
        [ `getfattr -d -m "^user" $testfile 2> /dev/null | \
        grep "user" | wc -l` -eq 3 ] || error

	echo "remove xattr..."
        setfattr -x trusted.name1 $testfile || error
        getfattr -d -m trusted $testfile 2> /dev/null | \
        grep "trusted.name1" && error || true

        setfattr -x user.author1 $testfile || error
        getfattr -d -m user $testfile 2> /dev/null | \
        grep "user.author1" && error || true

	# b10667: setting lustre special xattr be silently discarded
	echo "set lustre special xattr ..."
	setfattr -n "trusted.lov" -v "invalid value" $testfile || error

	rm -f $testfile
}
run_test 102a "user xattr test =================================="

test_102b() {
	# b10930: get/set/list trusted.lov xattr
	echo "get/set/list trusted.lov xattr ..."
	[ "$OSTCOUNT" -lt "2" ] && skip_env "skipping 2-stripe test" && return
	local testfile=$DIR/$tfile
	$SETSTRIPE -s 65536 -i 1 -c 2 $testfile || error "setstripe failed"
	getfattr -d -m "^trusted" $testfile 2> /dev/null | \
	grep "trusted.lov" || error "can't get trusted.lov from $testfile"

	local testfile2=${testfile}2
	local value=`getfattr -n trusted.lov $testfile 2> /dev/null | \
		     grep "trusted.lov" |sed -e 's/[^=]\+=//'`

	$MCREATE $testfile2
	setfattr -n trusted.lov -v $value $testfile2
	local tmp_file=${testfile}3
	$GETSTRIPE -v $testfile2 > $tmp_file
	local stripe_size=`grep "size"  $tmp_file| awk '{print $2}'`
	local stripe_count=`grep "count"  $tmp_file| awk '{print $2}'`
	[ "$stripe_size" -eq 65536 ] || error "stripe size $stripe_size != 65536"
	[ "$stripe_count" -eq 2 ] || error "stripe count $stripe_count != 2"
	rm -f $DIR/$tfile
}
run_test 102b "getfattr/setfattr for trusted.lov EAs ============"

test_102c() {
	# b10930: get/set/list lustre.lov xattr
	echo "get/set/list lustre.lov xattr ..."
	[ "$OSTCOUNT" -lt "2" ] && skip_env "skipping 2-stripe test" && return
	mkdir -p $DIR/$tdir
	chown $RUNAS_ID $DIR/$tdir
	local testfile=$DIR/$tdir/$tfile
	$RUNAS $SETSTRIPE -s 65536 -i 1 -c 2 $testfile||error "setstripe failed"
	$RUNAS getfattr -d -m "^lustre" $testfile 2> /dev/null | \
	grep "lustre.lov" || error "can't get lustre.lov from $testfile"

	local testfile2=${testfile}2
	local value=`getfattr -n lustre.lov $testfile 2> /dev/null | \
		     grep "lustre.lov" |sed -e 's/[^=]\+=//'  `

	$RUNAS $MCREATE $testfile2
	$RUNAS setfattr -n lustre.lov -v $value $testfile2
	local tmp_file=${testfile}3
	$RUNAS $GETSTRIPE -v $testfile2 > $tmp_file
	local stripe_size=`grep "size"  $tmp_file| awk '{print $2}'`
	local stripe_count=`grep "count"  $tmp_file| awk '{print $2}'`
	[ $stripe_size -eq 65536 ] || error "stripe size $stripe_size != 65536"
	[ $stripe_count -eq 2 ] || error "stripe count $stripe_count != 2"
}
run_test 102c "non-root getfattr/setfattr for lustre.lov EAs ==========="

compare_stripe_info1() {
	local stripe_index_all_zero=1

	for num in 1 2 3 4
	do
 		for count in `seq 1 $STRIPE_COUNT`
		do
			for offset in `seq 0 $[$STRIPE_COUNT - 1]`
			do
				local size=`expr $STRIPE_SIZE \* $num`
				local file=file"$num-$offset-$count"
				get_stripe_info client $PWD/$file "$1"
				if [ $stripe_size -ne $size ]; then
					error "$file: different stripe size $stripe_size, expected $size" && return
				fi
				if [ $stripe_count -ne $count ]; then
					error "$file: different stripe count $stripe_count, expected $count" && return
				fi
				if [ $stripe_index -ne 0 ]; then
				       stripe_index_all_zero=0
				fi
			done
		done
	done
	[ $stripe_index_all_zero -eq 1 ] && error "all files are being extracted starting from OST index 0"
	return 0
}

compare_stripe_info2() {
	for num in 1 2 3 4
	do
		for count in `seq 1 $STRIPE_COUNT`
		do
			for offset in `seq 0 $[$STRIPE_COUNT - 1]`
			do
				local size=`expr $STRIPE_SIZE \* $num`
				local file=file"$num-$offset-$count"
				get_stripe_info client $PWD/$file
				if [ $stripe_size -ne $size ]; then
					error "$file: different stripe size $stripe_size, expected $size" && return
				fi
				if [ $stripe_count -ne $count ]; then
					error "$file: different stripe count $stripe_count, expected $count" && return
				fi
				if [ $stripe_index -ne $offset ]; then
					error "$file: different stripe offset $stripe_index, expected $offset" && return
				fi
			done
		done
	done
}

find_lustre_tar() {
	[ -n "$(which tar 2>/dev/null)" ] && strings $(which tar) | grep -q lustre && echo tar
}

test_102d() {
	# b10930: tar test for trusted.lov xattr
	TAR=$(find_lustre_tar)
	[ -z "$TAR" ] && skip_env "lustre-aware tar is not installed" && return
	[ "$OSTCOUNT" -lt "2" ] && skip_env "skipping N-stripe test" && return
	setup_test102
	mkdir -p $DIR/d102d
	$TAR xf $TMP/f102.tar -C $DIR/d102d --xattrs
	cd $DIR/d102d/$tdir
	compare_stripe_info1
}
run_test 102d "tar restore stripe info from tarfile,not keep osts ==========="

test_102f() {
	# b10930: tar test for trusted.lov xattr
	TAR=$(find_lustre_tar)
	[ -z "$TAR" ] && skip_env "lustre-aware tar is not installed" && return
	[ "$OSTCOUNT" -lt "2" ] && skip_env "skipping N-stripe test" && return
	setup_test102
	mkdir -p $DIR/d102f
	cd $DIR
	$TAR cf - --xattrs $tdir | $TAR xf - --xattrs -C $DIR/d102f
	cd $DIR/d102f/$tdir
	compare_stripe_info1
}
run_test 102f "tar copy files, not keep osts ==========="

test_102h() { # bug 15777
	[ -z $(lctl get_param -n mdc.*.connect_flags | grep xattr) ] &&
		skip "must have user_xattr" && return
	[ -z "$(which setfattr 2>/dev/null)" ] &&
		skip_env "could not find setfattr" && return

	XBIG=trusted.big
	XSIZE=1024
	touch $DIR/$tfile
	VALUE=datadatadatadatadatadatadatadata
	while [ $(echo $VALUE | wc -c) -lt $XSIZE ]; do
		VALUE="$VALUE$VALUE"
	done
	log "save $XBIG on $DIR/$tfile"
        setfattr -n $XBIG -v "$VALUE" $DIR/$tfile ||
		error "saving $XBIG on $DIR/$tfile failed"
        ORIG=$(getfattr -n $XBIG $DIR/$tfile 2> /dev/null | grep $XBIG)
	OSIZE=$(echo $ORIG | wc -c)
	[ $OSIZE -lt $XSIZE ] && error "set $XBIG too small ($OSIZE < $XSIZE)"

	XSML=trusted.sml
	log "save $XSML on $DIR/$tfile"
        setfattr -n $XSML -v val $DIR/$tfile ||
		error "saving $XSML on $DIR/$tfile failed"
        NEW=$(getfattr -n $XBIG $DIR/$tfile 2> /dev/null | grep $XBIG)
	if [ "$NEW" != "$ORIG" ]; then
		log "orig: $ORIG"
		log "new: $NEW"
		error "$XBIG different after saving $XSML"
	fi

	log "grow $XSML on $DIR/$tfile"
        setfattr -n $XSML -v "$VALUE" $DIR/$tfile ||
		error "growing $XSML on $DIR/$tfile failed"
        NEW=$(getfattr -n $XBIG $DIR/$tfile 2> /dev/null | grep $XBIG)
	if [ "$NEW" != "$ORIG" ]; then
		log "orig: $ORIG"
		log "new: $NEW"
		error "$XBIG different after growing $XSML"
	fi
	log "$XBIG still valid after growing $XSML"
	rm -f $file
}
run_test 102h "grow xattr from inside inode to external block"

test_102i() { # bug 17038
        touch $DIR/$tfile
        ln -s $DIR/$tfile $DIR/${tfile}link
        getfattr -n trusted.lov $DIR/$tfile || error "lgetxattr on $DIR/$tfile failed"
        getfattr -h -n trusted.lov $DIR/${tfile}link 2>&1 | grep -i "no such attr" || error "error for lgetxattr on $DIR/${tfile}link is not ENODATA"
        rm -f $DIR/$tfile $DIR/${tfile}link
}
run_test 102i "lgetxattr test on symbolic link ============"

test_102j() {
	TAR=$(find_lustre_tar)
	[ -z "$TAR" ] && skip_env "lustre-aware tar is not installed" && return
	[ "$OSTCOUNT" -lt "2" ] && skip_env "skipping N-stripe test" && return
	setup_test102 "$RUNAS"
	mkdir -p $DIR/d102j
	chown $RUNAS_ID $DIR/d102j
	$RUNAS $TAR xf $TMP/f102.tar -C $DIR/d102j --xattrs
	cd $DIR/d102j/$tdir
	compare_stripe_info1 "$RUNAS"
}
run_test 102j "non-root tar restore stripe info from tarfile, not keep osts ==="

test_102k() {
        touch $DIR/$tfile
        # b22187 just check that does not crash for regular file.
        setfattr -n trusted.lov $DIR/$tfile
        # b22187 'setfattr -n trusted.lov' should work as remove LOV EA for directories
        local test_kdir=$DIR/d102k
        mkdir $test_kdir
        local default_size=`$GETSTRIPE -s $test_kdir`
        local default_count=`$GETSTRIPE -c $test_kdir`
        local default_offset=`$GETSTRIPE -o $test_kdir`
        $SETSTRIPE -s 65536 -i 1 -c $OSTCOUNT $test_kdir || error 'dir setstripe failed'
        setfattr -n trusted.lov $test_kdir
        local stripe_size=`$GETSTRIPE -s $test_kdir`
        local stripe_count=`$GETSTRIPE -c $test_kdir`
        local stripe_offset=`$GETSTRIPE -o $test_kdir`
        [ $stripe_size -eq $default_size ] || error "stripe size $stripe_size != $default_size"
        [ $stripe_count -eq $default_count ] || error "stripe count $stripe_count != $default_count"
        [ $stripe_offset -eq $default_offset ] || error "stripe offset $stripe_offset != $default_offset"
        rm -rf $DIR/$tfile $test_kdir
}
run_test 102k "setfattr without parameter of value shouldn't cause a crash"

cleanup_test102

run_acl_subtest()
{
    $LUSTRE/tests/acl/run $LUSTRE/tests/acl/$1.test
    return $?
}

test_103 () {
    [ "$UID" != 0 ] && skip_env "must run as root" && return
    [ -z "$(lctl get_param -n mdc.*-mdc-*.connect_flags | grep acl)" ] && skip "must have acl enabled" && return
    [ -z "$(which setfacl 2>/dev/null)" ] && skip_env "could not find setfacl" && return
    $GSS && skip "could not run under gss" && return

    declare -a identity_old

    for num in `seq $MDSCOUNT`; do
        switch_identity $num true || identity_old[$num]=$?
    done

    SAVE_UMASK=`umask`
    umask 0022
    cd $DIR

    echo "performing cp ..."
    run_acl_subtest cp || error
    echo "performing getfacl-noacl..."
    run_acl_subtest getfacl-noacl || error "getfacl-noacl test failed"
    echo "performing misc..."
    run_acl_subtest misc || error  "misc test failed"
    echo "performing permissions..."
    run_acl_subtest permissions || error "permissions failed"
    echo "performing setfacl..."
    run_acl_subtest setfacl || error  "setfacl test failed"

    # inheritance test got from HP
    echo "performing inheritance..."
    cp $LUSTRE/tests/acl/make-tree . || error "cannot copy make-tree"
    chmod +x make-tree || error "chmod +x failed"
    run_acl_subtest inheritance || error "inheritance test failed"
    rm -f make-tree

    cd $SAVE_PWD
    umask $SAVE_UMASK

    for num in `seq $MDSCOUNT`; do
	if [ "${identity_old[$num]}" = 1 ]; then
            switch_identity $num false || identity_old[$num]=$?
	fi
    done
}
run_test 103 "acl test ========================================="

test_104a() {
	touch $DIR/$tfile
	lfs df || error "lfs df failed"
	lfs df -ih || error "lfs df -ih failed"
	lfs df -h $DIR || error "lfs df -h $DIR failed"
	lfs df -i $DIR || error "lfs df -i $DIR failed"
	lfs df $DIR/$tfile || error "lfs df $DIR/$tfile failed"
	lfs df -ih $DIR/$tfile || error "lfs df -ih $DIR/$tfile failed"

	OSC=`lctl get_param -n devices | awk '/-osc-/ {print $4}' | head -n 1`
	lctl --device %$OSC deactivate
	lfs df || error "lfs df with deactivated OSC failed"
	lctl --device %$OSC recover
	lfs df || error "lfs df with reactivated OSC failed"
	rm -f $DIR/$tfile
}
run_test 104a "lfs df [-ih] [path] test ========================="

test_104b() {
	[ $RUNAS_ID -eq $UID ] && skip_env "RUNAS_ID = UID = $UID -- skipping" && return
	chmod 666 /dev/obd
	denied_cnt=$((`$RUNAS $LFS check servers 2>&1 | grep "Permission denied" | wc -l`))
	if [ $denied_cnt -ne 0 ];
	then
	            error "lfs check servers test failed"
	fi
}
run_test 104b "$RUNAS lfs check servers test ===================="

test_105a() {
	# doesn't work on 2.4 kernels
        touch $DIR/$tfile
        if [ -n "`mount | grep \"$DIR.*flock\" | grep -v noflock`" ];
        then
                flocks_test 1 on -f $DIR/$tfile || error "fail flock on"
        else
                flocks_test 1 off -f $DIR/$tfile || error "fail flock off"
        fi
	rm -f $DIR/$tfile
}
run_test 105a "flock when mounted without -o flock test ========"

test_105b() {
        touch $DIR/$tfile
        if [ -n "`mount | grep \"$DIR.*flock\" | grep -v noflock`" ];
        then
                flocks_test 1 on -c $DIR/$tfile || error "fail flock on"
        else
                flocks_test 1 off -c $DIR/$tfile || error "fail flock off"
        fi
	rm -f $DIR/$tfile
}
run_test 105b "fcntl when mounted without -o flock test ========"

test_105c() {
        touch $DIR/$tfile
        if [ -n "`mount | grep \"$DIR.*flock\" | grep -v noflock`" ];
        then
                flocks_test 1 on -l $DIR/$tfile || error "fail flock on"
        else
                flocks_test 1 off -l $DIR/$tfile || error "fail flock off"
        fi
	rm -f $DIR/$tfile
}
run_test 105c "lockf when mounted without -o flock test ========"

test_105d() { # bug 15924
        mkdir -p $DIR/$tdir
        [ -z "`mount | grep \"$DIR.*flock\" | grep -v noflock`" ] && \
                skip "mount w/o flock enabled" && return
        #define OBD_FAIL_LDLM_CP_CB_WAIT  0x315
        $LCTL set_param fail_loc=0x80000315
        flocks_test 2 $DIR/$tdir
}
run_test 105d "flock race (should not freeze) ========"

test_105e() { # bug 22660 && 22040
	[ -z "`mount | grep \"$DIR.*flock\" | grep -v noflock`" ] && \
		skip "mount w/o flock enabled" && return
	touch $DIR/$tfile
	flocks_test 3 $DIR/$tfile
}
run_test 105e "Two conflicting flocks from same process ======="

test_106() { #bug 10921
	mkdir -p $DIR/$tdir
	$DIR/$tdir && error "exec $DIR/$tdir succeeded"
	chmod 777 $DIR/$tdir || error "chmod $DIR/$tdir failed"
}
run_test 106 "attempt exec of dir followed by chown of that dir"

test_107() {
        CDIR=`pwd`
        cd $DIR

        local file=core
        rm -f $file

        local save_pattern=$(sysctl -n kernel.core_pattern)
        local save_uses_pid=$(sysctl -n kernel.core_uses_pid)
        sysctl -w kernel.core_pattern=$file
        sysctl -w kernel.core_uses_pid=0

        ulimit -c unlimited
        sleep 60 &
        SLEEPPID=$!

        sleep 1

        kill -s 11 $SLEEPPID
        wait $SLEEPPID
        if [ -e $file ]; then
                size=`stat -c%s $file`
                [ $size -eq 0 ] && error "Fail to create core file $file"
        else
                error "Fail to create core file $file"
        fi
        rm -f $file
        sysctl -w kernel.core_pattern=$save_pattern
        sysctl -w kernel.core_uses_pid=$save_uses_pid
        cd $CDIR
}
run_test 107 "Coredump on SIG"

test_110() {
	mkdir -p $DIR/d110
	mkdir $DIR/d110/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || error "mkdir with 255 char fail"
	mkdir $DIR/d110/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb && error "mkdir with 256 char should fail, but not"
	touch $DIR/d110/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx || error "create with 255 char fail"
	touch $DIR/d110/yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy && error ""create with 256 char should fail, but not

	ls -l $DIR/d110
    rm -fr $DIR/d110
}
run_test 110 "filename length checking"

test_115() {
	OSTIO_pre=$(ps -e|grep ll_ost_io|awk '{print $4}'|sort -n|tail -1|\
	    cut -c11-20)
        [ -z "$OSTIO_pre" ] && skip "no OSS threads" && \
	    return
        echo "Starting with $OSTIO_pre threads"

	NUMTEST=20000
	NUMFREE=`df -i -P $DIR | tail -n 1 | awk '{ print $4 }'`
	[ $NUMFREE -lt $NUMTEST ] && NUMTEST=$(($NUMFREE - 1000))
	echo "$NUMTEST creates/unlinks"
	mkdir -p $DIR/$tdir
	createmany -o $DIR/$tdir/$tfile $NUMTEST
	unlinkmany $DIR/$tdir/$tfile $NUMTEST

	OSTIO_post=$(ps -e|grep ll_ost_io|awk '{print $4}'|sort -n|tail -1|\
	    cut -c11-20)

	# don't return an error
        [ $OSTIO_post -eq $OSTIO_pre ] && echo \
	    "WARNING: No new ll_ost_io threads were created ($OSTIO_pre)" &&\
	    echo "This may be fine, depending on what ran before this test" &&\
	    echo "and how fast this system is." && return

        echo "Started with $OSTIO_pre threads, ended with $OSTIO_post"
}
run_test 115 "verify dynamic thread creation===================="

free_min_max () {
	wait_delete_completed
	AVAIL=($(lctl get_param -n osc.*[oO][sS][cC]-[^M]*.kbytesavail))
	echo OST kbytes available: ${AVAIL[@]}
	MAXI=0; MAXV=${AVAIL[0]}
	MINI=0; MINV=${AVAIL[0]}
	for ((i = 0; i < ${#AVAIL[@]}; i++)); do
	    #echo OST $i: ${AVAIL[i]}kb
	    if [ ${AVAIL[i]} -gt $MAXV ]; then
		MAXV=${AVAIL[i]}; MAXI=$i
	    fi
	    if [ ${AVAIL[i]} -lt $MINV ]; then
		MINV=${AVAIL[i]}; MINI=$i
	    fi
	done
	echo Min free space: OST $MINI: $MINV
	echo Max free space: OST $MAXI: $MAXV
}

test_116() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "$OSTCOUNT < 2 OSTs" && return

	echo -n "Free space priority "
	lctl get_param -n lov.*-clilov-*.qos_prio_free
	declare -a AVAIL
	free_min_max
	[ $MINV -gt 960000 ] && skip "too much free space in OST$MINI, skip" &&\
		return

	# generate uneven OSTs
	mkdir -p $DIR/$tdir/OST${MINI}
	declare -i FILL
	FILL=$(($MINV / 4))
	echo "Filling 25% remaining space in OST${MINI} with ${FILL}Kb"
	$SETSTRIPE -i $MINI -c 1 $DIR/$tdir/OST${MINI}||error "setstripe failed"
	i=0
	while [ $FILL -gt 0 ]; do
	    i=$(($i + 1))
	    dd if=/dev/zero of=$DIR/$tdir/OST${MINI}/$tfile-$i bs=2M count=1 2>/dev/null
	    FILL=$(($FILL - 2048))
	    echo -n .
	done
	FILL=$(($MINV / 4))
	sync
	sleep_maxage

	free_min_max
	DIFF=$(($MAXV - $MINV))
	DIFF2=$(($DIFF * 100 / $MINV))
	echo -n "diff=${DIFF}=${DIFF2}% must be > 20% for QOS mode..."
	if [ $DIFF2 -gt 20 ]; then
	    echo "ok"
	else
	    echo "failed - QOS mode won't be used"
	    error_ignore "QOS imbalance criteria not met"
	    return
	fi

	MINI1=$MINI; MINV1=$MINV
	MAXI1=$MAXI; MAXV1=$MAXV

	# now fill using QOS
	echo writing a bunch of files to QOS-assigned OSTs
	$SETSTRIPE $DIR/$tdir -c 1
	i=0
	while [ $FILL -gt 0 ]; do
	    i=$(($i + 1))
	    dd if=/dev/zero of=$DIR/$tdir/$tfile-$i bs=1024 count=200 2>/dev/null
	    FILL=$(($FILL - 200))
	    echo -n .
	done
	echo "wrote $i 200k files"
	sync
	sleep_maxage

	echo "Note: free space may not be updated, so measurements might be off"
	free_min_max
	DIFF2=$(($MAXV - $MINV))
	echo "free space delta: orig $DIFF final $DIFF2"
	[ $DIFF2 -gt $DIFF ] && echo "delta got worse!"
	DIFF=$(($MINV1 - ${AVAIL[$MINI1]}))
	echo "Wrote $DIFF to smaller OST $MINI1"
	DIFF2=$(($MAXV1 - ${AVAIL[$MAXI1]}))
	echo "Wrote $DIFF2 to larger OST $MAXI1"
	[ $DIFF -gt 0 ] && echo "Wrote $(($DIFF2 * 100 / $DIFF - 100))% more data to larger OST $MAXI1"

	# Figure out which files were written where
	UUID=$(lctl get_param -n lov.${FSNAME}-clilov-*.target_obd |
               awk '/'$MINI1': / {print $2; exit}')
	echo $UUID
        MINC=$($GETSTRIPE --obd $UUID $DIR/$tdir | wc -l)
	echo "$MINC files created on smaller OST $MINI1"
	UUID=$(lctl get_param -n lov.${FSNAME}-clilov-*.target_obd |
               awk '/'$MAXI1': / {print $2; exit}')
	echo $UUID
        MAXC=$($GETSTRIPE --obd $UUID $DIR/$tdir | wc -l)
	echo "$MAXC files created on larger OST $MAXI1"
	[ $MINC -gt 0 ] && echo "Wrote $(($MAXC * 100 / $MINC - 100))% more files to larger OST $MAXI1"
	[ $MAXC -gt $MINC ] || error_ignore "stripe QOS didn't balance free space"

	rm -rf $DIR/$tdir
}
run_test 116 "stripe QOS: free space balance ==================="

test_117() # bug 10891
{
        dd if=/dev/zero of=$DIR/$tfile bs=1M count=1
        #define OBD_FAIL_OST_SETATTR_CREDITS 0x21e
        lctl set_param fail_loc=0x21e
        > $DIR/$tfile || error "truncate failed"
        lctl set_param fail_loc=0
        echo "Truncate succeeded."
	rm -f $DIR/$tfile
}
run_test 117 "verify fsfilt_extend =========="

export OLD_RESENDCOUNT=""
set_resend_count () {
	local PROC_RESENDCOUNT="osc.${FSNAME}-OST*-osc-*.resend_count"
	OLD_RESENDCOUNT=$(lctl get_param -n $PROC_RESENDCOUNT | head -1)
	lctl set_param -n $PROC_RESENDCOUNT $1
	echo resend_count is set to $(lctl get_param -n $PROC_RESENDCOUNT)
}

[ "$SLOW" = "no" ] && set_resend_count 4 # for reduce test_118* time (bug 14842)

# Reset async IO behavior after error case
reset_async() {
	FILE=$DIR/reset_async

	# Ensure all OSCs are cleared
	$LSTRIPE -c -1 $FILE
        dd if=/dev/zero of=$FILE bs=64k count=$OSTCOUNT
	sync
        rm $FILE
}

test_118a() #bug 11710
{
	reset_async

 	multiop $DIR/$tfile oO_CREAT:O_RDWR:O_SYNC:w4096c
	DIRTY=$(lctl get_param -n llite.*.dump_page_cache | grep -c dirty)
        WRITEBACK=$(lctl get_param -n llite.*.dump_page_cache | grep -c writeback)

	if [[ $DIRTY -ne 0 || $WRITEBACK -ne 0 ]]; then
		error "Dirty pages not flushed to disk, dirty=$DIRTY, writeback=$WRITEBACK"
		return 1;
        fi
	rm -f $DIR/$tfile
}
run_test 118a "verify O_SYNC works =========="

test_118b()
{
	remote_ost_nodsh && skip "remote OST with nodsh" && return

	reset_async

	#define OBD_FAIL_OST_ENOENT 0x217
	set_nodes_failloc "$(osts_nodes)" 0x217
	multiop $DIR/$tfile oO_CREAT:O_RDWR:O_SYNC:w4096c
	RC=$?
	set_nodes_failloc "$(osts_nodes)" 0
        DIRTY=$(lctl get_param -n llite.*.dump_page_cache | grep -c dirty)
        WRITEBACK=$(lctl get_param -n llite.*.dump_page_cache |
                    grep -c writeback)

	if [[ $RC -eq 0 ]]; then
		error "Must return error due to dropped pages, rc=$RC"
		return 1;
	fi

	if [[ $DIRTY -ne 0 || $WRITEBACK -ne 0 ]]; then
		error "Dirty pages not flushed to disk, dirty=$DIRTY, writeback=$WRITEBACK"
		return 1;
	fi

	echo "Dirty pages not leaked on ENOENT"

	# Due to the above error the OSC will issue all RPCs syncronously
	# until a subsequent RPC completes successfully without error.
	multiop $DIR/$tfile Ow4096yc
	rm -f $DIR/$tfile

	return 0
}
run_test 118b "Reclaim dirty pages on fatal error =========="

test_118c()
{
	remote_ost_nodsh && skip "remote OST with nodsh" && return

	reset_async

	#define OBD_FAIL_OST_EROFS               0x216
	set_nodes_failloc "$(osts_nodes)" 0x216

	# multiop should block due to fsync until pages are written
	multiop $DIR/$tfile oO_CREAT:O_RDWR:O_SYNC:w4096c &
	MULTIPID=$!
	sleep 1

	if [[ `ps h -o comm -p $MULTIPID` != "multiop" ]]; then
		error "Multiop failed to block on fsync, pid=$MULTIPID"
	fi

        WRITEBACK=$(lctl get_param -n llite.*.dump_page_cache |
                    grep -c writeback)
	if [[ $WRITEBACK -eq 0 ]]; then
		error "No page in writeback, writeback=$WRITEBACK"
	fi

	set_nodes_failloc "$(osts_nodes)" 0
        wait $MULTIPID
	RC=$?
	if [[ $RC -ne 0 ]]; then
		error "Multiop fsync failed, rc=$RC"
	fi

        DIRTY=$(lctl get_param -n llite.*.dump_page_cache | grep -c dirty)
        WRITEBACK=$(lctl get_param -n llite.*.dump_page_cache |
                    grep -c writeback)
	if [[ $DIRTY -ne 0 || $WRITEBACK -ne 0 ]]; then
		error "Dirty pages not flushed to disk, dirty=$DIRTY, writeback=$WRITEBACK"
	fi

	rm -f $DIR/$tfile
	echo "Dirty pages flushed via fsync on EROFS"
	return 0
}
run_test 118c "Fsync blocks on EROFS until dirty pages are flushed =========="

test_118d()
{
	remote_ost_nodsh && skip "remote OST with nodsh" && return

	reset_async

	#define OBD_FAIL_OST_BRW_PAUSE_BULK
	set_nodes_failloc "$(osts_nodes)" 0x214
	# multiop should block due to fsync until pages are written
	multiop $DIR/$tfile oO_CREAT:O_RDWR:O_SYNC:w4096c &
	MULTIPID=$!
	sleep 1

	if [[ `ps h -o comm -p $MULTIPID` != "multiop" ]]; then
		error "Multiop failed to block on fsync, pid=$MULTIPID"
	fi

        WRITEBACK=$(lctl get_param -n llite.*.dump_page_cache |
                    grep -c writeback)
	if [[ $WRITEBACK -eq 0 ]]; then
		error "No page in writeback, writeback=$WRITEBACK"
	fi

        wait $MULTIPID || error "Multiop fsync failed, rc=$?"
	set_nodes_failloc "$(osts_nodes)" 0

        DIRTY=$(lctl get_param -n llite.*.dump_page_cache | grep -c dirty)
        WRITEBACK=$(lctl get_param -n llite.*.dump_page_cache |
                    grep -c writeback)
	if [[ $DIRTY -ne 0 || $WRITEBACK -ne 0 ]]; then
		error "Dirty pages not flushed to disk, dirty=$DIRTY, writeback=$WRITEBACK"
	fi

	rm -f $DIR/$tfile
	echo "Dirty pages gaurenteed flushed via fsync"
	return 0
}
run_test 118d "Fsync validation inject a delay of the bulk =========="

test_118f() {
        reset_async

        #define OBD_FAIL_OSC_BRW_PREP_REQ2        0x40a
        lctl set_param fail_loc=0x8000040a

	# Should simulate EINVAL error which is fatal
        multiop $DIR/$tfile oO_CREAT:O_RDWR:O_SYNC:w4096c
        RC=$?
	if [[ $RC -eq 0 ]]; then
		error "Must return error due to dropped pages, rc=$RC"
	fi

        lctl set_param fail_loc=0x0

        LOCKED=$(lctl get_param -n llite.*.dump_page_cache | grep -c locked)
        DIRTY=$(lctl get_param -n llite.*.dump_page_cache | grep -c dirty)
        WRITEBACK=$(lctl get_param -n llite.*.dump_page_cache |
                    grep -c writeback)
	if [[ $LOCKED -ne 0 ]]; then
		error "Locked pages remain in cache, locked=$LOCKED"
	fi

	if [[ $DIRTY -ne 0 || $WRITEBACK -ne 0 ]]; then
		error "Dirty pages not flushed to disk, dirty=$DIRTY, writeback=$WRITEBACK"
	fi

	rm -f $DIR/$tfile
	echo "No pages locked after fsync"

        reset_async
	return 0
}
run_test 118f "Simulate unrecoverable OSC side error =========="

test_118g() {
	reset_async

	#define OBD_FAIL_OSC_BRW_PREP_REQ        0x406
	lctl set_param fail_loc=0x406

	# simulate local -ENOMEM
	multiop $DIR/$tfile oO_CREAT:O_RDWR:O_SYNC:w4096c
	RC=$?

	lctl set_param fail_loc=0
	if [[ $RC -eq 0 ]]; then
		error "Must return error due to dropped pages, rc=$RC"
	fi

	LOCKED=$(lctl get_param -n llite.*.dump_page_cache | grep -c locked)
	DIRTY=$(lctl get_param -n llite.*.dump_page_cache | grep -c dirty)
	WRITEBACK=$(lctl get_param -n llite.*.dump_page_cache |
			grep -c writeback)
	if [[ $LOCKED -ne 0 ]]; then
		error "Locked pages remain in cache, locked=$LOCKED"
	fi

	if [[ $DIRTY -ne 0 || $WRITEBACK -ne 0 ]]; then
		error "Dirty pages not flushed to disk, dirty=$DIRTY, writeback=$WRITEBACK"
	fi

	rm -f $DIR/$tfile
	echo "No pages locked after fsync"

	reset_async
	return 0
}
run_test 118g "Don't stay in wait if we got local -ENOMEM  =========="

test_118h() {
	remote_ost_nodsh && skip "remote OST with nodsh" && return

        reset_async

	#define OBD_FAIL_OST_BRW_WRITE_BULK      0x20e
        set_nodes_failloc "$(osts_nodes)" 0x20e
	# Should simulate ENOMEM error which is recoverable and should be handled by timeout
        multiop $DIR/$tfile oO_CREAT:O_RDWR:O_SYNC:w4096c
        RC=$?

        set_nodes_failloc "$(osts_nodes)" 0
	if [[ $RC -eq 0 ]]; then
		error "Must return error due to dropped pages, rc=$RC"
	fi

        LOCKED=$(lctl get_param -n llite.*.dump_page_cache | grep -c locked)
        DIRTY=$(lctl get_param -n llite.*.dump_page_cache | grep -c dirty)
        WRITEBACK=$(lctl get_param -n llite.*.dump_page_cache |
                    grep -c writeback)
	if [[ $LOCKED -ne 0 ]]; then
		error "Locked pages remain in cache, locked=$LOCKED"
	fi

	if [[ $DIRTY -ne 0 || $WRITEBACK -ne 0 ]]; then
		error "Dirty pages not flushed to disk, dirty=$DIRTY, writeback=$WRITEBACK"
	fi

	rm -f $DIR/$tfile
	echo "No pages locked after fsync"

	return 0
}
run_test 118h "Verify timeout in handling recoverables errors  =========="

test_118i() {
	remote_ost_nodsh && skip "remote OST with nodsh" && return

        reset_async

	#define OBD_FAIL_OST_BRW_WRITE_BULK      0x20e
        set_nodes_failloc "$(osts_nodes)" 0x20e

	# Should simulate ENOMEM error which is recoverable and should be handled by timeout
        multiop $DIR/$tfile oO_CREAT:O_RDWR:O_SYNC:w4096c &
	PID=$!
	sleep 5
	set_nodes_failloc "$(osts_nodes)" 0

	wait $PID
        RC=$?
	if [[ $RC -ne 0 ]]; then
		error "got error, but should be not, rc=$RC"
	fi

        LOCKED=$(lctl get_param -n llite.*.dump_page_cache | grep -c locked)
        DIRTY=$(lctl get_param -n llite.*.dump_page_cache | grep -c dirty)
        WRITEBACK=$(lctl get_param -n llite.*.dump_page_cache | grep -c writeback)
	if [[ $LOCKED -ne 0 ]]; then
		error "Locked pages remain in cache, locked=$LOCKED"
	fi

	if [[ $DIRTY -ne 0 || $WRITEBACK -ne 0 ]]; then
		error "Dirty pages not flushed to disk, dirty=$DIRTY, writeback=$WRITEBACK"
	fi

	rm -f $DIR/$tfile
	echo "No pages locked after fsync"

	return 0
}
run_test 118i "Fix error before timeout in recoverable error  =========="

test_118j() {
	remote_ost_nodsh && skip "remote OST with nodsh" && return

        reset_async

	#define OBD_FAIL_OST_BRW_WRITE_BULK2     0x220
        set_nodes_failloc "$(osts_nodes)" 0x220

	# return -EIO from OST
        multiop $DIR/$tfile oO_CREAT:O_RDWR:O_SYNC:w4096c
        RC=$?
        set_nodes_failloc "$(osts_nodes)" 0x0
	if [[ $RC -eq 0 ]]; then
		error "Must return error due to dropped pages, rc=$RC"
	fi

        LOCKED=$(lctl get_param -n llite.*.dump_page_cache | grep -c locked)
        DIRTY=$(lctl get_param -n llite.*.dump_page_cache | grep -c dirty)
        WRITEBACK=$(lctl get_param -n llite.*.dump_page_cache | grep -c writeback)
	if [[ $LOCKED -ne 0 ]]; then
		error "Locked pages remain in cache, locked=$LOCKED"
	fi

	# in recoverable error on OST we want resend and stay until it finished
	if [[ $DIRTY -ne 0 || $WRITEBACK -ne 0 ]]; then
		error "Dirty pages not flushed to disk, dirty=$DIRTY, writeback=$WRITEBACK"
	fi

	rm -f $DIR/$tfile
	echo "No pages locked after fsync"

 	return 0
}
run_test 118j "Simulate unrecoverable OST side error =========="

test_118k()
{
	remote_ost_nodsh && skip "remote OSTs with nodsh" && return

	#define OBD_FAIL_OST_BRW_WRITE_BULK      0x20e
	set_nodes_failloc "$(osts_nodes)" 0x20e
	mkdir -p $DIR/$tdir

	for ((i=0;i<10;i++)); do
		(dd if=/dev/zero of=$DIR/$tdir/$tfile-$i bs=1M count=10 || \
			error "dd to $DIR/$tdir/$tfile-$i failed" )&
		SLEEPPID=$!
		sleep 0.500s
		kill $SLEEPPID
		wait $SLEEPPID
	done

	set_nodes_failloc "$(osts_nodes)" 0
	rm -rf $DIR/$tdir
}
run_test 118k "bio alloc -ENOMEM and IO TERM handling ========="

[ "$SLOW" = "no" ] && [ -n "$OLD_RESENDCOUNT" ] && set_resend_count $OLD_RESENDCOUNT

test_119a() # bug 11737
{
        BSIZE=$((512 * 1024))
        directio write $DIR/$tfile 0 1 $BSIZE
        # We ask to read two blocks, which is more than a file size.
        # directio will indicate an error when requested and actual
        # sizes aren't equeal (a normal situation in this case) and
        # print actual read amount.
        NOB=`directio read $DIR/$tfile 0 2 $BSIZE | awk '/error/ {print $6}'`
        if [ "$NOB" != "$BSIZE" ]; then
                error "read $NOB bytes instead of $BSIZE"
        fi
        rm -f $DIR/$tfile
}
run_test 119a "Short directIO read must return actual read amount"

test_119b() # bug 11737
{
        [ "$OSTCOUNT" -lt "2" ] && skip_env "skipping 2-stripe test" && return

        $SETSTRIPE -c 2 $DIR/$tfile || error "setstripe failed"
        dd if=/dev/zero of=$DIR/$tfile bs=1M count=1 seek=1 || error "dd failed"
        sync
        multiop $DIR/$tfile oO_RDONLY:O_DIRECT:r$((2048 * 1024)) || \
                error "direct read failed"
        rm -f $DIR/$tfile
}
run_test 119b "Sparse directIO read must return actual read amount"

test_119c() # bug 13099
{
        BSIZE=1048576
        directio write $DIR/$tfile 3 1 $BSIZE || error "direct write failed"
        directio readhole $DIR/$tfile 0 2 $BSIZE || error "reading hole failed"
        rm -f $DIR/$tfile
}
run_test 119c "Testing for direct read hitting hole"

test_119d() # bug 15950
{
        MAX_RPCS_IN_FLIGHT=`$LCTL get_param -n osc.*OST0000-osc-[^mM]*.max_rpcs_in_flight`
        $LCTL set_param -n osc.*OST0000-osc-[^mM]*.max_rpcs_in_flight 1
        BSIZE=1048576
        $SETSTRIPE $DIR/$tfile -i 0 -c 1 || error "setstripe failed"
        $DIRECTIO write $DIR/$tfile 0 1 $BSIZE || error "first directio failed"
        #define OBD_FAIL_OSC_DIO_PAUSE           0x40d
        lctl set_param fail_loc=0x40d
        $DIRECTIO write $DIR/$tfile 1 4 $BSIZE &
        pid_dio=$!
        sleep 1
        cat $DIR/$tfile > /dev/null &
        lctl set_param fail_loc=0
        pid_reads=$!
        wait $pid_dio
        log "the DIO writes have completed, now wait for the reads (should not block very long)"
        sleep 2
        [ -n "`ps h -p $pid_reads -o comm`" ] && \
        error "the read rpcs have not completed in 2s"
        rm -f $DIR/$tfile
        $LCTL set_param -n osc.*OST0000-osc-[^mM]*.max_rpcs_in_flight $MAX_RPCS_IN_FLIGHT
}
run_test 119d "The DIO path should try to send a new rpc once one is completed"

test_120a() {
        mkdir -p $DIR/$tdir
        [ -z "`lctl get_param -n mdc.*.connect_flags | grep early_lock_cancel`" ] && \
               skip "no early lock cancel on server" && return 0
        lru_resize_disable mdc
        lru_resize_disable osc
        cancel_lru_locks mdc
        stat $DIR/$tdir > /dev/null
        can1=`lctl get_param -n ldlm.services.ldlm_canceld.stats | awk '/ldlm_cancel/ {print $2}'`
        blk1=`lctl get_param -n ldlm.services.ldlm_cbd.stats | awk '/ldlm_bl_callback/ {print $2}'`
        mkdir $DIR/$tdir/d1
        can2=`lctl get_param -n ldlm.services.ldlm_canceld.stats | awk '/ldlm_cancel/ {print $2}'`
        blk2=`lctl get_param -n ldlm.services.ldlm_cbd.stats | awk '/ldlm_bl_callback/ {print $2}'`
        [ $can1 -eq $can2 ] || error $((can2-can1)) "cancel RPC occured."
        [ $blk1 -eq $blk2 ] || error $((blk2-blk1)) "blocking RPC occured."
        lru_resize_enable mdc
        lru_resize_enable osc
}
run_test 120a "Early Lock Cancel: mkdir test"

test_120b() {
        mkdir -p $DIR/$tdir
        [ -z "`lctl get_param -n mdc.*.connect_flags | grep early_lock_cancel`" ] && \
               skip "no early lock cancel on server" && return 0
        lru_resize_disable mdc
        lru_resize_disable osc
        cancel_lru_locks mdc
        stat $DIR/$tdir > /dev/null
        can1=`lctl get_param -n ldlm.services.ldlm_canceld.stats | awk '/ldlm_cancel/ {print $2}'`
        blk1=`lctl get_param -n ldlm.services.ldlm_cbd.stats | awk '/ldlm_bl_callback/ {print $2}'`
        touch $DIR/$tdir/f1
        can2=`lctl get_param -n ldlm.services.ldlm_canceld.stats | awk '/ldlm_cancel/ {print $2}'`
        blk2=`lctl get_param -n ldlm.services.ldlm_cbd.stats | awk '/ldlm_bl_callback/ {print $2}'`
        [ $can1 -eq $can2 ] || error $((can2-can1)) "cancel RPC occured."
        [ $blk1 -eq $blk2 ] || error $((blk2-blk1)) "blocking RPC occured."
        lru_resize_enable mdc
        lru_resize_enable osc
}
run_test 120b "Early Lock Cancel: create test"

test_120c() {
        mkdir -p $DIR/$tdir
        [ -z "`lctl get_param -n mdc.*.connect_flags | grep early_lock_cancel`" ] && \
               skip "no early lock cancel on server" && return 0
        lru_resize_disable mdc
        lru_resize_disable osc
        mkdir -p $DIR/$tdir/d1 $DIR/$tdir/d2
        touch $DIR/$tdir/d1/f1
        cancel_lru_locks mdc
        stat $DIR/$tdir/d1 $DIR/$tdir/d2 $DIR/$tdir/d1/f1 > /dev/null
        can1=`lctl get_param -n ldlm.services.ldlm_canceld.stats | awk '/ldlm_cancel/ {print $2}'`
        blk1=`lctl get_param -n ldlm.services.ldlm_cbd.stats | awk '/ldlm_bl_callback/ {print $2}'`
        ln $DIR/$tdir/d1/f1 $DIR/$tdir/d2/f2
        can2=`lctl get_param -n ldlm.services.ldlm_canceld.stats | awk '/ldlm_cancel/ {print $2}'`
        blk2=`lctl get_param -n ldlm.services.ldlm_cbd.stats | awk '/ldlm_bl_callback/ {print $2}'`
        [ $can1 -eq $can2 ] || error $((can2-can1)) "cancel RPC occured."
        [ $blk1 -eq $blk2 ] || error $((blk2-blk1)) "blocking RPC occured."
        lru_resize_enable mdc
        lru_resize_enable osc
}
run_test 120c "Early Lock Cancel: link test"

test_120d() {
        mkdir -p $DIR/$tdir
        [ -z "`lctl get_param -n mdc.*.connect_flags | grep early_lock_cancel`" ] && \
               skip "no early lock cancel on server" && return 0
        lru_resize_disable mdc
        lru_resize_disable osc
        touch $DIR/$tdir
        cancel_lru_locks mdc
        stat $DIR/$tdir > /dev/null
        can1=`lctl get_param -n ldlm.services.ldlm_canceld.stats | awk '/ldlm_cancel/ {print $2}'`
        blk1=`lctl get_param -n ldlm.services.ldlm_cbd.stats | awk '/ldlm_bl_callback/ {print $2}'`
        chmod a+x $DIR/$tdir
        can2=`lctl get_param -n ldlm.services.ldlm_canceld.stats | awk '/ldlm_cancel/ {print $2}'`
        blk2=`lctl get_param -n ldlm.services.ldlm_cbd.stats | awk '/ldlm_bl_callback/ {print $2}'`
        [ $can1 -eq $can2 ] || error $((can2-can1)) "cancel RPC occured."
        [ $blk1 -eq $blk2 ] || error $((blk2-blk1)) "blocking RPC occured."
        lru_resize_enable mdc
        lru_resize_enable osc
}
run_test 120d "Early Lock Cancel: setattr test"

test_120e() {
        mkdir -p $DIR/$tdir
        [ -z "`lctl get_param -n mdc.*.connect_flags | grep early_lock_cancel`" ] && \
               skip "no early lock cancel on server" && return 0
        lru_resize_disable mdc
        lru_resize_disable osc
        dd if=/dev/zero of=$DIR/$tdir/f1 count=1
        cancel_lru_locks mdc
        cancel_lru_locks osc
        dd if=$DIR/$tdir/f1 of=/dev/null
        stat $DIR/$tdir $DIR/$tdir/f1 > /dev/null
        can1=`lctl get_param -n ldlm.services.ldlm_canceld.stats |
              awk '/ldlm_cancel/ {print $2}'`
        blk1=`lctl get_param -n ldlm.services.ldlm_cbd.stats |
              awk '/ldlm_bl_callback/ {print $2}'`
        unlink $DIR/$tdir/f1
        can2=`lctl get_param -n ldlm.services.ldlm_canceld.stats |
              awk '/ldlm_cancel/ {print $2}'`
        blk2=`lctl get_param -n ldlm.services.ldlm_cbd.stats |
              awk '/ldlm_bl_callback/ {print $2}'`
        [ $can1 -eq $can2 ] || error $((can2-can1)) "cancel RPC occured."
        [ $blk1 -eq $blk2 ] || error $((blk2-blk1)) "blocking RPC occured."
        lru_resize_enable mdc
        lru_resize_enable osc
}
run_test 120e "Early Lock Cancel: unlink test"

test_120f() {
        [ -z "`lctl get_param -n mdc.*.connect_flags | grep early_lock_cancel`" ] && \
               skip "no early lock cancel on server" && return 0
        mkdir -p $DIR/$tdir
        lru_resize_disable mdc
        lru_resize_disable osc
        mkdir -p $DIR/$tdir/d1 $DIR/$tdir/d2
        dd if=/dev/zero of=$DIR/$tdir/d1/f1 count=1
        dd if=/dev/zero of=$DIR/$tdir/d2/f2 count=1
        cancel_lru_locks mdc
        cancel_lru_locks osc
        dd if=$DIR/$tdir/d1/f1 of=/dev/null
        dd if=$DIR/$tdir/d2/f2 of=/dev/null
        stat $DIR/$tdir/d1 $DIR/$tdir/d2 $DIR/$tdir/d1/f1 $DIR/$tdir/d2/f2 > /dev/null
        can1=`lctl get_param -n ldlm.services.ldlm_canceld.stats |
              awk '/ldlm_cancel/ {print $2}'`
        blk1=`lctl get_param -n ldlm.services.ldlm_cbd.stats |
              awk '/ldlm_bl_callback/ {print $2}'`
        mv $DIR/$tdir/d1/f1 $DIR/$tdir/d2/f2
        can2=`lctl get_param -n ldlm.services.ldlm_canceld.stats |
              awk '/ldlm_cancel/ {print $2}'`
        blk2=`lctl get_param -n ldlm.services.ldlm_cbd.stats |
              awk '/ldlm_bl_callback/ {print $2}'`
        [ $can1 -eq $can2 ] || error $((can2-can1)) "cancel RPC occured."
        [ $blk1 -eq $blk2 ] || error $((blk2-blk1)) "blocking RPC occured."
        lru_resize_enable mdc
        lru_resize_enable osc
}
run_test 120f "Early Lock Cancel: rename test"

test_120g() {
        [ -z "`lctl get_param -n mdc.*.connect_flags | grep early_lock_cancel`" ] && \
               skip "no early lock cancel on server" && return 0
        lru_resize_disable mdc
        lru_resize_disable osc
        count=10000
        echo create $count files
        mkdir -p $DIR/$tdir
        cancel_lru_locks mdc
        cancel_lru_locks osc
        t0=`date +%s`

        can0=`lctl get_param -n ldlm.services.ldlm_canceld.stats |
              awk '/ldlm_cancel/ {print $2}'`
        blk0=`lctl get_param -n ldlm.services.ldlm_cbd.stats |
              awk '/ldlm_bl_callback/ {print $2}'`
        createmany -o $DIR/$tdir/f $count
        sync
        can1=`lctl get_param -n ldlm.services.ldlm_canceld.stats |
              awk '/ldlm_cancel/ {print $2}'`
        blk1=`lctl get_param -n ldlm.services.ldlm_cbd.stats |
              awk '/ldlm_bl_callback/ {print $2}'`
        t1=`date +%s`
        echo total: $((can1-can0)) cancels, $((blk1-blk0)) blockings
        echo rm $count files
        rm -r $DIR/$tdir
        sync
        can2=`lctl get_param -n ldlm.services.ldlm_canceld.stats |
              awk '/ldlm_cancel/ {print $2}'`
        blk2=`lctl get_param -n ldlm.services.ldlm_cbd.stats |
              awk '/ldlm_bl_callback/ {print $2}'`
        t2=`date +%s`
        echo total: $count removes in $((t2-t1))
        echo total: $((can2-can1)) cancels, $((blk2-blk1)) blockings
        sleep 2
        # wait for commitment of removal
        lru_resize_enable mdc
        lru_resize_enable osc
}
run_test 120g "Early Lock Cancel: performance test"

test_121() { #bug #10589
	rm -rf $DIR/$tfile
	writes=$(LANG=C dd if=/dev/zero of=$DIR/$tfile count=1 2>&1 | awk -F '+' '/out$/ {print $1}')
#define OBD_FAIL_LDLM_CANCEL_RACE        0x310
	lctl set_param fail_loc=0x310
	cancel_lru_locks osc > /dev/null
	reads=$(LANG=C dd if=$DIR/$tfile of=/dev/null 2>&1 | awk -F '+' '/in$/ {print $1}')
	lctl set_param fail_loc=0
	[ "$reads" -eq "$writes" ] || error "read" $reads "blocks, must be" $writes
}
run_test 121 "read cancel race ========="

test_123a() { # was test 123, statahead(bug 11401)
        SLOWOK=0
        if [ -z "$(grep "processor.*: 1" /proc/cpuinfo)" ]; then
            log "testing on UP system. Performance may be not as good as expected."
			SLOWOK=1
        fi

        rm -rf $DIR/$tdir
        mkdir -p $DIR/$tdir
        NUMFREE=`df -i -P $DIR | tail -n 1 | awk '{ print $4 }'`
        [ $NUMFREE -gt 100000 ] && NUMFREE=100000 || NUMFREE=$((NUMFREE-1000))
        MULT=10
        for ((i=100, j=0; i<=$NUMFREE; j=$i, i=$((i * MULT)) )); do
                createmany -o $DIR/$tdir/$tfile $j $((i - j))

                max=`lctl get_param -n llite.*.statahead_max | head -n 1`
                lctl set_param -n llite.*.statahead_max 0
                lctl get_param llite.*.statahead_max
                cancel_lru_locks mdc
                cancel_lru_locks osc
                stime=`date +%s`
                time ls -l $DIR/$tdir | wc -l
                etime=`date +%s`
                delta=$((etime - stime))
                log "ls $i files without statahead: $delta sec"
                lctl set_param llite.*.statahead_max=$max

                swrong=`lctl get_param -n llite.*.statahead_stats | grep "statahead wrong:" | awk '{print $3}'`
                lctl get_param -n llite.*.statahead_max | grep '[0-9]'
                cancel_lru_locks mdc
                cancel_lru_locks osc
                stime=`date +%s`
                time ls -l $DIR/$tdir | wc -l
                etime=`date +%s`
                delta_sa=$((etime - stime))
                log "ls $i files with statahead: $delta_sa sec"
                lctl get_param -n llite.*.statahead_stats
                ewrong=`lctl get_param -n llite.*.statahead_stats | grep "statahead wrong:" | awk '{print $3}'`

                [ $swrong -lt $ewrong ] && log "statahead was stopped, maybe too many locks held!"
                [ $delta -eq 0 -o $delta_sa -eq 0 ] && continue

                if [ $((delta_sa * 100)) -gt $((delta * 105)) -a $delta_sa -gt $((delta + 2)) ]; then
                    max=`lctl get_param -n llite.*.statahead_max | head -n 1`
                    lctl set_param -n llite.*.statahead_max 0
                    lctl get_param llite.*.statahead_max
                    cancel_lru_locks mdc
                    cancel_lru_locks osc
                    stime=`date +%s`
                    time ls -l $DIR/$tdir | wc -l
                    etime=`date +%s`
                    delta=$((etime - stime))
                    log "ls $i files again without statahead: $delta sec"
                    lctl set_param llite.*.statahead_max=$max
                    if [ $((delta_sa * 100)) -gt $((delta * 105)) -a $delta_sa -gt $((delta + 2)) ]; then
                        if [  $SLOWOK -eq 0 ]; then
                                error "ls $i files is slower with statahead!"
                        else
                                log "ls $i files is slower with statahead!"
                        fi
                        break
                    fi
                fi

                [ $delta -gt 20 ] && break
                [ $delta -gt 8 ] && MULT=$((50 / delta))
                [ "$SLOW" = "no" -a $delta -gt 5 ] && break
        done
        log "ls done"

        stime=`date +%s`
        rm -r $DIR/$tdir
        sync
        etime=`date +%s`
        delta=$((etime - stime))
        log "rm -r $DIR/$tdir/: $delta seconds"
        log "rm done"
        lctl get_param -n llite.*.statahead_stats
}
run_test 123a "verify statahead work"

test_123b () { # statahead(bug 15027)
	mkdir -p $DIR/$tdir
	createmany -o $DIR/$tdir/$tfile-%d 1000

        cancel_lru_locks mdc
        cancel_lru_locks osc

#define OBD_FAIL_MDC_GETATTR_ENQUEUE     0x803
        lctl set_param fail_loc=0x80000803
        ls -lR $DIR/$tdir > /dev/null
        log "ls done"
        lctl set_param fail_loc=0x0
        lctl get_param -n llite.*.statahead_stats
        rm -r $DIR/$tdir
        sync

}
run_test 123b "not panic with network error in statahead enqueue (bug 15027)"

test_124a() {
	[ -z "`lctl get_param -n mdc.*.connect_flags | grep lru_resize`" ] && \
               skip "no lru resize on server" && return 0
        local NR=2000
        mkdir -p $DIR/$tdir || error "failed to create $DIR/$tdir"

        log "create $NR files at $DIR/$tdir"
        createmany -o $DIR/$tdir/f $NR ||
                error "failed to create $NR files in $DIR/$tdir"

        cancel_lru_locks mdc
        ls -l $DIR/$tdir > /dev/null

        local NSDIR=""
        local LRU_SIZE=0
        for VALUE in `lctl get_param ldlm.namespaces.*mdc-*.lru_size`; do
                local PARAM=`echo ${VALUE[0]} | cut -d "=" -f1`
                LRU_SIZE=$(lctl get_param -n $PARAM)
                if [ $LRU_SIZE -gt $(default_lru_size) ]; then
                        NSDIR=$(echo $PARAM | cut -d "." -f1-3)
						log "NSDIR=$NSDIR"
                        log "NS=$(basename $NSDIR)"
                        break
                fi
        done

        if [ -z "$NSDIR" -o $LRU_SIZE -lt $(default_lru_size) ]; then
                skip "Not enough cached locks created!"
                return 0
        fi
        log "LRU=$LRU_SIZE"

        local SLEEP=30

        # We know that lru resize allows one client to hold $LIMIT locks
        # for 10h. After that locks begin to be killed by client.
        local MAX_HRS=10
        local LIMIT=`lctl get_param -n $NSDIR.pool.limit`
		log "LIMIT=$LIMIT"

        # Make LVF so higher that sleeping for $SLEEP is enough to _start_
        # killing locks. Some time was spent for creating locks. This means
        # that up to the moment of sleep finish we must have killed some of
        # them (10-100 locks). This depends on how fast ther were created.
        # Many of them were touched in almost the same moment and thus will
        # be killed in groups.
        local LVF=$(($MAX_HRS * 60 * 60 / $SLEEP * $LIMIT / $LRU_SIZE))

        # Use $LRU_SIZE_B here to take into account real number of locks
        # created in the case of CMD, LRU_SIZE_B != $NR in most of cases
        local LRU_SIZE_B=$LRU_SIZE
        log "LVF=$LVF"
        local OLD_LVF=`lctl get_param -n $NSDIR.pool.lock_volume_factor`
		log "OLD_LVF=$OLD_LVF"
        lctl set_param -n $NSDIR.pool.lock_volume_factor $LVF

        # Let's make sure that we really have some margin. Client checks
        # cached locks every 10 sec.
        SLEEP=$((SLEEP+20))
        log "Sleep ${SLEEP} sec"
        local SEC=0
        while ((SEC<$SLEEP)); do
                echo -n "..."
                sleep 5
                SEC=$((SEC+5))
                LRU_SIZE=`lctl get_param -n $NSDIR/lru_size`
                echo -n "$LRU_SIZE"
        done
        echo ""
        lctl set_param -n $NSDIR.pool.lock_volume_factor $OLD_LVF
        local LRU_SIZE_A=`lctl get_param -n $NSDIR/lru_size`

        [ $LRU_SIZE_B -gt $LRU_SIZE_A ] || {
                error "No locks dropped in ${SLEEP}s. LRU size: $LRU_SIZE_A"
                unlinkmany $DIR/$tdir/f $NR
                return
        }

        log "Dropped "$((LRU_SIZE_B-LRU_SIZE_A))" locks in ${SLEEP}s"
        log "unlink $NR files at $DIR/$tdir"
        unlinkmany $DIR/$tdir/f $NR
}
run_test 124a "lru resize ======================================="

get_max_pool_limit()
{
        local limit=`lctl get_param -n ldlm.namespaces.*-MDT0000-mdc-*.pool.limit`
        local max=0
        for l in $limit; do
                if test $l -gt $max; then
                        max=$l
                fi
        done
        echo $max
}

test_124b() {
	[ -z "`lctl get_param -n mdc.*.connect_flags | grep lru_resize`" ] && \
               skip "no lru resize on server" && return 0

        LIMIT=`get_max_pool_limit`

        NR=$(($(default_lru_size)*20))
        if [ $NR -gt $LIMIT ]; then
                log "Limit lock number by $LIMIT locks"
                NR=$LIMIT
        fi
        lru_resize_disable mdc
        mkdir -p $DIR/$tdir/disable_lru_resize ||
		error "failed to create $DIR/$tdir/disable_lru_resize"

        createmany -o $DIR/$tdir/disable_lru_resize/f $NR
        log "doing ls -la $DIR/$tdir/disable_lru_resize 3 times"
        cancel_lru_locks mdc
        stime=`date +%s`
        PID=""
        ls -la $DIR/$tdir/disable_lru_resize > /dev/null &
        PID="$PID $!"
        sleep 2
        ls -la $DIR/$tdir/disable_lru_resize > /dev/null &
        PID="$PID $!"
        sleep 2
        ls -la $DIR/$tdir/disable_lru_resize > /dev/null &
        PID="$PID $!"
        wait $PID
        etime=`date +%s`
        nolruresize_delta=$((etime-stime))
        log "ls -la time: $nolruresize_delta seconds"
        log "lru_size = $(lctl get_param -n ldlm.namespaces.*mdc*.lru_size)"
        unlinkmany $DIR/$tdir/disable_lru_resize/f $NR

        lru_resize_enable mdc
        mkdir -p $DIR/$tdir/enable_lru_resize ||
		error "failed to create $DIR/$tdir/enable_lru_resize"

        createmany -o $DIR/$tdir/enable_lru_resize/f $NR
        log "doing ls -la $DIR/$tdir/enable_lru_resize 3 times"
        cancel_lru_locks mdc
        stime=`date +%s`
        PID=""
        ls -la $DIR/$tdir/enable_lru_resize > /dev/null &
        PID="$PID $!"
        sleep 2
        ls -la $DIR/$tdir/enable_lru_resize > /dev/null &
        PID="$PID $!"
        sleep 2
        ls -la $DIR/$tdir/enable_lru_resize > /dev/null &
        PID="$PID $!"
        wait $PID
        etime=`date +%s`
        lruresize_delta=$((etime-stime))
        log "ls -la time: $lruresize_delta seconds"
        log "lru_size = $(lctl get_param -n ldlm.namespaces.*mdc*.lru_size)"

        if [ $lruresize_delta -gt $nolruresize_delta ]; then
                log "ls -la is $(((lruresize_delta - $nolruresize_delta) * 100 / $nolruresize_delta))% slower with lru resize enabled"
        elif [ $nolruresize_delta -gt $lruresize_delta ]; then
                log "ls -la is $(((nolruresize_delta - $lruresize_delta) * 100 / $nolruresize_delta))% faster with lru resize enabled"
        else
                log "lru resize performs the same with no lru resize"
        fi
        unlinkmany $DIR/$tdir/enable_lru_resize/f $NR
}
run_test 124b "lru resize (performance test) ======================="

test_125() { # 13358
	[ -z "$(lctl get_param -n llite.*.client_type | grep local)" ] && skip "must run as local client" && return
	[ -z "$(lctl get_param -n mdc.*-mdc-*.connect_flags | grep acl)" ] && skip "must have acl enabled" && return
	mkdir -p $DIR/d125 || error "mkdir failed"
	$SETSTRIPE $DIR/d125 -s 65536 -c -1 || error "setstripe failed"
	setfacl -R -m u:bin:rwx $DIR/d125 || error "setfacl $DIR/d125 failed"
	ls -ld $DIR/d125 || error "cannot access $DIR/d125"
}
run_test 125 "don't return EPROTO when a dir has a non-default striping and ACLs"

test_126() { # bug 12829/13455
	[ -z "$(lctl get_param -n llite.*.client_type | grep local)" ] && skip "must run as local client" && return
	[ "$UID" != 0 ] && skip_env "skipping $TESTNAME (must run as root)" && return
	$GSS && skip "must run as gss disabled" && return

	$RUNAS -u 0 -g 1 touch $DIR/$tfile || error "touch failed"
	gid=`ls -n $DIR/$tfile | awk '{print $4}'`
	rm -f $DIR/$tfile
	[ $gid -eq "1" ] || error "gid is set to" $gid "instead of 1"
}
run_test 126 "check that the fsgid provided by the client is taken into account"

test_127a() { # bug 15521
        $SETSTRIPE -i 0 -c 1 $DIR/$tfile || error "setstripe failed"
        $LCTL set_param osc.*.stats=0
        FSIZE=$((2048 * 1024))
        dd if=/dev/zero of=$DIR/$tfile bs=$FSIZE count=1
        cancel_lru_locks osc
        dd if=$DIR/$tfile of=/dev/null bs=$FSIZE

        $LCTL get_param osc.*0000-osc-*.stats | grep samples > $DIR/${tfile}.tmp
        while read NAME COUNT SAMP UNIT MIN MAX SUM SUMSQ; do
                echo "got $COUNT $NAME"
                [ ! $MIN ] && error "Missing min value for $NAME proc entry"
                eval $NAME=$COUNT || error "Wrong proc format"

                case $NAME in
                        read_bytes|write_bytes)
                        [ $MIN -lt 4096 ] && error "min is too small: $MIN"
                        [ $MIN -gt $FSIZE ] && error "min is too big: $MIN"
                        [ $MAX -lt 4096 ] && error "max is too small: $MAX"
                        [ $MAX -gt $FSIZE ] && error "max is too big: $MAX"
                        [ $SUM -ne $FSIZE ] && error "sum is wrong: $SUM"
                        [ $SUMSQ -lt $(((FSIZE /4096) * (4096 * 4096))) ] &&
                                error "sumsquare is too small: $SUMSQ"
                        [ $SUMSQ -gt $((FSIZE * FSIZE)) ] &&
                                error "sumsquare is too big: $SUMSQ"
                        ;;
                        *) ;;
                esac
        done < $DIR/${tfile}.tmp

        #check that we actually got some stats
        [ "$read_bytes" ] || error "Missing read_bytes stats"
        [ "$write_bytes" ] || error "Missing write_bytes stats"
        [ "$read_bytes" != 0 ] || error "no read done"
        [ "$write_bytes" != 0 ] || error "no write done"
}
run_test 127a "verify the client stats are sane"

test_127b() { # bug LU-333
        $LCTL set_param llite.*.stats=0
        FSIZE=65536 # sized fixed to match PAGE_SIZE for most clients
        # perform 2 reads and writes so MAX is different from SUM.
        dd if=/dev/zero of=$DIR/$tfile bs=$FSIZE count=1
        dd if=/dev/zero of=$DIR/$tfile bs=$FSIZE count=1
        cancel_lru_locks osc
        dd if=$DIR/$tfile of=/dev/null bs=$FSIZE count=1
        dd if=$DIR/$tfile of=/dev/null bs=$FSIZE count=1

        $LCTL get_param llite.*.stats | grep samples > $TMP/${tfile}.tmp
        while read NAME COUNT SAMP UNIT MIN MAX SUM SUMSQ; do
                echo "got $COUNT $NAME"
                eval $NAME=$COUNT || error "Wrong proc format"

        case $NAME in
                read_bytes)
                        [ $COUNT -ne 2 ] && error "count is not 2: $COUNT"
                        [ $MIN -ne $FSIZE ] && error "min is not $FSIZE: $MIN"
                        [ $MAX -ne $FSIZE ] && error "max is incorrect: $MAX"
                        [ $SUM -ne $((FSIZE * 2)) ] && error "sum is wrong: $SUM"
                        ;;
                write_bytes)
                        [ $COUNT -ne 2 ] && error "count is not 2: $COUNT"
                        [ $MIN -ne $FSIZE ] && error "min is not $FSIZE: $MIN"
                        [ $MAX -ne $FSIZE ] && error "max is incorrect: $MAX"
                        [ $SUM -ne $((FSIZE * 2)) ] && error "sum is wrong: $SUM"
                        ;;
                        *) ;;
                esac
        done < $TMP/${tfile}.tmp

        #check that we actually got some stats
        [ "$read_bytes" ] || error "Missing read_bytes stats"
        [ "$write_bytes" ] || error "Missing write_bytes stats"
        [ "$read_bytes" != 0 ] || error "no read done"
        [ "$write_bytes" != 0 ] || error "no write done"
}
run_test 127b "verify the llite client stats are sane"

test_128() { # bug 15212
	touch $DIR/$tfile
	$LFS 2>&1 <<-EOF | tee $TMP/$tfile.log
		find $DIR/$tfile
		find $DIR/$tfile
	EOF

	result=$(grep error $TMP/$tfile.log)
	rm -f $DIR/$tfile
	[ -z "$result" ] || error "consecutive find's under interactive lfs failed"
}
run_test 128 "interactive lfs for 2 consecutive find's"

set_dir_limits () {
	local mntdev
	local canondev
	local node

	local LDPROC=/proc/fs/ldiskfs

	for facet in $(get_facets MDS); do
		canondev=$(ldiskfs_canon *.$(convert_facet2label $facet).mntdev $facet)
		do_facet $facet "test -e $LDPROC/$canondev/max_dir_size" || LDPROC=/sys/fs/ldiskfs
		do_facet $facet "echo $1 >$LDPROC/$canondev/max_dir_size"
	done
}
test_129() {
	[ "$FSTYPE" != "ldiskfs" ] && skip "not needed for FSTYPE=$FSTYPE" && return 0
	remote_mds_nodsh && skip "remote MDS with nodsh" && return

	EFBIG=27
	MAX=16384

	set_dir_limits $MAX

	mkdir -p $DIR/$tdir

	I=0
	J=0
	while [ ! $I -gt $((MAX * MDSCOUNT)) ]; do
		multiop $DIR/$tdir/$J Oc
		rc=$?
		if [ $rc -eq $EFBIG ]; then
			set_dir_limits 0
			echo "return code $rc received as expected"
			return 0
		elif [ $rc -ne 0 ]; then
			set_dir_limits 0
			error_exit "return code $rc received instead of expected $EFBIG"
		fi
		J=$((J+1))
		I=$(stat -c%s "$DIR/$tdir")
	done

	set_dir_limits 0
	error "exceeded dir size limit $MAX x $MDSCOUNT $((MAX * MDSCOUNT)) : $I bytes"
}
run_test 129 "test directory size limit ========================"

OLDIFS="$IFS"
cleanup_130() {
	trap 0
	IFS="$OLDIFS"
}

test_130a() {
	filefrag_op=$(filefrag -e 2>&1 | grep "invalid option")
	[ -n "$filefrag_op" ] && skip "filefrag does not support FIEMAP" && return

	trap cleanup_130 EXIT RETURN

	local fm_file=$DIR/$tfile
	lfs setstripe -s 65536 -c 1 $fm_file || error "setstripe failed on $fm_file"
	dd if=/dev/zero of=$fm_file bs=65536 count=1 || error "dd failed for $fm_file"

	filefrag -ves $fm_file || error "filefrag $fm_file failed"
	filefrag_op=`filefrag -ve $fm_file | grep -A 100 "ext:" | grep -v "ext:" | grep -v "found"`

	lun=`$GETSTRIPE $fm_file  | grep -A 10 obdidx | awk '{print $1}' | grep -v "obdidx"`

	start_blk=`echo $filefrag_op | cut -d: -f2 | cut -d. -f1`
	IFS=$'\n'
	tot_len=0
	for line in $filefrag_op
	do
		frag_lun=`echo $line | cut -d: -f5`
		ext_len=`echo $line | cut -d: -f4`
		if (( $frag_lun != $lun )); then
			cleanup_130
			error "FIEMAP on 1-stripe file($fm_file) failed"
			return
		fi
		(( tot_len += ext_len ))
	done

	if (( lun != frag_lun || start_blk != 0 || tot_len != 64 )); then
		cleanup_130
		error "FIEMAP on 1-stripe file($fm_file) failed;"
		return
	fi

	cleanup_130

	echo "FIEMAP on single striped file succeeded"
}
run_test 130a "FIEMAP (1-stripe file)"

test_130b() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "skipping FIEMAP on 2-stripe file test" && return

	filefrag_op=$(filefrag -e 2>&1 | grep "invalid option")
	[ -n "$filefrag_op" ] && skip "filefrag does not support FIEMAP" && return

	trap cleanup_130 EXIT RETURN

	local fm_file=$DIR/$tfile
	lfs setstripe -s 65536 -c 2 $fm_file || error "setstripe failed on $fm_file"
	dd if=/dev/zero of=$fm_file bs=1M count=2 || error "dd failed on $fm_file"

	filefrag -ves $fm_file || error "filefrag $fm_file failed"
	filefrag_op=`filefrag -ve $fm_file | grep -A 100 "ext:" | grep -v "ext:" | grep -v "found"`

	last_lun=`echo $filefrag_op | cut -d: -f5`

	IFS=$'\n'
	tot_len=0
	num_luns=1
	for line in $filefrag_op
	do
		frag_lun=`echo $line | cut -d: -f5`
		ext_len=`echo $line | cut -d: -f4`
		if (( $frag_lun != $last_lun )); then
			if (( tot_len != 1024 )); then
				cleanup_130
				error "FIEMAP on $fm_file failed; returned len $tot_len for OST $last_lun instead of 256"
				return
			else
				(( num_luns += 1 ))
				tot_len=0
			fi
		fi
		(( tot_len += ext_len ))
		last_lun=$frag_lun
	done
	if (( num_luns != 2 || tot_len != 1024 )); then
		cleanup_130
		error "FIEMAP on $fm_file failed; returned wrong number of luns or wrong len for OST $last_lun"
		return
	fi

	cleanup_130

	echo "FIEMAP on 2-stripe file succeeded"
}
run_test 130b "FIEMAP (2-stripe file)"

test_130c() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "skipping FIEMAP on 2-stripe file with hole test" && return

	filefrag_op=$(filefrag -e 2>&1 | grep "invalid option")
	[ -n "$filefrag_op" ] && skip "filefrag does not support FIEMAP" && return

	trap cleanup_130 EXIT RETURN

	local fm_file=$DIR/$tfile
	lfs setstripe -s 65536 -c 2 $fm_file || error "setstripe failed on $fm_file"
	dd if=/dev/zero of=$fm_file seek=1 bs=1M count=1 || error "dd failed on $fm_file"

	filefrag -ves $fm_file || error "filefrag $fm_file failed"
	filefrag_op=`filefrag -ve $fm_file | grep -A 100 "ext:" | grep -v "ext:" | grep -v "found"`

	last_lun=`echo $filefrag_op | cut -d: -f5`

	IFS=$'\n'
	tot_len=0
	num_luns=1
	for line in $filefrag_op
	do
		frag_lun=`echo $line | cut -d: -f5`
		ext_len=`echo $line | cut -d: -f4`
		if (( $frag_lun != $last_lun )); then
			logical=`echo $line | cut -d: -f2 | cut -d. -f1`
			if (( logical != 512 )); then
				cleanup_130
				error "FIEMAP on $fm_file failed; returned logical start for lun $logical instead of 512"
				return
			fi
			if (( tot_len != 512 )); then
				cleanup_130
				error "FIEMAP on $fm_file failed; returned len $tot_len for OST $last_lun instead of 1024"
				return
			else
				(( num_luns += 1 ))
				tot_len=0
			fi
		fi
		(( tot_len += ext_len ))
		last_lun=$frag_lun
	done
	if (( num_luns != 2 || tot_len != 512 )); then
		cleanup_130
		error "FIEMAP on $fm_file failed; returned wrong number of luns or wrong len for OST $last_lun"
		return
	fi

	cleanup_130

	echo "FIEMAP on 2-stripe file with hole succeeded"
}
run_test 130c "FIEMAP (2-stripe file with hole)"

test_130d() {
	[ "$OSTCOUNT" -lt "3" ] && skip_env "skipping FIEMAP on N-stripe file test" && return

	filefrag_op=$(filefrag -e 2>&1 | grep "invalid option")
	[ -n "$filefrag_op" ] && skip "filefrag does not support FIEMAP" && return

	trap cleanup_130 EXIT RETURN

	local fm_file=$DIR/$tfile
	lfs setstripe -s 65536 -c $OSTCOUNT $fm_file || error "setstripe failed on $fm_file"
	dd if=/dev/zero of=$fm_file bs=1M count=$OSTCOUNT || error "dd failed on $fm_file"

	filefrag -ves $fm_file || error "filefrag $fm_file failed"
	filefrag_op=`filefrag -ve $fm_file | grep -A 100 "ext:" | grep -v "ext:" | grep -v "found"`

	last_lun=`echo $filefrag_op | cut -d: -f5`

	IFS=$'\n'
	tot_len=0
	num_luns=1
	for line in $filefrag_op
	do
		frag_lun=`echo $line | cut -d: -f5`
		ext_len=`echo $line | cut -d: -f4`
		if (( $frag_lun != $last_lun )); then
			if (( tot_len != 1024 )); then
				cleanup_130
				error "FIEMAP on $fm_file failed; returned len $tot_len for OST $last_lun instead of 1024"
				return
			else
				(( num_luns += 1 ))
				tot_len=0
			fi
		fi
		(( tot_len += ext_len ))
		last_lun=$frag_lun
	done
	if (( num_luns != OSTCOUNT || tot_len != 1024 )); then
		cleanup_130
		error "FIEMAP on $fm_file failed; returned wrong number of luns or wrong len for OST $last_lun"
		return
	fi

	cleanup_130

	echo "FIEMAP on N-stripe file succeeded"
}
run_test 130d "FIEMAP (N-stripe file)"

test_130e() {
	[ "$OSTCOUNT" -lt "2" ] && skip_env "skipping continuation FIEMAP test" && return

	filefrag_op=$(filefrag -e 2>&1 | grep "invalid option")
	[ -n "$filefrag_op" ] && skip "filefrag does not support FIEMAP" && return

	trap cleanup_130 EXIT RETURN

	local fm_file=$DIR/$tfile
	lfs setstripe -s 131072 -c 2 $fm_file || error "setstripe failed on $fm_file"
	NUM_BLKS=512
	EXPECTED_LEN=$(( (NUM_BLKS / 2) * 64 ))
	for ((i = 0; i < $NUM_BLKS; i++))
	do
		dd if=/dev/zero of=$fm_file count=1 bs=64k seek=$((2*$i)) conv=notrunc > /dev/null 2>&1
	done

	filefrag -ves $fm_file || error "filefrag $fm_file failed"
	filefrag_op=`filefrag -ve $fm_file | grep -A 12000 "ext:" | grep -v "ext:" | grep -v "found"`

	last_lun=`echo $filefrag_op | cut -d: -f5`

	IFS=$'\n'
	tot_len=0
	num_luns=1
	for line in $filefrag_op
	do
		frag_lun=`echo $line | cut -d: -f5`
		ext_len=`echo $line | cut -d: -f4`
		if (( $frag_lun != $last_lun )); then
			if (( tot_len != $EXPECTED_LEN )); then
				cleanup_130
				error "FIEMAP on $fm_file failed; returned len $tot_len for OST $last_lun instead of $EXPECTED_LEN"
				return
			else
				(( num_luns += 1 ))
				tot_len=0
			fi
		fi
		(( tot_len += ext_len ))
		last_lun=$frag_lun
	done
	if (( num_luns != 2 || tot_len != $EXPECTED_LEN )); then
		cleanup_130
		error "FIEMAP on $fm_file failed; returned wrong number of luns or wrong len for OST $last_lun"
		return
	fi

	cleanup_130

	echo "FIEMAP with continuation calls succeeded"
}
run_test 130e "FIEMAP (test continuation FIEMAP calls)"

# Test for writev/readv
test_131a() {
	rwv -f $DIR/$tfile -w -n 3 524288 1048576 1572864 || \
	error "writev test failed"
	rwv -f $DIR/$tfile -r -v -n 2 1572864 1048576 || \
	error "readv failed"
	rm -f $DIR/$tfile
}
run_test 131a "test iov's crossing stripe boundary for writev/readv"

test_131b() {
	rwv -f $DIR/$tfile -w -a -n 3 524288 1048576 1572864 || \
	error "append writev test failed"
	rwv -f $DIR/$tfile -w -a -n 2 1572864 1048576 || \
	error "append writev test failed"
	rm -f $DIR/$tfile
}
run_test 131b "test append writev"

test_131c() {
	rwv -f $DIR/$tfile -w -d -n 1 1048576 || return 0
	error "NOT PASS"
}
run_test 131c "test read/write on file w/o objects"

test_131d() {
	rwv -f $DIR/$tfile -w -n 1 1572864
	NOB=`rwv -f $DIR/$tfile -r -n 3 524288 524288 1048576 | awk '/error/ {print $6}'`
	if [ "$NOB" != 1572864 ]; then
		error "Short read filed: read $NOB bytes instead of 1572864"
	fi
	rm -f $DIR/$tfile
}
run_test 131d "test short read"

test_131e() {
	rwv -f $DIR/$tfile -w -s 1048576 -n 1 1048576
	rwv -f $DIR/$tfile -r -z -s 0 -n 1 524288 || \
	error "read hitting hole failed"
	rm -f $DIR/$tfile
}
run_test 131e "test read hitting hole"

get_ost_param() {
        local token=$1
        local gl_sum=0
        for node in $(osts_nodes); do
                gl=$(do_node $node "$LCTL get_param -n ost.OSS.ost.stats" | awk '/'$token'/ {print $2}' | head -n 1)
                [ x$gl = x"" ] && gl=0
                gl_sum=$((gl_sum + gl))
        done
        echo $gl
}

som_mode_switch() {
        local som=$1
        local gl1=$2
        local gl2=$3

        if [ x$som = x"enabled" ]; then
                [ $((gl2 - gl1)) -gt 0 ] && error "no glimpse RPC is expected"
                MOUNTOPT=`echo $MOUNTOPT | sed 's/som_preview//g'`
                do_facet mgs "$LCTL conf_param $FSNAME.mdt.som=disabled"
        else
                [ $((gl2 - gl1)) -gt 0 ] || error "some glimpse RPC is expected"
                MOUNTOPT="$MOUNTOPT,som_preview"
                do_facet mgs "$LCTL conf_param $FSNAME.mdt.som=enabled"
        fi

        # do remount to make new mount-conf parameters actual
        echo remounting...
        sync
        stopall
        setupall
}

test_132() { #1028, SOM
        local num=$(get_mds_dir $DIR)
        local mymds=mds${num}
        local MOUNTOPT_SAVE=$MOUNTOPT

        dd if=/dev/zero of=$DIR/$tfile count=1 2>/dev/null
        cancel_lru_locks osc

        som1=$(do_facet $mymds "$LCTL get_param mdt.*.som" |  awk -F= ' {print $2}' | head -n 1)

        gl1=$(get_ost_param "ldlm_glimpse_enqueue")
        stat $DIR/$tfile >/dev/null
        gl2=$(get_ost_param "ldlm_glimpse_enqueue")
        echo "====> SOM is "$som1", "$((gl2 - gl1))" glimpse RPC occured"
        rm $DIR/$tfile
        som_mode_switch $som1 $gl1 $gl2

        dd if=/dev/zero of=$DIR/$tfile count=1 2>/dev/null
        cancel_lru_locks osc

        som2=$(do_facet $mymds "$LCTL get_param mdt.*.som" |  awk -F= ' {print $2}' | head -n 1)
        if [ $som1 == $som2 ]; then
            error "som is still "$som2
            if [ x$som2 = x"enabled" ]; then
                som2="disabled"
            else
                som2="enabled"
            fi
        fi

        gl1=$(get_ost_param "ldlm_glimpse_enqueue")
        stat $DIR/$tfile >/dev/null
        gl2=$(get_ost_param "ldlm_glimpse_enqueue")
        echo "====> SOM is "$som2", "$((gl2 - gl1))" glimpse RPC occured"
        som_mode_switch $som2 $gl1 $gl2
        MOUNTOPT=$MOUNTOPT_SAVE
}
run_test 132 "som avoids glimpse rpc"

check_stats() {
	local res
	local count
	case $1 in
	$SINGLEMDS) res=`do_facet $SINGLEMDS $LCTL get_param mdt.$FSNAME-MDT0000.md_stats | grep "$2"`
		 ;;
	ost) res=`do_facet ost $LCTL get_param obdfilter.$FSNAME-OST0000.stats | grep "$2"`
		 ;;
	*) error "Wrong argument $1" ;;
	esac
	echo $res
	count=`echo $res | awk '{print $2}'`
	[ -z "$res" ] && error "The counter for $2 on $1 was not incremented"
	# if the argument $3 is zero, it means any stat increment is ok.
	if [ $3 -gt 0 ] ; then
		[ $count -ne $3 ] && error "The $2 counter on $1 is wrong - expected $3"
	fi
}

test_133a() {
	local testdir=$DIR/${tdir}/stats_testdir
	mkdir -p $DIR/${tdir}

	# clear stats.
	do_facet $SINGLEMDS $LCTL set_param mdt.*.md_stats=clear
	do_facet ost $LCTL set_param obdfilter.*.stats=clear

	# verify mdt stats first.
	mkdir ${testdir} || error "mkdir failed"
	check_stats $SINGLEMDS "mkdir" 1
	touch ${testdir}/${tfile} || "touch failed"
	check_stats $SINGLEMDS "open" 1
	check_stats $SINGLEMDS "close" 1
	mknod ${testdir}/${tfile}-pipe p || "mknod failed"
	check_stats $SINGLEMDS "mknod" 1
	rm -f ${testdir}/${tfile}-pipe || "pipe remove failed"
	check_stats $SINGLEMDS "unlink" 1
	rm -f ${testdir}/${tfile} || error "file remove failed"
	check_stats $SINGLEMDS "unlink" 2

	# remove working dir and check mdt stats again.
	rmdir ${testdir} || error "rmdir failed"
	check_stats $SINGLEMDS "rmdir" 1

	rm -rf $DIR/${tdir}
}
run_test 133a "Verifying MDT stats ========================================"

test_133b() {
	local testdir=$DIR/${tdir}/stats_testdir
	mkdir -p ${testdir} || error "mkdir failed"
	touch ${testdir}/${tfile} || "touch failed"
	cancel_lru_locks mdc

	# clear stats.
	do_facet $SINGLEMDS $LCTL set_param mdt.*.md_stats=clear
	do_facet ost $LCTL set_param obdfilter.*.stats=clear

	# extra mdt stats verification.
	chmod 444 ${testdir}/${tfile} || error "chmod failed"
	check_stats $SINGLEMDS "setattr" 1
	$LFS df || error "lfs failed"
	check_stats $SINGLEMDS "statfs" 1

	rm -rf $DIR/${tdir}
}
run_test 133b "Verifying extra MDT stats =================================="

test_133c() {
	local testdir=$DIR/${tdir}/stats_testdir
	mkdir -p ${testdir} || error "mkdir failed"

	# verify obdfilter stats.
	$LFS setstripe -c 1 -o 0 ${testdir}/${tfile}
	sync
	cancel_lru_locks osc

	# clear stats.
	do_facet $SINGLEMDS $LCTL set_param mdt.*.md_stats=clear
	do_facet ost $LCTL set_param obdfilter.*.stats=clear

	dd if=/dev/zero of=${testdir}/${tfile} conv=notrunc bs=1024k count=1 || error "dd failed"
	sync
	cancel_lru_locks osc
	check_stats ost "write" 1

	dd if=${testdir}/${tfile} of=/dev/null bs=1k count=1 || error "dd failed"
	check_stats ost "read" 1

	> ${testdir}/${tfile} || error "truncate failed"
	check_stats ost "punch" 1

	rm -f ${testdir}/${tfile} || error "file remove failed"
	check_stats ost "destroy" 1

	rm -rf $DIR/${tdir}
}
run_test 133c "Verifying OST stats ========================================"

test_140() { #bug-17379
        mkdir -p $DIR/$tdir || error "Creating dir $DIR/$tdir"
        cd $DIR/$tdir || error "Changing to $DIR/$tdir"
        cp /usr/bin/stat . || error "Copying stat to $DIR/$tdir"

        # VFS limits max symlink depth to 5(4KSTACK) or 7(8KSTACK) or 8
        local i=0
        while i=`expr $i + 1`; do
                mkdir -p $i || error "Creating dir $i"
                cd $i || error "Changing to $i"
                ln -s ../stat stat || error "Creating stat symlink"
                # Read the symlink until ELOOP present,
                # not LBUGing the system is considered success,
                # we didn't overrun the stack.
                $OPENFILE -f O_RDONLY stat >/dev/null 2>&1; ret=$?
                [ $ret -ne 0 ] && {
                        if [ $ret -eq 40 ]; then
                                break  # -ELOOP
                        else
                                error "Open stat symlink"
                                return
                        fi
                }
        done
        i=`expr $i - 1`
        echo "The symlink depth = $i"
        [ $i -eq 5 -o $i -eq 7 -o $i -eq 8 ] || error "Invalid symlink depth"
}
run_test 140 "Check reasonable stack depth (shouldn't LBUG) ===="

test_150() {
	local TF="$TMP/$tfile"

        dd if=/dev/urandom of=$TF bs=6096 count=1 || error "dd failed"
        cp $TF $DIR/$tfile
        cancel_lru_locks osc
        cmp $TF $DIR/$tfile || error "$TMP/$tfile $DIR/$tfile differ"
        remount_client $MOUNT
        df -P $MOUNT
        cmp $TF $DIR/$tfile || error "$TF $DIR/$tfile differ (remount)"

        $TRUNCATE $TF 6000
        $TRUNCATE $DIR/$tfile 6000
        cancel_lru_locks osc
        cmp $TF $DIR/$tfile || error "$TF $DIR/$tfile differ (truncate1)"

        echo "12345" >>$TF
        echo "12345" >>$DIR/$tfile
        cancel_lru_locks osc
        cmp $TF $DIR/$tfile || error "$TF $DIR/$tfile differ (append1)"

        echo "12345" >>$TF
        echo "12345" >>$DIR/$tfile
        cancel_lru_locks osc
        cmp $TF $DIR/$tfile || error "$TF $DIR/$tfile differ (append2)"

        rm -f $TF
        true
}
run_test 150 "truncate/append tests"

function roc_hit() {
    local list=$(comma_list $(osts_nodes))

    ACCNUM=$(do_nodes $list $LCTL get_param -n obdfilter.*.stats | \
        awk '/'cache_hit'/ {sum+=$2} END {print sum}')
    echo $ACCNUM
}

function set_cache() {
    local on=1

    if [ "$2" == "off" ]; then
        on=0;
    fi
    local list=$(comma_list $(osts_nodes))
    do_nodes $list lctl set_param obdfilter.*.${1}_cache_enable $on

    cancel_lru_locks osc
}

test_151() {
        remote_ost_nodsh && skip "remote OST with nodsh" && return

        local CPAGES=3
        local list=$(comma_list $(osts_nodes))

        # check whether obdfilter is cache capable at all
        if ! do_nodes $list $LCTL get_param -n obdfilter.*.read_cache_enable > /dev/null; then
                echo "not cache-capable obdfilter"
                return 0
        fi

        # check cache is enabled on all obdfilters
        if do_nodes $list $LCTL get_param -n obdfilter.*.read_cache_enable | grep 0 >&/dev/null; then
                echo "oss cache is disabled"
                return 0
        fi

        do_nodes $list $LCTL set_param -n obdfilter.*.writethrough_cache_enable 1

        # pages should be in the case right after write
        dd if=/dev/urandom of=$DIR/$tfile bs=4k count=$CPAGES || error "dd failed"
        local BEFORE=`roc_hit`
        cancel_lru_locks osc
        cat $DIR/$tfile >/dev/null
        local AFTER=`roc_hit`
        if ! let "AFTER - BEFORE == CPAGES"; then
                error "NOT IN CACHE: before: $BEFORE, after: $AFTER"
        fi

        # the following read invalidates the cache
        cancel_lru_locks osc
        do_nodes $list $LCTL set_param -n obdfilter.*.read_cache_enable 0
        cat $DIR/$tfile >/dev/null

        # now data shouldn't be found in the cache
        BEFORE=`roc_hit`
        cancel_lru_locks osc
        cat $DIR/$tfile >/dev/null
        AFTER=`roc_hit`
        if let "AFTER - BEFORE != 0"; then
                error "IN CACHE: before: $BEFORE, after: $AFTER"
        fi

        do_nodes $list $LCTL set_param -n obdfilter.*.read_cache_enable 1
        rm -f $DIR/$tfile
}
run_test 151 "test cache on oss and controls ==============================="

test_152() {
        local TF="$TMP/$tfile"

        # simulate ENOMEM during write
#define OBD_FAIL_OST_NOMEM      0x226
        lctl set_param fail_loc=0x80000226
        dd if=/dev/urandom of=$TF bs=6096 count=1 || error "dd failed"
        cp $TF $DIR/$tfile
        sync || error "sync failed"
        lctl set_param fail_loc=0

        # discard client's cache
        cancel_lru_locks osc

        # simulate ENOMEM during read
        lctl set_param fail_loc=0x80000226
        cmp $TF $DIR/$tfile || error "cmp failed"
        lctl set_param fail_loc=0

        rm -f $TF
}
run_test 152 "test read/write with enomem ============================"

test_153() {
        multiop $DIR/$tfile Ow4096Ycu || error "multiop failed"
}
run_test 153 "test if fdatasync does not crash ======================="

test_154() {
	cp /etc/hosts $DIR/$tfile

	fid=$($LFS path2fid $DIR/$tfile)
	rc=$?
	[ $rc -ne 0 ] && error "error: could not get fid for $DIR/$tfile."

	echo "open fid $fid"
	diff /etc/hosts $DIR/.lustre/fid/$fid || error "open by fid failed: did not find expected data in file."

	echo "Opening a file by FID succeeded"
}
run_test 154 "Opening a file by FID"

test_155_small_load() {
    local temp=$TMP/$tfile
    local file=$DIR/$tfile

    dd if=/dev/urandom of=$temp bs=6096 count=1 || \
        error "dd of=$temp bs=6096 count=1 failed"
    cp $temp $file
    cancel_lru_locks osc
    cmp $temp $file || error "$temp $file differ"

    $TRUNCATE $temp 6000
    $TRUNCATE $file 6000
    cmp $temp $file || error "$temp $file differ (truncate1)"

    echo "12345" >>$temp
    echo "12345" >>$file
    cmp $temp $file || error "$temp $file differ (append1)"

    echo "12345" >>$temp
    echo "12345" >>$file
    cmp $temp $file || error "$temp $file differ (append2)"

    rm -f $temp $file
    true
}

test_155_big_load() {
    local temp=$TMP/$tfile
    local file=$DIR/$tfile

    free_min_max
    local cache_size=$(do_facet ost$((MAXI+1)) \
        "awk '/cache/ {sum+=\\\$4} END {print sum}' /proc/cpuinfo")
    local large_file_size=$((cache_size * 2))

    echo "OSS cache size: $cache_size KB"
    echo "Large file size: $large_file_size KB"

    [ $MAXV -le $large_file_size ] && \
        skip_env "max available OST size needs > $large_file_size KB" && \
        return 0

    $SETSTRIPE $file -c 1 -i $MAXI || error "$SETSTRIPE $file failed"

    dd if=/dev/urandom of=$temp bs=$large_file_size count=1k || \
        error "dd of=$temp bs=$large_file_size count=1k failed"
    cp $temp $file
    ls -lh $temp $file
    cancel_lru_locks osc
    cmp $temp $file || error "$temp $file differ"

    rm -f $temp $file
    true
}

test_155a() {
    set_cache read on
    set_cache writethrough on
    test_155_small_load
}
run_test 155a "Verify small file correctness: read cache:on write_cache:on"

test_155b() {
    set_cache read on
    set_cache writethrough off
    test_155_small_load
}
run_test 155b "Verify small file correctness: read cache:on write_cache:off"

test_155c() {
    set_cache read off
    set_cache writethrough on
    test_155_small_load
}
run_test 155c "Verify small file correctness: read cache:off write_cache:on"

test_155d() {
    set_cache read off
    set_cache writethrough off
    test_155_small_load
}
run_test 155d "Verify small file correctness: read cache:off write_cache:off"

test_155e() {
    set_cache read on
    set_cache writethrough on
    test_155_big_load
}
run_test 155e "Verify big file correctness: read cache:on write_cache:on"

test_155f() {
    set_cache read on
    set_cache writethrough off
    test_155_big_load
}
run_test 155f "Verify big file correctness: read cache:on write_cache:off"

test_155g() {
    set_cache read off
    set_cache writethrough on
    test_155_big_load
}
run_test 155g "Verify big file correctness: read cache:off write_cache:on"

test_155h() {
    set_cache read off
    set_cache writethrough off
    test_155_big_load
}
run_test 155h "Verify big file correctness: read cache:off write_cache:off"

test_156() {
    local CPAGES=3
    local BEFORE
    local AFTER
    local file="$DIR/$tfile"

    log "Turn on read and write cache"
    set_cache read on
    set_cache writethrough on

    log "Write data and read it back."
    log "Read should be satisfied from the cache."
    dd if=/dev/urandom of=$file bs=4k count=$CPAGES || error "dd failed"
    BEFORE=`roc_hit`
    cancel_lru_locks osc
    cat $file >/dev/null
    AFTER=`roc_hit`
    if ! let "AFTER - BEFORE == CPAGES"; then
        error "NOT IN CACHE: before: $BEFORE, after: $AFTER"
    else
        log "cache hits:: before: $BEFORE, after: $AFTER"
    fi

    log "Read again; it should be satisfied from the cache."
    BEFORE=$AFTER
    cancel_lru_locks osc
    cat $file >/dev/null
    AFTER=`roc_hit`
    if ! let "AFTER - BEFORE == CPAGES"; then
        error "NOT IN CACHE: before: $BEFORE, after: $AFTER"
    else
        log "cache hits:: before: $BEFORE, after: $AFTER"
    fi


    log "Turn off the read cache and turn on the write cache"
    set_cache read off
    set_cache writethrough on

    log "Read again; it should be satisfied from the cache."
    BEFORE=`roc_hit`
    cancel_lru_locks osc
    cat $file >/dev/null
    AFTER=`roc_hit`
    if ! let "AFTER - BEFORE == CPAGES"; then
        error "NOT IN CACHE: before: $BEFORE, after: $AFTER"
    else
        log "cache hits:: before: $BEFORE, after: $AFTER"
    fi

    log "Read again; it should not be satisfied from the cache."
    BEFORE=$AFTER
    cancel_lru_locks osc
    cat $file >/dev/null
    AFTER=`roc_hit`
    if ! let "AFTER - BEFORE == 0"; then
        error "IN CACHE: before: $BEFORE, after: $AFTER"
    else
        log "cache hits:: before: $BEFORE, after: $AFTER"
    fi

    log "Write data and read it back."
    log "Read should be satisfied from the cache."
    dd if=/dev/urandom of=$file bs=4k count=$CPAGES || error "dd failed"
    BEFORE=`roc_hit`
    cancel_lru_locks osc
    cat $file >/dev/null
    AFTER=`roc_hit`
    if ! let "AFTER - BEFORE == CPAGES"; then
        error "NOT IN CACHE: before: $BEFORE, after: $AFTER"
    else
        log "cache hits:: before: $BEFORE, after: $AFTER"
    fi

    log "Read again; it should not be satisfied from the cache."
    BEFORE=$AFTER
    cancel_lru_locks osc
    cat $file >/dev/null
    AFTER=`roc_hit`
    if ! let "AFTER - BEFORE == 0"; then
        error "IN CACHE: before: $BEFORE, after: $AFTER"
    else
        log "cache hits:: before: $BEFORE, after: $AFTER"
    fi


    log "Turn off read and write cache"
    set_cache read off
    set_cache writethrough off

    log "Write data and read it back"
    log "It should not be satisfied from the cache."
    rm -f $file
    dd if=/dev/urandom of=$file bs=4k count=$CPAGES || error "dd failed"
    cancel_lru_locks osc
    BEFORE=`roc_hit`
    cat $file >/dev/null
    AFTER=`roc_hit`
    if ! let "AFTER - BEFORE == 0"; then
        error_ignore 20762 "IN CACHE: before: $BEFORE, after: $AFTER"
    else
        log "cache hits:: before: $BEFORE, after: $AFTER"
    fi


    log "Turn on the read cache and turn off the write cache"
    set_cache read on
    set_cache writethrough off

    log "Write data and read it back"
    log "It should not be satisfied from the cache."
    rm -f $file
    dd if=/dev/urandom of=$file bs=4k count=$CPAGES || error "dd failed"
    BEFORE=`roc_hit`
    cancel_lru_locks osc
    cat $file >/dev/null
    AFTER=`roc_hit`
    if ! let "AFTER - BEFORE == 0"; then
        error_ignore 20762 "IN CACHE: before: $BEFORE, after: $AFTER"
    else
        log "cache hits:: before: $BEFORE, after: $AFTER"
    fi

    log "Read again; it should be satisfied from the cache."
    BEFORE=`roc_hit`
    cancel_lru_locks osc
    cat $file >/dev/null
    AFTER=`roc_hit`
    if ! let "AFTER - BEFORE == CPAGES"; then
        error "NOT IN CACHE: before: $BEFORE, after: $AFTER"
    else
        log "cache hits:: before: $BEFORE, after: $AFTER"
    fi

    rm -f $file
}
run_test 156 "Verification of tunables ============================"

#Changelogs
err17935 () {
    if [ $MDSCOUNT -gt 1 ]; then
	error_ignore 17935 $*
    else
	error $*
    fi
}
test_160() {
    USER=$(do_facet $SINGLEMDS lctl --device $MDT0 changelog_register -n)
    echo "Registered as changelog user $USER"
    do_facet $SINGLEMDS lctl get_param -n mdd.$MDT0.changelog_users | \
	grep -q $USER || error "User $USER not found in changelog_users"

    # change something
    mkdir -p $DIR/$tdir/pics/2008/zachy
    touch $DIR/$tdir/pics/2008/zachy/timestamp
    cp /etc/hosts $DIR/$tdir/pics/2008/zachy/pic1.jpg
    mv $DIR/$tdir/pics/2008/zachy $DIR/$tdir/pics/zach
    ln $DIR/$tdir/pics/zach/pic1.jpg $DIR/$tdir/pics/2008/portland.jpg
    ln -s $DIR/$tdir/pics/2008/portland.jpg $DIR/$tdir/pics/desktop.jpg
    rm $DIR/$tdir/pics/desktop.jpg

    $LFS changelog $MDT0 | tail -5

    echo "verifying changelog mask"
    do_facet $SINGLEMDS lctl set_param mdd.$MDT0.changelog_mask="-mkdir"
    mkdir -p $DIR/$tdir/pics/2009/sofia
    do_facet $SINGLEMDS lctl set_param mdd.$MDT0.changelog_mask="+mkdir"
    mkdir $DIR/$tdir/pics/2009/zachary
    DIRS=$($LFS changelog $MDT0 | tail -5 | grep -c MKDIR)
    [ $DIRS -eq 1 ] || err17935 "changelog mask count $DIRS != 1"

    # verify contents
    echo "verifying target fid"
    fidc=$($LFS changelog $MDT0 | grep timestamp | grep "CREAT" | \
	tail -1 | awk '{print $6}')
    fidf=$($LFS path2fid $DIR/$tdir/pics/zach/timestamp)
    [ "$fidc" == "t=$fidf" ] || \
	err17935 "fid in changelog $fidc != file fid $fidf"
    echo "verifying parent fid"
    fidc=$($LFS changelog $MDT0 | grep timestamp | grep "CREAT" | \
	tail -1 | awk '{print $7}')
    fidf=$($LFS path2fid $DIR/$tdir/pics/zach)
    [ "$fidc" == "p=$fidf" ] || \
	err17935 "pfid in changelog $fidc != dir fid $fidf"

    USER_REC1=$(do_facet $SINGLEMDS lctl get_param -n \
	mdd.$MDT0.changelog_users | grep $USER | awk '{print $2}')
    $LFS changelog_clear $MDT0 $USER $(($USER_REC1 + 5))
    USER_REC2=$(do_facet $SINGLEMDS lctl get_param -n \
	mdd.$MDT0.changelog_users | grep $USER | awk '{print $2}')
    echo "verifying user clear: $(( $USER_REC1 + 5 )) == $USER_REC2"
    [ $USER_REC2 == $(($USER_REC1 + 5)) ] || \
	err17935 "user index should be $(($USER_REC1 + 5)); is $USER_REC2"

    MIN_REC=$(do_facet $SINGLEMDS lctl get_param mdd.$MDT0.changelog_users | \
	awk 'min == "" || $2 < min {min = $2}; END {print min}')
    FIRST_REC=$($LFS changelog $MDT0 | head -1 | awk '{print $1}')
    echo "verifying min purge: $(( $MIN_REC + 1 )) == $FIRST_REC"
    [ $FIRST_REC == $(($MIN_REC + 1)) ] || \
	err17935 "first index should be $(($MIN_REC + 1)); is $FIRST_REC"

    echo "verifying user deregister"
    do_facet $SINGLEMDS lctl --device $MDT0 changelog_deregister $USER
    do_facet $SINGLEMDS lctl get_param -n mdd.$MDT0.changelog_users | \
	grep -q $USER && error "User $USER still found in changelog_users"

    USERS=$(( $(do_facet $SINGLEMDS lctl get_param -n \
	mdd.$MDT0.changelog_users | wc -l) - 2 ))
    if [ $USERS -eq 0 ]; then
	LAST_REC1=$(do_facet $SINGLEMDS lctl get_param -n \
	    mdd.$MDT0.changelog_users | head -1 | awk '{print $3}')
	touch $DIR/$tdir/chloe
	LAST_REC2=$(do_facet $SINGLEMDS lctl get_param -n \
	    mdd.$MDT0.changelog_users | head -1 | awk '{print $3}')
	echo "verify changelogs are off if we were the only user: $LAST_REC1 == $LAST_REC2"
	[ $LAST_REC1 == $LAST_REC2 ] || error "changelogs not off"
    else
	echo "$USERS other changelog users; can't verify off"
    fi
}
run_test 160 "changelog sanity"

test_161() {
    mkdir -p $DIR/$tdir
    cp /etc/hosts $DIR/$tdir/$tfile
    mkdir $DIR/$tdir/foo1
    mkdir $DIR/$tdir/foo2
    ln $DIR/$tdir/$tfile $DIR/$tdir/foo1/sofia
    ln $DIR/$tdir/$tfile $DIR/$tdir/foo2/zachary
    ln $DIR/$tdir/$tfile $DIR/$tdir/foo1/luna
    ln $DIR/$tdir/$tfile $DIR/$tdir/foo2/thor
    local FID=$($LFS path2fid $DIR/$tdir/$tfile | tr -d '[')
    if [ "$($LFS fid2path $DIR $FID | wc -l)" != "5" ]; then
	$LFS fid2path $DIR $FID
	err17935 "bad link ea"
    fi
    # middle
    rm $DIR/$tdir/foo2/zachary
    # last
    rm $DIR/$tdir/foo2/thor
    # first
    rm $DIR/$tdir/$tfile
    # rename
    mv $DIR/$tdir/foo1/sofia $DIR/$tdir/foo2/maggie
    if [ "$($LFS fid2path $FSNAME --link 1 $FID)" != "$tdir/foo2/maggie" ]
	then
	$LFS fid2path $DIR $FID
	err17935 "bad link rename"
    fi
    rm $DIR/$tdir/foo2/maggie

    # overflow the EA
    local longname=filename_avg_len_is_thirty_two_
    createmany -l$DIR/$tdir/foo1/luna $DIR/$tdir/foo2/$longname 1000 || \
	error "failed to hardlink many files"
    links=$($LFS fid2path $DIR $FID | wc -l)
    echo -n "${links}/1000 links in link EA"
    [ ${links} -gt 60 ] || err17935 "expected at least 60 links in link EA"
    unlinkmany $DIR/$tdir/foo2/$longname 1000 || \
	error "failed to unlink many hardlinks"
}
run_test 161 "link ea sanity"

check_path() {
    local expected=$1
    shift
    local fid=$2

    local path=$(${LFS} fid2path $*)
    RC=$?

    if [ $RC -ne 0 ]; then
      	err17935 "path looked up of $expected failed. Error $RC"
 	return $RC
    elif [ "${path}" != "${expected}" ]; then
      	err17935 "path looked up \"${path}\" instead of \"${expected}\""
 	return 2
    fi
    echo "fid $fid resolves to path $path (expected $expected)"
}

test_162() {
	# Make changes to filesystem
	mkdir -p $DIR/$tdir/d2
	touch $DIR/$tdir/d2/$tfile
	touch $DIR/$tdir/d2/x1
	touch $DIR/$tdir/d2/x2
	mkdir -p $DIR/$tdir/d2/a/b/c
	mkdir -p $DIR/$tdir/d2/p/q/r
	# regular file
	FID=$($LFS path2fid $DIR/$tdir/d2/$tfile | tr -d '[]')
	check_path "$tdir/d2/$tfile" $FSNAME $FID --link 0

	# softlink
	ln -s $DIR/$tdir/d2/$tfile $DIR/$tdir/d2/p/q/r/slink
	FID=$($LFS path2fid $DIR/$tdir/d2/p/q/r/slink | tr -d '[]')
	check_path "$tdir/d2/p/q/r/slink" $FSNAME $FID --link 0

	# softlink to wrong file
	ln -s /this/is/garbage $DIR/$tdir/d2/p/q/r/slink.wrong
	FID=$($LFS path2fid $DIR/$tdir/d2/p/q/r/slink.wrong | tr -d '[]')
	check_path "$tdir/d2/p/q/r/slink.wrong" $FSNAME $FID --link 0

	# hardlink
	ln $DIR/$tdir/d2/$tfile $DIR/$tdir/d2/p/q/r/hlink
	mv $DIR/$tdir/d2/$tfile $DIR/$tdir/d2/a/b/c/new_file
	FID=$($LFS path2fid $DIR/$tdir/d2/a/b/c/new_file | tr -d '[]')
	# fid2path dir/fsname should both work
	check_path "$tdir/d2/a/b/c/new_file" $FSNAME $FID --link 1
	check_path "$DIR/$tdir/d2/p/q/r/hlink" $DIR $FID --link 0

	# hardlink count: check that there are 2 links
	# Doesnt work with CMD yet: 17935
	${LFS} fid2path $DIR $FID | wc -l | grep -q 2 || \
		err17935 "expected 2 links"

	# hardlink indexing: remove the first link
	rm $DIR/$tdir/d2/p/q/r/hlink
	check_path "$tdir/d2/a/b/c/new_file" $FSNAME $FID --link 0

	return 0
}
run_test 162 "path lookup sanity"

test_163() {
	remote_mds_nodsh && skip "remote MDS with nodsh" && return
	copytool --test $FSNAME || { skip "copytool not runnable: $?" && return; }
	copytool $FSNAME &
	sleep 1
	local uuid=$($LCTL get_param -n mdc.${FSNAME}-MDT0000-mdc-*.uuid)
	# this proc file is temporary and linux-only
	do_facet $SINGLEMDS lctl set_param mdt.${FSNAME}-MDT0000.mdccomm=$uuid ||\
         error "kernel->userspace send failed"
	kill -INT $!
}
run_test 163 "kernel <-> userspace comms"

test_169() {
	# do directio so as not to populate the page cache
	log "creating a 10 Mb file"
	multiop $DIR/$tfile oO_CREAT:O_DIRECT:O_RDWR:w$((10*1048576))c || error "multiop failed while creating a file"
	log "starting reads"
	dd if=$DIR/$tfile of=/dev/null bs=4096 &
	log "truncating the file"
	multiop $DIR/$tfile oO_TRUNC:c || error "multiop failed while truncating the file"
	log "killing dd"
	kill %+ || true # reads might have finished
	echo "wait until dd is finished"
	wait
	log "removing the temporary file"
	rm -rf $DIR/$tfile || error "tmp file removal failed"
}
run_test 169 "parallel read and truncate should not deadlock"

test_170() {
        $LCTL clear	# bug 18514
        $LCTL debug_daemon start $TMP/${tfile}_log_good
        touch $DIR/$tfile
        $LCTL debug_daemon stop
        sed -e "s/^...../a/g" $TMP/${tfile}_log_good > $TMP/${tfile}_log_bad ||
               error "sed failed to read log_good"

        $LCTL debug_daemon start $TMP/${tfile}_log_good
        rm -rf $DIR/$tfile
        $LCTL debug_daemon stop

        $LCTL df $TMP/${tfile}_log_bad > $TMP/${tfile}_log_bad.out 2>&1 ||
               error "lctl df log_bad failed"

        local bad_line=$(tail -n 1 $TMP/${tfile}_log_bad.out | awk '{print $9}')
        local good_line1=$(tail -n 1 $TMP/${tfile}_log_bad.out | awk '{print $5}')

        $LCTL df $TMP/${tfile}_log_good > $TMP/${tfile}_log_good.out 2>&1
        local good_line2=$(tail -n 1 $TMP/${tfile}_log_good.out | awk '{print $5}')

	[ "$bad_line" ] && [ "$good_line1" ] && [ "$good_line2" ] ||
		error "bad_line good_line1 good_line2 are empty"

        cat $TMP/${tfile}_log_good >> $TMP/${tfile}_logs_corrupt
        cat $TMP/${tfile}_log_bad >> $TMP/${tfile}_logs_corrupt
        cat $TMP/${tfile}_log_good >> $TMP/${tfile}_logs_corrupt

        $LCTL df $TMP/${tfile}_logs_corrupt > $TMP/${tfile}_log_bad.out 2>&1
        local bad_line_new=$(tail -n 1 $TMP/${tfile}_log_bad.out | awk '{print $9}')
        local good_line_new=$(tail -n 1 $TMP/${tfile}_log_bad.out | awk '{print $5}')

	[ "$bad_line_new" ] && [ "$good_line_new" ] ||
		error "bad_line_new good_line_new are empty"

        local expected_good=$((good_line1 + good_line2*2))

        rm -f $TMP/${tfile}*
	# LU-231, short malformed line may not be counted into bad lines
        if [ $bad_line -ne $bad_line_new ] &&
		   [ $bad_line -ne $((bad_line_new - 1)) ]; then
                error "expected $bad_line bad lines, but got $bad_line_new"
                return 1
        fi

        if [ $expected_good -ne $good_line_new ]; then
                error "expected $expected_good good lines, but got $good_line_new"
                return 2
        fi
        true
}
run_test 170 "test lctl df to handle corrupted log ====================="

test_171() { # bug20592
#define OBD_FAIL_PTLRPC_DUMP_LOG         0x50e
        $LCTL set_param fail_loc=0x50e
        $LCTL set_param fail_val=3000
        multiop_bg_pause $DIR/$tfile O_s || true
        local MULTIPID=$!
        kill -USR1 $MULTIPID
        # cause log dump
        sleep 3
        wait $MULTIPID
        if dmesg | grep "recursive fault"; then
                error "caught a recursive fault"
        fi
        $LCTL set_param fail_loc=0
        true
}
run_test 171 "test libcfs_debug_dumplog_thread stuck in do_exit() ======"

# it would be good to share it with obdfilter-survey/libecho code
setup_obdecho_osc () {
        local rc=0
        local ost_nid=$1
        local obdfilter_name=$2
        echo "Creating new osc for $obdfilter_name on $ost_nid"
        # make sure we can find loopback nid
        $LCTL add_uuid $ost_nid $ost_nid >/dev/null 2>&1

        [ $rc -eq 0 ] && { $LCTL attach osc ${obdfilter_name}_osc     \
                           ${obdfilter_name}_osc_UUID || rc=2; }
        [ $rc -eq 0 ] && { $LCTL --device ${obdfilter_name}_osc setup \
                           ${obdfilter_name}_UUID  $ost_nid || rc=3; }
        return $rc
}

cleanup_obdecho_osc () {
        local obdfilter_name=$1
        $LCTL --device ${obdfilter_name}_osc cleanup >/dev/null
        $LCTL --device ${obdfilter_name}_osc detach  >/dev/null
        return 0
}

obdecho_create_test() {
        local OBD=$1
        local node=$2
        local rc=0
        local id
        do_facet $node "$LCTL attach echo_client ec ec_uuid" || rc=1
        [ $rc -eq 0 ] && { do_facet $node "$LCTL --device ec setup $OBD" ||
                           rc=2; }
        if [ $rc -eq 0 ]; then
            id=$(do_facet $node "$LCTL --device ec create 1"  | awk '/object id/ {print $6}')
            [ ${PIPESTATUS[0]} -eq 0 -a -n "$id" ] || rc=3
        fi
        echo "New object id is $id"
        [ $rc -eq 0 ] && { do_facet $node "$LCTL --device ec test_brw 10 w v 64 $id" ||
                           rc=4; }
        [ $rc -eq 0 -o $rc -gt 2 ] && { do_facet $node "$LCTL --device ec "    \
                                        "cleanup" || rc=5; }
        [ $rc -eq 0 -o $rc -gt 1 ] && { do_facet $node "$LCTL --device ec "    \
                                        "detach" || rc=6; }
        [ $rc -ne 0 ] && echo "obecho_create_test failed: $rc"
        return $rc
}

test_180a() {
        local rc=0
        local rmmod_local=0

        if ! module_loaded obdecho; then
            load_module obdecho/obdecho
            rmmod_local=1
        fi

        local osc=$($LCTL dl | grep -v mdt | awk '$3 == "osc" {print $4; exit}')
        local host=$(awk '/current_connection:/ {print $2}' /proc/fs/lustre/osc/$osc/import)
        local target=$(awk '/target:/ {print $2}' /proc/fs/lustre/osc/$osc/import)
        target=${target%_UUID}

        [[ -n $target ]]  && { setup_obdecho_osc $host $target || rc=1; } || rc=1
        [ $rc -eq 0 ] && { obdecho_create_test ${target}_osc client || rc=2; }
        [[ -n $target ]] && cleanup_obdecho_osc $target
        [ $rmmod_local -eq 1 ] && rmmod obdecho
        return $rc
}
run_test 180a "test obdecho on osc"

test_180b() {
        local rc=0
        local rmmod_remote=0

        do_facet ost "lsmod | grep -q obdecho || "                      \
                     "{ insmod ${LUSTRE}/obdecho/obdecho.ko || "        \
                     "modprobe obdecho; }" && rmmod_remote=1
        target=$(do_facet ost $LCTL dl | awk '/obdfilter/ {print $4;exit}')
        [[ -n $target ]] && { obdecho_create_test $target ost || rc=1; }
        [ $rmmod_remote -eq 1 ] && do_facet ost "rmmod obdecho"
        return $rc
}
run_test 180b "test obdecho directly on obdfilter"

test_181() { # bug 22177
	mkdir -p $DIR/$tdir || error "creating dir $DIR/$tdir"
	# create enough files to index the directory
	createmany -o $DIR/$tdir/foobar 4000
	# print attributes for debug purpose
	lsattr -d .
	# open dir
	multiop_bg_pause $DIR/$tdir D_Sc || return 1
	MULTIPID=$!
	# remove the files & current working dir
	unlinkmany $DIR/$tdir/foobar 4000
	rmdir $DIR/$tdir
	kill -USR1 $MULTIPID
	wait $MULTIPID
	stat $DIR/$tdir && error "open-unlinked dir was not removed!"
	return 0
}
run_test 181 "Test open-unlinked dir ========================"

# OST pools tests
POOL=${POOL:-cea1}
TGT_COUNT=$OSTCOUNT
TGTPOOL_FIRST=1
TGTPOOL_MAX=$(($TGT_COUNT - 1))
TGTPOOL_STEP=2
TGTPOOL_LIST=`seq $TGTPOOL_FIRST $TGTPOOL_STEP $TGTPOOL_MAX`
POOL_ROOT=${POOL_ROOT:-$DIR/d200.pools}
POOL_DIR_NAME=dir_tst
POOL_DIR=$POOL_ROOT/$POOL_DIR_NAME
POOL_FILE=$POOL_ROOT/file_tst

check_file_in_pool()
{
	file=$1
	res=$($GETSTRIPE $file | grep 0x | cut -f2)
	for i in $res
	do
		found=$(echo :$TGTPOOL_LIST: | tr " " ":"  | grep :$i:)
		if [[ "$found" == "" ]]
		then
			echo "pool list: $TGTPOOL_LIST"
			echo "striping: $res"
			error "$file not allocated in $POOL"
			return 1
		fi
	done
	return 0
}

trap "cleanup_pools $FSNAME" EXIT

test_200a() {
	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
    create_pool $FSNAME.$POOL || return $?
	[ $($LFS pool_list $FSNAME | grep -c $POOL) -eq 1 ] ||
		error "$POOL not in lfs pool_list"
}
run_test 200a "Create new pool =========================================="

test_200b() {
	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	TGT=$(for i in $TGTPOOL_LIST; do printf "$FSNAME-OST%04x_UUID " $i; done)
	do_facet mgs $LCTL pool_add $FSNAME.$POOL \
		$FSNAME-OST[$TGTPOOL_FIRST-$TGTPOOL_MAX/$TGTPOOL_STEP]
	wait_update $HOSTNAME "lctl get_param -n lov.$FSNAME-*.pools.$POOL | sort -u | tr '\n' ' ' " "$TGT" ||
		error "Add to pool failed"
	local lfscount=$($LFS pool_list $FSNAME.$POOL | grep -c "\-OST")
	local addcount=$((($TGTPOOL_MAX - $TGTPOOL_FIRST) / $TGTPOOL_STEP + 1))
	[ $lfscount -eq $addcount ] ||
		error "lfs pool_list bad ost count $lfscount != $addcount"
}
run_test 200b "Add targets to a pool ===================================="

test_200c() {
	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	mkdir -p $POOL_DIR
	$SETSTRIPE -c 2 -p $POOL $POOL_DIR
	[ $? = 0 ] || error "Cannot set pool $POOL to $POOL_DIR"
	# b-19919 test relative path works well
	mkdir -p $POOL_DIR/$POOL_DIR_NAME
	cd $POOL_DIR
	$SETSTRIPE -c 2 -p $POOL $POOL_DIR_NAME
	[ $? = 0 ] || error "Cannot set pool $POOL to $POOL_DIR/$POOL_DIR_NAME"
	$SETSTRIPE -c 2 -p $POOL ./$POOL_DIR_NAME
	[ $? = 0 ] || error "Cannot set pool $POOL to $POOL_DIR/./$POOL_DIR_NAME"
	$SETSTRIPE -c 2 -p $POOL ../$POOL_DIR_NAME
	[ $? = 0 ] || error "Cannot set pool $POOL to $POOL_DIR/../$POOL_DIR_NAME"
	$SETSTRIPE -c 2 -p $POOL ../$POOL_DIR_NAME/$POOL_DIR_NAME
	[ $? = 0 ] || error "Cannot set pool $POOL to $POOL_DIR/../$POOL_DIR_NAME/$POOL_DIR_NAME"
	rm -rf $POOL_DIR_NAME; cd -
}
run_test 200c "Set pool on a directory ================================="

test_200d() {
	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	res=$($GETSTRIPE --pool $POOL_DIR)
	[ $res = $POOL ] || error "Pool on $POOL_DIR is $res, not $POOL"
}
run_test 200d "Check pool on a directory ==============================="

test_200e() {
	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	failed=0
	for i in $(seq -w 1 $(($TGT_COUNT * 3)))
	do
		file=$POOL_DIR/file-$i
		touch $file
		check_file_in_pool $file
		if [[ $? != 0 ]]
		then
			failed=$(($failed + 1))
		fi
	done
	[ "$failed" = 0 ] || error "$failed files not allocated in $POOL"
}
run_test 200e "Check files allocation from directory pool =============="

test_200f() {
	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	mkdir -p $POOL_FILE
	failed=0
	for i in $(seq -w 1 $(($TGT_COUNT * 3)))
	do
		file=$POOL_FILE/spoo-$i
		$SETSTRIPE -p $POOL $file
		check_file_in_pool $file
		if [[ $? != 0 ]]
		then
			failed=$(($failed + 1))
		fi
	done
	[ "$failed" = 0 ] || error "$failed files not allocated in $POOL"
}
run_test 200f "Create files in a pool ==================================="

test_200g() {
	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	TGT=$($LCTL get_param -n lov.$FSNAME-clilov-*.pools.$POOL | tr '\n' ' ')
	res=$($LFS df --pool $FSNAME.$POOL | awk '{print $1}' | grep "$FSNAME-OST" | tr '\n' ' ')
	[ "$res" = "$TGT" ] || error "Pools OSTs '$TGT' is not '$res' that lfs df reports"
}
run_test 200g "lfs df a pool ============================================"

test_200h() { # b=24039
	mkdir -p $POOL_DIR || error "unable to create $POOL_DIR"

	local file="/..$POOL_DIR/$tfile-1"
	$SETSTRIPE -p $POOL $file || error "unable to create $file"

	cd $POOL_DIR
	$SETSTRIPE -p $POOL $tfile-2 || \
		error "unable to create $tfile-2 in $POOL_DIR"
}
run_test 200h "Create files in a pool with relative pathname ============"

test_201a() {
	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	TGT=$($LCTL get_param -n lov.$FSNAME-*.pools.$POOL | head -1)
	do_facet mgs $LCTL pool_remove $FSNAME.$POOL $TGT
	wait_update $HOSTNAME "lctl get_param -n lov.$FSNAME-*.pools.$POOL | grep $TGT" "" ||
		error "$TGT not removed from $FSNAME.$POOL"
}
run_test 201a "Remove a target from a pool ============================="

test_201b() {
	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	for TGT in $($LCTL get_param -n lov.$FSNAME-*.pools.$POOL | sort -u)
	do
		do_facet mgs $LCTL pool_remove $FSNAME.$POOL $TGT
 	done
	wait_update $HOSTNAME "lctl get_param -n lov.$FSNAME-*.pools.$POOL" "" ||
		error "Pool $FSNAME.$POOL cannot be drained"
	# striping on an empty/nonexistant pool should fall back to "pool of everything"
	touch ${POOL_DIR}/$tfile || error "failed to use fallback striping for empty pool"
	# setstripe on an empty pool should fail
	$SETSTRIPE -p $POOL ${POOL_FILE}/$tfile 2>/dev/null && \
		error "expected failure when creating file with empty pool"
	return 0
}
run_test 201b "Remove all targets from a pool =========================="

test_201c() {
	remote_mgs_nodsh && skip "remote MGS with nodsh" && return
	do_facet mgs $LCTL pool_destroy $FSNAME.$POOL

	sleep 2
    # striping on an empty/nonexistant pool should fall back to "pool of everything"
	touch ${POOL_DIR}/$tfile || error "failed to use fallback striping for missing pool"
	# setstripe on an empty pool should fail
	$SETSTRIPE -p $POOL ${POOL_FILE}/$tfile 2>/dev/null && \
		error "expected failure when creating file with missing pool"

	# get param should return err once pool is gone
	if wait_update $HOSTNAME "lctl get_param -n lov.$FSNAME-*.pools.$POOL 2>/dev/null ||
			echo foo" "foo"; then
		remove_pool_from_list $FSNAME.$POOL
		return 0
	fi
	error "Pool $FSNAME.$POOL is not destroyed"
}
run_test 201c "Remove a pool ============================================"

cleanup_pools $FSNAME

# usage: default_attr <count | size | offset>
default_attr() {
	$LCTL get_param -n lov.$FSNAME-clilov-\*.stripe${1}
}

# usage: trim <string>
# Trims leading and trailing whitespace from the parameter string
trim() {
    echo $@
}

# usage: check_default_stripe_attr <count | size | offset>
check_default_stripe_attr() {
	# $GETSTRIPE returns trailing whitespace which needs to be trimmed off
	ACTUAL=$(trim $($GETSTRIPE --$1 $DIR/$tdir))
	if [ $1 = "count" -o $1 = "size" ]; then
		EXPECTED=`default_attr $1`;
	else
		# the 'stripeoffset' parameter prints as an unsigned int, so
		# until this is fixed we hard-code -1 here
		EXPECTED=-1;
	fi
	[ "x$ACTUAL" != "x$EXPECTED" ] &&
		error "$DIR/$tdir has stripe $1 '$ACTUAL', not '$EXPECTED'"
}

# usage: check_raw_stripe_attr <count | size | offset>
check_raw_stripe_attr() {
	# $GETSTRIPE returns trailing whitespace which needs to be trimmed off
	ACTUAL=$(trim $($GETSTRIPE --raw --$1 $DIR/$tdir))
	if [ $1 = "count" -o $1 = "size" ]; then
		EXPECTED=0;
	else
		EXPECTED=-1;
	fi
	[ "x$ACTUAL" != "x$EXPECTED" ] &&
		error "$DIR/$tdir has raw stripe $1 '$ACTUAL', not '$EXPECTED'"
}


test_204a() {
	mkdir -p $DIR/$tdir
	$SETSTRIPE --count 0 --size 0 --offset -1 $DIR/$tdir

	check_default_stripe_attr count
	check_default_stripe_attr size
	check_default_stripe_attr offset

	return 0
}
run_test 204a "Print default stripe attributes ================="

test_204b() {
	mkdir -p $DIR/$tdir
	$SETSTRIPE --count 1 $DIR/$tdir

	check_default_stripe_attr size
	check_default_stripe_attr offset

	return 0
}
run_test 204b "Print default stripe size and offset  ==========="

test_204c() {
	mkdir -p $DIR/$tdir
	$SETSTRIPE --size 65536 $DIR/$tdir

	check_default_stripe_attr count
	check_default_stripe_attr offset

	return 0
}
run_test 204c "Print default stripe count and offset ==========="

test_204d() {
	mkdir -p $DIR/$tdir
	$SETSTRIPE --offset 0 $DIR/$tdir

	check_default_stripe_attr count
	check_default_stripe_attr size

	return 0
}
run_test 204d "Print default stripe count and size ============="

test_204e() {
	mkdir -p $DIR/$tdir
	$SETSTRIPE -d $DIR/$tdir

	check_raw_stripe_attr count
	check_raw_stripe_attr size
	check_raw_stripe_attr offset

	return 0
}
run_test 204e "Print raw stripe attributes ================="

test_204f() {
	mkdir -p $DIR/$tdir
	$SETSTRIPE --count 1 $DIR/$tdir

	check_raw_stripe_attr size
	check_raw_stripe_attr offset

	return 0
}
run_test 204f "Print raw stripe size and offset  ==========="

test_204g() {
	mkdir -p $DIR/$tdir
	$SETSTRIPE --size 65536 $DIR/$tdir

	check_raw_stripe_attr count
	check_raw_stripe_attr offset

	return 0
}
run_test 204g "Print raw stripe count and offset ==========="

test_204h() {
	mkdir -p $DIR/$tdir
	$SETSTRIPE --offset 0 $DIR/$tdir

	check_raw_stripe_attr count
	check_raw_stripe_attr size

	return 0
}
run_test 204h "Print raw stripe count and size ============="

test_212() {
	size=`date +%s`
	size=$((size % 8192 + 1))
	dd if=/dev/urandom of=$DIR/f212 bs=1k count=$size
	sendfile $DIR/f212 $DIR/f212.xyz || error "sendfile wrong"
	rm -f $DIR/f212 $DIR/f212.xyz
}
run_test 212 "Sendfile test ============================================"

test_213() {
	dd if=/dev/zero of=$DIR/$tfile bs=4k count=4
	cancel_lru_locks osc
	lctl set_param fail_loc=0x8000040f
	# generate a read lock
	cat $DIR/$tfile > /dev/null
	# write to the file, it will try to cancel the above read lock.
	cat /etc/hosts >> $DIR/$tfile
}
run_test 213 "OSC lock completion and cancel race don't crash - bug 18829"

test_214() { # for bug 20133
	mkdir -p $DIR/d214p/d214c
	for (( i=0; i < 340; i++ )) ; do
		touch $DIR/d214p/d214c/a$i
	done

	ls -l $DIR/d214p || error "ls -l $DIR/d214p failed"
	mv $DIR/d214p/d214c $DIR/ || error "mv $DIR/d214p/d214c $DIR/ failed"
	ls $DIR/d214c || error "ls $DIR/d214c failed"
	rm -rf $DIR/d214* || error "rm -rf $DIR/d214* failed"
}
run_test 214 "hash-indexed directory test - bug 20133"

# having "abc" as 1st arg, creates $TMP/lnet_abc.out and $TMP/lnet_abc.sys
create_lnet_proc_files() {
	cat /proc/sys/lnet/$1 >$TMP/lnet_$1.out || error "cannot read /proc/sys/lnet/$1"
	sysctl lnet.$1 >$TMP/lnet_$1.sys_tmp || error "cannot read lnet.$1"

	sed "s/^lnet.$1\ =\ //g" "$TMP/lnet_$1.sys_tmp" >$TMP/lnet_$1.sys
	rm -f "$TMP/lnet_$1.sys_tmp"
}

# counterpart of create_lnet_proc_files
remove_lnet_proc_files() {
	rm -f $TMP/lnet_$1.out $TMP/lnet_$1.sys
}

# uses 1st arg as trailing part of filename, 2nd arg as description for reports,
# 3rd arg as regexp for body
check_lnet_proc_stats() {
	local l=$(cat "$TMP/lnet_$1" |wc -l)
	[ $l = 1 ] || (cat "$TMP/lnet_$1" && error "$2 is not of 1 line: $l")

	grep -E "$3" "$TMP/lnet_$1" || (cat "$TMP/lnet_$1" && error "$2 misformatted")
}

# uses 1st arg as trailing part of filename, 2nd arg as description for reports,
# 3rd arg as regexp for body, 4th arg as regexp for 1st line, 5th arg is
# optional and can be regexp for 2nd line (lnet.routes case)
check_lnet_proc_entry() {
	local blp=2            # blp stands for 'position of 1st line of body'
	[ "$5" = "" ] || blp=3 # lnet.routes case

	local l=$(cat "$TMP/lnet_$1" |wc -l)
	# subtracting one from $blp because the body can be empty
	[ "$l" -ge "$(($blp - 1))" ] || (cat "$TMP/lnet_$1" && error "$2 is too short: $l")

	sed -n '1 p' "$TMP/lnet_$1" |grep -E "$4" >/dev/null ||
		(cat "$TMP/lnet_$1" && error "1st line of $2 misformatted")

	[ "$5" = "" ] || sed -n '2 p' "$TMP/lnet_$1" |grep -E "$5" >/dev/null ||
		(cat "$TMP/lnet_$1" && error "2nd line of $2 misformatted")

	# bail out if any unexpected line happened
	sed -n "$blp~1 p" "$TMP/lnet_$1" |grep -Ev "$3"
	[ "$?" != 0 ] || error "$2 misformatted"
}

test_215() { # for bugs 18102, 21079, 21517
	local N='(0|[1-9][0-9]*)'   # non-negative numeric
	local P='[1-9][0-9]*'       # positive numeric
	local I='(0|-?[1-9][0-9]*)' # any numeric (0 | >0 | <0)
	local NET='[a-z][a-z0-9]*'  # LNET net like o2ib2
	local ADDR='[0-9.]+'        # LNET addr like 10.0.0.1
	local NID="$ADDR@$NET"      # LNET nid like 10.0.0.1@o2ib2

	local L1 # regexp for 1st line
	local L2 # regexp for 2nd line (optional)
	local BR # regexp for the rest (body)

	# /proc/sys/lnet/stats should look as 11 space-separated non-negative numerics
	BR="^$N $N $N $N $N $N $N $N $N $N $N$"
	create_lnet_proc_files "stats"
	check_lnet_proc_stats "stats.out" "/proc/sys/lnet/stats" "$BR"
	check_lnet_proc_stats "stats.sys" "lnet.stats" "$BR"
	remove_lnet_proc_files "stats"

	# /proc/sys/lnet/routes should look like this:
	# Routing disabled/enabled
	# net hops state router
	# where net is a string like tcp0, hops >= 0, state is up/down,
	# router is a string like 192.168.1.1@tcp2
	L1="^Routing (disabled|enabled)$"
	L2="^net +hops +state +router$"
	BR="^$NET +$N +(up|down) +$NID$"
	create_lnet_proc_files "routes"
	check_lnet_proc_entry "routes.out" "/proc/sys/lnet/routes" "$BR" "$L1" "$L2"
	check_lnet_proc_entry "routes.sys" "lnet.routes" "$BR" "$L1" "$L2"
	remove_lnet_proc_files "routes"

	# /proc/sys/lnet/routers should look like this:
	# ref rtr_ref alive_cnt state last_ping ping_sent deadline down_ni router
	# where ref > 0, rtr_ref > 0, alive_cnt >= 0, state is up/down,
	# last_ping >= 0, ping_sent is boolean (0/1), deadline and down_ni are
	# numeric (0 or >0 or <0), router is a string like 192.168.1.1@tcp2
	L1="^ref +rtr_ref +alive_cnt +state +last_ping +ping_sent +deadline +down_ni +router$"
	BR="^$P +$P +$N +(up|down) +$N +(0|1) +$I +$I +$NID$"
	create_lnet_proc_files "routers"
	check_lnet_proc_entry "routers.out" "/proc/sys/lnet/routers" "$BR" "$L1"
	check_lnet_proc_entry "routers.sys" "lnet.routers" "$BR" "$L1"
	remove_lnet_proc_files "routers"

	# /proc/sys/lnet/peers should look like this:
	# nid refs state last max rtr min tx min queue
	# where nid is a string like 192.168.1.1@tcp2, refs > 0,
	# state is up/down/NA, max >= 0. last, rtr, min, tx, min are
	# numeric (0 or >0 or <0), queue >= 0.
	L1="^nid +refs +state +last +max +rtr +min +tx +min +queue$"
	BR="^$NID +$P +(up|down|NA) +$I +$N +$I +$I +$I +$I +$N$"
	create_lnet_proc_files "peers"
	check_lnet_proc_entry "peers.out" "/proc/sys/lnet/peers" "$BR" "$L1"
	check_lnet_proc_entry "peers.sys" "lnet.peers" "$BR" "$L1"
	remove_lnet_proc_files "peers"

	# /proc/sys/lnet/buffers  should look like this:
	# pages count credits min
	# where pages >=0, count >=0, credits and min are numeric (0 or >0 or <0)
	L1="^pages +count +credits +min$"
	BR="^ +$N +$N +$I +$I$"
	create_lnet_proc_files "buffers"
	check_lnet_proc_entry "buffers.out" "/proc/sys/lnet/buffers" "$BR" "$L1"
	check_lnet_proc_entry "buffers.sys" "lnet.buffers" "$BR" "$L1"
	remove_lnet_proc_files "buffers"

	# /proc/sys/lnet/nis should look like this:
	# nid status alive refs peer rtr max tx min
	# where nid is a string like 192.168.1.1@tcp2, status is up/down,
	# alive is numeric (0 or >0 or <0), refs > 0, peer >= 0,
	# rtr >= 0, max >=0, tx and min are numeric (0 or >0 or <0).
	L1="^nid +status +alive +refs +peer +rtr +max +tx +min$"
	BR="^$NID +(up|down) +$I +$P +$N +$N +$N +$I +$I$"
	create_lnet_proc_files "nis"
	check_lnet_proc_entry "nis.out" "/proc/sys/lnet/nis" "$BR" "$L1"
	check_lnet_proc_entry "nis.sys" "lnet.nis" "$BR" "$L1"
	remove_lnet_proc_files "nis"

	# can we successfully write to /proc/sys/lnet/stats?
	echo "0" >/proc/sys/lnet/stats || error "cannot write to /proc/sys/lnet/stats"
	sysctl -w lnet.stats=0 || error "cannot write to lnet.stats"
}
run_test 215 "/proc/sys/lnet exists and has proper content - bugs 18102, 21079, 21517"

test_216() { # bug 20317
        local node
        local p="$TMP/sanityN-$TESTNAME.parameters"
        save_lustre_params $HOSTNAME "osc.*.contention_seconds" > $p
        for node in $(osts_nodes); do
                save_lustre_params $node "ldlm.namespaces.filter-*.max_nolock_bytes" >> $p
                save_lustre_params $node "ldlm.namespaces.filter-*.contended_locks" >> $p
                save_lustre_params $node "ldlm.namespaces.filter-*.contention_seconds" >> $p
        done
        clear_osc_stats

        # agressive lockless i/o settings
        for node in $(osts_nodes); do
                do_node $node 'lctl set_param -n ldlm.namespaces.filter-*.max_nolock_bytes 2000000; lctl set_param -n ldlm.namespaces.filter-*.contended_locks 0; lctl set_param -n ldlm.namespaces.filter-*.contention_seconds 60'
        done
        lctl set_param -n osc.*.contention_seconds 60

        $DIRECTIO write $DIR/$tfile 0 10 4096
        $CHECKSTAT -s 40960 $DIR/$tfile

        # disable lockless i/o
        for node in $(osts_nodes); do
                do_node $node 'lctl set_param -n ldlm.namespaces.filter-*.max_nolock_bytes 0; lctl set_param -n ldlm.namespaces.filter-*.contended_locks 32; lctl set_param -n ldlm.namespaces.filter-*.contention_seconds 0'
        done
        lctl set_param -n osc.*.contention_seconds 0
        clear_osc_stats

        dd if=/dev/zero of=$DIR/$tfile count=0
        $CHECKSTAT -s 0 $DIR/$tfile

        restore_lustre_params <$p
        rm -f $p
        rm $DIR/$tfile
}
run_test 216 "check lockless direct write works and updates file size and kms correctly"

test_217() { # bug 22430
	local node
	for node in $(nodes_list); do
		if [[ $node = *-* ]] ; then
			echo "lctl ping $node@$NETTYPE"
			lctl ping $node@$NETTYPE
		else
			echo "skipping $node (no hiphen detected)"
		fi
	done
}
run_test 217 "check lctl ping for hostnames with hiphen ('-')"

test_218() {
       # do directio so as not to populate the page cache
       log "creating a 10 Mb file"
       multiop $DIR/$tfile oO_CREAT:O_DIRECT:O_RDWR:w$((10*1048576))c || error "multiop failed while creating a file"
       log "starting reads"
       dd if=$DIR/$tfile of=/dev/null bs=4096 &
       log "truncating the file"
       multiop $DIR/$tfile oO_TRUNC:c || error "multiop failed while truncating the file"
       log "killing dd"
       kill %+ || true # reads might have finished
       echo "wait until dd is finished"
       wait
       log "removing the temporary file"
       rm -rf $DIR/$tfile || error "tmp file removal failed"
}
run_test 218 "parallel read and truncate should not deadlock ======================="

test_219() {
        # write one partial page
        dd if=/dev/zero of=$DIR/$tfile bs=1024 count=1
        # set no grant so vvp_io_commit_write will do sync write
        $LCTL set_param fail_loc=0x411
        # write a full page at the end of file
        dd if=/dev/zero of=$DIR/$tfile bs=4096 count=1 seek=1 conv=notrunc

        $LCTL set_param fail_loc=0
        dd if=/dev/zero of=$DIR/$tfile bs=4096 count=1 seek=3
        $LCTL set_param fail_loc=0x411
        dd if=/dev/zero of=$DIR/$tfile bs=1024 count=1 seek=2 conv=notrunc
}
run_test 219 "LU-394: Write partial won't cause uncontiguous pages vec at LND"

test_220() { #LU-325
	local OSTIDX=0

	mkdir -p $DIR/$tdir
	local OST=$(lfs osts | grep ${OSTIDX}": " | \
		awk '{print $2}' | sed -e 's/_UUID$//')

        # on the mdt's osc
	local mdtosc_proc1=$(get_mdtosc_proc_path $SINGLEMDS $OST)
	local last_id=$(do_facet $SINGLEMDS lctl get_param -n \
			osc.$mdtosc_proc1.prealloc_last_id)
	local next_id=$(do_facet $SINGLEMDS lctl get_param -n \
			osc.$mdtosc_proc1.prealloc_next_id)

	$LFS df -i

	do_facet mgs $LCTL pool_new $FSNAME.$TESTNAME || return 1
	do_facet mgs $LCTL pool_add $FSNAME.$TESTNAME $OST || return 2

	$SETSTRIPE $DIR/$tdir -i $OSTIDX -c 1 -p $FSNAME.$TESTNAME

	echo "preallocated objects in MDS is $((last_id - next_id))" \
             "($last_id - $next_id)"

	count=$($LFS df -i $MOUNT | grep ^$OST | awk '{print $4}')
	echo "OST still has $count objects"

	free=$((count + last_id - next_id))
	echo "create $((free - next_id)) files @next_id..."
	createmany -o $DIR/$tdir/f $next_id $free || return 3

	local last_id2=$(do_facet mds${MDSIDX} lctl get_param -n \
			osc.$mdtosc_proc1.prealloc_last_id)
	local next_id2=$(do_facet mds${MDSIDX} lctl get_param -n \
			osc.$mdtosc_proc1.prealloc_next_id)

	echo "after creation, last_id=$last_id2, next_id=$next_id2"
	$LFS df -i

	echo "cleanup..."

	do_facet mgs $LCTL pool_remove $FSNAME.$TESTNAME $OST || return 4
	do_facet mgs $LCTL pool_destroy $FSNAME.$TESTNAME || return 5
	echo "unlink $((free - next_id)) files @ $next_id..."
	unlinkmany $DIR/$tdir/f $next_id $free || return 3
}
run_test 220 "the preallocated objects in MDS still can be used if ENOSPC is returned by OST with enough disk space"

#
# tests that do cleanup/setup should be run at the end
#

test_900() {
        local ls
        #define OBD_FAIL_MGC_PAUSE_PROCESS_LOG   0x903
        $LCTL set_param fail_loc=0x903
        # cancel_lru_locks mgc - does not work due to lctl set_param syntax
        for ls in /proc/fs/lustre/ldlm/namespaces/MGC*/lru_size; do
                echo "clear" > $ls
        done
        FAIL_ON_ERROR=true cleanup
        FAIL_ON_ERROR=true setup
}
run_test 900 "umount should not race with any mgc requeue thread"

complete $(basename $0) $SECONDS
check_and_cleanup_lustre
if [ "$I_MOUNTED" != "yes" ]; then
	lctl set_param debug="$OLDDEBUG" 2> /dev/null || true
fi
exit_status
