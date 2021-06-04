#
# LDISKFS_LINUX_SERIES
#
AC_DEFUN([LDISKFS_LINUX_SERIES], [
AC_MSG_CHECKING([which ldiskfs series to use])
case x$LDISKFS_SERIES in
	x)			# not set
		;;
	*.series)		# set externally
		;;
	*) LDISKFS_SERIES=
esac
AS_IF([test -z "$LDISKFS_SERIES"], [
AS_IF([test x$RHEL_KERNEL = xyes], [
	case $RHEL_RELEASE_NO in
	84)     LDISKFS_SERIES="4.18-rhel8.4.series"    ;;
	83)     LDISKFS_SERIES="4.18-rhel8.3.series"    ;;
	82)     LDISKFS_SERIES="4.18-rhel8.2.series"    ;;
	81)     LDISKFS_SERIES="4.18-rhel8.1.series"    ;;
	80)     LDISKFS_SERIES="4.18-rhel8.series"      ;;
	79)	LDISKFS_SERIES="3.10-rhel7.9.series"	;;
	78)	LDISKFS_SERIES="3.10-rhel7.8.series"	;;
	77)	LDISKFS_SERIES="3.10-rhel7.7.series"	;;
	76)	LDISKFS_SERIES="3.10-rhel7.6.series"	;;
	esac
], [test x$SUSE_KERNEL = xyes], [
	AS_VERSION_COMPARE([$LINUXRELEASE],[5.3.18],[
	AS_VERSION_COMPARE([$LINUXRELEASE],[4.12.14],[], [], [
		suse_conf=$LINUX_OBJ/include/generated/uapi/linux/suse_version.h
		suse_vers=$(awk '[$]2 == "SUSE_VERSION" {print [$]3 }' $suse_conf)
		suse_patchlevel=$(awk '[$]2 == "SUSE_PATCHLEVEL" {print [$]3 }' $suse_conf)
		echo "$suse_conf $suse_vers $suse_patchlevel  ${suse_vers}sp$suse_patchlevel" >> /tmp/log-nb
		case ${suse_vers}sp$suse_patchlevel in # (
		15sp0 ) LDISKFS_SERIES="4.12-sles15.series"
			if test ! -f $LINUX/arch/x86/kernel/cpu/hygon.c ; then
				# This file was added shortly after -150.22 so
				# this must be 150.22 or earlier
				LDISKFS_SERIES="4.12-sles15-22.series"
			fi
			;; # (
		15sp1 ) LDISKFS_SERIES="4.12-sles15sp1.series"
			if test ! -f $LINUX/arch/x86/kernel/cpu/umwait.c ; then
				# This file was added after -197.7 so
				# this must be -197.7 or earlier
				LDISKFS_SERIES="4.12-sles15sp1-7.series"
			fi
			;;
		esac
	]
	)], [LDISKFS_SERIES="5.4.21-ml.series"],
	    [LDISKFS_SERIES="5.4.21-ml.series"])
], [test x$UBUNTU_KERNEL = xyes], [
	AS_VERSION_COMPARE([$LINUXRELEASE],[5.4.0],[
	AS_VERSION_COMPARE([$LINUXRELEASE],[5.0.0],[
	AS_VERSION_COMPARE([$LINUXRELEASE],[4.15.0],[
	AS_VERSION_COMPARE([$LINUXRELEASE],[4.4.0], [],
	[
		KPLEV=$(echo $LINUXRELEASE | sed -n 's/.*-\([0-9]\+\).*/\1/p')
		AS_IF(
			[test -z "$KPLEV"], [
				AC_MSG_WARN([Failed to determine Kernel patch level. Assume latest.])
				LDISKFS_SERIES="4.4.0-73-ubuntu14+16.series"
			],
			[test $KPLEV -ge 73], [LDISKFS_SERIES="4.4.0-73-ubuntu14+16.series"],
			[test $KPLEV -ge 62], [LDISKFS_SERIES="4.4.0-62-ubuntu14+16.series"],
			[test $KPLEV -ge 49], [LDISKFS_SERIES="4.4.0-49-ubuntu14+16.series"],
			[LDISKFS_SERIES="4.4.0-45-ubuntu14+16.series"]
		)
	],
	[LDISKFS_SERIES="4.4.0-73-ubuntu14+16.series"])],
	[
		KPLEV=$(echo $LINUXRELEASE | sed -n 's/.*-\([0-9]\+\).*/\1/p')
		AS_IF(
			[test -z "$KPLEV"], [
				AC_MSG_WARN([Failed to determine Kernel patch level. Assume latest.])
				LDISKFS_SERIES="4.15.0-24-ubuntu18.series"
			],
			[test $KPLEV -ge 24], [LDISKFS_SERIES="4.15.0-24-ubuntu18.series"],
			[test $KPLEV -ge 20], [LDISKFS_SERIES="4.15.0-20-ubuntu18.series"]
		)
	],
	[LDISKFS_SERIES="4.15.0-24-ubuntu18.series"])],
	[LDISKFS_SERIES="5.0.0-13-ubuntu19.series"],
	[LDISKFS_SERIES="5.0.0-13-ubuntu19.series"])],
	[LDISKFS_SERIES="5.4.0-42-ubuntu20.series"],
	[LDISKFS_SERIES="5.4.0-42-ubuntu20.series"],
	[LDISKFS_SERIES="5.4.0-ml.series"])
])
])
# Not RHEL/SLES or Ubuntu .. probably mainline
AS_IF([test -z "$LDISKFS_SERIES"],
	[
	AS_VERSION_COMPARE([$LINUXRELEASE],[5.4.0],[],
	[LDISKFS_SERIES="5.4.0-ml.series"],[
	AS_VERSION_COMPARE([$LINUXRELEASE],[5.4.21],
		[LDISKFS_SERIES="5.4.0-ml.series"],  # lt
		[LDISKFS_SERIES="5.4.21-ml.series"], # eq
		[LDISKFS_SERIES="5.4.21-ml.series"]  # gt
		)])
	],
[])
AS_IF([test -z "$LDISKFS_SERIES"],
	[AC_MSG_RESULT([failed to identify series])],
	[AC_MSG_RESULT([$LDISKFS_SERIES for $LINUXRELEASE])])
AC_SUBST(LDISKFS_SERIES)
]) # LDISKFS_LINUX_SERIES

#
# LB_EXT_FREE_BLOCKS_WITH_BUFFER_HEAD
#
# 2.6.32-rc7 ext4_free_blocks requires struct buffer_head
# Note that RHEL6 is pre 2.6.32-rc7 so this check is still needed.
#
AC_DEFUN([LB_EXT_FREE_BLOCKS_WITH_BUFFER_HEAD], [
LB_CHECK_COMPILE([if 'ext4_free_blocks' needs 'struct buffer_head'],
ext4_free_blocks_with_buffer_head, [
	#include <linux/fs.h>
	#include "$EXT4_SRC_DIR/ext4.h"
],[
	ext4_free_blocks(NULL, NULL, NULL, 0, 0, 0);
],[
	AC_DEFINE(HAVE_EXT_FREE_BLOCK_WITH_BUFFER_HEAD, 1,
		[ext4_free_blocks do not require struct buffer_head])
])
]) # LB_EXT_FREE_BLOCKS_WITH_BUFFER_HEAD

#
# LB_EXT4_JOURNAL_START_3ARGS
#
# 3.9 added a type argument to ext4_journal_start and friends
#
AC_DEFUN([LB_EXT4_JOURNAL_START_3ARGS], [
LB_CHECK_COMPILE([if ext4_journal_start takes 3 arguments],
ext4_journal_start, [
	#include <linux/fs.h>
	#include "$EXT4_SRC_DIR/ext4_jbd2.h"
],[
	ext4_journal_start(NULL, 0, 0);
],[
	AC_DEFINE(JOURNAL_START_HAS_3ARGS, 1, [ext4_journal_start takes 3 arguments])
])
]) # LB_EXT4_JOURNAL_START_3ARGS

#
# LB_EXT4_BREAD_4ARGS
#
# 3.18 ext4_bread has 4 arguments
# NOTE: It may not be exported for modules, use a positive compiler test here.
#
AC_DEFUN([LB_EXT4_BREAD_4ARGS], [
LB_CHECK_COMPILE([if ext4_bread takes 4 arguments],
ext4_bread, [
	#include <linux/fs.h>
	#include "$EXT4_SRC_DIR/ext4.h"

	struct buffer_head *ext4_bread(handle_t *handle, struct inode *inode,
				       ext4_lblk_t block, int map_flags)
	{
		struct buffer_head *bh = NULL;
		(void)handle;
		(void)inode;
		(void)block;
		(void)map_flags;
		return bh;
	}
],[
	ext4_bread(NULL, NULL, 0, 0);
],[
	AC_DEFINE(HAVE_EXT4_BREAD_4ARGS, 1, [ext4_bread takes 4 arguments])
])
]) # LB_EXT4_BREAD_4ARGS

#
# LB_EXT4_HAVE_INFO_DQUOT
#
# in linux 4.4 i_dqout is in ext4_inode_info, not in struct inode
#
AC_DEFUN([LB_EXT4_HAVE_INFO_DQUOT], [
LB_CHECK_COMPILE([if i_dquot is in ext4_inode_info],
ext4_info_dquot, [
	#include <linux/fs.h>
	#include <linux/quota.h>
	#include "$EXT4_SRC_DIR/ext4.h"
],[
	struct ext4_inode_info in;
	struct dquot *dq;

	dq = in.i_dquot[0];
],[
	AC_DEFINE(HAVE_EXT4_INFO_DQUOT, 1, [i_dquot is in ext4_inode_info])
])
]) # LB_EXT4_HAVE_INFO_DQUOT

#
# LB_EXT4_HAVE_I_CRYPT_INFO
#
# in linux 4.8 i_crypt_info moved from ext4_inode_info to struct inode
#
# Determine if we need to enable CONFIG_LDISKFS_FS_ENCRYPTION.
# If we have i_crypt_info in ext4_inode_info, the config option
# should be enabled to make the ldiskfs module compilation happy.
# Otherwise i_crypy_info is in struct inode, we need to check kernel
# config option to determine that.
#
AC_DEFUN([LB_EXT4_HAVE_I_CRYPT_INFO], [
LB_CHECK_COMPILE([if i_crypt_info is in ext4_inode_info],
ext4_i_crypt_info, [
	#define CONFIG_EXT4_FS_ENCRYPTION 1
	#include <linux/fs.h>
	#include "$EXT4_SRC_DIR/ext4.h"
],[
	struct ext4_inode_info in;

	in.i_crypt_info = NULL;
],[
	AC_DEFINE(
		CONFIG_LDISKFS_FS_ENCRYPTION, 1,
		[enable encryption for ldiskfs]
	)
],[
	LB_CHECK_CONFIG([EXT4_FS_ENCRYPTION],[
		AC_DEFINE(
			CONFIG_LDISKFS_FS_ENCRYPTION, 1,
			[enable encryption for ldiskfs]
		)
	])
])
]) # LB_EXT4_HAVE_I_CRYPT_INFO

#
# LB_LDISKFS_JOURNAL_ENSURE_CREDITS
#
# kernel 4.18.0-240.1.1.el8 and
# kernel 5.4 commit a413036791d040e33badcc634453a4d0c0705499
#
# ext4_journal_ensure_credits was introduced to ensure given handle
# has at least requested amount of credits available, and possibly
# restarting transaction if needed.
#
AC_DEFUN([LB_LDISKFS_JOURNAL_ENSURE_CREDITS], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'ext4_journal_ensure_credits' exists],
ext4_journal_ensure_credits, [
	#include "$EXT4_SRC_DIR/ext4_jbd2.h"
	int __ext4_journal_ensure_credits(handle_t *handle, int check_cred,
		int extend_cred, int revoke_cred) { return 0; }
],[
	ext4_journal_ensure_credits(NULL, 0, 0);
],[
	AC_DEFINE(HAVE_LDISKFS_JOURNAL_ENSURE_CREDITS, 1,
		['ext4_journal_ensure_credits' exists])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LB_LDISKFS_JOURNAL_ENSURE_CREDITS

#
# LB_LDISKFS_IGET_HAS_FLAGS_ARG
#
# kernel 4.19 commit 8a363970d1dc38c4ec4ad575c862f776f468d057
# ext4_iget changed to a macro with 3 args was function with 2 args
#
AC_DEFUN([LB_LDISKFS_IGET_HAS_FLAGS_ARG], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if ldiskfs_iget takes a flags argument],
ext4_iget_3args, [
	#include <linux/fs.h>
	#include "$EXT4_SRC_DIR/ext4.h"
],[
	int f = EXT4_IGET_SPECIAL;
	(void)f;
],[
	AC_DEFINE(HAVE_LDISKFS_IGET_WITH_FLAGS, 1,
		[if ldiskfs_iget takes a flags argument])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LB_LDISKFS_IGET_HAS_FLAGS_ARG

#
# LDISKFS_AC_PATCH_PROGRAM
#
# Determine which program should be used to apply the patches to
# the ext4 source code to produce the ldiskfs source code.
#
AC_DEFUN([LDISKFS_AC_PATCH_PROGRAM], [
	AC_ARG_ENABLE([quilt],
		[AC_HELP_STRING([--disable-quilt],
			[disable use of quilt for ldiskfs])],
		[AS_IF([test "x$enableval" = xno],
			[use_quilt=no],
			[use_quilt=maybe])],
		[use_quilt=maybe]
	)

	AS_IF([test x$use_quilt = xmaybe], [
		AC_PATH_PROG([quilt_avail], [quilt], [no])
		AS_IF([test x$quilt_avail = xno], [
			use_quilt=no
		], [
			use_quilt=yes
		])
	])

	AS_IF([test x$use_quilt = xno], [
		AC_PATH_PROG([patch_avail], [patch], [no])
		AS_IF([test x$patch_avail = xno], [
			AC_MSG_ERROR([*** Need "quilt" or "patch" command])
		])
	])
]) # LDISKFS_AC_PATCH_PROGRAM

#
# LB_LDISKFS_FIND_ENTRY_LOCKED_EXISTS
#
# kernel 5.2 commit 8a363970d1dc38c4ec4ad575c862f776f468d057
# ext4: avoid declaring fs inconsistent due to invalid file handles
# __ext4_find_entry became a helper function for ext4_find_entry
# conflicting with previous ldiskfs patches.
# ldiskfs patches map ext4_find_entry to ldiskfs_find_entry_locked to
# avoid conflicting with __ext4_find_entry
#
# When the following check succeeds __ext4_find_entry helper is not
# used.
#
AC_DEFUN([LB_LDISKFS_FIND_ENTRY_LOCKED_EXISTS], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if __ldiskfs_find_entry is available],
ldiskfs_find_entry_locked, [
	#include <linux/fs.h>
	#include "$EXT4_SRC_DIR/ext4.h"
	#include "$EXT4_SRC_DIR/namei.c"

	static int __ext4_find_entry(void) { return 0; }
],[
	int x = __ext4_find_entry();
	(void)x;
],[
	AC_DEFINE(HAVE___LDISKFS_FIND_ENTRY, 1,
		[if __ldiskfs_find_entry is available])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LB_LDISKFS_FIND_ENTRY_LOCKED_EXISTS

#
# LB_LDISKFSFS_DIRHASH_WANTS_DIR
#
# kernel 5.2 commit 8a363970d1dc38c4ec4ad575c862f776f468d057
# ext4fs_dirhash UNICODE support
#
AC_DEFUN([LB_LDISKFSFS_DIRHASH_WANTS_DIR], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if ldiskfsfs_dirhash takes an inode argument],
ext4fs_dirhash, [
	#include <linux/fs.h>
	#include "$EXT4_SRC_DIR/ext4.h"

	int ext4fs_dirhash(const struct inode *dir, const char *name, int len,
			  struct dx_hash_info *hinfo)
	{
		(void)dir;
		(void)name;
		(void)len;
		(void)hinfo;
		return 0;
	}
],[
	int f = ext4fs_dirhash(NULL, NULL, 0, NULL);
	(void)f;
],[
	AC_DEFINE(HAVE_LDISKFSFS_GETHASH_INODE_ARG, 1,
		[ldiskfsfs_dirhash takes an inode argument])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LB_LDISKFSFS_DIRHASH_WANTS_DIR

#
# LB_JBD2_H_TOTAL_CREDITS
#
# kernel 5.5 commit 933f1c1e0b75bbc29730eef07c9e196c6dfd37e5
# jbd2: Reserve space for revoke descriptor blocks
#
AC_DEFUN([LB_JBD2_H_TOTAL_CREDITS], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if struct jbd2_journal_handle has h_total_credits member],
handle_t_h_revoke_credits, [
	#include <linux/jbd2.h>
],[
	int x = offsetof(struct jbd2_journal_handle, h_total_credits);
	(void)x;
],[
	AC_DEFINE(HAVE_JOURNAL_TOTAL_CREDITS, 1,
		[struct jbd2_journal_handle has h_total_credits member])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LB_JBD2_H_TOTAL_CREDITS

#
# LB_CONFIG_LDISKFS
#
AC_DEFUN([LB_CONFIG_LDISKFS], [
# --with-ldiskfs is deprecated now that ldiskfs is fully merged with lustre.
# However we continue to support this option through Lustre 2.5.
AC_ARG_WITH([ldiskfs],
	[],
	[AC_MSG_WARN([--with-ldiskfs is deprecated, please use --enable-ldiskfs])
	AS_IF([test x$withval != xyes -a x$withval != xno],
		[AC_MSG_ERROR([

The ldiskfs option is deprecated,
and no longer supports paths to external ldiskfs source
])])
])

AC_ARG_ENABLE([ldiskfs],
	[AS_HELP_STRING([--disable-ldiskfs],
		[disable ldiskfs osd (default is enable)])],
	[AS_IF([test x$enable_ldiskfs != xyes -a x$enable_ldiskfs != xno],
		[AC_MSG_ERROR([ldiskfs valid options are "yes" or "no"])])],
	[AS_IF([test "${with_ldiskfs+set}" = set],
		[enable_ldiskfs=$with_ldiskfs],
		[enable_ldiskfs=maybe])
])

AS_IF([test x$enable_server = xno],
	[AS_CASE([$enable_ldiskfs],
		[maybe], [enable_ldiskfs=no],
		[yes], [AC_MSG_ERROR([cannot build ldiskfs when servers are disabled])]
	)])

AS_IF([test x$enable_ldiskfs != xno],[
	# In the future, we chould change enable_ldiskfs from maybe to
	# either yes or no based on additional tests, e.g.  whether a patch
	# set is available for the detected kernel.  For now, we just always
	# set it to "yes".
	AS_IF([test x$enable_ldiskfs = xmaybe], [enable_ldiskfs=yes])
	AC_SUBST(ENABLE_LDISKFS, yes)

	LDISKFS_LINUX_SERIES
	LDISKFS_AC_PATCH_PROGRAM
	LB_EXT_FREE_BLOCKS_WITH_BUFFER_HEAD
	LB_EXT4_JOURNAL_START_3ARGS
	LB_EXT4_BREAD_4ARGS
	LB_EXT4_HAVE_INFO_DQUOT
	LB_EXT4_HAVE_I_CRYPT_INFO
	LB_LDISKFS_JOURNAL_ENSURE_CREDITS
	LB_LDISKFS_IGET_HAS_FLAGS_ARG
	LB_LDISKFS_FIND_ENTRY_LOCKED_EXISTS
	LB_LDISKFSFS_DIRHASH_WANTS_DIR
	LB_JBD2_H_TOTAL_CREDITS
	AC_DEFINE(CONFIG_LDISKFS_FS_POSIX_ACL, 1, [posix acls for ldiskfs])
	AC_DEFINE(CONFIG_LDISKFS_FS_SECURITY, 1, [fs security for ldiskfs])
	AC_DEFINE(CONFIG_LDISKFS_FS_XATTR, 1, [extened attributes for ldiskfs])
	AC_DEFINE(CONFIG_LDISKFS_FS_RW, 1, [enable rw access for ldiskfs])
	AC_SUBST(LDISKFS_SUBDIR, ldiskfs)
	AC_DEFINE(HAVE_LDISKFS_OSD, 1, Enable ldiskfs osd)
], [
	AC_SUBST(ENABLE_LDISKFS, no)
])

AC_MSG_CHECKING([whether to build ldiskfs])
AC_MSG_RESULT([$enable_ldiskfs])

AM_CONDITIONAL([LDISKFS_ENABLED], [test x$enable_ldiskfs = xyes])
]) # LB_CONFIG_LDISKFS


AC_DEFUN([LB_EXT4_SRC_DIR_SRC], [])
AC_DEFUN([LB_EXT4_SRC_DIR_RESULTS], [])

#
# LB_VALIDATE_EXT4_SRC_DIR
#
# Spot check the existence of several source files common to ext4.
# Detecting this at configure time allows us to avoid a potential build
# failure and provide a useful error message to explain what is wrong.
#
AC_DEFUN([LB_VALIDATE_EXT4_SRC_DIR], [
enable_ldiskfs_build="no"
AS_IF([test -n "$EXT4_SRC_DIR"], [
	enable_ldiskfs_build="yes"
	LB_CHECK_FILE([$EXT4_SRC_DIR/dir.c], [], [
		enable_ldiskfs_build="no"
		AC_MSG_WARN([ext4 must exist for ldiskfs build])
	])
	LB_CHECK_FILE([$EXT4_SRC_DIR/file.c], [], [
		enable_ldiskfs_build="no"
		AC_MSG_WARN([ext4 must exist for ldiskfs build])
	])
	LB_CHECK_FILE([$EXT4_SRC_DIR/inode.c], [], [
		enable_ldiskfs_build="no"
		AC_MSG_WARN([ext4 must exist for ldiskfs build])
	])
	LB_CHECK_FILE([$EXT4_SRC_DIR/super.c], [], [
		enable_ldiskfs_build="no"
		AC_MSG_WARN([ext4 must exist for ldiskfs build])
	])
])

AS_IF([test "x$enable_ldiskfs_build" = xno], [
	enable_ldiskfs="no"

	AC_MSG_WARN([

Disabling ldiskfs support because complete ext4 source does not exist.

If you are building using kernel-devel packages and require ldiskfs
server support then ensure that the matching kernel-debuginfo-common
and kernel-debuginfo-common-<arch> packages are installed.
])
])
]) # LB_VALIDATE_EXT4_SRC_DIR

#
# LB_EXT4_SRC_DIR
#
# Determine the location of the ext4 source code.  It it required
# for several configure tests and to build ldiskfs.
#
AC_DEFUN([LB_EXT4_SRC_DIR], [
AC_MSG_CHECKING([ext4 source directory])
# Kernel ext source located with devel headers
linux_src=$LINUX
AS_IF([test -e "$linux_src/fs/ext4/super.c"], [
	EXT4_SRC_DIR="$linux_src/fs/ext4"
], [
	# Kernel ext source provided by kernel-debuginfo-common package
	# that extracted to $LINUX
	linux_src=$(ls -1d $linux_src/../../debug/*/linux-${LINUXRELEASE%.*}* \
		2>/dev/null | tail -1)
	AS_IF([test -e "$linux_src/fs/ext4/super.c"], [
		EXT4_SRC_DIR="$linux_src/fs/ext4"
	], [
		# Kernel ext source provided by kernel-debuginfo-common package
		linux_src=$(ls -1d /usr/src/debug/*/linux-${LINUXRELEASE%.*}* \
			2>/dev/null | tail -1)
		AS_IF([test -e "$linux_src/fs/ext4/super.c"], [
			EXT4_SRC_DIR="$linux_src/fs/ext4"
		], [
			EXT4_SRC_DIR=""
		])
	])
])
AC_MSG_RESULT([$EXT4_SRC_DIR])
AC_SUBST(EXT4_SRC_DIR)

LB_VALIDATE_EXT4_SRC_DIR
]) # LB_EXT4_SRC_DIR

#
# LB_DEFINE_E2FSPROGS_NAMES
#
# Enable the use of alternate naming of ldiskfs-enabled e2fsprogs package.
#
AC_DEFUN([LB_DEFINE_E2FSPROGS_NAMES], [
AC_MSG_CHECKING([whether to use alternate names for e2fsprogs])
AC_ARG_WITH([ldiskfsprogs],
	AC_HELP_STRING([--with-ldiskfsprogs],
		[use alternate names for ldiskfs-enabled e2fsprogs]),
	[], [withval="no"])

AS_IF([test "x$withval" = xyes], [
	AC_MSG_RESULT([enabled])
	AC_DEFINE(HAVE_LDISKFSPROGS, 1, [enable use of ldiskfsprogs package])
	E2FSPROGS="ldiskfsprogs"
	MKE2FS="mkfs.ldiskfs"
	DEBUGFS="debugfs.ldiskfs"
	TUNE2FS="tunefs.ldiskfs"
	E2LABEL="label.ldiskfs"
	DUMPE2FS="dumpfs.ldiskfs"
	E2FSCK="fsck.ldiskfs"
	PFSCK="pfsck.ldiskfs"
], [
	AC_MSG_RESULT([disabled])
	E2FSPROGS="e2fsprogs"
	MKE2FS="mke2fs"
	DEBUGFS="debugfs"
	TUNE2FS="tune2fs"
	E2LABEL="e2label"
	DUMPE2FS="dumpe2fs"
	E2FSCK="e2fsck"
	PFSCK="fsck"
])

AC_DEFINE_UNQUOTED(E2FSPROGS, "$E2FSPROGS", [name of ldiskfs e2fsprogs package])
AC_DEFINE_UNQUOTED(MKE2FS, "$MKE2FS", [name of ldiskfs mkfs program])
AC_DEFINE_UNQUOTED(DEBUGFS, "$DEBUGFS", [name of ldiskfs debug program])
AC_DEFINE_UNQUOTED(TUNE2FS, "$TUNE2FS", [name of ldiskfs tune program])
AC_DEFINE_UNQUOTED(E2LABEL, "$E2LABEL", [name of ldiskfs label program])
AC_DEFINE_UNQUOTED(DUMPE2FS,"$DUMPE2FS", [name of ldiskfs dump program])
AC_DEFINE_UNQUOTED(E2FSCK, "$E2FSCK", [name of ldiskfs fsck program])
AC_DEFINE_UNQUOTED(PFSCK, "$PFSCK", [name of parallel fsck program])

AC_SUBST([E2FSPROGS], [$E2FSPROGS])
AC_SUBST([MKE2FS], [$MKE2FS])
AC_SUBST([DEBUGFS], [$DEBUGFS])
AC_SUBST([TUNE2FS], [$TUNE2FS])
AC_SUBST([E2LABEL], [$E2LABEL])
AC_SUBST([DUMPE2FS], [$DUMPE2FS])
AC_SUBST([E2FSCK], [$E2FSCK])
AC_SUBST([PFSCK], [$PFSCK])
]) # LB_DEFINE_E2FSPROGS_NAMES
