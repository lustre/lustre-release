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
	75)	LDISKFS_SERIES="3.10-rhel7.5.series"	;;
	74)	LDISKFS_SERIES="3.10-rhel7.4.series"	;;
	73)	LDISKFS_SERIES="3.10-rhel7.3.series"	;;
	72)	LDISKFS_SERIES="3.10-rhel7.2.series"	;;
	71)	LDISKFS_SERIES="3.10-rhel7.series"	;;
	69)	LDISKFS_SERIES="2.6-rhel6.9.series"	;;
	68)	LDISKFS_SERIES="2.6-rhel6.8.series"	;;
	67)	LDISKFS_SERIES="2.6-rhel6.7.series"	;;
	66)	LDISKFS_SERIES="2.6-rhel6.6.series"	;;
	65)	LDISKFS_SERIES="2.6-rhel6.5.series"	;;
	64)	LDISKFS_SERIES="2.6-rhel6.4.series"	;;
	6[0-3])	LDISKFS_SERIES="2.6-rhel6.series"	;;
	esac
], [test x$SUSE_KERNEL = xyes], [
	AS_VERSION_COMPARE([$LINUXRELEASE],[4.4.82],[
	AS_VERSION_COMPARE([$LINUXRELEASE],[4.4.0],[
	AS_VERSION_COMPARE([$LINUXRELEASE],[3.12.0],[
	AS_VERSION_COMPARE([$LINUXRELEASE],[3.0.0],[
	AS_VERSION_COMPARE([$LINUXRELEASE],[2.6.32], [],
	[LDISKFS_SERIES="2.6-sles11.series"],[LDISKFS_SERIES="2.6-sles11.series"])],
	[LDISKFS_SERIES="3.0-sles11.series"],[
		PLEV=$(grep PATCHLEVEL /etc/SuSE-release | sed -e 's/.*= *//')
		case $PLEV in
		2) LDISKFS_SERIES="3.0-sles11.series"
			;;
		3) LDISKFS_SERIES="3.0-sles11sp3.series"
			;;
		4) LDISKFS_SERIES="3.0-sles11sp4.series"
			;;
		esac
	])],[LDISKFS_SERIES="3.12-sles12.series"],[
		PLEV=$(grep PATCHLEVEL /etc/SuSE-release | sed -e 's/.*= *//')
		case $PLEV in
		1) LDISKFS_SERIES="3.12-sles12sp1.series"
			;;
		*) LDISKFS_SERIES="3.12-sles12.series"
			;;
		esac
	])],[LDISKFS_SERIES="4.4-sles12sp2.series"],
	    [LDISKFS_SERIES="4.4-sles12sp2.series"]
	)], [LDISKFS_SERIES="4.4-sles12sp3.series"],
            [LDISKFS_SERIES="4.4-sles12sp3.series"])
], [test x$UBUNTU_KERNEL = xyes], [
	AS_VERSION_COMPARE([$LINUXRELEASE],[4.4.0],
		[],
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
		[LDISKFS_SERIES="4.4.0-73-ubuntu14+16.series"]
	)
])
])
AS_IF([test -z "$LDISKFS_SERIES"],
	[AC_MSG_RESULT([failed to identify series])],
	[AC_MSG_RESULT([$LDISKFS_SERIES])])
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
# LB_EXT_PBLOCK
#
# 2.6.35 renamed ext_pblock to ext4_ext_pblock(ex)
#
AC_DEFUN([LB_EXT_PBLOCK], [
LB_CHECK_COMPILE([if Linux kernel has 'ext_pblock'],
ext_pblock, [
	#include <linux/fs.h>
	#include "$EXT4_SRC_DIR/ext4_extents.h"
],[
	ext_pblock(NULL);
],[
	AC_DEFINE(HAVE_EXT_PBLOCK, 1, [Linux kernel has ext_pblock])
])
]) # LB_EXT_PBLOCK

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
# LB_LDISKFS_MAP_BLOCKS
#
# Since 2.6.35 brought ext4_map_blocks() for IO.
# We just check this function whether existed.
# it must be exported by ldiskfs patches.
#
AC_DEFUN([LB_LDISKFS_MAP_BLOCKS], [
LB_CHECK_COMPILE([if kernel has ext4_map_blocks],
ext4_map_blocks, [
	#include <linux/fs.h>
	#include "$EXT4_SRC_DIR/ext4.h"
],[
	ext4_map_blocks(NULL, NULL, NULL, 0);
],[
	AC_DEFINE(HAVE_LDISKFS_MAP_BLOCKS, 1, [kernel has ext4_map_blocks])
])
])

#
# LB_EXT4_BREAD_4ARGS
#
# 3.18 ext4_bread has 4 arguments
#
AC_DEFUN([LB_EXT4_BREAD_4ARGS], [
LB_CHECK_COMPILE([if ext4_bread takes 4 arguments],
ext4_bread, [
	#include <linux/fs.h>
	#include "$EXT4_SRC_DIR/ext4.h"
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
	LB_EXT_PBLOCK
	LB_EXT4_JOURNAL_START_3ARGS
	LB_LDISKFS_MAP_BLOCKS
	LB_EXT4_BREAD_4ARGS
	LB_EXT4_HAVE_INFO_DQUOT
	AC_DEFINE(CONFIG_LDISKFS_FS_POSIX_ACL, 1, [posix acls for ldiskfs])
	AC_DEFINE(CONFIG_LDISKFS_FS_SECURITY, 1, [fs security for ldiskfs])
	AC_DEFINE(CONFIG_LDISKFS_FS_XATTR, 1, [extened attributes for ldiskfs])
	AC_DEFINE(CONFIG_LDISKFS_FS_RW, 1, [enable rw access for ldiskfs])
	AC_DEFINE(CONFIG_LDISKFS_FS_ENCRYPTION, 1, [enable encryption for ldiskfs])
	AC_SUBST(LDISKFS_SUBDIR, ldiskfs)
	AC_DEFINE(HAVE_LDISKFS_OSD, 1, Enable ldiskfs osd)
], [
	AC_SUBST(ENABLE_LDISKFS, no)
])

AC_MSG_CHECKING([whether to build ldiskfs])
AC_MSG_RESULT([$enable_ldiskfs])

AM_CONDITIONAL([LDISKFS_ENABLED], [test x$enable_ldiskfs = xyes])
]) # LB_CONFIG_LDISKFS

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
