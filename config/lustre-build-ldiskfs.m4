# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# config/lustre-build-ldiskfs.m4
#
# ldiskfs OSD related configuration
#

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
	94)     LDISKFS_SERIES="5.14-rhel9.4.series"    ;;
	93)     LDISKFS_SERIES="5.14-rhel9.3.series"    ;;
	92)     LDISKFS_SERIES="5.14-rhel9.2.series"    ;;
	91)     LDISKFS_SERIES="5.14-rhel9.1.series"    ;;
	90)     LDISKFS_SERIES="5.14-rhel9.series"      ;;
	810)    LDISKFS_SERIES="4.18-rhel8.10.series"   ;;
	89)     LDISKFS_SERIES="4.18-rhel8.9.series"    ;;
	88)     LDISKFS_SERIES="4.18-rhel8.8.series"    ;;
	87)     LDISKFS_SERIES="4.18-rhel8.7.series"    ;;
	86)     LDISKFS_SERIES="4.18-rhel8.6.series"    ;;
	85)     LDISKFS_SERIES="4.18-rhel8.5.series"    ;;
	84)     LDISKFS_SERIES="4.18-rhel8.4.series"    ;;
	79)	LDISKFS_SERIES="3.10-rhel7.9.series"	;;
	esac
], [test x$SUSE_KERNEL = xyes], [
	AS_VERSION_COMPARE([$LINUXRELEASE],[5.3.18],[
	AS_VERSION_COMPARE([$LINUXRELEASE],[4.12.14],[], [], [
		suse_conf=$LINUX_OBJ/include/generated/uapi/linux/suse_version.h
		suse_vers=$(awk '[$]2 == "SUSE_VERSION" {print [$]3 }' $suse_conf)
		suse_patchlevel=$(awk '[$]2 == "SUSE_PATCHLEVEL" {print [$]3 }' $suse_conf)
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
	    [
		suse_conf=$LINUX_OBJ/include/generated/uapi/linux/suse_version.h
		suse_vers=$(awk '[$]2 == "SUSE_VERSION" {print [$]3 }' $suse_conf)
		suse_patchlevel=$(awk '[$]2 == "SUSE_PATCHLEVEL" {print [$]3 }' $suse_conf)
		case ${suse_vers}sp${suse_patchlevel} in # (
		15sp2 ) LDISKFS_SERIES="5.4.21-ml.series"
			grep -A3 ext4_update_dx_flag $LINUX/fs/ext4/ext4.h \
			  | grep ext4_test_inode_flag
			if test $? -eq 0; then
				LDISKFS_SERIES="5.3.18-sles15sp2.series"
			fi
			;; # (
		15sp3 ) LDISKFS_SERIES="5.3.18-sles15sp3.series"
			update=$(echo $LINUXRELEASE | cut -d- -f2 | cut -d. -f2)
			if test $update -ge 59; then
				LDISKFS_SERIES="5.3.18-sles15sp3-59.series"
				up_patch=$(echo $LINUXRELEASE | cut -d- -f2 | cut -d. -f3 | cut -d_ -f1)
				if test $update -eq 59 -a $up_patch -le 60; then
					LDISKFS_SERIES="5.3.18-sles15sp3.series"
				fi
			fi
			;;
		15sp4 ) LDISKFS_SERIES="5.14.21-sles15sp4.series"
			;;
		15sp5 ) LDISKFS_SERIES="5.14.21-sles15sp5.series"
			;;
		esac
	    ])
], [test x$UBUNTU_KERNEL = xyes], [
        BASEVER=$(echo $LINUXRELEASE | cut -d'-' -f1)
	AS_VERSION_COMPARE([$BASEVER],[6.10.0],[
	AS_VERSION_COMPARE([$BASEVER],[6.8.0],[
	AS_VERSION_COMPARE([$BASEVER],[5.19.0],[
	AS_VERSION_COMPARE([$BASEVER],[5.15.0],[
	AS_VERSION_COMPARE([$BASEVER],[5.11.0],[
	AS_VERSION_COMPARE([$BASEVER],[5.8.0],[
	AS_VERSION_COMPARE([$BASEVER],[5.4.0],[
	AS_VERSION_COMPARE([$BASEVER],[5.0.0],[
	AS_VERSION_COMPARE([$BASEVER],[4.15.0], [],
	[
		KPLEV=$(echo $LINUXRELEASE | cut -d'-' -f2)
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
	[
		KPLEV=$(echo $LINUXRELEASE | cut -d'-' -f2)
		AS_IF(
			[test -z "$KPLEV"], [
				AC_MSG_WARN([Failed to determine Kernel patch level. Assume latest.])
				LDISKFS_SERIES="5.4.0-90-ubuntu20.series"
			],
			[test $KPLEV -eq 1007], [LDISKFS_SERIES="5.4.0-42-ubuntu20.series"],
			[test $KPLEV -ge 90], [LDISKFS_SERIES="5.4.0-90-ubuntu20.series"],
			[test $KPLEV -ge 80], [LDISKFS_SERIES="5.4.0-80-ubuntu20.series"],
			[test $KPLEV -ge 66], [LDISKFS_SERIES="5.4.0-66-ubuntu20.series"],
			[LDISKFS_SERIES="5.4.0-42-ubuntu20.series"]
		)
	],
	[LDISKFS_SERIES="5.4.0-ml.series"])],
	[
		KPLEV=$(echo $LINUXRELEASE | cut -d'-' -f2)
		AS_IF(
			[test -z "$KPLEV"], [
				AC_MSG_WARN([Failed to determine Kernel patch level. Assume latest.])
				LDISKFS_SERIES="5.8.0-63-ubuntu20.series"
			],
			[test $KPLEV -ge 63], [LDISKFS_SERIES="5.8.0-63-ubuntu20.series"],
			[LDISKFS_SERIES="5.8.0-53-ubuntu20.series"]
		)
	],
	[LDISKFS_SERIES="5.8.0-ml.series"])],
	[LDISKFS_SERIES="5.11.0-40-ubuntu20.series"],
	[LDISKFS_SERIES="5.11.0-40-ubuntu20.series"])],
	[
		KPLEV=$(echo $LINUXRELEASE | cut -d'-' -f2)
		AS_IF(
			[test -z "$KPLEV"], [
				AC_MSG_WARN([Failed to determine Kernel patch level. Assume latest.])
				LDISKFS_SERIES="5.15.0-106-ubuntu20.series"
			],
			[test $KPLEV -ge 106], [LDISKFS_SERIES="5.15.0-106-ubuntu20.series"],
			[LDISKFS_SERIES="5.15.0-83-ubuntu20.series"]
		)
	],
	[LDISKFS_SERIES="5.15.0-83-ubuntu20.series"])],
	[LDISKFS_SERIES="5.19.0-35-ubuntu.series"],
	[LDISKFS_SERIES="5.19.0-35-ubuntu.series"])],
	[
		KPLEV=$(echo $LINUXRELEASE | cut -d'-' -f2)
		AS_IF(
			[test -z "$KPLEV"], [
				AC_MSG_WARN([Failed to determine Kernel patch level. Assume latest.])
				LDISKFS_SERIES="6.8.0-45-ubuntu24.series"
			],
			[test $KPLEV -ge 44], [LDISKFS_SERIES="6.8.0-45-ubuntu24.series"],
			[LDISKFS_SERIES="6.7-ml.series"]
		)
	],
	[LDISKFS_SERIES="6.7-ml.series"])],
	[LDISKFS_SERIES="6.10-ml.series"],
	[LDISKFS_SERIES="6.10-ml.series"])
], [test x$OPENEULER_KERNEL = xyes], [
	case $OPENEULER_VERSION_NO in
	2203.0) LDISKFS_SERIES="5.10.0-oe2203.series" ;;
	2203.*) LDISKFS_SERIES="5.10.0-oe2203sp1.series" ;;
	esac
])
])
# Not RHEL/SLES/openEuler or Ubuntu .. probably mainline
AS_IF([test -z "$LDISKFS_SERIES"],
	[
	AS_VERSION_COMPARE([$LINUXRELEASE],[5.4.0],[
		], [
		LDISKFS_SERIES="5.4.0-ml.series"],[
	AS_VERSION_COMPARE([$LINUXRELEASE],[5.4.21],[
		LDISKFS_SERIES="5.4.0-ml.series"], [
		LDISKFS_SERIES="5.4.21-ml.series"],[
	AS_VERSION_COMPARE([$LINUXRELEASE],[5.10.0], [
		LDISKFS_SERIES="5.4.136-ml.series"], [
		LDISKFS_SERIES="5.10.0-ml.series"], [
	AS_VERSION_COMPARE([$LINUXRELEASE],[6.1.0], [
		LDISKFS_SERIES="5.10.0-ml.series"], [
		LDISKFS_SERIES="6.1.38-ml.series"], [
	AS_VERSION_COMPARE([$LINUXRELEASE],[6.6.0], [
		LDISKFS_SERIES="6.1.38-ml.series"], [
		LDISKFS_SERIES="6.6-ml.series"], [
	AS_VERSION_COMPARE([$LINUXRELEASE],[6.7.0], [
		LDISKFS_SERIES="6.6-ml.series"], [
		LDISKFS_SERIES="6.7-ml.series"], [
	AS_VERSION_COMPARE([$LINUXRELEASE],[6.10.0], [
		LDISKFS_SERIES="6.7-ml.series"], [
		LDISKFS_SERIES="6.10-ml.series"], [
	AS_VERSION_COMPARE([$LINUXRELEASE],[6.10.5], [
		LDISKFS_SERIES="6.10-ml.series"], [
		LDISKFS_SERIES="6.11-ml.series"], [
		LDISKFS_SERIES="6.11-ml.series"]
	)] # 6.11
	)] # 6.10
	)] # 6.7
	)] # 6.6
	)] # 6.1
	)] # 5.10
	)] # 5.4 LTS
	)],
[])
AS_IF([test -z "$LDISKFS_SERIES"],
	[AC_MSG_RESULT([failed to identify series])],
	[AC_MSG_RESULT([$LDISKFS_SERIES for $LINUXRELEASE])])
AC_SUBST(LDISKFS_SERIES)
]) # LDISKFS_LINUX_SERIES

#
# LB_EXT4_BREAD_4ARGS
#
# 3.18 ext4_bread has 4 arguments
# NOTE: It may not be exported for modules, use a positive compiler test here.
#
AC_DEFUN([LB_SRC_EXT4_BREAD_4ARGS], [
	LB2_LINUX_TEST_SRC([ext4_bread], [
		#include <linux/fs.h>
		#include "$EXT4_SRC_DIR/ext4.h"

		struct buffer_head *ext4_bread(handle_t *handle,
					       struct inode *inode,
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
	],[],[],[ext4_bread])
])
AC_DEFUN([LB_EXT4_BREAD_4ARGS], [
	LB2_MSG_LINUX_TEST_RESULT([if ext4_bread takes 4 arguments],
	[ext4_bread], [
		AC_DEFINE(HAVE_EXT4_BREAD_4ARGS, 1,
			[ext4_bread takes 4 arguments])
	])
]) # LB_EXT4_BREAD_4ARGS

#
# LB_EXT4_HAVE_INFO_DQUOT
#
# in linux 4.4 i_dqout is in ext4_inode_info, not in struct inode
#
AC_DEFUN([LB_SRC_EXT4_HAVE_INFO_DQUOT], [
	LB2_LINUX_TEST_SRC([ext4_info_dquot], [
		#include <linux/fs.h>
		#include <linux/quota.h>
		#include "$EXT4_SRC_DIR/ext4.h"
	],[
		struct ext4_inode_info in;
		struct dquot *dq;

		dq = in.i_dquot[0];
	])
])
AC_DEFUN([LB_EXT4_HAVE_INFO_DQUOT], [
	LB2_MSG_LINUX_TEST_RESULT([if i_dquot is in ext4_inode_info],
	[ext4_info_dquot], [
		AC_DEFINE(HAVE_EXT4_INFO_DQUOT, 1,
			[i_dquot is in ext4_inode_info])
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
AC_DEFUN([LB_SRC_EXT4_HAVE_I_CRYPT_INFO], [
	LB2_SRC_CHECK_CONFIG([EXT4_FS_ENCRYPTION])
	LB2_LINUX_TEST_SRC([ext4_i_crypt_info], [
		#define CONFIG_EXT4_FS_ENCRYPTION 1
		#include <linux/fs.h>
		#include "$EXT4_SRC_DIR/ext4.h"
	],[
		struct ext4_inode_info in;

		in.i_crypt_info = NULL;
	])
])
AC_DEFUN([LB_EXT4_HAVE_I_CRYPT_INFO], [
	LB2_MSG_LINUX_TEST_RESULT([if i_crypt_info is in ext4_inode_info],
	[ext4_i_crypt_info], [
		AC_DEFINE(CONFIG_LDISKFS_FS_ENCRYPTION, 1,
			[enable encryption for ldiskfs])
		test_have_i_crypt_info=yes
	],[
		test_have_i_crypt_info=no
	])
	AS_IF([test x$test_have_i_crypt_info = xno], [
		LB2_TEST_CHECK_CONFIG([EXT4_FS_ENCRYPTION],[
			AC_DEFINE(CONFIG_LDISKFS_FS_ENCRYPTION, 1,
				[enable encryption for ldiskfs])
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
AC_DEFUN([LB_SRC_LDISKFS_JOURNAL_ENSURE_CREDITS], [
	LB2_LINUX_TEST_SRC([ext4_journal_ensure_credits], [
		#include "$EXT4_SRC_DIR/ext4_jbd2.h"
		int __ext4_journal_ensure_credits(handle_t *handle, int check_cred,
			int extend_cred, int revoke_cred) { return 0; }
	],[
		ext4_journal_ensure_credits(NULL, 0, 0);
	],[-Werror],[],[__ext4_journal_ensure_credits])
])
AC_DEFUN([LB_LDISKFS_JOURNAL_ENSURE_CREDITS], [
	LB2_MSG_LINUX_TEST_RESULT([if 'ext4_journal_ensure_credits' exists],
	[ext4_journal_ensure_credits], [
		AC_DEFINE(HAVE_LDISKFS_JOURNAL_ENSURE_CREDITS, 1,
			['ext4_journal_ensure_credits' exists])
	])
]) # LB_LDISKFS_JOURNAL_ENSURE_CREDITS

#
# LB_LDISKFS_IGET_HAS_FLAGS_ARG
#
# kernel 4.19 commit 8a363970d1dc38c4ec4ad575c862f776f468d057
# ext4_iget changed to a macro with 3 args was function with 2 args
#
AC_DEFUN([LB_SRC_LDISKFS_IGET_HAS_FLAGS_ARG], [
	LB2_LINUX_TEST_SRC([ext4_iget_3args], [
		#include <linux/fs.h>
		#include "$EXT4_SRC_DIR/ext4.h"
	],[
		int f = EXT4_IGET_SPECIAL;
		(void)f;
	],[-Werror])
])
AC_DEFUN([LB_LDISKFS_IGET_HAS_FLAGS_ARG], [
	LB2_MSG_LINUX_TEST_RESULT([if ldiskfs_iget takes a flags argument],
	[ext4_iget_3args], [
		AC_DEFINE(HAVE_LDISKFS_IGET_WITH_FLAGS, 1,
			[if ldiskfs_iget takes a flags argument])
	])
]) # LB_LDISKFS_IGET_HAS_FLAGS_ARG

#
# LB_LDISKFS_IGET_EA_INODE
#
# kernel 6.4 commit b3e6bcb94590dea45396b9481e47b809b1be4afa
# extra iget flag EXT4_IGET_NO_CHECKS introduced to relax the ea_inode check.
#
AC_DEFUN([LB_SRC_LDISKFS_IGET_EA_INODE], [
	LB2_LINUX_TEST_SRC([ext4_iget_ea_inode], [
		#include <linux/fs.h>
		#include "$EXT4_SRC_DIR/ext4.h"
	],[
		int f = EXT4_IGET_EA_INODE;
		(void)f;
	],[-Werror])
])
AC_DEFUN([LB_LDISKFS_IGET_EA_INODE], [
	LB2_MSG_LINUX_TEST_RESULT([if 'EXT4_IGET_EA_INODE' exists],
	[ext4_iget_ea_inode], [
		AC_DEFINE(HAVE_LDISKFS_IGET_EA_INODE, 1,
			['EXT4_IGET_EA_INODE' exists])
	])
]) # LB_LDISKFS_IGET_EA_INODE

#
# LDISKFS_AC_PATCH_PROGRAM
#
# Determine which program should be used to apply the patches to
# the ext4 source code to produce the ldiskfs source code.
#
AC_DEFUN([LDISKFS_AC_PATCH_PROGRAM], [
	AC_ARG_ENABLE([quilt],
		[AS_HELP_STRING([--disable-quilt],
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
AC_DEFUN([LB_SRC_LDISKFS_FIND_ENTRY_LOCKED_EXISTS], [
	LB2_LINUX_TEST_SRC([ldiskfs_find_entry_locked], [
		#include <linux/fs.h>
		#include "$EXT4_SRC_DIR/ext4.h"
		#include "$EXT4_SRC_DIR/namei.c"

		static int __ext4_find_entry(void) { return 0; }
	],[
		int x = __ext4_find_entry();
		(void)x;
	],[-Werror])
])
AC_DEFUN([LB_LDISKFS_FIND_ENTRY_LOCKED_EXISTS], [
	LB2_MSG_LINUX_TEST_RESULT([if __ldiskfs_find_entry is available],
	[ldiskfs_find_entry_locked], [
		AC_DEFINE(HAVE___LDISKFS_FIND_ENTRY, 1,
			[if __ldiskfs_find_entry is available])
	])
]) # LB_LDISKFS_FIND_ENTRY_LOCKED_EXISTS

#
# LB_LDISKFSFS_DIRHASH_WANTS_DIR
#
# kernel 5.2 commit 8a363970d1dc38c4ec4ad575c862f776f468d057
# ext4fs_dirhash UNICODE support
#
AC_DEFUN([LB_SRC_LDISKFSFS_DIRHASH_WANTS_DIR], [
	LB2_LINUX_TEST_SRC([ext4fs_dirhash], [
		#include <linux/fs.h>
		#include "$EXT4_SRC_DIR/ext4.h"
	],[
		int f = ext4fs_dirhash(NULL, NULL, 0, NULL);
		(void)f;
	],[-Werror],[],[ext4fs_dirhash])
])
AC_DEFUN([LB_LDISKFSFS_DIRHASH_WANTS_DIR], [
	LB2_MSG_LINUX_TEST_RESULT([if ldiskfsfs_dirhash takes an inode argument],
	[ext4fs_dirhash], [
		AC_DEFINE(HAVE_LDISKFSFS_DIRHASH_WITH_DIR, 1,
			[if ldiskfsfs_dirhash takes an inode argument])
	])
]) # LB_LDISKFSFS_DIRHASH_WANTS_DIR

#
# LB_JBD2_H_TOTAL_CREDITS
#
# kernel 5.5 commit 933f1c1e0b75bbc29730eef07c9e196c6dfd37e5
# jbd2: Reserve space for revoke descriptor blocks
#
AC_DEFUN([LB_SRC_JBD2_H_TOTAL_CREDITS], [
	LB2_LINUX_TEST_SRC([handle_t_h_revoke_credits], [
		#include <linux/jbd2.h>
	],[
		int x = offsetof(struct jbd2_journal_handle, h_total_credits);
		(void)x;
	],[-Werror])
])
AC_DEFUN([LB_JBD2_H_TOTAL_CREDITS], [
	LB2_MSG_LINUX_TEST_RESULT([if struct jbd2_journal_handle has h_total_credits member],
	[handle_t_h_revoke_credits], [
		AC_DEFINE(HAVE_JOURNAL_TOTAL_CREDITS, 1,
			[struct jbd2_journal_handle has h_total_credits member])
	])
]) # LB_JBD2_H_TOTAL_CREDITS

#
# LB_EXT4_INC_DEC_COUNT_2ARGS
#
# Linux v5.9-rc7-8-g15ed2851b0f4
# ext4: remove unused argument from ext4_(inc|dec)_count
#
AC_DEFUN([LB_EXT4_INC_DEC_COUNT_2ARGS], [
	AC_MSG_CHECKING([if ext4_(inc|dec)_count() have 2 arguments])
	AS_IF([grep -q -E 'void ext4_inc_count.handle_t \*handle' $EXT4_SRC_DIR/namei.c],[
		AC_DEFINE(HAVE_EXT4_INC_DEC_COUNT_2ARGS, 1,
			[ext4_(inc|dec)_count() has 2 arguments])
		AC_MSG_RESULT(yes)
	],[
		AC_MSG_RESULT(no)
	])
]) # LB_EXT4_INC_DEC_COUNT_2ARGS

#
# LB_JBD2_JOURNAL_GET_MAX_TXN_BUFS
# Linux commit v5.10-rc2-9-gede7dc7fa0af
#  jbd2: rename j_maxlen to j_total_len and add jbd2_journal_max_txn_bufs
#
AC_DEFUN([LB_SRC_JBD2_JOURNAL_GET_MAX_TXN_BUFS], [
	LB2_LINUX_TEST_SRC([jbd2_journal_get_max_txn_bufs], [
		#include <linux/jbd2.h>
	],[
		journal_t *journal = NULL;
		int x = jbd2_journal_get_max_txn_bufs(journal);
		(void)x;
	],[-Werror],[],[])
])
AC_DEFUN([LB_JBD2_JOURNAL_GET_MAX_TXN_BUFS], [
	LB2_MSG_LINUX_TEST_RESULT([if jbd2_journal_get_max_txn_bufs is available],
	[jbd2_journal_get_max_txn_bufs], [
		AC_DEFINE(HAVE_JBD2_JOURNAL_GET_MAX_TXN_BUFS, 1,
			[if jbd2_journal_get_max_txn_bufs is available])
	])
]) # LB_JBD2_JOURNAL_GET_MAX_TXN_BUFS

#
# LB_EXT4_JOURNAL_GET_WRITE_ACCESS_4A
#
# Linux v5.14-rc2-19-g188c299e2a26
#    ext4: Support for checksumming from journal triggers
#
AC_DEFUN([LB_EXT4_JOURNAL_GET_WRITE_ACCESS_4A], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if jbd2_journal_get_max_txn_bufs is available],
ext4_journal_get_write_access, [
	#include <linux/fs.h>
	#include "$EXT4_SRC_DIR/ext4.h"
	#include "$EXT4_SRC_DIR/ext4_jbd2.h"

	int __ext4_journal_get_write_access(const char *where, unsigned int line,
				    handle_t *handle,
				    struct super_block *sb,
				    struct buffer_head *bh,
				    enum ext4_journal_trigger_type trigger_type)
	{
		return 0;
	}
],[
	handle_t *handle = NULL;
	struct super_block *sb = NULL;
	struct buffer_head *bh = NULL;
	enum ext4_journal_trigger_type trigger_type = EXT4_JTR_NONE;
	int err = ext4_journal_get_write_access(handle, sb, bh, trigger_type);

	(void)err;
],[
	AC_DEFINE(HAVE_EXT4_JOURNAL_GET_WRITE_ACCESS_4ARGS, 1,
		[ext4_journal_get_write_access() has 4 arguments])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LB_EXT4_JOURNAL_GET_WRITE_ACCESS_4A

#
# LB_HAVE_INODE_LOCK_SHARED
#
AC_DEFUN([LB_HAVE_INODE_LOCK_SHARED], [
LB_CHECK_COMPILE([if inode_lock_shared() defined],
inode_lock_shared, [
	#include <linux/fs.h>
],[
	struct inode i;

	inode_lock_shared(&i);
],[
	AC_DEFINE(HAVE_INODE_LOCK_SHARED, 1,
		[inode_lock_shared() defined])
])
]) # LB_HAVE_INODE_LOCK_SHARED

#
# LB_HAVE_INODE_IVERSION
#
AC_DEFUN([LB_HAVE_INODE_IVERSION], [
LB_CHECK_COMPILE([if iversion primitives defined],
inode_set_iversion, [
	#include <linux/iversion.h>
],[
	struct inode i;

	inode_set_iversion(&i, 0);
],[
	AC_DEFINE(HAVE_INODE_IVERSION, 1,
		[iversion primitives defined])
])
]) # LB_HAVE_INODE_IVERSION

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
	LB_EXT4_INC_DEC_COUNT_2ARGS
	LB_EXT4_JOURNAL_GET_WRITE_ACCESS_4A
	LB_HAVE_INODE_LOCK_SHARED
	LB_HAVE_INODE_IVERSION
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

AC_DEFUN([LB_KABI_LDISKFS], [AS_IF([test x$enable_ldiskfs != xno],[
	AC_DEFUN([LB_EXT4_LDISKFS_TESTS],[
		LB_SRC_EXT4_BREAD_4ARGS
		LB_SRC_EXT4_HAVE_INFO_DQUOT
		LB_SRC_EXT4_HAVE_I_CRYPT_INFO
		LB_SRC_LDISKFS_JOURNAL_ENSURE_CREDITS
		LB_SRC_LDISKFS_IGET_HAS_FLAGS_ARG
		LB_SRC_LDISKFS_IGET_EA_INODE
		LB_SRC_LDISKFS_FIND_ENTRY_LOCKED_EXISTS
		LB_SRC_LDISKFSFS_DIRHASH_WANTS_DIR
		LB_SRC_JBD2_H_TOTAL_CREDITS
		LB_SRC_JBD2_JOURNAL_GET_MAX_TXN_BUFS
		LB2_SRC_CHECK_CONFIG_IM([FS_ENCRYPTION])
	])
	AC_DEFUN([LB_EXT4_LDISKFS_CHECKS], [
		LB_EXT4_BREAD_4ARGS
		LB_EXT4_HAVE_INFO_DQUOT
		LB_EXT4_HAVE_I_CRYPT_INFO
		LB_LDISKFS_JOURNAL_ENSURE_CREDITS
		LB_LDISKFS_IGET_HAS_FLAGS_ARG
		LB_LDISKFS_IGET_EA_INODE
		LB_LDISKFS_FIND_ENTRY_LOCKED_EXISTS
		LB_LDISKFSFS_DIRHASH_WANTS_DIR
		LB_JBD2_H_TOTAL_CREDITS
		LB_JBD2_JOURNAL_GET_MAX_TXN_BUFS
		LB2_TEST_CHECK_CONFIG_IM([FS_ENCRYPTION], [
			EXT4_CRYPTO=],[
			EXT4_CRYPTO='%/crypto.c'])
	])
	AC_SUBST(EXT4_CRYPTO)
])])

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
# LB_EXT4_SOURCE_PATH
#
# Determine the location of the ext4 source code.  It it required
# for several configure tests and to build ldiskfs.
#
AC_DEFUN([LB_EXT4_SOURCE_PATH], [
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
]) # LB_EXT4_SOURCE_PATH

#
# LB_DEFINE_E2FSPROGS_NAMES
#
# Enable the use of alternate naming of ldiskfs-enabled e2fsprogs package.
#
AC_DEFUN([LB_DEFINE_E2FSPROGS_NAMES], [
AC_MSG_CHECKING([whether to use alternate names for e2fsprogs])
AC_ARG_WITH([ldiskfsprogs],
	AS_HELP_STRING([--with-ldiskfsprogs],
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
