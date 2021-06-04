#
# LC_CONFIG_SRCDIR
#
# Wrapper for AC_CONFIG_SUBDIR
#
AC_DEFUN([LC_CONFIG_SRCDIR], [
AC_CONFIG_SRCDIR([lustre/obdclass/obdo.c])
ldiskfs_is_ext4="yes"
])

#
# LC_PATH_DEFAULTS
#
# lustre specific paths
#
AC_DEFUN([LC_PATH_DEFAULTS], [
# ptlrpc kernel build requires this
LUSTRE="$PWD/lustre"
AC_SUBST(LUSTRE)

# mount.lustre
rootsbindir='/sbin'
AC_SUBST(rootsbindir)

demodir='$(docdir)/demo'
AC_SUBST(demodir)

pkgexampledir='${pkgdatadir}/examples'
AC_SUBST(pkgexampledir)
]) # LC_PATH_DEFAULTS

#
# LC_TARGET_SUPPORTED
#
# is the target os supported?
#
AC_DEFUN([LC_TARGET_SUPPORTED], [
case $target_os in
	linux*)
$1
		;;
	*)
$2
		;;
esac
]) # LC_TARGET_SUPPORTED

#
# LC_GLIBC_SUPPORT_FHANDLES
#
AC_DEFUN([LC_GLIBC_SUPPORT_FHANDLES], [
AC_CHECK_FUNCS([name_to_handle_at],
	[AC_DEFINE(HAVE_FHANDLE_GLIBC_SUPPORT, 1,
		[file handle and related syscalls are supported])],
	[AC_MSG_WARN([file handle and related syscalls are not supported])])
]) # LC_GLIBC_SUPPORT_FHANDLES

#
# LC_GLIBC_SUPPORT_COPY_FILE_RANGE
#
AC_DEFUN([LC_GLIBC_SUPPORT_COPY_FILE_RANGE], [
AC_CHECK_FUNCS([copy_file_range],
	[AC_DEFINE(HAVE_COPY_FILE_RANGE, 1,
		[copy_file_range() is supported])],
	[AC_MSG_WARN([copy_file_range() is not supported])])
]) # LC_GLIBC_SUPPORT_COPY_FILE_RANGE

#
# LC_STACK_SIZE
#
# Ensure the stack size is at least 8k in Lustre server (all kernels)
#
AC_DEFUN([LC_STACK_SIZE], [
LB_CHECK_COMPILE([if stack size is at least 8k],
stack_size_8k, [
	#include <linux/thread_info.h>
], [
	#if THREAD_SIZE < 8192
	#error "stack size < 8192"
	#endif
], [], [AC_MSG_ERROR([

Lustre requires that Linux is configured with at least a 8KB stack.
])])
]) # LC_STACK_SIZE

#
# LC_MDS_MAX_THREADS
#
# Allow the user to set the MDS thread upper limit
#
AC_DEFUN([LC_MDS_MAX_THREADS], [
AC_MSG_CHECKING([for maximum number of MDS threads])
AC_ARG_WITH([mds_max_threads],
	AC_HELP_STRING([--with-mds-max-threads=count],
		[maximum threads available on the MDS: (default=512)]),
	[AC_DEFINE_UNQUOTED(MDS_MAX_THREADS, $with_mds_max_threads,
		[maximum number of MDS threads])])
AC_MSG_RESULT([$with_mds_max_threads])
]) # LC_MDS_MAX_THREADS

#
# LC_CONFIG_PINGER
#
# the pinger is temporary, until we have the recovery node in place
#
AC_DEFUN([LC_CONFIG_PINGER], [
AC_MSG_CHECKING([whether to enable Lustre pinger support])
AC_ARG_ENABLE([pinger],
	AC_HELP_STRING([--disable-pinger],
		[disable recovery pinger support]),
	[], [enable_pinger="yes"])
AC_MSG_RESULT([$enable_pinger])
AS_IF([test "x$enable_pinger" != xno],
	[AC_DEFINE(CONFIG_LUSTRE_FS_PINGER, 1,[Use the Pinger])])
]) # LC_CONFIG_PINGER

#
# LC_CONFIG_CHECKSUM
#
# do checksum of bulk data between client and OST
#
AC_DEFUN([LC_CONFIG_CHECKSUM], [
AC_MSG_CHECKING([whether to enable data checksum support])
AC_ARG_ENABLE([checksum],
	AC_HELP_STRING([--disable-checksum],
		[disable data checksum support]),
	[], [enable_checksum="yes"])
AC_MSG_RESULT([$enable_checksum])
AS_IF([test "x$enable_checksum" != xno],
	[AC_DEFINE(ENABLE_CHECKSUM, 1, [do data checksums])])
]) # LC_CONFIG_CHECKSUM

#
# LC_CONFIG_FLOCK
#
# enable distributed flock by default
#
AC_DEFUN([LC_CONFIG_FLOCK], [
AC_MSG_CHECKING([whether to enable flock by default])
AC_ARG_ENABLE([flock],
	AC_HELP_STRING([--disable-flock],
		[disable flock by default]),
	[], [enable_flock="yes"])
AC_MSG_RESULT([$enable_flock])
AS_IF([test "x$enable_flock" != xno],
	[AC_DEFINE(ENABLE_FLOCK, 1, [enable flock by default])])
]) # LC_CONFIG_FLOCK

#
# LC_CONFIG_HEALTH_CHECK_WRITE
#
# Turn off the actual write to the disk
#
AC_DEFUN([LC_CONFIG_HEALTH_CHECK_WRITE], [
AC_MSG_CHECKING([whether to enable a write with the health check])
AC_ARG_ENABLE([health_write],
	AC_HELP_STRING([--enable-health_write],
		[enable disk writes when doing health check]),
	[], [enable_health_write="no"])
AC_MSG_RESULT([$enable_health_write])
AS_IF([test "x$enable_health_write" != xno],
	[AC_DEFINE(USE_HEALTH_CHECK_WRITE, 1, [Write when Checking Health])])
]) # LC_CONFIG_HEALTH_CHECK_WRITE

#
# LC_CONFIG_LRU_RESIZE
#
AC_DEFUN([LC_CONFIG_LRU_RESIZE], [
AC_MSG_CHECKING([whether to enable lru self-adjusting])
AC_ARG_ENABLE([lru_resize],
	AC_HELP_STRING([--enable-lru-resize],
		[enable lru resize support]),
	[], [enable_lru_resize="yes"])
AC_MSG_RESULT([$enable_lru_resize])
AS_IF([test "x$enable_lru_resize" != xno],
	[AC_DEFINE(HAVE_LRU_RESIZE_SUPPORT, 1, [Enable lru resize support])])
]) # LC_CONFIG_LRU_RESIZE

#
# LC_QUOTA_CONFIG
#
# Quota support. The kernel must support CONFIG_QUOTA.
#
AC_DEFUN([LC_QUOTA_CONFIG], [
LB_CHECK_CONFIG_IM([QUOTA], [],
	[AC_MSG_ERROR([

Lustre quota requires that CONFIG_QUOTA is enabled in your kernel.
])])
]) # LC_QUOTA_CONFIG

#
# LC_CONFIG_FHANDLE
#
# fhandle kernel support for open_by_handle_at() and name_to_handle_at()
# system calls. The kernel must support CONFIG_FHANDLE.
#
AC_DEFUN([LC_CONFIG_FHANDLE], [
LB_CHECK_CONFIG_IM([FHANDLE], [],
	[AC_MSG_ERROR([

Lustre fid handling requires that CONFIG_FHANDLE is enabled in your kernel.
])])
]) # LC_CONFIG_FHANDLE

#
# LC_POSIX_ACL_CONFIG
#
# POSIX ACL support.
#
AC_DEFUN([LC_POSIX_ACL_CONFIG], [
LB_CHECK_CONFIG_IM([FS_POSIX_ACL],
	[AC_DEFINE(CONFIG_LUSTRE_FS_POSIX_ACL, 1, [Enable POSIX acl])
], [ ])
]) # LC_POSIX_ACL_CONFIG

LB_CHECK_CONFIG_IM([CRYPTO_MD5], [],
		[AC_MSG_WARN([kernel MD5 support is recommended by using GSS.])])

#
# LC_CONFIG_GSS_KEYRING
#
# default 'auto', tests for dependencies, if found, enables;
# only called if gss is enabled
#
AC_DEFUN([LC_CONFIG_GSS_KEYRING], [
AC_MSG_CHECKING([whether to enable gss keyring backend])
AC_ARG_ENABLE([gss_keyring],
	[AC_HELP_STRING([--disable-gss-keyring],
		[disable gss keyring backend])],
	[], [enable_gss_keyring="auto"])
AC_MSG_RESULT([$enable_gss_keyring])
AS_IF([test "x$enable_gss_keyring" != xno], [
	LB_CHECK_CONFIG_IM([KEYS], [], [
		gss_keyring_conf_test="fail"
		AC_MSG_WARN([GSS keyring backend requires that CONFIG_KEYS be enabled in your kernel.])])

	AC_CHECK_LIB([keyutils], [keyctl_search], [], [
		gss_keyring_conf_test="fail"
		AC_MSG_WARN([GSS keyring backend requires libkeyutils])])

	AS_IF([test "x$gss_keyring_conf_test" != xfail], [
		AC_DEFINE([HAVE_GSS_KEYRING], [1],
			[Define this if you enable gss keyring backend])
		enable_gss_keyring="yes"
	], [
		AS_IF([test "x$enable_gss_keyring" = xyes], [
			AC_MSG_ERROR([Cannot enable gss_keyring. See above for details.])
		])
	])
])
]) # LC_CONFIG_GSS_KEYRING

#
# LC_KEY_TYPE_INSTANTIATE_2ARGS
#
# rhel7 key_type->instantiate takes 2 args (struct key, struct key_preparsed_payload)
#
AC_DEFUN([LC_KEY_TYPE_INSTANTIATE_2ARGS], [
LB_CHECK_COMPILE([if 'key_type->instantiate' has two args],
key_type_instantiate_2args, [
	#include <linux/key-type.h>
],[
	((struct key_type *)0)->instantiate(0, NULL);
],[
	AC_DEFINE(HAVE_KEY_TYPE_INSTANTIATE_2ARGS, 1,
		[key_type->instantiate has two args])
])
]) # LC_KEY_TYPE_INSTANTIATE_2ARGS

#
# LC_CONFIG_SUNRPC
#
AC_DEFUN([LC_CONFIG_SUNRPC], [
LB_CHECK_CONFIG_IM([SUNRPC], [], [
	AS_IF([test "x$sunrpc_required" = xyes], [
		AC_MSG_ERROR([

kernel SUNRPC support is required by using GSS.
])
	])])
]) # LC_CONFIG_SUNRPC

#
# LC_CONFIG_GSS (default 'auto' (tests for dependencies, if found, enables))
#
# Build gss and related tools of Lustre. Currently both kernel and user space
# parts are depend on linux platform.
#
AC_DEFUN([LC_CONFIG_GSS], [
AC_MSG_CHECKING([whether to enable gss support])
AC_ARG_ENABLE([gss],
	[AC_HELP_STRING([--enable-gss], [enable gss support])],
	[], [enable_gss="auto"])
AC_MSG_RESULT([$enable_gss])

AC_ARG_VAR([TEST_JOBS],
    [simultaneous jobs during configure (defaults to $(nproc))])
if test "x$ac_cv_env_TEST_JOBS_set" != "xset"; then
	TEST_JOBS=${TEST_JOBS:-$(nproc)}
fi
AC_SUBST(TEST_JOBS)

AC_ARG_VAR([TEST_DIR],
    [location of temporary parallel configure tests (defaults to $PWD/lb2)])
	TEST_DIR=${TEST_DIR:-$PWD/_lpb}
AC_SUBST(TEST_DIR)

AS_IF([test "x$enable_gss" != xno], [
	LC_CONFIG_GSS_KEYRING
	LC_KEY_TYPE_INSTANTIATE_2ARGS
	sunrpc_required=$enable_gss
	LC_CONFIG_SUNRPC
	sunrpc_required="no"

	LB_CHECK_CONFIG_IM([CRYPTO_MD5], [],
		[AC_MSG_WARN([kernel MD5 support is recommended by using GSS.])])
	LB_CHECK_CONFIG_IM([CRYPTO_SHA1], [],
		[AC_MSG_WARN([kernel SHA1 support is recommended by using GSS.])])
	LB_CHECK_CONFIG_IM([CRYPTO_SHA256], [],
		[AC_MSG_WARN([kernel SHA256 support is recommended by using GSS.])])
	LB_CHECK_CONFIG_IM([CRYPTO_SHA512], [],
		[AC_MSG_WARN([kernel SHA512 support is recommended by using GSS.])])

	require_krb5=$enable_gss
	AC_KERBEROS_V5
	require_krb5="no"

	AS_IF([test -n "$KRBDIR"], [
		gss_conf_test="success"
	], [
		gss_conf_test="failure"
	])

	AS_IF([test "x$gss_conf_test" = xsuccess && test "x$enable_gss" != xno], [
		AC_DEFINE([HAVE_GSS], [1], [Define this is if you enable gss])
		enable_gss="yes"
	], [
		enable_gss_keyring="no"
		enable_gss="no"
	])

	enable_ssk=$enable_gss
], [
	enable_gss_keyring="no"
])
]) # LC_CONFIG_GSS

# LC_OPENSSL_SSK
#
# OpenSSL 1.0+ return int for HMAC functions but older SLES11 versions do not
AC_DEFUN([LC_OPENSSL_SSK], [
AC_MSG_CHECKING([whether OpenSSL has functions needed for SSK])
AS_IF([test "x$enable_ssk" != xno], [
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
	#include <openssl/hmac.h>
	#include <openssl/evp.h>

	int main(void) {
		int rc;
		rc = HMAC_Init_ex(NULL, "test", 4, EVP_md_null(), NULL);
	}
])],[AC_DEFINE(HAVE_OPENSSL_SSK, 1,
	       [OpenSSL HMAC functions needed for SSK])],
	[enable_ssk="no"])
])
AC_MSG_RESULT([$enable_ssk])
]) # LC_OPENSSL_SSK

# LC_OPENSSL_GETSEPOL
#
# OpenSSL is needed for l_getsepol
AC_DEFUN([LC_OPENSSL_GETSEPOL], [
AC_MSG_CHECKING([whether openssl-devel is present])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([
	#include <openssl/evp.h>

	int main(void) {
		EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
	}
])],[
	AC_DEFINE(HAVE_OPENSSL_GETSEPOL, 1, [openssl-devel is present])
	enable_getsepol="yes"

],[
	enable_getsepol="no"
	AC_MSG_WARN([

No openssl-devel headers found, unable to build l_getsepol and SELinux status checking
])
])
AC_MSG_RESULT([$enable_getsepol])
]) # LC_OPENSSL_GETSEPOL

# LC_HAVE_LIBAIO
AC_DEFUN([LC_HAVE_LIBAIO], [
	AC_CHECK_HEADER([libaio.h],
		enable_libaio="yes",
		AC_MSG_WARN([libaio is not installed in the system]))
]) # LC_HAVE_LIBAIO

AC_DEFUN([LC_HAVE_PROJECT_QUOTA], [
LB_CHECK_COMPILE([if get_projid exists],
get_projid, [
	struct inode;
	#include <linux/quota.h>
],[
	struct dquot_operations ops = { };

	ops.get_projid(NULL, NULL);
],[
	AC_DEFINE(HAVE_PROJECT_QUOTA, 1,
		[get_projid function exists])
])
]) # LC_HAVE_PROJECT_QUOTA

#
# LC_INVALIDATE_RANGE
#
# 3.11 invalidatepage requires the length of the range to invalidate
#
AC_DEFUN([LC_INVALIDATE_RANGE], [
LB_CHECK_COMPILE([if 'address_space_operations.invalidatepage' requires 3 arguments],
address_space_ops_invalidatepage_3args, [
	#include <linux/fs.h>
],[
	struct address_space_operations a_ops;
	a_ops.invalidatepage(NULL, 0, 0);
],[
	AC_DEFINE(HAVE_INVALIDATE_RANGE, 1,
		[address_space_operations.invalidatepage needs 3 arguments])
])
]) # LC_INVALIDATE_RANGE

#
# LC_HAVE_DIR_CONTEXT
#
# 3.11 readdir now takes the new struct dir_context
#
AC_DEFUN([LC_HAVE_DIR_CONTEXT], [
LB_CHECK_COMPILE([if 'dir_context' exist],
dir_context, [
	#include <linux/fs.h>
],[
#ifdef FMODE_KABI_ITERATE
#error "back to use readdir in kabi_extand mode"
#else
	struct dir_context ctx;

	ctx.pos = 0;
#endif
],[
	AC_DEFINE(HAVE_DIR_CONTEXT, 1,
		[dir_context exist])
])
]) # LC_HAVE_DIR_CONTEXT

#
# LC_D_COMPARE_5ARGS
#
# 3.11 dentry_operations.d_compare() taken 5 arguments.
#
AC_DEFUN([LC_D_COMPARE_5ARGS], [
LB_CHECK_COMPILE([if 'd_compare' taken 5 arguments],
d_compare_5args, [
	#include <linux/dcache.h>
],[
	((struct dentry_operations*)0)->d_compare(NULL,NULL,0,NULL,NULL);
],[
	AC_DEFINE(HAVE_D_COMPARE_5ARGS, 1,
		[d_compare need 5 arguments])
])
]) # LC_D_COMPARE_5ARGS

#
# LC_HAVE_DCOUNT
#
# 3.11 need to access d_count to get dentry reference count
#
AC_DEFUN([LC_HAVE_DCOUNT], [
LB_CHECK_COMPILE([if 'd_count' exists],
d_count, [
	#include <linux/dcache.h>
],[
	struct dentry de = { };
	int count;

	count = d_count(&de);
],[
	AC_DEFINE(HAVE_D_COUNT, 1,
		[d_count exist])
])
]) # LC_HAVE_DCOUNT

#
# LC_PID_NS_FOR_CHILDREN
#
# 3.11 replaces pid_ns by pid_ns_for_children in struct nsproxy
#
AC_DEFUN([LC_PID_NS_FOR_CHILDREN], [
LB_CHECK_COMPILE([if 'struct nsproxy' has 'pid_ns_for_children'],
pid_ns_for_children, [
	#include <linux/nsproxy.h>
],[
	struct nsproxy ns;
	ns.pid_ns_for_children = NULL;
],[
	AC_DEFINE(HAVE_PID_NS_FOR_CHILDREN, 1,
		  ['struct nsproxy' has 'pid_ns_for_children'])
])
]) # LC_PID_NS_FOR_CHILDREN

#
# LC_OLDSIZE_TRUNCATE_PAGECACHE
#
# 3.12 truncate_pagecache without oldsize parameter
#
AC_DEFUN([LC_OLDSIZE_TRUNCATE_PAGECACHE], [
LB_CHECK_COMPILE([if 'truncate_pagecache' with 'old_size' parameter],
truncate_pagecache_old_size, [
	#include <linux/mm.h>
],[
	truncate_pagecache(NULL, 0, 0);
],[
	AC_DEFINE(HAVE_OLDSIZE_TRUNCATE_PAGECACHE, 1,
		[with oldsize])
])
]) # LC_OLDSIZE_TRUNCATE_PAGECACHE

#
# LC_PTR_ERR_OR_ZERO
#
# For some reason SLES11SP4 is missing the PTR_ERR_OR_ZERO macro
# It was added to linux kernel 3.12
#
AC_DEFUN([LC_PTR_ERR_OR_ZERO_MISSING], [
LB_CHECK_COMPILE([if 'PTR_ERR_OR_ZERO' is missing],
is_err_or_null, [
	#include <linux/err.h>
],[
	if (PTR_ERR_OR_ZERO(NULL)) return 0;
],[
	AC_DEFINE(HAVE_PTR_ERR_OR_ZERO, 1,
		['PTR_ERR_OR_ZERO' exist])
])
]) # LC_PTR_ERR_OR_ZERO_MISSING

#
# LC_HAVE_DENTRY_D_U_D_ALIAS
#
# 3.11 kernel moved d_alias to the union d_u in struct dentry
#
# Some distros move d_alias to d_u but it is still a struct list
#
AC_DEFUN([LC_HAVE_DENTRY_D_U_D_ALIAS], [
AS_IF([test "x$lb_cv_compile_i_dentry_d_alias_list" = xyes], [
	LB_CHECK_COMPILE([if list 'dentry.d_u.d_alias' exist],
	d_alias, [
		#include <linux/list.h>
		#include <linux/dcache.h>
	],[
		struct dentry de;
		INIT_LIST_HEAD(&de.d_u.d_alias);
	],[
		AC_DEFINE(HAVE_DENTRY_D_U_D_ALIAS, 1,
			[list dentry.d_u.d_alias exist])
	])
],[
	LB_CHECK_COMPILE([if hlist 'dentry.d_u.d_alias' exist],
	d_alias, [
		#include <linux/list.h>
		#include <linux/dcache.h>
	],[
		struct dentry de;
		INIT_HLIST_NODE(&de.d_u.d_alias);
	],[
		AC_DEFINE(HAVE_DENTRY_D_U_D_ALIAS, 1,
			[hlist dentry.d_u.d_alias exist])
	])
])
]) # LC_HAVE_DENTRY_D_U_D_ALIAS

#
# LC_HAVE_DENTRY_D_CHILD
#
# 3.11 kernel d_child has been moved out of the union d_u
# in struct dentry
#
AC_DEFUN([LC_HAVE_DENTRY_D_CHILD], [
LB_CHECK_COMPILE([if 'dentry.d_child' exist],
d_child, [
	#include <linux/list.h>
	#include <linux/dcache.h>
],[
	struct dentry de;
	INIT_LIST_HEAD(&de.d_child);
],[
	AC_DEFINE(HAVE_DENTRY_D_CHILD, 1,
		[dentry.d_child exist])
])
]) # LC_HAVE_DENTRY_D_CHILD

#
# LC_KIOCB_KI_LEFT
#
# 3.12 ki_left removed from struct kiocb
#
AC_DEFUN([LC_KIOCB_KI_LEFT], [
LB_CHECK_COMPILE([if 'struct kiocb' with 'ki_left' member],
kiocb_ki_left, [
	#include <linux/aio.h>
],[
	((struct kiocb*)0)->ki_left = 0;
],[
	AC_DEFINE(HAVE_KIOCB_KI_LEFT, 1,
		[ki_left exist])
])
]) # LC_KIOCB_KI_LEFT

#
# LC_VFS_RENAME_5ARGS
#
# 3.13 has vfs_rename with 5 args
#
AC_DEFUN([LC_VFS_RENAME_5ARGS], [
LB_CHECK_COMPILE([if Linux kernel has 'vfs_rename' with 5 args],
vfs_rename_5args, [
	#include <linux/fs.h>
],[
	vfs_rename(NULL, NULL, NULL, NULL, NULL);
], [
	AC_DEFINE(HAVE_VFS_RENAME_5ARGS, 1,
		[kernel has vfs_rename with 5 args])
])
]) # LC_VFS_RENAME_5ARGS

#
# LC_VFS_UNLINK_3ARGS
#
# 3.13 has vfs_unlink with 3 args
#
AC_DEFUN([LC_VFS_UNLINK_3ARGS], [
LB_CHECK_COMPILE([if Linux kernel has 'vfs_unlink' with 3 args],
vfs_unlink_3args, [
	#include <linux/fs.h>
],[
	vfs_unlink(NULL, NULL, NULL);
], [
	AC_DEFINE(HAVE_VFS_UNLINK_3ARGS, 1,
		[kernel has vfs_unlink with 3 args])
])
]) # LC_VFS_UNLINK_3ARGS

# LC_HAVE_D_IS_POSITIVE
#
# Kernel version 3.13 b18825a7c8e37a7cf6abb97a12a6ad71af160de7
# d_is_positive is added
#
AC_DEFUN([LC_HAVE_D_IS_POSITIVE], [
LB_CHECK_COMPILE([if 'd_is_positive' exist],
d_is_positive, [
	#include <linux/dcache.h>
],[
	d_is_positive(NULL);
],[
	AC_DEFINE(HAVE_D_IS_POSITIVE, 1,
		['d_is_positive' is available])
])
]) # LC_HAVE_D_IS_POSITIVE

#
# LC_HAVE_BVEC_ITER
#
# 3.14 move some of its data in struct bio into the new
# struct bvec_iter
#
AC_DEFUN([LC_HAVE_BVEC_ITER], [
LB_CHECK_COMPILE([if Linux kernel has struct bvec_iter],
have_bvec_iter, [
	#include <linux/bio.h>
],[
	struct bvec_iter iter;

	iter.bi_bvec_done = 0;
], [
	AC_DEFINE(HAVE_BVEC_ITER, 1,
		[kernel has struct bvec_iter])
])
]) # LC_HAVE_BVEC_ITER

#
# LC_IOP_SET_ACL
#
# 3.14 adds set_acl method to inode_operations
# see kernel commit 893d46e443346370cd4ea81d9d35f72952c62a37
#
AC_DEFUN([LC_IOP_SET_ACL], [
LB_CHECK_COMPILE([if 'inode_operations' has '.set_acl' member function],
inode_ops_set_acl, [
	#include <linux/fs.h>
],[
	struct inode_operations iop;
	iop.set_acl = NULL;
],[
	AC_DEFINE(HAVE_IOP_SET_ACL, 1,
		[inode_operations has .set_acl member function])
])
]) # LC_IOP_SET_ACL

#
# LC_HAVE_TRUNCATE_IPAGE_FINAL
#
# 3.14 bring truncate_inode_pages_final for evict_inode
#
AC_DEFUN([LC_HAVE_TRUNCATE_IPAGES_FINAL], [
LB_CHECK_COMPILE([if Linux kernel has truncate_inode_pages_final],
truncate_ipages_final, [
	#include <linux/mm.h>
],[
	truncate_inode_pages_final(NULL);
], [
	AC_DEFINE(HAVE_TRUNCATE_INODE_PAGES_FINAL, 1,
		[kernel has truncate_inode_pages_final])
])
]) # LC_HAVE_TRUNCATE_IPAGES_FINAL

#
# LC_IOPS_RENAME_WITH_FLAGS
#
# 3.14 has inode_operations->rename with 5 args
# commit 520c8b16505236fc82daa352e6c5e73cd9870cff
#
AC_DEFUN([LC_IOPS_RENAME_WITH_FLAGS], [
LB_CHECK_COMPILE([if 'inode_operations->rename' taken flags as argument],
iops_rename_with_flags, [
	#include <linux/fs.h>
],[
	struct inode *i1 = NULL, *i2 = NULL;
	struct dentry *d1 = NULL, *d2 = NULL;
	int rc;
	rc = ((struct inode_operations *)0)->rename(i1, d1, i2, d2, 0);
], [
	AC_DEFINE(HAVE_IOPS_RENAME_WITH_FLAGS, 1,
		[inode_operations->rename need flags as argument])
])
]) # LC_IOPS_RENAME_WITH_FLAGS

#
# LC_VFS_RENAME_6ARGS
#
# 3.15 has vfs_rename with 6 args
#
AC_DEFUN([LC_VFS_RENAME_6ARGS], [
LB_CHECK_COMPILE([if Linux kernel has 'vfs_rename' with 6 args],
vfs_rename_6args, [
	#include <linux/fs.h>
],[
	vfs_rename(NULL, NULL, NULL, NULL, NULL, NULL);
], [
	AC_DEFINE(HAVE_VFS_RENAME_6ARGS, 1,
		[kernel has vfs_rename with 6 args])
])
]) # LC_VFS_RENAME_6ARGS

#
# LC_DIRECTIO_USE_ITER
#
# 3.16 kernel changes direct IO to use iov_iter
#
AC_DEFUN([LC_DIRECTIO_USE_ITER], [
LB_CHECK_COMPILE([if direct IO uses iov_iter],
direct_io_iter, [
	#include <linux/fs.h>
],[
	struct address_space_operations ops = { };
	struct iov_iter *iter = NULL;
	loff_t offset = 0;

	ops.direct_IO(0, NULL, iter, offset);
],[
	AC_DEFINE(HAVE_DIRECTIO_ITER, 1,
		[direct IO uses iov_iter])
])
]) # LC_DIRECTIO_USE_ITER

#
# LC_HAVE_IOV_ITER_INIT_DIRECTION
#
#
# 3.16 linux commit 71d8e532b1549a478e6a6a8a44f309d050294d00
#      changed iov_iter_init api to start accepting a tag
#      that defines if its a read or write operation
#
AC_DEFUN([LC_HAVE_IOV_ITER_INIT_DIRECTION], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'iov_iter_init' takes a tag],
iter_init, [
	#include <linux/uio.h>
	#include <linux/fs.h>
],[
	const struct iovec *iov = NULL;

	iov_iter_init(NULL, READ, iov, 1, 0);
],[
	AC_DEFINE(HAVE_IOV_ITER_INIT_DIRECTION, 1,
		[iov_iter_init handles directional tag])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_HAVE_IOV_ITER_INIT_DIRECTION

#
# LC_HAVE_IOV_ITER_TRUNCATE
#
#
# 3.16 introduces a new API iov_iter_truncate()
#
AC_DEFUN([LC_HAVE_IOV_ITER_TRUNCATE], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'iov_iter_truncate' exists ],
iter_truncate, [
	#include <linux/uio.h>
	#include <linux/fs.h>
],[
	struct iov_iter *i = NULL;

	iov_iter_truncate(i, 0);
],[
	AC_DEFINE(HAVE_IOV_ITER_TRUNCATE, 1, [iov_iter_truncate exists])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_HAVE_IOV_ITER_TRUNCATE

#
# LC_HAVE_FILE_OPERATIONS_READ_WRITE_ITER
#
# 3.16 introduces [read|write]_iter to struct file_operations
#
AC_DEFUN([LC_HAVE_FILE_OPERATIONS_READ_WRITE_ITER], [
LB_CHECK_COMPILE([if 'file_operations.[read|write]_iter' exist],
file_function_iter, [
	#include <linux/fs.h>
],[
	((struct file_operations *)NULL)->read_iter(NULL, NULL);
	((struct file_operations *)NULL)->write_iter(NULL, NULL);
],[
	AC_DEFINE(HAVE_FILE_OPERATIONS_READ_WRITE_ITER, 1,
		[file_operations.[read|write]_iter functions exist])
])
]) # LC_HAVE_FILE_OPERATIONS_READ_WRITE_ITER

#
# LC_HAVE_INTERVAL_BLK_INTEGRITY
#
# 3.17 replace sector_size with interval in struct blk_integrity
#
AC_DEFUN([LC_HAVE_INTERVAL_BLK_INTEGRITY], [
LB_CHECK_COMPILE([if 'blk_integrity.interval' exist],
interval_blk_integrity, [
	#include <linux/blkdev.h>
],[
	((struct blk_integrity *)0)->interval = 0;
],[
	AC_DEFINE(HAVE_INTERVAL_BLK_INTEGRITY, 1,
		[blk_integrity.interval exist])
])
]) # LC_HAVE_INTERVAL_BLK_INTEGRITY

#
# LC_KEY_MATCH_DATA
#
# 3.17	replaces key_type::match with match_preparse
#	and has new struct key_match_data
#
AC_DEFUN([LC_KEY_MATCH_DATA], [
LB_CHECK_COMPILE([if struct key_match field exist],
key_match, [
	#include <linux/key-type.h>
],[
	struct key_match_data data;

	data.raw_data = NULL;
],[
	AC_DEFINE(HAVE_KEY_MATCH_DATA, 1,
		[struct key_match_data exist])
])
]) # LC_KEY_MATCH_DATA

#
# LC_NFS_FILLDIR_USE_CTX
#
# 3.18 kernel moved from void cookie to struct dir_context
#
AC_DEFUN([LC_NFS_FILLDIR_USE_CTX], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if filldir_t uses struct dir_context],
filldir_ctx, [
	#include <linux/fs.h>
],[
	int filldir(struct dir_context *ctx, const char* name,
		    int i, loff_t off, u64 tmp, unsigned temp)
	{
		return 0;
	}

	struct dir_context ctx = {
		.actor = filldir,
	};

	ctx.actor(NULL, "test", 0, (loff_t) 0, 0, 0);
],[
	AC_DEFINE(HAVE_FILLDIR_USE_CTX, 1,
		[filldir_t needs struct dir_context as argument])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_NFS_FILLDIR_USE_CTX

#
# LC_PERCPU_COUNTER_INIT
#
# 3.18	For kernels 3.18 and after percpu_counter_init starts
#	to pass a GFP_* memory allocation flag for internal
#	memory allocation purposes.
#
AC_DEFUN([LC_PERCPU_COUNTER_INIT], [
LB_CHECK_COMPILE([if percpu_counter_init uses GFP_* flag as argument],
percpu_counter_init, [
	#include <linux/percpu_counter.h>
],[
	percpu_counter_init(NULL, 0, GFP_KERNEL);
],[
	AC_DEFINE(HAVE_PERCPU_COUNTER_INIT_GFP_FLAG, 1,
		[percpu_counter_init uses GFP_* flag])
])
]) # LC_PERCPU_COUNTER_INIT

#
# LC_KIOCB_HAS_NBYTES
#
# 3.19 kernel removed ki_nbytes from struct kiocb
#
AC_DEFUN([LC_KIOCB_HAS_NBYTES], [
LB_CHECK_COMPILE([if struct kiocb has ki_nbytes field],
ki_nbytes, [
	#include <linux/fs.h>
],[
	struct kiocb iocb = { };

	iocb.ki_nbytes = 0;
],[
	AC_DEFINE(HAVE_KI_NBYTES, 1, [ki_nbytes field exist])
])
]) # LC_KIOCB_HAS_NBYTES

#
# LC_HAVE_DQUOT_QC_DQBLK
#
# 3.19 has quotactl_ops->[sg]et_dqblk that take struct kqid and qc_dqblk
# Added in commit 14bf61ffe
#
AC_DEFUN([LC_HAVE_DQUOT_QC_DQBLK], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'quotactl_ops.set_dqblk' takes struct qc_dqblk],
qc_dqblk, [
	#include <linux/fs.h>
	#include <linux/quota.h>
],[
	((struct quotactl_ops *)0)->set_dqblk(NULL, *((struct kqid*)0), (struct qc_dqblk*)0);
],[
	AC_DEFINE(HAVE_DQUOT_QC_DQBLK, 1,
		[quotactl_ops.set_dqblk takes struct qc_dqblk])
	AC_DEFINE(HAVE_DQUOT_KQID, 1,
		[quotactl_ops.set_dqblk takes struct kqid])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_HAVE_DQUOT_QC_DQBLK

#
# LC_HAVE_AIO_COMPLETE
#
# 3.19 kernel makes aio_complete() static
#
AC_DEFUN([LC_HAVE_AIO_COMPLETE], [
LB_CHECK_COMPILE([if kernel has exported aio_complete() ],
aio_complete, [
	#include <linux/aio.h>
],[
	aio_complete(NULL, 0, 0);
],[
	AC_DEFINE(HAVE_AIO_COMPLETE, 1, [aio_complete defined])
])
]) # LC_HAVE_AIO_COMPLETE

#
# LC_BACKING_DEV_INFO_REMOVAL
#
# 3.20 kernel removed backing_dev_info from address_space
#
AC_DEFUN([LC_BACKING_DEV_INFO_REMOVAL], [
LB_CHECK_COMPILE([if struct address_space has backing_dev_info],
backing_dev_info, [
	#include <linux/fs.h>
],[
	struct address_space mapping;

	mapping.backing_dev_info = NULL;
],[
	AC_DEFINE(HAVE_BACKING_DEV_INFO, 1, [backing_dev_info exist])
])
]) # LC_BACKING_DEV_INFO_REMOVAL

#
# LC_HAVE_BDI_CAP_MAP_COPY
#
# 3.20  removed mmap handling for backing devices since
#	it breaks on non-MMU systems. See kernel commit
#	b4caecd48005fbed3949dde6c1cb233142fd69e9
#
AC_DEFUN([LC_HAVE_BDI_CAP_MAP_COPY], [
LB_CHECK_COMPILE([if have 'BDI_CAP_MAP_COPY'],
bdi_cap_map_copy, [
	#include <linux/backing-dev.h>
],[
	struct backing_dev_info info;

	info.capabilities = BDI_CAP_MAP_COPY;
],[
	AC_DEFINE(HAVE_BDI_CAP_MAP_COPY, 1,
		[BDI_CAP_MAP_COPY exist])
])
]) # LC_HAVE_BDI_CAP_MAP_COPY

#
# LC_IOV_ITER_RW
#
# 4.1 kernel has iov_iter_rw
#
AC_DEFUN([LC_IOV_ITER_RW], [
LB_CHECK_COMPILE([if iov_iter_rw exist],
iov_iter_rw, [
	#include <linux/fs.h>
	#include <linux/uio.h>
],[
	struct iov_iter *iter = NULL;

	iov_iter_rw(iter);
],[
	AC_DEFINE(HAVE_IOV_ITER_RW, 1,
		[iov_iter_rw exist])
])
]) # LC_IOV_ITER_RW

#
# LC_HAVE_SYNC_READ_WRITE
#
# 4.1 new_sync_[read|write] no longer exported
#
AC_DEFUN([LC_HAVE_SYNC_READ_WRITE], [
LB_CHECK_EXPORT([new_sync_read], [fs/read_write.c],
	[AC_DEFINE(HAVE_SYNC_READ_WRITE, 1,
			[new_sync_[read|write] is exported by the kernel])])
]) # LC_HAVE_SYNC_READ_WRITE

#
# LC_HAVE___BI_CNT
#
# 4.1 redefined bi_cnt as __bi_cnt in commit dac56212e8127dbc0
#
AC_DEFUN([LC_HAVE___BI_CNT], [
LB_CHECK_COMPILE([if Linux kernel has __bi_cnt in struct bio],
have___bi_cnt, [
	#include <asm/atomic.h>
	#include <linux/bio.h>
	#include <linux/blk_types.h>
],[
	struct bio bio = { };
	int cnt;
	cnt = atomic_read(&bio.__bi_cnt);
], [
	AC_DEFINE(HAVE___BI_CNT, 1,
		[struct bio has __bi_cnt])
])
]) # LC_HAVE___BI_CNT

#
# LC_SYMLINK_OPS_USE_NAMEIDATA
#
# For the 4.2+ kernels the file system internal symlink api no
# longer uses struct nameidata as a argument
#
AC_DEFUN([LC_SYMLINK_OPS_USE_NAMEIDATA], [
LB_CHECK_COMPILE([if symlink inode operations have struct nameidata argument],
symlink_use_nameidata, [
	#include <linux/namei.h>
	#include <linux/fs.h>
],[
	struct nameidata *nd = NULL;

	((struct inode_operations *)0)->follow_link(NULL, nd);
	((struct inode_operations *)0)->put_link(NULL, nd, NULL);
],[
	AC_DEFINE(HAVE_SYMLINK_OPS_USE_NAMEIDATA, 1,
		[symlink inode operations need struct nameidata argument])
])
]) # LC_SYMLINK_OPS_USE_NAMEIDATA

#
# LC_BIO_ENDIO_USES_ONE_ARG
#
# 4.2 kernel bio_endio now only takes one argument
#
AC_DEFUN([LC_BIO_ENDIO_USES_ONE_ARG], [
LB_CHECK_COMPILE([if 'bio_endio' with one argument exist],
bio_endio, [
	#include <linux/bio.h>
],[
	bio_endio(NULL);
],[
	AC_DEFINE(HAVE_BIO_ENDIO_USES_ONE_ARG, 1,
		[bio_endio takes only one argument])
])
]) # LC_BIO_ENDIO_USES_ONE_ARG

#
# LC_ACCOUNT_PAGE_DIRTIED_3ARGS
#
# 4.2 [to 4.5] kernel page dirtied takes 3 arguments
#
AC_DEFUN([LC_ACCOUNT_PAGE_DIRTIED_3ARGS], [
LB_CHECK_COMPILE([if 'account_page_dirtied' with 3 args exists],
account_page_dirtied, [
	#include <linux/mm.h>
],[
	account_page_dirtied(NULL, NULL, NULL);
],[
	AC_DEFINE(HAVE_ACCOUNT_PAGE_DIRTIED_3ARGS, 1,
		[account_page_dirtied takes three arguments])
])
]) # LC_ACCOUNT_PAGE_DIRTIED_3ARGS

#
# LC_HAVE_CRYPTO_ALLOC_SKCIPHER
#
# Kernel version 4.12 commit 7a7ffe65c8c5
# introduced crypto_alloc_skcipher().
#
AC_DEFUN([LC_HAVE_CRYPTO_ALLOC_SKCIPHER], [
LB_CHECK_COMPILE([if crypto_alloc_skcipher is defined],
crypto_alloc_skcipher, [
	#include <crypto/skcipher.h>
],[
	crypto_alloc_skcipher(NULL, 0, 0);
],[
	AC_DEFINE(HAVE_CRYPTO_ALLOC_SKCIPHER, 1,
		[crypto_alloc_skcipher is defined])
])
]) # LC_HAVE_CRYPTO_ALLOC_SKCIPHER

#
# LC_HAVE_INTERVAL_EXP_BLK_INTEGRITY
#
# 4.3 replace interval with interval_exp in 'struct blk_integrity'
# 'struct blk_integrity_profile' is also added in this version,
# thus use this to determine whether 'struct blk_integrity' has profile
#
AC_DEFUN([LC_HAVE_INTERVAL_EXP_BLK_INTEGRITY], [
LB_CHECK_COMPILE([if 'blk_integrity.interval_exp' exist],
blk_integrity_interval_exp, [
	#include <linux/blkdev.h>
],[
	((struct blk_integrity *)0)->interval_exp = 0;
],[
	AC_DEFINE(HAVE_INTERVAL_EXP_BLK_INTEGRITY, 1,
		[blk_integrity.interval_exp exist])
])
]) # LC_HAVE_INTERVAL_EXP_BLK_INTEGRITY

#
# LC_HAVE_CACHE_HEAD_HLIST
#
# 4.3 kernel swiched to hlist for cache_head
#
AC_DEFUN([LC_HAVE_CACHE_HEAD_HLIST], [
LB_CHECK_COMPILE([if 'struct cache_head' has 'cache_list' field],
cache_head_has_hlist, [
	#include <linux/sunrpc/cache.h>
],[
	do {} while(sizeof(((struct cache_head *)0)->cache_list));
],[
	AC_DEFINE(HAVE_CACHE_HEAD_HLIST, 1,
		[cache_head has hlist cache_list])
])
]) # LC_HAVE_CACHE_HEAD_HLIST

#
# LC_HAVE_XATTR_HANDLER_SIMPLIFIED
#
# Kernel version 4.3 commit e409de992e3ea3674393465f07cc71c948edd87a
# simplified xattr_handler handling by passing in the handler pointer
#
AC_DEFUN([LC_HAVE_XATTR_HANDLER_SIMPLIFIED], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'struct xattr_handler' functions pass in handler pointer],
xattr_handler_simplified, [
	#include <linux/xattr.h>
],[
	struct xattr_handler handler;

	((struct xattr_handler *)0)->get(&handler, NULL, NULL, NULL, 0);
	((struct xattr_handler *)0)->set(&handler, NULL, NULL, NULL, 0, 0);
],[
	AC_DEFINE(HAVE_XATTR_HANDLER_SIMPLIFIED, 1, [handler pointer is parameter])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_HAVE_XATTR_HANDLER_SIMPLIFIED

#
# LC_HAVE_BIP_ITER_BIO_INTEGRITY_PAYLOAD
#
# 4.3 replace interval with interval_exp in 'struct blk_integrity'.
#
AC_DEFUN([LC_HAVE_BIP_ITER_BIO_INTEGRITY_PAYLOAD], [
LB_CHECK_COMPILE([if 'bio_integrity_payload.bip_iter' exist],
bio_integrity_payload_bip_iter, [
	#include <linux/bio.h>
],[
	((struct bio_integrity_payload *)0)->bip_iter.bi_size = 0;
],[
	AC_DEFINE(HAVE_BIP_ITER_BIO_INTEGRITY_PAYLOAD, 1,
		[bio_integrity_payload.bip_iter exist])
])
]) # LC_HAVE_BIP_ITER_BIO_INTEGRITY_PAYLOAD

#
# LC_BIO_INTEGRITY_PREP_FN
#
# Lustre kernel patch extents bio_integrity_prep to accept optional
# generate/verify_fn as extra args.
#
AC_DEFUN([LC_BIO_INTEGRITY_PREP_FN], [
LB_CHECK_COMPILE([if 'bio_integrity_prep_fn' exists],
bio_integrity_prep_fn, [
	#include <linux/bio.h>
],[
	bio_integrity_prep_fn(NULL, NULL, NULL);
],[
	AC_DEFINE(HAVE_BIO_INTEGRITY_PREP_FN, 1,
		[kernel has bio_integrity_prep_fn])
	AC_SUBST(PATCHED_INTEGRITY_INTF)
],[
	AC_SUBST(PATCHED_INTEGRITY_INTF, [#])
])
]) # LC_BIO_INTEGRITY_PREP_FN

#
# LC_HAVE_BI_OPF
#
# 4.4/4.8 redefined bi_rw as bi_opf (SLES12/kernel commit 4382e33ad37486)
#
AC_DEFUN([LC_HAVE_BI_OPF], [
LB_CHECK_COMPILE([if Linux kernel has bi_opf in struct bio],
have_bi_opf, [
	#include <linux/bio.h>
],[
	struct bio bio;

	bio.bi_opf = 0;
], [
	AC_DEFINE(HAVE_BI_OPF, 1,
		[struct bio has bi_opf])
])
]) # LC_HAVE_BI_OPF

#
# LC_HAVE_SUBMIT_BIO_2ARGS
#
# 4.4 removed an argument from submit_bio
#
AC_DEFUN([LC_HAVE_SUBMIT_BIO_2ARGS], [
LB_CHECK_COMPILE([if submit_bio takes two arguments],
have_submit_bio_2args, [
	#include <linux/bio.h>
],[
	struct bio bio;
	submit_bio(READ, &bio);
], [
	AC_DEFINE(HAVE_SUBMIT_BIO_2ARGS, 1,
		[submit_bio takes two arguments])
])
]) # LC_HAVE_SUBMIT_BIO_2_ARGS

#
# LC_HAVE_CLEAN_BDEV_ALIASES
#
# 4.4/4.9 unmap_underlying_metadata was replaced by clean_bdev_aliases
# (SLES12/kernel commit 29f3ad7d8380364c)
#
AC_DEFUN([LC_HAVE_CLEAN_BDEV_ALIASES], [
LB_CHECK_COMPILE([if kernel has clean_bdev_aliases],
have_clean_bdev_aliases, [
	#include <linux/buffer_head.h>
],[
	clean_bdev_aliases(NULL,1,1);
], [
	AC_DEFINE(HAVE_CLEAN_BDEV_ALIASES, 1,
		[kernel has clean_bdev_aliases])
])
]) # LC_HAVE_CLEAN_BDEV_ALIASES

#
# LC_HAVE_LOCKS_LOCK_FILE_WAIT
#
# 4.4 kernel have moved locks API users to
# locks_lock_inode_wait()
#
AC_DEFUN([LC_HAVE_LOCKS_LOCK_FILE_WAIT], [
LB_CHECK_COMPILE([if 'locks_lock_file_wait' exists],
locks_lock_file_wait, [
	#include <linux/fs.h>
],[
	locks_lock_file_wait(NULL, NULL);
],[
	AC_DEFINE(HAVE_LOCKS_LOCK_FILE_WAIT, 1,
		[kernel has locks_lock_file_wait])
])
]) # LC_HAVE_LOCKS_LOCK_FILE_WAIT

#
# LC_HAVE_KEY_PAYLOAD_DATA_ARRAY
#
# 4.4 kernel merged type-specific data with the payload data for keys
#
AC_DEFUN([LC_HAVE_KEY_PAYLOAD_DATA_ARRAY], [
LB_CHECK_COMPILE([if 'struct key' has 'payload.data' as an array],
key_payload_data_array, [
	#include <linux/key.h>
],[
	struct key key = { };

	key.payload.data[0] = NULL;
],[
	AC_DEFINE(HAVE_KEY_PAYLOAD_DATA_ARRAY, 1, [payload.data is an array])
])
]) #LC_HAVE_KEY_PAYLOAD_DATA_ARRAY

#
# LC_HAVE_XATTR_HANDLER_NAME
#
# Kernel version 4.4 commit 98e9cb5711c68223f0e4d5201b9a6add255ec550
# add a name member to struct xattr_handler
#
AC_DEFUN([LC_HAVE_XATTR_HANDLER_NAME], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'struct xattr_handler' has a name member],
xattr_handler_name, [
	#include <linux/xattr.h>
],[
	((struct xattr_handler *)NULL)->name = NULL;
],[
	AC_DEFINE(HAVE_XATTR_HANDLER_NAME, 1, [xattr_handler has a name member])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_HAVE_XATTR_HANDLER_NAME

#
# LC_HAVE_FILE_DENTRY
#
# 4.5 adds wrapper file_dentry
#
AC_DEFUN([LC_HAVE_FILE_DENTRY], [
LB_CHECK_COMPILE([if Linux kernel has 'file_dentry'],
file_dentry, [
	#include <linux/fs.h>
],[
	file_dentry(NULL);
], [
	AC_DEFINE(HAVE_FILE_DENTRY, 1,
		[kernel has file_dentry])
])
]) # LC_HAVE_FILE_DENTRY

#
# LC_HAVE_INODE_LOCK
#
# 4.5 introduced inode_lock
#
AC_DEFUN([LC_HAVE_INODE_LOCK], [
LB_CHECK_COMPILE([if 'inode_lock' is defined],
inode_lock, [
	#include <linux/fs.h>
],[
	inode_lock(NULL);
], [
	AC_DEFINE(HAVE_INODE_LOCK, 1,
		  [inode_lock is defined])
])
]) # LC_HAVE_INODE_LOCK

#
# LC_HAVE_IOP_GET_LINK
#
# 4.5 vfs replaced iop->follow_link with
# iop->get_link
#
AC_DEFUN([LC_HAVE_IOP_GET_LINK], [
LB_CHECK_COMPILE([if 'iop' has 'get_link'],
inode_ops_get_link, [
	#include <linux/fs.h>
],[
	struct inode_operations iop;
	iop.get_link = NULL;
],[
	AC_DEFINE(HAVE_IOP_GET_LINK, 1,
		[have iop get_link])
])
]) # LC_HAVE_IOP_GET_LINK

#
# LC_HAVE_IN_COMPAT_SYSCALL
#
# 4.6 renamed is_compat_task to in_compat_syscall
#
AC_DEFUN([LC_HAVE_IN_COMPAT_SYSCALL], [
LB_CHECK_COMPILE([if 'in_compat_syscall' is defined],
in_compat_syscall, [
	#include <linux/compat.h>
],[
	in_compat_syscall();
],[
	AC_DEFINE(HAVE_IN_COMPAT_SYSCALL, 1,
		[have in_compat_syscall])
])
]) # LC_HAVE_IN_COMPAT_SYSCALL

#
# LC_HAVE_XATTR_HANDLER_INODE_PARAM
#
# Kernel version 4.6 commit b296821a7c42fa58baa17513b2b7b30ae66f3336
# and commit 5930122683dff58f0846b0f0405b4bd598a3ba6a added inode parameter
# to xattr_handler functions
#
AC_DEFUN([LC_HAVE_XATTR_HANDLER_INODE_PARAM], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'struct xattr_handler' functions have inode parameter],
xattr_handler_inode_param, [
	#include <linux/xattr.h>
],[
	const struct xattr_handler handler;

	((struct xattr_handler *)0)->get(&handler, NULL, NULL, NULL, NULL, 0);
	((struct xattr_handler *)0)->set(&handler, NULL, NULL, NULL, NULL, 0, 0);
],[
	AC_DEFINE(HAVE_XATTR_HANDLER_INODE_PARAM, 1, [needs inode parameter])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_HAVE_XATTR_HANDLER_INODE_PARAM

#
# LC_D_IN_LOOKUP
#
# Kernel version 4.6 commit 85c7f81041d57cfe9dc97f4680d5586b54534a39
# introduced parallel lookups in the VFS layer. The inline function
# d_in_lookup was added to notify when the same item was being queried
# at the same time.
#
AC_DEFUN([LC_D_IN_LOOKUP], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'd_in_lookup' is defined],
d_in_lookup, [
	#include <linux/dcache.h>
],[
	d_in_lookup(NULL);
],[
	AC_DEFINE(HAVE_D_IN_LOOKUP, 1, [d_in_lookup is defined])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_D_IN_LOOKUP

#
# LC_LOCK_PAGE_MEMCG
#
# Kernel version 4.6 adds lock_page_memcg
#
AC_DEFUN([LC_LOCK_PAGE_MEMCG], [
LB_CHECK_COMPILE([if 'lock_page_memcg' is defined],
lock_page_memcg, [
	#include <linux/memcontrol.h>
],[
	lock_page_memcg(NULL);
],[
	AC_DEFINE(HAVE_LOCK_PAGE_MEMCG, 1,
		[lock_page_memcg is defined])
])
]) # LC_LOCK_PAGE_MEMCG

#
# LC_DIRECTIO_2ARGS
#
# Kernel version 4.7 commit c8b8e32d700fe943a935e435ae251364d016c497
# direct-io: eliminate the offset argument to ->direct_IO
#
AC_DEFUN([LC_DIRECTIO_2ARGS], [
LB_CHECK_COMPILE([if '->direct_IO()' taken 2 arguments],
direct_io_2args, [
	#include <linux/fs.h>
],[
	struct address_space_operations ops = { };
	struct iov_iter *iter = NULL;
	struct kiocb *iocb = NULL;
	int rc;

	rc = ops.direct_IO(iocb, iter);
],[
	AC_DEFINE(HAVE_DIRECTIO_2ARGS, 1,
		[direct_IO need 2 arguments])
])
]) # LC_DIRECTIO_2ARGS

#
# LC_GENERIC_WRITE_SYNC_2ARGS
#
# Kernel version 4.7 commit dde0c2e79848298cc25621ad080d47f94dbd7cce
# fs: add IOCB_SYNC and IOCB_DSYNC
#
AC_DEFUN([LC_GENERIC_WRITE_SYNC_2ARGS], [
LB_CHECK_COMPILE([if 'generic_write_sync()' taken 2 arguments],
generic_write_sync_2args, [
	#include <linux/fs.h>
],[
	struct kiocb *iocb = NULL;
	ssize_t rc;

	rc = generic_write_sync(iocb, 0);
],[
	AC_DEFINE(HAVE_GENERIC_WRITE_SYNC_2ARGS, 1,
		[generic_write_sync need 2 arguments])
])
]) # LC_GENERIC_WRITE_SYNC_2ARGS

#
# LC_FOP_ITERATE_SHARED
#
# Kernel v4.6-rc3-29-g6192269 adds iterate_shared method to file_operations
#
AC_DEFUN([LC_FOP_ITERATE_SHARED], [
LB_CHECK_COMPILE([if 'file_operations' has 'iterate_shared'],
fop_iterate_shared, [
	#include <linux/fs.h>
],[
	struct file_operations fop;
	fop.iterate_shared = NULL;
],[
	AC_DEFINE(HAVE_FOP_ITERATE_SHARED, 1,
		[file_operations has iterate_shared])
])
]) # LC_FOP_ITERATE_SHARED

#
# LC_EXPORT_DEFAULT_FILE_SPLICE_READ
#
# 4.8-rc8 commit 82c156f853840645604acd7c2cebcb75ed1b6652 switched
# generic_file_splice_read() to using ->read_iter. We can test this
# change since default_file_splice_read() is no longer exported.
#
AC_DEFUN([LC_EXPORT_DEFAULT_FILE_SPLICE_READ], [
LB_CHECK_EXPORT([default_file_splice_read], [fs/splice.c],
	[AC_DEFINE(HAVE_DEFAULT_FILE_SPLICE_READ_EXPORT, 1,
			[default_file_splice_read is exported])])
]) # LC_EXPORT_DEFAULT_FILE_SPLCE_READ

#
# LC_HAVE_POSIX_ACL_VALID_USER_NS
#
# 4.8 posix_acl_valid takes struct user_namespace
#
AC_DEFUN([LC_HAVE_POSIX_ACL_VALID_USER_NS], [
LB_CHECK_COMPILE([if 'posix_acl_valid' takes 'struct user_namespace'],
posix_acl_valid, [
	#include <linux/fs.h>
	#include <linux/posix_acl.h>
],[
	posix_acl_valid((struct user_namespace*)NULL, (const struct posix_acl*)NULL);
],[
	AC_DEFINE(HAVE_POSIX_ACL_VALID_USER_NS, 1,
		[posix_acl_valid takes struct user_namespace])
])
]) # LC_HAVE_POSIX_ACL_VALID_USER_NS

#
# LC_D_COMPARE_4ARGS
#
# Kernel version 4.8 commit 6fa67e707559303e086303aeecc9e8b91ef497d5
# get rid of 'parent' argument of ->d_compare()
#
AC_DEFUN([LC_D_COMPARE_4ARGS], [
LB_CHECK_COMPILE([if 'd_compare' taken 4 arguments],
d_compare_4args, [
	#include <linux/dcache.h>
],[
	((struct dentry_operations*)0)->d_compare(NULL,0,NULL,NULL);
],[
	AC_DEFINE(HAVE_D_COMPARE_4ARGS, 1,
		[d_compare need 4 arguments])
])
]) # LC_D_COMPARE_4ARGS

#
# LC_FULL_NAME_HASH_3ARGS
#
# Kernel version 4.8 commit 8387ff2577eb9ed245df9a39947f66976c6bcd02
# vfs: make the string hashes salt the hash
#
AC_DEFUN([LC_FULL_NAME_HASH_3ARGS], [
LB_CHECK_COMPILE([if 'full_name_hash' taken 3 arguments],
full_name_hash_3args, [
	#include <linux/stringhash.h>
],[
	unsigned int hash;
	hash = full_name_hash(NULL,NULL,0);
],[
	AC_DEFINE(HAVE_FULL_NAME_HASH_3ARGS, 1,
		[full_name_hash need 3 arguments])
])
]) # LC_FULL_NAME_HASH_3ARGS

#
# LC_STRUCT_POSIX_ACL_XATTR
#
# Kernel version 4.8 commit 2211d5ba5c6c4e972ba6dbc912b2897425ea6621
# posix_acl: xattr representation cleanups
#
AC_DEFUN([LC_STRUCT_POSIX_ACL_XATTR], [
LB_CHECK_COMPILE([if 'struct posix_acl_xattr_{header,entry}' defined],
struct_posix_acl_xattr, [
	#include <linux/fs.h>
	#include <linux/posix_acl_xattr.h>
],[
	struct posix_acl_xattr_header *h = NULL;
	struct posix_acl_xattr_entry  *e;
	e = (void *)(h + 1);
],[
	AC_DEFINE(HAVE_STRUCT_POSIX_ACL_XATTR, 1,
		[struct posix_acl_xattr_{header,entry} defined])
])
]) # LC_STRUCT_POSIX_ACL_XATTR

#
# LC_IOP_XATTR
#
# Kernel version 4.8 commit fd50ecaddf8372a1d96e0daeaac0f93cf04e4d42
# removed {get,set,remove}xattr inode operations
#
AC_DEFUN([LC_IOP_XATTR], [
LB_CHECK_COMPILE([if 'inode_operations' has {get,set,remove}xattr members],
inode_ops_xattr, [
	#include <linux/fs.h>
],[
	struct inode_operations iop;
	iop.setxattr = NULL;
	iop.getxattr = NULL;
	iop.removexattr = NULL;
],[
	AC_DEFINE(HAVE_IOP_XATTR, 1,
		[inode_operations has {get,set,remove}xattr members])
])
]) # LC_IOP_XATTR

#
# LC_GROUP_INFO_GID
#
# Kernel version 4.9 commit 81243eacfa400f5f7b89f4c2323d0de9982bb0fb
# cred: simpler, 1D supplementary groups
#
AC_DEFUN([LC_GROUP_INFO_GID], [
LB_CHECK_COMPILE([if 'struct group_info' has member 'gid'],
group_info_gid, [
	#include <linux/cred.h>
],[
	kgid_t *p;
	p = ((struct group_info *)0)->gid;
],[
	AC_DEFINE(HAVE_GROUP_INFO_GID, 1,
		[struct group_info has member gid])
])
]) # LC_GROUP_INFO_GID

#
# LC_VFS_SETXATTR
#
# Kernel version 4.9 commit 5d6c31910bc0713e37628dc0ce677dcb13c8ccf4
# added __vfs_{get,set,remove}xattr helpers
#
AC_DEFUN([LC_VFS_SETXATTR], [
LB_CHECK_COMPILE([if '__vfs_setxattr' helper is available],
vfs_setxattr, [
	#include <linux/xattr.h>
],[
	__vfs_setxattr(NULL, NULL, NULL, NULL, 0, 0);
],[
	AC_DEFINE(HAVE_VFS_SETXATTR, 1,
		['__vfs_setxattr is available])
])
]) # LC_VFS_SETXATTR

#
# LC_POSIX_ACL_UPDATE_MODE
#
# Kernel version 4.9 commit 073931017b49d9458aa351605b43a7e34598caef
# posix_acl: Clear SGID bit when setting file permissions
#
AC_DEFUN([LC_POSIX_ACL_UPDATE_MODE], [
LB_CHECK_COMPILE([if 'posix_acl_update_mode' exists],
posix_acl_update_mode, [
	#include <linux/fs.h>
	#include <linux/posix_acl.h>
],[
	posix_acl_update_mode(NULL, NULL, NULL);
],[
	AC_DEFINE(HAVE_POSIX_ACL_UPDATE_MODE, 1,
		['posix_acl_update_mode' is available])
])
]) # LC_POSIX_ACL_UPDATE_MODE

#
# LC_IOP_GENERIC_READLINK
#
# Kernel version 4.10 commit dfeef68862edd7d4bafe68ef7aeb5f658ef24bb5
# removed generic_readlink from individual file systems
#
AC_DEFUN([LC_IOP_GENERIC_READLINK], [
LB_CHECK_COMPILE([if 'generic_readlink' still exist],
inode_ops_readlink, [
	#include <linux/fs.h>
],[
	struct inode_operations iop;
	iop.readlink = generic_readlink;
],[
	AC_DEFINE(HAVE_IOP_GENERIC_READLINK, 1,
		[generic_readlink has been removed])
])
]) # LC_IOP_GENERIC_READLINK

#
# LC_HAVE_VM_FAULT_ADDRESS
#
# Kernel version 4.10 commit 1a29d85eb0f19b7d8271923d8917d7b4f5540b3e
# removed virtual_address field. Need to use address field instead
#
AC_DEFUN([LC_HAVE_VM_FAULT_ADDRESS], [
LB_CHECK_COMPILE([if 'struct vm_fault' replaced virtual_address with address field],
vm_fault_address, [
	#include <linux/mm.h>
],[
	struct vm_fault vmf;
	vmf.address = NULL;
],[
	AC_DEFINE(HAVE_VM_FAULT_ADDRESS, 1,
		[virtual_address has been replaced by address field])
])
]) # LC_HAVE_VM_FAULT_ADDRESS

#
# LC_INODEOPS_ENHANCED_GETATTR
#
# Kernel version 4.11 commit a528d35e8bfcc521d7cb70aaf03e1bd296c8493f
# expanded getattr to be able to get more stat information.
#
AC_DEFUN([LC_INODEOPS_ENHANCED_GETATTR], [
LB_CHECK_COMPILE([if 'inode_operations' getattr member can gather advance stats],
getattr_path, [
	#include <linux/fs.h>
],[
	struct path path;

	((struct inode_operations *)1)->getattr(&path, NULL, 0, 0);
],[
	AC_DEFINE(HAVE_INODEOPS_ENHANCED_GETATTR, 1,
		[inode_operations .getattr member function can gather advance stats])
])
]) # LC_INODEOPS_ENHANCED_GETATTR

#
# LC_VM_OPERATIONS_REMOVE_VMF_ARG
#
# Kernel version 4.11 commit 11bac80004499ea59f361ef2a5516c84b6eab675
# removed struct vm_area_struct as an argument for vm_operations since
# in the same kernel version struct vma_area_struct was folded into
# struct vm_fault.
#
AC_DEFUN([LC_VM_OPERATIONS_REMOVE_VMF_ARG], [
LB_CHECK_COMPILE([if 'struct vm_operations' removed struct vm_area_struct],
vm_operations_no_vm_area_struct, [
	#include <linux/mm.h>
],[
	struct vm_fault vmf;

	((struct vm_operations_struct *)0)->fault(&vmf);
	((struct vm_operations_struct *)0)->page_mkwrite(&vmf);
],[
	AC_DEFINE(HAVE_VM_OPS_USE_VM_FAULT_ONLY, 1,
		['struct vm_operations' remove struct vm_area_struct argument])
])
]) # LC_VM_OPERATIONS_REMOVE_VMF_ARG

#
# LC_HAVE_KEY_USAGE_REFCOUNT
#
# Kernel version 4.11 commit fff292914d3a2f1efd05ca71c2ba72a3c663201e
# converted key.usage from atomic_t to refcount_t.
#
AC_DEFUN([LC_HAVE_KEY_USAGE_REFCOUNT], [
LB_CHECK_COMPILE([if 'key.usage' is refcount_t],
key_usage_refcount, [
	#include <linux/key.h>
],[
	struct key key = { };

	refcount_read(&key.usage);
],[
	AC_DEFINE(HAVE_KEY_USAGE_REFCOUNT, 1, [key.usage is of type refcount_t])
])
]) #LC_HAVE_KEY_USAGE_REFCOUNT

#
# LC_HAVE_CRYPTO_MAX_ALG_NAME_128
#
# Kernel version 4.11 commit f437a3f477cce402dbec6537b29e9e33962c9f73
# switched CRYPTO_MAX_ALG_NAME from 64 to 128.
#
AC_DEFUN([LC_HAVE_CRYPTO_MAX_ALG_NAME_128], [
LB_CHECK_COMPILE([if 'CRYPTO_MAX_ALG_NAME' is 128],
crypto_max_alg_name, [
	#include <linux/crypto.h>
],[
	#if CRYPTO_MAX_ALG_NAME != 128
	exit(1);
	#endif
],[
	AC_DEFINE(HAVE_CRYPTO_MAX_ALG_NAME_128, 1,
		['CRYPTO_MAX_ALG_NAME' is 128])
])
]) # LC_HAVE_CRYPTO_MAX_ALG_NAME_128

#
# Kernel version 4.12 commit 47f38c539e9a42344ff5a664942075bd4df93876
# CURRENT_TIME is not 64 bit time safe so it was replaced with
# current_time()
#
AC_DEFUN([LC_CURRENT_TIME], [
LB_CHECK_COMPILE([if CURRENT_TIME has been replaced with current_time],
current_time, [
	#include <linux/fs.h>
],[
	struct iattr attr;

	attr.ia_atime = current_time(NULL);
],[
	AC_DEFINE(HAVE_CURRENT_TIME, 1,
		[current_time() has replaced CURRENT_TIME])
])
]) # LIBCFS_CURRENT_TIME

#
# Kernel version 4.12-rc3 85787090a21eb749d8b347eaf9ff1a455637473c
# changed struct super_block s_uuid into a proper uuid_t
#
AC_DEFUN([LC_SUPER_BLOCK_S_UUID], [
LB_CHECK_COMPILE([if 'struct super_block' s_uuid is uuid_t],
super_block_s_uuid, [
	#include <linux/fs.h>
],[
	struct super_block sb;

	uuid_parse(NULL, &sb.s_uuid);
],[
	AC_DEFINE(HAVE_S_UUID_AS_UUID_T, 1, ['s_uuid' is an uuid_t])
])
]) # LC_SUPER_BLOCK_S_UUID

#
# LC_SUPER_SETUP_BDI_NAME
#
# Kernel version 4.12 commit 9594caf216dc0fe3e318b34af0127276db661241
# unified bdi handling
#
AC_DEFUN([LC_SUPER_SETUP_BDI_NAME], [
LB_CHECK_COMPILE([if 'super_setup_bdi_name' exist],
super_setup_bdi_name, [
	#include <linux/fs.h>
],[
	super_setup_bdi_name(NULL, "lustre");
],[
	AC_DEFINE(HAVE_SUPER_SETUP_BDI_NAME, 1,
		['super_setup_bdi_name' is available])
])
]) # LC_SUPER_SETUP_BDI_NAME

#
# LC_BI_STATUS
#
# 4.12 replace bi_error to bi_status
#
AC_DEFUN([LC_BI_STATUS], [
LB_CHECK_COMPILE([if 'bi_status' exist],
bi_status, [
	#include <linux/blk_types.h>
],[
	((struct bio *)0)->bi_status = 0;
],[
	AC_DEFINE(HAVE_BI_STATUS, 1,
		['bi_status' is available])
])
]) # LC_BI_STATUS

#
# LC_BIO_INTEGRITY_ENABLED
#
# 4.13 removed bio_integrity_enabled
#
AC_DEFUN([LC_BIO_INTEGRITY_ENABLED], [
LB_CHECK_COMPILE([if 'bio_integrity_enabled' exist],
bio_integrity_enabled, [
	#include <linux/bio.h>
],[
	bio_integrity_enabled(NULL);
],[
	AC_DEFINE(HAVE_BIO_INTEGRITY_ENABLED, 1,
		['bio_integrity_enabled' is available])
])
]) # LC_BIO_INTEGRITY_ENABLED

#
# LC_PAGEVEC_INIT_ONE_PARAM
#
# 4.14 pagevec_init takes one parameter
#
AC_DEFUN([LC_PAGEVEC_INIT_ONE_PARAM], [
LB_CHECK_COMPILE([if 'pagevec_init' takes one parameter],
pagevec_init, [
	#include <linux/pagevec.h>
],[
	pagevec_init(NULL);
],[
	AC_DEFINE(HAVE_PAGEVEC_INIT_ONE_PARAM, 1,
		['pagevec_init' takes one parameter])
])
]) # LC_PAGEVEC_INIT_ONE_PARAM

#
# LC_BI_BDEV
#
# 4.14 replaced bi_bdev to bi_disk
#
AC_DEFUN([LC_BI_BDEV], [
LB_CHECK_COMPILE([if 'bi_bdev' exist],
bi_bdev, [
	#include <linux/bio.h>
],[
	((struct bio *)0)->bi_bdev = NULL;
],[
	AC_DEFINE(HAVE_BI_BDEV, 1,
		['bi_bdev' is available])
])
]) # LC_BI_BDEV

#
# LC_IS_ENCRYPTED
#
# 4.14 introduced IS_ENCRYPTED and S_ENCRYPTED
#
AC_DEFUN([LC_IS_ENCRYPTED], [
LB_CHECK_COMPILE([if IS_ENCRYPTED is defined],
is_encrypted, [
	#include <linux/fs.h>
],[
	IS_ENCRYPTED((struct inode *)0);
],[
	has_is_encrypted="yes"
])
]) # LC_IS_ENCRYPTED

#
# LC_I_PAGES
#
# kernel 4.17 commit b93b016313b3ba8003c3b8bb71f569af91f19fc7
#
AC_DEFUN([LC_I_PAGES], [
LB_CHECK_COMPILE([if struct address_space has i_pages],
i_pages, [
	#include <linux/fs.h>
],[
	struct address_space mapping = {};
	void *i_pages;

	i_pages = &mapping.i_pages;
],[
	AC_DEFINE(HAVE_I_PAGES, 1,
		[struct address_space has i_pages])
])
]) # LC_I_PAGES

#
# LC_VM_FAULT_T
#
# kernel 4.17 commit 3d3539018d2cbd12e5af4a132636ee7fd8d43ef0
# mm: create the new vm_fault_t type
#
AC_DEFUN([LC_VM_FAULT_T], [
LB_CHECK_COMPILE([if vm_fault_t type exists],
vm_fault_t, [
	#include <linux/mm_types.h>
],[
	vm_fault_t x = VM_FAULT_SIGBUS;
	(void)x
],[
	AC_DEFINE(HAVE_VM_FAULT_T, 1,
		[if vm_fault_t type exists])
])
]) # LC_VM_FAULT_T

#
# LC_VM_FAULT_RETRY
#
# kernel 4.17 commit 3d3539018d2cbd12e5af4a132636ee7fd8d43ef0
# mm: VM_FAULT_RETRY is defined in enum vm_fault_reason
#
AC_DEFUN([LC_VM_FAULT_RETRY], [
LB_CHECK_COMPILE([if VM_FAULT_RETRY is defined],
VM_FAULT_RETRY, [
	#include <linux/mm.h>
],[
	#ifndef VM_FAULT_RETRY
		vm_fault_t x;
		x = VM_FAULT_RETRY;
	#endif
],[
	AC_DEFINE(HAVE_VM_FAULT_RETRY, 1,
		[if VM_FAULT_RETRY is defined])
])
]) # LC_VM_FAULT_RETRY

#
# LC_INODE_TIMESPEC64
#
# kernel 4.17-rc7 commit 8efd6894ff089adeeac7cb9f32125b85d963d1bc
# fs: add timespec64_truncate()
# kernel 4.18 commit 95582b00838837fc07e042979320caf917ce3fe6
# inode timestamps switched to timespec64
# kernel 4.19-rc2 commit 976516404ff3fab2a8caa8bd6f5efc1437fed0b8
# y2038: remove unused time interfaces
# ...
#  timespec_trunc
# ...
# When inode times are timespec64 stop using the deprecated
# time interfaces.
#
# kernel v5.5-rc1-6-gba70609d5ec6 ba70609d5ec664a8f36ba1c857fcd97a478adf79
# fs: Delete timespec64_trunc()
#
AC_DEFUN([LC_INODE_TIMESPEC64], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if inode timestamps are struct timespec64],
inode_timespec64, [
	#include <linux/fs.h>
],[
	struct inode *inode = NULL;
	struct timespec64 ts = {0, 1};

	inode->i_atime = ts;
	(void)inode;
],[
	AC_DEFINE(HAVE_INODE_TIMESPEC64, 1,
		[inode times are using timespec64])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_INODE_TIMESPEC64

#
# LC___XA_SET_MARK
#
# kernel 4.20 commit v4.19-rc5-248-g9b89a0355144
# xarray: Add XArray marks - replaced radix_tree_tag_set
#
AC_DEFUN([LC___XA_SET_MARK], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if '__xa_set_mark' exists],
__xa_set_mark, [
	#include <linux/fs.h>
	#include <linux/radix-tree.h>
],[
	radix_tree_tag_set(NULL, 0, PAGECACHE_TAG_DIRTY);
],[
	AC_DEFINE(HAVE_RADIX_TREE_TAG_SET, 1,
		[__xa_set_mark exists])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC___XA_SET_MARK

#
# LC_UAPI_LINUX_MOUNT_H
#
# kernel 4.20 commit e262e32d6bde0f77fb0c95d977482fc872c51996
# vfs: Suppress MS_* flag defs within the kernel ...
#
AC_DEFUN([LC_UAPI_LINUX_MOUNT_H], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if MS_RDONLY was moved to uapi/linux/mount.h],
uapi_linux_mount, [
	#include <uapi/linux/mount.h>
],[
	int x = MS_RDONLY;
	(void)x;
],[
	AC_DEFINE(HAVE_UAPI_LINUX_MOUNT_H, 1,
		[if MS_RDONLY was moved to uapi/linux/mount.h])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_UAPI_LINUX_MOUNT_H

#
# LC_HAVE_SUNRPC_CACHE_HASH_LOCK_IS_A_SPINLOCK
#
# kernel 4.20 commit 1863d77f15da0addcd293a1719fa5d3ef8cde3ca
# SUNRPC: Replace the cache_detail->hash_lock with a regular spinlock
#
# Now that the reader functions are all RCU protected, use a regular
# spinlock rather than a reader/writer lock.
#
AC_DEFUN([LC_HAVE_SUNRPC_CACHE_HASH_LOCK_IS_A_SPINLOCK], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if cache_detail->hash_lock is a spinlock],
hash_lock_isa_spinlock_t, [
	#include <linux/sunrpc/cache.h>
],[
	spinlock_t *lock = &(((struct cache_detail *)0)->hash_lock);
	spin_lock(lock);
],[
	AC_DEFINE(HAVE_CACHE_HASH_SPINLOCK, 1,
		[if cache_detail->hash_lock is a spinlock])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_HAVE_SUNRPC_CACHE_HASH_LOCK_IS_A_SPINLOCK

#
# LC_HAS_LINUX_SELINUX_ENABLED
#
# kernel 5.1 commit 3d252529480c68bfd6a6774652df7c8968b28e41
# SELinux: Remove unused selinux_is_enabled
#
AC_DEFUN([LC_HAS_LINUX_SELINUX_ENABLED], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if linux/selinux.h exists],
selinux_is_enabled, [
	#include <linux/selinux.h>
],[
	bool has_selinux = selinux_is_enabled();
	(void)has_selinux;
],[
	AC_DEFINE(HAVE_LINUX_SELINUX_IS_ENABLED, 1,
		[if linux/selinux.h exists])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_HAS_LINUX_SELINUX_ENABLED

#
# LB_HAVE_BVEC_ITER_ALL
#
# kernel 5.1 commit 6dc4f100c175dd0511ae8674786e7c9006cdfbfa
# block: allow bio_for_each_segment_all() to iterate over multi-page bvec
#
AC_DEFUN([LB_HAVE_BVEC_ITER_ALL], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if bvec_iter_all exists for multi-page bvec iternation],
ext4fs_dirhash, [
	#include <linux/bvec.h>
],[
	struct bvec_iter_all iter;
	(void)iter;
],[
	AC_DEFINE(HAVE_BVEC_ITER_ALL, 1,
		[if bvec_iter_all exists for multi-page bvec iternation])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LB_HAVE_BVEC_ITER_ALL

#
# LC_ACCOUNT_PAGE_DIRTIED
#
# After 5.2 kernel page dirtied is not exported
#
AC_DEFUN([LC_ACCOUNT_PAGE_DIRTIED], [
LB_CHECK_EXPORT([account_page_dirtied], [mm/page-writeback.c],
	[AC_DEFINE(HAVE_ACCOUNT_PAGE_DIRTIED_EXPORT, 1,
			[account_page_dirtied is exported])])
]) # LC_ACCOUNT_PAGE_DIRTIED

#
# LC_KEYRING_SEARCH_4ARGS
#
# Kernel 5.2 commit dcf49dbc8077
# keys: Add a 'recurse' flag for keyring searches
#
AC_DEFUN([LC_KEYRING_SEARCH_4ARGS], [
LB_CHECK_COMPILE([if 'keyring_search' has 4 args],
keyring_search_4args, [
	#include <linux/key.h>
],[
	key_ref_t keyring;
	keyring_search(keyring, NULL, NULL, false);
],[
	AC_DEFINE(HAVE_KEYRING_SEARCH_4ARGS, 1,
		[keyring_search has 4 args])
])
]) # LC_KEYRING_SEARCH_4ARGS

#
# LC_BIO_BI_PHYS_SEGMENTS
#
# kernel 5.3-rc1 commit 14ccb66b3f585b2bc21e7256c96090abed5a512c
# block: remove the bi_phys_segments field in struct bio
#
AC_DEFUN([LC_BIO_BI_PHYS_SEGMENTS], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if struct bio has bi_phys_segments member],
bye_bio_bi_phys_segments, [
	#include <linux/bio.h>
],[
	struct bio *bio = NULL;
	bio->bi_phys_segments++;
],[
	AC_DEFINE(HAVE_BIO_BI_PHYS_SEGMENTS, 1,
		[struct bio has bi_phys_segments member])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_BIO_BI_PHYS_SEGMENTS

#
# LC_LM_COMPARE_OWNER_EXISTS
#
# kernel 5.3-rc3 commit f85d93385e9fe6886a751f647f6812a89bf6bee3
# locks: Cleanup lm_compare_owner and lm_owner_key
# removed lm_compare_owner
#
AC_DEFUN([LC_LM_COMPARE_OWNER_EXISTS], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if lock_manager_operations has lm_compare_owner],
lock_manager_ops_lm_compare_owner, [
	#include <linux/fs.h>
],[
	struct lock_manager_operations lm_ops;
	lm_ops.lm_compare_owner = NULL;
],[
	AC_DEFINE(HAVE_LM_COMPARE_OWNER, 1,
		[lock_manager_operations has lm_compare_owner])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_LM_COMPARE_OWNER_EXISTS

AC_DEFUN([LC_PROG_LINUX_SRC], [])
AC_DEFUN([LC_PROG_LINUX_RESULTS], [])

#
# LC_FSCRYPT_SUPPORT
#
# 5.4 introduced fscrypt encryption policies v2
#
AC_DEFUN([LC_FSCRYPT_SUPPORT], [
LB_CHECK_COMPILE([for fscrypt in-kernel support],
fscrypt_support, [
	#define __FS_HAS_ENCRYPTION 0
	#include <linux/fscrypt.h>
],[
	fscrypt_ioctl_get_policy_ex(NULL, NULL);
],[
	dnl When Lustre supports file name encryption, restore "yes" value
	dnl for has_fscrypt_support and remove warning message.
	has_fscrypt_support="no"
	AC_MSG_WARN([
This version of Lustre lacks file name encryption support,
so it cannot make use of in-kernel fscrypt.
Will use embedded llcrypt if possible.])
])
]) # LC_FSCRYPT_SUPPORT

#
# LC_PROG_LINUX
#
# Lustre linux kernel checks
#
AC_DEFUN([LC_PROG_LINUX], [
	AC_MSG_NOTICE([Lustre kernel checks
==============================================================================])

	LC_CONFIG_PINGER
	LC_CONFIG_CHECKSUM
	LC_CONFIG_FLOCK
	LC_CONFIG_HEALTH_CHECK_WRITE
	LC_CONFIG_LRU_RESIZE
	LC_CONFIG_FHANDLE
	LC_CONFIG_GSS

	LC_GLIBC_SUPPORT_FHANDLES
	LC_GLIBC_SUPPORT_COPY_FILE_RANGE
	LC_OPENSSL_SSK
	LC_OPENSSL_GETSEPOL

	# 3.10
	LC_HAVE_PROJECT_QUOTA

	# 3.11
	LC_INVALIDATE_RANGE
	LC_HAVE_DIR_CONTEXT
	LC_D_COMPARE_5ARGS
	LC_HAVE_DCOUNT
	LC_HAVE_DENTRY_D_U_D_ALIAS
	LC_HAVE_DENTRY_D_CHILD
	LC_PID_NS_FOR_CHILDREN

	# 3.12
	LC_OLDSIZE_TRUNCATE_PAGECACHE
	LC_PTR_ERR_OR_ZERO_MISSING
	LC_KIOCB_KI_LEFT

	# 3.13
	LC_VFS_RENAME_5ARGS
	LC_VFS_UNLINK_3ARGS
	LC_HAVE_D_IS_POSITIVE

	# 3.14
	LC_HAVE_BVEC_ITER
	LC_HAVE_TRUNCATE_IPAGES_FINAL
	LC_IOPS_RENAME_WITH_FLAGS
	LC_IOP_SET_ACL

	# 3.15
	LC_VFS_RENAME_6ARGS

	# 3.16
	LC_DIRECTIO_USE_ITER
	LC_HAVE_IOV_ITER_INIT_DIRECTION
	LC_HAVE_IOV_ITER_TRUNCATE
	LC_HAVE_FILE_OPERATIONS_READ_WRITE_ITER

	# 3.17
	LC_HAVE_INTERVAL_BLK_INTEGRITY
	LC_KEY_MATCH_DATA

	# 3.18
	LC_PERCPU_COUNTER_INIT
	LC_NFS_FILLDIR_USE_CTX

	# 3.19
	LC_KIOCB_HAS_NBYTES
	LC_HAVE_DQUOT_QC_DQBLK
	LC_HAVE_AIO_COMPLETE

	# 3.20
	LC_BACKING_DEV_INFO_REMOVAL
	LC_HAVE_BDI_CAP_MAP_COPY

	# 4.1.0
	LC_IOV_ITER_RW
	LC_HAVE_SYNC_READ_WRITE
	LC_HAVE___BI_CNT

	# 4.2
	LC_BIO_ENDIO_USES_ONE_ARG
	LC_SYMLINK_OPS_USE_NAMEIDATA
	LC_ACCOUNT_PAGE_DIRTIED_3ARGS
	LC_HAVE_CRYPTO_ALLOC_SKCIPHER

	# 4.3
	LC_HAVE_INTERVAL_EXP_BLK_INTEGRITY
	LC_HAVE_BIP_ITER_BIO_INTEGRITY_PAYLOAD
	LC_HAVE_CACHE_HEAD_HLIST
	LC_HAVE_XATTR_HANDLER_SIMPLIFIED

	# 4.4
	LC_HAVE_LOCKS_LOCK_FILE_WAIT
	LC_HAVE_KEY_PAYLOAD_DATA_ARRAY
	LC_HAVE_XATTR_HANDLER_NAME
	LC_HAVE_BI_OPF
	LC_HAVE_SUBMIT_BIO_2ARGS
	LC_HAVE_CLEAN_BDEV_ALIASES

	# 4.5
	LC_HAVE_FILE_DENTRY

	# 4.5
	LC_HAVE_INODE_LOCK
	LC_HAVE_IOP_GET_LINK

	# 4.6
	LC_HAVE_IN_COMPAT_SYSCALL
	LC_HAVE_XATTR_HANDLER_INODE_PARAM
	LC_LOCK_PAGE_MEMCG

	# 4.7
	LC_D_IN_LOOKUP
	LC_DIRECTIO_2ARGS
	LC_GENERIC_WRITE_SYNC_2ARGS
	LC_FOP_ITERATE_SHARED

	# 4.8
	LC_EXPORT_DEFAULT_FILE_SPLICE_READ
	LC_HAVE_POSIX_ACL_VALID_USER_NS
	LC_D_COMPARE_4ARGS
	LC_FULL_NAME_HASH_3ARGS
	LC_STRUCT_POSIX_ACL_XATTR
	LC_IOP_XATTR

	# 4.9
	LC_GROUP_INFO_GID
	LC_VFS_SETXATTR
	LC_POSIX_ACL_UPDATE_MODE

	# 4.10
	LC_IOP_GENERIC_READLINK
	LC_HAVE_VM_FAULT_ADDRESS

	# 4.11
	LC_INODEOPS_ENHANCED_GETATTR
	LC_VM_OPERATIONS_REMOVE_VMF_ARG
	LC_HAVE_KEY_USAGE_REFCOUNT
	LC_HAVE_CRYPTO_MAX_ALG_NAME_128

	# 4.12
	LC_CURRENT_TIME
	LC_SUPER_BLOCK_S_UUID
	LC_SUPER_SETUP_BDI_NAME
	LC_BI_STATUS

	# 4.13
	LC_BIO_INTEGRITY_ENABLED

	# 4.14
	LC_PAGEVEC_INIT_ONE_PARAM
	LC_BI_BDEV

	# 4.17
	LC_VM_FAULT_T
	LC_VM_FAULT_RETRY
	LC_I_PAGES

	# 4.18
	LC_INODE_TIMESPEC64

	# 4.20
	LC___XA_SET_MARK
	LC_UAPI_LINUX_MOUNT_H
	LC_HAVE_SUNRPC_CACHE_HASH_LOCK_IS_A_SPINLOCK

	# 5.1
	LC_HAS_LINUX_SELINUX_ENABLED
	LB_HAVE_BVEC_ITER_ALL

	# 5.2
	LC_ACCOUNT_PAGE_DIRTIED
	LC_KEYRING_SEARCH_4ARGS

	# 5.3
	LC_BIO_BI_PHYS_SEGMENTS
	LC_LM_COMPARE_OWNER_EXISTS

	# kernel patch to extend integrity interface
	LC_BIO_INTEGRITY_PREP_FN

	#
	AS_IF([test "x$enable_server" != xno], [
		LC_STACK_SIZE
		LC_QUOTA_CONFIG
	])
	LC_POSIX_ACL_CONFIG
]) # LC_PROG_LINUX

#
# LC_CONFIG_CLIENT
#
# Check whether to build the client side of Lustre
#
AC_DEFUN([LC_CONFIG_CLIENT], [
AC_MSG_CHECKING([whether to build Lustre client support])
AC_ARG_ENABLE([client],
	AC_HELP_STRING([--disable-client],
		[disable Lustre client support]),
	[], [enable_client="yes"])
AC_MSG_RESULT([$enable_client])
]) # LC_CONFIG_CLIENT

#
# --enable-mpitests
#
AC_DEFUN([LB_CONFIG_MPITESTS], [
AC_ARG_ENABLE([mpitests],
	AC_HELP_STRING([--enable-mpitests=<yes|no|mpicc wrapper>],
		       [include mpi tests]), [
		enable_mpitests="yes"
		case $enableval in
		yes)
			MPICC_WRAPPER="mpicc"
			MPI_BIN=$(eval which $MPICC_WRAPPER | xargs dirname)
			;;
		no)
			enable_mpitests="no"
			MPI_BIN=""
			;;
		*)
			MPICC_WRAPPER=$enableval
			MPI_BIN=$(eval echo $MPICC_WRAPPER | xargs dirname)
			;;
		esac
	], [
		enable_mpitests="yes"
		MPICC_WRAPPER="mpicc"
		MPI_BIN=$(eval which $MPICC_WRAPPER | xargs dirname)
	])

	if test "x$enable_mpitests" != "xno"; then
		oldcc=$CC
		CC=$MPICC_WRAPPER
		AC_CACHE_CHECK([whether mpitests can be built],
		lb_cv_mpi_tests, [AC_COMPILE_IFELSE([AC_LANG_SOURCE([
			#include <mpi.h>
			int main(void) {
				int flag;
				MPI_Initialized(&flag);
				return 0;
			}
		])], [lb_cv_mpi_tests="yes"], [lb_cv_mpi_tests="no"])
		])
		enable_mpitests=$lb_cv_mpi_tests
		CC=$oldcc
	fi
	AC_SUBST(MPI_BIN)
	AC_SUBST(MPICC_WRAPPER)
]) # LB_CONFIG_MPITESTS

#
# LC_CONFIG_QUOTA
#
# whether to enable quota support global control
#
AC_DEFUN([LC_CONFIG_QUOTA], [
AC_MSG_CHECKING([whether to enable quota support global control])
AC_ARG_ENABLE([quota],
	AC_HELP_STRING([--enable-quota],
		[enable quota support]),
	[], [enable_quota="yes"])
AS_IF([test "x$enable_quota" = xyes],
	[AC_MSG_RESULT([yes])],
	[AC_MSG_RESULT([no])])
]) # LC_CONFIG_QUOTA

#
# LC_QUOTA
#
AC_DEFUN([LC_QUOTA], [
#check global
LC_CONFIG_QUOTA
#check for utils
AS_IF([test "x$enable_quota" != xno -a "x$enable_utils" != xno], [
	AC_CHECK_HEADER([sys/quota.h],
		[AC_DEFINE(HAVE_SYS_QUOTA_H, 1,
			[Define to 1 if you have <sys/quota.h>.])],
		[AC_MSG_ERROR([don't find <sys/quota.h> in your system])])
])
]) # LC_QUOTA

#
# LC_OSD_ADDON
#
# configure support for optional OSD implementation
#
AC_DEFUN([LC_OSD_ADDON], [
AC_MSG_CHECKING([whether to use OSD addon])
AC_ARG_WITH([osd],
	AC_HELP_STRING([--with-osd=path],
		[set path to optional osd]),
	[
	case "$with_osd" in
	no)
		ENABLEOSDADDON=0
		;;
	*)
		OSDADDON="$with_osd"
		ENABLEOSDADDON=1
		;;
	esac
	], [
		ENABLEOSDADDON=0
	])
AS_IF([test $ENABLEOSDADDON -eq 0], [
	AC_MSG_RESULT([no])
	OSDADDON=""
], [
	OSDMODNAME=$(basename $OSDADDON)
	AS_IF([test -e $LUSTRE/$OSDMODNAME], [
		AC_MSG_RESULT([can't link])
		OSDADDON=""
	], [ln -s $OSDADDON $LUSTRE/$OSDMODNAME], [
		AC_MSG_RESULT([$OSDMODNAME])
		OSDADDON="obj-m += $OSDMODNAME/"
	], [
		AC_MSG_RESULT([can't link])
		OSDADDON=""
	])
])
AC_SUBST(OSDADDON)
]) # LC_OSD_ADDON

#
# LC_CONFIG_CRYPTO
#
# Check whether to enable Lustre client crypto
#
AC_DEFUN([LC_CONFIG_CRYPTO], [
AC_MSG_CHECKING([whether to enable Lustre client crypto])
AC_ARG_ENABLE([crypto],
	AC_HELP_STRING([--enable-crypto],
		[enable Lustre client crypto]),
	[], [enable_crypto="auto"])
AS_IF([test "x$enable_crypto" != xno -a "x$enable_dist" = xno], [
	AC_MSG_RESULT(
	)
	LC_IS_ENCRYPTED
	LC_FSCRYPT_SUPPORT])
AS_IF([test "x$has_fscrypt_support" = xyes], [
	AC_DEFINE(HAVE_LUSTRE_CRYPTO, 1, [Enable Lustre client crypto via in-kernel fscrypt])
	enable_crypto=yes],
	[AS_IF([test "x$has_is_encrypted" = xyes], [
	      AC_DEFINE(HAVE_LUSTRE_CRYPTO, 1, [Enable Lustre client crypto via embedded llcrypt])
	      AC_DEFINE(CONFIG_LL_ENCRYPTION, 1, [embedded llcrypt])
	      enable_crypto=yes
	      enable_llcrypt=yes], [
	      AS_IF([test "x$enable_crypto" = xyes],
	            [AC_MSG_ERROR([Lustre client crypto cannot be enabled because of lack of encryption support in your kernel.])])
	      AS_IF([test "x$enable_crypto" != xno -a "x$enable_dist" = xno],
	            [AC_MSG_WARN(Lustre client crypto cannot be enabled because of lack of encryption support in your kernel.)])
	      enable_crypto=no])])
AS_IF([test "x$enable_dist" != xno], [
	enable_crypto=yes
	enable_llcrypt=yes])
AC_MSG_RESULT([$enable_crypto])
]) # LC_CONFIG_CRYPTO

#
# LC_CONFIGURE
#
# other configure checks
#
AC_DEFUN([LC_CONFIGURE], [
AC_MSG_NOTICE([Lustre core checks
==============================================================================])

AS_IF([test $target_cpu == "i686" -o $target_cpu == "x86_64"],
	[CFLAGS="$CFLAGS -Wall -Werror"])

# maximum MDS thread count
LC_MDS_MAX_THREADS

# lustre/utils/gss/gss_util.c
# lustre/utils/gss/gssd_proc.c
# lustre/utils/gss/krb5_util.c
# lustre/utils/llog_reader.c
# lustre/utils/create_iam.c
# lustre/utils/libiam.c
AC_CHECK_HEADERS([netdb.h endian.h])
AC_CHECK_FUNCS([gethostbyname])

# lustre/utils/llverfs.c lustre/utils/libmount_utils_ldiskfs.c
AC_CHECK_HEADERS([ext2fs/ext2fs.h], [], [
	AS_IF([test "x$enable_utils" = xyes -a "x$enable_ldiskfs" = xyes], [
		AC_MSG_ERROR([
ext2fs.h not found. Please install e2fsprogs development package.
		])
	])
])

# lustre/tests/statx_test.c
AC_CHECK_FUNCS([statx])

# lustre/utils/lfs.c
AS_IF([test "$enable_dist" = "no"], [
		AC_CHECK_LIB([z], [crc32], [
				 AC_CHECK_HEADER([zlib.h], [], [
						 AC_MSG_ERROR([zlib.h not found.])])
				 ], [
				 AC_MSG_ERROR([
		zlib library not found. Please install zlib development package.])
		])
])

SELINUX=""

AC_CHECK_LIB([selinux], [is_selinux_enabled],
	[AC_CHECK_HEADERS([selinux/selinux.h],
			[SELINUX="-lselinux"
			AC_DEFINE([HAVE_SELINUX], 1,
				[support for selinux ])],
			[AC_MSG_WARN([

No libselinux-devel package found, unable to build selinux enabled tools
])
])],
	[AC_MSG_WARN([

No selinux package found, unable to build selinux enabled tools
])
])
AC_SUBST(SELINUX)

AC_CHECK_LIB([keyutils], [add_key])

# Super safe df
AC_MSG_CHECKING([whether to report minimum OST free space])
AC_ARG_ENABLE([mindf],
	AC_HELP_STRING([--enable-mindf],
		[Make statfs report the minimum available space on any single OST instead of the sum of free space on all OSTs]),
	[], [enable_mindf="no"])
AC_MSG_RESULT([$enable_mindf])
AS_IF([test "$enable_mindf" = "yes"],
	[AC_DEFINE([MIN_DF], 1, [Report minimum OST free space])])

AC_MSG_CHECKING([whether to randomly failing memory alloc])
AC_ARG_ENABLE([fail_alloc],
	AC_HELP_STRING([--disable-fail-alloc],
		[disable randomly alloc failure]),
	[], [enable_fail_alloc="yes"])
AC_MSG_RESULT([$enable_fail_alloc])
AS_IF([test "x$enable_fail_alloc" != xno],
	[AC_DEFINE([RANDOM_FAIL_ALLOC], 1,
		[enable randomly alloc failure])])

AC_MSG_CHECKING([whether to check invariants (expensive cpu-wise)])
AC_ARG_ENABLE([invariants],
	AC_HELP_STRING([--enable-invariants],
		[enable invariant checking (cpu intensive)]),
	[], [enable_invariants="no"])
AC_MSG_RESULT([$enable_invariants])
AS_IF([test "x$enable_invariants" = xyes],
	[AC_DEFINE([CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK], 1,
		[enable invariant checking])])

AC_MSG_CHECKING([whether to track references with lu_ref])
AC_ARG_ENABLE([lu_ref],
	AC_HELP_STRING([--enable-lu_ref],
		[enable lu_ref reference tracking code]),
	[], [enable_lu_ref="no"])
AC_MSG_RESULT([$enable_lu_ref])
AS_IF([test "x$enable_lu_ref" = xyes],
	[AC_DEFINE([USE_LU_REF], 1,
		[enable lu_ref reference tracking code])])

AC_MSG_CHECKING([whether to enable page state tracking])
AC_ARG_ENABLE([pgstate-track],
	AC_HELP_STRING([--enable-pgstate-track],
		[enable page state tracking]),
	[], [enable_pgstat_track="no"])
AC_MSG_RESULT([$enable_pgstat_track])
AS_IF([test "x$enable_pgstat_track" = xyes],
	[AC_DEFINE([CONFIG_DEBUG_PAGESTATE_TRACKING], 1,
		[enable page state tracking code])])

PKG_PROG_PKG_CONFIG
AC_MSG_CHECKING([systemd unit file directory])
AC_ARG_WITH([systemdsystemunitdir],
	[AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
		[Directory for systemd service files])],
	[], [with_systemdsystemunitdir=auto])
AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"],
	[def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
	AS_IF([test "x$def_systemdsystemunitdir" = "x"],
		[AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
		[AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
		with_systemdsystemunitdir=no],
	[with_systemdsystemunitdir="$def_systemdsystemunitdir"])])
AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
	[AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AC_MSG_RESULT([$with_systemdsystemunitdir])

AC_MSG_CHECKING([bash-completion directory])
AC_ARG_WITH([bash-completion-dir],
	AS_HELP_STRING([--with-bash-completion-dir[=PATH]],
		[Install the bash auto-completion script in this directory.]),
	[],
	[with_bash_completion_dir=yes])
AS_IF([test "x$with_bash_completion_dir" = "xyes"], [
	BASH_COMPLETION_DIR="`pkg-config --variable=completionsdir bash-completion`"
	AS_IF([test "x$BASH_COMPLETION_DIR" = "x"], [
		[BASH_COMPLETION_DIR="/usr/share/bash-completion/completions"]
	])
], [
	BASH_COMPLETION_DIR="$with_bash_completion_dir"
])
AC_SUBST([BASH_COMPLETION_DIR])
AC_MSG_RESULT([$BASH_COMPLETION_DIR])
]) # LC_CONFIGURE

#
# LC_CONDITIONALS
#
# AM_CONDITIONALS for lustre
#
AC_DEFUN([LC_CONDITIONALS], [
AM_CONDITIONAL(MPITESTS, test x$enable_mpitests = xyes, Build MPI Tests)
AM_CONDITIONAL(CLIENT, test x$enable_client = xyes)
AM_CONDITIONAL(SERVER, test x$enable_server = xyes)
AM_CONDITIONAL(SPLIT, test x$enable_split = xyes)
AM_CONDITIONAL(EXT2FS_DEVEL, test x$ac_cv_header_ext2fs_ext2fs_h = xyes)
AM_CONDITIONAL(GSS, test x$enable_gss = xyes)
AM_CONDITIONAL(GSS_KEYRING, test x$enable_gss_keyring = xyes)
AM_CONDITIONAL(GSS_PIPEFS, test x$enable_gss_pipefs = xyes)
AM_CONDITIONAL(GSS_SSK, test x$enable_ssk = xyes)
AM_CONDITIONAL(LIBPTHREAD, test x$enable_libpthread = xyes)
AM_CONDITIONAL(HAVE_SYSTEMD, test "x$with_systemdsystemunitdir" != "xno")
AM_CONDITIONAL(ENABLE_BASH_COMPLETION, test "x$with_bash_completion_dir" != "xno")
AM_CONDITIONAL(XATTR_HANDLER, test "x$lb_cv_compile_xattr_handler_flags" = xyes)
AM_CONDITIONAL(SELINUX, test "$SELINUX" = "-lselinux")
AM_CONDITIONAL(GETSEPOL, test x$enable_getsepol = xyes)
AM_CONDITIONAL(LLCRYPT, test x$enable_llcrypt = xyes)
AM_CONDITIONAL(LIBAIO, test x$enable_libaio = xyes)
]) # LC_CONDITIONALS

#
# LC_CONFIG_FILES
#
# files that should be generated with AC_OUTPUT
#
AC_DEFUN([LC_CONFIG_FILES],
[AC_CONFIG_FILES([
lustre/Makefile
lustre/autoMakefile
lustre/autoconf/Makefile
lustre/conf/Makefile
lustre/conf/resource/Makefile
lustre/contrib/Makefile
lustre/doc/Makefile
lustre/include/Makefile
lustre/include/lustre/Makefile
lustre/include/uapi/linux/lustre/Makefile
lustre/kernel_patches/targets/4.18-rhel8.4.target
lustre/kernel_patches/targets/4.18-rhel8.3.target
lustre/kernel_patches/targets/4.18-rhel8.2.target
lustre/kernel_patches/targets/4.18-rhel8.1.target
lustre/kernel_patches/targets/4.18-rhel8.target
lustre/kernel_patches/targets/3.10-rhel7.9.target
lustre/kernel_patches/targets/3.10-rhel7.8.target
lustre/kernel_patches/targets/3.10-rhel7.7.target
lustre/kernel_patches/targets/3.10-rhel7.6.target
lustre/kernel_patches/targets/3.10-rhel7.5.target
lustre/kernel_patches/targets/4.14-rhel7.5.target
lustre/kernel_patches/targets/4.14-rhel7.6.target
lustre/kernel_patches/targets/4.12-sles12sp4.target
lustre/kernel_patches/targets/4.12-sles12sp5.target
lustre/kernel_patches/targets/4.12-sles15sp1.target
lustre/kernel_patches/targets/4.12-sles15sp2.target
lustre/kernel_patches/targets/3.x-fc18.target
lustre/ldlm/Makefile
lustre/fid/Makefile
lustre/fid/autoMakefile
lustre/llite/Makefile
lustre/llite/autoMakefile
lustre/lov/Makefile
lustre/lov/autoMakefile
lustre/mdc/Makefile
lustre/mdc/autoMakefile
lustre/lmv/Makefile
lustre/lmv/autoMakefile
lustre/lfsck/Makefile
lustre/lfsck/autoMakefile
lustre/mdt/Makefile
lustre/mdt/autoMakefile
lustre/mdd/Makefile
lustre/mdd/autoMakefile
lustre/fld/Makefile
lustre/fld/autoMakefile
lustre/obdclass/Makefile
lustre/obdclass/autoMakefile
lustre/obdecho/Makefile
lustre/obdecho/autoMakefile
lustre/ofd/Makefile
lustre/ofd/autoMakefile
lustre/osc/Makefile
lustre/osc/autoMakefile
lustre/ost/Makefile
lustre/ost/autoMakefile
lustre/osd-ldiskfs/Makefile
lustre/osd-ldiskfs/autoMakefile
lustre/osd-zfs/Makefile
lustre/osd-zfs/autoMakefile
lustre/mgc/Makefile
lustre/mgc/autoMakefile
lustre/mgs/Makefile
lustre/mgs/autoMakefile
lustre/target/Makefile
lustre/ptlrpc/Makefile
lustre/ptlrpc/autoMakefile
lustre/ptlrpc/gss/Makefile
lustre/ptlrpc/gss/autoMakefile
lustre/quota/Makefile
lustre/quota/autoMakefile
lustre/scripts/Makefile
lustre/scripts/systemd/Makefile
lustre/tests/Makefile
lustre/tests/mpi/Makefile
lustre/tests/kernel/Makefile
lustre/tests/kernel/autoMakefile
lustre/utils/Makefile
lustre/utils/gss/Makefile
lustre/osp/Makefile
lustre/osp/autoMakefile
lustre/lod/Makefile
lustre/lod/autoMakefile
])
]) # LC_CONFIG_FILES
