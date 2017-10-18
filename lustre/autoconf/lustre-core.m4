#
# LC_CONFIG_SRCDIR
#
# Wrapper for AC_CONFIG_SUBDIR
#
AC_DEFUN([LC_CONFIG_SRCDIR], [
AC_CONFIG_SRCDIR([lustre/obdclass/obdo.c])
libcfs_is_module="yes"
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
# LC_CONFIG_OBD_BUFFER_SIZE
#
# the maximum buffer size of lctl ioctls
#
AC_DEFUN([LC_CONFIG_OBD_BUFFER_SIZE], [
AC_MSG_CHECKING([for maximum OBD ioctl size])
AC_ARG_WITH([obd-buffer-size],
	AC_HELP_STRING([--with-obd-buffer-size=[size]],
		[set lctl ioctl maximum bytes (default=8192)]),
	[OBD_BUFFER_SIZE=$with_obd_buffer_size],
	[OBD_BUFFER_SIZE=8192])
AC_MSG_RESULT([$OBD_BUFFER_SIZE bytes])
AC_DEFINE_UNQUOTED(CONFIG_LUSTRE_OBD_MAX_IOCTL_BUFFER, $OBD_BUFFER_SIZE,
	[IOCTL Buffer Size])
]) # LC_CONFIG_OBD_BUFFER_SIZE

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
	[AC_DEFINE(ENABLE_PINGER, 1,[Use the Pinger])])
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
# LC_EXPORT_TRUNCATE_COMPLETE_PAGE
#
# truncate_complete_page() has never been exported from an upstream kernel
# remove_from_page_cache() was exported between 2.6.35 and 2.6.38
# delete_from_page_cache() is exported from 2.6.39
#
AC_DEFUN([LC_EXPORT_TRUNCATE_COMPLETE_PAGE], [
LB_CHECK_EXPORT([truncate_complete_page], [mm/truncate.c],
	[AC_DEFINE(HAVE_TRUNCATE_COMPLETE_PAGE, 1,
		[kernel export truncate_complete_page])])
LB_CHECK_EXPORT([remove_from_page_cache], [mm/filemap.c],
	[AC_DEFINE(HAVE_REMOVE_FROM_PAGE_CACHE, 1,
		[kernel export remove_from_page_cache])])
LB_CHECK_EXPORT([delete_from_page_cache], [mm/filemap.c],
	[AC_DEFINE(HAVE_DELETE_FROM_PAGE_CACHE, 1,
		[kernel export delete_from_page_cache])])
]) # LC_EXPORT_TRUNCATE_COMPLETE_PAGE

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
# LC_HAVE_CRED_TGCRED
#
# rhel7 struct cred has no member tgcred
#
AC_DEFUN([LC_HAVE_CRED_TGCRED], [
LB_CHECK_COMPILE([if 'struct cred' has member 'tgcred'],
cred_tgcred, [
	#include <linux/cred.h>
],[
	((struct cred *)0)->tgcred = NULL;
],[
	AC_DEFINE(HAVE_CRED_TGCRED, 1,
		[struct cred has member tgcred])
])
]) # LC_HAVE_CRED_TGCRED

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
# LC_HAVE_CRYPTO_HASH
#
# 4.6 kernel commit 896545098777564212b9e91af4c973f094649aa7
# removed crypto_hash support. Since GSS only works with
# crypto_hash it has to be disabled for newer distros.
#
AC_DEFUN([LC_HAVE_CRYPTO_HASH], [
LB_CHECK_COMPILE([if crypto_hash API is supported],
crypto_hash, [
	#include <linux/crypto.h>
],[
	crypto_hash_digestsize(NULL);
], [], [enable_gss="no"])
])
]) # LC_HAVE_CRYPTO_HASH

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

AS_IF([test "x$enable_gss" != xno], [
	LC_CONFIG_GSS_KEYRING
	LC_HAVE_CRYPTO_HASH
	LC_HAVE_CRED_TGCRED
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

	AS_IF([test "x$gss_conf_test" = xsuccess], [
		AC_DEFINE([HAVE_GSS], [1], [Define this is if you enable gss])
		enable_gss="yes"
	], [
		enable_gss="no"
	])

	enable_ssk=$enable_gss
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
		HMAC_CTX ctx;
		HMAC_CTX_init(&ctx);
		rc = HMAC_Init_ex(&ctx, "test", 4, EVP_md_null(), NULL);
	}
])],[AC_DEFINE(HAVE_OPENSSL_SSK, 1,
	       [OpenSSL HMAC functions needed for SSK])],
	[enable_ssk="no"])
])
AC_MSG_RESULT([$enable_ssk])
]) # LC_OPENSSL_SSK

# LC_INODE_PERMISION_2ARGS
#
# up to v2.6.27 had a 3 arg version (inode, mask, nameidata)
# v2.6.27->v2.6.37 had a 2 arg version (inode, mask)
# v2.6.37->v3.0 had a 3 arg version (inode, mask, nameidata)
# v3.1 onward have a 2 arg version (inode, mask)
#
AC_DEFUN([LC_INODE_PERMISION_2ARGS], [
LB_CHECK_COMPILE([if 'inode_operations->permission' has two args],
inode_ops_permission_2args, [
	#include <linux/fs.h>
],[
	struct inode *inode __attribute__ ((unused));

	inode = NULL;
	inode->i_op->permission(NULL, 0);
],[
	AC_DEFINE(HAVE_INODE_PERMISION_2ARGS, 1,
		[inode_operations->permission has two args])
])
]) # LC_INODE_PERMISION_2ARGS

#
# LC_BLK_QUEUE_MAX_SEGMENTS
#
# 2.6.32 replaces 2 functions blk_queue_max_phys_segments and blk_queue_max_hw_segments by blk_queue_max_segments
#
AC_DEFUN([LC_BLK_QUEUE_MAX_SEGMENTS], [
LB_CHECK_COMPILE([if 'blk_queue_max_segments' is defined],
blk_queue_max_segments, [
	#include <linux/blkdev.h>
],[
	blk_queue_max_segments(NULL, 0);
],[
	AC_DEFINE(HAVE_BLK_QUEUE_MAX_SEGMENTS, 1,
		[blk_queue_max_segments is defined])
])
]) # LC_BLK_QUEUE_MAX_SEGMENTS

#
# LC_HAVE_XATTR_HANDLER_FLAGS
#
# 2.6.33 added a private flag to xattr_handler
#
AC_DEFUN([LC_HAVE_XATTR_HANDLER_FLAGS], [
LB_CHECK_COMPILE([if 'struct xattr_handler' has flags field],
xattr_handler_flags, [
	#include <linux/xattr.h>
],[
	struct xattr_handler handler;

	handler.flags = 0;
],[
	AC_DEFINE(HAVE_XATTR_HANDLER_FLAGS, 1, [flags field exist])
])
]) # LC_HAVE_XATTR_HANDLER_FLAGS

#
# LC_HAVE_DQUOT_FS_DISK_QUOTA
#
# 2.6.34 has quotactl_ops->[sg]et_dqblk that take struct fs_disk_quota
#
AC_DEFUN([LC_HAVE_DQUOT_FS_DISK_QUOTA], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'quotactl_ops.set_dqblk' takes struct fs_disk_quota],
fs_disk_quota, [
	#include <linux/fs.h>
	#include <linux/quota.h>
],[
	((struct quotactl_ops *)0)->set_dqblk(NULL, 0, 0, (struct fs_disk_quota*)0);
],[
	AC_DEFINE(HAVE_DQUOT_FS_DISK_QUOTA, 1,
		[quotactl_ops.set_dqblk takes struct fs_disk_quota])
],[
	LB_CHECK_COMPILE([if 'quotactl_ops.set_dqblk' takes struct kqid & fs_disk_quota],
	kqid_fs_disk_quota, [
		#include <linux/fs.h>
		#include <linux/quota.h>
	],[
		((struct quotactl_ops *)0)->set_dqblk((struct super_block*)0, *((struct kqid*)0), (struct fs_disk_quota*)0);
	],[
		AC_DEFINE(HAVE_DQUOT_FS_DISK_QUOTA, 1,
			[quotactl_ops.set_dqblk takes struct fs_disk_quota])
		AC_DEFINE(HAVE_DQUOT_KQID, 1,
			[quotactl_ops.set_dqblk takes struct kqid])
	])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_HAVE_DQUOT_FS_DISK_QUOTA

#
# LC_HAVE_DQUOT_SUSPEND
#
# 2.6.34 has renamed dquot options to dquot_*, check for dquot_suspend
#
AC_DEFUN([LC_HAVE_DQUOT_SUSPEND], [
LB_CHECK_COMPILE([if 'dquot_suspend' is defined],
dquot_suspend, [
	#include <linux/quotaops.h>
],[
	dquot_suspend(NULL, -1);
],[
	AC_DEFINE(HAVE_DQUOT_SUSPEND, 1, [dquot_suspend is defined])
])
]) # LC_HAVE_DQUOT_SUSPEND

#
# LC_QUOTA64
#
# Check if kernel has been patched for 64-bit quota limits support.
# The upstream version of this patch in RHEL6 2.6.32 kernels introduces
# the constant QFMT_VFS_V1 in include/linux/quota.h, so we can check for
# that in the absence of quotaio_v1.h in the kernel headers.
#
AC_DEFUN([LC_QUOTA64], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-I$LINUX/fs"
LB_CHECK_COMPILE([if kernel has 64-bit quota limits support],
quota64, [
	#include <linux/kernel.h>
	#include <linux/fs.h>
	#if defined(HAVE_FS_QUOTA_QUOTAIO_H)
	#include <quota/quotaio_v2.h>
	struct v2r1_disk_dqblk dqblk_r1;
	#else
	#include <linux/quota.h>
	int ver = QFMT_VFS_V1;
	#endif
], [], [
	AC_DEFINE(HAVE_QUOTA64, 1, [have quota64])
],[
	LB_CHECK_FILE([$LINUX/include/linux/lustre_version.h],
		[AC_MSG_ERROR([You have got no 64-bit kernel quota support.])])
])
EXTRA_KCFLAGS=$tmp_flags
]) # LC_QUOTA64

#
# LC_HAVE_ADD_WAIT_QUEUE_EXCLUSIVE
#
# 2.6.34 adds __add_wait_queue_exclusive
#
AC_DEFUN([LC_HAVE_ADD_WAIT_QUEUE_EXCLUSIVE], [
LB_CHECK_COMPILE([if '__add_wait_queue_exclusive' exists],
__add_wait_queue_exclusive, [
	#include <linux/wait.h>
],[
	wait_queue_head_t queue;
	wait_queue_t	  wait;
	__add_wait_queue_exclusive(&queue, &wait);
],[
	AC_DEFINE(HAVE___ADD_WAIT_QUEUE_EXCLUSIVE, 1,
		  [__add_wait_queue_exclusive exists])
])
]) # LC_HAVE_ADD_WAIT_QUEUE_EXCLUSIVE

#
# LC_FS_STRUCT_RWLOCK
#
# 2.6.36 fs_struct.lock use spinlock instead of rwlock.
#
AC_DEFUN([LC_FS_STRUCT_RWLOCK], [
LB_CHECK_COMPILE([if 'fs_struct.lock' use rwlock],
fs_struct_rwlock, [
	#include <asm/atomic.h>
	#include <linux/spinlock.h>
	#include <linux/fs_struct.h>
],[
	((struct fs_struct *)0)->lock = (rwlock_t){ 0 };
],[
	AC_DEFINE(HAVE_FS_STRUCT_RWLOCK, 1, [fs_struct.lock use rwlock])
])
]) # LC_FS_STRUCT_RWLOCK

#
# LC_SBOPS_EVICT_INODE
#
# 2.6.36 super_operations add evict_inode method. it hybird of
# delete_inode & clear_inode.
#
AC_DEFUN([LC_SBOPS_EVICT_INODE], [
LB_CHECK_COMPILE([if 'super_operations.evict_inode' exist],
super_ops_evict_inode, [
	#include <linux/fs.h>
],[
	((struct super_operations *)0)->evict_inode(NULL);
],[
	AC_DEFINE(HAVE_SBOPS_EVICT_INODE, 1,
		[super_operations.evict_inode() is exist in kernel])
])
]) # LC_SBOPS_EVICT_INODE

#
# LC_FILE_FSYNC
#
# 2.6.35 file_operations.fsync taken 2 arguments.
# 3.0.0 file_operations.fsync takes 4 arguments.
#
AC_DEFUN([LC_FILE_FSYNC], [
LB_CHECK_COMPILE([if 'file_operations.fsync' takes 4 arguments],
file_ops_fsync_4args, [
	#include <linux/fs.h>
],[
	((struct file_operations *)0)->fsync(NULL, 0, 0, 0);
],[
	AC_DEFINE(HAVE_FILE_FSYNC_4ARGS, 1,
		[file_operations.fsync takes 4 arguments])
],[
	LB_CHECK_COMPILE([if 'file_operations.fsync' takes 2 arguments],
	file_ops_fsync_2args, [
		#include <linux/fs.h>
	],[
		((struct file_operations *)0)->fsync(NULL, 0);
	],[
		AC_DEFINE(HAVE_FILE_FSYNC_2ARGS, 1,
			[file_operations.fsync takes 2 arguments])
	])
])
]) # LC_FILE_FSYNC

#
# LC_KERNEL_LOCKED
#
# 2.6.37 remove kernel_locked
#
AC_DEFUN([LC_KERNEL_LOCKED], [
LB_CHECK_COMPILE([if 'kernel_locked' is defined],
kernel_locked, [
	#include <linux/smp_lock.h>
],[
	kernel_locked();
],[
	AC_DEFINE(HAVE_KERNEL_LOCKED, 1, [kernel_locked is defined])
])
]) # LC_KERNEL_LOCKED

#
# LC_D_COMPARE_7ARGS
#
# 2.6.38 dentry_operations.d_compare() taken 7 arguments.
#
AC_DEFUN([LC_D_COMPARE_7ARGS], [
LB_CHECK_COMPILE([if 'dentry_operations.d_compare()' taken 7 arguments],
dentry_ops_d_compare_7arg, [
	#include <linux/dcache.h>
],[
	((struct dentry_operations*)0)->d_compare(NULL,NULL,NULL,NULL,0,NULL,NULL);
],[
	AC_DEFINE(HAVE_D_COMPARE_7ARGS, 1, [d_compare need 7 arguments])
])
]) # LC_D_COMPARE_7ARGS

#
# LC_D_DELETE_CONST
#
# 2.6.38 dentry_operations.d_delete() defined 'const' for 1st parameter.
#
AC_DEFUN([LC_D_DELETE_CONST], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'dentry_operations.d_delete()' has const declare on first parameter],
dentry_ops_d_delete_1st_const, [
	#include <linux/dcache.h>
],[
	const struct dentry *d = NULL;
	((struct dentry_operations*)0)->d_delete(d);
],[
	AC_DEFINE(HAVE_D_DELETE_CONST, const,
		[d_delete first parameter declared const])
],[
	AC_DEFINE(HAVE_D_DELETE_CONST, [],
		[d_delete first parameter declared is not const])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_D_DELETE_CONST

#
# LC_DCACHE_LOCK
#
# 2.6.38 dcache_lock removed. rcu-walk committed.
#
AC_DEFUN([LC_DCACHE_LOCK], [
LB_CHECK_COMPILE([if 'dcache_lock' is exist],
dcache_lock, [
	#include <linux/dcache.h>
],[
	spin_lock(&dcache_lock);
],[
	AC_DEFINE(HAVE_DCACHE_LOCK, 1,
		[dcache_lock is exist])
])
]) # LC_DCACHE_LOCK

#
# LC_INODE_I_RCU
#
# 2.6.38 inode.i_rcu added.
#
AC_DEFUN([LC_INODE_I_RCU], [
LB_CHECK_COMPILE([if 'inode.i_rcu' exists],
inode_i_rcu, [
	#include <linux/fs.h>
],[
	struct inode ino;
	struct rcu_head rcu = {};
	ino.i_rcu = rcu;
],[
	AC_DEFINE(HAVE_INODE_I_RCU, 1,
		[inode.i_rcu exists])
])
]) # LC_INODE_I_RCU

#
# LC_BLKDEV_GET_BY_DEV
#
# 2.6.38 export blkdev_get_by_dev
#
AC_DEFUN([LC_BLKDEV_GET_BY_DEV], [
LB_CHECK_EXPORT([blkdev_get_by_dev], [fs/block_dev.c],
	[AC_DEFINE(HAVE_BLKDEV_GET_BY_DEV, 1,
		[blkdev_get_by_dev is exported by the kernel])])
]) # LC_BLKDEV_GET_BY_DEV

#
# LC_EXPORT_SIMPLE_SETATTR
#
# 2.6.38 export simple_setattr
#
AC_DEFUN([LC_EXPORT_SIMPLE_SETATTR], [
LB_CHECK_EXPORT([simple_setattr], [fs/libfs.c],
	[AC_DEFINE(HAVE_SIMPLE_SETATTR, 1,
		[simple_setattr is exported by the kernel])])
]) # LC_EXPORT_SIMPLE_SETATTR

#
# LC_HAVE_BLK_PLUG
#
# 2.6.38 add struct blk_plug
#
AC_DEFUN([LC_HAVE_BLK_PLUG], [
LB_CHECK_COMPILE([if 'struct blk_plug' exists],
blk_plug, [
	#include <linux/blkdev.h>
],[
	struct blk_plug plug;

	blk_start_plug(&plug);
	blk_finish_plug(&plug);
],[
	AC_DEFINE(HAVE_BLK_PLUG, 1,
		[blk_plug struct exists])
])
]) # LC_HAVE_BLK_PLUG

#
# LC_IOP_TRUNCATE
#
# truncate callback removed since 2.6.39
#
AC_DEFUN([LC_IOP_TRUNCATE], [
LB_CHECK_COMPILE([if 'inode_operations' has '.truncate' member function],
inode_ops_truncate, [
	#include <linux/fs.h>
],[
	((struct inode_operations *)0)->truncate(NULL);
],[
	AC_DEFINE(HAVE_INODEOPS_TRUNCATE, 1,
		[inode_operations has .truncate member function])
])
]) # LC_IOP_TRUNCATE

#
# LC_HAVE_FSTYPE_MOUNT
#
# 2.6.39 replace get_sb with mount in struct file_system_type
#
AC_DEFUN([LC_HAVE_FSTYPE_MOUNT], [
LB_CHECK_COMPILE([if 'file_system_type' has 'mount' field],
file_system_type_mount, [
	#include <linux/fs.h>
],[
	struct file_system_type fst;
	void *i = (void *) fst.mount;
],[
	AC_DEFINE(HAVE_FSTYPE_MOUNT, 1,
		[struct file_system_type has mount field])
])
]) # LC_HAVE_FSTYPE_MOUNT

#
# LC_HAVE_FHANDLE_SYSCALLS
#
# 2.6.39 The open_by_handle_at() and name_to_handle_at() system calls were
# added to Linux kernel 2.6.39.
# Check if client supports these functions
#
AC_DEFUN([LC_HAVE_FHANDLE_SYSCALLS], [
LB_CHECK_CONFIG_IM([FHANDLE],[
	AC_DEFINE(HAVE_FHANDLE_SYSCALLS, 1,
		[kernel supports fhandles and related syscalls])
	])
]) # LC_HAVE_FHANDLE_SYSCALLS

#
# LC_HAVE_INODE_OWNER_OR_CAPABLE
#
# 2.6.39 renames is_owner_or_cap to inode_owner_or_capable
#
AC_DEFUN([LC_HAVE_INODE_OWNER_OR_CAPABLE], [
LB_CHECK_COMPILE([if 'inode_owner_or_capable' exist],
inode_owner_or_capable, [
	#include <linux/fs.h>
],[
	inode_owner_or_capable(NULL);
],[
	AC_DEFINE(HAVE_INODE_OWNER_OR_CAPABLE, 1,
		[inode_owner_or_capable exist])
])
]) # LC_HAVE_INODE_OWNER_OR_CAPABLE

#
# LC_DIRTY_INODE_WITH_FLAG
#
# 3.0 dirty_inode() has a flag parameter
# see kernel commit aa38572954ade525817fe88c54faebf85e5a61c0
#
AC_DEFUN([LC_DIRTY_INODE_WITH_FLAG], [
LB_CHECK_COMPILE([if 'dirty_inode' super_operation takes flag],
dirty_inode_super_operation_flag, [
	#include <linux/fs.h>
],[
	struct inode *inode;
	inode->i_sb->s_op->dirty_inode(NULL, 0);
],[
	AC_DEFINE(HAVE_DIRTY_INODE_HAS_FLAG, 1,
		[dirty_inode super_operation takes flag])
])
]) # LC_DIRTY_INODE_WITH_FLAG

#
# LC_SETNS
#
# 3.0 introduced setns
#
AC_DEFUN([LC_SETNS], [
AC_CHECK_HEADERS([sched.h], [], [],
		 [#define _GNU_SOURCE
		 ])
AC_CHECK_FUNCS([setns])
]) # LC_SETNS

#
# LC_GENERIC_PERMISSION
#
# 2.6.38 generic_permission taken 4 parameters.
# in fact, it means rcu-walk aware permission bring.
#
# 3.1 generic_permission taken 2 parameters.
# see kernel commit 2830ba7f34ebb27c4e5b8b6ef408cd6d74860890
#
AC_DEFUN([LC_GENERIC_PERMISSION], [
LB_CHECK_COMPILE([if 'generic_permission' take 2 arguments],
generic_permission_2args, [
	#include <linux/fs.h>
],[
	generic_permission(NULL, 0);
],[
	AC_DEFINE(HAVE_GENERIC_PERMISSION_2ARGS, 1,
		[generic_permission taken 2 arguments])
],[
	LB_CHECK_COMPILE([if 'generic_permission' take 4 arguments],
	generic_permission_4args, [
		#include <linux/fs.h>
	],[
		generic_permission(NULL, 0, 0, NULL);
	],[
		AC_DEFINE(HAVE_GENERIC_PERMISSION_4ARGS, 1,
			[generic_permission taken 4 arguments])
	])
])
]) # LC_GENERIC_PERMISSION

#
# LC_LM_XXX_LOCK_MANAGER_OPS
#
# 3.1 renames lock-manager ops(lock_manager_operations) from fl_xxx to lm_xxx
# see kernel commit 8fb47a4fbf858a164e973b8ea8ef5e83e61f2e50
#
AC_DEFUN([LC_LM_XXX_LOCK_MANAGER_OPS], [
LB_CHECK_COMPILE([if 'lock-manager' ops renamed to 'lm_xxx'],
lock_manager_ops_lm_xxx, [
	#include <linux/fs.h>
],[
	struct lock_manager_operations lm_ops;
	lm_ops.lm_compare_owner = NULL;
],[
	AC_DEFINE(HAVE_LM_XXX_LOCK_MANAGER_OPS, 1,
		[lock-manager ops renamed to lm_xxx])
])
]) # LC_LM_XXX_LOCK_MANAGER_OPS

#
# LC_INODE_DIO_WAIT
#
# 3.1 kills inode->i_alloc_sem, use i_dio_count and inode_dio_wait
#     instead.
# see kernel commit bd5fe6c5eb9c548d7f07fe8f89a150bb6705e8e3
#
AC_DEFUN([LC_INODE_DIO_WAIT], [
LB_CHECK_COMPILE([if 'inode->i_alloc_sem' is killed and use inode_dio_wait],
inode_dio_wait, [
	#include <linux/fs.h>
],[
	inode_dio_wait((struct inode *)0);
],[
	AC_DEFINE(HAVE_INODE_DIO_WAIT, 1,
		[inode->i_alloc_sem is killed and use inode_dio_wait])
])
]) # LC_INODE_DIO_WAIT

#
# LC_IOP_GET_ACL
#
# 3.1 adds get_acl method to inode_operations to read ACL from disk.
# see kernel commit 4e34e719e457f2e031297175410fc0bd4016a085
#
AC_DEFUN([LC_IOP_GET_ACL], [
LB_CHECK_COMPILE([if 'inode_operations' has '.get_acl' member function],
inode_ops_get_acl, [
	#include <linux/fs.h>
],[
	struct inode_operations iop;
	iop.get_acl = NULL;
],[
	AC_DEFINE(HAVE_IOP_GET_ACL, 1,
		[inode_operations has .get_acl member function])
])
]) # LC_IOP_GET_ACL

#
# LC_FILE_LLSEEK_SIZE
#
# 3.1 introduced generic_file_llseek_size()
#
AC_DEFUN([LC_FILE_LLSEEK_SIZE], [
LB_CHECK_EXPORT([generic_file_llseek_size], [fs/read_write.c],
	[AC_DEFINE(HAVE_FILE_LLSEEK_SIZE, 1,
		[generic_file_llseek_size is exported by the kernel])])
]) # LC_FILE_LLSEEK_SIZE

#
# LC_RADIX_EXCEPTION_ENTRY
# 3.1 adds radix_tree_exception_entry.
#
AC_DEFUN([LC_RADIX_EXCEPTION_ENTRY], [
LB_CHECK_COMPILE([radix_tree_exceptional_entry exist],
radix_tree_exceptional_entry, [
	#include <linux/radix-tree.h>
],[
	radix_tree_exceptional_entry(NULL);
],[
	AC_DEFINE(HAVE_RADIX_EXCEPTION_ENTRY, 1,
		[radix_tree_exceptional_entry exist])
])
]) # LC_RADIX_EXCEPTION_ENTRY

#
# LC_HAVE_PROTECT_I_NLINK
#
# 3.2 protects inode->i_nlink from direct modification
# see kernel commit a78ef704a8dd430225955f0709b22d4a6ba21deb
# at the same time adds set_nlink(), so checks set_nlink() for it.
#
AC_DEFUN([LC_HAVE_PROTECT_I_NLINK], [
LB_CHECK_COMPILE([if 'inode->i_nlink' is protected from direct modification],
inode_i_nlink_protected, [
	#include <linux/fs.h>
],[
	struct inode i;
	set_nlink(&i, 1);
],[
	AC_DEFINE(HAVE_PROTECT_I_NLINK, 1,
		[inode->i_nlink is protected from direct modification])
])
]) # LC_HAVE_PROTECT_I_NLINK

#
# 2.6.39 security_inode_init_security takes a 'struct qstr' parameter
#
# 3.2 security_inode_init_security takes a callback to set xattrs
#
AC_DEFUN([LC_HAVE_SECURITY_IINITSEC], [
LB_CHECK_COMPILE([if security_inode_init_security takes a callback],
security_inode_init_security_callback, [
	#include <linux/security.h>
],[
	security_inode_init_security(NULL, NULL, NULL, (const initxattrs)NULL, NULL);
],[
	AC_DEFINE(HAVE_SECURITY_IINITSEC_CALLBACK, 1,
		  [security_inode_init_security takes a callback to set xattrs])
],[
	LB_CHECK_COMPILE([if security_inode_init_security takes a 'struct qstr' parameter],
	security_inode_init_security_qstr, [
		#include <linux/security.h>
	],[
		security_inode_init_security(NULL, NULL, (struct qstr *)NULL, NULL, NULL, NULL);
	],[
		AC_DEFINE(HAVE_SECURITY_IINITSEC_QSTR, 1,
			  [security_inode_init_security takes a 'struct qstr' parameter])
	])
])
]) # LC_HAVE_SECURITY_IINITSEC

#
# LC_HAVE_MIGRATE_HEADER
#
# 3.3 introduces migrate_mode.h and migratepage has 4 args
#
AC_DEFUN([LC_HAVE_MIGRATE_HEADER], [
LB_CHECK_FILE([$LINUX/include/linux/migrate.h], [
	AC_DEFINE(HAVE_MIGRATE_H, 1,
		[kernel has include/linux/migrate.h])
],[
	LB_CHECK_FILE([$LINUX/include/linux/migrate_mode.h], [
		AC_DEFINE(HAVE_MIGRATE_MODE_H, 1,
			[kernel has include/linux/migrate_mode.h])
	])
])
]) # LC_HAVE_MIGRATE_HEADER

#
# LC_MIGRATEPAGE_4ARGS
#
AC_DEFUN([LC_MIGRATEPAGE_4ARGS], [
LB_CHECK_COMPILE([if 'address_space_operations.migratepage' has 4 args],
address_space_ops_migratepage_4args, [
	#include <linux/fs.h>
#ifdef HAVE_MIGRATE_H
	#include <linux/migrate.h>
#elif defined(HAVE_MIGRATE_MODE_H)
	#include <linux/migrate_mode.h>
#endif
],[
	struct address_space_operations aops;
	aops.migratepage(NULL, NULL, NULL, MIGRATE_ASYNC);
],[
	AC_DEFINE(HAVE_MIGRATEPAGE_4ARGS, 1,
		[address_space_operations.migratepage has 4 args])
])
]) # LC_MIGRATEPAGE_4ARGS

#
# LC_SUPEROPS_USE_DENTRY
#
# 3.3 switchs super_operations to use dentry as parameter (but not vfsmount)
# see kernel commit 34c80b1d93e6e20ca9dea0baf583a5b5510d92d4
#
AC_DEFUN([LC_SUPEROPS_USE_DENTRY], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'super_operations' use 'dentry' as parameter],
super_ops_dentry, [
	#include <linux/fs.h>
	int show_options(struct seq_file *seq, struct dentry *root) {
		return 0;
	}
],[
	struct super_operations ops;
	ops.show_options = show_options;
],[
	AC_DEFINE(HAVE_SUPEROPS_USE_DENTRY, 1,
		[super_operations use dentry as parameter])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_SUPEROPS_USE_DENTRY

#
# LC_INODEOPS_USE_UMODE_T
#
# 3.3 switchs inode_operations to use umode_t as parameter (but not int)
# see kernel commit 1a67aafb5f72a436ca044293309fa7e6351d6a35
#
AC_DEFUN([LC_INODEOPS_USE_UMODE_T], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'inode_operations' use 'umode_t' as parameter],
inode_ops_umode_t, [
	#include <linux/fs.h>
	#include <linux/types.h>
	int my_mknod(struct inode *dir, struct dentry *dchild,
		     umode_t mode, dev_t dev)
	{
		return 0;
	}
],[
	struct inode_operations ops;
	ops.mknod = my_mknod;
],[
	AC_DEFINE(HAVE_INODEOPS_USE_UMODE_T, 1,
		[inode_operations use umode_t as parameter])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_INODEOPS_USE_UMODE_T

#
# LC_KMAP_ATOMIC_HAS_1ARG
#
# 3.4 kmap_atomic removes second argument
# see kernel commit 1ec9c5ddc17aa398f05646abfcbaf315b544e62f
#
AC_DEFUN([LC_KMAP_ATOMIC_HAS_1ARG], [
LB_CHECK_COMPILE([if 'kmap_atomic' has only 1 argument],
kmap_atomic_1arg, [
	#include <linux/highmem.h>
],[
	kmap_atomic(NULL);
],[
	AC_DEFINE(HAVE_KMAP_ATOMIC_HAS_1ARG, 1,
		[have kmap_atomic has only 1 argument])
])
]) # LC_KMAP_ATOMIC_HAS_1ARG

#
# LC_HAVE_D_MAKE_ROOT
#
# 3.4 converts d_alloc_root to d_make_root
# see kernel commit 32991ab305ace7017c62f8eecbe5eb36dc32e13b
#
AC_DEFUN([LC_HAVE_D_MAKE_ROOT], [
LB_CHECK_COMPILE([if have 'd_make_root'],
d_make_root, [
	#include <linux/fs.h>
],[
	d_make_root((struct inode *)NULL);
],[
	AC_DEFINE(HAVE_D_MAKE_ROOT, 1,
		[have d_make_root])
])
]) # LC_HAVE_D_MAKE_ROOT

#
# LC_HAVE_CACHE_REGISTER
#
# 3.4 cache_register/cache_unregister are removed
# see kernel commit 2c5f846747526e2b83c5f1b8e69016be0e2e87c0
# Note, since 2.6.37 cache_register_net/cache_unregister_net
# are defined, but not exported.
# 3.3 cache_register_net/cache_unregister_net are
# exported and replacing cache_register/cache_unregister in 3.4
#
AC_DEFUN([LC_HAVE_CACHE_REGISTER], [
LB_CHECK_COMPILE([if have 'cache_register'],
cache_register, [
	#include <linux/sunrpc/cache.h>
],[
	cache_register(NULL);
],[
	AC_DEFINE(HAVE_CACHE_REGISTER, 1,
		[have cache_register])
])
]) # LC_HAVE_CACHE_REGISTER

#
# LC_HAVE_CLEAR_INODE
#
# 3.5 renames end_writeback() back to clear_inode()...
# see kernel commit dbd5768f87ff6fb0a4fe09c4d7b6c4a24de99430
#
AC_DEFUN([LC_HAVE_CLEAR_INODE], [
LB_CHECK_COMPILE([if have 'clear_inode'],
clear_inode, [
	#include <linux/fs.h>
],[
	clear_inode((struct inode *)NULL);
],[
	AC_DEFINE(HAVE_CLEAR_INODE, 1,
		[have clear_inode])
])
]) # LC_HAVE_CLEAR_INODE

#
# LC_HAVE_ENCODE_FH_PARENT
#
# 3.5 encode_fh has parent inode passed in directly
# see kernel commit b0b0382b
#
AC_DEFUN([LC_HAVE_ENCODE_FH_PARENT], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'encode_fh' have parent inode as parameter],
encode_fh_parent_inode, [
	#include <linux/exportfs.h>
	#include <linux/fs.h>
	#include <linux/types.h>
	int ll_encode_fh(struct inode *i, __u32 *a, int *b, struct inode *p)
	{
		return 0;
	}
],[
	struct export_operations exp_op;
	exp_op.encode_fh = ll_encode_fh;
],[
	AC_DEFINE(HAVE_ENCODE_FH_PARENT, 1,
		[have parent inode as parameter])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_HAVE_ENCODE_FH_PARENT

#
# LC_FILE_LLSEEK_SIZE_5ARG
#
# 3.5 has generic_file_llseek_size with 5 args
#
AC_DEFUN([LC_FILE_LLSEEK_SIZE_5ARG], [
LB_CHECK_COMPILE([if Linux kernel has 'generic_file_llseek_size' with 5 args],
generic_file_llseek_size_5args, [
	#include <linux/fs.h>
],[
	generic_file_llseek_size(NULL, 0, 0, 0, 0);
], [
	AC_DEFINE(HAVE_FILE_LLSEEK_SIZE_5ARGS, 1,
		[kernel has generic_file_llseek_size with 5 args])
])
]) # LC_FILE_LLSEEK_SIZE_5ARG

#
# LC_LLITE_DATA_IS_LIST
#
# 3.6 switch i_dentry/d_alias from list to hlist
#
# In the upstream kernels d_alias first changes
# to a hlist and then in later version, 3.11, gets
# moved to the union d_u. Due to some distros having
# d_alias in the d_u union as a struct list, which
# has never existed upstream stream, we can't test
# if d_alias is a list or hlist directly. If ever
# i_dentry and d_alias even up different combos then
# the build will fail. In that case then we will need
# to separate out the i_dentry and d_alias test below.
#
AC_DEFUN([LC_DATA_FOR_LLITE_IS_LIST], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'i_dentry/d_alias' uses 'list'],
i_dentry_d_alias_list, [
	#include <linux/fs.h>
],[
	struct inode inode;
	INIT_LIST_HEAD(&inode.i_dentry);
],[
	AC_DEFINE(DATA_FOR_LLITE_IS_LIST, 1,
		[both i_dentry/d_alias uses list])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_DATA_FOR_LLITE_IS_LIST

#
# LC_DENTRY_OPEN_USE_PATH
#
# 3.6 dentry_open uses struct path as first argument
# see kernel commit 765927b2
#
AC_DEFUN([LC_DENTRY_OPEN_USE_PATH], [
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_CHECK_COMPILE([if 'dentry_open' uses 'struct path' as first argument],
dentry_open_path, [
	#include <linux/fs.h>
	#include <linux/path.h>
],[
	struct path path;
	dentry_open(&path, 0, NULL);
],[
	AC_DEFINE(HAVE_DENTRY_OPEN_USE_PATH, 1,
		[dentry_open uses struct path as first argument])
])
EXTRA_KCFLAGS="$tmp_flags"
]) # LC_DENTRY_OPEN_USE_PATH

#
# LC_HAVE_IOP_ATOMIC_OPEN
#
# 3.6 vfs adds iop->atomic_open
#
AC_DEFUN([LC_HAVE_IOP_ATOMIC_OPEN], [
LB_CHECK_COMPILE([if 'iop' has 'atomic_open'],
inode_ops_atomic_open, [
	#include <linux/fs.h>
],[
	struct inode_operations iop;
	iop.atomic_open = NULL;
],[
	AC_DEFINE(HAVE_IOP_ATOMIC_OPEN, 1,
		[have iop atomic_open])
])
]) # LC_HAVE_IOP_ATOMIC_OPEN

#
# LC_HAVE_SB_START_WRITE
#
# RHEL6 2.6.32, 3.6 or newer support wrapped FS freeze functions
#
AC_DEFUN([LC_HAVE_SB_START_WRITE], [
LB_CHECK_COMPILE([if kernel supports wrapped FS freeze functions],
sb_start_write, [
	#include <linux/fs.h>
],[
	sb_start_write(NULL);
],[
	AC_DEFINE(HAVE_SB_START_WRITE, 1,
		[kernel supports wrapped FS freeze functions])
])
]) # LC_HAVE_SB_START_WRITE

#
# LC_HAVE_POSIXACL_USER_NS
#
# 3.7 posix_acl_{to,from}_xattr take struct user_namespace
#
AC_DEFUN([LC_HAVE_POSIXACL_USER_NS], [
LB_CHECK_COMPILE([if 'posix_acl_to_xattr' takes 'struct user_namespace'],
posix_acl_to_xattr_user_namespace, [
	#include <linux/fs.h>
	#include <linux/posix_acl_xattr.h>
],[
	posix_acl_to_xattr((struct user_namespace *)NULL, NULL, NULL, 0);
],[
	AC_DEFINE(HAVE_POSIXACL_USER_NS, 1,
		[posix_acl_to_xattr takes struct user_namespace])
])
]) # LC_HAVE_POSIXACL_USER_NS

#
# LC_HAVE_FILE_F_INODE
#
# 3.8 struct file has new member f_inode
#
AC_DEFUN([LC_HAVE_FILE_F_INODE], [
LB_CHECK_COMPILE([if 'struct file' has member 'f_inode'],
file_f_inode, [
	#include <linux/fs.h>
],[
	((struct file *)0)->f_inode = NULL;
],[
	AC_DEFINE(HAVE_FILE_F_INODE, 1,
		[struct file has member f_inode])
])
]) # LC_HAVE_FILE_F_INODE

#
# LC_HAVE_FILE_INODE
#
# 3.8 has introduced inline function file_inode
#
AC_DEFUN([LC_HAVE_FILE_INODE], [
LB_CHECK_COMPILE([if file_inode() exists],
file_inode, [
	#include <linux/fs.h>
],[
	file_inode(NULL);
],[
	AC_DEFINE(HAVE_FILE_INODE, 1,
		[file_inode() has been defined])
])
]) # LC_HAVE_FILE_INODE

#
# LC_HAVE_SUNRPC_UPCALL_HAS_3ARGS
#
AC_DEFUN([LC_HAVE_SUNRPC_UPCALL_HAS_3ARGS], [
LB_CHECK_COMPILE([if 'sunrpc_cache_pipe_upcall' takes 3 args],
sunrpc_cache_pipe_upcall_3args, [
	#include <linux/sunrpc/cache.h>
],[
	sunrpc_cache_pipe_upcall(NULL, NULL, NULL);
],[
	AC_DEFINE(HAVE_SUNRPC_UPCALL_HAS_3ARGS, 1,
		[sunrpc_cache_pipe_upcall takes 3 args])
])
]) # LC_HAVE_SUNRPC_UPCALL_HAS_3ARGS

#
# LC_HAVE_HLIST_FOR_EACH_3ARG
#
# 3.9 uses hlist_for_each_entry with 3 args
# b67bfe0d42cac56c512dd5da4b1b347a23f4b70a
#
AC_DEFUN([LC_HAVE_HLIST_FOR_EACH_3ARG], [
LB_CHECK_COMPILE([if 'hlist_for_each_entry' has 3 args],
hlist_for_each_entry_3args, [
	#include <linux/list.h>
	#include <linux/fs.h>
],[
	struct hlist_head *head = NULL;
	struct inode *inode;

	hlist_for_each_entry(inode, head, i_hash) {
		continue;
	}
],[
	AC_DEFINE(HAVE_HLIST_FOR_EACH_3ARG, 1,
		[hlist_for_each_entry has 3 args])
])
]) # LC_HAVE_HLIST_FOR_EACH_3ARG

#
# LC_HAVE_BIO_END_SECTOR
#
# 3.9 introduces bio_end_sector macro
# f73a1c7d117d07a96d89475066188a2b79e53c48
#
AC_DEFUN([LC_HAVE_BIO_END_SECTOR], [
LB_CHECK_COMPILE([if 'bio_end_sector' is defined],
bio_end_sector, [
	#include <linux/bio.h>
],[
	struct bio bio;

	bio_end_sector(&bio);
],[
	AC_DEFINE(HAVE_BIO_END_SECTOR, 1,
		  [bio_end_sector is defined])
])
]) # LC_HAVE_BIO_END_SECTOR

#
# 3.9 created is_sxid
#
AC_DEFUN([LC_HAVE_IS_SXID], [
LB_CHECK_COMPILE([if 'is_sxid' is defined],
is_sxid, [
	#include <linux/fs.h>
],[
	struct inode inode;

	is_sxid(inode.i_mode);
],[
	AC_DEFINE(HAVE_IS_SXID, 1, [is_sxid is defined])
])
]) # LC_HAVE_IS_SXID

#
# LC_HAVE_REMOVE_PROC_SUBTREE
#
# 3.10 introduced remove_proc_subtree
#
AC_DEFUN([LC_HAVE_REMOVE_PROC_SUBTREE], [
LB_CHECK_COMPILE([if 'remove_proc_subtree' is defined],
remove_proc_subtree, [
	#include <linux/proc_fs.h>
],[
	remove_proc_subtree(NULL, NULL);
], [
	AC_DEFINE(HAVE_REMOVE_PROC_SUBTREE, 1,
		  [remove_proc_subtree is defined])
])
]) # LC_HAVE_REMOVE_PROC_SUBTREE

#
# LC_HAVE_PROC_REMOVE
#
# 3.10 introduced proc_remove
#
AC_DEFUN([LC_HAVE_PROC_REMOVE], [
LB_CHECK_COMPILE([if 'proc_remove' is defined],
proc_remove, [
	#include <linux/proc_fs.h>
],[
	proc_remove(NULL);
], [
	AC_DEFINE(HAVE_PROC_REMOVE, 1,
		  [proc_remove is defined])
])
]) # LC_HAVE_PROC_REMOVE

AC_DEFUN([LC_HAVE_PROJECT_QUOTA], [
LB_CHECK_COMPILE([if get_projid exists],
get_projid, [
	#include <linux/quota.h>
],[
	struct dquot_operations ops;

	ops.get_projid(NULL, NULL);
],[
	AC_DEFINE(HAVE_PROJECT_QUOTA, 1,
		[get_projid function exists])
])
]) # LC_HAVE_PROJECT_QUOTA


#
# LC_HAVE_SECURITY_DENTRY_INIT_SECURITY
#
# 3.10 introduced security_dentry_init_security()
#
AC_DEFUN([LC_HAVE_SECURITY_DENTRY_INIT_SECURITY], [
LB_CHECK_COMPILE([if 'security_dentry_init_security' is defined],
security_dentry_init_security, [
	#include <linux/security.h>
],[
	security_dentry_init_security(NULL, 0, NULL, NULL, NULL);
],[
	AC_DEFINE(HAVE_SECURITY_DENTRY_INIT_SECURITY, 1,
		[security_dentry_init_security' is defined])
])
]) # LC_HAVE_SECURITY_DENTRY_INIT_SECURITY

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
	struct dir_context ctx;
	ctx.pos = 0;
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
LB_CHECK_COMPILE([if 'd_count' exist],
d_count, [
	#include <linux/dcache.h>
],[
	struct dentry de;
	d_count(&de);
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
# LC_HAVE_BI_CNT
#
# 4.4 redefined bi_cnt as __bi_cnt
#
AC_DEFUN([LC_HAVE_BI_CNT], [
LB_CHECK_COMPILE([if Linux kernel has bi_cnt in struct bio],
have_bi_cnt, [
	#include <asm/atomic.h>
	#include <linux/bio.h>
],[
	struct bio bio;
	int cnt;
	cnt = atomic_read(&bio.bi_cnt);
], [
	AC_DEFINE(HAVE_BI_CNT, 1,
		[struct bio has bi_cnt])
])
]) # LC_HAVE_BI_CNT

#
# LC_HAVE_BI_RW
#
# 4.4 redefined bi_rw as bi_opf
#
AC_DEFUN([LC_HAVE_BI_RW], [
LB_CHECK_COMPILE([if Linux kernel has bi_rw in struct bio],
have_bi_rw, [
	#include <linux/bio.h>
],[
	struct bio bio;
	bio.bi_rw;
], [
	AC_DEFINE(HAVE_BI_RW, 1,
		[struct bio has bi_rw])
])
]) # LC_HAVE_BI_RW

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
# 4.4 unmap_underlying_metadata was replaced by clean_bdev_aliases
#
AC_DEFUN([LC_HAVE_CLEAN_BDEV_ALIASES], [
LB_CHECK_COMPILE([if kernel has clean_bdev_aliases],
have_clean_bdev_aliases, [
	#include <linux/buffer_head.h>
],[
	struct block_device bdev;
	clean_bdev_aliases(&bdev,1,1);
], [
	AC_DEFINE(HAVE_CLEAN_BDEV_ALIASES, 1,
		[kernel has clean_bdev_aliases])
])
]) # LC_HAVE_CLEAN_BDEV_ALIASES

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
	struct address_space_operations ops;
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
	struct kiocb iocb;

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
# LC_CANCEL_DIRTY_PAGE
#
# 4.0.0 kernel removed cancel_dirty_page
#
AC_DEFUN([LC_CANCEL_DIRTY_PAGE], [
LB_CHECK_COMPILE([if cancel_dirty_page still exist],
cancel_dirty_page, [
	#include <linux/mm.h>
],[
	cancel_dirty_page(NULL, PAGE_SIZE);
],[
	AC_DEFINE(HAVE_CANCEL_DIRTY_PAGE, 1,
		[cancel_dirty_page is still available])
])
]) # LC_CANCEL_DIRTY_PAGE

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
# LC_NEW_CANCEL_DIRTY_PAGE
#
# 4.2 kernel has new cancel_dirty_page
#
AC_DEFUN([LC_NEW_CANCEL_DIRTY_PAGE], [
LB_CHECK_COMPILE([if cancel_dirty_page with one argument exist],
new_cancel_dirty_page, [
	#include <linux/mm.h>
],[
	cancel_dirty_page(NULL);
],[
	AC_DEFINE(HAVE_NEW_CANCEL_DIRTY_PAGE, 1,
		[cancel_dirty_page with one arguement is available])
])
]) # LC_NEW_CANCEL_DIRTY_PAGE

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
# LC_HAVE_LOOP_CTL_GET_FREE
#
# 4.x kernel have moved userspace APIs to
# the separate directory and all of them
# support LOOP_CTL_GET_FREE
#
AC_DEFUN([LC_HAVE_LOOP_CTL_GET_FREE], [
LB_CHECK_FILE([$LINUX/include/linux/loop.h], [
	LB_CHECK_COMPILE([if have 'HAVE_LOOP_CTL_GET_FREE'],
	LOOP_CTL_GET_FREE, [
		#include <linux/loop.h>
	],[
		int i;

		i = LOOP_CTL_GET_FREE;
	],[
		AC_DEFINE(HAVE_LOOP_CTL_GET_FREE, 1,
			[LOOP_CTL_GET_FREE exist])
	])
],[
	AC_DEFINE(HAVE_LOOP_CTL_GET_FREE, 1,
		[kernel has LOOP_CTL_GET_FREE])
])
]) # LC_HAVE_LOOP_CTL_GET_FREE

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
	((struct key *)0)->payload.data[0] = NULL;
],[
	AC_DEFINE(HAVE_KEY_PAYLOAD_DATA_ARRAY, 1, [payload.data is an array])
])
]) #LC_HAVE_KEY_PAYLOAD_DATA_ARRAY

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
	struct address_space_operations ops;
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
# Kernel version 4.7 commit c8b8e32d700fe943a935e435ae251364d016c497
# direct-io: eliminate the offset argument to ->direct_IO
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
# Kernel version 4.12 commit 47f38c539e9a42344ff5a664942075bd4df93876
# CURRENT_TIME is not 64 bit time safe so it was replaced with
# current_time()
#
AC_DEFUN([LC_CURRENT_TIME], [
LB_CHECK_COMPILE([if CURRENT_TIME has been replaced with current_time],
current_time, [
	#include <linux/fs.h>
],[
	struct timespec ts = current_time(NULL);
],[
	AC_DEFINE(HAVE_CURRENT_TIME, 1,
		[current_time() has replaced CURRENT_TIME])
])
]) # LIBCFS_CURRENT_TIME

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
# LC_PROG_LINUX
#
# Lustre linux kernel checks
#
AC_DEFUN([LC_PROG_LINUX], [
	AC_MSG_NOTICE([Lustre kernel checks
==============================================================================])

	LC_CONFIG_PINGER
	LC_CONFIG_CHECKSUM
	LC_CONFIG_HEALTH_CHECK_WRITE
	LC_CONFIG_LRU_RESIZE

	LC_GLIBC_SUPPORT_FHANDLES
	LC_CONFIG_GSS
	LC_OPENSSL_SSK

	# 2.6.32
	LC_BLK_QUEUE_MAX_SEGMENTS

	# 2.6.33
	LC_HAVE_XATTR_HANDLER_FLAGS

	# 2.6.34
	LC_HAVE_DQUOT_FS_DISK_QUOTA
	LC_HAVE_DQUOT_SUSPEND
	LC_HAVE_ADD_WAIT_QUEUE_EXCLUSIVE

	# 2.6.35, 3.0.0
	LC_FILE_FSYNC
	LC_EXPORT_SIMPLE_SETATTR
	LC_EXPORT_TRUNCATE_COMPLETE_PAGE

	# 2.6.36
	LC_FS_STRUCT_RWLOCK
	LC_SBOPS_EVICT_INODE

	# 2.6.37
	LC_KERNEL_LOCKED

	# 2.6.38
	LC_BLKDEV_GET_BY_DEV
	LC_GENERIC_PERMISSION
	LC_DCACHE_LOCK
	LC_INODE_I_RCU
	LC_D_COMPARE_7ARGS
	LC_D_DELETE_CONST
	LC_HAVE_BLK_PLUG

	# 2.6.39
	LC_HAVE_FHANDLE_SYSCALLS
	LC_HAVE_FSTYPE_MOUNT
	LC_IOP_TRUNCATE
	LC_HAVE_INODE_OWNER_OR_CAPABLE
	LC_HAVE_SECURITY_IINITSEC

	# 3.0
	LC_DIRTY_INODE_WITH_FLAG
	LC_SETNS

	# 3.1
	LC_LM_XXX_LOCK_MANAGER_OPS
	LC_INODE_DIO_WAIT
	LC_IOP_GET_ACL
	LC_FILE_LLSEEK_SIZE
	LC_INODE_PERMISION_2ARGS
	LC_RADIX_EXCEPTION_ENTRY
	LC_HAVE_LOOP_CTL_GET_FREE

	# 3.2
	LC_HAVE_PROTECT_I_NLINK

	# 3.3
	LC_HAVE_MIGRATE_HEADER
	LC_MIGRATEPAGE_4ARGS
	LC_SUPEROPS_USE_DENTRY
	LC_INODEOPS_USE_UMODE_T
	LC_HAVE_CACHE_REGISTER

	# 3.4
	LC_HAVE_D_MAKE_ROOT
	LC_KMAP_ATOMIC_HAS_1ARG

	# 3.5
	LC_HAVE_CLEAR_INODE
	LC_HAVE_ENCODE_FH_PARENT
	LC_FILE_LLSEEK_SIZE_5ARG

	# 3.6
	LC_DATA_FOR_LLITE_IS_LIST
	LC_DENTRY_OPEN_USE_PATH
	LC_HAVE_IOP_ATOMIC_OPEN
	LC_HAVE_SB_START_WRITE

	# 3.7
	LC_HAVE_POSIXACL_USER_NS

	# 3.8
	LC_HAVE_FILE_F_INODE
	LC_HAVE_FILE_INODE
	LC_HAVE_SUNRPC_UPCALL_HAS_3ARGS

	# 3.9
	LC_HAVE_HLIST_FOR_EACH_3ARG
	LC_HAVE_BIO_END_SECTOR
	LC_HAVE_IS_SXID

	# 3.10
	LC_HAVE_REMOVE_PROC_SUBTREE
	LC_HAVE_PROC_REMOVE
	LC_HAVE_PROJECT_QUOTA
	LC_HAVE_SECURITY_DENTRY_INIT_SECURITY

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
	LC_KIOCB_KI_LEFT

	# 3.13
	LC_VFS_RENAME_5ARGS
	LC_VFS_UNLINK_3ARGS

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
	LC_KEY_MATCH_DATA

	# 3.18
	LC_PERCPU_COUNTER_INIT
	LC_NFS_FILLDIR_USE_CTX

	# 3.19
	LC_KIOCB_HAS_NBYTES
	LC_HAVE_DQUOT_QC_DQBLK

	# 3.20
	LC_BACKING_DEV_INFO_REMOVAL
	LC_HAVE_BDI_CAP_MAP_COPY

	# 4.0.0
	LC_CANCEL_DIRTY_PAGE

	# 4.1.0
	LC_IOV_ITER_RW
	LC_HAVE_SYNC_READ_WRITE

	# 4.2
	LC_NEW_CANCEL_DIRTY_PAGE
	LC_BIO_ENDIO_USES_ONE_ARG
	LC_SYMLINK_OPS_USE_NAMEIDATA

	# 4.3
	LC_HAVE_CACHE_HEAD_HLIST
	LC_HAVE_XATTR_HANDLER_SIMPLIFIED

	# 4.4
	LC_HAVE_LOCKS_LOCK_FILE_WAIT
	LC_HAVE_KEY_PAYLOAD_DATA_ARRAY
	LC_HAVE_BI_CNT
	LC_HAVE_BI_RW
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

	# 4.7
	LC_DIRECTIO_2ARGS
	LC_GENERIC_WRITE_SYNC_2ARGS

	# 4.8
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

	# 4.12
	LC_CURRENT_TIME
	LC_SUPER_SETUP_BDI_NAME

	#
	AS_IF([test "x$enable_server" != xno], [
		LC_STACK_SIZE
		LC_QUOTA64
		LC_QUOTA_CONFIG
	])
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
			;;
		no)
			enable_mpitests="no"
			;;
		*)
			MPICC_WRAPPER=$enableval
			;;
		esac
	], [
		enable_mpitests="yes"
		MPICC_WRAPPER="mpicc"
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
# LC_CONFIG_NODEMAP_PROC_DEBUG
#
# enable nodemap proc file debugging
#
AC_DEFUN([LC_NODEMAP_PROC_DEBUG], [
AC_MSG_CHECKING([whether to enable nodemap proc debug])
AC_ARG_ENABLE([nodemap_proc_debug],
	AC_HELP_STRING([--enable-nodemap-proc-debug],
		[enable nodemap proc debug]),
	[], [enable_nodemap_proc_debug="no"])
AC_MSG_RESULT([$enable_nodemap_proc_debug])
AS_IF([test "x$enable_nodemap_proc_debug" != xno],
	[AC_DEFINE(NODEMAP_PROC_DEBUG, 1,
		[enable nodemap proc debug support])])
]) # LC_NODEMAP_PROC_DEBUG

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
		OSDADDON="subdir-m += $OSDMODNAME"
	], [
		AC_MSG_RESULT([can't link])
		OSDADDON=""
	])
])
AC_SUBST(OSDADDON)
]) # LC_OSD_ADDON

#
# LC_CONFIGURE
#
# other configure checks
#
AC_DEFUN([LC_CONFIGURE], [
AC_MSG_NOTICE([Lustre core checks
==============================================================================])

LC_CONFIG_OBD_BUFFER_SIZE

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

# lustre/utils/llverdev.c
AC_CHECK_HEADERS([blkid/blkid.h])

# lustre/utils/llverfs.c
AC_CHECK_HEADERS([ext2fs/ext2fs.h])

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
AM_CONDITIONAL(BLKID, test x$ac_cv_header_blkid_blkid_h = xyes)
AM_CONDITIONAL(EXT2FS_DEVEL, test x$ac_cv_header_ext2fs_ext2fs_h = xyes)
AM_CONDITIONAL(GSS, test x$enable_gss = xyes)
AM_CONDITIONAL(GSS_KEYRING, test x$enable_gss_keyring = xyes)
AM_CONDITIONAL(GSS_PIPEFS, test x$enable_gss_pipefs = xyes)
AM_CONDITIONAL(GSS_SSK, test x$enable_ssk = xyes)
AM_CONDITIONAL(LIBPTHREAD, test x$enable_libpthread = xyes)
AM_CONDITIONAL(HAVE_SYSTEMD, test "x$with_systemdsystemunitdir" != "xno")
AM_CONDITIONAL(XATTR_HANDLER, test "x$lb_cv_compile_xattr_handler_flags" = xyes)
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
lustre/contrib/Makefile
lustre/doc/Makefile
lustre/include/Makefile
lustre/include/lustre/Makefile
lustre/include/uapi/linux/Makefile
lustre/kernel_patches/targets/3.10-rhel7.target
lustre/kernel_patches/targets/2.6-rhel6.9.target
lustre/kernel_patches/targets/2.6-rhel6.8.target
lustre/kernel_patches/targets/2.6-rhel6.7.target
lustre/kernel_patches/targets/2.6-rhel6.6.target
lustre/kernel_patches/targets/2.6-rhel6.target
lustre/kernel_patches/targets/2.6-rhel5.target
lustre/kernel_patches/targets/2.6-sles11.target
lustre/kernel_patches/targets/3.0-sles11.target
lustre/kernel_patches/targets/3.0-sles11sp3.target
lustre/kernel_patches/targets/3.0-sles11sp4.target
lustre/kernel_patches/targets/3.12-sles12.target
lustre/kernel_patches/targets/4.4-sles12.target
lustre/kernel_patches/targets/4.4-sles12sp3.target
lustre/kernel_patches/targets/2.6-fc11.target
lustre/kernel_patches/targets/2.6-fc12.target
lustre/kernel_patches/targets/2.6-fc15.target
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
lustre/obdclass/linux/Makefile
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
