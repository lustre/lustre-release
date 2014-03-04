#
# LC_CONFIG_SRCDIR
#
# Wrapper for AC_CONFIG_SUBDIR
#
AC_DEFUN([LC_CONFIG_SRCDIR],
[AC_CONFIG_SRCDIR([lustre/obdclass/obdo.c])
libcfs_is_module=yes
ldiskfs_is_ext4=yes
])

#
# LC_PATH_DEFAULTS
#
# lustre specific paths
#
AC_DEFUN([LC_PATH_DEFAULTS],
[# ptlrpc kernel build requires this
LUSTRE="$PWD/lustre"
AC_SUBST(LUSTRE)

# mount.lustre
rootsbindir='$(CROSS_PATH)/sbin'
AC_SUBST(rootsbindir)

demodir='$(docdir)/demo'
AC_SUBST(demodir)

pkgexampledir='${pkgdatadir}/examples'
AC_SUBST(pkgexampledir)
])

#
# LC_TARGET_SUPPORTED
#
# is the target os supported?
#
AC_DEFUN([LC_TARGET_SUPPORTED],
[case $target_os in
	linux* | darwin*)
$1
		;;
	*)
$2
		;;
esac
])

#
# LC_CONFIG_OBD_BUFFER_SIZE
#
# the maximum buffer size of lctl ioctls
#
AC_DEFUN([LC_CONFIG_OBD_BUFFER_SIZE],
[AC_MSG_CHECKING([maximum OBD ioctl size])
AC_ARG_WITH([obd-buffer-size],
	AC_HELP_STRING([--with-obd-buffer-size=[size]],
			[set lctl ioctl maximum bytes (default=8192)]),
	[
		OBD_BUFFER_SIZE=$with_obd_buffer_size
	],[
		OBD_BUFFER_SIZE=8192
	])
AC_MSG_RESULT([$OBD_BUFFER_SIZE bytes])
AC_DEFINE_UNQUOTED(CONFIG_LUSTRE_OBD_MAX_IOCTL_BUFFER, $OBD_BUFFER_SIZE, [IOCTL Buffer Size])
])

#
# LC_READLINK_SSIZE_T
#
AC_DEFUN([LC_READLINK_SSIZE_T],
[AC_MSG_CHECKING([if readlink returns ssize_t])
AC_TRY_COMPILE([
	#include <unistd.h>
],[
	ssize_t readlink(const char *, char *, size_t);
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_POSIX_1003_READLINK, 1, [readlink returns ssize_t])
],[
	AC_MSG_RESULT([no])
])
])

#
# LC_FUNC_DEV_SET_RDONLY
#
# check whether dev_set_rdonly is exported.  This is needed until we
# have another mechanism to fence IO from the underlying device.
#
AC_DEFUN([LC_FUNC_DEV_SET_RDONLY],
[LB_CHECK_SYMBOL_EXPORT([dev_set_rdonly],
[block/ll_rw_block.c,block/blk-core.c],[
        AC_DEFINE(HAVE_DEV_SET_RDONLY, 1, [kernel exports dev_set_rdonly])
],[
        AC_MSG_WARN([kernel missing dev_set_rdonly patch for testing])
])
])

#
# Ensure stack size big than 8k in Lustre server (all kernels)
#
AC_DEFUN([LC_STACK_SIZE],
[AC_MSG_CHECKING([stack size big than 8k])
LB_LINUX_TRY_COMPILE([
	#include <linux/thread_info.h>
],[
        #if THREAD_SIZE < 8192
        #error "stack size < 8192"
        #endif
],[
        AC_MSG_RESULT(yes)
],[
        AC_MSG_ERROR([Lustre requires that Linux is configured with at least a 8KB stack.])
])
])

#
# Allow the user to set the MDS thread upper limit
#
AC_DEFUN([LC_MDS_MAX_THREADS],
[
	AC_ARG_WITH([mds_max_threads],
	AC_HELP_STRING([--with-mds-max-threads=count],
		       [maximum threads available on the MDS: (default=512)]),
	[
		MDS_THREAD_COUNT=$with_mds_max_threads
		AC_DEFINE_UNQUOTED(MDS_MAX_THREADS, $MDS_THREAD_COUNT, [maximum number of MDS threads])
	])
])

#
# LC_CONFIG_PINGER
#
# the pinger is temporary, until we have the recovery node in place
#
AC_DEFUN([LC_CONFIG_PINGER],
[AC_MSG_CHECKING([whether to enable pinger support])
AC_ARG_ENABLE([pinger],
	AC_HELP_STRING([--disable-pinger],
			[disable recovery pinger support]),
	[],[enable_pinger='yes'])
AC_MSG_RESULT([$enable_pinger])
if test x$enable_pinger != xno ; then
  AC_DEFINE(ENABLE_PINGER, 1, Use the Pinger)
fi
])

#
# LC_CONFIG_CHECKSUM
#
# do checksum of bulk data between client and OST
#
AC_DEFUN([LC_CONFIG_CHECKSUM],
[AC_MSG_CHECKING([whether to enable data checksum support])
AC_ARG_ENABLE([checksum],
       AC_HELP_STRING([--disable-checksum],
                       [disable data checksum support]),
       [],[enable_checksum='yes'])
AC_MSG_RESULT([$enable_checksum])
if test x$enable_checksum != xno ; then
  AC_DEFINE(ENABLE_CHECKSUM, 1, do data checksums)
fi
])

#
# LC_CONFIG_LIBLUSTRE_RECOVERY
#
AC_DEFUN([LC_CONFIG_LIBLUSTRE_RECOVERY],
[AC_MSG_CHECKING([whether to enable liblustre recovery support])
AC_ARG_ENABLE([liblustre-recovery],
	AC_HELP_STRING([--disable-liblustre-recovery],
			[disable liblustre recovery support]),
	[],[enable_liblustre_recovery='yes'])
AC_MSG_RESULT([$enable_liblustre_recovery])
if test x$enable_liblustre_recovery != xno ; then
  AC_DEFINE(ENABLE_LIBLUSTRE_RECOVERY, 1, Liblustre Can Recover)
fi
])

#
# LC_CONFIG_HEALTH_CHECK_WRITE
#
# Turn off the actual write to the disk
#
AC_DEFUN([LC_CONFIG_HEALTH_CHECK_WRITE],
[AC_MSG_CHECKING([whether to enable a write with the health check])
AC_ARG_ENABLE([health_write],
        AC_HELP_STRING([--enable-health_write],
                        [enable disk writes when doing health check]),
        [],[enable_health_write='no'])
AC_MSG_RESULT([$enable_health_write])
if test x$enable_health_write != xno ; then
  AC_DEFINE(USE_HEALTH_CHECK_WRITE, 1, Write when Checking Health)
fi
])

AC_DEFUN([LC_CONFIG_LRU_RESIZE],
[AC_MSG_CHECKING([whether to enable lru self-adjusting])
AC_ARG_ENABLE([lru_resize],
	AC_HELP_STRING([--enable-lru-resize],
			[enable lru resize support]),
	[],[enable_lru_resize='yes'])
AC_MSG_RESULT([$enable_lru_resize])
if test x$enable_lru_resize != xno; then
   AC_DEFINE(HAVE_LRU_RESIZE_SUPPORT, 1, [Enable lru resize support])
fi
])

#
# Quota support. The kernel must support CONFIG_QUOTA.
#
AC_DEFUN([LC_QUOTA_CONFIG],
[LB_LINUX_CONFIG_IM([QUOTA],[],[
        AC_MSG_ERROR([Lustre quota requires that CONFIG_QUOTA is enabled in your kernel.])
	])
])

# truncate_complete_page() has never been exported from an upstream kernel
# remove_from_page_cache() was exported between 2.6.35 and 2.6.38
# delete_from_page_cache() is exported from 2.6.39
AC_DEFUN([LC_EXPORT_TRUNCATE_COMPLETE_PAGE],
         [LB_CHECK_SYMBOL_EXPORT([truncate_complete_page],
                                 [mm/truncate.c],
                                 [AC_DEFINE(HAVE_TRUNCATE_COMPLETE_PAGE, 1,
                                            [kernel export truncate_complete_page])])
          LB_CHECK_SYMBOL_EXPORT([remove_from_page_cache],
                                 [mm/filemap.c],
                                 [AC_DEFINE(HAVE_REMOVE_FROM_PAGE_CACHE, 1,
                                            [kernel export remove_from_page_cache])])
          LB_CHECK_SYMBOL_EXPORT([delete_from_page_cache],
                                 [mm/filemap.c],
                                 [AC_DEFINE(HAVE_DELETE_FROM_PAGE_CACHE, 1,
                                            [kernel export delete_from_page_cache])])
         ])

#
# LC_CAPA_CRYPTO
#
AC_DEFUN([LC_CAPA_CRYPTO],
[LB_LINUX_CONFIG_IM([CRYPTO],[],[
	AC_MSG_ERROR([Lustre capability require that CONFIG_CRYPTO is enabled in your kernel.])
])
LB_LINUX_CONFIG_IM([CRYPTO_HMAC],[],[
	AC_MSG_ERROR([Lustre capability require that CONFIG_CRYPTO_HMAC is enabled in your kernel.])
])
LB_LINUX_CONFIG_IM([CRYPTO_SHA1],[],[
	AC_MSG_ERROR([Lustre capability require that CONFIG_CRYPTO_SHA1 is enabled in your kernel.])
])
])

#
# LC_CONFIG_RMTCLIENT
#
dnl FIXME
dnl the AES symbol usually tied with arch, e.g. CRYPTO_AES_586
dnl FIXME
AC_DEFUN([LC_CONFIG_RMTCLIENT],
[LB_LINUX_CONFIG_IM([CRYPTO_AES],[],[
        AC_MSG_WARN([Lustre remote client require that CONFIG_CRYPTO_AES is enabled in your kernel.])
])
])

#
# LC_CONFIG_GSS_KEYRING (default 'auto', tests for dependencies, if found, enables; only called if gss is enabled)
#
AC_DEFUN([LC_CONFIG_GSS_KEYRING],
[AC_MSG_CHECKING([whether to enable gss keyring backend])
 AC_ARG_ENABLE([gss_keyring],
               [AC_HELP_STRING([--disable-gss-keyring],
                               [disable gss keyring backend])],
               [],[enable_gss_keyring='auto'])
 AC_MSG_RESULT([$enable_gss_keyring])

 if test x$enable_gss_keyring != xno; then
	LB_LINUX_CONFIG_IM([KEYS],[],
			   [gss_keyring_conf_test='fail';
			    AC_MSG_WARN([GSS keyring backend require that CONFIG_KEYS be enabled in your kernel.])])

	AC_CHECK_LIB([keyutils], [keyctl_search], [],
		     [gss_keyring_conf_test='fail';
		      AC_MSG_WARN([libkeyutils is not found, which is required by gss keyring backend])],)

	if test x$gss_keyring_conf_test != xfail; then
		AC_DEFINE([HAVE_GSS_KEYRING], [1], [Define this if you enable gss keyring backend])
		enable_gss_keyring='yes'
	else
		if test x$enable_gss_keyring == xyes; then
			AC_MSG_ERROR([Cannot enable gss_keyring. See above for details.])
		else
			AC_MSG_WARN([Cannot enable gss keyring.  See above for details.])
		fi
	fi
 fi
])

AC_DEFUN([LC_CONFIG_SUNRPC],
[LB_LINUX_CONFIG_IM([SUNRPC],[],
                    [if test x$sunrpc_required == xyes; then
                         AC_MSG_ERROR([kernel SUNRPC support is required by using GSS.])
                     fi])
])

#
# LC_CONFIG_GSS (default 'auto' (tests for dependencies, if found, enables))
#
# Build gss and related tools of Lustre. Currently both kernel and user space
# parts are depend on linux platform.
#
AC_DEFUN([LC_CONFIG_GSS],
[AC_MSG_CHECKING([whether to enable gss/krb5 support])
 AC_ARG_ENABLE([gss],
               [AC_HELP_STRING([--enable-gss], [enable gss/krb5 support])],
               [],[enable_gss='auto'])
 AC_MSG_RESULT([$enable_gss])

 if test x$enable_gss != xno; then
        LC_CONFIG_GSS_KEYRING
	sunrpc_required=$enable_gss
	LC_CONFIG_SUNRPC
        sunrpc_required=no

	LB_LINUX_CONFIG_IM([CRYPTO_MD5],[],
			   [AC_MSG_WARN([kernel MD5 support is recommended by using GSS.])])
	LB_LINUX_CONFIG_IM([CRYPTO_SHA1],[],
			   [AC_MSG_WARN([kernel SHA1 support is recommended by using GSS.])])
	LB_LINUX_CONFIG_IM([CRYPTO_SHA256],[],
			   [AC_MSG_WARN([kernel SHA256 support is recommended by using GSS.])])
	LB_LINUX_CONFIG_IM([CRYPTO_SHA512],[],
			   [AC_MSG_WARN([kernel SHA512 support is recommended by using GSS.])])

	require_krb5=$enable_gss
	AC_KERBEROS_V5
	require_krb5=no

	if test x$KRBDIR != x; then
		AC_CHECK_LIB([gssapi], [gss_export_lucid_sec_context],
			     [GSSAPI_LIBS="$GSSAPI_LDFLAGS -lgssapi";
			      gss_conf_test='success'],
			     [AC_CHECK_LIB([gssglue], [gss_export_lucid_sec_context],
					   [GSSAPI_LIBS="$GSSAPI_LDFLAGS -lgssglue";
					    gss_conf_test='success'],
					   [if test x$enable_gss == xyes; then
						AC_MSG_ERROR([libgssapi or libgssglue is not found, which is required by GSS.])
					    else
						AC_MSG_WARN([libgssapi or libgssglue is not found, which is required by GSS.])
					    fi])],)
		AC_SUBST(GSSAPI_LIBS)
	fi

	if test x$gss_conf_test == xsuccess; then
		AC_DEFINE([HAVE_GSS], [1], [Define this is if you enable gss])
		enable_gss='yes'
	fi

 fi
])

# 2.6.24

# 2.6.24 has bio_endio with 2 args
AC_DEFUN([LC_BIO_ENDIO_2ARG],
[AC_MSG_CHECKING([if kernel has bio_endio with 2 args])
LB_LINUX_TRY_COMPILE([
        #include <linux/bio.h>
],[
        bio_endio(NULL, 0);
], [
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_BIO_ENDIO_2ARG, 1,
                [kernel has bio_endio with 2 args])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.24 removes long aged procfs entry -> deleted member
AC_DEFUN([LC_PROCFS_DELETED],
[AC_MSG_CHECKING([if kernel has deleted member in procfs entry struct])
LB_LINUX_TRY_COMPILE([
	#include <linux/proc_fs.h>
],[
        struct proc_dir_entry pde;

        pde.deleted = sizeof(pde);
], [
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_PROCFS_DELETED, 1,
                [kernel has deleted member in procfs entry struct])
],[
        AC_MSG_RESULT([no])
])
])

#
# 2.6.27
#

# up to v2.6.27 had a 3 arg version (inode, mask, nameidata)
# v2.6.27->v2.6.37 had a 2 arg version (inode, mask)
# v2.6.37->v3.0 had a 3 arg version (inode, mask, nameidata)
# v3.1 onward have a 2 arg version (inode, mask)
AC_DEFUN([LC_INODE_PERMISION_2ARGS],
[AC_MSG_CHECKING([inode_operations->permission has two args])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct inode *inode __attribute__ ((unused));

        inode = NULL;
        inode->i_op->permission(NULL, 0);
],[
        AC_DEFINE(HAVE_INODE_PERMISION_2ARGS, 1,
                  [inode_operations->permission has two args])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.34 has quotactl_ops->[sg]et_dqblk that take struct fs_disk_quota
AC_DEFUN([LC_HAVE_DQUOT_FS_DISK_QUOTA],
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
[AC_MSG_CHECKING([if quotactl_ops.set_dqblk takes struct fs_disk_quota])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
	#include <linux/quota.h>
],[
	((struct quotactl_ops *)0)->set_dqblk(NULL, 0, 0, (struct fs_disk_quota*)0);
],[
	AC_DEFINE(HAVE_DQUOT_FS_DISK_QUOTA, 1, [quotactl_ops.set_dqblk takes struct fs_disk_quota])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
	AC_MSG_CHECKING([if quotactl_ops.set_dqblk takes struct kqid & fs_disk_quota])
	LB_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
		#include <linux/quota.h>
	],[
		((struct quotactl_ops *)0)->set_dqblk((struct super_block*)0, *((struct kqid*)0), (struct fs_disk_quota*)0);
	],[
		AC_DEFINE(HAVE_DQUOT_FS_DISK_QUOTA, 1, [quotactl_ops.set_dqblk takes struct fs_disk_quota])
		AC_DEFINE(HAVE_DQUOT_KQID, 1, [quotactl_ops.set_dqblk takes struct kqid])
		AC_MSG_RESULT([yes])
	],[
		AC_MSG_RESULT([no])
		AC_MSG_CHECKING([if quotactl_ops.set_dqblk takes struct kqid&fs_disk_quota])
	])
])
EXTRA_KCFLAGS="$tmp_flags"
])

# 2.6.34 has renamed dquot options to dquot_*, check for dquot_suspend
AC_DEFUN([LC_HAVE_DQUOT_SUSPEND],
[AC_MSG_CHECKING([if dquot_suspend is defined])
LB_LINUX_TRY_COMPILE([
	#include <linux/quotaops.h>
],[
	dquot_suspend(NULL, -1);
],[
	AC_DEFINE(HAVE_DQUOT_SUSPEND, 1, [dquot_suspend is defined])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 2.6.27 sles11 move the quotaio_v1{2}.h from include/linux to fs
# 2.6.32 move the quotaio_v1{2}.h from fs to fs/quota
AC_DEFUN([LC_HAVE_QUOTAIO_H],
[LB_CHECK_FILE([$LINUX/include/linux/quotaio_v2.h],[
        AC_DEFINE(HAVE_QUOTAIO_H, 1,
                [kernel has include/linux/quotaio_v2.h])
],[LB_CHECK_FILE([$LINUX/fs/quotaio_v2.h],[
               AC_DEFINE(HAVE_FS_QUOTAIO_H, 1,
                [kernel has fs/quotaio_v1.h])
],[LB_CHECK_FILE([$LINUX/fs/quota/quotaio_v2.h],[
               AC_DEFINE(HAVE_FS_QUOTA_QUOTAIO_H, 1,
                [kernel has fs/quota/quotaio_v2.h])
],[
        AC_MSG_RESULT([no])
])
])
])
])

# 2.6.32

# 2.6.32 replaces 2 functions blk_queue_max_phys_segments and blk_queue_max_hw_segments by blk_queue_max_segments
AC_DEFUN([LC_BLK_QUEUE_MAX_SEGMENTS],
[AC_MSG_CHECKING([if blk_queue_max_segments is defined])
LB_LINUX_TRY_COMPILE([
        #include <linux/blkdev.h>
],[
        blk_queue_max_segments(NULL, 0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_BLK_QUEUE_MAX_SEGMENTS, 1,
                  [blk_queue_max_segments is defined])
],[
        AC_MSG_RESULT(no)
])
])

#
# LC_QUOTA64
#
# Check if kernel has been patched for 64-bit quota limits support.
# The upstream version of this patch in RHEL6 2.6.32 kernels introduces
# the constant QFMT_VFS_V1 in include/linux/quota.h, so we can check for
# that in the absence of quotaio_v1.h in the kernel headers.
#
AC_DEFUN([LC_QUOTA64],[
        AC_MSG_CHECKING([if kernel has 64-bit quota limits support])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-I$LINUX/fs"
        LB_LINUX_TRY_COMPILE([
                #include <linux/kernel.h>
                #include <linux/fs.h>
		#if defined(HAVE_FS_QUOTA_QUOTAIO_H)
                # include <quota/quotaio_v2.h>
                struct v2r1_disk_dqblk dqblk_r1;
                #else
                #include <linux/quota.h>
                int ver = QFMT_VFS_V1;
                #endif
        ],[],[
                AC_DEFINE(HAVE_QUOTA64, 1, [have quota64])
                AC_MSG_RESULT([yes])
        ],[
                LB_CHECK_FILE([$LINUX/include/linux/lustre_version.h],[
                        AC_MSG_ERROR([You have got no 64-bit kernel quota support.])
                ],[])
                AC_MSG_RESULT([no])
        ])
EXTRA_KCFLAGS=$tmp_flags
])

#
# 2.6.36 fs_struct.lock use spinlock instead of rwlock.
#
AC_DEFUN([LC_FS_STRUCT_RWLOCK],
[AC_MSG_CHECKING([if fs_struct.lock use rwlock])
LB_LINUX_TRY_COMPILE([
        #include <asm/atomic.h>
        #include <linux/spinlock.h>
        #include <linux/fs_struct.h>
],[
        ((struct fs_struct *)0)->lock = (rwlock_t){ 0 };
],[
        AC_DEFINE(HAVE_FS_STRUCT_RWLOCK, 1,
                  [fs_struct.lock use rwlock])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

#
# 2.6.36 super_operations add evict_inode method. it hybird of
# delete_inode & clear_inode.
#
AC_DEFUN([LC_SBOPS_EVICT_INODE],
[AC_MSG_CHECKING([if super_operations.evict_inode exist])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        ((struct super_operations *)0)->evict_inode(NULL);
],[
        AC_DEFINE(HAVE_SBOPS_EVICT_INODE, 1,
                [super_operations.evict_inode() is exist in kernel])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

#
# 2.6.35 file_operations.fsync taken 2 arguments.
# 3.0.0 file_operations.fsync takes 4 arguments.
#
AC_DEFUN([LC_FILE_FSYNC],
[AC_MSG_CHECKING([if file_operations.fsync takes 4 or 2 arguments])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        ((struct file_operations *)0)->fsync(NULL, 0, 0, 0);
],[
        AC_DEFINE(HAVE_FILE_FSYNC_4ARGS, 1,
                [file_operations.fsync takes 4 arguments])
        AC_MSG_RESULT([yes, 4 args])
],[
        LB_LINUX_TRY_COMPILE([
                #include <linux/fs.h>
        ],[
           ((struct file_operations *)0)->fsync(NULL, 0);
        ],[
                AC_DEFINE(HAVE_FILE_FSYNC_2ARGS, 1,
                        [file_operations.fsync takes 2 arguments])
                AC_MSG_RESULT([yes, 2 args])
        ],[
                AC_MSG_RESULT([no])
        ])
])
])

#
# 2.6.37 remove kernel_locked
#
AC_DEFUN([LC_KERNEL_LOCKED],
[AC_MSG_CHECKING([if kernel_locked is defined])
LB_LINUX_TRY_COMPILE([
        #include <linux/smp_lock.h>
],[
        kernel_locked();
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_KERNEL_LOCKED, 1,
                [kernel_locked is defined])
],[
        AC_MSG_RESULT([no])
])
])

#
# 2.6.38 dentry_operations.d_compare() taken 7 arguments.
#
AC_DEFUN([LC_D_COMPARE_7ARGS],
[AC_MSG_CHECKING([if d_compare taken 7 arguments])
LB_LINUX_TRY_COMPILE([
	#include <linux/dcache.h>
],[
	((struct dentry_operations*)0)->d_compare(NULL,NULL,NULL,NULL,0,NULL,NULL);
],[
	AC_DEFINE(HAVE_D_COMPARE_7ARGS, 1,
		[d_compare need 7 arguments])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 2.6.38 dentry_operations.d_delete() defined 'const' for 1st parameter.
#
AC_DEFUN([LC_D_DELETE_CONST],
[AC_MSG_CHECKING([if d_delete has const declare on first parameter])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
	#include <linux/dcache.h>
],[
	const struct dentry *d = NULL;
	((struct dentry_operations*)0)->d_delete(d);
],[
	AC_DEFINE(HAVE_D_DELETE_CONST, const,
		[d_delete first parameter declared const])
	AC_MSG_RESULT([yes])
],[
	AC_DEFINE(HAVE_D_DELETE_CONST, , [])
	AC_MSG_RESULT([no])
])
EXTRA_KCFLAGS="$tmp_flags"
])

#
# 2.6.38 dcache_lock removed. rcu-walk commited.
#
AC_DEFUN([LC_DCACHE_LOCK],
[AC_MSG_CHECKING([if dcache_lock is exist])
LB_LINUX_TRY_COMPILE([
	#include <linux/dcache.h>
],[
	spin_lock(&dcache_lock);
],[
	AC_DEFINE(HAVE_DCACHE_LOCK, 1,
		[dcache_lock is exist])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 2.6.38 inode.i_rcu added.
#
AC_DEFUN([LC_INODE_I_RCU],
[AC_MSG_CHECKING([if inode.i_rcu exists])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	struct inode ino;
	struct rcu_head rcu = {};
	ino.i_rcu = rcu;
],[
	AC_DEFINE(HAVE_INODE_I_RCU, 1,
		[inode.i_rcu exists])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 2.6.38 export blkdev_get_by_dev
#
AC_DEFUN([LC_BLKDEV_GET_BY_DEV],
[LB_CHECK_SYMBOL_EXPORT([blkdev_get_by_dev],
[fs/block_dev.c],[
AC_DEFINE(HAVE_BLKDEV_GET_BY_DEV, 1,
            [blkdev_get_by_dev is exported by the kernel])
],[
])
])

#
# 2.6.38 export simple_setattr
#
AC_DEFUN([LC_EXPORT_SIMPLE_SETATTR],
[LB_CHECK_SYMBOL_EXPORT([simple_setattr],
[fs/libfs.c],[
AC_DEFINE(HAVE_SIMPLE_SETATTR, 1,
            [simple_setattr is exported by the kernel])
],[
])
])

#
# truncate callback removed since 2.6.39
#
AC_DEFUN([LC_IOP_TRUNCATE],
[AC_MSG_CHECKING([inode_operations has .truncate member function])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        ((struct inode_operations *)0)->truncate(NULL);
],[
        AC_DEFINE(HAVE_INODEOPS_TRUNCATE, 1,
                  [inode_operations has .truncate member function])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

#
# 2.6.39 remove unplug_fn from request_queue.
#
AC_DEFUN([LC_REQUEST_QUEUE_UNPLUG_FN],
[AC_MSG_CHECKING([if request_queue has unplug_fn field])
LB_LINUX_TRY_COMPILE([
        #include <linux/blkdev.h>
],[
        do{ }while(sizeof(((struct request_queue *)0)->unplug_fn));
],[
        AC_DEFINE(HAVE_REQUEST_QUEUE_UNPLUG_FN, 1,
                  [request_queue has unplug_fn field])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

#
# 2.6.39 replace get_sb with mount in struct file_system_type
#
AC_DEFUN([LC_HAVE_FSTYPE_MOUNT],
[AC_MSG_CHECKING([if file_system_type has mount field])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	struct file_system_type fst;
	void *i = (void *) fst.mount;
],[
	AC_DEFINE(HAVE_FSTYPE_MOUNT, 1,
		[struct file_system_type has mount field])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 2.6.39 renames is_owner_or_cap to inode_owner_or_capable
#
AC_DEFUN([LC_HAVE_INODE_OWNER_OR_CAPABLE],
[AC_MSG_CHECKING([if inode_owner_or_capable exist])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	inode_owner_or_capable(NULL);
],[
	AC_DEFINE(HAVE_INODE_OWNER_OR_CAPABLE, 1,
		[inode_owner_or_capable exist])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.0 dirty_inode() has a flag parameter
# see kernel commit aa38572954ade525817fe88c54faebf85e5a61c0
#
AC_DEFUN([LC_DIRTY_INODE_WITH_FLAG],
[AC_MSG_CHECKING([if dirty_inode super_operation takes flag])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	struct inode *inode;
	inode->i_sb->s_op->dirty_inode(NULL, 0);
],[
	AC_DEFINE(HAVE_DIRTY_INODE_HAS_FLAG, 1,
		  [dirty_inode super_operation takes flag])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 2.6.38 generic_permission taken 4 parameters.
# in fact, it means rcu-walk aware permission bring.
#
# 3.1 generic_permission taken 2 parameters.
# see kernel commit 2830ba7f34ebb27c4e5b8b6ef408cd6d74860890
#
AC_DEFUN([LC_GENERIC_PERMISSION],
[AC_MSG_CHECKING([if generic_permission take 2 or 4 arguments])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	generic_permission(NULL, 0);
],[
	AC_DEFINE(HAVE_GENERIC_PERMISSION_2ARGS, 1,
		  [generic_permission taken 2 arguments])
	AC_MSG_RESULT([yes, 2 args])
],[
	LB_LINUX_TRY_COMPILE([
		#include <linux/fs.h>
	],[
		generic_permission(NULL, 0, 0, NULL);
	],[
		AC_DEFINE(HAVE_GENERIC_PERMISSION_4ARGS, 1,
			  [generic_permission taken 4 arguments])
		AC_MSG_RESULT([yes, 4 args])
	],[
		AC_MSG_RESULT([no])
	])
])
])

#
# 3.1 renames lock-manager ops(lock_manager_operations) from fl_xxx to lm_xxx
# see kernel commit 8fb47a4fbf858a164e973b8ea8ef5e83e61f2e50
#
AC_DEFUN([LC_LM_XXX_LOCK_MANAGER_OPS],
[AC_MSG_CHECKING([if lock-manager ops renamed to lm_xxx])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	struct lock_manager_operations lm_ops;
	lm_ops.lm_compare_owner = NULL;
],[
	AC_DEFINE(HAVE_LM_XXX_LOCK_MANAGER_OPS, 1,
		  [lock-manager ops renamed to lm_xxx])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.1 kills inode->i_alloc_sem, use i_dio_count and inode_dio_wait/
#     inode_dio_done instead.
# see kernel commit bd5fe6c5eb9c548d7f07fe8f89a150bb6705e8e3
#
AC_DEFUN([LC_INODE_DIO_WAIT],
[AC_MSG_CHECKING([if inode->i_alloc_sem is killed and use inode_dio_wait/done.])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	inode_dio_wait((struct inode *)0);
	inode_dio_done((struct inode *)0);
],[
	AC_DEFINE(HAVE_INODE_DIO_WAIT, 1,
		  [inode->i_alloc_sem is killed and use inode_dio_wait/done])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.1 adds get_acl method to inode_operations to read ACL from disk.
# see kernel commit 4e34e719e457f2e031297175410fc0bd4016a085
#
AC_DEFUN([LC_IOP_GET_ACL],
[AC_MSG_CHECKING([inode_operations has .get_acl member function])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct inode_operations iop;
        iop.get_acl = NULL;
],[
        AC_DEFINE(HAVE_IOP_GET_ACL, 1,
                  [inode_operations has .get_acl member function])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

#
# 3.1.1 has ext4_blocks_for_truncate
#
AC_DEFUN([LC_BLOCKS_FOR_TRUNCATE],
[AC_MSG_CHECKING([if kernel has ext4_blocks_for_truncate])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
	#include "$LINUX/fs/ext4/ext4_jbd2.h"
	#include "$LINUX/fs/ext4/truncate.h"
],[
	ext4_blocks_for_truncate(NULL);
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_BLOCKS_FOR_TRUNCATE, 1,
		  [kernel has ext4_blocks_for_truncate])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.1 introduced generic_file_llseek_size()
#
AC_DEFUN([LC_FILE_LLSEEK_SIZE],
	[LB_CHECK_SYMBOL_EXPORT([generic_file_llseek_size],
	[fs/read_write.c],
        [AC_DEFINE(HAVE_FILE_LLSEEK_SIZE, 1,
		   [generic_file_llseek_size is exported by the kernel])])
])

#
# 3.2 request_queue.make_request_fn defined as function returns with void
# see kernel commit 5a7bbad27a410350e64a2d7f5ec18fc73836c14f
#
AC_DEFUN([LC_HAVE_VOID_MAKE_REQUEST_FN],
[AC_MSG_CHECKING([if request_queue.make_request_fn returns void but not int])
LB_LINUX_TRY_COMPILE([
	#include <linux/blkdev.h>
],[
	int ret;
	make_request_fn		*mrf;
	ret = mrf(NULL, NULL);
],[
	AC_MSG_RESULT([no])
],[
	AC_DEFINE(HAVE_VOID_MAKE_REQUEST_FN, 1,
		  [request_queue.make_request_fn returns void but not int])
	AC_MSG_RESULT([yes])
])
])

#
# 3.2 protects inode->i_nlink from direct modification
# see kernel commit a78ef704a8dd430225955f0709b22d4a6ba21deb
# at the same time adds set_nlink(), so checks set_nlink() for it.
#
AC_DEFUN([LC_HAVE_PROTECT_I_NLINK],
[AC_MSG_CHECKING([if inode->i_nlink is protected from direct modification])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	struct inode i;
	set_nlink(&i, 1);
],[
	AC_DEFINE(HAVE_PROTECT_I_NLINK, 1,
		  [inode->i_nlink is protected from direct modification])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.3 introduces migrate_mode.h and migratepage has 4 args
#
AC_DEFUN([LC_HAVE_MIGRATE_HEADER],
[LB_CHECK_FILE([$LINUX/include/linux/migrate.h],[
		AC_DEFINE(HAVE_MIGRATE_H, 1,
		[kernel has include/linux/migrate.h])
],[LB_CHECK_FILE([$LINUX/include/linux/migrate_mode.h],[
		AC_DEFINE(HAVE_MIGRATE_MODE_H, 1,
			[kernel has include/linux/migrate_mode.h])
],[
	AC_MSG_RESULT([no])
])
])
])

AC_DEFUN([LC_MIGRATEPAGE_4ARGS],
[AC_MSG_CHECKING([if address_space_operations.migratepage has 4 args])
LB_LINUX_TRY_COMPILE([
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
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.3 switchs super_operations to use dentry as parameter (but not vfsmount)
# see kernel commit 34c80b1d93e6e20ca9dea0baf583a5b5510d92d4
#
AC_DEFUN([LC_SUPEROPS_USE_DENTRY],
[AC_MSG_CHECKING([if super_operations use dentry as parameter])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
	int show_options(struct seq_file *seq, struct dentry *root){
		return 0;
	}
],[
	struct super_operations ops;
	ops.show_options = show_options;
],[
	AC_DEFINE(HAVE_SUPEROPS_USE_DENTRY, 1,
		  [super_operations use dentry as parameter])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
EXTRA_KCFLAGS="$tmp_flags"
])

#
# 3.3 switchs inode_operations to use umode_t as parameter (but not int)
# see kernel commit 1a67aafb5f72a436ca044293309fa7e6351d6a35
#
AC_DEFUN([LC_INODEOPS_USE_UMODE_T],
[AC_MSG_CHECKING([if inode_operations use umode_t as parameter])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
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
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
EXTRA_KCFLAGS="$tmp_flags"
])

# 3.4 kmap_atomic removes second argument
# see kernel commit 1ec9c5ddc17aa398f05646abfcbaf315b544e62f
#
AC_DEFUN([LC_KMAP_ATOMIC_HAS_1ARG],
[AC_MSG_CHECKING([if kmap_atomic has only 1 argument])
LB_LINUX_TRY_COMPILE([
	#include <linux/highmem.h>
],[
	kmap_atomic(NULL);
],[
	AC_DEFINE(HAVE_KMAP_ATOMIC_HAS_1ARG, 1,
		  [have kmap_atomic has only 1 argument])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.4 switchs touch_atime to struct path
# see kernel commit 68ac1234fb949b66941d94dce4157742799fc581
#
AC_DEFUN([LC_TOUCH_ATIME_1ARG],
[AC_MSG_CHECKING([if touch_atime use one argument])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	touch_atime((struct path *)NULL);
],[
	AC_DEFINE(HAVE_TOUCH_ATIME_1ARG, 1,
		  [touch_atime use one argument])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.4 converts d_alloc_root to d_make_root
# see kernel commit 32991ab305ace7017c62f8eecbe5eb36dc32e13b
#
AC_DEFUN([LC_HAVE_D_MAKE_ROOT],
[AC_MSG_CHECKING([if have d_make_root])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	d_make_root((struct inode *)NULL);
],[
	AC_DEFINE(HAVE_D_MAKE_ROOT, 1,
		  [have d_make_root])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.5 renames end_writeback() back to clear_inode()...
# see kernel commit dbd5768f87ff6fb0a4fe09c4d7b6c4a24de99430
#
AC_DEFUN([LC_HAVE_CLEAR_INODE],
[AC_MSG_CHECKING([if have clear_inode])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	clear_inode((struct inode *)NULL);
],[
	AC_DEFINE(HAVE_CLEAR_INODE, 1,
		  [have clear_inode])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.5 encode_fh has parent inode passed in directly
# see kernel commit b0b0382b
#
AC_DEFUN([LC_HAVE_ENCODE_FH_PARENT],
[AC_MSG_CHECKING([if encode_fh have parent inode as parameter])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
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
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
EXTRA_KCFLAGS="$tmp_flags"
])

# 3.5 has generic_file_llseek_size with 5 args
AC_DEFUN([LC_FILE_LLSEEK_SIZE_5ARG],
[AC_MSG_CHECKING([if kernel has generic_file_llseek_size with 5 args])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	generic_file_llseek_size(NULL, 0, 0, 0, 0);
], [
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_FILE_LLSEEK_SIZE_5ARGS, 1,
		[kernel has generic_file_llseek_size with 5 args])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.6 switch i_dentry/d_alias from list to hlist
#
AC_DEFUN([LC_HAVE_DENTRY_D_ALIAS_HLIST],
[AC_MSG_CHECKING([if i_dentry/d_alias uses hlist])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
	#include <linux/list.h>
],[
	struct inode inode;
	struct dentry dentry;
	struct hlist_head head;
	struct hlist_node node;
	inode.i_dentry = head;
	dentry.d_alias = node;
],[
	AC_DEFINE(HAVE_DENTRY_D_ALIAS_HLIST, 1,
		  [have i_dentry/d_alias uses hlist])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
EXTRA_KCFLAGS="$tmp_flags"
])

#
# 3.6 dentry_open uses struct path as first argument
# see kernel commit 765927b2
#
AC_DEFUN([LC_DENTRY_OPEN_USE_PATH],
[AC_MSG_CHECKING([if dentry_open uses struct path as first argument])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
	#include <linux/path.h>
],[
	struct path path;
	dentry_open(&path, 0, NULL);
],[
	AC_DEFINE(HAVE_DENTRY_OPEN_USE_PATH, 1,
		  [dentry_open uses struct path as first argument])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
EXTRA_KCFLAGS="$tmp_flags"
])

#
# 3.6 vfs adds iop->atomic_open
#
AC_DEFUN([LC_HAVE_IOP_ATOMIC_OPEN],
[AC_MSG_CHECKING([if iop has atomic_open])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	struct inode_operations iop;
	iop.atomic_open = NULL;
],[
	AC_DEFINE(HAVE_IOP_ATOMIC_OPEN, 1,
		  [have iop atomic_open])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.7 posix_acl_{to,from}_xattr take struct user_namespace
#
AC_DEFUN([LC_HAVE_POSIXACL_USER_NS],
[AC_MSG_CHECKING([if posix_acl_to_xattr takes struct user_namespace])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
	#include <linux/posix_acl_xattr.h>
],[
	posix_acl_to_xattr((struct user_namespace *)NULL, NULL, NULL, 0);
],[
	AC_DEFINE(HAVE_POSIXACL_USER_NS, 1,
		  [posix_acl_to_xattr takes struct user_namespace])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.9 uses hlist_for_each_entry with 3 args
# b67bfe0d42cac56c512dd5da4b1b347a23f4b70a
#
AC_DEFUN([LC_HAVE_HLIST_FOR_EACH_3ARG],
[AC_MSG_CHECKING([if hlist_for_each_entry has 3 args])
LB_LINUX_TRY_COMPILE([
	#include <linux/list.h>
	#include <linux/fs.h>
],[
	struct inode *inode;
	struct dentry *dentry;
	hlist_for_each_entry(dentry, &inode->i_dentry, d_alias) {
		continue;
	}
],[
	AC_DEFINE(HAVE_HLIST_FOR_EACH_3ARG, 1, [3 args])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# 3.9 killed f_vfsmnt by
# 182be684784334598eee1d90274e7f7aa0063616
# replacement is f_path.mnt
#
AC_DEFUN([LC_HAVE_F_PATH_MNT],
[AC_MSG_CHECKING([if struct file has f_path.mnt])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	struct file *fp = NULL;
	struct path  path;

	path.mnt = fp->f_path.mnt;
],[
	AC_DEFINE(HAVE_F_PATH_MNT,1,[yes])
	AC_MSG_RESULT([yes])
],[
	AC_MSG_RESULT([no])
])
])

#
# LC_PROG_LINUX
#
# Lustre linux kernel checks
#
AC_DEFUN([LC_PROG_LINUX],
         [
         LC_CONFIG_PINGER
         LC_CONFIG_CHECKSUM
         LC_CONFIG_LIBLUSTRE_RECOVERY
         LC_CONFIG_HEALTH_CHECK_WRITE
         LC_CONFIG_LRU_RESIZE
         LC_LLITE_LLOOP_MODULE

         LC_CAPA_CRYPTO
         LC_CONFIG_RMTCLIENT
         LC_CONFIG_GSS

         # 2.6.24
         LC_BIO_ENDIO_2ARG
         LC_PROCFS_DELETED

         # 2.6.27.15-2 sles11
         LC_HAVE_QUOTAIO_H

         # 2.6.32
         LC_BLK_QUEUE_MAX_SEGMENTS

	 # 2.6.34
	 LC_HAVE_DQUOT_FS_DISK_QUOTA
	 LC_HAVE_DQUOT_SUSPEND

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

         # 2.6.39
         LC_REQUEST_QUEUE_UNPLUG_FN
	 LC_HAVE_FSTYPE_MOUNT
	 LC_IOP_TRUNCATE
	 LC_HAVE_INODE_OWNER_OR_CAPABLE

	 # 3.0
	 LC_DIRTY_INODE_WITH_FLAG

	 # 3.1
	 LC_LM_XXX_LOCK_MANAGER_OPS
	 LC_INODE_DIO_WAIT
	 LC_IOP_GET_ACL
	 LC_FILE_LLSEEK_SIZE
	 LC_INODE_PERMISION_2ARGS

	 # 3.1.1
	 LC_BLOCKS_FOR_TRUNCATE

	 # 3.2
	 LC_HAVE_VOID_MAKE_REQUEST_FN
	 LC_HAVE_PROTECT_I_NLINK

	 # 3.3
	 LC_HAVE_MIGRATE_HEADER
	 LC_MIGRATEPAGE_4ARGS
	 LC_SUPEROPS_USE_DENTRY
	 LC_INODEOPS_USE_UMODE_T

	 # 3.4
	 LC_TOUCH_ATIME_1ARG
	 LC_HAVE_D_MAKE_ROOT
	 LC_KMAP_ATOMIC_HAS_1ARG

	 # 3.5
	 LC_HAVE_CLEAR_INODE
	 LC_HAVE_ENCODE_FH_PARENT
	 LC_FILE_LLSEEK_SIZE_5ARG

	 # 3.6
	 LC_HAVE_DENTRY_D_ALIAS_HLIST
	 LC_DENTRY_OPEN_USE_PATH
	 LC_HAVE_IOP_ATOMIC_OPEN

	 # 3.7
	 LC_HAVE_POSIXACL_USER_NS

	 # 3.9
	 LC_HAVE_HLIST_FOR_EACH_3ARG
	 LC_HAVE_F_PATH_MNT

	 #
	 if test x$enable_server != xno ; then
		LC_FUNC_DEV_SET_RDONLY
		LC_STACK_SIZE
		LC_QUOTA64
		LC_QUOTA_CONFIG
	 fi
])

#
# LC_CONFIG_CLIENT
#
# Check whether to build the client side of Lustre
#
AC_DEFUN([LC_CONFIG_CLIENT],
[AC_MSG_CHECKING([whether to build Lustre client support])
AC_ARG_ENABLE([client],
	AC_HELP_STRING([--disable-client],
			[disable Lustre client support]),
	[],[enable_client='yes'])
AC_MSG_RESULT([$enable_client])
])

#
# LC_CONFIG_LIBLUSTRE
#
# whether to build liblustre
#
AC_DEFUN([LC_CONFIG_LIBLUSTRE],
[AC_MSG_CHECKING([whether to build Lustre library])
AC_ARG_ENABLE([liblustre],
	AC_HELP_STRING([--disable-liblustre],
			[disable building of Lustre library]),
	[],[enable_liblustre=$with_sysio])
AC_MSG_RESULT([$enable_liblustre])
# only build sysio if liblustre is built
with_sysio="$enable_liblustre"

AC_MSG_CHECKING([whether to build liblustre tests])
AC_ARG_ENABLE([liblustre-tests],
	AC_HELP_STRING([--enable-liblustre-tests],
			[enable liblustre tests, if --disable-tests is used]),
	[],[enable_liblustre_tests=$enable_tests])
if test x$enable_liblustre != xyes ; then
   enable_liblustre_tests='no'
fi
AC_MSG_RESULT([$enable_liblustre_tests])

AC_MSG_CHECKING([whether to enable liblustre acl])
AC_ARG_ENABLE([liblustre-acl],
	AC_HELP_STRING([--disable-liblustre-acl],
			[disable ACL support for liblustre]),
	[],[enable_liblustre_acl=yes])
AC_MSG_RESULT([$enable_liblustre_acl])
if test x$enable_liblustre_acl = xyes ; then
  AC_DEFINE(LIBLUSTRE_POSIX_ACL, 1, Liblustre Support ACL-enabled MDS)
fi

#
# --enable-mpitest
#
AC_ARG_ENABLE(mpitests,
	AC_HELP_STRING([--enable-mpitests=yes|no|mpicc wrapper],
                           [include mpi tests]),
	[
	 enable_mpitests=yes
         case $enableval in
         yes)
		MPICC_WRAPPER=mpicc
		;;
         no)
		enable_mpitests=no
		;;
         *)
		MPICC_WRAPPER=$enableval
                 ;;
	 esac
	],
	[
	MPICC_WRAPPER=mpicc
	enable_mpitests=yes
	]
)

if test x$enable_mpitests != xno; then
	AC_MSG_CHECKING([whether mpitests can be built])
	oldcc=$CC
	CC=$MPICC_WRAPPER
	AC_LINK_IFELSE(
	    [AC_LANG_PROGRAM([[
		    #include <mpi.h>
	        ]],[[
		    int flag;
		    MPI_Initialized(&flag);
		]])],
	    [
		    AC_MSG_RESULT([yes])
	    ],[
		    AC_MSG_RESULT([no])
		    enable_mpitests=no
	])
	CC=$oldcc
fi
AC_SUBST(MPICC_WRAPPER)

AC_MSG_NOTICE([Enabling Lustre configure options for libsysio])
ac_configure_args="$ac_configure_args --with-lustre-hack --with-sockets"

LC_CONFIG_PINGER
LC_CONFIG_LIBLUSTRE_RECOVERY
])

#
# LC_CONFIG_QUOTA
#
# whether to enable quota support global control
#
AC_DEFUN([LC_CONFIG_QUOTA],
[AC_ARG_ENABLE([quota],
	AC_HELP_STRING([--enable-quota],
			[enable quota support]),
	[],[enable_quota='yes'])
])

AC_DEFUN([LC_QUOTA],
[#check global
LC_CONFIG_QUOTA
#check for utils
if test x$enable_quota != xno -a x$enable_utils != xno; then
AC_CHECK_HEADER(sys/quota.h,
                [AC_DEFINE(HAVE_SYS_QUOTA_H, 1, [Define to 1 if you have <sys/quota.h>.])],
                [AC_MSG_ERROR([don't find <sys/quota.h> in your system])])
fi
])

#
# LC_CONFIG_SPLIT
#
# whether to enable split support
#
AC_DEFUN([LC_CONFIG_SPLIT],
[AC_MSG_CHECKING([whether to enable split support])
AC_ARG_ENABLE([split],
	AC_HELP_STRING([--enable-split],
			[enable split support]),
	[],[enable_split='no'])
AC_MSG_RESULT([$enable_split])
if test x$enable_split != xno; then
   AC_DEFINE(HAVE_SPLIT_SUPPORT, 1, [enable split support])
fi
])

#
# LC_LLITE_LLOOP_MODULE
# lloop_llite.ko does not currently work with page sizes
# of 64k or larger.
#
AC_DEFUN([LC_LLITE_LLOOP_MODULE],
[AC_MSG_CHECKING([whether to enable llite_lloop module])
LB_LINUX_TRY_COMPILE([
        #include <asm/page.h>
],[
        #if PAGE_SIZE >= 65536
        #error "PAGE_SIZE >= 65536"
        #endif
],[
        enable_llite_lloop_module='yes'
        AC_MSG_RESULT([yes])
],[
        enable_llite_lloop_module='no'
        AC_MSG_RESULT([no])
])
])

#
# LC_OSD_ADDON
#
# configure support for optional OSD implementation
#
AC_DEFUN([LC_OSD_ADDON],
[AC_MSG_CHECKING([for osd])
AC_ARG_WITH([osd],
	AC_HELP_STRING([--with-osd=path],
                       [set path to optional osd]),
        [
		case $with_osd in
			no)     ENABLEOSDADDON=0
				;;
			*)	OSDADDON="${with_osd}"
				ENABLEOSDADDON=1
				;;
		esac
	], [
		ENABLEOSDADDON=0
	])
if test $ENABLEOSDADDON -eq 0; then
	AC_MSG_RESULT([no])
	OSDADDON=
else
	OSDMODNAME=`basename $OSDADDON`
	if test -e $LUSTRE/$OSDMODNAME; then
		AC_MSG_RESULT([can't link])
		OSDADDON=
	elif ln -s $OSDADDON $LUSTRE/$OSDMODNAME; then
		AC_MSG_RESULT([$OSDMODNAME])
		OSDADDON="subdir-m += $OSDMODNAME"
	else
		AC_MSG_RESULT([can't link])
		OSDADDON=
	fi
fi
AC_SUBST(OSDADDON)
])

#
# LC_CONFIGURE
#
# other configure checks
#
AC_DEFUN([LC_CONFIGURE],
[LC_CONFIG_OBD_BUFFER_SIZE

if test $target_cpu == "i686" -o $target_cpu == "x86_64"; then
        CFLAGS="$CFLAGS -Werror"
fi

# maximum MDS thread count
LC_MDS_MAX_THREADS

# include/liblustre.h
AC_CHECK_HEADERS([sys/user.h sys/vfs.h stdint.h blkid/blkid.h])

# liblustre/llite_lib.h
AC_CHECK_HEADERS([xtio.h file.h])

# liblustre/dir.c
AC_CHECK_HEADERS([linux/types.h sys/types.h linux/unistd.h unistd.h])

# liblustre/lutil.c
AC_CHECK_HEADERS([netinet/in.h arpa/inet.h catamount/data.h])
AC_CHECK_FUNCS([inet_ntoa])

# libsysio/src/readlink.c
LC_READLINK_SSIZE_T

# lvfs/prng.c - depends on linux/types.h from liblustre/dir.c
AC_CHECK_HEADERS([linux/random.h], [], [],
                 [#ifdef HAVE_LINUX_TYPES_H
                  # include <linux/types.h>
                  #endif
                 ])

# utils/llverfs.c
AC_CHECK_HEADERS([ext2fs/ext2fs.h])

# check for -lz support
ZLIB=""
AC_CHECK_LIB([z],
             [adler32],
             [AC_CHECK_HEADERS([zlib.h],
                               [ZLIB="-lz"
                                AC_DEFINE([HAVE_ADLER], 1,
                                          [support alder32 checksum type])],
                               [AC_MSG_WARN([No zlib-devel package found,
                                             unable to use adler32 checksum])])],
             [AC_MSG_WARN([No zlib package found, unable to use adler32 checksum])]
)
AC_SUBST(ZLIB)

SELINUX=""
AC_CHECK_LIB([selinux],
		[is_selinux_enabled],
		[AC_CHECK_HEADERS([selinux.h],
				[SELINUX="-lselinux"
				AC_DEFINE([HAVE_SELINUX], 1,
						[support for selinux ])],
				[AC_MSG_WARN([No selinux-devel package found,
						unable to build selinux enabled
						tools])])],
		[AC_MSG_WARN([No selinux package found, unable to build selinux
				enabled tools])]
)
AC_SUBST(SELINUX)

# Super safe df
AC_ARG_ENABLE([mindf],
      AC_HELP_STRING([--enable-mindf],
                      [Make statfs report the minimum available space on any single OST instead of the sum of free space on all OSTs]),
      [],[])
if test "$enable_mindf" = "yes" ;  then
      AC_DEFINE([MIN_DF], 1, [Report minimum OST free space])
fi

AC_ARG_ENABLE([fail_alloc],
        AC_HELP_STRING([--disable-fail-alloc],
                [disable randomly alloc failure]),
        [],[enable_fail_alloc=yes])
AC_MSG_CHECKING([whether to randomly failing memory alloc])
AC_MSG_RESULT([$enable_fail_alloc])
if test x$enable_fail_alloc != xno ; then
        AC_DEFINE([RANDOM_FAIL_ALLOC], 1, [enable randomly alloc failure])
fi

AC_ARG_ENABLE([invariants],
        AC_HELP_STRING([--enable-invariants],
                [enable invariant checking (cpu intensive)]),
        [],[])
AC_MSG_CHECKING([whether to check invariants (expensive cpu-wise)])
AC_MSG_RESULT([$enable_invariants])
if test x$enable_invariants = xyes ; then
	AC_DEFINE([CONFIG_LUSTRE_DEBUG_EXPENSIVE_CHECK], 1, [enable invariant checking])
fi

AC_ARG_ENABLE([lu_ref],
        AC_HELP_STRING([--enable-lu_ref],
                [enable lu_ref reference tracking code]),
        [],[])
AC_MSG_CHECKING([whether to track references with lu_ref])
AC_MSG_RESULT([$enable_lu_ref])
if test x$enable_lu_ref = xyes ; then
        AC_DEFINE([USE_LU_REF], 1, [enable lu_ref reference tracking code])
fi

AC_ARG_ENABLE([pgstate-track],
              AC_HELP_STRING([--enable-pgstate-track],
                             [enable page state tracking]),
              [enable_pgstat_track='yes'],[])
AC_MSG_CHECKING([whether to enable page state tracking])
AC_MSG_RESULT([$enable_pgstat_track])
if test x$enable_pgstat_track = xyes ; then
        AC_DEFINE([CONFIG_DEBUG_PAGESTATE_TRACKING], 1,
                  [enable page state tracking code])
fi
])

#
# LC_CONDITIONALS
#
# AM_CONDITIONALS for lustre
#
AC_DEFUN([LC_CONDITIONALS],
[AM_CONDITIONAL(LIBLUSTRE, test x$enable_liblustre = xyes)
AM_CONDITIONAL(LIBLUSTRE_TESTS, test x$enable_liblustre_tests = xyes)
AM_CONDITIONAL(MPITESTS, test x$enable_mpitests = xyes, Build MPI Tests)
AM_CONDITIONAL(CLIENT, test x$enable_client = xyes)
AM_CONDITIONAL(SERVER, test x$enable_server = xyes)
AM_CONDITIONAL(SPLIT, test x$enable_split = xyes)
AM_CONDITIONAL(BLKID, test x$ac_cv_header_blkid_blkid_h = xyes)
AM_CONDITIONAL(EXT2FS_DEVEL, test x$ac_cv_header_ext2fs_ext2fs_h = xyes)
AM_CONDITIONAL(GSS, test x$enable_gss = xyes)
AM_CONDITIONAL(GSS_KEYRING, test x$enable_gss_keyring = xyes)
AM_CONDITIONAL(GSS_PIPEFS, test x$enable_gss_pipefs = xyes)
AM_CONDITIONAL(LIBPTHREAD, test x$enable_libpthread = xyes)
AM_CONDITIONAL(LLITE_LLOOP, test x$enable_llite_lloop_module = xyes)
])

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
lustre/include/lustre_ver.h
lustre/include/linux/Makefile
lustre/include/darwin/Makefile
lustre/include/lustre/Makefile
lustre/kernel_patches/targets/2.6-rhel6.target
lustre/kernel_patches/targets/2.6-rhel5.target
lustre/kernel_patches/targets/2.6-sles11.target
lustre/kernel_patches/targets/3.0-sles11.target
lustre/kernel_patches/targets/3.0-sles11sp3.target
lustre/kernel_patches/targets/2.6-fc11.target
lustre/kernel_patches/targets/2.6-fc12.target
lustre/kernel_patches/targets/2.6-fc15.target
lustre/kernel_patches/targets/3.x-fc18.target
lustre/ldlm/Makefile
lustre/fid/Makefile
lustre/fid/autoMakefile
lustre/liblustre/Makefile
lustre/liblustre/tests/Makefile
lustre/liblustre/tests/mpi/Makefile
lustre/llite/Makefile
lustre/llite/autoMakefile
lustre/lclient/Makefile
lustre/lov/Makefile
lustre/lov/autoMakefile
lustre/lvfs/Makefile
lustre/lvfs/autoMakefile
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
lustre/tests/Makefile
lustre/tests/mpi/Makefile
lustre/utils/Makefile
lustre/utils/gss/Makefile
lustre/osp/Makefile
lustre/osp/autoMakefile
lustre/lod/Makefile
lustre/lod/autoMakefile
lustre/obdclass/darwin/Makefile
])
])
