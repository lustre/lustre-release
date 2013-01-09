#* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
#* vim:expandtab:shiftwidth=8:tabstop=8:
#
# LC_CONFIG_SRCDIR
#
# Wrapper for AC_CONFIG_SUBDIR
#
AC_DEFUN([LC_CONFIG_SRCDIR],
[AC_CONFIG_SRCDIR([lustre/obdclass/obdo.c])
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
rootsbindir='/sbin'
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
# LC_FUNC_DEV_SET_RDONLY
#
# check for the old-style dev_set_rdonly which took an extra "devno" param
# and can only set a single device to discard writes at one time
#
AC_DEFUN([LC_FUNC_DEV_SET_RDONLY],
[AC_MSG_CHECKING([if kernel has new dev_set_rdonly])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
        #include <linux/blkdev.h>
],[
        #ifndef HAVE_CLEAR_RDONLY_ON_PUT
        #error needs to be patched by lustre kernel patches from Lustre version 1.4.3 or above.
        #endif
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_DEV_SET_RDONLY, 1, [kernel has new dev_set_rdonly])
],[
        AC_MSG_ERROR([no, Linux kernel source needs to be patches by lustre 
kernel patches from Lustre version 1.4.3 or above.])
])
])

#
# Allow the user to set the MDS thread upper limit
#
AC_DEFUN([LC_MDS_THREADS_MAX],
[
        AC_ARG_WITH([mds_max_threads],
        AC_HELP_STRING([--with-mds-max-threads=size],
                        [define the maximum number of threads available on the MDS: (default=512)]),
        [
                MDS_THREAD_COUNT=$with_mds_max_threads
                AC_DEFINE_UNQUOTED(MDS_THREADS_MAX, $MDS_THREAD_COUNT, [maximum number of mdt threads])
        ])
])

#
# LC_CONFIG_BACKINGFS
#
# setup, check the backing filesystem
#
AC_DEFUN([LC_CONFIG_BACKINGFS],
[
BACKINGFS="ldiskfs"

if test x$with_ldiskfs = xno ; then
	if test x$enable_server = xyes ; then
		AC_MSG_ERROR([ldiskfs is required for 2.6-based servers.])
	fi
else
	# ldiskfs is enabled
	LB_DEFINE_LDISKFS_OPTIONS
fi #ldiskfs

AC_MSG_CHECKING([which backing filesystem to use])
AC_MSG_RESULT([$BACKINGFS])
AC_SUBST(BACKINGFS)
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
# LC_HEADER_LDISKFS_XATTR
#
# CHAOS kernel-devel package will not include fs/ldiskfs/xattr.h
#
AC_DEFUN([LC_HEADER_LDISKFS_XATTR],
[AC_MSG_CHECKING([if ldiskfs has xattr.h header])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-I$LINUX/fs -I$LDISKFS_DIR -I$LDISKFS_DIR/ldiskfs"
LB_LINUX_TRY_COMPILE([
	#include <ldiskfs/xattr.h>
],[
        ldiskfs_xattr_get(NULL, 0, "", NULL, 0);
        ldiskfs_xattr_set_handle(NULL, NULL, 0, "", NULL, 0, 0);

],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_LDISKFS_XATTR_H, 1, [ldiskfs/xattr.h found])
],[
	AC_MSG_RESULT([no])
])
EXTRA_KCFLAGS="$tmp_flags"
])

#
# LC_CONFIG_HEALTH_CHECK_WRITE
#
# Turn on the actual write to the disk
#
AC_DEFUN([LC_CONFIG_HEALTH_CHECK_WRITE],
[AC_MSG_CHECKING([whether to enable a write with the health check])
AC_ARG_ENABLE([health-write],
        AC_HELP_STRING([--enable-health-write],
                        [enable disk writes when doing health check]),
        [],[enable_health_write='no'])
AC_MSG_RESULT([$enable_health_write])
if test x$enable_health_write == xyes ; then
  AC_DEFINE(USE_HEALTH_CHECK_WRITE, 1, Write when Checking Health)
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
AC_DEFINE_UNQUOTED(OBD_MAX_IOCTL_BUFFER, $OBD_BUFFER_SIZE, [IOCTL Buffer Size])
])

#
# LC_STRUCT_STATFS
#
# AIX does not have statfs.f_namelen
#
AC_DEFUN([LC_STRUCT_STATFS],
[AC_MSG_CHECKING([if struct statfs has a f_namelen field])
LB_LINUX_TRY_COMPILE([
	#include <linux/vfs.h>
],[
	struct statfs sfs;
	sfs.f_namelen = 1;
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_STATFS_NAMELEN, 1, [struct statfs has a namelen field])
],[
	AC_MSG_RESULT([no])
])
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
# LC_FUNC_MS_FLOCK_LOCK
#
# 2.6.5 kernel has MS_FLOCK_LOCK sb flag
#
AC_DEFUN([LC_FUNC_MS_FLOCK_LOCK],
[AC_MSG_CHECKING([if kernel has MS_FLOCK_LOCK sb flag])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        int flags = MS_FLOCK_LOCK;
],[
        AC_DEFINE(HAVE_MS_FLOCK_LOCK, 1,
                [kernel has MS_FLOCK_LOCK flag])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

#
# LC_FUNC_HAVE_CAN_SLEEP_ARG
#
# 2.6.5 kernel has third arg can_sleep in fs/locks.c: flock_lock_file_wait()
#
AC_DEFUN([LC_FUNC_HAVE_CAN_SLEEP_ARG],
[AC_MSG_CHECKING([if kernel has third arg can_sleep in fs/locks.c: flock_lock_file_wait()])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        int cansleep;
        struct file *file;
        struct file_lock *file_lock;
        flock_lock_file_wait(file, file_lock, cansleep);
],[
        AC_DEFINE(HAVE_CAN_SLEEP_ARG, 1,
                [kernel has third arg can_sleep in fs/locks.c: flock_lock_file_wait()])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

#
# LC_FUNC_RELEASEPAGE_WITH_GFP
#
# 2.6.9 ->releasepage() takes a gfp_t arg
# This kernel defines gfp_t (HAS_GFP_T) but doesn't use it for this function,
# while others either don't have gfp_t or pass gfp_t as the parameter.
#
AC_DEFUN([LC_FUNC_RELEASEPAGE_WITH_GFP],
[AC_MSG_CHECKING([if releasepage has a gfp_t parameter])
RELEASEPAGE_WITH_GFP="$(grep -c 'releasepage.*gfp_t' $LINUX/include/linux/fs.h)"
if test "$RELEASEPAGE_WITH_GFP" != 0 ; then
	AC_DEFINE(HAVE_RELEASEPAGE_WITH_GFP, 1,
                  [releasepage with gfp_t parameter])
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi
])

#
# between 2.6.5 - 2.6.22 filemap_populate is exported in some kernels
#
AC_DEFUN([LC_FILEMAP_POPULATE],
[AC_MSG_CHECKING([for exported filemap_populate])
LB_LINUX_TRY_COMPILE([
        #include <asm/page.h>
        #include <linux/mm.h>
],[
	filemap_populate(NULL, 0, 0, __pgprot(0), 0, 0);
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_FILEMAP_POPULATE, 1, [Kernel exports filemap_populate])
],[
        AC_MSG_RESULT([no])
])
])

#
# added in 2.6.15
#
AC_DEFUN([LC_D_ADD_UNIQUE],
[AC_MSG_CHECKING([for d_add_unique])
LB_LINUX_TRY_COMPILE([
        #include <linux/dcache.h>
],[
       d_add_unique(NULL, NULL);
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_D_ADD_UNIQUE, 1, [Kernel has d_add_unique])
],[
        AC_MSG_RESULT([no])
])
])

#
# added in 2.6.17
#
AC_DEFUN([LC_BIT_SPINLOCK_H],
[LB_CHECK_FILE([$LINUX/include/linux/bit_spinlock.h],[
	AC_MSG_CHECKING([if bit_spinlock.h can be compiled])
	LB_LINUX_TRY_COMPILE([
		#include <asm/processor.h>
		#include <linux/spinlock.h>
		#include <linux/bit_spinlock.h>
	],[],[
		AC_MSG_RESULT([yes])
		AC_DEFINE(HAVE_BIT_SPINLOCK_H, 1, [Kernel has bit_spinlock.h])
	],[
		AC_MSG_RESULT([no])
	])
],
[])
])

#
# After 2.6.26 we no longer have xattr_acl.h 
#
AC_DEFUN([LC_XATTR_ACL],
[LB_CHECK_FILE([$LINUX/include/linux/xattr_acl.h],[
	AC_MSG_CHECKING([if xattr_acl.h can be compiled])
	LB_LINUX_TRY_COMPILE([
		#include <linux/xattr_acl.h>
	],[],[
		AC_MSG_RESULT([yes])
		AC_DEFINE(HAVE_XATTR_ACL, 1, [Kernel has xattr_acl])
	],[
		AC_MSG_RESULT([no])
	])
],
[])
])


#
# added in 2.6.16
#
AC_DEFUN([LC_STRUCT_INTENT_FILE],
[AC_MSG_CHECKING([if struct open_intent has a file field])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
        #include <linux/namei.h>
],[
        struct open_intent intent;
        &intent.file;
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_FILE_IN_STRUCT_INTENT, 1, [struct open_intent has a file field])
],[
        AC_MSG_RESULT([no])
])
])


#
# After 2.6.16 the xattr_acl API is removed, and posix_acl is used instead
#
AC_DEFUN([LC_POSIX_ACL_XATTR_H],
[LB_CHECK_FILE([$LINUX/include/linux/posix_acl_xattr.h],[
        AC_MSG_CHECKING([if linux/posix_acl_xattr.h can be compiled])
        LB_LINUX_TRY_COMPILE([
                #include <linux/fs.h>
                #include <linux/posix_acl_xattr.h>
        ],[],[
                AC_MSG_RESULT([yes])
                AC_DEFINE(HAVE_LINUX_POSIX_ACL_XATTR_H, 1, [linux/posix_acl_xattr.h found])

        ],[
                AC_MSG_RESULT([no])
        ])
$1
],[
AC_MSG_RESULT([no])
])
])

#
# only for Lustre-patched kernels
#
AC_DEFUN([LC_LUSTRE_VERSION_H],
[LB_CHECK_FILE([$LINUX/include/linux/lustre_version.h],[
	rm -f "$LUSTRE/include/linux/lustre_version.h"
],[
	touch "$LUSTRE/include/linux/lustre_version.h"
	if test x$enable_server = xyes ; then
        	AC_MSG_WARN([Unpatched kernel detected.])
        	AC_MSG_WARN([Lustre servers cannot be built with an unpatched kernel;])
        	AC_MSG_WARN([disabling server build])
        	enable_server='no'
	fi
])
	if test x$enable_server = xyes ; then
		if test x$RHEL_KERNEL = xyes -a x$LINUXRELEASE != x${LINUXRELEASE##2.6.9} ; then
        		AC_MSG_WARN([Lustre server has been disabled with rhel4 kernel;])
        		AC_MSG_WARN([disabling server build])
        		enable_server='no'
		fi
		if test x$SUSE_KERNEL = xyes -a x$LINUXRELEASE != x${LINUXRELEASE##2.6.5} ; then
        		AC_MSG_WARN([Lustre server has been disabled with sles9 kernel;])
        		AC_MSG_WARN([disabling server build])
			enable_server='no'
		fi
	fi
])

#
# 2.6.19 check for FS_RENAME_DOES_D_MOVE flag
#
AC_DEFUN([LC_FS_RENAME_DOES_D_MOVE],
[AC_MSG_CHECKING([if kernel has FS_RENAME_DOES_D_MOVE flag])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        int v = FS_RENAME_DOES_D_MOVE;
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_FS_RENAME_DOES_D_MOVE, 1, [kernel has FS_RENAME_DOES_D_MOVE flag])
],[
        AC_MSG_RESULT([no])
])
])


#
# LC_FUNC_F_OP_FLOCK
#
# rhel4.2 kernel has f_op->flock field
#
AC_DEFUN([LC_FUNC_F_OP_FLOCK],
[AC_MSG_CHECKING([if struct file_operations has flock field])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct file_operations ll_file_operations_flock;
        ll_file_operations_flock.flock = NULL;
],[
        AC_DEFINE(HAVE_F_OP_FLOCK, 1,
                [struct file_operations has flock field])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# LC_EXPORT_SYNCHRONIZE_RCU
# after 2.6.12 synchronize_rcu is preferred over synchronize_kernel
AC_DEFUN([LC_EXPORT_SYNCHRONIZE_RCU],
[LB_CHECK_SYMBOL_EXPORT([synchronize_rcu],
[kernel/rcupdate.c],[
        AC_DEFINE(HAVE_SYNCHRONIZE_RCU, 1,
                [in 2.6.12 synchronize_rcu preferred over synchronize_kernel])
],[
])
])

# LC_INODE_I_MUTEX
# after 2.6.15 inode have i_mutex intead of i_sem
AC_DEFUN([LC_INODE_I_MUTEX],
[AC_MSG_CHECKING([if inode has i_mutex ])
LB_LINUX_TRY_COMPILE([
	#include <linux/mutex.h>
	#include <linux/fs.h>
	#undef i_mutex
],[
	struct inode i;

	mutex_unlock(&i.i_mutex);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_INODE_I_MUTEX, 1,
                [after 2.6.15 inode have i_mutex intead of i_sem])
],[
        AC_MSG_RESULT(no)
])
])

# LC_DQUOTOFF_MUTEX
# after 2.6.17 dquote use mutex instead if semaphore
AC_DEFUN([LC_DQUOTOFF_MUTEX],
[AC_MSG_CHECKING([use dqonoff_mutex])
LB_LINUX_TRY_COMPILE([
	#include <linux/mutex.h>
	#include <linux/fs.h>
        #include <linux/quota.h>
],[
        struct quota_info dq;

        mutex_unlock(&dq.dqonoff_mutex);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_DQUOTOFF_MUTEX, 1,
                [after 2.6.17 dquote use mutex instead if semaphore])
],[
        AC_MSG_RESULT(no)
])
])

#
# LC_FLUSH_OWNER_ID
# starting from 2.6.18 the file_operations .flush
# method has a new "fl_owner_t id" parameter
#
AC_DEFUN([LC_FLUSH_OWNER_ID],
[AC_MSG_CHECKING([if file_operations .flush has an fl_owner_t id])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct file_operations *fops = NULL;
        fl_owner_t id;
        int i;

        i = fops->flush(NULL, id);
],[
        AC_DEFINE(HAVE_FLUSH_OWNER_ID, 1,
                [file_operations .flush method has an fl_owner_t id])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

#
# LC_STATFS_DENTRY_PARAM
# starting from 2.6.18 linux kernel uses dentry instead of super_block
# for the first parameter of the super_operations->statfs() callback.
#
AC_DEFUN([LC_STATFS_DENTRY_PARAM],
[AC_MSG_CHECKING([if super_ops.statfs() first parameter is dentry])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
	((struct super_operations *)0)->statfs((struct dentry *)0, (struct kstatfs*)0);
],[
        AC_DEFINE(HAVE_STATFS_DENTRY_PARAM, 1,
                [super_ops.statfs() first parameter is dentry])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
EXTRA_KCFLAGS="$tmp_flags"
])

#
# LC_VFS_KERN_MOUNT
# starting from 2.6.18 kernel don't export do_kern_mount
# and want to use vfs_kern_mount instead.
#
AC_DEFUN([LC_VFS_KERN_MOUNT],
[AC_MSG_CHECKING([vfs_kern_mount exist in kernel])
LB_LINUX_TRY_COMPILE([
        #include <linux/mount.h>
],[
        vfs_kern_mount(NULL, 0, NULL, NULL);
],[
        AC_DEFINE(HAVE_VFS_KERN_MOUNT, 1,
                [vfs_kern_mount exist in kernel])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# 
# LC_INVALIDATEPAGE_RETURN_INT
# 2.6.17 changes return type for invalidatepage to 'void' from 'int'
#
AC_DEFUN([LC_INVALIDATEPAGE_RETURN_INT],
[AC_MSG_CHECKING([invalidatepage has return int])
LB_LINUX_TRY_COMPILE([
        #include <linux/buffer_head.h>
],[
	int rc = block_invalidatepage(NULL, 0);
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_INVALIDATEPAGE_RETURN_INT, 1,
		[Define if return type of invalidatepage should be int])
],[
	AC_MSG_RESULT(no)
])
])

# LC_UMOUNTBEGIN_HAS_VFSMOUNT
# after 2.6.18 umount_begin has different parameters
AC_DEFUN([LC_UMOUNTBEGIN_HAS_VFSMOUNT],
[AC_MSG_CHECKING([if umount_begin needs vfsmount parameter instead of super_block])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>

	struct vfsmount;
	static void cfg_umount_begin (struct vfsmount *v, int flags)
	{
    		;
	}

	static struct super_operations cfg_super_operations = {
		.umount_begin	= cfg_umount_begin,
	};
],[
	cfg_super_operations.umount_begin(NULL,0);
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_UMOUNTBEGIN_VFSMOUNT, 1,
		[Define umount_begin need second argument])
],[
	AC_MSG_RESULT(no)
])
EXTRA_KCFLAGS="$tmp_flags"
])

# inode have i_private field since 2.6.17
AC_DEFUN([LC_INODE_IPRIVATE],
[AC_MSG_CHECKING([if inode has a i_private field])
LB_LINUX_TRY_COMPILE([
#include <linux/fs.h>
],[
	struct inode i;
	i.i_private = NULL; 
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_INODE_IPRIVATE, 1,
		[struct inode has i_private field])
],[
	AC_MSG_RESULT(no)
])
])

# 2.6.19 API changes
# inode don't have i_blksize field
AC_DEFUN([LC_INODE_BLKSIZE],
[AC_MSG_CHECKING([inode has i_blksize field])
LB_LINUX_TRY_COMPILE([
#include <linux/fs.h>
],[
	struct inode i;
	i.i_blksize = 0; 
],[
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_INODE_BLKSIZE, 1,
		[struct inode has i_blksize field])
],[
	AC_MSG_RESULT(no)
])
])

# LC_VFS_READDIR_U64_INO
# 2.6.19 use u64 for inode number instead of inode_t
AC_DEFUN([LC_VFS_READDIR_U64_INO],
[AC_MSG_CHECKING([check vfs_readdir need 64bit inode number])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
#include <linux/fs.h>
	int fillonedir(void * __buf, const char * name, int namlen, loff_t offset,
                      u64 ino, unsigned int d_type)
	{
		return 0;
	}
],[
	filldir_t filter;

	filter = fillonedir;
	return 1;
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_VFS_READDIR_U64_INO, 1,
                [if vfs_readdir need 64bit inode number])
],[
        AC_MSG_RESULT(no)
])
EXTRA_KCFLAGS="$tmp_flags"
])

# LC_FILE_UPDATE_TIME
# 2.6.9 has inode_update_time instead of file_update_time
AC_DEFUN([LC_FILE_UPDATE_TIME],
[AC_MSG_CHECKING([if file_update_time is exported])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        file_update_time(NULL);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_FILE_UPDATE_TIME, 1,
                [use file_update_time])
],[
	AC_MSG_RESULT(no)
])
])

# LC_FILE_WRITEV
# 2.6.19 replaced writev with aio_write
AC_DEFUN([LC_FILE_WRITEV],
[AC_MSG_CHECKING([writev in fops])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct file_operations *fops = NULL;
        fops->writev = NULL;
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_FILE_WRITEV, 1,
                [use fops->writev])
],[
	AC_MSG_RESULT(no)
])
])


# LC_GENERIC_FILE_READ
# 2.6.19 replaced readv with aio_read
AC_DEFUN([LC_FILE_READV],
[AC_MSG_CHECKING([readv in fops])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct file_operations *fops = NULL;
        fops->readv = NULL;
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_FILE_READV, 1,
                [use fops->readv])
],[
        AC_MSG_RESULT(no)
])
])

# LC_NR_PAGECACHE
# 2.6.18 don't export nr_pagecahe
AC_DEFUN([LC_NR_PAGECACHE],
[AC_MSG_CHECKING([kernel export nr_pagecache])
LB_LINUX_TRY_COMPILE([
        #include <linux/pagemap.h>
],[
        return atomic_read(&nr_pagecache);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_NR_PAGECACHE, 1,
                [is kernel export nr_pagecache])
],[
        AC_MSG_RESULT(no)
])
])

# LC_CANCEL_DIRTY_PAGE
# 2.6.20 introduced cancel_dirty_page instead of clear_page_dirty.
AC_DEFUN([LC_CANCEL_DIRTY_PAGE],
        [AC_MSG_CHECKING([kernel has cancel_dirty_page])
        # the implementation of cancel_dirty_page in OFED 1.4.1's SLES10 SP2
        # backport is broken, so ignore it
        if test -f $OFED_BACKPORT_PATH/linux/mm.h &&
           test "$(sed -ne '/^static inline void cancel_dirty_page(struct page \*page, unsigned int account_size)$/,/^}$/p' $OFED_BACKPORT_PATH/linux/mm.h | md5sum)" = "c518cb32d6394760c5bca14cb7538d3e  -"; then
                AC_MSG_RESULT(no)
        else
                LB_LINUX_TRY_COMPILE([
                        #include <linux/mm.h>
                        #include <linux/page-flags.h>
],[
                        cancel_dirty_page(NULL, 0);
],[
                        AC_MSG_RESULT(yes)
                        AC_DEFINE(HAVE_CANCEL_DIRTY_PAGE, 1,
                                  [kernel has cancel_dirty_page instead of clear_page_dirty])
],[
                        AC_MSG_RESULT(no)
])
        fi
])

#
# LC_PAGE_CONSTANT
#
# In order to support raid5 zerocopy patch, we have to patch the kernel to make
# it support constant page, which means the page won't be modified during the
# IO.
#
AC_DEFUN([LC_PAGE_CONSTANT],
[AC_MSG_CHECKING([if kernel have PageConstant defined])
LB_LINUX_TRY_COMPILE([
        #include <linux/mm.h>
        #include <linux/page-flags.h>
],[
        #ifndef PG_constant
        #error "Have no raid5 zcopy patch"
        #endif
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_PAGE_CONSTANT, 1, [kernel have PageConstant supported])
],[
        AC_MSG_RESULT(no);
])
])

# RHEL5 in FS-cache patch rename PG_checked flag into PG_fs_misc
AC_DEFUN([LC_PG_FS_MISC],
[AC_MSG_CHECKING([kernel has PG_fs_misc])
LB_LINUX_TRY_COMPILE([
        #include <linux/mm.h>
        #include <linux/page-flags.h>
],[
        #ifndef PG_fs_misc
        #error PG_fs_misc not defined in kernel
        #endif
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_PG_FS_MISC, 1,
                  [is kernel have PG_fs_misc])
],[
        AC_MSG_RESULT(no)
])
])

# RHEL5 PageChecked and SetPageChecked defined
AC_DEFUN([LC_PAGE_CHECKED],
[AC_MSG_CHECKING([kernel has PageChecked and SetPageChecked])
LB_LINUX_TRY_COMPILE([
        #include <linux/autoconf.h>
#ifdef HAVE_LINUX_MMTYPES_H
        #include <linux/mm_types.h>
#endif
	#include <linux/page-flags.h>
],[
 	struct page *p;

        /* before 2.6.26 this define*/
        #ifndef PageChecked	
 	/* 2.6.26 use function instead of define for it */
 	SetPageChecked(p);
 	PageChecked(p);
 	#endif
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_PAGE_CHECKED, 1,
                  [does kernel have PageChecked and SetPageChecked])
],[
        AC_MSG_RESULT(no)
])
])

# truncate_complete_page() was exported from RHEL5/SLES10/SLES11
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

AC_DEFUN([LC_EXPORT_TRUNCATE_RANGE],
[LB_CHECK_SYMBOL_EXPORT([truncate_inode_pages_range],
[mm/truncate.c],[
AC_DEFINE(HAVE_TRUNCATE_RANGE, 1,
            [kernel export truncate_inode_pages_range])
],[
])
])

AC_DEFUN([LC_EXPORT_D_REHASH_COND],
[LB_CHECK_SYMBOL_EXPORT([d_rehash_cond],
[fs/dcache.c],[
AC_DEFINE(HAVE_D_REHASH_COND, 1,
            [d_rehash_cond is exported by the kernel])
],[
])
])

AC_DEFUN([LC_EXPORT___D_REHASH],
[LB_CHECK_SYMBOL_EXPORT([__d_rehash],
[fs/dcache.c],[
AC_DEFINE(HAVE___D_REHASH, 1,
            [__d_rehash is exported by the kernel])
],[
])
])

AC_DEFUN([LC_EXPORT_D_MOVE_LOCKED],
[LB_CHECK_SYMBOL_EXPORT([d_move_locked],
[fs/dcache.c],[
AC_DEFINE(HAVE_D_MOVE_LOCKED, 1,
            [d_move_locked is exported by the kernel])
],[
])
])

AC_DEFUN([LC_EXPORT___D_MOVE],
[LB_CHECK_SYMBOL_EXPORT([__d_move],
[fs/dcache.c],[
AC_DEFINE(HAVE___D_MOVE, 1,
            [__d_move is exported by the kernel])
],[
])
])

#
# LC_EXPORT_INVALIDATE_MAPPING_PAGES
#
# SLES9, RHEL4, RHEL5, vanilla 2.6.24 export invalidate_mapping_pages() but
# SLES10 2.6.16 does not, for some reason.  For filter cache invalidation.
#
AC_DEFUN([LC_EXPORT_INVALIDATE_MAPPING_PAGES],
    [LB_CHECK_SYMBOL_EXPORT([invalidate_mapping_pages], [mm/truncate.c], [
         AC_DEFINE(HAVE_INVALIDATE_MAPPING_PAGES, 1,
                        [exported invalidate_mapping_pages])],
    [LB_CHECK_SYMBOL_EXPORT([invalidate_inode_pages], [mm/truncate.c], [
         AC_DEFINE(HAVE_INVALIDATE_INODE_PAGES, 1,
                        [exported invalidate_inode_pages])], [
       AC_MSG_ERROR([no way to invalidate pages])
  ])
    ],[])
])

#
# LC_EXPORT_FILEMAP_FDATASYNC_RANGE
#
# No standard kernels export this
#
AC_DEFUN([LC_EXPORT_FILEMAP_FDATAWRITE_RANGE],
[LB_CHECK_SYMBOL_EXPORT([filemap_fdatawrite_range],
[mm/filemap.c],[
AC_DEFINE(HAVE_FILEMAP_FDATAWRITE_RANGE, 1,
            [filemap_fdatawrite_range is exported by the kernel])
],[
])
])

# The actual symbol exported varies among architectures, so we need
# to check many symbols (but only in the current architecture.)  No
# matter what symbol is exported, the kernel #defines node_to_cpumask
# to the appropriate function and that's what we use.
AC_DEFUN([LC_EXPORT_NODE_TO_CPUMASK],
         [LB_CHECK_SYMBOL_EXPORT([node_to_cpumask],
                                 [arch/$LINUX_ARCH/mm/numa.c],
                                 [AC_DEFINE(HAVE_NODE_TO_CPUMASK, 1,
                                            [node_to_cpumask is exported by
                                             the kernel])]) # x86_64
          LB_CHECK_SYMBOL_EXPORT([node_to_cpu_mask],
                                 [arch/$LINUX_ARCH/kernel/smpboot.c],
                                 [AC_DEFINE(HAVE_NODE_TO_CPUMASK, 1,
                                            [node_to_cpumask is exported by
                                             the kernel])]) # ia64
          LB_CHECK_SYMBOL_EXPORT([node_2_cpu_mask],
                                 [arch/$LINUX_ARCH/kernel/smpboot.c],
                                 [AC_DEFINE(HAVE_NODE_TO_CPUMASK, 1,
                                            [node_to_cpumask is exported by
                                             the kernel])]) # i386
          ])

#
# LC_VFS_INTENT_PATCHES
#
# check if the kernel has the VFS intent patches
AC_DEFUN([LC_VFS_INTENT_PATCHES],
[AC_MSG_CHECKING([if the kernel has the VFS intent patches])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
        #include <linux/namei.h>
],[
        struct nameidata nd;
        struct lookup_intent *it;

        it = &nd.intent;
        intent_init(it, IT_OPEN);
        it->d.lustre.it_disposition = 0;
        it->d.lustre.it_data = NULL;
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_VFS_INTENT_PATCHES, 1, [VFS intent patches are applied])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.22 lost second parameter for invalidate_bdev
AC_DEFUN([LC_INVALIDATE_BDEV_2ARG],
[AC_MSG_CHECKING([if invalidate_bdev has second argument])
LB_LINUX_TRY_COMPILE([
        #include <linux/buffer_head.h>
],[
        invalidate_bdev(NULL,0);
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_INVALIDATE_BDEV_2ARG, 1,
                [invalidate_bdev has second argument])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.12 merge patch from oracle to convert tree_lock from spinlock to rwlock
AC_DEFUN([LC_RW_TREE_LOCK],
[AC_MSG_CHECKING([if kernel has tree_lock as rwlock])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct address_space a;

        write_lock(&a.tree_lock);
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_RW_TREE_LOCK, 1, [kernel has tree_lock as rw_lock])
],[
        AC_MSG_RESULT([no])
])
EXTRA_KCFLAGS="$tmp_flags"
])

#
# LC_FUNC_GRAB_CACHE_PAGE_NOWAIT_GFP
#
# Check for our patched grab_cache_page_nowait_gfp() function
# after 2.6.29 we can emulate this using add_to_page_cache_lru()
#
AC_DEFUN([LC_FUNC_GRAB_CACHE_PAGE_NOWAIT_GFP],
[LB_CHECK_SYMBOL_EXPORT([grab_cache_page_nowait_gfp],
[mm/filemap.c],[
        AC_DEFINE(HAVE_GRAB_CACHE_PAGE_NOWAIT_GFP, 1,
                  [kernel exports grab_cache_page_nowait_gfp])
        ],
        [LB_CHECK_SYMBOL_EXPORT([add_to_page_cache_lru],
        [mm/filemap.c],[
                AC_DEFINE(HAVE_ADD_TO_PAGE_CACHE_LRU, 1,
                        [kernel exports add_to_page_cache_lru])
        ],[
        ])
        ])
])


# 2.6.23 have return type 'void' for unregister_blkdev
AC_DEFUN([LC_UNREGISTER_BLKDEV_RETURN_INT],
[AC_MSG_CHECKING([if unregister_blkdev return int])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        int i = unregister_blkdev(0,NULL);
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_UNREGISTER_BLKDEV_RETURN_INT, 1, 
                [unregister_blkdev return int])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.23 change .sendfile to .splice_read
# RHEL4 (-92 kernel) have both sendfile and .splice_read API
AC_DEFUN([LC_KERNEL_SENDFILE],
[AC_MSG_CHECKING([if kernel has .sendfile])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct file_operations file;

        file.sendfile = NULL;
], [
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_KERNEL_SENDFILE, 1,
                [kernel has .sendfile])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.23 change .sendfile to .splice_read
AC_DEFUN([LC_KERNEL_SPLICE_READ],
[AC_MSG_CHECKING([if kernel has .splice_read])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct file_operations file;

        file.splice_read = NULL;
], [
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_KERNEL_SPLICE_READ, 1,
                [kernel has .slice_read])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.23 extract nfs export related data into exportfs.h
AC_DEFUN([LC_HAVE_EXPORTFS_H],
[LB_CHECK_FILE([$LINUX/include/linux/exportfs.h], [
        AC_DEFINE(HAVE_LINUX_EXPORTFS_H, 1,
                [kernel has include/exportfs.h])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.23 have new page fault handling API
AC_DEFUN([LC_VM_OP_FAULT],
[AC_MSG_CHECKING([if kernel has .fault in vm_operation_struct])
LB_LINUX_TRY_COMPILE([
        #include <linux/mm.h>
],[
        struct vm_operations_struct op;

        op.fault = NULL;
], [
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_VM_OP_FAULT, 1,
                [if kernel has .fault in vm_operation_struct])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.23 has new shrinker API
AC_DEFUN([LC_REGISTER_SHRINKER],
[LB_CHECK_SYMBOL_EXPORT([register_shrinker],
[mm/vmscan.c],[
        AC_DEFINE(HAVE_REGISTER_SHRINKER, 1,
                  [kernel exports register_shrinker])
# 2.6.32 added another argument to struct shrinker->shrink
        AC_MSG_CHECKING([if passing shrinker as first argument])
        tmp_flags="$EXTRA_KCFLAGS"
        EXTRA_KCFLAGS="-Werror"
        LB_LINUX_TRY_COMPILE([
                #include <linux/mm.h>
                int test_shrink(struct shrinker *, int, gfp_t);
        ],[
                struct shrinker *shr = NULL;
                shr->shrink = test_shrink;
        ],[
                AC_MSG_RESULT([yes])
                AC_DEFINE(SHRINKER_FIRST_ARG, [struct shrinker *shrinker,], 
                        [kernel is passing shrinker as first argument])
        ],[
                AC_MSG_RESULT([no])
                AC_DEFINE(SHRINKER_FIRST_ARG, , 
                        [kernel doesn't have shrinker as first argument])
        ])
        EXTRA_KCFLAGS="$tmp_flags"
        ],[
                AC_DEFINE(SHRINKER_FIRST_ARG, , 
                        [kernel doesn't have shrinker as first argument])
])
])

# 2.6.23 add code to wait other users to complete before removing procfs entry
AC_DEFUN([LC_PROCFS_USERS],
[AC_MSG_CHECKING([if kernel has pde_users member in procfs entry struct])
LB_LINUX_TRY_COMPILE([
        #include <linux/proc_fs.h>
],[
        struct proc_dir_entry pde;

        pde.pde_users   = 0;
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_PROCFS_USERS, 1,
                [kernel has pde_users member in procfs entry struct])
],[
	LB_LINUX_TRY_COMPILE([
		#include "$LINUX/fs/proc/internal.h"
	],[
		struct proc_dir_entry_aux pde_aux;

		pde_aux.pde_users = 0;
	],[
		AC_MSG_RESULT([yes])
		AC_DEFINE(HAVE_PROCFS_USERS, 1,
			[kernel has pde_users member in proc_dir_entry_aux])
	],[
		AC_MSG_RESULT([no])
	])
])
])

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
                [if kernel has bio_endio with 2 args])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.24 has new members in exports struct.
AC_DEFUN([LC_FH_TO_DENTRY],
[AC_MSG_CHECKING([if kernel has .fh_to_dentry member in export_operations struct])
LB_LINUX_TRY_COMPILE([
#ifdef HAVE_LINUX_EXPORTFS_H
        #include <linux/exportfs.h>
#else
        #include <linux/fs.h>
#endif
],[
        struct export_operations exp;

        exp.fh_to_dentry   = NULL;
], [
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_FH_TO_DENTRY, 1,
                [kernel has .fh_to_dentry member in export_operations struct])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.24 need linux/mm_types.h included
AC_DEFUN([LC_HAVE_MMTYPES_H],
[LB_CHECK_FILE([$LINUX/include/linux/mm_types.h], [
        AC_DEFINE(HAVE_LINUX_MMTYPES_H, 1,
                [kernel has include/mm_types.h])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.24 remove long aged procfs entry -> deleted member
AC_DEFUN([LC_PROCFS_DELETED],
[AC_MSG_CHECKING([if kernel has deleted member in procfs entry struct])
LB_LINUX_TRY_COMPILE([
	#include <linux/proc_fs.h>
],[
        struct proc_dir_entry pde;

        pde.deleted   = NULL;
], [
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_PROCFS_DELETED, 1,
                [kernel has deleted member in procfs entry struct])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.25 change define to inline
AC_DEFUN([LC_MAPPING_CAP_WRITEBACK_DIRTY],
[AC_MSG_CHECKING([if kernel have mapping_cap_writeback_dirty])
LB_LINUX_TRY_COMPILE([
        #include <linux/backing-dev.h>
],[
        #ifndef mapping_cap_writeback_dirty
        mapping_cap_writeback_dirty(NULL);
        #endif
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_MAPPING_CAP_WRITEBACK_DIRTY, 1,
                [kernel have mapping_cap_writeback_dirty])
],[
        AC_MSG_RESULT([no])
])
])



# 2.6.26 isn't export set_fs_pwd and change paramter in fs struct
AC_DEFUN([LC_FS_STRUCT_USE_PATH],
[AC_MSG_CHECKING([fs_struct use path structure])
LB_LINUX_TRY_COMPILE([
        #include <asm/atomic.h>
        #include <linux/spinlock.h>
        #include <linux/fs_struct.h>
],[
        struct path path;
        struct fs_struct fs;

        fs.pwd = path;
], [
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_FS_STRUCT_USE_PATH, 1,
                [fs_struct use path structure])
],[
        AC_MSG_RESULT([no])
])
])


#
# LC_LINUX_FIEMAP_H
#
# If we have fiemap.h
# after 2.6.27 use fiemap.h in include/linux
#
AC_DEFUN([LC_LINUX_FIEMAP_H],
[LB_CHECK_FILE([$LINUX/include/linux/fiemap.h],[
        AC_MSG_CHECKING([if fiemap.h can be compiled])
        LB_LINUX_TRY_COMPILE([
                #include <linux/types.h>
                #include <linux/fiemap.h>
        ],[],[
                AC_MSG_RESULT([yes])
                AC_DEFINE(HAVE_LINUX_FIEMAP_H, 1, [Kernel has fiemap.h])
        ],[
                AC_MSG_RESULT([no])
        ])
],
[])
])

#2.6.27
AC_DEFUN([LC_INODE_PERMISION_2ARGS],
[AC_MSG_CHECKING([inode_operations->permission have two args])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct inode *inode;

        inode->i_op->permission(NULL,0);
],[
        AC_DEFINE(HAVE_INODE_PERMISION_2ARGS, 1, 
                  [inode_operations->permission have two args])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.27 have file_remove_suid instead of remove_suid
AC_DEFUN([LC_FILE_REMOVE_SUID],
[AC_MSG_CHECKING([kernel have file_remove_suid])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        file_remove_suid(NULL);
],[
        AC_DEFINE(HAVE_FILE_REMOVE_SUID, 1,
                  [kernel have file_remove_suid])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# (Ubuntu) 2.6.24's remove_suid() takes a struct path *
AC_DEFUN([LC_PATH_REMOVE_SUID],
[AC_MSG_CHECKING([kernel has a remove_suid that takes a struct path])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct path *a_path = NULL;
        remove_suid(a_path);
],[
        AC_DEFINE(HAVE_PATH_REMOVE_SUID, 1,
                  [kernel has a remove suid that takes a struct path])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.27 have new page locking API
AC_DEFUN([LC_TRYLOCKPAGE],
[AC_MSG_CHECKING([kernel use trylock_page for page lock])
LB_LINUX_TRY_COMPILE([
        #include <linux/pagemap.h>
],[
        trylock_page(NULL);
],[
        AC_DEFINE(HAVE_TRYLOCK_PAGE, 1,
                  [kernel use trylock_page for page lock])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.27 and some older have mapping->tree_lock as spin_lock
AC_DEFUN([LC_RW_TREE_LOCK],
[AC_MSG_CHECKING([mapping->tree_lock is rw_lock])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-Werror"
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	struct address_space *map = NULL;

	write_lock_irq(&map->tree_lock);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_RW_TREE_LOCK, 1,
                [mapping->tree_lock is rw_lock])
],[
        AC_MSG_RESULT(no)
])
EXTRA_KCFLAGS="$tmp_flags"
])

# 2.6.5 sles9 hasn't define sysctl_vfs_cache_pressure
AC_DEFUN([LC_HAVE_SYSCTL_VFS_CACHE_PRESSURE],
[LB_CHECK_SYMBOL_EXPORT([sysctl_vfs_cache_pressure],
[fs/dcache.c],[
        AC_DEFINE(HAVE_SYSCTL_VFS_CACHE_PRESSURE, 1, [kernel exports sysctl_vfs_cache_pressure])
],[
])
])

# vfs_symlink seems to have started out with 3 args until 2.6.7 where a
# "mode" argument was added, but then again, in some later version it was
# removed
AC_DEFUN([LC_4ARGS_VFS_SYMLINK],
[AC_MSG_CHECKING([if vfs_symlink wants 4 args])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	struct inode *dir;
	struct dentry *dentry;
	const char *oldname = NULL;
	int mode = 0;

	vfs_symlink(dir, dentry, oldname, mode);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_4ARGS_VFS_SYMLINK, 1,
                  [vfs_symlink wants 4 args])
],[
        AC_MSG_RESULT(no)
])
])

# 2.6.27 sles11 remove the bi_hw_segments
AC_DEFUN([LC_BI_HW_SEGMENTS],
[AC_MSG_CHECKING([struct bio has a bi_hw_segments field])
LB_LINUX_TRY_COMPILE([
        #include <linux/bio.h>
],[
        struct bio io;
        io.bi_hw_segments = 0;
],[
        AC_DEFINE(HAVE_BI_HW_SEGMENTS, 1,
                [struct bio has a bi_hw_segments field])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

#
# 2.6.27 sles11 move the quotaio_v1{2}.h from include/linux to fs
# 2.6.32 move the quotaio_v1{2}.h from fs to fs/quota
AC_DEFUN([LC_HAVE_QUOTAIO_V1_H],
[LB_CHECK_FILE([$LINUX/include/linux/quotaio_v1.h],[
        AC_DEFINE(HAVE_QUOTAIO_V1_H, 1,
                [kernel has include/linux/quotaio_v1.h])
],[LB_CHECK_FILE([$LINUX/fs/quota/quotaio_v1.h],[
       	AC_DEFINE(HAVE_FS_QUOTA_QUOTAIO_V1_H, 1,
                [kernel has fs/quota/quotaio_v1.h])
],[
        AC_MSG_RESULT([no])
])
])
])

# sles10 sp2 need 5 parameter for vfs_symlink
AC_DEFUN([LC_VFS_SYMLINK_5ARGS],
[AC_MSG_CHECKING([vfs_symlink need 5 parameter])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct inode *dir = NULL;
        struct dentry *dentry = NULL;
        struct vfsmount *mnt = NULL;
        const char * path = NULL;
        vfs_symlink(dir, dentry, mnt, path, 0);
],[
        AC_DEFINE(HAVE_VFS_SYMLINK_5ARGS, 1,
                [vfs_symlink need 5 parameteres])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.27 removed the read_inode from super_operations.
AC_DEFUN([LC_READ_INODE_IN_SBOPS],
[AC_MSG_CHECKING([super_operations has a read_inode field])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct super_operations *sop;
        sop->read_inode(NULL);
],[
        AC_DEFINE(HAVE_READ_INODE_IN_SBOPS, 1,
                [super_operations has a read_inode])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.27 sles11 has sb_any_quota_active
AC_DEFUN([LC_SB_ANY_QUOTA_ACTIVE],
[AC_MSG_CHECKING([Kernel has sb_any_quota_active])
	# Ignore backported quotaops.h in OFED
	if test -f $OFED_BACKPORT_PATH/linux/quotaops.h ; then
		AC_MSG_RESULT(no)
	else
		LB_LINUX_TRY_COMPILE([
			#include <linux/quotaops.h>
],[
			sb_any_quota_active(NULL);
],[
			AC_DEFINE(HAVE_SB_ANY_QUOTA_ACTIVE, 1,
				[Kernel has a sb_any_quota_active])
			AC_MSG_RESULT([yes])
],[
			AC_MSG_RESULT([no])
])
	fi
])

# 2.6.27 sles11 has sb_has_quota_active
AC_DEFUN([LC_SB_HAS_QUOTA_ACTIVE],
[AC_MSG_CHECKING([Kernel has sb_has_quota_active])
	# Ignore backported quotaops.h in OFED
	if test -f $OFED_BACKPORT_PATH/linux/quotaops.h ; then
		AC_MSG_RESULT(no)
	else
	LB_LINUX_TRY_COMPILE([
		#include <linux/quotaops.h>
],[
		sb_has_quota_active(NULL, 0);
],[
		AC_DEFINE(HAVE_SB_HAS_QUOTA_ACTIVE, 1,
			[Kernel has a sb_has_quota_active])
		AC_MSG_RESULT([yes])
],[
		AC_MSG_RESULT([no])
])
	fi
])

# 2.6.27 has inode_permission instead of permisson
AC_DEFUN([LC_EXPORT_INODE_PERMISSION],
[LB_CHECK_SYMBOL_EXPORT([inode_permission],
[fs/namei.c],[
AC_DEFINE(HAVE_EXPORT_INODE_PERMISSION, 1,
            [inode_permission is exported by the kernel])
],[
])
])

# 2.6.27 use 5th parameter in quota_on for remount.
AC_DEFUN([LC_QUOTA_ON_5ARGS],
[AC_MSG_CHECKING([quota_on needs 5 parameters])
LB_LINUX_TRY_COMPILE([
        #include <linux/quota.h>
],[
        struct quotactl_ops *qop;
        qop->quota_on(NULL, 0, 0, NULL, 0);
],[
        AC_DEFINE(HAVE_QUOTA_ON_5ARGS, 1,
                [quota_on needs 5 paramters])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.27 use 3th parameter in quota_off for remount.
AC_DEFUN([LC_QUOTA_OFF_3ARGS],
[AC_MSG_CHECKING([quota_off needs 3 parameters])
LB_LINUX_TRY_COMPILE([
        #include <linux/quota.h>
],[
        struct quotactl_ops *qop;
        qop->quota_off(NULL, 0, 0);
],[
        AC_DEFINE(HAVE_QUOTA_OFF_3ARGS, 1,
                [quota_off needs 3 paramters])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.27 has vfs_dq_off inline function.
AC_DEFUN([LC_VFS_DQ_OFF],
[AC_MSG_CHECKING([vfs_dq_off is defined])
LB_LINUX_TRY_COMPILE([
        #include <linux/quotaops.h>
],[
        vfs_dq_off(NULL, 0);
],[
        AC_DEFINE(HAVE_VFS_DQ_OFF, 1, [vfs_dq_off is defined])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.27 has bdi_init()/bdi_destroy() functions.
AC_DEFUN([LC_EXPORT_BDI_INIT],
[LB_CHECK_SYMBOL_EXPORT([bdi_init],
[mm/backing-dev.c],[
        AC_DEFINE(HAVE_BDI_INIT, 1,
                [bdi_init/bdi_destroy functions are present])
],[
])
])

#
# LC_D_OBTAIN_ALIAS
# starting from 2.6.28 kernel replaces d_alloc_anon() with
# d_obtain_alias() for getting anonymous dentries
#
AC_DEFUN([LC_D_OBTAIN_ALIAS],
[AC_MSG_CHECKING([d_obtain_alias exist in kernel])
LB_LINUX_TRY_COMPILE([
        #include <linux/dcache.h>
],[
        d_obtain_alias(NULL);
],[
        AC_DEFINE(HAVE_D_OBTAIN_ALIAS, 1,
                [d_obtain_alias exist in kernel])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.29 change prepare/commit_write to write_begin/end
AC_DEFUN([LC_WRITE_BEGIN_END],
[AC_MSG_CHECKING([if kernel has .write_begin/end])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
#ifdef HAVE_LINUX_MMTYPES_H
        #include <linux/mm_types.h>
#endif
        #include <linux/pagemap.h>
],[
        struct address_space_operations aops;
        struct page *page;

        aops.write_begin = NULL;
        aops.write_end = NULL;
        page = grab_cache_page_write_begin(NULL, 0, 0);
], [
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_KERNEL_WRITE_BEGIN_END, 1,
                [kernel has .write_begin/end])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.29 blkdev_put has 2 arguments
AC_DEFUN([LC_BLKDEV_PUT_2ARGS],
[AC_MSG_CHECKING([blkdev_put needs 2 parameters])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        blkdev_put(NULL, 0);
],[
        AC_DEFINE(HAVE_BLKDEV_PUT_2ARGS, 1,
                [blkdev_put needs 2 paramters])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.29 dentry_open has 4 arguments
AC_DEFUN([LC_DENTRY_OPEN_4ARGS],
[AC_MSG_CHECKING([dentry_open needs 4 parameters])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        dentry_open(NULL, NULL, 0, NULL);
],[
        AC_DEFINE(HAVE_DENTRY_OPEN_4ARGS, 1,
                [dentry_open needs 4 paramters])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

AC_DEFUN([LC_ATOMIC_CMPXCHG],
[AC_MSG_CHECKING([if kernel has atomic_cmpxchg])
LB_LINUX_TRY_COMPILE([
        #include <asm/atomic.h>
],[
        #ifndef atomic_cmpxchg
        #error missing atomic_cmpxchg
        #endif
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_ATOMIC_CMPXCHG, 1, [kernel has atomic_cmpxchg])
],[
        AC_MSG_RESULT([no])
])
])

AC_DEFUN([LC_ATOMIC_INC_NOT_ZERO],
[AC_MSG_CHECKING([if kernel has atomic_inc_not_zero])
LB_LINUX_TRY_COMPILE([
        #include <asm/atomic.h>
],[
        #ifndef atomic_inc_not_zero
        #error missing atomic_inc_not_zero
        #endif
],[
        AC_MSG_RESULT([yes])
      	AC_DEFINE(HAVE_ATOMIC_INC_NOT_ZERO, 1, [kernel has atomic_inc_not_zero])
],[
        AC_MSG_RESULT([no])
])
])

# 2.6.31 replaces blk_queue_hardsect_size by blk_queue_logical_block_size function
AC_DEFUN([LC_BLK_QUEUE_LOG_BLK_SIZE],
[AC_MSG_CHECKING([if blk_queue_logical_block_size is defined])
LB_LINUX_TRY_COMPILE([
        #include <linux/blkdev.h>
],[
        blk_queue_logical_block_size(NULL, 0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_BLK_QUEUE_LOG_BLK_SIZE, 1,
                  [blk_queue_logical_block_size is defined])
],[
        AC_MSG_RESULT(no)
])
])

# 2.6.32 has bdi_register() functions.
AC_DEFUN([LC_EXPORT_BDI_REGISTER],
[LB_CHECK_SYMBOL_EXPORT([bdi_register],
[mm/backing-dev.c],[
        AC_DEFINE(HAVE_BDI_REGISTER, 1,
                [bdi_register function is present])
],[
])
])

# 2.6.32 add s_bdi for super block
AC_DEFUN([LC_SB_BDI],
[AC_MSG_CHECKING([if super_block has s_bdi field])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct super_block sb;
        sb.s_bdi = NULL;
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SB_BDI, 1,
                  [super_block has s_bdi field])
],[
        AC_MSG_RESULT(no)
])
])

# LC_WALK_SPACE_HAS_DATA_SEM
#
# 2.6.33 ext4_ext_walk_space() takes i_data_sem internally.
# Not a very robust check, but it will hopefully last long
# enough until it can avoid being conditional.
#
AC_DEFUN([LC_WALK_SPACE_HAS_DATA_SEM],
[AC_MSG_CHECKING([if ext4_ext_walk_space() takes i_data_sem])
WALK_SPACE_DATA_SEM="$(awk '/ext4_ext_walk_space/,/ext4_ext_find_extent/' $LINUX/fs/ext4/extents.c | grep -c 'down_read.*i_data_sem')"
if test "$WALK_SPACE_DATA_SEM" != 0 ; then
        AC_DEFINE(WALK_SPACE_HAS_DATA_SEM, 1,
                  [ext4_ext_walk_space takes i_data_sem])
        AC_MSG_RESULT([yes])
else
        AC_MSG_RESULT([no])
fi
])

# 2.6.32 without DQUOT_INIT defined.
AC_DEFUN([LC_DQUOT_INIT],
[AC_MSG_CHECKING([if DQUOT_INIT is defined])
LB_LINUX_TRY_COMPILE([
        #include <linux/quotaops.h>
],[
        DQUOT_INIT(NULL);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_DQUOT_INIT, 1,
                  [DQUOT_INIT is defined])
],[
        AC_MSG_RESULT(no)
])
])

# 2.6.32 add a limits member in struct request_queue.
AC_DEFUN([LC_REQUEST_QUEUE_LIMITS],
[AC_MSG_CHECKING([if request_queue has a limits field])
LB_LINUX_TRY_COMPILE([
        #include <linux/blkdev.h>
],[
        struct request_queue rq;
        rq.limits.io_min = 0;
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_REQUEST_QUEUE_LIMITS, 1,
                  [request_queue has a limits field])
],[
        AC_MSG_RESULT(no)
])
])

# RHEL6(backport from 2.6.34) removes 2 functions blk_queue_max_phys_segments and
# blk_queue_max_hw_segments add blk_queue_max_segments
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

# RHEL6(backport from 2.6.34) removes blk_queue_max_sectors and add blk_queue_max_hw_sectors
# check blk_queue_max_sectors and use it until disappear.
AC_DEFUN([LC_BLK_QUEUE_MAX_SECTORS],
[AC_MSG_CHECKING([if blk_queue_max_sectors is defined])
LB_LINUX_TRY_COMPILE([
        #include <linux/blkdev.h>
],[
        blk_queue_max_sectors(NULL, 0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_BLK_QUEUE_MAX_SECTORS, 1,
                  [blk_queue_max_sectors is defined])
],[
        AC_MSG_RESULT(no)
])
])


#
# LC_PROG_LINUX
#
# Lustre linux kernel checks
#
AC_DEFUN([LC_PROG_LINUX],
         [LC_LUSTRE_VERSION_H
          if test x$enable_server = xyes ; then
              LC_FUNC_DEV_SET_RDONLY
              LC_CONFIG_BACKINGFS
              LC_STACK_SIZE
          fi
          LC_CONFIG_PINGER
          LC_CONFIG_CHECKSUM
          LC_CONFIG_LIBLUSTRE_RECOVERY
          LC_CONFIG_HEALTH_CHECK_WRITE
          LC_CONFIG_LRU_RESIZE
          LC_CONFIG_ADAPTIVE_TIMEOUTS
          LC_CONFIG_DELAYED_RECOVERY
          LC_QUOTA_MODULE

          # RHEL4 patches
          LC_EXPORT_TRUNCATE_COMPLETE_PAGE
          LC_EXPORT_TRUNCATE_RANGE
          LC_EXPORT_D_REHASH_COND
          LC_EXPORT___D_REHASH
          LC_EXPORT_D_MOVE_LOCKED
          LC_EXPORT___D_MOVE
          LC_EXPORT_NODE_TO_CPUMASK

          LC_FUNC_RELEASEPAGE_WITH_GFP
          LC_HEADER_LDISKFS_XATTR
          LC_FUNC_GRAB_CACHE_PAGE_NOWAIT_GFP
          LC_STRUCT_STATFS
          LC_FILEMAP_POPULATE
          LC_D_ADD_UNIQUE
          LC_BIT_SPINLOCK_H
          LC_XATTR_ACL
          LC_STRUCT_INTENT_FILE
          LC_POSIX_ACL_XATTR_H
          LC_FUNC_MS_FLOCK_LOCK
          LC_FUNC_HAVE_CAN_SLEEP_ARG
          LC_FUNC_F_OP_FLOCK
          LC_QUOTA_READ
          LC_COOKIE_FOLLOW_LINK
          LC_FUNC_RCU
          LC_PERCPU_COUNTER
          LC_4ARGS_VFS_SYMLINK

          # does the kernel have VFS intent patches?
          LC_VFS_INTENT_PATCHES

	  # 2.6.5 sles9
	  LC_HAVE_SYSCTL_VFS_CACHE_PRESSURE

          # 2.6.12
          LC_RW_TREE_LOCK
          LC_EXPORT_SYNCHRONIZE_RCU

          # 2.6.15
          LC_INODE_I_MUTEX
          LC_ATOMIC_CMPXCHG
          LC_ATOMIC_INC_NOT_ZERO

          # 2.6.16
          LC_SECURITY_PLUG  # for SLES10 SP2

          # 2.6.17
          LC_DQUOTOFF_MUTEX

          # 2.6.18
          LC_NR_PAGECACHE
          LC_STATFS_DENTRY_PARAM
          LC_VFS_KERN_MOUNT
          LC_INVALIDATEPAGE_RETURN_INT
          LC_UMOUNTBEGIN_HAS_VFSMOUNT
          LC_INODE_IPRIVATE
          LC_EXPORT_FILEMAP_FDATAWRITE_RANGE
          LC_FLUSH_OWNER_ID
          if test x$enable_server = xyes ; then
                LC_EXPORT_INVALIDATE_MAPPING_PAGES
          fi

          #2.6.18 + RHEL5 (fc6)
          LC_PG_FS_MISC
          LC_PAGE_CHECKED
          LC_LINUX_FIEMAP_H

          # 2.6.19
          LC_INODE_BLKSIZE
          LC_VFS_READDIR_U64_INO
          LC_FILE_UPDATE_TIME
          LC_FILE_WRITEV
          LC_FILE_READV

          # 2.6.20
          LC_CANCEL_DIRTY_PAGE

          # raid5-zerocopy patch
          LC_PAGE_CONSTANT

          # 2.6.22
          LC_INVALIDATE_BDEV_2ARG
          LC_FS_RENAME_DOES_D_MOVE
          # 2.6.23
          LC_UNREGISTER_BLKDEV_RETURN_INT
          LC_KERNEL_SENDFILE
          LC_KERNEL_SPLICE_READ
          LC_HAVE_EXPORTFS_H
          LC_VM_OP_FAULT
          LC_REGISTER_SHRINKER
          LC_PROCFS_USERS

          # 2.6.25
          LC_MAPPING_CAP_WRITEBACK_DIRTY

          # 2.6.24
          LC_HAVE_MMTYPES_H
          LC_BIO_ENDIO_2ARG
          LC_FH_TO_DENTRY
          LC_PROCFS_DELETED

          # 2.6.24-19-generic Ubuntu
          LC_PATH_REMOVE_SUID

          # 2.6.26
          LC_FS_STRUCT_USE_PATH

          # 2.6.27
          LC_INODE_PERMISION_2ARGS
          LC_FILE_REMOVE_SUID
          LC_TRYLOCKPAGE
          LC_RW_TREE_LOCK
          LC_READ_INODE_IN_SBOPS
          LC_EXPORT_INODE_PERMISSION
          LC_QUOTA_ON_5ARGS
          LC_QUOTA_OFF_3ARGS
          LC_VFS_DQ_OFF

          # 2.6.27.15-2 sles11
          LC_BI_HW_SEGMENTS
          LC_HAVE_QUOTAIO_V1_H
          LC_VFS_SYMLINK_5ARGS
          LC_SB_ANY_QUOTA_ACTIVE
          LC_SB_HAS_QUOTA_ACTIVE
          LC_EXPORT_BDI_INIT

          #2.6.29
          LC_WRITE_BEGIN_END
          LC_D_OBTAIN_ALIAS
          LC_BLKDEV_PUT_2ARGS
          LC_DENTRY_OPEN_4ARGS

          # 2.6.31
          LC_BLK_QUEUE_LOG_BLK_SIZE

          # 2.6.32
          LC_EXPORT_BDI_REGISTER
          LC_SB_BDI
          if test x$enable_server = xyes ; then
              LC_WALK_SPACE_HAS_DATA_SEM
          fi
          LC_DQUOT_INIT
          LC_REQUEST_QUEUE_LIMITS
          LC_BLK_QUEUE_MAX_SECTORS
          LC_BLK_QUEUE_MAX_SEGMENTS

          #
          if test x$enable_server = xyes ; then
              LC_QUOTA64    # must after LC_HAVE_QUOTAIO_V1_H
          fi
])

#
# LC_CONFIG_CLIENT_SERVER
#
# Build client/server sides of Lustre
#
AC_DEFUN([LC_CONFIG_CLIENT_SERVER],
[AC_MSG_CHECKING([whether to build Lustre server support])
AC_ARG_ENABLE([server],
	AC_HELP_STRING([--disable-server],
			[disable Lustre server support]),
	[],[enable_server='yes'])
AC_MSG_RESULT([$enable_server])

AC_MSG_CHECKING([whether to build Lustre client support])
AC_ARG_ENABLE([client],
	AC_HELP_STRING([--disable-client],
			[disable Lustre client support]),
	[],[enable_client='yes'])
AC_MSG_RESULT([$enable_client])])

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

AC_DEFUN([LC_CONFIG_ADAPTIVE_TIMEOUTS],
[AC_MSG_CHECKING([whether to enable ptlrpc adaptive timeouts support])
AC_ARG_ENABLE([adaptive_timeouts],
	AC_HELP_STRING([--disable-adaptive-timeouts],
			[disable ptlrpc adaptive timeouts support]),
	[],[enable_adaptive_timeouts='yes'])
AC_MSG_RESULT([$enable_adaptive_timeouts])
if test x$enable_adaptive_timeouts == xyes; then
   AC_DEFINE(HAVE_AT_SUPPORT, 1, [Enable adaptive timeouts support])
fi
])

# config delayed recovery
AC_DEFUN([LC_CONFIG_DELAYED_RECOVERY],
[AC_MSG_CHECKING([whether to enable delayed recovery support])
AC_ARG_ENABLE([delayed-recovery],
	AC_HELP_STRING([--enable-delayed-recovery],
			[enable late recovery after main one]),
	[],[enable_delayed_recovery='no'])
AC_MSG_RESULT([$enable_delayed_recovery])
if test x$enable_delayed_recovery == xyes; then
   AC_DEFINE(HAVE_DELAYED_RECOVERY, 1, [Enable delayed recovery support])
fi
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

# whether to enable quota support(kernel modules)
AC_DEFUN([LC_QUOTA_MODULE],
[if test x$enable_quota != xno; then
    LB_LINUX_CONFIG([QUOTA],[
	enable_quota_module='yes'
	AC_DEFINE(HAVE_QUOTA_SUPPORT, 1, [Enable quota support])
    ],[
	enable_quota_module='no'
	AC_MSG_WARN([quota is not enabled because the kernel - lacks quota support])
    ])
fi
])

AC_DEFUN([LC_QUOTA],
[#check global
LC_CONFIG_QUOTA
#check for utils
AC_CHECK_HEADER(sys/quota.h,
                [AC_DEFINE(HAVE_SYS_QUOTA_H, 1, [Define to 1 if you have <sys/quota.h>.])],
                [AC_MSG_ERROR([don't find <sys/quota.h> in your system])])
])

AC_DEFUN([LC_QUOTA_READ],
[AC_MSG_CHECKING([if kernel supports quota_read])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	struct super_operations sp;
        void *i = (void *)sp.quota_read;
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(KERNEL_SUPPORTS_QUOTA_READ, 1, [quota_read found])
],[
	AC_MSG_RESULT([no])
])
])

#
# LC_COOKIE_FOLLOW_LINK
#
# kernel 2.6.13+ ->follow_link returns a cookie
#

AC_DEFUN([LC_COOKIE_FOLLOW_LINK],
[AC_MSG_CHECKING([if inode_operations->follow_link returns a cookie])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
        #include <linux/namei.h>
],[
        struct dentry dentry;
        struct nameidata nd;

        dentry.d_inode->i_op->put_link(&dentry, &nd, NULL);
],[
        AC_DEFINE(HAVE_COOKIE_FOLLOW_LINK, 1, [inode_operations->follow_link returns a cookie])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

#
# LC_FUNC_RCU
#
# kernels prior than 2.6.0(?) have no RCU supported; in kernel 2.6.5(SUSE), 
# call_rcu takes three parameters.
#
AC_DEFUN([LC_FUNC_RCU],
[AC_MSG_CHECKING([if kernel have RCU supported])
LB_LINUX_TRY_COMPILE([
        #include <linux/rcupdate.h>
],[],[
        AC_DEFINE(HAVE_RCU, 1, [have RCU defined])
        AC_MSG_RESULT([yes])

        AC_MSG_CHECKING([if call_rcu takes three parameters])
        LB_LINUX_TRY_COMPILE([
                #include <linux/rcupdate.h>
        ],[
                struct rcu_head rh;
                call_rcu(&rh, (void (*)(struct rcu_head *))1, NULL);
        ],[
                AC_DEFINE(HAVE_CALL_RCU_PARAM, 1, [call_rcu takes three parameters])
                AC_MSG_RESULT([yes])
        ],[
                AC_MSG_RESULT([no]) 
        ])

],[
        AC_MSG_RESULT([no])
])
])

#
# LC_QUOTA64
# linux kernel may have 64-bit limits support
#
AC_DEFUN([LC_QUOTA64],
[AC_MSG_CHECKING([if kernel has 64-bit quota limits support])
tmp_flags="$EXTRA_KCFLAGS"
EXTRA_KCFLAGS="-I$LINUX/fs"
LB_LINUX_TRY_COMPILE([
        #include <linux/kernel.h>
        #include <linux/fs.h>
        #ifdef HAVE_QUOTAIO_V1_H
        # include <linux/quotaio_v2.h>
        int versions[] = V2_INITQVERSIONS_R1;
        struct v2_disk_dqblk_r1 dqblk_r1;
        #else
        # ifdef HAVE_FS_QUOTA_QUOTAIO_V1_H
        #  include <quota/quotaio_v2.h>
        # else
        #  include <quotaio_v2.h>
        # endif
        struct v2r1_disk_dqblk dqblk_r1;
        #endif
],[],[
        AC_DEFINE(HAVE_QUOTA64, 1, [have quota64])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
        AC_MSG_WARN([4 TB (or larger) block quota limits can only be used with OSTs not larger than 4 TB.])
        AC_MSG_WARN([Continuing with limited quota support.])
        AC_MSG_WARN([quotacheck is needed for filesystems with recent quota versions.])
])
EXTRA_KCFLAGS=$tmp_flags
])

# LC_SECURITY_PLUG  # for SLES10 SP2
# check security plug in sles10 sp2 kernel
AC_DEFUN([LC_SECURITY_PLUG],
[AC_MSG_CHECKING([If kernel has security plug support])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct dentry   *dentry;
        struct vfsmount *mnt;
        struct iattr    *iattr;

        notify_change(dentry, mnt, iattr);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_SECURITY_PLUG, 1,
                [SLES10 SP2 use extra parameter in vfs])
],[
        AC_MSG_RESULT(no)
])
])

AC_DEFUN([LC_PERCPU_COUNTER],
[AC_MSG_CHECKING([if have struct percpu_counter defined])
LB_LINUX_TRY_COMPILE([
        #include <linux/percpu_counter.h>
],[],[
        AC_DEFINE(HAVE_PERCPU_COUNTER, 1, [percpu_counter found])
        AC_MSG_RESULT([yes])

        AC_MSG_CHECKING([if percpu_counter_inc takes the 2nd argument])
        LB_LINUX_TRY_COMPILE([
                #include <linux/percpu_counter.h>
        ],[
                struct percpu_counter c;
                percpu_counter_init(&c, 0);
        ],[
                AC_DEFINE(HAVE_PERCPU_2ND_ARG, 1, [percpu_counter_init has two
                                                   arguments])
                AC_MSG_RESULT([yes])
        ],[
                AC_MSG_RESULT([no])
        ])
],[
        AC_MSG_RESULT([no])
])
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
LC_MDS_THREADS_MAX

# include/liblustre.h
AC_CHECK_HEADERS([asm/page.h sys/user.h sys/vfs.h stdint.h blkid/blkid.h])

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

])

#
# LC_CONDITIONALS
#
# AM_CONDITIONALS for lustre
#
AC_DEFUN([LC_CONDITIONALS],
[AM_CONDITIONAL(LIBLUSTRE, test x$enable_liblustre = xyes)
AM_CONDITIONAL(USE_QUILT, test x$QUILT != xno)
AM_CONDITIONAL(LIBLUSTRE_TESTS, test x$enable_liblustre_tests = xyes)
AM_CONDITIONAL(MPITESTS, test x$enable_mpitests = xyes, Build MPI Tests)
AM_CONDITIONAL(CLIENT, test x$enable_client = xyes)
AM_CONDITIONAL(SERVER, test x$enable_server = xyes)
AM_CONDITIONAL(QUOTA, test x$enable_quota_module = xyes)
AM_CONDITIONAL(BLKID, test x$ac_cv_header_blkid_blkid_h = xyes)
AM_CONDITIONAL(EXT2FS_DEVEL, test x$ac_cv_header_ext2fs_ext2fs_h = xyes)
AM_CONDITIONAL(LIBPTHREAD, test x$enable_libpthread = xyes)
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
lustre/kernel_patches/targets/2.6-suse.target
lustre/kernel_patches/targets/2.6-vanilla.target
lustre/kernel_patches/targets/2.6-rhel4.target
lustre/kernel_patches/targets/2.6-rhel6.target
lustre/kernel_patches/targets/2.6-rhel5.target
lustre/kernel_patches/targets/2.6-fc5.target
lustre/kernel_patches/targets/2.6-patchless.target
lustre/kernel_patches/targets/2.6-sles10.target
lustre/kernel_patches/targets/2.6-sles11.target
lustre/kernel_patches/targets/hp_pnnl-2.4.target
lustre/kernel_patches/targets/rh-2.4.target
lustre/kernel_patches/targets/rhel-2.4.target
lustre/kernel_patches/targets/suse-2.4.21-2.target
lustre/kernel_patches/targets/sles-2.4.target
lustre/kernel_patches/targets/2.6-oel5.target
lustre/ldlm/Makefile
lustre/liblustre/Makefile
lustre/liblustre/tests/Makefile
lustre/liblustre/tests/mpi/Makefile
lustre/llite/Makefile
lustre/llite/autoMakefile
lustre/lov/Makefile
lustre/lov/autoMakefile
lustre/lvfs/Makefile
lustre/lvfs/autoMakefile
lustre/mdc/Makefile
lustre/mdc/autoMakefile
lustre/mds/Makefile
lustre/mds/autoMakefile
lustre/obdclass/Makefile
lustre/obdclass/autoMakefile
lustre/obdclass/linux/Makefile
lustre/obdecho/Makefile
lustre/obdecho/autoMakefile
lustre/obdfilter/Makefile
lustre/obdfilter/autoMakefile
lustre/osc/Makefile
lustre/osc/autoMakefile
lustre/ost/Makefile
lustre/ost/autoMakefile
lustre/mgc/Makefile
lustre/mgc/autoMakefile
lustre/mgs/Makefile
lustre/mgs/autoMakefile
lustre/ptlrpc/Makefile
lustre/ptlrpc/autoMakefile
lustre/quota/Makefile
lustre/quota/autoMakefile
lustre/scripts/Makefile
lustre/tests/Makefile
lustre/tests/mpi/Makefile
lustre/utils/Makefile
lustre/obdclass/darwin/Makefile
])
])
