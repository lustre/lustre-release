#* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
#
# LC_CONFIG_SRCDIR
#
# Wrapper for AC_CONFIG_SUBDIR
#
AC_DEFUN([LC_CONFIG_SRCDIR],
[AC_CONFIG_SRCDIR([lustre/obdclass/obdo.c])
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
# LC_CONFIG_EXT3
#
# that ext3 is enabled in the kernel
#
AC_DEFUN([LC_CONFIG_EXT3],
[LB_LINUX_CONFIG([EXT3_FS],[],[
	LB_LINUX_CONFIG([EXT3_FS_MODULE],[],[$2])
])
LB_LINUX_CONFIG([EXT3_FS_XATTR],[$1],[$3])
])

#
# LC_FSHOOKS
#
# If we have (and can build) fshooks.h
#
AC_DEFUN([LC_FSHOOKS],
[LB_CHECK_FILE([$LINUX/include/linux/fshooks.h],[
	AC_MSG_CHECKING([if fshooks.h can be compiled])
	LB_LINUX_TRY_COMPILE([
		#include <linux/fshooks.h>
	],[],[
		AC_MSG_RESULT([yes])
	],[
		AC_MSG_RESULT([no])
		AC_MSG_WARN([You might have better luck with gcc 3.3.x.])
		AC_MSG_WARN([You can set CC=gcc33 before running configure.])
		AC_MSG_ERROR([Your compiler cannot build fshooks.h.])
	])
$1
],[
$2
])
])

#
# LC_STRUCT_KIOBUF
#
# rh 2.4.18 has iobuf->dovary, but other kernels do not
#
AC_DEFUN([LC_STRUCT_KIOBUF],
[AC_MSG_CHECKING([if struct kiobuf has a dovary field])
LB_LINUX_TRY_COMPILE([
	#include <linux/iobuf.h>
],[
	struct kiobuf iobuf;
	iobuf.dovary = 1;
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_KIOBUF_DOVARY, 1, [struct kiobuf has a dovary field])
],[
	AC_MSG_RESULT([no])
])
])

#
# LC_FUNC_COND_RESCHED
#
# cond_resched() was introduced in 2.4.20
#
AC_DEFUN([LC_FUNC_COND_RESCHED],
[AC_MSG_CHECKING([if kernel offers cond_resched])
LB_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
],[
	cond_resched();
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_COND_RESCHED, 1, [cond_resched found])
],[
	AC_MSG_RESULT([no])
])
])

#
# LC_FUNC_ZAP_PAGE_RANGE
#
# if zap_page_range() takes a vma arg
#
AC_DEFUN([LC_FUNC_ZAP_PAGE_RANGE],
[AC_MSG_CHECKING([if zap_page_range with vma parameter])
ZAP_PAGE_RANGE_VMA="`grep -c 'zap_page_range.*struct vm_area_struct' $LINUX/include/linux/mm.h`"
if test "$ZAP_PAGE_RANGE_VMA" != 0 ; then
	AC_DEFINE(ZAP_PAGE_RANGE_VMA, 1, [zap_page_range with vma parameter])
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi
])

#
# LC_FUNC_PDE
#
# if proc_fs.h defines PDE()
#
AC_DEFUN([LC_FUNC_PDE],
[AC_MSG_CHECKING([if kernel defines PDE])
HAVE_PDE="`grep -c 'proc_dir_entry..PDE' $LINUX/include/linux/proc_fs.h`"
if test "$HAVE_PDE" != 0 ; then
	AC_DEFINE(HAVE_PDE, 1, [the kernel defines PDE])
	AC_MSG_RESULT([yes])
else
	AC_MSG_RESULT([no])
fi
])

#
# LC_FUNC_FILEMAP_FDATASYNC
#
# if filemap_fdatasync() exists
#
AC_DEFUN([LC_FUNC_FILEMAP_FDATAWRITE],
[AC_MSG_CHECKING([whether filemap_fdatawrite() is defined])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
],[
	int (*foo)(struct address_space *)= filemap_fdatawrite;
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_FILEMAP_FDATAWRITE, 1, [filemap_fdatawrite() found])
],[
	AC_MSG_RESULT([no])
])
])

#
# LC_FUNC_DIRECT_IO
#
# if direct_IO takes a struct file argument
#
AC_DEFUN([LC_FUNC_DIRECT_IO],
[AC_MSG_CHECKING([if kernel passes struct file to direct_IO])
HAVE_DIO_FILE="`grep -c 'direct_IO.*struct file' $LINUX/include/linux/fs.h`"
if test "$HAVE_DIO_FILE" != 0 ; then
	AC_DEFINE(HAVE_DIO_FILE, 1, [the kernel passes struct file to direct_IO])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi
])

#
# LC_HEADER_MM_INLINE
#
# RHEL kernels define page_count in mm_inline.h
#
AC_DEFUN([LC_HEADER_MM_INLINE],
[AC_MSG_CHECKING([if kernel has mm_inline.h header])
LB_LINUX_TRY_COMPILE([
	#include <linux/mm_inline.h>
],[
	#ifndef page_count
	#error mm_inline.h does not define page_count
	#endif
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_MM_INLINE, 1, [mm_inline found])
],[
	AC_MSG_RESULT([no])
])
])

#
# LC_STRUCT_INODE
#
# if inode->i_alloc_sem exists
#
AC_DEFUN([LC_STRUCT_INODE],
[AC_MSG_CHECKING([if struct inode has i_alloc_sem])
LB_LINUX_TRY_COMPILE([
	#include <linux/fs.h>
	#include <linux/version.h>
],[
	#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,24))
	#error "down_read_trylock broken before 2.4.24"
	#endif
	struct inode i;
	return (char *)&i.i_alloc_sem - (char *)&i;
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_I_ALLOC_SEM, 1, [struct inode has i_alloc_sem])
],[
	AC_MSG_RESULT([no])
])
])

#
# LC_FUNC_REGISTER_CACHE
#
# if register_cache() is defined by kernel
#
AC_DEFUN([LC_FUNC_REGISTER_CACHE],
[AC_MSG_CHECKING([if kernel defines register_cache()])
LB_LINUX_TRY_COMPILE([
	#include <linux/list.h>
	#include <linux/cache_def.h>
],[
	struct cache_definition cache;
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_REGISTER_CACHE, 1, [register_cache found])
	AC_MSG_CHECKING([if kernel expects return from cache shrink function])
	HAVE_CACHE_RETURN_INT="`grep -c 'int.*shrink' $LINUX/include/linux/cache_def.h`"
	if test "$HAVE_CACHE_RETURN_INT" != 0 ; then
		AC_DEFINE(HAVE_CACHE_RETURN_INT, 1, [kernel expects return from shrink_cache])
		AC_MSG_RESULT(yes)
	else
		AC_MSG_RESULT(no)
	fi
],[
	AC_MSG_RESULT([no])
])
])

#
# LC_FUNC_GRAB_CACHE_PAGE_NOWAIT_GFP
#
# check for our patched grab_cache_page_nowait_gfp() function
#
AC_DEFUN([LC_FUNC_GRAB_CACHE_PAGE_NOWAIT_GFP],
[AC_MSG_CHECKING([if kernel defines grab_cache_page_nowait_gfp()])
HAVE_GCPN_GFP="`grep -c 'grab_cache_page_nowait_gfp' $LINUX/include/linux/pagemap.h`"
if test "$HAVE_GCPN_GFP" != 0 ; then
	AC_DEFINE(HAVE_GRAB_CACHE_PAGE_NOWAIT_GFP, 1,
		[kernel has grab_cache_page_nowait_gfp()])
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi
])

#
# LC_FUNC_DEV_SET_RDONLY
#
# check for the old-style dev_set_rdonly which took an extra "devno" param
# and can only set a single device to discard writes at one time
#
AC_DEFUN([LC_FUNC_DEV_SET_RDONLY],
[AC_MSG_CHECKING([if kernel has old single-device dev_set_rdonly])
HAVE_OLD_DSR="`grep -c -s 'dev_set_rdonly.*no_write' $LINUX/drivers/block/ll_rw_blk.c`"
if test x$HAVE_OLD_DSR != "x1" ; then
	HAVE_OLD_DSR="`grep -c -s 'dev_set_rdonly.*no_write' $LINUX/drivers/block/blkpg.c`"
fi
if test x$HAVE_OLD_DSR = "x1" ; then
        AC_DEFINE(HAVE_OLD_DEV_SET_RDONLY, 1,
                [kernel has old single-device dev_set_rdonly])
        AC_MSG_RESULT(yes)
else
        AC_MSG_RESULT(no)
fi
])

#
# LC_CONFIG_BACKINGFS
#
# whether to use ldiskfs instead of ext3
#
AC_DEFUN([LC_CONFIG_BACKINGFS],
[
BACKINGFS='ext3'

# 2.6 gets ldiskfs
AC_MSG_CHECKING([whether to enable ldiskfs])
AC_ARG_ENABLE([ldiskfs],
	AC_HELP_STRING([--enable-ldiskfs],
			[use ldiskfs for the Lustre backing FS]),
	[],[enable_ldiskfs="$linux25"])
AC_MSG_RESULT([$enable_ldiskfs])

if test x$enable_ldiskfs = xyes ; then
	BACKINGFS="ldiskfs"

	AC_MSG_CHECKING([whether to enable quilt for making ldiskfs])
	AC_ARG_ENABLE([quilt],
			AC_HELP_STRING([--disable-quilt],[disable use of quilt for ldiskfs]),
			[],[enable_quilt='yes'])
	AC_MSG_RESULT([$enable_quilt])

	AC_PATH_PROG(PATCH, patch, [no])

	if test x$enable_quilt = xno ; then
	    QUILT="no"
	else
	    AC_PATH_PROG(QUILT, quilt, [no])
	fi

	if test x$enable_ldiskfs$PATCH$QUILT = xyesnono ; then
		AC_MSG_ERROR([Quilt or patch are needed to build the ldiskfs module (for Linux 2.6)])
	fi

	AC_DEFINE(CONFIG_LDISKFS_FS_MODULE, 1, [build ldiskfs as a module])
	AC_DEFINE(CONFIG_LDISKFS_FS_XATTR, 1, [enable extended attributes for ldiskfs])
	AC_DEFINE(CONFIG_LDISKFS_FS_POSIX_ACL, 1, [enable posix acls])
	AC_DEFINE(CONFIG_LDISKFS_FS_SECURITY, 1, [enable fs security])
fi

AC_MSG_CHECKING([which backing filesystem to use])
AC_MSG_RESULT([$BACKINGFS])
AC_SUBST(BACKINGFS)

case $BACKINGFS in
	ext3)
		# --- Check that ext3 and ext3 xattr are enabled in the kernel
		LC_CONFIG_EXT3([],[
			AC_MSG_ERROR([Lustre requires that ext3 is enabled in the kernel])
		],[
			AC_MSG_WARN([Lustre requires that extended attributes for ext3 are enabled in the kernel])
			AC_MSG_WARN([This build may fail.])
		])
		;;
	ldiskfs)
		AC_MSG_CHECKING([which ldiskfs series to use])
		case $LINUXRELEASE in
		2.6.5*) LDISKFS_SERIES="2.6-suse.series" ;;
		2.6.9*) LDISKFS_SERIES="2.6-rhel4.series" ;;
		2.6.10-ac*) LDISKFS_SERIES="2.6-fc3.series" ;;
		2.6.10*) LDISKFS_SERIES="2.6-rhel4.series" ;;
		2.6.12*) LDISKFS_SERIES="2.6.12-vanilla.series" ;;
		2.6.15*) LDISKFS_SERIES="2.6-fc5.series";;
		2.6.16*) LDISKFS_SERIES="2.6-sles10.series";;
		2.6.18*) LDISKFS_SERIES="2.6.18-vanilla.series";;
		*) AC_MSG_WARN([Unknown kernel version $LINUXRELEASE, fix lustre/autoconf/lustre-core.m4])
		esac
		AC_MSG_RESULT([$LDISKFS_SERIES])
		AC_SUBST(LDISKFS_SERIES)
		;;
esac # $BACKINGFS
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

AC_DEFUN([LC_FUNC_PAGE_MAPPED],
[AC_MSG_CHECKING([if kernel offers page_mapped])
LB_LINUX_TRY_COMPILE([
	#include <linux/mm.h>
],[
	page_mapped(NULL);
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_PAGE_MAPPED, 1, [page_mapped found])
],[
	AC_MSG_RESULT([no])
])
])

AC_DEFUN([LC_STRUCT_FILE_OPS_UNLOCKED_IOCTL],
[AC_MSG_CHECKING([if struct file_operations has an unlocked_ioctl field])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        struct file_operations fops;
        &fops.unlocked_ioctl;
],[
        AC_MSG_RESULT([yes])
        AC_DEFINE(HAVE_UNLOCKED_IOCTL, 1, [struct file_operations has an unlock ed_ioctl field])
],[
        AC_MSG_RESULT([no])
])
])

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
# LC_POSIX_ACL_XATTR
#
# If we have xattr_acl.h 
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


AC_DEFUN([LC_POSIX_ACL_XATTR_H],
[LB_CHECK_FILE([$LINUX/include/linux/posix_acl_xattr.h],[
        AC_MSG_CHECKING([if linux/posix_acl_xattr.h can be compiled])
        LB_LINUX_TRY_COMPILE([
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
])

AC_DEFUN([LC_FUNC_SET_FS_PWD],
[AC_MSG_CHECKING([if kernel exports show_task])
have_show_task=0
        if grep -q "EXPORT_SYMBOL(show_task)" \
                 "$LINUX/fs/namespace.c" 2>/dev/null ; then
		AC_DEFINE(HAVE_SET_FS_PWD, 1, [set_fs_pwd is exported])
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
        fi
])


#
# LC_FUNC_MS_FLOCK_LOCK
#
# SLES9 kernel has MS_FLOCK_LOCK sb flag
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
# SLES9 kernel has third arg can_sleep
# in fs/locks.c: flock_lock_file_wait()
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

#
# LC_FUNC_MS_FLOCK_LOCK
#
# SLES9 kernel has MS_FLOCK_LOCK sb flag
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
# SLES9 kernel has third arg can_sleep
# in fs/locks.c: flock_lock_file_wait()
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
# LC_TASK_PPTR
#
# task struct has p_pptr instead of parent
#
AC_DEFUN([LC_TASK_PPTR],
[AC_MSG_CHECKING([task p_pptr found])
LB_LINUX_TRY_COMPILE([
	#include <linux/sched.h>
],[
	struct task_struct *p;
	
	p = p->p_pptr;
],[
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_TASK_PPTR, 1, [task p_pptr found])
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

# LC_INODE_I_MUTEX
# after 2.6.15 inode have i_mutex intead of i_sem
AC_DEFUN([LC_INODE_I_MUTEX],
[AC_MSG_CHECKING([use inode have i_mutex ])
LB_LINUX_TRY_COMPILE([
	#include <linux/mutex.h>
	#include <linux/fs.h>
],[
	struct inode i;

	mutex_unlock(&i.i_mutex);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_INODE_I_MUTEX, 1,
                [after 2.6.15 inode have i_mutex intead of i_sem])
],[
        AC_MSG_RESULT(NO)
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
        AC_MSG_RESULT(NO)
])
])

#
# LC_STATFS_DENTRY_PARAM
# starting from 2.6.18 linux kernel uses dentry instead of
# super_block for first vfs_statfs argument
#
AC_DEFUN([LC_STATFS_DENTRY_PARAM],
[AC_MSG_CHECKING([first vfs_statfs parameter is dentry])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
	int vfs_statfs(struct dentry *, struct kstatfs *);
],[
        AC_DEFINE(HAVE_STATFS_DENTRY_PARAM, 1,
                [first parameter of vfs_statfs is dentry])
        AC_MSG_RESULT([yes])
],[
        AC_MSG_RESULT([no])
])
])

#
# LC_VFS_KERN_MOUNT
# starting from 2.6.18 kernel don`t export do_kern_mount
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
# more 2.6 api changes.  return type for the invalidatepage
# address_space_operation is 'void' in new kernels but 'int' in old
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
	AC_MSG_RESULT(NO)
])
])

# LC_UMOUNTBEGIN_HAS_VFSMOUNT
# more 2.6 API changes. 2.6.18 umount_begin has different parameters
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
	AC_MSG_RESULT(NO)
])
EXTRA_KCFLAGS="$tmp_flags"
])

# 2.6.19 API changes
# inode don`t have i_blksize field
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
	AC_MSG_RESULT(NO)
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
        AC_MSG_RESULT(NO)
])
EXTRA_KCFLAGS="$tmp_flags"
])

# LC_GENERIC_FILE_WRITE
# 2.6.19 introduce do_sync_write instead of
# generic_file_write
AC_DEFUN([LC_GENERIC_FILE_WRITE],
[AC_MSG_CHECKING([use generic_file_write])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        int result = generic_file_read(NULL, NULL, 0, 0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_GENERIC_FILE_WRITE, 1,
                [use generic_file_write])
],[
	AC_MSG_RESULT(NO)
])
])

# LC_GENERIC_FILE_READ
# 2.6.19 need to use do_sync_read instead of
# generic_file_read
AC_DEFUN([LC_GENERIC_FILE_READ],
[AC_MSG_CHECKING([use generic_file_read])
LB_LINUX_TRY_COMPILE([
        #include <linux/fs.h>
],[
        int result = generic_file_read(NULL, NULL, 0, 0);
],[
        AC_MSG_RESULT(yes)
        AC_DEFINE(HAVE_GENERIC_FILE_READ, 1,
                [use generic_file_read])
],[
        AC_MSG_RESULT(NO)
])
])

# LC_NR_PAGECACHE
# 2.6.18 don`t export nr_pagecahe
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
        AC_MSG_RESULT(NO)
])
])


#
# LC_PROG_LINUX
#
# Lustre linux kernel checks
#
AC_DEFUN([LC_PROG_LINUX],
[ LC_LUSTRE_VERSION_H
if test x$enable_server = xyes ; then
	LC_CONFIG_BACKINGFS
fi
LC_CONFIG_PINGER
LC_CONFIG_LIBLUSTRE_RECOVERY
LC_CONFIG_QUOTA

LC_TASK_PPTR

LC_STRUCT_KIOBUF
LC_FUNC_COND_RESCHED
LC_FUNC_ZAP_PAGE_RANGE
LC_FUNC_PDE
LC_FUNC_DIRECT_IO
LC_HEADER_MM_INLINE
LC_STRUCT_INODE
LC_FUNC_REGISTER_CACHE
LC_FUNC_GRAB_CACHE_PAGE_NOWAIT_GFP
LC_FUNC_DEV_SET_RDONLY
LC_FUNC_FILEMAP_FDATAWRITE
LC_STRUCT_STATFS
LC_FUNC_PAGE_MAPPED
LC_STRUCT_FILE_OPS_UNLOCKED_IOCTL
LC_FILEMAP_POPULATE
LC_D_ADD_UNIQUE
LC_BIT_SPINLOCK_H
LC_XATTR_ACL
LC_STRUCT_INTENT_FILE
LC_POSIX_ACL_XATTR_H
LC_FUNC_SET_FS_PWD
LC_FUNC_MS_FLOCK_LOCK
LC_FUNC_HAVE_CAN_SLEEP_ARG
LC_FUNC_F_OP_FLOCK
LC_QUOTA_READ
LC_COOKIE_FOLLOW_LINK

# 2.6.15
LC_INODE_I_MUTEX

# 2.6.17
LC_DQUOTOFF_MUTEX

# 2.6.18
LC_NR_PAGECACHE
LC_STATFS_DENTRY_PARAM
LC_VFS_KERN_MOUNT
LC_INVALIDATEPAGE_RETURN_INT
LC_UMOUNTBEGIN_HAS_VFSMOUNT

# 2.6.19
LC_INODE_BLKSIZE
LC_VFS_READDIR_U64_INO
LC_GENERIC_FILE_READ
LC_GENERIC_FILE_WRITE
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

AC_MSG_CHECKING([whether to build mpitests])
AC_ARG_ENABLE([mpitests],
	AC_HELP_STRING([--enable-mpitests],
			[build liblustre mpi tests]),
	[],[enable_mpitests=no])
AC_MSG_RESULT([$enable_mpitests])

AC_MSG_NOTICE([Enabling Lustre configure options for libsysio])
ac_configure_args="$ac_configure_args --with-lustre-hack --with-sockets"

LC_CONFIG_PINGER
LC_CONFIG_LIBLUSTRE_RECOVERY
])

#
# LC_CONFIG_QUOTA
#
# whether to enable quota support
#
AC_DEFUN([LC_CONFIG_QUOTA],
[AC_MSG_CHECKING([whether to enable quota support])
AC_ARG_ENABLE([quota], 
	AC_HELP_STRING([--enable-quota],
			[enable quota support]),
	[],[enable_quota='yes'])
AC_MSG_RESULT([$enable_quota])
if test x$linux25 != xyes; then
   enable_quota='no'
fi
if test x$enable_quota != xno; then
   AC_DEFINE(HAVE_QUOTA_SUPPORT, 1, [Enable quota support])
fi
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
	#include <linux/namei.h>
        #include <linux/fs.h>

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
# LC_CONFIGURE
#
# other configure checks
#
AC_DEFUN([LC_CONFIGURE],
[LC_CONFIG_OBD_BUFFER_SIZE

# include/liblustre.h
AC_CHECK_HEADERS([asm/page.h sys/user.h sys/vfs.h stdint.h blkid/blkid.h])

# include/lustre/lustre_user.h
# See note there re: __ASM_X86_64_PROCESSOR_H
AC_CHECK_HEADERS([linux/quota.h])

# liblustre/llite_lib.h
AC_CHECK_HEADERS([xtio.h file.h])

# liblustre/dir.c
AC_CHECK_HEADERS([linux/types.h sys/types.h linux/unistd.h unistd.h])

# liblustre/lutil.c
AC_CHECK_HEADERS([netinet/in.h arpa/inet.h catamount/data.h])
AC_CHECK_FUNCS([inet_ntoa])

# utils/llverfs.c
AC_CHECK_HEADERS([ext2fs/ext2fs.h])

# Super safe df
AC_ARG_ENABLE([mindf],
      AC_HELP_STRING([--enable-mindf],
                      [Make statfs report the minimum available space on any single OST instead of the sum of free space on all OSTs]),
      [],[])
if test "$enable_mindf" = "yes" ;  then
      AC_DEFINE([MIN_DF], 1, [Report minimum OST free space])
fi

])

#
# LC_CONDITIONALS
#
# AM_CONDITIONALS for lustre
#
AC_DEFUN([LC_CONDITIONALS],
[AM_CONDITIONAL(LIBLUSTRE, test x$enable_liblustre = xyes)
AM_CONDITIONAL(LDISKFS, test x$enable_ldiskfs = xyes)
AM_CONDITIONAL(USE_QUILT, test x$QUILT != xno)
AM_CONDITIONAL(LIBLUSTRE_TESTS, test x$enable_liblustre_tests = xyes)
AM_CONDITIONAL(MPITESTS, test x$enable_mpitests = xyes, Build MPI Tests)
AM_CONDITIONAL(CLIENT, test x$enable_client = xyes)
AM_CONDITIONAL(SERVER, test x$enable_server = xyes)
AM_CONDITIONAL(QUOTA, test x$enable_quota = xyes)
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
lustre/contrib/Makefile
lustre/doc/Makefile
lustre/include/Makefile
lustre/include/lustre_ver.h
lustre/include/linux/Makefile
lustre/include/lustre/Makefile
lustre/kernel_patches/targets/2.6-suse.target
lustre/kernel_patches/targets/2.6-vanilla.target
lustre/kernel_patches/targets/2.6-rhel4.target
lustre/kernel_patches/targets/2.6-fc5.target
lustre/kernel_patches/targets/2.6-patchless.target
lustre/kernel_patches/targets/hp_pnnl-2.4.target
lustre/kernel_patches/targets/rh-2.4.target
lustre/kernel_patches/targets/rhel-2.4.target
lustre/kernel_patches/targets/suse-2.4.21-2.target
lustre/kernel_patches/targets/sles-2.4.target
lustre/ldiskfs/Makefile
lustre/ldiskfs/autoMakefile
lustre/ldlm/Makefile
lustre/liblustre/Makefile
lustre/liblustre/tests/Makefile
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
lustre/scripts/version_tag.pl
lustre/tests/Makefile
lustre/utils/Makefile
])
case $lb_target_os in
        darwin)
                AC_CONFIG_FILES([ lustre/obdclass/darwin/Makefile ])
                ;;
esac

])
