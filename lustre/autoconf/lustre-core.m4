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

pymoddir='${pkglibdir}/python/Lustre'
AC_SUBST(pymoddir)
])

#
# LC_TARGET_SUPPORTED
#
# is the target os supported?
#
AC_DEFUN([LC_TARGET_SUPPORTED],
[case $target_os in
	linux*)
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
[AC_CHECK_FILE([$LINUX/include/linux/fshooks.h],[
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
[AC_MSG_CHECKING([if zap_pag_range with vma parameter])
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
HAVE_GCPN_GFP="`grep -c 'grab_cache_page_nowait_gfp' $LINUX/mm/filemap.c`"
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
# whether to use extN or ldiskfs instead of ext3
#
AC_DEFUN([LC_CONFIG_BACKINGFS],
[
BACKINGFS='ext3'

# LLNL patches their ext3 and calls it extN
AC_MSG_CHECKING([whether to use extN])
AC_ARG_ENABLE([extN],
	AC_HELP_STRING([--enable-extN],
			[use extN instead of ext3 for lustre backend]),
	[BACKINGFS='extN'],[enable_extN='no'])
AC_MSG_RESULT([$enable_extN])

# SuSE gets ldiskfs
AC_MSG_CHECKING([whether to enable ldiskfs])
AC_ARG_ENABLE([ldiskfs],
	AC_HELP_STRING([--enable-ldiskfs],
			[use ldiskfs for the Lustre backing FS]),
	[],[enable_ldiskfs="$linux25"])
AC_MSG_RESULT([$enable_ldiskfs])

if test x$enable_ldiskfs = xyes ; then
	BACKINGFS="ldiskfs"

	AC_PATH_PROG(PATCH, patch, [no])
	AC_PATH_PROG(QUILT, quilt, [no])

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
		LC_FSHOOKS([
			LDISKFS_SERIES="2.6-suse.series"
		],[
			LDISKFS_SERIES="2.6-rhel4.series"
		])
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
# LC_PROG_LINUX
#
# Lustre linux kernel checks
#
AC_DEFUN([LC_PROG_LINUX],
[LC_CONFIG_BACKINGFS
LC_CONFIG_PINGER

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
	[],[enable_liblustre="no"])
AC_MSG_RESULT([$enable_liblustre])
# only build sysio if liblustre is built
with_sysio="$enable_liblustre"

AC_MSG_CHECKING([whether to build mpitests])
AC_ARG_ENABLE([mpitests],
	AC_HELP_STRING([--enable-mpitests],
			[build liblustre mpi tests]),
	[],[enable_mpitests=no])
AC_MSG_RESULT([$enable_mpitests])
])

#
# LC_CONFIGURE
#
# other configure checks
#
AC_DEFUN([LC_CONFIGURE],
[LC_CONFIG_OBD_BUFFER_SIZE

# include/liblustre.h
AC_CHECK_HEADERS([asm/page.h sys/user.h stdint.h])

# liblustre/llite_lib.h
AC_CHECK_HEADERS([xtio.h file.h])

# liblustre/dir.c
AC_CHECK_HEADERS([linux/types.h sys/types.h linux/unistd.h unistd.h])

# liblustre/lutil.c
AC_CHECK_HEADERS([netinet/in.h arpa/inet.h catamount/data.h])
AC_CHECK_FUNCS([inet_ntoa])
])

#
# LC_CONDITIONALS
#
# AM_CONDITIONALS for lustre
#
AC_DEFUN([LC_CONDITIONALS],
[AM_CONDITIONAL(LIBLUSTRE, test x$enable_liblustre = xyes)
AM_CONDITIONAL(EXTN, test x$enable_extN = xyes)
AM_CONDITIONAL(LDISKFS, test x$enable_ldiskfs = xyes)
AM_CONDITIONAL(USE_QUILT, test x$QUILT != xno)
AM_CONDITIONAL(MPITESTS, test x$enable_mpitests = xyes, Build MPI Tests)
AM_CONDITIONAL(LIBLUSTRE, test x$enable_liblustre = xyes)
AM_CONDITIONAL(MPITESTS, test x$enable_mpitests = xyes, Build MPI Tests)
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
lustre/doc/Makefile
lustre/include/Makefile
lustre/include/linux/Makefile
lustre/include/lustre/Makefile
lustre/kernel_patches/targets/2.6-suse.target
lustre/kernel_patches/targets/2.6-vanilla.target
lustre/kernel_patches/targets/2.6-rhel4.target
lustre/kernel_patches/targets/hp_pnnl-2.4.target
lustre/kernel_patches/targets/rh-2.4.target
lustre/kernel_patches/targets/rhel-2.4.target
lustre/kernel_patches/targets/suse-2.4.21-2.target
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
lustre/obdecho/Makefile
lustre/obdecho/autoMakefile
lustre/obdfilter/Makefile
lustre/obdfilter/autoMakefile
lustre/osc/Makefile
lustre/osc/autoMakefile
lustre/ost/Makefile
lustre/ost/autoMakefile
lustre/ptlrpc/Makefile
lustre/ptlrpc/autoMakefile
lustre/scripts/Makefile
lustre/scripts/version_tag.pl
lustre/tests/Makefile
lustre/utils/Lustre/Makefile
lustre/utils/Makefile
])
])
