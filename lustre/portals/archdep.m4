# -------- we can't build modules unless srcdir = builddir
if test x$enable_modules != xno ; then
	AC_CHECK_FILE([autoMakefile.am],[],
		[AC_MSG_ERROR([At this time, Lustre does not support building kernel modules with srcdir != buildir.])])
fi

# -------- in kernel compilation? (2.5 only) -------------
AC_MSG_CHECKING([if inkernel build support is requested])
AC_ARG_ENABLE([inkernel],
	AC_HELP_STRING([--enable-inkernel],
		       [set up 2.5 kernel makefiles]),
	[],[enable_inkernel=no])
AC_MSG_RESULT([$enable_inkernel])
AM_CONDITIONAL(INKERNEL, test x$enable_inkernel = xyes)

# -------- are we building against an external portals? -------
AC_MSG_CHECKING([for Cray portals])
AC_ARG_WITH([cray-portals],
	AC_HELP_STRING([--with-cray-portals=path],
		       [path to cray portals]),
	[
	        if test "$with_cray_portals" != no; then
			CRAY_PORTALS_PATH=$with_cray_portals
			CRAY_PORTALS_INCLUDES="$with_cray_portals/include"
			CRAY_PORTALS_LIBS="$with_cray_portals"
                fi
	],[with_cray_portals=no])
AC_SUBST(CRAY_PORTALS_PATH)
AC_MSG_RESULT([$CRAY_PORTALS_PATH])

AC_MSG_CHECKING([for Cray portals includes])
AC_ARG_WITH([cray-portals-includes],
	AC_HELP_STRING([--with-cray-portals-includes=path],
		       [path to cray portals includes]),
	[
	        if test "$with_cray_portals_includes" != no; then
			CRAY_PORTALS_INCLUDES="$with_cray_portals_includes"
                fi
	])
AC_SUBST(CRAY_PORTALS_INCLUDES)
AC_MSG_RESULT([$CRAY_PORTALS_INCLUDES])

AC_MSG_CHECKING([for Cray portals libs])
AC_ARG_WITH([cray-portals-libs],
	AC_HELP_STRING([--with-cray-portals-libs=path],
		       [path to cray portals libs]),
	[
	        if test "$with_cray_portals_libs" != no; then
			CRAY_PORTALS_LIBS="$with_cray_portals_libs"
                fi
	])
AC_SUBST(CRAY_PORTALS_LIBS)
AC_MSG_RESULT([$CRAY_PORTALS_LIBS])

if test x$CRAY_PORTALS_INCLUDES != x ; then
	if test ! -r $CRAY_PORTALS_INCLUDES/portals/api.h ; then
		AC_MSG_ERROR([Cray portals headers were not found in $CRAY_PORTALS_INCLUDES.  Please check the paths passed to --with-cray-portals or --with-cray-portals-includes.])
	fi
fi
if test x$CRAY_PORTALS_LIBS != x ; then
	if test ! -r $CRAY_PORTALS_LIBS/libportals.a ; then
		AC_MSG_ERROR([Cray portals libraries were not found in $CRAY_PORTALS_LIBS.  Please check the paths passed to --with-cray-portals or --with-cray-portals-libs.])
	fi
fi

AC_MSG_CHECKING([whether to use Cray portals])
if test x$CRAY_PORTALS_INCLUDES != x -a x$CRAY_PORTALS_LIBS != x ; then
	with_cray_portals=yes
	AC_DEFINE(CRAY_PORTALS, 1, [Building with Cray Portals])
	CRAY_PORTALS_INCLUDES="-I$CRAY_PORTALS_INCLUDES"
else
	with_cray_portals=no
fi
AC_MSG_RESULT([$with_cray_portals])
AM_CONDITIONAL(CRAY_PORTALS, test x$with_cray_portals != xno)

# ----------------------------------------
# some tests for catamount-like systems
# ----------------------------------------
AC_ARG_ENABLE([sysio_init],
	AC_HELP_STRING([--disable-sysio-init],
		[call sysio init functions when initializing liblustre]),
	[],[enable_sysio_init=yes])
AC_MSG_CHECKING([whether to initialize libsysio])
AC_MSG_RESULT([$enable_sysio_init])
if test x$enable_sysio_init != xno ; then
	AC_DEFINE([INIT_SYSIO], 1, [call sysio init functions])
fi

AC_ARG_ENABLE([urandom],
	AC_HELP_STRING([--disable-urandom],
		[disable use of /dev/urandom for liblustre]),
	[],[enable_urandom=yes])
AC_MSG_CHECKING([whether to use /dev/urandom for liblustre])
AC_MSG_RESULT([$enable_urandom])
if test x$enable_urandom != xno ; then
	AC_DEFINE([LIBLUSTRE_USE_URANDOM], 1, [use /dev/urandom for random data])
fi

# -------- check for -lcap and -lpthread ----
if test x$enable_liblustre = xyes ; then
	AC_CHECK_LIB([cap], [cap_get_proc],
		[
			CAP_LIBS="-lcap"
			AC_DEFINE([HAVE_LIBCAP], 1, [use libcap])
		],
		[CAP_LIBS=""])
	AC_SUBST(CAP_LIBS)
	AC_CHECK_LIB([pthread], [pthread_create],
		[
			PTHREAD_LIBS="-lpthread"
			AC_DEFINE([HAVE_LIBPTHREAD], 1, [use libpthread])
		],
		[PTHREAD_LIBS=""])
	AC_SUBST(PTHREAD_LIBS)
fi

# -------- enable tests and utils? -------
if test x$enable_tests = xno ; then
	AC_MSG_NOTICE([disabling tests])
	enable_tests=no
fi
if test x$enable_utils = xno ; then
	AC_MSG_NOTICE([disabling utilities])
	enable_utils=no
fi

if test x$enable_modules != xno ; then
	# -------- set linuxdir ------------
	AC_MSG_CHECKING([for Linux sources])
	AC_ARG_WITH([linux],
		AC_HELP_STRING([--with-linux=path],
			       [set path to Linux source (default=/usr/src/linux)]),
		[LINUX=$with_linux],
		[LINUX=/usr/src/linux])
	AC_MSG_RESULT([$LINUX])
	AC_SUBST(LINUX)
	if test x$enable_inkernel = xyes ; then
	        echo ln -s `pwd` $LINUX/fs/lustre
	        rm $LINUX/fs/lustre
	        ln -s `pwd` $LINUX/fs/lustre
	fi

	# -------- check for .confg --------
	AC_ARG_WITH([linux-config],
		[AC_HELP_STRING([--with-linux-config=path],
				[set path to Linux .conf (default=\$LINUX/.config)])],
		[LINUX_CONFIG=$with_linux_config],
		[LINUX_CONFIG=$LINUX/.config])
	AC_SUBST(LINUX_CONFIG)

	AC_CHECK_FILE([/boot/kernel.h],
		[KERNEL_SOURCE_HEADER='/boot/kernel.h'],
		[AC_CHECK_FILE([/var/adm/running-kernel.h]),
			[KERNEL_SOURCE_HEADER='/var/adm/running-kernel.h']])

	AC_ARG_WITH([kernel-source-header],
		AC_HELP_STRING([--with-kernel-source-header=path],
				[Use a different kernel version header.  Consult README.kernel-source for details.]),
		[KERNEL_SOURCE_HEADER=$with_kernel_source_header])

	#  --------------------
	ARCH_UM=
	UML_CFLAGS=

	AC_MSG_CHECKING([if you are running user mode linux for $host_cpu])
	if test -e $LINUX/include/asm-um ; then
		if test  X`ls -id $LINUX/include/asm/ | awk '{print $1}'` = X`ls -id $LINUX/include/asm-um | awk '{print $1}'` ; then
			ARCH_UM='ARCH=um'
			# see notes in Rules.in
			UML_CFLAGS='-O0'
			AC_MSG_RESULT(yes)
	    	else
			AC_MSG_RESULT([no (asm doesn't point at asm-um)])
		fi
	else
		AC_MSG_RESULT([no (asm-um missing)])
	fi

	AC_SUBST(ARCH_UM)
	AC_SUBST(UML_CFLAGS)

	# --------- Linux 25 ------------------
	AC_CHECK_FILE([$LINUX/include/linux/namei.h],
		[
	        	linux25="yes"
			KMODEXT=".ko"
			enable_ldiskfs="yes"
			BACKINGFS="ldiskfs"
		],[
			KMODEXT=".o"
			linux25="no"
		])
	AC_MSG_CHECKING([if you are using Linux 2.6])
	AC_MSG_RESULT([$linux25])

	AC_SUBST(LINUX25)
	AC_SUBST(KMODEXT)

	AC_PATH_PROG(PATCH, patch, [no])
	AC_PATH_PROG(QUILT, quilt, [no])

	if test x$enable_ldiskfs$PATCH$QUILT = xyesnono ; then
		AC_MSG_ERROR([Quilt or patch are needed to build the ldiskfs module (for Linux 2.6)])
	fi
fi
AM_CONDITIONAL(LINUX25, test x$linux25 = xyes)
AM_CONDITIONAL(USE_QUILT, test x$QUILT != xno)

# -------  Makeflags ------------------

CPPFLAGS="$CPPFLAGS $CRAY_PORTALS_INCLUDES -I\$(top_srcdir)/include -I\$(top_srcdir)/portals/include"

# liblustre are all the same
LLCPPFLAGS="-D__arch_lib__ -D_LARGEFILE64_SOURCE=1"
AC_SUBST(LLCPPFLAGS)

LLCFLAGS="-g -Wall -fPIC"
AC_SUBST(LLCFLAGS)

# everyone builds against portals and lustre

if test x$enable_ldiskfs = xyes ; then
	AC_DEFINE(CONFIG_LDISKFS_FS_MODULE, 1, [build ldiskfs as a module])
	AC_DEFINE(CONFIG_LDISKFS_FS_XATTR, 1, [enable extended attributes for ldiskfs])
	AC_DEFINE(CONFIG_LDISKFS_FS_POSIX_ACL, 1, [enable posix acls])
	AC_DEFINE(CONFIG_LDISKFS_FS_SECURITY, 1, [enable fs security])
fi

EXTRA_KCFLAGS="-g $CRAY_PORTALS_INCLUDES -I$PWD/portals/include -I$PWD/include"

# these are like AC_TRY_COMPILE, but try to build modules against the
# kernel, inside the kernel-tests directory

AC_DEFUN([LUSTRE_MODULE_CONFTEST],
[cat >conftest.c <<_ACEOF
$1
_ACEOF
])

AC_DEFUN([LUSTRE_MODULE_COMPILE_IFELSE],
[m4_ifvaln([$1], [LUSTRE_MODULE_CONFTEST([$1])])dnl
rm -f kernel-tests/conftest.o kernel-tests/conftest.mod.c kernel-tests/conftest.ko
AS_IF([AC_TRY_COMMAND(cp conftest.c kernel-tests && make [$2] CC=$CC -f $PWD/kernel-tests/Makefile LUSTRE_LINUX_CONFIG=$LINUX_CONFIG -o tmp_include_depends -o scripts -o include/config/MARKER -C $LINUX EXTRA_CFLAGS="-Werror-implicit-function-declaration $EXTRA_KCFLAGS" $ARCH_UM SUBDIRS=$PWD/kernel-tests) >/dev/null && AC_TRY_COMMAND([$3])],
	[$4],
	[_AC_MSG_LOG_CONFTEST
m4_ifvaln([$5],[$5])dnl])dnl
rm -f kernel-tests/conftest.o kernel-tests/conftest.mod.c kernel-tests/conftest.mod.o kernel-tests/conftest.ko m4_ifval([$1], [kernel-tests/conftest.c conftest.c])[]dnl
])

AC_DEFUN([LUSTRE_MODULE_TRY_COMPILE],
[LUSTRE_MODULE_COMPILE_IFELSE(
	[AC_LANG_PROGRAM([[$1]], [[$2]])],
	[modules],
	[test -s kernel-tests/conftest.o],
	[$3], [$4])])

AC_DEFUN([LUSTRE_MODULE_TRY_MAKE],
[LUSTRE_MODULE_COMPILE_IFELSE([AC_LANG_PROGRAM([[$1]], [[$2]])], [$3], [$4], [$5], [$6])])

# ------------ include paths ------------------

if test x$enable_modules != xno ; then
	# ------------ .config exists ----------------
	AC_CHECK_FILE([$LINUX_CONFIG],[],
		[AC_MSG_ERROR([Kernel config could not be found.  If you are building from a kernel-source rpm consult README.kernel-source])])

	# ----------- make dep run? ------------------
	AC_CHECK_FILES([$LINUX/include/linux/autoconf.h
			$LINUX/include/linux/version.h
			$LINUX/include/linux/config.h],[],
		[AC_MSG_ERROR([Run make config in $LINUX.])])

	# ------------ rhconfig.h includes runtime-generated bits --
	# red hat kernel-source checks

	# we know this exists after the check above.  if the user
	# tarred up the tree and ran make dep etc. in it, then
	# version.h gets overwritten with a standard linux one.

	if grep rhconfig $LINUX/include/linux/version.h >/dev/null ; then
		# This is a clean kernel-source tree, we need to
		# enable extensive workarounds to get this to build
		# modules
		AC_CHECK_FILE([$KERNEL_SOURCE_HEADER],
			[if test $KERNEL_SOURCE_HEADER = '/boot/kernel.h' ; then
				AC_MSG_WARN([Using /boot/kernel.h from RUNNING kernel.])
				AC_MSG_WARN([If this is not what you want, use --with-kernel-source-header.])
				AC_MSG_WARN([Consult README.kernel-source for details.])
			fi],
			[AC_MSG_ERROR([$KERNEL_SOURCE_HEADER not found.  Consult README.kernel-source for details.])])
		EXTRA_KCFLAGS="-include $KERNEL_SOURCE_HEADER $EXTRA_KCFLAGS"
	fi

	# --- check that we can build modules at all
	AC_MSG_CHECKING([that modules can be built])
	LUSTRE_MODULE_TRY_COMPILE([],[],
		[
			AC_MSG_RESULT([yes])
		],[
			AC_MSG_RESULT([no])
			AC_MSG_WARN([Consult config.log for details.])
			AC_MSG_WARN([If you are trying to build with a kernel-source rpm, consult README.kernel-source])
			AC_MSG_ERROR([Kernel modules could not be built.])
		])

	# ------------ LINUXRELEASE and moduledir ------------------
	MODULE_TARGET="SUBDIRS"
	if test $linux25 = 'yes' ; then
		# ------------ external module support ---------------------
		makerule="$PWD/kernel-tests"
		AC_MSG_CHECKING([for external module build support])
		rm -f kernel-tests/conftest.i
		LUSTRE_MODULE_TRY_MAKE([],[],
			[$makerule LUSTRE_KERNEL_TEST=conftest.i],
			[test -s kernel-tests/conftest.i],
			[
				AC_MSG_RESULT([no])
			],[
				AC_MSG_RESULT([yes])
				makerule="_module_$makerule"
				MODULE_TARGET="M"
			])
	else
		makerule="_dir_$PWD/kernel-tests"
	fi
	AC_SUBST(MODULE_TARGET)
	LINUXRELEASE=
	rm -f kernel-tests/conftest.i
	AC_MSG_CHECKING([for Linux release])
	LUSTRE_MODULE_TRY_MAKE(
		[#include <linux/version.h>],
		[char *LINUXRELEASE;
		 LINUXRELEASE=UTS_RELEASE;],
		[$makerule LUSTRE_KERNEL_TEST=conftest.i],
		[test -s kernel-tests/conftest.i],
		[
			# LINUXRELEASE="UTS_RELEASE"
			eval $(grep "LINUXRELEASE=" kernel-tests/conftest.i)
		],[
			AC_MSG_RESULT([unknown])
			AC_MSG_ERROR([Could not preprocess test program.  Consult config.log for details.])
		])
	rm -f kernel-tests/conftest.i
	if test x$LINUXRELEASE = x ; then
		AC_MSG_RESULT([unknown])
		AC_MSG_ERROR([Could not determine Linux release version from linux/version.h.])
	fi
	AC_MSG_RESULT([$LINUXRELEASE])
	AC_SUBST(LINUXRELEASE)

	moduledir='/lib/modules/'$LINUXRELEASE/kernel
	modulefsdir='$(moduledir)/fs/$(PACKAGE)'
	modulenetdir='$(moduledir)/net/$(PACKAGE)'

	AC_SUBST(moduledir)
	AC_SUBST(modulefsdir)
	AC_SUBST(modulenetdir)

	# ------------ RELEASE --------------------------------
	AC_MSG_CHECKING([for Lustre release])
  	RELEASE="`echo ${LINUXRELEASE} | tr '-' '_'`_`date +%Y%m%d%H%M`"
	AC_MSG_RESULT($RELEASE)
	AC_SUBST(RELEASE)

	# ---------- Portals flags --------------------

	AC_MSG_CHECKING([for zero-copy TCP support])
	AC_ARG_ENABLE([zerocopy],
		AC_HELP_STRING([--disable-zerocopy],
			       [disable socknal zerocopy]),
		[],[enable_zerocopy='yes'])
	if test x$enable_zerocopy = xno ; then
		AC_MSG_RESULT([no (by request)])
	else
		ZCCD="`grep -c zccd $LINUX/include/linux/skbuff.h`"
		if test "$ZCCD" != 0 ; then
			AC_DEFINE(SOCKNAL_ZC, 1, [use zero-copy TCP])
			AC_MSG_RESULT(yes)
		else
			AC_MSG_RESULT([no (no kernel support)])
		fi
	fi

	AC_ARG_ENABLE([affinity],
		AC_HELP_STRING([--disable-affinity],
			       [disable process/irq affinity]),
		[],[enable_affinity='yes'])

	AC_MSG_CHECKING([for CPU affinity support])
	if test x$enable_affinity = xno ; then
		AC_MSG_RESULT([no (by request)])
	else
		LUSTRE_MODULE_TRY_COMPILE(
			[
				#include <linux/sched.h>
			],[
				struct task_struct t;
				#ifdef CPU_ARRAY_SIZE
				cpumask_t m;
				#else
				unsigned long m;
				#endif
				set_cpus_allowed(&t, m);
			],[
				AC_DEFINE(CPU_AFFINITY, 1, [kernel has cpu affinity support])
				AC_MSG_RESULT([yes])
			],[
				AC_MSG_RESULT([no (no kernel support)])
			])
	fi

	#####################################

	AC_MSG_CHECKING([if quadrics kernel headers are present])
	if test -d $LINUX/drivers/net/qsnet ; then
		AC_MSG_RESULT([yes])
		QSWNAL="qswnal"
		AC_MSG_CHECKING([for multirail EKC])
		if test -f $LINUX/include/elan/epcomms.h; then
			AC_MSG_RESULT([supported])
			QSWCPPFLAGS="-DMULTIRAIL_EKC=1"
		else
			AC_MSG_RESULT([not supported])
			if test -d $LINUX/drivers/net/qsnet/include; then
				QSWCPPFLAGS="-I$LINUX/drivers/net/qsnet/include"
			else
				QSWCPPFLAGS="-I$LINUX/include/linux"
			fi
		fi
	else
		AC_MSG_RESULT([no])
		QSWNAL=""
		QSWCPPFLAGS=""
	fi
	AC_SUBST(QSWCPPFLAGS)
	AC_SUBST(QSWNAL)

	AC_MSG_CHECKING([if gm support was requested])
	AC_ARG_WITH([gm],
		AC_HELP_STRING([--with-gm=path],
			       [build gmnal against path]),
		[
			case $with_gm in 
				yes)
					AC_MSG_RESULT([yes])
					GMCPPFLAGS="-I/usr/local/gm/include"
					GMNAL="gmnal"
					;;
				no)
					AC_MSG_RESULT([no])
					GMCPPFLAGS=""
					GMNAL=""
					;;
				*)
					AC_MSG_RESULT([yes])
					GMCPPFLAGS="-I$with_gm/include -I$with_gm/drivers -I$with_gm/drivers/linux/gm"
					GMNAL="gmnal"
					;;
			esac
		],[
			AC_MSG_RESULT([no])
			GMCPPFLAGS=""
			GMNAL=""
		])
	AC_SUBST(GMCPPFLAGS)
	AC_SUBST(GMNAL)

	#### OpenIB 
	AC_MSG_CHECKING([if OpenIB kernel headers are present])
	OPENIBCPPFLAGS="-I$LINUX/drivers/infiniband/include -DIN_TREE_BUILD"
	EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS $OPENIBCPPFLAGS"
	LUSTRE_MODULE_TRY_COMPILE(
		[
			#include <ts_ib_core.h>
		],[
	                struct ib_device_properties props;
			return 0;
		],[
			AC_MSG_RESULT([yes])
			OPENIBNAL="openibnal"
		],[
			AC_MSG_RESULT([no])
			OPENIBNAL=""
			OPENIBCPPFLAGS=""
		])
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
	AC_SUBST(OPENIBCPPFLAGS)
	AC_SUBST(OPENIBNAL)

	#### Infinicon IB
	AC_MSG_CHECKING([if Infinicon IB kernel headers are present])
	# for how the only infinicon ib build has headers in /usr/include/iba
	IIBCPPFLAGS="-I/usr/include -DIN_TREE_BUILD"
	EXTRA_KCFLAGS_save="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS $IIBCPPFLAGS"
	LUSTRE_MODULE_TRY_COMPILE(
		[
			#include <linux/iba/ibt.h>
		],[
	                IBT_INTERFACE_UNION interfaces;
	                FSTATUS             rc;

	                rc = IbtGetInterfaceByVersion(IBT_INTERFACE_VERSION_2,
						      &interfaces);

			return rc == FSUCCESS ? 0 : 1;
		],[
			AC_MSG_RESULT([yes])
			IIBNAL="iibnal"
		],[
			AC_MSG_RESULT([no])
			IIBNAL=""
			IIBCPPFLAGS=""
		])
	EXTRA_KCFLAGS="$EXTRA_KCFLAGS_save"
	AC_SUBST(IIBCPPFLAGS)
	AC_SUBST(IIBNAL)

	# ---------- Red Hat 2.4.18 has iobuf->dovary --------------
	# But other kernels don't

	AC_MSG_CHECKING([if struct kiobuf has a dovary field])
	LUSTRE_MODULE_TRY_COMPILE(
		[
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

	# ----------- 2.6.4 no longer has page->list ---------------
	AC_MSG_CHECKING([if struct page has a list field])
	LUSTRE_MODULE_TRY_COMPILE(
		[
			#include <linux/mm.h>
		],[
			struct page page;
			&page.list;
		],[
			AC_MSG_RESULT([yes])
			AC_DEFINE(HAVE_PAGE_LIST, 1, [struct page has a list field])
		],[
			AC_MSG_RESULT([no])
		])

	# ---------- Red Hat 2.4.20 backports some 2.5 bits --------
	# This needs to run after we've defined the KCPPFLAGS

	AC_MSG_CHECKING([if task_struct has a sighand field])
	LUSTRE_MODULE_TRY_COMPILE(
		[
			#include <linux/sched.h>
		],[
			struct task_struct p;
			p.sighand = NULL;
		],[
			AC_DEFINE(CONFIG_RH_2_4_20, 1, [this kernel contains Red Hat 2.4.20 patches])
			AC_MSG_RESULT([yes])
		],[
			AC_MSG_RESULT([no])
		])

	# ---------- 2.4.20 introduced cond_resched --------------

	AC_MSG_CHECKING([if kernel offers cond_resched])
	LUSTRE_MODULE_TRY_COMPILE(
		[
			#include <linux/sched.h>
		],[
			cond_resched();
		],[
			AC_MSG_RESULT([yes])
			AC_DEFINE(HAVE_COND_RESCHED, 1, [cond_resched found])
		],[
			AC_MSG_RESULT([no])
		])

	# --------- zap_page_range(vma) --------------------------------
	AC_MSG_CHECKING([if zap_pag_range with vma parameter])
	ZAP_PAGE_RANGE_VMA="`grep -c 'zap_page_range.*struct vm_area_struct' $LINUX/include/linux/mm.h`"
	if test "$ZAP_PAGE_RANGE_VMA" != 0 ; then
		AC_DEFINE(ZAP_PAGE_RANGE_VMA, 1, [zap_page_range with vma parameter])
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
	fi

	# ---------- Red Hat 2.4.21 backports some more 2.5 bits --------

	AC_MSG_CHECKING([if kernel defines PDE])
	HAVE_PDE="`grep -c 'proc_dir_entry..PDE' $LINUX/include/linux/proc_fs.h`"
	if test "$HAVE_PDE" != 0 ; then
		AC_DEFINE(HAVE_PDE, 1, [the kernel defines PDE])
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
	fi

	AC_MSG_CHECKING([if kernel passes struct file to direct_IO])
	HAVE_DIO_FILE="`grep -c 'direct_IO.*struct file' $LINUX/include/linux/fs.h`"
	if test "$HAVE_DIO_FILE" != 0 ; then
		AC_DEFINE(HAVE_DIO_FILE, 1, [the kernel passes struct file to direct_IO])
		AC_MSG_RESULT(yes)
	else
		AC_MSG_RESULT(no)
	fi

	AC_MSG_CHECKING([if kernel defines cpu_online()])
	LUSTRE_MODULE_TRY_COMPILE(
		[
			#include <linux/sched.h>
		],[
			cpu_online(0);
		],[
			AC_MSG_RESULT([yes])
			AC_DEFINE(HAVE_CPU_ONLINE, 1, [cpu_online found])
		],[
			AC_MSG_RESULT([no])
		])
	AC_MSG_CHECKING([if kernel defines cpumask_t])
	LUSTRE_MODULE_TRY_COMPILE(
		[
			#include <linux/sched.h>
		],[
			return sizeof (cpumask_t);
		],[
			AC_MSG_RESULT([yes])
			AC_DEFINE(HAVE_CPUMASK_T, 1, [cpumask_t found])
		],[
			AC_MSG_RESULT([no])
		])

	# ---------- RHEL kernels define page_count in mm_inline.h
	AC_MSG_CHECKING([if kernel has mm_inline.h header])
	LUSTRE_MODULE_TRY_COMPILE(
		[
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

	# ---------- inode->i_alloc_sem --------------
	AC_MSG_CHECKING([if struct inode has i_alloc_sem])
	LUSTRE_MODULE_TRY_COMPILE(
		[
			#include <linux/fs.h>
			#include <linux/version.h>
		],[
			#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,24))
			#error "x86_64 down_read_trylock broken before 2.4.24"
			#endif
			struct inode i;
			return (char *)&i.i_alloc_sem - (char *)&i;
		],[
			AC_MSG_RESULT([yes])
			AC_DEFINE(HAVE_I_ALLOC_SEM, 1, [struct inode has i_alloc_sem])
		],[
			AC_MSG_RESULT([no])
		])


	# ---------- modules? ------------------------
	AC_MSG_CHECKING([for module support])
	LUSTRE_MODULE_TRY_COMPILE(
		[
			#include <linux/config.h>
		],[
			#ifndef CONFIG_MODULES
			#error CONFIG_MODULES not #defined
			#endif
		],[
			AC_MSG_RESULT([yes])
		],[
			AC_MSG_RESULT([no])
			AC_MSG_ERROR([module support is required to build Lustre kernel modules.])
		])

	# ---------- modversions? --------------------
	AC_MSG_CHECKING([for MODVERSIONS])
	LUSTRE_MODULE_TRY_COMPILE(
		[
			#include <linux/config.h>
		],[
			#ifndef CONFIG_MODVERSIONS
			#error CONFIG_MODVERSIONS not #defined
			#endif
		],[
			AC_MSG_RESULT([yes])
		],[
			AC_MSG_RESULT([no])
		])

	# ------------ preempt -----------------------
	AC_MSG_CHECKING([if preempt is enabled])
	LUSTRE_MODULE_TRY_COMPILE(
		[
			#include <linux/config.h>
		],[
			#ifndef CONFIG_PREEMPT
			#error CONFIG_PREEMPT is not #defined
			#endif
		],[
			AC_MSG_RESULT([yes])
			AC_MSG_ERROR([Lustre does not support kernels with preempt enabled.])
		],[
			AC_MSG_RESULT([no])
		])

	# ------------ kallsyms (so software watchdogs produce useful stacks)
	AC_MSG_CHECKING([if kallsyms is enabled])
	LUSTRE_MODULE_TRY_COMPILE(
		[
			#include <linux/config.h>
		],[
			#ifndef CONFIG_KALLSYMS
			#error CONFIG_KALLSYMS is not #defined
			#endif
		],[
			AC_MSG_RESULT([yes])
		],[
			AC_MSG_RESULT([no])
			if test "x$ARCH_UM" = "x" ; then
				AC_MSG_ERROR([Lustre requires that CONFIG_KALLSYMS is enabled in your kernel.])
			fi
		])

	# ------------ check for our show_task patch
	AC_MSG_CHECKING([if kernel exports show_task])
	have_show_task=0
	for file in ksyms sched ; do
		if grep -q "EXPORT_SYMBOL(show_task)" \
			 "$LINUX/kernel/$file.c" 2>/dev/null ; then
			have_show_task=1
			break
		fi
	done
	if test x$have_show_task = x1 ; then
		AC_DEFINE(HAVE_SHOW_TASK, 1, [show_task is exported])
		AC_MSG_RESULT(yes)
	else
		AC_MSG_RESULT(no)
	fi

	case $BACKINGFS in
		ext3)
			# --- Check that ext3 and ext3 xattr are enabled in the kernel
			AC_MSG_CHECKING([that ext3 is enabled in the kernel])
			LUSTRE_MODULE_TRY_COMPILE(
				[
					#include <linux/config.h>
				],[
					#ifndef CONFIG_EXT3_FS
					#ifndef CONFIG_EXT3_FS_MODULE
					#error CONFIG_EXT3_FS not #defined
					#endif
					#endif
				],[
					AC_MSG_RESULT([yes])
				],[
					AC_MSG_RESULT([no])
					AC_MSG_ERROR([Lustre requires that ext3 is enabled in the kernel (CONFIG_EXT3_FS)])
				])
	
			AC_MSG_CHECKING([that extended attributes for ext3 are enabled in the kernel])
			LUSTRE_MODULE_TRY_COMPILE(
				[
					#include <linux/config.h>
				],[
					#ifndef CONFIG_EXT3_FS_XATTR
					#error CONFIG_EXT3_FS_XATTR not #defined
					#endif
				],[
					AC_MSG_RESULT([yes])
				],[
					AC_MSG_RESULT([no])
					AC_MSG_WARN([Lustre requires that extended attributes for ext3 are enabled in the kernel (CONFIG_EXT3_FS_XATTR.)])
					AC_MSG_WARN([This build may fail.])
				])
			;;
		ldiskfs)
			AC_MSG_CHECKING([if fshooks are present])
			LUSTRE_MODULE_TRY_COMPILE(
				[
					#include <linux/fshooks.h>
				],[],[
					AC_MSG_RESULT([yes])
					LDISKFS_SERIES="2.6-suse.series"
				],[
					AC_MSG_RESULT([no])
					LDISKFS_SERIES="2.6-vanilla.series"
				])
			AC_SUBST(LDISKFS_SERIES)
			# --- check which ldiskfs series we should use
			;;
	esac # $BACKINGFS
fi

AM_CONDITIONAL(BUILD_QSWNAL, test x$QSWNAL = "xqswnal")
AM_CONDITIONAL(BUILD_GMNAL, test x$GMNAL = "xgmnal")
AM_CONDITIONAL(BUILD_OPENIBNAL, test x$OPENIBNAL = "xopenibnal")
AM_CONDITIONAL(BUILD_IIBNAL, test x$IIBNAL = "xiibnal")

# portals/utils/portals.c
AC_CHECK_HEADERS([netdb.h netinet/tcp.h asm/types.h])
AC_CHECK_FUNCS([gethostbyname socket connect])

# portals/utils/debug.c
AC_CHECK_HEADERS([linux/version.h])

# include/liblustre.h
AC_CHECK_HEADERS([asm/page.h sys/user.h stdint.h])

# liblustre/llite_lib.h
AC_CHECK_HEADERS([xtio.h file.h])

# liblustre/dir.c
AC_CHECK_HEADERS([linux/types.h sys/types.h linux/unistd.h unistd.h])

# liblustre/lutil.c
AC_CHECK_HEADERS([netinet/in.h arpa/inet.h catamount/data.h])
AC_CHECK_FUNCS([inet_ntoa])

CPPFLAGS="-include \$(top_builddir)/include/config.h $CPPFLAGS"
EXTRA_KCFLAGS="-include $PWD/include/config.h $EXTRA_KCFLAGS"
AC_SUBST(EXTRA_KCFLAGS)

echo "CPPFLAGS: $CPPFLAGS"
echo "LLCPPFLAGS: $LLCPPFLAGS"
echo "CFLAGS: $CFLAGS"
echo "EXTRA_KCFLAGS: $EXTRA_KCFLAGS"
echo "LLCFLAGS: $LLCFLAGS"

ENABLE_INIT_SCRIPTS=0
if test x$enable_utils = xyes ; then
        AC_MSG_CHECKING([whether to install init scripts])
        # our scripts only work on red hat systems
        if test -f /etc/init.d/functions -a -f /etc/sysconfig/network ; then
                ENABLE_INIT_SCRIPTS=1
                AC_MSG_RESULT([yes])
        else
                AC_MSG_RESULT([no])
        fi
fi
AM_CONDITIONAL(INIT_SCRIPTS, test x$ENABLE_INIT_SCRIPTS = "x1")
AC_SUBST(ENABLE_INIT_SCRIPTS)
