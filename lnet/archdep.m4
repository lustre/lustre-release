# -------- we can't build modules unless srcdir = builddir
if test x$enable_modules != xno ; then
AC_CHECK_FILE([Makefile.am],[],
	[AC_ERROR([At this time, Lustre does not support building kernel modules with srcdir != buildir.])])
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
AC_MSG_CHECKING([if Cray portals should be used])
AC_ARG_WITH([cray-portals],
	AC_HELP_STRING([--with-cray-portals=path],
		       [path to cray portals]),
	[
		CRAY_PORTALS_INCLUDE="-I$with_cray_portals"
		AC_DEFINE(CRAY_PORTALS, 1, [Building with Cray Portals])
	],[with_cray_portals=no])
AC_MSG_RESULT([$with_cray_portals])
AM_CONDITIONAL(CRAY_PORTALS, test x$with_cray_portals != xno)
if test x$enable_tests = xno ; then
	AC_MSG_NOTICE([disabling tests])
	enable_tests=no
fi
if test x$enable_utils = xno ; then
	AC_MSG_NOTICE([disabling utilities])
	enable_utils=no
fi

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

#  --------------------
ARCH_UM=
UML_CFLAGS=
if test x$enable_modules != xno ; then
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
fi
AC_SUBST(ARCH_UM)
AC_SUBST(UML_CFLAGS)
# --------- Linux 25 ------------------

AC_MSG_CHECKING([if you are running linux 2.5])
if test -e $LINUX/include/linux/namei.h ; then
        linux25="yes"
	KMODEXT=".ko"
else
	KMODEXT=".o"
        linux25="no"
fi
AC_MSG_RESULT([$linux25])
AM_CONDITIONAL(LINUX25, test x$linux25 = xyes)
AC_SUBST(KMODEXT)

# -------  Makeflags ------------------

CPPFLAGS="$CRAY_PORTALS_INCLUDE $CRAY_PORTALS_COMMANDLINE -I\$(top_srcdir)/include -I\$(top_srcdir)/portals/include"

# liblustre are all the same
LLCPPFLAGS="-D__arch_lib__ -D_LARGEFILE64_SOURCE=1"
AC_SUBST(LLCPPFLAGS)

LLCFLAGS="-g -Wall -fPIC"
AC_SUBST(LLCFLAGS)

# everyone builds against portals and lustre

if test x$enable_ldiskfs = xyes ; then
	AC_DEFINE(CONFIG_LDISKFS_FS_MODULE, 1, [build ldiskfs as a module])
	AC_DEFINE(CONFIG_LDISKFS_FS_XATTR, 1, [enable extended attributes for ldiskfs])
	AC_DEFINE(CONFIG_LDISKFS_POSIX_ACL, 1, [enable posix acls])
	AC_DEFINE(CONFIG_LDISKFS_FS_SECURITY, 1, [enable fs security])
fi

EXTRA_KCFLAGS="-g -I$PWD/portals/include -I$PWD/include $CRAY_PORTALS_INCLUDE $CRAY_PORTALS_COMMANDLINE"

# ----------- make dep run? ------------------

if test x$enable_modules != xno ; then
	AC_MSG_CHECKING([if make dep has been run in kernel source (host $host_cpu)])
	if test -f $LINUX/include/linux/config.h ; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		AC_MSG_ERROR([** cannot find $LINUX/include/linux/config.h. Run make dep in $LINUX.])
	fi
fi

# ------------ include paths ------------------

if test x$enable_modules != xno ; then
	# ------------ autoconf.h ------------------
	AC_MSG_CHECKING([if autoconf.h is in kernel source])
	if test -f $LINUX/include/linux/autoconf.h ; then
		AC_MSG_RESULT(yes)
	else
		AC_MSG_RESULT(no)
		AC_MSG_ERROR([** cannot find $LINUX/include/linux/autoconf.h. Run make config in $LINUX.])
	fi

	# ------------ LINUXRELEASE and moduledir ------------------
	AC_MSG_CHECKING([for Linux release])

	# this is bogus, as it doesn't work against kernel-source rpms  
	dnl We need to rid ourselves of the nasty [ ] quotes.
	changequote(, )
	dnl Get release from version.h
	LINUXRELEASE="`sed -ne 's/.*UTS_RELEASE[ \"]*\([0-9.a-zA-Z_-]*\).*/\1/p' $LINUX/include/linux/version.h`"
	changequote([, ])

	moduledir='$(libdir)/modules/'$LINUXRELEASE/kernel
	AC_SUBST(moduledir)

	modulefsdir='$(moduledir)/fs/$(PACKAGE)'
	AC_SUBST(modulefsdir)

	AC_MSG_RESULT($LINUXRELEASE)
	AC_SUBST(LINUXRELEASE)

	# ------------ RELEASE --------------------------------
	AC_MSG_CHECKING([lustre release])
  
	dnl We need to rid ourselves of the nasty [ ] quotes.
	changequote(, )
	dnl Get release from version.h
	RELEASE="`sed -ne 's/-/_/g' -e 's/.*UTS_RELEASE[ \"]*\([0-9.a-zA-Z_]*\).*/\1/p' $LINUX/include/linux/version.h`_`date +%Y%m%d%H%M`"
	changequote([, ])

	AC_MSG_RESULT($RELEASE)
	AC_SUBST(RELEASE)
fi

# ---------- Portals flags --------------------

#AC_PREFIX_DEFAULT([])
#if test "x$prefix" = xNONE || test "x$prefix" = x; then
#  usrprefix=/usr
#else
#  usrprefix='${prefix}'
#fi
#AC_SUBST(usrprefix)

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

AC_MSG_CHECKING([for CPU affinity support])
AC_ARG_ENABLE([affinity],
	AC_HELP_STRING([--disable-affinity],
		       [disable process/irq affinity]),
	[],[enable_affinity='yes'])
if test x$enable_affinity = xno ; then
	AC_MSG_RESULT([no (by request)])
else
	SET_CPUS_ALLOW="`grep -c set_cpus_allowed $LINUX/kernel/softirq.c`"
	if test "$SET_CPUS_ALLOW" != 0 ; then
		AC_DEFINE(CPU_AFFINITY, 1, [kernel has cpu affinity support])
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no (no kernel support)])
	fi
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
		QSWCPPFLAGS="-I$LINUX/drivers/net/qsnet/include"
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


#fixme: where are the default IB includes?
default_ib_include_dir=/usr/local/ib/include
an_ib_include_file=vapi.h

AC_MSG_CHECKING([if ib nal support was requested])
AC_ARG_WITH([ib],
	AC_HELP_STRING([--with-ib=yes/no/path],
		       [Path to IB includes]),
	[
		case $with_ib in
			yes)
				AC_MSG_RESULT([yes])
				IBCPPFLAGS="-I/usr/local/ib/include"
				IBNAL="ibnal"
				;;
			no)
				AC_MSG_RESULT([no])
				IBCPPFLAGS=""
				IBNAL=""
				;;
			*)
				AC_MSG_RESULT([yes])
				IBCPPFLAGS="-I$with_ib"
				IBNAL=""
				;;
		esac
	],[
		AC_MSG_RESULT([no])
		IBFLAGS=""
		IBNAL=""
	])
AC_SUBST(IBNAL)
AC_SUBST(IBCPPFLAGS)


def_scamac=/opt/scali/include
AC_MSG_CHECKING([if ScaMAC support was requested])
AC_ARG_WITH([scamac],
	AC_HELP_STRING([--with-scamac=yes/no/path],
		       [Path to ScaMAC includes (default=/opt/scali/include)]),
	[
		case $with_scamac in
			yes)
				AC_MSG_RESULT([yes])
				SCIMACCPPFLAGS="-I/opt/scali/include"
				SCIMACNAL="scimacnal"
				;;
			no)
				AC_MSG_RESULT([no])
				SCIMACCPPFLAGS=""
				SCIMACNAL=""
				;;
			*)
				AC_MSG_RESULT([yes])
				SCIMACCPPFLAGS="-I$with_scamac -I$with_scamac/icm"
				SCIMACNAL="scimacnal"
				;;
		esac
	],[
		AC_MSG_RESULT([no])
		SCIMACCPPFLAGS=""
		SCIMACNAL=""
	])
AC_SUBST(SCIMACCPPFLAGS)
AC_SUBST(SCIMACNAL)
# if test "$with_scamac" != no -a -f ${with_scamac}/scamac.h; then

AC_SUBST(MOD_LINK)
AC_SUBST(LINUX25)

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
AS_IF([_AC_EVAL_STDERR([cp conftest.c kernel-tests && make modules -C $LINUX $ARCH_UM SUBDIRS=$PWD/kernel-tests >/dev/null]) &&
	AC_TRY_COMMAND([test -s kernel-tests/conftest.o])],
	[$2],
	[_AC_MSG_LOG_CONFTEST
m4_ifvaln([$3],[$3])dnl])dnl
rm -f kernel-tests/conftest.o kernel-tests/conftest.mod.c kernel-tests/conftest.mod.o kernel-tests/conftest.ko m4_ifval([$1], [kernel-tests/conftest.c conftest.c])[]dnl
])

AC_DEFUN([LUSTRE_MODULE_TRY_COMPILE],
[LUSTRE_MODULE_COMPILE_IFELSE([AC_LANG_PROGRAM([[$1]], [[$2]])], [$3], [$4])])

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

AC_MSG_CHECKING([for kernel version])
LUSTRE_MODULE_TRY_COMPILE(
	[
		#include <linux/sched.h>
	],[
		struct task_struct p;
		p.sighand = NULL;
	],[
		AC_DEFINE(CONFIG_RH_2_4_20, 1, [this kernel contains Red Hat 2.4.20 patches])
		AC_MSG_RESULT([redhat-2.4.20])
	],[
		AC_MSG_RESULT([$LINUXRELEASE])
	])

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

if test x$enable_modules != xno ; then
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

	if test $BACKINGFS = 'ext3' ; then
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
	fi # BACKINGFS = ext3
fi

CPPFLAGS="-include \$(top_builddir)/include/config.h $CPPFLAGS"
EXTRA_KCFLAGS="-include $PWD/include/config.h $EXTRA_KCFLAGS"
AC_SUBST(EXTRA_KCFLAGS)

#echo "KCPPFLAGS: $KCPPFLAGS"
#echo "KCFLAGS: $KCFLAGS"
#echo "LLCPPFLAGS: $LLCPPFLAGS"
#echo "LLCFLAGS: $LLCFLAGS"
#echo "MOD_LINK: $MOD_LINK"
#echo "CFLAGS: $CFLAGS"
#echo "CPPFLAGS: $CPPFLAGS"
