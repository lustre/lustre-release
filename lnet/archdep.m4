
# -------- in kernel compilation? (2.5 only) -------------
AC_ARG_ENABLE(inkernel, [  --enable-inkernel set up 2.5 kernel makefiles])
AM_CONDITIONAL(INKERNEL, test x$enable_inkernel = xyes)
echo "Makefile for in kernel build: $INKERNEL"

# -------- are we building against an external portals? -------
# haha, I wonder how one is really supposed to do this
# automake seems to have a DEFS variable which looks good
AC_ARG_WITH(cray-portals, [  --with-cray-portals=[path] path to cray portals],
	CRAY_PORTALS_INCLUDE="-I$with_cray_portals"
	CC="$CC -DCRAY_PORTALS=1"
	)
AC_SUBST(CRAY_PORTALS_INCLUDE)
AM_CONDITIONAL(CRAY_PORTALS, test ! "x$with_cray_portals" = x)

# -------- liblustre compilation --------------
AC_ARG_WITH(lib, [  --with-lib compile lustre library], host_cpu="lib")

# -------- set linuxdir ------------

AC_ARG_WITH(linux, [  --with-linux=[path] set path to Linux source (default=/usr/src/linux)],LINUX=$with_linux,LINUX=/usr/src/linux)
AC_SUBST(LINUX)
if test x$enable_inkernel = xyes ; then
        echo ln -s `pwd` $LINUX/fs/lustre
        rm $LINUX/fs/lustre
        ln -s `pwd` $LINUX/fs/lustre
fi

#  --------------------
AC_MSG_CHECKING(if you are running user mode linux for $host_cpu ...)
if test $host_cpu = "lib" ; then 
        host_cpu="lib"
	AC_MSG_RESULT(no building Lustre library)
else
  if test -e $LINUX/include/asm-um ; then
    if test  X`ls -id $LINUX/include/asm/ | awk '{print $1}'` = X`ls -id $LINUX/include/asm-um | awk '{print $1}'` ; then
	host_cpu="um";
	AC_MSG_RESULT(yes)
    else
	AC_MSG_RESULT(no (asm doesn't point at asm-um))
    fi

  else 
        AC_MSG_RESULT(no (asm-um missing))
  fi
fi

# --------- Linux 25 ------------------

AC_MSG_CHECKING(if you are running linux 2.5)
if test -e $LINUX/include/linux/namei.h ; then
        linux25="yes"
        AC_MSG_RESULT(yes)
else
        linux25="no"
        AC_MSG_RESULT(no)
fi
AM_CONDITIONAL(LINUX25, test x$linux25 = xyes)
echo "Makefiles for in linux 2.5 build: $LINUX25"

# -------  Makeflags ------------------

AC_MSG_CHECKING(setting make flags system architecture: )
case ${host_cpu} in
	lib )
	AC_MSG_RESULT($host_cpu)
	KCFLAGS='-g -Wall '
	KCPPFLAGS='-D__arch_lib__ '
   	libdir='${exec_prefix}/lib/lustre'
        MOD_LINK=elf_i386
;;
	um )
	AC_MSG_RESULT($host_cpu)
	KCFLAGS='-g -Wall -pipe -Wno-trigraphs -Wstrict-prototypes -fno-strict-aliasing -fno-common '
        case ${linux25} in
                yes )
                KCPPFLAGS='-D__KERNEL__ -U__i386__ -Ui386 -DUM_FASTCALL -D__arch_um__ -DSUBARCH="i386" -DNESTING=0 -D_LARGEFILE64_SOURCE  -Derrno=kernel_errno -DPATCHLEVEL=4 -DMODULE -I$(LINUX)/arch/um/include -I$(LINUX)/arch/um/kernel/tt/include -I$(LINUX)/arch/um/kernel/skas/include -O2 -nostdinc -iwithprefix include'
        ;;
                * )
                KCPPFLAGS='-D__KERNEL__ -U__i386__ -Ui386 -DUM_FASTCALL -D__arch_um__ -DSUBARCH="i386" -DNESTING=0 -D_LARGEFILE64_SOURCE  -Derrno=kernel_errno -DPATCHLEVEL=4 -DMODULE -I$(LINUX)/arch/um/kernel/tt/include -I$(LINUX)/arch/um/include '
        ;;
        esac

        MOD_LINK=elf_i386
;;
	i*86 )
	AC_MSG_RESULT($host_cpu)
        KCFLAGS='-g -O2 -Wall -Wstrict-prototypes -pipe'
        case ${linux25} in
                yes )
                KCPPFLAGS='-D__KERNEL__ -DMODULE -march=i686 -I$(LINUX)/include/asm-i386/mach-default -nostdinc -iwithprefix include '
        ;;
                * )
                KCPPFLAGS='-D__KERNEL__ -DMODULE '
        ;;
        esac
        MOD_LINK=elf_i386
;;

	alphaev6 )
	AC_MSG_RESULT($host_cpu)
        KCFLAGS='-g -O2  -Wall -Wstrict-prototypes -Wno-trigraphs -fomit-frame-pointer -fno-strict-aliasing -fno-common -pipe -mno-fp-regs -ffixed-8 -mcpu=ev5 -Wa,-mev6'
        KCPPFLAGS='-D__KERNEL__ -DMODULE '
        MOD_LINK=elf64alpha
;;

	alphaev67 )
	AC_MSG_RESULT($host_cpu)
        KCFLAGS='-g -O2  -Wall -Wstrict-prototypes -Wno-trigraphs -fomit-frame-pointer -fno-strict-aliasing -fno-common -pipe -mno-fp-regs -ffixed-8 -mcpu=ev5 -Wa,-mev6'
        KCPPFLAGS='-D__KERNEL__ -DMODULE '
        MOD_LINK=elf64alpha
;;

	alpha* )
	AC_MSG_RESULT($host_cpu)
        KCFLAGS='-g -O2  -Wall -Wstrict-prototypes -Wno-trigraphs -fomit-frame-pointer -fno-strict-aliasing -fno-common -pipe -mno-fp-regs -ffixed-8 -mcpu=ev5 -Wa,-mev5'
        KCPPFLAGS='-D__KERNEL__ -DMODULE '
        MOD_LINK=elf64alpha
;;

	ia64 )
	AC_MSG_RESULT($host_cpu)
        KCFLAGS='-g -O2 -Wall -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -pipe -ffixed-r13 -mfixed-range=f10-f15,f32-f127 -falign-functions=32 -mb-step'
	KCPPFLAGS='-D__KERNEL__ -DMODULE'
        MOD_LINK=elf64_ia64
;;

	x86_64 )
	AC_MSG_RESULT($host_cpu)
        KCFLAGS='-g -O2 -Wall -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fomit-frame-pointer -mno-red-zone -mcmodel=kernel -pipe -fno-reorder-blocks -finline-limit=2000 -fno-strength-reduce -fno-asynchronous-unwind-tables'
	KCPPFLAGS='-D__KERNEL__ -DMODULE'
        MOD_LINK=elf_x86_64
;;

	sparc64 )
	AC_MSG_RESULT($host_cpu)
        KCFLAGS='-O2 -Wall -Wstrict-prototypes -Wno-trigraphs -fomit-frame-pointer -fno-strict-aliasing -fno-common -Wno-unused -m64 -pipe -mno-fpu -mcpu=ultrasparc -mcmodel=medlow -ffixed-g4 -fcall-used-g5 -fcall-used-g7 -Wno-sign-compare -Wa,--undeclared-regs'
        KCPPFLAGS='-D__KERNEL__'
        MOD_LINK=elf64_sparc

;;

	powerpc )
	AC_MSG_RESULT($host_cpu)
        KCFLAGS='-O2 -g -Wall -Wstrict-prototypes -Wno-trigraphs -fomit-frame-pointer -fno-strict-aliasing -fno-common -D__powerpc__ -fsigned-char -msoft-float -pipe -ffixed-r2 -Wno-uninitialized -mmultiple -mstring'
        KCPPFLAGS='-D__KERNEL__ -DMODULE'
        MOD_LINK=elf32ppclinux
;;

        *)
	AC_ERROR("Unknown Linux Platform: $host_cpu")
;;
esac

# ----------- make dep run? ------------------

if test $host_cpu != "lib" ; then 
  AC_MSG_CHECKING(if make dep has been run in kernel source (host $host_cpu) )
  if test -f $LINUX/include/linux/config.h ; then
  AC_MSG_RESULT(yes)
 else
  AC_MSG_ERROR(** cannot find $LINUX/include/linux/config.h. Run make dep in $LINUX.)
  fi
fi

# ------------ include paths ------------------

KINCFLAGS="$CRAY_PORTALS_INCLUDE $CRAY_PORTALS_COMMANDLINE \
	-I\$(top_srcdir)/include \
	-I\$(top_srcdir)/portals/include"
if test $host_cpu != "lib" ; then 
    KINCFLAGS="$KINCFLAGS -I$LINUX/include -I$LINUX/include"
fi
CPPFLAGS="$KINCFLAGS $ARCHCPPFLAGS"

if test $host_cpu != "lib" ; then 
# ------------ autoconf.h ------------------
  AC_MSG_CHECKING(if autoconf.h is in kernel source)
  if test -f $LINUX/include/linux/autoconf.h ; then
      AC_MSG_RESULT(yes)
  else
      AC_MSG_ERROR(** cannot find $LINUX/include/linux/autoconf.h. Run make config in $LINUX.)
  fi

# ------------ LINUXRELEASE and moduledir ------------------
  AC_MSG_CHECKING(for Linux release)
  
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
  AC_MSG_CHECKING(lustre release)
  
  dnl We need to rid ourselves of the nasty [ ] quotes.
  changequote(, )
  dnl Get release from version.h
  RELEASE="`sed -ne 's/-/_/g' -e 's/.*UTS_RELEASE[ \"]*\([0-9.a-zA-Z_]*\).*/\1/p' $LINUX/include/linux/version.h`_`date +%Y%m%d%H%M`"
  changequote([, ])

  AC_MSG_RESULT($RELEASE)
  AC_SUBST(RELEASE)

# ---------- modversions? --------------------
  AC_MSG_CHECKING(for MODVERSIONS)
  if egrep -e 'MODVERSIONS.*1' $LINUX/include/linux/autoconf.h >/dev/null 2>&1;
  then
	if test $linux25 != "yes"; then
                MFLAGS="-DMODULE -DMODVERSIONS -include $LINUX/include/linux/modversions.h -DEXPORT_SYMTAB"
                AC_MSG_RESULT(yes)
        fi
  fi
fi

# ---------- Portals flags --------------------

#AC_PREFIX_DEFAULT([])
#if test "x$prefix" = xNONE || test "x$prefix" = x; then
#  usrprefix=/usr
#else
#  usrprefix='${prefix}'
#fi
#AC_SUBST(usrprefix)

AC_MSG_CHECKING(if kernel has CPU affinity support)
SET_CPUS_ALLOW="`grep -c set_cpus_allowed $LINUX/kernel/softirq.c`"
if test "$SET_CPUS_ALLOW" != 0 ; then
  enable_affinity_temp="-DCPU_AFFINITY=1"
  AC_MSG_RESULT(yes)
else
  enable_affinity_temp=""
  AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING(if kernel has zero-copy TCP support)
ZCCD="`grep -c zccd $LINUX/include/linux/skbuff.h`"
if test "$ZCCD" != 0 ; then
  enable_zerocopy_temp="-DSOCKNAL_ZC=1"
  AC_MSG_RESULT(yes)
else
  enable_zerocopy_temp=""
  AC_MSG_RESULT(no)
fi

AC_ARG_ENABLE(zerocopy, [  --disable-zerocopy disable socknal zerocopy],enable_zerocopy="", enable_zerocopy=$enable_zerocopy_temp)

AC_ARG_ENABLE(affinity, [  --disable-affinity disable process/irq affinity],enable_affinity="", enable_affinity=$enable_affinity_temp)
#####################################

AC_MSG_CHECKING(if quadrics kernel headers are present)
if test -d $LINUX/drivers/net/qsnet ; then
  AC_MSG_RESULT(yes)
  QSWNAL="qswnal"
  AC_MSG_CHECKING(for multirail EKC)
  if test -f $LINUX/include/elan/epcomms.h; then
	AC_MSG_RESULT(supported)
	with_quadrics="-DMULTIRAIL_EKC=1"
  else
	AC_MSG_RESULT(not supported)
	with_quadrics="-I$LINUX/drivers/net/qsnet/include"
  fi
  :
else
  AC_MSG_RESULT(no)
  QSWNAL=""
  with_quadrics=""
  :
fi
AC_SUBST(with_quadrics)
AC_SUBST(QSWNAL)

# R. Read 5/02
GMNAL=""
echo "checking with-gm=" ${with_gm}
if test "${with_gm+set}" = set; then
  if test "${with_gm}" = yes; then
    with_gm="-I/usr/local/gm/include"
  else
    with_gm="-I$with_gm/include -I$with_gm/drivers -I$with_gm/drivers/linux/gm"
  fi
  GMNAL="gmnal"
else
# default case - no GM
  with_gm=""
fi
AC_SUBST(with_gm)
AC_SUBST(GMNAL)


#fixme: where are the default IB includes?
default_ib_include_dir=/usr/local/ib/include
an_ib_include_file=vapi.h

AC_ARG_WITH(ib, [  --with-ib=[yes/no/path] Path to IB includes], with_ib=$withval, with_ib=$default_ib)
AC_MSG_CHECKING(if IB headers are present)
if test "$with_ib" = yes; then
    with_ib=$default_ib_include_dir
fi
if test "$with_ib" != no -a -f ${with_ib}/${an_ib_include_file}; then
    AC_MSG_RESULT(yes)
    IBNAL="ibnal"
    with_ib="-I${with_ib}"
else
    AC_MSG_RESULT(no)
    IBNAL=""
    with_ib=""
fi
AC_SUBST(IBNAL)
AC_SUBST(with_ib)


def_scamac=/opt/scali/include
AC_ARG_WITH(scamac, [  --with-scamac=[yes/no/path] Path to ScaMAC includes (default=/opt/scali/include)], with_scamac=$withval, with_scamac=$def_scamac)
AC_MSG_CHECKING(if ScaMAC headers are present)
if test "$with_scamac" = yes; then
  with_scamac=$def_scamac
fi
if test "$with_scamac" != no -a -f ${with_scamac}/scamac.h; then
  AC_MSG_RESULT(yes)
  SCIMACNAL="scimacnal"
  with_scamac="-I${with_scamac} -I${with_scamac}/icm"
else
  AC_MSG_RESULT(no)
  SCIMACNAL=""
  with_scamac=""
fi

AC_SUBST(with_scamac)
AC_SUBST(SCIMACNAL)

CFLAGS="$KCFLAGS"
CPPFLAGS="$KINCFLAGS $KCPPFLAGS $MFLAGS $enable_zerocopy $enable_affinity $with_quadrics $with_gm $with_scamac $with_ib"

AM_CONDITIONAL(LIBLUSTRE, test x$host_cpu = xlib)
AC_SUBST(MOD_LINK)
AC_SUBST(LINUX25)
AM_CONDITIONAL(LIBLUSTRE, test x$host_cpu = xlib)

# ---------- Red Hat 2.4.18 has iobuf->dovary --------------
# But other kernels don't

AC_MSG_CHECKING([if struct kiobuf has a dovary field])
AC_TRY_COMPILE([#define __KERNEL__
		#include <linux/iobuf.h>],
	       [struct kiobuf iobuf;
		iobuf.dovary = 1;],
	       [AC_MSG_RESULT([yes])
                CPPFLAGS="$CPPFLAGS -DHAVE_KIOBUF_DOVARY"],
	       [AC_MSG_RESULT([no])])

# ---------- Red Hat 2.4.20 backports some 2.5 bits --------
# This needs to run after we've defined the KCPPFLAGS

AC_MSG_CHECKING(for kernel version)
AC_TRY_COMPILE([#define __KERNEL__
             #include <linux/sched.h>],
            [struct task_struct p;
             p.sighand = NULL;],
            [RH_2_4_20=1],
            [RH_2_4_20=0])

if test $RH_2_4_20 = 1; then
	AC_MSG_RESULT(redhat-2.4.20)
	CPPFLAGS="$CPPFLAGS -DCONFIG_RH_2_4_20"
else
	AC_MSG_RESULT($LINUXRELEASE)
fi 

# ---------- Red Hat 2.4.21 backports some more 2.5 bits --------

AC_MSG_CHECKING(if kernel defines PDE)
HAVE_PDE="`grep -c 'proc_dir_entry..PDE' $LINUX/include/linux/proc_fs.h`"
if test "$HAVE_PDE" != 0 ; then
  CPPFLAGS="$CPPFLAGS -DHAVE_PDE"
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING(if kernel passes struct file to direct_IO)
HAVE_DIO_FILE="`grep -c 'direct_IO.*struct file' $LINUX/include/linux/fs.h`"
if test "$HAVE_DIO_FILE" != 0 ; then
  CPPFLAGS="$CPPFLAGS -DHAVE_DIO_FILE"
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi

# --- Check that ext3 and ext3 xattr are enabled in the kernel
if test "$host_cpu" != "lib" ; then 
	AC_MSG_CHECKING([that ext3 is enabled in the kernel])
	AC_TRY_COMPILE([
#define __KERNEL__
#include <linux/config.h>
		],
		[
#ifdef CONFIG_EXT3_FS
	return 0;
#else
#error CONFIG_EXT3_FS not #defined
#endif
		],[AC_MSG_RESULT([yes])],
		[AC_MSG_RESULT([no])
		AC_MSG_ERROR([Lustre requires that ext3 is enabled in the kernel (CONFIG_EXT3_FS)])
		])
# disable this check until our xattr patches define it!
#	AC_MSG_CHECKING([that extended attributes for ext3 are enabled in the kernel])
#	AC_TRY_COMPILE([
##define __KERNEL__
##include <linux/config.h>
#		],
#		[
##ifdef CONFIG_EXT3_FS_XATTR
#	return 0;
##else
##error CONFIG_EXT3_FS_XATTR not #defined
##endif
#		],[AC_MSG_RESULT([yes])],
#		[AC_MSG_RESULT([no])
#		AC_MSG_ERROR([Lustre requires that extended attributes for ext3 are enabled in the kernel (CONFIG_EXT3_FS_XATTR)])
#		])
fi

