
# -------- in kernel compilation? (2.5 only) -------------
AC_ARG_ENABLE(inkernel, [ --enable-inkernel set up 2.5 kernel makefiles])
AM_CONDITIONAL(INKERNEL, test x$enable_inkernel = xyes)
echo "Makefile for in kernel build: $INKERNEL"

# -------- liblustre compilation --------------
AC_ARG_WITH(lib, [  --with-lib compile lustre library], host_cpu="lib")

# -------- set linuxdir ------------

AC_ARG_WITH(linux, [  --with-linux=[path] set path to Linux source (default=/usr/src/linux)],LINUX=$with_linux,LINUX=/usr/src/linux)
AC_SUBST(LINUX)

# --------- UML?  --------------------
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
                KCPPFLAGS='-D__KERNEL__ -U__i386__ -Ui386 -DUM_FASTCALL -D__arch_um__ -DSUBARCH="i386" -DNESTING=0 -D_LARGEFILE64_SOURCE  -Derrno=kernel_errno -DPATCHLEVEL=4 -DMODULE -I$(LINUX)/arch/um/include -I$(LINUX)/arch/um/kernel/tt/include -I$(LINUX)/arch/um/kernel/skas/include -O2 -nostdinc -iwithprefix include -DKBUILD_BASENAME=$(MODULE) -DKBUILD_MODNAME=$(MODULE) '
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
        KCFLAGS='-gstabs -O2 -Wall -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -pipe -ffixed-r13 -mfixed-range=f10-f15,f32-f127 -falign-functions=32 -mb-step'
	KCPPFLAGS='-D__KERNEL__ -DMODULE'
        MOD_LINK=elf64_ia64
;;

	sparc64 )
	AC_MSG_RESULT($host_cpu)
        KCFLAGS='-O2 -Wall -Wstrict-prototypes -Wno-trigraphs -fomit-frame-pointer -fno-strict-aliasing -fno-common -Wno-unused -m64 -pipe -mno-fpu -mcpu=ultrasparc -mcmodel=medlow -ffixed-g4 -fcall-used-g5 -fcall-used-g7 -Wno-sign-compare -Wa,--undeclared-regs'
        KCPPFLAGS='-D__KERNEL__'
        MOD_LINK=elf64_sparc

;;

	powerpc )
	AC_MSG_RESULT($host_cpu)
        KCFLAGS='-O2 -Wall -Wstrict-prototypes -Wno-trigraphs -fomit-frame-pointer -fno-strict-aliasing -fno-common -D__powerpc__ -fsigned-char -msoft-float -pipe -ffixed-r2 -Wno-uninitialized -mmultiple -mstring'
        KCPPFLAGS='-D__KERNEL__'
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

if test $host_cpu != "lib" ; then 
    KINCFLAGS='-I$(top_srcdir)/include -I$(top_srcdir)/portals/include -I$(LINUX)/include'
else
    KINCFLAGS='-I$(top_srcdir)/include -I$(top_srcdir)/portals/include'
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

# ------------ RELEASE and moduledir ------------------
  AC_MSG_CHECKING(for Linux release)
  
  dnl We need to rid ourselves of the nasty [ ] quotes.
  changequote(, )
  dnl Get release from version.h
  RELEASE="`sed -ne 's/.*UTS_RELEASE[ \"]*\([0-9.a-zA-Z_-]*\).*/\1/p' $LINUX/include/linux/version.h`"
  changequote([, ])
  
  moduledir='$(libdir)/modules/'$RELEASE/kernel
  AC_SUBST(moduledir)
  
  modulefsdir='$(moduledir)/fs/$(PACKAGE)'
  AC_SUBST(modulefsdir)
  
  AC_MSG_RESULT($RELEASE)
  AC_SUBST(RELEASE)

# ---------- modversions? --------------------
  AC_MSG_CHECKING(for MODVERSIONS)
  if egrep -e 'MODVERSIONS.*1' $LINUX/include/linux/autoconf.h >/dev/null 2>&1;
  then
        MFLAGS="-DMODULE -DMODVERSIONS -include $LINUX/include/linux/modversions.h -DEXPORT_SYMTAB"
        AC_MSG_RESULT(yes)
  else
        MFLAGS=
        AC_MSG_RESULT(no)
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
if test "$target_cpu" != ia64 ; then
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

AC_ARG_ENABLE(zerocopy, [  --enable-zerocopy enable socknal zerocopy],enable_zerocopy="-DSOCKNAL_ZC=1", enable_zercopy=$enable_zerocopy_temp)

AC_ARG_ENABLE(affinity, [  --enable-affinity enable process/irq affinity],enable_affinity="-DCPU_AFFINITY=1", enable_affinity=$enable_affinity_temp)
#####################################

AC_MSG_CHECKING(if quadrics kernel headers are present)
if test -d $LINUX/drivers/net/qsnet ; then
  AC_MSG_RESULT(yes)
  QSWNAL="qswnal"
  with_quadrics="-I$LINUX/drivers/net/qsnet/include"
  :
elif test -d $LINUX/drivers/qsnet1 ; then
  AC_MSG_RESULT(yes)
  QSWNAL="qswnal"
  with_quadrics="-I$LINUX/drivers/qsnet1/include -DPROPRIETARY_ELAN"
  :
elif test -d $LINUX/drivers/quadrics ; then
  AC_MSG_RESULT(yes)
  QSWNAL="qswnal"
  with_quadrics="-I$LINUX/drivers/quadrics/include -DPROPRIETARY_ELAN"
  :
#elif test -d /usr/include/elan3 ; then
#  AC_MSG_RESULT(yes)
#  QSWNAL="qswnal"
#  with_quadrics=""
#  :
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
    with_gm=-I"$with_gm/include"
  fi
  GMNAL="gmnal"
else
# default case - no GM
  with_gm=""
fi
AC_SUBST(with_gm)
AC_SUBST(GMNAL)


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
CPPFLAGS="$KINCFLAGS $KCPPFLAGS $MFLAGS $enable_zerocopy $enable_affinity $with_quadrics $with_gm $with_scamac "

AC_SUBST(MOD_LINK)
AC_SUBST(LINUX25)
AM_CONDITIONAL(LIBLUSTRE, test x$host_cpu = xlib)


