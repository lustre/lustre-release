
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
	AM_CONDITIONAL(LIBLUSTRE, test x$host_cpu = xlib)
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

# ---------- SMP -------------------
#AC_MSG_CHECKING(for SMP)
#if egrep -e SMP=y $LINUX/.config >/dev/null 2>&1; then
#        SMPFLAG=
#        AC_MSG_RESULT(yes)
#else
#        SMPFLAG=
#        AC_MSG_RESULT(no)
#fi

CFLAGS="$KCFLAGS"
CPPFLAGS="$KINCFLAGS $KCPPFLAGS $MFLAGS "

AC_SUBST(MOD_LINK)
AC_SUBST(LINUX25)
