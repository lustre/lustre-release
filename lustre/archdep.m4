AC_ARG_WITH(lib, [  --with-lib compile lustre library], host_cpu="lib")

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

AC_MSG_CHECKING(setting make flags system architecture: )
case ${host_cpu} in
	lib )
	AC_MSG_RESULT($host_cpu)
	KCFLAGS='-g -Wall '
	KCPPFLAGS='-D__arch_lib__ '
        MOD_LINK=elf_i386
;;
	um )
	AC_MSG_RESULT($host_cpu)
	KCFLAGS='-g -Wall -pipe -Wno-trigraphs -Wstrict-prototypes -fno-strict-aliasing -fno-common '
        case ${linux25} in
                yes )
                KCPPFLAGS='-D__KERNEL__ -U__i386__ -Ui386 -DUM_FASTCALL -D__arch_um__ -DSUBARCH="i386" -DNESTING=0 -D_LARGEFILE64_SOURCE  -Derrno=kernel_errno -DPATCHLEVEL=4 -DMODULE -I$(LINUX)/arch/um/include -I$(LINUX)/arch/um/kernel/tt/include -O2 -nostdinc -iwithprefix include -DKBUILD_BASENAME=$(MODULE) -DKBUILD_MODNAME=$(MODULE) '
        ;;
                * )
		KCPPFLAGS='-D__KERNEL__ -U__i386__ -Ui386 -DUM_FASTCALL -D__arch_um__ -DSUBARCH="i386" -DNESTING=0 -D_LARGEFILE64_SOURCE  -Derrno=kernel_errno -DPATCHLEVEL=4 -DMODULE -I$(LINUX)/arch/um/include '
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

if test $host_cpu != lib ; then 
AC_MSG_CHECKING(for MODVERSIONS)
if egrep -e 'MODVERSIONS.*1' $LINUX/include/linux/autoconf.h >/dev/null 2>&1;
then
	MFLAGS="-DMODULE -DMODVERSIONS -include $LINUX/include/linux/modversions.h -DEXPORT_SYMTAB"
	AC_MSG_RESULT(yes)
else
	MFLAGS=
	AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING(for SMP)
if egrep -e SMP=y $LINUX/.config >/dev/null 2>&1; then
	SMPFLAG=
	AC_MSG_RESULT(yes)
else
	SMPFLAG=
	AC_MSG_RESULT(no)
fi
fi

CFLAGS="$KCFLAGS $MFLAGS"
ARCHCPPFLAGS="$KCPPFLAGS"
