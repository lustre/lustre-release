AC_MSG_CHECKING(if you are running user mode linux for $host_alias..)
if test -e $LINUX/include/asm-um ; then
if test  X`ls -id $LINUX/include/asm | awk '{print $1}'` = X`ls -id $LINUX/include/asm-um | awk '{print $1}'` ; then
	host_cpu="um";
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

else 
        AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING(setting make flags system architecture: )
case ${host_cpu} in
	um )
	AC_MSG_RESULT($host_cpu)
	KCFLAGS='-g  -Wall -pipe -Wno-trigraphs -Wstrict-prototypes -fno-strict-aliasing -fno-common '
	KCPPFLAGS='-D__KERNEL__ -U__i386__ -Ui386 -DUM_FASTCALL -D__arch_um__ -DSUBARCH="i386" -DNESTING=0 -D_LARGEFILE64_SOURCE  -Derrno=kernel_errno -DPATCHLEVEL=4 -DMODULE -I$(LINUX)/arch/um/include '
        MOD_LINK=elf_i386
;;
	i*86 )
	AC_MSG_RESULT($host_cpu)
        KCFLAGS='-g -O2 -Wall -Wstrict-prototypes -pipe'
        KCPPFLAGS='-D__KERNEL__ -DMODULE '
        MOD_LINK=elf_i386
;;

	alpha )
	AC_MSG_RESULT($host_cpu)
        KCFLAGS='-g -O2 -Wall -Wstrict-prototypes -pipe'
        KCPPFLAGS='-D__KERNEL__ -DMODULE '
        MOD_LINK=elf64_alpha
;;

	ia64 )
	AC_MSG_RESULT($host_cpu)
	KCFLAGS='-Wall -Wstrict-prototypes -Wno-trigraphs -g -O2 -fno-strict-aliasing -fno-common -pipe -ffixed-r13 -mfixed-range=f10-f15,f32-f127 -falign-functions=32 -mb-step'
        KCPPFLAGS='-D__KERNEL__ -DMODULE'
        MOD_LINK=elf64_ia64
;;

	sparc64 )
	AC_MSG_RESULT($host_cpu)
        KCFLAGS='-Wall -Wstrict-prototypes -Wno-trigraphs -O2 -fomit-frame-pointer -fno-strict-aliasing -fno-common -Wno-unused -m64 -pipe -mno-fpu -mcpu=ultrasparc -mcmodel=medlow -ffixed-g4 -fcall-used-g5 -fcall-used-g7 -Wno-sign-compare -Wa,--undeclared-regs'
        KCPPFLAGS='-D__KERNEL__'
        MOD_LINK=elf64_sparc

;;

        *)
	AC_ERROR("Unknown Linux Platform: $host_cpu")
esac

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

CFLAGS="$KCFLAGS $MFLAGS"
ARCHCPPFLAGS="$KCPPFLAGS"
