#
# LB_DARWIN_CONDITIONALS
#
# AM_CONDITIONALs for darwin
#
AC_DEFUN([LB_DARWIN_CONDITIONALS],
[
])

#
# LB_PROG_DARWIN
#
# darwin tests
#
AC_DEFUN([LB_PROG_DARWIN],
[kernel_framework="/System/Library/Frameworks/Kernel.framework"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -x c -arch ppc -pipe -Wno-trigraphs"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -fasm-blocks -g -O0 -mtune=G4"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -Wno-four-char-constants -Wmost -O0"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -fmessage-length=0 -ffix-and-continue"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -I$kernel_framework/Headers"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -I$kernel_framework/Headers/bsd"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -I$kernel_framework/PrivateHeaders"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -fno-common -nostdinc -fno-builtin"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -finline -fno-keep-inline-functions"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -force_cpusubtype_ALL -fno-exceptions"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -msoft-float -static -mlong-branch"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -DKERNEL -DKERNEL_PRIVATE"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -DDRIVER_PRIVATE -DAPPLE -DNeXT"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -D__KERNEL__ -D__DARWIN__"
EXTRA_KLDFLAGS="-arch ppc -static -nostdlib -r"
EXTRA_KLIBS="-lkmodc++ -lkmod -lcc_kext"
KMODEXT=""
])
