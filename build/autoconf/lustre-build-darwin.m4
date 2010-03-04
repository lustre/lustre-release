#
# LB_DARWIN_CHECK_FUNCS
#
# check for functions in the darwin kernel
# Note that this is broken for cross compiling
#
AC_DEFUN([LB_DARWIN_CHECK_FUNCS],
[AC_FOREACH([AC_Func], [$1],
  [AH_TEMPLATE(AS_TR_CPP(HAVE_[]AC_Func),
               [Define to 1 if you have the `]AC_Func[' function.])])dnl
for ac_func in $1
do
AC_MSG_CHECKING([for $1])
AS_IF([AC_TRY_COMMAND(nm /mach | grep "[$1]" >/dev/null 2>/dev/null)],[
	AC_MSG_RESULT([yes])
	AC_DEFINE_UNQUOTED(AS_TR_CPP([HAVE_$ac_func])) $2
],[
	AC_MSG_RESULT([no]) $3
])
done
])

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
#
# FIXME: there should be a better way to get these than hard coding them
#
case $target_cpu in 
	powerpc*)
		EXTRA_KCFLAGS="$EXTRA_KCFLAGS -arch ppc -mtune=G4 -mlong-branch"
		EXTRA_KLDFLAGS="-arch ppc"
		;;
	i?86 | x86_64)
		EXTRA_KCFLAGS="$EXTRA_KCFLAGS -arch i386"
		EXTRA_KLDFLAGS="-arch i386"
		;;
esac

# Kernel of OS X is not 64bits(even in Tiger), but -m64 can be taken by gcc in Tiger
# (Tiger can support 64bits applications), so we have to eliminate -m64 while 
# building kextensions for and OS X.
CC=`echo $CC | sed -e "s/\-m64//g"`
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -x c -pipe -Wno-trigraphs -fasm-blocks -g -O0"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -Wno-four-char-constants -Wmost -O0"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -fmessage-length=0"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -I$kernel_framework/Headers"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -I$kernel_framework/Headers/bsd"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -I$kernel_framework/PrivateHeaders"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -fno-common -nostdinc -fno-builtin"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -finline -fno-keep-inline-functions"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -force_cpusubtype_ALL -fno-exceptions"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -msoft-float -static"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -DKERNEL -DKERNEL_PRIVATE"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -DDRIVER_PRIVATE -DAPPLE -DNeXT"
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -D__KERNEL__ -D__DARWIN__"
#
# C flags for Panther/Tiger
#
case $target_os in
        darwin8*)
                EXTRA_KCFLAGS="$EXTRA_KCFLAGS -D__DARWIN8__"
	;;
        darwin7*)
                EXTRA_KCFLAGS="$EXTRA_KCFLAGS -ffix-and-continue"
        ;;
esac

#
# Debugging flags. Remove!
#
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -O0 -DMACH_ASSERT=1"
EXTRA_KLDFLAGS="$EXTRA_KLDFLAGS -static -nostdlib -r"
EXTRA_KLIBS="-lkmodc++ -lkmod -lcc_kext"
KMODEXT=""

AC_SUBST(EXTRA_KLDFLAGS)
AC_SUBST(EXTRA_KLIBS)

kextdir='/System/Library/Extensions/$(firstword $(macos_PROGRAMS)).kext'
plistdir='$(kextdir)/Contents'
macosdir='$(plistdir)/MacOS'

AC_SUBST(kextdir)
AC_SUBST(plistdir)
AC_SUBST(macosdir)

LN_PROG_DARWIN

LP_PROG_DARWIN

LC_PROG_DARWIN
])
