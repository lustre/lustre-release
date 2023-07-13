# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# config/lustre-toolchain.m4
#
# Configure the global compiler flags and toolchain settings
#

#
# LTC_LLVM_TOOLCHAIN
#
# Read LLVM and LLVM_IAS env variables and set CC and friends
# based on their values
#
AC_DEFUN([LTC_LLVM_TOOLCHAIN], [
AC_ARG_VAR(LLVM, "Enable LLVM toolchain")
AC_ARG_VAR(LLVM_IAS, "Disable LLVM integrated assembler")

if [[ -n "$LLVM" ]]; then

if [[ -z "${LLVM##*/*}" ]]; then
LLVM_PREFIX="$LLVM"
fi

if [[ -z "${LLVM##*-*}" ]]; then
LLVM_SUFFIX="$LLVM"
fi

HOSTCC="$LLVM_PREFIX"clang"$LLVM_SUFFIX"
HOSTCXX="$LLVM_PREFIX"clang++"$LLVM_SUFFIX"
CC="$LLVM_PREFIX"clang"$LLVM_SUFFIX"
CXX="$LLVM_PREFIX"clang++"$LLVM_SUFFIX"
LD="$LLVM_PREFIX"ld.lld"$LLVM_SUFFIX"
AR="$LLVM_PREFIX"llvm-ar"$LLVM_SUFFIX"
NM="$LLVM_PREFIX"llvm-nm"$LLVM_SUFFIX"
OBJCOPY="$LLVM_PREFIX"llvm-objcopy"$LLVM_SUFFIX"
OBJDUMP="$LLVM_PREFIX"llvm-objdump"$LLVM_SUFFIX"
READELF="$LLVM_PREFIX"llvm-readelf"$LLVM_SUFFIX"
STRIP="$LLVM_PREFIX"llvm-strip"$LLVM_SUFFIX"

if [[ "$LLVM_IAS" == "0" ]]; then
CC="$CC -fno-integrated-as"
fi

fi
]) # LTC_LLVM_TOOLCHAIN

#
# LTC_CONFIG_ERROR
#
# Simple flag to make compiler flags very lax, for
# development purposes
#
AC_DEFUN([LTC_CONFIG_ERROR], [
AC_ARG_ENABLE([strict-errors],
    AS_HELP_STRING([--disable-strict-errors], [Disable strict error C flags]))

AS_IF([test "x$enable_strict_errors" != "xno"], [
AS_IF([test $target_cpu == "i686" -o $target_cpu == "x86_64"], [
CFLAGS="$CFLAGS -Wall -Werror"
])
], [
CFLAGS="$CFLAGS -Wall -Wno-error -Wno-error=incompatible-function-pointer-types -Wno-error=incompatible-pointer-types"
])
]) # LTC_CONFIG_ERROR

#
# LTC_PROG_CC
#
# checks on the C compiler
#
AC_DEFUN([LTC_PROG_CC], [
AC_PROG_RANLIB
AC_CHECK_TOOL(LD, [ld], [no])
AC_CHECK_TOOL(OBJDUMP, [objdump], [no])
AC_CHECK_TOOL(STRIP, [strip], [no])

# ---------  unsigned long long sane? -------
AC_CHECK_SIZEOF(unsigned long long, 0)
AS_IF([test $ac_cv_sizeof_unsigned_long_long != 8],
	[AC_MSG_ERROR([we assume that sizeof(unsigned long long) == 8.])])

AS_IF([test $target_cpu = powerpc64], [
	AC_MSG_WARN([set compiler with -m64])
	CFLAGS="$CFLAGS -m64"
	CC="$CC -m64"
])

# libcfs/include for util headers, lustre/include for liblustreapi and friends
# UAPI headers from OpenSFS are included if modules support is enabled, otherwise
# it will use the native kernel implementation.
CPPFLAGS="-I$PWD/libcfs/include -I$PWD/lnet/utils/ -I$PWD/lustre/include $CPPFLAGS"

CCASFLAGS="-Wall -fPIC -D_GNU_SOURCE"
AC_SUBST(CCASFLAGS)

# everyone builds against lnet and lustre kernel headers
EXTRA_KCFLAGS="$EXTRA_KCFLAGS -g -I$PWD/libcfs/include -I$PWD/libcfs/include/libcfs -I$PWD/lnet/include/uapi -I$PWD/lnet/include -I$PWD/lustre/include/uapi -I$PWD/lustre/include"
AC_SUBST(EXTRA_KCFLAGS)
]) # LTC_PROG_CC

#
# LTC_CC_NO_FORMAT_TRUNCATION
#
# Check if gcc supports -Wno-format-truncation
# To supress many warnings with gcc7
#
AC_DEFUN([LTC_CC_NO_FORMAT_TRUNCATION], [
	AC_MSG_CHECKING([for -Wno-format-truncation support])

	saved_flags="$CFLAGS"
	CFLAGS="-Werror -Wno-format-truncation"

	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])], [
		EXTRA_KCFLAGS="$EXTRA_KCFLAGS -Wno-format-truncation"
		AC_SUBST(EXTRA_KCFLAGS)
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
	])

	CFLAGS="$saved_flags"
]) # LTC_CC_NO_FORMAT_TRUNCATION

#
# LTC_CC_NO_STRINGOP_TRUNCATION
#
# Check if gcc supports -Wno-stringop-truncation
# To supress many warnings with gcc8
#
AC_DEFUN([LTC_CC_NO_STRINGOP_TRUNCATION], [
	AC_MSG_CHECKING([for -Wno-stringop-truncation support])

	saved_flags="$CFLAGS"
	CFLAGS="-Werror -Wno-stringop-truncation"

	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])], [
		EXTRA_KCFLAGS="$EXTRA_KCFLAGS -Wno-stringop-truncation"
		AC_SUBST(EXTRA_KCFLAGS)
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
	])

	CFLAGS="$saved_flags"
]) # LTC_CC_NO_STRINGOP_TRUNCATION

#
# LTC_CC_NO_STRINGOP_OVERFLOW
#
# Check if gcc supports -Wno-stringop-overflow
# To supress many warnings with gcc8
#
AC_DEFUN([LTC_CC_NO_STRINGOP_OVERFLOW], [
	AC_MSG_CHECKING([for -Wno-stringop-overflow support])

	saved_flags="$CFLAGS"
	CFLAGS="-Werror -Wno-stringop-overflow"

	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])], [
		EXTRA_KCFLAGS="$EXTRA_KCFLAGS -Wno-stringop-overflow"
		AC_SUBST(EXTRA_KCFLAGS)
		TEST_RESULT="yes"
		AC_MSG_RESULT([yes])
	], [
		AC_MSG_RESULT([no])
	])

	CFLAGS="$saved_flags"
	AM_CONDITIONAL(NO_STRINGOP_OVERFLOW, test x$TEST_RESULT = xyes)
]) # LTC_CC_NO_STRINGOP_OVERFLOW

#
# LTC_TOOLCHAIN_CONFIGURE
#
# main configure steps
#
AC_DEFUN([LTC_TOOLCHAIN_CONFIGURE], [
AC_REQUIRE([LTC_LLVM_TOOLCHAIN])
AC_REQUIRE([AC_PROG_CC])
AC_REQUIRE([AC_PROG_CXX])

AM_PROG_AS
AC_CHECK_TOOLS(AR, ar)
LTC_PROG_CC

LTC_CONFIG_ERROR

LTC_CC_NO_FORMAT_TRUNCATION
LTC_CC_NO_STRINGOP_TRUNCATION
LTC_CC_NO_STRINGOP_OVERFLOW

if test $ac_test_CFLAGS; then
	CFLAGS=$ac_save_CFLAGS
fi

CFLAGS="$CFLAGS $EXTRA_CFLAGS"
]) # LTC_TOOLCHAIN_CONFIGURE

#
# LTC_TOOLCHAIN_STATUS
#
# main configure steps
#
AC_DEFUN([LTC_TOOLCHAIN_STATUS], [
cat <<_ACEOF

CC:            $CC
CFLAGS:        $CFLAGS
EXTRA_CFLAGS:  $EXTRA_CFLAGS

EXTRA_KCFLAGS: $EXTRA_KCFLAGS

LD:            $LD

CXX:           $CXX
CPPFLAGS:      $CPPFLAGS

Type 'make' to build Lustre.
_ACEOF
]) # LTC_TOOLCHAIN_STATUS
