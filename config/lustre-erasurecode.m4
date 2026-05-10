dnl Use plain C version of ISA-L erasure code
AC_DEFUN([EC_ISA_L_SUPPORT],[
  isa_l_library="../../erasurecode/libec.a"

  AC_SUBST([ISA_L_LIBRARY], $isa_l_library)
])

#
# EC_GFNI_SUPPORT
#
# Detect whether we can build the GFNI/AVX-{2,512} accelerated EC
# primitives.  The kernels are C with __attribute__((target("avx2,gfni")))
# / target("avx512f,avx512bw,gfni") and use _mm{256,512}_gf2p8affine
# intrinsics.  We require x86_64 and a compiler new enough to recognise
# the intrinsic when the matching target attribute is in scope: clang 8
# or GCC 10.  GCC 8 and 9 accept it but mark GF2P8AFFINEQB commutative,
# so they may swap the data and matrix operands and emit wrong parity.
#
AC_DEFUN([EC_GFNI_SUPPORT],[
AC_MSG_CHECKING([whether to build GFNI EC primitives])
ec_gfni="no"
case "$target_cpu" in
x86_64|amd64)
	AC_LANG_PUSH([C])
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
		#include <immintrin.h>
		#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 10
		#error GCC before 10 miscompiles GF2P8AFFINEQB
		#endif
		__attribute__((target("avx2,gfni")))
		static __m256i probe(__m256i a, __m256i b)
		{
			return _mm256_gf2p8affine_epi64_epi8(a, b, 0);
		}
		int main(void) { (void)probe; return 0; }
	]])], [ec_gfni="yes"], [ec_gfni="no"])
	AC_LANG_POP([C])
	;;
esac
AC_MSG_RESULT([$ec_gfni])
AM_CONDITIONAL([EC_GFNI], [test "x$ec_gfni" = "xyes"])
# -DLUSTRE_EC_GFNI is scoped to the libec.a build (via libec_a_CPPFLAGS)
# rather than defined globally in config.h: the GFNI dispatch in
# ec_base_aliases.c must only be active where the GFNI kernel objects
# are actually linked (libec.a).  ec_base_aliases.c is also compiled
# into liblustreapi, which does not link the GFNI objects, so a global
# define would leave liblustreapi with undefined references.
EC_GFNI_CFLAGS=""
if test "x$ec_gfni" = "xyes"; then
	EC_GFNI_CFLAGS="-DLUSTRE_EC_GFNI"
fi
AC_SUBST([EC_GFNI_CFLAGS])
])

#
# EC_CONFIGURE
#
# other configure checks
#
AC_DEFUN([EC_CONFIGURE], [
AC_MSG_NOTICE([Erasurecode core checks
==============================================================================])
EC_ISA_L_SUPPORT
EC_GFNI_SUPPORT
]) # EC_CONFIGURE

#
# EC_CONFIG_FILES
#
# files that should be generated with AC_OUTPUT
#
AC_DEFUN([EC_CONFIG_FILES], [
AC_CONFIG_FILES([
lustre/utils/erasurecode/Makefile
lustre/utils/erasurecode/autoMakefile
])
]) # EC_CONFIG_FILES
