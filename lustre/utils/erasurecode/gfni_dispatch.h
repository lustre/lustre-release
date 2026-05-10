/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) 2026 Hiroshi Nishida <hnishida@thelustrecollective.com>
 *
 * GFNI-accelerated Reed-Solomon primitives used by the Lustre EC
 * library when running on x86_64 CPUs with GFNI / AVX2 / AVX-512.
 *
 * The functions declared here are implemented in gfni_glue.c and the
 * per-ISA kernels in gf_*vect_*_gfni.c (compiler intrinsics gated by
 * __attribute__((target("avx2,gfni"))) / target("avx512f,avx512bw,gfni")).
 * ec_base_aliases.c picks the best available implementation at runtime
 * via isal_have_gfni() / isal_have_avx512_gfni().  Five entry points
 * dispatch this way: ec_init_tables(), ec_encode_data(),
 * ec_encode_data_update(), gf_vect_dot_prod() and gf_vect_mad().
 */

#ifndef _LUSTRE_GFNI_DISPATCH_H
#define _LUSTRE_GFNI_DISPATCH_H

#ifdef __KERNEL__
# include <linux/types.h>
#else
# include <stdint.h>
# include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

bool isal_have_gfni(void);
bool isal_have_avx512_gfni(void);

void
gf_vect_mul_init_gfni(unsigned char c, unsigned char *tbl);

void
ec_init_tables_gfni(int k, int rows, unsigned char *a, unsigned char *g_tbls);

void
ec_encode_data_avx2_gfni(int len, int k, int rows, unsigned char *g_tbls,
			 unsigned char **data, unsigned char **coding);

void
ec_encode_data_avx512_gfni(int len, int k, int rows, unsigned char *g_tbls,
			   unsigned char **data, unsigned char **coding);

void
ec_encode_data_update_avx2_gfni(int len, int k, int rows, int vec_i,
				unsigned char *g_tbls, unsigned char *data,
				unsigned char **coding);

void
ec_encode_data_update_avx512_gfni(int len, int k, int rows, int vec_i,
				  unsigned char *g_tbls, unsigned char *data,
				  unsigned char **coding);

/*
 * Low-level per-vector kernels, defined in the matching
 * gf_*vect_{dot_prod,mad}_avx{2,512}_gfni.c files.  Most are reached
 * only through the multi-row peeling in gfni_glue.c, but the four
 * single-vector ones -- gf_vect_{dot_prod,mad}_avx{2,512}_gfni() --
 * are also called straight from ec_base_aliases.c, where
 * gf_vect_dot_prod() and gf_vect_mad() dispatch on the ISA.
 */
void
gf_vect_dot_prod_avx2_gfni(int len, int vec, unsigned char *gftbls,
			   unsigned char **src, unsigned char *dest);
void
gf_2vect_dot_prod_avx2_gfni(int len, int vec, unsigned char *gftbls,
			    unsigned char **src, unsigned char **dest);
void
gf_3vect_dot_prod_avx2_gfni(int len, int vec, unsigned char *gftbls,
			    unsigned char **src, unsigned char **dest);

void
gf_vect_dot_prod_avx512_gfni(int len, int vec, unsigned char *gftbls,
			     unsigned char **src, unsigned char *dest);
void
gf_2vect_dot_prod_avx512_gfni(int len, int vec, unsigned char *gftbls,
			      unsigned char **src, unsigned char **dest);
void
gf_3vect_dot_prod_avx512_gfni(int len, int vec, unsigned char *gftbls,
			      unsigned char **src, unsigned char **dest);
void
gf_4vect_dot_prod_avx512_gfni(int len, int vec, unsigned char *gftbls,
			      unsigned char **src, unsigned char **dest);
void
gf_5vect_dot_prod_avx512_gfni(int len, int vec, unsigned char *gftbls,
			      unsigned char **src, unsigned char **dest);
void
gf_6vect_dot_prod_avx512_gfni(int len, int vec, unsigned char *gftbls,
			      unsigned char **src, unsigned char **dest);

void
gf_vect_mad_avx2_gfni(int len, int vec, int vec_i, unsigned char *gftbls,
		      unsigned char *src, unsigned char *dest);
void
gf_2vect_mad_avx2_gfni(int len, int vec, int vec_i, unsigned char *gftbls,
		       unsigned char *src, unsigned char **dest);

void
gf_vect_mad_avx512_gfni(int len, int vec, int vec_i, unsigned char *gftbls,
			unsigned char *src, unsigned char *dest);
void
gf_2vect_mad_avx512_gfni(int len, int vec, int vec_i, unsigned char *gftbls,
			 unsigned char *src, unsigned char **dest);
void
gf_3vect_mad_avx512_gfni(int len, int vec, int vec_i, unsigned char *gftbls,
			 unsigned char *src, unsigned char **dest);
void
gf_4vect_mad_avx512_gfni(int len, int vec, int vec_i, unsigned char *gftbls,
			 unsigned char *src, unsigned char **dest);
void
gf_5vect_mad_avx512_gfni(int len, int vec, int vec_i, unsigned char *gftbls,
			 unsigned char *src, unsigned char **dest);
void
gf_6vect_mad_avx512_gfni(int len, int vec, int vec_i, unsigned char *gftbls,
			 unsigned char *src, unsigned char **dest);

#ifdef __cplusplus
}
#endif

#endif /* _LUSTRE_GFNI_DISPATCH_H */
