// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright(c) 2011-2017 Intel Corporation All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <linux/lustre/erasure_code.h>

#if defined(LUSTRE_EC_GFNI) && !defined(__KERNEL__)
# include "gfni_dispatch.h"
#endif

void
gf_vect_dot_prod(int len, int vlen, unsigned char *v,
		 unsigned char **src, unsigned char *dest)
{
	/*
	 * Dispatch on the same predicates as ec_encode_data(), so that any
	 * table ec_init_tables() produced is valid input here.  Leaving
	 * this on the base path would make the exported contract depend on
	 * the CPU: a caller pairing ec_init_tables() with this routine
	 * would hand affine-matrix tables to a helper that reads the
	 * coefficient at v[j * 32 + 1] in log/exp form.
	 */
#if defined(LUSTRE_EC_GFNI) && !defined(__KERNEL__)
	if (isal_have_avx512_gfni()) {
		gf_vect_dot_prod_avx512_gfni(len, vlen, v, src, dest);
		return;
	}
	if (isal_have_gfni()) {
		gf_vect_dot_prod_avx2_gfni(len, vlen, v, src, dest);
		return;
	}
#endif
	gf_vect_dot_prod_base(len, vlen, v, src, dest);
}

void
gf_vect_mad(int len, int vec, int vec_i, unsigned char *v,
	    unsigned char *src, unsigned char *dest)
{
#if defined(LUSTRE_EC_GFNI) && !defined(__KERNEL__)
	if (isal_have_avx512_gfni()) {
		gf_vect_mad_avx512_gfni(len, vec, vec_i, v, src, dest);
		return;
	}
	if (isal_have_gfni()) {
		gf_vect_mad_avx2_gfni(len, vec, vec_i, v, src, dest);
		return;
	}
#endif
	gf_vect_mad_base(len, vec, vec_i, v, src, dest);
}

void
ec_encode_data(int len, int srcs, int dests, unsigned char *v,
	       unsigned char **src, unsigned char **dest)
{
#if defined(LUSTRE_EC_GFNI) && !defined(__KERNEL__)
	if (isal_have_avx512_gfni()) {
		ec_encode_data_avx512_gfni(len, srcs, dests, v, src, dest);
		return;
	}
	if (isal_have_gfni()) {
		ec_encode_data_avx2_gfni(len, srcs, dests, v, src, dest);
		return;
	}
#endif
	ec_encode_data_base(len, srcs, dests, v, src, dest);
}

void
ec_encode_data_update(int len, int k, int rows, int vec_i, unsigned char *v,
		      unsigned char *data, unsigned char **dest)
{
#if defined(LUSTRE_EC_GFNI) && !defined(__KERNEL__)
	if (isal_have_avx512_gfni()) {
		ec_encode_data_update_avx512_gfni(len, k, rows, vec_i, v,
						  data, dest);
		return;
	}
	if (isal_have_gfni()) {
		ec_encode_data_update_avx2_gfni(len, k, rows, vec_i, v,
						data, dest);
		return;
	}
#endif
	ec_encode_data_update_base(len, k, rows, vec_i, v, data, dest);
}

int
gf_vect_mul(int len, unsigned char *a, void *src, void *dest)
{
	return gf_vect_mul_base(len, a, (unsigned char *)src,
				(unsigned char *)dest);
}

void
ec_init_tables(int k, int rows, unsigned char *a, unsigned char *g_tbls)
{
#if defined(LUSTRE_EC_GFNI) && !defined(__KERNEL__)
	/*
	 * Must match the dispatch in ec_encode_data() and
	 * ec_encode_data_update() exactly: the affine-matrix table format
	 * is only valid input to a GFNI kernel, so test the same pair of
	 * predicates they do. Testing isal_have_gfni() alone would hand
	 * base-format tables to ec_encode_data_avx512_gfni() on a CPU
	 * reporting AVX-512 GFNI without AVX2, silently producing wrong
	 * parity.
	 */
	if (isal_have_avx512_gfni() || isal_have_gfni()) {
		ec_init_tables_gfni(k, rows, a, g_tbls);
		return;
	}
#endif
	ec_init_tables_base(k, rows, a, g_tbls);
}

void
gf_vect_mul_init(unsigned char c, unsigned char *gftbl)
{
	gf_vect_mul_init_base(c, gftbl);
}
