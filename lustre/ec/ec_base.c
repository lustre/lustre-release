/**********************************************************************
  Copyright(c) 2011-2015 Intel Corporation All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#ifdef __KERNEL__
#include <linux/string.h> // for memset
#include <linux/types.h>
#include <asm/bitsperlong.h> // for BITS_PER_LONG

#include <uapi/linux/lustre/erasure_code.h>
#include <uapi/linux/lustre/ec_base.h> // for GF tables
#else
#include <limits.h>
#include <string.h> // for memset
#include <stdint.h>

#include <linux/lustre/erasure_code.h>
#include <linux/lustre/ec_base.h> // for GF tables
#endif /* __KERNEL__ */

/*
 * Below this region length, the cost of building a 256-entry product
 * table outweighs the per-byte gf_mul() work it replaces, so the
 * affected *_base routines fall back to the scalar gf_mul() path.
 *
 * Building the table costs 256 gf_mul() calls, which is what the direct
 * path would spend on a 256-byte region on its own, and the table path
 * then adds a full pass over dest. 256 is therefore a lower bound on
 * where the table can help, not a safe threshold: measured with
 * ec_encode_data_base() at k=6/p=2, -O2, a 256-byte region is about 26%
 * slower through the table than through gf_mul(), and break-even sits
 * nearer 1 KiB. The crossover is platform-dependent, so round to 1 KiB.
 */
#define GF_REGION_TBL_MIN_LEN 1024

/*
 * 64-bit little-endian hosts fill the 32-byte table in
 * gf_vect_mul_init_base() with four 64-bit stores. __WORDSIZE comes from
 * glibc's <bits/wordsize.h> and so is only defined in the userspace build;
 * kernel builds use BITS_PER_LONG, which also covers arm64, ppc64le and
 * riscv64.
 */
#ifdef __KERNEL__
#define GF_VECT_MUL_INIT_64 (BITS_PER_LONG == 64)
#elif defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64) ||      \
	defined(_WIN64)
#define GF_VECT_MUL_INIT_64 1
#else
#define GF_VECT_MUL_INIT_64 0
#endif

/*
 * Byte-indexed per-coefficient lookup table (256 bytes).
 * After gf_build_mul_tbl(c, tbl), tbl[b] = c * b in GF(2^8). The hot-path
 * region multiply is then gf_region_mul(tbl, b), a single byte-indexed
 * load.
 *
 * Reference implementation: gf-nishida-16's GF8crtRegTbl / GF8LkupRT.
 */
static inline void
gf_build_mul_tbl(unsigned char c, unsigned char *tbl)
{
	int b;

	for (b = 0; b < 256; b++)
		tbl[b] = gf_mul(c, (unsigned char) b);
}

/*
 * Byte-indexed region GF(2^8) multiply. `tbl` is a table built by
 * gf_build_mul_tbl() above. Takes unsigned char rather than being a macro
 * so a signed index cannot subscript backwards.
 *
 * One dependent load per byte, with no nibble split and no recombining
 * shift/or, which is what makes this cheaper than a 4-bit table lookup.
 */
static inline unsigned char
gf_region_mul(const unsigned char *tbl, unsigned char x)
{
	return tbl[x];
}

void
ec_init_tables_base(int k, int rows, unsigned char *a, unsigned char *g_tbls)
{
	int i, j;

	for (i = 0; i < rows; i++) {
		for (j = 0; j < k; j++) {
			gf_vect_mul_init_base(*a++, g_tbls);
			g_tbls += 32;
		}
	}
}

/*
 * The widest index gf_mul() can form is gflog_base[0] + gflog_base[0],
 * i.e. twice the 511 sentinel, and every entry from 511 upward must be
 * zero.  A static array is zero-filled past its last initializer, so
 * only the declared size needs checking.
 */
_Static_assert(sizeof(gff_base) > 2 * 511,
	       "gff_base must cover twice the gflog_base zero sentinel");

unsigned char
gf_mul(unsigned char a, unsigned char b)
{
	/*
	 * Branch-free: gflog_base[0] is a sentinel (511) and gff_base has a
	 * zeroed tail, so a zero operand indexes into the zeros and yields 0
	 * without a (a==0||b==0) test; the doubled antilog removes the
	 * reduction wrap. See the table comment in ec_base.h.
	 */
	return gff_base[gflog_base[a] + gflog_base[b]];
}

unsigned char
gf_inv(unsigned char a)
{
	if (a == 0)
		return 0;

	return gff_base[255 - gflog_base[a]];
}

void
gf_gen_rs_matrix(unsigned char *a, int m, int k)
{
	int i, j;
	unsigned char p, gen = 1;

	memset(a, 0, k * m);
	for (i = 0; i < k; i++)
		a[k * i + i] = 1;

	for (i = k; i < m; i++) {
		p = 1;
		for (j = 0; j < k; j++) {
			a[k * i + j] = p;
			p = gf_mul(p, gen);
		}
		gen = gf_mul(gen, 2);
	}
}

void
gf_gen_cauchy1_matrix(unsigned char *a, int m, int k)
{
	int i, j;
	unsigned char *p;

	// Identity matrix in high position
	memset(a, 0, k * m);
	for (i = 0; i < k; i++)
		a[k * i + i] = 1;

	// For the rest choose 1/(i + j) | i != j
	p = &a[k * k];
	for (i = k; i < m; i++)
		for (j = 0; j < k; j++)
			*p++ = gf_inv(i ^ j);
}

int
gf_invert_matrix(unsigned char *in_mat, unsigned char *out_mat, const int n)
{
	int i, j, k;
	unsigned char temp;

	// Set out_mat[] to the identity matrix
	for (i = 0; i < n * n; i++) // memset(out_mat, 0, n*n)
		out_mat[i] = 0;

	for (i = 0; i < n; i++)
		out_mat[i * n + i] = 1;

	// Inverse
	for (i = 0; i < n; i++) {
		// Check for 0 in pivot element
		if (in_mat[i * n + i] == 0) {
			// Find a row with non-zero in current column and swap
			for (j = i + 1; j < n; j++)
				if (in_mat[j * n + i])
					break;

			if (j == n) // Couldn't find means it's singular
				return -1;

			for (k = 0; k < n; k++) { // Swap rows i,j
				temp = in_mat[i * n + k];
				in_mat[i * n + k] = in_mat[j * n + k];
				in_mat[j * n + k] = temp;

				temp = out_mat[i * n + k];
				out_mat[i * n + k] = out_mat[j * n + k];
				out_mat[j * n + k] = temp;
			}
		}

		temp = gf_inv(in_mat[i * n + i]); // 1/pivot
		for (j = 0; j < n; j++) {         // Scale row i by 1/pivot
			in_mat[i * n + j] = gf_mul(in_mat[i * n + j], temp);
			out_mat[i * n + j] = gf_mul(out_mat[i * n + j], temp);
		}

		for (j = 0; j < n; j++) {
			if (j == i)
				continue;

			temp = in_mat[j * n + i];
			for (k = 0; k < n; k++) {
				out_mat[j * n + k] ^=
					gf_mul(temp, out_mat[i * n + k]);
				in_mat[j * n + k] ^=
					gf_mul(temp, in_mat[i * n + k]);
			}
		}
	}
	return 0;
}

// Calculates const table gftbl in GF(2^8) from single input A
// gftbl(A) = {A{00}, A{01}, A{02}, ... , A{0f} }, {A{00}, A{10}, A{20}, ... , A{f0} }

void
gf_vect_mul_init_base(unsigned char c, unsigned char *tbl)
{
	unsigned char c2 = (c << 1) ^ ((c & 0x80) ? 0x1d : 0);   // * 2 by GF{2}
	unsigned char c4 = (c2 << 1) ^ ((c2 & 0x80) ? 0x1d : 0); // * 4 by GF{2}
	unsigned char c8 = (c4 << 1) ^ ((c4 & 0x80) ? 0x1d : 0); // * 8 by GF{2}

#if GF_VECT_MUL_INIT_64 && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
	unsigned long long v1, v2, v4, v8, *t;
	unsigned long long v10, v20, v40, v80;
	unsigned char c17, c18, c20, c24;

	t = (unsigned long long *) tbl;

	v1 = c * 0x0100010001000100ull;
	v2 = c2 * 0x0101000001010000ull;
	v4 = c4 * 0x0101010100000000ull;
	v8 = c8 * 0x0101010101010101ull;

	v4 = v1 ^ v2 ^ v4;
	t[0] = v4;
	t[1] = v8 ^ v4;

	c17 = (c8 << 1) ^ ((c8 & 0x80) ? 0x1d : 0);   // Mult by GF{2}
	c18 = (c17 << 1) ^ ((c17 & 0x80) ? 0x1d : 0); // Mult by GF{2}
	c20 = (c18 << 1) ^ ((c18 & 0x80) ? 0x1d : 0); // Mult by GF{2}
	c24 = (c20 << 1) ^ ((c20 & 0x80) ? 0x1d : 0); // Mult by GF{2}

	v10 = c17 * 0x0100010001000100ull;
	v20 = c18 * 0x0101000001010000ull;
	v40 = c20 * 0x0101010100000000ull;
	v80 = c24 * 0x0101010101010101ull;

	v40 = v10 ^ v20 ^ v40;
	t[2] = v40;
	t[3] = v80 ^ v40;

#else // 32-bit or other
	unsigned char c3, c5, c6, c7, c9, c10, c11, c12, c13, c14, c15;
	unsigned char c17, c18, c19, c20, c21, c22, c23, c24, c25, c26;
	unsigned char c27, c28, c29, c30, c31;

	c3 = c2 ^ c;
	c5 = c4 ^ c;
	c6 = c4 ^ c2;
	c7 = c4 ^ c3;

	c9 = c8 ^ c;
	c10 = c8 ^ c2;
	c11 = c8 ^ c3;
	c12 = c8 ^ c4;
	c13 = c8 ^ c5;
	c14 = c8 ^ c6;
	c15 = c8 ^ c7;

	tbl[0] = 0;
	tbl[1] = c;
	tbl[2] = c2;
	tbl[3] = c3;
	tbl[4] = c4;
	tbl[5] = c5;
	tbl[6] = c6;
	tbl[7] = c7;
	tbl[8] = c8;
	tbl[9] = c9;
	tbl[10] = c10;
	tbl[11] = c11;
	tbl[12] = c12;
	tbl[13] = c13;
	tbl[14] = c14;
	tbl[15] = c15;

	c17 = (c8 << 1) ^ ((c8 & 0x80) ? 0x1d : 0);   // Mult by GF{2}
	c18 = (c17 << 1) ^ ((c17 & 0x80) ? 0x1d : 0); // Mult by GF{2}
	c19 = c18 ^ c17;
	c20 = (c18 << 1) ^ ((c18 & 0x80) ? 0x1d : 0); // Mult by GF{2}
	c21 = c20 ^ c17;
	c22 = c20 ^ c18;
	c23 = c20 ^ c19;
	c24 = (c20 << 1) ^ ((c20 & 0x80) ? 0x1d : 0); // Mult by GF{2}
	c25 = c24 ^ c17;
	c26 = c24 ^ c18;
	c27 = c24 ^ c19;
	c28 = c24 ^ c20;
	c29 = c24 ^ c21;
	c30 = c24 ^ c22;
	c31 = c24 ^ c23;

	tbl[16] = 0;
	tbl[17] = c17;
	tbl[18] = c18;
	tbl[19] = c19;
	tbl[20] = c20;
	tbl[21] = c21;
	tbl[22] = c22;
	tbl[23] = c23;
	tbl[24] = c24;
	tbl[25] = c25;
	tbl[26] = c26;
	tbl[27] = c27;
	tbl[28] = c28;
	tbl[29] = c29;
	tbl[30] = c30;
	tbl[31] = c31;

#endif // GF_VECT_MUL_INIT_64 && little-endian
}

void
gf_vect_dot_prod_base(int len, int vlen, unsigned char *v, unsigned char **src, unsigned char *dest)
{
	int i, j;
	unsigned char tbl[256];
	const unsigned char *s;

	/* Short regions: the table build does not pay off (see threshold). */
	if (len < GF_REGION_TBL_MIN_LEN) {
		unsigned char sum;

		for (i = 0; i < len; i++) {
			sum = 0;
			for (j = 0; j < vlen; j++)
				sum ^= gf_mul(src[j][i], v[j * 32 + 1]);
			dest[i] = sum;
		}
		return;
	}

	/*
	 * One source at a time, rebuilding a single stack table per source so
	 * the routine stays allocation-free. The first source initializes
	 * dest; the rest XOR-accumulate.
	 */
	gf_build_mul_tbl(v[1], tbl);
	s = src[0];
	for (i = 0; i < len; i++) {
		dest[i] = gf_region_mul(tbl, *s);
		s++;
	}

	for (j = 1; j < vlen; j++) {
		gf_build_mul_tbl(v[j * 32 + 1], tbl);
		s = src[j];
		for (i = 0; i < len; i++) {
			dest[i] ^= gf_region_mul(tbl, *s);
			s++;
		}
	}
}

void
gf_vect_mad_base(int len, int vec, int vec_i, unsigned char *v, unsigned char *src,
		 unsigned char *dest)
{
	int i;
	unsigned char tbl[256];
	unsigned char c = v[vec_i * 32 + 1];

	if (len < GF_REGION_TBL_MIN_LEN) {
		for (i = 0; i < len; i++)
			dest[i] ^= gf_mul(src[i], c);
		return;
	}

	gf_build_mul_tbl(c, tbl);
	for (i = 0; i < len; i++)
		dest[i] ^= gf_region_mul(tbl, src[i]);
}

void
ec_encode_data_base(int len, int srcs, int dests, unsigned char *v, unsigned char **src,
		    unsigned char **dest)
{
	int i, j, l;
	unsigned char tbl[256];

	/* Short regions: the table build does not pay off (see threshold). */
	if (len < GF_REGION_TBL_MIN_LEN) {
		for (l = 0; l < dests; l++) {
			for (i = 0; i < len; i++) {
				unsigned char s = 0;

				for (j = 0; j < srcs; j++)
					s ^= gf_mul(src[j][i],
						v[j * 32 + l * srcs * 32 + 1]);
				dest[l][i] = s;
			}
		}
		return;
	}

	/*
	 * Per dest, one source at a time, rebuilding a single stack table per
	 * source so the routine stays allocation-free. The first source
	 * initializes the dest row; the rest XOR-accumulate.
	 */
	for (l = 0; l < dests; l++) {
		unsigned char *d = dest[l];
		const unsigned char *s;

		gf_build_mul_tbl(v[l * srcs * 32 + 1], tbl);
		s = src[0];
		for (i = 0; i < len; i++)
			d[i] = gf_region_mul(tbl, s[i]);

		for (j = 1; j < srcs; j++) {
			gf_build_mul_tbl(v[j * 32 + l * srcs * 32 + 1], tbl);
			s = src[j];
			for (i = 0; i < len; i++)
				d[i] ^= gf_region_mul(tbl, s[i]);
		}
	}
}

void
ec_encode_data_update_base(int len, int k, int rows, int vec_i, unsigned char *v,
			   unsigned char *data, unsigned char **dest)
{
	int i, l;
	unsigned char tbl[256];

	if (len < GF_REGION_TBL_MIN_LEN) {
		for (l = 0; l < rows; l++) {
			unsigned char c = v[vec_i * 32 + l * k * 32 + 1];
			unsigned char *d = dest[l];

			for (i = 0; i < len; i++)
				d[i] ^= gf_mul(data[i], c);
		}
		return;
	}

	for (l = 0; l < rows; l++) {
		unsigned char *d = dest[l];

		gf_build_mul_tbl(v[vec_i * 32 + l * k * 32 + 1], tbl);
		for (i = 0; i < len; i++)
			d[i] ^= gf_region_mul(tbl, data[i]);
	}
}

int
gf_vect_mul_base(int len, unsigned char *a, unsigned char *src, unsigned char *dest)
{
	// 2nd element of table array is ref value used to fill it in
	unsigned char c = a[1];
	unsigned char tbl[256];
	int i;

	// Len must be aligned to 32B
	if ((len % 32) != 0)
		return -1;

	if (len < GF_REGION_TBL_MIN_LEN) {
		for (i = 0; i < len; i++)
			dest[i] = gf_mul(c, src[i]);
		return 0;
	}

	gf_build_mul_tbl(c, tbl);
	for (i = 0; i < len; i++)
		dest[i] = gf_region_mul(tbl, src[i]);
	return 0;
}
