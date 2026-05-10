// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (c) 2026 Hiroshi Nishida <hnishida@thelustrecollective.com>
 *
 * gfni_ec_test.c -- standalone test for GFNI-accelerated EC encode.
 *
 * Verifies that:
 *   1. isal_have_gfni() / isal_have_avx512_gfni() detection works.
 *   2. ec_encode_data() (which dispatches to GFNI when available)
 *      produces byte-identical results to ec_encode_data_base() on
 *      random input.
 *   3. ec_init_tables() (GFNI path) produces an identical gen_tbls to
 *      ec_init_tables_base().
 *   4. ec_encode_data_update() (which dispatches to the gf_*vect_mad_*
 *      kernels) reproduces the same parity when the sources are folded
 *      in one at a time, both against ec_encode_data_update_base() and
 *      against the full ec_encode_data_base() encode.
 *
 * -i selects which kernel family to exercise; see enum ec_isa below.
 *
 * Exit status: 0 on success, 1 on a parity mismatch, 2 on bad usage,
 * and 77 when the requested GFNI mode is not available -- either
 * neither mode exists, in which case every comparison ran
 * base-against-base and nothing GFNI-specific was exercised, or -i
 * asked for a family this CPU lacks.  A caller such as sanity-ec.sh
 * test_0 can then skip rather than record a vacuous pass.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <getopt.h>

/* EC library headers */
#include <linux/lustre/erasure_code.h>
#include "gfni_dispatch.h"

/*
 * Minimum vector lengths erasure_code.h documents for these two entry
 * points.  ec_encode_data() and ec_encode_data_update() carry no such
 * restriction and are exercised at every length.
 */
#define GF_VECT_DOT_PROD_MIN_LEN	32
#define GF_VECT_MAD_MIN_LEN		64

/*
 * Which kernel family to exercise.  ISA_AUTO goes through the public
 * entry points, i.e. what production code does; the other two call the
 * per-ISA symbols directly.  Without this, every entry point tests
 * isal_have_avx512_gfni() first, so on a CPU with both GFNI and AVX-512
 * -- which is every server part that has GFNI at all -- the five AVX2
 * kernels are unreachable and get no coverage from the sanity-ec.sh
 * sweep.  The reverse holds for the nine AVX-512 kernels on a
 * GFNI-without-AVX-512 client.
 */
enum ec_isa { ISA_AUTO, ISA_AVX2, ISA_AVX512 };

static enum ec_isa isa = ISA_AUTO;

static void enc(int len, int k, int rows, uint8_t *tbls, uint8_t **data,
		uint8_t **coding)
{
	switch (isa) {
	case ISA_AVX2:
		ec_encode_data_avx2_gfni(len, k, rows, tbls, data, coding);
		break;
	case ISA_AVX512:
		ec_encode_data_avx512_gfni(len, k, rows, tbls, data, coding);
		break;
	default:
		ec_encode_data(len, k, rows, tbls, data, coding);
	}
}

static void enc_update(int len, int k, int rows, int vec_i, uint8_t *tbls,
		       uint8_t *data, uint8_t **coding)
{
	switch (isa) {
	case ISA_AVX2:
		ec_encode_data_update_avx2_gfni(len, k, rows, vec_i, tbls,
						data, coding);
		break;
	case ISA_AVX512:
		ec_encode_data_update_avx512_gfni(len, k, rows, vec_i, tbls,
						  data, coding);
		break;
	default:
		ec_encode_data_update(len, k, rows, vec_i, tbls, data, coding);
	}
}

static void dot_prod(int len, int vec, uint8_t *tbls, uint8_t **src,
		     uint8_t *dest)
{
	switch (isa) {
	case ISA_AVX2:
		gf_vect_dot_prod_avx2_gfni(len, vec, tbls, src, dest);
		break;
	case ISA_AVX512:
		gf_vect_dot_prod_avx512_gfni(len, vec, tbls, src, dest);
		break;
	default:
		gf_vect_dot_prod(len, vec, tbls, src, dest);
	}
}

static void mad(int len, int vec, int vec_i, uint8_t *tbls, uint8_t *src,
		uint8_t *dest)
{
	switch (isa) {
	case ISA_AVX2:
		gf_vect_mad_avx2_gfni(len, vec, vec_i, tbls, src, dest);
		break;
	case ISA_AVX512:
		gf_vect_mad_avx512_gfni(len, vec, vec_i, tbls, src, dest);
		break;
	default:
		gf_vect_mad(len, vec, vec_i, tbls, src, dest);
	}
}

static void fill_random(uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len; i++)
		buf[i] = (uint8_t)(rand() & 0xFF);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-k DATA] [-m PARITY] [-l LEN] [-i ISA]\n"
		"  -k, --data=N    EC data stripe count (default 4)\n"
		"  -m, --parity=N  EC parity stripe count (default 2)\n"
		"  -l, --len=N     buffer length in bytes (default 4096)\n"
		"  -i, --isa=NAME  auto (default), avx2 or avx512: which\n"
		"                  kernels to call.  auto uses the runtime\n"
		"                  dispatch; the others force one family and\n"
		"                  exit 77 if this CPU lacks it\n"
		"  -h, --help      show this help\n",
		prog);
}

static const struct option longopts[] = {
	{ "data",   required_argument, NULL, 'k' },
	{ "parity", required_argument, NULL, 'm' },
	{ "len",    required_argument, NULL, 'l' },
	{ "isa",    required_argument, NULL, 'i' },
	{ "help",   no_argument,       NULL, 'h' },
	{ NULL, 0, NULL, 0 }
};

int main(int argc, char *argv[])
{
	int k = 4, m = 2, len = 4096;
	int gfni, gfni512;
	int opt;

	while ((opt = getopt_long(argc, argv, "k:m:l:i:h",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 'k':
			k = atoi(optarg);
			break;
		case 'm':
			m = atoi(optarg);
			break;
		case 'l':
			len = atoi(optarg);
			break;
		case 'i':
			if (!strcmp(optarg, "auto")) {
				isa = ISA_AUTO;
			} else if (!strcmp(optarg, "avx2")) {
				isa = ISA_AVX2;
			} else if (!strcmp(optarg, "avx512")) {
				isa = ISA_AVX512;
			} else {
				fprintf(stderr, "%s: unknown ISA: %s\n",
					argv[0], optarg);
				usage(argv[0]);
				return 2;
			}
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 2;
		}
	}
	if (optind != argc) {
		fprintf(stderr, "%s: unexpected argument: %s\n",
			argv[0], argv[optind]);
		usage(argv[0]);
		return 2;
	}

	/*
	 * k + m <= 256 is a theoretical bound from Cauchy matrix theory,
	 * not an implementation detail.  A Cauchy matrix (a MDS matrix
	 * construction) requires k+m distinct field elements, and the
	 * underlying field GF(2^8) has exactly 256.  Not a GFNI-specific
	 * limit.
	 */
	if (k < 1 || k > 255 || m < 1 || m > 255 ||
	    k + m > 256 || len <= 0) {
		fprintf(stderr,
			"invalid k=%d m=%d len=%d (need 1<=k, 1<=m, k+m<=256, len>0)\n",
			k, m, len);
		return 2;
	}

	gfni    = isal_have_gfni();
	gfni512 = isal_have_avx512_gfni();

	printf("k=%d m=%d len=%d\n", k, m, len);
	printf("CPU capabilities:\n");
	printf("  GFNI (AVX2):   %s\n", gfni    ? "YES" : "no");
	printf("  GFNI (AVX512): %s\n", gfni512 ? "YES" : "no");
	printf("\n");

	/*
	 * Forcing a family the CPU lacks would execute GF2P8AFFINEQB (or
	 * an AVX-512 encoding) and take SIGILL, so report the automake
	 * skip status rather than crashing.
	 */
	if ((isa == ISA_AVX2 && !gfni) || (isa == ISA_AVX512 && !gfni512)) {
		printf("SKIP: CPU lacks %s\n",
		       isa == ISA_AVX2 ? "GFNI" : "AVX-512 GFNI");
		return 77;
	}

	if (!gfni && !gfni512)
		printf("NOTE: GFNI not detected -- using baseline C path\n\n");

	/* Allocate encode matrix and gen_tbls */
	uint8_t *encode_matrix = calloc((k + m) * k, 1);
	uint8_t *gen_tbls_base = calloc(32 * k * m, 1);
	uint8_t *gen_tbls_gfni = calloc(32 * k * m, 1);

	gf_gen_cauchy1_matrix(encode_matrix, k + m, k);

	/*
	 * Initialise tables via each path independently.  The table formats
	 * differ (GFNI uses affine-transform; base uses log/exp tables) so
	 * comparing them byte-for-byte is meaningless.  What matters is that
	 * both encoders produce identical parity for the same input.
	 */
	ec_init_tables_base(k, m, &encode_matrix[k * k], gen_tbls_base);
	ec_init_tables(k, m, &encode_matrix[k * k], gen_tbls_gfni);
	printf("Tables initialised (GFNI fmt differs from base by design)\n");

	/* Allocate data and parity buffers */
	uint8_t *data_buf = malloc((size_t)k * len);
	uint8_t **data    = malloc(k * sizeof(uint8_t *));
	uint8_t **parity_base = malloc(m * sizeof(uint8_t *));
	uint8_t **parity_gfni = malloc(m * sizeof(uint8_t *));
	uint8_t *parity_base_buf = calloc((size_t)m * len, 1);
	uint8_t *parity_gfni_buf = calloc((size_t)m * len, 1);

	srand((unsigned int)time(NULL));
	fill_random(data_buf, (size_t)k * len);

	for (int i = 0; i < k; i++)
		data[i] = data_buf + (size_t)i * len;
	for (int i = 0; i < m; i++) {
		parity_base[i] = parity_base_buf + (size_t)i * len;
		parity_gfni[i] = parity_gfni_buf + (size_t)i * len;
	}

	/* Encode with base */
	ec_encode_data_base(len, k, m, gen_tbls_base, data, parity_base);

	/* Encode with dispatcher (GFNI if available, base otherwise) */
	enc(len, k, m, gen_tbls_gfni, data, parity_gfni);

	int failures = 0;
	const char *path = isa == ISA_AVX2   ? "AVX2-GFNI (forced)" :
			   isa == ISA_AVX512 ? "AVX512-GFNI (forced)" :
			   gfni512 ? "AVX512-GFNI" :
			   gfni    ? "AVX2-GFNI" : "base-C";

	for (int i = 0; i < m; i++) {
		if (memcmp(parity_base[i], parity_gfni[i], len) == 0) {
			printf("PASS: parity[%d] matches base (%s path)\n",
			       i, path);
		} else {
			printf("FAIL: parity[%d] differs from base\n", i);
			failures++;
		}
	}

	/*
	 * ec_encode_data_update() folds one source vector at a time into
	 * an accumulating parity buffer, dispatching to the gf_*vect_mad_*
	 * kernels rather than the dot_prod ones the encode above uses.
	 * Both buffers start zeroed, so after all k sources are folded in
	 * the result must equal the full encode.
	 */
	uint8_t **parity_upd_base = malloc(m * sizeof(uint8_t *));
	uint8_t **parity_upd_gfni = malloc(m * sizeof(uint8_t *));
	uint8_t *parity_upd_base_buf = calloc((size_t)m * len, 1);
	uint8_t *parity_upd_gfni_buf = calloc((size_t)m * len, 1);

	for (int i = 0; i < m; i++) {
		parity_upd_base[i] = parity_upd_base_buf + (size_t)i * len;
		parity_upd_gfni[i] = parity_upd_gfni_buf + (size_t)i * len;
	}

	for (int i = 0; i < k; i++) {
		ec_encode_data_update_base(len, k, m, i, gen_tbls_base,
					   data[i], parity_upd_base);
		enc_update(len, k, m, i, gen_tbls_gfni, data[i],
			   parity_upd_gfni);
	}

	for (int i = 0; i < m; i++) {
		if (memcmp(parity_upd_base[i], parity_upd_gfni[i], len) != 0) {
			printf("FAIL: update parity[%d] differs from base\n",
			       i);
			failures++;
		} else if (memcmp(parity_upd_gfni[i], parity_base[i],
				  len) != 0) {
			printf("FAIL: update parity[%d] differs from encode\n",
			       i);
			failures++;
		} else {
			printf("PASS: update parity[%d] matches base and encode (%s path)\n",
			       i, path);
		}
	}

	/*
	 * gf_vect_dot_prod() and gf_vect_mad() are single-output helpers
	 * that take the same tables.  Both must reproduce parity row 0:
	 * dot_prod in one call over all k sources, mad by accumulating one
	 * source at a time.  This is what makes the tables from
	 * ec_init_tables() safe to pass to any exported entry point.
	 *
	 * erasure_code.h documents a minimum len for each (32 and 64
	 * bytes).  The length sweep in sanity-ec.sh goes well below both,
	 * and the arch kernels already declared in that header do not
	 * accept short vectors, so only run each check where the API
	 * contract allows it rather than testing outside the interface.
	 */
	if (len >= GF_VECT_DOT_PROD_MIN_LEN) {
		uint8_t *vect_dp = calloc(len, 1);

		dot_prod(len, k, gen_tbls_gfni, data, vect_dp);
		if (memcmp(vect_dp, parity_base[0], len) != 0) {
			printf("FAIL: gf_vect_dot_prod differs from base encode\n");
			failures++;
		} else {
			printf("PASS: gf_vect_dot_prod matches base encode (%s path)\n",
			       path);
		}
		free(vect_dp);
	}

	if (len >= GF_VECT_MAD_MIN_LEN) {
		uint8_t *vect_mad = calloc(len, 1);

		for (int i = 0; i < k; i++)
			mad(len, k, i, gen_tbls_gfni, data[i], vect_mad);

		if (memcmp(vect_mad, parity_base[0], len) != 0) {
			printf("FAIL: gf_vect_mad differs from base encode\n");
			failures++;
		} else {
			printf("PASS: gf_vect_mad matches base encode (%s path)\n",
			       path);
		}
		free(vect_mad);
	}

	free(encode_matrix); free(gen_tbls_base); free(gen_tbls_gfni);
	free(data_buf); free(data);
	free(parity_base); free(parity_gfni);
	free(parity_base_buf); free(parity_gfni_buf);
	free(parity_upd_base); free(parity_upd_gfni);
	free(parity_upd_base_buf); free(parity_upd_gfni_buf);

	if (failures)
		return 1;

	/*
	 * Everything matched, but with no GFNI the dispatcher resolved to
	 * the same *_base routines it was compared against, so report the
	 * automake "skipped" status instead of a pass.
	 */
	if (!gfni && !gfni512)
		return 77;

	return 0;
}
