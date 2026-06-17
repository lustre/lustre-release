// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2025 Whamcloud. All rights reserved.
 *
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Verify the computations in the ec module.
 *
 * Author: Ronnie Sahlberg
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/version.h>

#include <uapi/linux/lustre/erasure_code.h>

/* Random ID passed by userspace, and printed in messages, used to
 * separate different runs of that module. */
static int run_id;
module_param(run_id, int, 0644);
MODULE_PARM_DESC(run_id, "run ID");

#define PREFIX "lustre_ec_test_%u:"

#define MAX_EC_STRIPES 16

static int ec_test_01(int len)
{
	__u8 *buf = NULL;
	__u8 *encode_matrix = NULL;
	__u8 *g_tbls = NULL;
	__u8 *stripes[MAX_EC_STRIPES];
	int i, j, k = 5, p = 3, m;
	__u8 er[] = { 0xa4, 0xc2, 0x17 };
	int rc = -1;

	m = k + p;
	buf =  kmalloc(m * len, GFP_KERNEL);
	if (buf == NULL)
		goto out;

	/*
	 * Create a stripeset with 5 data stripes.with
	 * the following content
	 * stripe[0] = { 0, ...
	 * stripe[1] = { 1, ...
	 * stripe[2] = { 2, ...
	 * stripe[3] = { 3, ...
	 * stripe[4] = { 4, ...
	 *
	 *.When computing three parities using a cauchy matric this
	 * will result in the following parity stripes:
	 * stripe[5] = { 0xa4, ...
	 * stripe[6] = { 0xc2, ...
	 * stripe[7] = { 0x17, ...
	 */
	for (i = 0; i < m; i++) {
		stripes[i] = &buf[i * len];
		memset(stripes[i], i, len);
	}
	g_tbls =  kmalloc(k * p * 32, GFP_KERNEL);
	if (g_tbls == NULL)
		goto out;

	encode_matrix =  kmalloc(m * k, GFP_KERNEL);
	if (encode_matrix == NULL)
		goto out;

	gf_gen_cauchy1_matrix(encode_matrix, m, k);
	ec_init_tables(k, p, &encode_matrix[k * k], g_tbls);
	ec_encode_data(len, k, p, g_tbls, stripes, &stripes[k]);


	for (i = 0; i < p; i++)
		for (j = 0; j < len; j++)
			if (stripes[i + k][j] != er[i]) {
				pr_err(PREFIX " Wrong value for len:%d p:%d pos:%d Expected 0x%02x but got 0x%02x\n",
				       run_id, len, i, j,
				       er[i], stripes[i + k][j]);
				goto out;
			}

	rc = 0;
 out:
	kfree(buf);
	kfree(g_tbls);
	kfree(encode_matrix);
	return rc;
}

/*
 * ec_test_01() reads only tbl[0]..tbl[4] of each region table.  Encode
 * varied data with the table path (4096) and the gf_mul() fallback (256)
 * and compare, so every table entry is checked.
 */
static int ec_test_02(void)
{
	int len = 4096, cmp = 256;
	int i, j, k = 5, p = 3, m = k + p;
	__u8 *stripes[MAX_EC_STRIPES];
	__u8 *encode_matrix = NULL;
	__u8 *g_tbls = NULL;
	__u8 *saved = NULL;
	__u8 *buf = NULL;
	int rc = -1;

	buf = kmalloc(m * len, GFP_KERNEL);
	saved = kmalloc(p * cmp, GFP_KERNEL);
	g_tbls = kmalloc(k * p * 32, GFP_KERNEL);
	encode_matrix = kmalloc(m * k, GFP_KERNEL);
	if (!buf || !saved || !g_tbls || !encode_matrix)
		goto out;

	for (i = 0; i < m; i++) {
		stripes[i] = &buf[i * len];
		for (j = 0; j < len; j++)
			stripes[i][j] = (j + i * 37) & 0xff;
	}

	gf_gen_cauchy1_matrix(encode_matrix, m, k);
	ec_init_tables(k, p, &encode_matrix[k * k], g_tbls);

	ec_encode_data(len, k, p, g_tbls, stripes, &stripes[k]);
	for (i = 0; i < p; i++)
		memcpy(&saved[i * cmp], stripes[k + i], cmp);

	ec_encode_data(cmp, k, p, g_tbls, stripes, &stripes[k]);
	for (i = 0; i < p; i++)
		for (j = 0; j < cmp; j++)
			if (stripes[k + i][j] != saved[i * cmp + j]) {
				pr_err(PREFIX " table/fallback mismatch p:%d pos:%d 0x%02x != 0x%02x\n",
				       run_id, i, j, saved[i * cmp + j],
				       stripes[k + i][j]);
				goto out;
			}

	rc = 0;
out:
	kfree(buf);
	kfree(saved);
	kfree(g_tbls);
	kfree(encode_matrix);
	return rc;
}

/*
 * ec_test_01() reaches ec_encode_data_base() only: 4096 goes through
 * its region-table path, 256 is below GF_REGION_TBL_MIN_LEN and takes
 * the scalar fallback. The other *_base routines are not covered here.
 * The expected parities do not depend on len, since every data
 * stripe is filled with a constant.
 */
static const int ec_test_lens[] = { 4096, 256 };

static int __init ec_test_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ec_test_lens); i++) {
		if (ec_test_01(ec_test_lens[i])) {
			pr_err(PREFIX " EC test len:%d failed\n",
			       run_id, ec_test_lens[i]);
			return -1;
		}
	}
	if (ec_test_02()) {
		pr_err(PREFIX " EC differential test failed\n", run_id);
		return -1;
	}
	/* below message is checked in sanity.sh test_129 */
	pr_err(PREFIX " EC test passed\n", run_id);

	return 0;
}

static void __exit ec_test_exit(void)
{
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre erasure coding test module");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(ec_test_init);
module_exit(ec_test_exit);
