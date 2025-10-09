// SPDX-License-Identifier: BSD-2-Clause
/**********************************************************************
 * Copyright(c) 2011-2015 Intel Corporation All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *    Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *    Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *    Neither the name of Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
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

#include <linux/limits.h>
#include <linux/module.h>
#include <linux/string.h>	/* for memset */

#include "erasure_code.h"

void ec_init_tables(int k, int rows, unsigned char *a, unsigned char *g_tbls);
EXPORT_SYMBOL(ec_init_tables);

void gf_gen_cauchy1_matrix(unsigned char *a, int m, int k);
EXPORT_SYMBOL(gf_gen_cauchy1_matrix);

int gf_invert_matrix(unsigned char *in_mat, unsigned char *out_mat,
		     const int n);
EXPORT_SYMBOL(gf_invert_matrix);

void
ec_encode_data(int len, int srcs, int dests, unsigned char *v,
	       unsigned char **src, unsigned char **dest);
EXPORT_SYMBOL(ec_encode_data);

static int __init ec_init(void)
{
	return 0;
}

static void __exit ec_exit(void)
{
}

MODULE_AUTHOR("Intel Corporation");
MODULE_DESCRIPTION("M to N erasure code handling");
MODULE_VERSION("1.0.0");
MODULE_LICENSE("Dual BSD/GPL");

module_init(ec_init);
module_exit(ec_exit);
