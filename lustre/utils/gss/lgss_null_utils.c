// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015, Trustees of Indiana University
 *
 * Author: Jeremy Filizetti <jfilizet@iu.edu>
 */

#include <string.h>
#include <time.h>
#include "lgss_utils.h"

static int lgss_null_prepare_cred(struct lgss_cred *cred)
{
	uint64_t tmp;

	cred->lc_mech_token.value = malloc(sizeof(uint64_t));
	if (!cred->lc_mech_token.value)
		return -1;
	cred->lc_mech_token.length = sizeof(uint64_t);

	/* random token so it's not cached by the other side */
	tmp = random();
	tmp <<= 32;

	/* Sec part flags needed on the other end */
	tmp |= cred->lc_root_flags;

	/* big-endian for the wire */
	tmp = htobe64(tmp);
	memcpy(cred->lc_mech_token.value, &tmp, cred->lc_mech_token.length);

	return 0;
}

static void lgss_null_release_cred(struct lgss_cred *cred)
{
	free(cred->lc_mech_token.value);
}

static int lgss_null_validate_cred(struct lgss_cred *cred,
				   gss_buffer_desc *token,
				   gss_buffer_desc *ctx_token)
{
	if (token->length <= 0)
		return -1;

	ctx_token->length = token->length;
	ctx_token->value = malloc(ctx_token->length);
	memcpy(ctx_token->value, token->value, ctx_token->length);

	return 0;
}
struct lgss_mech_type lgss_mech_null = {
	.lmt_name		= "gssnull",
	.lmt_mech_n		= LGSS_MECH_NULL,
	.lmt_prepare_cred	= lgss_null_prepare_cred,
	.lmt_release_cred	= lgss_null_release_cred,
	.lmt_validate_cred	= lgss_null_validate_cred,
};
