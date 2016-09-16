/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (C) 2015, Trustees of Indiana University
 *
 * Author: Jeremy Filizetti <jfilizet@iu.edu>
 */

#include <limits.h>
#include <string.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#include "sk_utils.h"
#include "lgss_utils.h"

/**
 * Create the initial shared key credentials
 */
static int lgss_sk_prepare_cred(struct lgss_cred *cred)
{
	uint32_t flags = cred->lc_root_flags;

	switch (cred->lc_svc_type) {
	case 'n':
		flags |= LGSS_SVC_NULL;
		break;
	case 'a':
		flags |= LGSS_SVC_AUTH;
		break;
	case 'i':
		flags |= LGSS_SVC_INTG;
		break;
	case 'p':
		flags |= LGSS_SVC_PRIV;
		break;
	default:
		break;
	}

	cred->lc_mech_cred = sk_create_cred(cred->lc_tgt_uuid, NULL, flags);
	if (cred->lc_mech_cred == NULL) {
		printerr(0, "sk: cannot create credential: %s\n",
			 cred->lc_tgt_uuid);
		return -ENOKEY;
	}

	return 0;
}

/* Free all the sk_cred resources */
static void lgss_sk_release_cred(struct lgss_cred *cred)
{
	struct sk_cred *skc = cred->lc_mech_cred;

	sk_free_cred(skc);
	cred->lc_mech_cred = NULL;
	free(cred->lc_mech_token.value);
	return;
}

/**
 * Session key parameter generation is deferred until here because if privacy
 * mode is enabled the session key parameter generation can take a while
 * depending on the key size used and prepare is called before returning
 * from the request_key upcall by lgss_keyring
 */
static int lgss_sk_using_cred(struct lgss_cred *cred)
{
	struct sk_cred *skc = cred->lc_mech_cred;
	gss_buffer_desc bufs[7];
	uint32_t flags;
	int numbufs = 7;
	int rc;

	rc = sk_gen_params(skc, true);
	if (rc)
		return rc;

	/* HMAC is generated in this order */
	bufs[0] = skc->sc_kctx.skc_iv;
	bufs[1] = skc->sc_p;
	bufs[2] = skc->sc_pub_key;
	bufs[3] = skc->sc_tgt;
	bufs[4] = skc->sc_nodemap_hash;

	/* big endian flags for the wire */
	flags = htobe64(skc->sc_flags);
	bufs[5].value = &flags;
	bufs[5].length = sizeof(flags);

	/* sign all the bufs except HMAC */
	rc = sk_sign_bufs(&skc->sc_kctx.skc_shared_key, bufs, numbufs - 1,
			  EVP_sha256(), &skc->sc_hmac);
	if (rc)
		return rc;

	bufs[6] = skc->sc_hmac;
	rc = sk_encode_netstring(bufs, numbufs, &cred->lc_mech_token);
	if (rc)
		return rc;

	printerr(2, "Created netstring of %zd bytes\n",
		 cred->lc_mech_token.length);

	return 0;
}

static int lgss_sk_validate_cred(struct lgss_cred *cred, gss_buffer_desc *token,
				 gss_buffer_desc *ctx_token)
{
	struct sk_cred *skc = cred->lc_mech_cred;
	gss_buffer_desc bufs[2];
	int numbufs = 2;
	int i;
	uint32_t rc;

	i = sk_decode_netstring(bufs, numbufs, token);
	if (i < numbufs) {
		printerr(0, "Failed to decode netstring\n");
		return -1;
	}

	/* decoded buffers from server should be:
	 * bufs[0] = sc_pub_key
	 * bufs[1] = sc_hmac */
	rc = sk_verify_hmac(skc, bufs, numbufs - 1, EVP_sha256(), &bufs[1]);
	if (rc != GSS_S_COMPLETE) {
		printerr(0, "Invalid HMAC receieved: 0x%x\n", rc);
		return -1;
	}

	rc = sk_compute_key(skc, &bufs[0]);
	if (rc == GSS_S_DEFECTIVE_TOKEN) {
		/* Defective token for short key means we need to retry
		 * because there is a chance that the parameters generated
		 * resulted in a key that is 1 byte short */
		printerr(0, "Short key computed, must retry\n");
		return -EAGAIN;
	} else if (rc != GSS_S_COMPLETE) {
		printerr(0, "Failed to compute session key: 0x%x\n", rc);
		return -1;
	}

	rc = sk_kdf(skc, cred->lc_self_nid, &cred->lc_mech_token);
	if (rc) {
		printerr(0, "Failed to calulate derived key\n");
		return -1;
	}

	if (sk_serialize_kctx(skc, ctx_token)) {
		printerr(0, "Failed to serialize context for kernel\n");
		return -1;
	}

	return 0;
}

struct lgss_mech_type lgss_mech_sk = {
	.lmt_name		= "sk",
	.lmt_mech_n		= LGSS_MECH_SK,
	.lmt_prepare_cred	= lgss_sk_prepare_cred,
	.lmt_release_cred	= lgss_sk_release_cred,
	.lmt_using_cred		= lgss_sk_using_cred,
	.lmt_validate_cred	= lgss_sk_validate_cred,
};
