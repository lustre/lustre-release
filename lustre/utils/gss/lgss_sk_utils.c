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
	gss_buffer_desc bufs[SK_INIT_BUFFERS];
	uint32_t version;
	uint32_t flags;
	int rc;

	rc = sk_gen_params(skc);
	if (rc)
		return rc;

	/* HMAC is generated in this order */
	version = htobe32(SK_MSG_VERSION);
	bufs[SK_INIT_VERSION].value = &version;
	bufs[SK_INIT_VERSION].length = sizeof(version);
	bufs[SK_INIT_RANDOM].value = &skc->sc_kctx.skc_host_random;
	bufs[SK_INIT_RANDOM].length = sizeof(skc->sc_kctx.skc_host_random);
	bufs[SK_INIT_PUB_KEY] = skc->sc_pub_key;
	bufs[SK_INIT_P] = skc->sc_p;
	bufs[SK_INIT_TARGET] = skc->sc_tgt;
	bufs[SK_INIT_NODEMAP] = skc->sc_nodemap_hash;
	flags = htobe32(skc->sc_flags);
	bufs[SK_INIT_FLAGS].value = &flags;
	bufs[SK_INIT_FLAGS].length = sizeof(flags);

	/* sign all the bufs except HMAC */
	rc = sk_sign_bufs(&skc->sc_kctx.skc_shared_key, bufs,
			  SK_INIT_BUFFERS - 1, EVP_sha256(),
			  &skc->sc_hmac);
	if (rc)
		return rc;

	bufs[SK_INIT_HMAC] = skc->sc_hmac;
	rc = sk_encode_netstring(bufs, SK_INIT_BUFFERS, &cred->lc_mech_token);
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
	gss_buffer_desc bufs[SK_RESP_BUFFERS];
	uint32_t version;
	int i;
	uint32_t rc;

	/* Decode responder buffers and validate */
	i = sk_decode_netstring(bufs, SK_RESP_BUFFERS, token);
	if (i != SK_RESP_BUFFERS) {
		printerr(0, "Invalid token received\n");
		return -EINVAL;
	}

	rc = sk_verify_hmac(skc, bufs, SK_RESP_BUFFERS - 1, EVP_sha256(),
			    &bufs[SK_RESP_HMAC]);
	if (rc != GSS_S_COMPLETE) {
		printerr(0, "Invalid HMAC receieved: 0x%x\n", rc);
		return -EINVAL;
	}

	if (bufs[SK_RESP_VERSION].length != sizeof(version)) {
		printerr(0, "Invalid version received (wrong size)\n");
		return -EINVAL;
	}
	memcpy(&version, bufs[SK_RESP_VERSION].value, sizeof(version));
	version = be32toh(version);
	if (version != SK_MSG_VERSION) {
		printerr(0, "Invalid version received: %d\n", version);
		return -EINVAL;
	}

	/* In the rare event that both the random values are equal the
	 * client has the responsability to retry the connection attempt
	 * otherwise we would leak information about the plain text by
	 * reuusing IVs as both peer and host use the same values other
	 * than the nonce. */
	memcpy(&skc->sc_kctx.skc_peer_random, bufs[SK_RESP_RANDOM].value,
	       sizeof(skc->sc_kctx.skc_peer_random));
	if (skc->sc_kctx.skc_host_random == skc->sc_kctx.skc_peer_random) {
		printerr(0, "Host and peer randoms are equal, must retry to "
			 "ensure unique value for nonce\n");
		return -EAGAIN;
	}

	rc = sk_compute_dh_key(skc, &bufs[SK_RESP_PUB_KEY]);
	if (rc == GSS_S_DEFECTIVE_TOKEN) {
		/* Defective token for short key means we need to retry
		 * because there is a chance that the parameters generated
		 * resulted in a key that is 1 byte short */
		printerr(0, "Short key computed, must retry\n");
		return -EAGAIN;
	} else if (rc != GSS_S_COMPLETE) {
		printerr(0, "Failed to compute session key: 0x%x\n", rc);
		return -EINVAL;
	}

	rc = sk_session_kdf(skc, cred->lc_self_nid, &cred->lc_mech_token,
			    token);
	if (rc) {
		printerr(0, "Failed to calulate derived key\n");
		return -EINVAL;
	}

	rc = sk_compute_keys(skc);
	if (rc) {
		printerr(0, "Failed to compute HMAC and session key\n");
		return -EINVAL;
	}

	if (sk_serialize_kctx(skc, ctx_token)) {
		printerr(0, "Failed to serialize context for kernel\n");
		return -EINVAL;
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
