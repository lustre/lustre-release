/*
 * Modifications for Lustre
 *
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
 *  linux/include/linux/sunrpc/gss_krb5_types.h
 *
 *  Adapted from MIT Kerberos 5-1.2.1 lib/include/krb5.h,
 *  lib/gssapi/krb5/gssapiP_krb5.h, and others
 *
 *  Copyright (c) 2000 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson   <andros@umich.edu>
 *  Bruce Fields   <bfields@umich.edu>
 */

/*
 * Copyright 1995 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

#ifndef PTLRPC_GSS_UTILS_H
#define PTLRPC_GSS_UTILS_H

#include "gss_internal.h"

struct gss_keyblock {
	rawobj_t		 kb_key;
	struct crypto_blkcipher *kb_tfm;
};

int gss_keyblock_init(struct gss_keyblock *kb, char *alg_name,
		      const int alg_mode);
void gss_keyblock_free(struct gss_keyblock *kb);
int gss_keyblock_dup(struct gss_keyblock *new, struct gss_keyblock *kb);
int gss_get_bytes(char **ptr, const char *end, void *res, size_t len);
int gss_get_rawobj(char **ptr, const char *end, rawobj_t *res);
int gss_get_keyblock(char **ptr, const char *end, struct gss_keyblock *kb,
		     __u32 keysize);
int gss_setup_sgtable(struct sg_table *sgt, struct scatterlist *prealloc_sg,
		      const void *buf, unsigned int buf_len);
void gss_teardown_sgtable(struct sg_table *sgt);
int gss_crypt_generic(struct crypto_blkcipher *tfm, int decrypt, void *iv,
			void *in, void *out, int length);
int gss_digest_hmac(struct crypto_hash *tfm, rawobj_t *key, rawobj_t *hdr,
		    int msgcnt, rawobj_t *msgs, int iovcnt, lnet_kiov_t *iovs,
		    rawobj_t *cksum);
int gss_digest_norm(struct crypto_hash *tfm, struct gss_keyblock *kb,
		    rawobj_t *hdr, int msgcnt, rawobj_t *msgs, int iovcnt,
		    lnet_kiov_t *iovs, rawobj_t *cksum);
int gss_add_padding(rawobj_t *msg, int msg_buflen, int blocksize);
int gss_crypt_rawobjs(struct crypto_blkcipher *tfm, int use_internal_iv,
		      int inobj_cnt, rawobj_t *inobjs, rawobj_t *outobj,
		      int enc);

#endif /* PTLRPC_GSS_UTILS_H */
