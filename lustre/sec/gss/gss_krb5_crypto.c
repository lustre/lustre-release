/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Modifications for Lustre
 * Copyright 2004, Cluster File Systems, Inc.
 * All rights reserved
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
 *  linux/net/sunrpc/gss_krb5_crypto.c
 *
 *  Copyright (c) 2000 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson   <andros@umich.edu>
 *  Bruce Fields   <bfields@umich.edu>
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_SEC
#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#else
#include <liblustre.h>
//#include "../kcrypto/libcrypto.h"
#endif

#include <libcfs/kp30.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_net.h>
#include <linux/lustre_import.h>
#include <linux/lustre_sec.h>

#include "gss_err.h"
#include "gss_internal.h"
#include "gss_api.h"
#include "gss_krb5.h"

__u32
krb5_encrypt(struct crypto_tfm *tfm,
             void * iv,
             void * in,
             void * out,
             int length)
{
        __u32 ret = -EINVAL;
#ifdef __KERNEL__
        struct scatterlist sg[1];
        __u8 local_iv[16] = {0};

        if (length % crypto_tfm_alg_blocksize(tfm) != 0)
                goto out;

        if (crypto_tfm_alg_ivsize(tfm) > 16) {
                CERROR("tfm iv size to large %d\n", crypto_tfm_alg_ivsize(tfm));
                goto out;
        }

        if (iv)
                memcpy(local_iv, iv, crypto_tfm_alg_ivsize(tfm));

        memcpy(out, in, length);
        sg[0].page = virt_to_page(out);
        sg[0].offset = offset_in_page(out);
        sg[0].length = length;

        ret = crypto_cipher_encrypt_iv(tfm, sg, sg, length, local_iv);

out:
#endif	
        return(ret);
}

//EXPORT_SYMBOL(krb5_encrypt);

__u32
krb5_decrypt(struct crypto_tfm *tfm,
             void * iv,
             void * in,
             void * out,
             int length)
{
        __u32 ret = -EINVAL;
#ifdef __KERNEL__
        struct scatterlist sg[1];
        __u8 local_iv[16] = {0};

        if (length % crypto_tfm_alg_blocksize(tfm) != 0)
                goto out;

        if (crypto_tfm_alg_ivsize(tfm) > 16) {
                CERROR("tfm iv size to large %d\n", crypto_tfm_alg_ivsize(tfm));
                goto out;
        }
        if (iv)
                memcpy(local_iv,iv, crypto_tfm_alg_ivsize(tfm));

        memcpy(out, in, length);
        sg[0].page = virt_to_page(out);
        sg[0].offset = offset_in_page(out);
        sg[0].length = length;

        ret = crypto_cipher_decrypt_iv(tfm, sg, sg, length, local_iv);

out:
#endif
        return(ret);
}

//EXPORT_SYMBOL(krb5_decrypt);

#ifdef __KERNEL__
void
buf_to_sg(struct scatterlist *sg, char *ptr, int len)
{
        sg->page = virt_to_page(ptr);
        sg->offset = offset_in_page(ptr);
        sg->length = len;
}

/* checksum the plaintext data and hdrlen bytes of the token header */
__s32
make_checksum(__s32 cksumtype,
              char *header, int hdrlen,
              rawobj_t *body,
              rawobj_t *cksum)
{
        char                           *cksumname;
        struct crypto_tfm              *tfm = NULL; /* XXX add to ctx? */
        struct scatterlist              sg[1];
        __u32                           code = GSS_S_FAILURE;

        switch (cksumtype) {
                case CKSUMTYPE_RSA_MD5:
                        cksumname = "md5";
                        break;
                default:
                        CERROR("unsupported checksum %d", cksumtype);
                        goto out;
        }
        if (!(tfm = crypto_alloc_tfm(cksumname, 0)))
                goto out;
        cksum->len = crypto_tfm_alg_digestsize(tfm);
        OBD_ALLOC(cksum->data, cksum->len);
        if (!cksum->data)
                goto out;

        crypto_digest_init(tfm);
        buf_to_sg(sg, header, hdrlen);
        crypto_digest_update(tfm, sg, 1);
        if (body->len) {
                buf_to_sg(sg, (char *)body->data, body->len);
                crypto_digest_update(tfm, sg, 1);
        }

        crypto_digest_final(tfm, cksum->data);
        code = 0;
out:
        if (tfm)
                crypto_free_tfm(tfm);
        return code;
}

//EXPORT_SYMBOL(make_checksum);

static
void obj_to_scatter_list(rawobj_t *obj, struct scatterlist *list,
                         int listlen)
{
        __u8   *ptr = obj->data;
        __u32   size = obj->len;
        int index = 0;

        while (size) {
                LASSERT(index++ < listlen);
                list->page = virt_to_page(ptr);
                list->offset = (int) ptr & (~PAGE_MASK);
                list->length = (list->offset + size) > PAGE_SIZE ?
                                (PAGE_SIZE - list->offset) : size;
                ptr += list->length;
                size -= list->length;
                list++;
        }
}
#endif

int gss_encrypt_rawobj(struct crypto_tfm *tfm,
                       rawobj_t *inobj, rawobj_t *outobj,
                       int enc)
{
        int rc = -EINVAL;
#ifdef __KERNEL__
        struct scatterlist *src_list, *dst_list;
        __u8 local_iv[16] = {0};
        int list_len;
        ENTRY;

        LASSERT(outobj->len >= inobj->len);

        list_len = ((inobj->len + PAGE_SIZE - 1) >> PAGE_SHIFT) + 1;
        OBD_ALLOC(src_list, sizeof(*src_list) * list_len * 2);
        if (!src_list) {
                CERROR("can't alloc %d\n", sizeof(*src_list) * list_len * 2);
                RETURN(-ENOMEM);
        }
        dst_list = src_list + list_len;

        obj_to_scatter_list(inobj, src_list, list_len);
        obj_to_scatter_list(outobj, dst_list, list_len);

        if (enc)
                rc = crypto_cipher_encrypt_iv(tfm, dst_list, src_list,
                                              inobj->len, local_iv);
        else
                rc = crypto_cipher_decrypt_iv(tfm, dst_list, src_list,
                                              inobj->len, local_iv);

        if (rc) {
                CERROR("encrypt error %u\n", rc);
                GOTO(out_free, rc);
        }

        outobj->len = inobj->len;
	EXIT;
out_free:
        OBD_FREE(src_list, sizeof(*src_list) * list_len * 2);
#endif
        return rc;
}
