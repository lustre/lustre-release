/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Modifications for Lustre
 * Copyright 2004, Cluster File Systems, Inc.
 * All rights reserved
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
 *  linux/net/sunrpc/gss_krb5_seqnum.c
 *
 *  Adapted from MIT Kerberos 5-1.2.1 lib/gssapi/krb5/util_seqnum.c
 *
 *  Copyright (c) 2000 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Andy Adamson   <andros@umich.edu>
 */

/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
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

__s32
krb5_make_seq_num(struct crypto_tfm *key,
                  int direction,
                  __s32 seqnum,
                  unsigned char *cksum,
                  unsigned char *buf)
{
        unsigned char plain[8];

        plain[0] = (unsigned char) (seqnum & 0xff);
        plain[1] = (unsigned char) ((seqnum >> 8) & 0xff);
        plain[2] = (unsigned char) ((seqnum >> 16) & 0xff);
        plain[3] = (unsigned char) ((seqnum >> 24) & 0xff);

        plain[4] = direction;
        plain[5] = direction;
        plain[6] = direction;
        plain[7] = direction;

        return krb5_encrypt(key, cksum, plain, buf, 8);
}

__s32
krb5_get_seq_num(struct crypto_tfm *key,
                 unsigned char *cksum,
                 unsigned char *buf,
                 int *direction,
                 __s32 * seqnum)
{
        __s32 code;
        unsigned char plain[8];

        if ((code = krb5_decrypt(key, cksum, buf, plain, 8)))
                return code;

        if ((plain[4] != plain[5]) || (plain[4] != plain[6])
                                   || (plain[4] != plain[7]))
                return (__s32)KG_BAD_SEQ;

        *direction = plain[4];

        *seqnum = ((plain[0]) |
                   (plain[1] << 8) | (plain[2] << 16) | (plain[3] << 24));

        return (0);
}
