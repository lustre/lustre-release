/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Modifications for Lustre
 * Copyright 2004, Cluster File Systems, Inc.
 * All rights reserved
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
 * Somewhat simplified version of the gss api.
 *
 * Dug Song <dugsong@monkey.org>
 * Andy Adamson <andros@umich.edu>
 * Bruce Fields <bfields@umich.edu>
 * Copyright (c) 2000 The Regents of the University of Michigan
 *
 * $Id: gss_api.h,v 1.3 2005/04/04 13:12:39 yury Exp $
 */

#ifndef __SEC_GSS_GSS_API_H_
#define __SEC_GSS_GSS_API_H_

struct gss_api_mech;

/* The mechanism-independent gss-api context: */
struct gss_ctx {
        struct gss_api_mech        *mech_type;
        void                       *internal_ctx_id;
};

#define GSS_C_NO_BUFFER                ((rawobj_t) 0)
#define GSS_C_NO_CONTEXT        ((struct gss_ctx *) 0)
#define GSS_C_NULL_OID                ((rawobj_t) 0)

/*XXX  arbitrary length - is this set somewhere? */
#define GSS_OID_MAX_LEN 32

/* gss-api prototypes; note that these are somewhat simplified versions of
 * the prototypes specified in RFC 2744. */
__u32 kgss_import_sec_context(
                rawobj_t                *input_token,
                struct gss_api_mech     *mech,
                struct gss_ctx         **ctx_id);
__u32 kgss_inquire_context(
                struct gss_ctx         *ctx_id,
                __u64                  *endtime);
__u32 kgss_get_mic(
                struct gss_ctx          *ctx_id,
                __u32                    qop,
                rawobj_t                *message,
                rawobj_t                *mic_token);
__u32 kgss_verify_mic(
                struct gss_ctx          *ctx_id,
                rawobj_t                *message,
                rawobj_t                *mic_token,
                __u32                   *qstate);
__u32 kgss_wrap(
                struct gss_ctx          *ctx_id,
                __u32                    qop,
                rawobj_buf_t            *in_token,
                rawobj_t                *out_token);
__u32 kgss_unwrap(
                struct gss_ctx          *ctx_id,
                __u32                    qop,
                rawobj_t                *in_token,
                rawobj_t                *out_token);
__u32 kgss_delete_sec_context(
                struct gss_ctx         **ctx_id);

struct subflavor_desc {
        __u32           subflavor;
        __u32           qop;
        __u32           service;
        char           *name;
};

/* Each mechanism is described by the following struct: */
struct gss_api_mech {
        struct list_head        gm_list;
        struct module          *gm_owner;
        char                   *gm_name;
        rawobj_t                gm_oid;
        atomic_t                gm_count;
        struct gss_api_ops     *gm_ops;
        int                     gm_sf_num;
        struct subflavor_desc  *gm_sfs;
};

/* and must provide the following operations: */
struct gss_api_ops {
        __u32 (*gss_import_sec_context)(
                        rawobj_t               *input_token,
                        struct gss_ctx         *ctx_id);
        __u32 (*gss_inquire_context)(
                        struct gss_ctx         *ctx_id,
                        __u64                  *endtime);
        __u32 (*gss_get_mic)(
                        struct gss_ctx         *ctx_id,
                        __u32                   qop, 
                        rawobj_t               *message,
                        rawobj_t               *mic_token);
        __u32 (*gss_verify_mic)(
                        struct gss_ctx         *ctx_id,
                        rawobj_t               *message,
                        rawobj_t               *mic_token,
                        __u32                  *qstate);
        __u32 (*gss_wrap)(
                        struct gss_ctx         *ctx,
                        __u32                   qop,
                        rawobj_buf_t           *in_token,
                        rawobj_t               *out_token);
        __u32 (*gss_unwrap)(
                        struct gss_ctx         *ctx,
                        __u32                   qop,
                        rawobj_t               *in_token,
                        rawobj_t               *out_token);
        void (*gss_delete_sec_context)(
                        void                   *internal_ctx_id);
};

int kgss_mech_register(struct gss_api_mech *mech);
void kgss_mech_unregister(struct gss_api_mech *mech);

struct gss_api_mech * kgss_OID_to_mech(rawobj_t *);
struct gss_api_mech * kgss_name_to_mech(char *name);
struct gss_api_mech * kgss_subflavor_to_mech(__u32 subflavor);

struct gss_api_mech * kgss_mech_get(struct gss_api_mech *);
void kgss_mech_put(struct gss_api_mech *);

#endif /* __SEC_GSS_GSS_API_H_ */
