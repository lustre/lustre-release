/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/ptlrpc/layout.c
 *  Lustre Metadata Target (mdt) request handler
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_RPC

#ifdef __KERNEL__
#include <linux/module.h>
#else
# include <liblustre.h>
#endif

/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>

#include <obd_support.h>
/* lustre_swab_mdt_body */
#include <lustre/lustre_idl.h>
/* obd2cli_tgt() (required by DEBUG_REQ()) */
#include <obd.h>

/* struct ptlrpc_request, lustre_msg* */
#include <lustre_req_layout.h>

static const struct req_msg_field *empty[] = {}; /* none */

static const struct req_msg_field *mdt_body_only[] = {
        &RMF_MDT_BODY
};

static const struct req_msg_field *mds_statfs_server[] = {
        &RMF_OBD_STATFS
};

static const struct req_msg_field *mds_getattr_name_client[] = {
        &RMF_MDT_BODY,
        &RMF_NAME
};

static const struct req_msg_field *mds_reint_create_client[] = {
        &RMF_REC_CREATE,
        &RMF_NAME
};

static const struct req_format *req_formats[] = {
        &RQF_MDS_GETSTATUS,
        &RQF_MDS_STATFS,
        &RQF_MDS_GETATTR,
        &RQF_MDS_GETATTR_NAME,
        &RQF_MDS_REINT_CREATE
};

struct req_msg_field {
        __u32       rmf_flags;
        const char *rmf_name;
        int         rmf_size;
        void      (*rmf_swabber)(void *);
        int         rmf_offset[ARRAY_SIZE(req_formats)][RCL_NR];
};

enum rmf_flags {
        RMF_F_STRING = 1 << 0
};

struct req_capsule;

/*
 * Request fields.
 */
#define DEFINE_MSGF(name, flags, size, swabber) {       \
        .rmf_name    = (name),                          \
        .rmf_flags   = (flags),                         \
        .rmf_size    = (size),                          \
        .rmf_swabber = (void (*)(void*))(swabber)       \
}

const struct req_msg_field RMF_MDT_BODY =
        DEFINE_MSGF("mdt_body", 0,
                    sizeof(struct mdt_body), lustre_swab_mdt_body);
EXPORT_SYMBOL(RMF_MDT_BODY);

const struct req_msg_field RMF_OBD_STATFS =
        DEFINE_MSGF("obd_statfs", 0,
                    sizeof(struct obd_statfs), lustre_swab_obd_statfs);
EXPORT_SYMBOL(RMF_OBD_STATFS);

const struct req_msg_field RMF_NAME =
        DEFINE_MSGF("name", RMF_F_STRING, 0, NULL);
EXPORT_SYMBOL(RMF_NAME);

const struct req_msg_field RMF_REC_CREATE =
        DEFINE_MSGF("rec_create", 0,
                    sizeof(struct mdt_rec_create), lustre_swab_mdt_rec_create);
EXPORT_SYMBOL(RMF_REC_CREATE);

/*
 * Request formats.
 */

struct req_format {
        const char *rf_name;
        int         rf_idx;
        struct {
                int                          nr;
                const struct req_msg_field **d;
        } rf_fields[RCL_NR];
};

#define DEFINE_REQ_FMT(name, client, client_nr, server, server_nr) {    \
        .rf_name   = name,                                              \
        .rf_fields = {                                                  \
                [RCL_CLIENT] = {                                        \
                        .nr = client_nr,                                \
                        .d  = client                                    \
                },                                                      \
                [RCL_SERVER] = {                                        \
                        .nr = server_nr,                                \
                        .d  = server                                    \
                }                                                       \
        }                                                               \
}

#define DEFINE_REQ_FMT0(name, client, server)                           \
DEFINE_REQ_FMT(name, client, ARRAY_SIZE(client), server, ARRAY_SIZE(server))

const struct req_format RQF_MDS_GETSTATUS =
        DEFINE_REQ_FMT0("MDS_GETSTATUS", empty, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_GETSTATUS);

const struct req_format RQF_MDS_STATFS =
        DEFINE_REQ_FMT0("MDS_STATFS", empty, mds_statfs_server);
EXPORT_SYMBOL(RQF_MDS_STATFS);

const struct req_format RQF_MDS_GETATTR =
        DEFINE_REQ_FMT0("MDS_GETATTR", mdt_body_only, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_GETATTR);

const struct req_format RQF_MDS_GETATTR_NAME =
        DEFINE_REQ_FMT0("MDS_GETATTR_NAME",
                        mds_getattr_name_client, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_GETATTR_NAME);

const struct req_format RQF_MDS_REINT_CREATE =
        DEFINE_REQ_FMT0("MDS_REINT_CREATE",
                        mds_reint_create_client, mdt_body_only);
EXPORT_SYMBOL(RQF_MDS_REINT_CREATE);

int req_layout_init(void)
{
        int i;
        int j;
        int k;

        for (i = 0; i < ARRAY_SIZE(req_formats); ++i) {
                struct req_format *rf;

                rf = (struct req_format *)req_formats[i];
                rf->rf_idx = i;
                for (j = 0; j < RCL_NR; ++j) {
                        for (k = 0; k < rf->rf_fields[j].nr; ++k) {
                                struct req_msg_field *field;

                                field = (typeof(field))rf->rf_fields[j].d[k];
                                LASSERT(field->rmf_offset[i][j] == 0);
                                /*
                                 * k + 1 to detect unused format/field
                                 * combinations.
                                 */
                                field->rmf_offset[i][j] = k + 1;
                        }
                }
        }
        return 0;
}
EXPORT_SYMBOL(req_layout_init);

void req_layout_fini(void)
{
}
EXPORT_SYMBOL(req_layout_fini);

void req_capsule_init(struct req_capsule *pill,
                      struct ptlrpc_request *req, enum req_location location)
{
        LASSERT(location == RCL_SERVER || location == RCL_CLIENT);

        memset(pill, 0, sizeof *pill);
        pill->rc_req = req;
        pill->rc_loc = location;
}
EXPORT_SYMBOL(req_capsule_init);

void req_capsule_fini(struct req_capsule *pill)
{
}
EXPORT_SYMBOL(req_capsule_fini);

static int __req_format_is_sane(const struct req_format *fmt)
{
        return
                0 <= fmt->rf_idx && fmt->rf_idx < ARRAY_SIZE(req_formats) &&
                req_formats[fmt->rf_idx] == fmt;
}

static void __req_capsule_init(struct req_capsule *pill,
                               const struct req_format *fmt,
                               enum req_location loc)
{
        LASSERT(0 <= loc && loc < ARRAY_SIZE(pill->rc_fmt));
        LASSERT(pill->rc_fmt[loc] == NULL);
        LASSERT(ergo(loc != pill->rc_loc, pill->rc_swabbed == 0));
        LASSERT(__req_format_is_sane(fmt));

        pill->rc_fmt[loc] = fmt;
}

void req_capsule_server_init(struct req_capsule *pill,
                             const struct req_format *fmt)
{
        __req_capsule_init(pill, fmt, RCL_SERVER);
}
EXPORT_SYMBOL(req_capsule_server_init);

void req_capsule_client_init(struct req_capsule *pill,
                             const struct req_format *fmt)
{
        __req_capsule_init(pill, fmt, RCL_CLIENT);
}
EXPORT_SYMBOL(req_capsule_client_init);

int req_capsule_start(struct req_capsule *pill,
                      const struct req_format *fmt, int *area)
{
        int i;
        int nr;
        int result;

        LASSERT(pill->rc_loc == RCL_SERVER);

        nr = fmt->rf_fields[RCL_SERVER].nr;
        for (i = 0; i < nr; ++i)
                area[i] = fmt->rf_fields[RCL_SERVER].d[i]->rmf_size;
        req_capsule_server_init(pill, fmt);
        result = lustre_pack_reply(pill->rc_req, nr, area, NULL);
        if (result != 0) {
                DEBUG_REQ(D_ERROR, pill->rc_req,
                          "Failed to pack %d fields in format `%s': ",
                          nr, fmt->rf_name);
        }
        return result;
}
EXPORT_SYMBOL(req_capsule_start);

static void *__req_capsule_get(const struct req_capsule *pill,
                               const struct req_msg_field *field,
                               enum req_location loc)
{
        const struct req_format     *fmt;
        const struct ptlrpc_request *req;
        struct lustre_msg           *msg;
        void                        *value;
        int                          offset;

        void *(*getter)(struct lustre_msg *m, int n, int minlen);

        static const char *rcl_names[RCL_NR] = {
                [RCL_CLIENT] = "client",
                [RCL_SERVER] = "server"
        };

        LASSERT(0 <= loc && loc < ARRAY_SIZE(pill->rc_fmt));
        CLASSERT(ARRAY_SIZE(pill->rc_fmt) == ARRAY_SIZE(field->rmf_offset[0]));

        fmt = pill->rc_fmt[loc];
        LASSERT(fmt != NULL);
        LASSERT(__req_format_is_sane(fmt));

        offset = field->rmf_offset[fmt->rf_idx][loc];
        LASSERT(offset > 0);
        -- offset;
        LASSERT(0 <= offset && offset < (sizeof(pill->rc_swabbed) << 3));

        req = pill->rc_req;
        msg = loc == RCL_CLIENT ? req->rq_reqmsg : req->rq_repmsg;

        getter = (field->rmf_flags & RMF_F_STRING) ?
                (typeof(getter))lustre_msg_string : lustre_msg_buf;

        value = getter(msg, offset, field->rmf_size);

        if (!(pill->rc_swabbed & (1 << offset)) && loc != pill->rc_loc &&
            field->rmf_swabber != NULL && value != NULL &&
            lustre_msg_swabbed(msg))
                field->rmf_swabber(value);
        if (value == NULL)
                DEBUG_REQ(D_ERROR, pill->rc_req,
                          "Wrong buffer for field `%s' (%d) in format `%s': "
                          "%d < %d (%s)\n",
                          field->rmf_name, offset, fmt->rf_name,
                          lustre_msg_buflen(msg, offset), field->rmf_size,
                          rcl_names[loc]);
        return value;
}

const void *req_capsule_client_get(const struct req_capsule *pill,
                                   const struct req_msg_field *field)
{
        return (const void *)__req_capsule_get(pill, field, RCL_CLIENT);
}
EXPORT_SYMBOL(req_capsule_client_get);

void *req_capsule_server_get(const struct req_capsule *pill,
                             const struct req_msg_field *field)
{
        return __req_capsule_get(pill, field, RCL_SERVER);
}
EXPORT_SYMBOL(req_capsule_server_get);

