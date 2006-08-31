/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  mdd/mdd_orphans.c
 *
 *  Orphan handling code
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Mike Pershin <tappro@clusterfs.com>
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
#define DEBUG_SUBSYSTEM S_MDS

#include <obd.h>
#include <obd_class.h>
#include <lustre_ver.h>
#include <obd_support.h>

#include "mdd_internal.h"

const char orph_index_name[] = "orphans";

static const struct dt_index_features orph_index_features = {
        .dif_flags       = DT_IND_UPDATE,
        .dif_keysize_min = sizeof(struct orph_key),
        .dif_keysize_max = sizeof(struct orph_key),
        .dif_recsize_min = sizeof(loff_t),
        .dif_recsize_max = sizeof(loff_t)
};

enum {
        ORPH_OP_UNLINK,
        ORPH_OP_TRUNCATE
};

static struct orph_key *orph_key_fill(const struct lu_context *ctx,
                                      const struct lu_fid *lf, __u32 op)
{
        struct orph_key *key = &mdd_ctx_info(ctx)->mti_orph_key;
        LASSERT(key);
        key->ok_fid.f_seq = cpu_to_be64(fid_seq(lf));
        key->ok_fid.f_oid = cpu_to_be32(fid_oid(lf));
        key->ok_fid.f_ver = cpu_to_be32(fid_ver(lf));
        key->ok_op = cpu_to_be32(op);
        return key;
}

static int orph_index_insert(const struct lu_context *ctx, 
                             struct mdd_object *obj, __u32 op,
                             loff_t *offset, struct thandle *th)
{
        struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
        struct dt_object *dor = mdd->mdd_orphans;
        struct orph_key *key = orph_key_fill(ctx, mdo2fid(obj), op);
        int rc;
        ENTRY;

        rc = dor->do_index_ops->dio_insert(ctx, dor, (struct dt_rec *)offset,
                                           (struct dt_key *)key, th);
        RETURN(rc);
}

static int orph_index_delete(const struct lu_context *ctx, 
                             struct mdd_object *obj, __u32 op,
                             struct thandle *th)
{
        struct mdd_device *mdd = mdo2mdd(&obj->mod_obj);
        struct dt_object *dor = mdd->mdd_orphans;
        struct orph_key *key = orph_key_fill(ctx, mdo2fid(obj), op);
        int rc;
        ENTRY;

        rc = dor->do_index_ops->dio_delete(ctx, dor,
                                           (struct dt_key *)key, th);
        RETURN(rc);

}
#if 0
static int orph_index_iterate(struct lu_server_orph *orph,
                       const struct lu_context *ctx,
                       seqno_t seq, mdsno_t *mds)
{
        struct dt_object *dt_obj = orph->orph_obj;
        struct dt_rec    *rec = orph_rec(ctx, 0);
        int rc;
        ENTRY;

        rc = dt_obj->do_index_ops->dio_lookup(ctx, dt_obj, rec,
                                              orph_key(ctx, seq));
        if (rc == 0)
                *mds = be64_to_cpu(*(__u64 *)rec);
        RETURN(rc);
}
#endif
int orph_index_init(const struct lu_context *ctx, struct mdd_device *mdd)
{
        struct lu_fid fid;
        struct dt_object *d;
        int rc;
        ENTRY;

        d = dt_store_open(ctx, mdd->mdd_child, orph_index_name, &fid);
        if (!IS_ERR(d)) {
                mdd->mdd_orphans = d;
                rc = d->do_ops->do_index_try(ctx, d, &orph_index_features);
                if (rc == 0)
                        LASSERT(d->do_index_ops != NULL);
                else
                        CERROR("\"%s\" is not an index!\n", orph_index_name);
        } else {
                CERROR("cannot find \"%s\" obj %d\n",
                       orph_index_name, (int)PTR_ERR(d));
                rc = PTR_ERR(d);
        }

        RETURN(rc);
}

void orph_index_fini(const struct lu_context *ctx, struct mdd_device *mdd)
{
        ENTRY;
        if (mdd->mdd_orphans != NULL) {
                if (!IS_ERR(mdd->mdd_orphans))
                        lu_object_put(ctx, &mdd->mdd_orphans->do_lu);
                mdd->mdd_orphans = NULL;
        }
        EXIT;
}

int inline __mdd_orphan_add(const struct lu_context *ctx,
                            struct mdd_object *obj,
                            struct thandle *th)
{
        loff_t offset = 0;
        return orph_index_insert(ctx, obj, ORPH_OP_UNLINK, &offset, th);
}

int inline __mdd_orphan_del(const struct lu_context *ctx,
                            struct mdd_object *obj,
                            struct thandle *th)
{
        return orph_index_delete(ctx, obj, ORPH_OP_UNLINK, th);
}


