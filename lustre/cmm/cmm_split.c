/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/cmm/cmm_split.c
 *  Lustre splitting dir
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Alex thomas <alex@clusterfs.com>
 *           Wang Di     <wangdi@clusterfs.com>
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

#include <obd_class.h>
#include <lustre_fid.h>
#include <lustre_mds.h>
#include <lustre_idl.h>
#include "cmm_internal.h"
#include "mdc_internal.h"

#define CMM_NO_SPLIT_EXPECTED   0
#define CMM_EXPECT_SPLIT        1
#define CMM_NO_SPLITTABLE       2

enum {
        SPLIT_SIZE =  12*1024
};

static inline struct lu_fid* cmm2_fid(struct cmm_object *obj)
{
       return &(obj->cmo_obj.mo_lu.lo_header->loh_fid);
}

static int cmm_expect_splitting(const struct lu_context *ctx,
                                struct md_object *mo, struct md_attr *ma)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct lu_fid *fid = NULL;
        int rc = CMM_EXPECT_SPLIT;
        ENTRY;

        if (cmm->cmm_tgt_count == 0)
                GOTO(cleanup, rc = CMM_NO_SPLIT_EXPECTED);

        if (ma->ma_attr.la_size < SPLIT_SIZE)
                GOTO(cleanup, rc = CMM_NO_SPLIT_EXPECTED);

        if (ma->ma_lmv_size)
                GOTO(cleanup, rc = CMM_NO_SPLIT_EXPECTED);

        OBD_ALLOC_PTR(fid);
        rc = cmm_root_get(ctx, &cmm->cmm_md_dev, fid);
        if (rc)
                GOTO(cleanup, rc);

        rc = CMM_EXPECT_SPLIT;

        if (lu_fid_eq(fid, cmm2_fid(md2cmm_obj(mo))))
                GOTO(cleanup, rc = CMM_NO_SPLIT_EXPECTED);

cleanup:
        if (fid)
                OBD_FREE_PTR(fid);
        RETURN(rc);
}

#define cmm_md_size(stripes)                            \
       (sizeof(struct lmv_stripe_md) + (stripes) * sizeof(struct lu_fid))

static int cmm_alloc_fid(const struct lu_context *ctx, struct cmm_device *cmm,
                         struct lu_fid *fid, int count)
{
        struct  mdc_device *mc, *tmp;
        int rc = 0, i = 0;

        LASSERT(count == cmm->cmm_tgt_count);
        /* FIXME: this spin_lock maybe not proper,
         * because fid_alloc may need RPC */
        spin_lock(&cmm->cmm_tgt_guard);
        list_for_each_entry_safe(mc, tmp, &cmm->cmm_targets,
                                 mc_linkage) {
                LASSERT(cmm->cmm_local_num != mc->mc_num);

                rc = obd_fid_alloc(mc->mc_desc.cl_exp, &fid[i], NULL);
                if (rc > 0) {
                        struct lu_site *ls;

                        ls = cmm->cmm_md_dev.md_lu_dev.ld_site;
                        rc = fld_client_create(ls->ls_client_fld,
                                               fid_seq(&fid[i]),
                                               mc->mc_num, ctx);
                }
                if (rc < 0) {
                        spin_unlock(&cmm->cmm_tgt_guard);
                        RETURN(rc);
                }
                i++;
        }
        spin_unlock(&cmm->cmm_tgt_guard);
        LASSERT(i == count);
        if (rc == 1)
                rc = 0;
        RETURN(rc);
}

struct cmm_object *cmm_object_find(const struct lu_context *ctxt,
                                   struct cmm_device *d,
                                   const struct lu_fid *f)
{
        struct lu_object *o;
        struct cmm_object *m;
        ENTRY;

        o = lu_object_find(ctxt, d->cmm_md_dev.md_lu_dev.ld_site, f);
        if (IS_ERR(o))
                m = (struct cmm_object *)o;
        else
                m = lu2cmm_obj(lu_object_locate(o->lo_header,
                               d->cmm_md_dev.md_lu_dev.ld_type));
        RETURN(m);
}

static inline void cmm_object_put(const struct lu_context *ctxt,
                                  struct cmm_object *o)
{
        lu_object_put(ctxt, &o->cmo_obj.mo_lu);
}

static int cmm_creat_remote_obj(const struct lu_context *ctx,
                                struct cmm_device *cmm,
                                struct lu_fid *fid, struct md_attr *ma)
{
        struct cmm_object *obj;
        struct md_create_spec *spec;
        int rc;
        ENTRY;

        obj = cmm_object_find(ctx, cmm, fid);
        if (IS_ERR(obj))
                RETURN(PTR_ERR(obj));

        OBD_ALLOC_PTR(spec);
        spec->u.sp_pfid = fid;
        rc = mo_object_create(ctx, md_object_next(&obj->cmo_obj),
                              spec, ma);
        OBD_FREE_PTR(spec);

        cmm_object_put(ctx, obj);
        RETURN(rc);
}

static int cmm_create_slave_objects(const struct lu_context *ctx,
                                    struct md_object *mo, struct md_attr *ma)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct lmv_stripe_md *lmv = NULL;
        int lmv_size, i, rc;
        struct lu_fid *lf = cmm2_fid(md2cmm_obj(mo));
        ENTRY;

        lmv_size = cmm_md_size(cmm->cmm_tgt_count + 1);

        /* This lmv will be free after finish splitting. */
        OBD_ALLOC(lmv, lmv_size);
        if (!lmv)
                RETURN(-ENOMEM);

        lmv->mea_master = cmm->cmm_local_num;
        lmv->mea_magic = MEA_MAGIC_HASH_SEGMENT;
        lmv->mea_count = cmm->cmm_tgt_count + 1;

        lmv->mea_ids[0] = *lf;

        rc = cmm_alloc_fid(ctx, cmm, &lmv->mea_ids[1], cmm->cmm_tgt_count);
        if (rc)
                GOTO(cleanup, rc);

        for (i = 1; i < cmm->cmm_tgt_count + 1; i ++) {
                rc = cmm_creat_remote_obj(ctx, cmm, &lmv->mea_ids[i], ma);
                if (rc)
                        GOTO(cleanup, rc);
        }

        ma->ma_lmv_size = lmv_size;
        ma->ma_lmv = lmv;
cleanup:
        RETURN(rc);
}

static int cmm_send_split_pages(const struct lu_context *ctx,
                                struct md_object *mo, struct lu_rdpg *rdpg,
                                struct lu_fid *fid, __u32 hash_end)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct cmm_object *obj;
        int rc = 0, i;
        ENTRY;

        obj = cmm_object_find(ctx, cmm, fid);
        if (IS_ERR(obj))
                RETURN(PTR_ERR(obj));

        for (i = 0; i < rdpg->rp_npages; i++) {
                rc = mdc_send_page(cmm, ctx, md_object_next(&obj->cmo_obj),
                                   rdpg->rp_pages[i], hash_end);
                if (rc)
                        break;
        }
        cmm_object_put(ctx, obj);
        RETURN(rc);
}

static int cmm_split_entries(const struct lu_context *ctx, struct md_object *mo,
                             struct lu_rdpg *rdpg, struct lu_fid *lf,
                             __u32 end)
{
        int rc, i;
        ENTRY;

        /* Read splitted page and send them to the slave master */
        do {
                /* init page with '0' */
                for (i = 0; i < rdpg->rp_npages; i++) {
                        memset(kmap(rdpg->rp_pages[i]), 0, CFS_PAGE_SIZE);
                        kunmap(rdpg->rp_pages[i]);
                }

                rc = mo_readpage(ctx, md_object_next(mo), rdpg);

                /* -E2BIG means it already reach the end of the dir */
                if (rc == -E2BIG)
                        RETURN(0);
                if (rc)
                        RETURN(rc);

                rc = cmm_send_split_pages(ctx, mo, rdpg, lf, end);

        } while (rc == 0);

        /* it means already finish splitting this segment */
        if (rc == -E2BIG)
                rc = 0;
        RETURN(rc);
}

#if 0
static int cmm_remove_entries(const struct lu_context *ctx,
                              struct md_object *mo, struct lu_rdpg *rdpg)
{
        struct lu_dirpage *dp;
        struct lu_dirent  *ent;
        int rc = 0, i;
        ENTRY;

        for (i = 0; i < rdpg->rp_npages; i++) {
                kmap(rdpg->rp_pages[i]);
                dp = page_address(rdpg->rp_pages[i]);
                for (ent = lu_dirent_start(dp); ent != NULL;
                                  ent = lu_dirent_next(ent)) {
                        rc = mdo_name_remove(ctx, md_object_next(mo),
                                             ent->lde_name);
                        if (rc) {
                                kunmap(rdpg->rp_pages[i]);
                                RETURN(rc);
                        }
                }
                kunmap(rdpg->rp_pages[i]);
        }
        RETURN(rc);
}
#endif
#define SPLIT_PAGE_COUNT 1
static int cmm_scan_and_split(const struct lu_context *ctx,
                              struct md_object *mo, struct md_attr *ma)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        __u32 hash_segement;
        struct lu_rdpg   *rdpg = NULL;
        int rc = 0, i;

        OBD_ALLOC_PTR(rdpg);
        if (!rdpg)
                RETURN(-ENOMEM);

        rdpg->rp_npages = SPLIT_PAGE_COUNT;
        rdpg->rp_count  = CFS_PAGE_SIZE * rdpg->rp_npages;

        OBD_ALLOC(rdpg->rp_pages, rdpg->rp_npages * sizeof rdpg->rp_pages[0]);
        if (rdpg->rp_pages == NULL)
                GOTO(free_rdpg, rc = -ENOMEM);

        for (i = 0; i < rdpg->rp_npages; i++) {
                rdpg->rp_pages[i] = alloc_pages(GFP_KERNEL, 0);
                if (rdpg->rp_pages[i] == NULL)
                        GOTO(cleanup, rc = -ENOMEM);
        }

        hash_segement = MAX_HASH_SIZE / (cmm->cmm_tgt_count + 1);
        for (i = 1; i < cmm->cmm_tgt_count + 1; i++) {
                struct lu_fid *lf = &ma->ma_lmv->mea_ids[i];
                __u32 hash_end;

                rdpg->rp_hash = i * hash_segement;
                hash_end = rdpg->rp_hash + hash_segement;

                rc = cmm_split_entries(ctx, mo, rdpg, lf, hash_end);
                if (rc)
                        GOTO(cleanup, rc);
        }
cleanup:
        for (i = 0; i < rdpg->rp_npages; i++)
                if (rdpg->rp_pages[i] != NULL)
                        __free_pages(rdpg->rp_pages[i], 0);
        if (rdpg->rp_pages)
                OBD_FREE(rdpg->rp_pages, rdpg->rp_npages *
                                         sizeof rdpg->rp_pages[0]);
free_rdpg:
        if (rdpg)
                OBD_FREE_PTR(rdpg);

        RETURN(rc);
}

int cml_try_to_split(const struct lu_context *ctx, struct md_object *mo)
{
        struct md_attr *ma;
        int rc = 0;
        ENTRY;

        LASSERT(S_ISDIR(lu_object_attr(&mo->mo_lu)));

        OBD_ALLOC_PTR(ma);
        if (ma == NULL)
                RETURN(-ENOMEM);

        ma->ma_need = MA_INODE|MA_LMV;
        rc = mo_attr_get(ctx, mo, ma);
        if (rc)
                GOTO(cleanup, ma);

        /* step1: checking whether the dir need to be splitted */
        rc = cmm_expect_splitting(ctx, mo, ma);
        if (rc != CMM_EXPECT_SPLIT)
                GOTO(cleanup, rc = 0);

        /* step2: create slave objects */
        rc = cmm_create_slave_objects(ctx, mo, ma);
        if (rc)
                GOTO(cleanup, ma);

        /* step3: scan and split the object */
        rc = cmm_scan_and_split(ctx, mo, ma);
        if (rc)
                GOTO(cleanup, ma);

        /* step4: set mea to the master object */
        rc = mo_xattr_set(ctx, md_object_next(mo), ma->ma_lmv, ma->ma_lmv_size,
                          MDS_LMV_MD_NAME, 0);

        if (rc == -ERESTART) 
                CWARN("Dir"DFID" has been split \n", 
                                PFID(lu_object_fid(&mo->mo_lu)));
cleanup:
        if (ma->ma_lmv_size && ma->ma_lmv)
                OBD_FREE(ma->ma_lmv, ma->ma_lmv_size);

        OBD_FREE_PTR(ma);

        RETURN(rc);
}
