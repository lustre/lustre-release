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
#include <lustre/lustre_idl.h>
#include "cmm_internal.h"
#include "mdc_internal.h"

#define CMM_NO_SPLIT_EXPECTED   0
#define CMM_EXPECT_SPLIT        1
#define CMM_NO_SPLITTABLE       2

enum {
        SPLIT_SIZE =  64*1024
};

int cmm_mdsnum_check(const struct lu_env *env, struct md_object *mp,
                   const char *name)
{
        struct md_attr *ma = &cmm_env_info(env)->cmi_ma;
        struct lmv_stripe_md *lmv;
        int rc = 0;
        ENTRY;
        memset(ma, 0, sizeof(*ma));
        ma->ma_need = MA_INODE | MA_LMV;
        rc = mo_attr_get(env, mp, ma);
        if (rc)
                RETURN(rc);

        if (ma->ma_valid & MA_LMV) {
                int stripe;
                lmv = ma->ma_lmv = lmv;
                /* 
                 * Get stripe by name to check the name belongs to master
                 * otherwise return the -ERESTART
                 * Master stripe is always 0
                 */
                stripe = mea_name2idx(lmv, name, strlen(name));
                if (stripe != 0)
                        rc = -ERESTART;
        }
        RETURN(rc);
}

static int cmm_expect_splitting(const struct lu_env *env,
                                struct md_object *mo,
                                struct md_attr *ma)
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
        rc = cmm_child_ops(cmm)->mdo_root_get(env, cmm->cmm_child, fid);
        if (rc)
                GOTO(cleanup, rc);

        rc = CMM_EXPECT_SPLIT;

        if (lu_fid_eq(fid, cmm2fid(md2cmm_obj(mo))))
                GOTO(cleanup, rc = CMM_NO_SPLIT_EXPECTED);

        EXIT;
cleanup:
        if (fid)
                OBD_FREE_PTR(fid);
        return rc;
}

#define cmm_md_size(stripes) \
       (sizeof(struct lmv_stripe_md) + (stripes) * sizeof(struct lu_fid))

struct cmm_object *cmm_object_find(const struct lu_env *env,
                                   struct cmm_device *d,
                                   const struct lu_fid *f)
{
        struct lu_object *o;
        struct cmm_object *m;
        ENTRY;

        o = lu_object_find(env, d->cmm_md_dev.md_lu_dev.ld_site, f);
        if (IS_ERR(o))
                m = (struct cmm_object *)o;
        else
                m = lu2cmm_obj(lu_object_locate(o->lo_header,
                               d->cmm_md_dev.md_lu_dev.ld_type));
        RETURN(m);
}

static inline void cmm_object_put(const struct lu_env *env,
                                  struct cmm_object *o)
{
        lu_object_put(env, &o->cmo_obj.mo_lu);
}

static int cmm_object_create(const struct lu_env *env,
                             struct cmm_device *cmm,
                             struct lu_fid *fid,
                             struct md_attr *ma,
                             struct lmv_stripe_md *lmv,
                             int lmv_size)
{
        struct md_create_spec *spec;
        struct cmm_object *obj;
        int rc;
        ENTRY;

        obj = cmm_object_find(env, cmm, fid);
        if (IS_ERR(obj))
                RETURN(PTR_ERR(obj));

        OBD_ALLOC_PTR(spec);

        spec->u.sp_ea.fid = fid;
        spec->u.sp_ea.eadata = lmv;
        spec->u.sp_ea.eadatalen = lmv_size;
        spec->sp_cr_flags |= MDS_CREATE_SLAVE_OBJ;
        rc = mo_object_create(env, md_object_next(&obj->cmo_obj),
                              spec, ma);
        OBD_FREE_PTR(spec);

        cmm_object_put(env, obj);
        RETURN(rc);
}

static int cmm_fid_alloc(const struct lu_env *env,
                         struct cmm_device *cmm,
                         struct mdc_device *mc,
                         struct lu_fid *fid)
{
        int rc;
        ENTRY;

        LASSERT(cmm != NULL);
        LASSERT(mc != NULL);
        LASSERT(fid != NULL);

        down(&mc->mc_fid_sem);

        /* Alloc new fid on @mc. */
        rc = obd_fid_alloc(mc->mc_desc.cl_exp, fid, NULL);
        if (rc > 0) {
                /* Setup FLD for new sequenceif needed. */
                rc = fld_client_create(cmm->cmm_fld, fid_seq(fid),
                                       mc->mc_num, env);
                if (rc)
                        CERROR("Can't create fld entry, rc %d\n", rc);
        }
        up(&mc->mc_fid_sem);
        
        RETURN(rc);
}

static int cmm_slaves_create(const struct lu_env *env,
                             struct md_object *mo,
                             struct md_attr *ma)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct lmv_stripe_md *lmv = NULL, *slave_lmv = NULL;
        struct lu_fid *lf = cmm2fid(md2cmm_obj(mo));
        struct mdc_device *mc, *tmp;
        int lmv_size, i = 1, rc = 0;
        ENTRY;

        lmv_size = cmm_md_size(cmm->cmm_tgt_count + 1);

        /* This lmv will free after finish splitting. */
        OBD_ALLOC(lmv, lmv_size);
        if (!lmv)
                RETURN(-ENOMEM);

        lmv->mea_master = cmm->cmm_local_num;
        lmv->mea_magic = MEA_MAGIC_HASH_SEGMENT;
        lmv->mea_count = cmm->cmm_tgt_count + 1;

        /* Store master FID to local node idx number. */
        lmv->mea_ids[0] = *lf;

        OBD_ALLOC_PTR(slave_lmv);
        if (!slave_lmv)
                GOTO(cleanup, rc = -ENOMEM);

        slave_lmv->mea_master = cmm->cmm_local_num;
        slave_lmv->mea_magic = MEA_MAGIC_HASH_SEGMENT;
        slave_lmv->mea_count = 0;

        list_for_each_entry_safe(mc, tmp, &cmm->cmm_targets, mc_linkage) {
                /* Alloc fid for slave object. */
                rc = cmm_fid_alloc(env, cmm, mc, &lmv->mea_ids[i]);
                if (rc) {
                        CERROR("Can't alloc fid for slave "LPU64", rc %d\n",
                               mc->mc_num, rc);
                        GOTO(cleanup, rc);
                }

                /* Create slave on remote MDT. */
                rc = cmm_object_create(env, cmm, &lmv->mea_ids[i], ma,
                                       slave_lmv, sizeof(*slave_lmv));
                if (rc)
                        GOTO(cleanup, rc);
                i++;
        }

        ma->ma_lmv_size = lmv_size;
        ma->ma_lmv = lmv;
        EXIT;
cleanup:
        if (slave_lmv)
                OBD_FREE_PTR(slave_lmv);
        if (rc && lmv) {
                OBD_FREE(lmv, lmv_size);
                ma->ma_lmv = NULL;
                ma->ma_lmv_size = 0;
        }
        return rc;
}

static int cmm_send_split_pages(const struct lu_env *env,
                                struct md_object *mo,
                                struct lu_rdpg *rdpg,
                                struct lu_fid *fid, int len)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct cmm_object *obj;
        int rc = 0;
        ENTRY;

        obj = cmm_object_find(env, cmm, fid);
        if (IS_ERR(obj))
                RETURN(PTR_ERR(obj));

        rc = mdc_send_page(cmm, env, md_object_next(&obj->cmo_obj),
                           rdpg->rp_pages[0], len);
        cmm_object_put(env, obj);
        RETURN(rc);
}

static int cmm_remove_dir_ent(const struct lu_env *env,
                              struct md_object *mo,
                              struct lu_dirent *ent)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct cmm_object *obj;
        char *name;
        int is_dir, rc;
        ENTRY;

        if (!strncmp(ent->lde_name, ".", ent->lde_namelen) ||
            !strncmp(ent->lde_name, "..", ent->lde_namelen))
                RETURN(0);

        obj = cmm_object_find(env, cmm, &ent->lde_fid);
        if (IS_ERR(obj))
                RETURN(PTR_ERR(obj));

        if (lu_object_exists(&obj->cmo_obj.mo_lu) > 0)
                is_dir = S_ISDIR(lu_object_attr(&obj->cmo_obj.mo_lu));
        else
                /* XXX: is this correct? */
                is_dir = 1;

        OBD_ALLOC(name, ent->lde_namelen + 1);
        if (!name)
                GOTO(cleanup, rc = -ENOMEM);

        memcpy(name, ent->lde_name, ent->lde_namelen);
        rc = mdo_name_remove(env, md_object_next(mo),
                             name, is_dir);
        OBD_FREE(name, ent->lde_namelen + 1);
        if (rc)
                GOTO(cleanup, rc);

        /*
         * This ent will be transferred to slave MDS and insert it there, so in
         * the slave MDS, we should know whether this object is dir or not, so
         * use the highest bit of the hash to indicate that (because we do not
         * use highest bit of hash).
         */
        if (is_dir)
                ent->lde_hash |= MAX_HASH_HIGHEST_BIT;
cleanup:
        cmm_object_put(env, obj);

        RETURN(rc);
}

static int cmm_remove_entries(const struct lu_env *env,
                              struct md_object *mo, struct lu_rdpg *rdpg,
                              __u32 hash_end, __u32 *len)
{
        struct lu_dirpage *dp;
        struct lu_dirent  *ent;
        int rc = 0;
        ENTRY;

        kmap(rdpg->rp_pages[0]);
        dp = page_address(rdpg->rp_pages[0]);
        for (ent = lu_dirent_start(dp); ent != NULL;
             ent = lu_dirent_next(ent)) {
                if (ent->lde_hash < hash_end) {
                        rc = cmm_remove_dir_ent(env, mo, ent);
                        if (rc) {
                                CERROR("Can not del %s rc %d\n", ent->lde_name,
                                                                 rc);
                                GOTO(unmap, rc);
                        }
                } else {
                        if (ent != lu_dirent_start(dp))
                                *len = (int)((__u32)ent - (__u32)dp);
                        else
                                *len = 0;
                        GOTO(unmap, rc);
                }
        }
        *len = CFS_PAGE_SIZE;
        EXIT;
unmap:
        kunmap(rdpg->rp_pages[0]);
        return rc;
}

static int cmm_split_entries(const struct lu_env *env,
                             struct md_object *mo, struct lu_rdpg *rdpg,
                             struct lu_fid *lf, __u32 end)
{
        int rc, done = 0;
        ENTRY;

        LASSERTF(rdpg->rp_npages == 1, "Now Only support split 1 page each time"
                 "npages %d\n", rdpg->rp_npages);

        /* Read split page and send them to the slave master. */
        do {
                struct lu_dirpage *ldp;
                __u32  len = 0;

                /* init page with '0' */
                memset(kmap(rdpg->rp_pages[0]), 0, CFS_PAGE_SIZE);
                kunmap(rdpg->rp_pages[0]);

                rc = mo_readpage(env, md_object_next(mo), rdpg);
                if (rc)
                        RETURN(rc);

                /* Remove the old entries */
                rc = cmm_remove_entries(env, mo, rdpg, end, &len);
                if (rc)
                        RETURN(rc);

                /* Send page to slave object */
                if (len > 0) {
                        rc = cmm_send_split_pages(env, mo, rdpg, lf, len);
                        if (rc)
                                RETURN(rc);
                }

                kmap(rdpg->rp_pages[0]);
                ldp = page_address(rdpg->rp_pages[0]);
                if (ldp->ldp_hash_end >= end) {
                        done = 1;
                }
                rdpg->rp_hash = ldp->ldp_hash_end;
                kunmap(rdpg->rp_pages[0]);
        } while (!done);

        RETURN(rc);
}

#define SPLIT_PAGE_COUNT 1

static int cmm_scan_and_split(const struct lu_env *env,
                              struct md_object *mo,
                              struct md_attr *ma)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct lu_rdpg *rdpg = NULL;
        __u32 hash_segement;
        int rc = 0, i;

        OBD_ALLOC_PTR(rdpg);
        if (!rdpg)
                RETURN(-ENOMEM);

        rdpg->rp_npages = SPLIT_PAGE_COUNT;
        rdpg->rp_count  = CFS_PAGE_SIZE * rdpg->rp_npages;

        OBD_ALLOC(rdpg->rp_pages, rdpg->rp_npages * sizeof(rdpg->rp_pages[0]));
        if (rdpg->rp_pages == NULL)
                GOTO(free_rdpg, rc = -ENOMEM);

        for (i = 0; i < rdpg->rp_npages; i++) {
                rdpg->rp_pages[i] = alloc_pages(GFP_KERNEL, 0);
                if (rdpg->rp_pages[i] == NULL)
                        GOTO(cleanup, rc = -ENOMEM);
        }

        hash_segement = MAX_HASH_SIZE / (cmm->cmm_tgt_count + 1);
        for (i = 1; i < cmm->cmm_tgt_count + 1; i++) {
                struct lu_fid *lf;
                __u32 hash_end;

                lf = &ma->ma_lmv->mea_ids[i];

                rdpg->rp_hash = i * hash_segement;
                hash_end = rdpg->rp_hash + hash_segement;
                rc = cmm_split_entries(env, mo, rdpg, lf, hash_end);
                if (rc)
                        GOTO(cleanup, rc);
        }
        EXIT;
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

        return rc;
}

static struct lu_buf *cmm_buf_get(const struct lu_env *env, void *area,
                                  ssize_t len)
{
        struct lu_buf *buf;

        buf = &cmm_env_info(env)->cmi_buf;
        buf->lb_buf = area;
        buf->lb_len = len;
        return buf;
}

int cml_try_to_split(const struct lu_env *env, struct md_object *mo)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct md_attr *ma = &cmm_env_info(env)->cmi_ma;
        struct lu_buf *buf;
        int rc = 0;
        ENTRY;

        LASSERT(S_ISDIR(lu_object_attr(&mo->mo_lu)));
        
        memset(ma, 0, sizeof(*ma));
        ma->ma_need = MA_INODE | MA_LMV;
        rc = mo_attr_get(env, mo, ma);
        if (rc)
                GOTO(cleanup, ma);

        /* step1: checking whether the dir need to be splitted */
        rc = cmm_expect_splitting(env, mo, ma);
        if (rc != CMM_EXPECT_SPLIT)
                GOTO(cleanup, rc = 0);

        /*
         * Disable trans for splitting, since there will be so many trans in
         * this one ops, confilct with current recovery design.
         */
        rc = cmm_upcall(env, &cmm->cmm_md_dev, MD_NO_TRANS);
        if (rc)
                GOTO(cleanup, rc = 0);

        /* step2: create slave objects */
        rc = cmm_slaves_create(env, mo, ma);
        if (rc)
                GOTO(cleanup, ma);

        /* step3: scan and split the object */
        rc = cmm_scan_and_split(env, mo, ma);
        if (rc)
                GOTO(cleanup, ma);

        buf = cmm_buf_get(env, ma->ma_lmv, ma->ma_lmv_size);
        
        /* step4: set mea to the master object */
        rc = mo_xattr_set(env, md_object_next(mo), buf, MDS_LMV_MD_NAME, 0);
        if (rc == -ERESTART)
                CWARN("Dir "DFID" has been split\n",
                      PFID(lu_object_fid(&mo->mo_lu)));
        EXIT;
cleanup:
        if (ma->ma_lmv_size && ma->ma_lmv)
                OBD_FREE(ma->ma_lmv, ma->ma_lmv_size);
        
        return rc;
}

