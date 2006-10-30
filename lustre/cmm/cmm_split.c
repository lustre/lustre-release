/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/cmm/cmm_split.c
 *  Lustre splitting dir
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Alex Thomas  <alex@clusterfs.com>
 *           Wang Di      <wangdi@clusterfs.com>
 *           Yury Umanets <umka@clusterfs.com>
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

enum {
        CMM_SPLIT_SIZE =  64 * 1024
};

enum {
        CMM_NO_SPLIT_EXPECTED = 0,
        CMM_EXPECT_SPLIT      = 1,
        CMM_NOT_SPLITTABLE    = 2
};

#define CMM_SPLIT_PAGE_COUNT 1

/*
 * This function checks if passed @name come to correct server (local MDT). If
 * not - return -ERESTART and let client know that dir was split and client
 * needs to chose correct stripe.
 */
int cmm_split_check(const struct lu_env *env, struct md_object *mp,
                    const char *name)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mp));
        struct md_attr *ma = &cmm_env_info(env)->cmi_ma;
        int rc;
        ENTRY;
        
        if (cmm->cmm_tgt_count == 0)
                RETURN(0);

        /* Try to get the LMV EA size */
        memset(ma, 0, sizeof(*ma));
        ma->ma_need = MA_LMV;
        rc = mo_attr_get(env, mp, ma);
        if (rc)
                RETURN(rc);
        
        /* No LMV just return */
        if (!(ma->ma_valid & MA_LMV))
                RETURN(0);

        LASSERT(ma->ma_lmv_size > 0);
        OBD_ALLOC(ma->ma_lmv, ma->ma_lmv_size);
        if (ma->ma_lmv == NULL)
                RETURN(-ENOMEM);

        /* Get LMV EA, Note: refresh valid here for getting LMV_EA */
        ma->ma_valid &= ~MA_LMV;
        ma->ma_need = MA_LMV;
        rc = mo_attr_get(env, mp, ma);
        if (rc)
                GOTO(cleanup, rc);

        /* Skip checking the slave dirs (mea_count is 0) */
        if (ma->ma_lmv->mea_count != 0) {
                int idx;

                /* 
                 * Get stripe by name to check the name belongs to master dir,
                 * otherwise return the -ERESTART
                 */
                idx = mea_name2idx(ma->ma_lmv, name, strlen(name));
                
                /* 
                 * Check if name came to correct MDT server. We suppose that if
                 * client does not know about split, it sends create operation
                 * to master MDT. And this is master job to say it that dir got
                 * split and client should orward request to correct MDT. This
                 * is why we check here if stripe zero or not. Zero stripe means
                 * master stripe. If stripe calculated from name is not zero -
                 * return -ERESTART.
                 */
                if (idx != 0)
                        rc = -ERESTART;
        }
        EXIT;
cleanup:
        OBD_FREE(ma->ma_lmv, ma->ma_lmv_size);
        return rc;
}

/*
 * Return preferable access mode to caller taking into account possible split
 * and the fact of existing not splittable dirs in principle.
 */
int cmm_split_access(const struct lu_env *env, struct md_object *mo,
                     mdl_mode_t lm)
{
        struct md_attr *ma = &cmm_env_info(env)->cmi_ma;
        int rc, split;
        ENTRY;

        memset(ma, 0, sizeof(*ma));
        
        /*
         * Check only if we need protection from split.  If not - mdt handles
         * other cases.
         */
        rc = cmm_split_expect(env, mo, ma, &split);
        if (rc) {
                CERROR("Can't check for possible split, rc %d\n", rc);
                RETURN(MDL_MINMODE);
        }

        /*
         * Do not take PDO lock on non-splittable objects if this is not PW,
         * this should speed things up a bit.
         */
        if (split == CMM_NOT_SPLITTABLE && lm != MDL_PW)
                RETURN(MDL_NL);

        /* Protect splitting by exclusive lock. */
        if (split == CMM_EXPECT_SPLIT && lm == MDL_PW)
                RETURN(MDL_EX);

        /* 
         * Have no idea about lock mode, let it be what higher layer wants.
         */
        RETURN(MDL_MINMODE);
}

/* Check if split is expected for current thead. */
int cmm_split_expect(const struct lu_env *env, struct md_object *mo,
                     struct md_attr *ma, int *split)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct lu_fid root_fid;
        int rc;
        ENTRY;

        /* No need split for single MDS */
        if (cmm->cmm_tgt_count == 0) {
                *split = CMM_NO_SPLIT_EXPECTED;
                RETURN(0);
        }

        /* No need split for Root object */
        rc = cmm_child_ops(cmm)->mdo_root_get(env, cmm->cmm_child, &root_fid);
        if (rc)
                RETURN(rc);

        if (lu_fid_eq(&root_fid, cmm2fid(md2cmm_obj(mo)))) {
                *split = CMM_NO_SPLIT_EXPECTED;
                RETURN(0);
        }

        /*
         * Assumption: ma_valid = 0 here, we only need get
         * inode and lmv_size for this get_attr
         */
        LASSERT(ma->ma_valid == 0); 
        ma->ma_need = MA_INODE | MA_LMV;
        rc = mo_attr_get(env, mo, ma);
        if (rc)
                RETURN(rc);

        /* No need split for already split object */
        if (ma->ma_valid & MA_LMV) {
                LASSERT(ma->ma_lmv_size > 0);
                *split = CMM_NOT_SPLITTABLE;
                RETURN(0);
        }

        /* No need split for object whose size < CMM_SPLIT_SIZE */
        if (ma->ma_attr.la_size < CMM_SPLIT_SIZE) {
                *split = CMM_NO_SPLIT_EXPECTED;
                RETURN(0);
        }

        *split = CMM_EXPECT_SPLIT;
        RETURN(0);
}

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

/*
 * Allocate new on passed @mc for slave object which is going to create there
 * soon.
 */
static int cmm_split_fid_alloc(const struct lu_env *env, 
                               struct cmm_device *cmm,
                               struct mdc_device *mc, 
                               struct lu_fid *fid)
{
        int rc;
        ENTRY;

        LASSERT(cmm != NULL && mc != NULL && fid != NULL);

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

/* Allocate new slave object on passed @mc */
static int cmm_split_slave_create(const struct lu_env *env, 
                                  struct cmm_device *cmm,
                                  struct mdc_device *mc,
                                  struct lu_fid *fid, 
                                  struct md_attr *ma,
                                  struct lmv_stripe_md *lmv,
                                  int lmv_size)
{
        struct md_create_spec *spec;
        struct cmm_object *obj;
        int rc;
        ENTRY;

        /* Allocate new fid and store it to @fid */
        rc = cmm_split_fid_alloc(env, cmm, mc, fid);
        if (rc) {
                CERROR("Can't alloc new fid on "LPU64
                       ", rc %d\n", mc->mc_num, rc);
                RETURN(rc);
        }

        /* Allocate new object on @mc */
        obj = cmm_object_find(env, cmm, fid);
        if (IS_ERR(obj))
                RETURN(PTR_ERR(obj));

        OBD_ALLOC_PTR(spec);
        if (spec == NULL)
                RETURN(-ENOMEM);

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

/*
 * Create so many slaves as number of stripes. This is called in split time
 * before sending pages to slaves.
 */
static int cmm_split_slaves_create(const struct lu_env *env,
                                   struct md_object *mo,
                                   struct md_attr *ma)
{
        struct cmm_device    *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct lu_fid        *lf  = cmm2fid(md2cmm_obj(mo));
        struct lmv_stripe_md *slave_lmv = NULL;
        struct mdc_device    *mc, *tmp;
        struct lmv_stripe_md *lmv;
        int i = 1, rc = 0;
        ENTRY;

        /* Init the split MEA */
        lmv = ma->ma_lmv;
        lmv->mea_master = cmm->cmm_local_num;
        lmv->mea_magic = MEA_MAGIC_HASH_SEGMENT;
        lmv->mea_count = cmm->cmm_tgt_count + 1;

        /* 
         * Store master FID to local node idx number. Local node is always
         * master and its stripe number if 0.
         */
        lmv->mea_ids[0] = *lf;

        OBD_ALLOC_PTR(slave_lmv);
        if (slave_lmv == NULL)
                RETURN(-ENOMEM);

        slave_lmv->mea_master = cmm->cmm_local_num;
        slave_lmv->mea_magic = MEA_MAGIC_HASH_SEGMENT;
        slave_lmv->mea_count = 0;

        list_for_each_entry_safe(mc, tmp, &cmm->cmm_targets, mc_linkage) {
                rc = cmm_split_slave_create(env, cmm, mc, &lmv->mea_ids[i],
                                            ma, slave_lmv, sizeof(*slave_lmv));
                if (rc)
                        GOTO(cleanup, rc);
                i++;
        }

        ma->ma_valid |= MA_LMV;
        EXIT;
cleanup:
        OBD_FREE_PTR(slave_lmv);
        return rc;
}

/* Remove one entry from local MDT. */
static int cmm_split_remove_entry(const struct lu_env *env,
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
                /* 
                 * XXX: These days only cross-ref dirs are possible, so for the
                 * sake of simplicity, in split, we suppose that all cross-ref
                 * names pint to directory and do not do additional getattr to
                 * remote MDT.
                 */
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
         * This @ent will be transferred to slave MDS and insert it there, so in
         * the slave MDS, we should know whether this object is dir or not, so
         * use the highest bit of the hash to indicate that (because we do not
         * use highest bit of hash).
         */
        if (is_dir)
                ent->lde_hash |= MAX_HASH_HIGHEST_BIT;
        EXIT;
cleanup:
        cmm_object_put(env, obj);
        return rc;
}

/*
 * Remove all entries from passed page. These entries are going to remote MDT
 * and thus should be removed locally.
 */
static int cmm_split_remove_page(const struct lu_env *env,
                                 struct md_object *mo,
                                 struct lu_rdpg *rdpg,
                                 __u32 hash_end, __u32 *len)
{
        struct lu_dirpage *dp;
        struct lu_dirent  *ent;
        int rc = 0;
        ENTRY;

        kmap(rdpg->rp_pages[0]);
        dp = page_address(rdpg->rp_pages[0]);

        /* If page is empty return zero len. */
        if (lu_dirent_start(dp) == NULL) {
                *len = 0;
                GOTO(unmap, rc = 0);
        }
        
        for (ent = lu_dirent_start(dp); ent != NULL;
             ent = lu_dirent_next(ent)) {
                if (ent->lde_hash < hash_end) {
                        rc = cmm_split_remove_entry(env, mo, ent);
                        if (rc) {
                                CERROR("Can not del %s rc %d\n",
                                       ent->lde_name, rc);
                                GOTO(unmap, rc);
                        }
                } else {
                        if (ent != lu_dirent_start(dp))
                                *len = (int)((__u32)ent - (__u32)dp);
                        else
                                *len = 0;
                        GOTO(unmap, 0);
                }
        }
        *len =  CFS_PAGE_SIZE;
        EXIT;
unmap:
        kunmap(rdpg->rp_pages[0]);
        return rc;
}

/* Send one page to remote MDT for creating entries there. */
static int cmm_split_send_page(const struct lu_env *env,
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

/* Read one page of entries from local MDT. */
static int cmm_split_read_page(const struct lu_env *env, 
                               struct md_object *mo,
                               struct lu_rdpg *rdpg)
{
        int rc;
        ENTRY;
        memset(kmap(rdpg->rp_pages[0]), 0, CFS_PAGE_SIZE);
        kunmap(rdpg->rp_pages[0]);
        rc = mo_readpage(env, md_object_next(mo), rdpg);
        RETURN(rc);
}

/* 
 * This function performs migration of all pages with entries which fit into one
 * stripe and one hash segment.
 */
static int cmm_split_process_stripe(const struct lu_env *env,
                                    struct md_object *mo,
                                    struct lu_rdpg *rdpg, 
                                    struct lu_fid *lf,
                                    __u32 end)
{
        int rc, done = 0;
        ENTRY;

        LASSERT(rdpg->rp_npages == 1);
        do {
                struct lu_dirpage *ldp;
                __u32 len = 0;

                /* Read one page from local MDT. */
                rc = cmm_split_read_page(env, mo, rdpg);
                if (rc) {
                        CERROR("Error in readpage: %d\n", rc);
                        RETURN(rc);
                }

                /* Remove local entries which are going to remite MDT. */
                rc = cmm_split_remove_page(env, mo, rdpg, end, &len);
                if (rc) {
                        CERROR("Error in remove stripe entries: %d\n", rc);
                        RETURN(rc);
                }

                /* Send entries page to slave MDT. */
                if (len > 0) {
                        rc = cmm_split_send_page(env, mo, rdpg, lf, len);
                        if (rc) {
                                CERROR("Error in sending page: %d\n", rc);
                                RETURN(rc);
                        }
                }

                kmap(rdpg->rp_pages[0]);
                ldp = page_address(rdpg->rp_pages[0]);
                if (ldp->ldp_hash_end >= end)
                        done = 1;

                rdpg->rp_hash = ldp->ldp_hash_end;
                kunmap(rdpg->rp_pages[0]);
        } while (!done);

        RETURN(rc);
}

static int cmm_split_process_dir(const struct lu_env *env,
                                 struct md_object *mo,
                                 struct md_attr *ma)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct lu_rdpg *rdpg = NULL;
        __u32 hash_segement;
        int rc = 0, i;
        ENTRY;

        OBD_ALLOC_PTR(rdpg);
        if (!rdpg)
                RETURN(-ENOMEM);

        rdpg->rp_npages = CMM_SPLIT_PAGE_COUNT;
        rdpg->rp_count  = CFS_PAGE_SIZE * rdpg->rp_npages;

        OBD_ALLOC(rdpg->rp_pages, rdpg->rp_npages * sizeof(rdpg->rp_pages[0]));
        if (rdpg->rp_pages == NULL)
                GOTO(free_rdpg, rc = -ENOMEM);

        for (i = 0; i < rdpg->rp_npages; i++) {
                rdpg->rp_pages[i] = alloc_pages(GFP_KERNEL, 0);
                if (rdpg->rp_pages[i] == NULL)
                        GOTO(cleanup, rc = -ENOMEM);
        }

        LASSERT(ma->ma_valid & MA_LMV);
        hash_segement = MAX_HASH_SIZE / (cmm->cmm_tgt_count + 1);
        for (i = 1; i < cmm->cmm_tgt_count + 1; i++) {
                struct lu_fid *lf;
                __u32 hash_end;

                lf = &ma->ma_lmv->mea_ids[i];

                rdpg->rp_hash = i * hash_segement;
                hash_end = rdpg->rp_hash + hash_segement;
                rc = cmm_split_process_stripe(env, mo, rdpg, lf, hash_end);
                if (rc) {
                        CERROR("Error (rc = %d) while splitting for %d: fid="
                               DFID", %08x:%08x\n", rc, i, PFID(lf), 
                               rdpg->rp_hash, hash_end);
                        GOTO(cleanup, rc);
                }
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

#define CMM_MD_SIZE(stripes)  (sizeof(struct lmv_stripe_md) +  \
                               (stripes) * sizeof(struct lu_fid))

int cmm_split_try(const struct lu_env *env, struct md_object *mo)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct md_attr    *ma = &cmm_env_info(env)->cmi_ma;
        struct lu_buf     *buf;
        int rc = 0, split;
        ENTRY;

        LASSERT(S_ISDIR(lu_object_attr(&mo->mo_lu)));
        memset(ma, 0, sizeof(*ma));

        /* Step1: Checking whether the dir needs to be split. */
        rc = cmm_split_expect(env, mo, ma, &split);
        if (rc)
                RETURN(rc);

        if (split == CMM_NOT_SPLITTABLE) {
                /* Let caller know that dir is already split. */
                RETURN(-EALREADY);
        } else if (split == CMM_NO_SPLIT_EXPECTED) {
                /* No split is expected, caller may proceed with create. */
                RETURN(0);
        } else {
                /* Split should be done now, let's do it. */
                CWARN("Dir "DFID" is going to split\n",
                      PFID(lu_object_fid(&mo->mo_lu)));
        }

        /*
         * Disable transacrions for split, since there will be so many trans in
         * this one ops, confilct with current recovery design.
         */
        rc = cmm_upcall(env, &cmm->cmm_md_dev, MD_NO_TRANS);
        if (rc) {
                CERROR("Can't disable trans for split, rc %d\n", rc);
                RETURN(rc);
        }

        /* Step2: Prepare the md memory */
        ma->ma_lmv_size = CMM_MD_SIZE(cmm->cmm_tgt_count + 1);
        OBD_ALLOC(ma->ma_lmv, ma->ma_lmv_size);
        if (ma->ma_lmv == NULL)
                RETURN(-ENOMEM);

        /* Step3: Create slave objects and fill the ma->ma_lmv */
        rc = cmm_split_slaves_create(env, mo, ma);
        if (rc) {
                CERROR("Can't create slaves for split, rc %d\n", rc);
                GOTO(cleanup, rc);
        }

        /* Step4: Scan and split the object. */
        rc = cmm_split_process_dir(env, mo, ma);
        if (rc) {
                CERROR("Can't scan and split, rc %d\n", rc);
                GOTO(cleanup, rc);
        }

        /* Step5: Set mea to the master object. */
        LASSERT(ma->ma_valid & MA_LMV);
        buf = cmm_buf_get(env, ma->ma_lmv, ma->ma_lmv_size);
        rc = mo_xattr_set(env, md_object_next(mo), buf,
                          MDS_LMV_MD_NAME, 0);
        if (rc) {
                CERROR("Can't set MEA to master dir, " "rc %d\n", rc);
                GOTO(cleanup, rc);
        }

        /* Finally, split succeed, tell client to recreate the object */
        CWARN("Dir "DFID" has been split\n", PFID(lu_object_fid(&mo->mo_lu)));
        rc = -ERESTART;
        EXIT;
cleanup:
        OBD_FREE(ma->ma_lmv, ma->ma_lmv_size);
        return rc;
}
