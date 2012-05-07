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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/cmm/cmm_split.c
 *
 * Lustre splitting dir
 *
 * Author: Alex Thomas  <alex@clusterfs.com>
 * Author: Wang Di      <wangdi@clusterfs.com>
 * Author: Yury Umanets <umka@clusterfs.com>
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

/**
 * \addtogroup split
 * @{
 */
enum {
        CMM_SPLIT_SIZE =  128 * 1024
};

/**
 * This function checks if passed \a name come to correct server (local MDT).
 *
 * \param mp Parent directory
 * \param name Name to lookup
 * \retval  -ERESTART Let client know that dir was split and client needs to
 * chose correct stripe.
 */
int cmm_split_check(const struct lu_env *env, struct md_object *mp,
                    const char *name)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mp));
        struct md_attr *ma = &cmm_env_info(env)->cmi_ma;
        struct cml_object *clo = md2cml_obj(mp);
        int rc, lmv_size;
        ENTRY;

        cmm_lprocfs_time_start(env);

        /* Not split yet */
        if (clo->clo_split == CMM_SPLIT_NONE ||
            clo->clo_split == CMM_SPLIT_DENIED)
                GOTO(out, rc = 0);

        lmv_size = CMM_MD_SIZE(cmm->cmm_tgt_count + 1);

        /* Try to get the LMV EA */
        memset(ma, 0, sizeof(*ma));

        ma->ma_need = MA_LMV;
        ma->ma_lmv_size = lmv_size;
        OBD_ALLOC(ma->ma_lmv, lmv_size);
        if (ma->ma_lmv == NULL)
                GOTO(out, rc = -ENOMEM);

        /* Get LMV EA, Note: refresh valid here for getting LMV_EA */
        rc = mo_attr_get(env, mp, ma);
        if (rc)
                GOTO(cleanup, rc);

        /* No LMV just return */
        if (!(ma->ma_valid & MA_LMV)) {
                /* update split state if unknown */
                if (clo->clo_split == CMM_SPLIT_UNKNOWN)
                        clo->clo_split = CMM_SPLIT_NONE;
                GOTO(cleanup, rc = 0);
        }

        /* Skip checking the slave dirs (mea_count is 0) */
        if (ma->ma_lmv->mea_count != 0) {
                int idx;

                /**
                 * This gets stripe by name to check the name belongs to master
                 * dir, otherwise return the -ERESTART
                 */
                idx = mea_name2idx(ma->ma_lmv, name, strlen(name));

                /**
                 * When client does not know about split, it sends create() to
                 * the master MDT and master replay back if directory is split.
                 * So client should orward request to correct MDT. This
                 * is why we check here if stripe zero or not. Zero stripe means
                 * master stripe. If stripe calculated from name is not zero -
                 * return -ERESTART.
                 */
                if (idx != 0)
                        rc = -ERESTART;

                /* update split state to DONE if unknown */
                if (clo->clo_split == CMM_SPLIT_UNKNOWN)
                        clo->clo_split = CMM_SPLIT_DONE;
        } else {
                /* split is denied for slave dir */
                clo->clo_split = CMM_SPLIT_DENIED;
        }
        EXIT;
cleanup:
        OBD_FREE(ma->ma_lmv, lmv_size);
out:
        cmm_lprocfs_time_end(env, cmm, LPROC_CMM_SPLIT_CHECK);
        return rc;
}

/**
 * Return preferable access mode to the caller taking into account the split
 * case and the fact of existing not splittable dirs.
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
        if (split == CMM_SPLIT_DONE && lm != MDL_PW)
                RETURN(MDL_NL);

        /* Protect splitting by exclusive lock. */
        if (split == CMM_SPLIT_NEEDED && lm == MDL_PW)
                RETURN(MDL_EX);

        /*
         * Have no idea about lock mode, let it be what higher layer wants.
         */
        RETURN(MDL_MINMODE);
}

/**
 * Check if split is expected for current thread.
 *
 * \param mo Directory to split.
 * \param ma md attributes.
 * \param split Flag to save split information.
 */
int cmm_split_expect(const struct lu_env *env, struct md_object *mo,
                     struct md_attr *ma, int *split)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct cml_object *clo = md2cml_obj(mo);
        struct lu_fid root_fid;
        int rc;
        ENTRY;

        if (clo->clo_split == CMM_SPLIT_DONE ||
            clo->clo_split == CMM_SPLIT_DENIED) {
                *split = clo->clo_split;
                RETURN(0);
        }
        /* CMM_SPLIT_UNKNOWN case below */

        /* No need to split root object. */
        rc = cmm_child_ops(cmm)->mdo_root_get(env, cmm->cmm_child,
                                              &root_fid);
        if (rc)
                RETURN(rc);

        if (lu_fid_eq(&root_fid, cmm2fid(md2cmm_obj(mo)))) {
                /* update split state */
                *split = clo->clo_split == CMM_SPLIT_DENIED;
                RETURN(0);
        }

        /*
         * Assumption: ma_valid = 0 here, we only need get inode and lmv_size
         * for this get_attr.
         */
        LASSERT(ma->ma_valid == 0);
        ma->ma_need = MA_INODE | MA_LMV;
        rc = mo_attr_get(env, mo, ma);
        if (rc)
                RETURN(rc);

        /* No need split for already split object */
        if (ma->ma_valid & MA_LMV) {
                LASSERT(ma->ma_lmv_size > 0);
                *split = clo->clo_split = CMM_SPLIT_DONE;
                RETURN(0);
        }

        /* No need split for object whose size < CMM_SPLIT_SIZE */
        if (ma->ma_attr.la_size < CMM_SPLIT_SIZE) {
                *split = clo->clo_split = CMM_SPLIT_NONE;
                RETURN(0);
        }

        *split = clo->clo_split = CMM_SPLIT_NEEDED;
        RETURN(0);
}

struct cmm_object *cmm_object_find(const struct lu_env *env,
                                   struct cmm_device *d,
                                   const struct lu_fid *f)
{
        return md2cmm_obj(md_object_find_slice(env, &d->cmm_md_dev, fid));
}

static inline void cmm_object_put(const struct lu_env *env,
                                  struct cmm_object *o)
{
        lu_object_put(env, &o->cmo_obj.mo_lu);
}

/**
 * Allocate new FID on passed \a mc for slave object which is going to
 * create there soon.
 */
static int cmm_split_fid_alloc(const struct lu_env *env,
                               struct cmm_device *cmm,
                               struct mdc_device *mc,
                               struct lu_fid *fid)
{
        int rc;
        ENTRY;

        LASSERT(cmm != NULL && mc != NULL && fid != NULL);

        cfs_down(&mc->mc_fid_sem);

        /* Alloc new fid on \a mc. */
        rc = obd_fid_alloc(mc->mc_desc.cl_exp, fid, NULL);
        if (rc > 0)
                rc = 0;
        cfs_up(&mc->mc_fid_sem);

        RETURN(rc);
}

/**
 * Allocate new slave object on passed \a mc.
 */
static int cmm_split_slave_create(const struct lu_env *env,
                                  struct cmm_device *cmm,
                                  struct mdc_device *mc,
                                  struct lu_fid *fid,
                                  struct md_attr *ma,
                                  struct lmv_stripe_md *lmv,
                                  int lmv_size)
{
        struct md_op_spec *spec = &cmm_env_info(env)->cmi_spec;
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

        memset(spec, 0, sizeof *spec);
        spec->u.sp_ea.fid = fid;
        spec->u.sp_ea.eadata = lmv;
        spec->u.sp_ea.eadatalen = lmv_size;
        spec->sp_cr_flags |= MDS_CREATE_SLAVE_OBJ;
        rc = mo_object_create(env, md_object_next(&obj->cmo_obj),
                              spec, ma);
        cmm_object_put(env, obj);
        RETURN(rc);
}

/**
 * Create so many slaves as number of stripes.
 * This is called in split time before sending pages to slaves.
 */
static int cmm_split_slaves_create(const struct lu_env *env,
                                   struct md_object *mo,
                                   struct md_attr *ma)
{
        struct cmm_device    *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct lu_fid        *lf  = cmm2fid(md2cmm_obj(mo));
        struct lmv_stripe_md *slave_lmv = &cmm_env_info(env)->cmi_lmv;
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

        memset(slave_lmv, 0, sizeof *slave_lmv);
        slave_lmv->mea_master = cmm->cmm_local_num;
        slave_lmv->mea_magic = MEA_MAGIC_HASH_SEGMENT;
        slave_lmv->mea_count = 0;

        cfs_list_for_each_entry_safe(mc, tmp, &cmm->cmm_targets, mc_linkage) {
                rc = cmm_split_slave_create(env, cmm, mc, &lmv->mea_ids[i],
                                            ma, slave_lmv, sizeof(*slave_lmv));
                if (rc)
                        GOTO(cleanup, rc);
                i++;
        }
        EXIT;
cleanup:
        return rc;
}

static inline int cmm_split_special_entry(struct lu_dirent *ent)
{
        if (!strncmp(ent->lde_name, ".", le16_to_cpu(ent->lde_namelen)) ||
            !strncmp(ent->lde_name, "..", le16_to_cpu(ent->lde_namelen)))
                return 1;
        return 0;
}

/**
 * Convert string to the lu_name structure.
 */
static inline struct lu_name *cmm_name(const struct lu_env *env,
                                       char *name, int buflen)
{
        struct lu_name *lname;
        struct cmm_thread_info *cmi;

        LASSERT(buflen > 0);
        LASSERT(name[buflen - 1] == '\0');

        cmi = cmm_env_info(env);
        lname = &cmi->cti_name;
        lname->ln_name = name;
        /* do NOT count the terminating '\0' of name for length */
        lname->ln_namelen = buflen - 1;
        return lname;
}

/**
 * Helper for cmm_split_remove_page(). It removes one entry from local MDT.
 * Do not corrupt byte order in page, it will be sent to remote MDT.
 */
static int cmm_split_remove_entry(const struct lu_env *env,
                                  struct md_object *mo,
                                  struct lu_dirent *ent)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct cmm_thread_info *cmi;
        struct md_attr *ma;
        struct cmm_object *obj;
        int is_dir, rc;
        char *name;
        struct lu_name *lname;
        ENTRY;

        if (cmm_split_special_entry(ent))
                RETURN(0);

        fid_le_to_cpu(&cmm_env_info(env)->cmi_fid, &ent->lde_fid);
        obj = cmm_object_find(env, cmm, &cmm_env_info(env)->cmi_fid);
        if (IS_ERR(obj))
                RETURN(PTR_ERR(obj));

        cmi = cmm_env_info(env);
        ma = &cmi->cmi_ma;

        if (lu_object_exists(&obj->cmo_obj.mo_lu) > 0)
                is_dir = S_ISDIR(lu_object_attr(&obj->cmo_obj.mo_lu));
        else
                /**
                 * \note These days only cross-ref dirs are possible, so for the
                 * sake of simplicity, in split, we suppose that all cross-ref
                 * names point to directory and do not do additional getattr to
                 * remote MDT.
                 */
                is_dir = 1;

        OBD_ALLOC(name, le16_to_cpu(ent->lde_namelen) + 1);
        if (!name)
                GOTO(cleanup, rc = -ENOMEM);

        memcpy(name, ent->lde_name, le16_to_cpu(ent->lde_namelen));
        lname = cmm_name(env, name, le16_to_cpu(ent->lde_namelen) + 1);
        /**
         * \note When split, no need update parent's ctime,
         * and no permission check for name_remove.
         */
        ma->ma_attr.la_ctime = 0;
        if (is_dir)
                ma->ma_attr.la_mode = S_IFDIR;
        else
                ma->ma_attr.la_mode = 0;
        ma->ma_attr.la_valid = LA_MODE;
        ma->ma_valid = MA_INODE;

        ma->ma_attr_flags |= MDS_PERM_BYPASS;
        rc = mdo_name_remove(env, md_object_next(mo), lname, ma);
        OBD_FREE(name, le16_to_cpu(ent->lde_namelen) + 1);
        if (rc)
                GOTO(cleanup, rc);

        /**
         * \note For each entry transferred to the slave MDS we should know
         * whether this object is dir or not. Therefore the highest bit of the
         * hash is used to indicate that (it is unused for hash purposes anyway).
         */
        if (is_dir) {
                ent->lde_hash = le64_to_cpu(ent->lde_hash);
                ent->lde_hash = cpu_to_le64(ent->lde_hash | MAX_HASH_HIGHEST_BIT);
        }
        EXIT;
cleanup:
        cmm_object_put(env, obj);
        return rc;
}

/**
 * Remove all entries from passed page.
 * These entries are going to remote MDT and thus should be removed locally.
 */
static int cmm_split_remove_page(const struct lu_env *env,
                                 struct md_object *mo,
                                 struct lu_rdpg *rdpg,
                                 __u64 hash_end, __u32 *len)
{
        struct lu_dirpage *dp;
        struct lu_dirent  *ent;
        int rc = 0;
        ENTRY;

        *len = 0;
        cfs_kmap(rdpg->rp_pages[0]);
        dp = page_address(rdpg->rp_pages[0]);
        for (ent = lu_dirent_start(dp);
             ent != NULL && le64_to_cpu(ent->lde_hash) < hash_end;
             ent = lu_dirent_next(ent)) {
                rc = cmm_split_remove_entry(env, mo, ent);
                if (rc) {
                        /*
                         * XXX: Error handler to insert remove name back,
                         * currently we assumed it will success anyway in
                         * verfication test.
                         */
                        CERROR("Can not del %*.*s, rc %d\n",
                               le16_to_cpu(ent->lde_namelen),
                               le16_to_cpu(ent->lde_namelen),
                               ent->lde_name, rc);
                        GOTO(unmap, rc);
                }
                *len += lu_dirent_size(ent);
        }

        if (ent != lu_dirent_start(dp))
                *len += sizeof(struct lu_dirpage);
        EXIT;
unmap:
        cfs_kunmap(rdpg->rp_pages[0]);
        return rc;
}

/**
 * Send one page of entries to the slave MDT.
 * This page contains entries to be created there.
 */
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

/** Read one page of entries from local MDT. */
static int cmm_split_read_page(const struct lu_env *env,
                               struct md_object *mo,
                               struct lu_rdpg *rdpg)
{
        int rc;
        ENTRY;
        memset(cfs_kmap(rdpg->rp_pages[0]), 0, CFS_PAGE_SIZE);
        cfs_kunmap(rdpg->rp_pages[0]);
        rc = mo_readpage(env, md_object_next(mo), rdpg);
        RETURN(rc);
}

/**
 * This function performs migration of each directory stripe to its MDS.
 */
static int cmm_split_process_stripe(const struct lu_env *env,
                                    struct md_object *mo,
                                    struct lu_rdpg *rdpg,
                                    struct lu_fid *lf,
                                    __u64 end)
{
        int rc, done = 0;
        ENTRY;

        LASSERT(rdpg->rp_npages == 1);
        do {
                struct lu_dirpage *ldp;
                __u32 len = 0;

                /** - Read one page of entries from local MDT. */
                rc = cmm_split_read_page(env, mo, rdpg);
                if (rc) {
                        CERROR("Error in readpage: %d\n", rc);
                        RETURN(rc);
                }

                /** - Remove local entries which are going to remite MDT. */
                rc = cmm_split_remove_page(env, mo, rdpg, end, &len);
                if (rc) {
                        CERROR("Error in remove stripe entries: %d\n", rc);
                        RETURN(rc);
                }

                /**
                 * - Send entries page to slave MDT and repeat while there are
                 * more pages.
                 */
                if (len > 0) {
                        rc = cmm_split_send_page(env, mo, rdpg, lf, len);
                        if (rc) {
                                CERROR("Error in sending page: %d\n", rc);
                                RETURN(rc);
                        }
                }

                cfs_kmap(rdpg->rp_pages[0]);
                ldp = page_address(rdpg->rp_pages[0]);
                if (le64_to_cpu(ldp->ldp_hash_end) >= end)
                        done = 1;

                rdpg->rp_hash = le64_to_cpu(ldp->ldp_hash_end);
                cfs_kunmap(rdpg->rp_pages[0]);
        } while (!done);

        RETURN(rc);
}

/**
 * Directory scanner for split operation.
 *
 * It calculates hashes for names and organizes files to stripes.
 */
static int cmm_split_process_dir(const struct lu_env *env,
                                 struct md_object *mo,
                                 struct md_attr *ma)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct lu_rdpg *rdpg = &cmm_env_info(env)->cmi_rdpg;
        __u64 hash_segment;
        int rc = 0, i;
        ENTRY;

        memset(rdpg, 0, sizeof *rdpg);
        rdpg->rp_npages = CMM_SPLIT_PAGE_COUNT;
        rdpg->rp_count  = CFS_PAGE_SIZE * rdpg->rp_npages;
        rdpg->rp_pages  = cmm_env_info(env)->cmi_pages;

        for (i = 0; i < rdpg->rp_npages; i++) {
                rdpg->rp_pages[i] = cfs_alloc_page(CFS_ALLOC_STD);
                if (rdpg->rp_pages[i] == NULL)
                        GOTO(cleanup, rc = -ENOMEM);
        }

        hash_segment = MAX_HASH_SIZE;
        /** Whole hash range is divided on segments by number of MDS-es. */
        do_div(hash_segment, cmm->cmm_tgt_count + 1);
        /**
         * For each segment the cmm_split_process_stripe() is called to move
         * entries on new server.
         */
        for (i = 1; i < cmm->cmm_tgt_count + 1; i++) {
                struct lu_fid *lf;
                __u64 hash_end;

                lf = &ma->ma_lmv->mea_ids[i];

                rdpg->rp_hash = i * hash_segment;
                if (i == cmm->cmm_tgt_count)
                        hash_end = MAX_HASH_SIZE;
                else
                        hash_end = rdpg->rp_hash + hash_segment;
                rc = cmm_split_process_stripe(env, mo, rdpg, lf, hash_end);
                if (rc) {
                        CERROR("Error (rc = %d) while splitting for %d: fid="
                               DFID", "LPX64":"LPX64"\n", rc, i, PFID(lf),
                               rdpg->rp_hash, hash_end);
                        GOTO(cleanup, rc);
                }
        }
        EXIT;
cleanup:
        for (i = 0; i < rdpg->rp_npages; i++)
                if (rdpg->rp_pages[i] != NULL)
                        cfs_free_page(rdpg->rp_pages[i]);
        return rc;
}

/**
 * Directory splitting.
 *
 * Big directory can be split eventually.
 */
int cmm_split_dir(const struct lu_env *env, struct md_object *mo)
{
        struct cmm_device *cmm = cmm_obj2dev(md2cmm_obj(mo));
        struct md_attr    *ma = &cmm_env_info(env)->cmi_ma;
        int                rc = 0, split;
        struct lu_buf     *buf;
        ENTRY;

        cmm_lprocfs_time_start(env);

        LASSERT(S_ISDIR(lu_object_attr(&mo->mo_lu)));
        memset(ma, 0, sizeof(*ma));

        /** - Step1: Checking whether the dir needs to be split. */
        rc = cmm_split_expect(env, mo, ma, &split);
        if (rc)
                GOTO(out, rc);

        if (split != CMM_SPLIT_NEEDED) {
                /* No split is needed, caller may proceed with create. */
                GOTO(out, rc = 0);
        }

        /* Split should be done now, let's do it. */
        CWARN("Dir "DFID" is going to split (size: "LPU64")\n",
              PFID(lu_object_fid(&mo->mo_lu)), ma->ma_attr.la_size);

        /**
         * /note Disable transactions for split, since there will be so many trans in
         * this one ops, conflict with current recovery design.
         */
        rc = cmm_upcall(env, &cmm->cmm_md_dev, MD_NO_TRANS, NULL);
        if (rc) {
                CERROR("Can't disable trans for split, rc %d\n", rc);
                GOTO(out, rc);
        }

        /** - Step2: Prepare the md memory */
        ma->ma_lmv_size = CMM_MD_SIZE(cmm->cmm_tgt_count + 1);
        OBD_ALLOC(ma->ma_lmv, ma->ma_lmv_size);
        if (ma->ma_lmv == NULL)
                GOTO(out, rc = -ENOMEM);

        /** - Step3: Create slave objects and fill the ma->ma_lmv */
        rc = cmm_split_slaves_create(env, mo, ma);
        if (rc) {
                CERROR("Can't create slaves for split, rc %d\n", rc);
                GOTO(cleanup, rc);
        }

        /** - Step4: Scan and split the object. */
        rc = cmm_split_process_dir(env, mo, ma);
        if (rc) {
                CERROR("Can't scan and split, rc %d\n", rc);
                GOTO(cleanup, rc);
        }

        /** - Step5: Set mea to the master object. */
        buf = cmm_buf_get(env, ma->ma_lmv, ma->ma_lmv_size);
        rc = mo_xattr_set(env, md_object_next(mo), buf,
                          MDS_LMV_MD_NAME, 0);
        if (rc) {
                CERROR("Can't set MEA to master dir, " "rc %d\n", rc);
                GOTO(cleanup, rc);
        }

        /* set flag in cmm_object */
        md2cml_obj(mo)->clo_split = CMM_SPLIT_DONE;

        /**
         * - Finally, split succeed, tell client to repeat opetartion on correct
         * MDT.
         */
        CWARN("Dir "DFID" has been split\n", PFID(lu_object_fid(&mo->mo_lu)));
        rc = -ERESTART;
        EXIT;
cleanup:
        OBD_FREE(ma->ma_lmv, ma->ma_lmv_size);
out:
        cmm_lprocfs_time_end(env, cmm, LPROC_CMM_SPLIT);
        return rc;
}
/** @} */
