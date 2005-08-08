/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cluster File Systems, Inc. <info@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_CMOBD

#include <linux/version.h>
#include <linux/init.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>
#include <linux/obd_class.h>
#include <linux/lustre_log.h>
#include <linux/lustre_cmobd.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>

#include "cm_internal.h"

void lov_free_memmd(struct lov_stripe_md **lsmp);

int lov_alloc_memmd(struct lov_stripe_md **lsmp, int stripe_count, 
                    int pattern);

int smfs_rec_unpack(struct smfs_proc_args *args, char *record, 
                    char **pbuf, int *opcode);

/* helper functions for cmobd to construct pseudo lsm */
int cmobd_dummy_lsm(struct lov_stripe_md **lsmp, int stripe_cnt, 
                    struct obdo *oa, __u32 stripe_size)
{
        int i, rc;
        ENTRY;

        rc = lov_alloc_memmd(lsmp, stripe_cnt, LOV_PATTERN_CMOBD);
        if (rc < 0)
                RETURN(rc);
        
        for (i = 0; i < stripe_cnt; i++) {
                (*lsmp)->lsm_oinfo[i].loi_id = oa->o_id;
                (*lsmp)->lsm_object_id = oa->o_id;
                if (oa->o_valid & OBD_MD_FLGROUP) {
                        (*lsmp)->lsm_oinfo[i].loi_gr = oa->o_gr;
                        (*lsmp)->lsm_object_gr = oa->o_gr;
                }
                (*lsmp)->lsm_oinfo[i].loi_ost_idx = i;
                (*lsmp)->lsm_stripe_size = stripe_size;
        }
        RETURN(0);
}

void cmobd_free_lsm(struct lov_stripe_md **lsmp)
{
        ENTRY;
        lov_free_memmd(lsmp);
        EXIT;
}

/* reintegration functions */
static int cmobd_setattr_reint(struct obd_device *obd, void *rec)
{
        int rc = 0;
        struct lov_stripe_md *lsm;
        struct cm_obd *cmobd = &obd->u.cm;
        struct obd_export *exp = cmobd->master_exp;
        struct obdo *oa = (struct obdo *)rec;
        ENTRY;
        
        rc = cmobd_dummy_lsm(&lsm, cmobd->master_desc.ld_tgt_count, oa, 
                             (__u32)cmobd->master_desc.ld_default_stripe_size);
        if (rc)
                GOTO(out, rc);

        rc = obd_setattr(exp, oa, lsm, NULL);

        cmobd_free_lsm(&lsm);
out:
        RETURN(rc);
}

static int cmobd_create_reint(struct obd_device *obd, void *rec)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct obd_export *exp = cmobd->master_exp;
        struct obdo *oa = (struct obdo *)rec;
        struct obd_trans_info oti = { 0 };
        struct lov_stripe_md *lsm;
        int rc;
        ENTRY;
         
        rc = cmobd_dummy_lsm(&lsm, cmobd->master_desc.ld_tgt_count, oa,
                             (__u32)cmobd->master_desc.ld_default_stripe_size);
        if (rc)
                GOTO(out, rc);
        if (cmobd->master_group != oa->o_gr) {
                int group = oa->o_gr;
                int valsize = sizeof(group);

                rc = obd_set_info(exp, strlen("mds_conn"),
                                  "mds_conn", valsize, &group);
                if (rc)
                        GOTO(out, rc);
                cmobd->master_group = oa->o_gr;
        }

        oti.oti_flags |= OBD_MODE_CROW;
        rc = obd_create(exp, oa, NULL, 0, &lsm, &oti);
        cmobd_free_lsm(&lsm);
        EXIT;
out:
        return rc;
}

/* direct cut-n-paste of filter_blocking_ast() */
static int cache_blocking_ast(struct ldlm_lock *lock,
                              struct ldlm_lock_desc *desc,
                              void *data, int flag)
{
        int rc, do_ast;
        ENTRY;

        if (flag == LDLM_CB_CANCELING) {
                /* Don't need to do anything here. */
                RETURN(0);
        }

        /* XXX layering violation!  -phil */
        lock_res_and_lock(lock);
        
        /* get this: if filter_blocking_ast() is racing with ldlm_intent_policy,
         * such that filter_blocking_ast is called just before l_i_p takes the
         * ns_lock, then by the time we get the lock, we might not be the
         * correct blocking function anymore.  So check, and return early, if
         * so. */
        if (lock->l_blocking_ast != cache_blocking_ast) {
                unlock_res_and_lock(lock);
                RETURN(0);
        }

        lock->l_flags |= LDLM_FL_CBPENDING;
        do_ast = (!lock->l_readers && !lock->l_writers);
        unlock_res_and_lock(lock);

        if (do_ast) {
                struct lustre_handle lockh;
                LDLM_DEBUG(lock, "already unused, calling ldlm_cli_cancel");
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc < 0)
                        CERROR("ldlm_cli_cancel: %d\n", rc);
        } else {
                LDLM_DEBUG(lock, "Lock still has references, will be "
                           "cancelled later");
        }
        RETURN(0);
}

static int master_blocking_ast(struct ldlm_lock *lock, 
                               struct ldlm_lock_desc *desc,
                               void *data, int flag)
{
        int rc;
        struct lustre_handle lockh;
        ENTRY;

        switch (flag) {
        case LDLM_CB_BLOCKING:
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc < 0) {
                        CDEBUG(D_INODE, "ldlm_cli_cancel: %d\n", rc);
                        RETURN(rc);
                }
                break;
        case LDLM_CB_CANCELING: 
                /* do nothing here by now */
                break;
        default:
                LBUG();
        }
        RETURN(0);
}

static int cmobd_write_extents(struct obd_device *obd, struct obdo *oa, 
                               struct ldlm_extent *extent)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct obd_device *cache = cmobd->cache_exp->exp_obd;
        struct lustre_handle lockh_src = { 0 };
        struct lustre_handle lockh_dst = { 0 };
        struct ldlm_res_id res_id;
        ldlm_policy_data_t policy;
        struct lov_stripe_md *lsm;
        int flags = 0, err, rc = 0;
        ENTRY;

        /* XXX for debug write replay without smfs and kml */
        res_id.name[0]= oa->o_id;
        res_id.name[1]= oa->o_gr;
        policy.l_extent.start = extent->start;
        policy.l_extent.end = extent->end;
        
        /* get extent read lock on the source replay file */
        rc = ldlm_cli_enqueue(NULL, NULL, cache->obd_namespace, res_id,
                              LDLM_EXTENT, &policy, LCK_PR,
                              &flags, cache_blocking_ast, ldlm_completion_ast,
                              NULL, NULL, NULL, 0, NULL, &lockh_src);
        if (rc != ELDLM_OK)
                RETURN(rc);
        
        /* construct the pseudo lsm */
        rc = cmobd_dummy_lsm(&lsm, cmobd->master_desc.ld_tgt_count, oa,
                             (__u32)cmobd->master_desc.ld_default_stripe_size);
        if (rc)
                GOTO(out_lock, rc);
        
        rc = obd_enqueue(cmobd->master_exp, lsm, LDLM_EXTENT, &policy, 
                         LCK_PW, &flags, master_blocking_ast, 
                         ldlm_completion_ast, NULL,
                         NULL, 0, NULL, &lockh_dst);
        if (rc != ELDLM_OK)
                GOTO(out_lsm, rc);

        err = cmobd_replay_write(obd, oa, &policy.l_extent);
        
        rc = obd_cancel(cmobd->master_exp, lsm, LCK_PW, &lockh_dst);
        if (rc)
                GOTO(out_lsm, rc);

        /* XXX in fact, I just want to cancel the only lockh_dst instantly. */
        rc = obd_cancel_unused(cmobd->master_exp, lsm, 0, NULL);
        if (err)
                rc = err;
out_lsm:
        cmobd_free_lsm(&lsm);
out_lock:
        ldlm_lock_decref(&lockh_src, LCK_PR);
        RETURN(rc);
}

static int cmobd_write_reint(struct obd_device *obd, void *rec)
{
        struct obdo *oa = (struct obdo *)rec;
        struct cm_obd *cmobd = &obd->u.cm;
        struct ldlm_extent *extent = NULL; 
        char *extents_buf = NULL;
        struct obd_device *cache;
        int rc = 0, ext_num = 0;
        unsigned long csb, ino;
        __u32 size = 0;
        ENTRY;

        size = sizeof(csb);
        obd_get_info(cmobd->cache_exp, strlen("cache_sb") + 1,
                     "cache_sb", &size, &csb); 
 
        ino = *(int*)(&oa->o_inline[0]);
        
        cache = cmobd->cache_exp->exp_obd;
        rc = fsfilt_get_ino_write_extents(cache, (struct super_block *)csb,
                                          ino, &extents_buf, &ext_num);
        if (rc)
                GOTO(out, rc);   
        extent = (struct ldlm_extent *)extents_buf;
        size = ext_num;
        while (extent && size --) { 
                rc = cmobd_write_extents(obd, oa, extent);
                if (rc)
                        GOTO(out, rc); 
                extent ++;
        }
out:
        if (extents_buf)
                fsfilt_free_write_extents(cache, (struct super_block *)csb, 
                                          ino, extents_buf, ext_num); 
        RETURN(rc);
}

int cmobd_reint_oss(struct obd_device *obd, void *record, int opcode)
{
        switch (opcode) {
        case OST_CREATE:
                return cmobd_create_reint(obd, record);
        case OST_SETATTR:
                return cmobd_setattr_reint(obd, record);
        case OST_WRITE:
                return cmobd_write_reint(obd, record);
        default:
                CERROR("unrecognized oss reint opcode %d\n", 
                       opcode);
                return -EINVAL;
        }
}
