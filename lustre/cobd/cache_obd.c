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

#define DEBUG_SUBSYSTEM S_COBD

#include <linux/version.h>
#include <linux/init.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_log.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>
#include <linux/obd_cache.h>

static int cobd_attach(struct obd_device *obd, obd_count len, void *buf)
{
        struct lprocfs_static_vars lvars;
        
        lprocfs_init_vars(cobd, &lvars);
        return lprocfs_obd_attach(obd, lvars.obd_vars);
}

static int cobd_detach(struct obd_device *obd)
{
        return lprocfs_obd_detach(obd);
}

static int connect_to_obd(char *name, struct lustre_handle *conn)
{ 
        struct obd_uuid   obd_uuid;
        struct obd_device *obd;
        int    rc = 0;
        ENTRY;
 
        obd = class_name2obd(name);
        if (obd == NULL) {
                CERROR("%s: unable to find a client for obd: %s\n",
                       obd->obd_name, name);
                RETURN(-EINVAL);
        }
        rc = obd_connect(conn, obd, &obd_uuid, 0);
        RETURN(rc);
}

static int cobd_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = (struct lustre_cfg *)buf;
        struct cache_obd  *cobd = &obd->u.cobd;
//        struct lustre_handle real_conn = {0,}, cache_conn = {0,};
        struct lustre_handle  cache_conn = {0,};
        struct obd_device *real;
        struct obd_device *cache;
        int rc;
        ENTRY;

        if (lcfg->lcfg_inllen1 == 0 || lcfg->lcfg_inlbuf1 == NULL) {
                CERROR("%s: setup requires real device name\n", 
                       obd->obd_name);
                RETURN(-EINVAL);
        }

        real = class_name2obd(lcfg->lcfg_inlbuf1);
        if (real == NULL) {
                CERROR("%s: unable to find a client for real: %s\n",
                       obd->obd_name, lcfg->lcfg_inlbuf1);
                RETURN(-EINVAL);
        }

        if (lcfg->lcfg_inllen2 == 0 || lcfg->lcfg_inlbuf2 == NULL) {
                CERROR("%s: setup requires cache device name\n", obd->obd_name);
                RETURN(-EINVAL);
        }

        cache  = class_name2obd(lcfg->lcfg_inlbuf2);
        if (cache == NULL) {
                CERROR("%s: unable to find a client for cache: %s\n",
                       obd->obd_name, lcfg->lcfg_inlbuf2);
                RETURN(-EINVAL);
        }

        OBD_ALLOC(cobd->cobd_real_name, strlen(lcfg->lcfg_inlbuf1) + 1);
        if (!cobd->cobd_real_name) 
                GOTO(exit, rc = -ENOMEM);
        memcpy(cobd->cobd_real_name, lcfg->lcfg_inlbuf1, 
               strlen(lcfg->lcfg_inlbuf1));
        
        OBD_ALLOC(cobd->cobd_cache_name, strlen(lcfg->lcfg_inlbuf2) + 1);
        if (!cobd->cobd_cache_name) 
                GOTO(exit, rc = -ENOMEM);
        memcpy(cobd->cobd_cache_name, lcfg->lcfg_inlbuf2, 
               strlen(lcfg->lcfg_inlbuf2));

#if 0        
        /* don't bother checking attached/setup;
         * obd_connect() should, and it can change underneath us */
        rc = connect_to_obd(cobd->cobd_real_name, &real_conn);
        if (rc != 0)
                GOTO(exit, rc);
        cobd->cobd_real_exp = class_conn2export(&real_conn);
#endif        
        rc = connect_to_obd(cobd->cobd_cache_name, &cache_conn);
        if (rc != 0) {
                obd_disconnect(cobd->cobd_cache_exp, 0);
                GOTO(exit, rc);
        }
        cobd->cobd_cache_exp = class_conn2export(&cache_conn);
        
        cobd->cache_on = 1;
        if (!strcmp(real->obd_type->typ_name, LUSTRE_MDC_NAME)) {
                /* set mds_num for lustre */
                int mds_num;
                mds_num = REAL_MDS_NUMBER;
                obd_set_info(cobd->cobd_real_exp, strlen("mds_num"),
                             "mds_num", sizeof(mds_num), &mds_num);
                mds_num = CACHE_MDS_NUMBER;
                obd_set_info(cobd->cobd_cache_exp, strlen("mds_num"),
                             "mds_num", sizeof(mds_num), &mds_num);
        }
        /*default write to real obd*/
exit:
        if (rc) {
                if (cobd->cobd_cache_name)
                        OBD_FREE(cobd->cobd_cache_name, 
                                 strlen(cobd->cobd_cache_name) + 1);
                if (cobd->cobd_real_name)
                        OBD_FREE(cobd->cobd_real_name, 
                                 strlen(cobd->cobd_real_name) + 1);
        }
        RETURN(rc);
}

static int cobd_cleanup(struct obd_device *obd, int flags)
{
        struct cache_obd  *cobd = &obd->u.cobd;
        int                rc;

        if (!list_empty(&obd->obd_exports))
                return (-EBUSY);
        
        if (cobd->cobd_cache_name)
                OBD_FREE(cobd->cobd_cache_name, 
                         strlen(cobd->cobd_cache_name) + 1);
        if (cobd->cobd_real_name)
                OBD_FREE(cobd->cobd_real_name, 
                         strlen(cobd->cobd_real_name) + 1);
        if (cobd->cache_on) { 
                rc = obd_disconnect(cobd->cobd_cache_exp, flags);
                if (rc != 0)
                        CERROR("error %d disconnecting cache\n", rc);
        }
        rc = obd_disconnect(cobd->cobd_real_exp, flags);
        if (rc != 0)
                CERROR("error %d disconnecting real\n", rc);
        
        return (rc);
}

struct obd_export *cobd_get_exp(struct obd_device *obd)
{
        struct cache_obd  *cobd = &obd->u.cobd;
        
        if (cobd->cache_on)  
                return cobd->cobd_cache_exp;
        else
                return cobd->cobd_real_exp;
}

static int
cobd_connect(struct lustre_handle *conn, struct obd_device *obd,
             struct obd_uuid *cluuid, unsigned long connect_flags)
{
        int rc;
        rc = class_connect(conn, obd, cluuid);
        return rc; 
}

static int cobd_disconnect(struct obd_export *exp, int flags)
{
        int rc;
        rc = class_disconnect(exp, 0);
        return rc; 
}

static int cobd_get_info(struct obd_export *exp, obd_count keylen,
                         void *key, __u32 *vallen, void *val)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;
        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        /* intercept cache utilisation info? */

        return obd_get_info(cobd_exp, keylen, key, vallen, val);
}

static int cobd_set_info(struct obd_export *exp, obd_count keylen,
                         void *key, obd_count vallen, void *val)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        /* intercept cache utilisation info? */

        return obd_set_info(cobd_exp, keylen, key, vallen, val);
}

static int cobd_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                       unsigned long max_age)
{
        struct obd_export *cobd_exp;

        cobd_exp = cobd_get_exp(obd);

        return obd_statfs(class_exp2obd(cobd_exp), osfs, max_age);
}

static int cobd_packmd(struct obd_export *exp,
                       struct lov_mds_md **disk_tgt,
                       struct lov_stripe_md *mem_src)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_packmd(cobd_exp, disk_tgt, mem_src);
}

static int cobd_unpackmd(struct obd_export *exp,
                         struct lov_stripe_md **mem_tgt,
                         struct lov_mds_md *disk_src,
                         int disk_len)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_unpackmd(cobd_exp, mem_tgt, disk_src, disk_len);
}

static int cobd_create(struct obd_export *exp, struct obdo *obdo,
                       struct lov_stripe_md **ea,
                       struct obd_trans_info *oti)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_create(cobd_exp, obdo, ea, oti); 
}

static int cobd_destroy(struct obd_export *exp, struct obdo *obdo,
                        struct lov_stripe_md *ea,
                        struct obd_trans_info *oti)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_destroy(cobd_exp, obdo, ea, oti); 
}

static int cobd_precleanup(struct obd_device *obd, int flags)
{
        /*FIXME Do we need some cleanup here?*/
        return 0;
}

static int cobd_getattr(struct obd_export *exp, struct obdo *oa,
                        struct lov_stripe_md *lsm)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_getattr(cobd_exp, oa, lsm);
}

static int cobd_getattr_async(struct obd_export *exp,
                             struct obdo *obdo, struct lov_stripe_md *ea,
                             struct ptlrpc_request_set *set)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_getattr_async(cobd_exp, obdo, ea, set);
}

static int cobd_setattr(struct obd_export *exp, struct obdo *obdo,
                        struct lov_stripe_md *ea,
                        struct obd_trans_info *oti)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_setattr(cobd_exp, obdo, ea, oti);
}

static int cobd_md_getstatus(struct obd_export *exp, struct ll_fid *rootfid)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_getstatus(cobd_exp, rootfid);
}

static int cobd_brw(int cmd, struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md *ea, obd_count oa_bufs,
                    struct brw_page *pg, struct obd_trans_info *oti)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_brw(cmd, cobd_exp, oa, ea, oa_bufs, pg, oti);
}

static int cobd_brw_async(int cmd, struct obd_export *exp,
                          struct obdo *oa, struct lov_stripe_md *ea,
                          obd_count oa_bufs, struct brw_page *pg,
                          struct ptlrpc_request_set *set,
                          struct obd_trans_info *oti)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_brw_async(cmd, cobd_exp, oa, ea, oa_bufs, 
                             pg, set, oti);
}

static int cobd_prep_async_page(struct obd_export *exp, 
                                struct lov_stripe_md *lsm,
                                struct lov_oinfo *loi, 
                                struct page *page, obd_off offset, 
                                struct obd_async_page_ops *ops, 
                                void *data, void **res)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_prep_async_page(cobd_exp, lsm, loi, page, offset,
                                   ops, data, res);
}

static int cobd_queue_async_io(struct obd_export *exp,
                               struct lov_stripe_md *lsm,
                               struct lov_oinfo *loi, void *cookie,
                               int cmd, obd_off off, int count,
                               obd_flag brw_flags, obd_flag async_flags)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_queue_async_io(cobd_exp, lsm, loi, cookie, cmd, off, count,
                                  brw_flags, async_flags);
}

static int cobd_set_async_flags(struct obd_export *exp,
                               struct lov_stripe_md *lsm,
                               struct lov_oinfo *loi, void *cookie,
                               obd_flag async_flags)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_set_async_flags(cobd_exp, lsm, loi, cookie, async_flags);
}

static int cobd_queue_group_io(struct obd_export *exp, 
                               struct lov_stripe_md *lsm, 
                               struct lov_oinfo *loi, 
                               struct obd_io_group *oig, 
                               void *cookie, int cmd, obd_off off, 
                               int count, obd_flag brw_flags,
                               obd_flag async_flags)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_queue_group_io(cobd_exp, lsm, loi, oig, cookie,
                                  cmd, off, count, brw_flags, async_flags);
}

static int cobd_trigger_group_io(struct obd_export *exp, 
                                 struct lov_stripe_md *lsm, 
                                 struct lov_oinfo *loi,
                                 struct obd_io_group *oig)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_trigger_group_io(cobd_exp, lsm, loi, oig); 
}

static int cobd_teardown_async_page(struct obd_export *exp,
                                    struct lov_stripe_md *lsm,
                                    struct lov_oinfo *loi, void *cookie)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_teardown_async_page(cobd_exp, lsm, loi, cookie);
}

static int cobd_punch(struct obd_export *exp, struct obdo *oa,
                      struct lov_stripe_md *ea, obd_size start,
                      obd_size end, struct obd_trans_info *oti)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_punch(cobd_exp, oa, ea, start, end, oti);
}

static int cobd_sync(struct obd_export *exp, struct obdo *oa,
                     struct lov_stripe_md *ea, obd_size start, 
                     obd_size end)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_sync(cobd_exp, oa, ea, start, end);
}

static int cobd_enqueue(struct obd_export *exp, struct lov_stripe_md *ea,
                        __u32 type, ldlm_policy_data_t *policy,
                        __u32 mode, int *flags, void *bl_cb, void *cp_cb,
                        void *gl_cb, void *data, __u32 lvb_len,
                        void *lvb_swabber, struct lustre_handle *lockh)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_enqueue(cobd_exp, ea, type, policy, mode, flags, 
                           bl_cb, cp_cb, gl_cb, data, lvb_len,
                           lvb_swabber, lockh);
}

static int cobd_match(struct obd_export *exp, struct lov_stripe_md *ea,
                      __u32 type, ldlm_policy_data_t *policy, __u32 mode,
                      int *flags, void *data, struct lustre_handle *lockh)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_match(cobd_exp, ea, type, policy, mode, flags, data,
                         lockh); 
}
static int cobd_change_cbdata(struct obd_export *exp,
                              struct lov_stripe_md *lsm, 
                              ldlm_iterator_t it, void *data)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_change_cbdata(cobd_exp, lsm, it, data);
}

static int cobd_cancel(struct obd_export *exp,
                       struct lov_stripe_md *ea, __u32 mode,
                       struct lustre_handle *lockh)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_cancel(cobd_exp, ea, mode, lockh);
}

static int cobd_cancel_unused(struct obd_export *exp,
                              struct lov_stripe_md *ea, int flags,
                              void *opaque)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_cancel_unused(cobd_exp, ea, flags, opaque);
}

static int cobd_preprw(int cmd, struct obd_export *exp, struct obdo *oa,
                       int objcount, struct obd_ioobj *obj,
                       int niocount, struct niobuf_remote *nb,
                       struct niobuf_local *res, struct obd_trans_info *oti)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_preprw(cmd, cobd_exp, oa, objcount, obj, niocount, nb, 
                          res, oti);
}

static int cobd_commitrw(int cmd, struct obd_export *exp, struct obdo *oa,
                         int objcount, struct obd_ioobj *obj,
                         int niocount, struct niobuf_local *local,
                         struct obd_trans_info *oti, int rc)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_commitrw(cmd, cobd_exp, oa, objcount, obj, niocount, 
                            local, oti, rc);
}

static int cobd_flush(struct obd_device *obd)
{
       /*FLUSH the filesystem from the cache 
        *to the real device */
        return 0; 
}

static int cobd_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                          void *karg, void *uarg)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct cache_obd  *cobd = &obd->u.cobd;
        struct obd_device *real_dev = NULL;
        struct obd_export *cobd_exp;
        int rc = 0;
 
        switch (cmd) {
        case OBD_IOC_COBD_CON:
                if (!cobd->cache_on) {
                        struct lustre_handle cache_conn = {0,};
                        
                        rc = obd_disconnect(cobd->cobd_real_exp, 0);
                        if (rc != 0)
                                CERROR("error %d disconnecting real\n", rc);
                        rc = connect_to_obd(cobd->cobd_cache_name, &cache_conn);
                        if (rc != 0)
                                RETURN(rc); 
                        cobd->cobd_cache_exp = class_conn2export(&cache_conn);
                        
                        cobd->cache_on = 1;
                }
                break;
        case OBD_IOC_COBD_COFF: 
                if (cobd->cache_on) {
                        struct lustre_handle real_conn = {0,};
                        struct obd_device *cache_dev = NULL;
                        int m_easize, m_cooksize;

                        cache_dev = class_exp2obd(cobd->cobd_cache_exp); 
                        m_easize = cache_dev->u.cli.cl_max_mds_easize; 
                        m_cooksize = cache_dev->u.cli.cl_max_mds_cookiesize; 
                        rc = obd_disconnect(cobd->cobd_cache_exp, 0);
                        if (rc != 0)
                                CERROR("error %d disconnecting real\n", rc);

                        /*FIXME, should read from real_dev*/
                        
                        rc = connect_to_obd(cobd->cobd_real_name, &real_conn);
                        if (rc != 0)
                                RETURN(rc); 
                        cobd->cobd_real_exp = class_conn2export(&real_conn);
                        real_dev = class_exp2obd(cobd->cobd_real_exp);
                        real_dev->u.cli.cl_max_mds_easize = m_easize;
                        real_dev->u.cli.cl_max_mds_cookiesize = m_cooksize;
                        cobd->cache_on = 0;
                }
                break;
        case OBD_IOC_COBD_CFLUSH:
                if (cobd->cache_on) {
                        cobd->cache_on = 0;
                        cobd_flush(obd);
                }
                break;
        default:
                cobd_exp = cobd_get_exp(obd);
                rc = obd_iocontrol(cmd, cobd_exp, len, karg, uarg);
        }
        
        return rc;
}

static int cobd_llog_init(struct obd_device *obd, struct obd_llogs *llogs, 
                          struct obd_device *disk_obd, int count, 
                          struct llog_catid *logid)
{
        struct obd_export *cobd_exp;
        struct obd_device *cobd_obd;

        cobd_exp = cobd_get_exp(obd);
        cobd_obd = class_exp2obd(cobd_exp);
        
        return obd_llog_init(cobd_obd, &cobd_obd->obd_llogs, 
                             disk_obd, count, logid);
}

static int cobd_llog_finish(struct obd_device *obd, struct obd_llogs *llogs, 
                            int count)
{
        struct obd_export *cobd_exp;
        struct obd_device *cobd_obd;

        cobd_exp = cobd_get_exp(obd);
        cobd_obd = class_exp2obd(cobd_exp);

        return obd_llog_finish(cobd_obd, &cobd_obd->obd_llogs, count);
}

static int cobd_notify(struct obd_device *obd, struct obd_device *watched,
                       int active, void *data)
{
        struct obd_export *cobd_exp;

        cobd_exp = cobd_get_exp(obd);

        return obd_notify(class_exp2obd(cobd_exp), watched, active, data);
}

static int cobd_pin(struct obd_export *exp, obd_id ino, __u32 gen,
                    int type, struct obd_client_handle *handle, int flag)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);

        return obd_pin(cobd_exp, ino, gen, type, handle, flag);
}

static int cobd_unpin(struct obd_export *exp,
                      struct obd_client_handle *handle, int flag)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);

        return obd_unpin(cobd_exp, handle, flag);
}

static int cobd_init_ea_size(struct obd_export *exp, int easize, int cookiesize)
{
        struct obd_export *cobd_exp;

        cobd_exp = cobd_get_exp(exp->exp_obd);
        return obd_init_ea_size(cobd_exp, easize, cookiesize);
}

static int  cobd_import_event(struct obd_device *obd,
                              struct obd_import *imp,
                              enum obd_import_event event)
{
        struct obd_export *cobd_exp;

        cobd_exp = cobd_get_exp(obd);

        obd_import_event(class_exp2obd(cobd_exp), imp, event);
        
        return 0; 
}

static int cobd_md_getattr(struct obd_export *exp, struct ll_fid *fid,
                           unsigned long valid, unsigned int ea_size,
                           struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_getattr(cobd_exp, fid, valid, ea_size, request);
}

static int cobd_md_req2lustre_md (struct obd_export *mdc_exp, 
                                  struct ptlrpc_request *req, unsigned int offset,
                                  struct obd_export *osc_exp, struct lustre_md *md)
{
        struct obd_device *obd = class_exp2obd(mdc_exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       mdc_exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_req2lustre_md(cobd_exp, req, offset, osc_exp, md);
}

static int cobd_md_change_cbdata(struct obd_export *exp, struct ll_fid *fid, 
                                 ldlm_iterator_t it, void *data)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_change_cbdata(cobd_exp, fid, it, data);
}

static int cobd_md_getattr_name(struct obd_export *exp, struct ll_fid *fid,
                                char *filename, int namelen, 
                                unsigned long valid,
                                unsigned int ea_size, 
                                struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_getattr_name(cobd_exp, fid, filename, namelen, valid,
                               ea_size, request);
}

static int cobd_md_create(struct obd_export *exp, struct mdc_op_data *op_data,
                          const void *data, int datalen, int mode, 
                          __u32 uid, __u32 gid, __u64 rdev, 
                          struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_create(cobd_exp, op_data, data, datalen, mode,
                         uid, gid, rdev, request);
}

static int cobd_md_unlink(struct obd_export *exp, struct mdc_op_data *data,
                          struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_unlink(cobd_exp, data, request);
}

static int cobd_md_valid_attrs(struct obd_export *exp, struct ll_fid *fid)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_valid_attrs(cobd_exp, fid);
}

static int cobd_md_rename(struct obd_export *exp, struct mdc_op_data *data,
                          const char *old, int oldlen, const char *new, 
                          int newlen, struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_rename(cobd_exp, data, old, oldlen, new, newlen, request);
}

static int cobd_md_link(struct obd_export *exp, struct mdc_op_data *data,
                        struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_link(cobd_exp, data, request);
}

static int cobd_md_setattr(struct obd_export *exp, struct mdc_op_data *data,
                           struct iattr *iattr, void *ea, int ealen, void *ea2, 
                           int ea2len, struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_setattr(cobd_exp, data, iattr, ea, ealen, ea2, ea2len, request);
}

static int cobd_md_readpage(struct obd_export *exp, struct ll_fid *mdc_fid,
                            __u64 offset, struct page *page, 
                            struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_readpage(cobd_exp, mdc_fid, offset, page, request);
}

static int cobd_md_close(struct obd_export *exp, struct obdo *obdo,
                         struct obd_client_handle *och, 
                         struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_close(cobd_exp, obdo, och, request);
}

static int cobd_md_done_writing(struct obd_export *exp, struct obdo *obdo)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_done_writing(cobd_exp, obdo);
}

static int cobd_md_sync(struct obd_export *exp, struct ll_fid *fid,
                        struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        
        return md_sync(cobd_exp, fid, request);
}

static int cobd_md_set_open_replay_data(struct obd_export *exp,
                                        struct obd_client_handle *och,
                                        struct ptlrpc_request *open_req)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        
        return md_set_open_replay_data(cobd_exp, och, open_req);
}

static int cobd_md_clear_open_replay_data(struct obd_export *exp,
                                          struct obd_client_handle *och)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
 
        return md_clear_open_replay_data(cobd_exp, och);
}

static int cobd_md_store_inode_generation(struct obd_export *exp,
                                          struct ptlrpc_request *req, 
                                          int reqoff, int repoff)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);

        return md_store_inode_generation(cobd_exp, req, reqoff, repoff);
}

static int cobd_md_set_lock_data(struct obd_export *exp, __u64 *l, void *data)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);

        return md_set_lock_data(cobd_exp, l, data);
}

static int cobd_md_enqueue(struct obd_export *exp, int lock_type,
                           struct lookup_intent *it, int lock_mode,
                           struct mdc_op_data *data, struct lustre_handle *lockh,
                           void *lmm, int lmmsize, 
                           ldlm_completion_callback cb_completion,
                           ldlm_blocking_callback cb_blocking, void *cb_data)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_enqueue(cobd_exp, lock_type, it, lock_mode, data,
                          lockh, lmm, lmmsize, cb_completion, cb_blocking,
                          cb_data);
}

static int cobd_md_intent_lock(struct obd_export *exp, struct ll_uctxt *uctxt,
                               struct ll_fid *pfid, const char *name, int len,
                               void *lmm, int lmmsize,
                               struct ll_fid *cfid, struct lookup_intent *it,
                               int lookup_flags, struct ptlrpc_request **reqp,
                               ldlm_blocking_callback cb_blocking)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_intent_lock(cobd_exp, uctxt, pfid, name, len, lmm, lmmsize,
                              cfid, it, lookup_flags, reqp, cb_blocking);
}

static struct obd_device * cobd_md_get_real_obd(struct obd_export *exp,
                                                char *name, int len)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return NULL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_get_real_obd(cobd_exp, name, len);
}

static int cobd_md_change_cbdata_name(struct obd_export *exp,
                                      struct ll_fid *fid, char *name,
                                      int namelen, struct ll_fid *fid2,
                                      ldlm_iterator_t it, void *data)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_change_cbdata_name(cobd_exp, fid, name, namelen, fid2, it, 
                                     data);
}
static struct obd_ops cobd_obd_ops = {
        .o_owner                = THIS_MODULE,
        .o_attach               = cobd_attach,
        .o_detach               = cobd_detach,
        .o_setup                = cobd_setup,
        .o_cleanup              = cobd_cleanup,
        .o_connect              = cobd_connect,
        .o_disconnect           = cobd_disconnect,
        .o_set_info             = cobd_set_info,
        .o_get_info             = cobd_get_info,
        .o_statfs               = cobd_statfs,

        .o_packmd               = cobd_packmd,
        .o_unpackmd             = cobd_unpackmd,
        .o_create               = cobd_create,
        .o_destroy              = cobd_destroy,
        .o_precleanup           = cobd_precleanup,
        .o_getattr              = cobd_getattr,
        .o_getattr_async        = cobd_getattr_async,
        .o_setattr              = cobd_setattr,

        .o_brw                  = cobd_brw,
        .o_brw_async            = cobd_brw_async,
        .o_prep_async_page      = cobd_prep_async_page,
        .o_queue_async_io       = cobd_queue_async_io,
        .o_set_async_flags      = cobd_set_async_flags,
        .o_queue_group_io       = cobd_queue_group_io,
        .o_trigger_group_io     = cobd_trigger_group_io,
        .o_teardown_async_page  = cobd_teardown_async_page,
        .o_preprw               = cobd_preprw,
        .o_punch                = cobd_punch,
        .o_sync                 = cobd_sync,
        .o_enqueue              = cobd_enqueue,
        .o_match                = cobd_match,
        .o_change_cbdata        = cobd_change_cbdata,
        .o_cancel               = cobd_cancel,
        .o_cancel_unused        = cobd_cancel_unused,
        .o_iocontrol            = cobd_iocontrol,
        .o_commitrw             = cobd_commitrw,
        .o_llog_init            = cobd_llog_init,
        .o_llog_finish          = cobd_llog_finish,
        .o_notify               = cobd_notify,
        .o_pin                  = cobd_pin,
        .o_unpin                = cobd_unpin,
        .o_import_event         = cobd_import_event,
        .o_init_ea_size         = cobd_init_ea_size,
};

struct md_ops cobd_md_ops = {
        .m_getstatus            = cobd_md_getstatus,
        .m_getattr              = cobd_md_getattr,
        .m_req2lustre_md        = cobd_md_req2lustre_md,
        .m_change_cbdata        = cobd_md_change_cbdata,
        .m_getattr_name         = cobd_md_getattr_name,
        .m_create               = cobd_md_create,
        .m_unlink               = cobd_md_unlink,
        .m_valid_attrs          = cobd_md_valid_attrs,
        .m_rename               = cobd_md_rename,
        .m_link                 = cobd_md_link,
        .m_setattr              = cobd_md_setattr,
        .m_readpage             = cobd_md_readpage,
        .m_close                = cobd_md_close,
        .m_done_writing         = cobd_md_done_writing,
        .m_sync                 = cobd_md_sync,
        .m_set_open_replay_data = cobd_md_set_open_replay_data,
        .m_clear_open_replay_data = cobd_md_clear_open_replay_data,
        .m_store_inode_generation = cobd_md_store_inode_generation,
        .m_set_lock_data        = cobd_md_set_lock_data,
        .m_enqueue              = cobd_md_enqueue,
        .m_get_real_obd         = cobd_md_get_real_obd,
        .m_intent_lock          = cobd_md_intent_lock,
        .m_change_cbdata_name   = cobd_md_change_cbdata_name,
};

static int __init cobd_init(void)
{
        struct lprocfs_static_vars lvars;
        ENTRY;

        printk(KERN_INFO "Lustre: Caching OBD driver; info@clusterfs.com\n");

        lprocfs_init_vars(cobd, &lvars);
        RETURN(class_register_type(&cobd_obd_ops, &cobd_md_ops,
                                   lvars.module_vars, OBD_CACHE_DEVICENAME));
}

static void /*__exit*/ cobd_exit(void)
{
        class_unregister_type(OBD_CACHE_DEVICENAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Caching OBD driver");
MODULE_LICENSE("GPL");

module_init(cobd_init);
module_exit(cobd_exit);
