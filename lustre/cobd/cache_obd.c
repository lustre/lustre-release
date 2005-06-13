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
#include <linux/obd_lmv.h>

static int cobd_attach(struct obd_device *obd,
                       obd_count len, void *buf)
{
        struct lprocfs_static_vars lvars;
        
        lprocfs_init_vars(cobd, &lvars);
        return lprocfs_obd_attach(obd, lvars.obd_vars);
}

static int cobd_detach(struct obd_device *obd)
{
        return lprocfs_obd_detach(obd);
}

static int cobd_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = (struct lustre_cfg *)buf;
        struct cache_obd  *cobd = &obd->u.cobd;
        struct obd_device *master_obd, *cache_obd;
        struct lustre_handle conn = { 0 };
        int rc = 0;
        ENTRY;

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1 ||
            lustre_cfg_buf(lcfg, 1) == NULL) {
                CERROR("%s: setup requires master device name\n", 
                       obd->obd_name);
                RETURN(-EINVAL);
        }

        if (LUSTRE_CFG_BUFLEN(lcfg, 2) < 1 ||
            lustre_cfg_buf(lcfg, 2) == NULL) {
                CERROR("%s: setup requires cache device name\n",
                       obd->obd_name);
                RETURN(-EINVAL);
        }
        sema_init(&cobd->sem, 1);

        /*get the cache obd name and master name */
        OBD_ALLOC(cobd->master_name, LUSTRE_CFG_BUFLEN(lcfg, 1));
        if (!cobd->master_name) 
                RETURN(-ENOMEM);
        memcpy(cobd->master_name, lustre_cfg_string(lcfg, 1), 
               LUSTRE_CFG_BUFLEN(lcfg, 1));
        
        OBD_ALLOC(cobd->cache_name, LUSTRE_CFG_BUFLEN(lcfg, 2));
        if (!cobd->cache_name) {
                OBD_FREE(cobd->master_name, LUSTRE_CFG_BUFLEN(lcfg, 1));
                RETURN(-ENOMEM);
        }
        memcpy(cobd->cache_name, lustre_cfg_string(lcfg, 2), 
               LUSTRE_CFG_BUFLEN(lcfg, 2));

        /* getting master obd */
        master_obd = class_name2obd(cobd->master_name);
        if (!master_obd) {
                CERROR("can't find master obd by name %s\n",
                       cobd->master_name);
                GOTO(put_names, rc = -EINVAL);
        }

        /* connecting master */
        memset(&conn, 0, sizeof(conn));
        rc = class_connect(&conn, master_obd, &obd->obd_uuid);
        if (rc)
               GOTO(put_names, rc);
        
        cobd->master_exp = class_conn2export(&conn);

        /* getting cache obd */
        cache_obd = class_name2obd(cobd->cache_name);
        if (!cache_obd) {
                class_disconnect(cobd->master_exp, 0);
                CERROR("can't find cache obd by name %s\n",
                       cobd->cache_name);
                GOTO(put_names, rc);
        }

        /* connecting cache */
        memset(&conn, 0, sizeof(conn));
        rc = class_connect(&conn, cache_obd, &obd->obd_uuid);
        if (rc) {
                class_disconnect(cobd->master_exp, 0);
                GOTO(put_names, rc);
        }
        cobd->cache_exp = class_conn2export(&conn);
        
        /* default set cache on */
        cobd->cache_on = 1;
        EXIT;
put_names:
        if (rc) {
                if (cobd->master_name) {
                        OBD_FREE(cobd->master_name, LUSTRE_CFG_BUFLEN(lcfg, 1));
                        cobd->master_name = NULL;
                } 
                if (cobd->cache_name) {
                        OBD_FREE(cobd->cache_name, LUSTRE_CFG_BUFLEN(lcfg, 2));
                        cobd->cache_name = NULL;
                }
        
        }
        RETURN(rc);
}

static int cobd_cleanup(struct obd_device *obd, int flags)
{
        struct cache_obd  *cobd = &obd->u.cobd;
        int rc = 0;
        ENTRY;

        if (!list_empty(&obd->obd_exports))
                RETURN(-EBUSY);

        if (cobd->cache_name)
                OBD_FREE(cobd->cache_name, 
                         strlen(cobd->cache_name) + 1);
        if (cobd->master_name)
                OBD_FREE(cobd->master_name, 
                         strlen(cobd->master_name) + 1);
        
        rc = class_disconnect(cobd->master_exp, flags);
        if (rc) {
                CERROR("error disconnecting master, err %d\n",
                       rc);
        }
        rc = class_disconnect(cobd->cache_exp, flags);
        if (rc) {
                CERROR("error disconnecting master, err %d\n",
                       rc);
        }

        RETURN(0);
}

static inline struct obd_export *
cobd_get_exp(struct obd_device *obd)
{
        struct cache_obd *cobd = &obd->u.cobd;
        if (cobd->cache_on) {
                CDEBUG(D_TRACE, "get cache exp %p \n", cobd->cache_exp); 
                if (cobd->cache_real_exp)
                       return cobd->cache_real_exp;
                return cobd->cache_exp;
        }
        CDEBUG(D_TRACE, "get master exp %p \n", cobd->master_exp);
        if (cobd->master_real_exp)
                return cobd->master_real_exp; 
        return cobd->master_exp;
}

static int
client_obd_connect(struct obd_device *obd,
                   struct obd_export *exp,
                   struct lustre_handle *conn,
                   struct obd_connect_data *data,
                   unsigned long flags)
{ 
        struct obd_device *cli_obd;
        int rc = 0;
        ENTRY;
 
        LASSERT(obd);
        LASSERT(conn);
        
        cli_obd = class_exp2obd(exp);
        if (cli_obd == NULL) 
                RETURN(-EINVAL);

        rc = obd_connect(conn, cli_obd, &obd->obd_uuid, data, flags);
        if (rc) 
                CERROR("error connecting err %d\n", rc);
        
        RETURN(rc);
}

static int
client_obd_disconnect(struct obd_device *obd,
                      struct obd_export *exp,
                      unsigned long flags)
{
        struct obd_device *cli_obd;
        int rc = 0;
        ENTRY;

        cli_obd = class_exp2obd(exp);
        cli_obd->obd_no_recov = obd->obd_no_recov;
        
        rc = obd_disconnect(exp, flags);
        if (rc) {
                CERROR("error disconnecting from %s, err %d\n",
                       cli_obd->obd_name, rc);
                class_export_put(exp);
        }
        RETURN(rc);
}

static int
cobd_connect(struct lustre_handle *conn, struct obd_device *obd,
             struct obd_uuid *cluuid, struct obd_connect_data *data,
             unsigned long flags)
{
        struct lustre_handle cache_conn = { 0 };
        struct cache_obd *cobd = &obd->u.cobd;
        struct obd_export *exp, *cobd_exp;
        int rc = 0;
        ENTRY;

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);
        exp = class_conn2export(conn);

        cobd_exp = cobd_get_exp(obd);
        
        /* connecting cache */
        rc = client_obd_connect(obd, cobd_exp, &cache_conn, 
                                data, flags);
        if (rc)
                GOTO(err_discon, rc);
       
        cobd->cache_real_exp = class_conn2export(&cache_conn);
        cobd->cache_on = 1;
        EXIT;
err_discon:
        if (rc)
                class_disconnect(exp, 0);
        else
                class_export_put(exp);
        RETURN(rc);
}

static int
cobd_disconnect(struct obd_export *exp, unsigned long flags)
{
        struct obd_device *obd;
        struct obd_export *cobd_exp;
        int rc = 0;
        ENTRY;
        
        LASSERT(exp != NULL);
        obd = class_exp2obd(exp);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }
        cobd_exp = cobd_get_exp(obd);
        
        rc = client_obd_disconnect(obd, cobd_exp, flags);

        class_disconnect(exp, flags);
        
        RETURN(rc);
}

static int cobd_get_info(struct obd_export *exp, __u32 keylen,
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
                       void *acl, int acl_size,
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
        return obd_create(cobd_exp, obdo, acl, acl_size, ea, oti);
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
        /* FIXME-WANGDI: do we need some cleanup here? */
        return 0;
}

static int cobd_getattr(struct obd_export *exp, struct obdo *oa,
                        struct lov_stripe_md *ea)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return obd_getattr(cobd_exp, oa, ea);
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

static int cobd_md_getstatus(struct obd_export *exp,
                             struct lustre_id *rootid)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_getstatus(cobd_exp, rootid);
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
                               obd_flags brw_flags, obd_flags async_flags)
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
                               obd_flags async_flags)
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
                               int count, obd_flags brw_flags,
                               obd_flags async_flags)
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
                              struct lov_stripe_md *ea,
                              int flags, void *opaque)
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

static int cobd_preprw(int cmd, struct obd_export *exp,
                       struct obdo *oa, int objcount,
                       struct obd_ioobj *obj, int niocount,
                       struct niobuf_remote *nb,
                       struct niobuf_local *res,
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
        return obd_preprw(cmd, cobd_exp, oa, objcount, obj,
                          niocount, nb, res, oti);
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
        return obd_commitrw(cmd, cobd_exp, oa, objcount, obj,
                            niocount, local, oti, rc);
}

static int cobd_flush(struct obd_device *obd)
{
        return 0; 
}

static int cobd_iocontrol(unsigned int cmd, struct obd_export *exp,
                          int len, void *karg, void *uarg)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct cache_obd  *cobd = &obd->u.cobd;
        struct obd_export *cobd_exp;
        int rc = 0;
        ENTRY;

        down(&cobd->sem);
        
        switch (cmd) {
        case OBD_IOC_COBD_CON:
                if (!cobd->cache_on) {
                        struct lustre_handle conn = {0};

                        rc = obd_cancel_unused(cobd->master_real_exp, NULL,
                                               LDLM_FL_COBD_SWITCH, NULL);
                        if (rc) {
                                CWARN("can't cancel unused locks on master export, "
                                      "err %d\n", rc);
                        }
                        
                        rc = client_obd_disconnect(obd, cobd->master_real_exp, 0);
                        if (rc) {
                                CWARN("can't disconnect master export, err %d\n",
                                      rc);
                        }
                        
                        rc = client_obd_connect(obd, cobd->cache_exp, &conn,
                                                NULL, OBD_OPT_REAL_CLIENT);
                        if (rc)
                                GOTO(out, rc);

                        cobd->cache_real_exp = class_conn2export(&conn);
                        cobd->cache_on = 1;
                }
                break;
        case OBD_IOC_COBD_COFF: 
                if (cobd->cache_on) {
                        struct lustre_handle conn = {0,};
                        struct obd_device *master = NULL;
                        struct obd_device *cache = NULL;
                        int easize, cooksize;

                        cache = class_exp2obd(cobd->cache_exp); 
                        easize = cache->u.cli.cl_max_mds_easize; 
                        cooksize = cache->u.cli.cl_max_mds_cookiesize;

                        rc = obd_cancel_unused(cobd->cache_real_exp, NULL,
                                               LDLM_FL_COBD_SWITCH, NULL);
                        if (rc) {
                                CWARN("can't cancel unused locks on cache export, "
                                      "err %d\n", rc);
                        }
                        
                        rc = client_obd_disconnect(obd, cobd->cache_real_exp, 0);
                        if (rc) {
                                CWARN("can't disconnect cache export, err %d\n",
                                      rc);
                        }
                        rc = client_obd_connect(obd, cobd->master_exp, &conn,
                                                NULL, OBD_OPT_REAL_CLIENT);
                        if (rc)
                                GOTO(out, rc);
                        cobd->master_real_exp = class_conn2export(&conn);

                        master = class_exp2obd(cobd->master_exp);
                        master->u.cli.cl_max_mds_easize = easize;
                        master->u.cli.cl_max_mds_cookiesize = cooksize;
                        cobd->cache_on = 0;
                }
                break;
        case OBD_IOC_COBD_CFLUSH:
                if (cobd->cache_on) {
                        cobd->cache_on = 0;
                        cobd_flush(obd);
                        cobd->cache_on = 1;
                } else {
                        CERROR("%s: cache is turned off\n", obd->obd_name);
                }
                break;
        default:
                cobd_exp = cobd_get_exp(obd);
                rc = obd_iocontrol(cmd, cobd_exp, len, karg, uarg);
        }

        EXIT;
out:
        up(&cobd->sem);
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

static int cobd_md_getattr(struct obd_export *exp, struct lustre_id *id,
                    	   __u64 valid, const char *ea_name, int ea_namelen,
                           unsigned int ea_size, struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_getattr(cobd_exp, id, valid, ea_name, ea_namelen, ea_size, 
                          request);
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

static int cobd_md_change_cbdata(struct obd_export *exp, struct lustre_id *id, 
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
        return md_change_cbdata(cobd_exp, id, it, data);
}

static int cobd_md_getattr_lock(struct obd_export *exp, struct lustre_id *id,
                                char *filename, int namelen, __u64 valid,
                                unsigned int ea_size, struct ptlrpc_request **request)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_getattr_lock(cobd_exp, id, filename, namelen, valid,
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

static int cobd_md_valid_attrs(struct obd_export *exp,
                               struct lustre_id *id)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return -EINVAL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_valid_attrs(cobd_exp, id);
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

static int cobd_md_readpage(struct obd_export *exp,
                            struct lustre_id *mdc_id,
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
        return md_readpage(cobd_exp, mdc_id, offset, page, request);
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

static int cobd_md_sync(struct obd_export *exp, struct lustre_id *id,
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
        
        return md_sync(cobd_exp, id, request);
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

static int cobd_md_intent_lock(struct obd_export *exp, struct lustre_id *pid, 
                               const char *name, int len, void *lmm, int lmmsize,
                               struct lustre_id *cid, struct lookup_intent *it,
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
        return md_intent_lock(cobd_exp, pid, name, len, lmm, lmmsize,
                              cid, it, lookup_flags, reqp, cb_blocking);
}

static struct obd_device *cobd_md_get_real_obd(struct obd_export *exp,
                                               struct lustre_id *id)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct obd_export *cobd_exp;

        if (obd == NULL) {
                CERROR("invalid client cookie "LPX64"\n", 
                       exp->exp_handle.h_cookie);
                return NULL;
        }
        cobd_exp = cobd_get_exp(obd);
        return md_get_real_obd(cobd_exp, id);
}

static int cobd_md_change_cbdata_name(struct obd_export *exp,
                                      struct lustre_id *id, char *name,
                                      int namelen, struct lustre_id *id2,
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
        return md_change_cbdata_name(cobd_exp, id, name, namelen,
                                     id2, it, data);
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
        .m_getattr_lock         = cobd_md_getattr_lock,
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
