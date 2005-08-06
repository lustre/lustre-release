/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2005 Cluster File Systems, Inc.
 *   Author Nathan <nathan@clusterfs.com>
 *   Author LinSongTao <lincent@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org
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
 *
 *  For testing and management it is treated as an obd_device,
 *  although * it does not export a full OBD method table (the
 *  requests are coming * in over the wire, so object target modules
 *  do not have a full * method table.)
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_CONFOBD

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/pagemap.h>
# include <linux/miscdevice.h>
# include <linux/init.h>
#else
# include <liblustre.h>
#endif

#include <linux/obd_class.h>
//#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_log.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_disk.h>
//#include <linux/lprocfs_status.h>
#include "mgc_internal.h"

          
static int mgc_fs_setup(struct super_block *sb, struct vfsmount *mnt)
{
        struct lvfs_run_ctxt saved;
        struct lustre_sb_info *sbi = s2sbi(sb);
        struct obd_device *obd = sbi->lsi_mgc;
        struct mgc_obd *mgcobd = &obd->u.mgc;
        struct dentry *dentry;
        int err = 0;

        LASSERT(obd);

        obd->obd_fsops = fsfilt_get_ops(MT_STR(sbi->lsi_ldd));
        if (IS_ERR(obd->obd_fsops)) {
               CERROR("No fstype %s rc=%ld\n", MT_STR(sbi->lsi_ldd), 
                      PTR_ERR(obd->obd_fsops));
               return(PTR_ERR(obd->obd_fsops));
        }

        mgcobd->mgc_vfsmnt = mnt;
        mgcobd->mgc_sb = mnt->mnt_root->d_inode->i_sb; // is this different than sb? */
        fsfilt_setup(obd, mgcobd->mgc_sb);

        OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
        obd->obd_lvfs_ctxt.pwdmnt = mnt;
        obd->obd_lvfs_ctxt.pwd = mnt->mnt_root;
        obd->obd_lvfs_ctxt.fs = get_ds();
        //obd->obd_lvfs_ctxt.cb_ops = mds_lvfs_ops;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        dentry = lookup_one_len(MOUNT_CONFIGS_DIR, current->fs->pwd,
                                strlen(MOUNT_CONFIGS_DIR));
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (IS_ERR(dentry)) {
                err = PTR_ERR(dentry);
                CERROR("cannot lookup %s directory: rc = %d\n", 
                       MOUNT_CONFIGS_DIR, err);
                goto err_ops;
        }
        mgcobd->mgc_configs_dir = dentry;
        return (0);

err_ops:        
        fsfilt_put_ops(obd->obd_fsops);
        obd->obd_fsops = NULL;
        mgcobd->mgc_sb = NULL;
        return(err);
}

static int mgc_fs_cleanup(struct obd_device *obd)
{
        struct mgc_obd *mgc = &obd->u.mgc;

       // in mgc_cleanup: llog_cleanup(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT));
        
        if (mgc->mgc_configs_dir != NULL) {
                struct lvfs_run_ctxt saved;
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                l_dput(mgc->mgc_configs_dir);
                mgc->mgc_configs_dir = NULL; 
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        }

        if (mgc->mgc_vfsmnt)
                // FIXME mntput should not be done by real server, only us 
                // FIXME or mntcount on sbi?
                mntput(mgc->mgc_vfsmnt);
        mgc->mgc_sb = NULL;
        
        if (obd->obd_fsops) 
                fsfilt_put_ops(obd->obd_fsops);
        return(0);
}

static int mgc_cleanup(struct obd_device *obd)
{
        struct mgc_obd *mgc = &obd->u.mgc;
        int rc;

        rc = llog_cleanup(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT));

        // FIXME REPL rc = obd_llog_finish(obd, 0);
        if (rc != 0)
                CERROR("failed to cleanup llogging subsystems\n");


        if (mgc->mgc_sb)
                /* if we're a server, eg. something's mounted */
                mgc_fs_cleanup(obd);

        //lprocfs_obd_cleanup(obd);
        
        //rc = mgc_obd_cleanup(obd);
        
        if (!lustre_put_mount(obd->obd_name))
             CERROR("mount_put failed\n");

        ptlrpcd_decref();
        
        OBD_FREE(mgc->mgc_rpc_lock, sizeof (*mgc->mgc_rpc_lock));

        return(rc);
}

static int mgc_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_mount_info *lmi;
        struct mgc_obd *mgc = &obd->u.mgc;
        //struct lprocfs_static_vars lvars;
        int rc;
        ENTRY;

        OBD_ALLOC(mgc->mgc_rpc_lock, sizeof (*mgc->mgc_rpc_lock));
        if (!mgc->mgc_rpc_lock)
                RETURN(-ENOMEM);
        mgc_init_rpc_lock(mgc->mgc_rpc_lock);

        ptlrpcd_addref();

        //mgc_obd_setup(obd, len, buf);
        //lprocfs_init_vars(mgc, &lvars);
        //lprocfs_obd_setup(obd, lvars.obd_vars);
        
        rc = llog_setup(obd, LLOG_CONFIG_ORIG_CTXT, obd, 0, NULL,
                        &llog_lvfs_ops);
        //need ORIG and REPL rc = llog_setup(obd, LLOG_CONFIG_REPL_CTXT, tgt, 0, NULL,
       //                 &llog_client_ops);
        //rc = obd_llog_init(obd, obd, 0, NULL);
        if (rc) {
                CERROR("failed to setup llogging subsystems\n");
                GOTO(err_rpc_lock, rc);
        }

        lmi = lustre_get_mount(obd->obd_name);
        if (!lmi) {
                CERROR("No mount registered!");
                mgc_cleanup(obd);
                RETURN(-ENOENT);
        }

        rc = mgc_fs_setup(lmi->lmi_sb, lmi->lmi_mnt);
        if (rc) {
                CERROR("fs setup failed %d\n", rc);
                mgc_cleanup(obd);
                RETURN(-ENOENT);
                GOTO(err_rpc_lock, rc);
        }

        RETURN(rc);

err_rpc_lock:
        ptlrpcd_decref();
        OBD_FREE(mgc->mgc_rpc_lock, sizeof (*mgc->mgc_rpc_lock));
        RETURN(rc);
}


static int mgc_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_ioctl_data *data = karg;
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        MOD_INC_USE_COUNT;
#else
        if (!try_module_get(THIS_MODULE)) {
                CERROR("Can't get module. Is it alive?");
                return -EINVAL;
        }
#endif
        switch (cmd) {
        /* REPLicator context */
        case OBD_IOC_PARSE: {
                CERROR("MGC parsing llog %s\n", data->ioc_inlbuf1);
                ctxt = llog_get_context(exp->exp_obd, LLOG_CONFIG_REPL_CTXT);
                rc = class_config_parse_llog(ctxt, data->ioc_inlbuf1, NULL);
                GOTO(out, rc);
        }
#ifdef __KERNEL__
        case OBD_IOC_LLOG_INFO:
        case OBD_IOC_LLOG_PRINT: {
                ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
                rc = llog_ioctl(ctxt, cmd, data);

                GOTO(out, rc);
        }
#endif
        /* ORIGinator context */
        case OBD_IOC_DUMP_LOG: {
                struct lvfs_run_ctxt saved;
                ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = class_config_dump_llog(ctxt, data->ioc_inlbuf1, NULL);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                if (rc)
                        RETURN(rc);

                RETURN(rc);
        }
        case OBD_IOC_START: {
                char *conf_prof;
                char *name = data->ioc_inlbuf1;
                int len = strlen(name) + sizeof("-conf");

                OBD_ALLOC(conf_prof, len);
                if (!conf_prof) {
                        CERROR("no memory\n");
                        RETURN(-ENOMEM);
                }
                sprintf(conf_prof, "%s-conf", name);

                ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
                rc = class_config_parse_llog(ctxt, conf_prof, NULL);
                if (rc < 0)
                        CERROR("Unable to process log: %s\n", conf_prof);
                OBD_FREE(conf_prof, len);

                RETURN(rc);
        }
        default:
                CERROR("mgc_ioctl(): unrecognised ioctl %#x\n", cmd);
                GOTO(out, rc = -ENOTTY);
        }
out:
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        MOD_DEC_USE_COUNT;
#else
        module_put(THIS_MODULE);
#endif

        return rc;
}

static int mgc_import_event(struct obd_device *obd,
                            struct obd_import *imp,
                            enum obd_import_event event)
{
        int rc = 0;

        LASSERT(imp->imp_obd == obd);

        switch (event) {
        case IMP_EVENT_DISCON: {
                break;
        }
        case IMP_EVENT_INACTIVE: {
                if (obd->obd_observer)
                        rc = obd_notify(obd->obd_observer, obd, 0);
                break;
        }
        case IMP_EVENT_ACTIVE: {
                if (obd->obd_observer)
                        rc = obd_notify(obd->obd_observer, obd, 1);
                break;
        }
        default:
                CERROR("Unknown import event %d\n", event);
                LBUG();
        }
        RETURN(rc);
}

static int mgc_llog_init(struct obd_device *obd, struct obd_device *tgt,
                         int count, struct llog_catid *logid)
{
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        rc = llog_setup(obd, LLOG_CONFIG_REPL_CTXT, tgt, 0, NULL,
                        &llog_client_ops);
        if (rc == 0) {
                ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
                ctxt->loc_imp = obd->u.mgc.mgc_import;
        }

        RETURN(rc);
}

static int mgc_llog_finish(struct obd_device *obd, int count)
{
        int rc;
        ENTRY;

        rc = llog_cleanup(llog_get_context(obd, LLOG_CONFIG_REPL_CTXT));
        RETURN(rc);
}

/*mgc_obd_setup for mount-conf*/
int mgc_obd_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct lustre_cfg* lcfg = buf;
        struct mgc_obd *mgc = &obddev->u.mgc;
        struct obd_import *imp;
        struct obd_uuid server_uuid;
        int rq_portal, rp_portal, connect_op;
        char *name = obddev->obd_type->typ_name;
        int rc;
        ENTRY;

        if (strcmp(name, LUSTRE_MGC_NAME) == 0) {
                rq_portal = MGS_REQUEST_PORTAL;
                rp_portal = MGC_REPLY_PORTAL;
                connect_op = MGS_CONNECT;
        } else {
                CERROR("wrong client OBD type \"%s\", can't setup\n",
                       name);
                RETURN(-EINVAL);
        }

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1) {
                CERROR("requires a TARGET UUID\n");
                RETURN(-EINVAL);
        }

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) > 37) {
                CERROR("client UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        if (LUSTRE_CFG_BUFLEN(lcfg, 2) < 1) {
                CERROR("setup requires a SERVER UUID\n");
                RETURN(-EINVAL);
        }

        if (LUSTRE_CFG_BUFLEN(lcfg, 2) > 37) {
                CERROR("target UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        sema_init(&mgc->mgc_sem, 1);
        mgc->mgc_conn_count = 0;
        memcpy(server_uuid.uuid, lustre_cfg_buf(lcfg, 2),
               min_t(unsigned int, LUSTRE_CFG_BUFLEN(lcfg, 2),
                     sizeof(server_uuid)));

        rc = ldlm_get_ref();
        if (rc) {
                CERROR("ldlm_get_ref failed: %d\n", rc);
                GOTO(err, rc);
        }

        ptlrpc_init_client(rq_portal, rp_portal, name,
                           &obddev->obd_ldlm_client);

        imp = class_new_import();
        if (imp == NULL)
                GOTO(err_ldlm, rc = -ENOENT);
        imp->imp_client = &obddev->obd_ldlm_client;
        imp->imp_obd = obddev;
        imp->imp_connect_op = connect_op;
        imp->imp_generation = 0;
        imp->imp_initial_recov = 1;
        INIT_LIST_HEAD(&imp->imp_pinger_chain);
        memcpy(imp->imp_target_uuid.uuid, lustre_cfg_buf(lcfg, 1),
               LUSTRE_CFG_BUFLEN(lcfg, 1));
        class_import_put(imp);

        rc = client_import_add_conn(imp, &server_uuid, 1);
        if (rc) {
                CERROR("can't add initial connection\n");
                GOTO(err_import, rc);
        }

        mgc->mgc_import = imp;

        RETURN(rc);

err_import:
        class_destroy_import(imp);
err_ldlm:
        ldlm_put_ref(0);
err:
        RETURN(rc);
}

/*mgc_obd_cleaup for mount-conf*/
int mgc_obd_cleanup(struct obd_device *obddev)
{
        struct mgc_obd *mgc = &obddev->u.mgc;

        if (!mgc->mgc_import)
                RETURN(-EINVAL);

        class_destroy_import(mgc->mgc_import);
        mgc->mgc_import = NULL;

        ldlm_put_ref(obddev->obd_force);

        RETURN(0);
}

/* mgc_connect_import for mount-conf*/
int mgc_connect_import(struct lustre_handle *dlm_handle,
                       struct obd_device *obd, struct obd_uuid *cluuid,
                       struct obd_connect_data *data)
{
        struct mgc_obd *mgc = &obd->u.mgc;
        struct obd_import *imp = mgc->mgc_import;
        struct obd_export *exp;
        int rc;
        ENTRY;

        down(&mgc->mgc_sem);
        rc = class_connect(dlm_handle, obd, cluuid);
        if (rc)
                GOTO(out_sem, rc);

        mgc->mgc_conn_count++;
        if (mgc->mgc_conn_count > 1)
                GOTO(out_sem, rc);
        exp = class_conn2export(dlm_handle);

        imp->imp_dlm_handle = *dlm_handle;
        rc = ptlrpc_init_import(imp);
        if (rc != 0) 
                GOTO(out_disco, rc);

        if (data)
                memcpy(&imp->imp_connect_data, data, sizeof(*data));
        rc = ptlrpc_connect_import(imp, NULL);
        if (rc != 0) {
                LASSERT (imp->imp_state == LUSTRE_IMP_DISCON);
                GOTO(out_disco, rc);
        }
        LASSERT(exp->exp_connection);

        ptlrpc_pinger_add_import(imp);
        EXIT;

        if (rc) {
out_disco:
                mgc->mgc_conn_count--;
                class_disconnect(exp);
        } else {
                class_export_put(exp);
        }
out_sem:
        up(&mgc->mgc_sem);
        return rc;
}

/* mgc_disconnect_export for mount-conf*/
int mgc_disconnect_export(struct obd_export *exp)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct mgc_obd *mgc = &obd->u.mgc;
        struct obd_import *imp = mgc->mgc_import;
        int rc = 0, err;
        ENTRY;

        if (!obd) {
                CERROR("invalid export for disconnect: exp %p cookie "LPX64"\n",
                       exp, exp ? exp->exp_handle.h_cookie : -1);
                RETURN(-EINVAL);
        }

        down(&mgc->mgc_sem);
        if (!mgc->mgc_conn_count) {
                CERROR("disconnecting disconnected device (%s)\n",
                       obd->obd_name);
                GOTO(out_sem, rc = -EINVAL);
        }

        mgc->mgc_conn_count--;
        if (mgc->mgc_conn_count)
                GOTO(out_no_disconnect, rc = 0);

        /* Some non-replayable imports (MDS's OSCs) are pinged, so just
         * delete it regardless.  (It's safe to delete an import that was
         * never added.) */
        (void)ptlrpc_pinger_del_import(imp);

        /* Yeah, obd_no_recov also (mainly) means "forced shutdown". */
        if (obd->obd_no_recov)
                ptlrpc_invalidate_import(imp);
        else
                rc = ptlrpc_disconnect_import(imp);

        EXIT;
 out_no_disconnect:
        err = class_disconnect(exp);
        if (!rc && err)
                rc = err;
 out_sem:
        up(&mgc->mgc_sem);
        RETURN(rc);
}

/* reuse the client_import_[add/del]_conn*/
struct obd_ops mgc_obd_ops = {
        .o_owner        = THIS_MODULE,
        .o_setup        = mgc_setup,
        .o_cleanup      = mgc_cleanup,
        .o_add_conn     = client_import_add_conn,
        .o_del_conn     = client_import_del_conn,
        .o_connect      = mgc_connect_import,
        .o_disconnect   = mgc_disconnect_export,
        .o_iocontrol    = mgc_iocontrol,
        .o_import_event = mgc_import_event,
        .o_llog_init    = mgc_llog_init,
        .o_llog_finish  = mgc_llog_finish,
};

int __init mgc_init(void)
{
        struct lprocfs_static_vars lvars;
        lprocfs_init_vars(mgc, &lvars);
        return class_register_type(&mgc_obd_ops, lvars.module_vars,
                                   LUSTRE_MGC_NAME);
}

#ifdef __KERNEL__
static void /*__exit*/ mgc_exit(void)
{
        class_unregister_type(LUSTRE_MGC_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Management Client");
MODULE_LICENSE("GPL");

module_init(mgc_init);
module_exit(mgc_exit);
#endif
