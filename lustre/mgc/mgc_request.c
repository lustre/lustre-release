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
#define DEBUG_SUBSYSTEM S_MGC

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/pagemap.h>
# include <linux/miscdevice.h>
# include <linux/init.h>
#else
# include <liblustre.h>
#endif

#include <linux/obd_class.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_log.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_disk.h>
#include <linux/lustre_mgs.h>

#include "mgc_internal.h"


/* Get index and add to config llog, depending on flags */
int mgc_target_add(struct obd_export *exp, struct mgmt_ost_info *moi)
{
        struct ptlrpc_request *req;
        struct mgmt_ost_info *req_moi, *rep_moi;
        int size = sizeof(*req_moi);
        int rep_size = sizeof(*moi);
        int rc;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), MGMT_TARGET_ADD, 
                              1, &size, NULL);
        if (!req)
                RETURN(rc = -ENOMEM);

        req_moi = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*req_moi));
        memcpy(req_moi, moi, sizeof(*req_moi));

        req->rq_replen = lustre_msg_size(1, &rep_size);

        rc = ptlrpc_queue_wait(req);
        if (!rc) {
                int index;
                rep_moi = lustre_swab_repbuf(req, 0, sizeof(*rep_moi),
                                             lustre_swab_mgmt_ost_info);
                index = rep_moi->moi_stripe_index;
                if (index != moi->moi_stripe_index) {
                        CERROR ("OST ADD failed. rc=%d\n", index);
                        GOTO (out, rc = -EINVAL);
                }
                CERROR("OST ADD OK.(index = %d)\n", index);
        }
out:
        ptlrpc_req_finished(req);

        RETURN(rc);
}
EXPORT_SYMBOL(mgc_target_add); 

/* Remove from config llog */
int mgc_target_del(struct obd_export *exp, struct mgmt_ost_info *moi)
{
        struct ptlrpc_request *req;
        struct mgmt_ost_info *req_moi, *rep_moi;
        int size = sizeof(*req_moi);
        int rc;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), MGMT_TARGET_DEL,
                              1, &size, NULL);
        if (!req)
                RETURN(rc = -ENOMEM);

        req_moi = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*req_moi));
        memcpy(req_moi, moi, sizeof(*req_moi));

        rc = ptlrpc_queue_wait(req);
        if (!rc) {
                int index;
                rep_moi = lustre_swab_repbuf(req, 0, sizeof(*rep_moi),
                                             lustre_swab_mgmt_ost_info);
                index = rep_moi->moi_stripe_index;
                if (index != moi->moi_stripe_index) {
                        CERROR ("OST DEL failed. rc=%d\n", index);
                        GOTO (out, rc = -EINVAL);
                }
                CERROR("OST DEL OK.(old index = %d)\n", index);
        }
out:
        ptlrpc_req_finished(req);

        RETURN(rc);
}
EXPORT_SYMBOL(mgc_target_del);

static int mgc_fs_setup(struct obd_device *obd, struct super_block *sb, 
                        struct vfsmount *mnt)
{
        struct lvfs_run_ctxt saved;
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct client_obd *cli = &obd->u.cli;
        struct dentry *dentry;
        int err = 0;

        LASSERT(lsi);

        obd->obd_fsops = fsfilt_get_ops(MT_STR(lsi->lsi_ldd));
        if (IS_ERR(obd->obd_fsops)) {
               CERROR("No fstype %s rc=%ld\n", MT_STR(lsi->lsi_ldd), 
                      PTR_ERR(obd->obd_fsops));
               return(PTR_ERR(obd->obd_fsops));
        }

        cli->cl_mgc_vfsmnt = mnt;
        cli->cl_mgc_sb = mnt->mnt_root->d_inode->i_sb;
        // FIXME which is the right SB? - filter_common_setup also 
        CERROR("SB's: fill=%p mnt=%p root=%p\n", sb, mnt->mnt_sb, mnt->mnt_root->d_inode->i_sb);
        fsfilt_setup(obd, cli->cl_mgc_sb);

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
        cli->cl_mgc_configs_dir = dentry;
        return (0);

err_ops:        
        fsfilt_put_ops(obd->obd_fsops);
        obd->obd_fsops = NULL;
        cli->cl_mgc_sb = NULL;
        return(err);
}

static int mgc_fs_cleanup(struct obd_device *obd)
{
        struct client_obd *cli = &obd->u.cli;
        int rc;

        if (cli->cl_mgc_configs_dir != NULL) {
                struct lvfs_run_ctxt saved;
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                l_dput(cli->cl_mgc_configs_dir);
                cli->cl_mgc_configs_dir = NULL; 
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        }

        rc = lustre_put_mount(obd->obd_name, cli->cl_mgc_vfsmnt);
        if (rc)
             CERROR("mount_put failed %d\n", rc);

        cli->cl_mgc_vfsmnt = NULL;
        cli->cl_mgc_sb = NULL;
        
        if (obd->obd_fsops) 
                fsfilt_put_ops(obd->obd_fsops);
        return(rc);
}

static int mgc_cleanup(struct obd_device *obd)
{
        struct client_obd *cli = &obd->u.cli;
        int rc;

        //lprocfs_obd_cleanup(obd);

        if (cli->cl_mgc_vfsmnt) {
                /* if we're a server, eg. something's mounted */
                mgc_fs_cleanup(obd);
        }

        rc = obd_llog_finish(obd, 0);
        if (rc != 0)
                CERROR("failed to cleanup llogging subsystems\n");

        ptlrpcd_decref();
        
        OBD_FREE(cli->cl_mgc_rpc_lock, sizeof (*cli->cl_mgc_rpc_lock));

        return client_obd_cleanup(obd);
}

/* the same as mdc_setup */
static int mgc_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct client_obd *cli = &obd->u.cli;
        int rc;
        ENTRY;

        OBD_ALLOC(cli->cl_mgc_rpc_lock, sizeof (*cli->cl_mgc_rpc_lock));
        if (!cli->cl_mgc_rpc_lock)
                RETURN(-ENOMEM);
        mgc_init_rpc_lock(cli->cl_mgc_rpc_lock);

        ptlrpcd_addref();

        rc = client_obd_setup(obd, len, buf);
        if (rc)
                GOTO(err_rpc_lock, rc);

        rc = obd_llog_init(obd, obd, 0, NULL);
        if (rc) {
                CERROR("failed to setup llogging subsystems\n");
                GOTO(err_rpc_lock, rc);
        }

#if 0
        struct lustre_mount_info *lmi;
        /* FIXME There's only one mgc for all local servers.  Must mgc_fs_setup 
           on demand only when reading a local log file, then cleanup.
           Make sure there's a lock so nobody else can mgc_fs_setup in the 
           meantime */
        lmi = lustre_get_mount(obd->obd_name);
        if (lmi) {
                CERROR("mgc has local disk\n");
                /* there's a local disk, we must get access */
                rc = mgc_fs_setup(obd, lmi->lmi_sb, lmi->lmi_mnt);
                if (rc) {
                        CERROR("fs setup failed %d\n", rc);
                        mgc_cleanup(obd);
                        RETURN(-ENOENT);
                }
        }
        else
                CERROR("mgc does not have local disk (client only)\n");
#endif

        INIT_LIST_HEAD(&cli->cl_mgc_open_llogs);

        RETURN(rc);

err_rpc_lock:
        ptlrpcd_decref();
        OBD_FREE(cli->cl_mgc_rpc_lock, sizeof (*cli->cl_mgc_rpc_lock));
        RETURN(rc);
}

static int mgc_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_ioctl_data *data = karg;
        struct llog_ctxt *ctxt;
        struct lvfs_run_ctxt saved;
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
                ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = class_config_dump_llog(ctxt, data->ioc_inlbuf1, NULL);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                if (rc)
                        RETURN(rc);

                GOTO(out, rc);
        }
        case OBD_IOC_START: {
                char *name = data->ioc_inlbuf1;
                CERROR("getting config log %s\n", name);
                /* FIXME Get llog from MGS */

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
                rc = class_config_parse_llog(ctxt, name, NULL);
                if (rc < 0)
                        CERROR("Unable to process log: %s\n", name);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                GOTO(out, rc);
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

#define INIT_RECOV_BACKUP "init_recov_bk"
int mgc_set_info(struct obd_export *exp, obd_count keylen,
                 void *key, obd_count vallen, void *val)
{
        struct obd_import *imp = class_exp2cliimp(exp);
        int rc = -EINVAL;
        ENTRY;

        /* Try to "recover" the initial connection; i.e. retry */
        if (keylen == strlen("initial_recov") &&
            memcmp(key, "initial_recov", keylen) == 0) {
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
                imp->imp_initial_recov = *(int *)val;
                CDEBUG(D_HA, "%s: set imp_initial_recov = %d\n",
                       exp->exp_obd->obd_name, imp->imp_initial_recov);
                RETURN(0);
        }
        /* Turn off initial_recov after we try all backup servers once */
        if (keylen == strlen(INIT_RECOV_BACKUP) &&
            memcmp(key, INIT_RECOV_BACKUP, keylen) == 0) {
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
                imp->imp_initial_recov_bk = *(int *)val;
                CDEBUG(D_HA, "%s: set imp_initial_recov_bk = %d\n",
                       exp->exp_obd->obd_name, imp->imp_initial_recov_bk);
                RETURN(0);
        }
        /* Hack alert */
        if (keylen == strlen("register") &&
            memcmp(key, "register", keylen) == 0) {
                struct mgmt_ost_info *moi;
                if (vallen != sizeof(struct mgmt_ost_info))
                        RETURN(-EINVAL);
                moi = (struct mgmt_ost_info *)val;
                CERROR("register %s %#x\n", moi->moi_ostname, moi->moi_flags);
                rc =  mgc_target_add(exp, moi);
                RETURN(rc);
        }
        RETURN(rc);
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
        case IMP_EVENT_INVALIDATE: {
                struct ldlm_namespace *ns = obd->obd_namespace;

                ldlm_namespace_cleanup(ns, LDLM_FL_LOCAL_ONLY);

                break;
        }
        case IMP_EVENT_INACTIVE: {
                break;
        }
        case IMP_EVENT_ACTIVE: {
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

        rc = llog_setup(obd, LLOG_CONFIG_ORIG_CTXT, tgt, 0, NULL,
                        &llog_lvfs_ops);
        if (rc)
                RETURN(rc);

        rc = llog_setup(obd, LLOG_CONFIG_REPL_CTXT, tgt, 0, NULL,
                        &llog_client_ops);
        if (rc == 0) {
                ctxt = llog_get_context(obd, LLOG_CONFIG_REPL_CTXT);
                ctxt->loc_imp = obd->u.cli.cl_import;
        }

        RETURN(rc);
}

static int mgc_llog_finish(struct obd_device *obd, int count)
{
        int rc;
        ENTRY;

        rc = llog_cleanup(llog_get_context(obd, LLOG_CONFIG_REPL_CTXT));
        rc = llog_cleanup(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT));

        RETURN(rc);
}

/* reuse the client_import_[add/del]_conn*/
struct obd_ops mgc_obd_ops = {
        .o_owner        = THIS_MODULE,
        .o_setup        = mgc_setup,
        .o_cleanup      = mgc_cleanup,
        .o_add_conn     = client_import_add_conn,
        .o_del_conn     = client_import_del_conn,
        .o_connect      = client_connect_import,
        .o_disconnect   = client_disconnect_export,
        .o_iocontrol    = mgc_iocontrol,
        .o_set_info     = mgc_set_info,
        .o_import_event = mgc_import_event,
        .o_llog_init    = mgc_llog_init,
        .o_llog_finish  = mgc_llog_finish,
};

int __init mgc_init(void)
{
        return class_register_type(&mgc_obd_ops, NULL, LUSTRE_MGC_NAME);
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
