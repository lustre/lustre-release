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
#define D_MGC D_CONFIG|D_ERROR

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

/********************** class fns **********************/

static int mgc_fs_setup(struct obd_device *obd, struct super_block *sb, 
                        struct vfsmount *mnt)
{
        struct lvfs_run_ctxt saved;
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct client_obd *cli = &obd->u.cli;
        struct dentry *dentry;
        int err = 0;

        LASSERT(lsi);
        LASSERT(lsi->lsi_srv_mnt == mnt);

        /* The mgc fs exclusion sem. Only one fs can be setup at a time.
           Maybe just overload the cl_sem? */
        down(&cli->cl_mgc_sem);

        obd->obd_fsops = fsfilt_get_ops(MT_STR(lsi->lsi_ldd));
        if (IS_ERR(obd->obd_fsops)) {
               CERROR("No fstype %s rc=%ld\n", MT_STR(lsi->lsi_ldd), 
                      PTR_ERR(obd->obd_fsops));
               return(PTR_ERR(obd->obd_fsops));
        }

        cli->cl_mgc_vfsmnt = mnt;
        // FIXME which is the right SB? - filter_common_setup also 
        CERROR("SB's: fill=%p mnt=%p root=%p\n", sb, mnt->mnt_sb, mnt->mnt_root->d_inode->i_sb);
        fsfilt_setup(obd, mnt->mnt_root->d_inode->i_sb);

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

        /* We keep the cl_mgc_sem until mgc_fs_cleanup */
        return (0);

err_ops:        
        fsfilt_put_ops(obd->obd_fsops);
        obd->obd_fsops = NULL;
        cli->cl_mgc_vfsmnt = NULL;
        up(&cli->cl_mgc_sem);
        return(err);
}

static int mgc_fs_cleanup(struct obd_device *obd)
{
        struct client_obd *cli = &obd->u.cli;
        int rc = 0;

        LASSERT(cli->cl_mgc_vfsmnt != NULL);

        if (cli->cl_mgc_configs_dir != NULL) {
                struct lvfs_run_ctxt saved;
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                l_dput(cli->cl_mgc_configs_dir);
                cli->cl_mgc_configs_dir = NULL; 
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        }

        /* never got mount
        rc = server_put_mount(obd->obd_name, cli->cl_mgc_vfsmnt);
        if (rc)
             CERROR("mount_put failed %d\n", rc);
        */

        cli->cl_mgc_vfsmnt = NULL;
        
        if (obd->obd_fsops) 
                fsfilt_put_ops(obd->obd_fsops);
        
        up(&cli->cl_mgc_sem);
        
        return(rc);
}

static int mgc_cleanup(struct obd_device *obd)
{
        struct client_obd *cli = &obd->u.cli;
        int rc;

        /* FIXME calls to mgc_fs_setup must take an obd ref to insure there's
           no fs by the time we get here. */
        LASSERT(cli->cl_mgc_vfsmnt == NULL);
        
        rc = obd_llog_finish(obd, 0);
        if (rc != 0)
                CERROR("failed to cleanup llogging subsystems\n");

        ptlrpcd_decref();
        
        return client_obd_cleanup(obd);
}

static int mgc_setup(struct obd_device *obd, obd_count len, void *buf)
{
        int rc;
        ENTRY;

        ptlrpcd_addref();

        rc = client_obd_setup(obd, len, buf);
        if (rc)
                GOTO(err_decref, rc);

        rc = obd_llog_init(obd, obd, 0, NULL);
        if (rc) {
                CERROR("failed to setup llogging subsystems\n");
                GOTO(err_cleanup, rc);
        }

        RETURN(rc);

err_cleanup:
        client_obd_cleanup(obd);
err_decref:
        ptlrpcd_decref();
        RETURN(rc);
}

/* based on ll_mdc_blocking_ast */
static int mgc_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                            void *data, int flag)
{
        int rc;
        struct lustre_handle lockh;
        ENTRY;

        switch (flag) {
        case LDLM_CB_BLOCKING:
                /* mgs wants the lock, give it up... */
                LDLM_ERROR(lock, "MGC blocking CB");

                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc < 0) {
                        CDEBUG(D_INODE, "ldlm_cli_cancel: %d\n", rc);
                        RETURN(rc);
                }
                break;
        case LDLM_CB_CANCELING: {
                /* We've given up the lock, prepare ourselves to update.
                   FIXME */
                LDLM_ERROR(lock, "MGC cancel CB");
                
                //struct inode *inode = ll_inode_from_lock(lock);
                /* <adilger> in the MGC case I suspect this callback will 
                   trigger a new enqueue for the same lock (in a separate
                   thread likely, which won't match the just-being-cancelled
                   lock due to CBPENDING flag) + config llog processing */
                /* FIXME make sure not to re-enqueue when the mgc is stopping
                   (we get called from client_disconnect_export) */
                
                CERROR("Lock res "LPU64"\n", lock->l_resource->lr_name.name[0]);
                /* FIXME should pass logname,sb as part of lock->l_ast_data,
                   lustre_get_process_log that.  Or based on resource.
                   Either way, must have one lock per llog. */
                //update_llog();

                break;
        }
        default:
                LBUG();
        }

        RETURN(0);
}

/* based on ll_get_dir_page and osc_enqueue. */
static int mgc_enqueue(struct obd_export *exp, struct lov_stripe_md *lsm,
                       __u32 type, ldlm_policy_data_t *policy, __u32 mode,
                       int *flags, void *bl_cb, void *cp_cb, void *gl_cb,
                       void *data, __u32 lvb_len, void *lvb_swabber,
                       struct lustre_handle *lockh)
{                       
        struct obd_device *obd = class_exp2obd(exp);
        /* FIXME use fsname, vers and separate locks? see mgs_get_cfg_lock */
        struct ldlm_res_id res_id = { .name = { 12321 } };
        int rc;
        ENTRY;

        /* We're only called from obd_mount */
        //LASSERT(mode == LCK_CR);
        LASSERT(type == LDLM_PLAIN);

        CDEBUG(D_MGC, "Enqueue for %s\n", (char *)data);

        /* Search for already existing locks.*/
        rc = ldlm_lock_match(obd->obd_namespace, 0, &res_id, type, 
                             NULL, mode, lockh);
        if (rc == 1) 
                RETURN(ELDLM_OK);


        rc = ldlm_cli_enqueue(exp, NULL, obd->obd_namespace, res_id,
                              type, NULL, mode, flags, 
                              mgc_blocking_ast, ldlm_completion_ast, NULL,
                              data, NULL, 0, NULL, lockh);

        RETURN(rc);
}

static int mgc_cancel(struct obd_export *exp, struct lov_stripe_md *md,
                      __u32 mode, struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
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

/* Get index and add to config llog, depending on flags */
int mgc_target_add(struct obd_export *exp, struct mgmt_target_info *mti)
{
        struct ptlrpc_request *req;
        struct mgmt_target_info *req_mti, *rep_mti;
        int size = sizeof(*req_mti);
        int rep_size = sizeof(*mti);
        int rc;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), MGMT_TARGET_ADD, 
                              1, &size, NULL);
        if (!req)
                RETURN(rc = -ENOMEM);

        req_mti = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*req_mti));
        memcpy(req_mti, mti, sizeof(*req_mti));

        req->rq_replen = lustre_msg_size(1, &rep_size);

        CDEBUG(D_MGC, "requesting add for %s\n", mti->mti_svname);
        
        rc = ptlrpc_queue_wait(req);
        if (!rc) {
                rep_mti = lustre_swab_repbuf(req, 0, sizeof(*rep_mti),
                                             lustre_swab_mgmt_target_info);
                memcpy(mti, rep_mti, sizeof(*rep_mti));
                CDEBUG(D_MGC, "target_add %s got index = %d\n",
                       mti->mti_svname, mti->mti_stripe_index);
        } else {
                CERROR("target_add failed. rc=%d\n", rc);
        }
        ptlrpc_req_finished(req);

        RETURN(rc);
}

/* Remove from config llog */
int mgc_target_del(struct obd_export *exp, struct mgmt_target_info *mti)
{
        struct ptlrpc_request *req;
        struct mgmt_target_info *req_mti, *rep_mti;
        int size = sizeof(*req_mti);
        int rc;
        ENTRY;

        req = ptlrpc_prep_req(class_exp2cliimp(exp), MGMT_TARGET_DEL,
                              1, &size, NULL);
        if (!req)
                RETURN(rc = -ENOMEM);

        req_mti = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*req_mti));
        memcpy(req_mti, mti, sizeof(*req_mti));

        rc = ptlrpc_queue_wait(req);
        if (!rc) {
                int index;
                rep_mti = lustre_swab_repbuf(req, 0, sizeof(*rep_mti),
                                             lustre_swab_mgmt_target_info);
                index = rep_mti->mti_stripe_index;
                if (index != mti->mti_stripe_index) {
                        CERROR ("OST DEL failed. rc=%d\n", index);
                        GOTO (out, rc = -EINVAL);
                }
                CERROR("OST DEL OK.(old index = %d)\n", index);
        }
out:
        ptlrpc_req_finished(req);

        RETURN(rc);
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
        if (keylen == strlen("add_target") &&
            memcmp(key, "add_target", keylen) == 0) {
                struct mgmt_target_info *mti;
                if (vallen != sizeof(struct mgmt_target_info))
                        RETURN(-EINVAL);
                mti = (struct mgmt_target_info *)val;
                CDEBUG(D_MGC, "add_target %s %#x\n",
                       mti->mti_svname, mti->mti_flags);
                rc =  mgc_target_add(exp, mti);
                RETURN(rc);
        }
        if (keylen == strlen("set_fs") &&
            memcmp(key, "set_fs", keylen) == 0) {
                struct super_block *sb = (struct super_block *)val;
                struct lustre_sb_info *lsi;
                if (vallen != sizeof(struct super_block))
                        RETURN(-EINVAL);
                lsi = s2lsi(sb);
                rc = mgc_fs_setup(exp->exp_obd, sb, lsi->lsi_srv_mnt);
                if (rc) {
                        CERROR("set_fs got %d\n", rc);
                }
                RETURN(rc);
        }
        if (keylen == strlen("clear_fs") &&
            memcmp(key, "clear_fs", keylen) == 0) {
                if (vallen != 0)
                        RETURN(-EINVAL);
                rc = mgc_fs_cleanup(exp->exp_obd);
                if (rc) {
                        CERROR("clear_fs got %d\n", rc);
                }
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
        case IMP_EVENT_INVALIDATE: {
                struct ldlm_namespace *ns = obd->obd_namespace;

                ldlm_namespace_cleanup(ns, LDLM_FL_LOCAL_ONLY);

                break;
        }
        case IMP_EVENT_DISCON: 
        case IMP_EVENT_INACTIVE: 
        case IMP_EVENT_ACTIVE: 
        case IMP_EVENT_OCD:
                break;
        default:
                CERROR("Unknown import event %#x\n", event);
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

/* Get the client export to the MGS */
static struct obd_export *get_mgs_export(struct obd_device *mgc)
{
        struct obd_export *exp, *n;

        /* FIXME is this a Bad Idea?  Should I just store this export 
           somewhere in the u.cli? */

        /* There should be exactly 2 exports in the mgc, the mgs export and 
           the mgc self-export, in that order. So just return the list head. */
        LASSERT(!list_empty(&mgc->obd_exports));
        LASSERT(mgc->obd_num_exports == 2);
        list_for_each_entry_safe(exp, n, &mgc->obd_exports, exp_obd_chain) {
                LASSERT(exp != mgc->obd_self_export);
                break;
        }
        /*FIXME there's clearly a better way, but I'm too confused to sort it 
          out now...
        exp = &list_entry(&mgc->obd_exports->head, export_obd, exp_obd_chain);
        */
        return exp;
}

/* Get a config log from the MGS and process it.
   This func is called for both clients and servers. */
static int mgc_process_log(struct obd_device *mgc, char *logname, 
                           struct config_llog_instance *cfg)
{
        struct llog_ctxt *rctxt;
        struct config_llog_data *cld;
        struct lustre_handle lockh;
        int rc, rcl, flags = 0;
        ENTRY;

        rctxt = llog_get_context(mgc, LLOG_CONFIG_REPL_CTXT);
        if (!rctxt) {
                CERROR("missing llog context\n");
                RETURN(-EINVAL);
        }

        /* Remember where we last stopped in this log. 
           hmm - hold global config lock over the entire llog parse?
           I could just 'get' it again after the parse.  */
        if (cfg && cfg->cfg_instance) 
                cld = config_log_get(cfg->cfg_instance);
        else
                cld = config_log_get(logname);
        if (cld && cfg) {
                cfg->cfg_last_idx = cld->cld_gen;
                CDEBUG(D_MGC, "parsing log %s from %d\n", logname, 
                       cfg->cfg_last_idx);
        }

        /* Get the cfg lock on the llog */
        rcl = mgc_enqueue(get_mgs_export(mgc), NULL, LDLM_PLAIN, NULL, 
                          LCK_CR, &flags, NULL, NULL, NULL, 
                          logname, 0, NULL, &lockh);
        if (rcl) {
                CERROR("Can't get cfg lock: %d\n", rcl);
                config_log_put();
                RETURN(rcl);
        }
        
        //FIXME Copy the mgs remote log to the local disk

        rc = class_config_parse_llog(rctxt, logname, cfg);
        
        /* Now drop the lock so MGS can revoke it */ 
        rcl = mgc_cancel(get_mgs_export(mgc), NULL, LCK_CR, &lockh);
        if (rcl) {
                CERROR("Can't drop cfg lock: %d\n", rcl);
        }
        
        /* Remember our gen */
        if (!rc && cld && cfg)
                cld->cld_gen = cfg->cfg_last_idx;
        config_log_put();

        if (rc) {
                LCONSOLE_ERROR("%s: The configuration '%s' could not be read "
                               "(%d) from the MGS.\n",
                               mgc->obd_name, logname, rc);
        }

        RETURN(rc);
}

static int mgc_process_config(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = buf;
        int cmd;
        int rc = 0;
        ENTRY;

        switch(cmd = lcfg->lcfg_command) {
        case LCFG_LOV_ADD_OBD:
        case LCFG_LOV_DEL_OBD: {
                struct mgmt_target_info *mti;

                if (LUSTRE_CFG_BUFLEN(lcfg, 1) != 
                    sizeof(struct mgmt_target_info))
                        GOTO(out, rc = -EINVAL);

                mti = (struct mgmt_target_info *)lustre_cfg_buf(lcfg, 1);
                CDEBUG(D_MGC, "add_target %s %#x\n",    
                       mti->mti_svname, mti->mti_flags);
                rc = mgc_target_add(get_mgs_export(obd), mti);
                GOTO(out, rc);
        }
        case LCFG_PARSE_LOG: {
                char *logname = lustre_cfg_string(lcfg, 1);
                struct config_llog_instance *cfg;
                cfg = (struct config_llog_instance *)lustre_cfg_buf(lcfg, 2);
                CDEBUG(D_MGC, "parse_log %s from %d\n", logname, 
                       cfg->cfg_last_idx);
                rc = mgc_process_log(obd, logname, cfg);
                GOTO(out, rc);
        }
        default: {
                CERROR("Unknown command: %d\n", lcfg->lcfg_command);
                GOTO(out, rc = -EINVAL);

        }
        }
out:
        RETURN(rc);
}

struct obd_ops mgc_obd_ops = {
        .o_owner        = THIS_MODULE,
        .o_setup        = mgc_setup,
        .o_cleanup      = mgc_cleanup,
        .o_add_conn     = client_import_add_conn,
        .o_del_conn     = client_import_del_conn,
        .o_connect      = client_connect_import,
        .o_disconnect   = client_disconnect_export,
        .o_enqueue      = mgc_enqueue,
        .o_cancel       = mgc_cancel,
        .o_iocontrol    = mgc_iocontrol,
        .o_set_info     = mgc_set_info,
        .o_import_event = mgc_import_event,
        .o_llog_init    = mgc_llog_init,
        .o_llog_finish  = mgc_llog_finish,
        .o_process_config = mgc_process_config,
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
