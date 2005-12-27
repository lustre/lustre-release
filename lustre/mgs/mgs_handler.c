/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mgs/mgs_handler.c
 *  Lustre Management Server (mgs) request handler
 *
 *  Copyright (C) 2001-2005 Cluster File Systems, Inc.
 *   Author Nathan <nathan@clusterfs.com>
 *   Author LinSongTao <lincent@clusterfs.com>
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MGS
#define D_MGS D_CONFIG|D_ERROR

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
#include <linux/lprocfs_status.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_commit_confd.h>
#include <linux/lustre_disk.h>
#include "mgs_internal.h"

static int mgs_cleanup(struct obd_device *obd);

/* Establish a connection to the MGS.*/
static int mgs_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct obd_connect_data *data)
{
        struct obd_export *exp;
        int rc;
        ENTRY;

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);
        exp = class_conn2export(conn);
        LASSERT(exp);

        if (data != NULL) {
                data->ocd_connect_flags &= MGMT_CONNECT_SUPPORTED;
                exp->exp_connect_flags = data->ocd_connect_flags;
        }

        if (rc) {
                class_disconnect(exp);
        } else {
                class_export_put(exp);
        }

        RETURN(rc);
}

static int mgs_disconnect(struct obd_export *exp)
{
        unsigned long irqflags;
        int rc;
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

        /* Disconnect early so that clients can't keep using export */
        rc = class_disconnect(exp);
        ldlm_cancel_locks_for_export(exp);

        /* complete all outstanding replies */
        spin_lock_irqsave(&exp->exp_lock, irqflags);
        while (!list_empty(&exp->exp_outstanding_replies)) {
                struct ptlrpc_reply_state *rs =
                        list_entry(exp->exp_outstanding_replies.next,
                                   struct ptlrpc_reply_state, rs_exp_list);
                struct ptlrpc_service *svc = rs->rs_service;

                spin_lock(&svc->srv_lock);
                list_del_init(&rs->rs_exp_list);
                ptlrpc_schedule_difficult_reply(rs);
                spin_unlock(&svc->srv_lock);
        }
        spin_unlock_irqrestore(&exp->exp_lock, irqflags);

        class_export_put(exp);
        RETURN(rc);
}

static int mgs_handle(struct ptlrpc_request *req);

/* Start the MGS obd */
static int mgs_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lprocfs_static_vars lvars;
        struct mgs_obd *mgs = &obd->u.mgs;
        struct lustre_mount_info *lmi;
        struct lustre_sb_info *lsi;
        struct vfsmount *mnt;
        int rc = 0;
        ENTRY;

        CDEBUG(D_CONFIG, "Starting MGS\n");

        /* Find our disk */
        lmi = server_get_mount(obd->obd_name);
        if (!lmi) 
                RETURN(rc = -EINVAL);

        mnt = lmi->lmi_mnt;
        lsi = s2lsi(lmi->lmi_sb);
        obd->obd_fsops = fsfilt_get_ops(MT_STR(lsi->lsi_ldd));
        if (IS_ERR(obd->obd_fsops))
                GOTO(err_put, rc = PTR_ERR(obd->obd_fsops));

        /* namespace for mgs llog */
        obd->obd_namespace = ldlm_namespace_new("MGS", LDLM_NAMESPACE_SERVER);
        if (obd->obd_namespace == NULL) {
                mgs_cleanup(obd);
                GOTO(err_ops, rc = -ENOMEM);
        }

        /* ldlm setup */
        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mgs_ldlm_client", &obd->obd_ldlm_client);

        LASSERT(!lvfs_check_rdonly(lvfs_sbdev(mnt->mnt_sb)));

        rc = mgs_fs_setup(obd, mnt);
        if (rc) {
                CERROR("%s: MGS filesystem method init failed: rc = %d\n",
                       obd->obd_name, rc);
                GOTO(err_ns, rc);
        }

        rc = llog_start_commit_thread();
        if (rc < 0)
                GOTO(err_fs, rc);

        rc = llog_setup(obd, LLOG_CONFIG_ORIG_CTXT, obd, 0, NULL,
                        &llog_lvfs_ops);
        if (rc)
                GOTO(err_fs, rc);

        /* Internal mgs setup */
        mgs_init_db_list(obd);

        /* Start the service threads */
        mgs->mgs_service =
                ptlrpc_init_svc(MGS_NBUFS, MGS_BUFSIZE, MGS_MAXREQSIZE,
                                MGS_MAXREPSIZE, MGS_REQUEST_PORTAL, 
                                MGC_REPLY_PORTAL, MGS_SERVICE_WATCHDOG_TIMEOUT,
                                mgs_handle, LUSTRE_MGS_NAME, 
                                obd->obd_proc_entry, NULL, MGS_NUM_THREADS);

        if (!mgs->mgs_service) {
                CERROR("failed to start service\n");
                GOTO(err_fs, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(obd, mgs->mgs_service, "lustre_mgs");
        if (rc)
                GOTO(err_thread, rc);

        /* Setup proc */
        lprocfs_init_vars(mgs, &lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

        ldlm_timeout = 6;
        ping_evictor_start();

        LCONSOLE_INFO("MGS %s started\n", obd->obd_name);

        RETURN(0);

err_thread:
        ptlrpc_unregister_service(mgs->mgs_service);
err_fs:
        /* No extra cleanup needed for llog_init_commit_thread() */
        mgs_fs_cleanup(obd);
err_ns:
        ldlm_namespace_free(obd->obd_namespace, 0);
        obd->obd_namespace = NULL;
err_ops:
        fsfilt_put_ops(obd->obd_fsops);
err_put:
        server_put_mount(obd->obd_name, mgs->mgs_vfsmnt);
        mgs->mgs_sb = 0;
        return rc;
}

static int mgs_precleanup(struct obd_device *obd, int stage)
{
        int rc = 0;
        ENTRY;

        switch (stage) {
        case OBD_CLEANUP_SELF_EXP:
                mgs_cleanup_db_list(obd);
                llog_cleanup(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT));
                rc = obd_llog_finish(obd, 0);
        }
        RETURN(rc);
}

static int mgs_cleanup(struct obd_device *obd)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        lvfs_sbdev_type save_dev;
        ENTRY;

        ping_evictor_stop();

        if (mgs->mgs_sb == NULL)
                RETURN(0);

        save_dev = lvfs_sbdev(mgs->mgs_sb);
        
        lprocfs_obd_cleanup(obd);

        ptlrpc_unregister_service(mgs->mgs_service);

        mgs_fs_cleanup(obd);

        server_put_mount(obd->obd_name, mgs->mgs_vfsmnt);
        mgs->mgs_sb = NULL;

        ldlm_namespace_free(obd->obd_namespace, obd->obd_force);

        LASSERT(!obd->obd_recovering);

        lvfs_clear_rdonly(save_dev);

        fsfilt_put_ops(obd->obd_fsops);

        LCONSOLE_INFO("%s has stopped.\n", obd->obd_name);

        RETURN(0);
}

/* similar to filter_prepare_destroy */
static int mgs_get_cfg_lock(struct obd_device *obd, char *fsname,
                            struct lustre_handle *lockh)
{
        /* FIXME resource should be based on fsname, 
           one lock per fs.  One lock per config log? */
        struct ldlm_res_id res_id = {.name = {12321}};
        int rc, flags = 0;

        CERROR("mgs_lock %s\n", fsname);

        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, res_id,
                              LDLM_PLAIN, NULL, LCK_EX, &flags,
                              ldlm_blocking_ast, ldlm_completion_ast, 
                              NULL, NULL, NULL, 0, NULL, lockh);
        if (rc) {
                CERROR("can't take cfg lock %d\n", rc);
        }

        return rc;
}

static int mgs_put_cfg_lock(struct lustre_handle *lockh)
{
        CERROR("mgs_unlock\n");
        
        ldlm_lock_decref(lockh, LCK_EX);
        return 0;
}

static int mgs_handle_target_add(struct ptlrpc_request *req)
{    
        struct obd_device *obd = req->rq_export->exp_obd;
        struct lustre_handle lockh;
        struct mgmt_target_info *mti, *rep_mti;
        int rep_size = sizeof(*mti);
        int rc, lockrc;
        ENTRY;

        mti = lustre_swab_reqbuf(req, 0, sizeof(*mti),
                                 lustre_swab_mgmt_target_info);
        
        CDEBUG(D_MGS, "adding %s, index=%d\n", mti->mti_svname, 
               mti->mti_stripe_index);

        /* set the new target index if needed */
        if (mti->mti_flags & LDD_F_NEED_INDEX) {
                rc = mgs_set_next_index(obd, mti);
                if (rc) {
                        CERROR("Can't get index (%d)\n", rc);
                        GOTO(out, rc);
                }
        }

        /* revoke the config lock so everyone will update */
        lockrc = mgs_get_cfg_lock(obd, mti->mti_fsname, &lockh);
        if (lockrc != ELDLM_OK) {
                LCONSOLE_ERROR("Can't signal other nodes to update their "
                               "configuration (%d). Updating local logs "
                               "anyhow; you might have to manually restart "
                               "other servers to get the latest configuration."
                               "\n", lockrc);
        }

        /* create the log for the new target 
           and update the client/mdt logs */
        rc = mgs_write_log_target(obd, mti);
        
        /* done with log update */
        if (lockrc == ELDLM_OK)
                mgs_put_cfg_lock(&lockh);

        if (rc) {
                CERROR("Failed to write %s log (%d)\n", 
                       mti->mti_svname, rc);
                GOTO(out, rc);
        }

out:
        CDEBUG(D_MGS, "replying with %s, index=%d, rc=%d\n", mti->mti_svname, 
               mti->mti_stripe_index, rc);
        lustre_pack_reply(req, 1, &rep_size, NULL); 
        /* send back the whole mti in the reply */
        rep_mti = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*rep_mti));
        memcpy(rep_mti, mti, sizeof(*rep_mti));
        RETURN(rc);
}

int mgs_handle(struct ptlrpc_request *req)
{
        int fail = OBD_FAIL_MGMT_ALL_REPLY_NET;
        int rc = 0;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MGMT_ALL_REQUEST_NET | OBD_FAIL_ONCE, 0);

        LASSERT(current->journal_info == NULL);
        if (req->rq_reqmsg->opc != MGMT_CONNECT) {
                if (req->rq_export == NULL) {
                        CERROR("lustre_mgs: operation %d on unconnected MGS\n",
                               req->rq_reqmsg->opc);
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }
        }

        switch (req->rq_reqmsg->opc) {
        case MGMT_CONNECT:
                DEBUG_REQ(D_MGS, req, "connect");
                OBD_FAIL_RETURN(OBD_FAIL_MGMT_CONNECT_NET, 0);
                rc = target_handle_connect(req, mgs_handle);
                break;
        case MGMT_DISCONNECT:
                DEBUG_REQ(D_MGS, req, "disconnect");
                OBD_FAIL_RETURN(OBD_FAIL_MGMT_DISCONNECT_NET, 0);
                rc = target_handle_disconnect(req);
                req->rq_status = rc;            /* superfluous? */
                break;

        case MGMT_TARGET_ADD:
                DEBUG_REQ(D_MGS, req, "target add\n");
                rc = mgs_handle_target_add(req);
                break;
        case MGMT_TARGET_DEL:
                DEBUG_REQ(D_MGS, req, "target del\n");
                //rc = mgs_handle_target_del(req);
                break;

        case LDLM_ENQUEUE:
                DEBUG_REQ(D_MGS, req, "enqueue");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_ENQUEUE, 0);
                rc = ldlm_handle_enqueue(req, ldlm_server_completion_ast,
                                         ldlm_server_blocking_ast, NULL);
                fail = OBD_FAIL_LDLM_REPLY;
                break;
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                DEBUG_REQ(D_MGS, req, "callback");
                CERROR("callbacks should not happen on MGS\n");
                LBUG();
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_BL_CALLBACK, 0);
                break;

        case OBD_PING:
                DEBUG_REQ(D_INFO, req, "ping");
                rc = target_handle_ping(req);
                break;

        case OBD_LOG_CANCEL:
                DEBUG_REQ(D_MGS, req, "log cancel\n");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOG_CANCEL_NET, 0);
                rc = -ENOTSUPP; /* la la la */
                break;

        case LLOG_ORIGIN_HANDLE_CREATE:
                DEBUG_REQ(D_MGS, req, "llog_init");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_create(req);
                break;
        case LLOG_ORIGIN_HANDLE_NEXT_BLOCK:
                DEBUG_REQ(D_MGS, req, "llog next block");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_next_block(req);
                break;
        case LLOG_ORIGIN_HANDLE_READ_HEADER:
                DEBUG_REQ(D_MGS, req, "llog read header");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_read_header(req);
                break;
        case LLOG_ORIGIN_HANDLE_CLOSE:
                DEBUG_REQ(D_MGS, req, "llog close");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_close(req);
                break;
        case LLOG_CATINFO:
                DEBUG_REQ(D_MGS, req, "llog catinfo");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_catinfo(req);
                break;
        default:
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
        }

        LASSERT(current->journal_info == NULL);
        
        CDEBUG(D_CONFIG | (rc?D_ERROR:0), "MGS handle cmd=%d rc=%d\n",
               req->rq_reqmsg->opc, rc);

 out:
        target_send_reply(req, rc, fail);
        RETURN(0);
}

static inline int mgs_destroy_export(struct obd_export *exp)
{
        ENTRY;

        target_destroy_export(exp);

        RETURN(0);
}


/* use obd ops to offer management infrastructure */
static struct obd_ops mgs_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_connect         = mgs_connect,
        .o_disconnect      = mgs_disconnect,
        .o_setup           = mgs_setup,
        .o_precleanup      = mgs_precleanup,
        .o_cleanup         = mgs_cleanup,
        .o_destroy_export  = mgs_destroy_export,
        .o_iocontrol       = mgs_iocontrol,
};

static int __init mgs_init(void)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(mgs, &lvars);
        class_register_type(&mgs_obd_ops, lvars.module_vars, LUSTRE_MGS_NAME);

        return 0;
}

static void /*__exit*/ mgs_exit(void)
{
        class_unregister_type(LUSTRE_MGS_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre  Management Server (MGS)");
MODULE_LICENSE("GPL");

module_init(mgs_init);
module_exit(mgs_exit);
