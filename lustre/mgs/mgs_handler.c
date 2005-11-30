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

static int mgs_postsetup(struct obd_device *obd);
static int mgs_cleanup(struct obd_device *obd);

/* Establish a connection to the MGS.*/
static int mgs_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct obd_connect_data *data)
{
        struct obd_export *exp;
        int rc, abort_recovery;
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

#if 0
        /* FIXME: recovery of connection*/
        rc = mgs_client_add(obd, &obd->u.mgs, med, -1);
        GOTO(out, rc);
#endif 
out:
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

/* Start the MGS obd */
static int mgs_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lprocfs_static_vars lvars;
        char *ns_name = "MGS";
        struct mgs_obd *mgs = &obd->u.mgs;
        struct lustre_mount_info *lmi;
        struct lustre_sb_info *lsi;
        struct vfsmount *mnt;
        int rc = 0;
        ENTRY;

        CDEBUG(D_CONFIG, "Starting MGS\n");

        lmi = lustre_get_mount(obd->obd_name);
        if (!lmi) 
                RETURN(rc = -EINVAL);

        mnt = lmi->lmi_mnt;
        lsi = s2lsi(lmi->lmi_sb);
        obd->obd_fsops = fsfilt_get_ops(MT_STR(lsi->lsi_ldd));
        if (IS_ERR(obd->obd_fsops))
                GOTO(err_put, rc = PTR_ERR(obd->obd_fsops));

        /* namespace for mgs llog */
        obd->obd_namespace = ldlm_namespace_new(ns_name, LDLM_NAMESPACE_SERVER);
        if (obd->obd_namespace == NULL) {
                mgs_cleanup(obd);
                GOTO(err_ops, rc = -ENOMEM);
        }

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

        rc = mgs_postsetup(obd);
        if (rc)
                GOTO(err_fs, rc);

        lprocfs_init_vars(mgs, &lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

        LCONSOLE_INFO("MGS %s started\n", obd->obd_name);

        ldlm_timeout = 6;
        ping_evictor_start();

        RETURN(0);

err_fs:
        /* No extra cleanup needed for llog_init_commit_thread() */
        mgs_fs_cleanup(obd);
err_ns:
        ldlm_namespace_free(obd->obd_namespace, 0);
        obd->obd_namespace = NULL;
err_ops:
        fsfilt_put_ops(obd->obd_fsops);
err_put:
        lustre_put_mount(obd->obd_name, mgs->mgs_vfsmnt);
        mgs->mgs_sb = 0;
        return rc;
}

static int mgs_postsetup(struct obd_device *obd)
{
        int rc = 0;
        ENTRY;

        rc = llog_setup(obd, LLOG_CONFIG_ORIG_CTXT, obd, 0, NULL,
                        &llog_lvfs_ops);
        RETURN(rc);
}

static int mgs_precleanup(struct obd_device *obd, int stage)
{
        int rc = 0;
        ENTRY;

        llog_cleanup(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT));
        rc = obd_llog_finish(obd, 0);
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

//       lprocfs_obd_cleanup(obd);

 //       mgs_update_server_data(obd, 1);

        //mgs_fs_cleanup(obd);

        lustre_put_mount(obd->obd_name, mgs->mgs_vfsmnt);
        mgs->mgs_sb = NULL;

        ldlm_namespace_free(obd->obd_namespace, obd->obd_force);

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_recovering) {
                target_cancel_recovery_timer(obd);
                obd->obd_recovering = 0;
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);

        lvfs_clear_rdonly(save_dev);

        fsfilt_put_ops(obd->obd_fsops);

        LCONSOLE_INFO("MGS %s has stopped.\n", obd->obd_name);

        RETURN(0);
}

static int mgmt_handle_target_add(struct ptlrpc_request *req)
{    
        struct obd_device *obd = &req->rq_export->exp_obd;
        struct mgs_obd *mgs = &obd->u.mgs;
        struct mgmt_ost_info *req_moi, *moi, *rep_moi;
        int rep_size = sizeof(*moi);
        int index, rc;

        OBD_ALLOC(moi, sizeof(*moi));
        if (!moi)
                GOTO(out, rc = -ENOMEM);
        req_moi = lustre_swab_reqbuf(req, 0, sizeof(*moi),
                                     lustre_swab_mgmt_ost_info);
        memcpy(moi, req_moi, sizeof(*moi));
        
        /* NEED_INDEX implies FIRST_START, but not vice-versa */
        if (moi->moi_flags & LDD_F_NEED_INDEX) {
                rc = mgs_get_index(moi);
               // rc = mgmt_handle_first_connect(req);
        }

        if (moi->moi_flags & LDD_F_SV_TYPE_MDT) {
                rc = llog_add_mds(obd, moi);
        }

out:
        lustre_pack_reply(req, 1, &rep_size, NULL); 
        rep_moi = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*rep_moi));
        memcpy(rep_moi, moi, sizeof(*rep_moi));
        if (rc)
                rep_moi->moi_stripe_index = rc;
        return rc;
}

int mgs_handle(struct ptlrpc_request *req)
{
        struct mgs_obd *mgs = NULL; /* quell gcc overwarning */
        struct obd_device *obd = NULL;
        int fail = OBD_FAIL_MGMT_ALL_REPLY_NET;
        int rc = 0;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MGMT_ALL_REQUEST_NET | OBD_FAIL_ONCE, 0);

        LASSERT(current->journal_info == NULL);
        /* XXX identical to MDS */
        if (req->rq_reqmsg->opc != MGMT_CONNECT) {
                if (req->rq_export == NULL) {
                        CERROR("lustre_mgs: operation %d on unconnected MGS\n",
                               req->rq_reqmsg->opc);
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }
                obd = req->rq_export->exp_obd;
                mgs = &obd->u.mgs;
        }

        switch (req->rq_reqmsg->opc) {
        case MGMT_CONNECT:
                DEBUG_REQ(D_INODE, req, "connect");
                OBD_FAIL_RETURN(OBD_FAIL_MGMT_CONNECT_NET, 0);
                rc = target_handle_connect(req, mgs_handle);
                if (!rc) {
                        /* Now that we have an export, set mgs. */
                        obd = req->rq_export->exp_obd;
                        mgs = mgs_req2mgs(req);
                }
                break;

        case MGMT_DISCONNECT:
                DEBUG_REQ(D_INODE, req, "disconnect");
                OBD_FAIL_RETURN(OBD_FAIL_MGMT_DISCONNECT_NET, 0);
                rc = target_handle_disconnect(req);
                req->rq_status = rc;            /* superfluous? */
                break;

        case LDLM_ENQUEUE:
                DEBUG_REQ(D_INODE, req, "enqueue");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_ENQUEUE, 0);
                rc = ldlm_handle_enqueue(req, ldlm_server_completion_ast,
                                         ldlm_server_blocking_ast, NULL);
                fail = OBD_FAIL_LDLM_REPLY;
                break;
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                DEBUG_REQ(D_INODE, req, "callback");
                CERROR("callbacks should not happen on MDS\n");
                LBUG();
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_BL_CALLBACK, 0);
                break;

        case OBD_PING:
                DEBUG_REQ(D_INODE, req, "ping");
                rc = target_handle_ping(req);
                break;

        case OBD_LOG_CANCEL:
                CDEBUG(D_INODE, "log cancel\n");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOG_CANCEL_NET, 0);
                rc = -ENOTSUPP; /* la la la */
                break;
        case MGMT_FIRST_CONNECT:
                CDEBUG(D_INODE, "server connect at first time\n");
                OBD_FAIL_RETURN(OBD_FAIL_MGMT_FIRST_CONNECT, 0);
                rc = mgmt_handle_first_connect(req);
                break;
        case MGMT_TARGET_ADD:
                CDEBUG(D_INODE, "target add\n");
                rc = mgmt_handle_target_add(req);
                break;
        case MGMT_TARGET_DEL:
                CDEBUG(D_INODE, "target del\n");
                rc = mgmt_handle_target_del(req);
                break;
        case MGMT_MDS_ADD:
                CDEBUG(D_INODE, "mds add\n");
                rc = mgmt_handle_mds_add(req);
                break;
        case LLOG_ORIGIN_HANDLE_CREATE:
                DEBUG_REQ(D_INODE, req, "llog_init");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_create(req);
                break;
        case LLOG_ORIGIN_HANDLE_NEXT_BLOCK:
                DEBUG_REQ(D_INODE, req, "llog next block");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_next_block(req);
                break;
        case LLOG_ORIGIN_HANDLE_READ_HEADER:
                DEBUG_REQ(D_INODE, req, "llog read header");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_read_header(req);
                break;
        case LLOG_ORIGIN_HANDLE_CLOSE:
                DEBUG_REQ(D_INODE, req, "llog close");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_close(req);
                break;
        case LLOG_CATINFO:
                DEBUG_REQ(D_INODE, req, "llog catinfo");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_catinfo(req);
                break;
        default:
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
        }

        LASSERT(current->journal_info == NULL);

 out:
        target_send_reply(req, rc, fail);
        RETURN(0);
}

static int mgt_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct lprocfs_static_vars lvars;
        int rc = 0;
        ENTRY;

       lprocfs_init_vars(mgt, &lvars);
       lprocfs_obd_setup(obd, lvars.obd_vars);

        mgs->mgs_service =
                ptlrpc_init_svc(MGS_NBUFS, MGS_BUFSIZE, MGS_MAXREQSIZE,
                                MGS_MAXREPSIZE, MGS_REQUEST_PORTAL, 
                                MGC_REPLY_PORTAL, MGS_SERVICE_WATCHDOG_TIMEOUT,
                                mgs_handle, "mgs", obd->obd_proc_entry, NULL,
                                MGT_NUM_THREADS);

        if (!mgs->mgs_service) {
                CERROR("failed to start service\n");
                GOTO(err_lprocfs, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(obd, mgs->mgs_service, "ll_mgt");
        if (rc)
                GOTO(err_thread, rc);

        RETURN(0);

err_thread:
        ptlrpc_unregister_service(mgs->mgs_service);
err_lprocfs:
        lprocfs_obd_cleanup(obd);
        return rc;
}


static int mgt_cleanup(struct obd_device *obd)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        ENTRY;

        ptlrpc_unregister_service(mgs->mgs_service);

        lprocfs_obd_cleanup(obd);

        RETURN(0);
}

struct lvfs_callback_ops mgs_lvfs_ops = {
     //     l_fid2dentry:     mgs_lvfs_fid2dentry,
    //    l_open_llog:      mgs_lvfs_open_llog,
};

/* use obd ops to offer management infrastructure */
static struct obd_ops mgs_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_connect         = mgs_connect,
        .o_disconnect      = mgs_disconnect,
        .o_setup           = mgs_setup,
        .o_precleanup      = mgs_precleanup,
        .o_cleanup         = mgs_cleanup,
        .o_iocontrol       = mgs_iocontrol,
};

static struct obd_ops mgt_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_setup           = mgt_setup,
        .o_cleanup         = mgt_cleanup,
};

static int __init mgs_init(void)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(mgs, &lvars);
        class_register_type(&mgs_obd_ops, lvars.module_vars, LUSTRE_MGS_NAME);
        lprocfs_init_vars(mgt, &lvars);
        class_register_type(&mgt_obd_ops, lvars.module_vars, LUSTRE_MGT_NAME);

        return 0;
}

static void /*__exit*/ mgs_exit(void)
{
        class_unregister_type(LUSTRE_MGS_NAME);
        class_unregister_type(LUSTRE_MGT_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre  Management Server (MGS)");
MODULE_LICENSE("GPL");

module_init(mgs_init);
module_exit(mgs_exit);
