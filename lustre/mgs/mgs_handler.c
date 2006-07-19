/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mgs/mgs_handler.c
 *  Lustre Management Server (mgs) request handler
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Nathan Rutman <nathan@clusterfs.com>
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
#define D_MGS D_CONFIG/*|D_WARNING*/

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/pagemap.h>
# include <linux/miscdevice.h>
# include <linux/init.h>
#else
# include <liblustre.h>
#endif

#include <obd_class.h>
#include <lustre_dlm.h>
#include <lprocfs_status.h>
#include <lustre_fsfilt.h>
#include <lustre_commit_confd.h>
#include <lustre_disk.h>
#include <lustre_ver.h>
#include "mgs_internal.h"


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
                data->ocd_connect_flags &= MGS_CONNECT_SUPPORTED;
                exp->exp_connect_flags = data->ocd_connect_flags;
                data->ocd_version = LUSTRE_VERSION_CODE;
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

static int mgs_cleanup(struct obd_device *obd);
static int mgs_handle(struct ptlrpc_request *req);

/* Start the MGS obd */
static int mgs_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
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

        /* Allow reconnect attempts */
        obd->obd_replayable = 1;

        /* Internal mgs setup */
        mgs_init_fsdb_list(obd);
        sema_init(&mgs->mgs_sem, 1);

        /* Start the service threads */
        mgs->mgs_service =
                ptlrpc_init_svc(MGS_NBUFS, MGS_BUFSIZE, MGS_MAXREQSIZE,
                                MGS_MAXREPSIZE, MGS_REQUEST_PORTAL,
                                MGC_REPLY_PORTAL, MGS_SERVICE_WATCHDOG_TIMEOUT,
                                mgs_handle, LUSTRE_MGS_NAME,
                                obd->obd_proc_entry, NULL, MGS_NUM_THREADS,
                                LCT_MD_THREAD);

        if (!mgs->mgs_service) {
                CERROR("failed to start service\n");
                GOTO(err_fs, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(obd, mgs->mgs_service, "ll_mgs");
        if (rc)
                GOTO(err_thread, rc);

        /* Setup proc */
        lprocfs_init_vars(mgs, &lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

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

static int mgs_precleanup(struct obd_device *obd, enum obd_cleanup_stage stage)
{
        int rc = 0;
        ENTRY;

        switch (stage) {
        case OBD_CLEANUP_EARLY:
        case OBD_CLEANUP_EXPORTS:
                break;
        case OBD_CLEANUP_SELF_EXP:
                llog_cleanup(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT));
                rc = obd_llog_finish(obd, 0);
                break;
        case OBD_CLEANUP_OBD:
                break;
        }
        RETURN(rc);
}

static int mgs_ldlm_nsfree(void *data)
{
        struct ldlm_namespace *ns = (struct ldlm_namespace *)data;
        int rc;
        ENTRY;

        ptlrpc_daemonize("ll_mgs_nsfree");
        rc = ldlm_namespace_free(ns, 1 /* obd_force should always be on */);
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

        ptlrpc_unregister_service(mgs->mgs_service);

        lprocfs_obd_cleanup(obd);

        mgs_cleanup_fsdb_list(obd);

        mgs_fs_cleanup(obd);

        server_put_mount(obd->obd_name, mgs->mgs_vfsmnt);
        mgs->mgs_sb = NULL;

        /* Free the namespace in it's own thread, so that if the
           ldlm_cancel_handler put the last mgs obd ref, we won't
           deadlock here. */
        cfs_kernel_thread(mgs_ldlm_nsfree, obd->obd_namespace,
                          CLONE_VM | CLONE_FILES);

        lvfs_clear_rdonly(save_dev);

        fsfilt_put_ops(obd->obd_fsops);

        LCONSOLE_INFO("%s has stopped.\n", obd->obd_name);
        RETURN(0);
}

/* similar to filter_prepare_destroy */
static int mgs_get_cfg_lock(struct obd_device *obd, char *fsname,
                            struct lustre_handle *lockh)
{
        struct ldlm_res_id res_id;
        int rc, flags = 0;
        ENTRY;

        rc = mgc_logname2resid(fsname, &res_id);
        if (!rc)
                rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, res_id,
                                      LDLM_PLAIN, NULL, LCK_EX, &flags,
                                      ldlm_blocking_ast, ldlm_completion_ast,
                                      NULL, fsname, NULL, 0, NULL, lockh);
        if (rc)
                CERROR("can't take cfg lock for %s (%d)\n", fsname, rc);

        RETURN(rc);
}

static int mgs_put_cfg_lock(struct lustre_handle *lockh)
{
        ENTRY;
        ldlm_lock_decref(lockh, LCK_EX);
        RETURN(0);
}

/* rc=0 means ok */
static int mgs_check_target(struct obd_device *obd, struct mgs_target_info *mti)
{
        int rc;
        ENTRY;

        rc = mgs_check_index(obd, mti);
        if (rc == 0) {
                LCONSOLE_ERROR("Index for %s has disappeared!  "
                               "Regenerating this portion of the logs."
                               "\n", mti->mti_svname);
                mti->mti_flags |= LDD_F_UPDATE;
                rc = 1;
        } else if (rc == -1) {
                LCONSOLE_ERROR("Client log %s-client has disappeared! "
                               "Regenerating all logs.\n",
                               mti->mti_fsname);
                mti->mti_flags |= LDD_F_WRITECONF;
                rc = 1;
        } else {
                /* Index is correctly marked as used */

                /* If the logs don't contain the mti_nids then add
                   them as failover nids */
                rc = mgs_check_failnid(obd, mti);
        }


        RETURN(rc);
}

/* Called whenever a target starts up.  Flags indicate first connect, etc. */
static int mgs_handle_target_reg(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct lustre_handle lockh;
        struct mgs_target_info *mti, *rep_mti;
        int rep_size = sizeof(*mti);
        int rc = 0, lockrc;
        ENTRY;

        mti = lustre_swab_reqbuf(req, 0, sizeof(*mti),
                                 lustre_swab_mgs_target_info);

        if (!(mti->mti_flags & (LDD_F_WRITECONF | LDD_F_UPGRADE14 |
                                LDD_F_UPDATE))) {
                /* We're just here as a startup ping. */
                CDEBUG(D_MGS, "Server %s is running on %s\n",
                       mti->mti_svname, obd_export_nid2str(req->rq_export));
                rc = mgs_check_target(obd, mti);
                /* above will set appropriate mti flags */
                if (!rc)
                        /* Nothing wrong, don't revoke lock */
                        GOTO(out_nolock, rc);
        }

        /* Revoke the config lock to make sure nobody is reading. */
        /* Although actually I think it should be alright if
           someone was reading while we were updating the logs - if we
           revoke at the end they will just update from where they left off. */
        lockrc = mgs_get_cfg_lock(obd, mti->mti_fsname, &lockh);
        if (lockrc != ELDLM_OK) {
                LCONSOLE_ERROR("%s: Can't signal other nodes to update "
                               "their configuration (%d). Updating local logs "
                               "anyhow; you might have to manually restart "
                               "other nodes to get the latest configuration.\n",
                               obd->obd_name, lockrc);
        }

        /* Log writing contention is handled by the fsdb_sem */

        if (mti->mti_flags & LDD_F_WRITECONF) {
                rc = mgs_erase_logs(obd, mti->mti_fsname);
                mti->mti_flags |= LDD_F_UPDATE;
                LCONSOLE_WARN("%s: Logs for fs %s were removed by user request."
                              " All servers must re-register in order to "
                              "regenerate the client log.\n",
                              obd->obd_name, mti->mti_fsname);
                mti->mti_flags &= ~LDD_F_WRITECONF;
        }

        /* COMPAT_146 */
        if (mti->mti_flags & LDD_F_UPGRADE14) {
                rc = mgs_upgrade_sv_14(obd, mti);
                if (rc) {
                        CERROR("Can't upgrade from 1.4 (%d)\n", rc);
                        GOTO(out, rc);
                }

                mti->mti_flags &= ~LDD_F_UPGRADE14;
                /* Turn off the upgrade flag permanently */
                mti->mti_flags |= LDD_F_REWRITE_LDD;
        }
        /* end COMPAT_146 */

        if (mti->mti_flags & LDD_F_UPDATE) {
                CDEBUG(D_MGS, "adding %s, index=%d\n", mti->mti_svname,
                       mti->mti_stripe_index);

                /* create the log for the new target
                   and update the client/mdt logs */
                rc = mgs_write_log_target(obd, mti);
                if (rc) {
                        CERROR("Failed to write %s log (%d)\n",
                               mti->mti_svname, rc);
                        GOTO(out, rc);
                }

                mti->mti_flags &= ~(LDD_F_VIRGIN | LDD_F_UPDATE |
                                    LDD_F_NEED_INDEX);
                mti->mti_flags |= LDD_F_REWRITE_LDD;
        }

out:
        /* done with log update */
        if (lockrc == ELDLM_OK)
                mgs_put_cfg_lock(&lockh);
out_nolock:
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
        int fail = OBD_FAIL_MGS_ALL_REPLY_NET;
        int rc = 0;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MGS_ALL_REQUEST_NET | OBD_FAIL_ONCE, 0);

        LASSERT(current->journal_info == NULL);
        if (req->rq_reqmsg->opc != MGS_CONNECT) {
                if (req->rq_export == NULL) {
                        CERROR("lustre_mgs: operation %d on unconnected MGS\n",
                               req->rq_reqmsg->opc);
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }
        }

        switch (req->rq_reqmsg->opc) {
        case MGS_CONNECT:
                DEBUG_REQ(D_MGS, req, "connect");
                rc = target_handle_connect(req, mgs_handle);
                if (!rc && (req->rq_reqmsg->conn_cnt > 1))
                        /* Make clients trying to reconnect after a MGS restart
                           happy; also requires obd_replayable */
                        lustre_msg_add_op_flags(req->rq_repmsg,
                                                MSG_CONNECT_RECONNECT);
                break;
        case MGS_DISCONNECT:
                DEBUG_REQ(D_MGS, req, "disconnect");
                rc = target_handle_disconnect(req);
                req->rq_status = rc;            /* superfluous? */
                break;
        case MGS_TARGET_REG:
                DEBUG_REQ(D_MGS, req, "target add\n");
                rc = mgs_handle_target_reg(req);
                break;
        case MGS_TARGET_DEL:
                DEBUG_REQ(D_MGS, req, "target del\n");
                //rc = mgs_handle_target_del(req);
                break;

        case LDLM_ENQUEUE:
                DEBUG_REQ(D_MGS, req, "enqueue");
                rc = ldlm_handle_enqueue(req, ldlm_server_completion_ast,
                                         ldlm_server_blocking_ast, NULL);
                fail = OBD_FAIL_LDLM_REPLY;
                break;
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                DEBUG_REQ(D_MGS, req, "callback");
                CERROR("callbacks should not happen on MGS\n");
                LBUG();
                break;

        case OBD_PING:
                DEBUG_REQ(D_INFO, req, "ping");
                rc = target_handle_ping(req);
                break;
        case OBD_LOG_CANCEL:
                DEBUG_REQ(D_MGS, req, "log cancel\n");
                rc = -ENOTSUPP; /* la la la */
                break;

        case LLOG_ORIGIN_HANDLE_CREATE:
                DEBUG_REQ(D_MGS, req, "llog_init");
                rc = llog_origin_handle_create(req);
                break;
        case LLOG_ORIGIN_HANDLE_NEXT_BLOCK:
                DEBUG_REQ(D_MGS, req, "llog next block");
                rc = llog_origin_handle_next_block(req);
                break;
        case LLOG_ORIGIN_HANDLE_READ_HEADER:
                DEBUG_REQ(D_MGS, req, "llog read header");
                rc = llog_origin_handle_read_header(req);
                break;
        case LLOG_ORIGIN_HANDLE_CLOSE:
                DEBUG_REQ(D_MGS, req, "llog close");
                rc = llog_origin_handle_close(req);
                break;
        case LLOG_CATINFO:
                DEBUG_REQ(D_MGS, req, "llog catinfo");
                rc = llog_catinfo(req);
                break;
        default:
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
        }

        LASSERT(current->journal_info == NULL);

        CDEBUG_EX(D_CONFIG | (rc?D_ERROR:0), "MGS handle cmd=%d rc=%d\n",
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

/* from mdt_iocontrol */
int mgs_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                  void *karg, void *uarg)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_ioctl_data *data = karg;
        struct lvfs_run_ctxt saved;
        int rc = 0;

        ENTRY;
        CDEBUG(D_IOCTL, "handling ioctl cmd %#x\n", cmd);

        switch (cmd) {

        case OBD_IOC_PARAM: {
                struct lustre_handle lockh;
                struct lustre_cfg *lcfg;
                struct llog_rec_hdr rec;
                char fsname[32], *devname;
                int lockrc;

                CERROR("MGS param\n");

                rec.lrh_len = llog_data_len(data->ioc_plen1);

                if (data->ioc_type == LUSTRE_CFG_TYPE) {
                        rec.lrh_type = OBD_CFG_REC;
                } else {
                        CERROR("unknown cfg record type:%d \n", data->ioc_type);
                        RETURN(-EINVAL);
                }

                OBD_ALLOC(lcfg, data->ioc_plen1);
                if (lcfg == NULL)
                        RETURN(-ENOMEM);
                rc = copy_from_user(lcfg, data->ioc_pbuf1, data->ioc_plen1);
                if (rc)
                        GOTO(out_free, rc);

                if (lcfg->lcfg_bufcount < 1)
                        GOTO(out_free, rc = -EINVAL);

                /* Extract fsname */
                memset(fsname, 0, sizeof(fsname));
                devname = lustre_cfg_string(lcfg, 0);
                if (devname) {
                        char *ptr = strchr(devname, '-');
                        if (!ptr) {
                                /* assume devname is the fsname */
                                strncpy(fsname, devname, sizeof(fsname));
                        } else {
                                strncpy(fsname, devname, ptr - devname);
                        }
                        CDEBUG(D_MGS, "set param on fs %s device %s\n",
                               fsname, devname);
                } else {
                        CDEBUG(D_MGS, "set global param\n");
                }

                rc = mgs_setparam(obd, fsname, lcfg);
                if (rc) {
                        CERROR("setparam err %d\n", rc);
                        GOTO(out_free, rc);
                }

                /* Revoke lock so everyone updates.  Should be alright if
                   someone was already reading while we were updating the logs,
                   so we don't really need to hold the lock while we're
                   writing (above). */
                if (fsname) {
                        lockrc = mgs_get_cfg_lock(obd, fsname, &lockh);
                        if (lockrc != ELDLM_OK)
                                CERROR("lock error %d for fs %s\n", lockrc,
                                       fsname);
                        else
                                mgs_put_cfg_lock(&lockh);
                }
out_free:
                OBD_FREE(lcfg, data->ioc_plen1);
                RETURN(rc);
        }

        case OBD_IOC_DUMP_LOG: {
                struct llog_ctxt *ctxt =
                        llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = class_config_dump_llog(ctxt, data->ioc_inlbuf1, NULL);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                if (rc)
                        RETURN(rc);

                RETURN(rc);
        }

        case OBD_IOC_LLOG_CHECK:
        case OBD_IOC_LLOG_INFO:
        case OBD_IOC_LLOG_PRINT: {
                struct llog_ctxt *ctxt =
                        llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);

                push_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
                rc = llog_ioctl(ctxt, cmd, data);
                pop_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);

                RETURN(rc);
        }

        default:
                CDEBUG(D_INFO, "unknown command %x\n", cmd);
                RETURN(-EINVAL);
        }
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
        class_register_type(&mgs_obd_ops, NULL,
                            lvars.module_vars, LUSTRE_MGS_NAME, NULL);

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
