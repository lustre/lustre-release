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
#include "mgs_internal.h"

static int mgs_postsetup(struct obd_device *obd);
static int mgs_cleanup(struct obd_device *obd);

/* Establish a connection to the MGS.*/
static int mgs_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct obd_connect_data *data)
{
        struct obd_export *exp;
        struct mgs_export_data *med;
        struct mgs_client_data *mcd;
        int rc, abort_recovery;
        ENTRY;

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        /* Check for aborted recovery. */
        spin_lock_bh(&obd->obd_processing_task_lock);
        abort_recovery = obd->obd_abort_recovery;
        spin_unlock_bh(&obd->obd_processing_task_lock);
        if (abort_recovery)
                target_abort_recovery(obd);

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);
        exp = class_conn2export(conn);
        LASSERT(exp);
        med = &exp->exp_mgs_data;

        if (data != NULL) {
                data->ocd_connect_flags &= MGS_CONNECT_SUPPORTED;
                exp->exp_connect_flags = data->ocd_connect_flags;
        }

        OBD_ALLOC(mcd, sizeof(*mcd));
        if (!mcd) {
                CERROR("mgs: out of memory for client data\n");
                GOTO(out, rc = -ENOMEM);
        }

        memcpy(mcd->mcd_uuid, cluuid, sizeof(mcd->mcd_uuid));
        med->med_mcd = mcd;

out:
        if (rc) {
                if (mcd) {
                        OBD_FREE(mcd, sizeof(*mcd));
                        med->med_mcd = NULL;
                }
                class_disconnect(exp);
        } else {
                class_export_put(exp);
        }

        RETURN(rc);
}

static int mgs_init_export(struct obd_export *exp)
{
        struct mgs_export_data *med = &exp->exp_mgs_data;

        INIT_LIST_HEAD(&med->med_open_head);
        spin_lock_init(&med->med_open_lock);
        RETURN(0);
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

/* mount the file system (secretly) */
static int mgs_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lprocfs_static_vars lvars;
        struct lustre_cfg* lcfg = buf;
        char *options = NULL;
        struct mgs_obd *mgs = &obd->u.mgs;
        struct vfsmount *mnt;
        unsigned long page;
        int rc = 0;
        ENTRY;

        /* setup 1:/dev/loop/0 2:ext3 3:mgs 4:errors=remount-ro,iopen_nopriv*/

        if (lcfg->lcfg_bufcount < 3)
                RETURN(rc = -EINVAL);

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) == 0 || LUSTRE_CFG_BUFLEN(lcfg, 2) == 0)
                RETURN(rc = -EINVAL);

        obd->obd_fsops = fsfilt_get_ops(lustre_cfg_string(lcfg, 2));
        if (IS_ERR(obd->obd_fsops))
                RETURN(rc = PTR_ERR(obd->obd_fsops));

        page = __get_free_page(GFP_KERNEL);
        if (!page)
                RETURN(-ENOMEM);

        options = (char *)page;
        memset(options, 0, PAGE_SIZE);

        if (LUSTRE_CFG_BUFLEN(lcfg, 4) > 0 && lustre_cfg_buf(lcfg, 4))
                sprintf(options , ",%s", lustre_cfg_string(lcfg, 4));

        //FIXME mount was already done in lustre_fill_super,
        //we just need to access it
        mnt = do_kern_mount(lustre_cfg_string(lcfg, 2), 0,
                            lustre_cfg_string(lcfg, 1), (void *)options);
        free_page(page);
        if (IS_ERR(mnt)) {
                rc = PTR_ERR(mnt);
                CERROR("do_kern_mount failed: rc = %d\n", rc);
                GOTO(err_ops, rc);
        }

        CDEBUG(D_SUPER, "%s: mnt = %p\n", lustre_cfg_string(lcfg, 1), mnt);

        LASSERT(!lvfs_check_rdonly(lvfs_sbdev(mnt->mnt_sb)));

        rc = mgs_fs_setup(obd, mnt);
        if (rc) {
                CERROR("%s: MGS filesystem method init failed: rc = %d\n",
                       obd->obd_name, rc);
                GOTO(err_put, rc);
        }

        INIT_LIST_HEAD(&mgs->mgs_open_llogs);
        INIT_LIST_HEAD(&mgs->mgs_update_llhs);

        rc = llog_start_commit_thread();
        if (rc < 0)
                GOTO(err_fs, rc);
#if 0  
        //FIXME: no LDLM support for llog now
        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mgs_ldlm_client", &obd->obd_ldlm_client);
#endif
        obd->obd_replayable = 1;

        rc = mgs_postsetup(obd);
        if (rc)
                GOTO(err_fs, rc);

        lprocfs_init_vars(mgs, &lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

        if (obd->obd_recovering) {
                LCONSOLE_WARN("MGT %s now serving %s, but will be in recovery "
                              "until %d %s reconnect, or if no clients "
                              "reconnect for %d:%.02d; during that time new "
                              "clients will not be allowed to connect. "
                              "Recovery progress can be monitored by watching "
                              "/proc/fs/lustre/mgs/%s/recovery_status.\n",
                              obd->obd_name,
                              lustre_cfg_string(lcfg, 1),
                              obd->obd_recoverable_clients,
                              (obd->obd_recoverable_clients == 1) 
                              ? "client" : "clients",
                              (int)(OBD_RECOVERY_TIMEOUT / HZ) / 60,
                              (int)(OBD_RECOVERY_TIMEOUT / HZ) % 60,
                              obd->obd_name);
        } else {
                LCONSOLE_INFO("MGT %s now serving %s with recovery %s.\n",
                              obd->obd_name,
                              lustre_cfg_string(lcfg, 1),
                              obd->obd_replayable ? "enabled" : "disabled");
        }
//FIXME: no ldlm support now
        ldlm_timeout = 6;
        ping_evictor_start();

        RETURN(0);

err_fs:
        /* No extra cleanup needed for llog_init_commit_thread() */
        mgs_fs_cleanup(obd);
err_put:
        unlock_kernel();
        mntput(mgs->mgs_vfsmnt);
        mgs->mgs_sb = 0;
        lock_kernel();
err_ops:
        fsfilt_put_ops(obd->obd_fsops);
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
        int must_relock = 0;
        ENTRY;

        ping_evictor_stop();

        if (mgs->mgs_sb == NULL)
                RETURN(0);
        save_dev = lvfs_sbdev(mgs->mgs_sb);

        lprocfs_obd_cleanup(obd);

        mgs_update_server_data(obd, 1);

        mgs_fs_cleanup(obd);

        if (atomic_read(&obd->u.mgs.mgs_vfsmnt->mnt_count) > 2)
                CERROR("%s: mount busy, mnt_count %d != 2\n", obd->obd_name,
                       atomic_read(&obd->u.mgs.mgs_vfsmnt->mnt_count));

        /* We can only unlock kernel if we are in the context of sys_ioctl,
           otherwise we never called lock_kernel */
        if (kernel_locked()) {
                unlock_kernel();
                must_relock++;
        }

        mntput(mgs->mgs_vfsmnt);
        mgs->mgs_sb = NULL;

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_recovering) {
                target_cancel_recovery_timer(obd);
                obd->obd_recovering = 0;
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);

        lvfs_clear_rdonly(save_dev);

        if (must_relock)
                lock_kernel();

        fsfilt_put_ops(obd->obd_fsops);

        LCONSOLE_INFO("MDT %s has stopped.\n", obd->obd_name);

        RETURN(0);
}

/* Look up an entry by inode number. */
/* this function ONLY returns valid dget'd dentries with an initialized inode
   or errors */
struct dentry *mgs_fid2dentry(struct mgs_obd *mgs, struct ll_fid *fid,
                              struct vfsmount **mnt)
{
        unsigned long ino = fid->id;
        __u32 generation = fid->generation;
        struct mgs_open_llog *mollog, *n;
        struct list_head *llog_list = &mgs->mgs_open_llogs;
        struct inode *inode;
        struct dentry *result = NULL;

        if (ino == 0)
                RETURN(ERR_PTR(-ESTALE));


        CDEBUG(D_DENTRY, "--> mgs_fid2dentry: ino/gen %lu/%u, sb %p\n",
               ino, generation, mgs->mgs_sb);

        list_for_each_entry_safe(mollog, n, llog_list, mol_list) {
                if (mollog->mol_id == ino) {
                        result = mollog->mol_dentry;
                        dget(result);
                }
        }

        if (!result)
                RETURN(NULL);

        inode = result->d_inode;
        if (!inode)
                RETURN(ERR_PTR(-ENOENT));

        if (generation && inode->i_generation != generation) {
                /* we didn't find the right inode.. */
                CERROR("bad inode %lu, link: %lu ct: %d or generation %u/%u\n",
                       inode->i_ino, (unsigned long)inode->i_nlink,
                       atomic_read(&inode->i_count), inode->i_generation,
                       generation);
                dput(result);
                RETURN(ERR_PTR(-ENOENT));
        }

        if (mnt) {
                *mnt = mgs->mgs_vfsmnt;
                mntget(*mnt);
        }

        RETURN(result);
}

static struct dentry *mgs_lvfs_fid2dentry(__u64 id, __u32 gen, __u64 gr,
                                          void *data)
{
        struct obd_device *obd = data;
        struct ll_fid fid;
        fid.id = id;
        fid.generation = gen;
        return mgs_fid2dentry(&obd->u.mgs, &fid, NULL);
}

static int mgs_open_llog(__u64 id, void *data, void *handle)
{
        struct obd_device *obd = data; 
        struct mgs_update_llh *mul = handle;
        struct llog_handle *lgh = &mul->mul_lgh;
        struct dentry *dentry = lgh->lgh_file->f_dentry;
        __u64  id = dentry->d_inode->i_ino;
        struct mgs_obd *mgs = &obd->u.mgs;
        struct mgs_open_llog *mollog, *n;
        struct list_head *llog_list = &mgs->mgs_open_llogs;
         
        list_for_each_entry_safe(mollog, n, llog_list, mol_list) {
                if (mollog->mol_id == id) {
                        spin_lock(&mollog->mol_lock);
                        mollog->mol_ref++;
                        spin_unlock(&mollog->mol_lock);
                        dget(dentry);
                        return 0;
                }
        }

        /* add a new open llog  to mgs_open_llogs */
        OBD_ALLOC(mollog, sizeof(*mollog));
        if (!mollog) {
                CERROR("No memory for mollog.\n");
                return -ENOMEM;
        }
        mollog->mol_id = id;
        mollog->mol_dentry = dentry;
        mollog->mol_update = 0;
        mollog->mol_ref = 1;
        spin_lock_init(&mollog->mol_lock);

        spin_lock(&mgs->mgs_llogs_lock);
        list_add(&mollog->mol_list, &mgs->mgs_open_llogs);
        spin_unlock(&mgs->mgs_llogs_lock);

        lgh->
        return 0;
}

int mgs_handle(struct ptlrpc_request *req)
{
        int fail = OBD_FAIL_MGS_ALL_REPLY_NET;
        int rc = 0;
        struct mgs_obd *mgs = NULL; /* quell gcc overwarning */
        struct obd_device *obd = NULL;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MGS_ALL_REQUEST_NET | OBD_FAIL_ONCE, 0);

        LASSERT(current->journal_info == NULL);
        /* XXX identical to MDS */
        if (req->rq_reqmsg->opc != MGS_CONNECT) {
                struct mgs_export_data *med;
                int abort_recovery;

                if (req->rq_export == NULL) {
                        CERROR("lustre_mgs: operation %d on unconnected MGS\n",
                               req->rq_reqmsg->opc);
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }

                med = &req->rq_export->exp_mgs_data;
                obd = req->rq_export->exp_obd;
                mgs = &obd->u.mgs;

                /* sanity check: if the xid matches, the request must
                 * be marked as a resent or replayed */
                if (req->rq_xid == med->med_mcd->mcd_last_xid)
                        LASSERTF(lustre_msg_get_flags(req->rq_reqmsg) &
                                 (MSG_RESENT | MSG_REPLAY),
                                 "rq_xid "LPU64" matches last_xid, "
                                 "expected RESENT flag\n",
                                 req->rq_xid);
                /* else: note the opposite is not always true; a
                 * RESENT req after a failover will usually not match
                 * the last_xid, since it was likely never
                 * committed. A REPLAYed request will almost never
                 * match the last xid, however it could for a
                 * committed, but still retained, open. */

                /* Check for aborted recovery. */
                spin_lock_bh(&obd->obd_processing_task_lock);
                abort_recovery = obd->obd_abort_recovery;
                spin_unlock_bh(&obd->obd_processing_task_lock);
                if (abort_recovery) {
                        target_abort_recovery(obd);
                } 
        }

        switch (req->rq_reqmsg->opc) {
        case MGS_CONNECT:
                DEBUG_REQ(D_INODE, req, "connect");
                OBD_FAIL_RETURN(OBD_FAIL_MGS_CONNECT_NET, 0);
                rc = target_handle_connect(req, mgs_handle);
                if (!rc) {
                        /* Now that we have an export, set mgs. */
                        obd = req->rq_export->exp_obd;
                        mgs = mgs_req2mgs(req);
                }
                break;

        case MGS_DISCONNECT:
                DEBUG_REQ(D_INODE, req, "disconnect");
                OBD_FAIL_RETURN(OBD_FAIL_MGS_DISCONNECT_NET, 0);
                rc = target_handle_disconnect(req);
                req->rq_status = rc;            /* superfluous? */
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

        /* If we're DISCONNECTing, the mgs_export_data is already freed */
        if (!rc && req->rq_reqmsg->opc != MGS_DISCONNECT) {
                struct mgs_export_data *med = &req->rq_export->exp_mgs_data;
                req->rq_repmsg->last_xid =
                        le64_to_cpu(med->med_mcd->mcd_last_xid);

                target_committed_to_req(req);
        }

        EXIT;
 out:

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LAST_REPLAY) {
                if (obd && obd->obd_recovering) {
                        DEBUG_REQ(D_HA, req, "LAST_REPLAY, queuing reply");
                        return target_queue_final_reply(req, rc);
                }
                /* Lost a race with recovery; let the error path DTRT. */
                rc = req->rq_status = -ENOTCONN;
        }

        target_send_reply(req, rc, fail);
        return 0;
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
                                MGS_REQUEST_PORTAL, MGC_REPLY_PORTAL,
                                MGS_SERVICE_WATCHDOG_TIMEOUT,
                                mgs_handle, "mgs", obd->obd_proc_entry, NULL);

        if (!mgs->mgs_service) {
                CERROR("failed to start service\n");
                GOTO(err_lprocfs, rc = -ENOMEM);
        }

        rc = ptlrpc_start_n_threads(obd, mgs->mgs_service, MGT_NUM_THREADS,
                                    "ll_mgt");
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
        l_fid2dentry:     mgs_lvfs_fid2dentry,
        l_open_llog:      mgs_lvfs_open_llog,
};

/* use obd ops to offer management infrastructure */
static struct obd_ops mgs_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_connect         = mgs_connect,
        .o_init_export     = mgs_init_export,
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
