/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
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

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_LDLM

#ifdef __KERNEL__
# include <linux/module.h>
#else
# include <liblustre.h>
#endif
#include <linux/obd_ost.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_mds.h>

int client_obd_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct ptlrpc_connection *conn;
        struct obd_ioctl_data* data = buf;
        struct client_obd *cli = &obddev->u.cli;
        struct obd_import *imp;
        struct obd_uuid server_uuid;
        int rq_portal, rp_portal, connect_op;
        char *name;
        ENTRY;

        if (obddev->obd_type->typ_ops->o_brw) {
                rq_portal = OST_REQUEST_PORTAL;
                rp_portal = OSC_REPLY_PORTAL;
                name = "osc";
                connect_op = OST_CONNECT;
        } else {
                rq_portal = MDS_REQUEST_PORTAL;
                rp_portal = MDC_REPLY_PORTAL;
                name = "mdc";
                connect_op = MDS_CONNECT;
        }

        if (data->ioc_inllen1 < 1) {
                CERROR("requires a TARGET UUID\n");
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen1 > 37) {
                CERROR("client UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen2 < 1) {
                CERROR("setup requires a SERVER UUID\n");
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen2 > 37) {
                CERROR("target UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        sema_init(&cli->cl_sem, 1);
        cli->cl_conn_count = 0;
        memcpy(server_uuid.uuid, data->ioc_inlbuf2, MIN(data->ioc_inllen2,
                                                        sizeof(server_uuid)));

        conn = ptlrpc_uuid_to_connection(&server_uuid);
        if (conn == NULL)
                RETURN(-ENOENT);

        ptlrpc_init_client(rq_portal, rp_portal, name,
                           &obddev->obd_ldlm_client);

        imp = class_new_import();
        if (imp == NULL) {
                ptlrpc_put_connection(conn);
                RETURN(-ENOMEM);
        }
        imp->imp_connection = conn;
        imp->imp_client = &obddev->obd_ldlm_client;
        imp->imp_obd = obddev;
        imp->imp_connect_op = connect_op;
        imp->imp_generation = 0;
        memcpy(imp->imp_target_uuid.uuid, data->ioc_inlbuf1, data->ioc_inllen1);
        class_import_put(imp);

        cli->cl_import = imp;
        cli->cl_max_mds_easize = sizeof(struct lov_mds_md);
        cli->cl_sandev = to_kdev_t(0);

        RETURN(0);
}

int client_obd_cleanup(struct obd_device *obddev, int force, int failover)
{
        struct client_obd *client = &obddev->u.cli;

        if (!client->cl_import)
                RETURN(-EINVAL);
        class_destroy_import(client->cl_import);
        client->cl_import = NULL;
        RETURN(0);
}

#ifdef __KERNEL__
/* convert a pathname into a kdev_t */
static kdev_t path2dev(char *path)
{
        struct dentry *dentry;
        struct nameidata nd;
        kdev_t dev;
        KDEVT_VAL(dev, 0);

        if (!path_init(path, LOOKUP_FOLLOW, &nd))
                return 0;

        if (path_walk(path, &nd))
                return 0;

        dentry = nd.dentry;
        if (dentry->d_inode && !is_bad_inode(dentry->d_inode) &&
            S_ISBLK(dentry->d_inode->i_mode))
                dev = dentry->d_inode->i_rdev;
        path_release(&nd);

        return dev;
}

int client_sanobd_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct client_obd *cli = &obddev->u.cli;
        ENTRY;

        if (data->ioc_inllen3 < 1) {
                CERROR("setup requires a SAN device pathname\n");
                RETURN(-EINVAL);
        }

        client_obd_setup(obddev, len, buf);

        cli->cl_sandev = path2dev(data->ioc_inlbuf3);
        if (!kdev_t_to_nr(cli->cl_sandev)) {
                CERROR("%s seems not a valid SAN device\n", data->ioc_inlbuf3);
                RETURN(-EINVAL);
        }

        RETURN(0);
}
#endif

int ptlrpc_import_connect(struct lustre_handle *conn, struct obd_device *obd,
                          struct obd_uuid *cluuid)
{
        struct client_obd *cli = &obd->u.cli;
        struct obd_import *imp = cli->cl_import;
        struct obd_export *exp;
        struct ptlrpc_request *request;
        /* XXX maybe this is a good time to create a connect struct? */
        int rc, size[] = {sizeof(imp->imp_target_uuid),
                          sizeof(obd->obd_uuid),
                          sizeof(*conn)};
        char *tmp[] = {imp->imp_target_uuid.uuid,
                       obd->obd_uuid.uuid,
                       (char *)conn};
        int rq_opc = (obd->obd_type->typ_ops->o_brw) ? OST_CONNECT :MDS_CONNECT;
        int msg_flags;

        ENTRY;
        down(&cli->cl_sem);
        rc = class_connect(conn, obd, cluuid);
        if (rc)
                GOTO(out_sem, rc);

        cli->cl_conn_count++;
        if (cli->cl_conn_count > 1)
                GOTO(out_sem, rc);

        if (obd->obd_namespace != NULL)
                CERROR("already have namespace!\n");
        obd->obd_namespace = ldlm_namespace_new(obd->obd_name,
                                                LDLM_NAMESPACE_CLIENT);
        if (obd->obd_namespace == NULL)
                GOTO(out_disco, rc = -ENOMEM);

        request = ptlrpc_prep_req(imp, rq_opc, 3, size, tmp);
        if (!request)
                GOTO(out_ldlm, rc = -ENOMEM);

        request->rq_level = LUSTRE_CONN_NEW;
        request->rq_replen = lustre_msg_size(0, NULL);

        imp->imp_export = exp = class_conn2export(conn);
        exp->exp_connection = ptlrpc_connection_addref(request->rq_connection);

        imp->imp_level = LUSTRE_CONN_CON;
        rc = ptlrpc_queue_wait(request);
        if (rc) {
                class_export_put(imp->imp_export);
                imp->imp_export = exp = NULL;
                GOTO(out_req, rc);
        }

        msg_flags = lustre_msg_get_op_flags(request->rq_repmsg);
        if (rq_opc == MDS_CONNECT || msg_flags & MSG_CONNECT_REPLAYABLE) {
                imp->imp_replayable = 1;
                CDEBUG(D_HA, "connected to replayable target: %s\n",
                       imp->imp_target_uuid.uuid);
        }
        imp->imp_level = LUSTRE_CONN_FULL;
        imp->imp_remote_handle = request->rq_repmsg->handle;
        CDEBUG(D_HA, "local import: %p, remote handle: "LPX64"\n", imp,
               imp->imp_remote_handle.cookie);

        EXIT;
out_req:
        ptlrpc_req_finished(request);
        if (rc) {
out_ldlm:
                ldlm_namespace_free(obd->obd_namespace);
                obd->obd_namespace = NULL;
out_disco:
                cli->cl_conn_count--;
                class_disconnect(conn, 0);
        }
out_sem:
        up(&cli->cl_sem);
        return rc;
}

int ptlrpc_import_disconnect(struct lustre_handle *conn, int failover)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct client_obd *cli = &obd->u.cli;
        struct obd_import *imp = cli->cl_import;
        struct ptlrpc_request *request = NULL;
        int rc = 0, err, rq_opc;
        ENTRY;

        if (!obd) {
                CERROR("invalid connection for disconnect: cookie "LPX64"\n",
                       conn ? conn->cookie : -1UL);
                RETURN(-EINVAL);
        }

        rq_opc = obd->obd_type->typ_ops->o_brw ? OST_DISCONNECT:MDS_DISCONNECT;
        down(&cli->cl_sem);
        if (!cli->cl_conn_count) {
                CERROR("disconnecting disconnected device (%s)\n",
                       obd->obd_name);
                GOTO(out_sem, rc = -EINVAL);
        }

        cli->cl_conn_count--;
        if (cli->cl_conn_count)
                GOTO(out_no_disconnect, rc = 0);

        if (obd->obd_namespace != NULL) {
                /* obd_no_recov == local only */
                ldlm_cli_cancel_unused(obd->obd_namespace, NULL,
                                       obd->obd_no_recov);
                ldlm_namespace_free(obd->obd_namespace);
                obd->obd_namespace = NULL;
        }

        /* Yeah, obd_no_recov also (mainly) means "forced shutdown". */
        if (obd->obd_no_recov && imp->imp_level != LUSTRE_CONN_FULL) {
                ptlrpc_abort_inflight(imp);
        } else {
                request = ptlrpc_prep_req(imp, rq_opc, 0, NULL, NULL);
                if (!request)
                        GOTO(out_req, rc = -ENOMEM);
                
                request->rq_replen = lustre_msg_size(0, NULL);
                
                /* Process disconnects even if we're waiting for recovery. */
                request->rq_level = LUSTRE_CONN_RECOVD;
                
                rc = ptlrpc_queue_wait(request);
                if (rc)
                        GOTO(out_req, rc);
        }
        if (imp->imp_export) {
                class_export_put(imp->imp_export);
                imp->imp_export = NULL;
        }
        EXIT;
 out_req:
        if (request)
                ptlrpc_req_finished(request);
 out_no_disconnect:
        err = class_disconnect(conn, 0);
        if (!rc && err)
                rc = err;
 out_sem:
        up(&cli->cl_sem);
        RETURN(rc);
}

/* Debugging check only needed during development */
#ifdef OBD_CTXT_DEBUG
# define ASSERT_CTXT_MAGIC(magic) LASSERT((magic) == OBD_RUN_CTXT_MAGIC)
# define ASSERT_NOT_KERNEL_CTXT(msg) LASSERT(!segment_eq(get_fs(), get_ds()))
# define ASSERT_KERNEL_CTXT(msg) LASSERT(segment_eq(get_fs(), get_ds()))
#else
# define ASSERT_CTXT_MAGIC(magic) do {} while(0)
# define ASSERT_NOT_KERNEL_CTXT(msg) do {} while(0)
# define ASSERT_KERNEL_CTXT(msg) do {} while(0)
#endif

/* push / pop to root of obd store */
void push_ctxt(struct obd_run_ctxt *save, struct obd_run_ctxt *new_ctx,
               struct obd_ucred *uc)
{
        //ASSERT_NOT_KERNEL_CTXT("already in kernel context!\n");
        ASSERT_CTXT_MAGIC(new_ctx->magic);
        OBD_SET_CTXT_MAGIC(save);

        /*
        CDEBUG(D_INFO,
               "= push %p->%p = cur fs %p pwd %p:d%d:i%d (%*s), pwdmnt %p:%d\n",
               save, current, current->fs, current->fs->pwd,
               atomic_read(&current->fs->pwd->d_count),
               atomic_read(&current->fs->pwd->d_inode->i_count),
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt,
               atomic_read(&current->fs->pwdmnt->mnt_count));
        */

        save->fs = get_fs();
        LASSERT(atomic_read(&current->fs->pwd->d_count));
        LASSERT(atomic_read(&new_ctx->pwd->d_count));
        save->pwd = dget(current->fs->pwd);
        save->pwdmnt = mntget(current->fs->pwdmnt);

        LASSERT(save->pwd);
        LASSERT(save->pwdmnt);
        LASSERT(new_ctx->pwd);
        LASSERT(new_ctx->pwdmnt);

        if (uc) {
                save->fsuid = current->fsuid;
                save->fsgid = current->fsgid;
                save->cap = current->cap_effective;

                current->fsuid = uc->ouc_fsuid;
                current->fsgid = uc->ouc_fsgid;
                current->cap_effective = uc->ouc_cap;
                if (uc->ouc_suppgid1 != -1)
                        current->groups[current->ngroups++] = uc->ouc_suppgid1;
                if (uc->ouc_suppgid2 != -1)
                        current->groups[current->ngroups++] = uc->ouc_suppgid2;
        }
        set_fs(new_ctx->fs);
        set_fs_pwd(current->fs, new_ctx->pwdmnt, new_ctx->pwd);

        /*
        CDEBUG(D_INFO,
               "= push %p->%p = cur fs %p pwd %p:d%d:i%d (%*s), pwdmnt %p:%d\n",
               new_ctx, current, current->fs, current->fs->pwd,
               atomic_read(&current->fs->pwd->d_count),
               atomic_read(&current->fs->pwd->d_inode->i_count),
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt,
               atomic_read(&current->fs->pwdmnt->mnt_count));
        */
}

void pop_ctxt(struct obd_run_ctxt *saved, struct obd_run_ctxt *new_ctx,
              struct obd_ucred *uc)
{
        //printk("pc0");
        ASSERT_CTXT_MAGIC(saved->magic);
        //printk("pc1");
        ASSERT_KERNEL_CTXT("popping non-kernel context!\n");

        /*
        CDEBUG(D_INFO,
               " = pop  %p==%p = cur %p pwd %p:d%d:i%d (%*s), pwdmnt %p:%d\n",
               new_ctx, current, current->fs, current->fs->pwd,
               atomic_read(&current->fs->pwd->d_count),
               atomic_read(&current->fs->pwd->d_inode->i_count),
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt,
               atomic_read(&current->fs->pwdmnt->mnt_count));
        */

        LASSERT(current->fs->pwd == new_ctx->pwd);
        LASSERT(current->fs->pwdmnt == new_ctx->pwdmnt);

        set_fs(saved->fs);
        set_fs_pwd(current->fs, saved->pwdmnt, saved->pwd);

        dput(saved->pwd);
        mntput(saved->pwdmnt);
        if (uc) {
                current->fsuid = saved->fsuid;
                current->fsgid = saved->fsgid;
                current->cap_effective = saved->cap;

                if (uc->ouc_suppgid1 != -1)
                        current->ngroups--;
                if (uc->ouc_suppgid2 != -1)
                        current->ngroups--;
        }

        /*
        CDEBUG(D_INFO,
               "= pop  %p->%p = cur fs %p pwd %p:d%d:i%d (%*s), pwdmnt %p:%d\n",
               saved, current, current->fs, current->fs->pwd,
               atomic_read(&current->fs->pwd->d_count),
               atomic_read(&current->fs->pwd->d_inode->i_count),
               current->fs->pwd->d_name.len, current->fs->pwd->d_name.name,
               current->fs->pwdmnt,
               atomic_read(&current->fs->pwdmnt->mnt_count));
        */
}

/* utility to make a file */
struct dentry *simple_mknod(struct dentry *dir, char *name, int mode)
{
        struct dentry *dchild;
        int err = 0;
        ENTRY;

        ASSERT_KERNEL_CTXT("kernel doing mknod outside kernel context\n");
        CDEBUG(D_INODE, "creating file %*s\n", (int)strlen(name), name);

        dchild = lookup_one_len(name, dir, strlen(name));
        if (IS_ERR(dchild))
                GOTO(out_up, dchild);

        if (dchild->d_inode) {
                if ((dchild->d_inode->i_mode & S_IFMT) != S_IFREG)
                        GOTO(out_err, err = -EEXIST);

                GOTO(out_up, dchild);
        }

        err = vfs_create(dir->d_inode, dchild, (mode & ~S_IFMT) | S_IFREG);
        if (err)
                GOTO(out_err, err);

        RETURN(dchild);

out_err:
        dput(dchild);
        dchild = ERR_PTR(err);
out_up:
        return dchild;
}

/* utility to make a directory */
struct dentry *simple_mkdir(struct dentry *dir, char *name, int mode)
{
        struct dentry *dchild;
        int err = 0;
        ENTRY;

        ASSERT_KERNEL_CTXT("kernel doing mkdir outside kernel context\n");
        CDEBUG(D_INODE, "creating directory %*s\n", (int)strlen(name), name);
        dchild = lookup_one_len(name, dir, strlen(name));
        if (IS_ERR(dchild))
                GOTO(out_up, dchild);

        if (dchild->d_inode) {
                if (!S_ISDIR(dchild->d_inode->i_mode))
                        GOTO(out_err, err = -ENOTDIR);

                GOTO(out_up, dchild);
        }

        err = vfs_mkdir(dir->d_inode, dchild, mode);
        if (err)
                GOTO(out_err, err);

        RETURN(dchild);

out_err:
        dput(dchild);
        dchild = ERR_PTR(err);
out_up:
        return dchild;
}

/*
 * Read a file from within kernel context.  Prior to calling this
 * function we should already have done a push_ctxt().
 */
int lustre_fread(struct file *file, char *str, int len, loff_t *off)
{
        ASSERT_KERNEL_CTXT("kernel doing read outside kernel context\n");
        if (!file || !file->f_op || !file->f_op->read || !off)
                RETURN(-ENOSYS);

        return file->f_op->read(file, str, len, off);
}

/*
 * Write a file from within kernel context.  Prior to calling this
 * function we should already have done a push_ctxt().
 */
int lustre_fwrite(struct file *file, const char *str, int len, loff_t *off)
{
        ENTRY;
        ASSERT_KERNEL_CTXT("kernel doing write outside kernel context\n");
        if (!file)
                RETURN(-ENOENT);
        if (!file->f_op)
                RETURN(-ENOSYS);
        if (!off)
                RETURN(-EINVAL);

        if (!file->f_op->write)
                RETURN(-EROFS);

        RETURN(file->f_op->write(file, str, len, off));
}

/*
 * Sync a file from within kernel context.  Prior to calling this
 * function we should already have done a push_ctxt().
 */
int lustre_fsync(struct file *file)
{
        ENTRY;
        ASSERT_KERNEL_CTXT("kernel doing sync outside kernel context\n");
        if (!file || !file->f_op || !file->f_op->fsync)
                RETURN(-ENOSYS);

        RETURN(file->f_op->fsync(file, file->f_dentry, 0));
}

/* --------------------------------------------------------------------------
 * from old lib/target.c
 * -------------------------------------------------------------------------- */

int target_handle_reconnect(struct lustre_handle *conn, struct obd_export *exp,
                            struct obd_uuid *cluuid)
{
        if (exp->exp_connection) {
                struct lustre_handle *hdl;
                hdl = &exp->exp_ldlm_data.led_import->imp_remote_handle;
                /* Might be a re-connect after a partition. */
                if (!memcmp(&conn->cookie, &hdl->cookie, sizeof conn->cookie)) {
                        CERROR("%s reconnecting\n", cluuid->uuid);
                        conn->cookie = exp->exp_handle.h_cookie;
                        RETURN(EALREADY);
                } else {
                        CERROR("%s reconnecting from %s, "
                               "handle mismatch (ours "LPX64", theirs "
                               LPX64")\n", cluuid->uuid,
                               exp->exp_connection->c_remote_uuid.uuid,
                               hdl->cookie, conn->cookie);
                        /* XXX disconnect them here? */
                        memset(conn, 0, sizeof *conn);
                        /* This is a little scary, but right now we build this
                         * file separately into each server module, so I won't
                         * go _immediately_ to hell.
                         */
                        RETURN(-EALREADY);
                }
        }

        conn->cookie = exp->exp_handle.h_cookie;
        CDEBUG(D_INFO, "existing export for UUID '%s' at %p\n",
               cluuid->uuid, exp);
        CDEBUG(D_IOCTL,"connect: cookie "LPX64"\n", conn->cookie);
        RETURN(0);
}

int target_handle_connect(struct ptlrpc_request *req, svc_handler_t handler)
{
        struct obd_device *target;
        struct obd_export *export = NULL;
        struct obd_import *dlmimp;
        struct lustre_handle conn;
        struct obd_uuid tgtuuid;
        struct obd_uuid cluuid;
        struct obd_uuid remote_uuid;
        struct list_head *p;
        char *str, *tmp;
        int rc, i, abort_recovery;
        ENTRY;

        LASSERT_REQSWAB (req, 0);
        str = lustre_msg_string (req->rq_reqmsg, 0, sizeof (tgtuuid.uuid) - 1);
        if (str == NULL) {
                CERROR("bad target UUID for connect\n");
                GOTO(out, rc = -EINVAL);
        }
        obd_str2uuid (&tgtuuid, str);

        LASSERT_REQSWAB (req, 1);
        str = lustre_msg_string (req->rq_reqmsg, 1, sizeof (cluuid.uuid) - 1);
        if (str == NULL) {
                CERROR("bad client UUID for connect\n");
                GOTO(out, rc = -EINVAL);
        }
        obd_str2uuid (&cluuid, str);

        i = class_uuid2dev(&tgtuuid);
        if (i == -1) {
                CERROR("UUID '%s' not found for connect\n", tgtuuid.uuid);
                GOTO(out, rc = -ENODEV);
        }

        target = &obd_dev[i];
        if (!target || target->obd_stopping || !target->obd_set_up) {
                CERROR("UUID '%s' is not available for connect\n", str);
                GOTO(out, rc = -ENODEV);
        }

        /* XXX extract a nettype and format accordingly */
        snprintf(remote_uuid.uuid, sizeof remote_uuid, 
                 "NET_"LPX64"_UUID", req->rq_peer.peer_nid);

        spin_lock_bh(&target->obd_processing_task_lock);
        abort_recovery = target->obd_abort_recovery;
        spin_unlock_bh(&target->obd_processing_task_lock);
        if (abort_recovery)
                target_abort_recovery(target);

        tmp = lustre_msg_buf(req->rq_reqmsg, 2, sizeof conn);
        if (tmp == NULL)
                GOTO(out, rc = -EPROTO);

        memcpy(&conn, tmp, sizeof conn);

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                GOTO(out, rc);

        /* lctl gets a backstage, all-access pass. */
        if (obd_uuid_equals(&cluuid, &lctl_fake_uuid))
                goto dont_check_exports;

        spin_lock(&target->obd_dev_lock);
        list_for_each(p, &target->obd_exports) {
                export = list_entry(p, struct obd_export, exp_obd_chain);
                if (obd_uuid_equals(&cluuid, &export->exp_client_uuid)) {
                        spin_unlock(&target->obd_dev_lock);
                        LASSERT(export->exp_obd == target);

                        rc = target_handle_reconnect(&conn, export, &cluuid);
                        break;
                }
                export = NULL;
        }
        /* If we found an export, we already unlocked. */
        if (!export)
                spin_unlock(&target->obd_dev_lock);

        /* Tell the client if we're in recovery. */
        /* If this is the first client, start the recovery timer */
        if (target->obd_recovering) {
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_RECOVERING);
                target_start_recovery_timer(target, handler);
        }

        /* Tell the client if we support replayable requests */
        if (target->obd_replayable)
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_REPLAYABLE);

        if (export == NULL) {
                if (target->obd_recovering) {
                        CERROR("denying connection for new client %s: "
                               "in recovery\n", cluuid.uuid);
                        rc = -EBUSY;
                } else {
 dont_check_exports:
                        rc = obd_connect(&conn, target, &cluuid);
                }
        }

        /* If all else goes well, this is our RPC return code. */
        req->rq_status = 0;

        if (rc && rc != EALREADY)
                GOTO(out, rc);

        req->rq_repmsg->handle = conn;

        /* If the client and the server are the same node, we will already
         * have an export that really points to the client's DLM export,
         * because we have a shared handles table.
         *
         * XXX this will go away when shaver stops sending the "connect" handle
         * in the real "remote handle" field of the request --phik 24 Apr 2003
         */
        if (req->rq_export != NULL)
                class_export_put(req->rq_export);

        /* ownership of this export ref transfers to the request */
        export = req->rq_export = class_conn2export(&conn);
        LASSERT(export != NULL);

        if (req->rq_connection != NULL)
                ptlrpc_put_connection(req->rq_connection);
        if (export->exp_connection != NULL)
                ptlrpc_put_connection(export->exp_connection);
        export->exp_connection = ptlrpc_get_connection(&req->rq_peer,
                                                       &remote_uuid);
        req->rq_connection = ptlrpc_connection_addref(export->exp_connection);

        if (rc == EALREADY) {
                /* We indicate the reconnection in a flag, not an error code. */
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_RECONNECT);
                GOTO(out, rc = 0);
        }

        memcpy(&conn, lustre_msg_buf(req->rq_reqmsg, 2, sizeof conn),
               sizeof conn);

        if (export->exp_ldlm_data.led_import != NULL)
                class_destroy_import(export->exp_ldlm_data.led_import);
        dlmimp = export->exp_ldlm_data.led_import = class_new_import();
        dlmimp->imp_connection = ptlrpc_connection_addref(req->rq_connection);
        dlmimp->imp_client = &export->exp_obd->obd_ldlm_client;
        dlmimp->imp_remote_handle = conn;
        dlmimp->imp_obd = target;
        dlmimp->imp_export = class_export_get(export);
        dlmimp->imp_dlm_fake = 1;
        dlmimp->imp_level = LUSTRE_CONN_FULL;
        class_import_put(dlmimp);
out:
        if (rc)
                req->rq_status = rc;
        RETURN(rc);
}

int target_handle_disconnect(struct ptlrpc_request *req)
{
        struct lustre_handle *conn = &req->rq_reqmsg->handle;
        struct obd_import *dlmimp;
        int rc;
        ENTRY;

        rc = lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
        if (rc)
                RETURN(rc);

        req->rq_status = obd_disconnect(conn, 0);

        dlmimp = req->rq_export->exp_ldlm_data.led_import;
        class_destroy_import(dlmimp);

        class_export_put(req->rq_export);
        req->rq_export = NULL;
        RETURN(0);
}

/*
 * Recovery functions 
 */

void target_cancel_recovery_timer(struct obd_device *obd)
{
        del_timer(&obd->obd_recovery_timer);
}

static void abort_delayed_replies(struct obd_device *obd)
{
        struct ptlrpc_request *req;
        struct list_head *tmp, *n;
        list_for_each_safe(tmp, n, &obd->obd_delayed_reply_queue) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                DEBUG_REQ(D_ERROR, req, "aborted:");
                req->rq_status = -ENOTCONN;
                req->rq_type = PTL_RPC_MSG_ERR;
                ptlrpc_reply(req);
                list_del(&req->rq_list);
                OBD_FREE(req->rq_reqmsg, req->rq_reqlen);
                OBD_FREE(req, sizeof *req);
        }
}

static void abort_recovery_queue(struct obd_device *obd)
{
        struct ptlrpc_request *req;
        struct list_head *tmp, *n;
        list_for_each_safe(tmp, n, &obd->obd_recovery_queue) {
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                DEBUG_REQ(D_ERROR, req, "aborted:");
                req->rq_status = -ENOTCONN;
                req->rq_type = PTL_RPC_MSG_ERR;
                ptlrpc_reply(req);
                list_del(&req->rq_list);
                class_export_put(req->rq_export);
                OBD_FREE(req->rq_reqmsg, req->rq_reqlen);
                OBD_FREE(req, sizeof *req);
        }
}

void target_abort_recovery(void *data)
{
        struct obd_device *obd = data;

        CERROR("disconnecting clients and aborting recovery\n");
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (!obd->obd_recovering) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                EXIT;
                return;
        }

        obd->obd_recovering = obd->obd_abort_recovery = 0;
        obd->obd_recoverable_clients = 0;
        wake_up(&obd->obd_next_transno_waitq);
        target_cancel_recovery_timer(obd);
        spin_unlock_bh(&obd->obd_processing_task_lock);
        class_disconnect_exports(obd, 0);
        abort_delayed_replies(obd);
        abort_recovery_queue(obd);
}

static void target_recovery_expired(unsigned long castmeharder)
{
        struct obd_device *obd = (struct obd_device *)castmeharder;
        CERROR("recovery timed out, aborting\n");
        spin_lock_bh(&obd->obd_processing_task_lock);
        obd->obd_abort_recovery = 1;
        wake_up(&obd->obd_next_transno_waitq);
        spin_unlock_bh(&obd->obd_processing_task_lock);
}

static void reset_recovery_timer(struct obd_device *obd)
{
        int recovering;
        spin_lock(&obd->obd_dev_lock);
        recovering = obd->obd_recovering;
        spin_unlock(&obd->obd_dev_lock);

        if (!recovering)
                return;
        CDEBUG(D_ERROR, "timer will expire in %ld seconds\n",
               OBD_RECOVERY_TIMEOUT / HZ);
        mod_timer(&obd->obd_recovery_timer, jiffies + OBD_RECOVERY_TIMEOUT);
}


/* Only start it the first time called */
void target_start_recovery_timer(struct obd_device *obd, svc_handler_t handler)
{
        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_recovery_handler) {
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return;
        }
        CERROR("%s: starting recovery timer\n", obd->obd_name);
        obd->obd_recovery_handler = handler;
        obd->obd_recovery_timer.function = target_recovery_expired;
        obd->obd_recovery_timer.data = (unsigned long)obd;
        init_timer(&obd->obd_recovery_timer);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        reset_recovery_timer(obd);
}

static int check_for_next_transno(struct obd_device *obd)
{
        struct ptlrpc_request *req;
        int wake_up;

        req = list_entry(obd->obd_recovery_queue.next,
                         struct ptlrpc_request, rq_list);
        LASSERT(req->rq_reqmsg->transno >= obd->obd_next_recovery_transno);

        wake_up = req->rq_reqmsg->transno == obd->obd_next_recovery_transno ||
                (obd->obd_recovering) == 0;
        CDEBUG(D_HA, "check_for_next_transno: "LPD64" vs "LPD64", %d == %d\n",
               req->rq_reqmsg->transno, obd->obd_next_recovery_transno,
               obd->obd_recovering, wake_up);
        return wake_up;
}

static void process_recovery_queue(struct obd_device *obd)
{
        struct ptlrpc_request *req;
        int abort_recovery = 0;
        struct l_wait_info lwi = { 0 };
        ENTRY;

        for (;;) {
                spin_lock_bh(&obd->obd_processing_task_lock);
                LASSERT(obd->obd_processing_task == current->pid);
                req = list_entry(obd->obd_recovery_queue.next,
                                 struct ptlrpc_request, rq_list);

                if (req->rq_reqmsg->transno != obd->obd_next_recovery_transno) {
                        spin_unlock_bh(&obd->obd_processing_task_lock);
                        CDEBUG(D_HA, "Waiting for transno "LPD64" (1st is "
                               LPD64")\n",
                               obd->obd_next_recovery_transno,
                               req->rq_reqmsg->transno);
                        l_wait_event(obd->obd_next_transno_waitq,
                                     check_for_next_transno(obd), &lwi);
                        spin_lock_bh(&obd->obd_processing_task_lock);
                        abort_recovery = obd->obd_abort_recovery;
                        spin_unlock_bh(&obd->obd_processing_task_lock);
                        if (abort_recovery) {
                                target_abort_recovery(obd);
                                return;
                        }
                        continue;
                }
                list_del_init(&req->rq_list);
                spin_unlock_bh(&obd->obd_processing_task_lock);

                DEBUG_REQ(D_ERROR, req, "processing: ");
                (void)obd->obd_recovery_handler(req);
                reset_recovery_timer(obd);
#warning FIXME: mds_fsync_super(mds->mds_sb);
                class_export_put(req->rq_export);
                OBD_FREE(req->rq_reqmsg, req->rq_reqlen);
                OBD_FREE(req, sizeof *req);
                spin_lock_bh(&obd->obd_processing_task_lock);
                obd->obd_next_recovery_transno++;
                if (list_empty(&obd->obd_recovery_queue)) {
                        obd->obd_processing_task = 0;
                        spin_unlock_bh(&obd->obd_processing_task_lock);
                        break;
                }
                spin_unlock_bh(&obd->obd_processing_task_lock);
        }
        EXIT;
}

int target_queue_recovery_request(struct ptlrpc_request *req,
                                  struct obd_device *obd)
{
        struct list_head *tmp;
        int inserted = 0;
        __u64 transno = req->rq_reqmsg->transno;
        struct ptlrpc_request *saved_req;
        struct lustre_msg *reqmsg;

        /* CAVEAT EMPTOR: The incoming request message has been swabbed
         * (i.e. buflens etc are in my own byte order), but type-dependent
         * buffers (eg mds_body, ost_body etc) have NOT been swabbed. */

        if (!transno) {
                INIT_LIST_HEAD(&req->rq_list);
                DEBUG_REQ(D_HA, req, "not queueing");
                return 1;
        }

        /* XXX If I were a real man, these LBUGs would be sane cleanups. */
        /* XXX just like the request-dup code in queue_final_reply */
        OBD_ALLOC(saved_req, sizeof *saved_req);
        if (!saved_req)
                LBUG();
        OBD_ALLOC(reqmsg, req->rq_reqlen);
        if (!reqmsg)
                LBUG();

        spin_lock_bh(&obd->obd_processing_task_lock);

        /* If we're processing the queue, we want don't want to queue this
         * message.
         * 
         * Also, if this request has a transno less than the one we're waiting
         * for, we should process it now.  It could (and currently always will)
         * be an open request for a descriptor that was opened some time ago.
         */
        if (obd->obd_processing_task == current->pid ||
            transno < obd->obd_next_recovery_transno) {
                /* Processing the queue right now, don't re-add. */
                LASSERT(list_empty(&req->rq_list));
                spin_unlock_bh(&obd->obd_processing_task_lock);
                OBD_FREE(reqmsg, req->rq_reqlen);
                OBD_FREE(saved_req, sizeof *saved_req);
                return 1;
        }

        memcpy(saved_req, req, sizeof *req);
        memcpy(reqmsg, req->rq_reqmsg, req->rq_reqlen);
        req = saved_req;
        req->rq_reqmsg = reqmsg;
        class_export_get(req->rq_export);
        INIT_LIST_HEAD(&req->rq_list);

        /* XXX O(n^2) */
        list_for_each(tmp, &obd->obd_recovery_queue) {
                struct ptlrpc_request *reqiter =
                        list_entry(tmp, struct ptlrpc_request, rq_list);

                if (reqiter->rq_reqmsg->transno > transno) {
                        list_add_tail(&req->rq_list, &reqiter->rq_list);
                        inserted = 1;
                        break;
                }
        }

        if (!inserted) {
                list_add_tail(&req->rq_list, &obd->obd_recovery_queue);
        }

        if (obd->obd_processing_task != 0) {
                /* Someone else is processing this queue, we'll leave it to
                 * them.
                 */
                if (transno == obd->obd_next_recovery_transno)
                        wake_up(&obd->obd_next_transno_waitq);
                spin_unlock_bh(&obd->obd_processing_task_lock);
                return 0;
        }

        /* Nobody is processing, and we know there's (at least) one to process
         * now, so we'll do the honours.
         */
        obd->obd_processing_task = current->pid;
        spin_unlock_bh(&obd->obd_processing_task_lock);

        process_recovery_queue(obd);
        return 0;
}

struct obd_device * target_req2obd(struct ptlrpc_request *req)
{
        return req->rq_export->exp_obd;
}

int target_queue_final_reply(struct ptlrpc_request *req, int rc)
{
        struct obd_device *obd = target_req2obd(req);
        struct ptlrpc_request *saved_req;
        struct lustre_msg *reqmsg;
        int recovery_done = 0;

        if (rc) {
                /* Just like ptlrpc_error, but without the sending. */
                lustre_pack_msg(0, NULL, NULL, &req->rq_replen,
                                &req->rq_repmsg);
                req->rq_type = PTL_RPC_MSG_ERR;
        }

        LASSERT(list_empty(&req->rq_list));
        /* XXX just like the request-dup code in queue_recovery_request */
        OBD_ALLOC(saved_req, sizeof *saved_req);
        if (!saved_req)
                LBUG();
        OBD_ALLOC(reqmsg, req->rq_reqlen);
        if (!reqmsg)
                LBUG();
        memcpy(saved_req, req, sizeof *saved_req);
        memcpy(reqmsg, req->rq_reqmsg, req->rq_reqlen);
        req = saved_req;
        req->rq_reqmsg = reqmsg;
        list_add(&req->rq_list, &obd->obd_delayed_reply_queue);

        spin_lock_bh(&obd->obd_processing_task_lock);
        --obd->obd_recoverable_clients;
        recovery_done = (obd->obd_recoverable_clients == 0);
        spin_unlock_bh(&obd->obd_processing_task_lock);

        if (recovery_done) {
                struct list_head *tmp, *n;
                ldlm_reprocess_all_ns(req->rq_export->exp_obd->obd_namespace);
                CDEBUG(D_ERROR,
                       "%s: all clients recovered, sending delayed replies\n",
                       obd->obd_name);
                obd->obd_recovering = 0;
                list_for_each_safe(tmp, n, &obd->obd_delayed_reply_queue) {
                        req = list_entry(tmp, struct ptlrpc_request, rq_list);
                        DEBUG_REQ(D_ERROR, req, "delayed:");
                        ptlrpc_reply(req);
                        list_del(&req->rq_list);
                        OBD_FREE(req->rq_reqmsg, req->rq_reqlen);
                        OBD_FREE(req, sizeof *req);
                }
                target_cancel_recovery_timer(obd);
        } else {
                CERROR("%s: %d recoverable clients remain\n",
                       obd->obd_name, obd->obd_recoverable_clients);
        }

        return 1;
}

static void ptlrpc_abort_reply (struct ptlrpc_request *req)
{
        /* On return, we must be sure that the ACK callback has either
         * happened or will not happen.  Note that the SENT callback will
         * happen come what may since we successfully posted the PUT. */
        int rc;
        struct l_wait_info lwi;
        unsigned long flags;

 again:
        /* serialise with ACK callback */
        spin_lock_irqsave (&req->rq_lock, flags);
        if (!req->rq_want_ack) {
                spin_unlock_irqrestore (&req->rq_lock, flags);
                /* The ACK callback has happened already.  Although the
                 * SENT callback might still be outstanding (yes really) we
                 * don't care; this is just like normal completion. */
                return;
        }
        spin_unlock_irqrestore (&req->rq_lock, flags);

        /* Have a bash at unlinking the MD.  This will fail until the SENT
         * callback has happened since the MD is busy from the PUT.  If the
         * ACK still hasn't arrived after then, a successful unlink will
         * ensure the ACK callback never happens. */
        rc = PtlMDUnlink (req->rq_reply_md_h);
        switch (rc) {
        default:
                LBUG ();
        case PTL_OK:
                /* SENT callback happened; ACK callback preempted */
                LASSERT (req->rq_want_ack);
                spin_lock_irqsave (&req->rq_lock, flags);
                req->rq_want_ack = 0;
                spin_unlock_irqrestore (&req->rq_lock, flags);
                return;
        case PTL_INV_MD:
                /* Both SENT and ACK callbacks happened */
                LASSERT (!req->rq_want_ack);
                return;
        case PTL_MD_INUSE:
                /* Still sending or ACK callback in progress: wait until
                 * either callback has completed and try again.
                 * Actually we can't wait for the SENT callback because
                 * there's no state the SENT callback can touch that will
                 * allow it to communicate with us!  So we just wait here
                 * for a short time, effectively polling for the SENT
                 * callback by calling PtlMDUnlink() again, to see if it
                 * has finished.  Note that if the ACK does arrive, its
                 * callback wakes us in short order. --eeb */
                lwi = LWI_TIMEOUT (HZ/4, NULL, NULL);
                rc = l_wait_event(req->rq_wait_for_rep, !req->rq_want_ack,
                                  &lwi);
                CDEBUG (D_HA, "Retrying req %p: %d\n", req, rc);
                /* NB go back and test rq_want_ack with locking, to ensure
                 * if ACK callback happened, it has completed stopped
                 * referencing this req. */
                goto again;
        }
}

void target_send_reply(struct ptlrpc_request *req, int rc, int fail_id)
{
        int i;
        int netrc;
        unsigned long flags;
        struct ptlrpc_req_ack_lock *ack_lock;
        struct l_wait_info lwi = { 0 };
        wait_queue_t commit_wait;
        struct obd_device *obd =
                req->rq_export ? req->rq_export->exp_obd : NULL;
        struct obd_export *exp = 
                (req->rq_export && req->rq_ack_locks[0].mode) ?
                req->rq_export : NULL;

        if (exp) {
                exp->exp_outstanding_reply = req;
                spin_lock_irqsave (&req->rq_lock, flags);
                req->rq_want_ack = 1;
                spin_unlock_irqrestore (&req->rq_lock, flags);
        }

        if (!OBD_FAIL_CHECK(fail_id | OBD_FAIL_ONCE)) {
                if (rc) {
                        DEBUG_REQ(D_ERROR, req, "processing error (%d)", rc);
                        netrc = ptlrpc_error(req);
                } else {
                        DEBUG_REQ(D_NET, req, "sending reply");
                        netrc = ptlrpc_reply(req);
                }
        } else {
                obd_fail_loc |= OBD_FAIL_ONCE | OBD_FAILED;
                DEBUG_REQ(D_ERROR, req, "dropping reply");
                if (!exp && req->rq_repmsg) {
                        OBD_FREE(req->rq_repmsg, req->rq_replen);
                        req->rq_repmsg = NULL;
                }
                init_waitqueue_head(&req->rq_wait_for_rep);
                netrc = 0;
        }

        /* a failed send simulates the callbacks */
        LASSERT(netrc == 0 || req->rq_want_ack == 0);
        if (exp == NULL) {
                LASSERT(req->rq_want_ack == 0);
                return;
        }
        LASSERT(obd != NULL);

        init_waitqueue_entry(&commit_wait, current);
        add_wait_queue(&obd->obd_commit_waitq, &commit_wait);
        rc = l_wait_event(req->rq_wait_for_rep,
                          !req->rq_want_ack || req->rq_resent ||
                          req->rq_transno <= obd->obd_last_committed, &lwi);
        remove_wait_queue(&obd->obd_commit_waitq, &commit_wait);

        spin_lock_irqsave (&req->rq_lock, flags);
        /* If we got here because the ACK callback ran, this acts as a
         * barrier to ensure the callback completed the wakeup. */
        spin_unlock_irqrestore (&req->rq_lock, flags);

        /* If we committed the transno already, then we might wake up before
         * the ack arrives.  We need to stop waiting for the ack before we can
         * reuse this request structure.  We are guaranteed by this point that
         * this cannot abort the sending of the actual reply.*/
        ptlrpc_abort_reply(req);

        if (req->rq_resent) {
                DEBUG_REQ(D_HA, req, "resent: not cancelling locks");
                return;
        }

        LASSERT(rc == 0);
        DEBUG_REQ(D_HA, req, "cancelling locks for %s",
                  req->rq_want_ack ? "commit" : "ack");

        exp->exp_outstanding_reply = NULL;

        for (ack_lock = req->rq_ack_locks, i = 0; i < 4; i++, ack_lock++) {
                if (!ack_lock->mode)
                        break;
                ldlm_lock_decref(&ack_lock->lock, ack_lock->mode);
        }
}

int target_handle_ping(struct ptlrpc_request *req)
{
        return lustre_pack_msg(0, NULL, NULL, &req->rq_replen, &req->rq_repmsg);
}
