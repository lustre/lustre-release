/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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
 *
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_RPC

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/init.h>
#else
# include <liblustre.h>
#endif
#include <linux/obd.h>
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_net.h>
#include <linux/lprocfs_status.h>

extern int ptlrpc_init_portals(void);
extern void ptlrpc_exit_portals(void);

static __u32 ptlrpc_last_xid = 0;
static spinlock_t ptlrpc_last_xid_lock = SPIN_LOCK_UNLOCKED;

__u32 ptlrpc_next_xid(void)
{
        __u32 tmp;
        spin_lock(&ptlrpc_last_xid_lock);
        tmp = ++ptlrpc_last_xid;
        spin_unlock(&ptlrpc_last_xid_lock);
        return tmp;
}

int connmgr_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct recovd_obd *recovd = &obddev->u.recovd;
        int err;
        ENTRY;

        memset(recovd, 0, sizeof(*recovd));

        err = recovd_setup(recovd);
        RETURN(err);
}

int connmgr_cleanup(struct obd_device *dev)
{
        struct recovd_obd *recovd = &dev->u.recovd;
        int err;

        err = recovd_cleanup(recovd);
        RETURN(err);
}

int connmgr_iocontrol(unsigned int cmd, struct lustre_handle *hdl, int len,
                      void *karg, void *uarg)
{
        struct ptlrpc_connection *conn = NULL;
        struct obd_device *obd = class_conn2obd(hdl);
        struct recovd_obd *recovd = &obd->u.recovd;
        struct obd_ioctl_data *data = karg;
        struct list_head *tmp;
        int rc = 0;

        ENTRY;

        if (cmd != OBD_IOC_RECOVD_NEWCONN && cmd != OBD_IOC_RECOVD_FAILCONN)
                RETURN(-EINVAL); /* XXX ENOSYS? */

        /* Find the connection that's been rebuilt or has failed. */
        spin_lock(&recovd->recovd_lock);
        list_for_each(tmp, &recovd->recovd_troubled_items) {
                conn = list_entry(tmp, struct ptlrpc_connection,
                                  c_recovd_data.rd_managed_chain);

                LASSERT(conn->c_recovd_data.rd_recovd == recovd); /* sanity */
#warning check buffer overflow in next line
                if (!strcmp(conn->c_remote_uuid.uuid, data->ioc_inlbuf1))
                        break;
                conn = NULL;
        }

        if (!conn) {
                if (cmd == OBD_IOC_RECOVD_NEWCONN)
                        GOTO(out, rc = -EINVAL);
                /* XXX macroize/inline and share with loop above */
                list_for_each(tmp, &recovd->recovd_managed_items) {
                        conn = list_entry(tmp, struct ptlrpc_connection,
                                          c_recovd_data.rd_managed_chain);

                        LASSERT(conn->c_recovd_data.rd_recovd == recovd);

#warning check buffer overflow in next line
                        if (!strcmp(conn->c_remote_uuid.uuid,
                                    data->ioc_inlbuf1))
                                break;
                        conn = NULL;
                }
                if (!conn)
                        GOTO(out, rc = -EINVAL);
        }

        if (cmd == OBD_IOC_RECOVD_FAILCONN) {
                spin_unlock(&recovd->recovd_lock);
                recovd_conn_fail(conn);
                spin_lock(&recovd->recovd_lock);
                goto out;
        }


        /* else (NEWCONN) */
        spin_lock(&conn->c_lock);

        /* whatever happens, reset the INVALID flag */
        conn->c_flags &= ~CONN_INVALID;

        /* XXX is this a good check?  should we allow readdressing of
         * XXX conns that aren't in recovery?
         */
        if (conn->c_recovd_data.rd_phase != RD_PREPARING) {
                spin_unlock(&conn->c_lock);
                GOTO(out, rc = -EALREADY);
        }

        if (data->ioc_inllen2) {
                CERROR("conn %p UUID change %s -> %s\n",
                       conn, conn->c_remote_uuid.uuid, data->ioc_inlbuf2);
                obd_str2uuid(&conn->c_remote_uuid, data->ioc_inlbuf2);
        } else {
                CERROR("conn %p UUID %s reconnected\n", conn,
                       conn->c_remote_uuid.uuid);
        }
        ptlrpc_readdress_connection(conn, &conn->c_remote_uuid);
        spin_unlock(&conn->c_lock);

        conn->c_recovd_data.rd_phase = RD_PREPARED;
        wake_up(&recovd->recovd_waitq);
 out:
        spin_unlock(&recovd->recovd_lock);
        RETURN(rc);
}

static int connmgr_connect(struct lustre_handle *conn, struct obd_device *src,
                           struct obd_uuid *cluuid, struct recovd_obd *recovd,
                           ptlrpc_recovery_cb_t recover)
{
        return class_connect(conn, src, cluuid);
}

int connmgr_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;
        int rc = 0;

        lprocfs_init_vars(&lvars);
        rc = lprocfs_obd_attach(dev, lvars.obd_vars);
        return rc;
}

int conmgr_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

/* use obd ops to offer management infrastructure */
static struct obd_ops recovd_obd_ops = {
        o_owner:        THIS_MODULE,
        o_attach:       connmgr_attach,
        o_detach:       conmgr_detach,
        o_setup:        connmgr_setup,
        o_cleanup:      connmgr_cleanup,
        o_iocontrol:    connmgr_iocontrol,
        o_connect:      connmgr_connect,
        o_disconnect:   class_disconnect
};



__init int ptlrpc_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;
        ENTRY;

        rc = ptlrpc_init_portals();
        if (rc)
                RETURN(rc);
        ptlrpc_init_connection();

        lprocfs_init_vars(&lvars);
        rc = class_register_type(&recovd_obd_ops, lvars.module_vars,
                                 LUSTRE_HA_NAME);
        if (rc)
                RETURN(rc);
        ptlrpc_put_connection_superhack = ptlrpc_put_connection;
        ptlrpc_abort_inflight_superhack = ptlrpc_abort_inflight;
        RETURN(0);
}

static void __exit ptlrpc_exit(void)
{
        class_unregister_type(LUSTRE_HA_NAME);
        ptlrpc_exit_portals();
        ptlrpc_cleanup_connection();
}

/* rpc.c */
EXPORT_SYMBOL(ptlrpc_next_xid);

/* recovd.c */
EXPORT_SYMBOL(ptlrpc_recovd);
EXPORT_SYMBOL(recovd_conn_fail);
EXPORT_SYMBOL(recovd_conn_manage);
EXPORT_SYMBOL(recovd_conn_fixed);
EXPORT_SYMBOL(recovd_setup);
EXPORT_SYMBOL(recovd_cleanup);

/* connection.c */
EXPORT_SYMBOL(ptlrpc_readdress_connection);
EXPORT_SYMBOL(ptlrpc_get_connection);
EXPORT_SYMBOL(ptlrpc_put_connection);
EXPORT_SYMBOL(ptlrpc_connection_addref);
EXPORT_SYMBOL(ptlrpc_init_connection);
EXPORT_SYMBOL(ptlrpc_cleanup_connection);

/* niobuf.c */
EXPORT_SYMBOL(ptlrpc_bulk_put);
EXPORT_SYMBOL(ptlrpc_bulk_get);
EXPORT_SYMBOL(ptlrpc_register_bulk_put);
EXPORT_SYMBOL(ptlrpc_register_bulk_get);
EXPORT_SYMBOL(ptlrpc_abort_bulk);
EXPORT_SYMBOL(ptlrpc_reply);
EXPORT_SYMBOL(ptlrpc_error);
EXPORT_SYMBOL(ptlrpc_resend_req);
EXPORT_SYMBOL(ptl_send_rpc);
EXPORT_SYMBOL(ptlrpc_link_svc_me);
EXPORT_SYMBOL(obd_brw_set_free);
EXPORT_SYMBOL(obd_brw_set_new);
EXPORT_SYMBOL(obd_brw_set_add);
EXPORT_SYMBOL(obd_brw_set_del);

/* client.c */
EXPORT_SYMBOL(ptlrpc_init_client);
EXPORT_SYMBOL(ptlrpc_cleanup_client);
EXPORT_SYMBOL(ptlrpc_req_to_uuid);
EXPORT_SYMBOL(ptlrpc_uuid_to_connection);
EXPORT_SYMBOL(ptlrpc_queue_wait);
EXPORT_SYMBOL(ptlrpc_continue_req);
EXPORT_SYMBOL(ptlrpc_replay_req);
EXPORT_SYMBOL(ptlrpc_restart_req);
EXPORT_SYMBOL(ptlrpc_prep_req);
EXPORT_SYMBOL(ptlrpc_free_req);
EXPORT_SYMBOL(ptlrpc_abort);
EXPORT_SYMBOL(ptlrpc_req_finished);
EXPORT_SYMBOL(ptlrpc_request_addref);
EXPORT_SYMBOL(ptlrpc_prep_bulk);
EXPORT_SYMBOL(ptlrpc_free_bulk);
EXPORT_SYMBOL(ptlrpc_prep_bulk_page);
EXPORT_SYMBOL(ptlrpc_free_bulk_page);
EXPORT_SYMBOL(ll_brw_sync_wait);
EXPORT_SYMBOL(ptlrpc_abort_inflight);
EXPORT_SYMBOL(ptlrpc_retain_replayable_request);

/* service.c */
EXPORT_SYMBOL(ptlrpc_init_svc);
EXPORT_SYMBOL(ptlrpc_stop_all_threads);
EXPORT_SYMBOL(ptlrpc_start_thread);
EXPORT_SYMBOL(ptlrpc_unregister_service);

/* pack_generic.c */
EXPORT_SYMBOL(lustre_pack_msg);
EXPORT_SYMBOL(lustre_msg_size);
EXPORT_SYMBOL(lustre_unpack_msg);
EXPORT_SYMBOL(lustre_msg_buf);

/* recover.c */
EXPORT_SYMBOL(ptlrpc_run_recovery_upcall);
EXPORT_SYMBOL(ptlrpc_reconnect_import);
EXPORT_SYMBOL(ptlrpc_replay);
EXPORT_SYMBOL(ptlrpc_resend);
EXPORT_SYMBOL(ptlrpc_wake_delayed);

#ifdef __KERNEL__
MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Request Processor");
MODULE_LICENSE("GPL");

module_init(ptlrpc_init);
module_exit(ptlrpc_exit);
#endif
