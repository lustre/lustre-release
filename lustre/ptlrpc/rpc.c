/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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

#include <linux/module.h>
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_ha.h>
#include <linux/init.h>

extern int ptlrpc_init_portals(void);
extern void ptlrpc_exit_portals(void);

int connmgr_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct recovd_obd *recovd = &obddev->u.recovd;
        int err;
        ENTRY;

        MOD_INC_USE_COUNT;
        memset(recovd, 0, sizeof(*recovd));

        err = recovd_setup(recovd);
        if (err) {
                MOD_DEC_USE_COUNT;
                RETURN(err);
        }

        RETURN(0);
}

int connmgr_cleanup(struct obd_device *dev)
{
        struct recovd_obd *recovd = &dev->u.recovd;
        int err;

        err = recovd_cleanup(recovd);
        if (err)
                LBUG();

        MOD_DEC_USE_COUNT;
        RETURN(0);
}

int connmgr_iocontrol(long cmd, struct lustre_handle *hdl, int len, void *karg,
                      void *uarg)
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

                if (!strcmp(conn->c_remote_uuid, data->ioc_inlbuf1))
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
                        
                        if (!strcmp(conn->c_remote_uuid, data->ioc_inlbuf1))
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

                /* Jump straight to the "failed" phase of recovery. */
                conn->c_recovd_data.rd_phase = RD_FAILED;
                goto out;
        }

        /* else (NEWCONN) */
        if (conn->c_recovd_data.rd_phase != RD_PREPARING)
                GOTO(out, rc = -EALREADY);

        spin_lock(&conn->c_lock);
        if (data->ioc_inllen2) {
                CERROR("conn %p UUID change %s -> %s\n",
                       conn, conn->c_remote_uuid, data->ioc_inlbuf2);
                strcpy(conn->c_remote_uuid, data->ioc_inlbuf2);
        } else {
                CERROR("conn %p UUID %s reconnected\n", conn,
                       conn->c_remote_uuid);
        }
        ptlrpc_readdress_connection(conn, conn->c_remote_uuid);
        spin_unlock(&conn->c_lock);
        
        conn->c_recovd_data.rd_phase = RD_PREPARED;
        wake_up(&recovd->recovd_waitq);
 out:
        spin_unlock(&recovd->recovd_lock);
        RETURN(rc);
}


/* use obd ops to offer management infrastructure */
static struct obd_ops recovd_obd_ops = {
        o_setup:       connmgr_setup,
        o_cleanup:     connmgr_cleanup,
        o_iocontrol:   connmgr_iocontrol,
        o_connect:     class_connect,
        o_disconnect:  class_disconnect
};

static int __init ptlrpc_init(void)
{
        int rc; 
        rc = ptlrpc_init_portals();
        if (rc) 
                RETURN(rc);
        ptlrpc_init_connection();
        class_register_type(&recovd_obd_ops, LUSTRE_HA_NAME);
        return 0;
}

static void __exit ptlrpc_exit(void)
{
        class_unregister_type(LUSTRE_HA_NAME);
        ptlrpc_exit_portals();
        ptlrpc_cleanup_connection();
}

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
EXPORT_SYMBOL(ptlrpc_send_bulk);
EXPORT_SYMBOL(ptlrpc_register_bulk);
EXPORT_SYMBOL(ptlrpc_abort_bulk);
EXPORT_SYMBOL(ptlrpc_reply);
EXPORT_SYMBOL(ptlrpc_error);
EXPORT_SYMBOL(ptlrpc_resend_req);
EXPORT_SYMBOL(ptl_send_rpc);
EXPORT_SYMBOL(ptlrpc_link_svc_me);

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
EXPORT_SYMBOL(ptlrpc_req_finished);
EXPORT_SYMBOL(ptlrpc_prep_bulk);
EXPORT_SYMBOL(ptlrpc_free_bulk);
EXPORT_SYMBOL(ptlrpc_prep_bulk_page);
EXPORT_SYMBOL(ptlrpc_free_bulk_page);
EXPORT_SYMBOL(ptlrpc_check_status);

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

EXPORT_SYMBOL(ll_recover);


MODULE_AUTHOR("Cluster File Systems, Inc <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Request Processor v1.0");
MODULE_LICENSE("GPL");

module_init(ptlrpc_init);
module_exit(ptlrpc_exit);
