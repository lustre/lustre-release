/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_RPC

#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>

#include "ptlrpc_internal.h"
cfs_mem_cache_t *ptlrpc_cbdata_slab;
extern spinlock_t ptlrpc_last_xid_lock;
extern spinlock_t ptlrpc_rs_debug_lock;
extern spinlock_t ptlrpc_all_services_lock;
extern struct semaphore pinger_sem;
extern struct semaphore ptlrpcd_sem;
extern int ptlrpc_init_portals(void);
extern void ptlrpc_exit_portals(void);

__init int ptlrpc_init(void)
{
        int rc, cleanup_phase = 0;
        ENTRY;

        lustre_assert_wire_constants();
        spin_lock_init(&ptlrpc_last_xid_lock);
        spin_lock_init(&ptlrpc_rs_debug_lock);
        spin_lock_init(&ptlrpc_all_services_lock);
        init_mutex(&pinger_sem);
        init_mutex(&ptlrpcd_sem);

        rc = ptlrpc_init_portals();
        if (rc)
                RETURN(rc);
        cleanup_phase = 1;

        rc = ptlrpc_init_connection();
        if (rc)
                GOTO(cleanup, rc);
        cleanup_phase = 2;

        ptlrpc_put_connection_superhack = ptlrpc_put_connection;

        rc = ptlrpc_start_pinger();
        if (rc)
                GOTO(cleanup, rc);
        cleanup_phase = 3;

        rc = ldlm_init();
        if (rc)
                GOTO(cleanup, rc);
        cleanup_phase = 4;

        ptlrpc_cbdata_slab = cfs_mem_cache_create("ptlrpc_cbdatas",
                                sizeof (struct ptlrpc_set_cbdata), 0, 
                                SLAB_HWCACHE_ALIGN);
        if (ptlrpc_cbdata_slab == NULL)
                GOTO(cleanup, rc);

        RETURN(0);

cleanup:
        switch(cleanup_phase) {
        case 4:
                ldlm_exit();
        case 3:
                ptlrpc_stop_pinger();
        case 2:
                ptlrpc_cleanup_connection();
        case 1:
                ptlrpc_exit_portals();
        default: ;
        }

        return rc;
}

#ifdef __KERNEL__
static void __exit ptlrpc_exit(void)
{
        ldlm_exit();
        ptlrpc_stop_pinger();
        ptlrpc_exit_portals();
        ptlrpc_cleanup_connection();
        cfs_mem_cache_destroy(ptlrpc_cbdata_slab);
}

/* connection.c */
EXPORT_SYMBOL(ptlrpc_dump_connections);
EXPORT_SYMBOL(ptlrpc_readdress_connection);
EXPORT_SYMBOL(ptlrpc_get_connection);
EXPORT_SYMBOL(ptlrpc_put_connection);
EXPORT_SYMBOL(ptlrpc_connection_addref);
EXPORT_SYMBOL(ptlrpc_init_connection);
EXPORT_SYMBOL(ptlrpc_cleanup_connection);

/* niobuf.c */
EXPORT_SYMBOL(ptlrpc_start_bulk_transfer);
EXPORT_SYMBOL(ptlrpc_abort_bulk);
EXPORT_SYMBOL(ptlrpc_register_bulk);
EXPORT_SYMBOL(ptlrpc_unregister_bulk);
EXPORT_SYMBOL(ptlrpc_send_reply);
EXPORT_SYMBOL(ptlrpc_reply);
EXPORT_SYMBOL(ptlrpc_send_error);
EXPORT_SYMBOL(ptlrpc_error);
EXPORT_SYMBOL(ptlrpc_resend_req);
EXPORT_SYMBOL(ptl_send_rpc);

/* client.c */
EXPORT_SYMBOL(ptlrpc_init_client);
EXPORT_SYMBOL(ptlrpc_cleanup_client);
EXPORT_SYMBOL(ptlrpc_uuid_to_connection);
EXPORT_SYMBOL(ptlrpc_queue_wait);
EXPORT_SYMBOL(ptlrpc_replay_req);
EXPORT_SYMBOL(ptlrpc_restart_req);
EXPORT_SYMBOL(ptlrpc_add_rqs_to_pool);
EXPORT_SYMBOL(ptlrpc_init_rq_pool);
EXPORT_SYMBOL(ptlrpc_free_rq_pool);
EXPORT_SYMBOL(ptlrpc_prep_req_pool);
EXPORT_SYMBOL(ptlrpc_at_set_req_timeout);
EXPORT_SYMBOL(ptlrpc_prep_req);
EXPORT_SYMBOL(ptlrpc_free_req);
EXPORT_SYMBOL(ptlrpc_unregister_reply);
EXPORT_SYMBOL(ptlrpc_req_finished);
EXPORT_SYMBOL(ptlrpc_req_finished_with_imp_lock);
EXPORT_SYMBOL(ptlrpc_request_addref);
EXPORT_SYMBOL(ptlrpc_prep_bulk_imp);
EXPORT_SYMBOL(ptlrpc_prep_bulk_exp);
EXPORT_SYMBOL(ptlrpc_free_bulk);
EXPORT_SYMBOL(ptlrpc_prep_bulk_page);
EXPORT_SYMBOL(ptlrpc_abort_inflight);
EXPORT_SYMBOL(ptlrpc_retain_replayable_request);
EXPORT_SYMBOL(ptlrpc_next_xid);

EXPORT_SYMBOL(ptlrpc_prep_set);
EXPORT_SYMBOL(ptlrpc_set_add_cb);
EXPORT_SYMBOL(ptlrpc_set_add_req);
EXPORT_SYMBOL(ptlrpc_set_add_new_req);
EXPORT_SYMBOL(ptlrpc_set_destroy);
EXPORT_SYMBOL(ptlrpc_set_next_timeout);
EXPORT_SYMBOL(ptlrpc_check_set);
EXPORT_SYMBOL(ptlrpc_set_wait);
EXPORT_SYMBOL(ptlrpc_expired_set);
EXPORT_SYMBOL(ptlrpc_interrupted_set);
EXPORT_SYMBOL(ptlrpc_mark_interrupted);

/* service.c */
EXPORT_SYMBOL(ptlrpc_save_lock);
EXPORT_SYMBOL(ptlrpc_schedule_difficult_reply);
EXPORT_SYMBOL(ptlrpc_commit_replies);
EXPORT_SYMBOL(ptlrpc_init_svc);
EXPORT_SYMBOL(ptlrpc_stop_all_threads);
EXPORT_SYMBOL(ptlrpc_start_threads);
EXPORT_SYMBOL(ptlrpc_start_thread);
EXPORT_SYMBOL(ptlrpc_unregister_service);
EXPORT_SYMBOL(ptlrpc_daemonize);
EXPORT_SYMBOL(ptlrpc_service_health_check);

/* pack_generic.c */
EXPORT_SYMBOL(lustre_msg_swabbed);
EXPORT_SYMBOL(lustre_msg_check_version);
EXPORT_SYMBOL(lustre_pack_request);
EXPORT_SYMBOL(lustre_pack_reply);
EXPORT_SYMBOL(lustre_pack_reply_flags);
EXPORT_SYMBOL(lustre_shrink_reply);
EXPORT_SYMBOL(lustre_free_reply_state);
EXPORT_SYMBOL(lustre_msg_size);
EXPORT_SYMBOL(lustre_packed_msg_size);
EXPORT_SYMBOL(lustre_unpack_msg);
EXPORT_SYMBOL(lustre_msg_buf);
EXPORT_SYMBOL(lustre_msg_string);
EXPORT_SYMBOL(lustre_swab_buf);
EXPORT_SYMBOL(lustre_swab_reqbuf);
EXPORT_SYMBOL(lustre_swab_repbuf);
EXPORT_SYMBOL(lustre_swab_obdo);
EXPORT_SYMBOL(lustre_swab_obd_statfs);
EXPORT_SYMBOL(lustre_swab_obd_ioobj);
EXPORT_SYMBOL(lustre_swab_niobuf_remote);
EXPORT_SYMBOL(lustre_swab_ost_body);
EXPORT_SYMBOL(lustre_swab_ost_last_id);
EXPORT_SYMBOL(lustre_swab_ost_lvb);
EXPORT_SYMBOL(lustre_swab_mds_status_req);
EXPORT_SYMBOL(lustre_swab_mds_body);
EXPORT_SYMBOL(lustre_swab_obd_quotactl);
EXPORT_SYMBOL(lustre_swab_mds_rec_setattr);
EXPORT_SYMBOL(lustre_swab_mds_rec_create);
EXPORT_SYMBOL(lustre_swab_mds_rec_join);
EXPORT_SYMBOL(lustre_swab_mds_rec_link);
EXPORT_SYMBOL(lustre_swab_mds_rec_unlink);
EXPORT_SYMBOL(lustre_swab_mds_rec_rename);
EXPORT_SYMBOL(lustre_swab_lov_desc);
EXPORT_SYMBOL(lustre_swab_lov_user_md);
EXPORT_SYMBOL(lustre_swab_lov_user_md_objects);
EXPORT_SYMBOL(lustre_swab_lov_user_md_join);
EXPORT_SYMBOL(lustre_swab_ldlm_res_id);
EXPORT_SYMBOL(lustre_swab_ldlm_policy_data);
EXPORT_SYMBOL(lustre_swab_ldlm_intent);
EXPORT_SYMBOL(lustre_swab_ldlm_resource_desc);
EXPORT_SYMBOL(lustre_swab_ldlm_lock_desc);
EXPORT_SYMBOL(lustre_swab_ldlm_request);
EXPORT_SYMBOL(lustre_swab_ldlm_reply);
EXPORT_SYMBOL(lustre_swab_qdata);
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(1, 7, 0, 0)
EXPORT_SYMBOL(lustre_swab_qdata_old);
#else
#warning "remove quota code above for format absolete in new release"
#endif
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(1, 9, 0, 0)
EXPORT_SYMBOL(lustre_swab_qdata_old2);
#else
#warning "remove quota code above for format absolete in new release"
#endif
EXPORT_SYMBOL(lustre_swab_quota_adjust_qunit);
EXPORT_SYMBOL(lustre_msg_get_flags);
EXPORT_SYMBOL(lustre_msg_add_flags);
EXPORT_SYMBOL(lustre_msg_set_flags);
EXPORT_SYMBOL(lustre_msg_clear_flags);
EXPORT_SYMBOL(lustre_msg_get_op_flags);
EXPORT_SYMBOL(lustre_msg_add_op_flags);
EXPORT_SYMBOL(lustre_msg_set_op_flags);
EXPORT_SYMBOL(lustre_msg_get_handle );
EXPORT_SYMBOL(lustre_msg_get_type);
EXPORT_SYMBOL(lustre_msg_get_version);
EXPORT_SYMBOL(lustre_msg_add_version);
EXPORT_SYMBOL(lustre_msg_get_opc);
EXPORT_SYMBOL(lustre_msg_get_last_xid);
EXPORT_SYMBOL(lustre_msg_get_last_committed);
EXPORT_SYMBOL(lustre_msg_get_transno);
EXPORT_SYMBOL(lustre_msg_get_status);
EXPORT_SYMBOL(lustre_msg_get_slv);
EXPORT_SYMBOL(lustre_msg_get_limit);
EXPORT_SYMBOL(lustre_msg_set_slv);
EXPORT_SYMBOL(lustre_msg_set_limit);
EXPORT_SYMBOL(lustre_msg_get_conn_cnt);
EXPORT_SYMBOL(lustre_msg_is_v1);
EXPORT_SYMBOL(lustre_msg_get_magic);
EXPORT_SYMBOL(lustre_msg_set_handle);
EXPORT_SYMBOL(lustre_msg_set_type);
EXPORT_SYMBOL(lustre_msg_set_opc);
EXPORT_SYMBOL(lustre_msg_set_last_xid);
EXPORT_SYMBOL(lustre_msg_set_last_committed);
EXPORT_SYMBOL(lustre_msg_set_transno);
EXPORT_SYMBOL(lustre_msg_set_status);
EXPORT_SYMBOL(lustre_msg_set_conn_cnt);
EXPORT_SYMBOL(lustre_swab_mgs_target_info);

/* recover.c */
EXPORT_SYMBOL(ptlrpc_disconnect_import);
EXPORT_SYMBOL(ptlrpc_resend);
EXPORT_SYMBOL(ptlrpc_wake_delayed);
EXPORT_SYMBOL(ptlrpc_set_import_active);
EXPORT_SYMBOL(ptlrpc_activate_import);
EXPORT_SYMBOL(ptlrpc_deactivate_import);
EXPORT_SYMBOL(ptlrpc_invalidate_import);
EXPORT_SYMBOL(ptlrpc_fail_import);
EXPORT_SYMBOL(ptlrpc_recover_import);
EXPORT_SYMBOL(ptlrpc_import_setasync);

/* pinger.c */
EXPORT_SYMBOL(ptlrpc_pinger_add_import);
EXPORT_SYMBOL(ptlrpc_pinger_del_import);
EXPORT_SYMBOL(ptlrpc_pinger_sending_on_import);

/* ptlrpcd.c */
EXPORT_SYMBOL(ptlrpcd_addref);
EXPORT_SYMBOL(ptlrpcd_decref);
EXPORT_SYMBOL(ptlrpcd_add_req);
EXPORT_SYMBOL(ptlrpcd_wake);

/* llogd.c */
EXPORT_SYMBOL(llog_origin_handle_create);
EXPORT_SYMBOL(llog_origin_handle_destroy);
EXPORT_SYMBOL(llog_origin_handle_next_block);
EXPORT_SYMBOL(llog_origin_handle_prev_block);
EXPORT_SYMBOL(llog_origin_handle_read_header);
EXPORT_SYMBOL(llog_origin_handle_close);
EXPORT_SYMBOL(llog_client_ops);
EXPORT_SYMBOL(llog_catinfo);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Request Processor and Lock Management");
MODULE_LICENSE("GPL");

cfs_module(ptlrpc, "1.0.0", ptlrpc_init, ptlrpc_exit);
#endif
