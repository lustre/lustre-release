/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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
#include <lustre_req_layout.h>

#include "ptlrpc_internal.h"

extern cfs_spinlock_t ptlrpc_last_xid_lock;
#if RS_DEBUG
extern cfs_spinlock_t ptlrpc_rs_debug_lock;
#endif
extern cfs_spinlock_t ptlrpc_all_services_lock;
extern cfs_semaphore_t pinger_sem;
extern cfs_semaphore_t ptlrpcd_sem;

__init int ptlrpc_init(void)
{
        int rc, cleanup_phase = 0;
        ENTRY;

        lustre_assert_wire_constants();
#if RS_DEBUG
        cfs_spin_lock_init(&ptlrpc_rs_debug_lock);
#endif
        cfs_spin_lock_init(&ptlrpc_all_services_lock);
        cfs_init_mutex(&pinger_sem);
        cfs_init_mutex(&ptlrpcd_sem);
        ptlrpc_init_xid();

        rc = req_layout_init();
        if (rc)
                RETURN(rc);

        rc = ptlrpc_hr_init();
        if (rc)
                RETURN(rc);

        cleanup_phase = 1;

        rc = ptlrpc_init_portals();
        if (rc)
                GOTO(cleanup, rc);
        cleanup_phase = 2;

        rc = ptlrpc_connection_init();
        if (rc)
                GOTO(cleanup, rc);
        cleanup_phase = 3;

        ptlrpc_put_connection_superhack = ptlrpc_connection_put;

        rc = ptlrpc_start_pinger();
        if (rc)
                GOTO(cleanup, rc);
        cleanup_phase = 4;

        rc = ldlm_init();
        if (rc)
                GOTO(cleanup, rc);
        cleanup_phase = 5;

        rc = sptlrpc_init();
        if (rc)
                GOTO(cleanup, rc);

        cleanup_phase = 6;
        rc = llog_recov_init();
        if (rc)
                GOTO(cleanup, rc);

        RETURN(0);

cleanup:
        switch(cleanup_phase) {
        case 6:
                sptlrpc_fini();
        case 5:
                ldlm_exit();
        case 4:
                ptlrpc_stop_pinger();
        case 3:
                ptlrpc_connection_fini();
        case 2:
                ptlrpc_exit_portals();
        case 1:
                ptlrpc_hr_fini();
                req_layout_fini();
        default: ;
        }

        return rc;
}

#ifdef __KERNEL__
static void __exit ptlrpc_exit(void)
{
        llog_recov_fini();
        sptlrpc_fini();
        ldlm_exit();
        ptlrpc_stop_pinger();
        ptlrpc_exit_portals();
        ptlrpc_hr_fini();
        ptlrpc_connection_fini();
}

/* connection.c */
EXPORT_SYMBOL(ptlrpc_connection_get);
EXPORT_SYMBOL(ptlrpc_connection_put);
EXPORT_SYMBOL(ptlrpc_connection_addref);
EXPORT_SYMBOL(ptlrpc_connection_init);
EXPORT_SYMBOL(ptlrpc_connection_fini);

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
EXPORT_SYMBOL(ptlrpc_prep_fakereq);
EXPORT_SYMBOL(ptlrpc_fakereq_finished);
EXPORT_SYMBOL(ptlrpc_at_set_req_timeout);
EXPORT_SYMBOL(ptlrpc_request_alloc);
EXPORT_SYMBOL(ptlrpc_request_alloc_pool);
EXPORT_SYMBOL(ptlrpc_request_free);
EXPORT_SYMBOL(ptlrpc_request_pack);
EXPORT_SYMBOL(ptlrpc_request_alloc_pack);
EXPORT_SYMBOL(ptlrpc_prep_req);
EXPORT_SYMBOL(ptlrpc_unregister_reply);
EXPORT_SYMBOL(ptlrpc_req_finished);
EXPORT_SYMBOL(ptlrpc_req_finished_with_imp_lock);
EXPORT_SYMBOL(ptlrpc_request_addref);
EXPORT_SYMBOL(ptlrpc_prep_bulk_imp);
EXPORT_SYMBOL(ptlrpc_prep_bulk_exp);
EXPORT_SYMBOL(ptlrpc_free_bulk);
EXPORT_SYMBOL(ptlrpc_prep_bulk_page);
EXPORT_SYMBOL(ptlrpc_abort_inflight);
EXPORT_SYMBOL(ptlrpc_cleanup_imp);
EXPORT_SYMBOL(ptlrpc_retain_replayable_request);
EXPORT_SYMBOL(ptlrpc_next_xid);
EXPORT_SYMBOL(ptlrpc_req_set_repsize);
EXPORT_SYMBOL(ptlrpc_request_set_replen);

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
EXPORT_SYMBOL(ptlrpc_service_health_check);
EXPORT_SYMBOL(ptlrpc_hpreq_reorder);

/* pack_generic.c */
EXPORT_SYMBOL(lustre_msg_check_version);
EXPORT_SYMBOL(lustre_pack_request);
EXPORT_SYMBOL(lustre_pack_reply);
EXPORT_SYMBOL(lustre_pack_reply_flags);
EXPORT_SYMBOL(lustre_shrink_msg);
EXPORT_SYMBOL(lustre_free_reply_state);
EXPORT_SYMBOL(lustre_msg_size);
EXPORT_SYMBOL(lustre_packed_msg_size);
EXPORT_SYMBOL(ptlrpc_unpack_rep_msg);
EXPORT_SYMBOL(ptlrpc_unpack_req_msg);
EXPORT_SYMBOL(lustre_msg_buf);
EXPORT_SYMBOL(lustre_msg_string);
EXPORT_SYMBOL(ptlrpc_buf_set_swabbed);
EXPORT_SYMBOL(ptlrpc_buf_need_swab);
EXPORT_SYMBOL(lustre_swab_ptlrpc_body);
EXPORT_SYMBOL(lustre_swab_obdo);
EXPORT_SYMBOL(lustre_swab_obd_statfs);
EXPORT_SYMBOL(lustre_swab_obd_ioobj);
EXPORT_SYMBOL(lustre_swab_niobuf_remote);
EXPORT_SYMBOL(lustre_swab_ost_body);
EXPORT_SYMBOL(lustre_swab_ost_last_id);
EXPORT_SYMBOL(lustre_swab_ost_lvb);
EXPORT_SYMBOL(lustre_swab_mds_status_req);
EXPORT_SYMBOL(lustre_swab_mds_body);
EXPORT_SYMBOL(lustre_swab_mdt_body);
EXPORT_SYMBOL(lustre_swab_mdt_ioepoch);
EXPORT_SYMBOL(lustre_swab_obd_quotactl);
EXPORT_SYMBOL(lustre_swab_mds_remote_perm);
EXPORT_SYMBOL(lustre_swab_mdt_remote_perm);
EXPORT_SYMBOL(lustre_swab_mdt_rec_reint);
EXPORT_SYMBOL(lustre_swab_lov_desc);
EXPORT_SYMBOL(lustre_swab_lov_user_md_v1);
EXPORT_SYMBOL(lustre_swab_lov_user_md_v3);
EXPORT_SYMBOL(lustre_swab_lov_user_md_objects);
EXPORT_SYMBOL(lustre_swab_lov_mds_md);
EXPORT_SYMBOL(lustre_swab_ldlm_res_id);
EXPORT_SYMBOL(lustre_swab_ldlm_policy_data);
EXPORT_SYMBOL(lustre_swab_ldlm_intent);
EXPORT_SYMBOL(lustre_swab_ldlm_resource_desc);
EXPORT_SYMBOL(lustre_swab_ldlm_lock_desc);
EXPORT_SYMBOL(lustre_swab_ldlm_request);
EXPORT_SYMBOL(lustre_swab_ldlm_reply);
EXPORT_SYMBOL(dump_ioo);
EXPORT_SYMBOL(dump_rniobuf);
EXPORT_SYMBOL(dump_obdo);
EXPORT_SYMBOL(dump_ost_body);
EXPORT_SYMBOL(dump_rcs);
EXPORT_SYMBOL(lustre_swab_qdata);
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
EXPORT_SYMBOL(lustre_msg_get_versions);
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
EXPORT_SYMBOL(lustre_msg_set_versions);
EXPORT_SYMBOL(lustre_msg_set_transno);
EXPORT_SYMBOL(lustre_msg_set_status);
EXPORT_SYMBOL(lustre_msg_set_conn_cnt);
EXPORT_SYMBOL(lustre_swab_mgs_target_info);
EXPORT_SYMBOL(lustre_swab_generic_32s);
EXPORT_SYMBOL(lustre_swab_lustre_capa);
EXPORT_SYMBOL(lustre_swab_lustre_capa_key);
EXPORT_SYMBOL(lustre_swab_fiemap);

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

/* pinger.c */
EXPORT_SYMBOL(ptlrpc_pinger_add_import);
EXPORT_SYMBOL(ptlrpc_pinger_del_import);
EXPORT_SYMBOL(ptlrpc_add_timeout_client);
EXPORT_SYMBOL(ptlrpc_del_timeout_client);
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

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Request Processor and Lock Management");
MODULE_LICENSE("GPL");

cfs_module(ptlrpc, "1.0.0", ptlrpc_init, ptlrpc_exit);
#endif
