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

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_net.h>

#include "ptlrpc_internal.h"

extern int ptlrpc_init_portals(void);
extern void ptlrpc_exit_portals(void);

int (*ptlrpc_ldlm_namespace_cleanup)(struct ldlm_namespace *, int);
int (*ptlrpc_ldlm_replay_locks)(struct obd_import *);

#define GET_HOOK(name)                                                         \
if (!ptlrpc_##name) {                                                          \
        if (!(ptlrpc_##name = inter_module_get(#name))) {                      \
                CERROR("can't i_m_g(\"" #name "\")\n");                        \
                return 0;                                                      \
        }                                                                      \
}

static int ldlm_hooks_referenced;

/* This is called from ptlrpc_get_connection, which runs after all the modules
 * are loaded, but before anything else interesting happens.
 */
int ptlrpc_get_ldlm_hooks(void)
{
        if (ldlm_hooks_referenced)
                return 1;

        GET_HOOK(ldlm_namespace_cleanup);
        GET_HOOK(ldlm_replay_locks);

        ldlm_hooks_referenced = 1;
        RETURN(1);
}

#undef GET_HOOK

#define PUT_HOOK(hook)                                                         \
if (ptlrpc_##hook) {                                                           \
        inter_module_put(#hook);                                               \
        ptlrpc_##hook = NULL;                                                  \
}

void ptlrpc_put_ldlm_hooks(void)
{
        ENTRY;
        PUT_HOOK(ldlm_namespace_cleanup);
        PUT_HOOK(ldlm_replay_locks);
        ldlm_hooks_referenced = 0;
        EXIT;
}

#undef PUT_HOOK

int ptlrpc_ldlm_hooks_referenced(void)
{
        return ldlm_hooks_referenced;
}

__init int ptlrpc_init(void)
{
        int rc;
        ENTRY;

        rc = ptlrpc_init_portals();
        if (rc)
                RETURN(rc);

        ptlrpc_init_connection();

        ptlrpc_put_connection_superhack = ptlrpc_put_connection;
        ptlrpc_abort_inflight_superhack = ptlrpc_abort_inflight;
        RETURN(0);
}

static void __exit ptlrpc_exit(void)
{
        ptlrpc_exit_portals();
        ptlrpc_cleanup_connection();
}

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
EXPORT_SYMBOL(obd_brw_set_new);
EXPORT_SYMBOL(obd_brw_set_add);
EXPORT_SYMBOL(obd_brw_set_del);
EXPORT_SYMBOL(obd_brw_set_decref);
EXPORT_SYMBOL(obd_brw_set_addref);

/* client.c */
EXPORT_SYMBOL(ptlrpc_init_client);
EXPORT_SYMBOL(ptlrpc_cleanup_client);
EXPORT_SYMBOL(ptlrpc_req_to_uuid);
EXPORT_SYMBOL(ptlrpc_uuid_to_connection);
EXPORT_SYMBOL(ptlrpc_queue_wait);
EXPORT_SYMBOL(ptlrpc_replay_req);
EXPORT_SYMBOL(ptlrpc_restart_req);
EXPORT_SYMBOL(ptlrpc_prep_req);
EXPORT_SYMBOL(ptlrpc_free_req);
EXPORT_SYMBOL(ptlrpc_abort);
EXPORT_SYMBOL(ptlrpc_req_finished);
EXPORT_SYMBOL(ptlrpc_request_addref);
EXPORT_SYMBOL(ptlrpc_prep_bulk_imp);
EXPORT_SYMBOL(ptlrpc_prep_bulk_exp);
EXPORT_SYMBOL(ptlrpc_free_bulk);
EXPORT_SYMBOL(ptlrpc_prep_bulk_page);
EXPORT_SYMBOL(ptlrpc_free_bulk_page);
EXPORT_SYMBOL(ll_brw_sync_wait);
EXPORT_SYMBOL(ptlrpc_abort_inflight);
EXPORT_SYMBOL(ptlrpc_retain_replayable_request);
EXPORT_SYMBOL(ptlrpc_next_xid);

EXPORT_SYMBOL(ptlrpc_prep_set);
EXPORT_SYMBOL(ptlrpc_drop_set);
EXPORT_SYMBOL(ptlrpc_set_add_req);
EXPORT_SYMBOL(ptlrpc_req_completed);
EXPORT_SYMBOL(ptlrpc_req_result);

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
EXPORT_SYMBOL(lustre_msg_string);
EXPORT_SYMBOL(lustre_swab_reqbuf);
EXPORT_SYMBOL(lustre_swab_repbuf);
EXPORT_SYMBOL(lustre_swab_obdo);
EXPORT_SYMBOL(lustre_swab_obd_statfs);
EXPORT_SYMBOL(lustre_swab_obd_ioobj);
EXPORT_SYMBOL(lustre_swab_niobuf_remote);
EXPORT_SYMBOL(lustre_swab_ost_body);
EXPORT_SYMBOL(lustre_swab_ll_fid);
EXPORT_SYMBOL(lustre_swab_mds_status_req);
EXPORT_SYMBOL(lustre_swab_mds_fileh_body);
EXPORT_SYMBOL(lustre_swab_mds_body);
EXPORT_SYMBOL(lustre_swab_mds_rec_setattr);
EXPORT_SYMBOL(lustre_swab_mds_rec_create);
EXPORT_SYMBOL(lustre_swab_mds_rec_link);
EXPORT_SYMBOL(lustre_swab_mds_rec_unlink);
EXPORT_SYMBOL(lustre_swab_mdx_rec_rename);
EXPORT_SYMBOL(lustre_swab_lov_desc);
EXPORT_SYMBOL(lustre_swab_ldlm_res_id);
EXPORT_SYMBOL(lustre_swab_ldlm_extent);
EXPORT_SYMBOL(lustre_swab_ldlm_intent);
EXPORT_SYMBOL(lustre_swab_ldlm_resource_desc);
EXPORT_SYMBOL(lustre_swab_ldlm_lock_desc);
EXPORT_SYMBOL(lustre_swab_ldlm_request);
EXPORT_SYMBOL(lustre_swab_ldlm_reply);
EXPORT_SYMBOL(lustre_swab_ptlbd_op);
EXPORT_SYMBOL(lustre_swab_ptlbd_niob);
EXPORT_SYMBOL(lustre_swab_ptlbd_rsp);

/* ptlrpc_module.c */
EXPORT_SYMBOL(ptlrpc_put_ldlm_hooks);
EXPORT_SYMBOL(ptlrpc_ldlm_hooks_referenced);

/* recover.c */
EXPORT_SYMBOL(ptlrpc_run_recovery_upcall);
EXPORT_SYMBOL(ptlrpc_reconnect_import);
EXPORT_SYMBOL(ptlrpc_replay);
EXPORT_SYMBOL(ptlrpc_resend);
EXPORT_SYMBOL(ptlrpc_wake_delayed);
EXPORT_SYMBOL(ptlrpc_set_import_active);
EXPORT_SYMBOL(ptlrpc_fail_import);
EXPORT_SYMBOL(ptlrpc_fail_export);
EXPORT_SYMBOL(ptlrpc_recover_import);

#ifdef __KERNEL__
MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Request Processor");
MODULE_LICENSE("GPL");

module_init(ptlrpc_init);
module_exit(ptlrpc_exit);
#endif
