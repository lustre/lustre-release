/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2003 Cluster File Systems, Inc.
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

/* Intramodule declarations for ptlrpc. */

#ifndef PTLRPC_INTERNAL_H
#define PTLRPC_INTERNAL_H

struct ldlm_namespace;
struct obd_import;
struct ldlm_res_id;

/* ldlm hooks that we need, managed via inter_module_{get,put} */
extern int (*ptlrpc_ldlm_namespace_cleanup)(struct ldlm_namespace *, int);
extern int (*ptlrpc_ldlm_cli_cancel_unused)(struct ldlm_namespace *,
                                     struct ldlm_res_id *, int);
extern int (*ptlrpc_ldlm_replay_locks)(struct obd_import *);

int ptlrpc_get_ldlm_hooks(void);
void ptlrpc_daemonize(void);

int ptlrpc_request_handle_eviction(struct ptlrpc_request *);
void lustre_assert_wire_constants (void);

void ptlrpc_lprocfs_register_service(struct obd_device *obddev,
                                     struct ptlrpc_service *svc);
void ptlrpc_lprocfs_unregister_service(struct ptlrpc_service *svc);


static inline int opcode_offset(__u32 opc) {
        if (opc < OST_LAST_OPC) {
                 /* OST opcode */
                return (opc - OST_FIRST_OPC);
        } else if (opc < MDS_LAST_OPC) {
                /* MDS opcode */
                return (opc - MDS_FIRST_OPC +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else if (opc < LDLM_LAST_OPC) {
                /* LDLM Opcode */
                return (opc - LDLM_FIRST_OPC + 
                        (MDS_LAST_OPC - MDS_FIRST_OPC) + 
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else if (opc < PTLBD_LAST_OPC) {
                /* Portals Block Device */
                return (opc - PTLBD_FIRST_OPC + 
                        (LDLM_LAST_OPC - LDLM_FIRST_OPC) +
                        (MDS_LAST_OPC - MDS_FIRST_OPC) +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else if (opc == OBD_PING) {
                /* OBD Ping */
                return (opc - OBD_PING + 
                        (PTLBD_LAST_OPC - PTLBD_FIRST_OPC) +
                        (LDLM_LAST_OPC - LDLM_FIRST_OPC) +
                        (MDS_LAST_OPC - MDS_FIRST_OPC) +
                        (OST_LAST_OPC - OST_FIRST_OPC));
        } else { 
                /* Unknown Opcode */
                return -1;
        }
}

#define LUSTRE_MAX_OPCODES (1 + (PTLBD_LAST_OPC - PTLBD_FIRST_OPC) \
                              + (LDLM_LAST_OPC - LDLM_FIRST_OPC)   \
                              + (MDS_LAST_OPC - MDS_FIRST_OPC)     \
                              + (OST_LAST_OPC - OST_FIRST_OPC))

enum {
        PTLRPC_REQWAIT_CNTR = 0,
        PTLRPC_SVCEQDEPTH_CNTR = 1,
        PTLRPC_SVCIDLETIME_CNTR = 2,
        PTLRPC_LAST_CNTR    = 3
};

#endif /* PTLRPC_INTERNAL_H */
