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
void ptlrpc_put_ldlm_hooks(void);
void ptlrpc_daemonize(void);

int ptlrpc_import_handle_eviction(struct obd_import *);

#endif /* PTLRPC_INTERNAL_H */
