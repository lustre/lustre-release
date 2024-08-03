/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2015, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LUSTRE_HA_H
#define _LUSTRE_HA_H

/** \defgroup ha ha
 *
 * @{
 */

struct obd_import;
struct obd_export;
struct obd_device;
struct ptlrpc_request;


int ptlrpc_replay(struct obd_import *imp);
int ptlrpc_resend(struct obd_import *imp);
void ptlrpc_free_committed(struct obd_import *imp);
void ptlrpc_wake_delayed(struct obd_import *imp);
int ptlrpc_recover_import(struct obd_import *imp, char *new_uuid, int async);
int ptlrpc_set_import_active(struct obd_import *imp, int active);
void ptlrpc_activate_import(struct obd_import *imp, bool set_state_full);
void ptlrpc_deactivate_import(struct obd_import *imp);
void ptlrpc_invalidate_import(struct obd_import *imp);
void ptlrpc_fail_import(struct obd_import *imp, __u32 conn_cnt);
void ptlrpc_pinger_force(struct obd_import *imp);
/** @} ha */

#endif
