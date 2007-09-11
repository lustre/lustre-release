/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _LUSTRE_HA_H
#define _LUSTRE_HA_H

struct obd_import;
struct obd_export;
struct obd_device;
struct ptlrpc_request;


int ptlrpc_replay(struct obd_import *imp);
int ptlrpc_resend(struct obd_import *imp);
void ptlrpc_free_committed(struct obd_import *imp);
void ptlrpc_wake_delayed(struct obd_import *imp);
int ptlrpc_recover_import(struct obd_import *imp, char *new_uuid);
int ptlrpc_set_import_active(struct obd_import *imp, int active);
void ptlrpc_activate_import(struct obd_import *imp);
void ptlrpc_deactivate_import(struct obd_import *imp);
void ptlrpc_invalidate_import(struct obd_import *imp);
void ptlrpc_fail_import(struct obd_import *imp, __u32 conn_cnt);

#endif
