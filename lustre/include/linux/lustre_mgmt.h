/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef LUSTRE_MGMT_H
#define LUSTRE_MGMT_H

#define LUSTRE_MGMTCLI_NAME "mgmtcli"

/* For the convenience and type-safety of inter_module_getters. */

struct obd_device;
struct obd_uuid;

/*
 * The caller is responsible for ensuring that relevant_uuid -- if non-NULL --
 * points to valid memory until deregister is called.  If relevant_uuid is NULL,
 * all management events will be propagated to the registrant.  Notice that
 * deregister doesn't take a relevant_uuid-matching parameter; I should probably
 * fix that at some point.
 */
typedef int (*mgmtcli_register_for_events_t)(struct obd_device *mgmt_obd,
                                             struct obd_device *notify_obd,
                                             struct obd_uuid *relevant_uuid);

typedef int (*mgmtcli_deregister_for_events_t)(struct obd_device *mgmt_obd,
                                               struct obd_device *notify_obd);

#endif /* LUSTRE_MGMT_H */
