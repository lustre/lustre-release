/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2003 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef OSC_INTERNAL_H
#define OSC_INTERNAL_H

/* osc/osc_rpcd.c */
int osc_rpcd_addref(void);
int osc_rpcd_decref(void);
void osc_rpcd_add_req(struct ptlrpc_request *req);

#endif /* OSC_INTERNAL_H */
