/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef OST_INTERNAL_H
#define OST_INTERNAL_H

#ifdef LPROCFS
extern void ost_print_req(void *seq_file, struct ptlrpc_request *req);
#else
# define ost_print_req NULL
#endif

#endif /* OST_INTERNAL_H */
