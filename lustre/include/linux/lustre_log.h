/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <info@clusterfs.com>
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
 * Generic infrastructure for managing a collection of logs.
 *
 * These logs are used for:
 *
 * - orphan recovery: OST adds record on create
 * - mtime/size consistency: the OST adds a record on first write
 * - open/unlinked objects: OST adds a record on destroy
 *
 * - mds unlink log: the MDS adds an entry upon delete
 *
 * - raid1 replication log between OST's
 * - MDS replication logs
 */

#ifndef _LUSTRE_LOG_H
#define _LUSTRE_LOG_H

#include <linux/lustre_lite.h>
#include <linux/lustre_idl.h>
#include <linux/obd.h>

/* In-memory descriptor for a log object or log catalog */
struct llog_handle {
        struct list_head        lgh_list;
        struct llog_cookie      lgh_cookie;
        struct obd_device      *lgh_obd;
        void                   *lgh_hdr;
        struct file            *lgh_file;
        struct llog_handle     *(*lgh_log_create)(struct llog_handle *loghandle,
                                                  struct obd_trans_info *oti);
        struct llog_handle     *(*lgh_log_open)(struct llog_handle *cathandle,
                                                struct llog_cookie *logcookie);
        int                     (*lgh_log_close)(struct llog_handle *cathandle,
                                                 struct llog_handle *loghandle);
        int                     lgh_index;
};

/* exported api prototypes */
extern int llog_add_record(struct llog_handle *cathandle,
                           struct llog_trans_hdr *rec,
                           struct lov_mds_md *lmm,
                           struct obd_trans_info *oti,
                           struct llog_cookie *logcookies);

extern int llog_cancel_records(struct llog_handle *cathandle, int count,
                               struct llog_cookie *cookies);

/* internal api */
extern struct llog_handle *llog_alloc_handle(void);
extern void llog_free_handle(struct llog_handle *handle);
extern int llog_init_catalog(struct llog_handle *cathandle);
extern struct llog_handle *llog_id2handle(struct llog_handle *cathandle,
                                          struct llog_cookie *cookie);

#endif

