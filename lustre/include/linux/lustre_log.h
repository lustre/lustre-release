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

/* catalog of log objects */

/* WARNING: adjust size records! */
#define LLOG_LOG_SIZE            (64 << 10) /* == PTL_MD_MAX_IOV */
#define LLOG_REC_SIZE            64
#define LLOG_NUM_REC             (LLOG_LOG_SIZE / LLOG_REC_SIZE)

struct llog_logid {
        __u64           lgl_oid;
        __u64           lgl_bootcount;
};

struct llog_loglist_header {
        char               llh_bitmap[8192];
        struct llog_logid  llh_current;
        struct llog_logid  llh_logs[0];
};

/* OST records for
   - orphans
   - size adjustments
   - open unlinked files
*/

struct llog_trans_rec {
        __u64             ltr_op;
        struct ll_fid     ltr_fid;
        obd_id            ltr_oid;
} __attribute__((packed));

/* header structure of each log */

/* bitmap of allocated entries is based on minimum entry size of 16
   bytes with a log file size of 64K that is 16K entries, ie. 16K bits
   in the bitmap or a 2kb bitmap */

struct llog_index {
        __u32                 lgi_bitmap[LLOG_NUM_REC / sizeof(__u32)];
        __u32                 lgi_numrec;
        struct llog_trans_rec lgi_records[0];
};

struct llog_handle {
        struct file *lgh_file;
        struct llog_index *lgh_hdr;
        struct llog_logid lgh_lid;
};

/* cookie to find a log entry back */
struct llog_cookie {
        struct llog_logid lgc_lid;
        __u64             lgc_recno;
};

/* exported api prototypes */
int llog_add_record(struct llog_handle **, void *recbuf, int reclen,
                    struct llog_cookie *cookie);
int llog_clear_records(int count, struct llog_cookie **cookies);
int llog_clear_record(struct llog_handle *handle, __u32 recno);
int llog_delete(struct llog_logid *id);

/* internal api */
int llog_id2handle(struct llog_logid *logid);

#endif

