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

#define LLOG_MAX_OBJ             (64 << 10)

/* Identifier for a single log object */
struct llog_logid {
        __u64                   lgl_oid;
        __u64                   lgl_bootcount;
};

/* On-disk header structure of catalog of available log object (internal) */
#define LLOG_HEADER_SIZE        (4096)     /* <= PAGE_SIZE */
#define LLOG_HDR_RSVD_U32       (16)
#define LLOG_HDR_DATA_SIZE      (LLOG_HDR_RSVD_U32 * sizeof(__u32))
#define LLOG_BITMAP_SIZE        (LLOG_HEADER_SIZE - LLOG_HDR_DATA_SIZE)

#define LLOG_LOGLIST_MAGIC      0x6d50e67d
struct llog_catalog_header {
        __u32                   lch_size;
        __u32                   lch_magic;
        __u32                   lch_numrec;
        __u32                   lch_reserved[LLOG_HDR_RSVD_U32 - 4];
        __u32                   lch_bitmap[LLOG_BITMAP_SIZE / sizeof(__u32)];
        __u32                   lch_size_end;
        struct llog_logid       lch_logs[0];
};


/* Log data records */
typedef enum {
        OST_CREATE_REC = 1,
} llog_op_type;

/* Log record header - stored in originating host endian order (use magic to
 * check order).
 * Each record must start with this and be a multiple of 64 bits in size.
 */
struct llog_trans_hdr {
        __u32                   lth_len;
        llog_op_type            lth_op;
};

struct llog_create_rec {
        struct llog_trans_hdr   lcr_hdr;
        struct ll_fid           lcr_fid;
        obd_id                  lcr_oid;
        obd_count               lcr_ogener;
        __u32                   lcr_end_len;
} __attribute__((packed));

struct llog_unlink_rec {
        struct llog_trans_hdr   lur_hdr;
        obd_id                  lur_oid;
        obd_count               lur_ogener;
        __u32                   lur_end_len;
} __attribute__((packed));

/* On-disk header structure of each log object - stored in creating host
 * endian order, with the exception of the bitmap - stored in little endian
 * order so that we can use ext2_{clear,set,test}_bit() for optimized
 * little-endian handling of bitmaps.
 */
#define LLOG_MAX_LOG_SIZE       (64 << 10) /* == PTL_MD_MAX_IOV */
#define LLOG_MIN_REC_SIZE       (16)

#define LLOG_OBJECT_MAGIC       0xffb45539
struct llog_object_hdr {
        /* This first chunk should be exactly 4096 bytes in size */
        __u32                   loh_size;
        __u32                   loh_magic;
        __u32                   loh_numrec;
        __u32                   loh_reserved[LLOG_HDR_RSVD_U32 - 4];
        __u32                   loh_bitmap[LLOG_BITMAP_SIZE / sizeof(__u32)];
        __u32                   loh_size_end;

        struct llog_trans_rec   loh_records[0];
};

static inline llog_log_swabbed(struct llog_object_hdr *hdr)
{
        if (hdr->loh_magic == __swab32(LLOG_OBJECT_MAGIC))
                return 1;
        if (hdr->loh_magic == LLOG_OBJECT_MAGIC)
                return 0;
        return -EINVAL;
}

/* In-memory descriptor for a log object */
struct llog_handle {
        struct list_head        lgh_list;
        struct llog_logid       lgh_lid;
        struct brw_page         lgh_pga[2];
        struct lov_stripe_md   *lgh_lsm;
};

/* cookie to find a log record back in a specific log object */
struct llog_cookie {
        struct llog_logid       lgc_lid;
        __u32                   lgc_index;
        __u32                   lgc_offset;
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

