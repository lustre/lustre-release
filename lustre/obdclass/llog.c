/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author: Andreas Dilger <adilger@clusterfs.com>
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
 * OST<->MDS recovery logging infrastructure.
 *
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 */

#define DEBUG_SUBSYSTEM S_LOG

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include <linux/fs.h>
#include <linux/obd_class.h>
#include <linux/lustre_log.h>
#include <portals/list.h>

/* Allocate a new log or catalog handle */
struct llog_handle *llog_alloc_handle(void)
{
        struct llog_handle *loghandle;
        ENTRY;

        OBD_ALLOC(loghandle, sizeof(*loghandle));
        if (loghandle == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        OBD_ALLOC(loghandle->lgh_hdr, LLOG_CHUNK_SIZE);
        if (loghandle->lgh_hdr == NULL) {
                OBD_FREE(loghandle, sizeof(*loghandle));
                RETURN(ERR_PTR(-ENOMEM));
        }

        INIT_LIST_HEAD(&loghandle->lgh_list);
        sema_init(&loghandle->lgh_lock, 1);

        RETURN(loghandle);
}
EXPORT_SYMBOL(llog_alloc_handle);


void llog_free_handle(struct llog_handle *loghandle)
{
        if (!loghandle)
                return;

        list_del_init(&loghandle->lgh_list);
        OBD_FREE(loghandle->lgh_hdr, LLOG_CHUNK_SIZE);
        OBD_FREE(loghandle, sizeof(*loghandle));
}
EXPORT_SYMBOL(llog_free_handle);


int llog_cancel_rec(struct llog_handle *loghandle, int index)
{
        struct llog_log_hdr *llh = loghandle->lgh_hdr;
        int rc = 0;
        ENTRY;

        CDEBUG(D_HA, "canceling %d in log "LPX64"\n",
               index, loghandle->lgh_id.lgl_oid);

        if (!ext2_clear_bit(index, llh->llh_bitmap)) {
                CERROR("catalog index %u already clear?\n", index);
                LBUG();
        }

        llh->llh_count--;

        if (llh->llh_flags & LLOG_F_ZAP_WHEN_EMPTY &&
            llh->llh_count == 1 &&
            loghandle->lgh_last_idx == LLOG_BITMAP_BYTES * 8) {
                rc = llog_destroy(loghandle);
                if (rc)
                        CERROR("failure destroying log after last cancel: %d\n",
                               rc);
                LASSERT(rc == 0);
                RETURN(rc);
        }

        rc = llog_write_rec(loghandle, &llh->llh_hdr, NULL, 0, NULL, 0);
        if (rc) 
                CERROR("failure re-writing header %d\n", rc);
        LASSERT(rc == 0);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_cancel_rec);

#if 0
int filter_log_cancel(struct obd_export *exp, struct lov_stripe_md *lsm,
                      int num_cookies, struct llog_cookie *logcookies,
                      int flags)
{
        struct obd_device *obd = exp->exp_obd;
        struct obd_run_ctxt saved;
        int rc;
        ENTRY;

        push_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);
        rc = llog_cancel_records(obd->u.filter.fo_catalog, num_cookies,
                                 logcookies);
        pop_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);

        RETURN(rc);
}
#endif


int llog_process_log(struct llog_handle *loghandle, llog_cb_t cb, void *data)
{
        struct llog_log_hdr *llh = loghandle->lgh_hdr;
        void *buf;
        __u64 cur_offset = LLOG_CHUNK_SIZE;
        int rc = 0, index = 0;
        ENTRY;

        OBD_ALLOC(buf, PAGE_SIZE);
        if (!buf)
                RETURN(-ENOMEM);

        while (rc == 0) {
                struct llog_rec_hdr *rec;

                /* there is likely a more efficient way than this */
                while (index < LLOG_BITMAP_BYTES * 8 &&
                       !ext2_test_bit(index, llh->llh_bitmap))
                        ++index;

                if (index >= LLOG_BITMAP_BYTES * 8)
                        break;

                rc = llog_next_block(loghandle, 0, index, 
                                     &cur_offset, buf, PAGE_SIZE);
                if (rc)
                        RETURN(rc);

                rec = buf;

                /* skip records in buffer until we are at the one we want */
                while (rec->lrh_index < index) {
                        if (rec->lrh_index == 0)
                                RETURN(0); /* no more records */

                        cur_offset += rec->lrh_len;
                        rec = ((void *)rec + rec->lrh_len);

                        if ((void *)rec > buf + PAGE_SIZE) {
                                CERROR("log index %u not in log @ "LPU64"\n",
                                       index, cur_offset);
                                LBUG(); /* record not in this buffer? */
                        }

                        rc = cb(loghandle, rec, data);
                        ++index;
                }
        }

        RETURN(rc);
}
EXPORT_SYMBOL(llog_process_log);

int llog_write_header(struct llog_handle *loghandle, int size)
{
        struct llog_log_hdr *llh;
        int rc;
        ENTRY;
        LASSERT(sizeof(*llh) == LLOG_CHUNK_SIZE);

        if (loghandle->lgh_file->f_dentry->d_inode->i_size)
                RETURN(-EBUSY);

        llh = loghandle->lgh_hdr;
        llh->llh_size = size;
        llh->llh_hdr.lrh_type = LLOG_OBJECT_MAGIC;
        llh->llh_hdr.lrh_len = llh->llh_tail.lrt_len = sizeof(*llh);
        llh->llh_timestamp = LTIME_S(CURRENT_TIME);
        llh->llh_bitmap_offset = offsetof(typeof(*llh), llh_bitmap);

        /* write the header record in the log */
        rc = llog_write_rec(loghandle, &llh->llh_hdr, NULL, 0, NULL, 0);
        if (rc > 0)
                rc = 0;
        RETURN(rc);
}
