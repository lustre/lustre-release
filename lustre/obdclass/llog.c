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

        sema_init(&loghandle->lgh_lock, 1);

        RETURN(loghandle);
}
EXPORT_SYMBOL(llog_alloc_handle);


void llog_free_handle(struct llog_handle *loghandle)
{
        if (!loghandle)
                return;

        if (loghandle->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN)
                list_del_init(&loghandle->u.phd.phd_entry);
        if (loghandle->lgh_hdr->llh_flags & LLOG_F_IS_CAT)
                LASSERT(list_empty(&loghandle->u.chd.chd_head));

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

        if (index == 0) {
                CERROR("cannot cancel index 0 (which is header)\n");
                RETURN(-EINVAL);
        }

        if (!ext2_clear_bit(index, llh->llh_bitmap)) {
                CERROR("catalog index %u already clear?\n", index);
                LBUG();
        }

        llh->llh_count--;

        if (llh->llh_flags & LLOG_F_ZAP_WHEN_EMPTY &&
            llh->llh_count == 1 &&
            loghandle->lgh_last_idx == (LLOG_BITMAP_BYTES * 8) - 1) {
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

int llog_init_handle(struct llog_handle *handle, int flags,
                     struct obd_uuid *uuid)
{
        int rc;
        struct llog_log_hdr *llh;
        ENTRY;
        LASSERT(handle->lgh_hdr == NULL);

        OBD_ALLOC(llh, sizeof(*llh));
        if (llh == NULL)
                RETURN(-ENOMEM);

        handle->lgh_hdr = llh;
        rc = llog_read_header(handle);
        if (rc == 0) {
                LASSERT((llh->llh_flags & flags)== flags);
                if (uuid)
                        LASSERT(obd_uuid_equals(uuid, &llh->llh_tgtuuid));
                GOTO(out, rc);
        } else if (rc != LLOG_EEMPTY) {
                GOTO(out, rc);
        }
        rc = 0;

        handle->lgh_last_idx = 0; /* header is record with index 0 */
        llh->llh_count = 1;         /* for the header record */
        llh->llh_hdr.lrh_type = LLOG_HDR_MAGIC;
        llh->llh_hdr.lrh_len = llh->llh_tail.lrt_len = LLOG_CHUNK_SIZE;
        llh->llh_hdr.lrh_index = llh->llh_tail.lrt_index = 0;
        llh->llh_timestamp = LTIME_S(CURRENT_TIME);
        llh->llh_flags = flags;
        memcpy(&llh->llh_tgtuuid, uuid, sizeof(llh->llh_tgtuuid));
        llh->llh_bitmap_offset = offsetof(typeof(*llh), llh_bitmap);
        ext2_set_bit(0, llh->llh_bitmap);

 out:
        if (flags & LLOG_F_IS_CAT) {
                INIT_LIST_HEAD(&handle->u.chd.chd_head);
                llh->llh_size = sizeof(struct llog_logid_rec);
        }
        else if (llh->llh_flags & LLOG_F_IS_PLAIN)
                INIT_LIST_HEAD(&handle->u.phd.phd_entry);
        else
                LBUG();
        if (rc)
                OBD_FREE(llh, sizeof(*llh));
        return(rc);
}
EXPORT_SYMBOL(llog_init_handle);

int llog_process_log(struct llog_handle *loghandle, llog_cb_t cb, void *data)
{
        struct llog_log_hdr *llh = loghandle->lgh_hdr;
        void *buf;
        __u64 cur_offset = LLOG_CHUNK_SIZE;
        int rc = 0, index = 1;
        ENTRY;

        OBD_ALLOC(buf, LLOG_CHUNK_SIZE);
        if (!buf)
                RETURN(-ENOMEM);

        while (rc == 0) {
                struct llog_rec_hdr *rec;

                /* skip records not set in bitmap */
                while (index < (LLOG_BITMAP_BYTES * 8) &&
                       !ext2_test_bit(index, llh->llh_bitmap))
                        ++index;

                LASSERT(index <= LLOG_BITMAP_BYTES * 8);
                if (index == LLOG_BITMAP_BYTES * 8)
                        break;

                /* get the buf with our target record */
                rc = llog_next_block(loghandle, 0, index, 
                                     &cur_offset, buf, PAGE_SIZE);
                if (rc)
                        GOTO(out, rc);
                LASSERT(ext2_test_bit(index, llh->llh_bitmap));

                rec = buf;
                index = rec->lrh_index;

                /* process records in buffer, starting where we found one */
                while ((void *)rec < buf+PAGE_SIZE) {
                        if (rec->lrh_index == 0)
                                GOTO(out, 0); /* no more records */

                        /* if set, process the callback on this record */
                        if (ext2_test_bit(index, llh->llh_bitmap)) {
                                rc = cb(loghandle, rec, data);
                                if (rc) 
                                        GOTO(out, rc);
                        }

                        /* next record, still in buffer? */
                        ++index;
                        rec = ((void *)rec + rec->lrh_len);
                }
        }

 out:
        if (buf)
                OBD_FREE(buf, LLOG_CHUNK_SIZE);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_process_log);

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
#endif
