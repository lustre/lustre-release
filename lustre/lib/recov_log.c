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
 */

#include <linux/obd.h>
#include <linux/lustre_log.h>

/* Create a new log handle and add it to the open list.
 * This log handle will be closed when all of the records in it are removed.
 */
static int llog_new_log(struct lustre_handle *conn, struct list_head *loglist,
                        void *transhandle)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct llog_handle *loghandle;
        struct llog_object_hdr *loh;
        struct obdo *oa;
        void *addr;
        ENTRY;

        if (list_empty(loglist)) {
                XXX do stuff to allocate log_catalog;
        }

        OBD_ALLOC(loghandle, sizeof(*loghandle));
        if (loghandle == NULL)
                RETURN(-ENOMEM);

        loghandle->lgh_pga[0].pg = alloc_page(GFP_KERNEL);
        if (loghandle->lgh_pga[0].pg == NULL)
                GOTO(out_handle, rc = -ENOMEM);
        loghandle->lgh_pga[0].count = LLOG_HEADER_SIZE;

        loh = kmap(loghandle->lgh_pga[0].pg);
        clear_page(loh);
        loh->loh_size = loh->loh_size_end = LLOG_HEADER_SIZE;
        loh->loh_magic = LLOG_OBJECT_MAGIC;
        kunmap(loghandle->lgh_pga[0].pg);

        loghandle->lgh_pga[1].pg = alloc_page(GFP_KERNEL);
        if (loghandle->lgh_pga[1].pg == NULL)
                GOTO(out_pga1, rc = -ENOMEM);
        loghandle->lgh_pga[0].off = LLOG_HEADER_SIZE;

        obdo_alloc(oa);
        rc = obd_create(conn, oa, &loghandle->lsm, NULL)
        if (rc) {
                obdo_free(oa);
                GOTO(out_pga2, rc);
        }

retry:
        lch = kmap(obd->u.
        index = ext2_find_first_zero_bit(lch->lch_bitmap, LLOG_BITMAP_SIZE * 8);
        if (ext2_set_bit(index, lch->lch_bitmap)) {
                CERROR("log catalog bit %u changed under us!\n", index);
                goto retry;
        }
        if (index > lch->lch_numrec
        rc = obd_brw(OBD_BRW_WRITE, conn,
        list_add_tail(&loghandle->lgh_list, loglist);
        loghandle->lgh_lid.lid_oid = oa->o_id;
        //loghandle->lgh_lid.lid_bootcount = ????;

out_pga2:
        __free_page(loghandle->lgh_pga[1].pg);
out_pga1:
        __free_page(loghandle->lgh_pga[0].pg);
out_handle:
        OBD_FREE(loghandle, sizeof(*loghandle));

        RETURN(rc);
}

/* We start a new log object here if needed, either because no log has been
 * started, or because the current log cannot fit the new record.
 */
int llog_get_log(conn, struct list_head *loglist, int reclen, void *transhandle)
{
        if (list_empty(loglist)) {
                loghandle = llog_new_log(conn, loglist, transhandle);
                if (IS_ERR(loghandle))
                        RETURN(rc = PTR_ERR(loghandle));
        } else {
                loghandle = list_entry(loglist->prev, struct llog_handle,
                                       lgh_list);
                if (loghandle->lgh_pga[1].off + reclen >= LLOG_MAX_LOG_SIZE) {
                        __free_page(loghandle->lgh_pga[1].pg);
                        loghandle->lgh_pga[1].pg = NULL;
                        loghandle = llog_new_log(conn, loglist, transhandle);
                        if (IS_ERR(loghandle))
                                RETURN(rc = PTR_ERR(loghandle));
                }
        }
}

/* Add a single record to the recovery log.  */
int llog_add_record(struct lustre_handle *conn, struct list_head *loglist,
                    llog_trans_hdr *rec, struct llog_cookie *logcookie,
                    void *transhandle)
{
        struct llog_handle *loghandle;
        struct llog_object_hdr *loh;
        int reclen = rec->lgh_len;
        int num_pga = 2;
        int rc;
        ENTRY;

        loghandle = llog_get_log(conn, loglist, reclen, transhandle);

#if PAGE_SIZE > LLOG_HEADER_SIZE
        /* It is possible we are still writing in the first page */
        if (loghandle->lgh_pga[1].off < PAGE_SIZE) {
                memcpy(kmap(loghandle->lgh_pga[0]->page) +
                       loghandle->lgh_pga[1].off, rec, reclen);
                loghandle->lgh_pga[0].count = loghandle->lgh_pga[1].off+reclen;
                num_pga = 1;
        } else
#endif
        {
                memcpy(kmap(loghandle->lgh_pga[1]->page) +
                       loghandle->lgh_pga[1].off, rec, reclen);
#if PAGE_SIZE > LLOG_HEADER_SIZE
                loghandle->lgh_pga[0].count = LLOG_HEADER_SIZE;
#endif
                loghandle->lgh_pga[1].count = reclen;
        }
        kunmap(loghandle->lgh_pga->page);
        rc = obd_brw(OBD_BRW_WRITE, conn, loghandle->lgh_lsm, num_pga,
                     loghandle->lgh_pga, NULL, NULL);

        if (rc)
                RETURN(rc);

        loh = kmap(logcookie->lgc_pga[0].pg);
        logcookie->lgc_lid = loghandle->lgh_lid;
        logcookie->lgc_offset = loghandle->lgh_pga[1].off;
        logcookie->lgc_index = loh->loh_numrec++;
        ext2_set_bit(logcookie->lgc_index, loh->loh_bitmap);
        kunmap(logcookie->lgc_pga[0].pg);

        loghandle->lgh_pga[1].off += reclen;

        RETURN(0);
}

int llog_clear_records(int count, struct llog_cookie **cookies)
int llog_clear_record(struct llog_handle *handle, __u32 recno)
int llog_delete(struct llog_logid *id)
