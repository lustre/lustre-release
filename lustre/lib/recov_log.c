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

/* Create a new log or catalog handle */
static struct log_handle *llog_new_handle(struct lustre_handle *conn,
                                          struct obd_trans_info *oti)
{
        struct llog_handle *loghandle;
        int rc;
        ENTRY;

        OBD_ALLOC(loghandle, sizeof(*loghandle));
        if (loghandle == NULL)
                GOTO(out, rc = -ENOMEM);

        loghandle->lgh_pga[0].pg = alloc_page(GFP_KERNEL);
        if (loghandle->lgh_pga[0].pg == NULL)
                GOTO(out_handle, rc = -ENOMEM);
        loghandle->lgh_pga[0].count = LLOG_HEADER_SIZE;

        loghandle->lgh_pga[1].pg = alloc_page(GFP_KERNEL);
        if (loghandle->lgh_pga[1].pg == NULL)
                GOTO(out_pga1, rc = -ENOMEM);
        loghandle->lgh_pga[0].off = LLOG_HEADER_SIZE;

        obdo_alloc(loghandle->lgh_oa);
        if (!loghandle->lgh_oa)
                GOTO(out_pga2, rc = -ENOMEM);

        rc = obd_create(conn, loghandle->lgh_oa, loghandle->lgh_lsm, oti)
        if (rc) {
                CERROR("couldn't create new log object: rc %d\n", rc);
                GOTO(out_oa, rc);
        }

        rc = obd_open(conn, loghandle->lgh_oa, loghandle->lgh_lsm, oti, NULL);
        if (rc) {
                CERROR("couldn't open new log object "LPX64": rc %d\n",
                       loghandle->lgh_oa->o_id, rc);
                GOTO(out_destroy, rc);
        }
        LIST_HEAD_INIT(&loghandle->lgh_list);
        loghandle->lgh_lid.lid_oid = oa->o_id;
        //loghandle->lgh_lid.lid_bootcount = ????;

        RETURN(loghandle);

out_destroy:
        obd_destroy(conn, loghandle->lgh_oa, loghandle->lgh_lsm, oti);
out_oa:
        obd_free(loghandle->lgh_oa);
out_pga2:
        __free_page(loghandle->lgh_pga[1].pg);
out_pga1:
        __free_page(loghandle->lgh_pga[0].pg);
out:
        RETURN(ERR_PTR(rc));
}

/* Create a new log handle and add it to the open list.
 * This log handle will be closed when all of the records in it are removed.
 */
static struct llog_handle *llog_new_log(struct lustre_handle *conn,
                                        struct obd_trans_info *oti)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct llog_handle *loghandle, *cathandle;
        struct llog_object_hdr *loh;
        struct llog_logid *lid;
        int num_pga = 2;
        ENTRY;

        cathandle = obd->obd_catalog;
        loghandle = llog_new_handle(conn, oti);
        if (IS_ERR(loghandle))
                RETURN(loghandle);

        loh = kmap(loghandle->lgh_pga[0].pg);
        clear_page(loh);
        loh->loh_size = loh->loh_size_end = LLOG_HEADER_SIZE;
        loh->loh_magic = LLOG_OBJECT_MAGIC;
        kunmap(loghandle->lgh_pga[0].pg);

        lch = kmap(cathandle->lgh_pga[0].pg);
retry:
        index = ext2_find_first_zero_bit(lch->lch_bitmap, LLOG_BITMAP_BYTES*8);
        /* Not much we can do here - we already leaked a few thousandd logs */
        LASSERT(index < LLOG_BITMAP_BYTES*8);

        if (ext2_set_bit(index, lch->lch_bitmap)) {
                CERROR("log catalog bit %u changed under us!!?\n", index);
                goto retry;
        }
        if (index >= lch->lch_maxrec)
                lch->lch_maxrec = index + 1;

        offset = LLOG_HEADER_SIZE + index * sizeof(*loh->loh_lid);
#if PAGE_SIZE > LLOG_HEADER_SIZE
        if (offset + sizeof(*loh->loh_lid) < PAGE_SIZE) {
                num_pga = 1;
                lid = (void *)lch + offset;
                *lid = loghandle->lgh_lid;
                cathandle->lgh_pga[0].len = offset+sizeof(lch->lch_lids[index]);
                kunmap(lch);
        } else
#endif
        {
                void *addr;

#if PAGE_SIZE > LLOG_HEADER_SIZE
                cathandle->lgh_pga[0].len = LLOG_HEADER_SIZE;
#endif
                kunmap(lch);

                cathandle->lgh_pga[1].off = offset;
                cathandle->lgh_pga[1].len = sizeof(*lid);
                addr = kmap(cathandle->lgh_pga[1].pg);
                lid = addr + (offset & ~PAGE_MASK);
                *lid = loghandle->lgh_lid;
                kunmap(cathandle->lgh_pga[1].pg);
        }

        rc = obd_brw(OBD_BRW_WRITE, conn, cathandle->lgh_lsm, num_pga,
                     cathandle->lgh_pga, NULL, oti);
        if (rc) {
        list_add_tail(&loghandle->lgh_list, &cathandle->lgh_list);

        RETURN(0);

out_handle:
        OBD_FREE(loghandle, sizeof(*loghandle));

        RETURN(rc);
}

int llog_init_catalog(struct lustre_handle *conn, struct obd_trans_info *oti)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct llog_handle *cathandle;
        struct llog_catalog_hdr *lch;
        ENTRY;

        if (obd->obd_catalog != NULL)
                RETURN(0);

        cathandle = llog_new_handle(conn, oti);
        if (IS_ERR(cathandle))
                RETURN(ERR_PTR(cathandle));
        obd->obd_catalog = cathandle;

        lch = kmap(cathandle->lgh_pga[0].pg);
        clear_page(lch);
        lch->lch_size = lch->lch_size_end = LLOG_HEADER_SIZE;
        lcg->lcg_magic = LLOG_CATALOG_MAGIC;
        kunmap(cathandle->lgh_pga[0].pg);

        RETURN(0);
}

/* We start a new log object here if needed, either because no log has been
 * started, or because the current log cannot fit the new record.
 */
int llog_get_log(struct lustre_handle *conn, int reclen,
                 struct obd_trans_info *oti)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct list_head *loglist = &obd->obd_catalog->lgh_list;

        if (list_empty(loglist)) {
                loghandle = llog_new_log(conn, oti);
                if (IS_ERR(loghandle))
                        RETURN(rc = PTR_ERR(loghandle));
        } else {
                loghandle = list_entry(loglist->prev, struct llog_handle,
                                       lgh_list);
                if (loghandle->lgh_pga[1].off + reclen >= LLOG_MAX_LOG_SIZE) {
                        __free_page(loghandle->lgh_pga[1].pg);
                        loghandle->lgh_pga[1].pg = NULL;
                        loghandle = llog_new_log(conn, oti);
                        if (IS_ERR(loghandle))
                                RETURN(rc = PTR_ERR(loghandle));
                }
        }
}

/* Add a single record to the recovery log.  */
int llog_add_record(struct lustre_handle *conn, struct llog_trans_hdr *rec,
                    struct llog_cookie *logcookie, struct obd_trans_info *oti)
{
        struct llog_handle *loghandle;
        struct llog_object_hdr *loh;
        int reclen = rec->lgh_len;
        int offset;
        int index;
        int num_pga = 2;
        int rc;
        ENTRY;

        loghandle = llog_get_log(conn, reclen, transhandle);

        offset = loghandle->lgh_pga[1].off;

        loh = kmap(loghandle->lgc_pga[0].pg);
        index = loh->loh_numrec++;
        ext2_set_bit(index, loh->loh_bitmap);

#if PAGE_SIZE > LLOG_HEADER_SIZE
        /* It is possible we are still writing in the first page */
        if (offset < PAGE_SIZE) {
                memcpy(loh + offset, rec, reclen);
                loghandle->lgh_pga[0].count = offset + reclen;
                kunmap(loghandle->lgh_pga[0]->pg);
                num_pga = 1;
        } else
#endif
        {
#if PAGE_SIZE > LLOG_HEADER_SIZE
                loghandle->lgh_pga[0].count = LLOG_HEADER_SIZE;
#endif
                kunmap(loghandle->lgh_pga[0]->pg);

                memcpy(kmap(loghandle->lgh_pga[1]->pg) + (offset & ~PAGE_MASK),
                       rec, reclen);
                loghandle->lgh_pga[1].count = reclen;
                kunmap(loghandle->lgh_pga[1]->pg);
        }
        rc = obd_brw(OBD_BRW_WRITE, conn, loghandle->lgh_lsm, num_pga,
                     loghandle->lgh_pga, NULL, oti);
        if (rc)
                RETURN(rc);

        loghandle->lgh_pga[1].off += reclen;

        logcookie->lgc_lid = loghandle->lgh_lid;
        logcookie->lgc_index = index;
        logcookie->lgc_offset = offset;

        RETURN(0);
}

int llog_clear_records(int count, struct llog_cookie **cookies)
int llog_clear_record(struct llog_handle *handle, __u32 recno)
int llog_delete(struct llog_logid *id)
