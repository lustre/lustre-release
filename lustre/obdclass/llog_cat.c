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

/* Create a new log handle and add it to the open list.
 * This log handle will be closed when all of the records in it are removed.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 */
static struct llog_handle *llog_cat_new_log(struct llog_handle *cathandle)
{
        struct llog_handle *loghandle;
        struct llog_log_hdr *llh;
        struct llog_logid_rec rec;
        int rc, index, bitmap_size, i;
        ENTRY;

        rc = llog_create(cathandle->lgh_ctxt, &loghandle, NULL, NULL);
        if (rc)
                RETURN(ERR_PTR(rc));

        rc = llog_init_handle(loghandle, 
                              LLOG_F_IS_PLAIN | LLOG_F_ZAP_WHEN_EMPTY, 
                              &cathandle->lgh_hdr->llh_tgtuuid);
        if (rc)
                GOTO(out_destroy, rc);

        /* Find first free entry */
        llh = cathandle->lgh_hdr;
        bitmap_size = sizeof(llh->llh_bitmap) * 8;
        for (i = 0, index = le32_to_cpu(llh->llh_count); i < bitmap_size; 
             i++, index++) {
                index %= bitmap_size;
                if (ext2_set_bit(index, llh->llh_bitmap)) {
                        /* XXX This should trigger log clean up or similar */
                        CERROR("catalog index %d is still in use\n", index);
                } else {
                        cathandle->lgh_last_idx = index;
                        llh->llh_count = cpu_to_le32(le32_to_cpu(llh->llh_count) + 1);
                        break;
                }
        }
        if (i == bitmap_size) {
                CERROR("no free catalog slots for log...\n");
                GOTO(out_destroy, rc = -ENOSPC);
        }

        CDEBUG(D_HA, "new recovery log "LPX64": catalog index %u\n",
               loghandle->lgh_id.lgl_oid, index);

        /* build the record for this log in the catalog */
        rec.lid_hdr.lrh_len = cpu_to_le32(sizeof(rec));
        rec.lid_hdr.lrh_index = cpu_to_le32(index);
        rec.lid_hdr.lrh_type = cpu_to_le32(LLOG_LOGID_MAGIC);
        rec.lid_id = loghandle->lgh_id;
        rec.lid_tail.lrt_len = cpu_to_le32(sizeof(rec));
        rec.lid_tail.lrt_index = cpu_to_le32(index);

        /* update the catalog: header and record */
        rc = llog_write_rec(cathandle, &rec.lid_hdr, 
                            &loghandle->u.phd.phd_cookie, 1, NULL, index);
        if (rc < 0) {
                GOTO(out_destroy, rc);
        }

        loghandle->lgh_hdr->llh_cat_idx = cpu_to_le32(index);
        cathandle->u.chd.chd_current_log = loghandle;
        LASSERT(list_empty(&loghandle->u.phd.phd_entry));
        list_add_tail(&loghandle->u.phd.phd_entry, &cathandle->u.chd.chd_head);

 out_destroy:
        if (rc < 0)
                llog_destroy(loghandle);

        RETURN(loghandle);
}
EXPORT_SYMBOL(llog_cat_new_log);

/* Assumes caller has already pushed us into the kernel context and is locking.
 * We return a lock on the handle to ensure nobody yanks it from us.
 */
int llog_cat_id2handle(struct llog_handle *cathandle, struct llog_handle **res,
                       struct llog_logid *logid)
{
        struct llog_handle *loghandle;
        int rc = 0;
        ENTRY;

        if (cathandle == NULL)
                RETURN(-EBADF);

        list_for_each_entry(loghandle, &cathandle->u.chd.chd_head, 
                            u.phd.phd_entry) {
                struct llog_logid *cgl = &loghandle->lgh_id;
                if (cgl->lgl_oid == logid->lgl_oid) {
                        if (cgl->lgl_ogen != logid->lgl_ogen) {
                                CERROR("log "LPX64" generation %x != %x\n",
                                       logid->lgl_oid, cgl->lgl_ogen,
                                       logid->lgl_ogen);
                                continue;
                        }
                        loghandle->u.phd.phd_cat_handle = cathandle;
                        cathandle->u.chd.chd_current_log = loghandle;
                        GOTO(out, rc = 0);
                }
        }

        rc = llog_create(cathandle->lgh_ctxt, &loghandle, logid, NULL);
        if (rc) {
                CERROR("error opening log id "LPX64":%x: rc %d\n",
                       logid->lgl_oid, logid->lgl_ogen, rc);
        } else {
                rc = llog_init_handle(loghandle, LLOG_F_IS_PLAIN, NULL);
                if (!rc) {
                        list_add(&loghandle->u.phd.phd_entry, 
                                 &cathandle->u.chd.chd_head);
                        cathandle->u.chd.chd_current_log = loghandle;
                }
        }
        if (!rc) {
                loghandle->u.phd.phd_cat_handle = cathandle;
                loghandle->u.phd.phd_cookie.lgc_lgl = cathandle->lgh_id;
                loghandle->u.phd.phd_cookie.lgc_index = 
                        le32_to_cpu(loghandle->lgh_hdr->llh_cat_idx);
        }

out:
        *res = loghandle;
        RETURN(rc);
}

int llog_cat_put(struct llog_handle *cathandle)
{
        struct llog_handle *loghandle, *n;
        int rc;
        ENTRY;

        list_for_each_entry_safe(loghandle, n, &cathandle->u.chd.chd_head, 
                                 u.phd.phd_entry) {
                int err = llog_close(loghandle);
                if (err)
                        CERROR("error closing loghandle\n");
        }
        rc = llog_close(cathandle);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_put);

/* Return the currently active log handle.  If the current log handle doesn't
 * have enough space left for the current record, start a new one.
 *
 * If reclen is 0, we only want to know what the currently active log is,
 * otherwise we get a lock on this log so nobody can steal our space.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 */
static struct llog_handle *llog_cat_current_log(struct llog_handle *cathandle, 
                                                int create)
{
        struct llog_handle *loghandle = NULL;
        ENTRY;

        loghandle = cathandle->u.chd.chd_current_log;
        if (loghandle) {
                struct llog_log_hdr *llh = loghandle->lgh_hdr;
                if (loghandle->lgh_last_idx < (sizeof(llh->llh_bitmap) * 8) - 1)
                        RETURN(loghandle);
        }

        CDEBUG(D_INODE, "creating new log\n");
        if (create)
                loghandle = llog_cat_new_log(cathandle);
        RETURN(loghandle);
}

/* Add a single record to the recovery log(s) using a catalog
 * Returns as llog_write_record
 *
 * Assumes caller has already pushed us into the kernel context.
 */
int llog_cat_add_rec(struct llog_handle *cathandle, struct llog_rec_hdr *rec,
                    struct llog_cookie *reccookie, void *buf)
{
        struct llog_handle *loghandle;
        int rc;
        ENTRY;

        LASSERT(le32_to_cpu(rec->lrh_len) <= LLOG_CHUNK_SIZE);
        down(&cathandle->lgh_lock);
        loghandle = llog_cat_current_log(cathandle, 1);
        if (IS_ERR(loghandle)) {
                up(&cathandle->lgh_lock);
                RETURN(PTR_ERR(loghandle));
        }
        down(&loghandle->lgh_lock);
        up(&cathandle->lgh_lock);
        rc = llog_write_rec(loghandle, rec, reccookie, 1, buf, -1);

        up(&loghandle->lgh_lock);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_add_rec);

/* For each cookie in the cookie array, we clear the log in-use bit and either:
 * - the log is empty, so mark it free in the catalog header and delete it
 * - the log is not empty, just write out the log header
 *
 * The cookies may be in different log files, so we need to get new logs
 * each time.
 *
 * Assumes caller has already pushed us into the kernel context.
 */
int llog_cat_cancel_records(struct llog_handle *cathandle, int count,
                        struct llog_cookie *cookies)
{
        int i, index, rc = 0;
        ENTRY;

        down(&cathandle->lgh_lock);
        for (i = 0; i < count; i++, cookies++) {
                struct llog_handle *loghandle;
                struct llog_logid *lgl = &cookies->lgc_lgl;

                rc = llog_cat_id2handle(cathandle, &loghandle, lgl);
                if (rc) {
                        CERROR("Cannot find log "LPX64"\n", lgl->lgl_oid);
                        break;
                }

                down(&loghandle->lgh_lock);
                rc = llog_cancel_rec(loghandle, cookies->lgc_index);
                up(&loghandle->lgh_lock);
                
                if (rc == 1) {          /* log has been destroyed */
                        index = loghandle->u.phd.phd_cookie.lgc_index;
                        if (cathandle->u.chd.chd_current_log == loghandle)
                                cathandle->u.chd.chd_current_log = NULL;
                        llog_free_handle(loghandle);
                        
                        LASSERT(index);
                        rc = llog_cancel_rec(cathandle, index);
                }
        }
        up(&cathandle->lgh_lock);

        RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_cancel_records);

int llog_cat_process_cb(struct llog_handle *cat_llh, struct llog_rec_hdr *rec, void *data)
{
        struct llog_process_data *d = data;
        struct llog_logid_rec *lir = (struct llog_logid_rec *)rec;
        struct llog_handle *llh;
        int rc;

        if (le32_to_cpu(rec->lrh_type) != LLOG_LOGID_MAGIC) {
                CERROR("invalid record in catalog\n");
                RETURN(-EINVAL);
        }
        CERROR("processing log "LPX64" in catalog "LPX64"\n", 
               lir->lid_id.lgl_oid, cat_llh->lgh_id.lgl_oid);

        rc = llog_cat_id2handle(cat_llh, &llh, &lir->lid_id);
        if (rc) {
                CERROR("Cannot find handle for log "LPX64"\n", lir->lid_id.lgl_oid);
                RETURN(rc);
        }        

        rc = llog_process(llh, d->lpd_cb, d->lpd_data);
        RETURN(rc);
}

int llog_cat_process(struct llog_handle *cat_llh, llog_cb_t cb, void *data)
{
        struct llog_process_data d;
        int rc;
        ENTRY;
        d.lpd_data = data;
        d.lpd_cb = cb;

        rc = llog_process(cat_llh, llog_cat_process_cb, &d);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_process);


#if 0
/* Assumes caller has already pushed us into the kernel context. */
int llog_cat_init(struct llog_handle *cathandle, struct obd_uuid *tgtuuid)
{
        struct llog_log_hdr *llh;
        loff_t offset = 0;
        int rc = 0;
        ENTRY;

        LASSERT(sizeof(*llh) == LLOG_CHUNK_SIZE);

        down(&cathandle->lgh_lock);
        llh = cathandle->lgh_hdr;

        if (cathandle->lgh_file->f_dentry->d_inode->i_size == 0) {
                llog_write_rec(cathandle, &llh->llh_hdr, NULL, 0, NULL, 0);

write_hdr:    
                rc = lustre_fwrite(cathandle->lgh_file, llh, LLOG_CHUNK_SIZE,
                                   &offset);
                if (rc != LLOG_CHUNK_SIZE) {
                        CERROR("error writing catalog header: rc %d\n", rc);
                        OBD_FREE(llh, sizeof(*llh));
                        if (rc >= 0)
                                rc = -ENOSPC;
                } else
                        rc = 0;
        } else {
                rc = lustre_fread(cathandle->lgh_file, llh, LLOG_CHUNK_SIZE,
                                  &offset);
                if (rc != LLOG_CHUNK_SIZE) {
                        CERROR("error reading catalog header: rc %d\n", rc);
                        /* Can we do much else if the header is bad? */
                        goto write_hdr;
                } else
                        rc = 0;
        }

        cathandle->lgh_tgtuuid = &llh->llh_tgtuuid;
        up(&cathandle->lgh_lock);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_init);

#endif
