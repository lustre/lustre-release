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
 * - 1 log file for each OST<->MDS connection, so that if an OST fails it
 *   need only look at logs relevant to itself
 */

#define DEBUG_SUBSYSTEM S_UNDEFINED

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

        INIT_LIST_HEAD(&loghandle->lgh_list);
        sema_init(&loghandle->lgh_lock, 1);

        RETURN(loghandle);
}

void llog_free_handle(struct llog_handle *loghandle)
{
        if (!loghandle)
                return;

        list_del_init(&loghandle->lgh_list);
        OBD_FREE(loghandle, sizeof(*loghandle));
}

/* Create a new log handle and add it to the open list.
 * This log handle will be closed when all of the records in it are removed.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 */
static struct llog_handle *llog_new_log(struct llog_handle *cathandle,
                                        struct obd_trans_info *oti)
{
        struct llog_handle *loghandle;
        struct llog_catalog_hdr *lch;
        struct llog_object_hdr *loh;
        loff_t offset;
        int rc, index, bitmap_size, i;
        ENTRY;

        LASSERT(sizeof(*loh) == LLOG_CHUNK_SIZE);

        loghandle = cathandle->lgh_log_create(cathandle->lgh_obd, oti);
        if (IS_ERR(loghandle))
                GOTO(out, rc = PTR_ERR(loghandle));

        OBD_ALLOC(loh, sizeof(*loh));
        if (!loh)
                GOTO(out_handle, rc = -ENOMEM);
        loh->loh_hdr.lth_type = LLOG_OBJECT_MAGIC;
        loh->loh_hdr.lth_len = loh->loh_hdr_end_len = sizeof(*loh);
        loh->loh_timestamp = CURRENT_TIME;
        loh->loh_bitmap_offset = offsetof(struct llog_object_hdr, loh_bitmap);
        loghandle->lgh_hdr = loh;

        lch = cathandle->lgh_hdr;
        bitmap_size = sizeof(lch->lch_bitmap) * 8;
        /* This should basically always find the first entry free */
        for (i = 0, index = lch->lch_index; i < bitmap_size; i++, index++) {
                index %= bitmap_size;
                if (ext2_set_bit(index, lch->lch_bitmap))
                        /* XXX This should trigger log clean up or similar */
                        CERROR("catalog index %d is still in use\n", index);
                else {
                        lch->lch_index = (index + 1) % bitmap_size;
                        break;
                }
        }
        if (i == bitmap_size)
                CERROR("no free catalog slots for log...\n");

        CDEBUG(D_HA, "new recovery log "LPX64":%x catalog index %u\n",
               loghandle->lgh_cookie.lgc_lgl.lgl_oid,
               loghandle->lgh_cookie.lgc_lgl.lgl_ogen, index);
        loghandle->lgh_cookie.lgc_index = index;

        offset = sizeof(*lch) + index * sizeof(loghandle->lgh_cookie);

        /* XXX Hmm, what to do if the catalog update fails?  Under normal
         *     operations we would clean this handle up anyways, and at
         *     worst we leak some objects.
         *
         *     We don't want to mark a catalog in-use if it wasn't written.
         *     The only danger is if the OST crashes - the log is lost.
         */
        rc = lustre_fwrite(cathandle->lgh_file, &loghandle->lgh_cookie,
                           sizeof(loghandle->lgh_cookie), &offset);
        if (rc != sizeof(loghandle->lgh_cookie)) {
                CERROR("error adding log "LPX64" to catalog: rc %d\n",
                       loghandle->lgh_cookie.lgc_lgl.lgl_oid, rc);
                rc = rc < 0 ? : -ENOSPC;
        } else {
                offset = 0;
                rc = lustre_fwrite(cathandle->lgh_file, lch, sizeof(*lch),
                                   &offset);
                if (rc != sizeof(*lch)) {
                        CERROR("error marking catalog entry %d in use: rc %d\n",
                               index, rc);
                        rc = rc < 0 ? : -ENOSPC;
                }
        }
        list_add_tail(&loghandle->lgh_list, &cathandle->lgh_list);

        RETURN(loghandle);

out_handle:
        llog_free_handle(loghandle);
out:
        RETURN(ERR_PTR(rc));
}

/* Assumes caller has already pushed us into the kernel context. */
int llog_init_catalog(struct llog_handle *cathandle)
{
        struct llog_catalog_hdr *lch;
        struct file *file = cathandle->lgh_file;
        loff_t offset = 0;
        int rc = 0;
        ENTRY;

        LASSERT(sizeof(*lch) == LLOG_CHUNK_SIZE);

        down(&cathandle->lgh_lock);
        OBD_ALLOC(lch, sizeof(*lch));
        if (!lch)
                GOTO(out, rc = -ENOMEM);

        cathandle->lgh_hdr = lch;

        if (file->f_dentry->d_inode->i_size == 0) {
write_hdr:      lch->lch_hdr.lth_type = LLOG_CATALOG_MAGIC;
                lch->lch_hdr.lth_len = lch->lch_hdr_end_len = LLOG_CHUNK_SIZE;
                lch->lch_timestamp = CURRENT_TIME;
                lch->lch_bitmap_offset = offsetof(struct llog_catalog_hdr,
                                                  lch_bitmap);
                rc = lustre_fwrite(file, lch, sizeof(*lch), &offset);
                if (rc != sizeof(*lch)) {
                        CERROR("error writing catalog header: rc %d\n", rc);
                        OBD_FREE(lch, sizeof(*lch));
                        if (rc >= 0)
                                rc = -ENOSPC;
                } else
                        rc = 0;
        } else {
                rc = lustre_fread(file, lch, sizeof(*lch), &offset);
                if (rc != sizeof(*lch)) {
                        CERROR("error reading catalog header: rc %d\n", rc);
                        /* Can we do much else if the header is bad? */
                        goto write_hdr;
                } else
                        rc = 0;
        }

out:
        up(&cathandle->lgh_lock);
        RETURN(rc);
}

/* Return the currently active log handle.  If the current log handle doesn't
 * have enough space left for the current record, start a new one.
 *
 * If reclen is 0, we only want to know what the currently active log is,
 * otherwise we get a lock on this log so nobody can steal our space.
 *
 * Assumes caller has already pushed us into the kernel context and is locking.
 */
struct llog_handle *llog_current_log(struct llog_handle *cathandle, int reclen,
                                     struct obd_trans_info *oti)
{
        struct list_head *loglist = &cathandle->lgh_list;
        struct llog_handle *loghandle = NULL;
        ENTRY;

        if (!list_empty(loglist)) {
                struct llog_object_hdr *loh;

                loghandle = list_entry(loglist->prev, struct llog_handle,
                                       lgh_list);
                loh = loghandle->lgh_hdr;
                if (loh->loh_numrec < sizeof(loh->loh_bitmap) * 8)
                        GOTO(out, loghandle);
        }

        if (reclen) {
                loghandle = llog_new_log(cathandle, oti);
                GOTO(out, loghandle);
        }
out:
        return loghandle;
}

/* Add a single record to the recovery log(s).
 * Returns number of bytes in returned logcookies, or negative error code.
 *
 * Assumes caller has already pushed us into the kernel context.
 */
int llog_add_record(struct llog_handle *cathandle, struct llog_trans_hdr *rec,
                    struct lov_stripe_md *lsm, struct obd_trans_info *oti,
                    struct llog_cookie *logcookies)
{
        struct llog_handle *loghandle;
        struct llog_object_hdr *loh;
        int reclen = rec->lth_len;
        struct file *file;
        loff_t offset;
        size_t left;
        int index;
        int rc;
        ENTRY;

        LASSERT(rec->lth_len <= LLOG_CHUNK_SIZE);
        down(&cathandle->lgh_lock);
        loghandle = llog_current_log(cathandle, reclen, oti);
        if (IS_ERR(loghandle)) {
                up(&cathandle->lgh_lock);
                RETURN(PTR_ERR(loghandle));
        }
        down(&loghandle->lgh_lock);
        up(&cathandle->lgh_lock);

        loh = loghandle->lgh_hdr;
        file = loghandle->lgh_file;

        /* Make sure that records don't cross a chunk boundary, so we can
         * process them page-at-a-time if needed.  If it will cross a chunk
         * boundary, write in a fake (but referenced) entry to pad the chunk.
         *
         * We know that llog_current_log() will return a loghandle that is
         * big enough to hold reclen, so all we care about is padding here.
         */
        left = LLOG_CHUNK_SIZE - (file->f_pos & (LLOG_CHUNK_SIZE - 1));
        if (left != 0 && left != reclen && left < reclen + LLOG_MIN_REC_SIZE) {
                struct llog_null_trans {
                        struct llog_trans_hdr hdr;
                        __u32 padding[6];
                } pad = { .hdr = { .lth_len = left } };

                LASSERT(left >= LLOG_MIN_REC_SIZE);
                if (left <= sizeof(pad))
                        *(__u32 *)((char *)&pad + left - sizeof(__u32)) = left;

                rc = lustre_fwrite(loghandle->lgh_file, &pad,
                                   min(sizeof(pad), left),
                                   &loghandle->lgh_file->f_pos);
                if (rc != min(sizeof(pad), left)) {
                        CERROR("error writing padding record: rc %d\n", rc);
                        GOTO(out, rc < 0 ? rc : -EIO);
                }

                left -= rc;
                if (left) {
                        LASSERT(left >= sizeof(__u32));
                        loghandle->lgh_file->f_pos += left - sizeof(__u32);
                        rc = lustre_fwrite(loghandle->lgh_file, &pad,
                                           sizeof(__u32),
                                           &loghandle->lgh_file->f_pos);
                        if (rc != sizeof(__u32)) {
                                CERROR("error writing padding end: rc %d\n",
                                       rc);
                                GOTO(out, rc < 0 ? rc : -EIO);
                        }
                }

                loghandle->lgh_index++;
        }

        index = loghandle->lgh_index++;
        if (ext2_set_bit(index, loh->loh_bitmap)) {
                CERROR("argh, index %u already set in log bitmap?\n", index);
                LBUG(); /* should never happen */
        }
        loh->loh_numrec++;

        offset = 0;
        rc = lustre_fwrite(loghandle->lgh_file, loh, sizeof(*loh), &offset);
        if (rc != sizeof(*loh)) {
                CERROR("error writing log header: rc %d\n", rc);
                GOTO(out, rc < 0 ? rc : -EIO);
        }

        rc = lustre_fwrite(loghandle->lgh_file, rec, reclen,
                           &loghandle->lgh_file->f_pos);
        if (rc != reclen) {
                CERROR("error writing log record: rc %d\n", rc);
                GOTO(out, rc < 0 ? rc : -EIO);
        }

        *logcookies = loghandle->lgh_cookie;
        logcookies->lgc_index = index;

out:
        up(&loghandle->lgh_lock);
        RETURN(sizeof(*logcookies));
}

/* Remove a log entry from the catalog.
 * Assumes caller has already pushed us into the kernel context and is locking.
 */
int llog_delete_log(struct llog_handle *cathandle,struct llog_handle *loghandle)
{
        struct llog_cookie *lgc = &loghandle->lgh_cookie;
        int catindex = lgc->lgc_index;
        struct llog_catalog_hdr *lch = cathandle->lgh_hdr;
        loff_t offset = 0;
        int rc = 0;
        ENTRY;

        CDEBUG(D_HA, "log "LPX64":%x empty, closing\n",
               lgc->lgc_lgl.lgl_oid, lgc->lgc_lgl.lgl_ogen);

        if (ext2_clear_bit(catindex, lch->lch_bitmap)) {
                CERROR("catalog index %u already clear?\n", catindex);
        } else {
                rc = lustre_fwrite(cathandle->lgh_file, lch, sizeof(*lch),
                                   &offset);

                if (rc != sizeof(*lch)) {
                        CERROR("log %u cancel error: rc %d\n", catindex, rc);
                        if (rc >= 0)
                                rc = -EIO;
                } else
                        rc = 0;
        }
        RETURN(rc);
}

/* Assumes caller has already pushed us into the kernel context and is locking.
 * We return a lock on the handle to ensure nobody yanks it from us.
 */
struct llog_handle *llog_id2handle(struct llog_handle *cathandle,
                                   struct llog_cookie *logcookie)
{
        struct llog_handle *loghandle;
        struct llog_logid *lgl = &logcookie->lgc_lgl;
        ENTRY;

        if (cathandle == NULL)
                RETURN(ERR_PTR(-EBADF));

        list_for_each_entry(loghandle, &cathandle->lgh_list, lgh_list) {
                struct llog_logid *cgl = &loghandle->lgh_cookie.lgc_lgl;
                if (cgl->lgl_oid == lgl->lgl_oid) {
                        if (cgl->lgl_ogen != lgl->lgl_ogen) {
                                CERROR("log "LPX64" generation %x != %x\n",
                                       lgl->lgl_oid, cgl->lgl_ogen,
                                       lgl->lgl_ogen);
                                continue;
                        }
                        GOTO(out, loghandle);
                }
        }

        loghandle = cathandle->lgh_log_open(cathandle->lgh_obd, logcookie);
        if (IS_ERR(loghandle)) {
                CERROR("error opening log id "LPX64":%x: rc %d\n",
                       lgl->lgl_oid, lgl->lgl_ogen, (int)PTR_ERR(loghandle));
        } else {
                list_add(&loghandle->lgh_list, &cathandle->lgh_list);
        }

out:
        RETURN(loghandle);
}

/* For each cookie in the cookie array, we clear the log in-use bit and either:
 * - the log is empty, so mark it free in the catalog header and delete it
 * - the log is not empty, just write out the log header
 *
 * The cookies may be in different log files, so we need to get new logs
 * each time.
 *
 * Assumes caller has already pushed us into the kernel context.
 */
int llog_cancel_records(struct llog_handle *cathandle, int count,
                        struct llog_cookie *cookies)
{
        int rc = 0;
        int i;
        ENTRY;

        down(&cathandle->lgh_lock);
        for (i = 0; i < count; i++, cookies++) {
                struct llog_handle *loghandle;
                struct llog_object_hdr *loh;
                struct llog_logid *lgl = &cookies->lgc_lgl;

                loghandle = llog_id2handle(cathandle, cookies);
                if (IS_ERR(loghandle)) {
                        if (!rc)
                                rc = PTR_ERR(loghandle);
                        continue;
                }

                down(&loghandle->lgh_lock);
                loh = loghandle->lgh_hdr;
                CDEBUG(D_HA, "cancelling "LPX64" index %u: %u\n",
                       lgl->lgl_oid, cookies->lgc_index,
                        ext2_test_bit(cookies->lgc_index, loh->loh_bitmap));
                if (!ext2_clear_bit(cookies->lgc_index, loh->loh_bitmap)) {
                        CERROR("log index %u in "LPX64":%x already clear?\n",
                               cookies->lgc_index, lgl->lgl_oid, lgl->lgl_ogen);
                } else if (--loh->loh_numrec == 0 &&
                           loghandle != llog_current_log(cathandle, 0, NULL)) {
                        loghandle->lgh_log_close(cathandle, loghandle);
                } else {
                        loff_t offset = 0;
                        int ret = lustre_fwrite(loghandle->lgh_file, loh,
                                                sizeof(*loh), &offset);

                        if (ret != sizeof(*loh)) {
                                CERROR("error cancelling index %u: rc %d\n",
                                       cookies->lgc_index, ret);
                                /* XXX mark handle bad? */
                                if (!rc)
                                        rc = ret;
                        }
                }
                up(&loghandle->lgh_lock);
        }
        up(&cathandle->lgh_lock);

        RETURN(rc);
}
