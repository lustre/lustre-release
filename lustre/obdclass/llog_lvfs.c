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
#include <linux/lvfs.h>

static int llog_lvfs_pad(struct l_file *file, int len, int index)
{
        struct llog_rec_hdr rec;
        struct llog_rec_tail tail;
        int rc;
        ENTRY;
        
        LASSERT(len >= LLOG_MIN_REC_SIZE && (len & 0xf) == 0);

        tail.lrt_len = rec.lrh_len = len;
        tail.lrt_index = rec.lrh_index = index;
        rec.lrh_type = 0;

        rc = lustre_fwrite(file, &rec, sizeof(rec), &file->f_pos);
        if (rc != sizeof(rec)) {
                CERROR("error writing padding record: rc %d\n", rc);
                GOTO(out, rc < 0 ? rc : rc = -EIO);
        }
        
        file->f_pos += len - sizeof(rec) - sizeof(tail);
        rc = lustre_fwrite(file, &tail, sizeof(tail), &file->f_pos);
        if (rc != sizeof(tail)) {
                CERROR("error writing padding record: rc %d\n", rc);
                GOTO(out, rc < 0 ? rc : rc = -EIO);
        }
        rc = 0;
 out: 
        RETURN(rc);
}

static int llog_vfs_write_blob(struct l_file *file, struct llog_rec_hdr *rec,
                               void *buf, loff_t off)
{
        int rc;
        struct llog_rec_tail end;
        loff_t saved_off = file->f_pos;

        ENTRY;
        file->f_pos = off;

        if (!buf) {
                rc = lustre_fwrite(file, rec, rec->lrh_len, &file->f_pos);
                if (rc != rec->lhr_len) {
                        CERROR("error writing log record: rc %d\n", rc);
                        GOTO(out, rc < 0 ? rc : rc = -ENOSPC);
                }
                GOTO(out, rc = 0);
        }

        /* the buf case */
        buflen = rec->lrh_len;
        rec->lrh_len = sizeof(*rec) + size_round(buflen) + sizeof(*end);
        rc = lustre_fwrite(file, rec, sizeof(*rec), &file->f_pos);
        if (rc != sizeof(*rec)) {
                CERROR("error writing log transhdr: rc %d\n", rc);
                GOTO(out, rc < 0 ? rc : rc = -ENOSPC);
        }

        rc = lustre_fwrite(file, buf, buflen, &file->f_pos);
        if (rc != buflen) {
                CERROR("error writing log buffer: rc %d\n", rc);
                GOTO(out, rc < 0 ? rc : rc  = -ENOSPC);
        }

        loghandle->lgh_file->f_pos += size_round(buflen) - buflen;
        end.lrt_len = rec->lrh_len;
        end.lrt_index = rec->lrh_index;
        rc = lustre_fwrite(file, &end, sizeof(end), &file->f_pos);
        if (rc != sizeof(end)) {
                CERROR("error writing log tail: rc %d\n", rc);
                GOTO(out, rc < 0 ? rc : rc =  -ENOSPC);
        }

        rc = 0;
 out: 
        if (saved_off > file->f_pos)
                file->f_pos = saved_off;
        LASSERT(rc <= 0);
        RETURN(rc);
}

/* returns negative in on error; 0 if success && reccookie == 0; 1 otherwise */
/* appends if idx == -1, otherwise overwrites record idx. */
int llog_lvfs_write_record(struct llog_handle *loghandle,
                           struct llog_rec_hdr *rec,
                           struct llog_cookie *reccookie, void *buf, int idx)
{
        struct llog_log_hdr *llh;
        int reclen = rec->lrh_len, index, rc, buflen;
        struct file *file;
        loff_t offset;
        size_t left;
        ENTRY;

        llh = loghandle->lgh_hdr;
        file = loghandle->lgh_file;

        if (idx != -1) { 
                loff_t saved_offset;

                /* no header: only allowed to insert record 0 */
                if (idx != 0 && !file->f_dentry->d_inode->i_size) {
                        CERROR("idx != -1 in empty log ");
                        LBUG();
                }

                if (!loghandle->lgh_hdr->llh_size != rec->lrh_len)
                        RETURN(-EINVAL);

                rc = llog_lvfs_write_blob(file, llh, NULL, 0);
                /* we are done if we only write the header or on error */
                if (rc || idx == 0)
                        RETURN(rc);

                saved_offset = sizeof(*llh) + idx * rec->lrh_len;
                rc = llog_lvfs_write_blob(file, rec, buf, saved_offset);
                if (rc)
                        RETURN(rc);
        }

        /* Make sure that records don't cross a chunk boundary, so we can
         * process them page-at-a-time if needed.  If it will cross a chunk
         * boundary, write in a fake (but referenced) entry to pad the chunk.
         *
         * We know that llog_current_log() will return a loghandle that is
         * big enough to hold reclen, so all we care about is padding here.
         */
        left = LLOG_CHUNK_SIZE - (file->f_pos & (LLOG_CHUNK_SIZE - 1));

        if (left != 0 && left <= reclen) {
                loghandle->lgh_index++;
                rc = llog_lvfs_pad(file, len, loghandle->lgh_index);
                if (rc)
                        RETURN(rc);
        }

        index = loghandle->lgh_index++;
        rec->lrh_index = index;
        if (ext2_set_bit(index, llh->llh_bitmap)) {
                CERROR("argh, index %u already set in log bitmap?\n", index);
                LBUG(); /* should never happen */
        }
        llh->llh_count++;

        offset = 0;
        rc = llog_lvfs_write_blob(file, llh, NULL, 0);
        if (rc)
                RETURN(rc);

        rc = llog_lvfs_write_blob(file, rec, buf, file->f_pos);
        if (rc)
                RETURN(rc);

 out:
        CDEBUG(D_HA, "added record "LPX64":%x+%u, %u bytes\n",
               loghandle->lgh_cookie.lgc_lgl.lgl_oid,
               loghandle->lgh_cookie.lgc_lgl.lgl_ogen, index, rec->lrh_len);
        if (rc == 0 && reccookie) {
                reccookie->lgc_lgl = loghandle->lgh_id;
                reccookie->lgc_index = index;
                rc = 1;
        }
        RETURN(rc);
}
EXPORT_SYMBOL(llog_vfs_write_record);

int llog_lvfs_next_block(struct llog_handle *loghandle, int cur_idx,
                         int next_idx, __u64 *cur_offset, void *buf, int len)
{
        int rc;
        ENTRY;

        if (len == 0 || len & (LLOG_CHUNK_SIZE - 1))
                RETURN(-EINVAL);

        CDEBUG(D_OTHER, "looking for log index %u (cur idx %u off "LPU64"\n",
               next_idx, cur_idx, *cur_offset);

        /* We can skip reading at least as many log blocks as the number of
         * minimum sized log records we are skipping.  If it turns out that we
         * are not far enough along the log (because the actual records are
         * larger than minimum size) we just skip some more records. */
        while ((*cur_offset = (*cur_offset +
                               (next_idx - cur_idx) * LLOG_MIN_REC_SIZE) &
                                ~(LLOG_CHUNK_SIZE - 1)) <
               loghandle->lgh_file->f_dentry->d_inode->i_size) {
                struct llog_rec_hdr *rec;

                rc = fsfilt_read_record(loghandle->lgh_obd, loghandle->lgh_file,
                                        buf, LLOG_CHUNK_SIZE, *cur_offset);
                if (rc)
                        RETURN(rc);

                rec = buf;
                /* sanity check that the start of the new buffer is no farther
                 * than the record that we wanted.  This shouldn't happen. */
                if (rec->lrh_index > next_idx) {
                        CERROR("missed desired record? %u > %u\n",
                               rec->lrh_index, next_idx);
                        RETURN(-ENOENT);
                }

                /* Check if last record in this buffer is higher than what we
                 * are looking for, or is zero (implying that this is the last
                 * buffer in the log).  In conjunction with the previous test,
                 * this means that the record we are looking for is in the
                 * current buffer, or the client asked for a record beyond the
                 * end of the log, which is the client's problem. */
                rec = buf + LLOG_CHUNK_SIZE - sizeof(__u32);
                if (rec->lrh_index == 0)
                        RETURN(0);

                cur_idx = rec->lrh_index;
                if (cur_idx >= next_idx) {
                        while (rc == 0 && (len -= LLOG_CHUNK_SIZE) > 0) {
                                buf += LLOG_CHUNK_SIZE;
                                *cur_offset += LLOG_CHUNK_SIZE;

                                rc = fsfilt_read_record(loghandle->lgh_obd,
                                                        loghandle->lgh_file,
                                                        buf, LLOG_CHUNK_SIZE,
                                                        *cur_offset);
                        }

                        RETURN(rc);
                }
        }

        RETURN(-ENOENT);
}
EXPORT_SYMBOL(llog_lvfs_next_block);


/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
int llog_lvfs_create(struct obd_device *obd, 
                                     struct llog_handle **res, char *name)
{
        char logname[24];
        struct llog_handle *loghandle;
        int rc, open_flags = O_RDWR | O_CREAT | O_LARGEFILE;
        ENTRY;

        loghandle = llog_alloc_handle();
        if (!loghandle)
                RETURN(-ENOMEM);
        *res = loghandle;

        if (name) {
                sprintf(logname, "LOGS/%s", name);
                
                loghandle->lgh_file = l_filp_open(logname, open_flags, 0644);
                if (IS_ERR(loghandle->lgh_file)) {
                        rc = PTR_ERR(loghandle->lgh_file);
                        CERROR(D_HA, "logfile creation %s: %d\n", logname, rc);
                        obd->u.mds.mds_catalog->lgh_index++;
                        GOTO(out_handle, rc);
                }
                loghandle->lgh_cookie.lgc_lgl.lgl_oid =
                        loghandle->lgh_file->f_dentry->d_inode->i_ino;
                loghandle->lgh_cookie.lgc_lgl.lgl_ogen =
                        loghandle->lgh_file->f_dentry->d_inode->i_generation;
        } else {
                struct obdo *oa;
                struct l_dentry *de;
                oa = obdo_alloc();
                if (!oa) 
                        GOTO(out, rc = -ENOMEM);
                /* XXX */
                oa->o_gr = 1;
                oa->o_valid = OBD_MD_FLGROUP;
                rc = obd_create(obd->obd_log_exp, oa, NULL, NULL);
                if (rc) 
                        GOTO(out, rc);
                de = lvfs_fid2dentry(loghandle->lgh_obd = obd, oa);
                if (IS_ERR(de))
                        GOTO(out, rc = PTR_ERR(de));
                loghandle->lgh_file = l_dentry_open(de, open_flags);
                if (IS_ERR(loghandle->lgh_file))
                        GOTO(out, rc = PTR_ERR(loghandle->lgh_file));
                loghandle->lgh_cookie.lgc_lgl.lgl_oid = oa->o_id;
                loghandle->lgh_cookie.lgc_lgl.lgl_ogr = oa->o_gr;
                
        }

        RETURN(loghandle);

out_handle:
        obdo_free(oa);
        llog_free_handle(loghandle);
        return rc;
}


int llog_lvfs_close(struct llog_handle *handle)
{
        int rc;
        ENTRY;

        rc = filp_close(handle->lgh_file, 0);
        if (rc)
                CERROR("error closing log: rc %d\n", rc);

        llog_free_handle(handle);
        RETURN(rc);
}

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
int mds_log_close(struct llog_handle *cathandle, struct llog_handle *loghandle)
{
        struct llog_log_hdr *llh = loghandle->lgh_hdr;
        struct mds_obd *mds = &cathandle->lgh_obd->u.mds;
        struct dentry *dchild = NULL;
        int rc;
        ENTRY;

        /* If we are going to delete this log, grab a ref before we close
         * it so we don't have to immediately do another lookup.
         */
        if (llh->llh_hdr.lrh_type != LLOG_CATALOG_MAGIC && llh->llh_count == 0){
                CDEBUG(D_INODE, "deleting log file "LPX64":%x\n",
                       loghandle->lgh_cookie.lgc_lgl.lgl_oid,
                       loghandle->lgh_cookie.lgc_lgl.lgl_ogen);
                down(&mds->mds_logs_dir->d_inode->i_sem);
                dchild = dget(loghandle->lgh_file->f_dentry);
                llog_delete_log(cathandle, loghandle);
        } else {
                CDEBUG(D_INODE, "closing log file "LPX64":%x\n",
                       loghandle->lgh_cookie.lgc_lgl.lgl_oid,
                       loghandle->lgh_cookie.lgc_lgl.lgl_ogen);
        }

        rc = filp_close(loghandle->lgh_file, 0);

        llog_free_handle(loghandle); /* also removes loghandle from list */

        if (dchild) {
                int err = vfs_unlink(mds->mds_logs_dir->d_inode, dchild);
                if (err) {
                        CERROR("error unlinking empty log %*s: rc %d\n",
                               dchild->d_name.len, dchild->d_name.name, err);
                        if (!rc)
                                rc = err;
                }
                l_dput(dchild);
                up(&mds->mds_logs_dir->d_inode->i_sem);
        }
        RETURN(rc);
}

struct llog_handle *mds_log_open(struct obd_device *obd,
                                 struct llog_cookie *logcookie);

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
static struct llog_handle *filter_log_create(struct obd_device *obd)
{
        struct filter_obd *filter = &obd->u.filter;
        struct lustre_handle parent_lockh;
        struct dentry *dparent, *dchild;
        struct llog_handle *loghandle;
        struct file *file;
        struct obdo obdo;
        int err, rc;
        obd_id id;
        ENTRY;

        loghandle = llog_alloc_handle();
        if (!loghandle)
                RETURN(ERR_PTR(-ENOMEM));

        memset(&obdo, 0, sizeof(obdo));
        obdo.o_valid = OBD_MD_FLGROUP;
        obdo.o_gr = 1; /* FIXME: object groups */
 retry:
        id = filter_next_id(filter, &obdo);

        dparent = filter_parent_lock(obd, obdo.o_gr, id, LCK_PW, &parent_lockh);
        if (IS_ERR(dparent))
                GOTO(out_ctxt, rc = PTR_ERR(dparent));

        dchild = filter_fid2dentry(obd, dparent, obdo.o_gr, id);
        if (IS_ERR(dchild))
                GOTO(out_lock, rc = PTR_ERR(dchild));

        if (dchild->d_inode != NULL) {
                /* This would only happen if lastobjid was bad on disk */
                CERROR("Serious error: objid %*s already exists; is this "
                       "filesystem corrupt?  I will try to work around it.\n",
                       dchild->d_name.len, dchild->d_name.name);
                f_dput(dchild);
                ldlm_lock_decref(&parent_lockh, LCK_PW);
                goto retry;
        }

        rc = ll_vfs_create(dparent->d_inode, dchild, S_IFREG, NULL);
        if (rc) {
                CERROR("log create failed rc = %d\n", rc);
                GOTO(out_child, rc);
        }

        rc = filter_update_last_objid(obd, obdo.o_gr, 0);
        if (rc) {
                CERROR("can't write lastobjid but log created: rc %d\n",rc);
                GOTO(out_destroy, rc);
        }

        /* dentry_open does a dput(dchild) and mntput(mnt) on error */
        mntget(filter->fo_vfsmnt);
        file = dentry_open(dchild, filter->fo_vfsmnt, O_RDWR | O_LARGEFILE);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("error opening log file "LPX64": rc %d\n", id, rc);
                GOTO(out_destroy, rc);
        }
        ldlm_lock_decref(&parent_lockh, LCK_PW);

        loghandle->lgh_file = file;
        loghandle->lgh_cookie.lgc_lgl.lgl_oid = id;
        loghandle->lgh_cookie.lgc_lgl.lgl_ogen = dchild->d_inode->i_generation;
        loghandle->lgh_log_create = filter_log_create;
        loghandle->lgh_log_open = filter_log_open;
        loghandle->lgh_log_close = filter_log_close;
        loghandle->lgh_obd = obd;

        RETURN(loghandle);

out_destroy:
        err = vfs_unlink(dparent->d_inode, dchild);
        if (err)
                CERROR("error unlinking %*s on error: rc %d\n",
                       dchild->d_name.len, dchild->d_name.name, err);
out_child:
        f_dput(dchild);
out_lock:
        ldlm_lock_decref(&parent_lockh, LCK_PW);
out_ctxt:
        llog_free_handle(loghandle);
        RETURN(ERR_PTR(rc));
}

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
struct llog_handle *mds_log_open(struct obd_device *obd,
                                 struct llog_cookie *logcookie)
{
        struct ll_fid fid = { .id = logcookie->lgc_lgl.lgl_oid,
                              .generation = logcookie->lgc_lgl.lgl_ogen,
                              .f_type = S_IFREG };
        struct llog_handle *loghandle;
        struct dentry *dchild;
        int rc;
        ENTRY;

        loghandle = llog_alloc_handle();
        if (loghandle == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        down(&obd->u.mds.mds_logs_dir->d_inode->i_sem);
        dchild = mds_fid2dentry(&obd->u.mds, &fid, NULL);
        up(&obd->u.mds.mds_logs_dir->d_inode->i_sem);
        if (IS_ERR(dchild)) {
                rc = PTR_ERR(dchild);
                CERROR("error looking up log file "LPX64":%x: rc %d\n",
                       fid.id, fid.generation, rc);
                GOTO(out, rc);
        }

        if (dchild->d_inode == NULL) {
                rc = -ENOENT;
                CERROR("nonexistent log file "LPX64":%x: rc %d\n",
                       fid.id, fid.generation, rc);
                GOTO(out_put, rc);
        }

        /* dentry_open does a dput(de) and mntput(mds->mds_vfsmnt) on error */
        mntget(obd->u.mds.mds_vfsmnt);
        loghandle->lgh_file = dentry_open(dchild, obd->u.mds.mds_vfsmnt,
                                          O_RDWR | O_LARGEFILE);
        if (IS_ERR(loghandle->lgh_file)) {
                rc = PTR_ERR(loghandle->lgh_file);
                CERROR("error opening logfile "LPX64":%x: rc %d\n",
                       fid.id, fid.generation, rc);
                GOTO(out, rc);
        }
        memcpy(&loghandle->lgh_cookie, logcookie, sizeof(*logcookie));
        loghandle->lgh_log_create = mds_log_create;
        loghandle->lgh_log_open = mds_log_open;
        loghandle->lgh_log_close = mds_log_close;
        loghandle->lgh_obd = obd;

        RETURN(loghandle);

out_put:
        l_dput(dchild);
out:
        llog_free_handle(loghandle);
        return ERR_PTR(rc);
}



struct llog_handle *mds_get_catalog(struct obd_device *obd)
{
        struct mds_server_data *msd = obd->u.mds.mds_server_data;
        struct obd_run_ctxt saved;
        struct llog_handle *cathandle = NULL;
        int rc = 0;
        ENTRY;

        push_ctxt(&saved, &obd->u.mds.mds_ctxt, NULL);

        if (msd->msd_catalog_oid) {
                struct llog_cookie catcookie;

                catcookie.lgc_lgl.lgl_oid = le64_to_cpu(msd->msd_catalog_oid);
                catcookie.lgc_lgl.lgl_ogen = le32_to_cpu(msd->msd_catalog_ogen);
                cathandle = mds_log_open(obd, &catcookie);
                if (IS_ERR(cathandle)) {
                        CERROR("error opening catalog "LPX64":%x: rc %d\n",
                               catcookie.lgc_lgl.lgl_oid,
                               catcookie.lgc_lgl.lgl_ogen,
                               (int)PTR_ERR(cathandle));
                        msd->msd_catalog_oid = 0;
                        msd->msd_catalog_ogen = 0;
                }
                /* ORPHANS FIXME: compare catalog UUID to msd_peeruuid */
        }

        if (!msd->msd_catalog_oid) {
                struct llog_logid *lgl;

                cathandle = mds_log_create(obd, "LOGS/catalog");
                if (IS_ERR(cathandle)) {
                        CERROR("error creating new catalog: rc %d\n",
                               (int)PTR_ERR(cathandle));
                        GOTO(out, cathandle);
                }
                lgl = &cathandle->lgh_cookie.lgc_lgl;
                msd->msd_catalog_oid = cpu_to_le64(lgl->lgl_oid);
                msd->msd_catalog_ogen = cpu_to_le32(lgl->lgl_ogen);
                rc = mds_update_server_data(obd, 1);
                if (rc) {
                        CERROR("error writing new catalog to disk: rc %d\n",rc);
                        GOTO(out_handle, rc);
                }
        }

        rc = llog_init_catalog(cathandle, &obd->u.mds.mds_lov_name);

out:
        pop_ctxt(&saved, &obd->u.mds.mds_ctxt, NULL);
        RETURN(cathandle);

out_handle:
        mds_log_close(cathandle, cathandle);
        cathandle = ERR_PTR(rc);
        goto out;

}

static struct llog_handle *filter_log_create(struct obd_device *obd);

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
static int filter_log_close(struct llog_handle *cathandle,
                            struct llog_handle *loghandle)
{
        struct llog_object_hdr *llh = loghandle->lgh_hdr;
        struct file *file = loghandle->lgh_file;
        struct dentry *dparent = NULL, *dchild = NULL;
        struct lustre_handle parent_lockh;
        struct llog_logid *lgl = &loghandle->lgh_cookie.lgc_lgl;
        int rc;
        ENTRY;

        /* If we are going to delete this log, grab a ref before we close
         * it so we don't have to immediately do another lookup. */
        if (llh->llh_hdr.lth_type != LLOG_CATALOG_MAGIC && llh->llh_count == 0){
                CDEBUG(D_INODE, "deleting log file "LPX64":%x\n",
                       lgl->lgl_oid, lgl->lgl_ogen);
                dparent = filter_parent_lock(loghandle->lgh_obd, S_IFREG,
                                             lgl->lgl_oid,LCK_PW,&parent_lockh);
                if (IS_ERR(dparent)) {
                        rc = PTR_ERR(dparent);
                        CERROR("error locking parent, orphan log %*s: rc %d\n",
                               file->f_dentry->d_name.len,
                               file->f_dentry->d_name.name, rc);
                        RETURN(rc);
                } else {
                        dchild = dget(file->f_dentry);
                        llog_delete_log(cathandle, loghandle);
                }
        } else {
                CDEBUG(D_INODE, "closing log file "LPX64":%x\n",
                       lgl->lgl_oid, lgl->lgl_ogen);
        }

        rc = filp_close(file, 0);

        llog_free_handle(loghandle); /* also removes loghandle from list */

        if (dchild != NULL) {
                int err = vfs_unlink(dparent->d_inode, dchild);
                if (err) {
                        CERROR("error unlinking empty log %*s: rc %d\n",
                               dchild->d_name.len, dchild->d_name.name, err);
                        if (!rc)
                                rc = err;
                }
                f_dput(dchild);
                ldlm_lock_decref(&parent_lockh, LCK_PW);
        }
        RETURN(rc);
}

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
static struct llog_handle *filter_log_open(struct obd_device *obd,
                                           struct llog_cookie *logcookie)
{
        struct llog_logid *lgl = &logcookie->lgc_lgl;
        struct llog_handle *loghandle;
        struct dentry *dchild;
        int rc;
        ENTRY;

        loghandle = llog_alloc_handle();
        if (!loghandle)
                RETURN(ERR_PTR(-ENOMEM));

        dchild = filter_fid2dentry(obd, NULL, S_IFREG, lgl->lgl_oid);
        if (IS_ERR(dchild))
                GOTO(out_handle, rc = PTR_ERR(dchild));

        if (dchild->d_inode == NULL) {
                CERROR("logcookie references non-existent object %*s\n",
                       dchild->d_name.len, dchild->d_name.name);
                GOTO(out_dentry, rc = -ENOENT);
        }

        if (dchild->d_inode->i_generation != lgl->lgl_ogen) {
                CERROR("logcookie for %*s had different generation %x != %x\n",
                       dchild->d_name.len, dchild->d_name.name,
                       dchild->d_inode->i_generation, lgl->lgl_ogen);
                GOTO(out_dentry, rc = -ESTALE);
        }

        /* dentry_open does a dput(dchild) and mntput(mnt) on error */
        mntget(obd->u.filter.fo_vfsmnt);
        loghandle->lgh_file = dentry_open(dchild, obd->u.filter.fo_vfsmnt,
                                          O_RDWR);
        if (IS_ERR(loghandle->lgh_file)) {
                rc = PTR_ERR(loghandle->lgh_file);
                CERROR("error opening logfile %*s: rc %d\n",
                       dchild->d_name.len, dchild->d_name.name, rc);
                GOTO(out_dentry, rc);
        }
        memcpy(&loghandle->lgh_cookie, logcookie, sizeof(*logcookie));
        loghandle->lgh_obd = obd;
        RETURN(loghandle);

out_dentry:
        f_dput(dchild);
out_handle:
        llog_free_handle(loghandle);
        RETURN(ERR_PTR(rc));
}


/* This is called from filter_setup() and should be single threaded */
struct llog_handle *filter_get_catalog(struct obd_device *obd)
{
        struct filter_obd *filter = &obd->u.filter;
        struct filter_server_data *fsd = filter->fo_fsd;
        struct obd_run_ctxt saved;
        struct llog_handle *cathandle = NULL;
        int rc;
        ENTRY;

        push_ctxt(&saved, &filter->fo_ctxt, NULL);
        if (fsd->fsd_catalog_oid) {
                struct llog_cookie catcookie;

                catcookie.lgc_lgl.lgl_oid = le64_to_cpu(fsd->fsd_catalog_oid);
                catcookie.lgc_lgl.lgl_ogen = le32_to_cpu(fsd->fsd_catalog_ogen);
                cathandle = filter_log_open(obd, &catcookie);
                if (IS_ERR(cathandle)) {
                        CERROR("error opening catalog "LPX64":%x: rc %d\n",
                               catcookie.lgc_lgl.lgl_oid,
                               catcookie.lgc_lgl.lgl_ogen,
                               (int)PTR_ERR(cathandle));
                        fsd->fsd_catalog_oid = 0;
                        fsd->fsd_catalog_ogen = 0;
                }
        }

        if (!fsd->fsd_catalog_oid) {
                struct llog_logid *lgl;

                cathandle = filter_log_create(obd);
                if (IS_ERR(cathandle)) {
                        CERROR("error creating new catalog: rc %d\n",
                               (int)PTR_ERR(cathandle));
                        GOTO(out, cathandle);
                }
                lgl = &cathandle->lgh_cookie.lgc_lgl;
                fsd->fsd_catalog_oid = cpu_to_le64(lgl->lgl_oid);
                fsd->fsd_catalog_ogen = cpu_to_le32(lgl->lgl_ogen);
                rc = filter_update_server_data(obd, filter->fo_rcvd_filp,fsd,0);
                if (rc) {
                        CERROR("error writing new catalog to disk: rc %d\n",rc);
                        GOTO(out_handle, rc);
                }
        }

        rc = llog_cat_init(cathandle, &obd->u.filter.fo_mdc_uuid);
        if (rc)
                GOTO(out_handle, rc);
out:
        pop_ctxt(&saved, &filter->fo_ctxt, NULL);
        RETURN(cathandle);

out_handle:
        filter_log_close(cathandle, cathandle);
        cathandle = ERR_PTR(rc);
        goto out;
}

void filter_put_catalog(struct llog_handle *cathandle)
{
        struct llog_handle *loghandle, *n;
        int rc;
        ENTRY;

        list_for_each_entry_safe(loghandle, n, &cathandle->lgh_list, lgh_list)
                filter_log_close(cathandle, loghandle);

        rc = filp_close(cathandle->lgh_file, 0);
        if (rc)
                CERROR("error closing catalog: rc %d\n", rc);

        llog_free_handle(cathandle);
        EXIT;
}

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

struct llog_operations llog_lvfs_ops = {
        lop_write_rec: llog_lvfs_write_rec;
        lop_next_block: llog_lvfs_next_block;
        lop_open: llog_lvfs_open;
        lop_cancel: llog_lvfs_cancel;
        lop_create:llog_lvfs_create;
        lop_close:llog_lvfs_close;
}
EXPORT_SYMBOL(llog_lvfs_ops);
