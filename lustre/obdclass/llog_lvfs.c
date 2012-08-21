/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/llog_lvfs.c
 *
 * OST<->MDS recovery logging infrastructure.
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LOG

#ifndef __KERNEL__
#include <liblustre.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <lustre_log.h>
#include <obd_ost.h>
#include <libcfs/list.h>
#include <lvfs.h>
#include <lustre_fsfilt.h>
#include <lustre_disk.h>
#include "llog_internal.h"

#if defined(__KERNEL__) && defined(LLOG_LVFS)

static int llog_lvfs_pad(struct obd_device *obd, struct l_file *file,
                                int len, int index)
{
        struct llog_rec_hdr rec = { 0 };
        struct llog_rec_tail tail;
        int rc;
        ENTRY;

        LASSERT(len >= LLOG_MIN_REC_SIZE && (len & 0x7) == 0);

        tail.lrt_len = rec.lrh_len = len;
        tail.lrt_index = rec.lrh_index = index;
        rec.lrh_type = LLOG_PAD_MAGIC;

        rc = fsfilt_write_record(obd, file, &rec, sizeof(rec), &file->f_pos, 0);
        if (rc) {
                CERROR("error writing padding record: rc %d\n", rc);
                goto out;
        }

        file->f_pos += len - sizeof(rec) - sizeof(tail);
        rc = fsfilt_write_record(obd, file, &tail, sizeof(tail),&file->f_pos,0);
        if (rc) {
                CERROR("error writing padding record: rc %d\n", rc);
                goto out;
        }

 out:
        RETURN(rc);
}

static int llog_lvfs_write_blob(struct obd_device *obd, struct l_file *file,
                                struct llog_rec_hdr *rec, void *buf, loff_t off)
{
        int rc;
        struct llog_rec_tail end;
        loff_t saved_off = file->f_pos;
        int buflen = rec->lrh_len;

        ENTRY;

        file->f_pos = off;

        if (buflen == 0)
                CWARN("0-length record\n");

        if (!buf) {
                rc = fsfilt_write_record(obd, file, rec, buflen,&file->f_pos,0);
                if (rc) {
                        CERROR("error writing log record: rc %d\n", rc);
                        goto out;
                }
                GOTO(out, rc = 0);
        }

        /* the buf case */
        rec->lrh_len = sizeof(*rec) + buflen + sizeof(end);
        rc = fsfilt_write_record(obd, file, rec, sizeof(*rec), &file->f_pos, 0);
        if (rc) {
                CERROR("error writing log hdr: rc %d\n", rc);
                goto out;
        }

        rc = fsfilt_write_record(obd, file, buf, buflen, &file->f_pos, 0);
        if (rc) {
                CERROR("error writing log buffer: rc %d\n", rc);
                goto out;
        }

        end.lrt_len = rec->lrh_len;
        end.lrt_index = rec->lrh_index;
        rc = fsfilt_write_record(obd, file, &end, sizeof(end), &file->f_pos, 0);
        if (rc) {
                CERROR("error writing log tail: rc %d\n", rc);
                goto out;
        }

        rc = 0;
 out:
        if (saved_off > file->f_pos)
                file->f_pos = saved_off;
        LASSERT(rc <= 0);
        RETURN(rc);
}

static int llog_lvfs_read_blob(struct obd_device *obd, struct l_file *file,
                                void *buf, int size, loff_t off)
{
        loff_t offset = off;
        int rc;
        ENTRY;

        rc = fsfilt_read_record(obd, file, buf, size, &offset);
        if (rc) {
                CERROR("error reading log record: rc %d\n", rc);
                RETURN(rc);
        }
        RETURN(0);
}

static int llog_lvfs_read_header(const struct lu_env *env,
				 struct llog_handle *handle)
{
        struct obd_device *obd;
        int rc;
        ENTRY;

        LASSERT(sizeof(*handle->lgh_hdr) == LLOG_CHUNK_SIZE);

        obd = handle->lgh_ctxt->loc_exp->exp_obd;

        if (i_size_read(handle->lgh_file->f_dentry->d_inode) == 0) {
                CDEBUG(D_HA, "not reading header from 0-byte log\n");
                RETURN(LLOG_EEMPTY);
        }

        rc = llog_lvfs_read_blob(obd, handle->lgh_file, handle->lgh_hdr,
                                 LLOG_CHUNK_SIZE, 0);
        if (rc) {
                CERROR("error reading log header from %.*s\n",
                       handle->lgh_file->f_dentry->d_name.len,
                       handle->lgh_file->f_dentry->d_name.name);
        } else {
                struct llog_rec_hdr *llh_hdr = &handle->lgh_hdr->llh_hdr;

                if (LLOG_REC_HDR_NEEDS_SWABBING(llh_hdr))
                        lustre_swab_llog_hdr(handle->lgh_hdr);

                if (llh_hdr->lrh_type != LLOG_HDR_MAGIC) {
                        CERROR("bad log %.*s header magic: %#x (expected %#x)\n",
                               handle->lgh_file->f_dentry->d_name.len,
                               handle->lgh_file->f_dentry->d_name.name,
                               llh_hdr->lrh_type, LLOG_HDR_MAGIC);
                        rc = -EIO;
                } else if (llh_hdr->lrh_len != LLOG_CHUNK_SIZE) {
                        CERROR("incorrectly sized log %.*s header: %#x "
                               "(expected %#x)\n",
                               handle->lgh_file->f_dentry->d_name.len,
                               handle->lgh_file->f_dentry->d_name.name,
                               llh_hdr->lrh_len, LLOG_CHUNK_SIZE);
                        CERROR("you may need to re-run lconf --write_conf.\n");
                        rc = -EIO;
                }
        }

        handle->lgh_last_idx = handle->lgh_hdr->llh_tail.lrt_index;
        handle->lgh_file->f_pos = i_size_read(handle->lgh_file->f_dentry->d_inode);

        RETURN(rc);
}

/* returns negative in on error; 0 if success && reccookie == 0; 1 otherwise */
/* appends if idx == -1, otherwise overwrites record idx. */
static int llog_lvfs_write_rec(const struct lu_env *env,
			       struct llog_handle *loghandle,
			       struct llog_rec_hdr *rec,
			       struct llog_cookie *reccookie, int cookiecount,
			       void *buf, int idx)
{
        struct llog_log_hdr *llh;
        int reclen = rec->lrh_len, index, rc;
        struct llog_rec_tail *lrt;
        struct obd_device *obd;
        struct file *file;
        size_t left;
        ENTRY;

        llh = loghandle->lgh_hdr;
        file = loghandle->lgh_file;
        obd = loghandle->lgh_ctxt->loc_exp->exp_obd;

        /* record length should not bigger than LLOG_CHUNK_SIZE */
        if (buf)
                rc = (reclen > LLOG_CHUNK_SIZE - sizeof(struct llog_rec_hdr) -
                      sizeof(struct llog_rec_tail)) ? -E2BIG : 0;
        else
                rc = (reclen > LLOG_CHUNK_SIZE) ? -E2BIG : 0;
        if (rc)
                RETURN(rc);

        if (buf)
                /* write_blob adds header and tail to lrh_len. */
                reclen = sizeof(*rec) + rec->lrh_len +
                         sizeof(struct llog_rec_tail);

        if (idx != -1) {
                loff_t saved_offset;

                /* no header: only allowed to insert record 1 */
                if (idx != 1 && !i_size_read(file->f_dentry->d_inode)) {
                        CERROR("idx != -1 in empty log\n");
                        LBUG();
                }

                if (idx && llh->llh_size && llh->llh_size != rec->lrh_len)
                        RETURN(-EINVAL);

                if (!ext2_test_bit(idx, llh->llh_bitmap))
                        CERROR("Modify unset record %u\n", idx);
                if (idx != rec->lrh_index)
                        CERROR("Index mismatch %d %u\n", idx, rec->lrh_index);

                rc = llog_lvfs_write_blob(obd, file, &llh->llh_hdr, NULL, 0);
                /* we are done if we only write the header or on error */
                if (rc || idx == 0)
                        RETURN(rc);

                /* Assumes constant lrh_len */
                saved_offset = sizeof(*llh) + (idx - 1) * reclen;

                if (buf) {
                        struct llog_rec_hdr check;

                        /* We assume that caller has set lgh_cur_* */
                        saved_offset = loghandle->lgh_cur_offset;
                        CDEBUG(D_OTHER,
                               "modify record "LPX64": idx:%d/%u/%d, len:%u "
                               "offset %llu\n",
                               loghandle->lgh_id.lgl_oid, idx, rec->lrh_index,
                               loghandle->lgh_cur_idx, rec->lrh_len,
                               (long long)(saved_offset - sizeof(*llh)));
                        if (rec->lrh_index != loghandle->lgh_cur_idx) {
                                CERROR("modify idx mismatch %u/%d\n",
                                       idx, loghandle->lgh_cur_idx);
                                RETURN(-EFAULT);
                        }
#if 1  /* FIXME remove this safety check at some point */
                        /* Verify that the record we're modifying is the
                           right one. */
                        rc = llog_lvfs_read_blob(obd, file, &check,
                                                 sizeof(check), saved_offset);
                        if (check.lrh_index != idx || check.lrh_len != reclen) {
                                CERROR("Bad modify idx %u/%u size %u/%u (%d)\n",
                                       idx, check.lrh_index, reclen,
                                       check.lrh_len, rc);
                                RETURN(-EFAULT);
                        }
#endif
                }

                rc = llog_lvfs_write_blob(obd, file, rec, buf, saved_offset);
                if (rc == 0 && reccookie) {
                        reccookie->lgc_lgl = loghandle->lgh_id;
                        reccookie->lgc_index = idx;
                        rc = 1;
                }
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

        /* NOTE: padding is a record, but no bit is set */
        if (left != 0 && left != reclen &&
            left < (reclen + LLOG_MIN_REC_SIZE)) {
                 index = loghandle->lgh_last_idx + 1;
                 rc = llog_lvfs_pad(obd, file, left, index);
                 if (rc)
                         RETURN(rc);
                 loghandle->lgh_last_idx++; /*for pad rec*/
         }
         /* if it's the last idx in log file, then return -ENOSPC */
         if (loghandle->lgh_last_idx >= LLOG_BITMAP_SIZE(llh) - 1)
                 RETURN(-ENOSPC);
        loghandle->lgh_last_idx++;
        index = loghandle->lgh_last_idx;
        LASSERT(index < LLOG_BITMAP_SIZE(llh));
        rec->lrh_index = index;
        if (buf == NULL) {
                lrt = (struct llog_rec_tail *)
                        ((char *)rec + rec->lrh_len - sizeof(*lrt));
                lrt->lrt_len = rec->lrh_len;
                lrt->lrt_index = rec->lrh_index;
        }
        /*The caller should make sure only 1 process access the lgh_last_idx,
         *Otherwise it might hit the assert.*/
        LASSERT(index < LLOG_BITMAP_SIZE(llh));
        if (ext2_set_bit(index, llh->llh_bitmap)) {
                CERROR("argh, index %u already set in log bitmap?\n", index);
                LBUG(); /* should never happen */
        }
        llh->llh_count++;
        llh->llh_tail.lrt_index = index;

        rc = llog_lvfs_write_blob(obd, file, &llh->llh_hdr, NULL, 0);
        if (rc)
                RETURN(rc);

        rc = llog_lvfs_write_blob(obd, file, rec, buf, file->f_pos);
        if (rc)
                RETURN(rc);

        CDEBUG(D_RPCTRACE, "added record "LPX64": idx: %u, %u \n",
               loghandle->lgh_id.lgl_oid, index, rec->lrh_len);
        if (rc == 0 && reccookie) {
                reccookie->lgc_lgl = loghandle->lgh_id;
                reccookie->lgc_index = index;
                if ((rec->lrh_type == MDS_UNLINK_REC) ||
                    (rec->lrh_type == MDS_SETATTR64_REC))
                        reccookie->lgc_subsys = LLOG_MDS_OST_ORIG_CTXT;
                else if (rec->lrh_type == OST_SZ_REC)
                        reccookie->lgc_subsys = LLOG_SIZE_ORIG_CTXT;
                else
                        reccookie->lgc_subsys = -1;
                rc = 1;
        }
        if (rc == 0 && rec->lrh_type == LLOG_GEN_REC)
                rc = 1;

        RETURN(rc);
}

/* We can skip reading at least as many log blocks as the number of
* minimum sized log records we are skipping.  If it turns out
* that we are not far enough along the log (because the
* actual records are larger than minimum size) we just skip
* some more records. */

static void llog_skip_over(__u64 *off, int curr, int goal)
{
        if (goal <= curr)
                return;
        *off = (*off + (goal-curr-1) * LLOG_MIN_REC_SIZE) &
                ~(LLOG_CHUNK_SIZE - 1);
}


/* sets:
 *  - cur_offset to the furthest point read in the log file
 *  - cur_idx to the log index preceeding cur_offset
 * returns -EIO/-EINVAL on error
 */
static int llog_lvfs_next_block(const struct lu_env *env,
				struct llog_handle *loghandle, int *cur_idx,
				int next_idx, __u64 *cur_offset, void *buf,
				int len)
{
        int rc;
        ENTRY;

        if (len == 0 || len & (LLOG_CHUNK_SIZE - 1))
                RETURN(-EINVAL);

        CDEBUG(D_OTHER, "looking for log index %u (cur idx %u off "LPU64")\n",
               next_idx, *cur_idx, *cur_offset);

        while (*cur_offset < i_size_read(loghandle->lgh_file->f_dentry->d_inode)) {
                struct llog_rec_hdr *rec;
                struct llog_rec_tail *tail;
                loff_t ppos;

                llog_skip_over(cur_offset, *cur_idx, next_idx);

                ppos = *cur_offset;
                rc = fsfilt_read_record(loghandle->lgh_ctxt->loc_exp->exp_obd,
                                        loghandle->lgh_file, buf, len,
                                        &ppos);
                if (rc) {
                        CERROR("Cant read llog block at log id "LPU64
                               "/%u offset "LPU64"\n",
                               loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen,
                               *cur_offset);
                        RETURN(rc);
                }

                /* put number of bytes read into rc to make code simpler */
                rc = ppos - *cur_offset;
                *cur_offset = ppos;

                if (rc < len) {
                        /* signal the end of the valid buffer to llog_process */
                        memset(buf + rc, 0, len - rc);
                }

                if (rc == 0) /* end of file, nothing to do */
                        RETURN(0);

                if (rc < sizeof(*tail)) {
                        CERROR("Invalid llog block at log id "LPU64"/%u offset "
                               LPU64"\n", loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen, *cur_offset);
                        RETURN(-EINVAL);
                }

                rec = buf;
                tail = (struct llog_rec_tail *)((char *)buf + rc -
                                                sizeof(struct llog_rec_tail));

		if (LLOG_REC_HDR_NEEDS_SWABBING(rec))
			lustre_swab_llog_rec(rec);

                *cur_idx = tail->lrt_index;

                /* this shouldn't happen */
                if (tail->lrt_index == 0) {
                        CERROR("Invalid llog tail at log id "LPU64"/%u offset "
                               LPU64"\n", loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen, *cur_offset);
                        RETURN(-EINVAL);
                }
                if (tail->lrt_index < next_idx)
                        continue;

                /* sanity check that the start of the new buffer is no farther
                 * than the record that we wanted.  This shouldn't happen. */
                if (rec->lrh_index > next_idx) {
                        CERROR("missed desired record? %u > %u\n",
                               rec->lrh_index, next_idx);
                        RETURN(-ENOENT);
                }
                RETURN(0);
        }
        RETURN(-EIO);
}

static int llog_lvfs_prev_block(const struct lu_env *env,
				struct llog_handle *loghandle,
				int prev_idx, void *buf, int len)
{
        __u64 cur_offset;
        int rc;
        ENTRY;

        if (len == 0 || len & (LLOG_CHUNK_SIZE - 1))
                RETURN(-EINVAL);

        CDEBUG(D_OTHER, "looking for log index %u\n", prev_idx);

        cur_offset = LLOG_CHUNK_SIZE;
        llog_skip_over(&cur_offset, 0, prev_idx);

        while (cur_offset < i_size_read(loghandle->lgh_file->f_dentry->d_inode)) {
                struct llog_rec_hdr *rec;
                struct llog_rec_tail *tail;
                loff_t ppos;

                ppos = cur_offset;

                rc = fsfilt_read_record(loghandle->lgh_ctxt->loc_exp->exp_obd,
                                        loghandle->lgh_file, buf, len,
                                        &ppos);
                if (rc) {
                        CERROR("Cant read llog block at log id "LPU64
                               "/%u offset "LPU64"\n",
                               loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen,
                               cur_offset);
                        RETURN(rc);
                }

                /* put number of bytes read into rc to make code simpler */
                rc = ppos - cur_offset;
                cur_offset = ppos;

                if (rc == 0) /* end of file, nothing to do */
                        RETURN(0);

                if (rc < sizeof(*tail)) {
                        CERROR("Invalid llog block at log id "LPU64"/%u offset "
                               LPU64"\n", loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen, cur_offset);
                        RETURN(-EINVAL);
                }

                tail = buf + rc - sizeof(struct llog_rec_tail);

                /* this shouldn't happen */
                if (tail->lrt_index == 0) {
                        CERROR("Invalid llog tail at log id "LPU64"/%u offset "
                               LPU64"\n", loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen, cur_offset);
                        RETURN(-EINVAL);
                }
                if (le32_to_cpu(tail->lrt_index) < prev_idx)
                        continue;

                /* sanity check that the start of the new buffer is no farther
                 * than the record that we wanted.  This shouldn't happen. */
                rec = buf;
                if (le32_to_cpu(rec->lrh_index) > prev_idx) {
                        CERROR("missed desired record? %u > %u\n",
                               le32_to_cpu(rec->lrh_index), prev_idx);
                        RETURN(-ENOENT);
                }
                RETURN(0);
        }
        RETURN(-EIO);
}

static struct file *llog_filp_open(char *dir, char *name, int flags, int mode)
{
        char *logname;
        struct file *filp;
        int len;

        OBD_ALLOC(logname, PATH_MAX);
        if (logname == NULL)
                return ERR_PTR(-ENOMEM);

        len = snprintf(logname, PATH_MAX, "%s/%s", dir, name);
        if (len >= PATH_MAX - 1) {
                filp = ERR_PTR(-ENAMETOOLONG);
        } else {
                filp = l_filp_open(logname, flags, mode);
		if (IS_ERR(filp) && PTR_ERR(filp) != -ENOENT)
                        CERROR("logfile creation %s: %ld\n", logname,
                               PTR_ERR(filp));
        }
        OBD_FREE(logname, PATH_MAX);
        return filp;
}

static int llog_lvfs_open(const struct lu_env *env,  struct llog_handle *handle,
			  struct llog_logid *logid, char *name,
			  enum llog_open_param open_param)
{
	struct llog_ctxt	*ctxt = handle->lgh_ctxt;
	struct l_dentry		*dchild = NULL;
	struct obd_device	*obd;
	int			 rc = 0;

	ENTRY;

	LASSERT(ctxt);
	LASSERT(ctxt->loc_exp);
	LASSERT(ctxt->loc_exp->exp_obd);
	obd = ctxt->loc_exp->exp_obd;

	LASSERT(handle);
	if (logid != NULL) {
		dchild = obd_lvfs_fid2dentry(ctxt->loc_exp, logid->lgl_oid,
					     logid->lgl_ogen, logid->lgl_oseq);
		if (IS_ERR(dchild)) {
			rc = PTR_ERR(dchild);
			CERROR("%s: error looking up logfile #"LPX64"#"
			       LPX64"#%08x: rc = %d\n",
			       ctxt->loc_obd->obd_name, logid->lgl_oid,
			       logid->lgl_oseq, logid->lgl_ogen, rc);
			GOTO(out, rc);
		}
		if (dchild->d_inode == NULL) {
			l_dput(dchild);
			rc = -ENOENT;
			CERROR("%s: nonexistent llog #"LPX64"#"LPX64"#%08x: "
			       "rc = %d\n", ctxt->loc_obd->obd_name,
			       logid->lgl_oid, logid->lgl_oseq,
			       logid->lgl_ogen, rc);
			GOTO(out, rc);
		}
		/* l_dentry_open will call dput(dchild) if there is an error */
		handle->lgh_file = l_dentry_open(&obd->obd_lvfs_ctxt, dchild,
						 O_RDWR | O_LARGEFILE);
		if (IS_ERR(handle->lgh_file)) {
			rc = PTR_ERR(handle->lgh_file);
			handle->lgh_file = NULL;
			CERROR("%s: error opening llog #"LPX64"#"LPX64"#%08x: "
			       "rc = %d\n", ctxt->loc_obd->obd_name,
			       logid->lgl_oid, logid->lgl_oseq,
			       logid->lgl_ogen, rc);
			GOTO(out, rc);
		}

		handle->lgh_id = *logid;
	} else if (name) {
		handle->lgh_file = llog_filp_open(MOUNT_CONFIGS_DIR, name,
						  O_RDWR | O_LARGEFILE, 0644);
		if (IS_ERR(handle->lgh_file)) {
			rc = PTR_ERR(handle->lgh_file);
			handle->lgh_file = NULL;
			if (rc == -ENOENT && open_param == LLOG_OPEN_NEW) {
				OBD_ALLOC(handle->lgh_name, strlen(name) + 1);
				if (handle->lgh_name)
					strcpy(handle->lgh_name, name);
				else
					GOTO(out, rc = -ENOMEM);
				rc = 0;
			} else {
				GOTO(out, rc);
			}
		} else {
			handle->lgh_id.lgl_oseq = FID_SEQ_LLOG;
			handle->lgh_id.lgl_oid =
				handle->lgh_file->f_dentry->d_inode->i_ino;
			handle->lgh_id.lgl_ogen =
				handle->lgh_file->f_dentry->d_inode->i_generation;
		}
	} else {
		LASSERTF(open_param == LLOG_OPEN_NEW, "%#x\n", open_param);
		handle->lgh_file = NULL;
	}

	/* No new llog is expected but doesn't exist */
	if (open_param != LLOG_OPEN_NEW && handle->lgh_file == NULL)
		GOTO(out_name, rc = -ENOENT);

	RETURN(0);
out_name:
	if (handle->lgh_name != NULL)
		OBD_FREE(handle->lgh_name, strlen(name) + 1);
out:
	RETURN(rc);
}

static int llog_lvfs_exist(struct llog_handle *handle)
{
	return (handle->lgh_file != NULL);
}

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
static int llog_lvfs_create(const struct lu_env *env,
			    struct llog_handle *handle,
			    struct thandle *th)
{
	struct llog_ctxt	*ctxt = handle->lgh_ctxt;
	struct obd_device	*obd;
	struct l_dentry		*dchild = NULL;
	struct obdo		*oa = NULL;
	int			 rc = 0;
	int			 open_flags = O_RDWR | O_CREAT | O_LARGEFILE;

	ENTRY;

	LASSERT(ctxt);
	LASSERT(ctxt->loc_exp);
	obd = ctxt->loc_exp->exp_obd;
	LASSERT(handle->lgh_file == NULL);

	if (handle->lgh_name) {
		handle->lgh_file = llog_filp_open(MOUNT_CONFIGS_DIR,
						  handle->lgh_name,
						  open_flags, 0644);
		if (IS_ERR(handle->lgh_file))
			RETURN(PTR_ERR(handle->lgh_file));

		handle->lgh_id.lgl_oseq = FID_SEQ_LLOG;
		handle->lgh_id.lgl_oid =
			handle->lgh_file->f_dentry->d_inode->i_ino;
		handle->lgh_id.lgl_ogen =
			handle->lgh_file->f_dentry->d_inode->i_generation;
	} else {
		OBDO_ALLOC(oa);
		if (oa == NULL)
			RETURN(-ENOMEM);

		oa->o_seq = FID_SEQ_LLOG;
		oa->o_valid = OBD_MD_FLGENER | OBD_MD_FLGROUP;

		rc = obd_create(NULL, ctxt->loc_exp, oa, NULL, NULL);
		if (rc)
			GOTO(out, rc);

		/* FIXME: rationalize the misuse of o_generation in
		 *        this API along with mds_obd_{create,destroy}.
		 *        Hopefully it is only an internal API issue. */
#define o_generation o_parent_oid
		dchild = obd_lvfs_fid2dentry(ctxt->loc_exp, oa->o_id,
					     oa->o_generation, oa->o_seq);
		if (IS_ERR(dchild))
			GOTO(out, rc = PTR_ERR(dchild));

		handle->lgh_file = l_dentry_open(&obd->obd_lvfs_ctxt, dchild,
						 open_flags);
		if (IS_ERR(handle->lgh_file))
			GOTO(out, rc = PTR_ERR(handle->lgh_file));

		handle->lgh_id.lgl_oseq = oa->o_seq;
		handle->lgh_id.lgl_oid = oa->o_id;
		handle->lgh_id.lgl_ogen = oa->o_generation;
out:
		OBDO_FREE(oa);
	}
	RETURN(rc);
}

static int llog_lvfs_close(const struct lu_env *env,
			   struct llog_handle *handle)
{
	int rc;

	ENTRY;

	if (handle->lgh_file == NULL)
		RETURN(0);
	rc = filp_close(handle->lgh_file, 0);
	if (rc)
		CERROR("%s: error closing llog #"LPX64"#"LPX64"#%08x: "
		       "rc = %d\n", handle->lgh_ctxt->loc_obd->obd_name,
		       handle->lgh_id.lgl_oid, handle->lgh_id.lgl_oseq,
		       handle->lgh_id.lgl_ogen, rc);
	handle->lgh_file = NULL;
	if (handle->lgh_name)
		OBD_FREE(handle->lgh_name, strlen(handle->lgh_name) + 1);
	RETURN(rc);
}

static int llog_lvfs_destroy(const struct lu_env *env,
			     struct llog_handle *handle)
{
        struct dentry *fdentry;
        struct obdo *oa;
        struct obd_device *obd = handle->lgh_ctxt->loc_exp->exp_obd;
        char *dir;
        void *th;
        struct inode *inode;
        int rc, rc1;
        ENTRY;

        dir = MOUNT_CONFIGS_DIR;

	LASSERT(handle->lgh_file);
        fdentry = handle->lgh_file->f_dentry;
        inode = fdentry->d_parent->d_inode;
        if (strcmp(fdentry->d_parent->d_name.name, dir) == 0) {
                struct lvfs_run_ctxt saved;
                struct vfsmount *mnt = mntget(handle->lgh_file->f_vfsmnt);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                dget(fdentry);
		rc = llog_lvfs_close(env, handle);
		if (rc == 0) {
			mutex_lock_nested(&inode->i_mutex, I_MUTEX_PARENT);
			rc = ll_vfs_unlink(inode, fdentry, mnt);
			mutex_unlock(&inode->i_mutex);
		}
		mntput(mnt);

                dput(fdentry);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                RETURN(rc);
        }

        OBDO_ALLOC(oa);
        if (oa == NULL)
                RETURN(-ENOMEM);

        oa->o_id = handle->lgh_id.lgl_oid;
        oa->o_seq = handle->lgh_id.lgl_oseq;
        oa->o_generation = handle->lgh_id.lgl_ogen;
#undef o_generation
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP | OBD_MD_FLGENER;

	rc = llog_lvfs_close(env, handle);
        if (rc)
                GOTO(out, rc);

        th = fsfilt_start_log(obd, inode, FSFILT_OP_UNLINK, NULL, 1);
        if (IS_ERR(th)) {
                CERROR("fsfilt_start failed: %ld\n", PTR_ERR(th));
                GOTO(out, rc = PTR_ERR(th));
        }

        rc = obd_destroy(NULL, handle->lgh_ctxt->loc_exp, oa,
                         NULL, NULL, NULL, NULL);

        rc1 = fsfilt_commit(obd, inode, th, 0);
        if (rc == 0 && rc1 != 0)
                rc = rc1;
 out:
        OBDO_FREE(oa);
        RETURN(rc);
}

/* reads the catalog list */
int llog_get_cat_list(struct obd_device *disk_obd,
                      char *name, int idx, int count, struct llog_catid *idarray)
{
        struct lvfs_run_ctxt saved;
        struct l_file *file;
        int rc, rc1 = 0;
        int size = sizeof(*idarray) * count;
        loff_t off = idx *  sizeof(*idarray);
        ENTRY;

        if (!count)
                RETURN(0);

        push_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);
        file = filp_open(name, O_RDWR | O_CREAT | O_LARGEFILE, 0700);
        if (!file || IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("OBD filter: cannot open/create %s: rc = %d\n",
                       name, rc);
                GOTO(out, rc);
        }

        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", name,
                       file->f_dentry->d_inode->i_mode);
                GOTO(out, rc = -ENOENT);
        }

        CDEBUG(D_CONFIG, "cat list: disk size=%d, read=%d\n",
               (int)i_size_read(file->f_dentry->d_inode), size);

        /* read for new ost index or for empty file */
        memset(idarray, 0, size);
        if (i_size_read(file->f_dentry->d_inode) < off)
                GOTO(out, rc = 0);

        rc = fsfilt_read_record(disk_obd, file, idarray, size, &off);
        if (rc) {
                CERROR("OBD filter: error reading %s: rc %d\n", name, rc);
                GOTO(out, rc);
        }

        EXIT;
 out:
        pop_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);
        if (file && !IS_ERR(file))
                rc1 = filp_close(file, 0);
        if (rc == 0)
                rc = rc1;
        return rc;
}
EXPORT_SYMBOL(llog_get_cat_list);

/* writes the cat list */
int llog_put_cat_list(struct obd_device *disk_obd,
                      char *name, int idx, int count, struct llog_catid *idarray)
{
        struct lvfs_run_ctxt saved;
        struct l_file *file;
        int rc, rc1 = 0;
        int size = sizeof(*idarray) * count;
        loff_t off = idx * sizeof(*idarray);

        if (!count)
                GOTO(out1, rc = 0);

        push_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);
        file = filp_open(name, O_RDWR | O_CREAT | O_LARGEFILE, 0700);
        if (!file || IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("OBD filter: cannot open/create %s: rc = %d\n",
                       name, rc);
                GOTO(out, rc);
        }

        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", name,
                       file->f_dentry->d_inode->i_mode);
                GOTO(out, rc = -ENOENT);
        }

        rc = fsfilt_write_record(disk_obd, file, idarray, size, &off, 1);
        if (rc) {
                CDEBUG(D_INODE,"OBD filter: error writeing %s: rc %d\n",
                       name, rc);
                GOTO(out, rc);
        }

out:
        pop_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);
        if (file && !IS_ERR(file))
                rc1 = filp_close(file, 0);

        if (rc == 0)
                rc = rc1;
out1:
        RETURN(rc);
}
EXPORT_SYMBOL(llog_put_cat_list);

struct llog_operations llog_lvfs_ops = {
	.lop_write_rec		= llog_lvfs_write_rec,
	.lop_next_block		= llog_lvfs_next_block,
	.lop_prev_block		= llog_lvfs_prev_block,
	.lop_read_header	= llog_lvfs_read_header,
	.lop_create		= llog_lvfs_create,
	.lop_destroy		= llog_lvfs_destroy,
	.lop_close		= llog_lvfs_close,
	.lop_open		= llog_lvfs_open,
	.lop_exist		= llog_lvfs_exist,
};
EXPORT_SYMBOL(llog_lvfs_ops);
#else /* !__KERNEL__ */
int llog_get_cat_list(struct obd_device *disk_obd,
		      char *name, int idx, int count,
		      struct llog_catid *idarray)
{
	LBUG();
	return 0;
}

int llog_put_cat_list(struct obd_device *disk_obd,
		      char *name, int idx, int count,
		      struct llog_catid *idarray)
{
	LBUG();
	return 0;
}

struct llog_operations llog_lvfs_ops = {};
#endif
