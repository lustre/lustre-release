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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/llog.c
 *
 * OST<->MDS recovery logging infrastructure.
 * Invariants in implementation:
 * - we do not share logs among different OST<->MDS connections, so that
 *   if an OST or MDS fails it need only look at log(s) relevant to itself
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mikhail Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_LOG

#include <linux/pid_namespace.h>
#include <linux/kthread.h>
#include <llog_swab.h>
#include <lustre_log.h>
#include <obd_class.h>
#include "llog_internal.h"
/*
 * Allocate a new log or catalog handle
 * Used inside llog_open().
 */
static struct llog_handle *llog_alloc_handle(void)
{
	struct llog_handle *loghandle;

	OBD_ALLOC_PTR(loghandle);
	if (loghandle == NULL)
		return NULL;

	init_rwsem(&loghandle->lgh_lock);
	mutex_init(&loghandle->lgh_hdr_mutex);
	INIT_LIST_HEAD(&loghandle->u.phd.phd_entry);
	atomic_set(&loghandle->lgh_refcount, 1);

	return loghandle;
}

/*
 * Free llog handle and header data if exists. Used in llog_close() only
 */
static void llog_free_handle(struct llog_handle *loghandle)
{
	LASSERT(loghandle != NULL);

	/* failed llog_init_handle */
	if (loghandle->lgh_hdr == NULL)
		goto out;

	if (loghandle->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN)
		LASSERT(list_empty(&loghandle->u.phd.phd_entry));
	else if (loghandle->lgh_hdr->llh_flags & LLOG_F_IS_CAT)
		LASSERT(list_empty(&loghandle->u.chd.chd_head));
	OBD_FREE_LARGE(loghandle->lgh_hdr, loghandle->lgh_hdr_size);
out:
	OBD_FREE_PTR(loghandle);
}

void llog_handle_get(struct llog_handle *loghandle)
{
	atomic_inc(&loghandle->lgh_refcount);
}

void llog_handle_put(struct llog_handle *loghandle)
{
	LASSERT(atomic_read(&loghandle->lgh_refcount) > 0);
	if (atomic_dec_and_test(&loghandle->lgh_refcount))
		llog_free_handle(loghandle);
}

static int llog_declare_destroy(const struct lu_env *env,
				struct llog_handle *handle,
				struct thandle *th)
{
	struct llog_operations *lop;
	int rc;

	ENTRY;

	rc = llog_handle2ops(handle, &lop);
	if (rc)
		RETURN(rc);
	if (lop->lop_declare_destroy == NULL)
		RETURN(-EOPNOTSUPP);

	rc = lop->lop_declare_destroy(env, handle, th);

	RETURN(rc);
}

int llog_trans_destroy(const struct lu_env *env, struct llog_handle *handle,
		       struct thandle *th)
{
	struct llog_operations	*lop;
	int rc;
	ENTRY;

	rc = llog_handle2ops(handle, &lop);
	if (rc < 0)
		RETURN(rc);
	if (lop->lop_destroy == NULL)
		RETURN(-EOPNOTSUPP);

	LASSERT(handle->lgh_obj != NULL);
	if (!dt_object_exists(handle->lgh_obj))
		RETURN(0);

	rc = lop->lop_destroy(env, handle, th);

	RETURN(rc);
}

int llog_destroy(const struct lu_env *env, struct llog_handle *handle)
{
	struct llog_operations	*lop;
	struct dt_device	*dt;
	struct thandle		*th;
	int rc;

	ENTRY;

	rc = llog_handle2ops(handle, &lop);
	if (rc < 0)
		RETURN(rc);
	if (lop->lop_destroy == NULL)
		RETURN(-EOPNOTSUPP);

	if (handle->lgh_obj == NULL) {
		/* if lgh_obj == NULL, then it is from client side destroy */
		rc = lop->lop_destroy(env, handle, NULL);
		RETURN(rc);
	}

	if (!dt_object_exists(handle->lgh_obj))
		RETURN(0);

	dt = lu2dt_dev(handle->lgh_obj->do_lu.lo_dev);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = llog_declare_destroy(env, handle, th);
	if (rc != 0)
		GOTO(out_trans, rc);

	rc = dt_trans_start_local(env, dt, th);
	if (rc < 0)
		GOTO(out_trans, rc);

	rc = lop->lop_destroy(env, handle, th);

out_trans:
	dt_trans_stop(env, dt, th);

	RETURN(rc);
}
EXPORT_SYMBOL(llog_destroy);

/* returns negative on error; 0 if success; 1 if success & log destroyed */
int llog_cancel_rec(const struct lu_env *env, struct llog_handle *loghandle,
		    int index)
{
	struct llog_thread_info *lgi = llog_info(env);
	struct dt_device	*dt;
	struct llog_log_hdr	*llh = loghandle->lgh_hdr;
	struct thandle		*th;
	int			 rc;
	int rc1;
	bool subtract_count = false;

	ENTRY;

	CDEBUG(D_RPCTRACE, "Canceling %d in log "DFID"\n", index,
	       PFID(&loghandle->lgh_id.lgl_oi.oi_fid));

	if (index == 0) {
		CERROR("Can't cancel index 0 which is header\n");
		RETURN(-EINVAL);
	}

	LASSERT(loghandle != NULL);
	LASSERT(loghandle->lgh_ctxt != NULL);
	LASSERT(loghandle->lgh_obj != NULL);

	dt = lu2dt_dev(loghandle->lgh_obj->do_lu.lo_dev);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = llog_declare_write_rec(env, loghandle, &llh->llh_hdr, index, th);
	if (rc < 0)
		GOTO(out_trans, rc);

	if ((llh->llh_flags & LLOG_F_ZAP_WHEN_EMPTY)) {
		rc = llog_declare_destroy(env, loghandle, th);
		if (rc < 0)
			GOTO(out_trans, rc);
	}

	th->th_wait_submit = 1;
	rc = dt_trans_start_local(env, dt, th);
	if (rc < 0)
		GOTO(out_trans, rc);

	down_write(&loghandle->lgh_lock);
	/* clear bitmap */
	mutex_lock(&loghandle->lgh_hdr_mutex);
	if (!ext2_clear_bit(index, LLOG_HDR_BITMAP(llh))) {
		CDEBUG(D_RPCTRACE, "Catalog index %u already clear?\n", index);
		GOTO(out_unlock, rc);
	}

	loghandle->lgh_hdr->llh_count--;
	subtract_count = true;
	/* Pass this index to llog_osd_write_rec(), which will use the index
	 * to only update the necesary bitmap. */
	lgi->lgi_cookie.lgc_index = index;
	/* update header */
	rc = llog_write_rec(env, loghandle, &llh->llh_hdr, &lgi->lgi_cookie,
			    LLOG_HEADER_IDX, th);
	if (rc != 0)
		GOTO(out_unlock, rc);

	if ((llh->llh_flags & LLOG_F_ZAP_WHEN_EMPTY) &&
	    (llh->llh_count == 1) &&
	    ((loghandle->lgh_last_idx == LLOG_HDR_BITMAP_SIZE(llh) - 1) ||
	     (loghandle->u.phd.phd_cat_handle != NULL &&
	      loghandle->u.phd.phd_cat_handle->u.chd.chd_current_log !=
		loghandle))) {
		/* never try to destroy it again */
		llh->llh_flags &= ~LLOG_F_ZAP_WHEN_EMPTY;
		rc = llog_trans_destroy(env, loghandle, th);
		if (rc < 0) {
			/* Sigh, can not destroy the final plain llog, but
			 * the bitmap has been clearly, so the record can not
			 * be accessed anymore, let's return 0 for now, and
			 * the orphan will be handled by LFSCK. */
			CERROR("%s: can't destroy empty llog "DFID": rc = %d\n",
			       loghandle->lgh_ctxt->loc_obd->obd_name,
			       PFID(&loghandle->lgh_id.lgl_oi.oi_fid), rc);
			GOTO(out_unlock, rc = 0);
		}
		rc = LLOG_DEL_PLAIN;
	}

out_unlock:
	mutex_unlock(&loghandle->lgh_hdr_mutex);
	up_write(&loghandle->lgh_lock);
out_trans:
	rc1 = dt_trans_stop(env, dt, th);
	if (rc == 0)
		rc = rc1;
	if (rc < 0 && subtract_count) {
		mutex_lock(&loghandle->lgh_hdr_mutex);
		loghandle->lgh_hdr->llh_count++;
		ext2_set_bit(index, LLOG_HDR_BITMAP(llh));
		mutex_unlock(&loghandle->lgh_hdr_mutex);
	}
	RETURN(rc);
}

int llog_read_header(const struct lu_env *env, struct llog_handle *handle,
		     const struct obd_uuid *uuid)
{
	struct llog_operations *lop;
	int rc;
	ENTRY;

	rc = llog_handle2ops(handle, &lop);
	if (rc)
		RETURN(rc);

	if (lop->lop_read_header == NULL)
		RETURN(-EOPNOTSUPP);

	rc = lop->lop_read_header(env, handle);
	if (rc == LLOG_EEMPTY) {
		struct llog_log_hdr *llh = handle->lgh_hdr;

		/* lrh_len should be initialized in llog_init_handle */
		handle->lgh_last_idx = 0; /* header is record with index 0 */
		llh->llh_count = 1;         /* for the header record */
		llh->llh_hdr.lrh_type = LLOG_HDR_MAGIC;
		LASSERT(handle->lgh_ctxt->loc_chunk_size >=
						LLOG_MIN_CHUNK_SIZE);
		llh->llh_hdr.lrh_len = handle->lgh_ctxt->loc_chunk_size;
		llh->llh_hdr.lrh_index = 0;
		llh->llh_timestamp = ktime_get_real_seconds();
		if (uuid)
			memcpy(&llh->llh_tgtuuid, uuid,
			       sizeof(llh->llh_tgtuuid));
		llh->llh_bitmap_offset = offsetof(typeof(*llh), llh_bitmap);
		/* Since update llog header might also call this function,
		 * let's reset the bitmap to 0 here */
		memset(LLOG_HDR_BITMAP(llh), 0, llh->llh_hdr.lrh_len -
						llh->llh_bitmap_offset -
						sizeof(llh->llh_tail));
		ext2_set_bit(0, LLOG_HDR_BITMAP(llh));
		LLOG_HDR_TAIL(llh)->lrt_len = llh->llh_hdr.lrh_len;
		LLOG_HDR_TAIL(llh)->lrt_index = llh->llh_hdr.lrh_index;
		rc = 0;
	}
	RETURN(rc);
}
EXPORT_SYMBOL(llog_read_header);

int llog_init_handle(const struct lu_env *env, struct llog_handle *handle,
		     int flags, struct obd_uuid *uuid)
{
	struct llog_log_hdr	*llh;
	enum llog_flag		 fmt = flags & LLOG_F_EXT_MASK;
	int			 rc;
	int			chunk_size = handle->lgh_ctxt->loc_chunk_size;
	ENTRY;

	LASSERT(handle->lgh_hdr == NULL);

	LASSERT(chunk_size >= LLOG_MIN_CHUNK_SIZE);
	OBD_ALLOC_LARGE(llh, chunk_size);
	if (llh == NULL)
		RETURN(-ENOMEM);

	handle->lgh_hdr = llh;
	handle->lgh_hdr_size = chunk_size;
	/* first assign flags to use llog_client_ops */
	llh->llh_flags = flags;
	rc = llog_read_header(env, handle, uuid);
	if (rc == 0) {
		if (unlikely((llh->llh_flags & LLOG_F_IS_PLAIN &&
			      flags & LLOG_F_IS_CAT) ||
			     (llh->llh_flags & LLOG_F_IS_CAT &&
			      flags & LLOG_F_IS_PLAIN))) {
			CERROR("%s: llog type is %s but initializing %s\n",
			       handle->lgh_ctxt->loc_obd->obd_name,
			       llh->llh_flags & LLOG_F_IS_CAT ?
			       "catalog" : "plain",
			       flags & LLOG_F_IS_CAT ? "catalog" : "plain");
			GOTO(out, rc = -EINVAL);
		} else if (llh->llh_flags &
			   (LLOG_F_IS_PLAIN | LLOG_F_IS_CAT)) {
			/*
			 * it is possible to open llog without specifying llog
			 * type so it is taken from llh_flags
			 */
			flags = llh->llh_flags;
		} else {
			/* for some reason the llh_flags has no type set */
			CERROR("llog type is not specified!\n");
			GOTO(out, rc = -EINVAL);
		}
		if (unlikely(uuid &&
			     !obd_uuid_equals(uuid, &llh->llh_tgtuuid))) {
			CERROR("%s: llog uuid mismatch: %s/%s\n",
			       handle->lgh_ctxt->loc_obd->obd_name,
			       (char *)uuid->uuid,
			       (char *)llh->llh_tgtuuid.uuid);
			GOTO(out, rc = -EEXIST);
		}
	}
	if (flags & LLOG_F_IS_CAT) {
		LASSERT(list_empty(&handle->u.chd.chd_head));
		INIT_LIST_HEAD(&handle->u.chd.chd_head);
		llh->llh_size = sizeof(struct llog_logid_rec);
		llh->llh_flags |= LLOG_F_IS_FIXSIZE;
	} else if (!(flags & LLOG_F_IS_PLAIN)) {
		CERROR("%s: unknown flags: %#x (expected %#x or %#x)\n",
		       handle->lgh_ctxt->loc_obd->obd_name,
		       flags, LLOG_F_IS_CAT, LLOG_F_IS_PLAIN);
		rc = -EINVAL;
	}
	llh->llh_flags |= fmt;
out:
	if (rc) {
		OBD_FREE_LARGE(llh, chunk_size);
		handle->lgh_hdr = NULL;
	}
	RETURN(rc);
}
EXPORT_SYMBOL(llog_init_handle);

static int llog_process_thread(void *arg)
{
	struct llog_process_info	*lpi = arg;
	struct llog_handle		*loghandle = lpi->lpi_loghandle;
	struct llog_log_hdr		*llh = loghandle->lgh_hdr;
	struct llog_process_cat_data	*cd  = lpi->lpi_catdata;
	char				*buf;
	size_t				 chunk_size;
	__u64				 cur_offset;
	int				 rc = 0, index = 1, last_index;
	int				 saved_index = 0;
	int				 last_called_index = 0;
	bool				 repeated = false;

	ENTRY;

	if (llh == NULL)
		RETURN(-EINVAL);

	cur_offset = chunk_size = llh->llh_hdr.lrh_len;
	/* expect chunk_size to be power of two */
	LASSERT(is_power_of_2(chunk_size));

	OBD_ALLOC_LARGE(buf, chunk_size);
	if (buf == NULL) {
		lpi->lpi_rc = -ENOMEM;
		RETURN(0);
	}

	if (cd != NULL) {
		last_called_index = cd->lpcd_first_idx;
		index = cd->lpcd_first_idx + 1;
	}
	if (cd != NULL && cd->lpcd_last_idx)
		last_index = cd->lpcd_last_idx;
	else
		last_index = LLOG_HDR_BITMAP_SIZE(llh) - 1;

	while (rc == 0) {
		struct llog_rec_hdr *rec;
		off_t chunk_offset = 0;
		unsigned int buf_offset = 0;
		bool partial_chunk;
		int	lh_last_idx;

		/* skip records not set in bitmap */
		while (index <= last_index &&
		       !ext2_test_bit(index, LLOG_HDR_BITMAP(llh)))
			++index;

		/* There are no indices prior the last_index */
		if (index > last_index)
			break;

		CDEBUG(D_OTHER, "index: %d last_index %d\n", index,
		       last_index);

repeat:
		/* get the buf with our target record; avoid old garbage */
		memset(buf, 0, chunk_size);
		/* the record index for outdated chunk data */
		lh_last_idx = loghandle->lgh_last_idx + 1;
		rc = llog_next_block(lpi->lpi_env, loghandle, &saved_index,
				     index, &cur_offset, buf, chunk_size);
		if (repeated && rc)
			CDEBUG(D_OTHER, "cur_offset %llu, chunk_offset %llu,"
			       " buf_offset %u, rc = %d\n", cur_offset,
			       (__u64)chunk_offset, buf_offset, rc);
		/* we`ve tried to reread the chunk, but there is no
		 * new records */
		if (rc == -EIO && repeated && (chunk_offset + buf_offset) ==
		    cur_offset)
			GOTO(out, rc = 0);
		if (rc != 0)
			GOTO(out, rc);

		/* NB: after llog_next_block() call the cur_offset is the
		 * offset of the next block after read one.
		 * The absolute offset of the current chunk is calculated
		 * from cur_offset value and stored in chunk_offset variable.
		 */
		if ((cur_offset & (chunk_size - 1)) != 0) {
			partial_chunk = true;
			chunk_offset = cur_offset & ~(chunk_size - 1);
		} else {
			partial_chunk = false;
			chunk_offset = cur_offset - chunk_size;
		}

		/* NB: when rec->lrh_len is accessed it is already swabbed
		 * since it is used at the "end" of the loop and the rec
		 * swabbing is done at the beginning of the loop. */
		for (rec = (struct llog_rec_hdr *)(buf + buf_offset);
		     (char *)rec < buf + chunk_size;
		     rec = llog_rec_hdr_next(rec)) {

			CDEBUG(D_OTHER, "processing rec 0x%p type %#x\n",
			       rec, rec->lrh_type);

			if (LLOG_REC_HDR_NEEDS_SWABBING(rec))
				lustre_swab_llog_rec(rec);

			CDEBUG(D_OTHER, "after swabbing, type=%#x idx=%d\n",
			       rec->lrh_type, rec->lrh_index);

			/* the bitmap could be changed during processing
			 * records from the chunk. For wrapped catalog
			 * it means we can read deleted record and try to
			 * process it. Check this case and reread the chunk. */

			/* for partial chunk the end of it is zeroed, check
			 * for index 0 to distinguish it. */
			if ((partial_chunk && rec->lrh_index == 0) ||
			     (index == lh_last_idx &&
			      lh_last_idx != (loghandle->lgh_last_idx + 1))) {
				/* concurrent llog_add() might add new records
				 * while llog_processing, check this is not
				 * the case and re-read the current chunk
				 * otherwise. */
				int records;
				/* lgh_last_idx could be less then index
				 * for catalog, if catalog is wrapped */
				if ((index > loghandle->lgh_last_idx &&
				    !(loghandle->lgh_hdr->llh_flags &
				      LLOG_F_IS_CAT)) || repeated ||
				    (loghandle->lgh_obj != NULL &&
				     dt_object_remote(loghandle->lgh_obj)))
					GOTO(out, rc = 0);
				/* <2 records means no more records
				 * if the last record we processed was
				 * the final one, then the underlying
				 * object might have been destroyed yet.
				 * we better don't access that.. */
				mutex_lock(&loghandle->lgh_hdr_mutex);
				records = loghandle->lgh_hdr->llh_count;
				mutex_unlock(&loghandle->lgh_hdr_mutex);
				if (records <= 1)
					GOTO(out, rc = 0);
				CDEBUG(D_OTHER, "Re-read last llog buffer for "
				       "new records, index %u, last %u\n",
				       index, loghandle->lgh_last_idx);
				/* save offset inside buffer for the re-read */
				buf_offset = (char *)rec - (char *)buf;
				cur_offset = chunk_offset;
				repeated = true;
				goto repeat;
			}

			repeated = false;

			if (rec->lrh_len == 0 || rec->lrh_len > chunk_size) {
				CWARN("%s: invalid length %d in llog "DFID
				      "record for index %d/%d\n",
				       loghandle->lgh_ctxt->loc_obd->obd_name,
				       rec->lrh_len,
				       PFID(&loghandle->lgh_id.lgl_oi.oi_fid),
				       rec->lrh_index, index);

				GOTO(out, rc = -EINVAL);
			}

			if (rec->lrh_index < index) {
				CDEBUG(D_OTHER, "skipping lrh_index %d\n",
				       rec->lrh_index);
				continue;
			}

			if (rec->lrh_index != index) {
				CERROR("%s: "DFID" Invalid record: index %u"
				       " but expected %u\n",
				       loghandle->lgh_ctxt->loc_obd->obd_name,
				       PFID(&loghandle->lgh_id.lgl_oi.oi_fid),
				       rec->lrh_index, index);
				GOTO(out, rc = -ERANGE);
			}

			CDEBUG(D_OTHER,
			       "lrh_index: %d lrh_len: %d (%d remains)\n",
			       rec->lrh_index, rec->lrh_len,
			       (int)(buf + chunk_size - (char *)rec));

			loghandle->lgh_cur_idx = rec->lrh_index;
			loghandle->lgh_cur_offset = (char *)rec - (char *)buf +
						    chunk_offset;

			/* if set, process the callback on this record */
			if (ext2_test_bit(index, LLOG_HDR_BITMAP(llh))) {
				rc = lpi->lpi_cb(lpi->lpi_env, loghandle, rec,
						 lpi->lpi_cbdata);
				last_called_index = index;
				if (rc == LLOG_PROC_BREAK) {
					GOTO(out, rc);
				} else if (rc == LLOG_DEL_RECORD) {
					rc = llog_cancel_rec(lpi->lpi_env,
							     loghandle,
							     rec->lrh_index);
				}
				if (rc)
					GOTO(out, rc);
				/* some stupid callbacks directly cancel records
				 * and delete llog. Check it and stop
				 * processing. */
				if (loghandle->lgh_hdr == NULL ||
				    loghandle->lgh_hdr->llh_count == 1)
					GOTO(out, rc = 0);
			}
			/* exit if the last index is reached */
			if (index >= last_index)
				GOTO(out, rc = 0);
			++index;
		}
	}

out:
	if (cd != NULL)
		cd->lpcd_last_idx = last_called_index;

	if (unlikely(rc == -EIO && loghandle->lgh_obj != NULL)) {
		if (dt_object_remote(loghandle->lgh_obj)) {
			/* If it is remote object, then -EIO might means
			 * disconnection or eviction, let's return -EAGAIN,
			 * so for update recovery log processing, it will
			 * retry until the umount or abort recovery, see
			 * lod_sub_recovery_thread() */
			CERROR("%s retry remote llog process\n",
			       loghandle->lgh_ctxt->loc_obd->obd_name);
			rc = -EAGAIN;
		} else {
			/* something bad happened to the processing of a local
			 * llog file, probably I/O error or the log got
			 * corrupted to be able to finally release the log we
			 * discard any remaining bits in the header */
			CERROR("%s: Local llog found corrupted #"DOSTID":%x"
			       " %s index %d count %d\n",
			       loghandle->lgh_ctxt->loc_obd->obd_name,
			       POSTID(&loghandle->lgh_id.lgl_oi),
			       loghandle->lgh_id.lgl_ogen,
			       ((llh->llh_flags & LLOG_F_IS_CAT) ? "catalog" :
				"plain"), index, llh->llh_count);

			while (index <= last_index) {
				if (ext2_test_bit(index,
						  LLOG_HDR_BITMAP(llh)) != 0)
					llog_cancel_rec(lpi->lpi_env, loghandle,
							index);
				index++;
			}
			rc = 0;
		}
	}

	OBD_FREE_LARGE(buf, chunk_size);
	lpi->lpi_rc = rc;
	return 0;
}

static int llog_process_thread_daemonize(void *arg)
{
	struct llog_process_info	*lpi = arg;
	struct lu_env			 env;
	int				 rc;
	struct nsproxy			*new_ns, *curr_ns = current->nsproxy;

	task_lock(lpi->lpi_reftask);
	new_ns = lpi->lpi_reftask->nsproxy;
	if (curr_ns != new_ns) {
		get_nsproxy(new_ns);

		current->nsproxy = new_ns;
		/* XXX: we should call put_nsproxy() instead of
		 * atomic_dec(&ns->count) directly. But put_nsproxy() cannot be
		 * used outside of the kernel itself, because it calls
		 * free_nsproxy() which is not exported by the kernel
		 * (defined in kernel/nsproxy.c) */
		atomic_dec(&curr_ns->count);
	}
	task_unlock(lpi->lpi_reftask);

	unshare_fs_struct();

	/* client env has no keys, tags is just 0 */
	rc = lu_env_init(&env, LCT_LOCAL | LCT_MG_THREAD);
	if (rc)
		goto out;
	lpi->lpi_env = &env;

	rc = llog_process_thread(arg);

	lu_env_fini(&env);
out:
	complete(&lpi->lpi_completion);
	return rc;
}

int llog_process_or_fork(const struct lu_env *env,
			 struct llog_handle *loghandle,
			 llog_cb_t cb, void *data, void *catdata, bool fork)
{
        struct llog_process_info *lpi;
        int                      rc;

        ENTRY;

	OBD_ALLOC_PTR(lpi);
	if (lpi == NULL) {
		CERROR("cannot alloc pointer\n");
		RETURN(-ENOMEM);
	}
	lpi->lpi_loghandle = loghandle;
	lpi->lpi_cb        = cb;
	lpi->lpi_cbdata    = data;
	lpi->lpi_catdata   = catdata;

	if (fork) {
		struct task_struct *task;

		/* The new thread can't use parent env,
		 * init the new one in llog_process_thread_daemonize. */
		lpi->lpi_env = NULL;
		init_completion(&lpi->lpi_completion);
		/* take reference to current, so that
		 * llog_process_thread_daemonize() can use it to switch to
		 * namespace associated with current  */
		lpi->lpi_reftask = current;
		task = kthread_run(llog_process_thread_daemonize, lpi,
				   "llog_process_thread");
		if (IS_ERR(task)) {
			rc = PTR_ERR(task);
			CERROR("%s: cannot start thread: rc = %d\n",
			       loghandle->lgh_ctxt->loc_obd->obd_name, rc);
			GOTO(out_lpi, rc);
		}
		wait_for_completion(&lpi->lpi_completion);
	} else {
		lpi->lpi_env = env;
		llog_process_thread(lpi);
	}
	rc = lpi->lpi_rc;

out_lpi:
	OBD_FREE_PTR(lpi);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_process_or_fork);

int llog_process(const struct lu_env *env, struct llog_handle *loghandle,
		 llog_cb_t cb, void *data, void *catdata)
{
	int rc;
	rc = llog_process_or_fork(env, loghandle, cb, data, catdata, true);
	return rc == LLOG_DEL_PLAIN ? 0 : rc;
}
EXPORT_SYMBOL(llog_process);

int llog_reverse_process(const struct lu_env *env,
			 struct llog_handle *loghandle, llog_cb_t cb,
			 void *data, void *catdata)
{
        struct llog_log_hdr *llh = loghandle->lgh_hdr;
        struct llog_process_cat_data *cd = catdata;
        void *buf;
        int rc = 0, first_index = 1, index, idx;
	__u32	chunk_size = llh->llh_hdr.lrh_len;
        ENTRY;

	OBD_ALLOC_LARGE(buf, chunk_size);
	if (buf == NULL)
		RETURN(-ENOMEM);

	if (cd != NULL)
		first_index = cd->lpcd_first_idx + 1;
	if (cd != NULL && cd->lpcd_last_idx)
		index = cd->lpcd_last_idx;
	else
		index = LLOG_HDR_BITMAP_SIZE(llh) - 1;

	while (rc == 0) {
		struct llog_rec_hdr *rec;
		struct llog_rec_tail *tail;

		/* skip records not set in bitmap */
		while (index >= first_index &&
		       !ext2_test_bit(index, LLOG_HDR_BITMAP(llh)))
			--index;

		LASSERT(index >= first_index - 1);
		if (index == first_index - 1)
			break;

		/* get the buf with our target record; avoid old garbage */
		memset(buf, 0, chunk_size);
		rc = llog_prev_block(env, loghandle, index, buf, chunk_size);
		if (rc)
			GOTO(out, rc);

		rec = buf;
		idx = rec->lrh_index;
		CDEBUG(D_RPCTRACE, "index %u : idx %u\n", index, idx);
                while (idx < index) {
			rec = (void *)rec + rec->lrh_len;
			if (LLOG_REC_HDR_NEEDS_SWABBING(rec))
				lustre_swab_llog_rec(rec);
                        idx ++;
                }
		LASSERT(idx == index);
		tail = (void *)rec + rec->lrh_len - sizeof(*tail);

		/* process records in buffer, starting where we found one */
		while ((void *)tail > buf) {
			if (tail->lrt_index == 0)
				GOTO(out, rc = 0); /* no more records */

			/* if set, process the callback on this record */
			if (ext2_test_bit(index, LLOG_HDR_BITMAP(llh))) {
				rec = (void *)tail - tail->lrt_len +
				      sizeof(*tail);

				rc = cb(env, loghandle, rec, data);
				if (rc == LLOG_PROC_BREAK) {
					GOTO(out, rc);
				} else if (rc == LLOG_DEL_RECORD) {
					rc = llog_cancel_rec(env, loghandle,
							     tail->lrt_index);
				}
                                if (rc)
                                        GOTO(out, rc);
                        }

                        /* previous record, still in buffer? */
                        --index;
                        if (index < first_index)
                                GOTO(out, rc = 0);
			tail = (void *)tail - tail->lrt_len;
                }
        }

out:
	if (buf != NULL)
		OBD_FREE_LARGE(buf, chunk_size);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_reverse_process);

/**
 * new llog API
 *
 * API functions:
 *      llog_open - open llog, may not exist
 *      llog_exist - check if llog exists
 *      llog_close - close opened llog, pair for open, frees llog_handle
 *      llog_declare_create - declare llog creation
 *      llog_create - create new llog on disk, need transaction handle
 *      llog_declare_write_rec - declaration of llog write
 *      llog_write_rec - write llog record on disk, need transaction handle
 *      llog_declare_add - declare llog catalog record addition
 *      llog_add - add llog record in catalog, need transaction handle
 */
int llog_exist(struct llog_handle *loghandle)
{
	struct llog_operations	*lop;
	int			 rc;

	ENTRY;

	rc = llog_handle2ops(loghandle, &lop);
	if (rc)
		RETURN(rc);
	if (lop->lop_exist == NULL)
		RETURN(-EOPNOTSUPP);

	rc = lop->lop_exist(loghandle);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_exist);

int llog_declare_create(const struct lu_env *env,
			struct llog_handle *loghandle, struct thandle *th)
{
	struct llog_operations	*lop;
	int			 raised, rc;

	ENTRY;

	rc = llog_handle2ops(loghandle, &lop);
	if (rc)
		RETURN(rc);
	if (lop->lop_declare_create == NULL)
		RETURN(-EOPNOTSUPP);

	raised = cfs_cap_raised(CFS_CAP_SYS_RESOURCE);
	if (!raised)
		cfs_cap_raise(CFS_CAP_SYS_RESOURCE);
	rc = lop->lop_declare_create(env, loghandle, th);
	if (!raised)
		cfs_cap_lower(CFS_CAP_SYS_RESOURCE);
	RETURN(rc);
}

int llog_create(const struct lu_env *env, struct llog_handle *handle,
		struct thandle *th)
{
	struct llog_operations	*lop;
	int			 raised, rc;

	ENTRY;

	rc = llog_handle2ops(handle, &lop);
	if (rc)
		RETURN(rc);
	if (lop->lop_create == NULL)
		RETURN(-EOPNOTSUPP);

	raised = cfs_cap_raised(CFS_CAP_SYS_RESOURCE);
	if (!raised)
		cfs_cap_raise(CFS_CAP_SYS_RESOURCE);
	rc = lop->lop_create(env, handle, th);
	if (!raised)
		cfs_cap_lower(CFS_CAP_SYS_RESOURCE);
	RETURN(rc);
}

int llog_declare_write_rec(const struct lu_env *env,
			   struct llog_handle *handle,
			   struct llog_rec_hdr *rec, int idx,
			   struct thandle *th)
{
	struct llog_operations	*lop;
	int			 raised, rc;

	ENTRY;

	rc = llog_handle2ops(handle, &lop);
	if (rc)
		RETURN(rc);
	LASSERT(lop);
	if (lop->lop_declare_write_rec == NULL)
		RETURN(-EOPNOTSUPP);

	raised = cfs_cap_raised(CFS_CAP_SYS_RESOURCE);
	if (!raised)
		cfs_cap_raise(CFS_CAP_SYS_RESOURCE);
	rc = lop->lop_declare_write_rec(env, handle, rec, idx, th);
	if (!raised)
		cfs_cap_lower(CFS_CAP_SYS_RESOURCE);
	RETURN(rc);
}

int llog_write_rec(const struct lu_env *env, struct llog_handle *handle,
		   struct llog_rec_hdr *rec, struct llog_cookie *logcookies,
		   int idx, struct thandle *th)
{
	struct llog_operations	*lop;
	int			 raised, rc, buflen;

	ENTRY;

	/* API sanity checks */
	if (handle == NULL) {
		CERROR("loghandle is missed\n");
		RETURN(-EPROTO);
	} else if (handle->lgh_obj == NULL) {
		CERROR("loghandle %p with NULL object\n",
			handle);
		RETURN(-EPROTO);
	} else if (th == NULL) {
		CERROR("%s: missed transaction handle\n",
			handle->lgh_obj->do_lu.lo_dev->ld_obd->obd_name);
		RETURN(-EPROTO);
	} else if (handle->lgh_hdr == NULL) {
		CERROR("%s: loghandle %p with no header\n",
			handle->lgh_obj->do_lu.lo_dev->ld_obd->obd_name,
			handle);
		RETURN(-EPROTO);
	}

	rc = llog_handle2ops(handle, &lop);
	if (rc)
		RETURN(rc);

	if (lop->lop_write_rec == NULL)
		RETURN(-EOPNOTSUPP);

	buflen = rec->lrh_len;
	LASSERT(cfs_size_round(buflen) == buflen);

	raised = cfs_cap_raised(CFS_CAP_SYS_RESOURCE);
	if (!raised)
		cfs_cap_raise(CFS_CAP_SYS_RESOURCE);
	rc = lop->lop_write_rec(env, handle, rec, logcookies, idx, th);
	if (!raised)
		cfs_cap_lower(CFS_CAP_SYS_RESOURCE);
	RETURN(rc);
}

int llog_add(const struct lu_env *env, struct llog_handle *lgh,
	     struct llog_rec_hdr *rec, struct llog_cookie *logcookies,
	     struct thandle *th)
{
	int raised, rc;

	ENTRY;

	if (lgh->lgh_logops->lop_add == NULL)
		RETURN(-EOPNOTSUPP);

	raised = cfs_cap_raised(CFS_CAP_SYS_RESOURCE);
	if (!raised)
		cfs_cap_raise(CFS_CAP_SYS_RESOURCE);
	rc = lgh->lgh_logops->lop_add(env, lgh, rec, logcookies, th);
	if (!raised)
		cfs_cap_lower(CFS_CAP_SYS_RESOURCE);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_add);

int llog_declare_add(const struct lu_env *env, struct llog_handle *lgh,
		     struct llog_rec_hdr *rec, struct thandle *th)
{
	int raised, rc;

	ENTRY;

	if (lgh->lgh_logops->lop_declare_add == NULL)
		RETURN(-EOPNOTSUPP);

	raised = cfs_cap_raised(CFS_CAP_SYS_RESOURCE);
	if (!raised)
		cfs_cap_raise(CFS_CAP_SYS_RESOURCE);
	rc = lgh->lgh_logops->lop_declare_add(env, lgh, rec, th);
	if (!raised)
		cfs_cap_lower(CFS_CAP_SYS_RESOURCE);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_declare_add);

/**
 * Helper function to open llog or create it if doesn't exist.
 * It hides all transaction handling from caller.
 */
int llog_open_create(const struct lu_env *env, struct llog_ctxt *ctxt,
		     struct llog_handle **res, struct llog_logid *logid,
		     char *name)
{
	struct dt_device	*d;
	struct thandle		*th;
	int			 rc;

	ENTRY;

	rc = llog_open(env, ctxt, res, logid, name, LLOG_OPEN_NEW);
	if (rc)
		RETURN(rc);

	if (llog_exist(*res))
		RETURN(0);

	LASSERT((*res)->lgh_obj != NULL);

	d = lu2dt_dev((*res)->lgh_obj->do_lu.lo_dev);

	th = dt_trans_create(env, d);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	/* Create update llog object synchronously, which
	 * happens during inialization process see
	 * lod_sub_prep_llog(), to make sure the update
	 * llog object is created before corss-MDT writing
	 * updates into the llog object */
	if (ctxt->loc_flags & LLOG_CTXT_FLAG_NORMAL_FID)
		th->th_sync = 1;

	th->th_wait_submit = 1;
	rc = llog_declare_create(env, *res, th);
	if (rc == 0) {
		rc = dt_trans_start_local(env, d, th);
		if (rc == 0)
			rc = llog_create(env, *res, th);
	}
	dt_trans_stop(env, d, th);
out:
	if (rc)
		llog_close(env, *res);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_open_create);

/**
 * Helper function to delete existent llog.
 */
int llog_erase(const struct lu_env *env, struct llog_ctxt *ctxt,
	       struct llog_logid *logid, char *name)
{
	struct llog_handle	*handle;
	int			 rc = 0, rc2;

	ENTRY;

	/* nothing to erase */
	if (name == NULL && logid == NULL)
		RETURN(0);

	rc = llog_open(env, ctxt, &handle, logid, name, LLOG_OPEN_EXISTS);
	if (rc < 0)
		RETURN(rc);

	rc = llog_init_handle(env, handle, LLOG_F_IS_PLAIN, NULL);
	if (rc == 0)
		rc = llog_destroy(env, handle);

	rc2 = llog_close(env, handle);
	if (rc == 0)
		rc = rc2;
	RETURN(rc);
}
EXPORT_SYMBOL(llog_erase);

/*
 * Helper function for write record in llog.
 * It hides all transaction handling from caller.
 * Valid only with local llog.
 */
int llog_write(const struct lu_env *env, struct llog_handle *loghandle,
	       struct llog_rec_hdr *rec, int idx)
{
	struct dt_device	*dt;
	struct thandle		*th;
	int			 rc;

	ENTRY;

	LASSERT(loghandle);
	LASSERT(loghandle->lgh_ctxt);
	LASSERT(loghandle->lgh_obj != NULL);

	dt = lu2dt_dev(loghandle->lgh_obj->do_lu.lo_dev);

	th = dt_trans_create(env, dt);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = llog_declare_write_rec(env, loghandle, rec, idx, th);
	if (rc)
		GOTO(out_trans, rc);

	th->th_wait_submit = 1;
	rc = dt_trans_start_local(env, dt, th);
	if (rc)
		GOTO(out_trans, rc);

	down_write(&loghandle->lgh_lock);
	rc = llog_write_rec(env, loghandle, rec, NULL, idx, th);
	up_write(&loghandle->lgh_lock);
out_trans:
	dt_trans_stop(env, dt, th);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_write);

int llog_open(const struct lu_env *env, struct llog_ctxt *ctxt,
	      struct llog_handle **lgh, struct llog_logid *logid,
	      char *name, enum llog_open_param open_param)
{
	int	 raised;
	int	 rc;

	ENTRY;

	LASSERT(ctxt);
	LASSERT(ctxt->loc_logops);

	if (ctxt->loc_logops->lop_open == NULL) {
		*lgh = NULL;
		RETURN(-EOPNOTSUPP);
	}

	*lgh = llog_alloc_handle();
	if (*lgh == NULL)
		RETURN(-ENOMEM);
	(*lgh)->lgh_ctxt = ctxt;
	(*lgh)->lgh_logops = ctxt->loc_logops;

	raised = cfs_cap_raised(CFS_CAP_SYS_RESOURCE);
	if (!raised)
		cfs_cap_raise(CFS_CAP_SYS_RESOURCE);
	rc = ctxt->loc_logops->lop_open(env, *lgh, logid, name, open_param);
	if (!raised)
		cfs_cap_lower(CFS_CAP_SYS_RESOURCE);
	if (rc) {
		llog_free_handle(*lgh);
		*lgh = NULL;
	}
	RETURN(rc);
}
EXPORT_SYMBOL(llog_open);

int llog_close(const struct lu_env *env, struct llog_handle *loghandle)
{
	struct llog_operations	*lop;
	int			 rc;

	ENTRY;

	rc = llog_handle2ops(loghandle, &lop);
	if (rc)
		GOTO(out, rc);
	if (lop->lop_close == NULL)
		GOTO(out, rc = -EOPNOTSUPP);
	rc = lop->lop_close(env, loghandle);
out:
	llog_handle_put(loghandle);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_close);

/**
 * Helper function to get the llog size in records. It is used by MGS
 * mostly to check that config llog exists and contains data.
 *
 * \param[in] env	execution environment
 * \param[in] ctxt	llog context
 * \param[in] name	llog name
 *
 * \retval		true if there are records in llog besides a header
 * \retval		false on error or llog without records
 */
int llog_is_empty(const struct lu_env *env, struct llog_ctxt *ctxt,
		  char *name)
{
	struct llog_handle	*llh;
	int			 rc = 0;

	rc = llog_open(env, ctxt, &llh, NULL, name, LLOG_OPEN_EXISTS);
	if (rc < 0) {
		if (likely(rc == -ENOENT))
			rc = 0;
		GOTO(out, rc);
	}

	rc = llog_init_handle(env, llh, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_close, rc);
	rc = llog_get_size(llh);

out_close:
	llog_close(env, llh);
out:
	/* The header is record 1, the llog is still considered as empty
	 * if there is only header */
	return (rc <= 1);
}
EXPORT_SYMBOL(llog_is_empty);

int llog_copy_handler(const struct lu_env *env, struct llog_handle *llh,
		      struct llog_rec_hdr *rec, void *data)
{
	struct llog_handle	*copy_llh = data;

	/* Append all records */
	return llog_write(env, copy_llh, rec, LLOG_NEXT_IDX);
}

/* backup plain llog */
int llog_backup(const struct lu_env *env, struct obd_device *obd,
		struct llog_ctxt *ctxt, struct llog_ctxt *bctxt,
		char *name, char *backup)
{
	struct llog_handle	*llh, *bllh;
	int			 rc;

	ENTRY;

	/* open original log */
	rc = llog_open(env, ctxt, &llh, NULL, name, LLOG_OPEN_EXISTS);
	if (rc < 0) {
		/* the -ENOENT case is also reported to the caller
		 * but silently so it should handle that if needed.
		 */
		if (rc != -ENOENT)
			CERROR("%s: failed to open log %s: rc = %d\n",
			       obd->obd_name, name, rc);
		RETURN(rc);
	}

	rc = llog_init_handle(env, llh, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_close, rc);

	/* Make sure there's no old backup log */
	rc = llog_erase(env, bctxt, NULL, backup);
	if (rc < 0 && rc != -ENOENT)
		GOTO(out_close, rc);

	/* open backup log */
	rc = llog_open_create(env, bctxt, &bllh, NULL, backup);
	if (rc) {
		CERROR("%s: failed to open backup logfile %s: rc = %d\n",
		       obd->obd_name, backup, rc);
		GOTO(out_close, rc);
	}

	/* check that backup llog is not the same object as original one */
	if (llh->lgh_obj == bllh->lgh_obj) {
		CERROR("%s: backup llog %s to itself (%s), objects %p/%p\n",
		       obd->obd_name, name, backup, llh->lgh_obj,
		       bllh->lgh_obj);
		GOTO(out_backup, rc = -EEXIST);
	}

	rc = llog_init_handle(env, bllh, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_backup, rc);

	/* Copy log record by record */
	rc = llog_process_or_fork(env, llh, llog_copy_handler, (void *)bllh,
				  NULL, false);
	if (rc)
		CERROR("%s: failed to backup log %s: rc = %d\n",
		       obd->obd_name, name, rc);
out_backup:
	llog_close(env, bllh);
out_close:
	llog_close(env, llh);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_backup);

/* Get size of llog */
__u64 llog_size(const struct lu_env *env, struct llog_handle *llh)
{
	int rc;
	struct lu_attr la;

	rc = llh->lgh_obj->do_ops->do_attr_get(env, llh->lgh_obj, &la);
	if (rc) {
		CERROR("%s: attr_get failed, rc = %d\n",
		       llh->lgh_ctxt->loc_obd->obd_name, rc);
		return 0;
	}

	return la.la_size;
}
EXPORT_SYMBOL(llog_size);

