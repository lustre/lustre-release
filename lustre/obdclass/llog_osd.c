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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * lustre/obdclass/llog_osd.c
 *
 * Low level llog routines on top of OSD API
 *
 * This file provides set of methods for llog operations on top of
 * dt_device. It contains all supported llog_operations interfaces and
 * supplimental functions.
 *
 * Author: Alexey Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LOG

#include <linux/delay.h>

#include <dt_object.h>
#include <llog_swab.h>
#include <lustre_fid.h>
#include <obd.h>
#include <obd_class.h>

#include "llog_internal.h"
#include "local_storage.h"

/**
 * Implementation of the llog_operations::lop_declare_create
 *
 * This function is a wrapper over local_storage API function
 * local_object_declare_create().
 *
 * \param[in] env	execution environment
 * \param[in] los	local_storage for bottom storage device
 * \param[in] o		dt_object to create
 * \param[in] th	current transaction handle
 *
 * \retval		0 on successful declaration of the new object
 * \retval		negative error if declaration was failed
 */
static int llog_osd_declare_new_object(const struct lu_env *env,
				       struct local_oid_storage *los,
				       struct dt_object *o,
				       struct thandle *th)
{
	struct llog_thread_info *lgi = llog_info(env);

	lgi->lgi_attr.la_valid = LA_MODE;
	lgi->lgi_attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
	lgi->lgi_dof.dof_type = dt_mode_to_dft(S_IFREG);

	return local_object_declare_create(env, los, o, &lgi->lgi_attr,
					   &lgi->lgi_dof, th);
}

/**
 * Implementation of the llog_operations::lop_create
 *
 * This function is a wrapper over local_storage API function
 * local_object_create().
 *
 * \param[in] env	execution environment
 * \param[in] los	local_storage for bottom storage device
 * \param[in] o		dt_object to create
 * \param[in] th	current transaction handle
 *
 * \retval		0 on successful creation of the new object
 * \retval		negative error if creation was failed
 */
static int llog_osd_create_new_object(const struct lu_env *env,
				      struct local_oid_storage *los,
				      struct dt_object *o,
				      struct thandle *th)
{
	struct llog_thread_info *lgi = llog_info(env);

	lgi->lgi_attr.la_valid = LA_MODE;
	lgi->lgi_attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
	lgi->lgi_dof.dof_type = dt_mode_to_dft(S_IFREG);

	return local_object_create(env, los, o, &lgi->lgi_attr,
				   &lgi->lgi_dof, th);
}

/**
 * Implementation of the llog_operations::lop_exist
 *
 * This function checks that llog exists on storage.
 *
 * \param[in] handle	llog handle of the current llog
 *
 * \retval		true if llog object exists and is not just destroyed
 * \retval		false if llog doesn't exist or just destroyed
 */
static int llog_osd_exist(struct llog_handle *handle)
{
	LASSERT(handle->lgh_obj);
	return dt_object_exists(handle->lgh_obj) && !handle->lgh_destroyed;
}

static void *rec_tail(struct llog_rec_hdr *rec)
{
	return (void *)((char *)rec + rec->lrh_len -
			sizeof(struct llog_rec_tail));
}

/**
 * Write a padding record to the llog
 *
 * This function writes a padding record to the end of llog. That may
 * be needed if llog contains records of variable size, e.g. config logs
 * or changelogs.
 * The padding record just aligns llog to the llog chunk_size boundary if
 * the current record doesn't fit in the remaining space.
 *
 * It allocates full length to avoid two separate writes for header and tail.
 * Such 2-steps scheme needs extra protection and complex error handling.
 *
 * \param[in]     env	execution environment
 * \param[in]     o	dt_object to create
 * \param[in,out] off	pointer to the padding start offset
 * \param[in]     len	padding length
 * \param[in]     index	index of the padding record in a llog
 * \param[in]     th	current transaction handle
 *
 * \retval		0 on successful padding write
 * \retval		negative error if write failed
 */
static int llog_osd_pad(const struct lu_env *env, struct dt_object *o,
			loff_t *off, int len, int index, struct thandle *th)
{
	struct llog_thread_info	*lgi = llog_info(env);
	struct llog_rec_hdr	*rec;
	struct llog_rec_tail	*tail;
	int			 rc;

	ENTRY;

	LASSERT(th);
	LASSERT(off);
	LASSERT(len >= LLOG_MIN_REC_SIZE && (len & 0x7) == 0);

	OBD_ALLOC(rec, len);
	if (rec == NULL)
		RETURN(-ENOMEM);

	rec->lrh_len = len;
	rec->lrh_index = index;
	rec->lrh_type = LLOG_PAD_MAGIC;

	tail = rec_tail(rec);
	tail->lrt_len = len;
	tail->lrt_index = index;

	lgi->lgi_buf.lb_buf = rec;
	lgi->lgi_buf.lb_len = len;
	rc = dt_record_write(env, o, &lgi->lgi_buf, off, th);
	if (rc)
		CERROR("%s: error writing padding record: rc = %d\n",
		       o->do_lu.lo_dev->ld_obd->obd_name, rc);

	OBD_FREE(rec, len);
	RETURN(rc);
}

/**
 * Implementation of the llog_operations::lop_read_header
 *
 * This function reads the current llog header from the bottom storage
 * device.
 *
 * \param[in] env	execution environment
 * \param[in] handle	llog handle of the current llog
 *
 * \retval		0 on successful header read
 * \retval		negative error if read failed
 */
static int llog_osd_read_header(const struct lu_env *env,
				struct llog_handle *handle)
{
	struct llog_rec_hdr	*llh_hdr;
	struct dt_object	*o;
	struct llog_thread_info	*lgi;
	enum llog_flag		 flags;
	int			 rc;

	ENTRY;

	o = handle->lgh_obj;
	LASSERT(o);

	lgi = llog_info(env);

	rc = dt_attr_get(env, o, &lgi->lgi_attr);
	if (rc)
		RETURN(rc);

	LASSERT(lgi->lgi_attr.la_valid & LA_SIZE);

	if (lgi->lgi_attr.la_size == 0) {
		CDEBUG(D_HA, "not reading header from 0-byte log\n");
		RETURN(LLOG_EEMPTY);
	}

	flags = handle->lgh_hdr->llh_flags;

	lgi->lgi_off = 0;
	lgi->lgi_buf.lb_buf = handle->lgh_hdr;
	lgi->lgi_buf.lb_len = handle->lgh_hdr_size;
	rc = dt_read(env, o, &lgi->lgi_buf, &lgi->lgi_off);
	llh_hdr = &handle->lgh_hdr->llh_hdr;
	if (rc < sizeof(*llh_hdr) || rc < llh_hdr->lrh_len) {
		CERROR("%s: error reading "DFID" log header size %d: rc = %d\n",
		       o->do_lu.lo_dev->ld_obd->obd_name,
		       PFID(lu_object_fid(&o->do_lu)), rc < 0 ? 0 : rc,
		       -EFAULT);

		if (rc >= 0)
			rc = -EFAULT;

		RETURN(rc);
	}

	if (LLOG_REC_HDR_NEEDS_SWABBING(llh_hdr))
		lustre_swab_llog_hdr(handle->lgh_hdr);

	if (llh_hdr->lrh_type != LLOG_HDR_MAGIC) {
		CERROR("%s: bad log %s "DFID" header magic: %#x "
		       "(expected %#x)\n", o->do_lu.lo_dev->ld_obd->obd_name,
		       handle->lgh_name ? handle->lgh_name : "",
		       PFID(lu_object_fid(&o->do_lu)),
		       llh_hdr->lrh_type, LLOG_HDR_MAGIC);
		RETURN(-EIO);
	} else if (llh_hdr->lrh_len < LLOG_MIN_CHUNK_SIZE ||
		   llh_hdr->lrh_len > handle->lgh_hdr_size) {
		CERROR("%s: incorrectly sized log %s "DFID" header: "
		       "%#x (expected at least %#x)\n"
		       "you may need to re-run lconf --write_conf.\n",
		       o->do_lu.lo_dev->ld_obd->obd_name,
		       handle->lgh_name ? handle->lgh_name : "",
		       PFID(lu_object_fid(&o->do_lu)),
		       llh_hdr->lrh_len, LLOG_MIN_CHUNK_SIZE);
		RETURN(-EIO);
	} else if (LLOG_HDR_TAIL(handle->lgh_hdr)->lrt_index >
		   LLOG_HDR_BITMAP_SIZE(handle->lgh_hdr) ||
		   LLOG_HDR_TAIL(handle->lgh_hdr)->lrt_len !=
			llh_hdr->lrh_len) {
		CERROR("%s: incorrectly sized log %s "DFID" tailer: "
		       "%#x : rc = %d\n",
		       o->do_lu.lo_dev->ld_obd->obd_name,
		       handle->lgh_name ? handle->lgh_name : "",
		       PFID(lu_object_fid(&o->do_lu)),
		       LLOG_HDR_TAIL(handle->lgh_hdr)->lrt_len, -EIO);
		RETURN(-EIO);
	}

	handle->lgh_hdr->llh_flags |= (flags & LLOG_F_EXT_MASK);
	handle->lgh_last_idx = LLOG_HDR_TAIL(handle->lgh_hdr)->lrt_index;

	RETURN(0);
}

/**
 * Implementation of the llog_operations::lop_declare_write
 *
 * This function declares the new record write.
 *
 * \param[in] env	execution environment
 * \param[in] loghandle	llog handle of the current llog
 * \param[in] rec	llog record header. This is a real header of the full
 *			llog record to write. This is the beginning of buffer
 *			to write, the length of buffer is stored in
 *			\a rec::lrh_len
 * \param[in] idx	index of the llog record. If \a idx == -1 then this is
 *			append case, otherwise \a idx is the index of record
 *			to modify
 * \param[in] th	current transaction handle
 *
 * \retval		0 on successful declaration
 * \retval		negative error if declaration failed
 */
static int llog_osd_declare_write_rec(const struct lu_env *env,
				      struct llog_handle *loghandle,
				      struct llog_rec_hdr *rec,
				      int idx, struct thandle *th)
{
	struct llog_thread_info	*lgi = llog_info(env);
	__u32			chunk_size;
	struct dt_object	*o;
	int			 rc;

	ENTRY;

	LASSERT(env);
	LASSERT(th);
	LASSERT(loghandle);
	LASSERT(rec);
	LASSERT(rec->lrh_len <= loghandle->lgh_ctxt->loc_chunk_size);

	o = loghandle->lgh_obj;
	LASSERT(o);

	chunk_size = loghandle->lgh_ctxt->loc_chunk_size;
	lgi->lgi_buf.lb_len = chunk_size;
	lgi->lgi_buf.lb_buf = NULL;
	/* each time we update header */
	rc = dt_declare_record_write(env, o, &lgi->lgi_buf, 0,
				     th);
	if (rc || idx == 0) /* if error or just header */
		RETURN(rc);

	/**
	 * the pad record can be inserted so take into account double
	 * record size
	 */
	lgi->lgi_buf.lb_len = chunk_size * 2;
	lgi->lgi_buf.lb_buf = NULL;
	/* XXX: implement declared window or multi-chunks approach */
	rc = dt_declare_record_write(env, o, &lgi->lgi_buf, -1, th);

	RETURN(rc);
}

/**
 * Implementation of the llog_operations::lop_write
 *
 * This function writes the new record in the llog or modify the existed one.
 *
 * \param[in]  env		execution environment
 * \param[in]  loghandle	llog handle of the current llog
 * \param[in]  rec		llog record header. This is a real header of
 *				the full llog record to write. This is
 *				the beginning of buffer to write, the length
 *				of buffer is stored in \a rec::lrh_len
 * \param[in,out] reccookie	pointer to the cookie to return back if needed.
 *				It is used for further cancel of this llog
 *				record.
 * \param[in]  idx		index of the llog record. If \a idx == -1 then
 *				this is append case, otherwise \a idx is
 *				the index of record to modify
 * \param[in]  th		current transaction handle
 *
 * \retval			0 on successful write && \a reccookie == NULL
 *				1 on successful write && \a reccookie != NULL
 * \retval			negative error if write failed
 */
static int llog_osd_write_rec(const struct lu_env *env,
			      struct llog_handle *loghandle,
			      struct llog_rec_hdr *rec,
			      struct llog_cookie *reccookie,
			      int idx, struct thandle *th)
{
	struct llog_thread_info	*lgi = llog_info(env);
	struct llog_log_hdr	*llh;
	int			 reclen = rec->lrh_len;
	int			 index, rc;
	struct llog_rec_tail	*lrt;
	struct dt_object	*o;
	__u32			chunk_size;
	size_t			 left;
	__u32			orig_last_idx;
	ENTRY;

	llh = loghandle->lgh_hdr;
	o = loghandle->lgh_obj;

	chunk_size = llh->llh_hdr.lrh_len;
	CDEBUG(D_OTHER, "new record %x to "DFID"\n",
	       rec->lrh_type, PFID(lu_object_fid(&o->do_lu)));

	if (!llog_osd_exist(loghandle))
		RETURN(-ENOENT);

	/* record length should not bigger than  */
	if (reclen > loghandle->lgh_hdr->llh_hdr.lrh_len)
		RETURN(-E2BIG);

	/* sanity check for fixed-records llog */
	if (idx != LLOG_HEADER_IDX && (llh->llh_flags & LLOG_F_IS_FIXSIZE)) {
		LASSERT(llh->llh_size != 0);
		LASSERT(llh->llh_size == reclen);
	}

	/* return error if osp object is stale */
	if (idx != LLOG_HEADER_IDX && dt_object_stale(o))
		RETURN(-ESTALE);
	rc = dt_attr_get(env, o, &lgi->lgi_attr);
	if (rc)
		RETURN(rc);

	/**
	 * The modification case.
	 * If idx set then the record with that index must be modified.
	 * There are three cases possible:
	 * 1) the common case is the llog header update (idx == 0)
	 * 2) the llog record modification during llog process.
	 *    This is indicated by the \a loghandle::lgh_cur_idx > 0.
	 *    In that case the \a loghandle::lgh_cur_offset
	 * 3) otherwise this is assumed that llog consist of records of
	 *    fixed size, i.e. catalog. The llog header must has llh_size
	 *    field equal to record size. The record offset is calculated
	 *    just by /a idx value
	 *
	 * During modification we don't need extra header update because
	 * the bitmap and record count are not changed. The record header
	 * and tail remains the same too.
	 */
	if (idx != LLOG_NEXT_IDX) {
		/* llog can be empty only when first record is being written */
		LASSERT(ergo(idx > 0, lgi->lgi_attr.la_size > 0));

		if (!test_bit_le(idx, LLOG_HDR_BITMAP(llh))) {
			CERROR("%s: modify unset record %u\n",
			       o->do_lu.lo_dev->ld_obd->obd_name, idx);
			RETURN(-ENOENT);
		}

		if (idx != rec->lrh_index) {
			CERROR("%s: modify index mismatch %d %u\n",
			       o->do_lu.lo_dev->ld_obd->obd_name, idx,
			       rec->lrh_index);
			RETURN(-EFAULT);
		}

		if (idx == LLOG_HEADER_IDX) {
			/* llog header update */
			__u32	*bitmap = LLOG_HDR_BITMAP(llh);

			lgi->lgi_off = 0;

			/* If it does not indicate the bitmap index
			 * (reccookie == NULL), then it means update
			 * the whole update header. Otherwise only
			 * update header and bits needs to be updated,
			 * and in DNE cases, it will signaficantly
			 * shrink the RPC size.
			 * see distribute_txn_cancel_records()*/
			if (reccookie == NULL) {
				lgi->lgi_buf.lb_len = reclen;
				lgi->lgi_buf.lb_buf = rec;
				rc = dt_record_write(env, o, &lgi->lgi_buf,
						     &lgi->lgi_off, th);
				RETURN(rc);
			}

			/* update the header */
			lgi->lgi_buf.lb_len = llh->llh_bitmap_offset;
			lgi->lgi_buf.lb_buf = llh;
			rc = dt_record_write(env, o, &lgi->lgi_buf,
					     &lgi->lgi_off, th);
			if (rc != 0)
				RETURN(rc);

			/* update the bitmap */
			index = reccookie->lgc_index;
			lgi->lgi_off = llh->llh_bitmap_offset +
				      (index / (sizeof(*bitmap) * 8)) *
							sizeof(*bitmap);
			lgi->lgi_buf.lb_len = sizeof(*bitmap);
			lgi->lgi_buf.lb_buf =
					&bitmap[index/(sizeof(*bitmap)*8)];
			rc = dt_record_write(env, o, &lgi->lgi_buf,
					     &lgi->lgi_off, th);

			RETURN(rc);
		} else if (llh->llh_flags & LLOG_F_IS_FIXSIZE) {
			lgi->lgi_off = llh->llh_hdr.lrh_len +
				       (idx - 1) * reclen;
		} else if (reccookie != NULL && reccookie->lgc_index > 0) {
			/**
			 * The lgc_offset can be used only if index is
			 * the same.
			 */
			if (idx != reccookie->lgc_index) {
				CERROR("%s: modify index mismatch %d %d\n",
				       o->do_lu.lo_dev->ld_obd->obd_name, idx,
				       reccookie->lgc_index);
				RETURN(-EFAULT);
			}

			lgi->lgi_off = reccookie->lgc_offset;
			CDEBUG(D_OTHER, "modify record "DFID": idx:%u, "
			       "len:%u offset %llu\n",
			       PFID(&loghandle->lgh_id.lgl_oi.oi_fid), idx,
			       rec->lrh_len, (long long)lgi->lgi_off);
		} else {
			/* This can be result of lgh_cur_idx is not set during
			 * llog processing or llh_size is not set to proper
			 * record size for fixed records llog. Therefore it is
			 * impossible to get record offset. */
			CERROR("%s: can't get record offset, idx:%d, "
			       "len:%u.\n", o->do_lu.lo_dev->ld_obd->obd_name,
			       idx, rec->lrh_len);
			RETURN(-EFAULT);
		}

		/* update only data, header and tail remain the same */
		lgi->lgi_off += sizeof(struct llog_rec_hdr);
		lgi->lgi_buf.lb_len = REC_DATA_LEN(rec);
		lgi->lgi_buf.lb_buf = REC_DATA(rec);
		rc = dt_record_write(env, o, &lgi->lgi_buf, &lgi->lgi_off, th);
		if (rc == 0 && reccookie) {
			reccookie->lgc_lgl = loghandle->lgh_id;
			reccookie->lgc_index = idx;
			rc = 1;
		}
		RETURN(rc);
	}

	/**
	 * The append case.
	 * The most common case of using llog. The new index is assigned to
	 * the new record, new bit is set in llog bitmap and llog count is
	 * incremented.
	 *
	 * Make sure that records don't cross a chunk boundary, so we can
	 * process them page-at-a-time if needed.  If it will cross a chunk
	 * boundary, write in a fake (but referenced) entry to pad the chunk.
	 */


	/* simulate ENOSPC when new plain llog is being added to the
	 * catalog */
	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_LLOG_CREATE_FAILED2) &&
	    llh->llh_flags & LLOG_F_IS_CAT)
		RETURN(-ENOSPC);

	LASSERT(lgi->lgi_attr.la_valid & LA_SIZE);
	orig_last_idx = loghandle->lgh_last_idx;
	lgi->lgi_off = lgi->lgi_attr.la_size;

	if (loghandle->lgh_max_size > 0 &&
	    lgi->lgi_off >= loghandle->lgh_max_size) {
		CDEBUG(D_OTHER, "llog is getting too large (%u > %u) at %u "
		       DFID"\n", (unsigned)lgi->lgi_off,
		       loghandle->lgh_max_size, (int)loghandle->lgh_last_idx,
		       PFID(&loghandle->lgh_id.lgl_oi.oi_fid));
		/* this is to signal that this llog is full */
		loghandle->lgh_last_idx = LLOG_HDR_BITMAP_SIZE(llh) - 1;
		RETURN(-ENOSPC);
	}

	left = chunk_size - (lgi->lgi_off & (chunk_size - 1));
	/* NOTE: padding is a record, but no bit is set */
	if (left != 0 && left != reclen &&
	    left < (reclen + LLOG_MIN_REC_SIZE)) {
		index = loghandle->lgh_last_idx + 1;
		rc = llog_osd_pad(env, o, &lgi->lgi_off, left, index, th);
		if (rc)
			RETURN(rc);

		loghandle->lgh_last_idx++; /* for pad rec */
	}
	/* if it's the last idx in log file, then return -ENOSPC
	 * or wrap around if a catalog */
	if (llog_is_full(loghandle) ||
	    unlikely(llh->llh_flags & LLOG_F_IS_CAT &&
		     OBD_FAIL_PRECHECK(OBD_FAIL_CAT_RECORDS) &&
		     loghandle->lgh_last_idx >= cfs_fail_val)) {
		if (llh->llh_flags & LLOG_F_IS_CAT)
			loghandle->lgh_last_idx = 0;
		else
			RETURN(-ENOSPC);
	}

	down_write(&loghandle->lgh_last_sem);
	/* increment the last_idx along with llh_tail index, they should
	 * be equal for a llog lifetime */
	loghandle->lgh_last_idx++;
	index = loghandle->lgh_last_idx;
	LLOG_HDR_TAIL(llh)->lrt_index = index;
	/**
	 * NB: the caller should make sure only 1 process access
	 * the lgh_last_idx, e.g. append should be exclusive.
	 * Otherwise it might hit the assert.
	 */
	LASSERT(index < LLOG_HDR_BITMAP_SIZE(llh));
	rec->lrh_index = index;
	lrt = rec_tail(rec);
	lrt->lrt_len = rec->lrh_len;
	lrt->lrt_index = rec->lrh_index;

	/* the lgh_hdr_mutex protects llog header data from concurrent
	 * update/cancel, the llh_count and llh_bitmap are protected */
	mutex_lock(&loghandle->lgh_hdr_mutex);
	if (__test_and_set_bit_le(index, LLOG_HDR_BITMAP(llh))) {
		CERROR("%s: index %u already set in llog bitmap "DFID"\n",
		       o->do_lu.lo_dev->ld_obd->obd_name, index,
		       PFID(lu_object_fid(&o->do_lu)));
		mutex_unlock(&loghandle->lgh_hdr_mutex);
		LBUG(); /* should never happen */
	}
	llh->llh_count++;

	if (!(llh->llh_flags & LLOG_F_IS_FIXSIZE)) {
		/* Update the minimum size of the llog record */
		if (llh->llh_size == 0)
			llh->llh_size = reclen;
		else if (reclen < llh->llh_size)
			llh->llh_size = reclen;
	}

	if (lgi->lgi_attr.la_size == 0) {
		lgi->lgi_off = 0;
		lgi->lgi_buf.lb_len = llh->llh_hdr.lrh_len;
		lgi->lgi_buf.lb_buf = &llh->llh_hdr;
		rc = dt_record_write(env, o, &lgi->lgi_buf, &lgi->lgi_off, th);
		if (rc != 0)
			GOTO(out_unlock, rc);
	} else {
		__u32	*bitmap = LLOG_HDR_BITMAP(llh);

		/* Note: If this is not initialization (size == 0), then do not
		 * write the whole header (8k bytes), only update header/tail
		 * and bits needs to be updated. Because this update might be
		 * part of cross-MDT operation, which needs to write these
		 * updates into the update log(32KB limit) and also pack inside
		 * the RPC (1MB limit), if we write 8K for each operation, which
		 * will cost a lot space, and keep us adding more updates to one
		 * update log.*/
		lgi->lgi_off = 0;
		lgi->lgi_buf.lb_len = llh->llh_bitmap_offset;
		lgi->lgi_buf.lb_buf = &llh->llh_hdr;
		rc = dt_record_write(env, o, &lgi->lgi_buf, &lgi->lgi_off, th);
		if (rc != 0)
			GOTO(out_unlock, rc);

		lgi->lgi_off = llh->llh_bitmap_offset +
			      (index / (sizeof(*bitmap) * 8)) * sizeof(*bitmap);
		lgi->lgi_buf.lb_len = sizeof(*bitmap);
		lgi->lgi_buf.lb_buf = &bitmap[index/(sizeof(*bitmap)*8)];
		rc = dt_record_write(env, o, &lgi->lgi_buf, &lgi->lgi_off, th);
		if (rc != 0)
			GOTO(out_unlock, rc);

		lgi->lgi_off =  (unsigned long)LLOG_HDR_TAIL(llh) -
				(unsigned long)llh;
		lgi->lgi_buf.lb_len = sizeof(llh->llh_tail);
		lgi->lgi_buf.lb_buf = LLOG_HDR_TAIL(llh);
		rc = dt_record_write(env, o, &lgi->lgi_buf, &lgi->lgi_off, th);
		if (rc != 0)
			GOTO(out_unlock, rc);
	}

out_unlock:
	/* unlock here for remote object */
	mutex_unlock(&loghandle->lgh_hdr_mutex);
	if (rc)
		GOTO(out, rc);

	if (OBD_FAIL_PRECHECK(OBD_FAIL_LLOG_PROCESS_TIMEOUT) &&
	   cfs_fail_val == (unsigned int)(loghandle->lgh_id.lgl_oi.oi.oi_id &
					  0xFFFFFFFF)) {
		OBD_RACE(OBD_FAIL_LLOG_PROCESS_TIMEOUT);
		msleep(1 * MSEC_PER_SEC);
	}
	/* computed index can be used to determine offset for fixed-size
	 * records. This also allows to handle Catalog wrap around case */
	if (llh->llh_flags & LLOG_F_IS_FIXSIZE) {
		lgi->lgi_off = llh->llh_hdr.lrh_len + (index - 1) * reclen;
	} else {
		rc = dt_attr_get(env, o, &lgi->lgi_attr);
		if (rc)
			GOTO(out, rc);

		LASSERT(lgi->lgi_attr.la_valid & LA_SIZE);
		lgi->lgi_off = max_t(__u64, lgi->lgi_attr.la_size,
				     lgi->lgi_off);
	}

	lgi->lgi_buf.lb_len = reclen;
	lgi->lgi_buf.lb_buf = rec;
	rc = dt_record_write(env, o, &lgi->lgi_buf, &lgi->lgi_off, th);
	if (rc < 0)
		GOTO(out, rc);

	up_write(&loghandle->lgh_last_sem);

	CDEBUG(D_HA, "added record "DFID".%u, %u off%llu\n",
	       PFID(lu_object_fid(&o->do_lu)), index, rec->lrh_len,
	       lgi->lgi_off);
	if (reccookie != NULL) {
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
	RETURN(rc);
out:
	/* cleanup llog for error case */
	mutex_lock(&loghandle->lgh_hdr_mutex);
	clear_bit_le(index, LLOG_HDR_BITMAP(llh));
	llh->llh_count--;
	mutex_unlock(&loghandle->lgh_hdr_mutex);

	/* restore llog last_idx */
	if (dt_object_remote(o)) {
		loghandle->lgh_last_idx = orig_last_idx;
	} else if (--loghandle->lgh_last_idx == 0 &&
	    (llh->llh_flags & LLOG_F_IS_CAT) && llh->llh_cat_idx != 0) {
		/* catalog had just wrap-around case */
		loghandle->lgh_last_idx = LLOG_HDR_BITMAP_SIZE(llh) - 1;
	}

	LLOG_HDR_TAIL(llh)->lrt_index = loghandle->lgh_last_idx;
	up_write(&loghandle->lgh_last_sem);

	RETURN(rc);
}

/**
 * We can skip reading at least as many log blocks as the number of
 * minimum sized log records we are skipping.  If it turns out
 * that we are not far enough along the log (because the
 * actual records are larger than minimum size) we just skip
 * some more records.
 *
 * Note: in llog_process_thread, it will use bitmap offset as
 * the index to locate the record, which also includs some pad
 * records, whose record size is very small, and it also does not
 * consider pad record when recording minimum record size (otherwise
 * min_record size might be too small), so in some rare cases,
 * it might skip too much record for @goal, see llog_osd_next_block().
 *
 * When force_mini_rec is true, it means we have to use LLOG_MIN_REC_SIZE
 * as the min record size to skip over, usually because in the previous
 * try, it skip too much record, see loog_osd_next(prev)_block().
 */
static inline void llog_skip_over(struct llog_handle *lgh, __u64 *off,
				  int curr, int goal, __u32 chunk_size,
				  bool force_mini_rec)
{
	struct llog_log_hdr *llh = lgh->lgh_hdr;

	/* Goal should not bigger than the record count */
	if (goal > lgh->lgh_last_idx)
		goal = lgh->lgh_last_idx;

	if (goal > curr) {
		if (llh->llh_flags & LLOG_F_IS_FIXSIZE) {
			*off = chunk_size + (goal - 1) * llh->llh_size;
		} else {
			__u64 min_rec_size = LLOG_MIN_REC_SIZE;

			if (llh->llh_size > 0 && !force_mini_rec)
				min_rec_size = llh->llh_size;

			*off = *off + (goal - curr - 1) * min_rec_size;
		}
	}
	/* always align with lower chunk boundary*/
	*off &= ~(chunk_size - 1);
}

/**
 * Remove optional fields that the client doesn't expect.
 * This is typically in order to ensure compatibility with older clients.
 * It is assumed that since we exclusively remove fields, the block will be
 * big enough to handle the remapped records. It is also assumed that records
 * of a block have the same format (i.e.: the same features enabled).
 *
 * \param[in,out]    hdr	   Header of the block of records to remap.
 * \param[in,out]    last_hdr      Last header, don't read past this point.
 * \param[in]        flags	   Flags describing the fields to keep.
 * \param[in]        extra_flags   Flags describing the extra fields to keep.
 */
static void changelog_block_trim_ext(struct llog_rec_hdr *hdr,
				     struct llog_rec_hdr *last_hdr,
				     struct llog_handle *loghandle)
{
	enum changelog_rec_flags flags = CLF_SUPPORTED;
	enum changelog_rec_extra_flags extra_flags = CLFE_SUPPORTED;

	if (!(loghandle->lgh_hdr->llh_flags & LLOG_F_EXT_X_XATTR))
		extra_flags &= ~CLFE_XATTR;
	if (!(loghandle->lgh_hdr->llh_flags & LLOG_F_EXT_X_OMODE))
		extra_flags &= ~CLFE_OPEN;
	if (!(loghandle->lgh_hdr->llh_flags & LLOG_F_EXT_X_NID))
		extra_flags &= ~CLFE_NID;
	if (!(loghandle->lgh_hdr->llh_flags & LLOG_F_EXT_X_UIDGID))
		extra_flags &= ~CLFE_UIDGID;
	if (!(loghandle->lgh_hdr->llh_flags & LLOG_F_EXT_EXTRA_FLAGS))
		flags &= ~CLF_EXTRA_FLAGS;
	if (!(loghandle->lgh_hdr->llh_flags & LLOG_F_EXT_JOBID))
		flags &= ~CLF_JOBID;

	if (flags == CLF_SUPPORTED && extra_flags == CLFE_SUPPORTED)
		return;

	if (hdr->lrh_type != CHANGELOG_REC)
		return;

	do {
		struct changelog_rec *rec = (struct changelog_rec *)(hdr + 1);
		enum changelog_rec_extra_flags xflag = CLFE_INVALID;

		if (flags & CLF_EXTRA_FLAGS &&
		    rec->cr_flags & CLF_EXTRA_FLAGS) {
			xflag = changelog_rec_extra_flags(rec)->cr_extra_flags &
				extra_flags;
		}

		if (unlikely(hdr->lrh_len == 0)) {
			/* It is corruption case, we cannot know the next rec,
			 * jump to the last one directly to avoid dead loop. */
			LCONSOLE(D_WARNING, "Hit invalid llog record: "
				 "idx %u, type %u, id %u\n",
				 hdr->lrh_index, hdr->lrh_type, hdr->lrh_id);
			hdr = llog_rec_hdr_next(last_hdr);
			if (unlikely(hdr == last_hdr))
				LCONSOLE(D_WARNING, "The last record crashed: "
					 "idx %u, type %u, id %u\n",
					 hdr->lrh_index, hdr->lrh_type,
					 hdr->lrh_id);
			break;
		}

		changelog_remap_rec(rec, rec->cr_flags & flags, xflag);
		hdr = llog_rec_hdr_next(hdr);
		/* Yield CPU to avoid soft-lockup if there are too many records
		 * to be handled. */
		cond_resched();
	} while ((char *)hdr <= (char *)last_hdr);
}

/**
 * Implementation of the llog_operations::lop_next_block
 *
 * This function finds the the next llog block to return which contains
 * record with required index. It is main part of llog processing.
 *
 * \param[in]     env		execution environment
 * \param[in]     loghandle	llog handle of the current llog
 * \param[in,out] cur_idx	index preceeding cur_offset
 * \param[in]     next_idx	target index to find
 * \param[in,out] cur_offset	furtherst point read in the file
 * \param[in]     buf		pointer to data buffer to fill
 * \param[in]     len		required len to read, it is
 *				usually llog chunk_size.
 *
 * \retval			0 on successful buffer read
 * \retval			negative value on error
 */
static int llog_osd_next_block(const struct lu_env *env,
			       struct llog_handle *loghandle, int *cur_idx,
			       int next_idx, __u64 *cur_offset, void *buf,
			       int len)
{
	struct llog_thread_info	*lgi = llog_info(env);
	struct dt_object	*o;
	struct dt_device	*dt;
	int			 rc;
	__u32			chunk_size;
	int last_idx = *cur_idx;
	__u64 last_offset = *cur_offset;
	bool force_mini_rec = false;

	ENTRY;

	LASSERT(env);
	LASSERT(lgi);

	chunk_size = loghandle->lgh_hdr->llh_hdr.lrh_len;
	if (len == 0 || len & (chunk_size - 1))
		RETURN(-EINVAL);

	LASSERT(loghandle);
	LASSERT(loghandle->lgh_ctxt);

	o = loghandle->lgh_obj;
	LASSERT(o);
	LASSERT(llog_osd_exist(loghandle));
	dt = lu2dt_dev(o->do_lu.lo_dev);
	LASSERT(dt);

	rc = dt_attr_get(env, o, &lgi->lgi_attr);
	if (rc)
		GOTO(out, rc);

	CDEBUG(D_OTHER,
	       "looking for log index %u (cur idx %u off %llu), size %llu\n",
	       next_idx, *cur_idx,
	       *cur_offset, lgi->lgi_attr.la_size);

	while (*cur_offset < lgi->lgi_attr.la_size) {
		struct llog_rec_hdr	*rec, *last_rec;
		struct llog_rec_tail	*tail;

		llog_skip_over(loghandle, cur_offset, *cur_idx,
			       next_idx, chunk_size, force_mini_rec);

		/* read up to next llog chunk_size block */
		lgi->lgi_buf.lb_len = chunk_size -
				      (*cur_offset & (chunk_size - 1));
		lgi->lgi_buf.lb_buf = buf;

		rc = dt_read(env, o, &lgi->lgi_buf, cur_offset);
		if (rc < 0) {
			if (rc == -EBADR && !force_mini_rec)
				goto retry;

			CERROR("%s: can't read llog block from log "DFID
			       " offset %llu: rc = %d\n",
			       o->do_lu.lo_dev->ld_obd->obd_name,
			       PFID(lu_object_fid(&o->do_lu)), *cur_offset,
			       rc);
			GOTO(out, rc);
		}

		if (rc < len) {
			/* signal the end of the valid buffer to
			 * llog_process */
			memset(buf + rc, 0, len - rc);
		}

		if (rc == 0) { /* end of file, nothing to do */
			if (!force_mini_rec)
				goto retry;
			GOTO(out, rc);
		}

		if (rc < sizeof(*tail)) {
			if (!force_mini_rec)
				goto retry;

			CERROR("%s: invalid llog block at log id "DFID":%x "
			       "offset %llu\n",
			       o->do_lu.lo_dev->ld_obd->obd_name,
			       PFID(&loghandle->lgh_id.lgl_oi.oi_fid),
			       loghandle->lgh_id.lgl_ogen, *cur_offset);
			GOTO(out, rc = -EINVAL);
		}

		rec = buf;
		if (LLOG_REC_HDR_NEEDS_SWABBING(rec))
			lustre_swab_llog_rec(rec);
		tail = (struct llog_rec_tail *)((char *)buf + rc -
						sizeof(struct llog_rec_tail));

		if (llog_verify_record(loghandle, rec)) {
			/*
			 * the block seems corrupted. make a pad record so the
			 * caller can skip the block and try with the next one
			 */
			rec->lrh_len = rc;
			rec->lrh_index = next_idx;
			rec->lrh_type = LLOG_PAD_MAGIC;

			tail = rec_tail(rec);
			tail->lrt_len = rc;
			tail->lrt_index = next_idx;

			GOTO(out, rc = 0);
		}

		/* get the last record in block */
		last_rec = (struct llog_rec_hdr *)((char *)buf + rc -
						   tail->lrt_len);

		if (LLOG_REC_HDR_NEEDS_SWABBING(last_rec))
			lustre_swab_llog_rec(last_rec);

		if (last_rec->lrh_index != tail->lrt_index) {
			CERROR("%s: invalid llog tail at log id "DFID":%x offset %llu last_rec idx %u tail idx %u lrt len %u read_size %d\n",
			       o->do_lu.lo_dev->ld_obd->obd_name,
			       PFID(&loghandle->lgh_id.lgl_oi.oi_fid),
			       loghandle->lgh_id.lgl_ogen, *cur_offset,
			       last_rec->lrh_index, tail->lrt_index,
			       tail->lrt_len, rc);
			GOTO(out, rc = -EINVAL);
		}

		*cur_idx = tail->lrt_index;

		/* this shouldn't happen */
		if (tail->lrt_index == 0) {
			CERROR("%s: invalid llog tail at log id "DFID":%x "
			       "offset %llu bytes %d\n",
			       o->do_lu.lo_dev->ld_obd->obd_name,
			       PFID(&loghandle->lgh_id.lgl_oi.oi_fid),
			       loghandle->lgh_id.lgl_ogen, *cur_offset, rc);
			GOTO(out, rc = -EINVAL);
		}
		if (tail->lrt_index < next_idx) {
			last_idx = *cur_idx;
			last_offset = *cur_offset;
			continue;
		}

		/* sanity check that the start of the new buffer is no farther
		 * than the record that we wanted.  This shouldn't happen. */
		if (next_idx && rec->lrh_index > next_idx) {
			if (!force_mini_rec && next_idx > last_idx)
				goto retry;

			CERROR("%s: missed desired record? %u > %u\n",
			       o->do_lu.lo_dev->ld_obd->obd_name,
			       rec->lrh_index, next_idx);
			GOTO(out, rc = -ENOENT);
		}

		/* Trim unsupported extensions for compat w/ older clients */
		changelog_block_trim_ext(rec, last_rec, loghandle);

		GOTO(out, rc = 0);

retry:
		/* Note: because there are some pad records in the
		 * llog, so llog_skip_over() might skip too much
		 * records, let's try skip again with minimum record */
		force_mini_rec = true;
		*cur_offset = last_offset;
		*cur_idx = last_idx;
	}
	GOTO(out, rc = -EIO);
out:
	return rc;
}

/**
 * Implementation of the llog_operations::lop_prev_block
 *
 * This function finds the llog block to return which contains
 * record with required index but in reverse order - from end of llog
 * to the beginning.
 * It is main part of reverse llog processing.
 *
 * \param[in] env	execution environment
 * \param[in] loghandle	llog handle of the current llog
 * \param[in] prev_idx	target index to find
 * \param[in] buf	pointer to data buffer to fill
 * \param[in] len	required len to read, it is llog_chunk_size usually.
 *
 * \retval		0 on successful buffer read
 * \retval		negative value on error
 */
static int llog_osd_prev_block(const struct lu_env *env,
			       struct llog_handle *loghandle,
			       int prev_idx, void *buf, int len)
{
	struct llog_thread_info	*lgi = llog_info(env);
	struct dt_object	*o;
	struct dt_device	*dt;
	loff_t			 cur_offset;
	__u32			chunk_size;
	int			 rc;

	ENTRY;

	chunk_size = loghandle->lgh_hdr->llh_hdr.lrh_len;
	if (len == 0 || len & (chunk_size - 1))
		RETURN(-EINVAL);

	CDEBUG(D_OTHER, "looking for log index %u\n", prev_idx);

	LASSERT(loghandle);
	LASSERT(loghandle->lgh_ctxt);

	o = loghandle->lgh_obj;
	LASSERT(o);
	LASSERT(llog_osd_exist(loghandle));
	dt = lu2dt_dev(o->do_lu.lo_dev);
	LASSERT(dt);

	/* Let's only use mini record size for previous block read
	 * for now XXX */
	cur_offset = chunk_size;
	llog_skip_over(loghandle, &cur_offset, 0, prev_idx,
		       chunk_size, true);

	rc = dt_attr_get(env, o, &lgi->lgi_attr);
	if (rc)
		GOTO(out, rc);

	while (cur_offset < lgi->lgi_attr.la_size) {
		struct llog_rec_hdr	*rec, *last_rec;
		struct llog_rec_tail	*tail;

		lgi->lgi_buf.lb_len = len;
		lgi->lgi_buf.lb_buf = buf;
		rc = dt_read(env, o, &lgi->lgi_buf, &cur_offset);
		if (rc < 0) {
			CERROR("%s: can't read llog block from log "DFID
			       " offset %llu: rc = %d\n",
			       o->do_lu.lo_dev->ld_obd->obd_name,
			       PFID(lu_object_fid(&o->do_lu)), cur_offset, rc);
			GOTO(out, rc);
		}

		if (rc == 0) /* end of file, nothing to do */
			GOTO(out, rc);

		if (rc < sizeof(*tail)) {
			CERROR("%s: invalid llog block at log id "DFID":%x "
			       "offset %llu\n",
			       o->do_lu.lo_dev->ld_obd->obd_name,
			       PFID(&loghandle->lgh_id.lgl_oi.oi_fid),
			       loghandle->lgh_id.lgl_ogen, cur_offset);
			GOTO(out, rc = -EINVAL);
		}

		rec = buf;
		if (LLOG_REC_HDR_NEEDS_SWABBING(rec))
			lustre_swab_llog_rec(rec);

		tail = (struct llog_rec_tail *)((char *)buf + rc -
						sizeof(struct llog_rec_tail));
		/* get the last record in block */
		last_rec = (struct llog_rec_hdr *)((char *)buf + rc -
						   le32_to_cpu(tail->lrt_len));

		if (LLOG_REC_HDR_NEEDS_SWABBING(last_rec))
			lustre_swab_llog_rec(last_rec);
		LASSERT(last_rec->lrh_index == tail->lrt_index);

		/* this shouldn't happen */
		if (tail->lrt_index == 0) {
			CERROR("%s: invalid llog tail at log id "DFID":%x "
			       "offset %llu\n",
			       o->do_lu.lo_dev->ld_obd->obd_name,
			       PFID(&loghandle->lgh_id.lgl_oi.oi_fid),
			       loghandle->lgh_id.lgl_ogen, cur_offset);
			GOTO(out, rc = -EINVAL);
		}
		if (tail->lrt_index < prev_idx)
			continue;

		/* sanity check that the start of the new buffer is no farther
		 * than the record that we wanted.  This shouldn't happen. */
		if (rec->lrh_index > prev_idx) {
			CERROR("%s: missed desired record? %u > %u\n",
			       o->do_lu.lo_dev->ld_obd->obd_name,
			       rec->lrh_index, prev_idx);
			GOTO(out, rc = -ENOENT);
		}

		/* Trim unsupported extensions for compat w/ older clients */
		changelog_block_trim_ext(rec, last_rec, loghandle);

		GOTO(out, rc = 0);
	}
	GOTO(out, rc = -EIO);
out:
	return rc;
}

/**
 * This is helper function to get llog directory object. It is used by named
 * llog operations to find/insert/delete llog entry from llog directory.
 *
 * \param[in] env	execution environment
 * \param[in] ctxt	llog context
 *
 * \retval		dt_object of llog directory
 * \retval		ERR_PTR of negative value on error
 */
static struct dt_object *llog_osd_dir_get(const struct lu_env *env,
					  struct llog_ctxt *ctxt)
{
	struct dt_device	*dt;
	struct dt_thread_info	*dti = dt_info(env);
	struct dt_object	*dir;
	int			 rc;

	dt = ctxt->loc_exp->exp_obd->obd_lvfs_ctxt.dt;
	if (ctxt->loc_dir == NULL) {
		rc = dt_root_get(env, dt, &dti->dti_fid);
		if (rc)
			return ERR_PTR(rc);
		dir = dt_locate(env, dt, &dti->dti_fid);

		if (!IS_ERR(dir) && !dt_try_as_dir(env, dir)) {
			dt_object_put(env, dir);
			return ERR_PTR(-ENOTDIR);
		}
	} else {
		lu_object_get(&ctxt->loc_dir->do_lu);
		dir = ctxt->loc_dir;
	}

	return dir;
}

/**
 * Implementation of the llog_operations::lop_open
 *
 * This function opens the llog by its logid or by name, it may open also
 * non existent llog and assing then new id to it.
 * The llog_open/llog_close pair works similar to lu_object_find/put,
 * the object may not exist prior open. The result of open is just dt_object
 * in the llog header.
 *
 * \param[in] env		execution environment
 * \param[in] handle		llog handle of the current llog
 * \param[in] logid		logid of llog to open (nameless llog)
 * \param[in] name		name of llog to open (named llog)
 * \param[in] open_param
 *				LLOG_OPEN_NEW - new llog, may not exist
 *				LLOG_OPEN_EXIST - old llog, must exist
 *
 * \retval			0 on successful open, llog_handle::lgh_obj
 *				contains the dt_object of the llog.
 * \retval			negative value on error
 */
static int llog_osd_open(const struct lu_env *env, struct llog_handle *handle,
			 struct llog_logid *logid, char *name,
			 enum llog_open_param open_param)
{
	struct llog_thread_info		*lgi = llog_info(env);
	struct llog_ctxt		*ctxt = handle->lgh_ctxt;
	struct dt_object		*o;
	struct dt_device		*dt;
	struct ls_device		*ls;
	struct local_oid_storage	*los = NULL;
	int				 rc = 0;
	bool new_id = false;

	ENTRY;

	LASSERT(env);
	LASSERT(ctxt);
	LASSERT(ctxt->loc_exp);
	LASSERT(ctxt->loc_exp->exp_obd);
	dt = ctxt->loc_exp->exp_obd->obd_lvfs_ctxt.dt;
	LASSERT(dt);
	if (ctxt->loc_flags & LLOG_CTXT_FLAG_NORMAL_FID) {
		struct lu_object_conf conf = { 0 };
		if (logid != NULL) {
			logid_to_fid(logid, &lgi->lgi_fid);
		} else {
			/* If logid == NULL, then it means the caller needs
			 * to allocate new FID (llog_cat_declare_add_rec()). */
			rc = dt_fid_alloc(env, dt, &lgi->lgi_fid, NULL, NULL);
			if (rc < 0)
				RETURN(rc);
			rc = 0;
			conf.loc_flags = LOC_F_NEW;
		}

		o = dt_locate_at(env, dt, &lgi->lgi_fid,
				 dt->dd_lu_dev.ld_site->ls_top_dev, &conf);
		if (IS_ERR(o))
			RETURN(PTR_ERR(o));

		goto after_open;
	}

	ls = ls_device_get(dt);
	if (IS_ERR(ls))
		RETURN(PTR_ERR(ls));

	mutex_lock(&ls->ls_los_mutex);
	los = dt_los_find(ls, name != NULL ? FID_SEQ_LLOG_NAME : FID_SEQ_LLOG);
	mutex_unlock(&ls->ls_los_mutex);
	LASSERT(los);
	ls_device_put(env, ls);

	LASSERT(handle);

	if (logid != NULL) {
		logid_to_fid(logid, &lgi->lgi_fid);
	} else if (name) {
		struct dt_object *llog_dir;

		llog_dir = llog_osd_dir_get(env, ctxt);
		if (IS_ERR(llog_dir))
			GOTO(out, rc = PTR_ERR(llog_dir));
		dt_read_lock(env, llog_dir, 0);
		rc = dt_lookup_dir(env, llog_dir, name, &lgi->lgi_fid);
		dt_read_unlock(env, llog_dir);
		dt_object_put(env, llog_dir);
		if (rc == -ENOENT && open_param == LLOG_OPEN_NEW) {
			/* generate fid for new llog */
			rc = local_object_fid_generate(env, los,
						       &lgi->lgi_fid);
			new_id = true;
		}
		if (rc < 0)
			GOTO(out, rc);
		OBD_ALLOC(handle->lgh_name, strlen(name) + 1);
		if (handle->lgh_name)
			strcpy(handle->lgh_name, name);
		else
			GOTO(out, rc = -ENOMEM);
	} else {
		LASSERTF(open_param & LLOG_OPEN_NEW, "%#x\n", open_param);
		/* generate fid for new llog */
generate:
		rc = local_object_fid_generate(env, los, &lgi->lgi_fid);
		if (rc < 0)
			GOTO(out, rc);
		new_id = true;
	}
	if (OBD_FAIL_PRECHECK(OBD_FAIL_MDS_LLOG_UMOUNT_RACE) &&
	    cfs_fail_val == 1) {
		cfs_fail_val = 2;
		OBD_RACE(OBD_FAIL_MDS_LLOG_UMOUNT_RACE);
		msleep(MSEC_PER_SEC);
	}
	o = ls_locate(env, ls, &lgi->lgi_fid, NULL);
	if (IS_ERR(o))
		GOTO(out_name, rc = PTR_ERR(o));

	if (dt_object_exists(o) && new_id) {
		/* llog exists with just generated ID, e.g. some old llog file
		 * still is in use or is orphan, drop a warn and skip it. */
		CDEBUG(D_INFO, "%s: llog exists with the same FID: "DFID
		       ", skipping\n",
		       o->do_lu.lo_dev->ld_obd->obd_name,
		       PFID(lu_object_fid(&o->do_lu)));
		dt_object_put(env, o);
		/* just skip this llog ID, we shouldn't delete it because we
		 * don't know exactly what is its purpose and state. */
		goto generate;
	}

after_open:
	/* No new llog is expected but doesn't exist */
	if (open_param != LLOG_OPEN_NEW && !dt_object_exists(o)) {
		CDEBUG(D_INFO, "%s: llog FID: "DFID" obj %p doesn`t exist\n",
		       o->do_lu.lo_dev->ld_obd->obd_name,
		       PFID(lu_object_fid(&o->do_lu)), o);
		GOTO(out_put, rc = -ENOENT);
	}
	fid_to_logid(&lgi->lgi_fid, &handle->lgh_id);
	handle->lgh_obj = o;
	handle->private_data = los;
	LASSERT(handle->lgh_ctxt);

	RETURN(rc);

out_put:
	dt_object_put(env, o);
out_name:
	if (handle->lgh_name != NULL)
		OBD_FREE(handle->lgh_name, strlen(name) + 1);
out:
	if (los != NULL)
		dt_los_put(los);
	RETURN(rc);
}

/**
 * Get dir for regular fid log object
 *
 * Get directory for regular fid log object, and these regular fid log
 * object will be inserted under this directory, to satisfy the FS
 * consistency check, e2fsck etc.
 *
 * \param [in] env	execution environment
 * \param [in] dto	llog object
 *
 * \retval		pointer to the directory if it is found.
 * \retval		ERR_PTR(negative errno) if it fails.
 */
struct dt_object *llog_osd_get_regular_fid_dir(const struct lu_env *env,
					       struct dt_object *dto)
{
	struct llog_thread_info *lgi = llog_info(env);
	struct seq_server_site *ss = dto->do_lu.lo_dev->ld_site->ld_seq_site;
	struct lu_seq_range	*range = &lgi->lgi_range;
	struct lu_fid		*dir_fid = &lgi->lgi_fid;
	struct dt_object	*dir;
	int			rc;
	ENTRY;

	fld_range_set_any(range);
	LASSERT(ss != NULL);
	rc = ss->ss_server_fld->lsf_seq_lookup(env, ss->ss_server_fld,
				   fid_seq(lu_object_fid(&dto->do_lu)), range);
	if (rc < 0)
		RETURN(ERR_PTR(rc));

	lu_update_log_dir_fid(dir_fid, range->lsr_index);
	dir = dt_locate(env, lu2dt_dev(dto->do_lu.lo_dev), dir_fid);
	if (IS_ERR(dir))
		RETURN(dir);

	if (!dt_try_as_dir(env, dir)) {
		dt_object_put(env, dir);
		RETURN(ERR_PTR(-ENOTDIR));
	}

	RETURN(dir);
}

/**
 * Add llog object with regular FID to name entry
 *
 * Add llog object with regular FID to name space, and each llog
 * object on each MDT will be /update_log_dir/[seq:oid:ver],
 * so to satisfy the namespace consistency check, e2fsck etc.
 *
 * \param [in] env	execution environment
 * \param [in] dto	llog object
 * \param [in] th	thandle
 * \param [in] declare	if it is declare or execution
 *
 * \retval		0 if insertion succeeds.
 * \retval		negative errno if insertion fails.
 */
static int
llog_osd_regular_fid_add_name_entry(const struct lu_env *env,
				    struct dt_object *dto,
				    struct thandle *th, bool declare)
{
	struct llog_thread_info *lgi = llog_info(env);
	const struct lu_fid	*fid = lu_object_fid(&dto->do_lu);
	struct dt_insert_rec	*rec = &lgi->lgi_dt_rec;
	struct dt_object	*dir;
	char			*name = lgi->lgi_name;
	int			rc;
	ENTRY;

	if (!fid_is_norm(fid))
		RETURN(0);

	dir = llog_osd_get_regular_fid_dir(env, dto);
	if (IS_ERR(dir))
		RETURN(PTR_ERR(dir));

	rec->rec_fid = fid;
	rec->rec_type = S_IFREG;
	snprintf(name, sizeof(lgi->lgi_name), DFID, PFID(fid));
	dt_write_lock(env, dir, 0);
	if (declare) {
		rc = dt_declare_insert(env, dir, (struct dt_rec *)rec,
			       (struct dt_key *)name, th);
	} else {
		rc = dt_insert(env, dir, (struct dt_rec *)rec,
			       (struct dt_key *)name, th);
	}
	dt_write_unlock(env, dir);

	dt_object_put(env, dir);
	RETURN(rc);
}


/**
 * Implementation of the llog_operations::lop_declare_create
 *
 * This function declares the llog create. It declares also name insert
 * into llog directory in case of named llog.
 *
 * \param[in] env	execution environment
 * \param[in] res	llog handle of the current llog
 * \param[in] th	current transaction handle
 *
 * \retval		0 on successful create declaration
 * \retval		negative value on error
 */
static int llog_osd_declare_create(const struct lu_env *env,
				   struct llog_handle *res, struct thandle *th)
{
	struct llog_thread_info		*lgi = llog_info(env);
	struct dt_insert_rec		*rec = &lgi->lgi_dt_rec;
	struct local_oid_storage	*los;
	struct dt_object		*o;
	int				 rc;

	ENTRY;

	LASSERT(res->lgh_obj);
	LASSERT(th);

	/* object can be created by another thread */
	o = res->lgh_obj;
	if (dt_object_exists(o))
		RETURN(0);

	if (res->lgh_ctxt->loc_flags & LLOG_CTXT_FLAG_NORMAL_FID) {
		struct llog_thread_info *lgi = llog_info(env);

		lgi->lgi_attr.la_valid = LA_MODE | LA_SIZE;
		lgi->lgi_attr.la_size = 0;
		lgi->lgi_attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
		lgi->lgi_dof.dof_type = dt_mode_to_dft(S_IFREG);

		rc = dt_declare_create(env, o, &lgi->lgi_attr, NULL,
				       &lgi->lgi_dof, th);
		if (rc < 0)
			RETURN(rc);


		rc = llog_osd_regular_fid_add_name_entry(env, o, th, true);

		RETURN(rc);
	}
	los = res->private_data;
	LASSERT(los);

	rc = llog_osd_declare_new_object(env, los, o, th);
	if (rc)
		RETURN(rc);

	/* do not declare header initialization here as it's declared
	 * in llog_osd_declare_write_rec() which is always called */

	if (res->lgh_name) {
		struct dt_object *llog_dir;

		llog_dir = llog_osd_dir_get(env, res->lgh_ctxt);
		if (IS_ERR(llog_dir))
			RETURN(PTR_ERR(llog_dir));
		logid_to_fid(&res->lgh_id, &lgi->lgi_fid);
		rec->rec_fid = &lgi->lgi_fid;
		rec->rec_type = S_IFREG;
		rc = dt_declare_insert(env, llog_dir,
				       (struct dt_rec *)rec,
				       (struct dt_key *)res->lgh_name, th);
		dt_object_put(env, llog_dir);
		if (rc)
			CERROR("%s: can't declare named llog %s: rc = %d\n",
			       o->do_lu.lo_dev->ld_obd->obd_name,
			       res->lgh_name, rc);
	}
	RETURN(rc);
}

/**
 * Implementation of the llog_operations::lop_create
 *
 * This function creates the llog according with llog_handle::lgh_obj
 * and llog_handle::lgh_name.
 *
 * \param[in] env	execution environment
 * \param[in] res	llog handle of the current llog
 * \param[in] th	current transaction handle
 *
 * \retval		0 on successful create
 * \retval		negative value on error
 */
static int llog_osd_create(const struct lu_env *env, struct llog_handle *res,
			   struct thandle *th)
{
	struct llog_thread_info *lgi = llog_info(env);
	struct dt_insert_rec	*rec = &lgi->lgi_dt_rec;
	struct local_oid_storage *los;
	struct dt_object        *o;
	int                      rc = 0;

	ENTRY;

	LASSERT(env);
	o = res->lgh_obj;
	LASSERT(o);

	/* llog can be already created */
	if (dt_object_exists(o))
		RETURN(-EEXIST);

	if (res->lgh_ctxt->loc_flags & LLOG_CTXT_FLAG_NORMAL_FID) {
		struct llog_thread_info *lgi = llog_info(env);

		lgi->lgi_attr.la_valid = LA_MODE | LA_SIZE | LA_TYPE;
		lgi->lgi_attr.la_size = 0;
		lgi->lgi_attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
		lgi->lgi_dof.dof_type = dt_mode_to_dft(S_IFREG);

		dt_write_lock(env, o, 0);
		rc = dt_create(env, o, &lgi->lgi_attr, NULL,
			       &lgi->lgi_dof, th);
		dt_write_unlock(env, o);
		if (rc < 0)
			RETURN(rc);

		rc = llog_osd_regular_fid_add_name_entry(env, o, th, false);

		RETURN(rc);
	}

	los = res->private_data;
	LASSERT(los);

	dt_write_lock(env, o, 0);
	if (!dt_object_exists(o))
		rc = llog_osd_create_new_object(env, los, o, th);
	else
		rc = -EEXIST;

	dt_write_unlock(env, o);
	if (rc)
		RETURN(rc);

	if (res->lgh_name) {
		struct dt_object *llog_dir;

		llog_dir = llog_osd_dir_get(env, res->lgh_ctxt);
		if (IS_ERR(llog_dir))
			RETURN(PTR_ERR(llog_dir));

		logid_to_fid(&res->lgh_id, &lgi->lgi_fid);
		rec->rec_fid = &lgi->lgi_fid;
		rec->rec_type = S_IFREG;
		dt_read_lock(env, llog_dir, 0);
		rc = dt_insert(env, llog_dir, (struct dt_rec *)rec,
			       (struct dt_key *)res->lgh_name, th);
		dt_read_unlock(env, llog_dir);
		dt_object_put(env, llog_dir);
		if (rc)
			CERROR("%s: can't create named llog %s: rc = %d\n",
			       o->do_lu.lo_dev->ld_obd->obd_name,
			       res->lgh_name, rc);
	}
	RETURN(rc);
}

/**
 * Implementation of the llog_operations::lop_close
 *
 * This function closes the llog. It just put llog object and referenced
 * local storage.
 *
 * \param[in] env	execution environment
 * \param[in] handle	llog handle of the current llog
 *
 * \retval		0 on successful llog close
 * \retval		negative value on error
 */
static int llog_osd_close(const struct lu_env *env, struct llog_handle *handle)
{
	struct local_oid_storage	*los;
	int				 rc = 0;

	ENTRY;

	LASSERT(handle->lgh_obj);

	if (handle->lgh_ctxt->loc_flags & LLOG_CTXT_FLAG_NORMAL_FID) {
		/* Remove the object from the cache, otherwise it may
		 * hold LOD being released during cleanup process */
		dt_object_put_nocache(env, handle->lgh_obj);
		LASSERT(handle->private_data == NULL);
		RETURN(rc);
	} else {
		dt_object_put(env, handle->lgh_obj);
	}
	los = handle->private_data;
	LASSERT(los);
	dt_los_put(los);

	if (handle->lgh_name)
		OBD_FREE(handle->lgh_name, strlen(handle->lgh_name) + 1);

	RETURN(rc);
}

/**
 * delete llog object name entry
 *
 * Delete llog object (with regular FID) from name space (under
 * update_log_dir).
 *
 * \param [in] env	execution environment
 * \param [in] dto	llog object
 * \param [in] th	thandle
 * \param [in] declare	if it is declare or execution
 *
 * \retval		0 if deletion succeeds.
 * \retval		negative errno if deletion fails.
 */
static int
llog_osd_regular_fid_del_name_entry(const struct lu_env *env,
				    struct dt_object *dto,
				    struct thandle *th, bool declare)
{
	struct llog_thread_info *lgi = llog_info(env);
	const struct lu_fid	*fid = lu_object_fid(&dto->do_lu);
	struct dt_object	*dir;
	char			*name = lgi->lgi_name;
	int			rc;
	ENTRY;

	if (!fid_is_norm(fid))
		RETURN(0);

	dir = llog_osd_get_regular_fid_dir(env, dto);
	if (IS_ERR(dir))
		RETURN(PTR_ERR(dir));

	snprintf(name, sizeof(lgi->lgi_name), DFID, PFID(fid));
	dt_write_lock(env, dir, 0);
	if (declare) {
		rc = dt_declare_delete(env, dir, (struct dt_key *)name,
				       th);
	} else {
		rc = dt_delete(env, dir, (struct dt_key *)name, th);
	}
	dt_write_unlock(env, dir);

	dt_object_put(env, dir);
	RETURN(rc);
}

/**
 * Implementation of the llog_operations::lop_declare_destroy
 *
 * This function declare destroys the llog and deletes also entry in the
 * llog directory in case of named llog. Llog should be opened prior that.
 *
 * \param[in] env		execution environment
 * \param[in] loghandle	llog handle of the current llog
 *
 * \retval		0 on successful destroy
 * \retval		negative value on error
 */
static int llog_osd_declare_destroy(const struct lu_env *env,
				    struct llog_handle *loghandle,
				    struct thandle *th)
{
	struct llog_ctxt	*ctxt;
	struct dt_object	*o, *llog_dir = NULL;
	int			 rc;

	ENTRY;

	ctxt = loghandle->lgh_ctxt;
	LASSERT(ctxt);

	o = loghandle->lgh_obj;
	LASSERT(o);

	if (loghandle->lgh_name) {
		llog_dir = llog_osd_dir_get(env, ctxt);
		if (IS_ERR(llog_dir))
			RETURN(PTR_ERR(llog_dir));

		rc = dt_declare_delete(env, llog_dir,
				       (struct dt_key *)loghandle->lgh_name,
				       th);
		if (rc < 0)
			GOTO(out_put, rc);
	}

	rc = dt_declare_ref_del(env, o, th);
	if (rc < 0)
		GOTO(out_put, rc);

	rc = dt_declare_destroy(env, o, th);
	if (rc < 0)
		GOTO(out_put, rc);

	if (loghandle->lgh_ctxt->loc_flags & LLOG_CTXT_FLAG_NORMAL_FID) {
		rc = llog_osd_regular_fid_del_name_entry(env, o, th, true);
		if (rc < 0)
			GOTO(out_put, rc);
	}

out_put:
	if (!(IS_ERR_OR_NULL(llog_dir)))
		dt_object_put(env, llog_dir);

	RETURN(rc);
}


/**
 * Implementation of the llog_operations::lop_destroy
 *
 * This function destroys the llog and deletes also entry in the
 * llog directory in case of named llog. Llog should be opened prior that.
 * Destroy method is not part of external transaction and does everything
 * inside.
 *
 * \param[in] env		execution environment
 * \param[in] loghandle	llog handle of the current llog
 *
 * \retval		0 on successful destroy
 * \retval		negative value on error
 */
static int llog_osd_destroy(const struct lu_env *env,
			    struct llog_handle *loghandle, struct thandle *th)
{
	struct llog_ctxt	*ctxt;
	struct dt_object	*o, *llog_dir = NULL;
	int			 rc;

	ENTRY;

	ctxt = loghandle->lgh_ctxt;
	LASSERT(ctxt != NULL);

	o = loghandle->lgh_obj;
	LASSERT(o != NULL);

	dt_write_lock(env, o, 0);
	if (!llog_osd_exist(loghandle))
		GOTO(out_unlock, rc = 0);

	if (loghandle->lgh_name) {
		llog_dir = llog_osd_dir_get(env, ctxt);
		if (IS_ERR(llog_dir))
			GOTO(out_unlock, rc = PTR_ERR(llog_dir));

		dt_read_lock(env, llog_dir, 0);
		rc = dt_delete(env, llog_dir,
			       (struct dt_key *)loghandle->lgh_name,
			       th);
		dt_read_unlock(env, llog_dir);
		if (rc) {
			CERROR("%s: can't remove llog %s: rc = %d\n",
			       o->do_lu.lo_dev->ld_obd->obd_name,
			       loghandle->lgh_name, rc);
			GOTO(out_unlock, rc);
		}
	}

	dt_ref_del(env, o, th);
	rc = dt_destroy(env, o, th);
	if (rc < 0)
		GOTO(out_unlock, rc);

	loghandle->lgh_destroyed = true;
	if (loghandle->lgh_ctxt->loc_flags & LLOG_CTXT_FLAG_NORMAL_FID) {
		rc = llog_osd_regular_fid_del_name_entry(env, o, th, false);
		if (rc < 0)
			GOTO(out_unlock, rc);
	}

out_unlock:
	dt_write_unlock(env, o);
	if (!(IS_ERR_OR_NULL(llog_dir)))
		dt_object_put(env, llog_dir);
	RETURN(rc);
}

/**
 * Implementation of the llog_operations::lop_setup
 *
 * This function setup the llog on local storage.
 *
 * \param[in] env	execution environment
 * \param[in] obd	obd device the llog belongs to
 * \param[in] olg	the llog group, it is always zero group now.
 * \param[in] ctxt_idx	the llog index, it defines the purpose of this llog.
 *			Every new llog type have to use own index.
 * \param[in] disk_obd	the storage obd, where llog is stored.
 *
 * \retval		0 on successful llog setup
 * \retval		negative value on error
 */
static int llog_osd_setup(const struct lu_env *env, struct obd_device *obd,
			  struct obd_llog_group *olg, int ctxt_idx,
			  struct obd_device *disk_obd)
{
	struct llog_thread_info		*lgi = llog_info(env);
	struct llog_ctxt		*ctxt;
	int				 rc = 0;
	ENTRY;

	LASSERT(obd);
	LASSERT(olg->olg_ctxts[ctxt_idx]);

	ctxt = llog_ctxt_get(olg->olg_ctxts[ctxt_idx]);
	LASSERT(ctxt);

	if (disk_obd == NULL)
		GOTO(out, rc = 0);

	/* initialize data allowing to generate new fids,
	 * literally we need a sequece */
	lgi->lgi_fid.f_seq = FID_SEQ_LLOG;
	lgi->lgi_fid.f_oid = 1;
	lgi->lgi_fid.f_ver = 0;
	rc = local_oid_storage_init(env, disk_obd->obd_lvfs_ctxt.dt,
				    &lgi->lgi_fid,
				    &ctxt->loc_los_nameless);
	if (rc != 0)
		GOTO(out, rc);

	lgi->lgi_fid.f_seq = FID_SEQ_LLOG_NAME;
	lgi->lgi_fid.f_oid = 1;
	lgi->lgi_fid.f_ver = 0;
	rc = local_oid_storage_init(env, disk_obd->obd_lvfs_ctxt.dt,
				    &lgi->lgi_fid,
				    &ctxt->loc_los_named);
	if (rc != 0) {
		local_oid_storage_fini(env, ctxt->loc_los_nameless);
		ctxt->loc_los_nameless = NULL;
	}

	GOTO(out, rc);

out:
	llog_ctxt_put(ctxt);
	return rc;
}

/**
 * Implementation of the llog_operations::lop_cleanup
 *
 * This function cleanups the llog on local storage.
 *
 * \param[in] env	execution environment
 * \param[in] ctxt	the llog context
 *
 * \retval		0
 */
static int llog_osd_cleanup(const struct lu_env *env, struct llog_ctxt *ctxt)
{
	if (ctxt->loc_los_nameless != NULL) {
		local_oid_storage_fini(env, ctxt->loc_los_nameless);
		ctxt->loc_los_nameless = NULL;
	}

	if (ctxt->loc_los_named != NULL) {
		local_oid_storage_fini(env, ctxt->loc_los_named);
		ctxt->loc_los_named = NULL;
	}

	return 0;
}

const struct llog_operations llog_osd_ops = {
	.lop_next_block		= llog_osd_next_block,
	.lop_prev_block		= llog_osd_prev_block,
	.lop_read_header	= llog_osd_read_header,
	.lop_declare_destroy	= llog_osd_declare_destroy,
	.lop_destroy		= llog_osd_destroy,
	.lop_setup		= llog_osd_setup,
	.lop_cleanup		= llog_osd_cleanup,
	.lop_open		= llog_osd_open,
	.lop_exist		= llog_osd_exist,
	.lop_declare_create	= llog_osd_declare_create,
	.lop_create		= llog_osd_create,
	.lop_declare_write_rec	= llog_osd_declare_write_rec,
	.lop_write_rec		= llog_osd_write_rec,
	.lop_close		= llog_osd_close,
};
EXPORT_SYMBOL(llog_osd_ops);

const struct llog_operations llog_common_cat_ops = {
	.lop_next_block		= llog_osd_next_block,
	.lop_prev_block		= llog_osd_prev_block,
	.lop_read_header	= llog_osd_read_header,
	.lop_declare_destroy	= llog_osd_declare_destroy,
	.lop_destroy		= llog_osd_destroy,
	.lop_setup		= llog_osd_setup,
	.lop_cleanup		= llog_osd_cleanup,
	.lop_open		= llog_osd_open,
	.lop_exist		= llog_osd_exist,
	.lop_declare_create	= llog_osd_declare_create,
	.lop_create		= llog_osd_create,
	.lop_declare_write_rec	= llog_osd_declare_write_rec,
	.lop_write_rec		= llog_osd_write_rec,
	.lop_close		= llog_osd_close,
	.lop_add		= llog_cat_add_rec,
	.lop_declare_add	= llog_cat_declare_add_rec,
};
EXPORT_SYMBOL(llog_common_cat_ops);

/**
 * Read the special file which contains the list of llog catalogs IDs
 *
 * This function reads the CATALOGS file which contains the array of llog
 * catalogs IDs. The main purpose of this file is to store OSP llogs indexed
 * by OST/MDT number.
 *
 * \param[in]  env		execution environment
 * \param[in]  d		corresponding storage device
 * \param[in]  idx		position to start from, usually OST/MDT index
 * \param[in]  count		how many catalog IDs to read
 * \param[out] idarray		the buffer for the data. If it is NULL then
 *				function returns just number of catalog IDs
 *				in the file.
 * \param[in]  fid		LLOG_CATALOGS_OID for CATALOG object
 *
 * \retval			0 on successful read of catalog IDs
 * \retval			negative value on error
 * \retval			positive value which is number of records in
 *				the file if \a idarray is NULL
 */
int llog_osd_get_cat_list(const struct lu_env *env, struct dt_device *d,
			  int idx, int count, struct llog_catid *idarray,
			  const struct lu_fid *fid)
{
	struct llog_thread_info	*lgi = llog_info(env);
	struct dt_object	*o = NULL;
	struct thandle		*th;
	int			 rc, size;

	ENTRY;

	LASSERT(d);

	size = sizeof(*idarray) * count;
	lgi->lgi_off = idx *  sizeof(*idarray);

	lgi->lgi_fid = *fid;
	o = dt_locate(env, d, &lgi->lgi_fid);
	if (IS_ERR(o))
		RETURN(PTR_ERR(o));

	if (!dt_object_exists(o)) {
		th = dt_trans_create(env, d);
		if (IS_ERR(th))
			GOTO(out, rc = PTR_ERR(th));

		lgi->lgi_attr.la_valid = LA_MODE | LA_TYPE;
		lgi->lgi_attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
		lgi->lgi_dof.dof_type = dt_mode_to_dft(S_IFREG);

		th->th_wait_submit = 1;
		/* Make the llog object creation synchronization, so
		 * it will be reliable to the reference, especially
		 * for remote reference */
		th->th_sync = 1;

		rc = dt_declare_create(env, o, &lgi->lgi_attr, NULL,
				       &lgi->lgi_dof, th);
		if (rc)
			GOTO(out_trans, rc);

		rc = dt_trans_start_local(env, d, th);
		if (rc)
			GOTO(out_trans, rc);

		dt_write_lock(env, o, 0);
		if (!dt_object_exists(o))
			rc = dt_create(env, o, &lgi->lgi_attr, NULL,
				       &lgi->lgi_dof, th);
		dt_write_unlock(env, o);
out_trans:
		dt_trans_stop(env, d, th);
		if (rc)
			GOTO(out, rc);
	}

	rc = dt_attr_get(env, o, &lgi->lgi_attr);
	if (rc)
		GOTO(out, rc);

	if (!S_ISREG(lgi->lgi_attr.la_mode)) {
		CERROR("%s: CATALOGS is not a regular file!: mode = %o\n",
		       o->do_lu.lo_dev->ld_obd->obd_name,
		       lgi->lgi_attr.la_mode);
		GOTO(out, rc = -ENOENT);
	}

	CDEBUG(D_CONFIG, "cat list: disk size=%d, read=%d\n",
	       (int)lgi->lgi_attr.la_size, size);

	/* return just number of llogs */
	if (idarray == NULL) {
		rc = lgi->lgi_attr.la_size / sizeof(*idarray);
		GOTO(out, rc);
	}

	/* read for new ost index or for empty file */
	memset(idarray, 0, size);
	if (lgi->lgi_attr.la_size <= lgi->lgi_off)
		GOTO(out, rc = 0);
	if (lgi->lgi_attr.la_size < lgi->lgi_off + size)
		size = lgi->lgi_attr.la_size - lgi->lgi_off;

	lgi->lgi_buf.lb_buf = idarray;
	lgi->lgi_buf.lb_len = size;
	rc = dt_record_read(env, o, &lgi->lgi_buf, &lgi->lgi_off);
	/* -EFAULT means the llog is a sparse file. This is not an error
	 * after arbitrary OST index is supported. */
	if (rc < 0 && rc != -EFAULT) {
		CERROR("%s: error reading CATALOGS: rc = %d\n",
		       o->do_lu.lo_dev->ld_obd->obd_name,  rc);
		GOTO(out, rc);
	}

	EXIT;
out:
	dt_object_put(env, o);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_osd_get_cat_list);

/**
 * Write the special file which contains the list of llog catalogs IDs
 *
 * This function writes the CATALOG file which contains the array of llog
 * catalogs IDs. It is used mostly to store OSP llogs indexed by OST/MDT
 * number.
 *
 * \param[in]  env	execution environment
 * \param[in]  d	corresponding storage device
 * \param[in]  idx	position to start from, usually OST/MDT index
 * \param[in]  count	how many catalog IDs to write
 * \param[out] idarray	the buffer with the data to write.
 * \param[in]  fid	LLOG_CATALOGS_OID for CATALOG object
 *
 * \retval		0 on successful write of catalog IDs
 * \retval		negative value on error
 */
int llog_osd_put_cat_list(const struct lu_env *env, struct dt_device *d,
			  int idx, int count, struct llog_catid *idarray,
			  const struct lu_fid *fid)
{
	struct llog_thread_info	*lgi = llog_info(env);
	struct dt_object	*o = NULL;
	struct thandle		*th;
	int			 rc, size;

	if (count == 0)
		RETURN(0);

	LASSERT(d);

	size = sizeof(*idarray) * count;
	lgi->lgi_off = idx * sizeof(*idarray);
	lgi->lgi_fid = *fid;

	o = dt_locate(env, d, &lgi->lgi_fid);
	if (IS_ERR(o))
		RETURN(PTR_ERR(o));

	if (!dt_object_exists(o))
		GOTO(out, rc = -ENOENT);

	rc = dt_attr_get(env, o, &lgi->lgi_attr);
	if (rc)
		GOTO(out, rc);

	if (!S_ISREG(lgi->lgi_attr.la_mode)) {
		CERROR("%s: CATALOGS is not a regular file!: mode = %o\n",
		       o->do_lu.lo_dev->ld_obd->obd_name,
		       lgi->lgi_attr.la_mode);
		GOTO(out, rc = -ENOENT);
	}

	th = dt_trans_create(env, d);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	lgi->lgi_buf.lb_len = size;
	lgi->lgi_buf.lb_buf = idarray;
	rc = dt_declare_record_write(env, o, &lgi->lgi_buf, lgi->lgi_off, th);
	if (rc)
		GOTO(out_trans, rc);

	/* For update log, this happens during initialization,
	 * see lod_sub_prep_llog(), and we need make sure catlog
	 * file ID is written to catlist file(committed) before
	 * cross-MDT operation write update records to catlog FILE,
	 * otherwise, during failover these update records might
	 * missing */
	if (fid_is_update_log(fid))
		th->th_sync = 1;

	rc = dt_trans_start_local(env, d, th);
	if (rc)
		GOTO(out_trans, rc);

	th->th_wait_submit = 1;

	rc = dt_record_write(env, o, &lgi->lgi_buf, &lgi->lgi_off, th);
	if (rc)
		CDEBUG(D_INODE, "can't write CATALOGS at index %d: rc = %d\n",
		       idx, rc);
out_trans:
	dt_trans_stop(env, d, th);
out:
	dt_object_put(env, o);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_osd_put_cat_list);
