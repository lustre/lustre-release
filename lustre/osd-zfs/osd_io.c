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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/osd-zfs/osd_io.c
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_OSD

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_disk.h>
#include <lustre_fid.h>
#include <lustre_quota.h>

#include "osd_internal.h"

#include <sys/dnode.h>
#include <sys/dbuf.h>
#include <sys/spa.h>
#include <sys/stat.h>
#include <sys/zap.h>
#include <sys/spa_impl.h>
#include <sys/zfs_znode.h>
#include <sys/dmu_tx.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_prop.h>
#include <sys/sa_impl.h>
#include <sys/txg.h>

static char osd_0copy_tag[] = "zerocopy";

static void dbuf_set_pending_evict(dmu_buf_t *db)
{
	dmu_buf_impl_t *dbi = (dmu_buf_impl_t *)db;
	dbi->db_pending_evict = TRUE;
}

static void record_start_io(struct osd_device *osd, int rw, int discont_pages)
{
	struct obd_histogram *h = osd->od_brw_stats.hist;

	if (rw == READ) {
		atomic_inc(&osd->od_r_in_flight);
		lprocfs_oh_tally(&h[BRW_R_RPC_HIST],
				 atomic_read(&osd->od_r_in_flight));
		lprocfs_oh_tally(&h[BRW_R_DISCONT_PAGES], discont_pages);

	} else {
		atomic_inc(&osd->od_w_in_flight);
		lprocfs_oh_tally(&h[BRW_W_RPC_HIST],
				 atomic_read(&osd->od_w_in_flight));
		lprocfs_oh_tally(&h[BRW_W_DISCONT_PAGES], discont_pages);

	}
}

static void record_end_io(struct osd_device *osd, int rw,
			  unsigned long elapsed, int disksize, int npages)
{
	struct obd_histogram *h = osd->od_brw_stats.hist;

	if (rw == READ)
		atomic_dec(&osd->od_r_in_flight);
	else
		atomic_dec(&osd->od_w_in_flight);

	lprocfs_oh_tally_log2(&h[BRW_R_PAGES + rw], npages);
	if (disksize > 0)
		lprocfs_oh_tally_log2(&h[BRW_R_DISK_IOSIZE + rw], disksize);
	if (elapsed)
		lprocfs_oh_tally_log2(&h[BRW_R_IO_TIME + rw], elapsed);
}

static ssize_t __osd_read(const struct lu_env *env, struct dt_object *dt,
			  struct lu_buf *buf, loff_t *pos, size_t *size)
{
	struct osd_object *obj = osd_dt_obj(dt);
	uint64_t old_size;
	int rc;

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_dn);

	read_lock(&obj->oo_attr_lock);
	old_size = obj->oo_attr.la_size;
	read_unlock(&obj->oo_attr_lock);

	if (*pos + *size > old_size) {
		if (old_size < *pos)
			return 0;

		*size = old_size - *pos;
	}

	rc = osd_dmu_read(osd_obj2dev(obj), obj->oo_dn, *pos, *size,
			  buf->lb_buf, DMU_READ_PREFETCH);
	if (!rc) {
		rc = *size;
		*pos += *size;
	}

	return rc;
}

static ssize_t osd_read(const struct lu_env *env, struct dt_object *dt,
			struct lu_buf *buf, loff_t *pos)
{
	struct osd_device *osd = osd_obj2dev(osd_dt_obj(dt));
	size_t size = buf->lb_len;
	hrtime_t start = gethrtime();
	s64 delta_ms;
	int rc;

	record_start_io(osd, READ, 0);
	rc = __osd_read(env, dt, buf, pos, &size);
	delta_ms = gethrtime() - start;
	do_div(delta_ms, NSEC_PER_MSEC);
	record_end_io(osd, READ, delta_ms, size, size >> PAGE_SHIFT);

	return rc;
}

static inline ssize_t osd_read_no_record(const struct lu_env *env,
					 struct dt_object *dt,
					 struct lu_buf *buf, loff_t *pos)
{
	size_t size = buf->lb_len;

	return __osd_read(env, dt, buf, pos, &size);
}

static ssize_t osd_declare_write(const struct lu_env *env, struct dt_object *dt,
				const struct lu_buf *buf, loff_t pos,
				struct thandle *th)
{
	struct osd_object  *obj  = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	struct osd_thandle *oh;
	uint64_t            oid;
	ENTRY;

	oh = container_of(th, struct osd_thandle, ot_super);

	/* in some cases declare can race with creation (e.g. llog)
	 * and we need to wait till object is initialized. notice
	 * LOHA_EXISTs is supposed to be the last step in the
	 * initialization */

	/* size change (in dnode) will be declared by dmu_tx_hold_write() */
	if (dt_object_exists(dt))
		oid = obj->oo_dn->dn_object;
	else
		oid = DMU_NEW_OBJECT;

	/* XXX: we still miss for append declaration support in ZFS
	 *	-1 means append which is used by llog mostly, llog
	 *	can grow upto LLOG_MIN_CHUNK_SIZE*8 records */
	if (pos == -1)
		pos = max_t(loff_t, 256 * 8 * LLOG_MIN_CHUNK_SIZE,
			    obj->oo_attr.la_size + (2 << 20));
	osd_tx_hold_write(oh->ot_tx, oid, obj->oo_dn, pos, buf->lb_len);

	/* dt_declare_write() is usually called for system objects, such
	 * as llog or last_rcvd files. We needn't enforce quota on those
	 * objects, so always set the lqi_space as 0. */
	RETURN(osd_declare_quota(env, osd, obj->oo_attr.la_uid,
				 obj->oo_attr.la_gid, obj->oo_attr.la_projid,
				 0, oh, NULL, OSD_QID_BLK));
}

static ssize_t osd_write(const struct lu_env *env, struct dt_object *dt,
			const struct lu_buf *buf, loff_t *pos,
			 struct thandle *th)
{
	struct osd_object  *obj  = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	struct osd_thandle *oh;
	uint64_t            offset = *pos;
	int                 rc;

	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_dn);

	LASSERT(th != NULL);
	oh = container_of(th, struct osd_thandle, ot_super);

	osd_dmu_write(osd, obj->oo_dn, offset, (uint64_t)buf->lb_len,
		      buf->lb_buf, oh->ot_tx);
	write_lock(&obj->oo_attr_lock);
	if (obj->oo_attr.la_size < offset + buf->lb_len) {
		obj->oo_attr.la_size = offset + buf->lb_len;
		write_unlock(&obj->oo_attr_lock);
		/* osd_object_sa_update() will be copying directly from oo_attr
		 * into dbuf.  any update within a single txg will copy the
		 * most actual */
		rc = osd_object_sa_update(obj, SA_ZPL_SIZE(osd),
					&obj->oo_attr.la_size, 8, oh);
		if (unlikely(rc))
			GOTO(out, rc);
	} else {
		write_unlock(&obj->oo_attr_lock);
	}

	*pos += buf->lb_len;
	rc = buf->lb_len;

out:
	RETURN(rc);
}

/*
 * XXX: for the moment I don't want to use lnb_flags for osd-internal
 *      purposes as it's not very well defined ...
 *      instead I use the lowest bit of the address so that:
 *        arc buffer:  .lnb_data = abuf          (arc we loan for write)
 *        dbuf buffer: .lnb_data = dbuf | 1      (dbuf we get for read)
 *        copy buffer: .lnb_page->mapping = obj (page we allocate for write)
 *
 *      bzzz, to blame
 */
static int osd_bufs_put(const struct lu_env *env, struct dt_object *dt,
			struct niobuf_local *lnb, int npages)
{
	struct osd_object *obj  = osd_dt_obj(dt);
	struct osd_device *osd = osd_obj2dev(obj);
	unsigned long      ptr;
	int                i;

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_dn);

	for (i = 0; i < npages; i++) {
		if (lnb[i].lnb_page == NULL)
			continue;
		if (lnb[i].lnb_page->mapping == (void *)obj) {
			/* this is anonymous page allocated for copy-write */
			lnb[i].lnb_page->mapping = NULL;
			__free_page(lnb[i].lnb_page);
			atomic_dec(&osd->od_zerocopy_alloc);
		} else {
			/* see comment in osd_bufs_get_read() */
			ptr = (unsigned long)lnb[i].lnb_data;
			if (ptr & 1UL) {
				ptr &= ~1UL;
				dmu_buf_rele((void *)ptr, osd_0copy_tag);
				atomic_dec(&osd->od_zerocopy_pin);
			} else if (lnb[i].lnb_data != NULL) {
				int j, apages, abufsz;
				abufsz = arc_buf_size(lnb[i].lnb_data);
				apages = abufsz >> PAGE_SHIFT;
				/* these references to pages must be invalidated
				 * to prevent access in osd_bufs_put() */
				for (j = 0; j < apages; j++)
					lnb[i + j].lnb_page = NULL;
				dmu_return_arcbuf(lnb[i].lnb_data);
				atomic_dec(&osd->od_zerocopy_loan);
			}
		}
		lnb[i].lnb_page = NULL;
		lnb[i].lnb_data = NULL;
	}

	return 0;
}

static inline struct page *kmem_to_page(void *addr)
{
	LASSERT(!((unsigned long)addr & ~PAGE_MASK));
	if (is_vmalloc_addr(addr))
		return vmalloc_to_page(addr);
	else
		return virt_to_page(addr);
}

/**
 * Prepare buffers for read.
 *
 * The function maps the range described by \a off and \a len to \a lnb array.
 * dmu_buf_hold_array_by_bonus() finds/creates appropriate ARC buffers, then
 * we fill \a lnb array with the pages storing ARC buffers. Notice the current
 * implementationt passes TRUE to dmu_buf_hold_array_by_bonus() to fill ARC
 * buffers with actual data, I/O is done in the conext of osd_bufs_get_read().
 * A better implementation would just return the buffers (potentially unfilled)
 * and subsequent osd_read_prep() would do I/O for many ranges concurrently.
 *
 * \param[in] env	environment
 * \param[in] obj	object
 * \param[in] off	offset in bytes
 * \param[in] len	the number of bytes to access
 * \param[out] lnb	array of local niobufs pointing to the buffers with data
 *
 * \retval		0 for success
 * \retval		negative error number of failure
 */
static int osd_bufs_get_read(const struct lu_env *env, struct osd_object *obj,
			     loff_t off, ssize_t len, struct niobuf_local *lnb,
			     int maxlnb)
{
	struct osd_device *osd = osd_obj2dev(obj);
	int rc, i, numbufs, npages = 0, drop_cache = 0;
	hrtime_t start = gethrtime();
	dmu_buf_t **dbp;
	s64 delta_ms;

	ENTRY;
	record_start_io(osd, READ, 0);

	if (obj->oo_attr.la_size >= osd->od_readcache_max_filesize)
		drop_cache = 1;

	/* grab buffers for read:
	 * OSD API let us to grab buffers first, then initiate IO(s)
	 * so that all required IOs will be done in parallel, but at the
	 * moment DMU doesn't provide us with a method to grab buffers.
	 * If we discover this is a vital for good performance we
	 * can get own replacement for dmu_buf_hold_array_by_bonus().
	 */
	while (len > 0 &&
	       (obj->oo_dn->dn_datablkshift != 0 ||
		off < obj->oo_dn->dn_datablksz)) {
		if (obj->oo_dn->dn_datablkshift == 0 &&
		    off + len > obj->oo_dn->dn_datablksz)
			len = obj->oo_dn->dn_datablksz - off;

		dbp = NULL;
		if (unlikely(npages >= maxlnb))
			GOTO(err, rc = -EOVERFLOW);

		rc = -dmu_buf_hold_array_by_bonus(&obj->oo_dn->dn_bonus->db,
						  off, len, TRUE, osd_0copy_tag,
						  &numbufs, &dbp);
		if (unlikely(rc))
			GOTO(err, rc);

		for (i = 0; i < numbufs; i++) {
			int bufoff, tocpy, thispage;
			void *dbf = dbp[i];

			LASSERT(len > 0);

			atomic_inc(&osd->od_zerocopy_pin);

			bufoff = off - dbp[i]->db_offset;
			tocpy = min_t(int, dbp[i]->db_size - bufoff, len);

			/* kind of trick to differentiate dbuf vs. arcbuf */
			LASSERT(((unsigned long)dbp[i] & 1) == 0);
			dbf = (void *) ((unsigned long)dbp[i] | 1);

			while (tocpy > 0) {
				if (unlikely(npages >= maxlnb))
					GOTO(err, rc = -EOVERFLOW);

				thispage = PAGE_SIZE;
				thispage -= bufoff & (PAGE_SIZE - 1);
				thispage = min(tocpy, thispage);

				lnb->lnb_rc = 0;
				lnb->lnb_file_offset = off;
				lnb->lnb_page_offset = bufoff & ~PAGE_MASK;
				lnb->lnb_len = thispage;
				lnb->lnb_page = kmem_to_page(dbp[i]->db_data +
							     bufoff);
				/* mark just a single slot: we need this
				 * reference to dbuf to be released once */
				lnb->lnb_data = dbf;
				dbf = NULL;

				tocpy -= thispage;
				len -= thispage;
				bufoff += thispage;
				off += thispage;

				npages++;
				lnb++;
			}

			if (drop_cache)
				dbuf_set_pending_evict(dbp[i]);

			/* steal dbuf so dmu_buf_rele_array() can't release
			 * it */
			dbp[i] = NULL;
		}

		dmu_buf_rele_array(dbp, numbufs, osd_0copy_tag);
	}

	delta_ms = gethrtime() - start;
	do_div(delta_ms, NSEC_PER_MSEC);
	record_end_io(osd, READ, delta_ms, npages * PAGE_SIZE, npages);

	RETURN(npages);

err:
	LASSERT(rc < 0);
	if (dbp)
		dmu_buf_rele_array(dbp, numbufs, osd_0copy_tag);
	osd_bufs_put(env, &obj->oo_dt, lnb - npages, npages);
	RETURN(rc);
}

static inline arc_buf_t *osd_request_arcbuf(dnode_t *dn, size_t bs)
{
	arc_buf_t *abuf;

	abuf = dmu_request_arcbuf(&dn->dn_bonus->db, bs);
	if (unlikely(!abuf))
		return ERR_PTR(-ENOMEM);

#if ZFS_VERSION_CODE < OBD_OCD_VERSION(0, 7, 0, 0)
	/**
	 * ZFS prior to 0.7.0 doesn't guarantee PAGE_SIZE alignment for zio
	 * blocks smaller than (PAGE_SIZE << 2). This poses a problem of
	 * setting up page array for RDMA transfer. See LU-9305.
	 */
	if ((unsigned long)abuf->b_data & ~PAGE_MASK) {
		dmu_return_arcbuf(abuf);
		return NULL;
	}
#endif

	return abuf;
}

static int osd_bufs_get_write(const struct lu_env *env, struct osd_object *obj,
			      loff_t off, ssize_t len, struct niobuf_local *lnb,
			      int maxlnb)
{
	struct osd_device *osd = osd_obj2dev(obj);
	int                poff, plen, off_in_block, sz_in_block;
	int                rc, i = 0, npages = 0;
	dnode_t *dn = obj->oo_dn;
	arc_buf_t *abuf;
	uint32_t bs = dn->dn_datablksz;
	ENTRY;

	/*
	 * currently only full blocks are subject to zerocopy approach:
	 * so that we're sure nobody is trying to update the same block
	 */
	while (len > 0) {
		if (unlikely(npages >= maxlnb))
			GOTO(out_err, rc = -EOVERFLOW);

		off_in_block = off & (bs - 1);
		sz_in_block = min_t(int, bs - off_in_block, len);

		abuf = NULL;
		if (sz_in_block == bs) {
			/* full block, try to use zerocopy */
			abuf = osd_request_arcbuf(dn, bs);
			if (unlikely(IS_ERR(abuf)))
				GOTO(out_err, rc = PTR_ERR(abuf));
		}

		if (abuf != NULL) {
			atomic_inc(&osd->od_zerocopy_loan);

			/* go over pages arcbuf contains, put them as
			 * local niobufs for ptlrpc's bulks */
			while (sz_in_block > 0) {
				plen = min_t(int, sz_in_block, PAGE_SIZE);

				if (unlikely(npages >= maxlnb))
					GOTO(out_err, rc = -EOVERFLOW);

				lnb[i].lnb_file_offset = off;
				lnb[i].lnb_page_offset = 0;
				lnb[i].lnb_len = plen;
				lnb[i].lnb_rc = 0;
				if (sz_in_block == bs)
					lnb[i].lnb_data = abuf;
				else
					lnb[i].lnb_data = NULL;

				/* this one is not supposed to fail */
				lnb[i].lnb_page = kmem_to_page(abuf->b_data +
							off_in_block);
				LASSERT(lnb[i].lnb_page);

				lprocfs_counter_add(osd->od_stats,
						LPROC_OSD_ZEROCOPY_IO, 1);

				sz_in_block -= plen;
				len -= plen;
				off += plen;
				off_in_block += plen;
				i++;
				npages++;
			}
		} else {
			if (off_in_block == 0 && len < bs &&
					off + len >= obj->oo_attr.la_size)
				lprocfs_counter_add(osd->od_stats,
						LPROC_OSD_TAIL_IO, 1);

			/* can't use zerocopy, allocate temp. buffers */
			poff = off & (PAGE_SIZE - 1);
			while (sz_in_block > 0) {
				plen = min_t(int, poff + sz_in_block,
					     PAGE_SIZE);
				plen -= poff;

				if (unlikely(npages >= maxlnb))
					GOTO(out_err, rc = -EOVERFLOW);

				lnb[i].lnb_file_offset = off;
				lnb[i].lnb_page_offset = poff;
				poff = 0;

				lnb[i].lnb_len = plen;
				lnb[i].lnb_rc = 0;
				lnb[i].lnb_data = NULL;

				lnb[i].lnb_page = alloc_page(OSD_GFP_IO);
				if (unlikely(lnb[i].lnb_page == NULL))
					GOTO(out_err, rc = -ENOMEM);

				LASSERT(lnb[i].lnb_page->mapping == NULL);
				lnb[i].lnb_page->mapping = (void *)obj;

				atomic_inc(&osd->od_zerocopy_alloc);
				lprocfs_counter_add(osd->od_stats,
						LPROC_OSD_COPY_IO, 1);

				sz_in_block -= plen;
				len -= plen;
				off += plen;
				i++;
				npages++;
			}
		}
	}

	RETURN(npages);

out_err:
	osd_bufs_put(env, &obj->oo_dt, lnb, npages);
	RETURN(rc);
}

static int osd_bufs_get(const struct lu_env *env, struct dt_object *dt,
			loff_t offset, ssize_t len, struct niobuf_local *lnb,
			int maxlnb, enum dt_bufs_type rw)
{
	struct osd_object *obj  = osd_dt_obj(dt);
	int                rc;

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_dn);

	if (rw & DT_BUFS_TYPE_WRITE)
		rc = osd_bufs_get_write(env, obj, offset, len, lnb, maxlnb);
	else
		rc = osd_bufs_get_read(env, obj, offset, len, lnb, maxlnb);

	return rc;
}

static int osd_write_prep(const struct lu_env *env, struct dt_object *dt,
			struct niobuf_local *lnb, int npages)
{
	struct osd_object *obj = osd_dt_obj(dt);

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_dn);

	return 0;
}

static inline uint64_t osd_roundup2blocksz(uint64_t size,
					   uint64_t offset,
					   uint32_t blksz)
{
	LASSERT(blksz > 0);

	size += offset % blksz;

	if (likely(is_power_of_2(blksz)))
		return round_up(size, blksz);
	else
		return DIV_ROUND_UP_ULL(size, blksz) * blksz;
}

static int osd_declare_write_commit(const struct lu_env *env,
				    struct dt_object *dt,
				    struct niobuf_local *lnb, int npages,
				    struct thandle *th)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	struct osd_thandle *oh;
	uint64_t            offset = 0;
	uint32_t            size = 0;
	uint32_t blksz = obj->oo_dn->dn_datablksz;
	int		    i, rc;
	bool synced = false;
	long long	    space = 0;
	struct page	   *last_page = NULL;
	unsigned long	    discont_pages = 0;
	enum osd_quota_local_flags local_flags = 0;
	enum osd_qid_declare_flags declare_flags = OSD_QID_BLK;
	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_dn);

	LASSERT(lnb);
	LASSERT(npages > 0);

	oh = container_of(th, struct osd_thandle, ot_super);

	for (i = 0; i < npages; i++) {
		if (last_page && lnb[i].lnb_page->index != (last_page->index + 1))
			++discont_pages;
		last_page = lnb[i].lnb_page;
		if (lnb[i].lnb_rc)
			/* ENOSPC, network RPC error, etc.
			 * We don't want to book space for pages which will be
			 * skipped in osd_write_commit(). Hence we skip pages
			 * with lnb_rc != 0 here too */
			continue;
		/* ignore quota for the whole request if any page is from
		 * client cache or written by root.
		 *
		 * XXX once we drop the 1.8 client support, the checking
		 * for whether page is from cache can be simplified as:
		 * !(lnb[i].flags & OBD_BRW_SYNC)
		 *
		 * XXX we could handle this on per-lnb basis as done by
		 * grant. */
		if ((lnb[i].lnb_flags & OBD_BRW_NOQUOTA) ||
		    (lnb[i].lnb_flags & (OBD_BRW_FROM_GRANT | OBD_BRW_SYNC)) ==
		    OBD_BRW_FROM_GRANT)
			declare_flags |= OSD_QID_FORCE;

		if (size == 0) {
			/* first valid lnb */
			offset = lnb[i].lnb_file_offset;
			size = lnb[i].lnb_len;
			continue;
		}
		if (offset + size == lnb[i].lnb_file_offset) {
			/* this lnb is contiguous to the previous one */
			size += lnb[i].lnb_len;
			continue;
		}

		osd_tx_hold_write(oh->ot_tx, obj->oo_dn->dn_object,
				  obj->oo_dn, offset, size);
		/* Estimating space to be consumed by a write is rather
		 * complicated with ZFS. As a consequence, we don't account for
		 * indirect blocks and just use as a rough estimate the worse
		 * case where the old space is being held by a snapshot. Quota
		 * overrun will be adjusted once the operation is committed, if
		 * required. */
		space += osd_roundup2blocksz(size, offset, blksz);

		offset = lnb[i].lnb_file_offset;
		size = lnb[i].lnb_len;
	}

	if (size) {
		osd_tx_hold_write(oh->ot_tx, obj->oo_dn->dn_object, obj->oo_dn,
				  offset, size);
		space += osd_roundup2blocksz(size, offset, blksz);
	}

	/* backend zfs filesystem might be configured to store multiple data
	 * copies */
	space  *= osd->od_os->os_copies;
	space   = toqb(space);
	CDEBUG(D_QUOTA, "writing %d pages, reserving %lldK of quota space\n",
	       npages, space);

	record_start_io(osd, WRITE, discont_pages);
retry:
	/* acquire quota space if needed */
	rc = osd_declare_quota(env, osd, obj->oo_attr.la_uid,
			       obj->oo_attr.la_gid, obj->oo_attr.la_projid,
			       space, oh, &local_flags, declare_flags);

	if (!synced && rc == -EDQUOT &&
	    (local_flags & QUOTA_FL_SYNC) != 0) {
		dt_sync(env, th->th_dev);
		synced = true;
		CDEBUG(D_QUOTA, "retry after sync\n");
		local_flags = 0;
		goto retry;
	}

	/* we need only to store the overquota flags in the first lnb for
	 * now, once we support multiple objects BRW, this code needs be
	 * revised. */
	if (local_flags & QUOTA_FL_OVER_USRQUOTA)
		lnb[0].lnb_flags |= OBD_BRW_OVER_USRQUOTA;
	if (local_flags & QUOTA_FL_OVER_GRPQUOTA)
		lnb[0].lnb_flags |= OBD_BRW_OVER_GRPQUOTA;
#ifdef ZFS_PROJINHERIT
	if (local_flags & QUOTA_FL_OVER_PRJQUOTA)
		lnb[0].lnb_flags |= OBD_BRW_OVER_PRJQUOTA;
#endif

	RETURN(rc);
}

/**
 * Policy to grow ZFS block size by write pattern.
 * For sequential write, it grows block size gradually until it reaches the
 * maximum blocksize the dataset can support. Otherwise, it will pick a
 * a block size by the writing region of this I/O.
 */
static int osd_grow_blocksize(struct osd_object *obj, struct osd_thandle *oh,
			      uint64_t start, uint64_t end)
{
	struct osd_device	*osd = osd_obj2dev(obj);
	dnode_t *dn = obj->oo_dn;
	uint32_t		 blksz;
	int			 rc = 0;

	ENTRY;

	if (dn->dn_maxblkid > 0) /* can't change block size */
		GOTO(out, rc);

	if (dn->dn_datablksz >= osd->od_max_blksz)
		GOTO(out, rc);

	down_write(&obj->oo_guard);

	blksz = dn->dn_datablksz;
	if (blksz >= osd->od_max_blksz) /* check again after grabbing lock */
		GOTO(out_unlock, rc);

	/* now ZFS can support up to 16MB block size, and if the write
	 * is sequential, it just increases the block size gradually */
	if (start <= blksz) { /* sequential */
		blksz = (uint32_t)min_t(uint64_t, osd->od_max_blksz, end);
	} else { /* sparse, pick a block size by write region */
		blksz = (uint32_t)min_t(uint64_t, osd->od_max_blksz,
					end - start);
	}

	if (!is_power_of_2(blksz))
		blksz = size_roundup_power2(blksz);

	if (blksz > dn->dn_datablksz) {
		rc = -dmu_object_set_blocksize(osd->od_os, dn->dn_object,
					       blksz, 0, oh->ot_tx);
		LASSERT(ergo(rc == 0, dn->dn_datablksz >= blksz));
		if (rc < 0)
			CDEBUG(D_INODE, "object "DFID": change block size"
			       "%u -> %u error rc = %d\n",
			       PFID(lu_object_fid(&obj->oo_dt.do_lu)),
			       dn->dn_datablksz, blksz, rc);
	}
	EXIT;
out_unlock:
	up_write(&obj->oo_guard);
out:
	return rc;
}

static void osd_evict_dbufs_after_write(struct osd_object *obj,
					loff_t off, ssize_t len)
{
	dmu_buf_t **dbp;
	int i, rc, numbufs;

	rc = -dmu_buf_hold_array_by_bonus(&obj->oo_dn->dn_bonus->db, off, len,
					  TRUE, osd_0copy_tag, &numbufs, &dbp);
	if (unlikely(rc))
		return;

	for (i = 0; i < numbufs; i++)
		dbuf_set_pending_evict(dbp[i]);

	dmu_buf_rele_array(dbp, numbufs, osd_0copy_tag);
}

static int osd_write_commit(const struct lu_env *env, struct dt_object *dt,
			struct niobuf_local *lnb, int npages,
			struct thandle *th, __u64 user_size)
{
	struct osd_object  *obj  = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	struct osd_thandle *oh;
	uint64_t            new_size = 0;
	int                 i, abufsz, rc = 0, drop_cache = 0;
	unsigned long	   iosize = 0;
	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_dn);

	LASSERT(th != NULL);
	oh = container_of(th, struct osd_thandle, ot_super);

	/* adjust block size. Assume the buffers are sorted. */
	(void)osd_grow_blocksize(obj, oh, lnb[0].lnb_file_offset,
				 lnb[npages - 1].lnb_file_offset +
				 lnb[npages - 1].lnb_len);

	if (obj->oo_attr.la_size >= osd->od_readcache_max_filesize ||
	    lnb[npages - 1].lnb_file_offset + lnb[npages - 1].lnb_len >=
	    osd->od_readcache_max_filesize)
		drop_cache = 1;

	if (OBD_FAIL_CHECK(OBD_FAIL_OST_MAPBLK_ENOSPC))
		RETURN(-ENOSPC);

	/* if la_size is already bigger than specified user_size,
	 * ignore user_size
	 */
	if (obj->oo_attr.la_size > user_size)
		user_size = 0;

	/* LU-8791: take oo_guard to avoid the deadlock that changing block
	 * size and assigning arcbuf take place at the same time.
	 *
	 * Thread 1:
	 * osd_write_commit()
	 *  -> osd_grow_blocksize() with osd_object::oo_guard held
	 *   -> dmu_object_set_blocksize()
	 *    -> dnode_set_blksz(), with dnode_t::dn_struct_rwlock
	 *       write lock held
	 *     -> dbuf_new_size()
	 *      -> dmu_buf_will_dirty()
	 *       -> dbuf_read()
	 *        -> wait for the dbuf state to change
	 * Thread 2:
	 * osd_write_commit()
	 *  -> dmu_assign_arcbuf()
	 *   -> dbuf_assign_arcbuf(), set dbuf state to DB_FILL
	 *    -> dbuf_dirty()
	 *     -> try to hold the read lock of dnode_t::dn_struct_rwlock
	 *
	 * By taking the read lock, it can avoid thread 2 to enter into the
	 * critical section of assigning the arcbuf, while thread 1 is
	 * changing the block size.
	 */
	down_read(&obj->oo_guard);
	for (i = 0; i < npages; i++) {
		CDEBUG(D_INODE, "write %u bytes at %u\n",
			(unsigned) lnb[i].lnb_len,
			(unsigned) lnb[i].lnb_file_offset);

		if (lnb[i].lnb_rc) {
			/* ENOSPC, network RPC error, etc.
			 * Unlike ldiskfs, zfs allocates new blocks on rewrite,
			 * so we skip this page if lnb_rc is set to -ENOSPC */
			CDEBUG(D_INODE, "obj "DFID": skipping lnb[%u]: rc=%d\n",
				PFID(lu_object_fid(&dt->do_lu)), i,
				lnb[i].lnb_rc);
			continue;
		}

		if (new_size < lnb[i].lnb_file_offset + lnb[i].lnb_len)
			new_size = lnb[i].lnb_file_offset + lnb[i].lnb_len;
		if (lnb[i].lnb_page == NULL)
			continue;

		if (lnb[i].lnb_page->mapping == (void *)obj) {
			osd_dmu_write(osd, obj->oo_dn, lnb[i].lnb_file_offset,
				      lnb[i].lnb_len, kmap(lnb[i].lnb_page) +
				      lnb[i].lnb_page_offset, oh->ot_tx);
			kunmap(lnb[i].lnb_page);
			iosize += lnb[i].lnb_len;
			abufsz = lnb[i].lnb_len; /* to drop cache below */
		} else if (lnb[i].lnb_data) {
			int j, apages;
			LASSERT(((unsigned long)lnb[i].lnb_data & 1) == 0);
			/* buffer loaned for zerocopy, try to use it.
			 * notice that dmu_assign_arcbuf() is smart
			 * enough to recognize changed blocksize
			 * in this case it fallbacks to dmu_write() */
			abufsz = arc_buf_size(lnb[i].lnb_data);
			LASSERT(abufsz & PAGE_MASK);
			apages = abufsz >> PAGE_SHIFT;
			LASSERT(i + apages <= npages);
			/* these references to pages must be invalidated
			 * to prevent access in osd_bufs_put() */
			for (j = 0; j < apages; j++)
				lnb[i + j].lnb_page = NULL;
			dmu_assign_arcbuf(&obj->oo_dn->dn_bonus->db,
					  lnb[i].lnb_file_offset,
					  lnb[i].lnb_data, oh->ot_tx);
			/* drop the reference, otherwise osd_put_bufs()
			 * will be releasing it - bad! */
			lnb[i].lnb_data = NULL;
			atomic_dec(&osd->od_zerocopy_loan);
			iosize += abufsz;
		} else {
			/* we don't want to deal with cache if nothing
			 * has been send to ZFS at this step */
			continue;
		}

		if (!drop_cache)
			continue;

		/* we have to mark dbufs for eviction here because
		 * dmu_assign_arcbuf() may create a new dbuf for
		 * loaned abuf */
		osd_evict_dbufs_after_write(obj, lnb[i].lnb_file_offset,
					    abufsz);
	}
	up_read(&obj->oo_guard);

	if (unlikely(new_size == 0)) {
		/* no pages to write, no transno is needed */
		th->th_local = 1;
		/* it is important to return 0 even when all lnb_rc == -ENOSPC
		 * since ofd_commitrw_write() retries several times on ENOSPC */
		record_end_io(osd, WRITE, 0, 0, 0);
		RETURN(0);
	}

	/* if file has grown, take user_size into account */
	if (user_size && new_size > user_size)
		new_size = user_size;
	write_lock(&obj->oo_attr_lock);
	if (obj->oo_attr.la_size < new_size) {
		obj->oo_attr.la_size = new_size;
		write_unlock(&obj->oo_attr_lock);
		/* osd_object_sa_update() will be copying directly from
		 * oo_attr into dbuf. any update within a single txg will copy
		 * the most actual */
		rc = osd_object_sa_update(obj, SA_ZPL_SIZE(osd),
					  &obj->oo_attr.la_size, 8, oh);
	} else {
		write_unlock(&obj->oo_attr_lock);
	}

	record_end_io(osd, WRITE, 0, iosize, npages);

	RETURN(rc);
}

static int osd_read_prep(const struct lu_env *env, struct dt_object *dt,
			struct niobuf_local *lnb, int npages)
{
	struct osd_object *obj  = osd_dt_obj(dt);
	int                i;
	loff_t		   eof;

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_dn);

	read_lock(&obj->oo_attr_lock);
	eof = obj->oo_attr.la_size;
	read_unlock(&obj->oo_attr_lock);

	for (i = 0; i < npages; i++) {
		if (unlikely(lnb[i].lnb_rc < 0))
			continue;

		lnb[i].lnb_rc = lnb[i].lnb_len;

		if (lnb[i].lnb_file_offset + lnb[i].lnb_len >= eof) {
			/* send complete pages all the time */
			if (eof <= lnb[i].lnb_file_offset)
				lnb[i].lnb_rc = 0;

			/* all subsequent rc should be 0 */
			while (++i < npages)
				lnb[i].lnb_rc = 0;
			break;
		}
	}

	return 0;
}

/*
 * Punch/truncate an object
 *
 *      IN:     db  - dmu_buf of the object to free data in.
 *              off - start of section to free.
 *              len - length of section to free (DMU_OBJECT_END => to EOF).
 *
 *      RETURN: 0 if success
 *              error code if failure
 *
 * The transaction passed to this routine must have
 * dmu_tx_hold_sa() and if off < size, dmu_tx_hold_free()
 * called and then assigned to a transaction group.
 */
static int __osd_object_punch(struct osd_object *obj, objset_t *os,
			      dmu_tx_t *tx, uint64_t off, uint64_t len)
{
	dnode_t *dn = obj->oo_dn;
	uint64_t size = obj->oo_attr.la_size;
	int rc = 0;

	/* Assert that the transaction has been assigned to a
	   transaction group. */
	LASSERT(tx->tx_txg != 0);
	/*
	 * Nothing to do if file already at desired length.
	 */
	if (len == DMU_OBJECT_END && size == off)
		return 0;

	/* if object holds encrypted content, we need to make sure we truncate
	 * on an encryption unit boundary, or subsequent reads will get
	 * corrupted content
	 */
	if (len != DMU_OBJECT_END)
		len -= LUSTRE_ENCRYPTION_UNIT_SIZE -
			(off & ~LUSTRE_ENCRYPTION_MASK);
	if (obj->oo_lma_flags & LUSTRE_ENCRYPT_FL &&
	    off & ~LUSTRE_ENCRYPTION_MASK)
		off = (off & LUSTRE_ENCRYPTION_MASK) +
			LUSTRE_ENCRYPTION_UNIT_SIZE;


	/* XXX: dnode_free_range() can be used to save on dnode lookup */
	if (off < size)
		dmu_free_range(os, dn->dn_object, off, len, tx);

	return rc;
}

static int osd_punch(const struct lu_env *env, struct dt_object *dt,
			__u64 start, __u64 end, struct thandle *th)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	struct osd_thandle *oh;
	__u64               len;
	int                 rc = 0;
	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));

	LASSERT(th != NULL);
	oh = container_of(th, struct osd_thandle, ot_super);

	write_lock(&obj->oo_attr_lock);
	/* truncate */
	if (end == OBD_OBJECT_EOF || end >= obj->oo_attr.la_size)
		len = DMU_OBJECT_END;
	else
		len = end - start;
	write_unlock(&obj->oo_attr_lock);

	rc = __osd_object_punch(obj, osd->od_os, oh->ot_tx, start, len);

	/* set new size */
	if (len == DMU_OBJECT_END) {
		write_lock(&obj->oo_attr_lock);
		obj->oo_attr.la_size = start;
		write_unlock(&obj->oo_attr_lock);
		rc = osd_object_sa_update(obj, SA_ZPL_SIZE(osd),
					  &obj->oo_attr.la_size, 8, oh);
	}
	RETURN(rc);
}

static int osd_declare_punch(const struct lu_env *env, struct dt_object *dt,
			__u64 start, __u64 end, struct thandle *handle)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	struct osd_thandle *oh;
	__u64		    len;
	ENTRY;

	oh = container_of(handle, struct osd_thandle, ot_super);

	read_lock(&obj->oo_attr_lock);
	if (end == OBD_OBJECT_EOF || end >= obj->oo_attr.la_size)
		len = DMU_OBJECT_END;
	else
		len = end - start;

	/* declare we'll free some blocks ... */
	/* if object holds encrypted content, we need to make sure we truncate
	 * on an encryption unit boundary, or subsequent reads will get
	 * corrupted content
	 */
	if (obj->oo_lma_flags & LUSTRE_ENCRYPT_FL &&
	    start & ~LUSTRE_ENCRYPTION_MASK)
		start = (start & LUSTRE_ENCRYPTION_MASK) +
			LUSTRE_ENCRYPTION_UNIT_SIZE;
	if (start < obj->oo_attr.la_size) {
		read_unlock(&obj->oo_attr_lock);
		dmu_tx_mark_netfree(oh->ot_tx);
		dmu_tx_hold_free(oh->ot_tx, obj->oo_dn->dn_object, start, len);
	} else {
		read_unlock(&obj->oo_attr_lock);
	}

	RETURN(osd_declare_quota(env, osd, obj->oo_attr.la_uid,
				 obj->oo_attr.la_gid, obj->oo_attr.la_projid,
				 0, oh, NULL, OSD_QID_BLK));
}

static int osd_ladvise(const struct lu_env *env, struct dt_object *dt,
		       __u64 start, __u64 end, enum lu_ladvise_type advice)
{
	int	rc;
	ENTRY;

	switch (advice) {
	default:
		rc = -ENOTSUPP;
		break;
	}

	RETURN(rc);
}

static int osd_fallocate(const struct lu_env *env, struct dt_object *dt,
			 __u64 start, __u64 end, int mode, struct thandle *th)
{
	int rc = -EOPNOTSUPP;
	ENTRY;

	 /*
	  * space preallocation is not supported for ZFS
	  * Returns -EOPNOTSUPP for now
	  */
	RETURN(rc);
}

static int osd_declare_fallocate(const struct lu_env *env,
				 struct dt_object *dt, __u64 start, __u64 end,
				 int mode, struct thandle *th)
{
	int rc = -EOPNOTSUPP;
	ENTRY;

	 /*
	  * space preallocation is not supported for ZFS
	  * Returns -EOPNOTSUPP for now
	  */
	RETURN(rc);
}

static loff_t osd_lseek(const struct lu_env *env, struct dt_object *dt,
			loff_t offset, int whence)
{
	struct osd_object *obj = osd_dt_obj(dt);
	uint64_t size = obj->oo_attr.la_size;
	uint64_t result = offset;
	int rc;
	boolean_t hole = whence == SEEK_HOLE;

	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));
	LASSERT(offset >= 0);

	/* for SEEK_HOLE treat 'offset' beyond the end of file as in real
	 * hole. LOV to decide after all if that real hole or not.
	 */
	if (offset >= size)
		RETURN(hole ? offset : -ENXIO);

	rc = osd_dmu_offset_next(osd_obj2dev(obj)->od_os,
				 obj->oo_dn->dn_object, hole, &result);
	if (rc == ESRCH)
		RETURN(-ENXIO);

	/* file was dirty, so fall back to using generic logic:
	 * For HOLE return file size, for DATA the result is set
	 * already to the 'offset' parameter value.
	 */
	if (rc == EBUSY && hole)
		result = size;

	/* dmu_offset_next() only works on whole blocks so may return SEEK_HOLE
	 * result as end of the last block instead of logical EOF which we need
	 */
	if (result > size)
		result = size;

	RETURN(result);
}

const struct dt_body_operations osd_body_ops = {
	.dbo_read			= osd_read,
	.dbo_declare_write		= osd_declare_write,
	.dbo_write			= osd_write,
	.dbo_bufs_get			= osd_bufs_get,
	.dbo_bufs_put			= osd_bufs_put,
	.dbo_write_prep			= osd_write_prep,
	.dbo_declare_write_commit	= osd_declare_write_commit,
	.dbo_write_commit		= osd_write_commit,
	.dbo_read_prep			= osd_read_prep,
	.dbo_declare_punch		= osd_declare_punch,
	.dbo_punch			= osd_punch,
	.dbo_ladvise			= osd_ladvise,
	.dbo_declare_fallocate		= osd_declare_fallocate,
	.dbo_fallocate			= osd_fallocate,
	.dbo_lseek			= osd_lseek,
};

const struct dt_body_operations osd_body_scrub_ops = {
	.dbo_read			= osd_read_no_record,
	.dbo_declare_write		= osd_declare_write,
	.dbo_write			= osd_write,
};
