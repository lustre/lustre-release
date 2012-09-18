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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012, Intel Corporation.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd-zfs/osd_io.c
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_OSD

#include <lustre_ver.h>
#include <libcfs/libcfs.h>
#include <lustre_fsfilt.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_disk.h>
#include <lustre_fid.h>

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

static char *osd_zerocopy_tag = "zerocopy";

static ssize_t osd_read(const struct lu_env *env, struct dt_object *dt,
			struct lu_buf *buf, loff_t *pos,
			struct lustre_capa *capa)
{
	struct osd_object *obj  = osd_dt_obj(dt);
	struct osd_device *osd = osd_obj2dev(obj);
	uint64_t	   old_size;
	int		   size = buf->lb_len;
	int		   rc;

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_db);

	cfs_read_lock(&obj->oo_attr_lock);
	old_size = obj->oo_attr.la_size;
	cfs_read_unlock(&obj->oo_attr_lock);

	if (*pos + size > old_size) {
		if (old_size < *pos)
			return 0;
		else
			size = old_size - *pos;
	}

	rc = -dmu_read(osd->od_objset.os, obj->oo_db->db_object, *pos, size,
			buf->lb_buf, DMU_READ_PREFETCH);
	if (rc == 0) {
		rc = size;
		*pos += size;

		/* XXX: workaround for bug in HEAD: fsfilt_ldiskfs_read() returns
		 * requested number of bytes, not actually read ones */
		if (S_ISLNK(obj->oo_dt.do_lu.lo_header->loh_attr))
			rc = buf->lb_len;
	}
	return rc;
}

static ssize_t osd_declare_write(const struct lu_env *env, struct dt_object *dt,
				const loff_t size, loff_t pos,
				struct thandle *th)
{
	struct osd_object  *obj  = osd_dt_obj(dt);
	struct osd_thandle *oh;
	uint64_t            oid;
	ENTRY;

	oh = container_of0(th, struct osd_thandle, ot_super);

	/* in some cases declare can race with creation (e.g. llog)
	 * and we need to wait till object is initialized. notice
	 * LOHA_EXISTs is supposed to be the last step in the
	 * initialization */

	/* declare possible size change. notice we can't check
	 * current size here as another thread can change it */

	if (dt_object_exists(dt)) {
		LASSERT(obj->oo_db);
		oid = obj->oo_db->db_object;

		dmu_tx_hold_sa(oh->ot_tx, obj->oo_sa_hdl, 0);
	} else {
		oid = DMU_NEW_OBJECT;
		dmu_tx_hold_sa_create(oh->ot_tx, ZFS_SA_BASE_ATTR_SIZE);
	}

	dmu_tx_hold_write(oh->ot_tx, oid, pos, size);

	RETURN(0);
}

static ssize_t osd_write(const struct lu_env *env, struct dt_object *dt,
			const struct lu_buf *buf, loff_t *pos,
			struct thandle *th, struct lustre_capa *capa,
			int ignore_quota)
{
	struct osd_object  *obj  = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	udmu_objset_t      *uos = &osd->od_objset;
	struct osd_thandle *oh;
	uint64_t            offset = *pos;
	int                 rc;
	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_db);

	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

	dmu_write(osd->od_objset.os, obj->oo_db->db_object, offset,
		(uint64_t)buf->lb_len, buf->lb_buf, oh->ot_tx);
	cfs_write_lock(&obj->oo_attr_lock);
	if (obj->oo_attr.la_size < offset + buf->lb_len) {
		obj->oo_attr.la_size = offset + buf->lb_len;
		cfs_write_unlock(&obj->oo_attr_lock);
		/* osd_object_sa_update() will be copying directly from oo_attr
		 * into dbuf.  any update within a single txg will copy the
		 * most actual */
		rc = osd_object_sa_update(obj, SA_ZPL_SIZE(uos),
					&obj->oo_attr.la_size, 8, oh);
		if (unlikely(rc))
			GOTO(out, rc);
	} else {
		cfs_write_unlock(&obj->oo_attr_lock);
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
 *        arc buffer:  .lnb_obj = abuf          (arc we loan for write)
 *        dbuf buffer: .lnb_obj = dbuf | 1      (dbuf we get for read)
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
	LASSERT(obj->oo_db);

	for (i = 0; i < npages; i++) {
		if (lnb[i].page == NULL)
			continue;
		if (lnb[i].page->mapping == (void *)obj) {
			/* this is anonymous page allocated for copy-write */
			lnb[i].page->mapping = NULL;
			__free_page(lnb[i].page);
			cfs_atomic_dec(&osd->od_zerocopy_alloc);
		} else {
			/* see comment in osd_bufs_get_read() */
			ptr = (unsigned long)lnb[i].dentry;
			if (ptr & 1UL) {
				ptr &= ~1UL;
				dmu_buf_rele((void *)ptr, osd_zerocopy_tag);
				cfs_atomic_dec(&osd->od_zerocopy_pin);
			} else if (lnb[i].dentry != NULL) {
				dmu_return_arcbuf((void *)lnb[i].dentry);
				cfs_atomic_dec(&osd->od_zerocopy_loan);
			}
		}
		lnb[i].page = NULL;
		lnb[i].dentry = NULL;
	}

	return 0;
}

static struct page *kmem_to_page(void *addr)
{
	struct page *page;

	if (kmem_virt(addr))
		page = vmalloc_to_page(addr);
	else
		page = virt_to_page(addr);

	return page;
}

static int osd_bufs_get_read(const struct lu_env *env, struct osd_object *obj,
				loff_t off, ssize_t len, struct niobuf_local *lnb)
{
	struct osd_device *osd = osd_obj2dev(obj);
	dmu_buf_t        **dbp;
	int                rc, i, numbufs, npages = 0;
	ENTRY;

	/* grab buffers for read:
	 * OSD API let us to grab buffers first, then initiate IO(s)
	 * so that all required IOs will be done in parallel, but at the
	 * moment DMU doesn't provide us with a method to grab buffers.
	 * If we discover this is a vital for good performance we
	 * can get own replacement for dmu_buf_hold_array_by_bonus().
	 */
	while (len > 0) {
		rc = -dmu_buf_hold_array_by_bonus(obj->oo_db, off, len, TRUE,
						osd_zerocopy_tag, &numbufs,
						&dbp);
		LASSERT(rc == 0);

		for (i = 0; i < numbufs; i++) {
			int bufoff, tocpy, thispage;
			void *dbf = dbp[i];

			LASSERT(len > 0);

			cfs_atomic_inc(&osd->od_zerocopy_pin);

			bufoff = off - dbp[i]->db_offset;
			tocpy = min_t(int, dbp[i]->db_size - bufoff, len);

			/* kind of trick to differentiate dbuf vs. arcbuf */
			LASSERT(((unsigned long)dbp[i] & 1) == 0);
			dbf = (void *) ((unsigned long)dbp[i] | 1);

			while (tocpy > 0) {
				thispage = CFS_PAGE_SIZE;
				thispage -= bufoff & (CFS_PAGE_SIZE - 1);
				thispage = min(tocpy, thispage);

				lnb->rc = 0;
				lnb->lnb_file_offset = off;
				lnb->offset = bufoff & ~CFS_PAGE_MASK;
				lnb->len = thispage;
				lnb->page = kmem_to_page(dbp[i]->db_data +
								bufoff);
				/* mark just a single slot: we need this
				 * reference to dbuf to be release once */
				lnb->dentry = dbf;
				dbf = NULL;

				tocpy -= thispage;
				len -= thispage;
				bufoff += thispage;
				off += thispage;

				npages++;
				lnb++;
			}

			/* steal dbuf so dmu_buf_rele_array() cant release it */
			dbp[i] = NULL;
		}

		dmu_buf_rele_array(dbp, numbufs, osd_zerocopy_tag);
	}

	RETURN(npages);
}

static int osd_bufs_get_write(const struct lu_env *env, struct osd_object *obj,
				loff_t off, ssize_t len, struct niobuf_local *lnb)
{
	struct osd_device *osd = osd_obj2dev(obj);
	int                plen, off_in_block, sz_in_block;
	int                i = 0, npages = 0;
	arc_buf_t         *abuf;
	uint32_t           bs;
	uint64_t           dummy;
	ENTRY;

	dmu_object_size_from_db(obj->oo_db, &bs, &dummy);

	/*
	 * currently only full blocks are subject to zerocopy approach:
	 * so that we're sure nobody is trying to update the same block
	 */
	while (len > 0) {
		LASSERT(npages < PTLRPC_MAX_BRW_PAGES);

		off_in_block = off & (bs - 1);
		sz_in_block = min_t(int, bs - off_in_block, len);

		if (sz_in_block == bs) {
			/* full block, try to use zerocopy */

			abuf = dmu_request_arcbuf(obj->oo_db, bs);
			if (unlikely(abuf == NULL))
				GOTO(out_err, -ENOMEM);

			cfs_atomic_inc(&osd->od_zerocopy_loan);

			/* go over pages arcbuf contains, put them as
			 * local niobufs for ptlrpc's bulks */
			while (sz_in_block > 0) {
				plen = min_t(int, sz_in_block, CFS_PAGE_SIZE);

				lnb[i].lnb_file_offset = off;
				lnb[i].offset = 0;
				lnb[i].len = plen;
				lnb[i].rc = 0;
				if (sz_in_block == bs)
					lnb[i].dentry = (void *)abuf;
				else
					lnb[i].dentry = NULL;

				/* this one is not supposed to fail */
				lnb[i].page = kmem_to_page(abuf->b_data +
							off_in_block);
				LASSERT(lnb[i].page);

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
			while (sz_in_block > 0) {
				plen = min_t(int, sz_in_block, CFS_PAGE_SIZE);

				lnb[i].lnb_file_offset = off;
				lnb[i].offset = 0;
				lnb[i].len = plen;
				lnb[i].rc = 0;
				lnb[i].dentry = NULL;

				lnb[i].page = alloc_page(OSD_GFP_IO);
				if (unlikely(lnb[i].page == NULL))
					GOTO(out_err, -ENOMEM);

				LASSERT(lnb[i].page->mapping == NULL);
				lnb[i].page->mapping = (void *)obj;

				cfs_atomic_inc(&osd->od_zerocopy_alloc);
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
	RETURN(-ENOMEM);
}

static int osd_bufs_get(const struct lu_env *env, struct dt_object *dt,
			loff_t offset, ssize_t len, struct niobuf_local *lnb,
			int rw, struct lustre_capa *capa)
{
	struct osd_object *obj  = osd_dt_obj(dt);
	int                rc;

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_db);

	if (rw == 0)
		rc = osd_bufs_get_read(env, obj, offset, len, lnb);
	else
		rc = osd_bufs_get_write(env, obj, offset, len, lnb);

	return rc;
}

static int osd_write_prep(const struct lu_env *env, struct dt_object *dt,
			struct niobuf_local *lnb, int npages)
{
	struct osd_object *obj = osd_dt_obj(dt);

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_db);

	return 0;
}

static int osd_declare_write_commit(const struct lu_env *env,
				struct dt_object *dt,
				struct niobuf_local *lnb, int npages,
				struct thandle *th)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_thandle *oh;
	uint64_t            offset = 0;
	uint32_t            size = 0;
	int                 i;
	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_db);

	LASSERT(lnb);
	LASSERT(npages > 0);

	oh = container_of0(th, struct osd_thandle, ot_super);

	for (i = 0; i < npages; i++) {
		if (lnb[i].rc)
			/* ENOSPC, network RPC error, etc.
			 * We don't want to book space for pages which will be
			 * skipped in osd_write_commit(). Hence we skip pages
			 * with lnb_rc != 0 here too */
			continue;
		if (size == 0) {
			/* first valid lnb */
			offset = lnb[i].lnb_file_offset;
			size = lnb[i].len;
			continue;
		}
		if (offset + size == lnb[i].lnb_file_offset) {
			/* this lnb is contiguous to the previous one */
			size += lnb[i].len;
			continue;
		}

		dmu_tx_hold_write(oh->ot_tx, obj->oo_db->db_object, offset,size);

		offset = lnb->lnb_file_offset;
		size = lnb->len;
	}

	if (size)
		dmu_tx_hold_write(oh->ot_tx, obj->oo_db->db_object, offset,size);

	dmu_tx_hold_sa(oh->ot_tx, obj->oo_sa_hdl, 0);

	oh->ot_write_commit = 1; /* used in osd_trans_start() for fail_loc */

	RETURN(0);
}

static int osd_write_commit(const struct lu_env *env, struct dt_object *dt,
			struct niobuf_local *lnb, int npages,
			struct thandle *th)
{
	struct osd_object  *obj  = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	udmu_objset_t      *uos = &osd->od_objset;
	struct osd_thandle *oh;
	uint64_t            new_size = 0;
	int                 i, rc = 0;
	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_db);

	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

	for (i = 0; i < npages; i++) {
		CDEBUG(D_INODE, "write %u bytes at %u\n",
			(unsigned) lnb[i].len,
			(unsigned) lnb[i].lnb_file_offset);

		if (lnb[i].rc) {
			/* ENOSPC, network RPC error, etc.
			 * Unlike ldiskfs, zfs allocates new blocks on rewrite,
			 * so we skip this page if lnb_rc is set to -ENOSPC */
			CDEBUG(D_INODE, "obj "DFID": skipping lnb[%u]: rc=%d\n",
				PFID(lu_object_fid(&dt->do_lu)), i,
				lnb[i].rc);
			continue;
		}

		if (lnb[i].page->mapping == (void *)obj) {
			dmu_write(osd->od_objset.os, obj->oo_db->db_object,
				lnb[i].lnb_file_offset, lnb[i].len,
				kmap(lnb[i].page), oh->ot_tx);
			kunmap(lnb[i].page);
		} else if (lnb[i].dentry) {
			LASSERT(((unsigned long)lnb[i].dentry & 1) == 0);
			/* buffer loaned for zerocopy, try to use it.
			 * notice that dmu_assign_arcbuf() is smart
			 * enough to recognize changed blocksize
			 * in this case it fallbacks to dmu_write() */
			dmu_assign_arcbuf(obj->oo_db, lnb[i].lnb_file_offset,
					(void *)lnb[i].dentry, oh->ot_tx);
			/* drop the reference, otherwise osd_put_bufs()
			 * will be releasing it - bad! */
			lnb[i].dentry = NULL;
			cfs_atomic_dec(&osd->od_zerocopy_loan);
		}

		if (new_size < lnb[i].lnb_file_offset + lnb[i].len)
			new_size = lnb[i].lnb_file_offset + lnb[i].len;
	}

	if (unlikely(new_size == 0)) {
		/* no pages to write, no transno is needed */
		th->th_local = 1;
		/* it is important to return 0 even when all lnb_rc == -ENOSPC
		 * since ofd_commitrw_write() retries several times on ENOSPC */
		RETURN(0);
	}

	cfs_write_lock(&obj->oo_attr_lock);
	if (obj->oo_attr.la_size < new_size) {
		obj->oo_attr.la_size = new_size;
		cfs_write_unlock(&obj->oo_attr_lock);
		/* osd_object_sa_update() will be copying directly from
		 * oo_attr into dbuf. any update within a single txg will copy
		 * the most actual */
		rc = osd_object_sa_update(obj, SA_ZPL_SIZE(uos),
					&obj->oo_attr.la_size, 8, oh);
	} else {
		cfs_write_unlock(&obj->oo_attr_lock);
	}

	RETURN(rc);
}

static int osd_read_prep(const struct lu_env *env, struct dt_object *dt,
			struct niobuf_local *lnb, int npages)
{
	struct osd_object *obj  = osd_dt_obj(dt);
	struct lu_buf      buf;
	loff_t             offset;
	int                i;

	LASSERT(dt_object_exists(dt));
	LASSERT(obj->oo_db);

	for (i = 0; i < npages; i++) {
		buf.lb_buf = kmap(lnb[i].page);
		buf.lb_len = lnb[i].len;
		offset = lnb[i].lnb_file_offset;

		CDEBUG(D_OTHER, "read %u bytes at %u\n",
			(unsigned) lnb[i].len,
			(unsigned) lnb[i].lnb_file_offset);
		lnb[i].rc = osd_read(env, dt, &buf, &offset, NULL);
		kunmap(lnb[i].page);

		if (lnb[i].rc < buf.lb_len) {
			/* all subsequent rc should be 0 */
			while (++i < npages)
				lnb[i].rc = 0;
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
static int __osd_object_punch(objset_t *os, dmu_buf_t *db, dmu_tx_t *tx,
				uint64_t size, uint64_t off, uint64_t len)
{
	int rc = 0;

	/* Assert that the transaction has been assigned to a
	   transaction group. */
	LASSERT(tx->tx_txg != 0);
	/*
	 * Nothing to do if file already at desired length.
	 */
	if (len == DMU_OBJECT_END && size == off)
		return 0;

	if (off < size)
		rc = -dmu_free_range(os, db->db_object, off, len, tx);

	return rc;
}

static int osd_punch(const struct lu_env *env, struct dt_object *dt,
			__u64 start, __u64 end, struct thandle *th,
			struct lustre_capa *capa)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_device  *osd = osd_obj2dev(obj);
	udmu_objset_t      *uos = &osd->od_objset;
	struct osd_thandle *oh;
	__u64               len;
	int                 rc = 0;
	ENTRY;

	LASSERT(dt_object_exists(dt));
	LASSERT(osd_invariant(obj));

	LASSERT(th != NULL);
	oh = container_of0(th, struct osd_thandle, ot_super);

	cfs_write_lock(&obj->oo_attr_lock);
	/* truncate */
	if (end == OBD_OBJECT_EOF || end >= obj->oo_attr.la_size)
		len = DMU_OBJECT_END;
	else
		len = end - start;
	cfs_write_unlock(&obj->oo_attr_lock);

	rc = __osd_object_punch(osd->od_objset.os, obj->oo_db, oh->ot_tx,
				obj->oo_attr.la_size, start, len);
	/* set new size */
	if (len == DMU_OBJECT_END) {
		cfs_write_lock(&obj->oo_attr_lock);
		obj->oo_attr.la_size = start;
		cfs_write_unlock(&obj->oo_attr_lock);
		rc = osd_object_sa_update(obj, SA_ZPL_SIZE(uos),
					&obj->oo_attr.la_size, 8, oh);
	}
	RETURN(rc);
}

static int osd_declare_punch(const struct lu_env *env, struct dt_object *dt,
			__u64 start, __u64 end, struct thandle *handle)
{
	struct osd_object  *obj = osd_dt_obj(dt);
	struct osd_thandle *oh;
	__u64		    len;
	ENTRY;

	oh = container_of0(handle, struct osd_thandle, ot_super);

	cfs_read_lock(&obj->oo_attr_lock);
	if (end == OBD_OBJECT_EOF || end >= obj->oo_attr.la_size)
		len = DMU_OBJECT_END;
	else
		len = end - start;

	/* declare we'll free some blocks ... */
	if (start < obj->oo_attr.la_size) {
		cfs_read_unlock(&obj->oo_attr_lock);
		dmu_tx_hold_free(oh->ot_tx, obj->oo_db->db_object, start, len);
	} else {
		cfs_read_unlock(&obj->oo_attr_lock);
	}

	/* ... and we'll modify size attribute */
	dmu_tx_hold_sa(oh->ot_tx, obj->oo_sa_hdl, 0);

	RETURN(0);
}


struct dt_body_operations osd_body_ops = {
	.dbo_read			= osd_read,
	.dbo_declare_write		= osd_declare_write,
	.dbo_write			= osd_write,
	.dbo_bufs_get			= osd_bufs_get,
	.dbo_bufs_put			= osd_bufs_put,
	.dbo_write_prep			= osd_write_prep,
	.dbo_declare_write_commit	= osd_declare_write_commit,
	.dbo_write_commit		= osd_write_commit,
	.dbo_read_prep			= osd_read_prep,
	.do_declare_punch		= osd_declare_punch,
	.do_punch			= osd_punch,
};

