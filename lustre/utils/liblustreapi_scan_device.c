// SPDX-License-Identifier: LGPL-2.1+

/*
 * Copyright (c) 2026, The Lustre Collective.
 */

/*
 * llapi_scan_device(): llapi_scan_namespace()'s records, read off a
 * target instead of walked from a client.  A backend reads the objects
 * (lustreapi_scan_backend.h) and everything Lustre knows about them is
 * here, which is what keeps libext2fs out of this library.
 *
 * Author: Hiroshi Nishida <hnishida@thelustrecollective.com>
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <asm/byteorder.h>
#include <linux/lustre/lustre_fid.h>
#include <linux/lustre/lustre_idl.h>
#include <linux/lustre/lustre_user.h>

#include <lustre/lustreapi.h>

#include "lustreapi_internal.h"
#include "lustreapi_scan_backend.h"

#ifdef PLUGIN_DIR
#include <dlfcn.h>
#endif

/* One scan.  Shared by every worker; only sd_cursor, sd_end, sd_stop_rc and
 * sd_error are written after the workers start, and those are atomic.
 */
struct scan_dev {
	const struct llapi_scan_backend	*sd_be;
	void				*sd_tgt;
	struct llapi_scan_tgt		 sd_tgt_info;
	llapi_scan_cb_t			 sd_cb;
	llapi_scan_cb_t			 sd_filter;
	void				*sd_data;
	__u64				 sd_want;
	__u64				 sd_flags;
	enum llapi_scan_class		 sd_visible;
	__u32				 sd_want_xattr;
	__u64				 sd_cursor;	/* next chunk out */
	__u64				 sd_end;	/* one past the last */
	int				 sd_stop_rc;	/* consumer's value */
	int				 sd_error;	/* backend's, first */
};

/*
 * Room for one converted directory stripe: the header and a zeroed entry for
 * every stripe a directory can have, so lum_stripe_count never claims more
 * entries than the buffer holds.  The shard FIDs are not filled.  It is
 * XATTR_SIZE_MAX, so any foreign LMV an MDT can store fits whole.
 */
#define SCAN_LMV_BUF	XATTR_SIZE_MAX
static_assert(sizeof(struct lmv_user_md) +
	      LMV_MAX_STRIPE_COUNT * sizeof(struct lmv_user_mds_data) <=
	      SCAN_LMV_BUF, "SCAN_LMV_BUF holds every stripe");

/* One worker: its own backend context, its own counters, its own name
 * buffer, so that nothing but the merge at the end is shared.
 */
struct scan_worker {
	struct scan_dev		*sw_dev;
	void			*sw_bectx;
	struct llapi_scan_stats	 sw_stats;
	char			 sw_name[NAME_MAX + 1];
	/*
	 * The record's LMV is an lmv_user_md, or an lmv_foreign_md for a
	 * foreign directory, and the target holds the on-disk form:
	 * scan_lmv_to_user() converts into here.  A union rather than a
	 * bare char[], which would carry neither structure's alignment and
	 * leave the cast at the call site assuming one.
	 */
	union {
		struct lmv_user_md	 sl_user;
		struct lmv_foreign_md	 sl_foreign;
		char			 sl_buf[SCAN_LMV_BUF];
	}			 sw_lmv;
	pthread_t		 sw_thread;
};

/*
 * The xattrs a demand mask implies.  trusted.lma and trusted.link are always
 * read: an object without an LMA has no FID and no class, and on an MDT one
 * with a namespace FID but no link is the target's own and not a file's --
 * see scan_classify().  A size needs two, trusted.lov to say whether the
 * object's own size is the file's and trusted.som to answer when it is not.
 */
static __u32 scan_want_xattr(__u64 want)
{
	__u32 xa = LLAPI_SCAN_XA_BIT(LLAPI_SCAN_XA_LMA) |
		   LLAPI_SCAN_XA_BIT(LLAPI_SCAN_XA_LINK);

	if (want & LLAPI_SCAN_LAYOUT)
		xa |= LLAPI_SCAN_XA_BIT(LLAPI_SCAN_XA_LOV);
	if (want & LLAPI_SCAN_LMV)
		xa |= LLAPI_SCAN_XA_BIT(LLAPI_SCAN_XA_LMV);
	/*
	 * trusted.lmv with it: a striped directory's own size is not the
	 * directory's, and scan_size() has no other way to tell one.
	 */
	if (want & (LLAPI_SCAN_SIZE | LLAPI_SCAN_BLOCKS |
		    LLAPI_SCAN_LAZY_SIZE | LLAPI_SCAN_LAZY_BLOCKS))
		xa |= LLAPI_SCAN_XA_BIT(LLAPI_SCAN_XA_LOV) |
		      LLAPI_SCAN_XA_BIT(LLAPI_SCAN_XA_SOM) |
		      LLAPI_SCAN_XA_BIT(LLAPI_SCAN_XA_LMV);
	if (want & LLAPI_SCAN_HSM)
		xa |= LLAPI_SCAN_XA_BIT(LLAPI_SCAN_XA_HSM);

	return xa;
}

static const void *scan_xattr(const struct llapi_scan_obj *obj,
			      enum llapi_scan_xattr x, size_t *len)
{
	if (!(obj->so_xa_valid & LLAPI_SCAN_XA_BIT(x)))
		return NULL;
	*len = obj->so_xattr[x].sv_len;
	return obj->so_xattr[x].sv_buf;
}

/* Whether the object has a trusted.link, as every name in the namespace does */
static bool scan_has_link(const struct llapi_scan_obj *obj)
{
	size_t len;

	return scan_xattr(obj, LLAPI_SCAN_XA_LINK, &len) != NULL;
}

/*
 * The LMA as it is on disk is little-endian, which is what osd_get_lma()
 * undoes on the way in.  Never trust the length: this is a structure read
 * out of a device buffer that may have been written while we read it.
 */
static bool scan_decode_lma(const struct llapi_scan_obj *obj,
			    struct lustre_mdt_attrs *lma)
{
	const struct lustre_mdt_attrs *disk;
	size_t len = 0;

	disk = scan_xattr(obj, LLAPI_SCAN_XA_LMA, &len);
	if (disk == NULL || len < sizeof(*lma))
		return false;

	lma->lma_compat = __le32_to_cpu(disk->lma_compat);
	lma->lma_incompat = __le32_to_cpu(disk->lma_incompat);
	lma->lma_self_fid.f_seq = __le64_to_cpu(disk->lma_self_fid.f_seq);
	lma->lma_self_fid.f_oid = __le32_to_cpu(disk->lma_self_fid.f_oid);
	lma->lma_self_fid.f_ver = __le32_to_cpu(disk->lma_self_fid.f_ver);

	return true;
}

/*
 * What an object is, following osd_scrub_get_fid() and, for the visible
 * answer, fid_is_namespace_visible().  A FID is never invented for an object
 * without an LMA: reconstructing one is LFSCK's job.
 *
 * fid_is_namespace_visible() goes by the FID alone, which is not enough on
 * an MDT: the target's own files outside ROOT -- CONFIGS/mountdata with an
 * IGIF, the update logs with a normal FID -- pass it.  What they lack is a
 * name in the namespace, so an MDT object with such a FID and no trusted.link
 * is the target's own.  So is a user file whose trusted.link was lost: it is
 * reachable, but nothing here says so.
 */
static enum llapi_scan_class scan_classify(const struct lustre_mdt_attrs *lma,
					   bool have_lma, bool mdt,
					   bool have_link)
{
	__u64 seq;

	if (!have_lma)
		return LLAPI_SCAN_CLS_NO_LMA;

	if (lma->lma_incompat & ~(__u32)LMA_INCOMPAT_SUPP)
		return LLAPI_SCAN_CLS_BAD;
	if (lma->lma_compat & LMAC_NOT_IN_OI)
		return LLAPI_SCAN_CLS_INTERNAL;
	if (lma->lma_incompat & LMAI_AGENT)
		return LLAPI_SCAN_CLS_AGENT;
	/*
	 * An O/<seq>/LAST_ID has f_oid 0 and its sequence's own f_seq, so it
	 * would otherwise look like an ordinary object of that sequence.
	 * fid_is_namespace_visible() excludes it and so must this, or the
	 * target's own counter is delivered as its subject matter -- and
	 * before the OST tests, not after: osd_object_create() sets
	 * LMAC_FID_ON_OST for it, fid_is_on_ost() being true of a LAST_ID,
	 * so on an OST the counter answered as a data object.
	 */
	if (fid_is_last_id(&lma->lma_self_fid))
		return LLAPI_SCAN_CLS_INTERNAL;
	if (lma->lma_compat & LMAC_FID_ON_OST)
		return LLAPI_SCAN_CLS_OST_OBJ;

	seq = lma->lma_self_fid.f_seq;
	if (fid_seq_is_idif(seq))
		return LLAPI_SCAN_CLS_OST_OBJ;
	/*
	 * PENDING keeps a link to an open-unlinked file, so it has a normal
	 * FID and would otherwise read as visible.  Last of the tests, so
	 * only what would have been visible changes class.
	 */
	if (lma->lma_incompat & LMAI_ORPHAN)
		return LLAPI_SCAN_CLS_ORPHAN;
	/*
	 * The root itself, not its whole sequence: fid_is_namespace_visible()
	 * uses fid_is_root(), one FID out of FID_SEQ_ROOT, so a wider test
	 * here would classify the echo client's root -- FID_OID_ECHO_ROOT in
	 * the same sequence -- as namespace-visible where the MDT would not.
	 */
	if (fid_is_root(&lma->lma_self_fid) || fid_seq_is_dot(seq))
		return LLAPI_SCAN_CLS_VISIBLE;
	if (fid_seq_is_norm(seq) || fid_seq_is_igif(seq))
		return mdt && !have_link ? LLAPI_SCAN_CLS_INTERNAL :
					   LLAPI_SCAN_CLS_VISIBLE;

	return LLAPI_SCAN_CLS_INTERNAL;
}

/*
 * The master object of a striped directory: trusted.lmv holding an
 * lmv_mds_md_v1, which is what lmv_dir_striped() tests on the client side.
 * A shard's own LMV_MAGIC_STRIPE and a foreign LMV are neither.
 */
static bool scan_lmv_is_striped(const struct llapi_scan_obj *obj)
{
	size_t len = 0;
	__u32 magic;
	const void *lmv;

	lmv = scan_xattr(obj, LLAPI_SCAN_XA_LMV, &len);
	if (lmv == NULL || len < sizeof(magic))
		return false;

	memcpy(&magic, lmv, sizeof(magic));

	return __le32_to_cpu(magic) == LMV_MAGIC_V1;
}

/*
 * The directory stripe, converted to the form the record declares.
 *
 * A target holds trusted.lmv as lmv_mds_md_v1, little-endian; the record's
 * lfsr_lmv is an lmv_user_md, which is what a namespace scan puts there and
 * what every consumer of this API reads.  They are different structures --
 * lum_type and lum_max_inherit sit where lmv_layout_version and
 * lmv_migrate_offset do, and the pool name is at a different offset -- so
 * handing the raw bytes over would make the field mean one thing from one
 * scanner and another from the other.
 *
 * The shard FIDs are not carried: the user form names each stripe by FID and
 * MDT index, and the index is an FLD lookup, which a scan of a target has no
 * client to make.  A consumer that needs them reads the directory through a
 * mount.
 *
 * Returns the bytes written at @out, or 0 if there is nothing a consumer of
 * lmv_user_md could read -- a slave stripe's own LMV_MAGIC_STRIPE, an
 * unknown magic, or a value too large for @outlen.
 */
static __u32 scan_lmv_to_user(const void *disk, __u32 len, void *out,
			      __u32 outlen)
{
	const struct lmv_mds_md_v1 *md = disk;
	struct lmv_user_md *lmv = out;
	__u32 stripes, room;
	__u32 magic;

	if (len < sizeof(__u32))
		return 0;

	memcpy(&magic, disk, sizeof(magic));
	magic = __le32_to_cpu(magic);

	if (magic == LMV_MAGIC_FOREIGN) {
		/*
		 * Same structure on both sides, so this is a copy with the
		 * header put in host order.  lfm_value is opaque bytes and
		 * stays as it is.
		 */
		struct lmv_foreign_md *lfm = out;

		if (len < offsetof(struct lmv_foreign_md, lfm_value) ||
		    len > outlen)
			return 0;
		memcpy(out, disk, len);
		lfm->lfm_magic = magic;
		lfm->lfm_length = __le32_to_cpu(lfm->lfm_length);
		lfm->lfm_type = __le32_to_cpu(lfm->lfm_type);
		lfm->lfm_flags = __le32_to_cpu(lfm->lfm_flags);
		if (lfm->lfm_length >
		    len - offsetof(struct lmv_foreign_md, lfm_value))
			return 0;
		return len;
	}

	if (magic != LMV_MAGIC_V1 || len < sizeof(*md) ||
	    outlen < lmv_user_md_size(0, LMV_USER_MAGIC))
		return 0;

	/*
	 * The header is not the whole of what a reader may touch.  One
	 * buffer serves every object a worker meets, and a consumer sizing
	 * lum_objects[] by lum_stripe_count -- which is what
	 * lmv_dump_user_lmm() does -- reads past the header into whatever
	 * the last object left there, a preceding foreign LMV's value
	 * included.  The buffer holds at least LMV_MAX_STRIPE_COUNT entries, so
	 * the whole shard area the count claims is cleared.
	 *
	 * The count comes off a device, so the room bounds it before it
	 * measures anything.
	 */
	stripes = __le32_to_cpu(md->lmv_stripe_count);
	/*
	 * A count no Lustre directory can have is not a count: refused here
	 * rather than carried, because lmv_user_md_size() returns unsigned
	 * int and a count whose product with sizeof(struct lmv_user_mds_data)
	 * is a multiple of 2^32 -- 0x20000000 and its multiples -- computes
	 * back to the bare header size, so every bound built from it reads
	 * as "the array is there" for an array that is not.
	 */
	if (stripes > LMV_MAX_STRIPE_COUNT)
		return 0;
	room = (outlen - lmv_user_md_size(0, LMV_USER_MAGIC)) /
	       sizeof(struct lmv_user_mds_data);
	memset(out, 0, lmv_user_md_size(stripes < room ? stripes : room,
					LMV_USER_MAGIC_SPECIFIC));
	/*
	 * LMV_MAGIC_V1 and not LMV_USER_MAGIC: this is the directory's own
	 * stripe, read from trusted.lmv, and the rest of the library uses
	 * LMV_USER_MAGIC for a *default* LMV -- which lives in trusted.dmv
	 * and is not asked for here.  lmv_dump_user_lmm() keys off it for the
	 * "(Default)" prefix and for which fields a bare -v shows, and llite
	 * fills LMV_MAGIC_V1 for LL_IOC_LMV_GETSTRIPE, so the two scanners
	 * would otherwise describe one striped directory differently.  The
	 * size is the same either way: lmv_user_md_size() only grows for
	 * LMV_USER_MAGIC_SPECIFIC.
	 */
	lmv->lum_magic = LMV_MAGIC_V1;
	lmv->lum_stripe_count = __le32_to_cpu(md->lmv_stripe_count);
	lmv->lum_stripe_offset = __le32_to_cpu(md->lmv_master_mdt_index);
	lmv->lum_hash_type = __le32_to_cpu(md->lmv_hash_type);
	memcpy(lmv->lum_pool_name, md->lmv_pool_name,
	       sizeof(lmv->lum_pool_name));
	lmv->lum_pool_name[sizeof(lmv->lum_pool_name) - 1] = '\0';

	return lmv_user_md_size(0, LMV_USER_MAGIC);
}

/*
 * The first linkea entry: a name, and the FID of the directory it is in.
 * Entries are big-endian, the header is not necessarily; the kernel's
 * linkea_init() and linkea_entry_unpack() are what this mirrors.
 *
 * A name is not a path.  Turning one into the other is a walk of its own
 * and is not this scan's to do.
 */
static void scan_linkea(const struct llapi_scan_obj *obj, char *name,
			size_t namesize, struct llapi_scan_rec *rec)
{
	const struct link_ea_header *leh;
	const struct link_ea_entry *lee;
	size_t len = 0;
	__u32 reccount;
	__u32 magic;
	int reclen;
	int namelen;

	leh = scan_xattr(obj, LLAPI_SCAN_XA_LINK, &len);
	if (leh == NULL || len < sizeof(*leh))
		return;

	magic = leh->leh_magic;
	reccount = leh->leh_reccount;
	if (magic == __swab32(LINK_EA_MAGIC)) {
		magic = LINK_EA_MAGIC;
		reccount = __swab32(reccount);
	}
	if (magic != LINK_EA_MAGIC || reccount == 0)
		return;

	rec->lfsr_linkea = leh;
	rec->lfsr_linkeasize = len;
	rec->lfsr_valid |= LLAPI_SCAN_LINKEA;

	if (len < sizeof(*leh) + sizeof(*lee))
		return;

	lee = (const struct link_ea_entry *)(leh + 1);
	reclen = (lee->lee_reclen[0] << 8) | lee->lee_reclen[1];
	namelen = reclen - (int)sizeof(*lee);
	if (reclen <= (int)sizeof(*lee) ||
	    (size_t)reclen > len - sizeof(*leh))
		return;

	memcpy(&rec->lfsr_parent_fid, lee->lee_parent_fid,
	       sizeof(rec->lfsr_parent_fid));
	rec->lfsr_parent_fid.f_seq = __be64_to_cpu(rec->lfsr_parent_fid.f_seq);
	rec->lfsr_parent_fid.f_oid = __be32_to_cpu(rec->lfsr_parent_fid.f_oid);
	rec->lfsr_parent_fid.f_ver = __be32_to_cpu(rec->lfsr_parent_fid.f_ver);
	if (fid_is_sane(&rec->lfsr_parent_fid))
		rec->lfsr_valid |= LLAPI_SCAN_PARENT;
	else
		memset(&rec->lfsr_parent_fid, 0, sizeof(rec->lfsr_parent_fid));

	if ((size_t)namelen >= namesize)
		namelen = namesize - 1;
	memcpy(name, lee->lee_name, namelen);
	name[namelen] = '\0';
	rec->lfsr_name = name;
}

/*
 * HSM state, from trusted.hsm.  Its flags are the HS_* values the MDT hands
 * to llapi_hsm_state_get(), and the archive id narrows the same way there,
 * so both producers answer alike.
 */
static void scan_hsm(const struct llapi_scan_obj *obj,
		     struct llapi_scan_rec *rec)
{
	const struct hsm_attrs *hsm;
	size_t len = 0;

	hsm = scan_xattr(obj, LLAPI_SCAN_XA_HSM, &len);
	if (hsm == NULL || len < sizeof(*hsm))
		return;

	rec->lfsr_hsm_states = __le32_to_cpu(hsm->hsm_flags);
	rec->lfsr_hsm_archive_id = __le64_to_cpu(hsm->hsm_arch_id);
	rec->lfsr_valid |= LLAPI_SCAN_HSM;
}

/*
 * Whether HSM has released the file, decided as mdt_hsm_is_released()
 * does: every component released.  The bytes are raw from the target.
 */
static bool scan_lov_released(const void *buf, size_t len)
{
	const struct lov_comp_md_v1 *comp = buf;
	const struct lov_user_md_v1 *v1 = buf;
	__u32 magic;
	__u16 count;
	__u16 i;

	if (len < sizeof(*v1))
		return false;

	magic = __le32_to_cpu(v1->lmm_magic);
	if (magic == LOV_MAGIC_V1 || magic == LOV_MAGIC_V3)
		return __le32_to_cpu(v1->lmm_pattern) & LOV_PATTERN_F_RELEASED;
	if (magic != LOV_MAGIC_COMP_V1 || len < sizeof(*comp))
		return false;

	count = __le16_to_cpu(comp->lcm_entry_count);
	if (len < sizeof(*comp) + count * sizeof(comp->lcm_entries[0]))
		return false;
	for (i = 0; i < count; i++) {
		__u32 off = __le32_to_cpu(comp->lcm_entries[i].lcme_offset);

		if (off > len - sizeof(*v1))
			return false;
		v1 = (const struct lov_user_md_v1 *)((const char *)buf + off);
		if (!(__le32_to_cpu(v1->lmm_pattern) & LOV_PATTERN_F_RELEASED))
			return false;
	}
	return true;
}

/*
 * Whether every instantiated component is on the MDT, as
 * mdt_lmm_dom_entry_check() decides for is_dom_only: then the MDT inode
 * holds the data, the MDT keeps no SOM for it (mdt_som.c), and the inode's
 * own size is the file's.  The bytes are raw from the target.
 */
static bool scan_lov_dom_only(const void *buf, size_t len)
{
	const struct lov_comp_md_v1 *comp = buf;
	const struct lov_user_md_v1 *v1;
	bool dom = false;
	__u16 count;
	__u16 i;

	if (len < sizeof(*comp) ||
	    __le32_to_cpu(comp->lcm_magic) != LOV_MAGIC_COMP_V1)
		return false;

	count = __le16_to_cpu(comp->lcm_entry_count);
	if (len < sizeof(*comp) + count * sizeof(comp->lcm_entries[0]))
		return false;
	for (i = 0; i < count; i++) {
		const struct lov_comp_md_entry_v1 *e = &comp->lcm_entries[i];
		__u32 off = __le32_to_cpu(e->lcme_offset);

		if (!(__le32_to_cpu(e->lcme_flags) & LCME_FL_INIT))
			continue;
		if (off > len - sizeof(*v1))
			return false;
		v1 = (const struct lov_user_md_v1 *)((const char *)buf + off);
		if (!(__le32_to_cpu(v1->lmm_pattern) & LOV_PATTERN_MDT))
			return false;
		dom = true;
	}
	return dom;
}

/*
 * Size and blocks.  The object's own size is the file's when the file has
 * no layout, HSM has released it, or all its data is on the MDT; trusted.som
 * answers otherwise, and answers lazily, which is what LLAPI_SCAN_LAZY_SIZE
 * already means.
 */
static void scan_size(const struct llapi_scan_obj *obj, __u64 want,
		      bool ost, struct llapi_scan_rec *rec)
{
	const struct lustre_som_attrs *som;
	const void *lov;
	size_t len = 0;
	__u16 valid;

	/*
	 * Only when asked for: without the demand mask naming a size, no
	 * layout was read, so nothing here knows whether the object's own
	 * size is the file's.
	 */
	if (!(want & (LLAPI_SCAN_SIZE | LLAPI_SCAN_BLOCKS |
		      LLAPI_SCAN_LAZY_SIZE | LLAPI_SCAN_LAZY_BLOCKS)))
		return;

	/*
	 * A striped directory's size and blocks are aggregated by the client
	 * across its shards, so the master object's own are not the
	 * directory's: ll_dir_ioctl() drops STATX_SIZE and STATX_BLOCKS for
	 * one, and a scan of a target, which holds only the master, answers
	 * "not known" as well rather than a number of its own.
	 */
	if (S_ISDIR(obj->so_mode) && scan_lmv_is_striped(obj))
		return;

	if (!S_ISREG(obj->so_mode) ||
	    !(obj->so_xa_valid & LLAPI_SCAN_XA_BIT(LLAPI_SCAN_XA_LOV))) {
		/* nothing is striped out from under it */
		rec->lfsr_stx.stx_size = obj->so_size;
		/*
		 * A regular file with no layout has no data blocks on an MDT:
		 * the inode's own are its xattrs, which mdt_pack_attr2body()
		 * does not report either.  On an OST the object is the data,
		 * so its own blocks are exactly what that target holds, which
		 * is what llapi_scan_device.3 promises for one.
		 */
		rec->lfsr_stx.stx_blocks = S_ISREG(obj->so_mode) && !ost ? 0 :
					   obj->so_blocks;
		rec->lfsr_stx.stx_mask |= STATX_SIZE | STATX_BLOCKS;
		return;
	}

	/* released: the MDT inode holds the size; one block, as for a client */
	lov = scan_xattr(obj, LLAPI_SCAN_XA_LOV, &len);
	if (lov != NULL && scan_lov_released(lov, len)) {
		rec->lfsr_stx.stx_size = obj->so_size;
		rec->lfsr_stx.stx_blocks = obj->so_size == 0 ? 0 : 1;
		rec->lfsr_stx.stx_mask |= STATX_SIZE | STATX_BLOCKS;
		return;
	}
	/* Data-on-MDT only: the inode is the data, as an OST object is */
	if (lov != NULL && scan_lov_dom_only(lov, len)) {
		rec->lfsr_stx.stx_size = obj->so_size;
		rec->lfsr_stx.stx_blocks = obj->so_blocks;
		rec->lfsr_stx.stx_mask |= STATX_SIZE | STATX_BLOCKS;
		return;
	}

	som = scan_xattr(obj, LLAPI_SCAN_XA_SOM, &len);
	if (som == NULL || len < sizeof(*som))
		return;

	valid = __le16_to_cpu(som->lsa_valid);
	if (!(valid & (SOM_FL_STRICT | SOM_FL_LAZY | SOM_FL_STALE)))
		return;

	rec->lfsr_stx.stx_size = __le64_to_cpu(som->lsa_size);
	rec->lfsr_stx.stx_blocks = __le64_to_cpu(som->lsa_blocks);
	/*
	 * SOM_FL_STRICT is "known strictly correct", and the MDT hands that
	 * one to a client as a real size: mdt_pack_attr2body() sets
	 * OBD_MD_FLSIZE and OBD_MD_FLBLOCKS for it while
	 * mdt_enable_strict_som is on, which it is by default.  Collapsing
	 * all three states to lazy would report the same file as approximate
	 * from a target and exact from a namespace, which is the difference
	 * the two bits exist to carry.
	 */
	if (valid & SOM_FL_STRICT)
		rec->lfsr_stx.stx_mask |= STATX_SIZE | STATX_BLOCKS;
	else
		rec->lfsr_valid |= LLAPI_SCAN_LAZY_SIZE |
				   LLAPI_SCAN_LAZY_BLOCKS;
}

/* The attributes the object carries itself, before any xattr is read. */
static void scan_rec_obj(const struct scan_dev *dev,
			 const struct llapi_scan_obj *obj,
			 struct llapi_scan_rec *rec)
{
	memset(rec, 0, sizeof(*rec));
	rec->lfsr_size = sizeof(*rec);
	rec->lfsr_parent_fd = -1;
	rec->lfsr_fd = -1;

	rec->lfsr_ino = obj->so_id;
	rec->lfsr_stx.stx_mode = obj->so_mode;
	rec->lfsr_stx.stx_nlink = obj->so_nlink;
	rec->lfsr_stx.stx_uid = obj->so_uid;
	rec->lfsr_stx.stx_gid = obj->so_gid;
	/*
	 * la_rdev holds the client's old_encode_dev() value; decode it as
	 * ll_update_inode() does, so this is what stat(2) shows.
	 */
	if (S_ISCHR(obj->so_mode) || S_ISBLK(obj->so_mode)) {
		rec->lfsr_stx.stx_rdev_major = (obj->so_rdev >> 8) & 0xff;
		rec->lfsr_stx.stx_rdev_minor = obj->so_rdev & 0xff;
	}
	rec->lfsr_stx.stx_blksize = getpagesize();	/* as ll_dir_ioctl() */
	/*
	 * The backend ABI carries whole seconds, so the nanoseconds are zero
	 * rather than unknown -- statx has no bit for a timestamp's fraction
	 * on its own, and a target's inode is not read at that resolution.
	 */
	rec->lfsr_stx.stx_atime.tv_sec = obj->so_atime;
	rec->lfsr_stx.stx_mtime.tv_sec = obj->so_mtime;
	rec->lfsr_stx.stx_ctime.tv_sec = obj->so_ctime;
	rec->lfsr_stx.stx_mask = STATX_MODE | STATX_TYPE | STATX_NLINK |
			       STATX_UID | STATX_GID | STATX_ATIME |
			       STATX_MTIME | STATX_CTIME;
	/*
	 * What this backend can answer for, as statx means it: the two do not
	 * support the same set, so the declaration is the backend's and not
	 * one constant here.  Narrowed to it for the same reason
	 * scan_rec_mdt() narrows the MDT's, so a record never reports a bit
	 * it does not also declare.  A backend that declares nothing leaves
	 * LLAPI_SCAN_ATTRS clear rather than having the record claim
	 * attributes nothing vouches for.
	 */
	rec->lfsr_stx.stx_attributes_mask = obj->so_attrs_mask;
	rec->lfsr_stx.stx_attributes = obj->so_flags & obj->so_attrs_mask;
	rec->lfsr_valid = LLAPI_SCAN_INO;
	if (obj->so_attrs_mask != 0)
		rec->lfsr_valid |= LLAPI_SCAN_ATTRS;

	if (obj->so_valid & LLAPI_SCAN_SO_BTIME) {
		rec->lfsr_stx.stx_btime.tv_sec = obj->so_btime;
		rec->lfsr_stx.stx_mask |= STATX_BTIME;
	}
	if (obj->so_valid & LLAPI_SCAN_SO_PROJID) {
		rec->lfsr_projid = obj->so_projid;
		rec->lfsr_valid |= LLAPI_SCAN_PROJID;
	}

	/*
	 * Only when the label really named an MDT and gave its number: an
	 * OST has no MDT index, and an unregistered target has none yet.
	 */
	if ((dev->sd_tgt_info.tt_flags &
	     (LLAPI_SCAN_TGT_MDT | LLAPI_SCAN_TGT_INDEX)) ==
	    (LLAPI_SCAN_TGT_MDT | LLAPI_SCAN_TGT_INDEX)) {
		rec->lfsr_mdt_index = dev->sd_tgt_info.tt_index;
		rec->lfsr_valid |= LLAPI_SCAN_MDT_INDEX;
	}
}

/*
 * Is an inode with no LMA an IGIF here?  Only on MDT0000.
 *
 * osd_scrub_get_fid() builds one only under os_convert_igif, which
 * osd_scrub_setup() sets for MDT0 alone, and says why: on another MDT the
 * object may be FID-on-OST, or carry a FID that a file-level restore has
 * already invalidated, and "we do not know which is the right FID for the
 * object".  An OST's no-LMA object is named by the IDIF in its trusted.fid,
 * which osd_get_idif() reads rather than computes -- the OST object id is in
 * the O/<seq>/d<n>/ directory entry that names the inode, not in the inode,
 * so a scan of inodes has the target's own id for it and no more.
 */
static bool scan_tgt_has_igif(const struct scan_dev *dev)
{
	__u32 need = LLAPI_SCAN_TGT_MDT | LLAPI_SCAN_TGT_INDEX;

	return (dev->sd_tgt_info.tt_flags & need) == need &&
	       dev->sd_tgt_info.tt_index == 0;
}

/*
 * An OST without OBD_ROCOMPAT_IDX_IN_IDIF (formatted before 2.6) stores its
 * IDIFs with OST index 0.  osd_check_lma() puts the index back, and so here.
 */
static void scan_idif_set_index(const struct scan_dev *dev, struct lu_fid *fid)
{
	__u32 need = LLAPI_SCAN_TGT_OST | LLAPI_SCAN_TGT_INDEX;
	__u32 idx = dev->sd_tgt_info.tt_index;

	if ((dev->sd_tgt_info.tt_flags & need) != need || idx == 0 ||
	    idx > 0xffff || !fid_is_idif(fid) || fid_idif_ost_idx(fid) != 0)
		return;

	fid->f_seq = fid_idif_seq(fid_idif_id(fid->f_seq, fid->f_oid,
					      fid->f_ver), idx);
}

/* The cheap stage: what the object carries, before any xattr is read. */
static int scan_sink_prefilter(void *ctx, const struct llapi_scan_obj *obj)
{
	struct scan_worker *w = ctx;
	struct scan_dev *dev = w->sw_dev;
	struct llapi_scan_rec rec;
	int rc;

	w->sw_stats.ss_seen++;

	if (__atomic_load_n(&dev->sd_stop_rc, __ATOMIC_ACQUIRE) != 0)
		return -1;

	if (dev->sd_filter == NULL)
		return 0;

	scan_rec_obj(dev, obj, &rec);
	rc = dev->sd_filter(&rec, dev->sd_data);
	if (rc > 0) {
		w->sw_stats.ss_filtered++;
		return 1;
	}
	if (rc < 0) {
		int zero = 0;

		__atomic_compare_exchange_n(&dev->sd_stop_rc, &zero, rc, false,
					    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
		return -1;
	}
	return 0;
}

static int scan_sink_object(void *ctx, const struct llapi_scan_obj *obj)
{
	struct scan_worker *w = ctx;
	struct scan_dev *dev = w->sw_dev;
	struct lustre_mdt_attrs lma = { 0 };
	struct llapi_scan_rec rec;
	enum llapi_scan_class cls;
	bool have_lma;
	size_t len = 0;
	const void *val;
	int rc;

	have_lma = scan_decode_lma(obj, &lma);
	cls = scan_classify(&lma, have_lma,
			    dev->sd_tgt_info.tt_flags & LLAPI_SCAN_TGT_MDT,
			    scan_has_link(obj));
	w->sw_stats.ss_class[cls]++;

	/*
	 * Only the target's own subject matter: the namespace-visible objects
	 * on an MDT, the data objects on an OST, which has no namespace at
	 * all.  The rest is counted and kept back unless it was asked for.
	 */
	if (cls != dev->sd_visible &&
	    !(dev->sd_flags & LLAPI_SCAN_F_INTERNAL))
		return 0;

	scan_rec_obj(dev, obj, &rec);

	rec.lfsr_class = cls;
	rec.lfsr_valid |= LLAPI_SCAN_CLASS;
	if (have_lma) {
		rec.lfsr_lma_compat = lma.lma_compat;
		rec.lfsr_lma_incompat = lma.lma_incompat;
		rec.lfsr_valid |= LLAPI_SCAN_LMA;
		/* the OSD keeps encryption in the LMA, not in the inode */
		rec.lfsr_stx.stx_attributes_mask |= STATX_ATTR_ENCRYPTED;
		if (lma.lma_incompat & LMAI_ENCRYPT)
			rec.lfsr_stx.stx_attributes |= STATX_ATTR_ENCRYPTED;
		rec.lfsr_valid |= LLAPI_SCAN_ATTRS;
		rec.lfsr_fid = lma.lma_self_fid;
		scan_idif_set_index(dev, &rec.lfsr_fid);
		if (fid_is_sane(&rec.lfsr_fid))
			rec.lfsr_valid |= LLAPI_SCAN_FID;
	} else if ((obj->so_valid & LLAPI_SCAN_SO_GEN) &&
		   scan_tgt_has_igif(dev)) {
		/*
		 * No LMA, so no FID of its own recorded: on MDT0000 the inode
		 * number and its generation are an IGIF, which is the FID such
		 * an object has.  osd_scrub.c answers one the same way rather
		 * than leaving a caller to assemble it.  The build takes a
		 * 32-bit inode, which is what a backend with a generation
		 * carries -- a ZFS object id is wider and has no IGIF form,
		 * and leaves LLAPI_SCAN_SO_GEN clear.
		 */
		lu_igif_build(&rec.lfsr_fid, (__u32)obj->so_id, obj->so_gen);
		/*
		 * fid_is_igif() and not fid_is_sane(): an inode numbered 1 to
		 * 11 builds a sequence fid_seq_is_rsvd() calls sane, and
		 * lustre_idl.h reserves those precisely because they are not
		 * inode numbers: lost+found would be [0xb:0x0:0x0], which is
		 * FID_SEQ_RSVD and names something else entirely.  Below the
		 * IGIF range there is no IGIF, and the object is left with
		 * the target's own id for it.
		 */
		if (fid_is_igif(&rec.lfsr_fid))
			rec.lfsr_valid |= LLAPI_SCAN_FID;
	}

	/* Raw, as on disk: llapi_layout_get_by_xattr() swabs it. */
	val = scan_xattr(obj, LLAPI_SCAN_XA_LOV, &len);
	if (val != NULL) {
		rec.lfsr_lmm = val;
		rec.lfsr_lmmsize = len;
		rec.lfsr_valid |= LLAPI_SCAN_LAYOUT;
	}
	val = scan_xattr(obj, LLAPI_SCAN_XA_LMV, &len);
	if (val != NULL) {
		__u32 ulen = scan_lmv_to_user(val, len, w->sw_lmv.sl_buf,
					      sizeof(w->sw_lmv.sl_buf));

		if (ulen != 0) {
			const struct lmv_user_md *lmv = &w->sw_lmv.sl_user;

			rec.lfsr_lmv = lmv;
			rec.lfsr_lmvsize = ulen;
			rec.lfsr_valid |= LLAPI_SCAN_LMV;
			/*
			 * scan_lmv_to_user() converts an lmv_mds_md_v1, but a
			 * foreign LMV has no such form and is copied out as
			 * the lmv_foreign_md it is.
			 */
			if (lmv_is_foreign(lmv->lum_magic))
				rec.lfsr_valid |= LLAPI_SCAN_LMV_FOREIGN;
		}
	}

	if (dev->sd_want & (LLAPI_SCAN_LINKEA | LLAPI_SCAN_PARENT))
		scan_linkea(obj, w->sw_name, sizeof(w->sw_name), &rec);
	scan_hsm(obj, &rec);
	scan_size(obj, dev->sd_want,
		  dev->sd_tgt_info.tt_flags & LLAPI_SCAN_TGT_OST, &rec);

	/* counted as handed over, as a walk counts it: a stop included */
	w->sw_stats.ss_emitted++;
	rc = dev->sd_cb(&rec, dev->sd_data);
	if (rc != 0) {
		int zero = 0;

		/* first stopper wins: several workers can decide at once */
		__atomic_compare_exchange_n(&dev->sd_stop_rc, &zero, rc, false,
					    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
		return -1;
	}

	return 0;
}

static void scan_sink_skip(void *ctx, enum llapi_scan_skip why)
{
	struct scan_worker *w = ctx;

	/*
	 * ss_seen is counted in the pre-filter, so only a skip raised before
	 * the object ever got there is counted here as well: a consumer
	 * checking its accounting needs emitted, filtered and skipped to be
	 * parts of seen rather than a separate tally.  SKIP_XATTR is raised
	 * after the pre-filter has run and its object is already in ss_seen,
	 * so counting it again would inflate exactly the torn-read case
	 * these counters exist to describe.
	 */
	if (why != LLAPI_SCAN_SKIP_XATTR)
		w->sw_stats.ss_seen++;
	w->sw_stats.ss_skipped++;
}

static void *scan_worker_run(void *arg)
{
	struct scan_worker *w = arg;
	struct scan_dev *dev = w->sw_dev;
	struct llapi_scan_sink sink = {
		.sk_ctx		= w,
		.sk_want_xattr	= dev->sd_want_xattr,
		.sk_prefilter	= scan_sink_prefilter,
		.sk_object	= scan_sink_object,
		.sk_skip	= scan_sink_skip,
	};

	for (;;) {
		__u64 idx;
		int done = 0;
		int rc;

		if (__atomic_load_n(&dev->sd_stop_rc, __ATOMIC_ACQUIRE) != 0 ||
		    __atomic_load_n(&dev->sd_error, __ATOMIC_ACQUIRE) != 0)
			break;

		idx = __atomic_fetch_add(&dev->sd_cursor, 1, __ATOMIC_RELAXED);
		if (idx >= __atomic_load_n(&dev->sd_end, __ATOMIC_ACQUIRE))
			break;

		rc = dev->sd_be->sb_scan_chunk(dev->sd_tgt, w->sw_bectx, idx,
					       &sink, &done);
		if (rc < 0) {
			int zero = 0;

			/* a consumer's stop is already recorded; anything
			 * else ends the scan, for every worker
			 */
			if (__atomic_load_n(&dev->sd_stop_rc,
					    __ATOMIC_ACQUIRE) == 0)
				__atomic_compare_exchange_n(&dev->sd_error,
							    &zero, rc, false,
							    __ATOMIC_ACQ_REL,
							    __ATOMIC_ACQUIRE);
			break;
		}

		/*
		 * The backend knows there is nothing at or beyond this
		 * chunk.  Chunks are handed out in order, so that is the end
		 * of the target for every worker, not just this one.
		 */
		if (done) {
			__u64 end = __atomic_load_n(&dev->sd_end,
						    __ATOMIC_ACQUIRE);

			while (idx + 1 < end &&
			       !__atomic_compare_exchange_n(&dev->sd_end, &end,
							    idx + 1, false,
							    __ATOMIC_ACQ_REL,
							    __ATOMIC_ACQUIRE))
				;
			break;
		}
	}

	return NULL;
}

static void scan_stats_merge(struct llapi_scan_stats *to,
			     const struct llapi_scan_stats *from)
{
	unsigned int i;

	to->ss_seen += from->ss_seen;
	to->ss_emitted += from->ss_emitted;
	to->ss_skipped += from->ss_skipped;
	to->ss_filtered += from->ss_filtered;
	for (i = 0; i < LLAPI_SCAN_CLS_MAX; i++)
		to->ss_class[i] += from->ss_class[i];
}

/*
 * The backend, loaded once: a plugin beside mount_osd_ldiskfs.so, found the
 * same way, or linked in where plugins are disabled.
 */
#ifndef PLUGIN_DIR
#ifdef HAVE_LDISKFS_SCAN
static struct llapi_scan_backend scan_backend_ldiskfs = {
	.sb_open	= scan_ldiskfs_open,
	.sb_close	= scan_ldiskfs_close,
	.sb_worker_init	= scan_ldiskfs_worker_init,
	.sb_worker_fini	= scan_ldiskfs_worker_fini,
	.sb_scan_chunk	= scan_ldiskfs_scan_chunk,
};
#endif /* HAVE_LDISKFS_SCAN */
#endif /* !PLUGIN_DIR */

static pthread_once_t scan_backend_once = PTHREAD_ONCE_INIT;
static struct llapi_scan_backend *scan_backend;

#ifdef PLUGIN_DIR
#define SCAN_DLSYM(handle, ops, func)					\
	((ops)->sb_##func = (typeof((ops)->sb_##func))			\
			    dlsym(handle, "scan_ldiskfs_" #func))

static void scan_backend_load(void)
{
	struct llapi_scan_backend *be;
	char filename[PATH_MAX];
	const char *dirname;
	void *handle;

	snprintf(filename, sizeof(filename), PLUGIN_DIR"/scan_osd_ldiskfs.so");
	handle = dlopen(filename, RTLD_NOW);

	/* $LUSTRE is how test-framework points at a build tree */
	if (handle == NULL) {
		dirname = secure_getenv("LUSTRE");
		if (dirname != NULL) {
			snprintf(filename, sizeof(filename),
				 "%s/utils/scan_osd_ldiskfs.so", dirname);
			handle = dlopen(filename, RTLD_NOW);
		}
	}
	if (handle == NULL) {
		/* worth saying out loud: the caller asked for a scan */
		llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO, -ENOTSUP,
			    "no device scan backend: %s", dlerror());
		return;
	}

	be = calloc(1, sizeof(*be));
	if (be == NULL) {
		dlclose(handle);
		return;
	}

	SCAN_DLSYM(handle, be, open);
	SCAN_DLSYM(handle, be, close);
	SCAN_DLSYM(handle, be, worker_init);
	SCAN_DLSYM(handle, be, worker_fini);
	SCAN_DLSYM(handle, be, scan_chunk);

	/*
	 * Every pointer, not dlerror(): glibc clears the pending error at the
	 * start of each _dlerror_run(), so a dlsym() that succeeds wipes what
	 * a failing one left behind and only the last of the five could be
	 * reported.  This library and the plugin ship in separate RPMs, and
	 * the $LUSTRE fallback above loads whatever a build tree has, so a
	 * scan_osd_ldiskfs.so out of step with this library is a real
	 * arrival -- and a symbol missing from it would be called through
	 * NULL.
	 */
	if (be->sb_open == NULL || be->sb_close == NULL ||
	    be->sb_worker_init == NULL || be->sb_worker_fini == NULL ||
	    be->sb_scan_chunk == NULL) {
		llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO, -ENOTSUP,
			    "%s is not a device scan backend", filename);
		dlclose(handle);
		free(be);
		return;
	}

	scan_backend = be;
}
#else /* !PLUGIN_DIR */
static void scan_backend_load(void)
{
#ifdef HAVE_LDISKFS_SCAN
	scan_backend = &scan_backend_ldiskfs;
#endif
}
#endif /* PLUGIN_DIR */

/* A Lustre target sets dirdata, which stock libext2fs refuses to open. */
static void scan_open_error(const char *device, int rc)
{
	if (rc == -ENOPKG)
		llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO, rc,
			    "%s: unsupported features; needs Lustre's e2fsprogs",
			    device);
	else
		llapi_error(LLAPI_MSG_ERROR, rc, "cannot open %s", device);
}

/**
 * llapi_scan_device() - scan a target's own objects, one record per object
 * @device:	block device, image or snapshot holding an MDT or OST
 * @sp:		scan parameters, or NULL for the defaults
 * @cb:		called once per object
 * @data:	passed to @cb and to sp->lfsp_filter untouched
 *
 * The target is opened read-only and is neither mounted nor coordinated
 * with.  It may be in service, at the cost of a stale view and the odd
 * object caught mid-update.  One that is unreadable or plainly invalid is
 * skipped and counted in lfsp_stats; another can give an inconsistent record.
 *
 * Records carry no path: a device holds names and parent FIDs, in lfsr_name
 * and lfsr_parent_fid.  The callback contract is llapi_scan_namespace()'s,
 * thread-safety included.
 *
 * Return: 0 on success, or a negative errno.  -ENOTSUP means this build
 * has no backend for the target; -ENOPKG means the backend is here and
 * refused the target, which is a different thing to tell a user and a
 * different thing for a test to skip on.  A callback returning non-zero
 * stops the scan, and its value is returned unchanged.
 */
int llapi_scan_device(const char *device, const struct llapi_scan_param *sp,
		      llapi_scan_cb_t cb, void *data)
{
	struct llapi_scan_param spl = { 0 };
	struct llapi_scan_stats stats = { 0 };
	struct scan_worker *workers;
	struct scan_dev dev = { 0 };
	unsigned int nworkers;
	unsigned int started;
	unsigned int i;
	__u64 known;
	int rc;

	if (device == NULL || cb == NULL)
		return -EINVAL;

	if (sp != NULL) {
		rc = scan_param_copyin(&spl, sp, LLAPI_SCAN_F_KNOWN_DEV);
		if (rc != 0)
			return rc;
		sp = &spl;
		/* only now: a short lfsp_size may not reach lfsp_stats */
		if (spl.lfsp_stats != NULL &&
		    spl.lfsp_stats->ss_size < LLAPI_SCAN_STATS_MIN_SIZE)
			return -EINVAL;
	}

	pthread_once(&scan_backend_once, scan_backend_load);
	if (scan_backend == NULL)
		return -ENOTSUP;

	dev.sd_be = scan_backend;
	dev.sd_cb = cb;
	dev.sd_data = data;
	dev.sd_filter = sp != NULL ? sp->lfsp_filter : NULL;
	dev.sd_flags = sp != NULL ? sp->lfsp_flags : 0;
	/* everything: no field here costs a read of its own, only the
	 * object's xattrs, which are one read whatever is asked of them
	 */
	dev.sd_want = scan_want_widen(sp != NULL && sp->lfsp_want != 0 ?
				      sp->lfsp_want : ~0ULL);
	dev.sd_want_xattr = scan_want_xattr(dev.sd_want);

	rc = dev.sd_be->sb_open(device, &dev.sd_tgt, &dev.sd_tgt_info);
	if (rc < 0) {
		scan_open_error(device, rc);
		return rc;
	}

	/*
	 * Which objects are the target's subject matter depends on what the
	 * target is, so a device whose label names neither is refused rather
	 * than guessed at: on a filesystem that is not a Lustre target no
	 * object has an LMA, every one of them classifies as CLS_NO_LMA, and
	 * a scan that delivered nothing would return 0 and read as an empty
	 * target.  Neither ENOTSUP, the answer for a build with no backend,
	 * nor ENOPKG, the answer for a target the backend refused: a
	 * caller keys its own behaviour off all three.
	 */
	if (!(dev.sd_tgt_info.tt_flags &
	      (LLAPI_SCAN_TGT_MDT | LLAPI_SCAN_TGT_OST))) {
		llapi_error(LLAPI_MSG_ERROR | LLAPI_MSG_NO_ERRNO, -EINVAL,
			    "%s: label '%s' names no MDT or OST", device,
			    dev.sd_tgt_info.tt_label);
		rc = -EINVAL;
		goto out_close;
	}

	/*
	 * The target is known now, so the demand mask can be answered for
	 * this scan rather than for the entry point: what a scan of a device
	 * fills, less the fields only the other kind of target has, less the
	 * MDT index where the label did not carry one.
	 */
	known = LLAPI_SCAN_WANT_KNOWN_DEV;
	if (!(dev.sd_tgt_info.tt_flags & LLAPI_SCAN_TGT_MDT))
		known &= ~(__u64)LLAPI_SCAN_WANT_MDT_ONLY;
	if (!(dev.sd_tgt_info.tt_flags & LLAPI_SCAN_TGT_INDEX))
		known &= ~(__u64)LLAPI_SCAN_MDT_INDEX;
	scan_param_report_got(sp, dev.sd_want, known);

	dev.sd_end = dev.sd_tgt_info.tt_chunks;
	dev.sd_visible = dev.sd_tgt_info.tt_flags & LLAPI_SCAN_TGT_OST ?
			 LLAPI_SCAN_CLS_OST_OBJ : LLAPI_SCAN_CLS_VISIBLE;

	nworkers = sp != NULL && sp->lfsp_thread_count > 1 ?
		   sp->lfsp_thread_count : 1;
	workers = calloc(nworkers, sizeof(*workers));
	if (workers == NULL) {
		rc = -ENOMEM;
		goto out_close;
	}

	for (i = 0; i < nworkers; i++) {
		workers[i].sw_dev = &dev;
		rc = dev.sd_be->sb_worker_init(dev.sd_tgt,
					       &workers[i].sw_bectx);
		if (rc < 0) {
			/*
			 * Degraded, not failed, once one worker exists: the
			 * same reasoning as the pthread_create() arm below.
			 * A backend opens the device again per worker, and
			 * lfsp_thread_count is a __u8, so running out here is
			 * a caller asking for more than the node has.
			 */
			if (i == 0)
				goto out_workers;
			llapi_error(LLAPI_MSG_WARN | LLAPI_MSG_NO_ERRNO, rc,
				    "scanning with %u of %u workers",
				    i, nworkers);
			nworkers = i;
			rc = 0;
			break;
		}
	}

	/* the caller's thread is one of the workers */
	for (started = 1; started < nworkers; started++) {
		rc = pthread_create(&workers[started].sw_thread, NULL,
				    scan_worker_run, &workers[started]);
		if (rc != 0) {
			/*
			 * Degraded, not failed: the cursor feeds whatever
			 * workers exist and the scan still covers everything,
			 * so this must not turn a complete result into an
			 * error a caller would retry.
			 */
			llapi_error(LLAPI_MSG_WARN | LLAPI_MSG_NO_ERRNO, -rc,
				    "scanning with %u of %u threads",
				    started, nworkers);
			rc = 0;
			break;
		}
	}

	scan_worker_run(&workers[0]);

	for (i = 1; i < started; i++)
		pthread_join(workers[i].sw_thread, NULL);

	for (i = 0; i < nworkers; i++)
		scan_stats_merge(&stats, &workers[i].sw_stats);
	if (rc == 0)
		rc = dev.sd_error;

	if (sp != NULL && sp->lfsp_stats != NULL) {
		struct llapi_scan_stats *out = sp->lfsp_stats;
		__u32 size = out->ss_size;

		if (size > sizeof(stats))
			size = sizeof(stats);
		/* a whole counter, never half of one */
		size = scan_stats_whole(size);
		stats.ss_size = size;
		memcpy(out, &stats, size);
	}

out_workers:
	for (i = 0; i < nworkers; i++) {
		if (workers[i].sw_bectx != NULL)
			dev.sd_be->sb_worker_fini(dev.sd_tgt,
						  workers[i].sw_bectx);
	}
	free(workers);
out_close:
	dev.sd_be->sb_close(dev.sd_tgt);

	/* a consumer that stopped the scan hears its own value back */
	return dev.sd_stop_rc != 0 ? dev.sd_stop_rc : rc;
}
