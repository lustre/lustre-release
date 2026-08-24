// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (c) 2026, The Lustre Collective
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustreapi library for scanning a Lustre namespace and delivering one
 * record per object to a consumer callback.
 *
 * The traversal itself is not new: llapi_find_with_cb() already walks the
 * namespace with a thread pool, fetching attributes through
 * LL_IOC_MDC_GETINFO_V2 and falling back to lstat() off Lustre.  What this
 * adds is a consumer contract - a versioned, self-describing record with a
 * validity mask - so that a tool consuming the scan does not have to know
 * how find_param works, and so that scanners other than this one can supply
 * the same record later.
 *
 * The record is an in-memory structure and deliberately not a serialization.
 * It is valid only for the duration of one callback.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <linux/lustre/lustre_fid.h>
#include <lustre/lustreapi.h>

#include "lustreapi_internal.h"

/*
 * struct llapi_scan_rec begins with its statx so that a record is one to
 * anything that takes a struct statx.  Both halves of that are asserted
 * here rather than trusted: the first says the cast is what lustreapi.h
 * says it is, and the second is why the first is safe to promise.
 *
 * A statx that grew past 256 bytes would move every field of the record
 * below it, under consumers already built against the old offsets, and
 * lfsr_size reports how much of a record was filled and never that a field
 * moved.  So the day the platform's statx changes size, this build stops
 * rather than that.
 */
static_assert(offsetof(struct llapi_scan_rec, lfsr_stx) == 0,
	      "llapi_scan_rec must begin with its statx");
static_assert(sizeof(lstatx_t) == 256,
	      "struct statx is no longer 256 bytes: every llapi_scan_rec field after lfsr_stx has moved");

/* Per-scan state, reachable from the traversal callback via fp_cb_data. */
struct llapi_scan_state {
	llapi_scan_cb_t		 ss_cb;
	llapi_scan_cb_t		 ss_filter;
	void			*ss_data;
	__u64			 ss_want;	/* 0 already widened to "all" */
	/* the first value that stopped the scan: non-zero from ss_cb, or
	 * negative from ss_filter
	 */
	int			 ss_stop_rc;
};

/*
 * The part of the record that costs nothing: path, name, and the object
 * type if the directory entry carried one.  This is what lfsp_filter sees,
 * and what lfs find's own pre-filters run against.
 */
void scan_rec_dirent(struct llapi_scan_rec *rec, const char *path,
		     int p, int d, const struct dirent64 *de)
{
	const char *name;

	memset(rec, 0, sizeof(*rec));
	rec->lfsr_size = sizeof(*rec);
	rec->lfsr_path = path;
	/*
	 * The basename, except for "/", whose own name is "/" -- as
	 * basename(3) answers it.  The loop that trimmed the start point
	 * kept that slash so lfsp_filter would have a name to test, and
	 * strrchr() would otherwise leave lfsr_name on the terminating NUL.
	 */
	name = strrchr(path, '/');
	rec->lfsr_name = (name != NULL && name[1] != '\0') ? name + 1 : path;
	rec->lfsr_parent_fd = p;
	rec->lfsr_fd = d;

	if (de != NULL && de->d_type != DT_UNKNOWN) {
		rec->lfsr_stx.stx_mode = DTTOIF(de->d_type);
		rec->lfsr_stx.stx_mask |= STATX_TYPE;
	}
}

/*
 * Bytes of a layout, from its own header, for the V1-ioctl fallback.
 *
 * Not lov_comp_md_size(): the two disagree on a foreign layout, where that
 * one returns lfm_length alone.  lfm_length is the length of lfm_value, so
 * the header has to be added -- which is what lov_foreign_md_size() does
 * and what the tree's own lov_foreign_size() macro does.  The other is
 * used to bound a copy in convert_lmdbuf_v1v2(), where under-reporting
 * only weakens the guard, but it is not a size to build a record on.
 */
static __u32 llapi_scan_lmm_size(const struct lov_user_md *lmm, mode_t mode)
{
	switch (lmm->lmm_magic) {
	case LOV_USER_MAGIC_V1:
	case LOV_USER_MAGIC_V3:
		/* a directory's default layout is a template: no objects */
		return lov_user_md_size(S_ISDIR(mode) ? 0 :
					lmm->lmm_stripe_count, lmm->lmm_magic);
	case LOV_USER_MAGIC_COMP_V1:
		return ((const struct lov_comp_md_v1 *)lmm)->lcm_size;
	case LOV_USER_MAGIC_FOREIGN: {
		const struct lov_foreign_md *lfm =
			(const struct lov_foreign_md *)lmm;

		return lov_foreign_md_size(lfm->lfm_length);
	}
	default:
		return 0;
	}
}

/*
 * Bytes of a directory stripe as LL_IOC_LMV_GETSTRIPE returned it: the
 * header plus one lmv_user_mds_data per stripe, whatever the magic says
 * (cb_get_dirstripe() sizes its buffer the same way), or a foreign LMV's
 * own length.
 */
static __u32 llapi_scan_lmv_size(const struct lmv_user_md *lmv)
{
	if (lmv_is_foreign(lmv->lum_magic)) {
		/* lmv_user_md is packed; read the foreign header by copy */
		struct lmv_foreign_md lfm;

		memcpy(&lfm, lmv, offsetof(struct lmv_foreign_md, lfm_value));
		return lfm.lfm_length + offsetof(struct lmv_foreign_md,
						 lfm_value);
	}
	return lmv_user_md_size(lmv->lum_stripe_count,
				LMV_USER_MAGIC_SPECIFIC);
}

/*
 * Fill the rest from what the traversal fetched.
 *
 * Every field is guarded by a bit rather than by a sentinel value, because
 * a scanner that cannot answer for a field and a scanner that answers zero
 * are different things, and a consumer counting bytes or ages has to be
 * able to tell them apart.  For lfsr_stx that bit is stx_mask's, which is why
 * the whole statx is taken rather than copied field by field: the MDT has
 * already said what it filled.
 *
 * lov_user_mds_data_v2 is packed, so lmd_stx is read through the struct
 * rather than through a pointer to it.
 */
static void scan_rec_mdt(struct llapi_scan_rec *rec,
			 const struct lov_user_mds_data *lmd,
			 const struct find_param *param, bool have_lmv)
{
	__u64 flags = lmd->lmd_flags;

	rec->lfsr_fid = lmd->lmd_fid;
	if (fid_is_sane(&rec->lfsr_fid))
		rec->lfsr_valid |= LLAPI_SCAN_FID;

	rec->lfsr_stx = lmd->lmd_stx;

	/*
	 * llite clears STATX_SIZE/BLOCKS from the mask when the MDT's answer
	 * is not authoritative, and OBD_MD_FLLAZYSIZE says the value it left
	 * in stx_size is the lazy SOM one.  Both are reported as what they
	 * are; a consumer that wants a strict size for every file has to
	 * glimpse, as lfs find does.
	 */
	if (!(rec->lfsr_stx.stx_mask & STATX_SIZE) && flags & OBD_MD_FLLAZYSIZE)
		rec->lfsr_valid |= LLAPI_SCAN_LAZY_SIZE;
	if (!(rec->lfsr_stx.stx_mask & STATX_BLOCKS) &&
	    flags & OBD_MD_FLLAZYBLOCKS)
		rec->lfsr_valid |= LLAPI_SCAN_LAZY_BLOCKS;

	/*
	 * stx_attributes has no bit of its own in stx_mask, so what says the
	 * flags were answered is OBD_MD_FLFLAGS: mdt_pack_attr2body() sets
	 * it only for LA_FLAGS, and ll_dir_ioctl() reads mbo_flags only
	 * under it.  stx_attributes_mask is not that answer -- llite fills
	 * it with a build-time constant, the STATX_ATTR_* bits the client
	 * can represent -- so gating on it would set this bit for every
	 * object whether or not the MDT reported flags at all.
	 *
	 * Masked down to that declaration all the same, because the MDT ORs
	 * the raw inode flags in and only the bits it names are STATX_ATTR_*
	 * values -- FS_INDEX_FL would otherwise read as STATX_ATTR_AUTOMOUNT.
	 */
	if (flags & OBD_MD_FLFLAGS) {
		rec->lfsr_stx.stx_attributes &=
			rec->lfsr_stx.stx_attributes_mask;
		rec->lfsr_valid |= LLAPI_SCAN_ATTRS;
	}

	/*
	 * Layouts are handed over raw.  Decoding them means composite,
	 * foreign and pool-carrying layouts, all of which
	 * llapi_layout_get_by_xattr() already does properly; a partial copy
	 * of that in the record would be a second, worse answer that
	 * consumers would come to depend on.
	 */
	if (lmd->lmd_lmm.lmm_magic != 0) {
		__u32 size = lmd->lmd_lmmsize;

		/*
		 * The V1 ioctl fallback for old client modules leaves
		 * lmd_lmmsize 0, so size the layout from its own header.
		 */
		if (size == 0)
			size = llapi_scan_lmm_size(&lmd->lmd_lmm,
						   lmd->lmd_stx.stx_mode);
		if (size != 0) {
			rec->lfsr_lmm = &lmd->lmd_lmm;
			rec->lfsr_lmmsize = size;
			rec->lfsr_valid |= LLAPI_SCAN_LAYOUT;
		}
	}
	if (have_lmv) {
		rec->lfsr_lmv = param->fp_lmv_md;
		rec->lfsr_lmvsize = llapi_scan_lmv_size(param->fp_lmv_md);
		rec->lfsr_valid |= LLAPI_SCAN_LMV;
		/*
		 * LL_IOC_LMV_GETSTRIPE answers for a foreign directory with a
		 * struct lmv_foreign_md, which has none of lmv_user_md's
		 * fields where a consumer would look for them.
		 */
		if (lmv_is_foreign(param->fp_lmv_md->lum_magic))
			rec->lfsr_valid |= LLAPI_SCAN_LMV_FOREIGN;
	}
	if (param->fp_file_mdt_index != OBD_NOT_FOUND) {
		rec->lfsr_mdt_index = param->fp_file_mdt_index;
		rec->lfsr_valid |= LLAPI_SCAN_MDT_INDEX;
	}
}

/*
 * The directory stripe, for a directory the scan holds open.  An unstriped
 * directory answers ENODATA: fp_lmv_md is filled in as the one-stripe shape
 * lfs find has always used, but the record does not point at it, because
 * "no stripe" is an answer and not a stripe.
 *
 * Return: 1 if the directory has a stripe, 0 if it has none, negative errno.
 */
static int llapi_scan_get_lmv(char *path, int d, struct find_param *param)
{
	struct lmv_user_md *lmv;
	int rc;

	rc = cb_get_dirstripe(path, d, param);
	/* only now: the E2BIG retry reallocates fp_lmv_md */
	lmv = param->fp_lmv_md;
	if (rc == 0)
		return 1;
	/* an ioctl failure comes back as -1 with errno; its own as -errno */
	if (rc == -1)
		rc = -errno;
	/*
	 * ENOTTY is not a Lustre directory at all -- cb_get_dirstripe() has
	 * already retried with O_NOFOLLOW by now.  Like ENODATA that is an
	 * answer and not a failure, and the object keeps its record: the
	 * lstat() fallback in get_lmd_info_fd() is there for exactly this.
	 */
	if (rc != -ENODATA && rc != -ENOTTY)
		return rc;

	lmv->lum_magic = LMV_MAGIC_V1;
	/* 0 until the MDT index is known, see scan_rec_gather() */
	lmv->lum_stripe_offset = 0;
	lmv->lum_stripe_count = 0;
	lmv->lum_hash_type = 0;
	/* the buffer is reused across objects: an unset field must not read
	 * as the previous directory's
	 */
	lmv->lum_pool_name[0] = '\0';
	return 0;
}

/*
 * Phase two of the record: what the MDT answers for, as much of it as
 * @want asks for, into @param's scratch buffers and from there into @rec.
 *
 * Written to be the one place that decides how an object's attributes are
 * fetched; lfs find is moved onto it by LU-20605, which is why it is here
 * rather than static to the scanner.  @want is taken
 * literally here -- 0 means nothing, and the public entry point is what
 * widens 0 to "everything".
 *
 * LLAPI_SCAN_MDT_INDEX for a regular file costs an open, which is why the
 * public default leaves it out; a special file is taken to live on its
 * parent's MDT, as lfs find has always assumed.  If an fd is opened for
 * it, it is left in *@fdp (and rec->lfsr_fd) for the caller to close, so a
 * caller that goes on to need one does not open twice.
 *
 * Return: 0 with @rec filled, or the negative errno of the fetch that
 * failed -- the caller decides what ENOENT, ESTALE and ENOTTY mean to it.
 */
int scan_rec_gather(struct find_param *param, char *path, int p,
		    int d, int *fdp, __u64 want,
		    struct llapi_scan_rec *rec)
{
	struct lov_user_mds_data *lmd = param->fp_lmd;
	bool have_lmv = false;
	int rc;

	if (!(want & LLAPI_SCAN_MDT_MASK))
		return 0;

	lmd->lmd_lmm.lmm_magic = 0;
	/*
	 * fp_lmd is one buffer for the whole scan.  get_lmd_info_fd() fills
	 * or clears lmd_stx on every path it takes; this is the cheap
	 * guarantee that nothing of the previous object's is left if a later
	 * change adds one that does not.
	 */
	memset(&lmd->lmd_stx, 0, sizeof(lmd->lmd_stx));
	param->fp_file_mdt_index = OBD_NOT_FOUND;
	param->fp_get_lmv = 0;

	if ((want & LLAPI_SCAN_LMV) && d != -1) {
		param->fp_get_lmv = 1;
		rc = llapi_scan_get_lmv(path, d, param);
		if (rc < 0)
			return rc;
		have_lmv = rc == 1;
	}

	rc = get_lmd_info_fd(path, p, d, lmd, param->fp_lum_size,
			     GET_LMD_INFO);
	if (rc < 0)
		return rc;

	if (want & LLAPI_SCAN_MDT_INDEX) {
		if (d != -1) {
			rc = llapi_file_fget_mdtidx(d,
						    &param->fp_file_mdt_index);
			/*
			 * An unstriped directory's offset is its MDT.  Not a
			 * foreign one: LL_IOC_LMV_GETSTRIPE answers 0 with a
			 * struct lmv_foreign_md in the same buffer, so
			 * fp_get_lmv is set, and lum_stripe_offset and
			 * lfm_type are both at offset 8 -- the store would
			 * land on the foreign type.  The record publishes
			 * this buffer as lfsr_lmv with LLAPI_SCAN_LMV_FOREIGN
			 * set, so a consumer reading what that bit promises
			 * would get an MDT index where the type belongs.
			 */
			if (rc == 0 && param->fp_get_lmv &&
			    !lmv_is_foreign(param->fp_lmv_md->lum_magic))
				param->fp_lmv_md->lum_stripe_offset =
					param->fp_file_mdt_index;
		} else if (S_ISREG(lmd->lmd_stx.stx_mode)) {
			/*
			 * FIXME: we could get the MDT index from the file's
			 * FID in lmd->lmd_lmm.lmm_oi without opening the
			 * file, once we are sure that LFSCK2 (2.6) has fixed
			 * up pre-2.0 LOV EAs.  That would still be an
			 * ioctl() to map the FID to the MDT, but not an
			 * open RPC.
			 */
			if (*fdp < 0)
				*fdp = open(path, O_RDONLY);
			if (*fdp < 0)
				rc = -errno;
			else
				rc = llapi_file_fget_mdtidx(*fdp,
						&param->fp_file_mdt_index);
		} else {
			rc = llapi_file_fget_mdtidx(p,
						    &param->fp_file_mdt_index);
		}
		/*
		 * An object the caller cannot open leaves the bit clear, as
		 * the project id and the HSM state do below: the index is one
		 * field of a record, and losing it is not losing the object.
		 * fp_file_mdt_index is still OBD_NOT_FOUND, so scan_rec_mdt()
		 * leaves LLAPI_SCAN_MDT_INDEX unset.
		 */
		if (rc < 0) {
			param->fp_file_mdt_index = OBD_NOT_FOUND;
			rc = 0;
		}
	}

	/*
	 * Not from the ioctl: FS_IOC_FSGETXATTR on the object itself, or
	 * LL_IOC_PROJECT on its parent for a special file.  That is an open
	 * per object, so it happens only when the demand mask asks.
	 */
	if (want & LLAPI_SCAN_PROJID) {
		__u32 projid = 0;

		/* an object the caller cannot open leaves the bit clear */
		if (get_projid(path, d != -1 ? &d : fdp,
			       lmd->lmd_stx.stx_mode, &projid) == 0) {
			rec->lfsr_projid = projid;
			rec->lfsr_valid |= LLAPI_SCAN_PROJID;
		}
	}

	/*
	 * Also not from the ioctl, and only for a regular file: HSM state is
	 * an ioctl of its own, so it waits for the demand mask too.
	 */
	if ((want & LLAPI_SCAN_HSM) && S_ISREG(lmd->lmd_stx.stx_mode)) {
		struct hsm_user_state hus = { 0 };

		if (d == -1 && *fdp < 0)
			*fdp = open(path, O_RDONLY | O_NONBLOCK);
		if (*fdp >= 0 &&
		    llapi_hsm_state_get_fd(*fdp, &hus) == 0) {
			rec->lfsr_hsm_states = hus.hus_states;
			rec->lfsr_hsm_archive_id = hus.hus_archive_id;
			rec->lfsr_valid |= LLAPI_SCAN_HSM;
		}
	}

	if (d == -1 && *fdp >= 0)
		rec->lfsr_fd = *fdp;
	scan_rec_mdt(rec, lmd, param, have_lmv);
	return 0;
}

/*
 * Traversal callback: the pre-filter first, then only as much gathering as
 * the demand mask asks for, then the record to the consumer.
 *
 * Returns the llapi_find_cb_t convention: 0 to continue, 1 to skip
 * descending, -1 to stop, or a negative errno.
 */
static int llapi_scan_cb_init(char *path, int p, int *dp,
			      struct find_param *param, struct dirent64 *de)
{
	struct llapi_scan_state *st = param->fp_cb_data;
	struct llapi_scan_rec rec;
	int d = dp == NULL ? -1 : *dp;
	int fd = -1;
	int rc;

	if (p == -1 && d == -1)
		return -EINVAL;

	/*
	 * A consumer has stopped the scan.  The traversal only abandons a
	 * walk on a negative return when fp_stop_on_error is set; otherwise
	 * it notes the value and carries on to the next entry, and with
	 * several threads the other workers know nothing about it.  So the
	 * stop is enforced here: nothing more is gathered, no directory is
	 * descended, and the consumer is not called again.
	 */
	if (__atomic_load_n(&st->ss_stop_rc, __ATOMIC_ACQUIRE) != 0)
		return -1;

	scan_rec_dirent(&rec, path, p, d, de);

	if (st->ss_filter != NULL) {
		rc = st->ss_filter(&rec, st->ss_data);
		if (rc > 0)
			goto out;		/* skip, but still descend */
		if (rc < 0)
			goto stop;
	}

	rc = scan_rec_gather(param, path, p, d, &fd, st->ss_want,
			     &rec);
	if (rc == -ENOENT || rc == -ESTALE)
		/* unlinked between readdir and here: not an error */
		goto out;
	if (rc < 0) {
		if (param->fp_stop_on_error)
			goto err;
		goto out;
	}

	rc = st->ss_cb(&rec, st->ss_data);
	if (rc != 0)
		goto stop;
out:
	if (fd >= 0)
		close(fd);
	/*
	 * The depth bookkeeping is the traversal's, not ours: returning 1 at
	 * the limit is what stops the descent, and cb_common_fini() undoes
	 * the increment on the way back up.
	 */
	if (param->fp_depth == param->fp_max_depth)
		return 1;

	param->fp_depth++;
	return 0;

stop:
	/*
	 * The traversal's own convention gives 1 and -1 meanings of its own
	 * and clamps anything positive to 0 on the way out, so the consumer's
	 * value is carried out of band.  First stopper wins: with several
	 * scan threads more than one can decide to stop at once.
	 */
	{
		int zero = 0;

		__atomic_compare_exchange_n(&st->ss_stop_rc, &zero, rc, false,
					    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
	}
	rc = -1;
err:
	if (fd >= 0)
		close(fd);
	return rc;
}

/**
 * llapi_scan_namespace() - walk a namespace, one record per object
 * @path:	directory to walk
 * @sp:		scan parameters, or NULL for the defaults
 * @cb:		called once per object
 * @data:	passed to @cb and to sp->lfsp_filter untouched
 *
 * The callback sees each object exactly once.  With lfsp_thread_count above 1
 * it is called from several threads at once and must be thread-safe; the
 * record it is given is private to that call, but @data is shared.
 *
 * The record is valid only for the duration of the call.  A consumer that
 * needs a field afterwards must copy it, including anything lfsr_path,
 * lfsr_name, lfsr_lmm or lfsr_lmv point at.  lfsr_parent_fd and lfsr_fd are the
 * scan's descriptors and are closed when it moves on.
 *
 * Return: 0 on success, or a negative errno.  A callback returning non-zero
 * stops the walk, and its value is returned unchanged.
 */
int llapi_scan_namespace(const char *path, const struct llapi_scan_param *sp,
			 llapi_scan_cb_t cb, void *data)
{
	struct llapi_scan_param spl = { 0 };
	struct llapi_scan_state st;
	struct find_param param = { 0 };
	char buf[PATH_MAX + 1];
	int rc;

	if (path == NULL || cb == NULL)
		return -EINVAL;

	/*
	 * Take a private copy of the parameter struct, whichever definition
	 * of it the caller was built against: shorter than ours reads as
	 * zero from where it stops, longer is accepted when the bytes past
	 * ours are zero.
	 */
	if (sp != NULL) {
		rc = scan_param_copyin(&spl, sp, LLAPI_SCAN_F_KNOWN_NS);
		if (rc != 0)
			return rc;
		sp = &spl;
	}

	rc = snprintf(buf, sizeof(buf), "%s", path);
	if (rc < 0 || rc >= (int)sizeof(buf))
		return -ENAMETOOLONG;

	/*
	 * A trailing slash would leave the root record's lfsr_name on the
	 * terminating NUL, and lfsp_filter is meant for name tests.  "/" is
	 * itself a name and keeps its slash.
	 */
	while (rc > 1 && buf[rc - 1] == '/')
		buf[--rc] = '\0';

	st.ss_cb = cb;
	st.ss_filter = sp ? sp->lfsp_filter : NULL;
	st.ss_data = data;
	/* everything, except what costs an ioctl or an open per object */
	st.ss_want = scan_want_widen(sp && sp->lfsp_want ? sp->lfsp_want :
					 LLAPI_SCAN_WANT_DEFAULT);
	scan_param_report_got(sp, st.ss_want, LLAPI_SCAN_WANT_KNOWN_NS);
	st.ss_stop_rc = 0;

	/* -1 is "unlimited", as lfs find sets it */
	param.fp_max_depth = (unsigned int)-1;
	if (sp != NULL && sp->lfsp_max_depth != 0)
		param.fp_max_depth = sp->lfsp_max_depth;
	param.fp_thread_count = sp ? sp->lfsp_thread_count : 0;
	param.fp_stop_on_error = sp &&
				 (sp->lfsp_flags & LLAPI_SCAN_F_STOP_ON_ERROR);
	param.fp_cb_data = &st;

	rc = llapi_find_with_cb(buf, &param, llapi_scan_cb_init,
				cb_common_fini);

	/* a consumer that stopped the scan hears its own value back */
	return st.ss_stop_rc != 0 ? st.ss_stop_rc : rc;
}
