// SPDX-License-Identifier: LGPL-2.1+

/*
 * Copyright (c) 2026, The Lustre Collective.
 */

/*
 * The ldiskfs backend of llapi_scan_device(): an MDT's or OST's objects read
 * off the block device with libext2fs, unmounted and without the server.
 * Opened read-only; there is no write path here.
 *
 * What this file knows is ext4.  What an LMA means is liblustreapi's, on the
 * other side of struct llapi_scan_sink.
 *
 * Author: Hiroshi Nishida <hnishida@thelustrecollective.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <ext2fs/ext2fs.h>

#include <linux/lustre/lustre_idl.h>

#include "lustreapi_scan_backend.h"

/*
 * No EXT2_FLAG_RW: there is no write path.  SKIP_MMP because we only read,
 * SOFTSUPP_FEATURES for ldiskfs features this build does not implement, and
 * IGNORE_CSUM_ERRORS so that ext2fs_open() gets past the metadata of a
 * mounted target.  A worker clears it on its own handle so libext2fs
 * verifies each inode.  That only helps on a target formatted with
 * metadata_csum, which mkfs.lustre does not enable.
 */
#define SCAN_EXT2_FLAGS	(EXT2_FLAG_SKIP_MMP | EXT2_FLAG_SOFTSUPP_FEATURES | \
			 EXT2_FLAG_64BITS | EXT2_FLAG_IGNORE_CSUM_ERRORS)

/* Enough block groups to cover about this many inodes per unit of work, so
 * the chunk count stays in the thousands and the shared cursor the workers
 * take from is not a contention point.
 */
#define SCAN_CHUNK_INODES	65536

/* Values libext2fs hands back are ours to free: LMA plus the five the
 * demand mask can ask for -- LOV, LMV, SOM, LINK and HSM.
 */
#define SCAN_EA_BUFS		LLAPI_SCAN_XA_MAX

struct scan_ldiskfs_tgt {
	ext2_filsys	 st_fs;		/* geometry, and the shared bitmap */
	char		*st_device;
	unsigned int	 st_groups_per_chunk;
};

struct scan_ldiskfs_worker {
	ext2_filsys		 sw_fs;	/* private handle and scan position */
	ext2_inode_scan		 sw_scan;
	struct ext2_inode_large	*sw_inode;
	unsigned int		 sw_bufsize;
	void			*sw_bufs[SCAN_EA_BUFS];
	int			 sw_nbufs;
};

static const char *const scan_xattr_name[LLAPI_SCAN_XA_MAX] = {
	[LLAPI_SCAN_XA_LMA]	= XATTR_NAME_LMA,
	[LLAPI_SCAN_XA_LOV]	= XATTR_NAME_LOV,
	[LLAPI_SCAN_XA_LMV]	= XATTR_NAME_LMV,
	[LLAPI_SCAN_XA_SOM]	= XATTR_NAME_SOM,
	[LLAPI_SCAN_XA_LINK]	= XATTR_NAME_LINK,
	[LLAPI_SCAN_XA_HSM]	= XATTR_NAME_HSM,
};

/*
 * The label mkfs.lustre wrote, fsname-MDT0000, gives the index and MDT versus
 * OST.  last_rcvd and CONFIGS/mountdata name the target too, and the mount
 * checks them against it, but the label is free at open time.
 */
static void scan_ldiskfs_label(const struct ext2_super_block *sb,
			       struct llapi_scan_tgt *tgt)
{
	const char *sep;
	size_t len;
	char *end;
	long idx;

	memcpy(tgt->tt_label, sb->s_volume_name, sizeof(sb->s_volume_name));
	tgt->tt_label[sizeof(sb->s_volume_name)] = '\0';

	/*
	 * fsname-MDT0000 once mounted, fsname:MDT0000 never mounted,
	 * fsname=MDT0000 after writeconf, fsname+MDT0000 after
	 * --nolocallogs: the target part is the last eight characters
	 * every way.  mount_lustre.c reads the same four separators.
	 */
	len = strlen(tgt->tt_label);
	if (len < 8)
		return;
	sep = tgt->tt_label + len - 8;
	if (sep[0] != '-' && sep[0] != ':' && sep[0] != '=' && sep[0] != '+')
		return;

	idx = strtol(sep + 4, &end, 16);
	if (end != sep + 8 || idx < 0)
		return;

	if (strncmp(sep + 1, "OST", 3) == 0)
		tgt->tt_flags |= LLAPI_SCAN_TGT_OST;
	else if (strncmp(sep + 1, "MDT", 3) == 0)
		tgt->tt_flags |= LLAPI_SCAN_TGT_MDT;
	else
		return;

	/*
	 * A target formatted without --index carries INDEX_UNASSIGNED
	 * (mount_utils.h, 0xffff) until it first registers, which reads as
	 * a real index here.  The target is still an MDT or an OST; only
	 * its number is not known yet.
	 */
	if (idx == 0xffff)
		return;

	tgt->tt_index = (__u32)idx;
	tgt->tt_flags |= LLAPI_SCAN_TGT_INDEX;
}

/*
 * Below EXT2_ET_BASE an errcode is a plain errno, so a missing device says
 * ENOENT rather than arriving as an I/O error.  An unsupported feature gets
 * ENOPKG, for the caller to explain: a Lustre target sets dirdata, which
 * only the e2fsprogs distributed with Lustre lists as supported, so the
 * package to install is the answer.  Not ENOTSUP, which is this library
 * saying it has no backend at all -- the two look alike from a shell and
 * mean opposite things about the node.
 *
 * A device with no ext superblock at all -- a ZFS target, a raw LUN, a file
 * that is not an image -- says EINVAL, the same answer llapi_scan_device()
 * gives a label naming neither an MDT nor an OST.  It is not EIO: that is
 * documented as a read of the target having failed, which tells a caller to
 * look at the media.
 */
static int scan_errcode(errcode_t err)
{
	if (err == EXT2_ET_UNSUPP_FEATURE || err == EXT2_ET_RO_UNSUPP_FEATURE)
		return -ENOPKG;
	if (err == EXT2_ET_BAD_MAGIC)
		return -EINVAL;
	if (err > 0 && err < EXT2_ET_BASE)
		return -(int)err;
	return -EIO;
}

int scan_ldiskfs_open(const char *device, void **tgtp,
		      struct llapi_scan_tgt *tgt)
{
	struct scan_ldiskfs_tgt *t;
	unsigned int ipg;
	errcode_t err;
	int rc;

	t = calloc(1, sizeof(*t));
	if (t == NULL)
		return -ENOMEM;

	t->st_device = strdup(device);
	if (t->st_device == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	err = ext2fs_open(device, SCAN_EXT2_FLAGS, 0, 0, unix_io_manager,
			  &t->st_fs);
	if (err != 0) {
		rc = scan_errcode(err);
		goto out;
	}

	ipg = t->st_fs->super->s_inodes_per_group;
	t->st_groups_per_chunk = ipg != 0 ?
		(SCAN_CHUNK_INODES + ipg - 1) / ipg : 1;
	if (t->st_groups_per_chunk < 1)
		t->st_groups_per_chunk = 1;

	memset(tgt, 0, sizeof(*tgt));
	scan_ldiskfs_label(t->st_fs->super, tgt);
	tgt->tt_chunks = (t->st_fs->group_desc_count +
			  t->st_groups_per_chunk - 1) / t->st_groups_per_chunk;

	*tgtp = t;
	return 0;
out:
	if (t->st_fs != NULL)
		ext2fs_close_free(&t->st_fs);
	free(t->st_device);
	free(t);
	return rc;
}

void scan_ldiskfs_close(void *tgt)
{
	struct scan_ldiskfs_tgt *t = tgt;

	if (t == NULL)
		return;
	if (t->st_fs != NULL)
		ext2fs_close_free(&t->st_fs);
	free(t->st_device);
	free(t);
}

int scan_ldiskfs_worker_init(void *tgt, void **wctxp)
{
	struct scan_ldiskfs_tgt *t = tgt;
	struct scan_ldiskfs_worker *wk;
	unsigned int inode_size;
	errcode_t err;
	int rc;

	/*
	 * The allocation bitmap is the authority on which objects exist, and
	 * every worker only ever tests it, so one copy is shared rather than
	 * one per worker.  ext2fs_open() leaves default_bitmap_type at
	 * EXT2FS_BMAP64_BITARRAY, whose test is a plain bit read, so the
	 * concurrent tests are safe; e2fsck's rbtree bitmap would not be.  It
	 * outlives the workers, which are joined before scan_ldiskfs_close().
	 *
	 * Read for the first worker and not at open, so an open that only
	 * wants the label does not pay for it.  The core starts the workers
	 * one after another, so this needs no lock.
	 */
	if (t->st_fs->inode_map == NULL) {
		err = ext2fs_read_inode_bitmap(t->st_fs);
		if (err != 0)
			return scan_errcode(err);
	}

	wk = calloc(1, sizeof(*wk));
	if (wk == NULL)
		return -ENOMEM;

	/* libext2fs is not thread-safe across one handle, so a worker gets
	 * its own -- and with it its own scan position.  It reads no bitmap:
	 * the target's is shared, and the inode scan never consults one.
	 */
	err = ext2fs_open(t->st_device, SCAN_EXT2_FLAGS, 0, 0, unix_io_manager,
			  &wk->sw_fs);
	if (err != 0) {
		rc = scan_errcode(err);
		goto out;
	}
	/* verify each inode it reads; see SCAN_EXT2_FLAGS */
	wk->sw_fs->flags &= ~EXT2_FLAG_IGNORE_CSUM_ERRORS;

	/* The scan buffer has to be at least the on-disk inode size, so that
	 * the inline xattr region comes back with the inode.
	 */
	inode_size = EXT2_INODE_SIZE(wk->sw_fs->super);
	wk->sw_bufsize = inode_size > sizeof(*wk->sw_inode) ?
			 inode_size : sizeof(*wk->sw_inode);
	err = ext2fs_get_memzero(wk->sw_bufsize, &wk->sw_inode);
	if (err != 0) {
		rc = -ENOMEM;
		goto out;
	}

	err = ext2fs_open_inode_scan(wk->sw_fs,
				     EXT2_INODE_SCAN_DEFAULT_BUFFER_BLOCKS,
				     &wk->sw_scan);
	if (err != 0) {
		rc = -EIO;
		goto out;
	}

	/* without this, a group whose inode table was never allocated fails
	 * the scan with EXT2_ET_MISSING_INODE_TABLE instead of being skipped
	 */
	ext2fs_inode_scan_flags(wk->sw_scan, EXT2_SF_SKIP_MISSING_ITABLE |
				EXT2_SF_WARN_GARBAGE_INODES, 0);

	*wctxp = wk;
	return 0;
out:
	if (wk->sw_inode != NULL)
		ext2fs_free_mem(&wk->sw_inode);
	if (wk->sw_fs != NULL)
		ext2fs_close_free(&wk->sw_fs);
	free(wk);
	return rc;
}

void scan_ldiskfs_worker_fini(void *tgt, void *wctx)
{
	struct scan_ldiskfs_worker *wk = wctx;

	if (wk == NULL)
		return;
	if (wk->sw_scan != NULL)
		ext2fs_close_inode_scan(wk->sw_scan);
	if (wk->sw_inode != NULL)
		ext2fs_free_mem(&wk->sw_inode);
	if (wk->sw_fs != NULL)
		ext2fs_close_free(&wk->sw_fs);
	free(wk);
}

/*
 * Cheap checks rejecting an object that cannot be legal, so one caught
 * mid-update is skipped.  metadata_csum is not enabled on a Lustre MDT, so
 * there is nothing exact to verify against.
 */
static int scan_inode_plausible(const struct ext2_inode_large *inode,
				unsigned int inode_size)
{
	__u16 fmt = inode->i_mode & LINUX_S_IFMT;

	if (inode->i_links_count == 0)
		return 0;

	switch (fmt) {
	case LINUX_S_IFREG:
	case LINUX_S_IFDIR:
	case LINUX_S_IFLNK:
	case LINUX_S_IFBLK:
	case LINUX_S_IFCHR:
	case LINUX_S_IFIFO:
	case LINUX_S_IFSOCK:
		break;
	default:
		return 0;
	}

	if (inode_size > EXT2_GOOD_OLD_INODE_SIZE) {
		/* i_extra_isize must fit in the inode, and must at least be
		 * large enough to hold itself
		 */
		if (inode->i_extra_isize >
		    inode_size - EXT2_GOOD_OLD_INODE_SIZE)
			return 0;
		if (inode->i_extra_isize != 0 &&
		    inode->i_extra_isize < sizeof(inode->i_extra_isize))
			return 0;
	}

	return 1;
}

/*
 * ldiskfs keeps a signed 32-bit seconds field, and for a large inode two
 * more epoch bits in the low half of the matching i_*time_extra.  Reading
 * the seconds unsigned turns a pre-1970 timestamp into a 2106 one, and
 * dropping the epoch bits puts anything past 2038 out by a multiple of
 * 2^32 -- either way the same object's mtime would differ between this
 * scanner and llapi_scan_namespace(), which is the comparison a consumer
 * filtering on age makes.
 */
#define SCAN_EXT4_EPOCH_MASK	0x3

static __s64 scan_inode_time(__u32 secs, __u32 extra, bool have_extra)
{
	__s64 t = (__s32)secs;

	if (have_extra)
		t += (__s64)(extra & SCAN_EXT4_EPOCH_MASK) << 32;

	return t;
}

/* whether i_extra_isize reaches @field, given the @have it accounts for */
#define scan_inode_has(have, field)					\
	((have) >= offsetof(struct ext2_inode_large, field) +		\
		   sizeof(((struct ext2_inode_large *)0)->field))

/* Inodes ldiskfs keeps for itself, as osd_scrub skips them. */
static bool scan_ino_is_fs_own(ext2_filsys fs, ext2_ino_t ino)
{
	if (ino < EXT2_FIRST_INODE(fs->super))
		return true;
	/* the project quota inode is above s_first_ino */
	return ext2fs_has_feature_project(fs->super) &&
	       ino == fs->super->s_prj_quota_inum;
}

/* Everything here is already in the inode buffer the scan handed back. */
static void scan_inode_attrs(ext2_filsys fs,
			     const struct ext2_inode_large *inode,
			     ext2_ino_t ino, unsigned int inode_size,
			     struct llapi_scan_obj *obj)
{
	unsigned int have = 0;
	bool xtra;

	memset(obj, 0, sizeof(*obj));

	obj->so_id = ino;
	obj->so_mode = inode->i_mode;
	obj->so_nlink = inode->i_links_count;
	obj->so_uid = inode->i_uid |
		      ((__u32)inode->osd2.linux2.l_i_uid_high << 16);
	obj->so_gid = inode->i_gid |
		      ((__u32)inode->osd2.linux2.l_i_gid_high << 16);
	obj->so_size = EXT2_I_SIZE(inode);
	/* 512-byte units, whatever huge_file and EXT4_HUGE_FILE_FL say */
	obj->so_blocks = ext2fs_get_stat_i_blocks(fs,
						 (struct ext2_inode *)inode);
	obj->so_gen = inode->i_generation;
	/* as ext4_iget() reads i_rdev, which osd-ldiskfs reports as la_rdev */
	if (LINUX_S_ISCHR(inode->i_mode) || LINUX_S_ISBLK(inode->i_mode)) {
		__u32 old = inode->i_block[0];
		__u32 new = inode->i_block[1];

		if (old != 0)
			obj->so_rdev = (((old >> 8) & 0xff) << 20) |
				       (old & 0xff);
		else
			obj->so_rdev = (((new & 0xfff00) >> 8) << 20) |
				       (new & 0xff) | ((new >> 12) & 0xfff00);
	}
	obj->so_valid |= LLAPI_SCAN_SO_GEN;
	/*
	 * The i_flags bits that share their values with STATX_ATTR_*, narrowed
	 * to the set a namespace scan can also report: ll_dir_ioctl() puts
	 * only IMMUTABLE, APPEND and -- under HAVE_LUSTRE_CRYPTO -- ENCRYPTED
	 * in stx_attributes_mask, and llapi_scan_namespace() takes
	 * stx_attributes from that mask.  Reporting COMPR and NODUMP here as
	 * well would make one file answer "lfs find --attrs d" differently
	 * depending on which scanner ran, where stx_attributes is meant to mean
	 * one thing whichever filled it.  The bit is on the MDT inode either
	 * way; making it answerable is llite's to do, for both scanners at
	 * once.
	 *
	 * so_attrs_mask is that same set, declared: a consumer can then tell
	 * "not immutable" from "this scanner cannot say", which is the
	 * distinction statx keeps stx_attributes_mask for.
	 */
	obj->so_flags = inode->i_flags & (EXT2_IMMUTABLE_FL | EXT2_APPEND_FL);
	/* not ENCRYPTED: osd-ldiskfs keeps it in the LMA, see the sink */
	obj->so_attrs_mask = STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND;

	/*
	 * The epoch bits, btime and projid all live past i_extra_isize, and
	 * a field is readable only if i_extra_isize reaches it: they are laid
	 * out ctime_extra, mtime_extra, atime_extra, crtime, crtime_extra,
	 * version_hi, projid, so a reader that clears one has not earned the
	 * next.  version_hi is named because it is four bytes between
	 * crtime_extra and projid: scan_inode_has() takes every offset from
	 * offsetof() and so cannot skip it, but a reader checking this list
	 * by hand would land short of projid without it.
	 *
	 * The three timestamps are gated together on i_atime_extra, the last
	 * of them: an inode reaching only i_ctime_extra loses the epoch bits
	 * it does carry, which errs towards the 1970 window rather than
	 * towards reading a field that is not there.
	 */
	if (inode_size > EXT2_GOOD_OLD_INODE_SIZE)
		have = EXT2_GOOD_OLD_INODE_SIZE + inode->i_extra_isize;

	xtra = scan_inode_has(have, i_atime_extra);
	obj->so_atime = scan_inode_time(inode->i_atime,
					inode->i_atime_extra, xtra);
	obj->so_mtime = scan_inode_time(inode->i_mtime,
					inode->i_mtime_extra, xtra);
	obj->so_ctime = scan_inode_time(inode->i_ctime,
					inode->i_ctime_extra, xtra);

	if (scan_inode_has(have, i_crtime)) {
		bool cxtra = scan_inode_has(have, i_crtime_extra);

		obj->so_btime = scan_inode_time(inode->i_crtime,
						inode->i_crtime_extra, cxtra);
		obj->so_valid |= LLAPI_SCAN_SO_BTIME;
	}
	if (scan_inode_has(have, i_projid)) {
		obj->so_projid = inode->i_projid;
		obj->so_valid |= LLAPI_SCAN_SO_PROJID;
	}
}

static void scan_ea_bufs_free(struct scan_ldiskfs_worker *wk)
{
	while (wk->sw_nbufs > 0)
		ext2fs_free_mem(&wk->sw_bufs[--wk->sw_nbufs]);
}

static int scan_ea_fetch(struct scan_ldiskfs_worker *wk,
			 struct ext2_xattr_handle *h, enum llapi_scan_xattr x,
			 struct llapi_scan_obj *obj)
{
	void *val = NULL;
	size_t len = 0;
	errcode_t err;

	if (wk->sw_nbufs == SCAN_EA_BUFS)
		return 0;
	err = ext2fs_xattr_get(h, scan_xattr_name[x], &val, &len);
	/* absent is normal; any other error leaves the object unread */
	if (err == EXT2_ET_EA_KEY_NOT_FOUND)
		return 0;
	if (err != 0)
		return -1;
	if (val == NULL)
		return 0;

	wk->sw_bufs[wk->sw_nbufs++] = val;
	obj->so_xattr[x].sv_buf = val;
	obj->so_xattr[x].sv_len = len;
	obj->so_xa_valid |= LLAPI_SCAN_XA_BIT(x);

	return 0;
}

static int scan_ea_fetch_set(struct scan_ldiskfs_worker *wk,
			     struct ext2_xattr_handle *h, __u32 want,
			     struct llapi_scan_obj *obj)
{
	int x;

	for (x = 0; x < LLAPI_SCAN_XA_MAX; x++) {
		if ((want & LLAPI_SCAN_XA_BIT(x)) &&
		    scan_ea_fetch(wk, h, x, obj) < 0)
			return -1;
	}

	return 0;
}

/*
 * ext2fs_xattrs_read_inode() follows i_file_acl to the external block, so an
 * object's xattrs come back in one pass whether or not they are inline.
 *
 * A failure here means the object's Lustre state is unreadable: without it
 * a visible object misclassifies and a striped file's own size passes as
 * the file's, so the caller must skip and count the object, not use it.
 */
static int scan_read_xattrs(struct scan_ldiskfs_worker *wk, ext2_ino_t ino,
			    __u32 want, struct llapi_scan_obj *obj)
{
	struct ext2_xattr_handle *h = NULL;
	int rc;

	if (ext2fs_xattrs_open(wk->sw_fs, ino, &h) != 0)
		return -1;

	/* follows i_file_acl itself, so an external block costs no re-read */
	if (ext2fs_xattrs_read_inode(h, wk->sw_inode) != 0) {
		ext2fs_xattrs_close(&h);
		return -1;
	}

	rc = scan_ea_fetch_set(wk, h, want, obj);
	ext2fs_xattrs_close(&h);

	return rc;
}

int scan_ldiskfs_scan_chunk(void *tgt, void *wctx, __u64 idx,
			    const struct llapi_scan_sink *sink, int *done)
{
	struct scan_ldiskfs_tgt *t = tgt;
	struct scan_ldiskfs_worker *wk = wctx;
	ext2_filsys fs = wk->sw_fs;
	unsigned int inode_size = EXT2_INODE_SIZE(fs->super);
	__u64 ipg = fs->super->s_inodes_per_group;
	__u64 group = idx * t->st_groups_per_chunk;
	__u64 end_ino;
	ext2_ino_t ino;
	errcode_t err;

	if (group >= fs->group_desc_count) {
		*done = 1;
		return 0;
	}

	/* group g holds inodes [g * ipg + 1, (g + 1) * ipg] */
	end_ino = (group + t->st_groups_per_chunk) * ipg;
	if (end_ino >= fs->super->s_inodes_count) {
		end_ino = fs->super->s_inodes_count;
		*done = 1;
	}

	err = ext2fs_inode_scan_goto_blockgroup(wk->sw_scan, (int)group);
	if (err != 0)
		return -EIO;

	for (;;) {
		struct llapi_scan_obj obj;
		int rc;

		err = ext2fs_get_next_inode_full(wk->sw_scan, &ino,
						 (struct ext2_inode *)
						 wk->sw_inode, wk->sw_bufsize);
		/*
		 * The errors that still advance the scan describe one
		 * inode, not the target: a bad block under it, a checksum
		 * that does not verify, a body libext2fs calls garbage.
		 * Skipping is what the scan promises for an object it
		 * cannot read; ending the target's scan on one of them
		 * would lose every inode after it as well.
		 */
		if (err == EXT2_ET_BAD_BLOCK_IN_INODE_TABLE ||
		    err == EXT2_ET_INODE_CSUM_INVALID ||
		    err == EXT2_ET_INODE_IS_GARBAGE) {
			/*
			 * The same questions the readable path below asks,
			 * and for the same reasons: whose chunk this inode
			 * is, whether it is an object at all, and whether
			 * the bitmap has it.  The bitmap is in another
			 * block, read for the first worker, so it is still
			 * good here.  ext2fs_get_next_inode_full() assigns
			 * *ino before it returns any of these three, so all
			 * can be asked here -- unlike the read failure
			 * handled below, which leaves it untouched.
			 *
			 * The bound matters here too: an unreadable inode
			 * past end_ino belongs to the chunk starting
			 * there, which reads it again, so counting it in
			 * this one counts it twice.
			 */
			if ((__u64)ino > end_ino)
				return 0;
			if (scan_ino_is_fs_own(fs, ino))
				continue;
			if (!ext2fs_test_inode_bitmap2(t->st_fs->inode_map,
						       ino))
				continue;
			sink->sk_skip(sink->sk_ctx, LLAPI_SCAN_SKIP_IO);
			continue;
		}
		/*
		 * A read of the inode table itself failed, and nothing has
		 * advanced -- retrying would read the same block forever.
		 * That one ends the scan of this target.
		 */
		if (err != 0)
			return -EIO;
		if (ino == 0) {
			*done = 1;	/* the end of the whole table */
			return 0;
		}
		if ((__u64)ino > end_ino)
			return 0;	/* the end of this chunk */

		/* ext4's own inodes: Lustre's objects start above */
		if (scan_ino_is_fs_own(fs, ino))
			continue;

		/*
		 * The inode table also returns freed inodes, stale but still
		 * parseable, so the bitmap is what says an object exists --
		 * as osd_iit_next() has it.  An empty slot is not a skipped
		 * object and is not counted as one.
		 *
		 * i_dtime is deliberately not consulted with it.  ldiskfs
		 * aliases it as NEXT_ORPHAN, and ext4_orphan_add() writes
		 * the next orphan's inode number there and dirties the
		 * inode, so it reaches the device: a file mid-truncate, or
		 * every orphan after an unclean shutdown this read-only
		 * scan replays no journal for, has i_dtime set with its
		 * links intact.  A genuinely freed inode is caught by the
		 * bitmap and by i_links_count in scan_inode_plausible(),
		 * which is what the kernel's own iterator relies on.
		 */
		if (!ext2fs_test_inode_bitmap2(t->st_fs->inode_map, ino))
			continue;

		if (!scan_inode_plausible(wk->sw_inode, inode_size)) {
			sink->sk_skip(sink->sk_ctx, LLAPI_SCAN_SKIP_INVALID);
			continue;
		}
		/* an ea_inode holds one xattr value, not an object */
		if (wk->sw_inode->i_flags & EXT4_EA_INODE_FL)
			continue;

		scan_inode_attrs(fs, wk->sw_inode, ino, inode_size, &obj);

		/* the cheap stage: no xattr has been read yet */
		rc = sink->sk_prefilter(sink->sk_ctx, &obj);
		if (rc > 0)
			continue;
		if (rc < 0)
			return rc;

		if (scan_read_xattrs(wk, ino, sink->sk_want_xattr,
				     &obj) < 0) {
			/* a partial read still holds buffers */
			scan_ea_bufs_free(wk);
			sink->sk_skip(sink->sk_ctx, LLAPI_SCAN_SKIP_XATTR);
			continue;
		}
		rc = sink->sk_object(sink->sk_ctx, &obj);
		scan_ea_bufs_free(wk);
		if (rc < 0)
			return rc;
	}
}
