/* SPDX-License-Identifier: LGPL-2.1+ */

/*
 * Copyright (c) 2026, The Lustre Collective.
 */

/*
 * The interface between llapi_scan_device() and a device backend.
 *
 * A backend gets an object's attributes off a target and hands them over;
 * what the bytes mean stays in liblustreapi, so a second backend is a second
 * reader and not a second copy of that.  It is also what keeps libext2fs out
 * of the library: the ldiskfs backend is dlopen'ed, as mount.lustre does.
 *
 * Control is inverted relative to a next()/read() iterator: the backend walks
 * one chunk of its id space and calls the sink per object.
 *
 * Author: Hiroshi Nishida <hnishida@thelustrecollective.com>
 */
#ifndef _LUSTREAPI_SCAN_BACKEND_H_
#define _LUSTREAPI_SCAN_BACKEND_H_

#include <stddef.h>
#include <linux/types.h>

/* The xattrs a backend may be asked to bring back with an object. */
enum llapi_scan_xattr {
	LLAPI_SCAN_XA_LMA = 0,		/* trusted.lma: always asked for */
	LLAPI_SCAN_XA_LOV,		/* trusted.lov */
	LLAPI_SCAN_XA_LMV,		/* trusted.lmv */
	LLAPI_SCAN_XA_SOM,		/* trusted.som */
	LLAPI_SCAN_XA_LINK,		/* trusted.link */
	LLAPI_SCAN_XA_HSM,		/* trusted.hsm */
	LLAPI_SCAN_XA_MAX
};

#define LLAPI_SCAN_XA_BIT(x)	(1U << (x))

/* Why an object was not delivered; counted, never silent. */
enum llapi_scan_skip {
	LLAPI_SCAN_SKIP_INVALID = 0,	/* not a legal object: a torn read */
	LLAPI_SCAN_SKIP_IO,		/* the target could not read it */
	LLAPI_SCAN_SKIP_XATTR,		/* its xattrs could not be read */
	LLAPI_SCAN_SKIP_MAX
};

/* A value the backend read, still in on-disk form. */
struct llapi_scan_val {
	const void	*sv_buf;
	size_t		 sv_len;
};

/**
 * struct llapi_scan_obj - one object, as the backend found it
 *
 * Attributes are in host order, xattr values are not.  The so_xattr pointers
 * are the backend's and last until the sink call returns.
 */
struct llapi_scan_obj {
	__u64	so_id;			/* inode number, dnode, object id */
	__u32	so_mode;
	__u32	so_nlink;
	__u32	so_uid;
	__u32	so_gid;
	__u32	so_projid;
	__u32	so_flags;		/* STATX_ATTR_*-compatible bits */
	__u32	so_gen;
	__u32	so_rdev;		/* la_rdev of a device node */
	__u64	so_size;		/* the target's own, not the file's */
	__u64	so_blocks;		/* 512-byte units, on this target */
	__s64	so_atime;
	__s64	so_mtime;
	__s64	so_ctime;
	__s64	so_btime;
	__u32	so_valid;		/* LLAPI_SCAN_SO_* that mean anything */
	__u32	so_xa_valid;		/* LLAPI_SCAN_XA_BIT() actually read */
	/*
	 * Which STATX_ATTR_* this backend can report in so_flags, as statx
	 * means stx_attributes_mask: a bit clear here is "cannot say", which
	 * is a different answer from the bit being clear in so_flags.  The
	 * backends do not support the same set, so one constant in the
	 * scanner would over-claim for one of them.  ENCRYPTED is not here:
	 * the scanner takes it from the LMA for every backend.
	 */
	__u32	so_attrs_mask;
	__u32	so_padding[1];
	struct llapi_scan_val so_xattr[LLAPI_SCAN_XA_MAX];
};

/* Attributes an inode may be too small to carry; zero is a different answer. */
#define LLAPI_SCAN_SO_PROJID	0x00000001U
#define LLAPI_SCAN_SO_BTIME	0x00000002U
#define LLAPI_SCAN_SO_GEN	0x00000004U

/* Target flags a backend reports at open time. */
#define LLAPI_SCAN_TGT_OST	0x00000001U	/* a recognised OST */
#define LLAPI_SCAN_TGT_MDT	0x00000002U	/* a recognised MDT */
#define LLAPI_SCAN_TGT_INDEX	0x00000004U	/* tt_index was assigned */

/**
 * struct llapi_scan_tgt - what the backend says about the target
 *
 * tt_chunks is the unit of work, its meaning the backend's: indices below it
 * must cover the target exactly once.
 */
struct llapi_scan_tgt {
	char	tt_label[64];		/* fsname-MDT0000, as formatted */
	__u32	tt_index;		/* target index, if TGT_INDEX */
	__u32	tt_flags;		/* LLAPI_SCAN_TGT_* */
	__u64	tt_chunks;		/* units of work */
};

/**
 * struct llapi_scan_sink - what the backend calls, once per object
 *
 * One sink per worker; sk_ctx must not be shared between threads.
 *
 * sk_prefilter() is the cheap stage, called with no xattr read behind it:
 * 0 to go on, 1 to drop the object, negative to stop the scan.  sk_object()
 * follows once the demanded xattrs are in hand, same convention.
 */
struct llapi_scan_sink {
	void	*sk_ctx;
	__u32	 sk_want_xattr;		/* LLAPI_SCAN_XA_BIT() to fetch */
	__u32	 sk_padding;
	int	(*sk_prefilter)(void *ctx, const struct llapi_scan_obj *obj);
	int	(*sk_object)(void *ctx, const struct llapi_scan_obj *obj);
	void	(*sk_skip)(void *ctx, enum llapi_scan_skip why);
};

/**
 * struct llapi_scan_backend - the entry points a backend exports
 *
 * Resolved by dlsym() as scan_ldiskfs_open and so on, or taken from the
 * linked-in table where plugins are disabled.  sb_scan_chunk() sets *done
 * on the last chunk of the target, which is how a scan ends without the
 * core knowing what a chunk is.  It says "no chunk after this one", not
 * "this chunk is empty": the chunk carrying the tail of the target still
 * delivers its objects, and the core keeps it inside the range.
 */
struct llapi_scan_backend {
	int	(*sb_open)(const char *device, void **tgtp,
			   struct llapi_scan_tgt *tgt);
	void	(*sb_close)(void *tgt);
	int	(*sb_worker_init)(void *tgt, void **wctxp);
	void	(*sb_worker_fini)(void *tgt, void *wctx);
	int	(*sb_scan_chunk)(void *tgt, void *wctx, __u64 idx,
				 const struct llapi_scan_sink *sink, int *done);
};

/* The ldiskfs entry points, for the build that links them in. */
int scan_ldiskfs_open(const char *device, void **tgtp,
		      struct llapi_scan_tgt *tgt);
void scan_ldiskfs_close(void *tgt);
int scan_ldiskfs_worker_init(void *tgt, void **wctxp);
void scan_ldiskfs_worker_fini(void *tgt, void *wctx);
int scan_ldiskfs_scan_chunk(void *tgt, void *wctx, __u64 idx,
			    const struct llapi_scan_sink *sink, int *done);

#endif /* _LUSTREAPI_SCAN_BACKEND_H_ */
