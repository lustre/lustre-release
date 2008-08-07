/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * FIEMAP data structures and flags. This header file will be used until
 * fiemap.h is available in the upstream kernel.
 */

#ifndef _LUSTRE_FIEMAP_H
#define _LUSTRE_FIEMAP_H

#ifndef HAVE_LINUX_FIEMAP_H

#include <linux/lustre_types.h>

struct ll_fiemap_extent {
        __u64   fe_logical;  /* logical offset in bytes for the start of
                              * the extent from the beginning of the file */
        __u64   fe_physical; /* physical offset in bytes for the start
                              * of the extent from the beginning of the disk */
        __u64   fe_length;   /* length in bytes for the extent */
        __u32   fe_flags;    /* FIEMAP_EXTENT_* flags for the extent */
        __u32   fe_device;   /* device number for this extent */
};

struct ll_user_fiemap {
        __u64   fm_start;         /* logical offset (inclusive) at
                                   * which to start mapping (in) */
        __u64   fm_length;        /* logical length of mapping which
                                   * userspace wants (in) */
        __u32   fm_flags;         /* FIEMAP_FLAG_* flags for request (in/out) */
        __u32   fm_mapped_extents;/* number of extents that were mapped (out) */
        __u32   fm_extent_count;  /* size of fm_extents array (in) */
        __u32   fm_reserved;
        struct  ll_fiemap_extent   fm_extents[0]; /* array of mapped extents (out).
                                                   * Lustre uses first extent to
                                                   * send end_offset */
};

#define FIEMAP_MAX_OFFSET      (~0ULL)

#define FIEMAP_FLAG_SYNC         0x00000001 /* sync file data before map */
#define FIEMAP_FLAG_XATTR        0x00000002 /* map extended attribute tree */
#define FIEMAP_FLAG_DEVICE_ORDER 0x40000000 /* return device ordered mapping */

#define FIEMAP_FLAGS_COMPAT    (FIEMAP_FLAG_SYNC | FIEMAP_FLAG_XATTR | \
                                FIEMAP_FLAG_DEVICE_ORDER)

#define FIEMAP_EXTENT_LAST             0x00000001 /* Last extent in file. */
#define FIEMAP_EXTENT_UNKNOWN          0x00000002 /* Data location unknown. */
#define FIEMAP_EXTENT_DELALLOC         0x00000004 /* Location still pending.
                                                   * Sets EXTENT_UNKNOWN. */
#define FIEMAP_EXTENT_NO_DIRECT        0x00000008 /* Data mapping undefined */
#define FIEMAP_EXTENT_SECONDARY        0x00000010 /* Data copied offline. May
                                                   * set EXTENT_NO_DIRECT. */
#define FIEMAP_EXTENT_NET              0x00000020 /* Data stored remotely.
                                                   * Sets EXTENT_NO_DIRECT. */
#define FIEMAP_EXTENT_DATA_COMPRESSED  0x00000040 /* Data is compressed by fs.
                                                   * Sets EXTENT_NO_DIRECT. */
#define FIEMAP_EXTENT_DATA_ENCRYPTED   0x00000080 /* Data is encrypted by fs.
                                                   * Sets EXTENT_NO_DIRECT. */
#define FIEMAP_EXTENT_NOT_ALIGNED      0x00000100 /* Extent offsets may not be
                                                   * block aligned. */
#define FIEMAP_EXTENT_DATA_INLINE      0x00000200 /* Data mixed with metadata.
                                                   * Sets EXTENT_NOT_ALIGNED.*/
#define FIEMAP_EXTENT_DATA_TAIL        0x00000400 /* Multiple files in block.
                                                   * Sets EXTENT_NOT_ALIGNED.*/
#define FIEMAP_EXTENT_UNWRITTEN        0x00000800 /* Space allocated, but
                                                   * no data (i.e. zero). */
#define FIEMAP_EXTENT_MERGED           0x00001000 /* File does not natively
                                                   * support extents. Result
                                                   * merged for efficiency. */

#else

#define ll_fiemap_extent fiemap_extent
#define ll_user_fiemap   fiemap

#endif /* HAVE_LINUX_FIEMAP_H */

static inline size_t fiemap_count_to_size(size_t extent_count)
{
        return (sizeof(struct ll_user_fiemap) + extent_count *
                                               sizeof(struct ll_fiemap_extent));
}

static inline unsigned fiemap_size_to_count(size_t array_size)
{
        return ((array_size - sizeof(struct ll_user_fiemap)) /
                                               sizeof(struct ll_fiemap_extent));
}

#endif /* _LUSTRE_FIEMAP_H */
