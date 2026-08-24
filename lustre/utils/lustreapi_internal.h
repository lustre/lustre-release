/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *     alternatives
 *
 * Copyright (c) 2016, 2017, Intel Corporation.
 */
/*
 *
 * lustre/utils/lustreapi_internal.h
 *
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 * Author: JC Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 * Author: Thomas Leibovici <thomas.leibovici@cea.fr>
 */

#ifndef _LUSTREAPI_INTERNAL_H_
#define _LUSTREAPI_INTERNAL_H_

#include <assert.h>
#include <dirent.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include <libcfs/util/ioctl.h>
#include <libcfs/util/param.h>

#include <linux/lustre/lustre_idl.h>
#include <linux/lustre/lustre_kernelcomm.h>

#include "lstddef.h"		/* ARRAY_SIZE */

#include <lustre/lustreapi.h>

struct cYAML;

int verify_pin_xattr_object(struct cYAML *yaml);
int dump_pin_object(struct cYAML *yaml, char *buff, int buflen);
struct cYAML *read_pin_xattr_object(const char *path);
struct cYAML *read_pin_xattr_object_fd(int fd);

#define MAX_IOC_BUFLEN	8192
#define MAX_INSTANCE_LEN  32

#define WANT_PATH   0x1
#define WANT_FSNAME 0x2
#define WANT_FD     0x4
#define WANT_INDEX  0x8
#define WANT_ERROR  0x10
#define WANT_DEV    0x20
#define WANT_NID    0x40

/* Define a fixed 4096-byte encryption unit size */
#define LUSTRE_ENCRYPTION_BLOCKBITS   12
#define LUSTRE_ENCRYPTION_UNIT_SIZE   ((size_t)1 << LUSTRE_ENCRYPTION_BLOCKBITS)
#define LUSTRE_ENCRYPTION_MASK        (~(LUSTRE_ENCRYPTION_UNIT_SIZE - 1))

#define OBD_NOT_FOUND	(-1)

/* mount point listings in /proc/mounts */
#ifndef PROC_MOUNTS
#define PROC_MOUNTS "/proc/mounts"
#endif

int get_root_path(int want, char *fsname, int *outfd, char *path, int index,
		  dev_t *dev, char **out_nid);
struct obd_ioctl_data;
int llapi_ioctl_pack(struct obd_ioctl_data *data, char **pbuf, int max_len);
int llapi_ioctl_dev(int dev_id, unsigned int cmd, void *buf);
int llapi_ioctl_unpack(struct obd_ioctl_data *data, char *pbuf, int max_len);
int sattr_cache_get_defaults(const char *const fsname,
			     const char *const pathname, unsigned int *scount,
			     unsigned int *ssize, unsigned int *soffset);

/**
 * Often when determining the parameter path in sysfs/procfs we
 * are often only interest set of data. This enum gives use the
 * ability to return data of parameters for:
 *
 * FILTER_BY_FS_NAME: a specific file system mount
 * FILTER_BY_PATH:    Using a Lustre file path to determine which
 *		      file system is of interest
 * FILTER_BY_EXACT:   The default behavior. Search the parameter
 *		      path as is.
 */
enum param_filter {
	FILTER_BY_NONE,
	FILTER_BY_EXACT,
	FILTER_BY_FS_NAME,
	FILTER_BY_PATH
};

int get_lustre_param_path(const char *obd_type, const char *filter,
			  enum param_filter type, const char *param_name,
			  glob_t *param);
int get_lustre_param_value(const char *obd_type, const char *filter,
			   enum param_filter type, const char *param_name,
			   char *value, size_t val_len);

static inline int
poolpath(glob_t *pool_path, const char *fsname, char *pathname)
{
	int rc;

	if (fsname != NULL)
		rc = get_lustre_param_path("lov", fsname, FILTER_BY_FS_NAME,
					   "pools", pool_path);
	else
		rc = get_lustre_param_path("lov", pathname, FILTER_BY_PATH,
					   "pools", pool_path);
	return rc;
}

#define LLAPI_LAYOUT_MAGIC 0x11AD1107 /* LLAPILOT */

/* Helper functions for testing validity of stripe attributes. */

static inline bool llapi_stripe_size_is_aligned(uint64_t size)
{
	return (size & (LOV_MIN_STRIPE_SIZE - 1)) == 0;
}

static inline bool llapi_stripe_size_is_too_big(uint64_t size)
{
	return size >= (1ULL << 32);
}

static inline bool llapi_stripe_count_is_valid(int64_t count)
{
	return count >= LLAPI_OVERSTRIPE_COUNT_MAX &&
	       count <= LOV_MAX_STRIPE_COUNT;
}

static inline bool llapi_stripe_index_is_valid(int64_t index)
{
	return index >= -1 && index <= LOV_V1_INSANE_STRIPE_INDEX;
}

static inline bool llapi_dir_stripe_count_is_valid(int64_t count)
{
	return count >= LMV_OVERSTRIPE_COUNT_MAX &&
	       count <= LMV_MAX_STRIPE_COUNT;
}

static inline bool llapi_dir_stripe_index_is_valid(int64_t index)
{
	return index >= -1 && index < LMV_MAX_STRIPE_COUNT;
}

static inline bool llapi_dir_hash_type_is_valid(int64_t hash)
{
	int64_t _hash = hash & LMV_HASH_TYPE_MASK;

	return _hash >= LMV_HASH_TYPE_UNKNOWN && _hash <  LMV_HASH_TYPE_MAX;
}

/*
 * Kernel communication for Changelogs and HSM requests.
 */
int libcfs_ukuc_start(struct lustre_kernelcomm *l, int groups, int rfd_flags);
int libcfs_ukuc_stop(struct lustre_kernelcomm *l);
int libcfs_ukuc_get_rfd(struct lustre_kernelcomm *link);
int libcfs_ukuc_msg_get(struct lustre_kernelcomm *l, char *buf, int maxsize,
			int transport);

enum lctl_param_flags {
	PARAM_FLAGS_YAML_FORMAT		= 0x0001,
	PARAM_FLAGS_SHOW_SOURCE		= 0x0002,
	PARAM_FLAGS_EXTRA_DETAILS	= 0x0004,
	PARAM_FLAGS_EXTRA_IGNORE_ERROR	= 0x0008,
};

int llapi_param_display_value(char *path, int version,
			      enum lctl_param_flags flags, FILE *fp);
int llapi_param_set_value(char *path, char *value, int version,
			  enum lctl_param_flags flags, FILE *fp);

enum get_lmd_info_type {
	GET_LMD_INFO = 1,
	GET_LMD_STRIPE = 2,
};

int get_lmd_info_fd(const char *path, int parentfd, int dirfd,
		    void *lmd_buf, int lmd_len, enum get_lmd_info_type type);

int lov_comp_md_size(struct lov_comp_md_v1 *lcm);

int open_parent(const char *path);

static inline bool is_mgs(void)
{
	glob_t path;
	int rc;

	rc = cfs_get_param_paths(&path, "mgs/MGS/exports");
	if (!rc) {
		cfs_free_param_data(&path);
		return true;
	}

	return false;
}

static inline bool is_mds(void)
{
	glob_t path;
	int rc;

	rc = cfs_get_param_paths(&path, "mdt/*-MDT*/exports");
	if (!rc) {
		cfs_free_param_data(&path);
		return true;
	}

	return false;
}

static inline bool is_oss(void)
{
	glob_t path;
	int rc;

	rc = cfs_get_param_paths(&path, "obdfilter/*-OST*/exports");
	if (!rc) {
		cfs_free_param_data(&path);
		return true;
	}

	return false;
}

static inline bool lmv_is_foreign(__u32 magic)
{
	return magic == LMV_MAGIC_FOREIGN;
}

static inline struct lov_user_md *
lov_comp_entry(struct lov_comp_md_v1 *comp_v1, int ent_idx)
{
	return (struct lov_user_md *)((char *)comp_v1 +
			comp_v1->lcm_entries[ent_idx].lcme_offset);
}

static inline struct lov_user_ost_data_v1 *
lov_v1v3_objects(struct lov_user_md *v1)
{
	if (v1->lmm_magic == LOV_USER_MAGIC_V3)
		return ((struct lov_user_md_v3 *)v1)->lmm_objects;
	else
		return v1->lmm_objects;
}

static inline void
lov_v1v3_pool_name(struct lov_user_md *v1, char *pool_name)
{
	if (v1->lmm_magic == LOV_USER_MAGIC_V3)
		snprintf(pool_name, LOV_MAXPOOLNAME + 1, "%s",
			 ((struct lov_user_md_v3 *)v1)->lmm_pool_name);
	else
		pool_name[0] = '\0';
}

int find_value_cmp(unsigned long long file, unsigned long long limit, int sign,
		   int negopt, unsigned long long margin, bool mds);
int find_comp_end_cmp(unsigned long long end, struct find_param *param);
void validate_printf_str(struct find_param *param);
int param_callback(char *path, llapi_find_cb_t cb_init,
		   llapi_find_cb_t cb_fini, struct find_param *param);
int cb_find_init(char *path, int p, int *dp, struct find_param *param,
		 struct dirent64 *de);
int cb_common_fini(char *path, int p, int *dp, struct find_param *param,
		   struct dirent64 *de);
/* @d keeps its number, but the ENOTTY retry may reopen what it names */
int cb_get_dirstripe(char *path, int d, struct find_param *param);
int get_projid(const char *path, int *fd, mode_t mode, __u32 *projid);

/* liblustreapi_scan.c: the record front-end lfs find shares with the scanner */
struct llapi_scan_rec;
/* the shortest struct llapi_scan_param a scan will act on: everything up to
 * and including the demand mask.  Anything after it may be missing, and is
 * read as zero.
 */
#define LLAPI_SCAN_PARAM_MIN_SIZE					\
	((__u32)(offsetof(struct llapi_scan_param, lfsp_want) +		\
		 sizeof(((struct llapi_scan_param *)0)->lfsp_want)))
/* and the longest: no definition of the struct will reach a page, so a size
 * past it is a caller's mistake, refused before its tail is read
 */
#define LLAPI_SCAN_PARAM_MAX_SIZE	4096
/* every lfsp_flags bit a namespace scan knows.  One mask per scanner, so that
 * a flag only one of them can act on cannot be quietly accepted by the other.
 * Deliberately not public: a caller that built against an "all flags" value
 * would mean a different set of bits by it than the library it is linked
 * against.
 */
#define LLAPI_SCAN_F_KNOWN_NS	(LLAPI_SCAN_F_STOP_ON_ERROR)
/*
 * What a namespace scan has to reach the MDT for.  The rest of what it can
 * answer for comes from the directory entry and is LLAPI_SCAN_DIRENT_MASK,
 * which is public because lfsp_filter runs against it.  Enumerated rather
 * than derived from "every bit up to the last one defined", so that a
 * field added for a scanner reading a device directly does not silently
 * become a field this one claims to fill.
 *
 * LLAPI_SCAN_LMV_FOREIGN is here because the gather sets it, and a mask
 * that did not name it would have scan_param_report_got() promise less
 * than the scan delivers.  Asked for alone it brings LLAPI_SCAN_LMV with
 * it: see scan_want_widen().
 *
 * STATX_INO is named here rather than through an alias: the ioctl fills
 * stx_ino, and nothing else does, so a demand mask of STATX_INO alone has
 * to reach the MDT.  LLAPI_SCAN_STATX_MASK promises the whole low half,
 * named or not, so asking for it alone is legal.
 */
#define LLAPI_SCAN_MDT_MASK	(LLAPI_SCAN_FID | LLAPI_SCAN_MODE |	\
				 ((__u64)STATX_INO) |			\
				 LLAPI_SCAN_NLINK | LLAPI_SCAN_UID |	\
				 LLAPI_SCAN_GID | LLAPI_SCAN_SIZE |	\
				 LLAPI_SCAN_BLOCKS | LLAPI_SCAN_ATIME |	\
				 LLAPI_SCAN_MTIME | LLAPI_SCAN_CTIME |	\
				 LLAPI_SCAN_BTIME | LLAPI_SCAN_ATTRS |	\
				 LLAPI_SCAN_LAYOUT | LLAPI_SCAN_LMV |	\
				 LLAPI_SCAN_LMV_FOREIGN |		\
				 LLAPI_SCAN_MDT_INDEX |			\
				 LLAPI_SCAN_PROJID |			\
				 LLAPI_SCAN_HSM |			\
				 LLAPI_SCAN_LAZY_SIZE |			\
				 LLAPI_SCAN_LAZY_BLOCKS)
/*
 * Which lfsp_want bits llapi_scan_namespace() can answer for, and not
 * public: a caller that built against an "everything" value would mean a
 * different set of bits by it than the library it is linked against.
 *
 * A bit outside it is dropped rather than refused -- see lfsp_got in
 * lustreapi.h -- so this is what the scanner may fill and nothing more.
 * Enumerated from the fields the gather actually sets.
 */
#define LLAPI_SCAN_WANT_KNOWN_NS	(LLAPI_SCAN_DIRENT_MASK |	\
					 LLAPI_SCAN_MDT_MASK)

/*
 * How much of the caller's struct to copy: whole fields only.
 *
 * lfsp_size is the caller's, and a size that stops inside a field leaves it
 * neither the caller's value nor zero.  lfsp_filter is where that bites: it
 * is a function pointer the scan then calls, and the range test alone does
 * not catch it, lfsp_filter ending at 32 where the minimum is 24, so 25..31
 * passes.  Every pointer this struct gains later is the same case.
 *
 * Rounded down rather than refused, because a short size is already how a
 * caller says "this field is missing" -- one that stops mid-field is the
 * same statement made imprecisely, and the field it stops in is exactly the
 * one to drop.
 */
static inline __u32 scan_param_whole(__u32 size)
{
#define SCAN_PF_END(f)							\
	((__u32)(offsetof(struct llapi_scan_param, f) +			\
		 sizeof(((struct llapi_scan_param *)0)->f)))
	static const __u32 ends[] = {
		SCAN_PF_END(lfsp_want), SCAN_PF_END(lfsp_filter),
		SCAN_PF_END(lfsp_thread_count), SCAN_PF_END(lfsp_padding),
		SCAN_PF_END(lfsp_got),
	};
	static_assert(SCAN_PF_END(lfsp_got) ==
		      sizeof(struct llapi_scan_param),
		      "a field was added without a row in ends[]");
#undef SCAN_PF_END
	__u32 whole = ends[0];
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ends); i++)
		if (ends[i] <= size)
			whole = ends[i];

	return whole;
}

/*
 * The reserved bytes are documented must-be-zero, so that a field carved
 * out of them later cannot be set by a newer caller and silently ignored
 * here: they are already inside lfsp_size, which is what catches an
 * appended field.
 */
static inline bool scan_param_padding_ok(const struct llapi_scan_param *sp)
{
	unsigned int i;

	for (i = 0; i < sizeof(sp->lfsp_padding); i++)
		if (sp->lfsp_padding[i] != 0)
			return false;

	return true;
}

/*
 * Take the caller's parameter block, whatever version of the struct it was
 * built against, and say whether this library can act on it.
 *
 * A shorter block than ours is the easy half: the fields it stops before
 * read as zero, which is what a caller built against an older header means
 * by not having them.  A longer one is the interoperability case -- an
 * application built against a newer header, running against this library --
 * and it is accepted as long as every byte past the end of our definition
 * is zero.  That is the caller demonstrating it set no field we could not
 * honour; one that did set such a field is refused, which is the same
 * answer an undefined lfsp_flags bit gets and for the same reason.
 *
 * Reading those bytes takes the caller at its word that lfsp_size describes
 * memory it owns, as every size-carrying interface does, up to
 * LLAPI_SCAN_PARAM_MAX_SIZE.
 *
 * The demand mask is not policed here.  A want bit this library does not
 * know is not an error -- it is dropped, and lfsp_got reports the rest --
 * because a field is asked for, where a flag is commanded.
 */
static inline int scan_param_copyin(struct llapi_scan_param *dst,
				    const struct llapi_scan_param *src,
				    __u64 known_flags)
{
	const unsigned char *tail;
	__u32 i;

	memset(dst, 0, sizeof(*dst));

	if (src->lfsp_size < LLAPI_SCAN_PARAM_MIN_SIZE ||
	    src->lfsp_size > LLAPI_SCAN_PARAM_MAX_SIZE)
		return -EINVAL;
	if (src->lfsp_flags & ~known_flags)
		return -EINVAL;

	if (src->lfsp_size > (__u32)sizeof(*dst)) {
		tail = (const unsigned char *)src + sizeof(*dst);
		for (i = 0; i < src->lfsp_size - (__u32)sizeof(*dst); i++)
			if (tail[i] != 0)
				return -EINVAL;
		memcpy(dst, src, sizeof(*dst));
	} else {
		memcpy(dst, src, scan_param_whole(src->lfsp_size));
	}
	/* ours from here on, whatever the caller's was */
	dst->lfsp_size = sizeof(*dst);

	if (!scan_param_padding_ok(dst))
		return -EINVAL;

	return 0;
}

/*
 * What a scan will answer for, reported to the caller before the first
 * record.  @known is the entry point's mask, already narrowed to the
 * target where the scan knows it.  A bit here says the scan may fill the
 * field, not that any one object has it: an object with no project id
 * still leaves LLAPI_SCAN_PROJID clear in lfsr_valid.
 */
/* LLAPI_SCAN_LMV_FOREIGN describes lfsr_lmv, so asking for it asks for that */
static inline __u64 scan_want_widen(__u64 want)
{
	if (want & LLAPI_SCAN_LMV_FOREIGN)
		want |= LLAPI_SCAN_LMV;
	return want;
}

static inline void scan_param_report_got(const struct llapi_scan_param *sp,
					 __u64 want, __u64 known)
{
	if (sp != NULL && sp->lfsp_got != NULL)
		*sp->lfsp_got = want & known;
}

/* what llapi_scan_namespace() gathers when lfsp_want is 0: everything,
 * except the fields that cost an ioctl or an open per object and have to
 * be named.
 */
#define LLAPI_SCAN_WANT_DEFAULT						\
	(~0ULL & ~(LLAPI_SCAN_MDT_INDEX | LLAPI_SCAN_PROJID |		\
		   LLAPI_SCAN_HSM))

void scan_rec_dirent(struct llapi_scan_rec *rec, const char *path,
		     int p, int d, const struct dirent64 *de);
int scan_rec_gather(struct find_param *param, char *path, int p,
		    int d, int *fdp, __u64 want,
		    struct llapi_scan_rec *rec);
int common_param_init(struct find_param *param, char *path);
void find_param_fini(struct find_param *param);
int parallel_find(char *path, llapi_find_cb_t cb_init, llapi_find_cb_t cb_fini,
		  struct find_param *param);
int work_unit_create_and_add(const char *path, struct find_param *param,
			     struct dirent64 *dent);
int llapi_semantic_traverse(char *path, int size, int parent,
			    llapi_find_cb_t sem_init,
			    llapi_find_cb_t sem_fini, void *data,
			    struct dirent64 *de);

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000UL
#endif
#ifndef ONE_MB
#define ONE_MB (1024 * 1024)
#endif
#define DEFAULT_IO_BUFLEN (64 * ONE_MB)

static inline struct timespec timespec_sub(struct timespec *before,
					   struct timespec *after)
{
	struct timespec ret;

	ret.tv_sec = after->tv_sec - before->tv_sec;
	if (after->tv_nsec < before->tv_nsec) {
		ret.tv_sec--;
		ret.tv_nsec = NSEC_PER_SEC + after->tv_nsec - before->tv_nsec;
	} else {
		ret.tv_nsec = after->tv_nsec - before->tv_nsec;
	}

	return ret;
}

/* not ready to expose as official APIs yet, but want to share code */
void llapi_bandwidth_throttle(struct timespec *now, struct timespec *start_time,
			      uint64_t bandwidth_bytes_sec,
			      uint64_t total_bytes_written);
void llapi_stats_log(struct timespec *now, struct timespec *start_time,
		     struct timespec *last_print, int stats_interval_sec,
		     uint64_t read_bytes, uint64_t write_bytes,
		     uint64_t offset, uint64_t file_size_bytes);

#ifndef BIT
#define BIT(nr) (1ULL << (nr))
#endif
int llapi_convert_mask2str(char *str, int size, __u64 mask,
			   const char *(*bit2str)(int), char sep);
int llapi_convert_str2mask(const char *str, const char *(*bit2str)(int bit),
			   __u64 *oldmask, __u64 minmask, __u64 allmask,
			   __u64 defmask);
int llapi_name_verify(const char *name, const char *extra_char,
		      unsigned int maxlen, const char *type);
#define llint_pool_name_verify(pool) \
	llapi_name_verify(pool, "-_", LOV_MAXPOOLNAME, "Pool")
#define llint_lqa_name_verify(lqa) \
	llapi_name_verify(lqa, "_", LQA_NAME_MAX, "LQA")
#endif /* _LUSTREAPI_INTERNAL_H_ */
