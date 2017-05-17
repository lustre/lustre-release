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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _LUSTREAPI_H_
#define _LUSTREAPI_H_

/** \defgroup llapi llapi
 *
 * @{
 */

#include <stdarg.h>
#include <stdint.h>
#include <lustre/lustre_user.h>

#ifndef LL_MAXQUOTAS
#define LL_MAXQUOTAS 3
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) ((sizeof(a)) / (sizeof((a)[0])))
#endif

extern bool liblustreapi_initialized;


typedef void (*llapi_cb_t)(char *obd_type_name, char *obd_name, char *obd_uuid,
			   void *args);

/* lustreapi message severity level */
enum llapi_message_level {
        LLAPI_MSG_OFF    = 0,
        LLAPI_MSG_FATAL  = 1,
        LLAPI_MSG_ERROR  = 2,
        LLAPI_MSG_WARN   = 3,
        LLAPI_MSG_NORMAL = 4,
        LLAPI_MSG_INFO   = 5,
        LLAPI_MSG_DEBUG  = 6,
        LLAPI_MSG_MAX
};

typedef void (*llapi_log_callback_t)(enum llapi_message_level level, int err,
				     const char *fmt, va_list ap);


/* the bottom three bits reserved for llapi_message_level */
#define LLAPI_MSG_MASK          0x00000007
#define LLAPI_MSG_NO_ERRNO      0x00000010

static inline const char *llapi_msg_level2str(enum llapi_message_level level)
{
	static const char *levels[LLAPI_MSG_MAX] = {"OFF", "FATAL", "ERROR",
						    "WARNING", "NORMAL",
						    "INFO", "DEBUG"};

	if (level >= LLAPI_MSG_MAX)
		return NULL;

	return levels[level];
}
extern void llapi_msg_set_level(int level);
int llapi_msg_get_level(void);
extern llapi_log_callback_t llapi_error_callback_set(llapi_log_callback_t cb);
extern llapi_log_callback_t llapi_info_callback_set(llapi_log_callback_t cb);

void llapi_error(enum llapi_message_level level, int err, const char *fmt, ...)
	__attribute__((__format__(__printf__, 3, 4)));
#define llapi_err_noerrno(level, fmt, a...)			\
	llapi_error((level) | LLAPI_MSG_NO_ERRNO, 0, fmt, ## a)
void llapi_printf(enum llapi_message_level level, const char *fmt, ...)
	__attribute__((__format__(__printf__, 2, 3)));

struct llapi_stripe_param {
	unsigned long long	lsp_stripe_size;
	char			*lsp_pool;
	int			lsp_stripe_offset;
	int			lsp_stripe_pattern;
	/* Number of stripes. Size of lsp_osts[] if lsp_specific is true.*/
	int			lsp_stripe_count;
	bool			lsp_is_specific;
	__u32			lsp_osts[0];
};

extern int llapi_file_open_param(const char *name, int flags, mode_t mode,
				 const struct llapi_stripe_param *param);
extern int llapi_file_create(const char *name, unsigned long long stripe_size,
                             int stripe_offset, int stripe_count,
                             int stripe_pattern);
extern int llapi_file_open(const char *name, int flags, int mode,
                           unsigned long long stripe_size, int stripe_offset,
                           int stripe_count, int stripe_pattern);
extern int llapi_file_create_pool(const char *name,
                                  unsigned long long stripe_size,
                                  int stripe_offset, int stripe_count,
                                  int stripe_pattern, char *pool_name);
extern int llapi_file_open_pool(const char *name, int flags, int mode,
                                unsigned long long stripe_size,
                                int stripe_offset, int stripe_count,
                                int stripe_pattern, char *pool_name);
extern int llapi_poollist(const char *name);
extern int llapi_get_poollist(const char *name, char **poollist, int list_size,
                              char *buffer, int buffer_size);
extern int llapi_get_poolmembers(const char *poolname, char **members,
                                 int list_size, char *buffer, int buffer_size);
extern int llapi_file_get_stripe(const char *path, struct lov_user_md *lum);
extern int llapi_file_lookup(int dirfd, const char *name);

#define VERBOSE_COUNT		   0x1
#define VERBOSE_SIZE		   0x2
#define VERBOSE_OFFSET		   0x4
#define VERBOSE_POOL		   0x8
#define VERBOSE_DETAIL		  0x10
#define VERBOSE_OBJID		  0x20
#define VERBOSE_GENERATION	  0x40
#define VERBOSE_MDTINDEX	  0x80
#define VERBOSE_LAYOUT		 0x100
#define VERBOSE_COMP_COUNT	 0x200
#define VERBOSE_COMP_FLAGS	 0x400
#define VERBOSE_COMP_START	 0x800
#define VERBOSE_COMP_END	0x1000
#define VERBOSE_COMP_ID		0x2000
#define VERBOSE_DFID		0x4000
#define VERBOSE_HASH_TYPE	0x8000
#define VERBOSE_DEFAULT		(VERBOSE_COUNT | VERBOSE_SIZE | \
				 VERBOSE_OFFSET | VERBOSE_POOL | \
				 VERBOSE_OBJID | VERBOSE_GENERATION | \
				 VERBOSE_LAYOUT | VERBOSE_HASH_TYPE | \
				 VERBOSE_COMP_COUNT | VERBOSE_COMP_FLAGS | \
				 VERBOSE_COMP_START | VERBOSE_COMP_END | \
				 VERBOSE_COMP_ID)

struct find_param {
	unsigned int		 fp_max_depth;
	dev_t			 fp_dev;
	mode_t			 fp_type; /* S_IFIFO,... */
	uid_t			 fp_uid;
	gid_t			 fp_gid;
	time_t			 fp_atime;
	time_t			 fp_mtime;
	time_t			 fp_ctime;
	/* {a,m,c}sign cannot be bitfields due to using pointers to
	 * access them during argument parsing. */
	int			 fp_asign;
	int			 fp_msign;
	int			 fp_csign;
	/* these need to be signed values */
	int			 fp_size_sign:2,
				 fp_stripe_size_sign:2,
				 fp_stripe_count_sign:2,
				 fp_comp_start_sign:2,
				 fp_comp_end_sign:2,
				 fp_comp_count_sign:2,
				 fp_mdt_count_sign:2;
	unsigned long long	 fp_size;
	unsigned long long	 fp_size_units;

	unsigned long long	 fp_zero_end:1,
				 fp_recursive:1,
				 fp_exclude_pattern:1,
				 fp_exclude_type:1,
				 fp_exclude_obd:1,
				 fp_exclude_mdt:1,
				 fp_exclude_gid:1,
				 fp_exclude_uid:1,
				 fp_check_gid:1,
				 fp_check_uid:1,
				 fp_check_pool:1,	/* LOV pool name */
				 fp_check_size:1,	/* file size */
				 fp_exclude_pool:1,
				 fp_exclude_size:1,
				 fp_exclude_atime:1,
				 fp_exclude_mtime:1,
				 fp_exclude_ctime:1,
				 fp_get_lmv:1,	/* get MDT list from LMV */
				 fp_raw:1,	/* do not fill in defaults */
				 fp_check_stripe_size:1, /* LOV stripe size */
				 fp_exclude_stripe_size:1,
				 fp_check_stripe_count:1, /* LOV stripe count */
				 fp_exclude_stripe_count:1,
				 fp_check_layout:1,
				 fp_exclude_layout:1,
				 fp_get_default_lmv:1, /* Get default LMV */
				 fp_migrate:1,
				 fp_check_projid:1,
				 fp_exclude_projid:1,
				 fp_check_comp_count:1,
				 fp_exclude_comp_count:1,
				 fp_check_comp_flags:1,
				 fp_exclude_comp_flags:1,
				 fp_check_comp_start:1,
				 fp_exclude_comp_start:1,
				 fp_check_comp_end:1,
				 fp_exclude_comp_end:1,
				 fp_check_comp_id:1,
				 fp_exclude_comp_id:1,
				 fp_check_mdt_count:1,
				 fp_exclude_mdt_count:1,
				 fp_check_hash_type:1,
				 fp_exclude_hash_type:1,
				 fp_yaml:1;	/* output layout in YAML */

	int			 fp_verbose;
	int			 fp_quiet;

	/* regular expression */
	char			*fp_pattern;

	struct  obd_uuid	*fp_obd_uuid;
	int			 fp_num_obds;
	int			 fp_num_alloc_obds;
	int			 fp_obd_index;
	int			*fp_obd_indexes;

	struct  obd_uuid	*fp_mdt_uuid;
	int			 fp_num_mdts;
	int			 fp_num_alloc_mdts;
	int			 fp_mdt_index;
	int			*fp_mdt_indexes;
	int			 fp_file_mdt_index;

	size_t			 fp_lum_size;
	struct  lov_user_mds_data *fp_lmd;

	char			 fp_poolname[LOV_MAXPOOLNAME + 1];

	__u32			 fp_lmv_stripe_count;
	struct lmv_user_md	*fp_lmv_md;

	unsigned long long	 fp_stripe_size;
	unsigned long long	 fp_stripe_size_units;
	unsigned long long	 fp_stripe_count;
	__u32			 fp_layout;

	__u32			 fp_comp_count;
	__u32			 fp_comp_flags;
	__u32			 fp_comp_id;
	unsigned long long	 fp_comp_start;
	unsigned long long	 fp_comp_start_units;
	unsigned long long	 fp_comp_end;
	unsigned long long	 fp_comp_end_units;
	unsigned long long	 fp_mdt_count;
	unsigned		 fp_projid;

	/* In-process parameters. */
	unsigned long		 fp_got_uuids:1,
				 fp_obds_printed:1;
	unsigned int		 fp_depth;
	unsigned int		 fp_hash_type;
};

extern int llapi_ostlist(char *path, struct find_param *param);
extern int llapi_uuid_match(char *real_uuid, char *search_uuid);
extern int llapi_getstripe(char *path, struct find_param *param);
extern int llapi_find(char *path, struct find_param *param);

extern int llapi_file_fget_mdtidx(int fd, int *mdtidx);
extern int llapi_dir_set_default_lmv_stripe(const char *name, int stripe_offset,
					   int stripe_count, int stripe_pattern,
					    const char *pool_name);
extern int llapi_dir_create_pool(const char *name, int flags, int stripe_offset,
				 int stripe_count, int stripe_pattern,
				 const char *poolname);
int llapi_direntry_remove(char *dname);

int llapi_obd_fstatfs(int fd, __u32 type, __u32 index,
		      struct obd_statfs *stat_buf, struct obd_uuid *uuid_buf);
extern int llapi_obd_statfs(char *path, __u32 type, __u32 index,
                     struct obd_statfs *stat_buf,
                     struct obd_uuid *uuid_buf);
extern int llapi_ping(char *obd_type, char *obd_name);
extern int llapi_target_check(int num_types, char **obd_types, char *dir);
extern int llapi_file_get_lov_uuid(const char *path, struct obd_uuid *lov_uuid);
extern int llapi_file_get_lmv_uuid(const char *path, struct obd_uuid *lmv_uuid);
extern int llapi_file_fget_lov_uuid(int fd, struct obd_uuid *lov_uuid);
extern int llapi_lov_get_uuids(int fd, struct obd_uuid *uuidp, int *ost_count);
extern int llapi_lmv_get_uuids(int fd, struct obd_uuid *uuidp, int *mdt_count);
extern int llapi_is_lustre_mnttype(const char *type);
extern int llapi_search_ost(char *fsname, char *poolname, char *ostname);
extern int llapi_get_obd_count(char *mnt, int *count, int is_mdt);
extern int llapi_parse_size(const char *optarg, unsigned long long *size,
			    unsigned long long *size_units, int bytes_spec);
extern int llapi_search_mounts(const char *pathname, int index,
                               char *mntdir, char *fsname);
extern int llapi_search_fsname(const char *pathname, char *fsname);
extern int llapi_getname(const char *path, char *buf, size_t size);
extern int llapi_search_fileset(const char *pathname, char *fileset);

extern int llapi_search_rootpath(char *pathname, const char *fsname);
extern int llapi_nodemap_exists(const char *name);
extern int llapi_migrate_mdt(char *path, struct find_param *param);
extern int llapi_mv(char *path, struct find_param *param);

struct mntent;
#define HAVE_LLAPI_IS_LUSTRE_MNT
extern int llapi_is_lustre_mnt(struct mntent *mnt);
extern int llapi_quotactl(char *mnt, struct if_quotactl *qctl);
extern int llapi_target_iterate(int type_num, char **obd_type, void *args,
				llapi_cb_t cb);
extern int llapi_get_connect_flags(const char *mnt, __u64 *flags);
extern int llapi_cp(int argc, char *argv[]);
extern int llapi_ls(int argc, char *argv[]);
extern int llapi_fid2path(const char *device, const char *fidstr, char *path,
			  int pathlen, long long *recno, int *linkno);
extern int llapi_path2fid(const char *path, lustre_fid *fid);
extern int llapi_get_mdt_index_by_fid(int fd, const lustre_fid *fid,
				      int *mdt_index);
extern int llapi_fd2fid(const int fd, lustre_fid *fid);
/* get FID of parent dir + the related name of entry in this parent dir */
extern int llapi_path2parent(const char *path, unsigned int linkno,
			     lustre_fid *parent_fid, char *name,
			     size_t name_size);
extern int llapi_fd2parent(int fd, unsigned int linkno,
			   lustre_fid *parent_fid, char *name,
			   size_t name_size);
extern int llapi_chomp_string(char *buf);
extern int llapi_open_by_fid(const char *dir, const lustre_fid *fid,
			     int open_flags);

extern int llapi_get_version_string(char *version, unsigned int version_size);
/* llapi_get_version() is deprecated, use llapi_get_version_string() instead */
extern int llapi_get_version(char *buffer, int buffer_size, char **version)
	__attribute__((deprecated));
extern int llapi_get_data_version(int fd, __u64 *data_version, __u64 flags);
extern int llapi_hsm_state_get_fd(int fd, struct hsm_user_state *hus);
extern int llapi_hsm_state_get(const char *path, struct hsm_user_state *hus);
extern int llapi_hsm_state_set_fd(int fd, __u64 setmask, __u64 clearmask,
				  __u32 archive_id);
extern int llapi_hsm_state_set(const char *path, __u64 setmask, __u64 clearmask,
			       __u32 archive_id);
extern int llapi_hsm_register_event_fifo(const char *path);
extern int llapi_hsm_unregister_event_fifo(const char *path);
extern void llapi_hsm_log_error(enum llapi_message_level level, int _rc,
				const char *fmt, va_list args);

extern int llapi_get_agent_uuid(char *path, char *buf, size_t bufsize);
extern int llapi_create_volatile_idx(char *directory, int idx, int mode);
static inline int llapi_create_volatile(char *directory, int mode)
{
	return llapi_create_volatile_idx(directory, -1, mode);
}


extern int llapi_fswap_layouts_grouplock(int fd1, int fd2, __u64 dv1, __u64 dv2,
					 int gid, __u64 flags);
extern int llapi_fswap_layouts(int fd1, int fd2, __u64 dv1, __u64 dv2,
			       __u64 flags);
extern int llapi_swap_layouts(const char *path1, const char *path2,
			      __u64 dv1, __u64 dv2, __u64 flags);

/* Changelog interface.  priv is private state, managed internally by these
 * functions */

/* Records received are in extended format now, though most of them are still
 * written in disk in changelog_rec format (to save space and time), it's
 * converted to extended format in the lustre api to ease changelog analysis. */
#define HAVE_CHANGELOG_EXTEND_REC 1

extern int llapi_changelog_start(void **priv, enum changelog_send_flag flags,
				 const char *mdtname, long long startrec);
extern int llapi_changelog_fini(void **priv);
extern int llapi_changelog_recv(void *priv, struct changelog_rec **rech);
extern int llapi_changelog_free(struct changelog_rec **rech);
extern int llapi_changelog_get_fd(void *priv);
/* Allow records up to endrec to be destroyed; requires registered id. */
extern int llapi_changelog_clear(const char *mdtname, const char *idstr,
                                 long long endrec);

/* HSM copytool interface.
 * priv is private state, managed internally by these functions
 */
struct hsm_copytool_private;
struct hsm_copyaction_private;

extern int llapi_hsm_copytool_register(struct hsm_copytool_private **priv,
				       const char *mnt, int archive_count,
				       int *archives, int rfd_flags);
extern int llapi_hsm_copytool_unregister(struct hsm_copytool_private **priv);
extern int llapi_hsm_copytool_get_fd(struct hsm_copytool_private *ct);
extern int llapi_hsm_copytool_recv(struct hsm_copytool_private *priv,
				   struct hsm_action_list **hal, int *msgsize);
extern int llapi_hsm_action_begin(struct hsm_copyaction_private **phcp,
				  const struct hsm_copytool_private *ct,
				  const struct hsm_action_item *hai,
				  int restore_mdt_index, int restore_open_flags,
				  bool is_error);
extern int llapi_hsm_action_end(struct hsm_copyaction_private **phcp,
				const struct hsm_extent *he,
				int hp_flags, int errval);
extern int llapi_hsm_action_progress(struct hsm_copyaction_private *hcp,
				     const struct hsm_extent *he, __u64 total,
				     int hp_flags);
extern int llapi_hsm_action_get_dfid(const struct hsm_copyaction_private *hcp,
				     lustre_fid *fid);
extern int llapi_hsm_action_get_fd(const struct hsm_copyaction_private *hcp);
extern int llapi_hsm_import(const char *dst, int archive, const struct stat *st,
			    unsigned long long stripe_size, int stripe_offset,
			    int stripe_count, int stripe_pattern,
			    char *pool_name, lustre_fid *newfid);

/* HSM user interface */
extern struct hsm_user_request *llapi_hsm_user_request_alloc(int itemcount,
							     int data_len);
extern int llapi_hsm_request(const char *path,
			     const struct hsm_user_request *request);
extern int llapi_hsm_current_action(const char *path,
				    struct hsm_current_action *hca);

/* JSON handling */
extern int llapi_json_init_list(struct llapi_json_item_list **item_list);
extern int llapi_json_destroy_list(struct llapi_json_item_list **item_list);
extern int llapi_json_add_item(struct llapi_json_item_list **item_list,
			       char *key, __u32 type, void *val);
extern int llapi_json_write_list(struct llapi_json_item_list **item_list,
				 FILE *fp);

/* File lease */
extern int llapi_lease_get(int fd, int mode);
extern int llapi_lease_check(int fd);
extern int llapi_lease_put(int fd);

/* Group lock */
int llapi_group_lock(int fd, int gid);
int llapi_group_unlock(int fd, int gid);

/* Ladvise */
int llapi_ladvise(int fd, unsigned long long flags, int num_advise,
		  struct llapi_lu_ladvise *ladvise);
/** @} llapi */

/* llapi_layout user interface */

/** Opaque data type abstracting the layout of a Lustre file. */
struct llapi_layout;

/*
 * Flags to control how layouts are retrieved.
 */

/* Replace non-specified values with expected inherited values. */
#define LAYOUT_GET_EXPECTED 0x1

/**
 * Return a pointer to a newly-allocated opaque data structure containing
 * the layout for the file at \a path.  The pointer should be freed with
 * llapi_layout_free() when it is no longer needed. Failure is indicated
 * by a NULL return value and an appropriate error code stored in errno.
 */
struct llapi_layout *llapi_layout_get_by_path(const char *path, uint32_t flags);

/**
 * Return a pointer to a newly-allocated opaque data type containing the
 * layout for the file referenced by open file descriptor \a fd.  The
 * pointer should be freed with llapi_layout_free() when it is no longer
 * needed. Failure is indicated by a NULL return value and an
 * appropriate error code stored in errno.
 */
struct llapi_layout *llapi_layout_get_by_fd(int fd, uint32_t flags);

/**
 * Return a pointer to a newly-allocated opaque data type containing the
 * layout for the file associated with Lustre file identifier string
 * \a fidstr.  The string \a path must name a path within the
 * filesystem that contains the file being looked up, such as the
 * filesystem root.  The returned pointer should be freed with
 * llapi_layout_free() when it is no longer needed.  Failure is
 * indicated with a NULL return value and an appropriate error code
 * stored in errno.
 */
struct llapi_layout *llapi_layout_get_by_fid(const char *path,
					     const lustre_fid *fid,
					     uint32_t flags);

/**
 * Allocate a new layout. Use this when creating a new file with
 * llapi_layout_file_create().
 */
struct llapi_layout *llapi_layout_alloc(void);

/**
 * Free memory allocated for \a layout.
 */
void llapi_layout_free(struct llapi_layout *layout);

/** Not a valid stripe size, offset, or RAID pattern. */
#define LLAPI_LAYOUT_INVALID	0x1000000000000001ULL

/**
 * When specified or returned as the value for stripe count,
 * stripe size, offset, or RAID pattern, the filesystem-wide
 * default behavior will apply.
 */
#define LLAPI_LAYOUT_DEFAULT	(LLAPI_LAYOUT_INVALID + 1)

/**
 * When specified or returned as the value for stripe count, all
 * available OSTs will be used.
 */
#define LLAPI_LAYOUT_WIDE	(LLAPI_LAYOUT_INVALID + 2)

/**
 * When specified as the value for layout pattern, file objects will be
 * stored using RAID0.  That is, data will be split evenly and without
 * redundancy across all OSTs in the layout.
 */
#define LLAPI_LAYOUT_RAID0	0

/**
* The layout includes a specific set of OSTs on which to allocate.
*/
#define LLAPI_LAYOUT_SPECIFIC	0x2000000000000000ULL

/**
 * A valid ost index should be less than maximum valid OST index (UINT_MAX).
 */
#define LLAPI_LAYOUT_IDX_MAX	0x00000000FFFFFFFFULL

/**
 * Flags to modify how layouts are retrieved.
 */
/******************** Stripe Count ********************/

/**
 * Store the stripe count of \a layout in \a count.
 *
 * \retval  0 Success
 * \retval -1 Error with status code in errno.
 */
int llapi_layout_stripe_count_get(const struct llapi_layout *layout,
				  uint64_t *count);

/**
 * Set the stripe count of \a layout to \a count.
 *
 * \retval  0 Success.
 * \retval -1 Invalid argument, errno set to EINVAL.
 */
int llapi_layout_stripe_count_set(struct llapi_layout *layout, uint64_t count);

/******************** Stripe Size ********************/

/**
 * Store the stripe size of \a layout in \a size.
 *
 * \retval  0 Success.
 * \retval -1 Invalid argument, errno set to EINVAL.
 */
int llapi_layout_stripe_size_get(const struct llapi_layout *layout,
				 uint64_t *size);

/**
 * Set the stripe size of \a layout to \a stripe_size.
 *
 * \retval  0 Success.
 * \retval -1 Invalid argument, errno set to EINVAL.
 */
int llapi_layout_stripe_size_set(struct llapi_layout *layout, uint64_t size);

/******************** Stripe Pattern ********************/

/**
 * Store the stripe pattern of \a layout in \a pattern.
 *
 * \retval 0  Success.
 * \retval -1 Error with status code in errno.
 */
int llapi_layout_pattern_get(const struct llapi_layout *layout,
			     uint64_t *pattern);

/**
 * Set the stripe pattern of \a layout to \a pattern.
 *
 * \retval  0 Success.
 * \retval -1 Invalid argument, errno set to EINVAL.
 */
int llapi_layout_pattern_set(struct llapi_layout *layout, uint64_t pattern);

/******************** OST Index ********************/

/**
 * Store the index of the OST where stripe number \a stripe_number is stored
 * in \a index.
 *
 * An error return value will result from a NULL layout, if \a
 * stripe_number is out of range, or if \a layout was not initialized
 * with llapi_layout_lookup_by{path,fd,fid}().
 *
 * \retval  0 Success
 * \retval -1 Invalid argument, errno set to EINVAL.
 */
int llapi_layout_ost_index_get(const struct llapi_layout *layout,
			       uint64_t stripe_number, uint64_t *index);

/**
 * Set the OST index associated with stripe number \a stripe_number to
 * \a ost_index.
 * NB: This is currently supported only for \a stripe_number = 0 and
 * other usage will return ENOTSUPP in errno.  A NULL \a layout or
 * out-of-range \a stripe_number will return EINVAL in errno.
 *
 * \retval  0 Success.
 * \retval -1 Error with errno set to non-zero value.
 */
int llapi_layout_ost_index_set(struct llapi_layout *layout, int stripe_number,
			       uint64_t index);

/******************** Pool Name ********************/

/**
 * Store up to \a pool_name_len characters of the name of the pool of
 * OSTs associated with \a layout into the buffer pointed to by
 * \a pool_name.
 *
 * The correct calling form is:
 *
 *   llapi_layout_pool_name_get(layout, pool_name, sizeof(pool_name));
 *
 * A pool defines a set of OSTs from which file objects may be
 * allocated for a file using \a layout.
 *
 * On success, the number of bytes stored is returned, excluding the
 * terminating '\0' character (zero indicates that \a layout does not
 * have an associated OST pool).  On error, -1 is returned and errno is
 * set appropriately. Possible sources of error include a NULL pointer
 * argument or insufficient space in \a dest to store the pool name,
 * in which cases errno will be set to EINVAL.
 *
 * \retval 0+		The number of bytes stored in \a dest.
 * \retval -1		Invalid argument, errno set to EINVAL.
 */
int llapi_layout_pool_name_get(const struct llapi_layout *layout,
			      char *pool_name, size_t pool_name_len);

/**
 * Set the name of the pool of OSTs from which file objects will be
 * allocated to \a pool_name.
 *
 * If the pool name uses "fsname.pool" notation to qualify the pool name
 * with a filesystem name, the "fsname." portion will be silently
 * discarded before storing the value. No validation that \a pool_name
 * is an existing non-empty pool in filesystem \a fsname will be
 * performed.  Such validation can be performed by the application if
 * desired using the llapi_search_ost() function.  The maximum length of
 * the stored value is defined by the constant LOV_MAXPOOLNAME.
 *
 * \retval  0	Success.
 * \retval -1	Invalid argument, errno set to EINVAL.
 */
int llapi_layout_pool_name_set(struct llapi_layout *layout,
			      const char *pool_name);

/******************** File Creation ********************/

/**
 * Open an existing file at \a path, or create it with the specified
 * \a layout and \a mode.
 *
 * One access mode and zero or more file creation flags and file status
 * flags May be bitwise-or'd in \a open_flags (see open(2)).  Return an
 * open file descriptor for the file.  If \a layout is non-NULL and
 * \a path is not on a Lustre filesystem this function will fail and set
 * errno to ENOTTY.
 *
 * An already existing file may be opened with this function, but
 * \a layout and \a mode will not be applied to it.  Callers requiring a
 * guarantee that the opened file is created with the specified
 * \a layout and \a mode should use llapi_layout_file_create().
 *
 * A NULL \a layout may be specified, in which case the standard Lustre
 * behavior for assigning layouts to newly-created files will apply.
 *
 * \retval 0+ An open file descriptor.
 * \retval -1 Error with status code in errno.
 */
int llapi_layout_file_open(const char *path, int open_flags, mode_t mode,
			   const struct llapi_layout *layout);

/**
 * Create a new file at \a path with the specified \a layout and \a mode.
 *
 * One access mode and zero or more file creation flags and file status
 * flags May be bitwise-or'd in \a open_flags (see open(2)).  Return an
 * open file descriptor for the file.  If \a layout is non-NULL and
 * \a path is not on a Lustre filesystem this function will fail and set
 * errno to ENOTTY.
 *
 * The function call
 *
 *   llapi_layout_file_create(path, open_flags, mode, layout)
 *
 * shall be equivalent to:
 *
 *   llapi_layout_file_open(path, open_flags|O_CREAT|O_EXCL, mode, layout)
 *
 * It is an error if \a path specifies an existing file.
 *
 * A NULL \a layout may be specified, in which the standard Lustre
 * behavior for assigning layouts to newly-created files will apply.
 *
 * \retval 0+ An open file descriptor.
 * \retval -1 Error with status code in errno.
 */
int llapi_layout_file_create(const char *path, int open_flags, int mode,
			     const struct llapi_layout *layout);

/**
 * Fetch the start and end offset of the current layout component.
 */
int llapi_layout_comp_extent_get(const struct llapi_layout *layout,
				 uint64_t *start, uint64_t *end);
/**
 * Set the extent of current layout component.
 */
int llapi_layout_comp_extent_set(struct llapi_layout *layout,
				 uint64_t start, uint64_t end);

/* PFL component flags table */
static const struct comp_flag_name {
	enum lov_comp_md_entry_flags cfn_flag;
	const char *cfn_name;
} comp_flags_table[] = {
	{ LCME_FL_INIT,		"init" },
	/* For now, only "init" is supported
	{ LCME_FL_PRIMARY,	"primary" },
	{ LCME_FL_STALE,	"stale" },
	{ LCME_FL_OFFLINE,	"offline" },
	{ LCME_FL_PREFERRED,	"preferred" }
	*/
};

/**
 * Gets the attribute flags of the current component.
 */
int llapi_layout_comp_flags_get(const struct llapi_layout *layout,
				uint32_t *flags);
/**
 * Sets the specified flags of the current component leaving other flags as-is.
 */
int llapi_layout_comp_flags_set(struct llapi_layout *layout, uint32_t flags);
/**
 * Clears the flags specified in the flags leaving other flags as-is.
 */
int llapi_layout_comp_flags_clear(struct llapi_layout *layout, uint32_t flags);
/**
 * Fetches the file-unique component ID of the current layout component.
 */
int llapi_layout_comp_id_get(const struct llapi_layout *layout, uint32_t *id);
/**
 * Adds one component to the existing composite or plain layout.
 */
int llapi_layout_comp_add(struct llapi_layout *layout);
/**
 * Deletes the current layout component from the composite layout.
 */
int llapi_layout_comp_del(struct llapi_layout *layout);

enum llapi_layout_comp_use {
	LLAPI_LAYOUT_COMP_USE_FIRST = 1,
	LLAPI_LAYOUT_COMP_USE_LAST = 2,
	LLAPI_LAYOUT_COMP_USE_NEXT = 3,
	LLAPI_LAYOUT_COMP_USE_PREV = 4,
};

/**
 * Set the currently active component to the specified component ID.
 */
int llapi_layout_comp_use_id(struct llapi_layout *layout, uint32_t id);
/**
 * Select the currently active component at the specified position.
 */
int llapi_layout_comp_use(struct llapi_layout *layout, uint32_t pos);
/**
 * Add layout components to an existing file.
 */
int llapi_layout_file_comp_add(const char *path,
			       const struct llapi_layout *layout);
/**
 * Delete component(s) by the specified component id or flags.
 */
int llapi_layout_file_comp_del(const char *path, uint32_t id, uint32_t flags);
/**
 * Change flags or other parameters of the component(s) by component ID of an
 * existing file. The component to be modified is specified by the
 * comp->lcme_id value, which must be an unique component ID. The new
 * attributes are passed in by @comp and @valid is used to specify which
 * attributes in the component are going to be changed.
 */
int llapi_layout_file_comp_set(const char *path,
			       const struct llapi_layout *comp,
			       uint32_t valid);

/** @} llapi */

#endif
