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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _MOUNT_UTILS_H_
#define _MOUNT_UTILS_H_

/* Some of the userland headers for libzfs also require
 * zfs/spl linux kernel headers, but including these pull
 * in linux kernel headers which conflicts with the
 * userland version of libcfs. So the solution is tell the
 * libzfs user land headrs that the zfs/spl kernel headers
 * are already included even if this is not the case.
 */
#ifdef HAVE_ZFS_OSD
#define _SPL_ZFS_H
#define _SPL_SIGNAL_H
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libcfs/util/list.h>
#include <linux/lustre_disk.h>
#include <linux/lustre_param.h>

extern char *progname;
extern int verbose;
extern int failover;

#define vprint(fmt, arg...) if (verbose > 0) printf(fmt, ##arg)
#define verrprint(fmt, arg...) if (verbose >= 0) fprintf(stderr, fmt, ##arg)

/* mo_flags */
#define MO_IS_LOOP		0x01
#define MO_FORCEFORMAT		0x02
#define MO_FAILOVER		0x04
#define MO_DRYRUN		0x08
#define MO_QUOTA		0x10
#define MO_NOHOSTID_CHECK	0x20
#define MO_RENAME		0x40
#define MO_ERASE_ALL		0x80

#define MAX_LOOP_DEVICES	16
#define INDEX_UNASSIGNED	0xFFFF

/* Maximum length of on-disk parameters in the form key=<value> */
#define PARAM_MAX		4096

/* used to describe the options to format the lustre disk, not persistent */
struct mkfs_opts {
	struct lustre_disk_data	mo_ldd; /* to be written in MOUNT_DATA_FILE */
	char	mo_device[128];   /* disk device name */
	char	**mo_pool_vdevs;  /* list of pool vdevs */
	char	mo_loopdev[128];  /* in case a loop dev is needed */
	char	mo_mkfsopts[512]; /* options to the backing-store mkfs */
	char	*mo_mountopts;    /* mount options for backing fs */
	__u64	mo_device_kb;     /* in KB */
	int	mo_stripe_count;
	int	mo_flags;
	int	mo_mgs_failnodes;
};

/* used to describe the options to mount the lustre disk */
struct mount_opts {
	struct lustre_disk_data	 mo_ldd;
	char	*mo_orig_options;
	char	*mo_usource;		/* user-specified mount device */
	char	*mo_source;		/* our mount device name */
	char	 mo_target[PATH_MAX];	/* mount directory */
#ifdef HAVE_GSS
	char	 mo_skpath[PATH_MAX];	/* shared key file/directory */
#endif
	int	 mo_nomtab;
	int	 mo_fake;
	int	 mo_force;
	int	 mo_retry;
	int	 mo_have_mgsnid;
	int	 mo_md_stripe_cache_size;
	int	 mo_nosvc;
	int	 mo_max_sectors_kb;
};

int get_mountdata(char *, struct lustre_disk_data *);

static inline char *mt_str(enum ldd_mount_type mt)
{
	static char *mount_type_string[] = {
		"ext3",
		"ldiskfs",
		"smfs",
		"reiserfs",
		"ldiskfs2",
		"zfs",
	};
	return mount_type_string[mt];
}

static inline char *mt_type(enum ldd_mount_type mt)
{
	static char *mount_type_string[] = {
		"osd-ldiskfs",
		"osd-ldiskfs",
		"osd-smfs",
		"osd-reiserfs",
		"osd-ldiskfs",
		"osd-zfs",
	};
	return mount_type_string[mt];
}

#define MT_STR(data)   mt_str((data)->ldd_mount_type)

#define IS_MDT(data)   ((data)->ldd_flags & LDD_F_SV_TYPE_MDT)
#define IS_OST(data)   ((data)->ldd_flags & LDD_F_SV_TYPE_OST)
#define IS_MGS(data)  ((data)->ldd_flags & LDD_F_SV_TYPE_MGS)
#define IS_SEPARATED_MGS(data)	((data)->ldd_flags == LDD_F_SV_TYPE_MGS)
#define IS_SERVER(data) ((data)->ldd_flags & (LDD_F_SV_TYPE_MGS | \
			  LDD_F_SV_TYPE_MDT | LDD_F_SV_TYPE_OST))


/* mkfs/mount helper functions */
void fatal(void);
int run_command_err(char *cmd, int cmdsz, char *error_msg);
int run_command(char *cmd, int cmdsz);
int add_param(char *buf, char *key, char *val);
int append_param(char *buf, char *key, char *val, char sep);
int get_param(char *buf, char *key, char **val);
char *strscat(char *dst, char *src, int buflen);
char *strscpy(char *dst, char *src, int buflen);
int check_mtab_entry(char *spec1, char *spec2, char *mntpt, char *type);
int update_mtab_entry(char *spec, char *mtpt, char *type, char *opts,
		      int flags, int freq, int pass);
int update_utab_entry(struct mount_opts *mop);
int check_mountfsoptions(char *mountopts, char *wanted_mountopts);
void trim_mountfsoptions(char *s);
__u64 get_device_size(char* device);
int lustre_rename_fsname(struct mkfs_opts *mop, const char *mntpt,
			 const char *oldname);

/* loopback helper functions */
int file_create(char *path, __u64 size);
int loop_format(struct mkfs_opts *mop);
int loop_setup(struct mkfs_opts *mop);
int loop_cleanup(struct mkfs_opts *mop);

/* generic target support */
int osd_write_ldd(struct mkfs_opts *mop);
int osd_read_ldd(char *dev, struct lustre_disk_data *ldd);
int osd_erase_ldd(struct mkfs_opts *mop, char *param);
void osd_print_ldd_params(struct mkfs_opts *mop);
int osd_is_lustre(char *dev, unsigned *mount_type);
int osd_make_lustre(struct mkfs_opts *mop);
int osd_prepare_lustre(struct mkfs_opts *mop,
		       char *wanted_mountopts, size_t len);
int osd_fix_mountopts(struct mkfs_opts *mop, char *mountopts, size_t len);
int osd_tune_lustre(char *dev, struct mount_opts *mop);
int osd_label_lustre(struct mount_opts *mop);
int osd_rename_fsname(struct mkfs_opts *mop, const char *oldname);
int osd_enable_quota(struct mkfs_opts *mop);
int osd_init(void);
void osd_fini(void);

struct module_backfs_ops {
	int	(*init)(void);
	void	(*fini)(void);
	int	(*read_ldd)(char *ds,  struct lustre_disk_data *ldd);
	int	(*write_ldd)(struct mkfs_opts *mop);
	int	(*erase_ldd)(struct mkfs_opts *mop, char *param);
	void	(*print_ldd_params)(struct mkfs_opts *mop);
	int	(*is_lustre)(char *dev, enum ldd_mount_type *mount_type);
	int	(*make_lustre)(struct mkfs_opts *mop);
	int	(*prepare_lustre)(struct mkfs_opts *mop,
				  char *wanted_mountopts, size_t len);
	int	(*fix_mountopts)(struct mkfs_opts *mop,
				 char *mountopts, size_t len);
	int	(*tune_lustre)(char *dev, struct mount_opts *mop);
	int	(*label_lustre)(struct mount_opts *mop);
	int	(*enable_quota)(struct mkfs_opts *mop);
	int	(*rename_fsname)(struct mkfs_opts *mop, const char *oldname);
	void   *dl_handle;
};

struct module_backfs_ops *load_backfs_module(enum ldd_mount_type mount_type);
void unload_backfs_ops(struct module_backfs_ops *ops);
#ifdef HAVE_OPENSSL_SSK
int load_shared_keys(struct mount_opts *mop);
#else
static inline int load_shared_keys(struct mount_opts *mop)
{
	return EOPNOTSUPP;
}
#endif
#endif
