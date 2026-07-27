// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/mount_utils_ldiskfs.c
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
*/

/* This source file is compiled into both mkfs.lustre and tunefs.lustre */

#if HAVE_CONFIG_H
#  include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <mntent.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>

#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <ctype.h>

#include <ext2fs/ext2fs.h>
#include <ext2fs/quotaio.h>

#ifndef BLKGETSIZE64
#include <linux/fs.h> /* for BLKGETSIZE64 */
#endif
#include <linux/major.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/lnet/lnetctl.h>
#include <linux/lustre/lustre_ver.h>
#include <libcfs/util/string.h>

#include "mount_utils.h"

#define MAX_HW_SECTORS_KB_PATH	"queue/max_hw_sectors_kb"
#define SCHEDULER_PATH		"queue/scheduler"
#define STRIPE_CACHE_SIZE	"md/stripe_cache_size"

#define DEFAULT_SCHEDULER	"deadline"
#define DEF_BULK_RPC_SIZE	(4U << 20) /* DT_DEF_BRW_SIZE */
#define MAX_BULK_RPC_SIZE	(64U << 20) /* DT_MAX_BRW_SIZE */

extern char *progname;

static ext2_filsys backfs;
static int open_flags_ro = EXT2_FLAG_64BITS | EXT2_FLAG_SKIP_MMP |
			   EXT2_FLAG_IGNORE_SB_ERRORS | EXT2_FLAG_SUPER_ONLY;
static int open_flags_rw = EXT2_FLAG_RW | EXT2_FLAG_64BITS;

/* keep it less than LL_FID_NAMELEN */
#define DUMMY_FILE_NAME_LEN             25
#define EXT3_DIRENT_SIZE                DUMMY_FILE_NAME_LEN

static void append_unique(char *buf, char *prefix, char *key, char *val,
			  size_t maxbuflen);
static bool is_e2fsprogs_feature_supp(const char *feature);
static int read_file(const char *path, char *buf, int size);

/* Determine if a device is a block device (as opposed to a file) */
static int is_block(char *devname)
{
	struct stat st;
	int	ret = 0;
	char	*devpath;

	ret = cfs_abs_path(devname, &devpath);
	if (ret != 0) {
		fprintf(stderr, "%s: failed to resolve path '%s': %s\n",
			progname, devname, strerror(-ret));
		return -1;
	}

	ret = access(devname, F_OK);
	if (ret != 0) {
		if (strncmp(devpath, "/dev/", 5) == 0) {
			/* nobody sane wants to create a loopback file under
			 * /dev. Let's just report the device doesn't exist */
			fprintf(stderr, "%s: %s apparently does not exist\n",
				progname, devpath);
			ret = -1;
			goto out;
		}
		ret = 0;
		goto out;
	}
	ret = stat(devpath, &st);
	if (ret != 0) {
		fprintf(stderr, "%s: cannot stat %s\n", progname, devpath);
		goto out;
	}
	ret = S_ISBLK(st.st_mode);
out:
	free(devpath);
	return ret;
}

static int translate_error(errcode_t err)
{
	int ret = err;

	/* Translate ext2 error to unix error code */
	if (err < EXT2_ET_BASE)
		return ret;
	switch (err) {
	case EXT2_ET_NO_MEMORY:
	case EXT2_ET_TDB_ERR_OOM:
		ret = ENOMEM;
		break;
	case EXT2_ET_INVALID_ARGUMENT:
	case EXT2_ET_LLSEEK_FAILED:
		ret = EINVAL;
		break;
	case EXT2_ET_NO_DIRECTORY:
		ret = ENOTDIR;
		break;
	case EXT2_ET_FILE_NOT_FOUND:
		ret = ENOENT;
		break;
	case EXT2_ET_DIR_NO_SPACE:
	case EXT2_ET_TOOSMALL:
	case EXT2_ET_BLOCK_ALLOC_FAIL:
	case EXT2_ET_INODE_ALLOC_FAIL:
	case EXT2_ET_EA_NO_SPACE:
		ret = ENOSPC;
		break;
	case EXT2_ET_SYMLINK_LOOP:
		ret = EMLINK;
		break;
	case EXT2_ET_FILE_TOO_BIG:
		ret = EFBIG;
		break;
	case EXT2_ET_TDB_ERR_EXISTS:
	case EXT2_ET_FILE_EXISTS:
		ret = EEXIST;
		break;
	case EXT2_ET_MMP_FAILED:
	case EXT2_ET_MMP_FSCK_ON:
		ret = EBUSY;
		break;
	case EXT2_ET_EA_KEY_NOT_FOUND:
		ret = ENOENT;
		break;
	case EXT2_ET_MAGIC_EXT2_FILE:
		ret = EFAULT;
		break;
	case EXT2_ET_UNIMPLEMENTED:
		ret = EOPNOTSUPP;
		break;
	case EXT2_ET_MAGIC_EXT2FS_FILSYS:
	case EXT2_ET_MAGIC_BADBLOCKS_LIST:
	case EXT2_ET_MAGIC_BADBLOCKS_ITERATE:
	case EXT2_ET_MAGIC_INODE_SCAN:
	case EXT2_ET_MAGIC_IO_CHANNEL:
	case EXT2_ET_MAGIC_UNIX_IO_CHANNEL:
	case EXT2_ET_MAGIC_IO_MANAGER:
	case EXT2_ET_MAGIC_BLOCK_BITMAP:
	case EXT2_ET_MAGIC_INODE_BITMAP:
	case EXT2_ET_MAGIC_GENERIC_BITMAP:
	case EXT2_ET_MAGIC_TEST_IO_CHANNEL:
	case EXT2_ET_MAGIC_DBLIST:
	case EXT2_ET_MAGIC_ICOUNT:
	case EXT2_ET_MAGIC_PQ_IO_CHANNEL:
	case EXT2_ET_MAGIC_E2IMAGE:
	case EXT2_ET_MAGIC_INODE_IO_CHANNEL:
	case EXT2_ET_MAGIC_EXTENT_HANDLE:
	case EXT2_ET_BAD_MAGIC:
	case EXT2_ET_MAGIC_EXTENT_PATH:
	case EXT2_ET_MAGIC_GENERIC_BITMAP64:
	case EXT2_ET_MAGIC_BLOCK_BITMAP64:
	case EXT2_ET_MAGIC_INODE_BITMAP64:
	case EXT2_ET_MAGIC_RESERVED_13:
	case EXT2_ET_MAGIC_RESERVED_14:
	case EXT2_ET_MAGIC_RESERVED_15:
	case EXT2_ET_MAGIC_RESERVED_16:
	case EXT2_ET_MAGIC_RESERVED_17:
	case EXT2_ET_MAGIC_RESERVED_18:
	case EXT2_ET_MAGIC_RESERVED_19:
	case EXT2_ET_MMP_MAGIC_INVALID:
	case EXT2_ET_MAGIC_EA_HANDLE:
	case EXT2_ET_DIR_CORRUPTED:
	case EXT2_ET_CORRUPT_SUPERBLOCK:
	case EXT2_ET_RESIZE_INODE_CORRUPT:
	case EXT2_ET_TDB_ERR_CORRUPT:
	case EXT2_ET_UNDO_FILE_CORRUPT:
	case EXT2_ET_FILESYSTEM_CORRUPTED:
	case EXT2_ET_CORRUPT_JOURNAL_SB:
	case EXT2_ET_INODE_CORRUPTED:
	case EXT2_ET_EA_INODE_CORRUPTED:
		ret = EUCLEAN;
		break;
	default:
		ret = EIO;
		break;
	}

	return ret;
}


static errcode_t open_backfs_rw(char *dev, int flags, int force)
{
	errcode_t retval;

	if (backfs && !(backfs->flags & EXT2_FLAG_RW))
		ext2fs_close_free(&backfs);

	if (!backfs) {
		retval = ext2fs_open(dev, open_flags_rw | flags,
				     0, 0, unix_io_manager, &backfs);
		if (retval) {
			fprintf(stderr,
				"Error while trying to open %s\n", dev);
			return retval;
		}

		if (((backfs->super->s_state & EXT2_ERROR_FS) ||
		     !(backfs->super->s_state & EXT2_VALID_FS) ||
		     ext2fs_has_feature_journal_needs_recovery(backfs->super)) &&
		    !force) {
			fprintf(stderr,
				"Filesystem is not clean, please run e2fsck\n");
			ext2fs_close_free(&backfs);
			return EXT2_ET_FILESYSTEM_CORRUPTED;
		}
	}

	return 0;
}

static errcode_t write_quota_inodes(ext2_filsys fs, unsigned int qtype_bits)
{
	errcode_t retval;
	quota_ctx_t qctx;

	retval = quota_init_context(&qctx, fs, qtype_bits);
	if (retval) {
		fprintf(stderr, "Error while initializing quota context\n");
		return retval;
	}
	quota_compute_usage(qctx);
	retval = quota_write_inode(qctx, QUOTA_ALL_BIT);
	if (retval) {
		fprintf(stderr, "Error while writing quota inodes\n");
		return retval;
	}
	quota_release_context(&qctx);

	return 0;
}

/* Write the server config files */
int ldiskfs_write_ldd(struct mkfs_opts *mop)
{
	errcode_t retval;
	ext2_ino_t configs_ino, mountdata_ino;
	ext2_file_t mountdata_file;
	struct ext2_inode inode;
	unsigned int written;
	char *dev;

	dev = mop->mo_device;
	if (mop->mo_flags & MO_IS_LOOP)
		dev = mop->mo_loopdev;

	retval = open_backfs_rw(dev, 0, 0);
	if (retval)
		return translate_error(retval);
	retval = ext2fs_read_bitmaps(backfs);
	if (retval)
		return translate_error(retval);

	/*
	 * Multiple mount protection enabled if explicitly requested with
	 * --mmp, or if a failover node is specified and not explicitly
	 * disabled with --nommp option. Explicitly disabling it with
	 * --nommp removes MMP from a target that already has it.
	 */
	if (((mop->mo_flags & MO_MMP) ||
	     ((mop->mo_flags & MO_FAILOVER) && !(mop->mo_flags & MO_NOMMP))) &&
	    !ext2fs_has_feature_mmp(backfs->super)) {
		retval = ext2fs_mmp_init(backfs);
		if (!retval) {
			ext2fs_set_feature_mmp(backfs->super);
			ext2fs_mark_super_dirty(backfs);
			ext2fs_flush(backfs);
		} else
			fprintf(stderr,
				"Error enabling multi-mount protection\n");
	} else if ((mop->mo_flags & MO_NOMMP) &&
		   ext2fs_has_feature_mmp(backfs->super)) {
		retval = ext2fs_mmp_read(backfs, backfs->super->s_mmp_block,
					 NULL);
		if (!retval) {
			backfs->flags &= ~EXT2_FLAG_SUPER_ONLY;
			ext2fs_block_alloc_stats2(backfs,
						  backfs->super->s_mmp_block,
						  -1);
		} else
			fprintf(stderr,
				"Error reading MMP block, disabling anyway\n");
		backfs->super->s_mmp_block = 0;
		backfs->super->s_mmp_update_interval = 0;
		ext2fs_clear_feature_mmp(backfs->super);
		ext2fs_mark_super_dirty(backfs);
		ext2fs_flush(backfs);
	}

	retval = ext2fs_namei(backfs, EXT2_ROOT_INO, EXT2_ROOT_INO,
			      MOUNT_CONFIGS_DIR, &configs_ino);
	if (retval) {
		if (retval != EXT2_ET_FILE_NOT_FOUND)
			return translate_error(retval);
		retval = ext2fs_new_inode(backfs, EXT2_ROOT_INO,
					  LINUX_S_IFDIR | 0777,
					  NULL, &configs_ino);
		if (retval)
			return translate_error(retval);
		retval = ext2fs_mkdir(backfs, EXT2_ROOT_INO, configs_ino,
				      MOUNT_CONFIGS_DIR);
		if (retval == EXT2_ET_DIR_NO_SPACE) {
			retval = ext2fs_expand_dir(backfs, EXT2_ROOT_INO);
			if (retval)
				return translate_error(retval);
			retval = ext2fs_mkdir(backfs, EXT2_ROOT_INO,
					      configs_ino,
					      MOUNT_CONFIGS_DIR);
		}
		if (retval) {
			fprintf(stderr, "Error creating config dir '%s'\n",
				MOUNT_CONFIGS_DIR);
			return translate_error(retval);
		}
	}
	retval = ext2fs_namei(backfs, EXT2_ROOT_INO, configs_ino,
			      CONFIGS_FILE, &mountdata_ino);
	if (retval) {
		if (retval != EXT2_ET_FILE_NOT_FOUND)
			return translate_error(retval);
		retval = ext2fs_new_inode(backfs, configs_ino, LINUX_S_IFREG |
					  0644, NULL, &mountdata_ino);
		if (retval)
			return translate_error(retval);
		retval = ext2fs_link(backfs, configs_ino, CONFIGS_FILE,
				     mountdata_ino, EXT2_FT_REG_FILE);
		if (retval == EXT2_ET_DIR_NO_SPACE) {
			retval = ext2fs_expand_dir(backfs, configs_ino);
			if (retval)
				return translate_error(retval);
			retval = ext2fs_link(backfs, configs_ino, CONFIGS_FILE,
					     mountdata_ino, EXT2_FT_REG_FILE);
		}
		if (retval) {
			fprintf(stderr, "Error while creating file %s\n",
				CONFIGS_FILE);
			return translate_error(retval);
		}
		ext2fs_inode_alloc_stats2(backfs, mountdata_ino, 1, 0);
		memset(&inode, 0, sizeof(inode));
		inode.i_mode = LINUX_S_IFREG | 0644;
		inode.i_atime = inode.i_ctime = inode.i_mtime =
			backfs->now ? backfs->now : time(0);
		inode.i_links_count = 1;
		if (ext2fs_has_feature_inline_data(backfs->super)) {
			inode.i_flags |= EXT4_INLINE_DATA_FL;
		} else if (ext2fs_has_feature_extents(backfs->super)) {
			ext2_extent_handle_t handle;

			inode.i_flags &= ~EXT4_EXTENTS_FL;
			retval = ext2fs_extent_open2(backfs, mountdata_ino,
						     &inode, &handle);
			if (retval)
				return translate_error(retval);
			ext2fs_extent_free(handle);
		}

		retval = ext2fs_write_new_inode(backfs, mountdata_ino, &inode);
		if (retval)
			return translate_error(retval);
		if (inode.i_flags & EXT4_INLINE_DATA_FL) {
			retval = ext2fs_inline_data_init(backfs,
							 mountdata_ino);
			if (retval)
				return translate_error(retval);
		}
	}
	retval = ext2fs_file_open(backfs, mountdata_ino,
				  EXT2_FILE_WRITE, &mountdata_file);
	if (retval)
		return translate_error(retval);
	retval = ext2fs_file_write(mountdata_file, &mop->mo_ldd,
				   sizeof(mop->mo_ldd), &written);
	ext2fs_file_close(mountdata_file);
	if (retval || written == 0) {
		fprintf(stderr, "Error while writing to file %s\n",
			MOUNT_DATA_FILE);
		if (!retval)
			retval = EXT2_ET_SHORT_WRITE;
		return translate_error(retval);
	}

	if (ext2fs_has_feature_quota(backfs->super)) {
		retval = write_quota_inodes(backfs, 0);
		if (retval)
			return translate_error(retval);
	}
	/* close the fs to write bitmaps, before the first mount happens */
	ext2fs_close_free(&backfs);

	return 0;
}

int ldiskfs_read_ldd(char *dev, struct lustre_disk_data *mo_ldd)
{
	errcode_t retval;
	ext2_ino_t ino;
	ext2_file_t file;
	unsigned int got;

	if (!backfs) {
		retval = ext2fs_open(dev, open_flags_ro, 0, 0,
				     unix_io_manager, &backfs);
		if (retval) {
			fprintf(stderr, "Unable to open fs on %s\n", dev);
			return translate_error(retval);
		}
	}
	retval = ext2fs_namei(backfs, EXT2_ROOT_INO, EXT2_ROOT_INO,
			      MOUNT_DATA_FILE, &ino);
	if (retval) {
		fprintf(stderr, "Error while looking up %s\n", MOUNT_DATA_FILE);
		goto read_label;
	}
	retval = ext2fs_file_open(backfs, ino, 0, &file);
	if (retval) {
		fprintf(stderr, "Error while opening file %s\n",
			MOUNT_DATA_FILE);
		goto read_label;
	}
	retval = ext2fs_file_read(file, mo_ldd, sizeof(*mo_ldd), &got);
	ext2fs_file_close(file);
	if (retval || got == 0)
		fprintf(stderr, "Failed to read file %s\n", MOUNT_DATA_FILE);
read_label:
	/* As long as we at least have the label, we're good to go */
	memset(mo_ldd->ldd_svname, 0, sizeof(mo_ldd->ldd_svname));
	strncpy(mo_ldd->ldd_svname, (char *)backfs->super->s_volume_name,
		EXT2_LABEL_LEN);

	return 0;
}

int ldiskfs_erase_ldd(struct mkfs_opts *mop, char *param)
{
	return 0;
}

void ldiskfs_print_ldd_params(struct mkfs_opts *mop)
{
	printf("Parameters:%s\n", mop->mo_ldd.ldd_params);
}

/* Check whether the file exists in the device */
static int file_in_dev(char *file_name, char *dev_name)
{
	ext2_ino_t ino;
	errcode_t retval;

	if (!backfs) {
		retval = ext2fs_open(dev_name, open_flags_ro, 0, 0,
				     unix_io_manager, &backfs);
		if (retval)
			return 0;
	}
	retval = ext2fs_namei(backfs, EXT2_ROOT_INO, EXT2_ROOT_INO,
			      file_name, &ino);
	if (!retval)
		return 1;

	return 0;
}

/* Check whether the device has already been used with lustre */
int ldiskfs_is_lustre(char *dev, unsigned *mount_type)
{
	int ret;

	ret = file_in_dev(MOUNT_DATA_FILE, dev);
	if (ret) {
		*mount_type = LDD_MT_LDISKFS;
		return 1;
	}

	ret = file_in_dev(LAST_RCVD, dev);
	if (ret) {
		*mount_type = LDD_MT_LDISKFS;
		return 1;
	}

	return 0;
}

/* Check if a certain feature is supported by e2fsprogs.
 * Firstly we try to use "debugfs supported_features" command to check if
 * the feature is supported. If this fails we try to set this feature with
 * mke2fs to check for its support. */
static bool is_e2fsprogs_feature_supp(const char *feature)
{
	static char supp_features[4096] = "";
	FILE *fp;
	char cmd[PATH_MAX];
	char imgname[] = "/tmp/test-img-XXXXXX";
	int fd;
	int ret;

	if (supp_features[0] == '\0') {
		snprintf(cmd, sizeof(cmd), "%s -c -R supported_features 2>&1",
			 DEBUGFS);

		/* Using popen() instead of run_command() since debugfs does
		 * not return proper error code if command is not supported */
		fp = popen(cmd, "r");
		if (!fp) {
			fprintf(stderr, "%s: %s\n", progname, strerror(errno));
		} else {
			ret = fread(supp_features, 1,
				    sizeof(supp_features) - 1, fp);
			supp_features[ret] = '\0';
			pclose(fp);
		}
	}

	if (strstr(supp_features,
		   strncmp(feature, "-O ", 3) ? feature : feature + 3))
		return true;

	fd = mkstemp(imgname);
	if (fd < 0)
		return false;

	close(fd);

	snprintf(cmd, sizeof(cmd), "%s -F %s %s 200 >/dev/null 2>&1",
		 MKE2FS, feature, imgname);
	/* run_command() displays the output of mke2fs when it fails for
	 * some feature, so use system() directly */
	ret = system(cmd);
	unlink(imgname);

	return ret == 0;
}

/**
 * append_unique() -  append @key or @key=@val pair to @buf only if @key does
 *                    not exists
 * @buf: buffer to hold @key or @key=@val
 * @prefix: prefix string before @key
 * @key: key string
 * @val: value string if it's a @key=@val pair
 * @maxbuflen: max len of @buf
 */
static void append_unique(char *buf, char *prefix, char *key, char *val,
			  size_t maxbuflen)
{
	char *anchor, *end;
	int  len;

	if (key == NULL)
		return;

	anchor = end = strstr(buf, key);
	/* try to find exact match string in @buf */
	while (end && *end != '\0' && *end != ',' && *end != ' ' && *end != '=')
		++end;
	len = end - anchor;
	if (anchor == NULL || strlen(key) != len ||
			strncmp(anchor, key, len) != 0) {
		if (prefix != NULL)
			strscat(buf, prefix, maxbuflen);

		strscat(buf, key, maxbuflen);
		if (val != NULL) {
			strscat(buf, "=\"", maxbuflen);
			strscat(buf, val, maxbuflen);
			strscat(buf, "\"", maxbuflen);
		}
	}
}

static int enable_default_ext4_features(struct mkfs_opts *mop, char *anchor,
					size_t maxbuflen, bool user_spec)
{
	unsigned long long blocks = mop->mo_device_kb / mop->mo_blocksize_kb;
	bool enable_64bit = false;

	/* Enable large block addresses if the LUN is over 2^32 blocks. */
	if (blocks > 0xffffffffULL && is_e2fsprogs_feature_supp("-O 64bit"))
		enable_64bit = true;

	append_unique(anchor, user_spec ? "," : " -O ",
		      "uninit_bg", NULL, maxbuflen);
	append_unique(anchor, ",", "extents", NULL, maxbuflen);

	if (IS_MDT(&mop->mo_ldd))
		append_unique(anchor, ",", "dirdata", NULL, maxbuflen);

	/* Multimount protection enabled if failover node or --mmp given */
	if ((mop->mo_flags & MO_MMP) ||
	    ((mop->mo_flags & MO_FAILOVER) && !(mop->mo_flags & MO_NOMMP)))
		append_unique(anchor, ",", "mmp", NULL, maxbuflen);

	/* Allow more than 65000 subdirectories */
	if (is_e2fsprogs_feature_supp("-O dir_nlink"))
		append_unique(anchor, ",", "dir_nlink", NULL, maxbuflen);

	/* Enable quota by default */
	if (is_e2fsprogs_feature_supp("-O quota")) {
		append_unique(anchor, ",", "quota", NULL, maxbuflen);
		/* Enable project quota by default */
		if (is_e2fsprogs_feature_supp("-O project"))
			append_unique(anchor, ",", "project", NULL, maxbuflen);
	} else {
		fatal();
		fprintf(stderr, "\"-O quota\" must be supported by "
			"e2fsprogs, please upgrade your e2fsprogs.\n");
		return EINVAL;
	}

	/* Allow files larger than 2TB */
	if (is_e2fsprogs_feature_supp("-O huge_file"))
		append_unique(anchor, ",", "huge_file", NULL, maxbuflen);

	if (enable_64bit) {
		append_unique(anchor, ",", "64bit", NULL, maxbuflen);
		append_unique(anchor, ",", "^resize_inode", NULL, maxbuflen);
	}

	/* Allow xattrs larger than one block, stored in a separate inode */
	if (IS_MDT(&mop->mo_ldd) && is_e2fsprogs_feature_supp("-O ea_inode"))
		append_unique(anchor, ",", "ea_inode", NULL, maxbuflen);

	/* Allow more than 10M entries in a single directory */
	if (is_e2fsprogs_feature_supp("-O large_dir"))
		append_unique(anchor, ",", "large_dir", NULL, maxbuflen);

	/* Disable fast_commit since it breaks ldiskfs transactions ordering */
	if (is_e2fsprogs_feature_supp("fast_commit"))
		append_unique(anchor, ",", "^fast_commit", NULL, maxbuflen);

	/* Cluster inode/block bitmaps and inode table for more efficient IO.
	 * Align the flex groups on a 1MB boundary for better performance. */
	/* This -O feature needs to go last, since it adds the "-G" option. */
	if (is_e2fsprogs_feature_supp("-O flex_bg")) {
		char tmp_buf[64];

		append_unique(anchor, ",", "flex_bg", NULL, maxbuflen);

		if (IS_OST(&mop->mo_ldd) &&
		    strstr(mop->mo_mkfsopts, "-G") == NULL) {
			snprintf(tmp_buf, sizeof(tmp_buf), " -G %u",
				 1024 / mop->mo_blocksize_kb);
			strscat(anchor, tmp_buf, maxbuflen);
		}
	}
	/* Don't add any more "-O" options here, see last comment above */
	return 0;
}

/**
 * moveopts_to_end() -  find the option string, move remaining strings to
 *                      where option string starts, and append the option
 *                      string at the end
 * @start: where the option string starts before the move
 *
 * Return the option string starts after the move
 */
static char *moveopts_to_end(char *start)
{
	size_t len;
	char save[512];
	char *end, *idx;

	/* skip whitespace before options */
	end = start + 2;
	while (*end == ' ')
		++end;

	/* find end of option characters */
	while (*end != ' ' && *end != '\0')
		++end;

	len = end - start;
	if (len >= sizeof(save))
		len = sizeof(save) - 1;

	/* save options */
	strncpy(save, start, len);
	save[len] = '\0';

	/* move remaining options up front */
	if (*end)
		memmove(start, end, strlen(end));
	*(start + strlen(end)) = '\0';

	/* append the specified options */
	if (*(start + strlen(start) - 1) != ' ')
		strcat(start, " ");
	idx = start + strlen(start);
	strcat(start, save);

	return idx;
}

struct md_geometry {
	unsigned long	mg_chunk_bytes;
	unsigned int	mg_data_disks;
	bool		mg_parity;	/* partial-row writes are RMW */
};

/* raidkm (md level 71) encodes its geometry in the md layout word (keep in
 * sync with md-kmec km/raid_km.h): bits 0-7 parity count m; bit 10
 * declustered flag; bits 16-23 declustered group width g, where the data
 * cells per row k = g - m.  Non-declustered arrays have k = raid_disks - m.
 */
#define RAIDKM_LAYOUT_M_MASK	0x00ff
#define RAIDKM_LAYOUT_DCL	0x0400
#define RAIDKM_LAYOUT_DCL_G(l)	(((l) >> 16) & 0xff)

/* raid10 encodes its replication factor in the md layout word; bits 0-7 are
 * the near copy count.  Far copies replicate into another region of the same
 * devices rather than widening the row, so a row spans raid_disks / near
 * devices -- the same width md itself reports as io_opt.
 */
#define RAID10_LAYOUT_NEAR(l)	((l) & 0xff)

static int md_read_geometry(const char *sys_path, struct md_geometry *geom)
{
	char path[PATH_MAX + 32];
	char level[64];
	char buf[64];
	long raid_disks;
	long data_disks;
	unsigned long chunk;
	int rc;

	snprintf(path, sizeof(path), "%s/md/level", sys_path);
	rc = read_file(path, level, sizeof(level));
	if (rc != 0)
		return -rc;

	snprintf(path, sizeof(path), "%s/md/raid_disks", sys_path);
	rc = read_file(path, buf, sizeof(buf));
	if (rc != 0)
		return -rc;
	raid_disks = strtol(buf, NULL, 0);

	snprintf(path, sizeof(path), "%s/md/chunk_size", sys_path);
	rc = read_file(path, buf, sizeof(buf));
	if (rc != 0)
		return -rc;
	chunk = strtoul(buf, NULL, 0);

	geom->mg_parity = true;
	if (strcmp(level, "raid0") == 0) {
		data_disks = raid_disks;
		geom->mg_parity = false;
	} else if (strcmp(level, "raid4") == 0 || strcmp(level, "raid5") == 0) {
		data_disks = raid_disks - 1;
	} else if (strcmp(level, "raid6") == 0) {
		data_disks = raid_disks - 2;
	} else if (strcmp(level, "raid10") == 0) {
		long layout, near;

		snprintf(path, sizeof(path), "%s/md/layout", sys_path);
		rc = read_file(path, buf, sizeof(buf));
		if (rc != 0)
			return -rc;
		layout = strtol(buf, NULL, 0);
		near = RAID10_LAYOUT_NEAR(layout);
		/* A device count that is not a multiple of the near copy
		 * count has no whole-chunk row, so no single stride is right.
		 */
		if (near <= 0 || raid_disks % near != 0)
			return -EINVAL;
		data_disks = raid_disks / near;
		geom->mg_parity = false;
	} else if (strcmp(level, "raidkm") == 0) {
		long layout, m;

		snprintf(path, sizeof(path), "%s/md/layout", sys_path);
		rc = read_file(path, buf, sizeof(buf));
		if (rc != 0)
			return -rc;
		layout = strtol(buf, NULL, 0);
		m = layout & RAIDKM_LAYOUT_M_MASK;
		if (layout & RAIDKM_LAYOUT_DCL)
			data_disks = RAIDKM_LAYOUT_DCL_G(layout) - m;
		else
			data_disks = raid_disks - m;
	} else {
		return -ENOTSUP;
	}

	if (chunk == 0 || data_disks <= 0)
		return -EINVAL;

	geom->mg_chunk_bytes = chunk;
	geom->mg_data_disks = data_disks;

	return 0;
}

/* Read the dm uuid of @sys_path, true only if it starts with @prefix */
static bool dm_read_uuid(const char *sys_path, const char *prefix,
			 char *uuid, int size)
{
	char path[PATH_MAX + 16];
	FILE *fp;

	/* Not read_file(): it prints an error if dm/uuid can't be read,
	 * e.g. while the device is being removed.
	 */
	snprintf(path, sizeof(path), "%s/dm/uuid", sys_path);
	fp = fopen(path, "r");
	if (!fp)
		return false;
	if (!fgets(uuid, size, fp)) {
		fclose(fp);
		return false;
	}
	fclose(fp);

	uuid[strcspn(uuid, "\n")] = '\0';
	return strncmp(uuid, prefix, strlen(prefix)) == 0;
}

static bool dm_read_lvm_uuid(const char *sys_path, char *uuid, int size)
{
	return dm_read_uuid(sys_path, "LVM-", uuid, size);
}

/* cryptsetup names its dm-crypt and dm-integrity devices "CRYPT-".  dm-crypt
 * shifts the data by its header (16MiB for LUKS2) and dm-integrity puts tag
 * sectors between data areas, so neither keeps the rows of the array below.
 */
static bool dm_is_cryptsetup(const char *sys_path)
{
	char uuid[256];

	return dm_read_uuid(sys_path, "CRYPT-", uuid, sizeof(uuid));
}

/* dm-thin and dm-vdo map each block independently onto their data device,
 * so a row-aligned extent above them is not row-aligned on the array.  LVM
 * names these pool devices with a "-tpool" or "-vpool" dm uuid suffix.
 */
static bool dm_is_remapping_pool(const char *sys_path)
{
	char uuid[256];
	size_t len;

	if (!dm_read_lvm_uuid(sys_path, uuid, sizeof(uuid)))
		return false;

	len = strlen(uuid);
	return len > 6 && (strcmp(uuid + len - 6, "-tpool") == 0 ||
			   strcmp(uuid + len - 6, "-vpool") == 0);
}

/* LVM reserves these in LV (not VG) names for the cache sub-LVs of a
 * dm-cache or dm-writecache LV, which hold no file data at a fixed offset.
 */
static bool dm_is_cache_component(const char *sys_path)
{
	static const char *const caches[] = { "_cdata", "_cmeta", "_cvol",
					      NULL };
	const char *const *c;
	char path[PATH_MAX + 16];
	char uuid[256];
	char name[256];
	char *lv;

	if (!dm_read_lvm_uuid(sys_path, uuid, sizeof(uuid)))
		return false;

	snprintf(path, sizeof(path), "%s/dm/name", sys_path);
	if (read_file(path, name, sizeof(name)) != 0)
		return false;

	/* The dm name is "<vg>-<lv>", with any '-' in either doubled */
	lv = name;
	while ((lv = strchr(lv, '-')) && lv[1] == '-')
		lv += 2;
	if (!lv)
		return false;

	for (c = caches; *c; c++)
		if (strstr(lv + 1, *c))
			return true;

	return false;
}

/* True if a member of the md array at @sys_path has its own io_opt that
 * does not divide the chunk, e.g. a nested md array (RAID60) or a hardware
 * RAID LUN.  A chunk then holds a partial member row, so no row of this
 * array is a whole row on the members.
 */
static bool md_member_geometry_differs(const char *sys_path,
				       const struct md_geometry *geom)
{
	char path[PATH_MAX * 2];
	char buf[64];
	struct dirent *d;
	bool differs = false;
	bool part;
	DIR *dir;

	snprintf(path, sizeof(path), "%s/slaves", sys_path);
	dir = opendir(path);
	if (!dir)
		return false;

	while (!differs && (d = readdir(dir)) != NULL) {
		unsigned long io_opt;

		if (d->d_name[0] == '.')
			continue;

		/* A partition has no queue/; use that of its disk */
		snprintf(path, sizeof(path), "%s/slaves/%s/partition",
			 sys_path, d->d_name);
		part = access(path, F_OK) == 0;
		snprintf(path, sizeof(path),
			 "%s/slaves/%s/%squeue/optimal_io_size",
			 sys_path, d->d_name, part ? "../" : "");
		if (read_file(path, buf, sizeof(buf)) != 0)
			continue;
		io_opt = strtoul(buf, NULL, 0);
		differs = io_opt != 0 && geom->mg_chunk_bytes % io_opt != 0;
	}
	closedir(dir);

	return differs;
}

/* Find the striped md array (if any) underneath a block device, descending
 * through stacked (dm) devices via sysfs slave links.  A dm device is only
 * followed when it has a single slave in the data path: one that spans or
 * stripes over several (e.g. an LV on several PVs) keeps no one array's rows,
 * so we report -EINVAL.  So does an md array whose members add their own
 * geometry.
 */
static int md_probe_sys_geometry(const char *sys_path,
				 struct md_geometry *geom, int depth)
{
	char path[PATH_MAX * 2];
	struct dirent *d;
	char *data = NULL;
	int nr_data = 0;
	DIR *dir;
	int rc;

	snprintf(path, sizeof(path), "%s/md/level", sys_path);
	if (access(path, F_OK) == 0) {
		rc = md_read_geometry(sys_path, geom);
		/* Members add their own geometry: no single row fits, so
		 * leave it to the blkid topology mke2fs reads.
		 */
		if (rc == 0 && md_member_geometry_differs(sys_path, geom))
			rc = -EINVAL;
		return rc;
	}

	if (depth <= 0 || dm_is_remapping_pool(sys_path) ||
	    dm_is_cryptsetup(sys_path))
		return -ENOTSUP;

	/* A partition of an md array (e.g. an LVM PV on md0p1) has neither
	 * md/ nor slaves/; its geometry is that of the array it is in.
	 */
	snprintf(path, sizeof(path), "%s/partition", sys_path);
	if (access(path, F_OK) == 0) {
		char *parent;

		snprintf(path, sizeof(path), "%s/..", sys_path);
		parent = realpath(path, NULL);
		if (!parent)
			return -ENOTSUP;
		rc = md_probe_sys_geometry(parent, geom, depth - 1);
		free(parent);
		return rc;
	}

	snprintf(path, sizeof(path), "%s/slaves", sys_path);
	dir = opendir(path);
	if (!dir)
		return -ENOTSUP;

	while ((d = readdir(dir)) != NULL) {
		char *real;

		if (d->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), "%s/slaves/%s", sys_path,
			 d->d_name);
		real = realpath(path, NULL);
		if (real && dm_is_cache_component(real)) {
			free(real);
			continue;
		}
		if (nr_data++ > 0) {
			free(real);
			free(data);
			closedir(dir);
			return -EINVAL;
		}
		data = real;
	}
	closedir(dir);

	if (!data)
		return -ENOTSUP;

	rc = md_probe_sys_geometry(data, geom, depth - 1);
	free(data);

	return rc;
}

/* Look up the geometry of the md array underneath @devname.  On success, if
 * @part_start_out is non-NULL it is set to the device's partition start (in
 * 512-byte sectors), or 0 when the device is not a partition, so that the
 * caller can check the partition's alignment against the array.
 */
static int ldiskfs_get_md_geometry(const char *devname,
				   struct md_geometry *geom,
				   unsigned long long *part_start_out)
{
	struct stat st;
	char sys_path[PATH_MAX];
	char attr_path[PATH_MAX + 16];
	char buf[64];
	char *real_sys_path;
	unsigned long long part_start = 0;
	int rc;

	if (stat(devname, &st) != 0 || !S_ISBLK(st.st_mode))
		return -ENOTSUP;

	if (major(st.st_rdev) == LOOP_MAJOR)
		return -ENOTSUP;

	snprintf(sys_path, sizeof(sys_path), "/sys/dev/block/%u:%u",
		 major(st.st_rdev), minor(st.st_rdev));

	snprintf(attr_path, sizeof(attr_path), "%s/partition", sys_path);
	if (access(attr_path, F_OK) == 0) {
		snprintf(attr_path, sizeof(attr_path), "%s/start", sys_path);
		if (read_file(attr_path, buf, sizeof(buf)) == 0)
			part_start = strtoull(buf, NULL, 0);

		snprintf(sys_path, sizeof(sys_path), "/sys/dev/block/%u:%u/..",
			 major(st.st_rdev), minor(st.st_rdev));
	}

	real_sys_path = realpath(sys_path, NULL);
	if (!real_sys_path)
		return -errno;

	rc = md_probe_sys_geometry(real_sys_path, geom, 4);
	free(real_sys_path);
	if (rc != 0)
		return rc;

	if (part_start_out)
		*part_start_out = part_start;

	return 0;
}

/* The OST default brw_size is the bigalloc cluster size when that is larger
 * than DEF_BULK_RPC_SIZE, see osd_conf_get().
 */
static unsigned long long ldiskfs_def_brw_size(const char *mkfsopts)
{
	static const char units[] = "KMGT";
	unsigned long long cluster;
	const char *opt;
	const char *unit;
	char *end;

	for (opt = strstr(mkfsopts, "-C"); opt; opt = strstr(opt + 2, "-C"))
		if (opt == mkfsopts || isspace((unsigned char)opt[-1]))
			break;
	if (!opt)
		return DEF_BULK_RPC_SIZE;

	/* Same suffixes as mke2fs -C, where 's' is 512-byte sectors */
	cluster = strtoull(opt + 2, &end, 0);
	unit = *end ? strchr(units, toupper((unsigned char)*end)) : NULL;
	if (unit)
		cluster <<= 10 * (unit - units + 1);
	else if (*end == 's')
		cluster <<= 9;

	return cluster > DEF_BULK_RPC_SIZE ? cluster : DEF_BULK_RPC_SIZE;
}

/* Build fs according to type */
int ldiskfs_make_lustre(struct mkfs_opts *mop)
{
	char mkfs_cmd[PATH_MAX];
	char buf[64];
	char *start;
	char *dev;
	int ret = 0, ext_opts = 0;
	bool enable_64bit = false;
	long inode_size = 0;
	size_t maxbuflen;

	mop->mo_blocksize_kb = 4;

	start = strstr(mop->mo_mkfsopts, "-b");
	if (start) {
		char *end = NULL;
		long blocksize;

		blocksize = strtol(start + 2, &end, 0);
		if (end && (*end == 'k' || *end == 'K'))
			blocksize *= 1024;
		/* EXT4_MIN_BLOCK_SIZE || EXT4_MAX_BLOCK_SIZE */
		if (blocksize < 1024 || blocksize > 65536) {
			fprintf(stderr,
				"%s: blocksize %lu not in 1024-65536 bytes, normally 4096 bytes\n",
				progname, blocksize);
			return EINVAL;
		}

		if ((blocksize & (blocksize - 1)) != 0) {
			fprintf(stderr,
				"%s: blocksize %lu not a power-of-two value\n",
				progname, blocksize);
			return EINVAL;
		}
		mop->mo_blocksize_kb = blocksize >> 10;
	}

	if (!(mop->mo_flags & MO_IS_LOOP)) {
		__u64 device_kb = get_device_size(mop->mo_device);

		if (device_kb == 0)
			return ENODEV;

		/* Compare to real size */
		if (mop->mo_device_kb == 0 || device_kb < mop->mo_device_kb)
			mop->mo_device_kb = device_kb;
	}

	if (mop->mo_device_kb != 0) {
		__u64 block_count;

		if (mop->mo_device_kb < 32384) {
			fprintf(stderr, "%s: size of filesystem must be larger "
				"than 32MB, but is set to %lldKB\n",
				progname, (long long)mop->mo_device_kb);
			return EINVAL;
		}
		block_count = mop->mo_device_kb / mop->mo_blocksize_kb;
		if (block_count > 0xffffffffULL) {
			/* If the LUN size is just over 2^32 blocks, limit the
			 * filesystem size to 2^32-1 blocks to avoid problems
			 * with ldiskfs/mkfs not handling this well. b=22906
			 */
			if (block_count < 0x100002000ULL)
				mop->mo_device_kb =
					0xffffffffULL * mop->mo_blocksize_kb;
			else
				enable_64bit = true;
		}
	}

	if ((mop->mo_ldd.ldd_mount_type != LDD_MT_EXT3) &&
	    (mop->mo_ldd.ldd_mount_type != LDD_MT_LDISKFS) &&
	    (mop->mo_ldd.ldd_mount_type != LDD_MT_LDISKFS2)) {
		fprintf(stderr, "%s: unsupported fs type: %d (%s)\n",
			progname, mop->mo_ldd.ldd_mount_type,
			MT_STR(&mop->mo_ldd));

		return EINVAL;
	}

	/* Journal size in MB */
	if (strstr(mop->mo_mkfsopts, "-J") == NULL &&
	    mop->mo_device_kb > 1024 * 1024) {
		/* Choose our own default journal size */
		long journal_mb = 0, max_mb;

		/* cap journal size at 4GB for MDT, leave at 1GB for OSTs */
		if (IS_MDT(&mop->mo_ldd))
			max_mb = 4096;
		else if (IS_OST(&mop->mo_ldd))
			max_mb = 1024;
		else /* Use mke2fs default size for MGS */
			max_mb = 0;

		/* Use at most 4% of device for journal */
		journal_mb = mop->mo_device_kb * 4 / (1024 * 100);
		if (journal_mb > max_mb)
			journal_mb = max_mb;

		if (journal_mb) {
			snprintf(buf, sizeof(buf), " -J size=%ld", journal_mb);
			strscat(mop->mo_mkfsopts, buf,
				sizeof(mop->mo_mkfsopts));
		}
	}

	/*
	 * The inode size is constituted by following elements
	 * (assuming all files are in composite layout and has
	 * 3 components):
	 *
	 *   ldiskfs inode size: 160
	 *   MDT extended attributes size, including:
	 *	ext4_xattr_header: 32
	 *	LOV EA size: 32(lov_comp_md_v1) +
	 *		     3 * 40(lov_comp_md_entry_v1) +
	 *		     3 * 32(lov_mds_md) +
	 *		     stripes * 24(lov_ost_data) +
	 *		     16(xattr_entry) + 4("lov")
	 *	LMA EA size: 24(lustre_mdt_attrs) +
	 *		     16(xattr_entry) + 4("lma")
	 *	SOM EA size: 24(lustre_som_attrs) +
	 *		     16(xattr_entry) + 4("som")
	 *	link EA size: 24(link_ea_header) + 18(link_ea_entry) +
	 *		      16(filename) + 16(xattr_entry) + 4("link")
	 *   and some margin for 4-byte alignment, ACLs and other EAs.
	 *
	 * If we say the average filename length is about 32 bytes,
	 * the calculation looks like:
	 * 160 + 32 + (32+3*(40+32)+24*stripes+20) + (24+20) + (24+20) +
	 *  (24+20) + (~42+16+20) + other <= 512*2^m, {m=0,1,2,3}
	 */
	if (strstr(mop->mo_mkfsopts, "-I") == NULL) {
		if (IS_MDT(&mop->mo_ldd)) {
			if (mop->mo_stripe_count > 59)
				inode_size = 512; /* bz 7241 */
			/* see also "-i" below for EA blocks */
			else if (mop->mo_stripe_count > 16)
				inode_size = 2048;
			else
				inode_size = 1024;
		} else if (IS_OST(&mop->mo_ldd)) {
			/* We store MDS FID and necessary composite
			 * layout information in the OST object EA:
			 *   ldiskfs inode size: 160
			 *   OST extended attributes size, including:
			 *	ext4_xattr_header: 32
			 *	LMA EA size: 24(lustre_mdt_attrs) +
			 *		     16(xattr_entry) + 4("lma")
			 *	FID EA size: 52(filter_fid) +
			 *		     16(xattr_entry) + 4("fid")
			 * 160 + 32 + (24+20) + (52+20) = 308
			 */
			inode_size = 512;
		}

		if (inode_size > 0) {
			snprintf(buf, sizeof(buf), " -I %ld", inode_size);
			strscat(mop->mo_mkfsopts, buf,
				sizeof(mop->mo_mkfsopts));
		}
	}

	/* Bytes_per_inode: disk size / num inodes */
	if (strstr(mop->mo_mkfsopts, "-i") == NULL &&
	    strstr(mop->mo_mkfsopts, "-N") == NULL) {
		long bytes_per_inode = 0;

		/* Allocate more inodes on MDT devices.  There is
		 * no data stored on the MDT, and very little extra
		 * metadata beyond the inode.  It could go down as
		 * low as 1024 bytes, but this is conservative.
		 * Account for external EA blocks for wide striping.
		 */
		if (IS_MDT(&mop->mo_ldd)) {
			bytes_per_inode = inode_size + 1536;

			if (mop->mo_stripe_count > 59) {
				int extra = mop->mo_stripe_count * 24;

				extra = ((extra - 1) | 4095) + 1;
				bytes_per_inode += extra;
			}
		}

		/* Allocate fewer inodes on large OST devices.  Most
		 * filesystems can be much more aggressive than even
		 * this, but it is impossible to know in advance.
		 */
		if (IS_OST(&mop->mo_ldd)) {
			/* OST > 16TB assume average file size 1MB */
			if (mop->mo_device_kb > (16ULL << 30))
				bytes_per_inode = 1024 * 1024;
			/* OST > 4TB assume average file size 512kB */
			else if (mop->mo_device_kb > (4ULL << 30))
				bytes_per_inode = 512 * 1024;
			/* OST > 1TB assume average file size 256kB */
			else if (mop->mo_device_kb > (1ULL << 30))
				bytes_per_inode = 256 * 1024;
			/* OST > 10GB assume average file size 64kB,
			 * plus a bit so that inodes will fit into a
			 * 256x flex_bg without overflowing.
			 */
			else if (mop->mo_device_kb > (10ULL << 20))
				bytes_per_inode = 69905;
		}

		if (bytes_per_inode > 0) {
			snprintf(buf, sizeof(buf), " -i %ld", bytes_per_inode);
			strscat(mop->mo_mkfsopts, buf,
				sizeof(mop->mo_mkfsopts));
			mop->mo_inode_size = bytes_per_inode;
		}
	}

	if (verbose < 2)
		strscat(mop->mo_mkfsopts, " -q", sizeof(mop->mo_mkfsopts));

	/* start handle -O mkfs options */
	start = strstr(mop->mo_mkfsopts, "-O");
	if (start) {
		if (strstr(start + 2, "-O") != NULL) {
			fprintf(stderr,
				"%s: don't specify multiple -O options\n",
				progname);
			return EINVAL;
		}
		start = moveopts_to_end(start);
		maxbuflen = sizeof(mop->mo_mkfsopts) -
			(start - mop->mo_mkfsopts) - strlen(start);
		ret = enable_default_ext4_features(mop, start, maxbuflen, 1);
	} else {
		start = mop->mo_mkfsopts + strlen(mop->mo_mkfsopts);
		maxbuflen = sizeof(mop->mo_mkfsopts) - strlen(mop->mo_mkfsopts);
		ret = enable_default_ext4_features(mop, start, maxbuflen, 0);
	}
	if (ret)
		return ret;
	/* end handle -O mkfs options */

	/* start handle -E mkfs options */
	start = strstr(mop->mo_mkfsopts, "-E");
	if (start) {
		if (strstr(start + 2, "-E") != NULL) {
			fprintf(stderr,
				"%s: don't specify multiple -E options\n",
				progname);
			return EINVAL;
		}
		start = moveopts_to_end(start);
		maxbuflen = sizeof(mop->mo_mkfsopts) -
			(start - mop->mo_mkfsopts) - strlen(start);
		ext_opts = 1;
	} else {
		start = mop->mo_mkfsopts + strlen(mop->mo_mkfsopts);
		maxbuflen = sizeof(mop->mo_mkfsopts) - strlen(mop->mo_mkfsopts);
	}

	/* In order to align the filesystem metadata on 1MB boundaries,
	 * give a resize value that will reserve a power-of-two group
	 * descriptor blocks, but leave one block for the superblock.
	 * Only useful for filesystems with < 2^32 blocks due to resize
	 * limitations.
	 */
	if (!enable_64bit && strstr(mop->mo_mkfsopts, "meta_bg") == NULL &&
	    IS_OST(&mop->mo_ldd) && mop->mo_device_kb > 100 * 1024) {
		unsigned int group_blocks = mop->mo_blocksize_kb * 8192;
		unsigned int desc_per_block = mop->mo_blocksize_kb * 1024 / 32;
		unsigned int resize_blks;
		__u64 block_count = mop->mo_device_kb / mop->mo_blocksize_kb;

		resize_blks = (1ULL<<32) - desc_per_block*group_blocks;
		if (resize_blks > block_count) {
			snprintf(buf, sizeof(buf), "%u", resize_blks);
			append_unique(start, ext_opts ? "," : " -E ",
				      "resize", buf, maxbuflen);
			ext_opts = 1;
		}
	}

	/* Avoid zeroing out the full journal - speeds up mkfs */
	if (is_e2fsprogs_feature_supp("-E lazy_journal_init")) {
		append_unique(start, ext_opts ? "," : " -E ",
			      "lazy_journal_init", NULL, maxbuflen);
		ext_opts = 1;
	}
	if (is_e2fsprogs_feature_supp("-E lazy_itable_init=0")) {
		append_unique(start, ext_opts ? "," : " -E ",
			    "lazy_itable_init", "0", maxbuflen);
		ext_opts = 1;
	}
	if (is_e2fsprogs_feature_supp("-E packed_meta_blocks")) {
		append_unique(start, ext_opts ? "," : " -E ",
			      "packed_meta_blocks", NULL, maxbuflen);
		ext_opts = 1;
	}

	/* For OSTs on striped md arrays, inspect the array geometry to (a)
	 * warn about a row that the default RPC size is not a multiple of,
	 * and (b) explicitly seed stride/stripe_width so mballoc can size
	 * and align allocations to full rows.  mke2fs can derive the latter
	 * from the blkid topology, but dm-cache replaces optimal_io_size with
	 * its own block size when that does not divide the row.  dm-thin and
	 * dm-vdo pools are not probed through, see dm_is_remapping_pool().
	 * Values given by the user are left alone -- but the warning is not
	 * suppressed by them, since the row shape is a property of the
	 * array, not of what was typed.
	 */
	if (IS_OST(&mop->mo_ldd) && !(mop->mo_flags & MO_IS_LOOP)) {
		struct md_geometry geom;
		unsigned long long part_start = 0;
		unsigned long long def_rpc;
		unsigned long bs = mop->mo_blocksize_kb * 1024;

		def_rpc = ldiskfs_def_brw_size(mop->mo_mkfsopts);

		if (ldiskfs_get_md_geometry(mop->mo_device, &geom,
					    &part_start) == 0) {
			unsigned long long row =
				(unsigned long long)geom.mg_chunk_bytes *
				geom.mg_data_disks;
			unsigned long stride;

			/* A partition that does not start on a full-stripe
			 * boundary phase-shifts the whole filesystem against
			 * the array: stride/stripe_width are still worth
			 * setting, but stripe-aligned allocations will not be
			 * stripe-aligned on the platter, so warn.
			 */
			if (part_start != 0 && (part_start * 512) % row != 0)
				fprintf(stderr,
					"%s: warning: partition %s starts at sector %llu which is not aligned to the %llu-byte RAID full stripe; large writes will be split across stripes\n",
					progname, mop->mo_device, part_start,
					row);

			/* An RPC avoids a partial row only if its size is a
			 * multiple of the data row.  The default bulk RPC
			 * sizes are powers of two, so that needs a row that is
			 * a power of two and no larger than the RPC.  If the
			 * row is not a power of two, every default-sized RPC
			 * leaves a partial row, which a parity array must
			 * service as a read-modify-write; avoiding that needs
			 * a non-default max_pages_per_rpc that is a multiple
			 * of the row, on every client.  raid0/raid10 have no
			 * parity, so a partial row costs them nothing.  Unlike
			 * stride/stripe_width the row cannot be corrected
			 * later -- it is a property of the array -- so say so
			 * now, while the geometry can still be chosen.  A row
			 * larger than the default RPC can still be fixed later
			 * by raising the RPC size, but not past the maximum.
			 */
			if (geom.mg_parity && row > MAX_BULK_RPC_SIZE)
				fprintf(stderr,
					"%s: warning: %s RAID data row is %llu bytes (%u data disks * %lu-byte chunk), which is larger than the maximum %u-byte bulk RPC, so each RPC will write a partial stripe (read-modify-write). This cannot be fixed after formatting. Consider a geometry where data_disks * chunk is a power of two no larger than %u bytes.\n",
					progname, mop->mo_device, row,
					geom.mg_data_disks,
					geom.mg_chunk_bytes,
					MAX_BULK_RPC_SIZE, MAX_BULK_RPC_SIZE);
			else if (geom.mg_parity && (row & (row - 1)) != 0)
				fprintf(stderr,
					"%s: warning: %s RAID data row is %llu bytes (%u data disks * %lu-byte chunk), which is not a power of two; the default bulk RPC sizes are not a multiple of it, so each RPC will write a partial stripe (read-modify-write) unless every client sets max_pages_per_rpc to a multiple of the row%s. Consider a geometry where data_disks * chunk is a power of two.\n",
					progname, mop->mo_device, row,
					geom.mg_data_disks,
					geom.mg_chunk_bytes,
					row <= def_rpc ? "" :
					", after obdfilter.*.brw_size is raised to match and the clients are remounted");
			else if (geom.mg_parity && row > def_rpc)
				fprintf(stderr,
					"%s: warning: %s RAID data row is %llu bytes (%u data disks * %lu-byte chunk), which is larger than the default %llu-byte bulk RPC, so each RPC will write a partial stripe (read-modify-write) unless obdfilter.*.brw_size is raised to a multiple of the row and the clients are remounted.\n",
					progname, mop->mo_device, row,
					geom.mg_data_disks,
					geom.mg_chunk_bytes, def_rpc);

			/* Explicitly seed stride/stripe_width so mballoc can
			 * size and align allocations to full rows.  Values
			 * given by the user are left alone.
			 */
			if (bs > 0 && geom.mg_chunk_bytes % bs == 0 &&
			    !strstr(mop->mo_mkfsopts, "stride=") &&
			    !strstr(mop->mo_mkfsopts, "stripe_width=") &&
			    !strstr(mop->mo_mkfsopts, "stripe-width=")) {
				stride = geom.mg_chunk_bytes / bs;

				snprintf(buf, sizeof(buf), "%lu", stride);
				append_unique(start, ext_opts ? "," : " -E ",
					      "stride", buf, maxbuflen);
				snprintf(buf, sizeof(buf), "%lu",
					 stride * geom.mg_data_disks);
				append_unique(start, ",", "stripe_width", buf,
					      maxbuflen);
				ext_opts = 1;
				vprint(
					"probed md geometry: %lu-byte chunk * %u data disks -> stride=%lu stripe_width=%lu\n",
					geom.mg_chunk_bytes,
					geom.mg_data_disks, stride,
					stride * geom.mg_data_disks);
			}
		}
	}

	/* end handle -E mkfs options */

	/* Allow reformat of full devices (as opposed to partitions).
	 * We already checked for mounted dev.
	 */
	strscat(mop->mo_mkfsopts, " -F", sizeof(mop->mo_mkfsopts));

	snprintf(mkfs_cmd, sizeof(mkfs_cmd), "%s -j -b %d -L %s ", MKE2FS,
		 mop->mo_blocksize_kb * 1024, mop->mo_ldd.ldd_svname);

	/* For loop device format the dev, not the filename */
	dev = mop->mo_device;
	if (mop->mo_flags & MO_IS_LOOP)
		dev = mop->mo_loopdev;

	vprint("formatting backing filesystem %s on %s\n",
	       MT_STR(&mop->mo_ldd), dev);
	vprint("\ttarget name   %s\n", mop->mo_ldd.ldd_svname);
	vprint("\tkilobytes     %llu\n", mop->mo_device_kb);
	vprint("\toptions       %s\n", mop->mo_mkfsopts);

	/* mkfs_cmd's trailing space is important! */
	strscat(mkfs_cmd, mop->mo_mkfsopts, sizeof(mkfs_cmd));
	strscat(mkfs_cmd, " ", sizeof(mkfs_cmd));
	strscat(mkfs_cmd, dev, sizeof(mkfs_cmd));
	if (mop->mo_device_kb != 0) {
		snprintf(buf, sizeof(buf), " %lluk",
			 (unsigned long long)mop->mo_device_kb);
		strscat(mkfs_cmd, buf, sizeof(mkfs_cmd));
	}

	vprint("mkfs_cmd = %s\n", mkfs_cmd);
	ret = run_command(mkfs_cmd, sizeof(mkfs_cmd));
	if (ret) {
		fatal();
		fprintf(stderr, "Unable to build fs %s (%d)\n", dev, ret);
	}
	return ret;
}

int ldiskfs_prepare_lustre(struct mkfs_opts *mop,
			   char *wanted_mountopts, size_t len)
{
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	int ret;

	/* Set MO_IS_LOOP to indicate a loopback device is needed */
	ret = is_block(mop->mo_device);
	if (ret < 0) {
		return errno;
	} else if (ret == 0) {
		mop->mo_flags |= MO_IS_LOOP;
	}

	if (IS_MDT(ldd) || IS_MGS(ldd))
		strscat(wanted_mountopts, ",user_xattr", len);

	return 0;
}

int ldiskfs_fix_mountopts(struct mkfs_opts *mop, char *mountopts, size_t len)
{
	if (strstr(mountopts, "errors=") == NULL) {
		if (strlen(mountopts) != 0)
			strscat(mountopts, ",", len);
		strscat(mountopts, "errors=remount-ro", len);
	}

	return 0;
}

static int read_file(const char *path, char *buf, int size)
{
	FILE *fd;

	fd = fopen(path, "r");
	if (fd == NULL)
		return errno;

	if (fgets(buf, size, fd) == NULL) {
		fprintf(stderr, "reading from %s: %s", path, strerror(errno));
		fclose(fd);
		return 1;
	}
	fclose(fd);

	/* strip trailing newline */
	size = strlen(buf);
	if (buf[size - 1] == '\n')
		buf[size - 1] = '\0';

	return 0;
}

static int write_file(const char *path, const char *buf)
{
	int fd, rc;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return errno;

	rc = write(fd, buf, strlen(buf));
	close(fd);

	return rc < 0 ? errno : 0;
}

static int tune_md_stripe_cache_size(const char *sys_path,
				     struct mount_opts *mop)
{
	char path[PATH_MAX];
	unsigned long old_stripe_cache_size;
	unsigned long new_stripe_cache_size;
	char buf[3 * sizeof(old_stripe_cache_size) + 2];
	int rc;

	if (mop->mo_md_stripe_cache_size <= 0)
		return 0;

	new_stripe_cache_size = mop->mo_md_stripe_cache_size;

	snprintf(path, sizeof(path), "%s/%s", sys_path, STRIPE_CACHE_SIZE);
	rc = read_file(path, buf, sizeof(buf));
	if (rc != 0) {
		if (verbose)
			fprintf(stderr, "warning: cannot read '%s': %s\n",
				path, strerror(errno));
		return rc;
	}

	old_stripe_cache_size = strtoul(buf, NULL, 0);
	if (old_stripe_cache_size == 0 || old_stripe_cache_size == ULONG_MAX)
		return EINVAL;

	if (new_stripe_cache_size <= old_stripe_cache_size)
		return 0;

	snprintf(buf, sizeof(buf), "%lu", new_stripe_cache_size);
	rc = write_file(path, buf);
	if (rc != 0) {
		if (verbose)
			fprintf(stderr, "warning: cannot write '%s': %s\n",
				path, strerror(errno));
		return rc;
	}

	return 0;
}

static int tune_block_dev_scheduler(const char *sys_path, const char *new_sched)
{
	char path[PATH_MAX];
	char buf[PATH_MAX];
	char *s, *e;
	char *old_sched;
	int rc;

	/* Before setting the scheduler, we need to check to see if
	 * it's already set to "noop". If it is then we don't want to
	 * override that setting. If it's set to anything other than
	 * "noop" then set the scheduler to what has been passed
	 * in. */

	snprintf(path, sizeof(path), "%s/%s", sys_path, SCHEDULER_PATH);
	rc = read_file(path, buf, sizeof(buf));
	if (rc != 0) {
		if (verbose)
			fprintf(stderr, "%s: cannot read '%s': %s\n",
				progname, path, strerror(errno));

		return rc;
	}

	/* The expected format of buf: noop anticipatory deadline [cfq] */
	s = strchr(buf, '[');
	e = strchr(buf, ']');

	/* If the format is not what we expect then be safe and error out. */
	if (s == NULL || e == NULL || !(s < e)) {
		if (verbose)
			fprintf(stderr,
				"%s: cannot parse scheduler options for '%s'\n",
				progname, path);

		return EINVAL;
	}

	old_sched = s + 1;
	*e = '\0';

	if (strcmp(old_sched, "noop") == 0 ||
	    strcmp(old_sched, "deadline") == 0 ||
	    strcmp(old_sched, "mq-deadline") == 0 ||
	    strstr(old_sched, new_sched) == 0)
		return 0;

	rc = write_file(path, new_sched);
	if (rc != 0) {
		if (verbose)
			fprintf(stderr,
				"%s: cannot set scheduler on '%s': %s\n",
				progname, path, strerror(errno));
		return rc;
	}

	fprintf(stderr, "%s: changed scheduler of '%s' from %s to %s\n",
		progname, path, old_sched, new_sched);

	return 0;
}

static int tune_block_dev(const char *src, struct mount_opts *mop);

static int tune_block_dev_slaves(const char *sys_path, struct mount_opts *mop)
{
	char slaves_path[PATH_MAX];
	DIR *slaves_dir;
	struct dirent *d;
	int rc = 0;

	snprintf(slaves_path, sizeof(slaves_path), "%s/slaves", sys_path);
	slaves_dir = opendir(slaves_path);
	if (slaves_dir == NULL) {
		if (errno == ENOENT)
			return 0;

		return errno;
	}

	while ((d = readdir(slaves_dir)) != NULL) {
		char path[PATH_MAX * 2];
		int rc2;

		if (d->d_type != DT_LNK)
			continue;

		snprintf(path, sizeof(path), "/dev/%s", d->d_name);
		rc2 = tune_block_dev(path, mop);
		if (rc2 != 0)
			rc = rc2;
	}

	closedir(slaves_dir);

	return rc;
}

/* This is to tune the kernel for good SCSI performance. */
static int tune_block_dev(const char *src, struct mount_opts *mop)
{
	struct stat st;
	char sys_path[PATH_MAX];
	char partition_path[PATH_MAX + sizeof("partition")];
	char *real_sys_path = NULL;
	int rc;

	/*
	 * Don't apply block device tuning for MDT or MGT devices,
	 * since we don't need huge IO sizes to get good performance
	 */
	if (!IS_OST(&mop->mo_ldd))
		return 0;

	if (src == NULL)
		return EINVAL;

	rc = stat(src, &st);
	if (rc < 0) {
		if (verbose)
			fprintf(stderr, "warning: cannot stat '%s': %s\n",
				src, strerror(errno));
		return errno;
	}

	if (!S_ISBLK(st.st_mode))
		return 0;

	if (major(st.st_rdev) == LOOP_MAJOR)
		return 0;

	snprintf(sys_path, sizeof(sys_path), "/sys/dev/block/%u:%u",
		 major(st.st_rdev), minor(st.st_rdev));

	snprintf(partition_path, sizeof(partition_path), "%s/partition",
		 sys_path);

	rc = access(partition_path, F_OK);
	if (rc < 0) {
		if (errno == ENOENT)
			goto have_whole_dev;

		if (verbose)
			fprintf(stderr, "warning: cannot access '%s': %s\n",
				partition_path, strerror(errno));
		rc = errno;
		goto out;
	}

	snprintf(sys_path, sizeof(sys_path), "/sys/dev/block/%u:%u/..",
		 major(st.st_rdev), minor(st.st_rdev));

have_whole_dev:
	/* Since we recurse on slave devices we resolve the sys_path to
	 * avoid path buffer overflows. */
	real_sys_path = realpath(sys_path, NULL);
	if (real_sys_path == NULL) {
		if (verbose)
			fprintf(stderr,
				"warning: cannot resolve '%s': %s\n",
				sys_path, strerror(errno));
		rc = errno;
		goto out;
	}

	if (major(st.st_rdev) == MD_MAJOR) {
		rc = tune_md_stripe_cache_size(real_sys_path, mop);
	} else {
		/* Ignore errors from tune_scheduler(). The worst that will
		 * happen is a block device with an "incorrect" scheduler.
		 */
		tune_block_dev_scheduler(real_sys_path, DEFAULT_SCHEDULER);

		/* If device is multipath device then tune its slave
		 * devices. */
		rc = tune_block_dev_slaves(real_sys_path, mop);
	}

out:
	free(real_sys_path);

	return rc;
}

static bool mount_opt_has(const char *opts, const char *name)
{
	size_t len = strlen(name);
	const char *p = opts;

	while (p && *p) {
		if (strncmp(p, name, len) == 0)
			return true;
		p = strchr(p, ',');
		if (p)
			p++;
	}

	return false;
}

/* Warn when mounting an OST that sits on a parity md array but whose
 * backing filesystem was formatted without matching RAID geometry: mballoc
 * then has no stripe to align to and large streaming writes split across
 * stripes, which a parity array services as read-modify-write.  Warning
 * only -- never fails the mount.
 */
static void check_md_stripe_geometry(char *dev, struct mount_opts *mop)
{
	struct md_geometry geom;
	ext2_filsys fs = NULL;
	unsigned long stride;
	unsigned long width;
	unsigned long fs_stripe;
	const char *env;

	/* l_tunedisk (run by udev) has no mount options and no one to warn */
	if (!IS_OST(&mop->mo_ldd) || !mop->mo_orig_options)
		return;

	env = getenv("MOUNT_LUSTRE_GEOMETRY_WARN");
	if (env && strcmp(env, "0") == 0)
		return;

	/* The admin chose the stripe with -o stripe=, so stay quiet */
	if (mount_opt_has(mop->mo_orig_options, "stripe=") ||
	    mount_opt_has(mop->mo_ldd.ldd_mount_opts, "stripe="))
		return;

	if (ldiskfs_get_md_geometry(dev, &geom, NULL) != 0 || !geom.mg_parity)
		return;

	if (ext2fs_open(dev, open_flags_ro, 0, 0, unix_io_manager, &fs))
		return;

	if (geom.mg_chunk_bytes % fs->blocksize != 0)
		goto out;

	stride = geom.mg_chunk_bytes / fs->blocksize;
	width = stride * geom.mg_data_disks;

	/* mballoc aligns to the stripe ext4_get_stripe_size() picks: -o stripe=
	 * (handled above), else stripe_width, else stride as a fallback.  So
	 * only that value matters, and it is stripe-aligned if it is any
	 * multiple of the array row -- a larger multiple only sizes
	 * allocations larger.
	 */
	fs_stripe = fs->super->s_raid_stripe_width;
	if (!fs_stripe)
		fs_stripe = fs->super->s_raid_stride;

	if (!fs_stripe)
		fprintf(stderr,
			"%s: warning: %s is on a striped md array but was formatted without RAID geometry; set it with 'tune2fs -E stride=%lu,stripe_width=%lu' or mount with '-o stripe=%lu' to avoid partial-stripe writes (set MOUNT_LUSTRE_GEOMETRY_WARN=0 to hide this warning)\n",
			progname, dev, stride, width, width);
	else if (fs_stripe % width != 0)
		fprintf(stderr,
			"%s: warning: %s RAID geometry mismatch: filesystem %s is %lu blocks which is not a multiple of the %lu-block array full stripe; set it with 'tune2fs -E stride=%lu,stripe_width=%lu' (set MOUNT_LUSTRE_GEOMETRY_WARN=0 to hide this warning)\n",
			progname, dev,
			fs->super->s_raid_stripe_width ? "stripe_width" :
							 "stride",
			fs_stripe, width, stride, width);
out:
	ext2fs_close_free(&fs);
}

int ldiskfs_tune_lustre(char *dev, struct mount_opts *mop)
{
	check_md_stripe_geometry(dev, mop);

	return tune_block_dev(dev, mop);
}

int ldiskfs_label_lustre(struct mount_opts *mop)
{
	errcode_t retval;
	int mnt_flags, fd;
	char mntpt[PATH_MAX + 1];
	struct ext2_super_block *sb;

	if (strlen(mop->mo_ldd.ldd_svname) > EXT2_LABEL_LEN) {
		fprintf(stderr,
			"Warning: label '%s' too long, truncating to '%.*s'\n",
			mop->mo_ldd.ldd_svname, EXT2_LABEL_LEN,
			mop->mo_ldd.ldd_svname);
		mop->mo_ldd.ldd_svname[EXT2_LABEL_LEN] = '\0';
	}

	retval = ext2fs_check_mount_point(mop->mo_source, &mnt_flags,
					  mntpt, sizeof(mntpt));
	if (!retval && (mnt_flags & EXT2_MF_MOUNTED)) {
		int ret;

		fd = open(mntpt, O_RDONLY);
		if (fd < 0)
			goto old_method;
		ret = ioctl(fd, FS_IOC_SETFSLABEL, mop->mo_ldd.ldd_svname);
		close(fd);
		if (ret == 0)
			return 0;
	}

old_method:
	/*
	 * label_lustre is called after the target is mounted, skip mmp
	 * and skip the unclean checks.
	 */
	retval = open_backfs_rw(mop->mo_source,
				EXT2_FLAG_SUPER_ONLY | EXT2_FLAG_SKIP_MMP, 1);
	if (retval)
		return translate_error(retval);

	sb = backfs->super;
	memset(sb->s_volume_name, 0, sizeof(sb->s_volume_name));
	strncpy((char *)sb->s_volume_name, mop->mo_ldd.ldd_svname,
		EXT2_LABEL_LEN);
	ext2fs_mark_super_dirty(backfs);
	ext2fs_close_free(&backfs);

	return 0;
}

int ldiskfs_label_read(char *dev, struct lustre_disk_data *ldd)
{
	errcode_t retval;
	int mnt_flags, fd;
	char mntpt[PATH_MAX + 1];

	retval = ext2fs_check_mount_point(dev, &mnt_flags,
					  mntpt, sizeof(mntpt));
	if (!retval && (mnt_flags & EXT2_MF_MOUNTED)) {
		int ret;

		fd = open(mntpt, O_RDONLY);
		if (fd < 0)
			goto old_method;
		memset(ldd->ldd_svname, 0, sizeof(ldd->ldd_svname));
		ret = ioctl(fd, FS_IOC_GETFSLABEL, ldd->ldd_svname);
		close(fd);
		if (ret == 0)
			return 0;
	}

old_method:
	/*
	 * device label could be changed after journal recovery,
	 * reopen the fs to get the latest label.
	 */
	if (backfs)
		ext2fs_close_free(&backfs);
	retval = ext2fs_open(dev, open_flags_ro, 0, 0,
			     unix_io_manager, &backfs);
	if (retval) {
		fprintf(stderr, "Unable to open fs on %s\n",
			dev);
		return translate_error(retval);
	}

	memset(ldd->ldd_svname, 0, sizeof(ldd->ldd_svname));
	strncpy(ldd->ldd_svname, (char *)backfs->super->s_volume_name,
		EXT2_LABEL_LEN);

	return 0;
}

struct cfg_entry {
	struct list_head ce_list;
	ext2_ino_t ino;
	char name[];
};

struct rename_params {
	struct list_head *cfg_list;
	const char *oldname;
};

static int rename_fsname_iter(ext2_ino_t dir,
			      int flags,
			      struct ext2_dir_entry *de,
			      int offset,
			      int blocksize,
			      char *buf, void *priv_data)
{
	struct rename_params *params = (struct rename_params *)priv_data;
	struct cfg_entry *ce;
	const char *oldname = params->oldname;
	int old_namelen = strlen(oldname);
	int namelen = ext2fs_dirent_name_len(de);
	char name[EXT2_NAME_LEN];
	char *ptr;

	if (namelen <= old_namelen)
		return 0;

	/* Construct null terminated name for strrchr */
	memcpy(name, de->name, namelen);
	name[namelen] = '\0';

	ptr = strrchr(name, '-');
	if (!ptr || (ptr - name) != old_namelen)
		return 0;

	if (strncmp(name, oldname, old_namelen) != 0)
		return 0;

	ce = malloc(sizeof(*ce) + namelen + 1);
	if (!ce) {
		fprintf(stderr, "Fail to init item for %s\n", name);
		return DIRENT_ABORT;
	}

	INIT_LIST_HEAD(&ce->ce_list);
	ce->ino = de->inode;
	memcpy(ce->name, de->name, namelen);
	ce->name[namelen] = '\0';

	list_add(&ce->ce_list, params->cfg_list);

	return 0;
}

int ldiskfs_rename_fsname(struct mkfs_opts *mop, const char *oldname)
{
	errcode_t retval;
	ext2_ino_t ino;
	ext2_file_t file;
	unsigned int size;
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	struct lr_server_data lsd;
	struct rename_params params;
	struct cfg_entry *ce;
	struct list_head cfg_list;
	int old_namelen = strlen(oldname);
	int new_namelen = strlen(ldd->ldd_fsname);
	char *dev;

	INIT_LIST_HEAD(&cfg_list);

	if (mop->mo_flags & MO_IS_LOOP)
		dev = mop->mo_loopdev;
	else
		dev = mop->mo_device;

	retval = open_backfs_rw(dev, 0, 0);
	if (retval)
		return translate_error(retval);
	retval = ext2fs_read_bitmaps(backfs);
	if (retval)
		return translate_error(retval);

	/* Change the filesystem label. */
	if (strlen(ldd->ldd_svname) > EXT2_LABEL_LEN) {
		fprintf(stderr,
			"Warning: label '%s' too long, truncating to '%.*s'\n",
			ldd->ldd_svname, EXT2_LABEL_LEN, ldd->ldd_svname);
		ldd->ldd_svname[EXT2_LABEL_LEN] = '\0';
	}
	memset(backfs->super->s_volume_name, 0,
	       sizeof(backfs->super->s_volume_name));
	strncpy((char *)backfs->super->s_volume_name, ldd->ldd_svname,
		EXT2_LABEL_LEN);
	ext2fs_mark_super_dirty(backfs);
	ext2fs_flush(backfs);

	retval = ext2fs_namei(backfs, EXT2_ROOT_INO, EXT2_ROOT_INO,
			      LAST_RCVD, &ino);
	if (retval) {
		if (retval == EXT2_ET_FILE_NOT_FOUND)
			goto config;

		return translate_error(retval);
	}
	retval = ext2fs_file_open(backfs, ino, EXT2_FILE_WRITE, &file);
	if (retval) {
		fprintf(stderr, "Unable to open %s\n", LAST_RCVD);
		return translate_error(retval);
	}
	retval = ext2fs_file_read(file, &lsd, sizeof(lsd), &size);
	if (retval || size != sizeof(lsd)) {
		fprintf(stderr, "Unable to read %s\n", LAST_RCVD);
		if (!retval)
			retval = EXT2_ET_SHORT_READ;
		ext2fs_file_close(file);
		return translate_error(retval);
	}
	retval = ext2fs_file_lseek(file, 0, EXT2_SEEK_SET, NULL);
	if (retval) {
		fprintf(stderr, "Unable to lseek %s\n", LAST_RCVD);
		ext2fs_file_close(file);
		return translate_error(retval);
	}

	/* replace fsname in lr_server_data::lsd_uuid. */
	if (old_namelen > new_namelen)
		memmove(lsd.lsd_uuid + new_namelen,
			lsd.lsd_uuid + old_namelen,
			sizeof(lsd.lsd_uuid) - old_namelen);
	else if (old_namelen < new_namelen)
		memmove(lsd.lsd_uuid + new_namelen,
			lsd.lsd_uuid + old_namelen,
			sizeof(lsd.lsd_uuid) - new_namelen);
	memcpy(lsd.lsd_uuid, ldd->ldd_fsname, new_namelen);
	retval = ext2fs_file_write(file, &lsd, sizeof(lsd), &size);
	if (retval || size != sizeof(lsd)) {
		fprintf(stderr, "Unable to write %s\n", LAST_RCVD);
		if (!retval)
			retval = EXT2_ET_SHORT_WRITE;
		ext2fs_file_close(file);
		return translate_error(retval);
	}
	ext2fs_file_close(file);

config:
	retval = ext2fs_namei(backfs, EXT2_ROOT_INO, EXT2_ROOT_INO,
			      MOUNT_CONFIGS_DIR, &ino);
	if (retval) {
		fprintf(stderr, "Unable to open dir %s\n", MOUNT_CONFIGS_DIR);
		return translate_error(retval);
	}
	params.cfg_list = &cfg_list;
	params.oldname = oldname;
	retval = ext2fs_dir_iterate2(backfs, ino, 0, NULL,
				     rename_fsname_iter, &params);
	if (retval) {
		fprintf(stderr, "Unable to iterate dir %s\n",
			MOUNT_CONFIGS_DIR);
		return translate_error(retval);
	}

	while (!list_empty(&cfg_list)) {
		ce = list_entry(cfg_list.next, struct cfg_entry, ce_list);
		if (IS_MGS(ldd)) {
			struct ext2_xattr_handle *h;

			retval = ext2fs_xattrs_open(backfs, ce->ino, &h);
			if (retval)
				break;
			retval = ext2fs_xattrs_read(h);
			if (retval)
				break;
			retval = ext2fs_xattr_set(h, XATTR_TARGET_RENAME,
						  ldd->ldd_fsname,
						  strlen(ldd->ldd_fsname));
			ext2fs_xattrs_close(&h);
			if (retval)
				break;
		} else {
			struct ext2_inode_large inode;

			retval = ext2fs_unlink(backfs, ino, ce->name, 0, 0);
			if (retval)
				break;
			memset(&inode, 0, sizeof(inode));
			retval = ext2fs_read_inode_full(backfs, ino,
				(struct ext2_inode *)&inode, sizeof(inode));
			if (retval)
				break;
			inode.i_mtime = inode.i_ctime =
				backfs->now ? backfs->now : time(0);
			retval = ext2fs_write_inode_full(backfs, ino,
					(struct ext2_inode *)&inode,
					sizeof(inode));
			if (retval)
				break;
			memset(&inode, 0, sizeof(inode));
			retval = ext2fs_read_inode_full(backfs, ce->ino,
				(struct ext2_inode *)&inode, sizeof(inode));
			if (retval)
				break;
			if (!inode.i_links_count) {
				list_del(&ce->ce_list);
				free(ce);
				continue;
			}
			inode.i_links_count--;
			inode.i_ctime = backfs->now ? backfs->now : time(0);
			if (inode.i_links_count)
				goto write_inode;

			inode.i_dtime = backfs->now ? backfs->now : time(0);
			retval = ext2fs_free_ext_attr(backfs, ce->ino, &inode);
			if (retval)
				goto write_inode;
			if (ext2fs_inode_has_valid_blocks2(backfs,
					(struct ext2_inode *)&inode)) {
				retval = ext2fs_punch(backfs, ce->ino,
						(struct ext2_inode *)&inode,
						NULL, 0, ~0ULL);
				if (retval)
					goto write_inode;
			}

			ext2fs_inode_alloc_stats2(backfs, ce->ino, -1,
						  LINUX_S_ISDIR(inode.i_mode));

write_inode:
			retval = ext2fs_write_inode_full(backfs, ce->ino,
					(struct ext2_inode *)&inode,
					sizeof(inode));
			if (retval)
				break;
		}
		list_del(&ce->ce_list);
		free(ce);
	}

	if (retval) {
		fprintf(stderr, "Fail to %s %s/%s: %s\n",
			IS_MGS(ldd) ? "setxattr" : "unlink",
			MOUNT_CONFIGS_DIR, ce->name,
			strerror(translate_error(retval)));
		while (!list_empty(&cfg_list)) {
			ce = list_entry(cfg_list.next, struct cfg_entry,
					ce_list);
			list_del(&ce->ce_list);
			free(ce);
		}
		return translate_error(retval);
	}

	if (ext2fs_has_feature_quota(backfs->super)) {
		retval = write_quota_inodes(backfs, 0);
		if (retval)
			return translate_error(retval);
	}

	return 0;
}

/* Enable quota accounting */
int ldiskfs_enable_quota(struct mkfs_opts *mop)
{
	errcode_t retval;
	char *dev;

	dev = mop->mo_device;
	if (mop->mo_flags & MO_IS_LOOP)
		dev = mop->mo_loopdev;

	retval = open_backfs_rw(dev, 0, 0);
	if (retval)
		return translate_error(retval);

	/* Quota feature is already enabled? */
	if (ext2fs_has_feature_quota(backfs->super)) {
		vprint("Quota feature is already enabled.\n");
		return 0;
	}

	/* Turn on quota feature */
	retval = write_quota_inodes(backfs, QUOTA_USR_BIT | QUOTA_GRP_BIT);
	if (retval)
		return translate_error(retval);

	ext2fs_set_feature_quota(backfs->super);
	ext2fs_mark_super_dirty(backfs);
	ext2fs_flush(backfs);

	return 0;
}

int ldiskfs_init(void)
{
	/* Required because full path to DEBUGFS is not specified */
	setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin", 0);

	return 0;
}

void ldiskfs_fini(void)
{
	if (backfs)
		ext2fs_close_free(&backfs);
}

#ifndef PLUGIN_DIR
struct module_backfs_ops ldiskfs_ops = {
	.init			= ldiskfs_init,
	.fini			= ldiskfs_fini,
	.read_ldd		= ldiskfs_read_ldd,
	.write_ldd		= ldiskfs_write_ldd,
	.erase_ldd		= ldiskfs_erase_ldd,
	.print_ldd_params	= ldiskfs_print_ldd_params,
	.is_lustre		= ldiskfs_is_lustre,
	.make_lustre		= ldiskfs_make_lustre,
	.prepare_lustre		= ldiskfs_prepare_lustre,
	.fix_mountopts		= ldiskfs_fix_mountopts,
	.tune_lustre		= ldiskfs_tune_lustre,
	.label_lustre		= ldiskfs_label_lustre,
	.label_read		= ldiskfs_label_read,
	.enable_quota		= ldiskfs_enable_quota,
	.rename_fsname		= ldiskfs_rename_fsname,
};
#endif /* PLUGIN_DIR */
