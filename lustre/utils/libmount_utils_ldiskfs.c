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
#define MAX_SECTORS_KB_PATH	"queue/max_sectors_kb"
#define SCHEDULER_PATH		"queue/scheduler"
#define STRIPE_CACHE_SIZE	"md/stripe_cache_size"

#define DEFAULT_SCHEDULER	"deadline"

extern char *progname;

static ext2_filsys backfs;
static int open_flags = EXT2_FLAG_64BITS | EXT2_FLAG_SKIP_MMP |
			EXT2_FLAG_IGNORE_SB_ERRORS | EXT2_FLAG_SUPER_ONLY;

/* keep it less than LL_FID_NAMELEN */
#define DUMMY_FILE_NAME_LEN             25
#define EXT3_DIRENT_SIZE                DUMMY_FILE_NAME_LEN

static void append_unique(char *buf, char *prefix, char *key, char *val,
			  size_t maxbuflen);
static bool is_e2fsprogs_feature_supp(const char *feature);
static void disp_old_e2fsprogs_msg(const char *feature, int make_backfs);

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

/* Write the server config files */
int ldiskfs_write_ldd(struct mkfs_opts *mop)
{
	char mntpt[] = "/tmp/mntXXXXXX";
	char filepnm[192];
	char *dev;
	FILE *filep;
	int ret = 0;
	size_t num;

	/* Mount this device temporarily in order to write these files */
	if (!mkdtemp(mntpt)) {
		fprintf(stderr, "%s: Can't create temp mount point %s: %s\n",
			progname, mntpt, strerror(errno));
		return errno;
	}

	dev = mop->mo_device;
	if (mop->mo_flags & MO_IS_LOOP)
		dev = mop->mo_loopdev;

	/* Multiple mount protection enabled if failover node specified */
	if (mop->mo_flags & MO_FAILOVER) {
		if (!backfs)
			ext2fs_open(dev, open_flags, 0, 0,
				    unix_io_manager, &backfs);
		if (!backfs || !ext2fs_has_feature_mmp(backfs->super)) {
			if (is_e2fsprogs_feature_supp("-O mmp")) {
				char *command = filepnm;

				snprintf(command, sizeof(filepnm),
					 TUNE2FS" -O mmp '%s' >/dev/null 2>&1",
					 dev);
				ret = run_command(command, sizeof(filepnm));
				if (ret)
					fprintf(stderr,
						"%s: Unable to set 'mmp' "
						"on %s: %d\n",
						progname, dev, ret);
			} else {
				disp_old_e2fsprogs_msg("mmp", 1);
			}
			/* avoid stale cache after following operations */
			if (backfs) {
				ext2fs_close(backfs);
				backfs = NULL;
			}
		}
	}

	ret = mount(dev, mntpt, MT_STR(&mop->mo_ldd), 0,
		(mop->mo_mountopts == NULL) ?
		"errors=remount-ro" : mop->mo_mountopts);
	if (ret) {
		fprintf(stderr, "%s: Unable to mount %s: %s\n",
			progname, dev, strerror(errno));
		ret = errno;
		if (errno == ENODEV) {
			fprintf(stderr, "Is the %s module available?\n",
				MT_STR(&mop->mo_ldd));
		}
		goto out_rmdir;
	}

	/* Set up initial directories */
	sprintf(filepnm, "%s/%s", mntpt, MOUNT_CONFIGS_DIR);
	ret = mkdir(filepnm, 0777);
	if ((ret != 0) && (errno != EEXIST)) {
		fprintf(stderr, "%s: Can't make configs dir %s (%s)\n",
			progname, filepnm, strerror(errno));
		goto out_umnt;
	} else if (errno == EEXIST) {
		ret = 0;
	}

	/* Save the persistent mount data into a file. Lustre must pre-read
	   this file to get the real mount options. */
	vprint("Writing %s\n", MOUNT_DATA_FILE);
	sprintf(filepnm, "%s/%s", mntpt, MOUNT_DATA_FILE);
	filep = fopen(filepnm, "w");
	if (!filep) {
		fprintf(stderr, "%s: Unable to create %s file: %s\n",
			progname, filepnm, strerror(errno));
		goto out_umnt;
	}
	num = fwrite(&mop->mo_ldd, sizeof(mop->mo_ldd), 1, filep);
	if (num < 1 && ferror(filep)) {
		fprintf(stderr, "%s: Unable to write to file (%s): %s\n",
			progname, filepnm, strerror(errno));
		fclose(filep);
		goto out_umnt;
	}
	fsync(filep->_fileno);
	fclose(filep);

out_umnt:
	umount(mntpt);
out_rmdir:
	rmdir(mntpt);
	return ret;
}

static int readcmd(char *cmd, char *buf, int len)
{
	FILE *fp;
	int red;

	fp = popen(cmd, "r");
	if (!fp)
		return errno;

	red = fread(buf, 1, len, fp);
	pclose(fp);

	/* strip trailing newline */
	if (buf[red - 1] == '\n')
		buf[red - 1] = '\0';

	return (red == 0) ? -ENOENT : 0;
}

int ldiskfs_read_ldd(char *dev, struct lustre_disk_data *mo_ldd)
{
	errcode_t retval;
	ext2_ino_t ino;
	ext2_file_t file;
	unsigned int got;
	char cmd[PATH_MAX];
	int ret = 0;

	if (!backfs) {
		retval = ext2fs_open(dev, open_flags, 0, 0,
				     unix_io_manager, &backfs);
		if (retval) {
			fprintf(stderr, "Unable to open fs on %s\n", dev);
			goto read_label;
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
	if (retval || got == 0)
		fprintf(stderr, "Failed to read file %s\n", MOUNT_DATA_FILE);
read_label:
	/* As long as we at least have the label, we're good to go */
	snprintf(cmd, sizeof(cmd), E2LABEL" %s", dev);
	ret = readcmd(cmd, mo_ldd->ldd_svname, sizeof(mo_ldd->ldd_svname) - 1);

	return ret;
}

int ldiskfs_erase_ldd(struct mkfs_opts *mop, char *param)
{
	return 0;
}

void ldiskfs_print_ldd_params(struct mkfs_opts *mop)
{
	printf("Parameters:%s\n", mop->mo_ldd.ldd_params);
}

/* Display the need for the latest e2fsprogs to be installed. make_backfs
 * indicates if the caller is make_lustre_backfs() or not. */
static void disp_old_e2fsprogs_msg(const char *feature, int make_backfs)
{
	static int msg_displayed;

	if (msg_displayed) {
		fprintf(stderr, "WARNING: %s does not support %s "
			"feature.\n\n", E2FSPROGS, feature);
		return;
	}

	msg_displayed++;

	fprintf(stderr, "WARNING: The %s package currently installed on "
		"your system does not support \"%s\" feature.\n",
		E2FSPROGS, feature);
#if !(HAVE_LDISKFSPROGS)
	fprintf(stderr, "Please install the latest version of e2fsprogs from\n"
		"https://downloads.whamcloud.com/public/e2fsprogs/latest/\n"
		"to enable this feature.\n");
#endif
	if (make_backfs)
		fprintf(stderr,
			"Feature will not be enabled until %s is updated and '%s -O %s %%{device}' is run.\n\n",
			E2FSPROGS, TUNE2FS, feature);
}

/* Check whether the file exists in the device */
static int file_in_dev(char *file_name, char *dev_name)
{
	ext2_ino_t ino;
	errcode_t retval;

	if (!backfs) {
		retval = ext2fs_open(dev_name, open_flags, 0, 0,
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
		/* in the -1 case, 'extents' means IS a lustre target */
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

	if ((fd = mkstemp(imgname)) < 0)
		return false;

	close(fd);

	snprintf(cmd, sizeof(cmd), "%s -F %s %s 100 >/dev/null 2>&1",
		 MKE2FS, feature, imgname);
	/* run_command() displays the output of mke2fs when it fails for
	 * some feature, so use system() directly */
	ret = system(cmd);
	unlink(imgname);

	return ret == 0;
}

/**
 * append_unique: append @key or @key=@val pair to @buf only if @key does not
 *                exists
 *      @buf: buffer to hold @key or @key=@val
 *      @prefix: prefix string before @key
 *      @key: key string
 *      @val: value string if it's a @key=@val pair
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

	if (IS_OST(&mop->mo_ldd)) {
		append_unique(anchor, user_spec ? "," : " -O ",
			      "extents", NULL, maxbuflen);
		append_unique(anchor, ",", "uninit_bg", NULL, maxbuflen);
	} else if (IS_MDT(&mop->mo_ldd)) {
		append_unique(anchor, user_spec ? "," : " -O ",
			      "dirdata", NULL, maxbuflen);
		append_unique(anchor, ",", "uninit_bg", NULL, maxbuflen);
		if (enable_64bit)
			append_unique(anchor, ",", "extents", NULL, maxbuflen);
		else
			append_unique(anchor, ",", "^extents", NULL, maxbuflen);
	} else {
		append_unique(anchor, user_spec ? "," : " -O ",
			      "uninit_bg", NULL, maxbuflen);
	}

	/* Multiple mount protection enabled only if failover node specified */
	if (mop->mo_flags & MO_FAILOVER) {
		if (is_e2fsprogs_feature_supp("-O mmp"))
			append_unique(anchor, ",", "mmp", NULL, maxbuflen);
		else
			disp_old_e2fsprogs_msg("mmp", 1);
	}

	/* Allow more than 65000 subdirectories */
	if (is_e2fsprogs_feature_supp("-O dir_nlink"))
		append_unique(anchor, ",", "dir_nlink", NULL, maxbuflen);

	/* The following options are only valid for ext4-based ldiskfs.
	 * If --backfstype=ext3 is specified, do not enable them. */
	if (mop->mo_ldd.ldd_mount_type == LDD_MT_EXT3)
		return 0;

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

	/* Allow files larger than 2TB.  Also needs LU-16, but not harmful. */
	if (is_e2fsprogs_feature_supp("-O huge_file"))
		append_unique(anchor, ",", "huge_file", NULL, maxbuflen);

	if (enable_64bit)
		append_unique(anchor, ",", "64bit", NULL, maxbuflen);

	if (blocks >= 0x1000000000 && is_e2fsprogs_feature_supp("-O meta_bg"))
		append_unique(anchor, ",", "meta_bg", NULL, maxbuflen);

	if (enable_64bit || strstr(mop->mo_mkfsopts, "meta_bg"))
		append_unique(anchor, ",", "^resize_inode", NULL, maxbuflen);

	/* Allow xattrs larger than one block, stored in a separate inode */
	if (IS_MDT(&mop->mo_ldd) && is_e2fsprogs_feature_supp("-O ea_inode"))
		append_unique(anchor, ",", "ea_inode", NULL, maxbuflen);

	/* Allow more than 10M directory entries */
	if (IS_MDT(&mop->mo_ldd) && is_e2fsprogs_feature_supp("-O large_dir"))
		append_unique(anchor, ",", "large_dir", NULL, maxbuflen);

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
 * moveopts_to_end: find the option string, move remaining strings to
 *                  where option string starts, and append the option
 *                  string at the end
 *      @start: where the option string starts before the move
 *      RETURN: where the option string starts after the move
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

		resize_blks = (1ULL<<32) - desc_per_block*group_blocks;
		snprintf(buf, sizeof(buf), "%u", resize_blks);
		append_unique(start, ext_opts ? "," : " -E ",
			      "resize", buf, maxbuflen);
		ext_opts = 1;
	}

	/* Avoid zeroing out the full journal - speeds up mkfs */
	if (is_e2fsprogs_feature_supp("-E lazy_journal_init=0")) {
		append_unique(start, ext_opts ? "," : " -E ",
			      "lazy_journal_init=0", NULL, maxbuflen);
		ext_opts = 1;
	}
	if (is_e2fsprogs_feature_supp("-E lazy_itable_init=0")) {
		append_unique(start, ext_opts ? "," : "-E",
			    "lazy_itable_init=0", NULL, maxbuflen);
		ext_opts = 1;
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
	if (strstr(mountopts, "errors=") == NULL)
		strscat(mountopts, ",errors=remount-ro", len);

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

static int tune_max_sectors_kb(const char *sys_path, struct mount_opts *mop)
{
	char path[PATH_MAX];
	unsigned long max_hw_sectors_kb;
	unsigned long old_max_sectors_kb;
	unsigned long new_max_sectors_kb;
	char buf[3 * sizeof(old_max_sectors_kb) + 2];
	int rc;

	if (mop->mo_max_sectors_kb >= 0) {
		new_max_sectors_kb = mop->mo_max_sectors_kb;
		goto have_new_max_sectors_kb;
	}

	snprintf(path, sizeof(path), "%s/%s", sys_path, MAX_HW_SECTORS_KB_PATH);
	rc = read_file(path, buf, sizeof(buf));
	if (rc != 0) {
		/* No MAX_HW_SECTORS_KB_PATH isn't necessary an
		 * error for some devices. */
		return 0;
	}

	max_hw_sectors_kb = strtoul(buf, NULL, 0);
	if (max_hw_sectors_kb == 0 || max_hw_sectors_kb == ULLONG_MAX) {
		/* No digits at all or something weird. */
		return 0;
	}

	new_max_sectors_kb = max_hw_sectors_kb;

	/* Don't increase IO request size limit past 16MB.  It is
	 * about PTLRPC_MAX_BRW_SIZE, but that isn't in a public
	 * header.  Note that even though the block layer allows
	 * larger values, setting max_sectors_kb = 32768 causes
	 * crashes (LU-6974). */
	if (new_max_sectors_kb > 16 * 1024)
		new_max_sectors_kb = 16 * 1024;

have_new_max_sectors_kb:
	snprintf(path, sizeof(path), "%s/%s", sys_path, MAX_SECTORS_KB_PATH);
	rc = read_file(path, buf, sizeof(buf));
	if (rc != 0) {
		/* No MAX_SECTORS_KB_PATH isn't necessary an error for
		 * some devices. */
		return 0;
	}

	old_max_sectors_kb = strtoul(buf, NULL, 0);
	if (old_max_sectors_kb == 0 || old_max_sectors_kb == ULLONG_MAX) {
		/* No digits at all or something weird. */
		return 0;
	}

	if (new_max_sectors_kb <= old_max_sectors_kb)
		return 0;

	snprintf(buf, sizeof(buf), "%lu", new_max_sectors_kb);
	rc = write_file(path, buf);
	if (rc != 0) {
		if (verbose)
			fprintf(stderr, "warning: cannot write '%s': %s\n",
				path, strerror(errno));
		return rc;
	}

	fprintf(stderr, "%s: increased '%s' from %lu to %lu\n",
		progname, path, old_max_sectors_kb, new_max_sectors_kb);

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

/* This is to tune the kernel for good SCSI performance.
 * For that we set the value of /sys/block/{dev}/queue/max_sectors_kb
 * to the value of /sys/block/{dev}/queue/max_hw_sectors_kb */
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
		/* Ignore errors from tune_max_sectors_kb() and
		 * tune_scheduler(). The worst that will happen is a block
		 * device with an "incorrect" scheduler. */
		tune_max_sectors_kb(real_sys_path, mop);
		tune_block_dev_scheduler(real_sys_path, DEFAULT_SCHEDULER);

		/* If device is multipath device then tune its slave
		 * devices. */
		rc = tune_block_dev_slaves(real_sys_path, mop);
	}

out:
	free(real_sys_path);

	return rc;
}

int ldiskfs_tune_lustre(char *dev, struct mount_opts *mop)
{
	return tune_block_dev(dev, mop);
}

int ldiskfs_label_lustre(struct mount_opts *mop)
{
	char label_cmd[PATH_MAX];
	int rc;

	snprintf(label_cmd, sizeof(label_cmd),
		 TUNE2FS" -f -L '%s' '%s' >/dev/null 2>&1",
		 mop->mo_ldd.ldd_svname, mop->mo_source);
	rc = run_command(label_cmd, sizeof(label_cmd));

	return rc;
}

int ldiskfs_rename_fsname(struct mkfs_opts *mop, const char *oldname)
{
	struct mount_opts opts;
	struct lustre_disk_data *ldd = &mop->mo_ldd;
	char mntpt[] = "/tmp/mntXXXXXX";
	char *dev;
	int ret;

	/* Change the filesystem label. */
	opts.mo_ldd = *ldd;
	opts.mo_source = mop->mo_device;
	ret = ldiskfs_label_lustre(&opts);
	if (ret) {
		if (errno != 0)
			ret = errno;
		fprintf(stderr, "Can't change filesystem label: %s\n",
			strerror(ret));
		return ret;
	}

	/* Mount this device temporarily in order to write these files */
	if (mkdtemp(mntpt) == NULL) {
		if (errno != 0)
			ret = errno;
		else
			ret = EINVAL;
		fprintf(stderr, "Can't create temp mount point %s: %s\n",
			mntpt, strerror(ret));
		return ret;
	}

	if (mop->mo_flags & MO_IS_LOOP)
		dev = mop->mo_loopdev;
	else
		dev = mop->mo_device;
	ret = mount(dev, mntpt, MT_STR(ldd), 0, ldd->ldd_mount_opts);
	if (ret) {
		if (errno != 0)
			ret = errno;
		fprintf(stderr, "Unable to mount %s: %s\n",
			dev, strerror(ret));
		if (ret == ENODEV)
			fprintf(stderr, "Is the %s module available?\n",
				MT_STR(ldd));
		goto out_rmdir;
	}

	ret = lustre_rename_fsname(mop, mntpt, oldname);
	umount(mntpt);

out_rmdir:
	rmdir(mntpt);
	return ret;
}

/* Enable quota accounting */
int ldiskfs_enable_quota(struct mkfs_opts *mop)
{
	char *dev;
	char cmd[512];
	int cmdsz = sizeof(cmd), ret;

	if (!is_e2fsprogs_feature_supp("-O quota")) {
		fprintf(stderr, "%s: \"-O quota\" is is not supported by "
			"current e2fsprogs\n", progname);
		return EINVAL;
	}

	dev = mop->mo_device;
	if (mop->mo_flags & MO_IS_LOOP)
		dev = mop->mo_loopdev;

	/* Quota feature is already enabled? */
	if (!backfs)
		ext2fs_open(dev, open_flags, 0, 0, unix_io_manager, &backfs);
	if (backfs && ext2fs_has_feature_quota(backfs->super)) {
		vprint("Quota feature is already enabled.\n");
		return 0;
	}

	/* Turn on quota feature by "tune2fs -O quota" */
	snprintf(cmd, cmdsz, "%s -O quota %s", TUNE2FS, dev);
	ret = run_command(cmd, cmdsz);
	if (ret)
		fprintf(stderr, "command:%s (%d)", cmd, ret);

	return ret;
}

int ldiskfs_init(void)
{
	/* Required because full path to DEBUGFS is not specified */
	setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin", 0);

	return 0;
}

void ldiskfs_fini(void)
{
	if (backfs) {
		ext2fs_close(backfs);
		backfs = NULL;
	}
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
	.enable_quota		= ldiskfs_enable_quota,
	.rename_fsname		= ldiskfs_rename_fsname,
};
#endif /* PLUGIN_DIR */
