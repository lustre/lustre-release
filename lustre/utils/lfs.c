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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/utils/lfs.c
 *
 * Author: Peter J. Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Robert Read <rread@clusterfs.com>
 */

/* for O_DIRECTORY */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <mntent.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <pwd.h>
#include <grp.h>
#include <sys/ioctl.h>
#include <sys/quota.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>

#include <libcfs/util/string.h>
#include <libcfs/util/ioctl.h>
#include <libcfs/util/parser.h>
#include <lustre/lustreapi.h>
#include <lustre_ver.h>
#include <linux/lustre_param.h>

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(a) ((sizeof(a)) / (sizeof((a)[0])))
#endif /* !ARRAY_SIZE */

/* all functions */
static int lfs_setstripe(int argc, char **argv);
static int lfs_find(int argc, char **argv);
static int lfs_getstripe(int argc, char **argv);
static int lfs_getdirstripe(int argc, char **argv);
static int lfs_setdirstripe(int argc, char **argv);
static int lfs_rmentry(int argc, char **argv);
static int lfs_osts(int argc, char **argv);
static int lfs_mdts(int argc, char **argv);
static int lfs_df(int argc, char **argv);
static int lfs_getname(int argc, char **argv);
static int lfs_check(int argc, char **argv);
#ifdef HAVE_SYS_QUOTA_H
static int lfs_setquota(int argc, char **argv);
static int lfs_quota(int argc, char **argv);
#endif
static int lfs_flushctx(int argc, char **argv);
static int lfs_cp(int argc, char **argv);
static int lfs_ls(int argc, char **argv);
static int lfs_poollist(int argc, char **argv);
static int lfs_changelog(int argc, char **argv);
static int lfs_changelog_clear(int argc, char **argv);
static int lfs_fid2path(int argc, char **argv);
static int lfs_path2fid(int argc, char **argv);
static int lfs_data_version(int argc, char **argv);
static int lfs_hsm_state(int argc, char **argv);
static int lfs_hsm_set(int argc, char **argv);
static int lfs_hsm_clear(int argc, char **argv);
static int lfs_hsm_action(int argc, char **argv);
static int lfs_hsm_archive(int argc, char **argv);
static int lfs_hsm_restore(int argc, char **argv);
static int lfs_hsm_release(int argc, char **argv);
static int lfs_hsm_remove(int argc, char **argv);
static int lfs_hsm_cancel(int argc, char **argv);
static int lfs_swap_layouts(int argc, char **argv);
static int lfs_mv(int argc, char **argv);
static int lfs_ladvise(int argc, char **argv);
static int lfs_list_commands(int argc, char **argv);

/* Setstripe and migrate share mostly the same parameters */
#define SSM_CMD_COMMON(cmd) \
	"usage: "cmd" [--component-end|-E <comp_end>]\n"		\
	"                 [--stripe-count|-c <stripe_count>]\n"		\
	"                 [--stripe-index|-i <start_ost_idx>]\n"	\
	"                 [--stripe-size|-S <stripe_size>]\n"		\
	"                 [--pool|-p <pool_name>]\n"			\
	"                 [--ost|-o <ost_indices>]\n"

#define SSM_HELP_COMMON \
	"\tstripe_count: Number of OSTs to stripe over (0=fs default, -1 all)\n" \
	"\tstart_ost_idx: OST index of first stripe (-1=default round robin)\n"\
	"\tstripe_size:  Number of bytes on each OST (0=fs default)\n" \
	"\t              Can be specified with K, M or G (for KB, MB, GB\n" \
	"\t              respectively)\n"				\
	"\tpool_name:    Name of OST pool to use (default none)\n"	\
	"\tost_indices:  List of OST indices, can be repeated multiple times\n"\
	"\t              Indices be specified in a format of:\n"	\
	"\t                -o <ost_1>,<ost_i>-<ost_j>,<ost_n>\n"	\
	"\t              Or:\n"						\
	"\t                -o <ost_1> -o <ost_i>-<ost_j> -o <ost_n>\n"	\
	"\t              If --pool is set with --ost, then the OSTs\n"	\
	"\t              must be the members of the pool.\n"		\
	"\tcomp_end:     Extent end of component, start after previous end.\n"\
	"\t              Can be specified with K, M or G (for KB, MB, GB\n" \
	"\t              respectively, -1 for EOF). Must be a multiple of\n"\
	"\t              stripe_size.\n"


#define MIGRATE_USAGE							\
	SSM_CMD_COMMON("migrate  ")					\
	"                 [--block|-b]\n"				\
	"                 [--non-block|-n]\n"				\
	"                 <filename>\n"					\
	SSM_HELP_COMMON							\
	"\n"								\
	"\tblock:        Block file access during data migration (default)\n" \
	"\tnon-block:    Abort migrations if concurrent access is detected\n" \

#define SETDIRSTRIPE_USAGE					\
	"		[--mdt-count|-c stripe_count>\n"	\
	"		[--mdt-index|-i mdt_index]\n"		\
	"		[--mdt-hash|-H mdt_hash]\n"		\
	"		[--default|-D] [--mode|-m mode] <dir>\n"	\
	"\tstripe_count: stripe count of the striped directory\n"	\
	"\tmdt_index: MDT index of first stripe\n"			\
	"\tmdt_hash:  hash type of the striped directory. mdt types:\n"	\
	"	fnv_1a_64 FNV-1a hash algorithm (default)\n"		\
	"	all_char  sum of characters % MDT_COUNT (not recommended)\n" \
	"\tdefault_stripe: set default dirstripe of the directory\n"	\
	"\tmode: the mode of the directory\n"

static const char	*progname;
static bool		 file_lease_supported = true;

/* all available commands */
command_t cmdlist[] = {
	{"setstripe", lfs_setstripe, 0,
	 "To create a file with specified striping/composite layout, or\n"
	 "create/replace the default layout on an existing directory:\n"
	 SSM_CMD_COMMON("setstripe")
	 "                 <directory|filename>\n"
	 " or\n"
	 "To add component(s) to an existing composite file:\n"
	 SSM_CMD_COMMON("setstripe --component-add")
	 SSM_HELP_COMMON
	 "To totally delete the default striping from an existing directory:\n"
	 "usage: setstripe -d <directory>\n"
	 " or\n"
	 "To delete the last component(s) from an existing composite file\n"
	 "(note that this will also delete any data in those components):\n"
	 "usage: setstripe --component-del [--component-id|-I <comp_id>]\n"
	 "                               [--component-flags|-F <comp_flags>]\n"
	 "                               <filename>\n"
	 "\tcomp_id:     Unique component ID to delete\n"
	 "\tcomp_flags:  'init' indicating all instantiated components\n"
	 "\t             '^init' indicating all uninstantiated components\n"
	 "\t-I and -F cannot be specified at the same time\n"},
	{"getstripe", lfs_getstripe, 0,
	 "To list the striping info for a given file or files in a\n"
	 "directory or recursively for all files in a directory tree.\n"
	 "usage: getstripe [--ost|-O <uuid>] [--quiet|-q] [--verbose|-v]\n"
	 "		   [--stripe-count|-c] [--stripe-index|-i]\n"
	 "		   [--pool|-p] [--stripe-size|-S] [--directory|-d]\n"
	 "		   [--mdt|-m] [--recursive|-r] [--raw|-R] [--yaml|-y]\n"
	 "		   [--layout|-L] [--fid|-F] [--generation|-g]\n"
	 "		   [--component-id[=comp_id]|-I[comp_id]]\n"
	 "		   [--component-flags[=comp_flags]]\n"
	 "		   [--component-count]\n"
	 "		   [--component-start[=[+-]comp_start]]\n"
	 "		   [--component-end[=[+-]comp_end]|-E[[+-]comp_end]]\n"
	 "		   <directory|filename> ..."},
	{"setdirstripe", lfs_setdirstripe, 0,
	 "To create a striped directory on a specified MDT. This can only\n"
	 "be done on MDT0 with the right of administrator.\n"
	 "usage: setdirstripe [OPTION] <directory>\n"
	 SETDIRSTRIPE_USAGE},
	{"getdirstripe", lfs_getdirstripe, 0,
	 "To list the striping info for a given directory\n"
	 "or recursively for all directories in a directory tree.\n"
	 "usage: getdirstripe [--obd|-O <uuid>] [--mdt-count|-c]\n"
	 "		      [--mdt-index|-i] [--mdt-hash|-t]\n"
	 "		      [--recursive|-r] [--yaml|-y]\n"
	 "		      [--default|-D] <dir> ..."},
	{"mkdir", lfs_setdirstripe, 0,
	 "To create a striped directory on a specified MDT. This can only\n"
	 "be done on MDT0 with the right of administrator.\n"
	 "usage: mkdir [OPTION] <directory>\n"
	 SETDIRSTRIPE_USAGE},
	{"rm_entry", lfs_rmentry, 0,
	 "To remove the name entry of the remote directory. Note: This\n"
	 "command will only delete the name entry, i.e. the remote directory\n"
	 "will become inaccessable after this command. This can only be done\n"
	 "by the administrator\n"
	 "usage: rm_entry <dir>\n"},
        {"pool_list", lfs_poollist, 0,
         "List pools or pool OSTs\n"
         "usage: pool_list <fsname>[.<pool>] | <pathname>\n"},
        {"find", lfs_find, 0,
         "find files matching given attributes recursively in directory tree.\n"
         "usage: find <directory|filename> ...\n"
         "     [[!] --atime|-A [+-]N] [[!] --ctime|-C [+-]N]\n"
         "     [[!] --mtime|-M [+-]N] [[!] --mdt|-m <uuid|index,...>]\n"
         "     [--maxdepth|-D N] [[!] --name|-n <pattern>]\n"
         "     [[!] --ost|-O <uuid|index,...>] [--print|-p] [--print0|-P]\n"
         "     [[!] --size|-s [+-]N[bkMGTPE]]\n"
         "     [[!] --stripe-count|-c [+-]<stripes>]\n"
         "     [[!] --stripe-index|-i <index,...>]\n"
         "     [[!] --stripe-size|-S [+-]N[kMGT]] [[!] --type|-t <filetype>]\n"
         "     [[!] --gid|-g|--group|-G <gid>|<gname>]\n"
         "     [[!] --uid|-u|--user|-U <uid>|<uname>] [[!] --pool <pool>]\n"
	 "     [[!] --projid <projid>]\n"
	 "     [[!] --layout|-L released,raid0]\n"
	 "     [[!] --component-count [+-]<comp_cnt>]\n"
	 "     [[!] --component-start [+-]N[kMGTPE]]\n"
	 "     [[!] --component-end|-E [+-]N[kMGTPE]]\n"
	 "     [[!] --component-flags <comp_flags>]\n"
	 "     [[!] --mdt-count|-T [+-]<stripes>]\n"
	 "     [[!] --mdt-hash|-H <hashtype>\n"
         "\t !: used before an option indicates 'NOT' requested attribute\n"
         "\t -: used before a value indicates less than requested value\n"
         "\t +: used before a value indicates more than requested value\n"
	 "\tmdt-hash:	hash type of the striped directory.\n"
	 "\t		fnv_1a_64 FNV-1a hash algorithm\n"
	 "\t		all_char  sum of characters % MDT_COUNT\n"},
        {"check", lfs_check, 0,
         "Display the status of MDS or OSTs (as specified in the command)\n"
         "or all the servers (MDS and OSTs).\n"
         "usage: check <osts|mds|servers>"},
        {"osts", lfs_osts, 0, "list OSTs connected to client "
         "[for specified path only]\n" "usage: osts [path]"},
        {"mdts", lfs_mdts, 0, "list MDTs connected to client "
         "[for specified path only]\n" "usage: mdts [path]"},
        {"df", lfs_df, 0,
         "report filesystem disk space usage or inodes usage"
         "of each MDS and all OSDs or a batch belonging to a specific pool .\n"
         "Usage: df [-i] [-h] [--lazy|-l] [--pool|-p <fsname>[.<pool>] [path]"},
        {"getname", lfs_getname, 0, "list instances and specified mount points "
         "[for specified path only]\n"
         "Usage: getname [-h]|[path ...] "},
#ifdef HAVE_SYS_QUOTA_H
        {"setquota", lfs_setquota, 0, "Set filesystem quotas.\n"
	 "usage: setquota <-u|-g|-p> <uname>|<uid>|<gname>|<gid>|<projid>\n"
         "                -b <block-softlimit> -B <block-hardlimit>\n"
         "                -i <inode-softlimit> -I <inode-hardlimit> <filesystem>\n"
	 "       setquota <-u|--user|-g|--group|-p|--projid> <uname>|<uid>|<gname>|<gid>|<projid>\n"
         "                [--block-softlimit <block-softlimit>]\n"
         "                [--block-hardlimit <block-hardlimit>]\n"
         "                [--inode-softlimit <inode-softlimit>]\n"
         "                [--inode-hardlimit <inode-hardlimit>] <filesystem>\n"
	 "       setquota [-t] <-u|--user|-g|--group|-p|--projid>\n"
         "                [--block-grace <block-grace>]\n"
         "                [--inode-grace <inode-grace>] <filesystem>\n"
         "       -b can be used instead of --block-softlimit/--block-grace\n"
         "       -B can be used instead of --block-hardlimit\n"
         "       -i can be used instead of --inode-softlimit/--inode-grace\n"
	 "       -I can be used instead of --inode-hardlimit\n\n"
	 "Note: The total quota space will be split into many qunits and\n"
	 "      balanced over all server targets, the minimal qunit size is\n"
	 "      1M bytes for block space and 1K inodes for inode space.\n\n"
	 "      Quota space rebalancing process will stop when this mininum\n"
	 "      value is reached. As a result, quota exceeded can be returned\n"
	 "      while many targets still have 1MB or 1K inodes of spare\n"
	 "      quota space."},
        {"quota", lfs_quota, 0, "Display disk usage and limits.\n"
	 "usage: quota [-q] [-v] [-h] [-o <obd_uuid>|-i <mdt_idx>|-I "
		       "<ost_idx>]\n"
	 "             [<-u|-g|-p> <uname>|<uid>|<gname>|<gid>|<projid>] <filesystem>\n"
	 "       quota [-o <obd_uuid>|-i <mdt_idx>|-I <ost_idx>] -t <-u|-g|-p> <filesystem>"},
#endif
        {"flushctx", lfs_flushctx, 0, "Flush security context for current user.\n"
         "usage: flushctx [-k] [mountpoint...]"},
        {"cp", lfs_cp, 0,
         "Remote user copy files and directories.\n"
         "usage: cp [OPTION]... [-T] SOURCE DEST\n\tcp [OPTION]... SOURCE... DIRECTORY\n\tcp [OPTION]... -t DIRECTORY SOURCE..."},
        {"ls", lfs_ls, 0,
         "Remote user list directory contents.\n"
         "usage: ls [OPTION]... [FILE]..."},
        {"changelog", lfs_changelog, 0,
         "Show the metadata changes on an MDT."
         "\nusage: changelog <mdtname> [startrec [endrec]]"},
        {"changelog_clear", lfs_changelog_clear, 0,
         "Indicate that old changelog records up to <endrec> are no longer of "
         "interest to consumer <id>, allowing the system to free up space.\n"
         "An <endrec> of 0 means all records.\n"
         "usage: changelog_clear <mdtname> <id> <endrec>"},
	{"fid2path", lfs_fid2path, 0,
	 "Resolve the full path(s) for given FID(s). For a specific hardlink "
	 "specify link number <linkno>.\n"
	/* "For a historical link name, specify changelog record <recno>.\n" */
	 "usage: fid2path [--link <linkno>] <fsname|rootpath> <fid> ..."
		/* [ --rec <recno> ] */ },
	{"path2fid", lfs_path2fid, 0, "Display the fid(s) for a given path(s).\n"
	 "usage: path2fid [--parents] <path> ..."},
	{"data_version", lfs_data_version, 0, "Display file data version for "
	 "a given path.\n" "usage: data_version -[n|r|w] <path>"},
	{"hsm_state", lfs_hsm_state, 0, "Display the HSM information (states, "
	 "undergoing actions) for given files.\n usage: hsm_state <file> ..."},
	{"hsm_set", lfs_hsm_set, 0, "Set HSM user flag on specified files.\n"
	 "usage: hsm_set [--norelease] [--noarchive] [--dirty] [--exists] "
	 "[--archived] [--lost] [--archive-id NUM] <file> ..."},
	{"hsm_clear", lfs_hsm_clear, 0, "Clear HSM user flag on specified "
	 "files.\n"
	 "usage: hsm_clear [--norelease] [--noarchive] [--dirty] [--exists] "
	 "[--archived] [--lost] <file> ..."},
	{"hsm_action", lfs_hsm_action, 0, "Display current HSM request for "
	 "given files.\n" "usage: hsm_action <file> ..."},
	{"hsm_archive", lfs_hsm_archive, 0,
	 "Archive file to external storage.\n"
	 "usage: hsm_archive [--filelist FILELIST] [--data DATA] [--archive NUM] "
	 "<file> ..."},
	{"hsm_restore", lfs_hsm_restore, 0,
	 "Restore file from external storage.\n"
	 "usage: hsm_restore [--filelist FILELIST] [--data DATA] <file> ..."},
	{"hsm_release", lfs_hsm_release, 0,
	 "Release files from Lustre.\n"
	 "usage: hsm_release [--filelist FILELIST] [--data DATA] <file> ..."},
	{"hsm_remove", lfs_hsm_remove, 0,
	 "Remove file copy from external storage.\n"
	 "usage: hsm_remove [--filelist FILELIST] [--data DATA]\n"
	 "                  [--mntpath MOUNTPATH] [--archive NUM] <file|FID> ...\n"
	 "\n"
	 "Note: To remove files from the archive that have been deleted on\n"
	 "Lustre, set mntpath and optionally archive. In that case, all the\n"
	 "positional arguments and entries in the file list must be FIDs."
	},
	{"hsm_cancel", lfs_hsm_cancel, 0,
	 "Cancel requests related to specified files.\n"
	 "usage: hsm_cancel [--filelist FILELIST] [--data DATA] <file> ..."},
	{"swap_layouts", lfs_swap_layouts, 0, "Swap layouts between 2 files.\n"
	 "usage: swap_layouts <path1> <path2>"},
	{"migrate", lfs_setstripe, 0,
	 "migrate a directory between MDTs.\n"
	 "usage: migrate --mdt-index <mdt_idx> [--verbose|-v] "
	 "<directory>\n"
	 "\tmdt_idx:      index of the destination MDT\n"
	 "\n"
	 "migrate file objects from one OST "
	 "layout\nto another (may be not safe with concurent writes).\n"
	 "usage: migrate  "
	 "[--stripe-count|-c] <stripe_count>\n"
	 "		[--stripe-index|-i] <start_ost_index>\n"
	 "		[--stripe-size|-S] <stripe_size>\n"
	 "		[--pool|-p] <pool_name>\n"
	 "		[--ost-list|-o] <ost_indices>\n"
	 "		[--block|-b]\n"
	 "		[--non-block|-n]\n"
	 "		<file|directory>\n"
	 "\tstripe_count:     number of OSTs to stripe a file over\n"
	 "\tstripe_ost_index: index of the first OST to stripe a file over\n"
	 "\tstripe_size:      number of bytes to store before moving to the next OST\n"
	 "\tpool_name:        name of the predefined pool of OSTs\n"
	 "\tost_indices:      OSTs to stripe over, in order\n"
	 "\tblock:            wait for the operation to return before continuing\n"
	 "\tnon-block:        do not wait for the operation to return.\n"},
	{"mv", lfs_mv, 0,
	 "To move directories between MDTs. This command is deprecated, "
	 "use \"migrate\" instead.\n"
	 "usage: mv <directory|filename> [--mdt-index|-M] <mdt_index> "
	 "[--verbose|-v]\n"},
	{"ladvise", lfs_ladvise, 0,
	 "Provide servers with advice about access patterns for a file.\n"
	 "usage: ladvise [--advice|-a ADVICE] [--start|-s START[kMGT]]\n"
	 "               [--background|-b]\n"
	 "               {[--end|-e END[kMGT]] | [--length|-l LENGTH[kMGT]]}\n"
	 "               <file> ...\n"},
	{"help", Parser_help, 0, "help"},
	{"exit", Parser_quit, 0, "quit"},
	{"quit", Parser_quit, 0, "quit"},
	{"--version", Parser_version, 0,
	 "output build version of the utility and exit"},
	{"--list-commands", lfs_list_commands, 0,
	 "list commands supported by the utility and exit"},
	{ 0, 0, 0, NULL }
};


#define MIGRATION_NONBLOCK	1

static int check_hashtype(const char *hashtype)
{
	int i;

	for (i = LMV_HASH_TYPE_ALL_CHARS; i < LMV_HASH_TYPE_MAX; i++)
		if (strcmp(hashtype, mdt_hash_name[i]) == 0)
			return i;

	return 0;
}

/**
 * Internal helper for migrate_copy_data(). Check lease and report error if
 * need be.
 *
 * \param[in]  fd           File descriptor on which to check the lease.
 * \param[out] lease_broken Set to true if the lease was broken.
 * \param[in]  group_locked Whether a group lock was taken or not.
 * \param[in]  path         Name of the file being processed, for error
 *			    reporting
 *
 * \retval 0       Migration can keep on going.
 * \retval -errno  Error occurred, abort migration.
 */
static int check_lease(int fd, bool *lease_broken, bool group_locked,
		       const char *path)
{
	int rc;

	if (!file_lease_supported)
		return 0;

	rc = llapi_lease_check(fd);
	if (rc > 0)
		return 0; /* llapi_check_lease returns > 0 on success. */

	if (!group_locked) {
		fprintf(stderr, "%s: cannot migrate '%s': file busy\n",
			progname, path);
		rc = rc ? rc : -EAGAIN;
	} else {
		fprintf(stderr, "%s: external attempt to access file '%s' "
			"blocked until migration ends.\n", progname, path);
		rc = 0;
	}
	*lease_broken = true;
	return rc;
}

static int migrate_copy_data(int fd_src, int fd_dst, size_t buf_size,
			     bool group_locked, const char *fname)
{
	void	*buf = NULL;
	ssize_t	 rsize = -1;
	ssize_t	 wsize = 0;
	size_t	 rpos = 0;
	size_t	 wpos = 0;
	off_t	 bufoff = 0;
	int	 rc;
	bool	 lease_broken = false;

	/* Use a page-aligned buffer for direct I/O */
	rc = posix_memalign(&buf, getpagesize(), buf_size);
	if (rc != 0)
		return -rc;

	while (1) {
		/* read new data only if we have written all
		 * previously read data */
		if (wpos == rpos) {
			if (!lease_broken) {
				rc = check_lease(fd_src, &lease_broken,
						 group_locked, fname);
				if (rc < 0)
					goto out;
			}
			rsize = read(fd_src, buf, buf_size);
			if (rsize < 0) {
				rc = -errno;
				fprintf(stderr, "%s: %s: read failed: %s\n",
					progname, fname, strerror(-rc));
				goto out;
			}
			rpos += rsize;
			bufoff = 0;
		}
		/* eof ? */
		if (rsize == 0)
			break;

		wsize = write(fd_dst, buf + bufoff, rpos - wpos);
		if (wsize < 0) {
			rc = -errno;
			fprintf(stderr,
				"%s: %s: write failed on volatile: %s\n",
				progname, fname, strerror(-rc));
			goto out;
		}
		wpos += wsize;
		bufoff += wsize;
	}

	rc = fsync(fd_dst);
	if (rc < 0) {
		rc = -errno;
		fprintf(stderr, "%s: %s: fsync failed: %s\n",
			progname, fname, strerror(-rc));
	}

out:
	free(buf);
	return rc;
}

static int migrate_copy_timestamps(int fdv, const struct stat *st)
{
	struct timeval	tv[2] = {
		{.tv_sec = st->st_atime},
		{.tv_sec = st->st_mtime}
	};

	return futimes(fdv, tv);
}

static int migrate_block(int fd, int fdv, const struct stat *st,
			 size_t buf_size, const char *name)
{
	__u64	dv1;
	int	gid;
	int	rc;
	int	rc2;

	rc = llapi_get_data_version(fd, &dv1, LL_DV_RD_FLUSH);
	if (rc < 0) {
		fprintf(stderr, "%s: %s: cannot get dataversion: %s\n",
			progname, name, strerror(-rc));
		return rc;
	}

	do
		gid = random();
	while (gid == 0);

	/* The grouplock blocks all concurrent accesses to the file.
	 * It has to be taken after llapi_get_data_version as it would
	 * block it too. */
	rc = llapi_group_lock(fd, gid);
	if (rc < 0) {
		fprintf(stderr, "%s: %s: cannot get group lock: %s\n",
			progname, name, strerror(-rc));
		return rc;
	}

	rc = migrate_copy_data(fd, fdv, buf_size, true, name);
	if (rc < 0) {
		fprintf(stderr, "%s: %s: data copy failed\n", progname, name);
		goto out_unlock;
	}

	/* Make sure we keep original atime/mtime values */
	rc = migrate_copy_timestamps(fdv, st);
	if (rc < 0) {
		fprintf(stderr, "%s: %s: timestamp copy failed\n",
			progname, name);
		goto out_unlock;
	}

	/* swap layouts
	 * for a migration we need to check data version on file did
	 * not change.
	 *
	 * Pass in gid=0 since we already own grouplock. */
	rc = llapi_fswap_layouts_grouplock(fd, fdv, dv1, 0, 0,
					   SWAP_LAYOUTS_CHECK_DV1);
	if (rc == -EAGAIN) {
		fprintf(stderr, "%s: %s: dataversion changed during copy, "
			"migration aborted\n", progname, name);
		goto out_unlock;
	} else if (rc < 0) {
		fprintf(stderr, "%s: %s: cannot swap layouts: %s\n", progname,
			name, strerror(-rc));
		goto out_unlock;
	}

out_unlock:
	rc2 = llapi_group_unlock(fd, gid);
	if (rc2 < 0 && rc == 0) {
		fprintf(stderr, "%s: %s: putting group lock failed: %s\n",
			progname, name, strerror(-rc2));
		rc = rc2;
	}

	return rc;
}

static int migrate_nonblock(int fd, int fdv, const struct stat *st,
			    size_t buf_size, const char *name)
{
	__u64	dv1;
	__u64	dv2;
	int	rc;

	rc = llapi_get_data_version(fd, &dv1, LL_DV_RD_FLUSH);
	if (rc < 0) {
		fprintf(stderr, "%s: %s: cannot get data version: %s\n",
			progname, name, strerror(-rc));
		return rc;
	}

	rc = migrate_copy_data(fd, fdv, buf_size, false, name);
	if (rc < 0) {
		fprintf(stderr, "%s: %s: data copy failed\n", progname, name);
		return rc;
	}

	rc = llapi_get_data_version(fd, &dv2, LL_DV_RD_FLUSH);
	if (rc != 0) {
		fprintf(stderr, "%s: %s: cannot get data version: %s\n",
			progname, name, strerror(-rc));
		return rc;
	}

	if (dv1 != dv2) {
		rc = -EAGAIN;
		fprintf(stderr, "%s: %s: data version changed during "
				"migration\n",
			progname, name);
		return rc;
	}

	/* Make sure we keep original atime/mtime values */
	rc = migrate_copy_timestamps(fdv, st);
	if (rc < 0) {
		fprintf(stderr, "%s: %s: timestamp copy failed\n",
			progname, name);
		return rc;
	}

	/* Atomically put lease, swap layouts and close.
	 * for a migration we need to check data version on file did
	 * not change. */
	rc = llapi_fswap_layouts(fd, fdv, 0, 0, SWAP_LAYOUTS_CLOSE);
	if (rc < 0) {
		fprintf(stderr, "%s: %s: cannot swap layouts: %s\n",
			progname, name, strerror(-rc));
		return rc;
	}

	return 0;
}

static int lfs_component_set(char *fname, int comp_id, __u32 flags)
{
	return -ENOTSUP;
}

static int lfs_component_del(char *fname, __u32 comp_id, __u32 flags)
{
	int	rc = 0;

	if (flags != 0 && comp_id != 0)
		return -EINVAL;

	/* LCME_FL_INIT is the only supported flag in PFL */
	if (flags != 0) {
		if (flags & ~LCME_KNOWN_FLAGS) {
			fprintf(stderr, "Invalid component flags %#x\n", flags);
			return -EINVAL;
		}
	} else if (comp_id > LCME_ID_MAX) {
		fprintf(stderr, "Invalid component id %u\n", comp_id);
		return -EINVAL;
	}

	rc = llapi_layout_file_comp_del(fname, comp_id, flags);
	if (rc)
		fprintf(stderr, "Delete component %#x from %s failed. %s\n",
			comp_id, fname, strerror(errno));
	return rc;
}

static int lfs_component_add(char *fname, struct llapi_layout *layout)
{
	int	rc;

	if (layout == NULL)
		return -EINVAL;

	rc = llapi_layout_file_comp_add(fname, layout);
	if (rc)
		fprintf(stderr, "Add layout component(s) to %s failed. %s\n",
			fname, strerror(errno));
	return rc;
}

static int lfs_component_create(char *fname, int open_flags, mode_t open_mode,
				struct llapi_layout *layout)
{
	struct stat	st;
	int	fd;

	if (layout == NULL)
		return -EINVAL;

	fd = lstat(fname, &st);
	if (fd == 0 && S_ISDIR(st.st_mode))
		open_flags = O_DIRECTORY | O_RDONLY;

	fd = llapi_layout_file_open(fname, open_flags, open_mode, layout);
	if (fd < 0)
		fprintf(stderr, "%s %s failed. %s\n",
			S_ISDIR(st.st_mode) ?
				"Set default composite layout to " :
				"Create composite file",
			fname, strerror(errno));
	return fd;
}

static int lfs_migrate(char *name, __u64 migration_flags,
		       struct llapi_stripe_param *param,
		       struct llapi_layout *layout)
{
	int			 fd = -1;
	int			 fdv = -1;
	char			 parent[PATH_MAX];
	int			 mdt_index;
	int                      random_value;
	char			 volatile_file[sizeof(parent) +
					       LUSTRE_VOLATILE_HDR_LEN +
					       2 * sizeof(mdt_index) +
					       2 * sizeof(random_value) + 4];
	char			*ptr;
	int			 rc;
	struct lov_user_md	*lum = NULL;
	int			 lum_size;
	int			 buf_size = 1024 * 1024 * 4;
	bool			 have_lease_rdlck = false;
	struct stat		 st;
	struct stat		 stv;

	/* find the right size for the IO and allocate the buffer */
	lum_size = lov_user_md_size(LOV_MAX_STRIPE_COUNT, LOV_USER_MAGIC_V3);
	lum = malloc(lum_size);
	if (lum == NULL) {
		rc = -ENOMEM;
		goto free;
	}

	rc = llapi_file_get_stripe(name, lum);
	/* failure can happen for many reasons and some may be not real errors
	 * (eg: no stripe)
	 * in case of a real error, a later call will fail with better
	 * error management */
	if (rc == 0) {
		if ((lum->lmm_magic == LOV_USER_MAGIC_V1 ||
		     lum->lmm_magic == LOV_USER_MAGIC_V3) &&
		    lum->lmm_stripe_size != 0)
			buf_size = lum->lmm_stripe_size;
	}

	/* open file, direct io */
	/* even if the file is only read, WR mode is nedeed to allow
	 * layout swap on fd */
	fd = open(name, O_RDWR | O_DIRECT);
	if (fd == -1) {
		rc = -errno;
		fprintf(stderr, "%s: %s: cannot open: %s\n", progname, name,
			strerror(-rc));
		goto free;
	}

	if (file_lease_supported) {
		rc = llapi_lease_get(fd, LL_LEASE_RDLCK);
		if (rc == -EOPNOTSUPP) {
			/* Older servers do not support file lease.
			 * Disable related checks. This opens race conditions
			 * as explained in LU-4840 */
			file_lease_supported = false;
		} else if (rc < 0) {
			fprintf(stderr, "%s: %s: cannot get open lease: %s\n",
				progname, name, strerror(-rc));
			goto error;
		} else {
			have_lease_rdlck = true;
		}
	}

	/* search for file directory pathname */
	if (strlen(name) > sizeof(parent)-1) {
		rc = -E2BIG;
		goto error;
	}
	strncpy(parent, name, sizeof(parent));
	ptr = strrchr(parent, '/');
	if (ptr == NULL) {
		if (getcwd(parent, sizeof(parent)) == NULL) {
			rc = -errno;
			goto error;
		}
	} else {
		if (ptr == parent)
			strcpy(parent, "/");
		else
			*ptr = '\0';
	}

	rc = llapi_file_fget_mdtidx(fd, &mdt_index);
	if (rc < 0) {
		fprintf(stderr, "%s: %s: cannot get MDT index: %s\n",
			progname, name, strerror(-rc));
		goto error;
	}

	do {
		int open_flags = O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW;
		mode_t open_mode = S_IRUSR | S_IWUSR;

		random_value = random();
		rc = snprintf(volatile_file, sizeof(volatile_file),
			      "%s/%s:%.4X:%.4X", parent, LUSTRE_VOLATILE_HDR,
			      mdt_index, random_value);
		if (rc >= sizeof(volatile_file)) {
			rc = -E2BIG;
			goto error;
		}

		/* create, open a volatile file, use caching (ie no directio) */
		if (param != NULL)
			fdv = llapi_file_open_param(volatile_file, open_flags,
						    open_mode, param);
		else if (layout != NULL)
			fdv = lfs_component_create(volatile_file, open_flags,
						   open_mode, layout);
		else
			fdv = -EINVAL;
	} while (fdv == -EEXIST);

	if (fdv < 0) {
		rc = fdv;
		fprintf(stderr, "%s: %s: cannot create volatile file in"
				" directory: %s\n",
			progname, parent, strerror(-rc));
		goto error;
	}

	/* In case the MDT does not support creation of volatile files
	 * we should try to unlink it. */
	(void)unlink(volatile_file);

	/* Not-owner (root?) special case.
	 * Need to set owner/group of volatile file like original.
	 * This will allow to pass related check during layout_swap.
	 */
	rc = fstat(fd, &st);
	if (rc != 0) {
		rc = -errno;
		fprintf(stderr, "%s: %s: cannot stat: %s\n", progname, name,
			strerror(errno));
		goto error;
	}
	rc = fstat(fdv, &stv);
	if (rc != 0) {
		rc = -errno;
		fprintf(stderr, "%s: %s: cannot stat: %s\n", progname,
			volatile_file, strerror(errno));
		goto error;
	}
	if (st.st_uid != stv.st_uid || st.st_gid != stv.st_gid) {
		rc = fchown(fdv, st.st_uid, st.st_gid);
		if (rc != 0) {
			rc = -errno;
			fprintf(stderr, "%s: %s: cannot chown: %s\n", progname,
				name, strerror(errno));
			goto error;
		}
	}

	if (migration_flags & MIGRATION_NONBLOCK && file_lease_supported) {
		rc = migrate_nonblock(fd, fdv, &st, buf_size, name);
		if (rc == 0) {
			have_lease_rdlck = false;
			fdv = -1; /* The volatile file is closed as we put the
				   * lease in non-blocking mode. */
		}
	} else {
		/* Blocking mode (forced if servers do not support file lease).
		 * It is also the default mode, since we cannot distinguish
		 * between a broken lease and a server that does not support
		 * atomic swap/close (LU-6785) */
		rc = migrate_block(fd, fdv, &st, buf_size, name);
	}

error:
	if (have_lease_rdlck)
		llapi_lease_put(fd);

	if (fd >= 0)
		close(fd);

	if (fdv >= 0)
		close(fdv);

free:
	if (lum)
		free(lum);

	return rc;
}

/**
 * Parse a string containing an OST index list into an array of integers.
 *
 * The input string contains a comma delimited list of individual
 * indices and ranges, for example "1,2-4,7". Add the indices into the
 * \a osts array and remove duplicates.
 *
 * \param[out] osts    array to store indices in
 * \param[in] size     size of \a osts array
 * \param[in] offset   starting index in \a osts
 * \param[in] arg      string containing OST index list
 *
 * \retval positive    number of indices in \a osts
 * \retval -EINVAL     unable to parse \a arg
 */
static int parse_targets(__u32 *osts, int size, int offset, char *arg)
{
	int rc;
	int nr = offset;
	int slots = size - offset;
	char *ptr = NULL;
	bool end_of_loop;

	if (arg == NULL)
		return -EINVAL;

	end_of_loop = false;
	while (!end_of_loop) {
		int start_index;
		int end_index;
		int i;
		char *endptr = NULL;

		rc = -EINVAL;

		ptr = strchrnul(arg, ',');

		end_of_loop = *ptr == '\0';
		*ptr = '\0';

		start_index = strtol(arg, &endptr, 0);
		if (endptr == arg) /* no data at all */
			break;
		if (*endptr != '-' && *endptr != '\0') /* has invalid data */
			break;
		if (start_index < 0)
			break;

		end_index = start_index;
		if (*endptr == '-') {
			end_index = strtol(endptr + 1, &endptr, 0);
			if (*endptr != '\0')
				break;
			if (end_index < start_index)
				break;
		}

		for (i = start_index; i <= end_index && slots > 0; i++) {
			int j;

			/* remove duplicate */
			for (j = 0; j < offset; j++) {
				if (osts[j] == i)
					break;
			}
			if (j == offset) { /* no duplicate */
				osts[nr++] = i;
				--slots;
			}
		}
		if (slots == 0 && i < end_index)
			break;

		*ptr = ',';
		arg = ++ptr;
		offset = nr;
		rc = 0;
	}
	if (!end_of_loop && ptr != NULL)
		*ptr = ',';

	return rc < 0 ? rc : nr;
}

struct lfs_setstripe_args {
	unsigned long long	 lsa_comp_end;
	unsigned long long	 lsa_stripe_size;
	int			 lsa_stripe_count;
	int			 lsa_stripe_off;
	__u32			 lsa_comp_flags;
	int			 lsa_nr_osts;
	__u32			*lsa_osts;
	char			*lsa_pool_name;
};

static inline void setstripe_args_init(struct lfs_setstripe_args *lsa)
{
	memset(lsa, 0, sizeof(*lsa));
	lsa->lsa_stripe_off = -1;
}

static inline bool setstripe_args_specified(struct lfs_setstripe_args *lsa)
{
	return (lsa->lsa_stripe_size != 0 || lsa->lsa_stripe_count != 0 ||
		lsa->lsa_stripe_off != -1 || lsa->lsa_pool_name != NULL ||
		lsa->lsa_comp_end != 0);
}

static int comp_args_to_layout(struct llapi_layout **composite,
			       struct lfs_setstripe_args *lsa)
{
	struct llapi_layout *layout = *composite;
	uint64_t prev_end = 0;
	int i = 0, rc;

	if (layout == NULL) {
		layout = llapi_layout_alloc();
		if (layout == NULL) {
			fprintf(stderr, "Alloc llapi_layout failed. %s\n",
				strerror(errno));
			return -ENOMEM;
		}
		*composite = layout;
	} else {
		uint64_t start;

		/* Get current component extent, current component
		 * must be the tail component. */
		rc = llapi_layout_comp_extent_get(layout, &start, &prev_end);
		if (rc) {
			fprintf(stderr, "Get comp extent failed. %s\n",
				strerror(errno));
			return rc;
		}

		rc = llapi_layout_comp_add(layout);
		if (rc) {
			fprintf(stderr, "Add component failed. %s\n",
				strerror(errno));
			return rc;
		}
	}

	rc = llapi_layout_comp_extent_set(layout, prev_end, lsa->lsa_comp_end);
	if (rc) {
		fprintf(stderr, "Set extent [%lu, %llu) failed. %s\n",
			prev_end, lsa->lsa_comp_end, strerror(errno));
		return rc;
	}

	if (lsa->lsa_stripe_size != 0) {
		rc = llapi_layout_stripe_size_set(layout,
						  lsa->lsa_stripe_size);
		if (rc) {
			fprintf(stderr, "Set stripe size %llu failed. %s\n",
				lsa->lsa_stripe_size, strerror(errno));
			return rc;
		}
	}

	if (lsa->lsa_stripe_count != 0) {
		rc = llapi_layout_stripe_count_set(layout,
						   lsa->lsa_stripe_count == -1 ?
						   LLAPI_LAYOUT_WIDE :
						   lsa->lsa_stripe_count);
		if (rc) {
			fprintf(stderr, "Set stripe count %d failed. %s\n",
				lsa->lsa_stripe_count, strerror(errno));
			return rc;
		}
	}

	if (lsa->lsa_pool_name != NULL) {
		rc = llapi_layout_pool_name_set(layout, lsa->lsa_pool_name);
		if (rc) {
			fprintf(stderr, "Set pool name: %s failed. %s\n",
				lsa->lsa_pool_name, strerror(errno));
			return rc;
		}
	}

	if (lsa->lsa_nr_osts > 0) {
		if (lsa->lsa_stripe_count > 0 &&
		    lsa->lsa_nr_osts != lsa->lsa_stripe_count) {
			fprintf(stderr, "stripe_count(%d) != nr_osts(%d)\n",
				lsa->lsa_stripe_count, lsa->lsa_nr_osts);
			return -EINVAL;
		}
		for (i = 0; i < lsa->lsa_nr_osts; i++) {
			rc = llapi_layout_ost_index_set(layout, i,
							lsa->lsa_osts[i]);
			if (rc)
				break;
		}
	} else if (lsa->lsa_stripe_off != -1) {
		rc = llapi_layout_ost_index_set(layout, 0, lsa->lsa_stripe_off);
	}
	if (rc) {
		fprintf(stderr, "Set ost index %d failed. %s\n",
			i, strerror(errno));
		return rc;
	}

	return 0;
}

/* In 'lfs setstripe --component-add' mode, we need to fetch the extent
 * end of the last component in the existing file, and adjust the
 * first extent start of the components to be added accordingly. */
static int adjust_first_extent(char *fname, struct llapi_layout *layout)
{
	struct llapi_layout *head;
	uint64_t start, end, stripe_size, prev_end = 0;
	int rc;

	if (layout == NULL)
		return -EINVAL;

	errno = 0;
	head = llapi_layout_get_by_path(fname, 0);
	if (head == NULL) {
		fprintf(stderr, "Read layout from %s failed. %s\n",
			fname, strerror(errno));
		return -EINVAL;
	} else if (errno == ENODATA) {
		/* file without LOVEA, this component-add will be turned
		 * into a component-create. */
		llapi_layout_free(head);
		return -ENODATA;
	} else {
		/* Current component of 'head' should be tail of component
		 * list by default, but we do an extra move cursor operation
		 * here to test if the layout is non-composite. */
		rc = llapi_layout_comp_use(head, LLAPI_LAYOUT_COMP_USE_LAST);
		if (rc < 0) {
			fprintf(stderr, "'%s' isn't a composite file?\n",
				fname);
			llapi_layout_free(head);
			return rc;
		}
	}

	rc = llapi_layout_comp_extent_get(head, &start, &prev_end);
	if (rc) {
		fprintf(stderr, "Get prev extent failed. %s\n",
			strerror(errno));
		llapi_layout_free(head);
		return rc;
	}

	llapi_layout_free(head);

	/* Make sure we use the first component of the layout to be added. */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	if (rc < 0) {
		fprintf(stderr, "Move component cursor failed. %s\n",
			strerror(errno));
		return rc;
	}

	rc = llapi_layout_comp_extent_get(layout, &start, &end);
	if (rc) {
		fprintf(stderr, "Get extent failed. %s\n", strerror(errno));
		return rc;
	}

	if (start > prev_end || end <= prev_end) {
		fprintf(stderr, "First extent to be set [%lu, %lu) isn't "
			"adjacent with the existing file extent end: %lu\n",
			start, end, prev_end);
		return -EINVAL;
	}

	rc = llapi_layout_stripe_size_get(layout, &stripe_size);
	if (rc) {
		fprintf(stderr, "Get stripe size failed. %s\n",
			strerror(errno));
		return rc;
	}

	if (stripe_size != LLAPI_LAYOUT_DEFAULT &&
	    (prev_end & (stripe_size - 1))) {
		fprintf(stderr, "Stripe size %lu not aligned with %lu\n",
			stripe_size, prev_end);
		return -EINVAL;
	}

	rc = llapi_layout_comp_extent_set(layout, prev_end, end);
	if (rc) {
		fprintf(stderr, "Set component extent [%lu, %lu) failed. %s\n",
			prev_end, end, strerror(errno));
		return rc;
	}

	return 0;
}

static inline bool comp_flags_is_neg(__u32 flags)
{
	return flags & LCME_FL_NEG;
}

static inline void comp_flags_set_neg(__u32 *flags)
{
	*flags |= LCME_FL_NEG;
}

static inline void comp_flags_clear_neg(__u32 *flags)
{
	*flags &= ~LCME_FL_NEG;
}

static int comp_str2flags(__u32 *flags, char *string)
{
	char *name;
	__u32 neg_flags = 0;

	if (string == NULL)
		return -EINVAL;

	*flags = 0;
	for (name = strtok(string, ","); name; name = strtok(NULL, ",")) {
		bool found = false;
		int i;

		for (i = 0; i < ARRAY_SIZE(comp_flags_table); i++) {
			__u32 comp_flag = comp_flags_table[i].cfn_flag;
			const char *comp_name = comp_flags_table[i].cfn_name;

			if (strcmp(name, comp_name) == 0) {
				*flags |= comp_flag;
				found = true;
			} else if (strncmp(name, "^", 1) == 0 &&
				   strcmp(name + 1, comp_name) == 0) {
				neg_flags |= comp_flag;
				found = true;
			}
		}
		if (!found) {
			llapi_printf(LLAPI_MSG_ERROR, "Component flag "
				     "'%s' is not supported.\n", name);
			return -EINVAL;
		}
	}

	if (*flags == 0 && neg_flags == 0)
		return -EINVAL;
	/* don't support mixed flags for now */
	if (*flags && neg_flags)
		return -EINVAL;

	if (neg_flags) {
		*flags = neg_flags;
		comp_flags_set_neg(flags);
	}

	return 0;
}

static inline bool arg_is_eof(char *arg)
{
	return !strncmp(arg, "-1", strlen("-1")) ||
	       !strncmp(arg, "EOF", strlen("EOF")) ||
	       !strncmp(arg, "eof", strlen("eof"));
}

enum {
	LFS_POOL_OPT = 3,
	LFS_COMP_COUNT_OPT,
	LFS_COMP_START_OPT,
	LFS_COMP_FLAGS_OPT,
	LFS_COMP_DEL_OPT,
	LFS_COMP_SET_OPT,
	LFS_COMP_ADD_OPT,
	LFS_PROJID_OPT,
};

/* functions */
static int lfs_setstripe(int argc, char **argv)
{
	struct lfs_setstripe_args	 lsa;
	struct llapi_stripe_param	*param = NULL;
	struct find_param		 migrate_mdt_param = {
		.fp_max_depth = -1,
		.fp_mdt_index = -1,
	};
	char				*fname;
	int				 result;
	int				 result2 = 0;
	char				*end;
	int				 c;
	int				 delete = 0;
	char				*mdt_idx_arg = NULL;
	unsigned long long		 size_units = 1;
	bool				 migrate_mode = false;
	bool				 migration_block = false;
	__u64				 migration_flags = 0;
	__u32				 osts[LOV_MAX_STRIPE_COUNT] = { 0 };
	int				 comp_del = 0, comp_set = 0;
	int				 comp_add = 0;
	__u32				 comp_id = 0;
	struct llapi_layout		*layout = NULL;

	struct option long_opts[] = {
		/* --block is only valid in migrate mode */
	{ .val = 'b',	.name = "block",	.has_arg = no_argument},
	{ .val = LFS_COMP_ADD_OPT,
			.name = "comp-add",	.has_arg = no_argument},
	{ .val = LFS_COMP_ADD_OPT,
			.name = "component-add",
						.has_arg = no_argument},
	{ .val = LFS_COMP_DEL_OPT,
			.name = "comp-del",	.has_arg = no_argument},
	{ .val = LFS_COMP_DEL_OPT,
			.name = "component-del",
						.has_arg = no_argument},
	{ .val = LFS_COMP_FLAGS_OPT,
			.name = "comp-flags",	.has_arg = required_argument},
	{ .val = LFS_COMP_FLAGS_OPT,
			.name = "component-flags",
						.has_arg = required_argument},
	{ .val = LFS_COMP_SET_OPT,
			.name = "comp-set",	.has_arg = no_argument},
	{ .val = LFS_COMP_SET_OPT,
			.name = "component-set",
						.has_arg = no_argument},
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 9, 59, 0)
	/* This formerly implied "stripe-count", but was explicitly
	 * made "stripe-count" for consistency with other options,
	 * and to separate it from "mdt-count" when DNE arrives. */
	{ .val = 'c',	.name = "count",	.has_arg = required_argument },
#endif
	{ .val = 'c',	.name = "stripe-count",	.has_arg = required_argument},
	{ .val = 'c',	.name = "stripe_count",	.has_arg = required_argument},
	{ .val = 'd',	.name = "delete",	.has_arg = no_argument},
	{ .val = 'E',	.name = "comp-end",	.has_arg = required_argument},
	{ .val = 'E',	.name = "component-end",
						.has_arg = required_argument},
	/* dirstripe {"mdt-hash",     required_argument, 0, 'H'}, */
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 9, 59, 0)
	/* This formerly implied "stripe-index", but was explicitly
	 * made "stripe-index" for consistency with other options,
	 * and to separate it from "mdt-index" when DNE arrives. */
	{ .val = 'i',	.name = "index",	.has_arg = required_argument },
#endif
	{ .val = 'i',	.name = "stripe-index",	.has_arg = required_argument},
	{ .val = 'i',	.name = "stripe_index",	.has_arg = required_argument},
	{ .val = 'I',	.name = "comp-id",	.has_arg = required_argument},
	{ .val = 'I',	.name = "component-id",	.has_arg = required_argument},
	{ .val = 'm',	.name = "mdt",		.has_arg = required_argument},
	{ .val = 'm',	.name = "mdt-index",	.has_arg = required_argument},
	{ .val = 'm',	.name = "mdt_index",	.has_arg = required_argument},
	/* --non-block is only valid in migrate mode */
	{ .val = 'n',	.name = "non-block",	.has_arg = no_argument},
	{ .val = 'o',	.name = "ost",		.has_arg = required_argument},
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
	{ .val = 'o',	.name = "ost-list",	.has_arg = required_argument },
	{ .val = 'o',	.name = "ost_list",	.has_arg = required_argument },
#endif
	{ .val = 'p',	.name = "pool",		.has_arg = required_argument },
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 9, 59, 0)
	/* This formerly implied "--stripe-size", but was confusing
	 * with "lfs find --size|-s", which means "file size", so use
	 * the consistent "--stripe-size|-S" for all commands. */
	{ .val = 's',	.name = "size",		.has_arg = required_argument },
#endif
	{ .val = 'S',	.name = "stripe-size",	.has_arg = required_argument },
	{ .val = 'S',	.name = "stripe_size",	.has_arg = required_argument },
	/* dirstripe {"mdt-count",    required_argument, 0, 'T'}, */
	/* --verbose is only valid in migrate mode */
	{ .val = 'v',	.name = "verbose",	.has_arg = no_argument },
	{ .val = LFS_COMP_ADD_OPT,
			.name = "component-add",
						.has_arg = no_argument },
	{ .val = LFS_COMP_DEL_OPT,
			.name = "component-del",
						.has_arg = no_argument },
	{ .val = LFS_COMP_FLAGS_OPT,
			.name = "component-flags",
						.has_arg = required_argument },
	{ .val = LFS_COMP_SET_OPT,
			.name = "component-set",
						.has_arg = no_argument },
	{ .name = NULL } };

	setstripe_args_init(&lsa);

	if (strcmp(argv[0], "migrate") == 0)
		migrate_mode = true;

	while ((c = getopt_long(argc, argv, "bc:dE:i:I:m:no:p:s:S:v",
				long_opts, NULL)) >= 0) {
		switch (c) {
		case 0:
			/* Long options. */
			break;
		case LFS_COMP_ADD_OPT:
			comp_add = 1;
			break;
		case LFS_COMP_DEL_OPT:
			comp_del = 1;
			break;
		case LFS_COMP_FLAGS_OPT:
			result = comp_str2flags(&lsa.lsa_comp_flags, optarg);
			if (result != 0) {
				fprintf(stderr, "error: %s: bad comp flags "
					"'%s'\n", argv[0], optarg);
				goto error;
			}
			break;
		case LFS_COMP_SET_OPT:
			comp_set = 1;
			break;
		case 'b':
			if (!migrate_mode) {
				fprintf(stderr, "--block is valid only for"
						" migrate mode\n");
				goto error;
			}
			migration_block = true;
			break;
		case 'c':
#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 6, 53, 0)
			if (strcmp(argv[optind - 1], "--count") == 0)
				fprintf(stderr, "warning: '--count' deprecated"
					", use '--stripe-count' instead\n");
#endif
			lsa.lsa_stripe_count = strtoul(optarg, &end, 0);
			if (*end != '\0') {
				fprintf(stderr, "error: %s: bad stripe count "
					"'%s'\n", argv[0], optarg);
				goto error;
			}
			break;
		case 'd':
			/* delete the default striping pattern */
			delete = 1;
			break;
		case 'E':
			if (lsa.lsa_comp_end != 0) {
				result = comp_args_to_layout(&layout, &lsa);
				if (result)
					goto error;

				setstripe_args_init(&lsa);
			}

			if (arg_is_eof(optarg)) {
				lsa.lsa_comp_end = LUSTRE_EOF;
			} else {
				result = llapi_parse_size(optarg,
							&lsa.lsa_comp_end,
							&size_units, 0);
				if (result) {
					fprintf(stderr, "error: %s: "
						"bad component end '%s'\n",
						argv[0], optarg);
					goto error;
				}
			}
			break;
		case 'i':
			if (strcmp(argv[optind - 1], "--index") == 0)
				fprintf(stderr, "warning: '--index' deprecated"
					", use '--stripe-index' instead\n");
			lsa.lsa_stripe_off = strtol(optarg, &end, 0);
			if (*end != '\0') {
				fprintf(stderr, "error: %s: bad stripe offset "
					"'%s'\n", argv[0], optarg);
				goto error;
			}
			break;
		case 'I':
			comp_id = strtoul(optarg, &end, 0);
			if (*end != '\0' || comp_id == 0 ||
			    comp_id > LCME_ID_MAX) {
				fprintf(stderr, "error: %s: bad comp ID "
					"'%s'\n", argv[0], optarg);
				goto error;
			}
			break;
		case 'm':
			if (!migrate_mode) {
				fprintf(stderr, "--mdt-index is valid only for"
						" migrate mode\n");
				goto error;
			}
			mdt_idx_arg = optarg;
			break;
		case 'n':
			if (!migrate_mode) {
				fprintf(stderr, "--non-block is valid only for"
						" migrate mode\n");
				goto error;
			}
			migration_flags |= MIGRATION_NONBLOCK;
			break;
		case 'o':
			lsa.lsa_nr_osts = parse_targets(osts,
						sizeof(osts) / sizeof(__u32),
						lsa.lsa_nr_osts, optarg);
			if (lsa.lsa_nr_osts < 0) {
				fprintf(stderr,
					"error: %s: bad OST indices '%s'\n",
					argv[0], optarg);
				goto error;
			}

			lsa.lsa_osts = osts;
			if (lsa.lsa_stripe_off == -1)
				lsa.lsa_stripe_off = osts[0];
			break;
		case 'p':
			if (optarg == NULL)
				goto error;
			lsa.lsa_pool_name = optarg;
			break;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 9, 59, 0)
		case 's':
#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 6, 53, 0)
			fprintf(stderr, "warning: '--size|-s' deprecated, "
				"use '--stripe-size|-S' instead\n");
#endif
#endif /* LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 9, 59, 0) */
		case 'S':
			result = llapi_parse_size(optarg, &lsa.lsa_stripe_size,
						  &size_units, 0);
			if (result) {
				fprintf(stderr, "error: %s: bad stripe size "
					"'%s'\n", argv[0], optarg);
				goto error;
			}
			break;
		case 'v':
			if (!migrate_mode) {
				fprintf(stderr, "--verbose is valid only for"
						" migrate mode\n");
				goto error;
			}
			migrate_mdt_param.fp_verbose = VERBOSE_DETAIL;
			break;
		default:
			goto error;
		}
	}

	fname = argv[optind];

	if (lsa.lsa_comp_end != 0) {
		result = comp_args_to_layout(&layout, &lsa);
		if (result)
			goto error;
	}

	if (optind == argc) {
		fprintf(stderr, "error: %s: missing filename|dirname\n",
			argv[0]);
		goto error;
	}

	/* Only LCME_FL_INIT flags is used in PFL, and it shouldn't be
	 * altered by user space tool, so we don't need to support the
	 * --component-set for this moment. */
	if (comp_set != 0) {
		fprintf(stderr, "error: %s: --component-set isn't supported.\n",
			argv[0]);
		goto error;
	}

	if ((delete + comp_set + comp_del + comp_add) > 1) {
		fprintf(stderr, "error: %s: can't specify --component-set, "
			"--component-del, --component-add or -d together\n",
			argv[0]);
		goto error;
	}

	if (delete && (setstripe_args_specified(&lsa) || comp_id != 0 ||
		       lsa.lsa_comp_flags != 0 || layout != NULL)) {
		fprintf(stderr, "error: %s: can't specify -d with "
			"-s, -c, -o, -p, -I, -F or -E options\n",
			argv[0]);
		goto error;
	}

	if ((comp_set || comp_del) &&
	    (setstripe_args_specified(&lsa) || layout != NULL)) {
		fprintf(stderr, "error: %s: can't specify --component-del or "
			"--component-set with -s, -c, -o, -p or -E options.\n",
			argv[0]);
		goto error;
	}

	if (comp_del && comp_id != 0 && lsa.lsa_comp_flags != 0) {
		fprintf(stderr, "error: %s: can't specify both -I and -F for "
			"--component-del option.\n", argv[0]);
		goto error;
	}

	if (comp_add || comp_del) {
		struct stat st;

		result = lstat(fname, &st);
		if (result == 0 && S_ISDIR(st.st_mode)) {
			fprintf(stderr, "error: %s: can't use --component-add "
				"or --component-del for directory.\n",
				argv[0]);
			goto error;
		}
	}

	if (comp_add) {
		if (layout == NULL) {
			fprintf(stderr, "error: %s: -E option must be present"
				"in --component-add mode.\n", argv[0]);
			goto error;
		}
		result = adjust_first_extent(fname, layout);
		if (result == -ENODATA)
			comp_add = 0;
		else if (result != 0)
			goto error;
	}

	if (mdt_idx_arg != NULL && optind > 3) {
		fprintf(stderr, "error: %s: cannot specify -m with other "
			"options\n", argv[0]);
		goto error;
	}

	if ((migration_flags & MIGRATION_NONBLOCK) && migration_block) {
		fprintf(stderr,
			"error: %s: cannot specify --non-block and --block\n",
			argv[0]);
		goto error;
	}

	if (!comp_del && !comp_set && comp_id != 0) {
		fprintf(stderr, "error: %s: -I can only be used with "
			"--component-del.\n", argv[0]);
		goto error;
	}

	if (mdt_idx_arg != NULL) {
		/* initialize migrate mdt parameters */
		migrate_mdt_param.fp_mdt_index = strtoul(mdt_idx_arg, &end, 0);
		if (*end != '\0') {
			fprintf(stderr, "error: %s: bad MDT index '%s'\n",
				argv[0], mdt_idx_arg);
			goto error;
		}
		migrate_mdt_param.fp_migrate = 1;
	} else if (layout == NULL) {
		/* initialize stripe parameters */
		param = calloc(1, offsetof(typeof(*param),
			       lsp_osts[lsa.lsa_nr_osts]));
		if (param == NULL) {
			fprintf(stderr, "error: %s: %s\n", argv[0],
				strerror(ENOMEM));
			goto error;
		}

		param->lsp_stripe_size = lsa.lsa_stripe_size;
		param->lsp_stripe_offset = lsa.lsa_stripe_off;
		param->lsp_stripe_count = lsa.lsa_stripe_count;
		param->lsp_stripe_pattern = 0;
		param->lsp_pool = lsa.lsa_pool_name;
		param->lsp_is_specific = false;
		if (lsa.lsa_nr_osts > 0) {
			if (lsa.lsa_stripe_count > 0 &&
			    lsa.lsa_nr_osts != lsa.lsa_stripe_count) {
				fprintf(stderr, "error: %s: stripe count '%d' "
					"doesn't match the number of OSTs: %d\n"
					, argv[0], lsa.lsa_stripe_count,
					lsa.lsa_nr_osts);
				free(param);
				goto error;
			}

			param->lsp_is_specific = true;
			param->lsp_stripe_count = lsa.lsa_nr_osts;
			memcpy(param->lsp_osts, osts,
			       sizeof(*osts) * lsa.lsa_nr_osts);
		}
	}

	for (fname = argv[optind]; fname != NULL; fname = argv[++optind]) {
		char *op;
		if (mdt_idx_arg != NULL) {
			result = llapi_migrate_mdt(fname, &migrate_mdt_param);
			op = "migrate mdt objects of";
		} else if (migrate_mode) {
			result = lfs_migrate(fname, migration_flags, param,
					     layout);
			op = "migrate ost objects of";
		} else if (comp_set != 0) {
			result = lfs_component_set(fname, comp_id,
						   lsa.lsa_comp_flags);
			op = "modify component flags of";
		} else if (comp_del != 0) {
			result = lfs_component_del(fname, comp_id,
						   lsa.lsa_comp_flags);
			op = "delete component of";
		} else if (comp_add != 0) {
			result = lfs_component_add(fname, layout);
			op = "add component to";
		} else if (layout != NULL) {
			result = lfs_component_create(fname, O_CREAT | O_WRONLY,
						      0644, layout);
			if (result >= 0) {
				close(result);
				result = 0;
			}
			op = "create composite";
		} else {
			result = llapi_file_open_param(fname,
						       O_CREAT | O_WRONLY,
						       0644, param);
			if (result >= 0) {
				close(result);
				result = 0;
			}
			op = "create striped";
		}
		if (result) {
			/* Save the first error encountered. */
			if (result2 == 0)
				result2 = result;
			fprintf(stderr, "error: %s: %s file '%s' failed: %s\n",
				argv[0], op, fname,
				lsa.lsa_pool_name != NULL && result == EINVAL ?
				"OST not in pool?" : strerror(errno));
			continue;
		}
	}

	free(param);
	llapi_layout_free(layout);
	return result2;
error:
	llapi_layout_free(layout);
	return CMD_HELP;
}

static int lfs_poollist(int argc, char **argv)
{
        if (argc != 2)
                return CMD_HELP;

        return llapi_poollist(argv[1]);
}

static int set_time(time_t *time, time_t *set, char *str)
{
        time_t t;
        int res = 0;

        if (str[0] == '+')
                res = 1;
        else if (str[0] == '-')
                res = -1;

        if (res)
                str++;

        t = strtol(str, NULL, 0);
        if (*time < t * 24 * 60 * 60) {
                if (res)
                        str--;
                fprintf(stderr, "Wrong time '%s' is specified.\n", str);
                return INT_MAX;
        }

        *set = *time - t * 24 * 60 * 60;
        return res;
}
static int name2uid(unsigned int *id, const char *name)
{
	struct passwd *passwd;

	passwd = getpwnam(name);
	if (passwd == NULL)
		return -ENOENT;
	*id = passwd->pw_uid;

	return 0;
}

static int name2gid(unsigned int *id, const char *name)
{
	struct group *group;

	group = getgrnam(name);
	if (group == NULL)
		return -ENOENT;
	*id = group->gr_gid;

	return 0;
}

static inline int name2projid(unsigned int *id, const char *name)
{
	return -ENOTSUP;
}

static int uid2name(char **name, unsigned int id)
{
	struct passwd *passwd;

	passwd = getpwuid(id);
	if (passwd == NULL)
		return -ENOENT;
	*name = passwd->pw_name;

	return 0;
}

static inline int gid2name(char **name, unsigned int id)
{
	struct group *group;

	group = getgrgid(id);
	if (group == NULL)
		return -ENOENT;
	*name = group->gr_name;

	return 0;
}

static int name2layout(__u32 *layout, char *name)
{
	char *ptr, *lyt;

	*layout = 0;
	for (ptr = name; ; ptr = NULL) {
		lyt = strtok(ptr, ",");
		if (lyt == NULL)
			break;
		if (strcmp(lyt, "released") == 0)
			*layout |= LOV_PATTERN_F_RELEASED;
		else if (strcmp(lyt, "raid0") == 0)
			*layout |= LOV_PATTERN_RAID0;
		else
			return -1;
	}
	return 0;
}

static int lfs_find(int argc, char **argv)
{
	int c, rc;
	int ret = 0;
        time_t t;
	struct find_param param = {
		.fp_max_depth = -1,
		.fp_quiet = 1,
	};
        struct option long_opts[] = {
		{"atime",        required_argument, 0, 'A'},
		{"comp-count",	 required_argument, 0, LFS_COMP_COUNT_OPT},
		{"component-count", required_argument, 0, LFS_COMP_COUNT_OPT},
		{"comp-flags",	 required_argument, 0, LFS_COMP_FLAGS_OPT},
		{"component-flags", required_argument, 0, LFS_COMP_FLAGS_OPT},
		{"comp-start",	 required_argument, 0, LFS_COMP_START_OPT},
		{"component-start", required_argument, 0, LFS_COMP_START_OPT},
		{"stripe-count", required_argument, 0, 'c'},
		{"stripe_count", required_argument, 0, 'c'},
		{"ctime",        required_argument, 0, 'C'},
		{"maxdepth",     required_argument, 0, 'D'},
		{"comp-end",	 required_argument, 0, 'E'},
		{"component-end", required_argument, 0, 'E'},
		{"gid",          required_argument, 0, 'g'},
		{"group",        required_argument, 0, 'G'},
		{"mdt-hash",     required_argument, 0, 'H'},
		{"stripe-index", required_argument, 0, 'i'},
		{"stripe_index", required_argument, 0, 'i'},
		/*{"component-id", required_argument, 0, 'I'},*/
		{"layout",	 required_argument, 0, 'L'},
                {"mdt",          required_argument, 0, 'm'},
                {"mdt-index",    required_argument, 0, 'm'},
                {"mdt_index",    required_argument, 0, 'm'},
                {"mtime",        required_argument, 0, 'M'},
                {"name",         required_argument, 0, 'n'},
     /* reserve {"or",           no_argument,     , 0, 'o'}, to match find(1) */
                {"obd",          required_argument, 0, 'O'},
                {"ost",          required_argument, 0, 'O'},
                /* no short option for pool, p/P already used */
		{"pool",	 required_argument, 0, LFS_POOL_OPT},
		{"print0",	 no_argument,	    0, 'p'},
		{"print",	 no_argument,	    0, 'P'},
		{"projid",	 required_argument, 0, LFS_PROJID_OPT},
                {"size",         required_argument, 0, 's'},
                {"stripe-size",  required_argument, 0, 'S'},
                {"stripe_size",  required_argument, 0, 'S'},
                {"type",         required_argument, 0, 't'},
		{"mdt-count",    required_argument, 0, 'T'},
                {"uid",          required_argument, 0, 'u'},
                {"user",         required_argument, 0, 'U'},
                {0, 0, 0, 0}
        };
        int pathstart = -1;
        int pathend = -1;
        int neg_opt = 0;
        time_t *xtime;
        int *xsign;
        int isoption;
        char *endptr;

        time(&t);

	/* when getopt_long_only() hits '!' it returns 1, puts "!" in optarg */
	while ((c = getopt_long_only(argc, argv,
			"-A:c:C:D:E:g:G:H:i:L:m:M:n:O:Ppqrs:S:t:T:u:U:v",
			long_opts, NULL)) >= 0) {
                xtime = NULL;
                xsign = NULL;
                if (neg_opt)
                        --neg_opt;
                /* '!' is part of option */
                /* when getopt_long_only() finds a string which is not
                 * an option nor a known option argument it returns 1
                 * in that case if we already have found pathstart and pathend
                 * (i.e. we have the list of pathnames),
                 * the only supported value is "!"
                 */
                isoption = (c != 1) || (strcmp(optarg, "!") == 0);
                if (!isoption && pathend != -1) {
                        fprintf(stderr, "err: %s: filename|dirname must either "
                                        "precede options or follow options\n",
                                        argv[0]);
                        ret = CMD_HELP;
                        goto err;
                }
                if (!isoption && pathstart == -1)
                        pathstart = optind - 1;
                if (isoption && pathstart != -1 && pathend == -1)
                        pathend = optind - 2;
                switch (c) {
                case 0:
                        /* Long options. */
                        break;
                case 1:
                        /* unknown; opt is "!" or path component,
                         * checking done above.
                         */
                        if (strcmp(optarg, "!") == 0)
                                neg_opt = 2;
                        break;
		case 'A':
			xtime = &param.fp_atime;
			xsign = &param.fp_asign;
			param.fp_exclude_atime = !!neg_opt;
			/* no break, this falls through to 'C' for ctime */
		case 'C':
			if (c == 'C') {
				xtime = &param.fp_ctime;
				xsign = &param.fp_csign;
				param.fp_exclude_ctime = !!neg_opt;
			}
			/* no break, this falls through to 'M' for mtime */
		case 'M':
			if (c == 'M') {
				xtime = &param.fp_mtime;
				xsign = &param.fp_msign;
				param.fp_exclude_mtime = !!neg_opt;
			}
			rc = set_time(&t, xtime, optarg);
			if (rc == INT_MAX) {
				ret = -1;
				goto err;
			}
			if (rc)
				*xsign = rc;
			break;
		case LFS_COMP_COUNT_OPT:
			if (optarg[0] == '+') {
				param.fp_comp_count_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param.fp_comp_count_sign =  1;
				optarg++;
			}

			param.fp_comp_count = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				fprintf(stderr, "error: bad component count "
					"'%s'\n", optarg);
				goto err;
			}
			param.fp_check_comp_count = 1;
			param.fp_exclude_comp_count = !!neg_opt;
			break;
		case LFS_COMP_FLAGS_OPT:
			rc = comp_str2flags(&param.fp_comp_flags, optarg);
			if (rc || comp_flags_is_neg(param.fp_comp_flags)) {
				fprintf(stderr, "error: bad component flags "
					"'%s'\n", optarg);
				goto err;
			}
			param.fp_check_comp_flags = 1;
			param.fp_exclude_comp_flags = !!neg_opt;
			break;
		case LFS_COMP_START_OPT:
			if (optarg[0] == '+') {
				param.fp_comp_start_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param.fp_comp_start_sign =  1;
				optarg++;
			}

			rc = llapi_parse_size(optarg, &param.fp_comp_start,
					      &param.fp_comp_start_units, 0);
			if (rc) {
				fprintf(stderr, "error: bad component start "
					"'%s'\n", optarg);
				goto err;
			}
			param.fp_check_comp_start = 1;
			param.fp_exclude_comp_start = !!neg_opt;
			break;
                case 'c':
                        if (optarg[0] == '+') {
				param.fp_stripe_count_sign = -1;
                                optarg++;
                        } else if (optarg[0] == '-') {
				param.fp_stripe_count_sign =  1;
                                optarg++;
                        }

			param.fp_stripe_count = strtoul(optarg, &endptr, 0);
                        if (*endptr != '\0') {
                                fprintf(stderr,"error: bad stripe_count '%s'\n",
                                        optarg);
                                ret = -1;
                                goto err;
                        }
			param.fp_check_stripe_count = 1;
			param.fp_exclude_stripe_count = !!neg_opt;
                        break;
		case 'D':
			param.fp_max_depth = strtol(optarg, 0, 0);
			break;
		case 'E':
			if (optarg[0] == '+') {
				param.fp_comp_end_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param.fp_comp_end_sign =  1;
				optarg++;
			}

			if (arg_is_eof(optarg)) {
				param.fp_comp_end = LUSTRE_EOF;
				param.fp_comp_end_units = 1;
				rc = 0;
			} else {
				rc = llapi_parse_size(optarg,
						&param.fp_comp_end,
						&param.fp_comp_end_units, 0);
			}
			if (rc) {
				fprintf(stderr, "error: bad component end "
					"'%s'\n", optarg);
				goto err;
			}
			param.fp_check_comp_end = 1;
			param.fp_exclude_comp_end = !!neg_opt;
			break;
		case 'g':
		case 'G':
			rc = name2gid(&param.fp_gid, optarg);
			if (rc) {
				param.fp_gid = strtoul(optarg, &endptr, 10);
                                if (*endptr != '\0') {
                                        fprintf(stderr, "Group/GID: %s cannot "
                                                "be found.\n", optarg);
                                        ret = -1;
                                        goto err;
                                }
                        }
			param.fp_exclude_gid = !!neg_opt;
			param.fp_check_gid = 1;
                        break;
		case 'H':
			param.fp_hash_type = check_hashtype(optarg);
			if (param.fp_hash_type == 0) {
				fprintf(stderr, "error: bad hash_type '%s'\n",
					optarg);
				ret = -1;
				goto err;
			}
			param.fp_check_hash_type = 1;
			param.fp_exclude_hash_type = !!neg_opt;
			break;
		case 'L':
			ret = name2layout(&param.fp_layout, optarg);
			if (ret)
				goto err;
			param.fp_exclude_layout = !!neg_opt;
			param.fp_check_layout = 1;
			break;
		case 'u':
		case 'U':
			rc = name2uid(&param.fp_uid, optarg);
			if (rc) {
				param.fp_uid = strtoul(optarg, &endptr, 10);
				if (*endptr != '\0') {
					fprintf(stderr, "User/UID: %s cannot "
                                                "be found.\n", optarg);
                                        ret = -1;
                                        goto err;
                                }
                        }
			param.fp_exclude_uid = !!neg_opt;
			param.fp_check_uid = 1;
                        break;
		case LFS_POOL_OPT:
                        if (strlen(optarg) > LOV_MAXPOOLNAME) {
                                fprintf(stderr,
                                        "Pool name %s is too long"
                                        " (max is %d)\n", optarg,
                                        LOV_MAXPOOLNAME);
                                ret = -1;
                                goto err;
                        }
                        /* we do check for empty pool because empty pool
                         * is used to find V1 lov attributes */
			strncpy(param.fp_poolname, optarg, LOV_MAXPOOLNAME);
			param.fp_poolname[LOV_MAXPOOLNAME] = '\0';
			param.fp_exclude_pool = !!neg_opt;
			param.fp_check_pool = 1;
                        break;
                case 'n':
			param.fp_pattern = (char *)optarg;
			param.fp_exclude_pattern = !!neg_opt;
                        break;
                case 'm':
                case 'i':
                case 'O': {
                        char *buf, *token, *next, *p;
                        int len = 1;
                        void *tmp;

                        buf = strdup(optarg);
                        if (buf == NULL) {
                                ret = -ENOMEM;
                                goto err;
                        }

			param.fp_exclude_obd = !!neg_opt;

                        token = buf;
                        while (token && *token) {
                                token = strchr(token, ',');
                                if (token) {
                                        len++;
                                        token++;
                                }
                        }
                        if (c == 'm') {
				param.fp_exclude_mdt = !!neg_opt;
				param.fp_num_alloc_mdts += len;
				tmp = realloc(param.fp_mdt_uuid,
					      param.fp_num_alloc_mdts *
					      sizeof(*param.fp_mdt_uuid));
				if (tmp == NULL) {
					ret = -ENOMEM;
					goto err_free;
				}

				param.fp_mdt_uuid = tmp;
                        } else {
				param.fp_exclude_obd = !!neg_opt;
				param.fp_num_alloc_obds += len;
				tmp = realloc(param.fp_obd_uuid,
					      param.fp_num_alloc_obds *
					      sizeof(*param.fp_obd_uuid));
				if (tmp == NULL) {
					ret = -ENOMEM;
					goto err_free;
				}

				param.fp_obd_uuid = tmp;
                        }
                        for (token = buf; token && *token; token = next) {
				struct obd_uuid *puuid;
				if (c == 'm') {
					puuid =
					&param.fp_mdt_uuid[param.fp_num_mdts++];
				} else {
					puuid =
					&param.fp_obd_uuid[param.fp_num_obds++];
				}
                                p = strchr(token, ',');
                                next = 0;
                                if (p) {
                                        *p = 0;
                                        next = p+1;
                                }

				if (strlen(token) > sizeof(puuid->uuid) - 1) {
					ret = -E2BIG;
					goto err_free;
				}

				strncpy(puuid->uuid, token,
					sizeof(puuid->uuid));
			}
err_free:
			if (buf)
				free(buf);
			break;
		}
		case 'p':
			param.fp_zero_end = 1;
			break;
		case 'P':
			break;
		case LFS_PROJID_OPT:
			rc = name2projid(&param.fp_projid, optarg);
			if (rc) {
				param.fp_projid = strtoul(optarg, &endptr, 10);
				if (*endptr != '\0') {
					fprintf(stderr,
						"Invalid project ID: %s",
						optarg);
					ret = -1;
					goto err;
				}
			}
			param.fp_exclude_projid = !!neg_opt;
			param.fp_check_projid = 1;
			break;
		case 's':
			if (optarg[0] == '+') {
				param.fp_size_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param.fp_size_sign =  1;
				optarg++;
			}

			ret = llapi_parse_size(optarg, &param.fp_size,
					       &param.fp_size_units, 0);
			if (ret) {
				fprintf(stderr, "error: bad file size '%s'\n",
					optarg);
				goto err;
			}
			param.fp_check_size = 1;
			param.fp_exclude_size = !!neg_opt;
			break;
		case 'S':
			if (optarg[0] == '+') {
				param.fp_stripe_size_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param.fp_stripe_size_sign =  1;
				optarg++;
			}

			ret = llapi_parse_size(optarg, &param.fp_stripe_size,
					       &param.fp_stripe_size_units, 0);
			if (ret) {
				fprintf(stderr, "error: bad stripe_size '%s'\n",
					optarg);
				goto err;
			}
			param.fp_check_stripe_size = 1;
			param.fp_exclude_stripe_size = !!neg_opt;
			break;
		case 't':
			param.fp_exclude_type = !!neg_opt;
			switch (optarg[0]) {
			case 'b':
				param.fp_type = S_IFBLK;
				break;
			case 'c':
				param.fp_type = S_IFCHR;
				break;
			case 'd':
				param.fp_type = S_IFDIR;
				break;
			case 'f':
				param.fp_type = S_IFREG;
				break;
			case 'l':
				param.fp_type = S_IFLNK;
				break;
			case 'p':
				param.fp_type = S_IFIFO;
				break;
			case 's':
				param.fp_type = S_IFSOCK;
				break;
			default:
				fprintf(stderr, "error: %s: bad type '%s'\n",
					argv[0], optarg);
				ret = CMD_HELP;
				goto err;
			};
			break;
		case 'T':
			if (optarg[0] == '+') {
				param.fp_mdt_count_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param.fp_mdt_count_sign =  1;
				optarg++;
			}

			param.fp_mdt_count = strtoul(optarg, &endptr, 0);
			if (*endptr != '\0') {
				fprintf(stderr, "error: bad mdt_count '%s'\n",
					optarg);
				ret = -1;
				goto err;
			}
			param.fp_check_mdt_count = 1;
			param.fp_exclude_mdt_count = !!neg_opt;
			break;
                default:
                        ret = CMD_HELP;
                        goto err;
                };
        }

        if (pathstart == -1) {
                fprintf(stderr, "error: %s: no filename|pathname\n",
                        argv[0]);
                ret = CMD_HELP;
                goto err;
        } else if (pathend == -1) {
                /* no options */
                pathend = argc;
        }

	do {
		rc = llapi_find(argv[pathstart], &param);
		if (rc != 0 && ret == 0)
			ret = rc;
	} while (++pathstart < pathend);

        if (ret)
                fprintf(stderr, "error: %s failed for %s.\n",
                        argv[0], argv[optind - 1]);
err:
	if (param.fp_obd_uuid && param.fp_num_alloc_obds)
		free(param.fp_obd_uuid);

	if (param.fp_mdt_uuid && param.fp_num_alloc_mdts)
		free(param.fp_mdt_uuid);

        return ret;
}

static int lfs_getstripe_internal(int argc, char **argv,
				  struct find_param *param)
{
	struct option long_opts[] = {
		{"comp-count",		no_argument, 0, LFS_COMP_COUNT_OPT},
		{"component-count",	no_argument, 0, LFS_COMP_COUNT_OPT},
		{"comp-flags",	    optional_argument, 0, LFS_COMP_FLAGS_OPT},
		{"component-flags", optional_argument, 0, LFS_COMP_FLAGS_OPT},
		{"comp-start",	    optional_argument, 0, LFS_COMP_START_OPT},
		{"component-start", optional_argument, 0, LFS_COMP_START_OPT},
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 9, 59, 0)
		/* This formerly implied "stripe-count", but was explicitly
		 * made "stripe-count" for consistency with other options,
		 * and to separate it from "mdt-count" when DNE arrives. */
		{"count",		no_argument,		0, 'c'},
#endif
		{"stripe-count",	no_argument,		0, 'c'},
		{"stripe_count",	no_argument,		0, 'c'},
		{"directory",		no_argument,		0, 'd'},
		{"default",		no_argument,		0, 'D'},
		{"comp-end",		optional_argument,	0, 'E'},
		{"component-end",	optional_argument,	0, 'E'},
		{"fid",			no_argument,		0, 'F'},
		{"generation",		no_argument,		0, 'g'},
		/* dirstripe {"mdt-hash",     required_argument, 0, 'H'}, */
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 9, 59, 0)
		/* This formerly implied "stripe-index", but was explicitly
		 * made "stripe-index" for consistency with other options,
		 * and to separate it from "mdt-index" when DNE arrives. */
		{"index",		no_argument,		0, 'i'},
#endif
		{"stripe-index",	no_argument,		0, 'i'},
		{"stripe_index",	no_argument,		0, 'i'},
		{"comp-id",		optional_argument,	0, 'I'},
		{"component-id",	optional_argument,	0, 'I'},
		{"layout",		no_argument,		0, 'L'},
		{"mdt",			no_argument,		0, 'm'},
		{"mdt-index",		no_argument,		0, 'm'},
		{"mdt_index",		no_argument,		0, 'm'},
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
		{"mdt-index",		no_argument,		0, 'M'},
		{"mdt_index",		no_argument,		0, 'M'},
#endif
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 9, 59, 0)
		/* This formerly implied "stripe-index", but was confusing
		 * with "file offset" (which will eventually be needed for
		 * with different layouts by offset), so deprecate it. */
		{"offset",		no_argument,		0, 'o'},
#endif
		{"obd",			required_argument,	0, 'O'},
		{"ost",			required_argument,	0, 'O'},
		{"pool",		no_argument,		0, 'p'},
		{"quiet",		no_argument,		0, 'q'},
		{"recursive",		no_argument,		0, 'r'},
		{"raw",			no_argument,		0, 'R'},
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 9, 59, 0)
		/* This formerly implied "--stripe-size", but was confusing
		 * with "lfs find --size|-s", which means "file size", so use
		 * the consistent "--stripe-size|-S" for all commands. */
		{"size",		no_argument,		0, 's'},
#endif
		{"stripe-size",		no_argument,		0, 'S'},
		{"stripe_size",		no_argument,		0, 'S'},
		/* dirstripe {"mdt-count",    required_argument, 0, 'T'}, */
		{"verbose",		no_argument,		0, 'v'},
		{"yaml",		no_argument,		0, 'y'},
		{0, 0, 0, 0}
	};
	int c, rc;
	char *end, *tmp;

	while ((c = getopt_long(argc, argv, "cdDE::FghiI::LmMoO:pqrRsSvy",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			if (strcmp(argv[optind - 1], "--count") == 0)
				fprintf(stderr, "warning: '--count' deprecated,"
					" use '--stripe-count' instead\n");
			if (!(param->fp_verbose & VERBOSE_DETAIL)) {
				param->fp_verbose |= VERBOSE_COUNT;
				param->fp_max_depth = 0;
			}
			break;
		case LFS_COMP_COUNT_OPT:
			param->fp_verbose |= VERBOSE_COMP_COUNT;
			param->fp_max_depth = 0;
			break;
		case LFS_COMP_FLAGS_OPT:
			if (optarg != NULL) {
				__u32 *flags = &param->fp_comp_flags;
				rc = comp_str2flags(flags, optarg);
				if (rc != 0) {
					fprintf(stderr, "error: %s bad "
						"component flags '%s'.\n",
						argv[0], optarg);
					return CMD_HELP;
				} else {
					param->fp_check_comp_flags = 1;
					param->fp_exclude_comp_flags =
						comp_flags_is_neg(*flags);
					comp_flags_clear_neg(flags);
				}
			} else {
				param->fp_verbose |= VERBOSE_COMP_FLAGS;
				param->fp_max_depth = 0;
			}
			break;
		case LFS_COMP_START_OPT:
			if (optarg != NULL) {
				tmp = optarg;
				if (tmp[0] == '+') {
					param->fp_comp_start_sign = -1;
					tmp++;
				} else if (tmp[0] == '-') {
					param->fp_comp_start_sign = 1;
					tmp++;
				}
				rc = llapi_parse_size(tmp,
						&param->fp_comp_start,
						&param->fp_comp_start_units, 0);
				if (rc != 0) {
					fprintf(stderr, "error: %s bad "
						"component start '%s'.\n",
						argv[0], tmp);
					return CMD_HELP;
				} else {
					param->fp_check_comp_start = 1;
				}
			} else {
				param->fp_verbose |= VERBOSE_COMP_START;
				param->fp_max_depth = 0;
			}
			break;
		case 'd':
			param->fp_max_depth = 0;
			break;
		case 'D':
			param->fp_get_default_lmv = 1;
			break;
		case 'E':
			if (optarg != NULL) {
				tmp = optarg;
				if (tmp[0] == '+') {
					param->fp_comp_end_sign = -1;
					tmp++;
				} else if (tmp[0] == '-') {
					param->fp_comp_end_sign = 1;
					tmp++;
				}

				if (arg_is_eof(tmp)) {
					param->fp_comp_end = LUSTRE_EOF;
					param->fp_comp_end_units = 1;
					rc = 0;
				} else {
					rc = llapi_parse_size(tmp,
						&param->fp_comp_end,
						&param->fp_comp_end_units, 0);
				}
				if (rc != 0) {
					fprintf(stderr, "error: %s bad "
						"component end '%s'.\n",
						argv[0], tmp);
					return CMD_HELP;
				}
				param->fp_check_comp_end = 1;
			} else {
				param->fp_verbose |= VERBOSE_COMP_END;
				param->fp_max_depth = 0;
			}
			break;
		case 'F':
			if (!(param->fp_verbose & VERBOSE_DETAIL)) {
				param->fp_verbose |= VERBOSE_DFID;
				param->fp_max_depth = 0;
			}
			break;
		case 'g':
			if (!(param->fp_verbose & VERBOSE_DETAIL)) {
				param->fp_verbose |= VERBOSE_GENERATION;
				param->fp_max_depth = 0;
			}
			break;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 9, 59, 0)
		case 'o':
			fprintf(stderr, "warning: '--offset|-o' deprecated, "
				"use '--stripe-index|-i' instead\n");
#endif
		case 'i':
#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 6, 53, 0)
			if (strcmp(argv[optind - 1], "--index") == 0)
				fprintf(stderr, "warning: '--index' deprecated"
					", use '--stripe-index' instead\n");
#endif
			if (!(param->fp_verbose & VERBOSE_DETAIL)) {
				param->fp_verbose |= VERBOSE_OFFSET;
				param->fp_max_depth = 0;
			}
			break;
		case 'I':
			if (optarg != NULL) {
				param->fp_comp_id = strtoul(optarg, &end, 0);
				if (*end != '\0' || param->fp_comp_id == 0 ||
				    param->fp_comp_id > LCME_ID_MAX) {
					fprintf(stderr, "error: %s bad "
						"component id '%s'\n",
						argv[0], optarg);
					return CMD_HELP;
				} else {
					param->fp_check_comp_id = 1;
				}
			} else {
				param->fp_max_depth = 0;
				param->fp_verbose |= VERBOSE_COMP_ID;
			}
			break;
		case 'L':
			if (!(param->fp_verbose & VERBOSE_DETAIL)) {
				param->fp_verbose |= VERBOSE_LAYOUT;
				param->fp_max_depth = 0;
			}
			break;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
		case 'M':
#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 11, 53, 0)
			fprintf(stderr, "warning: '-M' deprecated"
				", use '-m' instead\n");
#endif
#endif
		case 'm':
			if (!(param->fp_verbose & VERBOSE_DETAIL))
				param->fp_max_depth = 0;
			param->fp_verbose |= VERBOSE_MDTINDEX;
			break;
		case 'O':
			if (param->fp_obd_uuid) {
				fprintf(stderr,
					"error: %s: only one obduuid allowed",
					argv[0]);
				return CMD_HELP;
			}
			param->fp_obd_uuid = (struct obd_uuid *)optarg;
			break;
		case 'p':
			if (!(param->fp_verbose & VERBOSE_DETAIL)) {
				param->fp_verbose |= VERBOSE_POOL;
				param->fp_max_depth = 0;
			}
			break;
		case 'q':
			param->fp_quiet++;
			break;
		case 'r':
			param->fp_recursive = 1;
			break;
		case 'R':
			param->fp_raw = 1;
			break;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 9, 59, 0)
		case 's':
			fprintf(stderr, "warning: '--size|-s' deprecated, "
				"use '--stripe-size|-S' instead\n");
#endif /* LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 9, 59, 0) */
		case 'S':
			if (!(param->fp_verbose & VERBOSE_DETAIL)) {
				param->fp_verbose |= VERBOSE_SIZE;
				param->fp_max_depth = 0;
			}
			break;
		case 'v':
			param->fp_verbose = VERBOSE_DEFAULT | VERBOSE_DETAIL;
			break;
		case 'y':
			param->fp_yaml = 1;
			break;
		default:
			return CMD_HELP;
		}
	}

	if (optind >= argc)
		return CMD_HELP;

	if (param->fp_recursive)
		param->fp_max_depth = -1;
	else if (param->fp_verbose & VERBOSE_DETAIL)
		param->fp_max_depth = 1;

	if (!param->fp_verbose)
		param->fp_verbose = VERBOSE_DEFAULT;
	if (param->fp_quiet)
		param->fp_verbose = VERBOSE_OBJID;

	do {
		rc = llapi_getstripe(argv[optind], param);
	} while (++optind < argc && !rc);

	if (rc)
		fprintf(stderr, "error: %s failed for %s.\n",
			argv[0], argv[optind - 1]);
	return rc;
}

static int lfs_tgts(int argc, char **argv)
{
        char mntdir[PATH_MAX] = {'\0'}, path[PATH_MAX] = {'\0'};
        struct find_param param;
        int index = 0, rc=0;

        if (argc > 2)
                return CMD_HELP;

        if (argc == 2 && !realpath(argv[1], path)) {
                rc = -errno;
                fprintf(stderr, "error: invalid path '%s': %s\n",
                        argv[1], strerror(-rc));
                return rc;
        }

        while (!llapi_search_mounts(path, index++, mntdir, NULL)) {
                /* Check if we have a mount point */
                if (mntdir[0] == '\0')
                        continue;

                memset(&param, 0, sizeof(param));
                if (!strcmp(argv[0], "mdts"))
			param.fp_get_lmv = 1;

                rc = llapi_ostlist(mntdir, &param);
                if (rc) {
                        fprintf(stderr, "error: %s: failed on %s\n",
                                argv[0], mntdir);
                }
                if (path[0] != '\0')
                        break;
                memset(mntdir, 0, PATH_MAX);
        }

        return rc;
}

static int lfs_getstripe(int argc, char **argv)
{
	struct find_param param = { 0 };

	param.fp_max_depth = 1;
	return lfs_getstripe_internal(argc, argv, &param);
}

/* functions */
static int lfs_getdirstripe(int argc, char **argv)
{
	struct find_param param = { 0 };
	struct option long_opts[] = {
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
		{"mdt-count",	no_argument,		0, 'c'},
#endif
		{"mdt-hash",	no_argument,		0, 'H'},
		{"mdt-index",	no_argument,		0, 'i'},
		{"recursive",	no_argument,		0, 'r'},
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
		{"mdt-hash",	no_argument,		0, 't'},
#endif
		{"default",	no_argument,		0, 'D'},
		{"obd",		required_argument,	0, 'O'},
		{"mdt-count",	no_argument,		0, 'T'},
		{"yaml",	no_argument,		0, 'y'},
		{0, 0, 0, 0}
	};
	int c, rc;

	param.fp_get_lmv = 1;

	while ((c = getopt_long(argc, argv,
				"cDHiO:rtTy", long_opts, NULL)) != -1)
	{
		switch (c) {
		case 'O':
			if (param.fp_obd_uuid) {
				fprintf(stderr,
					"error: %s: only one obduuid allowed",
					argv[0]);
				return CMD_HELP;
			}
			param.fp_obd_uuid = (struct obd_uuid *)optarg;
			break;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
		case 'c':
#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 10, 50, 0)
			fprintf(stderr, "warning: '-c' deprecated"
				", use '-T' instead\n");
#endif
#endif
		case 'T':
			param.fp_verbose |= VERBOSE_COUNT;
			break;
		case 'i':
			param.fp_verbose |= VERBOSE_OFFSET;
			break;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
		case 't':
#endif
		case 'H':
			param.fp_verbose |= VERBOSE_HASH_TYPE;
			break;
		case 'D':
			param.fp_get_default_lmv = 1;
			break;
		case 'r':
			param.fp_recursive = 1;
			break;
		case 'y':
			param.fp_yaml = 1;
			break;
		default:
			return CMD_HELP;
		}
	}

	if (optind >= argc)
		return CMD_HELP;

	if (param.fp_recursive)
		param.fp_max_depth = -1;

	if (!param.fp_verbose)
		param.fp_verbose = VERBOSE_DEFAULT;

	do {
		rc = llapi_getstripe(argv[optind], &param);
	} while (++optind < argc && !rc);

	if (rc)
		fprintf(stderr, "error: %s failed for %s.\n",
			argv[0], argv[optind - 1]);
	return rc;
}

/* functions */
static int lfs_setdirstripe(int argc, char **argv)
{
	char			*dname;
	int			result;
	unsigned int		stripe_offset = -1;
	unsigned int		stripe_count = 1;
	enum lmv_hash_type	hash_type;
	char			*end;
	int			c;
	char			*stripe_offset_opt = NULL;
	char			*stripe_count_opt = NULL;
	char			*stripe_hash_opt = NULL;
	char			*mode_opt = NULL;
	bool			default_stripe = false;
	mode_t			mode = S_IRWXU | S_IRWXG | S_IRWXO;
	mode_t			previous_mode = 0;
	bool			delete = false;

	struct option long_opts[] = {
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
	{ .val = 'c',	.name = "count",	.has_arg = required_argument },
#endif
	{ .val = 'c',	.name = "mdt-count",	.has_arg = required_argument },
	{ .val = 'd',	.name = "delete",	.has_arg = no_argument },
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
	{ .val = 'i',	.name = "index",	.has_arg = required_argument },
#endif
	{ .val = 'i',	.name = "mdt-index",	.has_arg = required_argument },
	{ .val = 'm',	.name = "mode",		.has_arg = required_argument },
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
	{ .val = 't',	.name = "hash-type",	.has_arg = required_argument },
	{ .val = 't',	.name = "mdt-hash",	.has_arg = required_argument },
#endif
		{"mdt-hash",	required_argument, 0, 'H'},
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
	{ .val = 'D',	.name = "default_stripe",
						.has_arg = no_argument },
#endif
	{ .val = 'D',	.name = "default",	.has_arg = no_argument },
	{ .name = NULL } };

	while ((c = getopt_long(argc, argv, "c:dDi:H:m:t:", long_opts,
				NULL)) >= 0) {
		switch (c) {
		case 0:
			/* Long options. */
			break;
		case 'c':
#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 11, 53, 0)
			if (strcmp(argv[optind - 1], "--count") == 0)
				fprintf(stderr, "warning: '--count' deprecated"
					", use '--mdt-count' instead\n");
#endif
			stripe_count_opt = optarg;
			break;
		case 'd':
			delete = true;
			default_stripe = true;
			break;
		case 'D':
			default_stripe = true;
			break;
		case 'i':
#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 11, 53, 0)
			if (strcmp(argv[optind - 1], "--index") == 0)
				fprintf(stderr, "warning: '--index' deprecated"
					", use '--mdt-index' instead\n");
#endif
			stripe_offset_opt = optarg;
			break;
		case 'm':
			mode_opt = optarg;
			break;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
		case 't':
#endif
		case 'H':
#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 11, 53, 0)
			if (strcmp(argv[optind - 1], "--hash-type") == 0)
				fprintf(stderr, "warning: '--hash-type' "
					"deprecated, use '--mdt-hash' "
					"instead\n");
#endif
			stripe_hash_opt = optarg;
			break;
		default:
			fprintf(stderr, "error: %s: option '%s' "
					"unrecognized\n",
					argv[0], argv[optind - 1]);
			return CMD_HELP;
		}
	}

	if (optind == argc) {
		fprintf(stderr, "error: %s: missing dirname\n",
			argv[0]);
		return CMD_HELP;
	}

	if (!delete && stripe_offset_opt == NULL && stripe_count_opt == NULL) {
		fprintf(stderr, "error: %s: missing stripe offset and count.\n",
			argv[0]);
		return CMD_HELP;
	}

	if (stripe_offset_opt != NULL) {
		/* get the stripe offset */
		stripe_offset = strtoul(stripe_offset_opt, &end, 0);
		if (*end != '\0') {
			fprintf(stderr, "error: %s: bad stripe offset '%s'\n",
				argv[0], stripe_offset_opt);
			return CMD_HELP;
		}
	}

	if (delete) {
		if (stripe_offset_opt != NULL || stripe_count_opt != NULL) {
			fprintf(stderr, "error: %s: cannot specify -d with -s,"
				" or -i options.\n", argv[0]);
			return CMD_HELP;
		} else {
			stripe_count = 0;
		}
	}


	if (mode_opt != NULL) {
		mode = strtoul(mode_opt, &end, 8);
		if (*end != '\0') {
			fprintf(stderr, "error: %s: bad mode '%s'\n",
				argv[0], mode_opt);
			return CMD_HELP;
		}
		previous_mode = umask(0);
	}

	if (stripe_hash_opt == NULL) {
		hash_type = LMV_HASH_TYPE_FNV_1A_64;
	} else {
		hash_type = check_hashtype(stripe_hash_opt);
		if (hash_type == 0) {
			fprintf(stderr,
				"error: %s: bad stripe hash type '%s'\n",
				argv[0], stripe_hash_opt);
			return CMD_HELP;
		}
	}

	/* get the stripe count */
	if (stripe_count_opt != NULL) {
		stripe_count = strtoul(stripe_count_opt, &end, 0);
		if (*end != '\0') {
			fprintf(stderr, "error: %s: bad stripe count '%s'\n",
				argv[0], stripe_count_opt);
			return CMD_HELP;
		}
	}

	dname = argv[optind];
	do {
		if (default_stripe) {
			result = llapi_dir_set_default_lmv_stripe(dname,
						    stripe_offset, stripe_count,
						    hash_type, NULL);
		} else {
			result = llapi_dir_create_pool(dname, mode,
						       stripe_offset,
						       stripe_count, hash_type,
						       NULL);
		}

		if (result) {
			fprintf(stderr, "error: %s: create stripe dir '%s' "
				"failed\n", argv[0], dname);
			break;
		}
		dname = argv[++optind];
	} while (dname != NULL);

	if (mode_opt != NULL)
		umask(previous_mode);

	return result;
}

/* functions */
static int lfs_rmentry(int argc, char **argv)
{
	char *dname;
	int   index;
	int   result = 0;

	if (argc <= 1) {
		fprintf(stderr, "error: %s: missing dirname\n",
			argv[0]);
		return CMD_HELP;
	}

	index = 1;
	dname = argv[index];
	while (dname != NULL) {
		result = llapi_direntry_remove(dname);
		if (result) {
			fprintf(stderr, "error: %s: remove dir entry '%s' "
				"failed\n", argv[0], dname);
			break;
		}
		dname = argv[++index];
	}
	return result;
}

static int lfs_mv(int argc, char **argv)
{
	struct  find_param param = {
		.fp_max_depth = -1,
		.fp_mdt_index = -1,
	};
	char   *end;
	int     c;
	int     rc = 0;
	struct option long_opts[] = {
		{"mdt-index", required_argument, 0, 'M'},
		{"verbose",	no_argument,	   0, 'v'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, "M:v", long_opts, NULL)) != -1) {
		switch (c) {
		case 'M': {
			param.fp_mdt_index = strtoul(optarg, &end, 0);
			if (*end != '\0') {
				fprintf(stderr, "%s: invalid MDT index'%s'\n",
					argv[0], optarg);
				return CMD_HELP;
			}
			break;
		}
		case 'v': {
			param.fp_verbose = VERBOSE_DETAIL;
			break;
		}
		default:
			fprintf(stderr, "error: %s: unrecognized option '%s'\n",
				argv[0], argv[optind - 1]);
			return CMD_HELP;
		}
	}

	if (param.fp_mdt_index == -1) {
		fprintf(stderr, "%s: MDT index must be specified\n", argv[0]);
		return CMD_HELP;
	}

	if (optind >= argc) {
		fprintf(stderr, "%s: missing operand path\n", argv[0]);
		return CMD_HELP;
	}

	param.fp_migrate = 1;
	rc = llapi_migrate_mdt(argv[optind], &param);
	if (rc != 0)
		fprintf(stderr, "%s: cannot migrate '%s' to MDT%04x: %s\n",
			argv[0], argv[optind], param.fp_mdt_index,
			strerror(-rc));
	return rc;
}

static int lfs_osts(int argc, char **argv)
{
        return lfs_tgts(argc, argv);
}

static int lfs_mdts(int argc, char **argv)
{
        return lfs_tgts(argc, argv);
}

#define COOK(value)                                                     \
({                                                                      \
        int radix = 0;                                                  \
        while (value > 1024) {                                          \
                value /= 1024;                                          \
                radix++;                                                \
        }                                                               \
        radix;                                                          \
})
#define UUF     "%-20s"
#define CSF     "%11s"
#define CDF     "%11llu"
#define HDF     "%8.1f%c"
#define RSF     "%4s"
#define RDF     "%3d%%"

enum mntdf_flags {
	MNTDF_INODES	= 0x0001,
	MNTDF_COOKED	= 0x0002,
	MNTDF_LAZY	= 0x0004,
	MNTDF_VERBOSE	= 0x0008,
};

static int showdf(char *mntdir, struct obd_statfs *stat,
		  char *uuid, enum mntdf_flags flags,
		  char *type, int index, int rc)
{
	long long avail, used, total;
	double ratio = 0;
	char *suffix = "KMGTPEZY";
	/* Note if we have >2^64 bytes/fs these buffers will need to be grown */
	char tbuf[3 * sizeof(__u64)];
	char ubuf[3 * sizeof(__u64)];
	char abuf[3 * sizeof(__u64)];
	char rbuf[3 * sizeof(__u64)];

	if (!uuid || !stat)
		return -EINVAL;

	switch (rc) {
	case 0:
		if (flags & MNTDF_INODES) {
			avail = stat->os_ffree;
			used = stat->os_files - stat->os_ffree;
			total = stat->os_files;
		} else {
			int shift = flags & MNTDF_COOKED ? 0 : 10;

			avail = (stat->os_bavail * stat->os_bsize) >> shift;
			used  = ((stat->os_blocks - stat->os_bfree) *
				 stat->os_bsize) >> shift;
			total = (stat->os_blocks * stat->os_bsize) >> shift;
		}

		if ((used + avail) > 0)
			ratio = (double)used / (double)(used + avail);

		if (flags & MNTDF_COOKED) {
			int i;
			double cook_val;

			cook_val = (double)total;
			i = COOK(cook_val);
			if (i > 0)
				snprintf(tbuf, sizeof(tbuf), HDF, cook_val,
					 suffix[i - 1]);
			else
				snprintf(tbuf, sizeof(tbuf), CDF, total);

			cook_val = (double)used;
			i = COOK(cook_val);
			if (i > 0)
				snprintf(ubuf, sizeof(ubuf), HDF, cook_val,
					 suffix[i - 1]);
			else
				snprintf(ubuf, sizeof(ubuf), CDF, used);

			cook_val = (double)avail;
			i = COOK(cook_val);
			if (i > 0)
				snprintf(abuf, sizeof(abuf), HDF, cook_val,
					 suffix[i - 1]);
			else
				snprintf(abuf, sizeof(abuf), CDF, avail);
		} else {
			snprintf(tbuf, sizeof(tbuf), CDF, total);
			snprintf(ubuf, sizeof(tbuf), CDF, used);
			snprintf(abuf, sizeof(tbuf), CDF, avail);
		}

		sprintf(rbuf, RDF, (int)(ratio * 100 + 0.5));
		printf(UUF" "CSF" "CSF" "CSF" "RSF" %-s",
		       uuid, tbuf, ubuf, abuf, rbuf, mntdir);
		if (type)
			printf("[%s:%d]", type, index);

		if (stat->os_state) {
			/*
			 * Each character represents the matching
			 * OS_STATE_* bit.
			 */
			const char state_names[] = "DRSI";
			__u32	   state;
			__u32	   i;

			printf(" ");
			for (i = 0, state = stat->os_state;
			     state && i < sizeof(state_names); i++) {
				if (!(state & (1 << i)))
					continue;
				printf("%c", state_names[i]);
				state ^= 1 << i;
			}
		}

		printf("\n");
		break;
	case -ENODATA:
		printf(UUF": inactive device\n", uuid);
		break;
	default:
		printf(UUF": %s\n", uuid, strerror(-rc));
		break;
	}

	return 0;
}

struct ll_stat_type {
        int   st_op;
        char *st_name;
};

static int mntdf(char *mntdir, char *fsname, char *pool, enum mntdf_flags flags)
{
	struct obd_statfs stat_buf, sum = { .os_bsize = 1 };
	struct obd_uuid uuid_buf;
	char *poolname = NULL;
	struct ll_stat_type types[] = { { LL_STATFS_LMV, "MDT" },
					{ LL_STATFS_LOV, "OST" },
					{ 0, NULL } };
	struct ll_stat_type *tp;
	__u64 ost_ffree = 0;
	__u32 index;
	__u32 type;
	int fd;
	int rc = 0;
	int rc2;

	if (pool) {
		poolname = strchr(pool, '.');
		if (poolname != NULL) {
			if (strncmp(fsname, pool, strlen(fsname))) {
				fprintf(stderr, "filesystem name incorrect\n");
				return -ENODEV;
			}
			poolname++;
		} else
			poolname = pool;
	}

	fd = open(mntdir, O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		fprintf(stderr, "%s: cannot open '%s': %s\n", progname, mntdir,
			strerror(errno));
		return rc;
	}

	if (flags & MNTDF_INODES)
		printf(UUF" "CSF" "CSF" "CSF" "RSF" %-s\n",
		       "UUID", "Inodes", "IUsed", "IFree",
		       "IUse%", "Mounted on");
	else
		printf(UUF" "CSF" "CSF" "CSF" "RSF" %-s\n",
		       "UUID", flags & MNTDF_COOKED ? "bytes" : "1K-blocks",
		       "Used", "Available", "Use%", "Mounted on");

	for (tp = types; tp->st_name != NULL; tp++) {
		for (index = 0; ; index++) {
			memset(&stat_buf, 0, sizeof(struct obd_statfs));
			memset(&uuid_buf, 0, sizeof(struct obd_uuid));
			type = flags & MNTDF_LAZY ?
				tp->st_op | LL_STATFS_NODELAY : tp->st_op;
			rc2 = llapi_obd_fstatfs(fd, type, index,
					       &stat_buf, &uuid_buf);
			if (rc2 == -ENODEV)
				break;
			if (rc2 == -EAGAIN)
				continue;
			if (rc2 == -ENODATA) { /* Inactive device, OK. */
				if (!(flags & MNTDF_VERBOSE))
					continue;
			} else if (rc2 < 0 && rc == 0) {
				rc = rc2;
			}

			if (poolname && tp->st_op == LL_STATFS_LOV &&
			    llapi_search_ost(fsname, poolname,
					     obd_uuid2str(&uuid_buf)) != 1)
				continue;

			/* the llapi_obd_statfs() call may have returned with
			 * an error, but if it filled in uuid_buf we will at
			 * lease use that to print out a message for that OBD.
			 * If we didn't get anything in the uuid_buf, then fill
			 * it in so that we can print an error message. */
			if (uuid_buf.uuid[0] == '\0')
				snprintf(uuid_buf.uuid, sizeof(uuid_buf.uuid),
					 "%s%04x", tp->st_name, index);
			showdf(mntdir, &stat_buf, obd_uuid2str(&uuid_buf),
			       flags, tp->st_name, index, rc2);

			if (rc2 == 0) {
				if (tp->st_op == LL_STATFS_LMV) {
					sum.os_ffree += stat_buf.os_ffree;
					sum.os_files += stat_buf.os_files;
				} else /* if (tp->st_op == LL_STATFS_LOV) */ {
					sum.os_blocks += stat_buf.os_blocks *
						stat_buf.os_bsize;
					sum.os_bfree  += stat_buf.os_bfree *
						stat_buf.os_bsize;
					sum.os_bavail += stat_buf.os_bavail *
						stat_buf.os_bsize;
					ost_ffree += stat_buf.os_ffree;
				}
			}
		}
	}

	close(fd);

	/* If we don't have as many objects free on the OST as inodes
	 * on the MDS, we reduce the total number of inodes to
	 * compensate, so that the "inodes in use" number is correct.
	 * Matches ll_statfs_internal() so the results are consistent. */
	if (ost_ffree < sum.os_ffree) {
		sum.os_files = (sum.os_files - sum.os_ffree) + ost_ffree;
		sum.os_ffree = ost_ffree;
	}
	printf("\n");
	showdf(mntdir, &sum, "filesystem_summary:", flags, NULL, 0, 0);
	printf("\n");

	return rc;
}

static int lfs_df(int argc, char **argv)
{
	char mntdir[PATH_MAX] = {'\0'}, path[PATH_MAX] = {'\0'};
	enum mntdf_flags flags = 0;
	int c, rc = 0, index = 0;
	char fsname[PATH_MAX] = "", *pool_name = NULL;
	struct option long_opts[] = {
	{ .val = 'h',	.name = "human-readable",
						.has_arg = no_argument },
	{ .val = 'i',	.name = "inodes",	.has_arg = no_argument },
	{ .val = 'l',	.name = "lazy",		.has_arg = no_argument },
	{ .val = 'p',	.name = "pool",		.has_arg = required_argument },
	{ .val = 'v',	.name = "verbose",	.has_arg = no_argument },
	{ .name = NULL} };

	while ((c = getopt_long(argc, argv, "hilp:v", long_opts, NULL)) != -1) {
		switch (c) {
		case 'h':
			flags |= MNTDF_COOKED;
			break;
		case 'i':
			flags |= MNTDF_INODES;
			break;
		case 'l':
			flags |= MNTDF_LAZY;
			break;
		case 'p':
			pool_name = optarg;
			break;
		case 'v':
			flags |= MNTDF_VERBOSE;
			break;
		default:
			return CMD_HELP;
		}
	}
	if (optind < argc && !realpath(argv[optind], path)) {
		rc = -errno;
		fprintf(stderr, "error: invalid path '%s': %s\n",
			argv[optind], strerror(-rc));
		return rc;
	}

	while (!llapi_search_mounts(path, index++, mntdir, fsname)) {
		/* Check if we have a mount point */
		if (mntdir[0] == '\0')
			continue;

		rc = mntdf(mntdir, fsname, pool_name, flags);
		if (rc || path[0] != '\0')
			break;
		fsname[0] = '\0'; /* avoid matching in next loop */
		mntdir[0] = '\0'; /* avoid matching in next loop */
	}

	return rc;
}

static int lfs_getname(int argc, char **argv)
{
        char mntdir[PATH_MAX] = "", path[PATH_MAX] = "", fsname[PATH_MAX] = "";
        int rc = 0, index = 0, c;
        char buf[sizeof(struct obd_uuid)];

        while ((c = getopt(argc, argv, "h")) != -1)
                return CMD_HELP;

        if (optind == argc) { /* no paths specified, get all paths. */
                while (!llapi_search_mounts(path, index++, mntdir, fsname)) {
                        rc = llapi_getname(mntdir, buf, sizeof(buf));
                        if (rc < 0) {
                                fprintf(stderr,
                                        "cannot get name for `%s': %s\n",
                                        mntdir, strerror(-rc));
                                break;
                        }

                        printf("%s %s\n", buf, mntdir);

                        path[0] = fsname[0] = mntdir[0] = 0;
                }
        } else { /* paths specified, only attempt to search these. */
                for (; optind < argc; optind++) {
                        rc = llapi_getname(argv[optind], buf, sizeof(buf));
                        if (rc < 0) {
                                fprintf(stderr,
                                        "cannot get name for `%s': %s\n",
                                        argv[optind], strerror(-rc));
                                break;
                        }

                        printf("%s %s\n", buf, argv[optind]);
                }
        }
        return rc;
}

static int lfs_check(int argc, char **argv)
{
        int rc;
        char mntdir[PATH_MAX] = {'\0'};
        int num_types = 1;
        char *obd_types[2];
        char obd_type1[4];
        char obd_type2[4];

        if (argc != 2)
                return CMD_HELP;

        obd_types[0] = obd_type1;
        obd_types[1] = obd_type2;

        if (strcmp(argv[1], "osts") == 0) {
                strcpy(obd_types[0], "osc");
        } else if (strcmp(argv[1], "mds") == 0) {
                strcpy(obd_types[0], "mdc");
        } else if (strcmp(argv[1], "servers") == 0) {
                num_types = 2;
                strcpy(obd_types[0], "osc");
                strcpy(obd_types[1], "mdc");
        } else {
                fprintf(stderr, "error: %s: option '%s' unrecognized\n",
                                argv[0], argv[1]);
                        return CMD_HELP;
        }

        rc = llapi_search_mounts(NULL, 0, mntdir, NULL);
        if (rc < 0 || mntdir[0] == '\0') {
                fprintf(stderr, "No suitable Lustre mount found\n");
                return rc;
        }

	rc = llapi_target_check(num_types, obd_types, mntdir);
        if (rc)
                fprintf(stderr, "error: %s: %s status failed\n",
                                argv[0],argv[1]);

        return rc;

}

#ifdef HAVE_SYS_QUOTA_H
#define ARG2INT(nr, str, msg)                                           \
do {                                                                    \
        char *endp;                                                     \
        nr = strtol(str, &endp, 0);                                     \
        if (*endp) {                                                    \
                fprintf(stderr, "error: bad %s: %s\n", msg, str);       \
                return CMD_HELP;                                        \
        }                                                               \
} while (0)

#define ADD_OVERFLOW(a,b) ((a + b) < a) ? (a = ULONG_MAX) : (a = a + b)

/* Convert format time string "XXwXXdXXhXXmXXs" into seconds value
 * returns the value or ULONG_MAX on integer overflow or incorrect format
 * Notes:
 *        1. the order of specifiers is arbitrary (may be: 5w3s or 3s5w)
 *        2. specifiers may be encountered multiple times (2s3s is 5 seconds)
 *        3. empty integer value is interpreted as 0
 */
static unsigned long str2sec(const char* timestr)
{
        const char spec[] = "smhdw";
        const unsigned long mult[] = {1, 60, 60*60, 24*60*60, 7*24*60*60};
        unsigned long val = 0;
        char *tail;

        if (strpbrk(timestr, spec) == NULL) {
                /* no specifiers inside the time string,
                   should treat it as an integer value */
                val = strtoul(timestr, &tail, 10);
                return *tail ? ULONG_MAX : val;
        }

        /* format string is XXwXXdXXhXXmXXs */
        while (*timestr) {
                unsigned long v;
                int ind;
                char* ptr;

                v = strtoul(timestr, &tail, 10);
                if (v == ULONG_MAX || *tail == '\0')
                        /* value too large (ULONG_MAX or more)
                           or missing specifier */
                        goto error;

                ptr = strchr(spec, *tail);
                if (ptr == NULL)
                        /* unknown specifier */
                        goto error;

                ind = ptr - spec;

                /* check if product will overflow the type */
                if (!(v < ULONG_MAX / mult[ind]))
                        goto error;

                ADD_OVERFLOW(val, mult[ind] * v);
                if (val == ULONG_MAX)
                        goto error;

                timestr = tail + 1;
        }

        return val;

error:
        return ULONG_MAX;
}

#define ARG2ULL(nr, str, def_units)					\
do {									\
	unsigned long long limit, units = def_units;			\
	int rc;								\
									\
	rc = llapi_parse_size(str, &limit, &units, 1);			\
	if (rc < 0) {							\
		fprintf(stderr, "error: bad limit value %s\n", str);	\
		return CMD_HELP;					\
	}								\
	nr = limit;							\
} while (0)

static inline int has_times_option(int argc, char **argv)
{
        int i;

        for (i = 1; i < argc; i++)
                if (!strcmp(argv[i], "-t"))
                        return 1;

        return 0;
}

int lfs_setquota_times(int argc, char **argv)
{
        int c, rc;
        struct if_quotactl qctl;
        char *mnt, *obd_type = (char *)qctl.obd_type;
        struct obd_dqblk *dqb = &qctl.qc_dqblk;
        struct obd_dqinfo *dqi = &qctl.qc_dqinfo;
        struct option long_opts[] = {
	{ .val = 'b',	.name = "block-grace",	.has_arg = required_argument },
	{ .val = 'g',	.name = "group",	.has_arg = no_argument },
	{ .val = 'i',	.name = "inode-grace",	.has_arg = required_argument },
	{ .val = 'p',	.name = "projid",	.has_arg = no_argument },
	{ .val = 't',	.name = "times",	.has_arg = no_argument },
	{ .val = 'u',	.name = "user",		.has_arg = no_argument },
	{ .name = NULL } };
	int qtype;

	memset(&qctl, 0, sizeof(qctl));
	qctl.qc_cmd  = LUSTRE_Q_SETINFO;
	qctl.qc_type = ALLQUOTA;

	while ((c = getopt_long(argc, argv, "b:gi:ptu",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'u':
			qtype = USRQUOTA;
			goto quota_type;
		case 'g':
			qtype = GRPQUOTA;
			goto quota_type;
		case 'p':
			qtype = PRJQUOTA;
quota_type:
			if (qctl.qc_type != ALLQUOTA) {
				fprintf(stderr, "error: -u/g/p can't be used "
                                                "more than once\n");
				return CMD_HELP;
			}
			qctl.qc_type = qtype;
			break;
                case 'b':
                        if ((dqi->dqi_bgrace = str2sec(optarg)) == ULONG_MAX) {
                                fprintf(stderr, "error: bad block-grace: %s\n",
                                        optarg);
                                return CMD_HELP;
                        }
                        dqb->dqb_valid |= QIF_BTIME;
                        break;
                case 'i':
                        if ((dqi->dqi_igrace = str2sec(optarg)) == ULONG_MAX) {
                                fprintf(stderr, "error: bad inode-grace: %s\n",
                                        optarg);
                                return CMD_HELP;
                        }
                        dqb->dqb_valid |= QIF_ITIME;
                        break;
                case 't': /* Yes, of course! */
                        break;
                default: /* getopt prints error message for us when opterr != 0 */
                        return CMD_HELP;
                }
        }

	if (qctl.qc_type == ALLQUOTA) {
		fprintf(stderr, "error: neither -u, -g nor -p specified\n");
                return CMD_HELP;
        }

        if (optind != argc - 1) {
                fprintf(stderr, "error: unexpected parameters encountered\n");
                return CMD_HELP;
        }

        mnt = argv[optind];
        rc = llapi_quotactl(mnt, &qctl);
        if (rc) {
                if (*obd_type)
                        fprintf(stderr, "%s %s ", obd_type,
                                obd_uuid2str(&qctl.obd_uuid));
                fprintf(stderr, "setquota failed: %s\n", strerror(-rc));
                return rc;
        }

        return 0;
}

#define BSLIMIT (1 << 0)
#define BHLIMIT (1 << 1)
#define ISLIMIT (1 << 2)
#define IHLIMIT (1 << 3)

int lfs_setquota(int argc, char **argv)
{
        int c, rc;
        struct if_quotactl qctl;
        char *mnt, *obd_type = (char *)qctl.obd_type;
        struct obd_dqblk *dqb = &qctl.qc_dqblk;
        struct option long_opts[] = {
                {"block-softlimit", required_argument, 0, 'b'},
                {"block-hardlimit", required_argument, 0, 'B'},
                {"group",           required_argument, 0, 'g'},
                {"inode-softlimit", required_argument, 0, 'i'},
                {"inode-hardlimit", required_argument, 0, 'I'},
                {"user",            required_argument, 0, 'u'},
		{"projid",         required_argument, 0, 'p'},
                {0, 0, 0, 0}
        };
        unsigned limit_mask = 0;
        char *endptr;
	int qtype;

	if (has_times_option(argc, argv))
		return lfs_setquota_times(argc, argv);

	memset(&qctl, 0, sizeof(qctl));
	qctl.qc_cmd  = LUSTRE_Q_SETQUOTA;
	qctl.qc_type = ALLQUOTA; /* ALLQUOTA makes no sense for setquota,
				  * so it can be used as a marker that qc_type
				  * isn't reinitialized from command line */

	while ((c = getopt_long(argc, argv, "b:B:g:i:I:p:u:",
		long_opts, NULL)) != -1) {
		switch (c) {
		case 'u':
			qtype = USRQUOTA;
			rc = name2uid(&qctl.qc_id, optarg);
			goto quota_type;
                case 'g':
			qtype = GRPQUOTA;
			rc = name2gid(&qctl.qc_id, optarg);
			goto quota_type;
		case 'p':
			qtype = PRJQUOTA;
			rc = name2projid(&qctl.qc_id, optarg);
quota_type:
			if (qctl.qc_type != ALLQUOTA) {
				fprintf(stderr, "error: -u and -g can't be used"
						" more than once\n");
				return CMD_HELP;
                        }
			qctl.qc_type = qtype;
			if (rc) {
				qctl.qc_id = strtoul(optarg, &endptr, 10);
				if (*endptr != '\0') {
					fprintf(stderr, "error: can't find id "
						"for name %s\n", optarg);
					return CMD_HELP;
				}
			}
			break;
                case 'b':
			ARG2ULL(dqb->dqb_bsoftlimit, optarg, 1024);
			dqb->dqb_bsoftlimit >>= 10;
			limit_mask |= BSLIMIT;
			if (dqb->dqb_bsoftlimit &&
			    dqb->dqb_bsoftlimit <= 1024) /* <= 1M? */
				fprintf(stderr, "warning: block softlimit is "
					"smaller than the miminal qunit size, "
					"please see the help of setquota or "
					"Lustre manual for details.\n");
                        break;
                case 'B':
                        ARG2ULL(dqb->dqb_bhardlimit, optarg, 1024);
                        dqb->dqb_bhardlimit >>= 10;
                        limit_mask |= BHLIMIT;
			if (dqb->dqb_bhardlimit &&
			    dqb->dqb_bhardlimit <= 1024) /* <= 1M? */
				fprintf(stderr, "warning: block hardlimit is "
					"smaller than the miminal qunit size, "
					"please see the help of setquota or "
					"Lustre manual for details.\n");
                        break;
                case 'i':
                        ARG2ULL(dqb->dqb_isoftlimit, optarg, 1);
                        limit_mask |= ISLIMIT;
			if (dqb->dqb_isoftlimit &&
			    dqb->dqb_isoftlimit <= 1024) /* <= 1K inodes? */
				fprintf(stderr, "warning: inode softlimit is "
					"smaller than the miminal qunit size, "
					"please see the help of setquota or "
					"Lustre manual for details.\n");
                        break;
                case 'I':
                        ARG2ULL(dqb->dqb_ihardlimit, optarg, 1);
                        limit_mask |= IHLIMIT;
			if (dqb->dqb_ihardlimit &&
			    dqb->dqb_ihardlimit <= 1024) /* <= 1K inodes? */
				fprintf(stderr, "warning: inode hardlimit is "
					"smaller than the miminal qunit size, "
					"please see the help of setquota or "
					"Lustre manual for details.\n");
                        break;
                default: /* getopt prints error message for us when opterr != 0 */
			return CMD_HELP;
		}
	}

	if (qctl.qc_type == ALLQUOTA) {
		fprintf(stderr, "error: neither -u, -g nor -p was specified\n");
		return CMD_HELP;
	}

        if (limit_mask == 0) {
                fprintf(stderr, "error: at least one limit must be specified\n");
                return CMD_HELP;
        }

        if (optind != argc - 1) {
                fprintf(stderr, "error: unexpected parameters encountered\n");
                return CMD_HELP;
        }

        mnt = argv[optind];

        if ((!(limit_mask & BHLIMIT) ^ !(limit_mask & BSLIMIT)) ||
            (!(limit_mask & IHLIMIT) ^ !(limit_mask & ISLIMIT))) {
                /* sigh, we can't just set blimits/ilimits */
                struct if_quotactl tmp_qctl = {.qc_cmd  = LUSTRE_Q_GETQUOTA,
                                               .qc_type = qctl.qc_type,
                                               .qc_id   = qctl.qc_id};

                rc = llapi_quotactl(mnt, &tmp_qctl);
                if (rc < 0) {
                        fprintf(stderr, "error: setquota failed while retrieving"
                                        " current quota settings (%s)\n",
                                        strerror(-rc));
                        return rc;
                }

                if (!(limit_mask & BHLIMIT))
                        dqb->dqb_bhardlimit = tmp_qctl.qc_dqblk.dqb_bhardlimit;
                if (!(limit_mask & BSLIMIT))
                        dqb->dqb_bsoftlimit = tmp_qctl.qc_dqblk.dqb_bsoftlimit;
                if (!(limit_mask & IHLIMIT))
                        dqb->dqb_ihardlimit = tmp_qctl.qc_dqblk.dqb_ihardlimit;
                if (!(limit_mask & ISLIMIT))
                        dqb->dqb_isoftlimit = tmp_qctl.qc_dqblk.dqb_isoftlimit;

                /* Keep grace times if we have got no softlimit arguments */
                if ((limit_mask & BHLIMIT) && !(limit_mask & BSLIMIT)) {
                        dqb->dqb_valid |= QIF_BTIME;
                        dqb->dqb_btime = tmp_qctl.qc_dqblk.dqb_btime;
                }

                if ((limit_mask & IHLIMIT) && !(limit_mask & ISLIMIT)) {
                        dqb->dqb_valid |= QIF_ITIME;
                        dqb->dqb_itime = tmp_qctl.qc_dqblk.dqb_itime;
                }
        }

        dqb->dqb_valid |= (limit_mask & (BHLIMIT | BSLIMIT)) ? QIF_BLIMITS : 0;
        dqb->dqb_valid |= (limit_mask & (IHLIMIT | ISLIMIT)) ? QIF_ILIMITS : 0;

        rc = llapi_quotactl(mnt, &qctl);
        if (rc) {
                if (*obd_type)
                        fprintf(stderr, "%s %s ", obd_type,
                                obd_uuid2str(&qctl.obd_uuid));
                fprintf(stderr, "setquota failed: %s\n", strerror(-rc));
                return rc;
        }

        return 0;
}

/* Converts seconds value into format string
 * result is returned in buf
 * Notes:
 *        1. result is in descenting order: 1w2d3h4m5s
 *        2. zero fields are not filled (except for p. 3): 5d1s
 *        3. zero seconds value is presented as "0s"
 */
static char * __sec2str(time_t seconds, char *buf)
{
        const char spec[] = "smhdw";
        const unsigned long mult[] = {1, 60, 60*60, 24*60*60, 7*24*60*60};
        unsigned long c;
        char *tail = buf;
        int i;

        for (i = sizeof(mult) / sizeof(mult[0]) - 1 ; i >= 0; i--) {
                c = seconds / mult[i];

                if (c > 0 || (i == 0 && buf == tail))
                        tail += snprintf(tail, 40-(tail-buf), "%lu%c", c, spec[i]);

                seconds %= mult[i];
        }

        return tail;
}

static void sec2str(time_t seconds, char *buf, int rc)
{
        char *tail = buf;

        if (rc)
                *tail++ = '[';

        tail = __sec2str(seconds, tail);

        if (rc && tail - buf < 39) {
                *tail++ = ']';
                *tail++ = 0;
        }
}

static void diff2str(time_t seconds, char *buf, time_t now)
{

        buf[0] = 0;
        if (!seconds)
                return;
        if (seconds <= now) {
                strcpy(buf, "none");
                return;
        }
        __sec2str(seconds - now, buf);
}

static void print_quota_title(char *name, struct if_quotactl *qctl,
			      bool human_readable)
{
	printf("Disk quotas for %s %s (%cid %u):\n",
	       qtype_name(qctl->qc_type), name,
	       *qtype_name(qctl->qc_type), qctl->qc_id);
	printf("%15s%8s %7s%8s%8s%8s %7s%8s%8s\n",
	       "Filesystem", human_readable ? "used" : "kbytes",
	       "quota", "limit", "grace",
	       "files", "quota", "limit", "grace");
}

static void kbytes2str(__u64 num, char *buf, int buflen, bool h)
{
	if (!h) {
		snprintf(buf, buflen, "%ju", (uintmax_t)num);
	} else {
		if (num >> 40)
			snprintf(buf, buflen, "%5.4gP",
				 (double)num / ((__u64)1 << 40));
		else if (num >> 30)
			snprintf(buf, buflen, "%5.4gT",
				 (double)num / (1 << 30));
		else if (num >> 20)
			snprintf(buf, buflen, "%5.4gG",
				 (double)num / (1 << 20));
		else if (num >> 10)
			snprintf(buf, buflen, "%5.4gM",
				 (double)num / (1 << 10));
		else
			snprintf(buf, buflen, "%ju%s", (uintmax_t)num, "k");
	}
}

#define STRBUF_LEN	32
static void print_quota(char *mnt, struct if_quotactl *qctl, int type,
			int rc, bool h)
{
        time_t now;

        time(&now);

        if (qctl->qc_cmd == LUSTRE_Q_GETQUOTA || qctl->qc_cmd == Q_GETOQUOTA) {
		int bover = 0, iover = 0;
		struct obd_dqblk *dqb = &qctl->qc_dqblk;
		char numbuf[3][STRBUF_LEN];
		char timebuf[40];
		char strbuf[STRBUF_LEN];

                if (dqb->dqb_bhardlimit &&
		    lustre_stoqb(dqb->dqb_curspace) >= dqb->dqb_bhardlimit) {
                        bover = 1;
                } else if (dqb->dqb_bsoftlimit && dqb->dqb_btime) {
                        if (dqb->dqb_btime > now) {
                                bover = 2;
                        } else {
                                bover = 3;
                        }
                }

                if (dqb->dqb_ihardlimit &&
                    dqb->dqb_curinodes >= dqb->dqb_ihardlimit) {
                        iover = 1;
                } else if (dqb->dqb_isoftlimit && dqb->dqb_itime) {
			if (dqb->dqb_itime > now) {
				iover = 2;
			} else {
				iover = 3;
			}
                }


		if (strlen(mnt) > 15)
			printf("%s\n%15s", mnt, "");
		else
			printf("%15s", mnt);

		if (bover)
			diff2str(dqb->dqb_btime, timebuf, now);

		kbytes2str(lustre_stoqb(dqb->dqb_curspace),
			   strbuf, sizeof(strbuf), h);
		if (rc == -EREMOTEIO)
			sprintf(numbuf[0], "%s*", strbuf);
		else
			sprintf(numbuf[0], (dqb->dqb_valid & QIF_SPACE) ?
				"%s" : "[%s]", strbuf);

		kbytes2str(dqb->dqb_bsoftlimit, strbuf, sizeof(strbuf), h);
		if (type == QC_GENERAL)
			sprintf(numbuf[1], (dqb->dqb_valid & QIF_BLIMITS) ?
				"%s" : "[%s]", strbuf);
		else
			sprintf(numbuf[1], "%s", "-");

		kbytes2str(dqb->dqb_bhardlimit, strbuf, sizeof(strbuf), h);
		sprintf(numbuf[2], (dqb->dqb_valid & QIF_BLIMITS) ?
			"%s" : "[%s]", strbuf);

		printf(" %7s%c %6s %7s %7s",
		       numbuf[0], bover ? '*' : ' ', numbuf[1],
		       numbuf[2], bover > 1 ? timebuf : "-");

		if (iover)
			diff2str(dqb->dqb_itime, timebuf, now);

		sprintf(numbuf[0], (dqb->dqb_valid & QIF_INODES) ?
			"%ju" : "[%ju]", (uintmax_t)dqb->dqb_curinodes);

		if (type == QC_GENERAL)
			sprintf(numbuf[1], (dqb->dqb_valid & QIF_ILIMITS) ?
				"%ju" : "[%ju]",
				(uintmax_t)dqb->dqb_isoftlimit);
		else
			sprintf(numbuf[1], "%s", "-");

		sprintf(numbuf[2], (dqb->dqb_valid & QIF_ILIMITS) ?
			"%ju" : "[%ju]", (uintmax_t)dqb->dqb_ihardlimit);

		if (type != QC_OSTIDX)
			printf(" %7s%c %6s %7s %7s",
			       numbuf[0], iover ? '*' : ' ', numbuf[1],
			       numbuf[2], iover > 1 ? timebuf : "-");
		else
			printf(" %7s %7s %7s %7s", "-", "-", "-", "-");
		printf("\n");

        } else if (qctl->qc_cmd == LUSTRE_Q_GETINFO ||
                   qctl->qc_cmd == Q_GETOINFO) {
                char bgtimebuf[40];
                char igtimebuf[40];

                sec2str(qctl->qc_dqinfo.dqi_bgrace, bgtimebuf, rc);
                sec2str(qctl->qc_dqinfo.dqi_igrace, igtimebuf, rc);
                printf("Block grace time: %s; Inode grace time: %s\n",
                       bgtimebuf, igtimebuf);
        }
}

static int print_obd_quota(char *mnt, struct if_quotactl *qctl, int is_mdt,
			   bool h, __u64 *total)
{
        int rc = 0, rc1 = 0, count = 0;
        __u32 valid = qctl->qc_valid;

        rc = llapi_get_obd_count(mnt, &count, is_mdt);
        if (rc) {
                fprintf(stderr, "can not get %s count: %s\n",
                        is_mdt ? "mdt": "ost", strerror(-rc));
                return rc;
        }

        for (qctl->qc_idx = 0; qctl->qc_idx < count; qctl->qc_idx++) {
                qctl->qc_valid = is_mdt ? QC_MDTIDX : QC_OSTIDX;
                rc = llapi_quotactl(mnt, qctl);
                if (rc) {
			/* It is remote client case. */
			if (rc == -EOPNOTSUPP) {
                                rc = 0;
                                goto out;
                        }

                        if (!rc1)
                                rc1 = rc;
                        fprintf(stderr, "quotactl %s%d failed.\n",
                                is_mdt ? "mdt": "ost", qctl->qc_idx);
                        continue;
                }

		print_quota(obd_uuid2str(&qctl->obd_uuid), qctl,
			    qctl->qc_valid, 0, h);
		*total += is_mdt ? qctl->qc_dqblk.dqb_ihardlimit :
				   qctl->qc_dqblk.dqb_bhardlimit;
	}
out:
	qctl->qc_valid = valid;
	return rc ? : rc1;
}

static int lfs_quota(int argc, char **argv)
{
	int c;
	char *mnt, *name = NULL;
	struct if_quotactl qctl = { .qc_cmd = LUSTRE_Q_GETQUOTA,
				    .qc_type = ALLQUOTA };
	char *obd_type = (char *)qctl.obd_type;
	char *obd_uuid = (char *)qctl.obd_uuid.uuid;
	int rc = 0, rc1 = 0, rc2 = 0, rc3 = 0,
	    verbose = 0, pass = 0, quiet = 0, inacc;
	char *endptr;
	__u32 valid = QC_GENERAL, idx = 0;
	__u64 total_ialloc = 0, total_balloc = 0;
	bool human_readable = false;
	int qtype;

	while ((c = getopt(argc, argv, "gi:I:o:pqtuvh")) != -1) {
		switch (c) {
		case 'u':
			qtype = USRQUOTA;
			goto quota_type;
		case 'g':
			qtype = GRPQUOTA;
			goto quota_type;
		case 'p':
			qtype = PRJQUOTA;
quota_type:
			if (qctl.qc_type != ALLQUOTA) {
				fprintf(stderr, "error: use either -u or -g\n");
				return CMD_HELP;
			}
			qctl.qc_type = qtype;
			break;
                case 't':
                        qctl.qc_cmd = LUSTRE_Q_GETINFO;
                        break;
                case 'o':
                        valid = qctl.qc_valid = QC_UUID;
			strlcpy(obd_uuid, optarg, sizeof(qctl.obd_uuid));
                        break;
                case 'i':
                        valid = qctl.qc_valid = QC_MDTIDX;
                        idx = qctl.qc_idx = atoi(optarg);
                        break;
                case 'I':
                        valid = qctl.qc_valid = QC_OSTIDX;
                        idx = qctl.qc_idx = atoi(optarg);
                        break;
                case 'v':
                        verbose = 1;
                        break;
                case 'q':
                        quiet = 1;
                        break;
		case 'h':
			human_readable = true;
			break;
                default:
                        fprintf(stderr, "error: %s: option '-%c' "
                                        "unrecognized\n", argv[0], c);
                        return CMD_HELP;
                }
        }

        /* current uid/gid info for "lfs quota /path/to/lustre/mount" */
	if (qctl.qc_cmd == LUSTRE_Q_GETQUOTA && qctl.qc_type == ALLQUOTA &&
	    optind == argc - 1) {
all_output:
		memset(&qctl, 0, sizeof(qctl)); /* spoiled by print_*_quota */
		qctl.qc_cmd = LUSTRE_Q_GETQUOTA;
		qctl.qc_valid = valid;
		qctl.qc_idx = idx;
		qctl.qc_type = pass;
		switch (qctl.qc_type) {
		case USRQUOTA:
			qctl.qc_id = geteuid();
			rc = uid2name(&name, qctl.qc_id);
			break;
		case GRPQUOTA:
			qctl.qc_id = getegid();
			rc = gid2name(&name, qctl.qc_id);
			break;
		default:
			rc = -ENOTSUP;
			pass++;
			goto out;
		}
		if (rc)
			name = "<unknown>";
		pass++;
	/* lfs quota -u username /path/to/lustre/mount */
	} else if (qctl.qc_cmd == LUSTRE_Q_GETQUOTA) {
		/* options should be followed by u/g-name and mntpoint */
		if (optind + 2 != argc || qctl.qc_type == ALLQUOTA) {
			fprintf(stderr, "error: missing quota argument(s)\n");
			return CMD_HELP;
		}

		name = argv[optind++];
		switch (qctl.qc_type) {
		case USRQUOTA:
			rc = name2uid(&qctl.qc_id, name);
			break;
		case GRPQUOTA:
			rc = name2gid(&qctl.qc_id, name);
			break;
		case PRJQUOTA:
			rc = name2projid(&qctl.qc_id, name);
			break;
		default:
			rc = -ENOTSUP;
			break;
		}
		if (rc) {
			qctl.qc_id = strtoul(name, &endptr, 10);
			if (*endptr != '\0') {
				fprintf(stderr, "error: can't find id for name: %s\n",
						name);
				return CMD_HELP;
			}
		}
	} else if (optind + 1 != argc || qctl.qc_type == ALLQUOTA) {
		fprintf(stderr, "error: missing quota info argument(s)\n");
		return CMD_HELP;
	}

	mnt = argv[optind];
	rc1 = llapi_quotactl(mnt, &qctl);
	if (rc1 < 0) {
		switch (rc1) {
		case -ESRCH:
			fprintf(stderr, "%s quotas are not enabled.\n",
				qtype_name(qctl.qc_type));
			goto out;
		case -EPERM:
			fprintf(stderr, "Permission denied.\n");
		case -ENODEV:
		case -ENOENT:
			/* We already got error message. */
			goto out;
		default:
			fprintf(stderr, "Unexpected quotactl error: %s\n",
				strerror(-rc1));
		}
	}

	if (qctl.qc_cmd == LUSTRE_Q_GETQUOTA && !quiet)
		print_quota_title(name, &qctl, human_readable);

        if (rc1 && *obd_type)
                fprintf(stderr, "%s %s ", obd_type, obd_uuid);

        if (qctl.qc_valid != QC_GENERAL)
                mnt = "";

	inacc = (qctl.qc_cmd == LUSTRE_Q_GETQUOTA) &&
		((qctl.qc_dqblk.dqb_valid & (QIF_LIMITS|QIF_USAGE)) !=
		 (QIF_LIMITS|QIF_USAGE));

	print_quota(mnt, &qctl, QC_GENERAL, rc1, human_readable);

	if (qctl.qc_valid == QC_GENERAL && qctl.qc_cmd != LUSTRE_Q_GETINFO &&
	    verbose) {
		char strbuf[STRBUF_LEN];

		rc2 = print_obd_quota(mnt, &qctl, 1, human_readable,
				      &total_ialloc);
		rc3 = print_obd_quota(mnt, &qctl, 0, human_readable,
				      &total_balloc);
		kbytes2str(total_balloc, strbuf, sizeof(strbuf),
			   human_readable);
		printf("Total allocated inode limit: %ju, total "
		       "allocated block limit: %s\n", (uintmax_t)total_ialloc,
		       strbuf);
	}

	if (rc1 || rc2 || rc3 || inacc)
		printf("Some errors happened when getting quota info. "
		       "Some devices may be not working or deactivated. "
		       "The data in \"[]\" is inaccurate.\n");

out:
	if (pass > 0 && pass < LL_MAXQUOTAS)
		goto all_output;

	return rc1;
}
#endif /* HAVE_SYS_QUOTA_H! */

static int flushctx_ioctl(char *mp)
{
        int fd, rc;

        fd = open(mp, O_RDONLY);
        if (fd == -1) {
                fprintf(stderr, "flushctx: error open %s: %s\n",
                        mp, strerror(errno));
                return -1;
        }

        rc = ioctl(fd, LL_IOC_FLUSHCTX);
        if (rc == -1)
                fprintf(stderr, "flushctx: error ioctl %s: %s\n",
                        mp, strerror(errno));

        close(fd);
        return rc;
}

static int lfs_flushctx(int argc, char **argv)
{
	int     kdestroy = 0, c;
	char    mntdir[PATH_MAX] = {'\0'};
	int     index = 0;
	int     rc = 0;

        while ((c = getopt(argc, argv, "k")) != -1) {
                switch (c) {
                case 'k':
                        kdestroy = 1;
                        break;
                default:
                        fprintf(stderr, "error: %s: option '-%c' "
                                        "unrecognized\n", argv[0], c);
                        return CMD_HELP;
                }
        }

        if (kdestroy) {
            if ((rc = system("kdestroy > /dev/null")) != 0) {
                rc = WEXITSTATUS(rc);
                fprintf(stderr, "error destroying tickets: %d, continuing\n", rc);
            }
        }

	if (optind >= argc) {
		/* flush for all mounted lustre fs. */
		while (!llapi_search_mounts(NULL, index++, mntdir, NULL)) {
			/* Check if we have a mount point */
			if (mntdir[0] == '\0')
				continue;

			if (flushctx_ioctl(mntdir))
				rc = -1;

			mntdir[0] = '\0'; /* avoid matching in next loop */
		}
        } else {
                /* flush fs as specified */
                while (optind < argc) {
                        if (flushctx_ioctl(argv[optind++]))
                                rc = -1;
                }
        }
        return rc;
}

static int lfs_cp(int argc, char **argv)
{
	fprintf(stderr, "remote client copy file(s).\n"
		"obsolete, does not support it anymore.\n");
	return 0;
}

static int lfs_ls(int argc, char **argv)
{
	fprintf(stderr, "remote client lists directory contents.\n"
		"obsolete, does not support it anymore.\n");
	return 0;
}

static int lfs_changelog(int argc, char **argv)
{
        void *changelog_priv;
	struct changelog_rec *rec;
        long long startrec = 0, endrec = 0;
        char *mdd;
        struct option long_opts[] = {
                {"follow", no_argument, 0, 'f'},
                {0, 0, 0, 0}
        };
        char short_opts[] = "f";
        int rc, follow = 0;

        while ((rc = getopt_long(argc, argv, short_opts,
                                long_opts, NULL)) != -1) {
                switch (rc) {
                case 'f':
                        follow++;
                        break;
                case '?':
                        return CMD_HELP;
                default:
                        fprintf(stderr, "error: %s: option '%s' unrecognized\n",
                                argv[0], argv[optind - 1]);
                        return CMD_HELP;
                }
        }
        if (optind >= argc)
                return CMD_HELP;

        mdd = argv[optind++];
        if (argc > optind)
                startrec = strtoll(argv[optind++], NULL, 10);
        if (argc > optind)
                endrec = strtoll(argv[optind++], NULL, 10);

	rc = llapi_changelog_start(&changelog_priv,
				   CHANGELOG_FLAG_BLOCK |
				   CHANGELOG_FLAG_JOBID |
				   (follow ? CHANGELOG_FLAG_FOLLOW : 0),
				   mdd, startrec);
	if (rc < 0) {
		fprintf(stderr, "Can't start changelog: %s\n",
			strerror(errno = -rc));
		return rc;
	}

	while ((rc = llapi_changelog_recv(changelog_priv, &rec)) == 0) {
		time_t secs;
		struct tm ts;

		if (endrec && rec->cr_index > endrec) {
			llapi_changelog_free(&rec);
			break;
		}
		if (rec->cr_index < startrec) {
			llapi_changelog_free(&rec);
			continue;
		}

		secs = rec->cr_time >> 30;
		gmtime_r(&secs, &ts);
		printf("%ju %02d%-5s %02d:%02d:%02d.%09d %04d.%02d.%02d "
		       "0x%x t="DFID, (uintmax_t)rec->cr_index, rec->cr_type,
		       changelog_type2str(rec->cr_type),
		       ts.tm_hour, ts.tm_min, ts.tm_sec,
		       (int)(rec->cr_time & ((1 << 30) - 1)),
		       ts.tm_year + 1900, ts.tm_mon + 1, ts.tm_mday,
		       rec->cr_flags & CLF_FLAGMASK, PFID(&rec->cr_tfid));

		if (rec->cr_flags & CLF_JOBID) {
			struct changelog_ext_jobid *jid =
				changelog_rec_jobid(rec);

			if (jid->cr_jobid[0] != '\0')
				printf(" j=%s", jid->cr_jobid);
		}

		if (rec->cr_namelen)
			printf(" p="DFID" %.*s", PFID(&rec->cr_pfid),
			       rec->cr_namelen, changelog_rec_name(rec));

		if (rec->cr_flags & CLF_RENAME) {
			struct changelog_ext_rename *rnm =
				changelog_rec_rename(rec);

			if (!fid_is_zero(&rnm->cr_sfid))
				printf(" s="DFID" sp="DFID" %.*s",
				       PFID(&rnm->cr_sfid),
				       PFID(&rnm->cr_spfid),
				       (int)changelog_rec_snamelen(rec),
				       changelog_rec_sname(rec));
		}
		printf("\n");

		llapi_changelog_free(&rec);
        }

        llapi_changelog_fini(&changelog_priv);

        if (rc < 0)
                fprintf(stderr, "Changelog: %s\n", strerror(errno = -rc));

        return (rc == 1 ? 0 : rc);
}

static int lfs_changelog_clear(int argc, char **argv)
{
	long long endrec;
	int rc;

	if (argc != 4)
		return CMD_HELP;

	endrec = strtoll(argv[3], NULL, 10);

	rc = llapi_changelog_clear(argv[1], argv[2], endrec);

	if (rc == -EINVAL)
		fprintf(stderr, "%s: record out of range: %llu\n",
			argv[0], endrec);
	else if (rc == -ENOENT)
		fprintf(stderr, "%s: no changelog user: %s\n",
			argv[0], argv[2]);
	else if (rc)
		fprintf(stderr, "%s error: %s\n", argv[0],
			strerror(-rc));

	if (rc)
		errno = -rc;

	return rc;
}

static int lfs_fid2path(int argc, char **argv)
{
	struct option long_opts[] = {
		{ .val = 'c',	.name = "cur",	.has_arg = no_argument },
		{ .val = 'l',	.name = "link",	.has_arg = required_argument },
		{ .val = 'r',	.name = "rec",	.has_arg = required_argument },
		{ .name = NULL } };
	char  short_opts[] = "cl:r:";
	char *device, *fid, *path;
	long long recno = -1;
	int linkno = -1;
	int lnktmp;
	int printcur = 0;
	int rc = 0;

	while ((rc = getopt_long(argc, argv, short_opts,
		long_opts, NULL)) != -1) {
                switch (rc) {
                case 'c':
                        printcur++;
                        break;
                case 'l':
                        linkno = strtol(optarg, NULL, 10);
                        break;
                case 'r':
                        recno = strtoll(optarg, NULL, 10);
                        break;
                case '?':
                        return CMD_HELP;
                default:
                        fprintf(stderr, "error: %s: option '%s' unrecognized\n",
                                argv[0], argv[optind - 1]);
                        return CMD_HELP;
                }
        }

	if (argc < 3)
		return CMD_HELP;

	device = argv[optind++];
	path = calloc(1, PATH_MAX);
	if (path == NULL) {
		fprintf(stderr, "error: Not enough memory\n");
		return -errno;
	}

	rc = 0;
	while (optind < argc) {
		fid = argv[optind++];

		lnktmp = (linkno >= 0) ? linkno : 0;
		while (1) {
			int oldtmp = lnktmp;
			long long rectmp = recno;
			int rc2;
			rc2 = llapi_fid2path(device, fid, path, PATH_MAX,
					     &rectmp, &lnktmp);
			if (rc2 < 0) {
				fprintf(stderr, "%s: error on FID %s: %s\n",
					argv[0], fid, strerror(errno = -rc2));
				if (rc == 0)
					rc = rc2;
				break;
			}

			if (printcur)
				fprintf(stdout, "%lld ", rectmp);
			if (device[0] == '/') {
				fprintf(stdout, "%s", device);
				if (device[strlen(device) - 1] != '/')
					fprintf(stdout, "/");
			} else if (path[0] == '\0') {
				fprintf(stdout, "/");
			}
			fprintf(stdout, "%s\n", path);

			if (linkno >= 0)
				/* specified linkno */
				break;
			if (oldtmp == lnktmp)
				/* no more links */
				break;
		}
	}

	free(path);
	return rc;
}

static int lfs_path2fid(int argc, char **argv)
{
	struct option	  long_opts[] = {
		{"parents", no_argument, 0, 'p'},
		{0, 0, 0, 0}
	};
	char		**path;
	const char	  short_opts[] = "p";
	const char	 *sep = "";
	lustre_fid	  fid;
	int		  rc = 0;
	bool		  show_parents = false;

	while ((rc = getopt_long(argc, argv, short_opts,
				 long_opts, NULL)) != -1) {
		switch (rc) {
		case 'p':
			show_parents = true;
			break;
		default:
			fprintf(stderr, "error: %s: option '%s' unrecognized\n",
				argv[0], argv[optind - 1]);
			return CMD_HELP;
		}
	}

	if (optind > argc - 1)
		return CMD_HELP;
	else if (optind < argc - 1)
		sep = ": ";

	rc = 0;
	for (path = argv + optind; *path != NULL; path++) {
		int err = 0;
		if (!show_parents) {
			err = llapi_path2fid(*path, &fid);
			if (!err)
				printf("%s%s"DFID"\n",
				       *sep != '\0' ? *path : "", sep,
				       PFID(&fid));
		} else {
			char		name[NAME_MAX + 1];
			unsigned int	linkno = 0;

			while ((err = llapi_path2parent(*path, linkno, &fid,
						name, sizeof(name))) == 0) {
				if (*sep != '\0' && linkno == 0)
					printf("%s%s", *path, sep);

				printf("%s"DFID"/%s", linkno != 0 ? "\t" : "",
				       PFID(&fid), name);
				linkno++;
			}

			/* err == -ENODATA is end-of-loop */
			if (linkno > 0 && err == -ENODATA) {
				printf("\n");
				err = 0;
			}
		}

		if (err) {
			fprintf(stderr, "%s: can't get %sfid for %s: %s\n",
				argv[0], show_parents ? "parent " : "", *path,
				strerror(-err));
			if (rc == 0) {
				rc = err;
				errno = -err;
			}
		}
	}

	return rc;
}

static int lfs_data_version(int argc, char **argv)
{
	char *path;
	__u64 data_version;
	int fd;
	int rc;
	int c;
	int data_version_flags = LL_DV_RD_FLUSH; /* Read by default */

	if (argc < 2)
		return CMD_HELP;

	while ((c = getopt(argc, argv, "nrw")) != -1) {
		switch (c) {
		case 'n':
			data_version_flags = 0;
			break;
		case 'r':
			data_version_flags |= LL_DV_RD_FLUSH;
			break;
		case 'w':
			data_version_flags |= LL_DV_WR_FLUSH;
			break;
		default:
			return CMD_HELP;
		}
	}
	if (optind == argc)
		return CMD_HELP;

	path = argv[optind];
	fd = open(path, O_RDONLY);
	if (fd < 0)
		err(errno, "cannot open file %s", path);

	rc = llapi_get_data_version(fd, &data_version, data_version_flags);
	if (rc < 0)
		err(errno, "cannot get version for %s", path);
	else
		printf("%ju" "\n", (uintmax_t)data_version);

	close(fd);
	return rc;
}

static int lfs_hsm_state(int argc, char **argv)
{
	int rc;
	int i = 1;
	char *path;
	struct hsm_user_state hus;

	if (argc < 2)
		return CMD_HELP;

	do {
		path = argv[i];

		rc = llapi_hsm_state_get(path, &hus);
		if (rc) {
			fprintf(stderr, "can't get hsm state for %s: %s\n",
				path, strerror(errno = -rc));
			return rc;
		}

		/* Display path name and status flags */
		printf("%s: (0x%08x)", path, hus.hus_states);

		if (hus.hus_states & HS_RELEASED)
			printf(" released");
		if (hus.hus_states & HS_EXISTS)
			printf(" exists");
		if (hus.hus_states & HS_DIRTY)
			printf(" dirty");
		if (hus.hus_states & HS_ARCHIVED)
			printf(" archived");
		/* Display user-settable flags */
		if (hus.hus_states & HS_NORELEASE)
			printf(" never_release");
		if (hus.hus_states & HS_NOARCHIVE)
			printf(" never_archive");
		if (hus.hus_states & HS_LOST)
			printf(" lost_from_hsm");

		if (hus.hus_archive_id != 0)
			printf(", archive_id:%d", hus.hus_archive_id);
		printf("\n");

	} while (++i < argc);

	return 0;
}

#define LFS_HSM_SET   0
#define LFS_HSM_CLEAR 1

/**
 * Generic function to set or clear HSM flags.
 * Used by hsm_set and hsm_clear.
 *
 * @mode  if LFS_HSM_SET, set the flags, if LFS_HSM_CLEAR, clear the flags.
 */
static int lfs_hsm_change_flags(int argc, char **argv, int mode)
{
	struct option long_opts[] = {
	{ .val = 'A',	.name = "archived",	.has_arg = no_argument },
	{ .val = 'a',	.name = "noarchive",	.has_arg = no_argument },
	{ .val = 'd',	.name = "dirty",	.has_arg = no_argument },
	{ .val = 'e',	.name = "exists",	.has_arg = no_argument },
	{ .val = 'l',	.name = "lost",		.has_arg = no_argument },
	{ .val = 'r',	.name = "norelease",	.has_arg = no_argument },
	{ .val = 'i',	.name = "archive-id",	.has_arg = required_argument },
	{ .name = NULL } };
	char short_opts[] = "lraAdei:";
	__u64 mask = 0;
	int c, rc;
	char *path;
	__u32 archive_id = 0;
	char *end = NULL;

	if (argc < 3)
		return CMD_HELP;

	while ((c = getopt_long(argc, argv, short_opts,
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'l':
			mask |= HS_LOST;
			break;
		case 'a':
			mask |= HS_NOARCHIVE;
			break;
		case 'A':
			mask |= HS_ARCHIVED;
			break;
		case 'r':
			mask |= HS_NORELEASE;
			break;
		case 'd':
			mask |= HS_DIRTY;
			break;
		case 'e':
			mask |= HS_EXISTS;
			break;
		case 'i':
			archive_id = strtol(optarg, &end, 10);
			if (*end != '\0') {
				fprintf(stderr, "invalid archive_id: '%s'\n",
					end);
				return CMD_HELP;
			}
			break;
		case '?':
			return CMD_HELP;
		default:
			fprintf(stderr, "error: %s: option '%s' unrecognized\n",
				argv[0], argv[optind - 1]);
			return CMD_HELP;
		}
	}

	/* User should have specified a flag */
	if (mask == 0)
		return CMD_HELP;

	while (optind < argc) {

		path = argv[optind];

		/* If mode == 0, this means we apply the mask. */
		if (mode == LFS_HSM_SET)
			rc = llapi_hsm_state_set(path, mask, 0, archive_id);
		else
			rc = llapi_hsm_state_set(path, 0, mask, 0);

		if (rc != 0) {
			fprintf(stderr, "Can't change hsm flags for %s: %s\n",
				path, strerror(errno = -rc));
			return rc;
		}
		optind++;
	}

	return 0;
}

static int lfs_hsm_action(int argc, char **argv)
{
	int				 rc;
	int				 i = 1;
	char				*path;
	struct hsm_current_action	 hca;
	struct hsm_extent		 he;
	enum hsm_user_action		 hua;
	enum hsm_progress_states	 hps;

	if (argc < 2)
		return CMD_HELP;

	do {
		path = argv[i];

		rc = llapi_hsm_current_action(path, &hca);
		if (rc) {
			fprintf(stderr, "can't get hsm action for %s: %s\n",
				path, strerror(errno = -rc));
			return rc;
		}
		he = hca.hca_location;
		hua = hca.hca_action;
		hps = hca.hca_state;

		printf("%s: %s", path, hsm_user_action2name(hua));

		/* Skip file without action */
		if (hca.hca_action == HUA_NONE) {
			printf("\n");
			continue;
		}

		printf(" %s ", hsm_progress_state2name(hps));

		if ((hps == HPS_RUNNING) &&
		    (hua == HUA_ARCHIVE || hua == HUA_RESTORE))
			printf("(%llu bytes moved)\n",
			       (unsigned long long)he.length);
		else if ((he.offset + he.length) == LUSTRE_EOF)
			printf("(from %llu to EOF)\n",
			       (unsigned long long)he.offset);
		else
			printf("(from %llu to %llu)\n",
			       (unsigned long long)he.offset,
			       (unsigned long long)(he.offset + he.length));

	} while (++i < argc);

	return 0;
}

static int lfs_hsm_set(int argc, char **argv)
{
	return lfs_hsm_change_flags(argc, argv, LFS_HSM_SET);
}

static int lfs_hsm_clear(int argc, char **argv)
{
	return lfs_hsm_change_flags(argc, argv, LFS_HSM_CLEAR);
}

/**
 * Check file state and return its fid, to be used by lfs_hsm_request().
 *
 * \param[in]     file      Path to file to check
 * \param[in,out] fid       Pointer to allocated lu_fid struct.
 * \param[in,out] last_dev  Pointer to last device id used.
 *
 * \return 0 on success.
 */
static int lfs_hsm_prepare_file(const char *file, struct lu_fid *fid,
				dev_t *last_dev)
{
	struct stat	st;
	int		rc;

	rc = lstat(file, &st);
	if (rc) {
		fprintf(stderr, "Cannot stat %s: %s\n", file, strerror(errno));
		return -errno;
	}
	/* Checking for regular file as archiving as posix copytool
	 * rejects archiving files other than regular files
	 */
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "error: \"%s\" is not a regular file\n", file);
		return CMD_HELP;
	}
	/* A request should be ... */
	if (*last_dev != st.st_dev && *last_dev != 0) {
		fprintf(stderr, "All files should be "
			"on the same filesystem: %s\n", file);
		return -EINVAL;
	}
	*last_dev = st.st_dev;

	rc = llapi_path2fid(file, fid);
	if (rc) {
		fprintf(stderr, "Cannot read FID of %s: %s\n",
			file, strerror(-rc));
		return rc;
	}
	return 0;
}

/* Fill an HSM HUR item with a given file name.
 *
 * If mntpath is set, then the filename is actually a FID, and no
 * lookup on the filesystem will be performed.
 *
 * \param[in]  hur         the user request to fill
 * \param[in]  idx         index of the item inside the HUR to fill
 * \param[in]  mntpath     mountpoint of Lustre
 * \param[in]  fname       filename (if mtnpath is NULL)
 *                         or FID (if mntpath is set)
 * \param[in]  last_dev    pointer to last device id used
 *
 * \retval 0 on success
 * \retval CMD_HELP or a negative errno on error
 */
static int fill_hur_item(struct hsm_user_request *hur, unsigned int idx,
			 const char *mntpath, const char *fname,
			 dev_t *last_dev)
{
	struct hsm_user_item *hui = &hur->hur_user_item[idx];
	int rc;

	hui->hui_extent.length = -1;

	if (mntpath != NULL) {
		if (*fname == '[')
			fname++;
		rc = sscanf(fname, SFID, RFID(&hui->hui_fid));
		if (rc == 3) {
			rc = 0;
		} else {
			fprintf(stderr, "hsm: '%s' is not a valid FID\n",
				fname);
			rc = -EINVAL;
		}
	} else {
		rc = lfs_hsm_prepare_file(fname, &hui->hui_fid, last_dev);
	}

	if (rc == 0)
		hur->hur_request.hr_itemcount++;

	return rc;
}

static int lfs_hsm_request(int argc, char **argv, int action)
{
	struct option		 long_opts[] = {
		{"filelist", 1, 0, 'l'},
		{"data", 1, 0, 'D'},
		{"archive", 1, 0, 'a'},
		{"mntpath", 1, 0, 'm'},
		{0, 0, 0, 0}
	};
	dev_t			 last_dev = 0;
	char			 short_opts[] = "l:D:a:m:";
	struct hsm_user_request	*hur, *oldhur;
	int			 c, i;
	size_t			 len;
	int			 nbfile;
	char			*line = NULL;
	char			*filelist = NULL;
	char			 fullpath[PATH_MAX];
	char			*opaque = NULL;
	int			 opaque_len = 0;
	int			 archive_id = 0;
	FILE			*fp;
	int			 nbfile_alloc = 0;
	char			*some_file = NULL;
	char			*mntpath = NULL;
	int			 rc;

	if (argc < 2)
		return CMD_HELP;

	while ((c = getopt_long(argc, argv, short_opts,
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'l':
			filelist = optarg;
			break;
		case 'D':
			opaque = optarg;
			break;
		case 'a':
			if (action != HUA_ARCHIVE &&
			    action != HUA_REMOVE) {
				fprintf(stderr,
					"error: -a is supported only "
					"when archiving or removing\n");
				return CMD_HELP;
			}
			archive_id = atoi(optarg);
			break;
		case 'm':
			if (some_file == NULL) {
				mntpath = optarg;
				some_file = strdup(optarg);
			}
			break;
		case '?':
			return CMD_HELP;
		default:
			fprintf(stderr, "error: %s: option '%s' unrecognized\n",
				argv[0], argv[optind - 1]);
			return CMD_HELP;
		}
	}

	/* All remaining args are files, so we have at least nbfile */
	nbfile = argc - optind;

	if ((nbfile == 0) && (filelist == NULL))
		return CMD_HELP;

	if (opaque != NULL)
		opaque_len = strlen(opaque);

	/* Alloc the request structure with enough place to store all files
	 * from command line. */
	hur = llapi_hsm_user_request_alloc(nbfile, opaque_len);
	if (hur == NULL) {
		fprintf(stderr, "Cannot create the request: %s\n",
			strerror(errno));
		return errno;
	}
	nbfile_alloc = nbfile;

	hur->hur_request.hr_action = action;
	hur->hur_request.hr_archive_id = archive_id;
	hur->hur_request.hr_flags = 0;

	/* All remaining args are files, add them */
	if (nbfile != 0 && some_file == NULL)
		some_file = strdup(argv[optind]);

	for (i = 0; i < nbfile; i++) {
		rc = fill_hur_item(hur, i, mntpath, argv[optind + i],
				   &last_dev);
		if (rc)
			goto out_free;
	}

	/* from here stop using nb_file, use hur->hur_request.hr_itemcount */

	/* If a filelist was specified, read the filelist from it. */
	if (filelist != NULL) {
		fp = fopen(filelist, "r");
		if (fp == NULL) {
			fprintf(stderr, "Cannot read the file list %s: %s\n",
				filelist, strerror(errno));
			rc = -errno;
			goto out_free;
		}

		while ((rc = getline(&line, &len, fp)) != -1) {
			/* If allocated buffer was too small, get something
			 * larger */
			if (nbfile_alloc <= hur->hur_request.hr_itemcount) {
				ssize_t size;

				nbfile_alloc = nbfile_alloc * 2 + 1;
				oldhur = hur;
				hur = llapi_hsm_user_request_alloc(nbfile_alloc,
								   opaque_len);
				if (hur == NULL) {
					fprintf(stderr, "hsm: cannot allocate "
						"the request: %s\n",
						strerror(errno));
					hur = oldhur;
					rc = -errno;
					fclose(fp);
					goto out_free;
				}
				size = hur_len(oldhur);
				if (size < 0) {
					fprintf(stderr, "hsm: cannot allocate "
						"%u files + %u bytes data\n",
					    oldhur->hur_request.hr_itemcount,
					    oldhur->hur_request.hr_data_len);
					free(hur);
					hur = oldhur;
					rc = -E2BIG;
					fclose(fp);
					goto out_free;
				}
				memcpy(hur, oldhur, size);
				free(oldhur);
			}

			/* Chop CR */
			if (line[strlen(line) - 1] == '\n')
				line[strlen(line) - 1] = '\0';

			rc = fill_hur_item(hur, hur->hur_request.hr_itemcount,
					   mntpath, line, &last_dev);
			if (rc) {
				fclose(fp);
				goto out_free;
			}

			if (some_file == NULL) {
				some_file = line;
				line = NULL;
			}
		}

		rc = fclose(fp);
		free(line);
	}

	/* If a --data was used, add it to the request */
	hur->hur_request.hr_data_len = opaque_len;
	if (opaque != NULL)
		memcpy(hur_data(hur), opaque, opaque_len);

	/* Send the HSM request */
	if (realpath(some_file, fullpath) == NULL) {
		fprintf(stderr, "Could not find path '%s': %s\n",
			some_file, strerror(errno));
	}
	rc = llapi_hsm_request(fullpath, hur);
	if (rc) {
		fprintf(stderr, "Cannot send HSM request (use of %s): %s\n",
			some_file, strerror(-rc));
		goto out_free;
	}

out_free:
	free(some_file);
	free(hur);
	return rc;
}

static int lfs_hsm_archive(int argc, char **argv)
{
	return lfs_hsm_request(argc, argv, HUA_ARCHIVE);
}

static int lfs_hsm_restore(int argc, char **argv)
{
	return lfs_hsm_request(argc, argv, HUA_RESTORE);
}

static int lfs_hsm_release(int argc, char **argv)
{
	return lfs_hsm_request(argc, argv, HUA_RELEASE);
}

static int lfs_hsm_remove(int argc, char **argv)
{
	return lfs_hsm_request(argc, argv, HUA_REMOVE);
}

static int lfs_hsm_cancel(int argc, char **argv)
{
	return lfs_hsm_request(argc, argv, HUA_CANCEL);
}

static int lfs_swap_layouts(int argc, char **argv)
{
	if (argc != 3)
		return CMD_HELP;

	return llapi_swap_layouts(argv[1], argv[2], 0, 0,
				  SWAP_LAYOUTS_KEEP_MTIME |
				  SWAP_LAYOUTS_KEEP_ATIME);
}

static const char *const ladvise_names[] = LU_LADVISE_NAMES;

static enum lu_ladvise_type lfs_get_ladvice(const char *string)
{
	enum lu_ladvise_type advice;

	for (advice = 0;
	     advice < ARRAY_SIZE(ladvise_names); advice++) {
		if (ladvise_names[advice] == NULL)
			continue;
		if (strcmp(string, ladvise_names[advice]) == 0)
			return advice;
	}

	return LU_LADVISE_INVALID;
}

static int lfs_ladvise(int argc, char **argv)
{
	struct option		 long_opts[] = {
		{"advice",	required_argument,	0, 'a'},
		{"background",	no_argument,		0, 'b'},
		{"end",		required_argument,	0, 'e'},
		{"start",	required_argument,	0, 's'},
		{"length",	required_argument,	0, 'l'},
		{0, 0, 0, 0}
	};
	char			 short_opts[] = "a:be:l:s:";
	int			 c;
	int			 rc = 0;
	const char		*path;
	int			 fd;
	struct llapi_lu_ladvise	 advice;
	enum lu_ladvise_type	 advice_type = LU_LADVISE_INVALID;
	unsigned long long	 start = 0;
	unsigned long long	 end = LUSTRE_EOF;
	unsigned long long	 length = 0;
	unsigned long long	 size_units;
	unsigned long long	 flags = 0;

	optind = 0;
	while ((c = getopt_long(argc, argv, short_opts,
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'a':
			advice_type = lfs_get_ladvice(optarg);
			if (advice_type == LU_LADVISE_INVALID) {
				fprintf(stderr, "%s: invalid advice type "
					"'%s'\n", argv[0], optarg);
				fprintf(stderr, "Valid types:");

				for (advice_type = 0;
				     advice_type < ARRAY_SIZE(ladvise_names);
				     advice_type++) {
					if (ladvise_names[advice_type] == NULL)
						continue;
					fprintf(stderr, " %s",
						ladvise_names[advice_type]);
				}
				fprintf(stderr, "\n");

				return CMD_HELP;
			}
			break;
		case 'b':
			flags |= LF_ASYNC;
			break;
		case 'e':
			size_units = 1;
			rc = llapi_parse_size(optarg, &end,
					      &size_units, 0);
			if (rc) {
				fprintf(stderr, "%s: bad end offset '%s'\n",
					argv[0], optarg);
				return CMD_HELP;
			}
			break;
		case 's':
			size_units = 1;
			rc = llapi_parse_size(optarg, &start,
					      &size_units, 0);
			if (rc) {
				fprintf(stderr, "%s: bad start offset "
					"'%s'\n", argv[0], optarg);
				return CMD_HELP;
			}
			break;
		case 'l':
			size_units = 1;
			rc = llapi_parse_size(optarg, &length,
					      &size_units, 0);
			if (rc) {
				fprintf(stderr, "%s: bad length '%s'\n",
					argv[0], optarg);
				return CMD_HELP;
			}
			break;
		case '?':
			return CMD_HELP;
		default:
			fprintf(stderr, "%s: option '%s' unrecognized\n",
				argv[0], argv[optind - 1]);
			return CMD_HELP;
		}
	}

	if (advice_type == LU_LADVISE_INVALID) {
		fprintf(stderr, "%s: please give an advice type\n", argv[0]);
		fprintf(stderr, "Valid types:");
		for (advice_type = 0; advice_type < ARRAY_SIZE(ladvise_names);
		     advice_type++) {
			if (ladvise_names[advice_type] == NULL)
				continue;
			fprintf(stderr, " %s", ladvise_names[advice_type]);
		}
		fprintf(stderr, "\n");
		return CMD_HELP;
	}

	if (argc <= optind) {
		fprintf(stderr, "%s: please give one or more file names\n",
			argv[0]);
		return CMD_HELP;
	}

	if (end != LUSTRE_EOF && length != 0 && end != start + length) {
		fprintf(stderr, "%s: conflicting arguments of -l and -e\n",
			argv[0]);
		return CMD_HELP;
	}

	if (end == LUSTRE_EOF && length != 0)
		end = start + length;

	if (end <= start) {
		fprintf(stderr, "%s: range [%llu, %llu] is invalid\n",
			argv[0], start, end);
		return CMD_HELP;
	}

	while (optind < argc) {
		int rc2;

		path = argv[optind++];

		fd = open(path, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "%s: cannot open file '%s': %s\n",
				argv[0], path, strerror(errno));
			rc2 = -errno;
			goto next;
		}

		advice.lla_start = start;
		advice.lla_end = end;
		advice.lla_advice = advice_type;
		advice.lla_value1 = 0;
		advice.lla_value2 = 0;
		advice.lla_value3 = 0;
		advice.lla_value4 = 0;
		rc2 = llapi_ladvise(fd, flags, 1, &advice);
		close(fd);
		if (rc2 < 0) {
			fprintf(stderr, "%s: cannot give advice '%s' to file "
				"'%s': %s\n", argv[0],
				ladvise_names[advice_type],
				path, strerror(errno));
		}
next:
		if (rc == 0 && rc2 < 0)
			rc = rc2;
	}
	return rc;
}

static int lfs_list_commands(int argc, char **argv)
{
	char buffer[81] = ""; /* 80 printable chars + terminating NUL */

	Parser_list_commands(cmdlist, buffer, sizeof(buffer), NULL, 0, 4);

	return 0;
}

int main(int argc, char **argv)
{
        int rc;

	/* Ensure that liblustreapi constructor has run */
	if (!liblustreapi_initialized)
		fprintf(stderr, "liblustreapi was not properly initialized\n");

        setlinebuf(stdout);

	Parser_init("lfs > ", cmdlist);

	progname = argv[0]; /* Used in error messages */
        if (argc > 1) {
                rc = Parser_execarg(argc - 1, argv + 1, cmdlist);
        } else {
                rc = Parser_commands();
        }

        return rc < 0 ? -rc : rc;
}

#ifdef _LUSTRE_IDL_H_
/* Everything we need here should be included by lustreapi.h. */
# error "lfs should not depend on lustre_idl.h"
#endif /* _LUSTRE_IDL_H_ */
