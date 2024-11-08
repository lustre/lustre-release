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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
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
#include <inttypes.h>
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
#include <sys/param.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>
#include <zlib.h>
#include <libgen.h>
#include <asm/byteorder.h>
#include "lfs_project.h"

#include <libcfs/util/string.h>
#include <libcfs/util/ioctl.h>
#include <libcfs/util/parser.h>
#include <libcfs/util/string.h>
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_ver.h>
#include <linux/lustre/lustre_param.h>
#include <linux/lnet/nidstr.h>
#include <lnetconfig/cyaml.h>
#include "lstddef.h"

/* all functions */
static int lfs_find(int argc, char **argv);
static int lfs_getstripe(int argc, char **argv);
static int lfs_getdirstripe(int argc, char **argv);
static int lfs_setdirstripe(int argc, char **argv);
static int lfs_rmentry(int argc, char **argv);
static int lfs_unlink_foreign(int argc, char **argv);
static int lfs_osts(int argc, char **argv);
static int lfs_mdts(int argc, char **argv);
static int lfs_df(int argc, char **argv);
static int lfs_getname(int argc, char **argv);
static int lfs_check(int argc, char **argv);
#ifdef HAVE_SYS_QUOTA_H
static int lfs_setquota(int argc, char **argv);
static int lfs_quota(int argc, char **argv);
static int lfs_project(int argc, char **argv);
#endif
static int lfs_flushctx(int argc, char **argv);
static int lfs_poollist(int argc, char **argv);
static int lfs_changelog(int argc, char **argv);
static int lfs_changelog_clear(int argc, char **argv);
static int lfs_fid2path(int argc, char **argv);
static int lfs_path2fid(int argc, char **argv);
static int lfs_rmfid(int argc, char **argv);
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
static int lfs_getsom(int argc, char **argv);
static int lfs_heat_get(int argc, char **argv);
static int lfs_heat_set(int argc, char **argv);
static int lfs_mirror(int argc, char **argv);
static int lfs_mirror_list_commands(int argc, char **argv);
static int lfs_list_commands(int argc, char **argv);
static inline int lfs_mirror_resync(int argc, char **argv);
static inline int lfs_mirror_verify(int argc, char **argv);
static inline int lfs_mirror_read(int argc, char **argv);
static inline int lfs_mirror_write(int argc, char **argv);
static inline int lfs_mirror_copy(int argc, char **argv);
static int lfs_pcc_attach(int argc, char **argv);
static int lfs_pcc_attach_fid(int argc, char **argv);
static int lfs_pcc_detach(int argc, char **argv);
static int lfs_pcc_detach_fid(int argc, char **argv);
static int lfs_pcc_state(int argc, char **argv);
static int lfs_pcc(int argc, char **argv);
static int lfs_pcc_list_commands(int argc, char **argv);
static int lfs_migrate_to_dom(int fd, int fdv, char *name,
			      __u64 migration_flags);

struct pool_to_id_cbdata {
	const char *pool;
	__u32 id;
};
static int find_comp_id_by_pool(struct llapi_layout *layout, void *cbdata);
static int find_mirror_id_by_pool(struct llapi_layout *layout, void *cbdata);

enum setstripe_origin {
	SO_SETSTRIPE,
	SO_MIGRATE,
	SO_MIGRATE_MDT,
	SO_MIRROR_CREATE,
	SO_MIRROR_EXTEND,
	SO_MIRROR_SPLIT,
	SO_MIRROR_DELETE,
};

static int lfs_setstripe_internal(int argc, char **argv,
				  enum setstripe_origin opc);

static inline int lfs_setstripe(int argc, char **argv)
{
	return lfs_setstripe_internal(argc, argv, SO_SETSTRIPE);
}

static inline int lfs_setstripe_migrate(int argc, char **argv)
{
	return lfs_setstripe_internal(argc, argv, SO_MIGRATE);
}

static inline int lfs_mirror_create(int argc, char **argv)
{
	return lfs_setstripe_internal(argc, argv, SO_MIRROR_CREATE);
}

static inline int lfs_mirror_extend(int argc, char **argv)
{
	return lfs_setstripe_internal(argc, argv, SO_MIRROR_EXTEND);
}

static inline int lfs_mirror_split(int argc, char **argv)
{
	return lfs_setstripe_internal(argc, argv, SO_MIRROR_SPLIT);
}

static inline int lfs_mirror_delete(int argc, char **argv)
{
	return lfs_setstripe_internal(argc, argv, SO_MIRROR_DELETE);
}

/* Setstripe and migrate share mostly the same parameters */
#define SSM_CMD_COMMON(cmd) \
	"usage: "cmd" [--component-end|-E COMP_END]\n"			\
	"                 [--copy=LUSTRE_SRC]\n"			\
	"                 [--extension-size|--ext-size|-z SIZE]\n"	\
	"                 [--help|-h] [--layout|-L PATTERN]\n"		\
	"                 [--layout|-L PATTERN]\n"			\
	"                 [--mirror-count|-N[MIRROR_COUNT]]\n"		\
	"                 [--ost|-o OST_INDICES]\n"			\
	"                 [--overstripe-count|-C STRIPE_COUNT]\n"	\
	"                 [--pool|-p POOL_NAME]\n"			\
	"                 [--stripe-count|-c STRIPE_COUNT]\n"		\
	"                 [--stripe-index|-i START_OST_IDX]\n"		\
	"                 [--stripe-size|-S STRIPE_SIZE]\n"		\
	"                 [--yaml|-y YAML_TEMPLATE_FILE]\n"

#define MIRROR_EXTEND_USAGE						\
	"                 {--mirror-count|-N[MIRROR_COUNT]}\n"		\
	"                 [SETSTRIPE_OPTIONS|-f|--file VICTIM_FILE]\n"	\
	"                 [--no-verify]\n"

#define SETSTRIPE_USAGE							\
	SSM_CMD_COMMON("setstripe")					\
	MIRROR_EXTEND_USAGE						\
	"                 DIRECTORY|FILENAME\n"

#define MIGRATE_USAGE							\
	SSM_CMD_COMMON("migrate  ")					\
	"                 [--block|-b] [--non-block|-n]\n"		\
	"                 [--non-direct|-D] [--verbose|-v]\n"		\
	"                 FILENAME\n"

#define SETDIRSTRIPE_USAGE						\
	"		[--mdt-count|-c stripe_count>\n"		\
	"		[--help|-h] [--mdt-hash|-H mdt_hash]\n"		\
	"		[--mdt-index|-i mdt_index[,mdt_index,...]\n"	\
	"		[--default|-D] [--mode|-o mode]\n"		\
	"		[--max-inherit|-X max_inherit]\n"		\
	"		[--max-inherit-rr max_inherit_rr] <dir>\n"	\
	"To create dir with a foreign (free format) layout :\n"		\
	"setdirstripe|mkdir --foreign[=FOREIGN_TYPE] -x|-xattr STRING " \
	"		[--mode|-o MODE] [--flags HEX] DIRECTORY\n"

/**
 * command_t mirror_cmdlist - lfs mirror commands.
 */
command_t mirror_cmdlist[] = {
	{ .pc_name = "create", .pc_func = lfs_mirror_create,
	  .pc_help = "Create a mirrored file.\n"
		"usage: lfs mirror create --mirror-count|-N[MIRROR_COUNT]\n"
		"           [SETSTRIPE_OPTIONS] ... FILENAME|DIRECTORY ...\n" },
	{ .pc_name = "delete", .pc_func = lfs_mirror_delete,
	  .pc_help = "Delete a mirror from a file.\n"
	"usage: lfs mirror delete {--mirror-id <mirror_id> |\n"
	"\t		  --component-id|--comp-id|-I COMP_ID |\n"
	"\t		  -p <pool>} MIRRORED_FILE ...\n"
	},
	{ .pc_name = "extend", .pc_func = lfs_mirror_extend,
	  .pc_help = "Extend a mirrored file.\n"
		"usage: lfs mirror extend "
		"{--mirror-count|-N[MIRROR_COUNT]} [--no-verify] "
		"[SETSTRIPE_OPTIONS|-f VICTIM_FILE] ... FILENAME ...\n" },
	{ .pc_name = "split", .pc_func = lfs_mirror_split,
	  .pc_help = "Split a mirrored file.\n"
	"usage: lfs mirror split {--mirror-id MIRROR_ID |\n"
	"\t		--component-id|-I COMP_ID|-p POOL} [--destroy|-d]\n"
	"\t		[-f NEW_FILE] MIRRORED_FILE ...\n" },
	{ .pc_name = "read", .pc_func = lfs_mirror_read,
	  .pc_help = "Read the content of a specified mirror of a file.\n"
		"usage: lfs mirror read {--mirror-id|-N MIRROR_ID}\n"
		"\t\t[--outfile|-o <output_file>] <mirrored_file>\n" },
	{ .pc_name = "write", .pc_func = lfs_mirror_write,
	  .pc_help = "Write to a specified mirror of a file.\n"
		"usage: lfs mirror write {--mirror-id|-N MIRROR_ID}\n"
		"\t\t[--inputfile|-i <input_file>] <mirrored_file>\n" },
	{ .pc_name = "copy", .pc_func = lfs_mirror_copy,
	  .pc_help = "Copy a specified mirror to other mirror(s) of a file.\n"
		"usage: lfs mirror copy {--read-mirror|-i MIRROR_ID0}\n"
		"\t\t{--write-mirror|-o MIRROR_ID1[,...]} <mirrored_file>\n" },
	{ .pc_name = "resync", .pc_func = lfs_mirror_resync,
	  .pc_help = "Resynchronizes out-of-sync mirrored file(s).\n"
		"usage: lfs mirror resync [--only MIRROR_ID[,...]>]\n"
		"\t\t<mirrored_file> [<mirrored_file2>...]\n" },
	{ .pc_name = "verify", .pc_func = lfs_mirror_verify,
	  .pc_help = "Verify mirrored file(s).\n"
		"usage: lfs mirror verify [--only MIRROR_ID[,...]]\n"
		"\t\t[--verbose|-v] <mirrored_file> [<mirrored_file2> ...]\n" },
	{ .pc_name = "list-commands", .pc_func = lfs_mirror_list_commands,
	  .pc_help = "list commands supported by lfs mirror"},
	{ .pc_name = "help", .pc_func = Parser_help, .pc_help = "help" },
	{ .pc_name = "exit", .pc_func = Parser_quit, .pc_help = "quit" },
	{ .pc_name = "quit", .pc_func = Parser_quit, .pc_help = "quit" },
	{ .pc_help = NULL }
};

/**
 * command_t pcc_cmdlist - lfs pcc commands.
 */
command_t pcc_cmdlist[] = {
	{ .pc_name = "attach", .pc_func = lfs_pcc_attach,
	  .pc_help = "Attach given files to the Persistent Client Cache.\n"
		"usage: lfs pcc attach <--id|-i NUM> <file> ...\n"
		"\t-i: archive id for RW-PCC\n" },
	{ .pc_name = "attach_fid", .pc_func = lfs_pcc_attach_fid,
	  .pc_help = "Attach given files into PCC by FID(s).\n"
		"usage: lfs pcc attach_id {--id|-i NUM} {--mnt|-m MOUNTPOINT} FID ...\n"
		"\t-i: archive id for RW-PCC\n"
		"\t-m: Lustre mount point\n" },
	{ .pc_name = "state", .pc_func = lfs_pcc_state,
	  .pc_help = "Display the PCC state for given files.\n"
		"usage: lfs pcc state <file> ...\n" },
	{ .pc_name = "detach", .pc_func = lfs_pcc_detach,
	  .pc_help = "Detach given files from the Persistent Client Cache.\n"
		"usage: lfs pcc detach <file> ...\n" },
	{ .pc_name = "detach_fid", .pc_func = lfs_pcc_detach_fid,
	  .pc_help = "Detach given files from PCC by FID(s).\n"
		"usage: lfs pcc detach_fid <mntpath> <fid>...\n" },
	{ .pc_name = "list-commands", .pc_func = lfs_pcc_list_commands,
	  .pc_help = "list commands supported by lfs pcc"},
	{ .pc_name = "help", .pc_func = Parser_help, .pc_help = "help" },
	{ .pc_name = "exit", .pc_func = Parser_quit, .pc_help = "quit" },
	{ .pc_name = "quit", .pc_func = Parser_quit, .pc_help = "quit" },
	{ .pc_help = NULL }
};

/* all available commands */
command_t cmdlist[] = {
	{"setstripe", lfs_setstripe, 0,
	 "To create a file with specified striping/composite layout, or\n"
	 "create/replace the default layout on an existing directory:\n"
	 SSM_CMD_COMMON("setstripe")
	 "                 [--mode MODE]\n"
	 "                 <directory|filename>\n"
	 " or\n"
	 "To add component(s) to an existing composite file:\n"
	 SSM_CMD_COMMON("setstripe --component-add")
	 "To totally delete the default striping from an existing directory:\n"
	 "usage: setstripe [--delete|-d] <directory>\n"
	 " or\n"
	 "To create a mirrored file or set s default mirror layout on a directory:\n"
	 "usage: setstripe {--mirror-count|-N}[MIRROR_COUNT] [SETSTRIPE_OPTIONS] <directory|filename>\n"
	 " or\n"
	 "To delete the last component(s) from an existing composite file\n"
	 "(note that this will also delete any data in those components):\n"
	 "usage: setstripe --component-del [--component-id|-I COMP_ID]\n"
	 "                               [--component-flags|-F COMP_FLAGS]\n"
	 "                               <filename>\n"
	 "\tCOMP_ID:     Unique component ID to delete\n"
	 "\tCOMP_FLAGS:  'init' indicating all instantiated components\n"
	 "\t             '^init' indicating all uninstantiated components\n"
	 "\t-I and -F cannot be specified at the same time\n"
	 " or\n"
	 "To set or clear flags on a specific component\n"
	 "(note that this command can only be applied to mirrored files:\n"
	 "usage: setstripe --comp-set {-I COMP_ID|--comp-flags=COMP_FLAGS}\n"
	 "                            <filename>\n"
	 " or\n"
	 "To create a file with a foreign (free format) layout:\n"
	 "usage: setstripe --foreign[=FOREIGN_TYPE]\n"
	 "                 --xattr|-x LAYOUT_STRING [--flags HEX]\n"
	 "                 [--mode MODE] <filename>\n"},
	{"getstripe", lfs_getstripe, 0,
	 "To list the layout pattern for a given file or files in a\n"
	 "directory or recursively for all files in a directory tree.\n"
	 "usage: getstripe [--ost|-O UUID] [--quiet|-q] [--verbose|-v]\n"
	 "		   [--stripe-count|-c] [--stripe-index|-i] [--fid|-F]\n"
	 "		   [--pool|-p] [--stripe-size|-S] [--directory|-d]\n"
	 "		   [--mdt-index|-m] [--recursive|-r] [--raw|-R]\n"
	 "		   [--layout|-L] [--generation|-g] [--yaml|-y]\n"
	 "		   [--help|-h] [--component-id|-I[=COMP_ID]]\n"
	 "		   [--component-flags[=COMP_FLAGS]]\n"
	 "		   [--component-count]\n"
	 "		   [--extension-size|--ext-size|-z]\n"
	 "		   [--component-start[=[+-]COMP_START]]\n"
	 "		   [--component-end[=[+-]COMP_END]|-E[[+-]comp_end]]\n"
	 "		   [[!] --mirror-index=[+-]INDEX |\n"
	 "		   [!] --mirror-id=[+-]MIRROR_ID] [--mirror-count|-N]\n"
	 "		   [--no-follow]\n"
	 "		   <directory|filename> ..."},
	{"setdirstripe", lfs_setdirstripe, 0,
	 "Create striped directory on specified MDT, same as mkdir.\n"
	 "May be restricted to root or group users, depending on settings.\n"
	 "usage: setdirstripe [OPTION] <directory>\n"
	 SETDIRSTRIPE_USAGE},
	{"getdirstripe", lfs_getdirstripe, 0,
	 "To list the layout pattern info for a given directory\n"
	 "or recursively for all directories in a directory tree.\n"
	 "usage: getdirstripe [--mdt-count|-c] [--mdt-index|-m|-i]\n"
	 "		      [--help|-h] [--mdt-hash|-H] [--obd|-O UUID]\n"
	 "		      [--recursive|-r] [--yaml|-y]\n"
	 "		      [--verbose|-v] [--default|-D]\n"
	 "		      [--max-inherit|-X]\n"
	 "		      [--max-inherit-rr] <dir> ..."},
	{"mkdir", lfs_setdirstripe, 0,
	 "Create striped directory on specified MDT, same as setdirstripe.\n"
	 "usage: mkdir [OPTION] <directory>\n"
	 SETDIRSTRIPE_USAGE},
	{"rm_entry", lfs_rmentry, 0,
	 "To remove the name entry of the remote directory. Note: This\n"
	 "command will only delete the name entry, i.e. the remote directory\n"
	 "will become inaccessable after this command. This can only be done\n"
	 "by the administrator\n"
	 "usage: rm_entry <dir>\n"},
	{"unlink_foreign", lfs_unlink_foreign, 0,
	 "To remove the foreign file/dir.\n"
	 "Note: This is for files/dirs prevented to be removed using\n"
	 "unlink/rmdir, but works also for regular ones\n"
	 "usage: unlink_foreign <foreign_dir/file> [<foreign_dir/file> ...]\n"},
	{"pool_list", lfs_poollist, 0,
	 "List pools or pool OSTs\n"
	 "usage: pool_list <fsname>[.<pool>] | <pathname>\n"},
	{"find", lfs_find, 0,
	 "find files matching given attributes recursively in directory tree.\n"
	 "usage: find <directory|filename> ...\n"
	 "     [[!] --atime|-A [+-]N[smhdwy]] [[!] --btime|-B [+-]N[smhdwy]]\n"
	 "     [[!] --ctime|-C [+-]N[smhdwy]] [[!] --mtime|-M [+-]N[smhdwy]]\n"
	 "     [[!] --blocks|-b N] [[!] --component-count [+-]<comp_cnt>]\n"
	 "     [[!] --component-start [+-]N[kMGTPE]]\n"
	 "     [[!] --component-end|-E [+-]N[kMGTPE]]\n"
	 "     [[!] --component-flags {init,stale,prefer,offline,nosync,extension}]\n"
	 "     [[!] --extension-size|--ext-size|-z [+-]N[kMGT]]\n"
	 "     [[!] --foreign[=<foreign_type>]]\n"
	 "     [[!] --gid|-g|--group|-G <gid>|<gname>] [--help|-h]\n"
	 "     [[!] --layout|-L released,raid0,mdt] [--lazy]\n"
	 "     [--maxdepth|-D N] [[!] --mdt-count|-T [+-]<stripes>]\n"
	 "     [[!] --mdt-hash|-H <[^][blm],[^]fnv_1a_64,all_char,crush,...>\n"
	 "     [[!] --mdt-index|--mdt|-m <uuid|index,...>]\n"
	 "     [[!] --mirror-count|-N [+-]<n>]\n"
	 "     [[!] --mirror-state <[^]state>]\n"
	 "     [[!] --name|-n <pattern>] [[!] --newer[XY] <reference>]\n"
	 "     [[!] --ost|-O <uuid|index,...>] [[!] --perm [/-]mode]\n"
	 "     [[!] --pool <pool>] [--print|-P] [--print0|-0] [--printf <format>]\n"
	 "     [[!] --projid <projid>] [[!] --size|-s [+-]N[bkMGTPE]]\n"
	 "     [[!] --stripe-count|-c [+-]<stripes>]\n"
	 "     [[!] --stripe-index|-i <index,...>]\n"
	 "     [[!] --stripe-size|-S [+-]N[kMGT]] [[!] --type|-t <filetype>]\n"
	 "     [[!] --uid|-u|--user|-U <uid>|<uname>]\n"
	 "\t !: used before an option indicates 'NOT' requested attribute\n"
	 "\t -: used before a value indicates less than requested value\n"
	 "\t +: used before a value indicates more than requested value\n"
	 "\t ^: used before a flag indicates to exclude it\n"},
	{"check", lfs_check, 0,
	 "Display the status of MGTs, MDTs or OSTs (as specified in the command)\n"
	 "or all the servers (MGTs, MDTs and OSTs) [for specified path only].\n"
	 "usage: check {mgts|osts|mdts|all} [path]"},
	{"osts", lfs_osts, 0, "list OSTs connected to client "
	 "[for specified path only]\n" "usage: osts [path]"},
	{"mdts", lfs_mdts, 0, "list MDTs connected to client "
	 "[for specified path only]\n" "usage: mdts [path]"},
	{"df", lfs_df, 0,
	 "report filesystem disk space usage or inodes usage "
	 "of each MDS and all OSDs or a batch belonging to a specific pool.\n"
	 "Usage: df [--inodes|-i] [--human-readable|-h] [--lazy|-l]\n"
	 "          [--pool|-p <fsname>[.<pool>]] [path]"},
	{"getname", lfs_getname, 0,
	 "list instances and specified mount points [for specified path only]\n"
	 "Usage: getname [--help|-h] [--instance|-i] [--fsname|-n] [path ...]"},
#ifdef HAVE_SYS_QUOTA_H
	{"setquota", lfs_setquota, 0, "Set filesystem quotas.\n"
	 "usage: setquota [-t][-D] {-u|-U|-g|-G|-p|-P} {-b|-B|-i|-I LIMIT} [--pool POOL] FILESYSTEM\n"
	 "	 setquota {-u|-g|-p} --delete FILESYSTEM\n"},
	{"quota", lfs_quota, 0, "Display disk usage and limits.\n"
	 "usage: quota [-q] [-v] [-h] [-o OBD_UUID|-i MDT_IDX|-I OST_IDX]\n"
	 "	       [{-u|-g|-p} UNAME|UID|GNAME|GID|PROJID]\n"
	 "	       [--pool <OST pool name>] <filesystem>\n"
	 "	 quota -t <-u|-g|-p> [--pool <OST pool name>] <filesystem>\n"
	 "	 quota [-q] [-v] [h] {-U|-G|-P} [--pool <OST pool name>] <filesystem>"},
	{"project", lfs_project, 0,
	 "Change or list project attribute for specified file or directory.\n"
	 "usage: project [-d|-r] <file|directory...>\n"
	 "         list project ID and flags on file(s) or directories\n"
	 "       project [-p id] [-s] [-r] <file|directory...>\n"
	 "         set project ID and/or inherit flag for specified file(s) or directories\n"
	 "       project -c [-d|-r [-p id] [-0]] <file|directory...>\n"
	 "         check project ID and flags on file(s) or directories, print outliers\n"
	 "       project -C [-r] [-k] <file|directory...>\n"
	 "         clear the project inherit flag and ID on the file or directory\n"
	},
#endif
	{"flushctx", lfs_flushctx, 0,
	 "Flush security context for current user.\n"
	 "usage: flushctx [-k] [-r] [mountpoint...]"},
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
	 "usage: fid2path [--print-fid|-f] [--print-link|-c] [--link|-l <linkno>] "
	 "<fsname|root> <fid>..."},
	{"path2fid", lfs_path2fid, 0, "Display the fid(s) for a given path(s).\n"
	 "usage: path2fid [--parents] <path> ..."},
	{"rmfid", lfs_rmfid, 0, "Remove file(s) by FID(s)\n"
	 "usage: rmfid <fsname|rootpath> <fid> ..."},
	{"data_version", lfs_data_version, 0, "Display file data version for "
	 "a given path.\n" "usage: data_version [-n|-r|-w] <path>"},
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
	 "usage: hsm_remove [--filelist FILELIST] [--data DATA] "
	 "[--archive NUM]\n"
	 "                  (FILE [FILE ...] | "
	 "--mntpath MOUNTPATH FID [FID ...])\n"
	 "\n"
	 "Note: To remove an archived copy of a file already deleted from a "
	 "Lustre FS, the\n"
	 "--mntpath option and a list of FIDs must be specified"
	},
	{"hsm_cancel", lfs_hsm_cancel, 0,
	 "Cancel requests related to specified files.\n"
	 "usage: hsm_cancel [--filelist FILELIST] [--data DATA] <file> ..."},
	{"swap_layouts", lfs_swap_layouts, 0, "Swap layouts between 2 files.\n"
	 "usage: swap_layouts <path1> <path2>"},
	{"migrate", lfs_setstripe_migrate, 0,
	 "migrate directories and their inodes between MDTs.\n"
	 "usage: migrate [--mdt-count|-c STRIPE_COUNT] [--directory|-d]\n"
	 "               [--mdt-hash|-H HASH_TYPE]\n"
	 "               [--mdt-index|-m START_MDT_INDEX] [--verbose|-v]\n"
	 "		 DIRECTORY\n"
	 "\n"
	 "migrate file objects from one OST layout to another\n"
	 "(may be not safe with concurent writes).\n"
	 MIGRATE_USAGE },
	{"mv", lfs_mv, 0,
	 "To move directories between MDTs. This command is deprecated, "
	 "use \"migrate\" instead.\n"
	 "usage: mv <directory|filename> [--mdt-index|-m MDT_INDEX] "
	 "[--verbose|-v]\n"},
	{"ladvise", lfs_ladvise, 0,
	 "Provide servers with advice about access patterns for a file.\n"
	 "usage: ladvise [--advice|-a ADVICE] [--start|-s START[kMGT]]\n"
	 "               [--background|-b] [--unset|-u]\n\n"
	 "               {--end|-e END[kMGT]|--length|-l LENGTH[kMGT]}\n"
	 "               {[--mode|-m [READ,WRITE]}\n"
	 "               <file> ...\n"},
	{"mirror", lfs_mirror, mirror_cmdlist,
	 "lfs commands used to manage files with mirrored components:\n"
	 "lfs mirror create - create a mirrored file or directory\n"
	 "lfs mirror extend - add mirror(s) to an existing file\n"
	 "lfs mirror split  - split a mirror from an existing mirrored file\n"
	 "lfs mirror resync - resynchronize out-of-sync mirrored file(s)\n"
	 "lfs mirror read   - read a mirror content of a mirrored file\n"
	 "lfs mirror write  - write to a mirror of a mirrored file\n"
	 "lfs mirror copy   - copy a mirror to other mirror(s) of a file\n"
	 "lfs mirror verify - verify mirrored file(s)\n"},
	{"getsom", lfs_getsom, 0, "To list the SOM info for a given file.\n"
	 "usage: getsom [-s] [-b] [-f] <path>\n"
	 "\t-s: Only show the size value of the SOM data for a given file\n"
	 "\t-b: Only show the blocks value of the SOM data for a given file\n"
	 "\t-f: Only show the flags value of the SOM data for a given file\n"},
	{"heat_get", lfs_heat_get, 0,
	 "To get heat of files.\n"
	 "usage: heat_get <file> ...\n"},
	{"heat_set", lfs_heat_set, 0,
	 "To set heat flags of files.\n"
	 "usage: heat_set [--clear|-c] [--off|-o] [--on|-O] <file> ...\n"
	 "\t--clear|-c:	Clear file heat for given files\n"
	 "\t--off|-o:	Turn off file heat for given files\n"
	 "\t--on|-O:	Turn on file heat for given files\n"},
	{"pcc", lfs_pcc, pcc_cmdlist,
	 "lfs commands used to interact with PCC features:\n"
	 "lfs pcc attach - attach given files to Persistent Client Cache\n"
	 "lfs pcc attach_fid - attach given files into PCC by FID(s)\n"
	 "lfs pcc state  - display the PCC state for given files\n"
	 "lfs pcc detach - detach given files from Persistent Client Cache\n"
	 "lfs pcc detach_fid - detach given files from PCC by FID(s)\n"},
	{"help", Parser_help, 0, "help"},
	{"exit", Parser_quit, 0, "quit"},
	{"quit", Parser_quit, 0, "quit"},
	{"--version", Parser_version, 0,
	 "output build version of the utility and exit"},
	{"--list-commands", lfs_list_commands, 0,
	 "list commands supported by the utility and exit"},
	{ 0, 0, 0, NULL }
};

static int check_hashtype(const char *hashtype)
{
	int type_num = atoi(hashtype);
	int i;

	/* numeric hash type */
	if (hashtype && strlen(hashtype) == 1 &&
	    (type_num > 0 && type_num < LMV_HASH_TYPE_MAX))
		return type_num;
	/* string hash type */
	for (i = LMV_HASH_TYPE_ALL_CHARS; i < LMV_HASH_TYPE_MAX; i++)
		if (strcmp(hashtype, mdt_hash_name[i]) == 0)
			return i;

	return 0;
}

static uint32_t check_foreign_type_name(const char *foreign_type_name)
{
	uint32_t i;

	for (i = 0; i < LU_FOREIGN_TYPE_UNKNOWN; i++) {
		if (!lu_foreign_types[i].lft_name)
			break;
		if (strcmp(foreign_type_name,
			   lu_foreign_types[i].lft_name) == 0)
			return lu_foreign_types[i].lft_type;
	}

	return LU_FOREIGN_TYPE_UNKNOWN;
}

static const char *error_loc = "syserror";

static int
migrate_open_files(const char *name, __u64 migration_flags,
		   const struct llapi_stripe_param *param,
		   struct llapi_layout *layout, int *fd_src, int *fd_tgt)
{
	int			 fd = -1;
	int			 fdv = -1;
	int			 rflags;
	int			 mdt_index;
	int                      random_value;
	char			 parent[PATH_MAX];
	char			 volatile_file[PATH_MAX];
	char			*ptr;
	int			 rc;
	struct stat		 st;
	struct stat		 stv;

	if (!param && !layout) {
		error_loc = "layout information";
		return -EINVAL;
	}

	/* search for file directory pathname */
	if (strlen(name) > sizeof(parent) - 1) {
		error_loc = "source file name";
		return -ERANGE;
	}

	strncpy(parent, name, sizeof(parent));
	ptr = strrchr(parent, '/');
	if (!ptr) {
		if (!getcwd(parent, sizeof(parent))) {
			error_loc = "getcwd";
			return -errno;
		}
	} else {
		if (ptr == parent) /* leading '/' */
			ptr = parent + 1;
		*ptr = '\0';
	}

	/* even if the file is only read, WR mode is nedeed to allow
	 * layout swap on fd
	 */
	/* Allow migrating even without the key on encrypted files */
	rflags = O_RDWR | O_NOATIME | O_FILE_ENC;
	if (!(migration_flags & LLAPI_MIGRATION_NONDIRECT))
		rflags |= O_DIRECT;
source_open:
	fd = open(name, rflags);
	if (fd < 0) {
		/* If encrypted file without the key,
		 * retry mirror extend in O_DIRECT.
		 */
		if (errno == ENOKEY && !(rflags & O_DIRECT) &&
		    migration_flags & LLAPI_MIGRATION_MIRROR) {
			rflags |= O_DIRECT;
			goto source_open;
		}
		rc = -errno;
		error_loc = "cannot open source file";
		return rc;
	}

	rc = llapi_file_fget_mdtidx(fd, &mdt_index);
	if (rc < 0) {
		error_loc = "cannot get MDT index";
		goto out;
	}

	do {
		int open_flags = O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
			/* Allow migrating without the key on encrypted files */
			O_FILE_ENC;
		mode_t open_mode = S_IRUSR | S_IWUSR;

		if (rflags & O_DIRECT)
			open_flags |= O_DIRECT;
		random_value = random();
		rc = snprintf(volatile_file, sizeof(volatile_file),
			      "%s/%s:%.4X:%.4X:fd=%.2d", parent,
			      LUSTRE_VOLATILE_HDR, mdt_index,
			      random_value, fd);
		if (rc >= sizeof(volatile_file)) {
			rc = -ENAMETOOLONG;
			break;
		}

		/* create, open a volatile file, use caching (ie no directio) */
		if (layout) {
			/* Returns -1 and sets errno on error: */
			fdv = llapi_layout_file_open(volatile_file, open_flags,
						     open_mode, layout);
			if (fdv < 0)
				fdv = -errno;
		} else {
			/* Does the right thing on error: */
			fdv = llapi_file_open_param(volatile_file, open_flags,
						    open_mode, param);
		}
	} while (fdv < 0 && (rc = fdv) == -EEXIST);

	if (rc < 0) {
		error_loc = "cannot create volatile file";
		goto out;
	}

	/*
	 * In case the MDT does not support creation of volatile files
	 * we should try to unlink it.
	 */
	(void)unlink(volatile_file);

	/*
	 * Not-owner (root?) special case.
	 * Need to set owner/group of volatile file like original.
	 * This will allow to pass related check during layout_swap.
	 */
	rc = fstat(fd, &st);
	if (rc != 0) {
		rc = -errno;
		error_loc = "cannot stat source file";
		goto out;
	}

	rc = fstat(fdv, &stv);
	if (rc != 0) {
		rc = -errno;
		error_loc = "cannot stat volatile";
		goto out;
	}

	if (st.st_uid != stv.st_uid || st.st_gid != stv.st_gid) {
		rc = fchown(fdv, st.st_uid, st.st_gid);
		if (rc != 0) {
			rc = -errno;
			error_loc = "cannot change ownwership of volatile";
			goto out;
		}
	}

out:
	if (rc < 0) {
		if (fd > 0)
			close(fd);
		if (fdv > 0)
			close(fdv);
	} else {
		*fd_src = fd;
		*fd_tgt = fdv;
		error_loc = NULL;
	}
	return rc;
}

static int migrate_copy_data(int fd_src, int fd_dst, int (*check_file)(int))
{
	struct llapi_layout *layout;
	size_t buf_size = 4 * 1024 * 1024;
	void *buf = NULL;
	off_t pos = 0;
	off_t data_end = 0;
	size_t page_size = sysconf(_SC_PAGESIZE);
	bool sparse;
	int rc;

	layout = llapi_layout_get_by_fd(fd_src, 0);
	if (layout) {
		uint64_t stripe_size;

		rc = llapi_layout_stripe_size_get(layout, &stripe_size);
		if (rc == 0)
			buf_size = stripe_size;

		llapi_layout_free(layout);
	}

	/* Use a page-aligned buffer for direct I/O */
	rc = posix_memalign(&buf, page_size, buf_size);
	if (rc != 0)
		return -rc;

	sparse = llapi_file_is_sparse(fd_src);
	if (sparse) {
		rc = ftruncate(fd_dst, pos);
		if (rc < 0) {
			rc = -errno;
			return rc;
		}
	}

	while (1) {
		off_t data_off;
		size_t to_read, to_write;
		ssize_t rsize;

		if (sparse && pos >= data_end) {
			size_t data_size;

			data_off = llapi_data_seek(fd_src, pos, &data_size);
			if (data_off < 0) {
				/* Non-fatal, switch to full copy */
				sparse = false;
				continue;
			}
			/* hole at the end of file, truncate up to it */
			if (!data_size) {
				rc = ftruncate(fd_dst, data_off);
				if (rc < 0)
					goto out;
			}
			pos = data_off & ~(page_size - 1);
			data_end = data_off + data_size;
			to_read = ((data_end - pos - 1) | (page_size - 1)) + 1;
			to_read = MIN(to_read, buf_size);
		} else {
			to_read = buf_size;
		}

		if (check_file) {
			rc = check_file(fd_src);
			if (rc < 0)
				goto out;
		}

		rsize = pread(fd_src, buf, to_read, pos);
		if (rsize < 0) {
			rc = -errno;
			goto out;
		}
		/* EOF */
		if (rsize == 0)
			break;

		to_write = rsize;
		while (to_write > 0) {
			ssize_t written;

			written = pwrite(fd_dst, buf, to_write, pos);
			if (written < 0) {
				rc = -errno;
				goto out;
			}
			pos += written;
			to_write -= written;
		}
		if (rc || rsize < to_read)
			break;
	}

	rc = fsync(fd_dst);
	if (rc < 0)
		rc = -errno;
out:
	/* Try to avoid page cache pollution after migration. */
	(void)posix_fadvise(fd_src, 0, 0, POSIX_FADV_DONTNEED);
	(void)posix_fadvise(fd_dst, 0, 0, POSIX_FADV_DONTNEED);

	free(buf);
	return rc;
}

static int migrate_set_timestamps(int fd, const struct stat *st)
{
	struct timeval tv[2] = {
		{.tv_sec = st->st_atime},
		{.tv_sec = st->st_mtime}
	};

	return futimes(fd, tv);
}

static int migrate_block(int fd, int fdv)
{
	struct stat st;
	__u64	dv1;
	int	gid;
	int	rc;
	int	rc2;

	rc = fstat(fd, &st);
	if (rc < 0) {
		error_loc = "cannot stat source file";
		return -errno;
	}

	rc = llapi_get_data_version(fd, &dv1, LL_DV_RD_FLUSH);
	if (rc < 0) {
		error_loc = "cannot get dataversion";
		return rc;
	}

	do
		gid = random();
	while (gid == 0);

	/*
	 * The grouplock blocks all concurrent accesses to the file.
	 * It has to be taken after llapi_get_data_version as it would
	 * block it too.
	 */
	rc = llapi_group_lock(fd, gid);
	if (rc < 0) {
		error_loc = "cannot get group lock";
		return rc;
	}

	rc = migrate_copy_data(fd, fdv, NULL);
	if (rc < 0) {
		error_loc = "data copy failed";
		goto out_unlock;
	}

	/* Make sure we keep original atime/mtime values */
	rc = migrate_set_timestamps(fdv, &st);
	if (rc < 0) {
		error_loc = "set target file timestamp failed";
		goto out_unlock;
	}

	/*
	 * swap layouts
	 * for a migration we need to check data version on file did
	 * not change.
	 *
	 * Pass in gid=0 since we already own grouplock.
	 */
	rc = llapi_fswap_layouts_grouplock(fd, fdv, dv1, 0, 0,
					   SWAP_LAYOUTS_CHECK_DV1);
	if (rc == -EAGAIN) {
		error_loc = "file changed";
		goto out_unlock;
	} else if (rc < 0) {
		error_loc = "cannot swap layout";
		goto out_unlock;
	}

out_unlock:
	rc2 = llapi_group_unlock(fd, gid);
	if (rc2 < 0 && rc == 0) {
		error_loc = "unlock group lock";
		rc = rc2;
	}

	return rc;
}

/**
 * Internal helper for migrate_copy_data(). Check lease and report error if
 * need be.
 *
 * \param[in]  fd           File descriptor on which to check the lease.
 *
 * \retval 0       Migration can keep on going.
 * \retval -errno  Error occurred, abort migration.
 */
static int check_lease(int fd)
{
	int rc;

	rc = llapi_lease_check(fd);
	if (rc > 0)
		return 0; /* llapi_check_lease returns > 0 on success. */

	return -EBUSY;
}

static int migrate_nonblock(int fd, int fdv)
{
	struct stat st;
	__u64	dv1;
	__u64	dv2;
	int	rc;

	rc = fstat(fd, &st);
	if (rc < 0) {
		error_loc = "cannot stat source file";
		return -errno;
	}

	rc = llapi_get_data_version(fd, &dv1, LL_DV_RD_FLUSH);
	if (rc < 0) {
		error_loc = "cannot get data version";
		return rc;
	}

	rc = migrate_copy_data(fd, fdv, check_lease);
	if (rc < 0) {
		error_loc = "data copy failed";
		return rc;
	}

	rc = llapi_get_data_version(fd, &dv2, LL_DV_RD_FLUSH);
	if (rc != 0) {
		error_loc = "cannot get data version";
		return rc;
	}

	if (dv1 != dv2) {
		rc = -EAGAIN;
		error_loc = "source file changed";
		return rc;
	}

	/* Make sure we keep original atime/mtime values */
	rc = migrate_set_timestamps(fdv, &st);
	if (rc < 0) {
		error_loc = "set target file timestamp failed";
		return -errno;
	}
	return 0;
}

static
int lfs_layout_compid_by_pool(char *fname, const char *pool, int *comp_id)
{
	struct pool_to_id_cbdata data = { .pool = pool };
	struct llapi_layout *layout = NULL;
	int rc;

	layout = llapi_layout_get_by_path(fname, 0);
	if (!layout) {
		fprintf(stderr,
			"error %s: file '%s' couldn't get layout: rc=%d\n",
			progname, fname, errno);
		rc = -errno;
		goto free_layout;
	}
	rc = llapi_layout_sanity(layout, false, true);
	if (rc < 0) {
		llapi_layout_sanity_perror(errno);
		goto free_layout;
	}
	rc = llapi_layout_comp_iterate(layout, find_comp_id_by_pool, &data);
	if (rc < 0)
		goto free_layout;

	*comp_id = data.id;
	rc = 0;

free_layout:
	if (layout)
		llapi_layout_free(layout);
	return rc;
}

static int lfs_component_set(char *fname, int comp_id, const char *pool,
			     __u32 flags, __u32 neg_flags)
{
	__u32 ids[2];
	__u32 flags_array[2];
	size_t count = 0;
	int rc;

	if (!comp_id) {
		if (pool == NULL) {
			fprintf(stderr,
				"error %s: neither component id nor pool is specified\n",
				progname);
			return -EINVAL;
		}
		rc = lfs_layout_compid_by_pool(fname, pool, &comp_id);
		if (rc)
			return rc;
	}

	if (flags) {
		ids[count] = comp_id;
		flags_array[count] = flags;
		++count;
	}

	if (neg_flags) {
		if (neg_flags & LCME_FL_STALE) {
			fprintf(stderr,
				"%s: cannot clear 'stale' flags from component. Please use lfs-mirror-resync(1) instead\n",
				progname);
			return -EINVAL;
		}

		ids[count] = comp_id;
		flags_array[count] = neg_flags | LCME_FL_NEG;
		++count;
	}

	rc = llapi_layout_file_comp_set(fname, ids, flags_array, count);
	if (rc) {
		if (errno == EUCLEAN) {
			rc = -errno;
			fprintf(stderr,
				"%s: cannot set 'stale' flag on component '%#x' of the last non-stale mirror of '%s'\n",
				progname, comp_id, fname);
		} else {
			fprintf(stderr,
				"%s: cannot change the flags of component '%#x' of file '%s': %x / ^(%x)\n",
				progname, comp_id, fname, flags, neg_flags);
		}
	}

	return rc;
}

static int lfs_component_del(char *fname, __u32 comp_id,
			     __u32 flags, __u32 neg_flags)
{
	int	rc = 0;

	if (flags && neg_flags) {
		fprintf(stderr,
			"%s: cannot specify both positive and negative flags\n",
			progname);
		return -EINVAL;
	}

	if (!flags && neg_flags)
		flags = neg_flags | LCME_FL_NEG;

	if (flags && comp_id) {
		fprintf(stderr,
			"%s: cannot specify component ID and flags at the same time\n",
			progname);
		return -EINVAL;
	}

	if (!flags && !comp_id) {
		fprintf(stderr,
			"%s: neither flags nor component ID is specified\n",
			progname);
		return -EINVAL;
	}

	if (flags) {
		if (flags & ~LCME_KNOWN_FLAGS) {
			fprintf(stderr,
				"%s setstripe: unknown flags %#x\n",
				progname, flags);
			return -EINVAL;
		}
	} else if (comp_id > LCME_ID_MAX) {
		fprintf(stderr, "%s setstripe: invalid component id %u\n",
			progname, comp_id);
		return -EINVAL;
	}

	rc = llapi_layout_file_comp_del(fname, comp_id, flags);
	if (rc)
		fprintf(stderr,
			"%s setstripe: cannot delete component %#x from '%s': %s\n",
			progname, comp_id, fname, strerror(errno));
	return rc;
}

static int lfs_component_add(char *fname, struct llapi_layout *layout)
{
	int	rc;

	if (!layout)
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

	if (!layout)
		return -EINVAL;

	fd = lstat(fname, &st);
	if (fd == 0 && S_ISDIR(st.st_mode))
		open_flags = O_DIRECTORY | O_RDONLY;

	fd = llapi_layout_file_open(fname, open_flags, open_mode, layout);
	if (fd < 0)
		fprintf(stderr, "%s: cannot %s '%s': %s\n", progname,
			S_ISDIR(st.st_mode) ?
				"set default composite layout for" :
				"create composite file",
			fname, strerror(errno));
	return fd;
}

static int lfs_migrate(char *name, __u64 migration_flags,
		       struct llapi_stripe_param *param,
		       struct llapi_layout *layout)
{
	struct llapi_layout *existing;
	uint64_t dom_new, dom_cur;
	int fd = -1;
	int fdv = -1;
	int rc;

	rc = migrate_open_files(name, migration_flags, param, layout,
				&fd, &fdv);
	if (rc < 0)
		goto out;

	rc = llapi_layout_dom_size(layout, &dom_new);
	if (rc) {
		error_loc = "cannot get new layout DoM size";
		goto out;
	}
	/* special case for migration to DOM layout*/
	existing = llapi_layout_get_by_fd(fd, 0);
	if (!existing) {
		error_loc = "cannot get existing layout";
		goto out;
	}

	rc = llapi_layout_dom_size(existing, &dom_cur);
	if (rc) {
		error_loc = "cannot get current layout DoM size";
		goto out;
	}

	/*
	 * if file has DoM layout already then migration is possible to
	 * the new layout with the same DoM component via swap layout,
	 * if new layout used bigger DOM size, then mirroring is used
	 */
	if (dom_new > dom_cur) {
		rc = lfs_migrate_to_dom(fd, fdv, name, migration_flags);
		if (rc)
			error_loc = "cannot migrate to DOM layout";
		goto out_closed;
	}

	if (!(migration_flags & LLAPI_MIGRATION_NONBLOCK)) {
		/*
		 * Blocking mode (forced if servers do not support file lease).
		 * It is also the default mode, since we cannot distinguish
		 * between a broken lease and a server that does not support
		 * atomic swap/close (LU-6785)
		 */
		rc = migrate_block(fd, fdv);
		goto out;
	}

	rc = llapi_lease_acquire(fd, LL_LEASE_RDLCK);
	if (rc < 0) {
		error_loc = "cannot get lease";
		goto out;
	}

	rc = migrate_nonblock(fd, fdv);
	if (rc < 0) {
		llapi_lease_release(fd);
		goto out;
	}

	/*
	 * Atomically put lease, swap layouts and close.
	 * for a migration we need to check data version on file did
	 * not change.
	 */
	rc = llapi_fswap_layouts(fd, fdv, 0, 0, SWAP_LAYOUTS_CLOSE);
	if (rc < 0) {
		error_loc = "cannot swap layout";
		goto out;
	}

out:
	if (fd >= 0)
		close(fd);

	if (fdv >= 0)
		close(fdv);
out_closed:
	if (rc < 0)
		fprintf(stderr, "error: %s: %s: %s: %s\n",
			progname, name, error_loc, strerror(-rc));
	else if (migration_flags & LLAPI_MIGRATION_VERBOSE)
		printf("%s\n", name);

	return rc;
}

static int comp_str2flags(char *string, __u32 *flags, __u32 *neg_flags)
{
	char *name;
	char *dup_string = NULL;
	int rc = 0;

	*flags = 0;
	*neg_flags = 0;

	if (!string || !string[0])
		return -EINVAL;

	dup_string = strdup(string);
	if (!dup_string) {
		llapi_printf(LLAPI_MSG_ERROR,
			     "%s: insufficient memory\n",
			     progname);
		return -ENOMEM;
	}

	for (name = strtok(dup_string, ","); name; name = strtok(NULL, ",")) {
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
				*neg_flags |= comp_flag;
				found = true;
			}
		}
		if (!found) {
			llapi_printf(LLAPI_MSG_ERROR,
				     "%s: component flag '%s' not supported\n",
				     progname, name);
			rc = -EINVAL;
			goto out_free;
		}
	}

	if (!*flags && !*neg_flags)
		rc = -EINVAL;

	/* don't allow to set and exclude the same flag */
	if (*flags & *neg_flags)
		rc = -EINVAL;

out_free:
	free(dup_string);
	return rc;
}

static int mdthash_input(char *string, __u32 *inflags,
			 __u32 *exflags, __u32 *type)
{
	char *name;
	struct mhf_list {
		char *name;
		__u32 flag;
	} mhflist[] = {
		{"migrating", LMV_HASH_FLAG_MIGRATION},
		{"badtype", LMV_HASH_FLAG_BAD_TYPE},
		{"lostlmv", LMV_HASH_FLAG_LOST_LMV},
	};

	if (string == NULL)
		return -EINVAL;

	*inflags = 0;
	*exflags = 0;
	*type = 0;
	for (name = strtok(string, ","); name; name = strtok(NULL, ",")) {
		bool found = false;
		int i;

		for (i = 0; i < ARRAY_SIZE(mhflist); i++) {
			if (strcmp(name, mhflist[i].name) == 0 ||
			    name[0] == mhflist[i].name[0]) {
				*inflags |= mhflist[i].flag;
				found = true;
			} else if (name[0] == '^' &&
				   (strcmp(name + 1, mhflist[i].name) == 0 ||
				    name[1] == mhflist[i].name[0])) {
				*exflags |= mhflist[i].flag;
				found = true;
			}
		}
		if (!found) {
			i = check_hashtype(name);
			if (i > 0) {
				*type |= 1 << i;
				continue;
			}
			llapi_printf(LLAPI_MSG_ERROR,
				     "%s: invalid mdt_hash value '%s'\n",
				     progname, name);
			return -EINVAL;
		}
	}

	/* don't allow to include and exclude the same flag */
	if (*inflags & *exflags) {
		llapi_printf(LLAPI_MSG_ERROR,
			     "%s: include and exclude same flag '%s'\n",
			     progname, string);
		return -EINVAL;
	}

	return 0;
}

static int mirror_str2state(char *string, __u16 *state, __u16 *neg_state)
{
	if (!string)
		return -EINVAL;

	*state = 0;
	*neg_state = 0;

	if (strncmp(string, "^", 1) == 0) {
		*neg_state = llapi_layout_string_flags(string + 1);
		if (*neg_state != 0)
			return 0;
	} else {
		*state = llapi_layout_string_flags(string);
		if (*state != 0)
			return 0;
	}

	llapi_printf(LLAPI_MSG_ERROR,
		     "%s: mirrored file state '%s' not supported\n",
		     progname, string);
	return -EINVAL;
}

/**
 * struct mirror_args - Command-line arguments for mirror(s).
 * @m_count:  Number of mirrors to be created with this layout.
 * @m_flags:  Mirror level flags, only 'prefer' is supported.
 * @m_layout: Mirror layout.
 * @m_file:   A victim file. Its layout will be split and used as a mirror.
 * @m_next:   Point to the next node of the list.
 *
 * Command-line arguments for mirror(s) will be parsed and stored in
 * a linked list that consists of this structure.
 */
struct mirror_args {
	__u32			m_count;
	__u32			m_flags;
	struct llapi_layout	*m_layout;
	const char		*m_file;
	struct mirror_args	*m_next;
	bool			m_inherit;
};

/**
 * enum mirror_flags - Flags for extending a mirrored file.
 * @MF_NO_VERIFY: Indicates not to verify the mirror(s) from victim file(s)
 *	       in case the victim file(s) contains the same data as the
 *	       original mirrored file.
 * @MF_DESTROY: Indicates to delete the mirror from the mirrored file.
 * @MF_COMP_ID: specified component id instead of mirror id
 *
 * Flags for extending a mirrored file.
 */
enum mirror_flags {
	MF_NO_VERIFY	= 0x1,
	MF_DESTROY	= 0x2,
	MF_COMP_ID	= 0x4,
	MF_COMP_POOL	= 0x8,
};

/**
 * mirror_create_sanity_check() - Check mirror list.
 * @list:  A linked list that stores the mirror arguments.
 *
 * This function does a sanity check on @list for creating
 * a mirrored file.
 *
 * Return: 0 on success or a negative error code on failure.
 */
static int mirror_create_sanity_check(const char *fname,
				      struct mirror_args *list,
				      bool check_fname)
{
	int rc = 0;
	bool has_m_file = false;
	bool has_m_layout = false;

	if (!list)
		return -EINVAL;

	if (fname && check_fname) {
		struct llapi_layout *layout;

		layout = llapi_layout_get_by_path(fname, 0);
		if (!layout) {
			fprintf(stderr,
				"error: %s: file '%s' couldn't get layout\n",
				progname, fname);
			return -ENODATA;
		}

		rc = llapi_layout_sanity(layout, false, true);

		llapi_layout_free(layout);

		if (rc) {
			llapi_layout_sanity_perror(rc);
			return rc;
		}
	}

	while (list) {
		if (list->m_file) {
			has_m_file = true;
			llapi_layout_free(list->m_layout);

			list->m_layout =
				llapi_layout_get_by_path(list->m_file, 0);
			if (!list->m_layout) {
				fprintf(stderr,
					"error: %s: file '%s' has no layout\n",
					progname, list->m_file);
				return -ENODATA;
			}
		} else {
			has_m_layout = true;
			if (!list->m_layout) {
				fprintf(stderr, "error: %s: no mirror layout\n",
					progname);
				return -EINVAL;
			}
		}

		rc = llapi_layout_sanity(list->m_layout, false, true);
		if (rc) {
			llapi_layout_sanity_perror(rc);
			return rc;
		}

		list = list->m_next;
	}

	if (has_m_file && has_m_layout) {
		fprintf(stderr,
			"error: %s: -f <victim_file> option should not be specified with setstripe options\n",
			progname);
		return -EINVAL;
	}

	return 0;
}

static int mirror_set_flags(struct llapi_layout *layout, void *cbdata)
{
	__u32 mirror_flags = *(__u32 *)cbdata;
	uint32_t flags;
	int rc;

	rc = llapi_layout_comp_flags_get(layout, &flags);
	if (rc < 0)
		return rc;

	if (!flags) {
		rc = llapi_layout_comp_flags_set(layout, mirror_flags);
		if (rc)
			return rc;
	}

	return LLAPI_LAYOUT_ITER_CONT;
}

/**
 * mirror_create() - Create a mirrored file.
 * @fname:        The file to be created.
 * @mirror_list:  A linked list that stores the mirror arguments.
 *
 * This function creates a mirrored file @fname with the mirror(s)
 * from @mirror_list.
 *
 * Return: 0 on success or a negative error code on failure.
 */
static int mirror_create(char *fname, struct mirror_args *mirror_list)
{
	struct llapi_layout *layout = NULL;
	struct mirror_args *cur_mirror = NULL;
	uint16_t mirror_count = 0;
	int i = 0;
	int rc = 0;

	rc = mirror_create_sanity_check(fname, mirror_list, false);
	if (rc)
		return rc;

	cur_mirror = mirror_list;
	while (cur_mirror) {
		rc = llapi_layout_comp_iterate(cur_mirror->m_layout,
					       mirror_set_flags,
					       &cur_mirror->m_flags);
		if (rc) {
			rc = -errno;
			fprintf(stderr, "%s: failed to set mirror flags\n",
				progname);
			goto error;
		}

		for (i = 0; i < cur_mirror->m_count; i++) {
			rc = llapi_layout_merge(&layout, cur_mirror->m_layout);
			if (rc) {
				rc = -errno;
				fprintf(stderr,
					"error: %s: merge layout failed: %s\n",
					progname, strerror(errno));
				goto error;
			}
		}
		mirror_count += cur_mirror->m_count;
		cur_mirror = cur_mirror->m_next;
	}

	if (!layout) {
		fprintf(stderr, "error: %s: layout is NULL\n", progname);
		return -EINVAL;
	}

	rc = llapi_layout_mirror_count_set(layout, mirror_count);
	if (rc) {
		rc = -errno;
		fprintf(stderr, "error: %s: set mirror count failed: %s\n",
			progname, strerror(errno));
		goto error;
	}

	rc = lfs_component_create(fname, O_CREAT | O_WRONLY, 0666,
				  layout);
	if (rc >= 0) {
		close(rc);
		rc = 0;
	}

error:
	llapi_layout_free(layout);
	return rc;
}

/**
 * Compare files and check lease on @fd.
 *
 * \retval bytes number of bytes are the same
 */
static ssize_t mirror_file_compare(int fd, int fdv)
{
	const size_t buflen = 4 * 1024 * 1024; /* 4M */
	void *buf;
	ssize_t bytes_done = 0;
	ssize_t bytes_read = 0;

	buf = malloc(buflen * 2);
	if (!buf)
		return -ENOMEM;

	while (1) {
		if (!llapi_lease_check(fd)) {
			bytes_done = -EBUSY;
			break;
		}

		bytes_read = read(fd, buf, buflen);
		if (bytes_read <= 0)
			break;

		if (bytes_read != read(fdv, buf + buflen, buflen))
			break;

		/*
		 * XXX: should compute the checksum on each buffer and then
		 * compare checksum to avoid cache collision
		 */
		if (memcmp(buf, buf + buflen, bytes_read))
			break;

		bytes_done += bytes_read;
	}

	free(buf);

	return bytes_done;
}

static int mirror_extend_file(const char *fname, const char *victim_file,
			      enum mirror_flags mirror_flags)
{
	int fd = -1;
	int fdv = -1;
	struct stat stbuf;
	struct stat stbuf_v;
	struct ll_ioc_lease *data = NULL;
	int rc;

	fd = open(fname, O_RDWR);
	if (fd < 0) {
		error_loc = "open source file";
		rc = -errno;
		goto out;
	}

	fdv = open(victim_file, O_RDWR);
	if (fdv < 0) {
		error_loc = "open target file";
		rc = -errno;
		goto out;
	}

	if (fstat(fd, &stbuf) || fstat(fdv, &stbuf_v)) {
		error_loc = "stat source or target file";
		rc = -errno;
		goto out;
	}

	if (stbuf.st_dev != stbuf_v.st_dev) {
		error_loc = "stat source and target file";
		rc = -EXDEV;
		goto out;
	}

	/* mirrors should be of the same size */
	if (stbuf.st_size != stbuf_v.st_size) {
		error_loc = "file sizes don't match";
		rc = -EINVAL;
		goto out;
	}

	rc = llapi_lease_acquire(fd, LL_LEASE_RDLCK);
	if (rc < 0) {
		error_loc = "cannot get lease";
		goto out;
	}

	if (!(mirror_flags & MF_NO_VERIFY)) {
		ssize_t ret;
		/* mirrors should have the same contents */
		ret = mirror_file_compare(fd, fdv);
		if (ret != stbuf.st_size) {
			error_loc = "file busy or contents don't match";
			rc = ret < 0 ? ret : -EINVAL;
			goto out;
		}
	}

	/* Get rid of caching pages from clients */
	rc = llapi_file_flush(fd);
	if (rc < 0) {
		error_loc = "cannot get data version";
		goto out;
	}

	rc = llapi_file_flush(fdv);
	if (rc < 0) {
		error_loc = "cannot get data version";
		goto out;
	}

	rc = migrate_set_timestamps(fd, &stbuf);
	if (rc < 0) {
		error_loc = "cannot set source file timestamp";
		goto out;
	}

	/* Atomically put lease, merge layouts and close. */
	data = calloc(1, offsetof(typeof(*data), lil_ids[1]));
	if (!data) {
		error_loc = "memory allocation";
		goto out;
	}
	data->lil_mode = LL_LEASE_UNLCK;
	data->lil_flags = LL_LEASE_LAYOUT_MERGE;
	data->lil_count = 1;
	data->lil_ids[0] = fdv;
	rc = llapi_lease_set(fd, data);
	if (rc < 0) {
		error_loc = "cannot merge layout";
		goto out;
	} else if (rc == 0) {
		rc = -EBUSY;
		error_loc = "lost lease lock";
		goto out;
	}
	rc = 0;

out:
	if (data)
		free(data);
	if (fd >= 0)
		close(fd);
	if (fdv >= 0)
		close(fdv);
	if (!rc)
		(void) unlink(victim_file);
	if (rc < 0)
		fprintf(stderr, "error: %s: %s: %s: %s\n",
			progname, fname, error_loc, strerror(-rc));
	return rc;
}

static int mirror_extend_layout(char *name, struct llapi_layout *m_layout,
				bool inherit, uint32_t flags)
{
	struct llapi_layout *f_layout = NULL;
	struct ll_ioc_lease *data = NULL;
	struct stat st;
	int fd = -1;
	int fdv = -1;
	int rc = 0;

	if (inherit) {
		f_layout = llapi_layout_get_by_path(name, 0);
		if (!f_layout) {
			rc = -EINVAL;
			fprintf(stderr, "%s: cannot get layout\n", progname);
			goto out;
		}
		rc = llapi_layout_get_last_init_comp(f_layout);
		if (rc) {
			fprintf(stderr, "%s: cannot get the last init comp\n",
				progname);
			goto out;
		}
		rc = llapi_layout_mirror_inherit(f_layout, m_layout);
		if (rc) {
			fprintf(stderr,
				"%s: cannot inherit from the last init comp\n",
				progname);
			goto out;
		}
	}

	llapi_layout_comp_flags_set(m_layout, flags);
	rc = migrate_open_files(name,
			     LLAPI_MIGRATION_NONDIRECT | LLAPI_MIGRATION_MIRROR,
			     NULL, m_layout, &fd, &fdv);
	if (rc < 0)
		goto out;

	rc = llapi_lease_acquire(fd, LL_LEASE_RDLCK);
	if (rc < 0) {
		error_loc = "cannot get lease";
		goto out;
	}

	rc = fstat(fd, &st);
	if (rc < 0) {
		error_loc = "cannot stat source file";
		goto out;
	}

	rc = migrate_nonblock(fd, fdv);
	if (rc < 0) {
		llapi_lease_release(fd);
		goto out;
	}

	rc = migrate_set_timestamps(fd, &st);
	if (rc < 0) {
		error_loc = "cannot set source file timestamp";
		goto out;
	}

	/* Atomically put lease, merge layouts and close. */
	data = calloc(1, offsetof(typeof(*data), lil_ids[1]));
	if (!data) {
		error_loc = "memory allocation";
		goto out;
	}
	data->lil_mode = LL_LEASE_UNLCK;
	data->lil_flags = LL_LEASE_LAYOUT_MERGE;
	data->lil_count = 1;
	data->lil_ids[0] = fdv;
	rc = llapi_lease_set(fd, data);
	if (rc < 0) {
		error_loc = "cannot merge layout";
		goto out;
	} else if (rc == 0) {
		rc = -EBUSY;
		error_loc = "lost lease lock";
		goto out;
	}
	rc = 0;

out:
	if (data)
		free(data);
	if (fd >= 0)
		close(fd);
	if (fdv >= 0)
		close(fdv);
	if (rc < 0)
		fprintf(stderr, "error: %s: %s: %s: %s\n",
			progname, name, error_loc, strerror(-rc));
	return rc;
}

static int mirror_extend(char *fname, struct mirror_args *mirror_list,
			 enum mirror_flags mirror_flags)
{
	int rc = 0;

	while (mirror_list) {
		if (mirror_list->m_file) {
			rc = mirror_extend_file(fname, mirror_list->m_file,
						mirror_flags);
		} else {
			__u32 mirror_count = mirror_list->m_count;

			while (mirror_count > 0) {
				rc = mirror_extend_layout(fname,
							mirror_list->m_layout,
							mirror_list->m_inherit,
							mirror_list->m_flags);
				if (rc)
					break;

				--mirror_count;
			}
		}
		if (rc)
			break;

		mirror_list = mirror_list->m_next;
	}

	return rc;
}

static int find_mirror_id(struct llapi_layout *layout, void *cbdata)
{
	uint32_t id;
	int rc;

	rc = llapi_layout_mirror_id_get(layout, &id);
	if (rc < 0)
		return rc;

	if ((__u16)id == *(__u16 *)cbdata)
		return LLAPI_LAYOUT_ITER_STOP;

	return LLAPI_LAYOUT_ITER_CONT;
}

static int find_comp_id(struct llapi_layout *layout, void *cbdata)
{
	uint32_t id;
	int rc;

	rc = llapi_layout_comp_id_get(layout, &id);
	if (rc < 0)
		return rc;

	if (id == *(__u32 *)cbdata)
		return LLAPI_LAYOUT_ITER_STOP;

	return LLAPI_LAYOUT_ITER_CONT;
}

static int find_mirror_id_by_pool(struct llapi_layout *layout, void *cbdata)
{
	char buf[LOV_MAXPOOLNAME + 1];
	struct pool_to_id_cbdata *d = (void *)cbdata;
	uint32_t id;
	int rc;

	rc = llapi_layout_pool_name_get(layout, buf, sizeof(buf));
	if (rc < 0)
		return rc;
	if (strcmp(d->pool, buf))
		return LLAPI_LAYOUT_ITER_CONT;

	rc = llapi_layout_mirror_id_get(layout, &id);
	if (rc < 0)
		return rc;
	d->id = id;

	return LLAPI_LAYOUT_ITER_STOP;
}

static int find_comp_id_by_pool(struct llapi_layout *layout, void *cbdata)
{
	char buf[LOV_MAXPOOLNAME + 1];
	struct pool_to_id_cbdata *d = (void *)cbdata;
	uint32_t id;
	int rc;

	rc = llapi_layout_pool_name_get(layout, buf, sizeof(buf));
	if (rc < 0)
		return rc;
	if (strcmp(d->pool, buf))
		return LLAPI_LAYOUT_ITER_CONT;

	rc = llapi_layout_comp_id_get(layout, &id);
	if (rc < 0)
		return rc;
	d->id = id;

	return LLAPI_LAYOUT_ITER_STOP;
}

struct collect_ids_data {
	__u16	*cid_ids;
	int	cid_count;
	__u16	cid_exclude;
};

static int collect_mirror_id(struct llapi_layout *layout, void *cbdata)
{
	struct collect_ids_data *cid = cbdata;
	uint32_t id;
	int rc;

	rc = llapi_layout_mirror_id_get(layout, &id);
	if (rc < 0)
		return rc;

	if ((__u16)id != cid->cid_exclude) {
		int i;

		for (i = 0; i < cid->cid_count; i++) {
			/* already collected the mirror id */
			if (id == cid->cid_ids[i])
				return LLAPI_LAYOUT_ITER_CONT;
		}
		cid->cid_ids[cid->cid_count] = id;
		cid->cid_count++;
	}

	return LLAPI_LAYOUT_ITER_CONT;
}

/**
 * last_non_stale_mirror() - Check if a mirror is the last non-stale mirror.
 * @mirror_id: Mirror id to be checked.
 * @layout:    Mirror component list.
 *
 * This function checks if a mirror with specified @mirror_id is the last
 * non-stale mirror of a layout @layout.
 *
 * Return: true or false.
 */
static inline
bool last_non_stale_mirror(__u16 mirror_id, struct llapi_layout *layout)
{
	__u16 mirror_ids[128] = { 0 };
	struct collect_ids_data cid = {	.cid_ids = mirror_ids,
					.cid_count = 0,
					.cid_exclude = mirror_id, };
	int i;

	llapi_layout_comp_iterate(layout, collect_mirror_id, &cid);

	for (i = 0; i < cid.cid_count; i++) {
		struct llapi_resync_comp comp_array[1024] = { { 0 } };
		int comp_size = 0;

		comp_size = llapi_mirror_find_stale(layout, comp_array,
						    ARRAY_SIZE(comp_array),
						    &mirror_ids[i], 1);
		if (comp_size == 0)
			return false;
	}

	return true;
}

static int mirror_split(const char *fname, __u32 id, const char *pool,
			enum mirror_flags mflags, const char *victim_file)
{
	struct llapi_layout *layout;
	char parent[PATH_MAX];
	char victim[PATH_MAX];
	int flags = O_CREAT | O_EXCL | O_LOV_DELAY_CREATE | O_NOFOLLOW;
	char *ptr;
	struct ll_ioc_lease *data;
	uint16_t mirror_count;
	__u32 mirror_id;
	int mdt_index;
	int fd, fdv;
	bool purge = true; /* delete mirror by setting fdv=fd */
	bool is_encrypted;
	int rc;

	if (victim_file && (strcmp(fname, victim_file) == 0)) {
		fprintf(stderr,
			"error %s: the source file '%s' and -f file are the same\n",
			progname, fname);
		return -EINVAL;
	}

	/* check fname contains mirror with mirror_id/comp_id */
	layout = llapi_layout_get_by_path(fname, 0);
	if (!layout) {
		fprintf(stderr,
			"error %s: file '%s' couldn't get layout\n",
			progname, fname);
		return -EINVAL;
	}

	rc = llapi_layout_sanity(layout, false, true);
	if (rc) {
		llapi_layout_sanity_perror(rc);
		goto free_layout;
	}

	rc = llapi_layout_mirror_count_get(layout, &mirror_count);
	if (rc) {
		fprintf(stderr,
			"error %s: file '%s' couldn't get mirror count\n",
			progname, fname);
		goto free_layout;
	}
	if (mirror_count < 2) {
		fprintf(stderr,
			"error %s: file '%s' has %d component, cannot split\n",
			progname, fname, mirror_count);
		goto free_layout;
	}

	if (mflags & MF_COMP_POOL) {
		struct pool_to_id_cbdata data = { .pool = pool };

		rc = llapi_layout_comp_iterate(layout, find_mirror_id_by_pool,
					       &data);
		mirror_id = data.id;
	} else if (mflags & MF_COMP_ID) {
		rc = llapi_layout_comp_iterate(layout, find_comp_id, &id);
		mirror_id = mirror_id_of(id);
	} else {
		rc = llapi_layout_comp_iterate(layout, find_mirror_id, &id);
		mirror_id = id;
	}
	if (rc < 0) {
		fprintf(stderr, "error %s: failed to iterate layout of '%s'\n",
			progname, fname);
		goto free_layout;
	} else if (rc == LLAPI_LAYOUT_ITER_CONT) {
		if (mflags & MF_COMP_POOL) {
			fprintf(stderr,
				"error %s: file '%s' does not contain mirror with pool '%s'\n",
				progname, fname, pool);
			goto free_layout;
		} else if (mflags & MF_COMP_ID) {
			fprintf(stderr,
				"error %s: file '%s' does not contain mirror with comp-id %u\n",
				progname, fname, id);
			goto free_layout;
		} else {
			fprintf(stderr,
				"error %s: file '%s' does not contain mirror with id %u\n",
				progname, fname, id);
			goto free_layout;
		}
	}

	if (!victim_file && mflags & MF_DESTROY)
		/* Allow mirror split even without the key on encrypted files,
		 * and in this case of a 'split -d', open file with O_DIRECT
		 * (no IOs will be done).
		 */
		fd = open(fname, O_RDWR | O_DIRECT | O_FILE_ENC);
	else
		fd = open(fname, O_RDWR);

	if (fd < 0) {
		fprintf(stderr,
			"error %s: open file '%s' failed: %s\n",
			progname, fname, strerror(errno));
		goto free_layout;
	}

	/* get victim file directory pathname */
	if (strlen(fname) > sizeof(parent) - 1) {
		fprintf(stderr, "error %s: file name of '%s' too long\n",
			progname, fname);
		rc = -ERANGE;
		goto close_fd;
	}
	strncpy(parent, fname, sizeof(parent));
	ptr = strrchr(parent, '/');
	if (!ptr) {
		if (!getcwd(parent, sizeof(parent))) {
			fprintf(stderr, "error %s: getcwd failed: %s\n",
				progname, strerror(errno));
			rc = -errno;
			goto close_fd;
		}
	} else {
		if (ptr == parent)
			ptr = parent + 1;
		*ptr = '\0';
	}

	rc = llapi_file_fget_mdtidx(fd, &mdt_index);
	if (rc < 0) {
		fprintf(stderr, "%s: cannot get MDT index of '%s'\n",
			progname, fname);
		goto close_fd;
	}

	rc = llapi_file_is_encrypted(fd);
	if (rc < 0) {
		fprintf(stderr, "%s: cannot get flags of '%s': %d\n",
			progname, fname, rc);
		goto close_fd;
	}
	is_encrypted = rc;

again:
	if (!victim_file) {
		/* use a temp file to store the splitted layout */
		if (mflags & MF_DESTROY) {
			char file_path[PATH_MAX];
			unsigned int rnumber;
			int open_flags;

			if (last_non_stale_mirror(mirror_id, layout)) {
				rc = -EUCLEAN;
				fprintf(stderr,
					"%s: cannot destroy the last non-stale mirror of file '%s'\n",
					progname, fname);
				goto close_fd;
			}

			if (purge) {
				/* don't use volatile file for mirror destroy */
				fdv = fd;
			} else {
				/**
				 * try the old way to delete mirror using
				 * volatile file.
				 */
				do {
					rnumber = random();
					rc = snprintf(file_path,
						      sizeof(file_path),
						      "%s/" LUSTRE_VOLATILE_HDR ":%.4X:%.4X:fd=%.2d",
						      parent, mdt_index,
						      rnumber, fd);
					if (rc < 0 ||
					    rc >= sizeof(file_path)) {
						fdv = -ENAMETOOLONG;
						break;
					}

					open_flags = O_RDWR |
					     (O_LOV_DELAY_CREATE & ~O_ACCMODE) |
					     O_CREAT | O_EXCL | O_NOFOLLOW |
					     /* O_DIRECT for mirror split -d */
					     O_DIRECT |
					     /* Allow split without the key */
					     O_FILE_ENC;
					fdv = open(file_path, open_flags,
						   S_IRUSR | S_IWUSR);
					if (fdv < 0)
						rc = -errno;
				} while (fdv < 0 && rc == -EEXIST);
			}
		} else {
			if (is_encrypted) {
				rc = -1;
				fprintf(stderr,
					"error %s: not permitted on encrypted file '%s': %d\n",
					progname, fname, rc);
				goto close_fd;
			}

			snprintf(victim, sizeof(victim), "%s.mirror~%u",
				 fname, mirror_id);
			fdv = open(victim, flags, S_IRUSR | S_IWUSR);
		}
	} else {
		/* user specified victim file */
		if (is_encrypted) {
			rc = -1;
			fprintf(stderr,
				"error %s: not permitted on encrypted file '%s': %d\n",
				progname, fname, rc);
			goto close_fd;
		}
		fdv = open(victim_file, flags, S_IRUSR | S_IWUSR);
	}

	if (fdv < 0) {
		fprintf(stderr,
			"error %s: create victim file failed: %s\n",
			progname, strerror(errno));
		goto close_fd;
	}

	/* get lease lock of fname */
	rc = llapi_lease_acquire(fd, LL_LEASE_WRLCK);
	if (rc < 0) {
		fprintf(stderr,
			"error %s: cannot get lease of file '%s': %d\n",
			progname, fname, rc);
		goto close_victim;
	}

	/* Atomatically put lease, split layouts and close. */
	data = malloc(offsetof(typeof(*data), lil_ids[2]));
	if (!data) {
		rc = -ENOMEM;
		goto close_victim;
	}

	data->lil_mode = LL_LEASE_UNLCK;
	data->lil_flags = LL_LEASE_LAYOUT_SPLIT;
	data->lil_count = 2;
	data->lil_ids[0] = fdv;
	data->lil_ids[1] = mirror_id;
	rc = llapi_lease_set(fd, data);
	if (rc <= 0) {
		if ((rc == -EINVAL || rc == -EBUSY) && purge) {
			/* could be old MDS which prohibit fd==fdv */
			purge = false;
			goto again;

		}
		if (rc == 0) /* lost lease lock */
			rc = -EBUSY;
		fprintf(stderr,
			"error %s: cannot split '%s': %s\n",
			progname, fname, strerror(-rc));
	} else {
		rc = 0;
	}
	free(data);

close_victim:
	if (!purge)
		close(fdv);
close_fd:
	close(fd);
free_layout:
	llapi_layout_free(layout);
	return rc;
}

static inline
int lfs_mirror_resync_file(const char *fname, struct ll_ioc_lease *ioc,
			   __u16 *mirror_ids, int ids_nr);

static int lfs_migrate_to_dom(int fd, int fdv, char *name,
			      __u64 migration_flags)
{
	struct ll_ioc_lease *data = NULL;
	int rc;

	rc = llapi_lease_acquire(fd, LL_LEASE_RDLCK);
	if (rc < 0) {
		error_loc = "cannot get lease";
		goto out_close;
	}

	rc = migrate_nonblock(fd, fdv);
	if (rc < 0)
		goto out_release;

	/* Atomically put lease, merge layouts, resync and close. */
	data = calloc(1, offsetof(typeof(*data), lil_ids[1]));
	if (!data) {
		error_loc = "memory allocation";
		goto out_release;
	}
	data->lil_mode = LL_LEASE_UNLCK;
	data->lil_flags = LL_LEASE_LAYOUT_MERGE;
	data->lil_count = 1;
	data->lil_ids[0] = fdv;
	rc = llapi_lease_set(fd, data);
	if (rc < 0) {
		error_loc = "cannot merge layout";
		goto out_close;
	} else if (rc == 0) {
		rc = -EBUSY;
		error_loc = "lost lease lock";
		goto out_close;
	}
	close(fd);
	close(fdv);

	rc = lfs_mirror_resync_file(name, data, NULL, 0);
	if (rc) {
		error_loc = "cannot resync file";
		goto out;
	}

	/* delete first mirror now */
	rc = mirror_split(name, 1, NULL, MF_DESTROY, NULL);
	if (rc < 0)
		error_loc = "cannot delete old layout";
	goto out;

out_release:
	llapi_lease_release(fd);
out_close:
	close(fd);
	close(fdv);
out:
	if (rc < 0)
		fprintf(stderr, "error: %s: %s: %s: %s\n",
			progname, name, error_loc, strerror(-rc));
	else if (migration_flags & LLAPI_MIGRATION_VERBOSE)
		printf("%s\n", name);
	if (data)
		free(data);
	return rc;
}

/**
 * Parse a string containing an target index list into an array of integers.
 *
 * The input string contains a comma delimited list of individual
 * indices and ranges, for example "1,2-4,7". Add the indices into the
 * \a tgts array and remove duplicates.
 *
 * \param[out] tgts		array to store indices in
 * \param[in] size		size of \a tgts array
 * \param[in] offset		starting index in \a tgts
 * \param[in] arg		string containing OST index list
 * \param[in/out] overstriping	index list may contain duplicates
 *
 * \retval positive    number of indices in \a tgts
 * \retval -EINVAL     unable to parse \a arg
 */
static int parse_targets(__u32 *tgts, int size, int offset, char *arg,
			 unsigned long long *pattern)
{
	int rc;
	int nr = offset;
	int slots = size - offset;
	char *ptr = NULL;
	bool overstriped = false;
	bool end_of_loop;

	if (!arg)
		return -EINVAL;

	end_of_loop = false;
	while (!end_of_loop) {
		int start_index = 0;
		int end_index = 0;
		int i;
		char *endptr = NULL;

		rc = -EINVAL;

		ptr = strchrnul(arg, ',');

		end_of_loop = *ptr == '\0';
		*ptr = '\0';

		errno = 0;
		start_index = strtol(arg, &endptr, 0);
		if (endptr == arg) /* no data at all */
			break;
		if (errno != 0 || start_index < -1 ||
		    (*endptr != '-' && *endptr != '\0'))
			break;

		end_index = start_index;
		if (*endptr == '-') {
			errno = 0;
			end_index = strtol(endptr + 1, &endptr, 0);
			if (errno != 0 || *endptr != '\0' || end_index < -1)
				break;
			if (end_index < start_index)
				break;
		}

		for (i = start_index; i <= end_index && slots > 0; i++) {
			int j;

			/* remove duplicate */
			for (j = 0; j < offset; j++) {
				if (tgts[j] == i && pattern &&
				    *pattern == LLAPI_LAYOUT_OVERSTRIPING)
					overstriped = true;
				else if (tgts[j] == i)
					return -EINVAL;
			}

			j = offset;

			if (j == offset) { /* check complete */
				tgts[nr++] = i;
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
	if (!end_of_loop && ptr)
		*ptr = ',';

	if (!overstriped && pattern)
		*pattern = LLAPI_LAYOUT_DEFAULT;

	return rc < 0 ? rc : nr;
}

struct lfs_setstripe_args {
	unsigned long long	 lsa_comp_end;
	unsigned long long	 lsa_stripe_size;
	unsigned long long	 lsa_extension_size;
	long long		 lsa_stripe_count;
	long long		 lsa_stripe_off;
	__u32			 lsa_comp_flags;
	__u32			 lsa_comp_neg_flags;
	unsigned long long	 lsa_pattern;
	unsigned int		 lsa_mirror_count;
	int			 lsa_nr_tgts;
	bool			 lsa_first_comp;
	bool			 lsa_extension_comp;
	__u32			*lsa_tgts;
	char			*lsa_pool_name;
};

static inline void setstripe_args_init(struct lfs_setstripe_args *lsa)
{
	unsigned int mirror_count = lsa->lsa_mirror_count;
	bool first_comp = lsa->lsa_first_comp;

	memset(lsa, 0, sizeof(*lsa));

	lsa->lsa_stripe_size = LLAPI_LAYOUT_DEFAULT;
	lsa->lsa_stripe_count = LLAPI_LAYOUT_DEFAULT;
	lsa->lsa_stripe_off = LLAPI_LAYOUT_DEFAULT;
	lsa->lsa_pattern = LLAPI_LAYOUT_RAID0;
	lsa->lsa_pool_name = NULL;

	lsa->lsa_mirror_count = mirror_count;
	lsa->lsa_first_comp = first_comp;
}

/**
 * setstripe_args_init_inherit() - Initialize and inherit stripe options.
 * @lsa: Stripe options to be initialized and inherited.
 *
 * This function initializes stripe options in @lsa and inherit
 * stripe_size, stripe_count and OST pool_name options.
 *
 * Return: void.
 */
static inline void setstripe_args_init_inherit(struct lfs_setstripe_args *lsa)
{
	unsigned long long stripe_size;
	long long stripe_count;
	char *pool_name = NULL;

	stripe_size = lsa->lsa_stripe_size;
	stripe_count = lsa->lsa_stripe_count;
	pool_name = lsa->lsa_pool_name;

	setstripe_args_init(lsa);

	lsa->lsa_stripe_size = stripe_size;
	lsa->lsa_stripe_count = stripe_count;
	lsa->lsa_pool_name = pool_name;
}

static inline bool setstripe_args_specified(struct lfs_setstripe_args *lsa)
{
	return (lsa->lsa_stripe_size != LLAPI_LAYOUT_DEFAULT ||
		lsa->lsa_stripe_count != LLAPI_LAYOUT_DEFAULT ||
		lsa->lsa_stripe_off != LLAPI_LAYOUT_DEFAULT ||
		lsa->lsa_pattern != LLAPI_LAYOUT_RAID0 ||
		lsa->lsa_comp_end != 0);
}

static int lsa_args_stripe_count_check(struct lfs_setstripe_args *lsa)
{
	if (lsa->lsa_nr_tgts) {
		if (lsa->lsa_nr_tgts < 0 ||
		    lsa->lsa_nr_tgts >= LOV_MAX_STRIPE_COUNT) {
			fprintf(stderr, "Invalid nr_tgts(%d)\n",
				lsa->lsa_nr_tgts);
			errno = EINVAL;
			return -1;
		}

		if (lsa->lsa_stripe_count > 0 &&
		    lsa->lsa_stripe_count != LLAPI_LAYOUT_DEFAULT &&
		    lsa->lsa_stripe_count != LLAPI_LAYOUT_WIDE &&
		    lsa->lsa_nr_tgts != lsa->lsa_stripe_count) {
			fprintf(stderr, "stripe_count(%lld) != nr_tgts(%d)\n",
				lsa->lsa_stripe_count,
				lsa->lsa_nr_tgts);
			errno = EINVAL;
			return -1;
		}
	}

	return 0;

}

/**
 * comp_args_to_layout() - Create or extend a composite layout.
 * @composite:       Pointer to the composite layout.
 * @lsa:             Stripe options for the new component.
 *
 * This function creates or extends a composite layout by adding a new
 * component with stripe options from @lsa.
 *
 * When modified, adjust llapi_stripe_param_verify() if needed as well.
 *
 * Return: 0 on success or an error code on failure.
 */
static int comp_args_to_layout(struct llapi_layout **composite,
			       struct lfs_setstripe_args *lsa,
			       bool set_extent)
{
	struct llapi_layout *layout = *composite;
	uint64_t prev_end = 0;
	uint64_t size;
	int i = 0, rc;

new_comp:
	if (!layout) {
		layout = llapi_layout_alloc();
		if (!layout) {
			fprintf(stderr, "Alloc llapi_layout failed. %s\n",
				strerror(errno));
			errno = ENOMEM;
			return -1;
		}
		*composite = layout;
		lsa->lsa_first_comp = true;
	} else {
		uint64_t start;

		/*
		 * Get current component extent, current component
		 * must be the tail component.
		 */
		rc = llapi_layout_comp_extent_get(layout, &start, &prev_end);
		if (rc) {
			fprintf(stderr, "Get comp extent failed. %s\n",
				strerror(errno));
			return rc;
		}

		if (lsa->lsa_first_comp) {
			prev_end = 0;
			rc = llapi_layout_add_first_comp(layout);
		} else {
			rc = llapi_layout_comp_add(layout);
		}
		if (rc) {
			fprintf(stderr, "Add component failed. %s\n",
				strerror(errno));
			return rc;
		}
	}

	rc = llapi_layout_comp_flags_set(layout, lsa->lsa_comp_flags);
	if (rc) {
		fprintf(stderr, "Set flags 0x%x failed: %s\n",
			lsa->lsa_comp_flags, strerror(errno));
		return rc;
	}

	if (set_extent) {
		uint64_t comp_end = lsa->lsa_comp_end;

		/*
		 * The extendable component is 0-length, so it can be removed
		 * if there is insufficient space to extend it.
		 */
		if (lsa->lsa_extension_comp)
			comp_end = prev_end;

		rc = llapi_layout_comp_extent_set(layout, prev_end,
						  comp_end);
		if (rc) {
			fprintf(stderr, "Set extent [%lu, %lu) failed. %s\n",
				prev_end, comp_end, strerror(errno));
			return rc;
		}
	}
	/* reset lsa_first_comp */
	lsa->lsa_first_comp = false;

	/* Data-on-MDT component setting */
	if (lsa->lsa_pattern == LLAPI_LAYOUT_MDT) {
		/* Yaml support */
		if (lsa->lsa_stripe_count == 0)
			lsa->lsa_stripe_count = LLAPI_LAYOUT_DEFAULT;
		if (lsa->lsa_stripe_size == lsa->lsa_comp_end)
			lsa->lsa_stripe_size = LLAPI_LAYOUT_DEFAULT;
		if (lsa->lsa_stripe_off == -1 ||
		    lsa->lsa_stripe_off == 0)
			lsa->lsa_stripe_off = LLAPI_LAYOUT_DEFAULT;
		/*
		 * In case of Data-on-MDT patterns the only extra option
		 * applicable is stripe size option.
		 */
		if (lsa->lsa_stripe_count != LLAPI_LAYOUT_DEFAULT) {
			fprintf(stderr,
				"Option 'stripe-count' can't be specified with Data-on-MDT component: %lld\n",
				lsa->lsa_stripe_count);
			errno = EINVAL;
			return -1;
		}
		if (lsa->lsa_stripe_size != LLAPI_LAYOUT_DEFAULT &&
		    lsa->lsa_stripe_size != lsa->lsa_comp_end - prev_end) {
			fprintf(stderr,
				"Option 'stripe-size' can't be specified with Data-on-MDT component: %llu\n",
				lsa->lsa_stripe_size);
			errno = EINVAL;
			return -1;
		}
		if (lsa->lsa_nr_tgts != 0) {
			fprintf(stderr,
				"Option 'ost-list' can't be specified with Data-on-MDT component: '%i'\n",
				lsa->lsa_nr_tgts);
			errno = EINVAL;
			return -1;
		}
		if (lsa->lsa_stripe_off != LLAPI_LAYOUT_DEFAULT) {
			fprintf(stderr,
				"Option 'stripe-offset' can't be specified with Data-on-MDT component: %lld\n",
				lsa->lsa_stripe_off);
			errno = EINVAL;
			return -1;
		}
		if (lsa->lsa_pool_name != 0) {
			fprintf(stderr,
				"Option 'pool' can't be specified with Data-on-MDT component: '%s'\n",
				lsa->lsa_pool_name);
			errno = EINVAL;
			return -1;
		}

		rc = llapi_layout_pattern_set(layout, lsa->lsa_pattern);
		if (rc) {
			fprintf(stderr, "Set stripe pattern %#llx failed. %s\n",
				lsa->lsa_pattern,
				strerror(errno));
			return rc;
		}
		/* Data-on-MDT component has always single stripe up to end */
		lsa->lsa_stripe_size = lsa->lsa_comp_end;
	} else if (lsa->lsa_pattern == LLAPI_LAYOUT_OVERSTRIPING) {
		rc = llapi_layout_pattern_set(layout, lsa->lsa_pattern);
		if (rc) {
			fprintf(stderr, "Set stripe pattern %#llx failed. %s\n",
				lsa->lsa_pattern,
				strerror(errno));
			return rc;
		}
	}

	size = lsa->lsa_comp_flags & LCME_FL_EXTENSION ?
		lsa->lsa_extension_size : lsa->lsa_stripe_size;

	if (lsa->lsa_comp_flags & LCME_FL_EXTENSION)
		rc = llapi_layout_extension_size_set(layout, size);
	else
		rc = llapi_layout_stripe_size_set(layout, size);

	if (rc) {
		fprintf(stderr, "Set stripe size %lu failed: %s\n",
			size, strerror(errno));
		return rc;
	}

	rc = llapi_layout_stripe_count_set(layout, lsa->lsa_stripe_count);
	if (rc) {
		fprintf(stderr, "Set stripe count %lld failed: %s\n",
			lsa->lsa_stripe_count, strerror(errno));
		return rc;
	}

	if (lsa->lsa_pool_name) {
		rc = llapi_layout_pool_name_set(layout, lsa->lsa_pool_name);
		if (rc) {
			fprintf(stderr, "Set pool name: %s failed. %s\n",
				lsa->lsa_pool_name, strerror(errno));
			return rc;
		}
	} else {
		rc = llapi_layout_pool_name_set(layout, "");
		if (rc) {
			fprintf(stderr, "Clear pool name failed: %s\n",
				strerror(errno));
			return rc;
		}
	}

	rc = lsa_args_stripe_count_check(lsa);
	if (rc)
		return rc;

	if (lsa->lsa_nr_tgts > 0) {
		bool found = false;

		for (i = 0; i < lsa->lsa_nr_tgts; i++) {
			rc = llapi_layout_ost_index_set(layout, i,
							lsa->lsa_tgts[i]);
			if (rc)
				break;

			/* Make sure stripe offset is in OST list. */
			if (lsa->lsa_tgts[i] == lsa->lsa_stripe_off)
				found = true;
		}
		if (!found) {
			fprintf(stderr, "Invalid stripe offset '%lld', not in the target list",
				lsa->lsa_stripe_off);
			errno = EINVAL;
			return -1;
		}
	} else if (lsa->lsa_stripe_off != LLAPI_LAYOUT_DEFAULT &&
		   lsa->lsa_stripe_off != -1) {
		rc = llapi_layout_ost_index_set(layout, 0, lsa->lsa_stripe_off);
	}
	if (rc) {
		fprintf(stderr, "Set ost index %d failed. %s\n",
			i, strerror(errno));
		return rc;
	}

	/* Create the second, virtual component of extension space */
	if (lsa->lsa_extension_comp) {
		lsa->lsa_comp_flags |= LCME_FL_EXTENSION;
		lsa->lsa_extension_comp = false;
		goto new_comp;
	}

	return rc;
}

static int build_component(struct llapi_layout **layout,
			   struct lfs_setstripe_args *lsa, bool set_extent)
{
	int rc;

	rc = comp_args_to_layout(layout, lsa, set_extent);
	if (rc)
		return rc;

	if (lsa->lsa_mirror_count > 0) {
		rc = llapi_layout_mirror_count_set(*layout,
						   lsa->lsa_mirror_count);
		if (rc)
			return rc;

		rc = llapi_layout_flags_set(*layout, LCM_FL_RDONLY);
		if (rc)
			return rc;
		lsa->lsa_mirror_count = 0;
	}

	return rc;
}

static int build_prev_component(struct llapi_layout **layout,
				struct lfs_setstripe_args *prev,
				struct lfs_setstripe_args *lsa,
				bool set_extent)
{
	int extension = lsa->lsa_comp_flags & LCME_FL_EXTENSION;
	int rc;

	if (prev->lsa_stripe_size) {
		if (extension) {
			prev->lsa_comp_end = lsa->lsa_comp_end;
			prev->lsa_extension_size = lsa->lsa_extension_size;
			prev->lsa_extension_comp = true;
		}

		rc = build_component(layout, prev, true);
		if (rc)
			return rc;
	}

	/*
	 * Copy lsa to previous lsa;
	 * if this is an extension component, make the previous invalid;
	 */
	if (extension)
		prev->lsa_stripe_size = 0;
	else
		*prev = *lsa;

	return 0;
}

#ifndef LCME_TEMPLATE_FLAGS
#define LCME_TEMPLATE_FLAGS	(LCME_FL_PREF_RW | LCME_FL_NOSYNC | \
				 LCME_FL_EXTENSION)
#endif

static int build_layout_from_yaml_node(struct cYAML *node,
				       struct llapi_layout **layout,
				       struct lfs_setstripe_args *lsa,
				       struct lfs_setstripe_args *prevp)
{
	struct lfs_setstripe_args prev = { 0 };
	__u32 *osts = lsa->lsa_tgts;
	char *string;
	int rc = 0;

	if (!prevp)
		prevp = &prev;

	while (node) {
		string = node->cy_string;

		if (node->cy_type == CYAML_TYPE_OBJECT) {
			/* go deep to sub blocks */
			if (string && !strncmp(string, "component", 9) &&
			    strncmp(string, "component0", 10) &&
			    strncmp(string, "components", 10)) {
				rc = build_prev_component(layout, prevp, lsa,
							  true);
				if (rc)
					return rc;

				/* initialize lsa. */
				setstripe_args_init(lsa);
				lsa->lsa_first_comp = false;
				lsa->lsa_tgts = osts;
			}

			rc = build_layout_from_yaml_node(node->cy_child, layout,
							 lsa, prevp);
			if (rc)
				return rc;
		} else {
			if (!node->cy_string)
				return -EINVAL;

			/* skip leading lmm_ if present, to simplify parsing */
			if (strncmp(string, "lmm_", 4) == 0)
				string += 4;

			if (node->cy_type == CYAML_TYPE_STRING) {
				if (!strcmp(string, "lcme_extent.e_end")) {
					if (!strcmp(node->cy_valuestring, "EOF") ||
					    !strcmp(node->cy_valuestring, "eof"))
						lsa->lsa_comp_end = LUSTRE_EOF;
				} else if (!strcmp(string, "pool")) {
					lsa->lsa_pool_name = node->cy_valuestring;
				} else if (!strcmp(string, "pattern")) {
					if (!strcmp(node->cy_valuestring, "mdt"))
						lsa->lsa_pattern = LLAPI_LAYOUT_MDT;
					if (!strcmp(node->cy_valuestring,
						    "raid0,overstriped"))
						lsa->lsa_pattern =
							LLAPI_LAYOUT_OVERSTRIPING;
				} else if (!strcmp(string, "lcme_flags")) {
					rc = comp_str2flags(node->cy_valuestring,
							    &lsa->lsa_comp_flags,
							    &lsa->lsa_comp_neg_flags);
					if (rc)
						return rc;
					/*
					 * Only template flags have meaning in
					 * the layout for a new file
					 */
					lsa->lsa_comp_flags &= LCME_TEMPLATE_FLAGS;
				}
			} else if (node->cy_type == CYAML_TYPE_NUMBER) {
				if (!strcmp(string, "lcm_mirror_count")) {
					lsa->lsa_mirror_count = node->cy_valueint;
				} else if (!strcmp(string, "lcme_extent.e_start")) {
					if (node->cy_valueint == 0)
						lsa->lsa_first_comp = true;
				} else if (!strcmp(string, "lcme_extent.e_end")) {
					if (node->cy_valueint == -1)
						lsa->lsa_comp_end = LUSTRE_EOF;
					else
						lsa->lsa_comp_end = node->cy_valueint;
				} else if (!strcmp(string, "stripe_count")) {
					lsa->lsa_stripe_count = node->cy_valueint;
				} else if (!strcmp(string, "stripe_size")) {
					lsa->lsa_stripe_size = node->cy_valueint;
				} else if (!strcmp(string, "extension_size")) {
					lsa->lsa_extension_size = node->cy_valueint;
					lsa->lsa_extension_comp = true;
				} else if (!strcmp(string, "stripe_offset")) {
					lsa->lsa_stripe_off = node->cy_valueint;
				} else if (!strcmp(string, "l_ost_idx")) {
					osts[lsa->lsa_nr_tgts] = node->cy_valueint;
					lsa->lsa_nr_tgts++;
				}
			}
		}
		node = node->cy_next;
	}

	if (prevp == &prev) {
		rc = build_prev_component(layout, prevp, lsa, true);
		if (rc)
			return rc;

		if (!(lsa->lsa_comp_flags & LCME_FL_EXTENSION))
			rc = build_component(layout, lsa, *layout != NULL);
	}

	return rc;
}

static int lfs_comp_create_from_yaml(char *template,
				     struct llapi_layout **layout,
				     struct lfs_setstripe_args *lsa,
				     __u32 *osts)
{
	struct cYAML *tree = NULL, *err_rc = NULL;
	int rc = 0;

	tree = cYAML_build_tree(template, NULL, 0, &err_rc, false);
	if (!tree) {
		fprintf(stderr, "%s: cannot parse YAML file %s\n",
			progname, template);
		cYAML_build_error(-EINVAL, -1, "yaml", "from comp yaml",
				  "can't parse", &err_rc);
		cYAML_print_tree2file(stderr, err_rc);
		cYAML_free_tree(err_rc);
		rc = -EINVAL;
		goto err;
	}

	/* initialize lsa for plain file */
	setstripe_args_init(lsa);
	lsa->lsa_tgts = osts;

	rc = build_layout_from_yaml_node(tree, layout, lsa, NULL);
	if (rc) {
		fprintf(stderr, "%s: cannot build layout from YAML file %s.\n",
			progname, template);
		goto err;
	}
	/* clean clean lsa */
	setstripe_args_init(lsa);

err:
	if (tree)
		cYAML_free_tree(tree);
	return rc;
}

/**
 * Get the extension size from the next (SEL) component and extend the
 * current component on it. The start of the next component is to be
 * adjusted as well.
 *
 * \param[in] layout	the current layout
 * \param[in] start	the start of the current component
 * \param[in,out] end	the end of the current component
 * \param[in] offset	the offset to adjust the end position to instead of
 *			extension size
 *
 * \retval 0		- extended successfully
 * \retval < 0		- error
 */
static int layout_extend_comp(struct llapi_layout *layout,
			      uint64_t start, uint64_t *end,
			      uint64_t offset)
{
	uint64_t size, next_start, next_end;
	int rc;

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_NEXT);
	if (rc < 0) {
		fprintf(stderr,
			"%s setstripe: cannot move component cursor: %s\n",
			progname, strerror(errno));
		return rc;
	}

	/*
	 * Even if the @size will not be used below, this will fail if
	 * this is not a SEL component - a good confirmation we are
	 * working on right components.
	 */
	rc = llapi_layout_extension_size_get(layout, &size);
	if (rc < 0) {
		fprintf(stderr,
			"%s setstripe: cannot get component ext size: %s\n",
			progname, strerror(errno));
		return rc;
	}

	rc = llapi_layout_comp_extent_get(layout, &next_start, &next_end);
	if (rc) {
		fprintf(stderr, "%s setstripe: cannot get extent: %s\n",
			progname, strerror(errno));
		return rc;
	}

	next_start += offset ?: size;
	rc = llapi_layout_comp_extent_set(layout, next_start, next_end);
	if (rc) {
		fprintf(stderr, "%s setstripe: cannot set extent: %s\n",
			progname, strerror(errno));
		return rc;
	}

	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_PREV);
	if (rc < 0) {
		fprintf(stderr,
			"%s setstripe: cannot move component cursor: %s\n",
			progname, strerror(errno));
		return rc;
	}

	*end += offset ?: size;
	rc = llapi_layout_comp_extent_set(layout, start, *end);
	if (rc) {
		fprintf(stderr, "%s setstripe: cannot set extent: %s\n",
			progname, strerror(errno));
		return rc;
	}

	return 0;
}

/**
 * In 'lfs setstripe --component-add' mode, we need to fetch the extent
 * end of the last component in the existing file, and adjust the
 * first extent start of the components to be added accordingly.
 *
 * In the create mode, we need to check if the first component is an extendable
 * SEL component and extend its length to the extension size (first component
 * of the PFL file is initialised at the create time, cannot be 0-lenght.
 */
static int layout_adjust_first_extent(char *fname, struct llapi_layout *layout,
				      bool comp_add)
{
	struct llapi_layout *head;
	uint64_t start = 0, prev_end = 0;
	uint64_t end;
	int rc, ret = 0;

	if (!layout || !(comp_add || llapi_layout_is_composite(layout)))
		return 0;

	errno = 0;
	while (comp_add) {
		head = llapi_layout_get_by_path(fname, 0);
		if (!head) {
			fprintf(stderr,
				"%s setstripe: cannot read layout from '%s': %s\n",
				progname, fname, strerror(errno));
			return -EINVAL;
		} else if (errno == ENODATA) {
			/*
			 * file without LOVEA, this component-add will be turned
			 * into a component-create.
			 */
			llapi_layout_free(head);
			ret = -ENODATA;

			/*
			 * the new layout will be added to an empty one, it
			 * still needs to be adjusted below
			 */
			comp_add = 0;
			break;
		} else if (!llapi_layout_is_composite(head)) {
			fprintf(stderr,
				"%s setstripe: '%s' not a composite file\n",
				progname, fname);
			llapi_layout_free(head);
			return -EINVAL;
		}

		rc = llapi_layout_comp_extent_get(head, &start, &prev_end);
		if (rc) {
			fprintf(stderr,
				"%s setstripe: cannot get prev extent: %s\n",
				progname, strerror(errno));
			llapi_layout_free(head);
			return rc;
		}

		llapi_layout_free(head);
		break;
	}

	/* Make sure we use the first component of the layout to be added. */
	rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
	if (rc < 0) {
		fprintf(stderr,
			"%s setstripe: cannot move component cursor: %s\n",
			progname, strerror(errno));
		return rc;
	}

	rc = llapi_layout_comp_extent_get(layout, &start, &end);
	if (rc) {
		fprintf(stderr, "%s setstripe: cannot get extent: %s\n",
			progname, strerror(errno));
		return rc;
	}

	if (start == 0 && end == 0) {
		rc = layout_extend_comp(layout, start, &end,
					comp_add ? prev_end : 0);
		if (rc)
			return rc;
	}

	if (start > prev_end || end < prev_end) {
		fprintf(stderr,
			"%s setstripe: first extent [%lu, %lu) not adjacent with extent end %lu\n",
			progname, start, end, prev_end);
		return -EINVAL;
	}

	rc = llapi_layout_comp_extent_set(layout, prev_end, end);
	if (rc) {
		fprintf(stderr,
			"%s setstripe: cannot set component extent [%lu, %lu): %s\n",
			progname, prev_end, end, strerror(errno));
		return rc;
	}

	return ret;
}

static int mirror_adjust_first_extents(struct mirror_args *list)
{
	int rc = 0;

	if (!list)
		return 0;

	while (list) {
		rc = layout_adjust_first_extent(NULL, list->m_layout, false);
		if (rc)
			break;
		list = list->m_next;
	}

	return rc;
}

static inline bool arg_is_eof(char *arg)
{
	return !strncmp(arg, "-1", strlen("-1")) ||
	       !strncmp(arg, "EOF", strlen("EOF")) ||
	       !strncmp(arg, "eof", strlen("eof"));
}

/**
 * lfs_mirror_alloc() - Allocate a mirror argument structure.
 *
 * Return: Valid mirror_args pointer on success and
 *         NULL if memory allocation fails.
 */
static struct mirror_args *lfs_mirror_alloc(void)
{
	struct mirror_args *mirror = NULL;

	while (1) {
		mirror = calloc(1, sizeof(*mirror));
		if (mirror) {
			mirror->m_inherit = false;
			break;
		}

		sleep(1);
	}

	return mirror;
}

/**
 * lfs_mirror_free() - Free memory allocated for a mirror argument
 *                     structure.
 * @mirror: Previously allocated mirror argument structure by
 *	    lfs_mirror_alloc().
 *
 * Free memory allocated for @mirror.
 *
 * Return: void.
 */
static void lfs_mirror_free(struct mirror_args *mirror)
{
	if (mirror->m_layout)
		llapi_layout_free(mirror->m_layout);
	free(mirror);
}

/**
 * lfs_mirror_list_free() - Free memory allocated for a mirror list.
 * @mirror_list: Previously allocated mirror list.
 *
 * Free memory allocated for @mirror_list.
 *
 * Return: void.
 */
static void lfs_mirror_list_free(struct mirror_args *mirror_list)
{
	struct mirror_args *next_mirror = NULL;

	while (mirror_list) {
		next_mirror = mirror_list->m_next;
		lfs_mirror_free(mirror_list);
		mirror_list = next_mirror;
	}
}

enum {
	LFS_SETQUOTA_DELETE = 1,
	LFS_POOL_OPT = 3,
	LFS_COMP_COUNT_OPT,
	LFS_COMP_START_OPT,
	LFS_COMP_FLAGS_OPT,
	LFS_COMP_DEL_OPT,
	LFS_COMP_SET_OPT,
	LFS_COMP_ADD_OPT,
	LFS_COMP_NO_VERIFY_OPT,
	LFS_PROJID_OPT,
	LFS_LAYOUT_FLAGS_OPT, /* used for mirror and foreign flags */
	LFS_MIRROR_ID_OPT,
	LFS_MIRROR_STATE_OPT,
	LFS_LAYOUT_COPY,
	LFS_MIRROR_INDEX_OPT,
	LFS_LAYOUT_FOREIGN_OPT,
	LFS_MODE_OPT,
	LFS_NEWERXY_OPT,
	LFS_INHERIT_RR_OPT,
	LFS_FIND_PERM,
	LFS_PRINTF_OPT,
	LFS_NO_FOLLOW_OPT,
};

#ifndef LCME_USER_MIRROR_FLAGS
/* The mirror flags can be set by users at creation time. */
#define LCME_USER_MIRROR_FLAGS  (LCME_FL_PREF_RW)
#endif

/* functions */
static int lfs_setstripe_internal(int argc, char **argv,
				  enum setstripe_origin opc)
{
	struct lfs_setstripe_args	 lsa = { 0 };
	struct llapi_stripe_param	*param = NULL;
	struct find_param		 migrate_mdt_param = {
		.fp_max_depth = -1,
		.fp_mdt_index = -1,
	};
	char				*fname;
	int				 result = 0;
	int				 result2 = 0;
	char				*end;
	int				 c;
	int				 delete = 0;
	unsigned long long		 size_units = 1;
	bool				 migrate_mode = false;
	bool				 migrate_mdt_mode = false;
	bool				 setstripe_mode = false;
	bool				 migration_block = false;
	__u64				 migration_flags = 0;
	__u32				 tgts[LOV_MAX_STRIPE_COUNT] = { 0 };
	int				 comp_del = 0, comp_set = 0;
	int				 comp_add = 0;
	__u32				 comp_id = 0;
	struct llapi_layout		*layout = NULL;
	struct llapi_layout		**lpp = &layout;
	bool				 mirror_mode = false;
	bool				 has_m_file = false;
	__u32				 mirror_count = 0;
	enum mirror_flags		 mirror_flags = 0;
	struct mirror_args		*mirror_list = NULL;
	struct mirror_args		*new_mirror = NULL;
	struct mirror_args		*last_mirror = NULL;
	__u16				 mirror_id = 0;
	char				 cmd[PATH_MAX];
	bool from_yaml = false;
	bool from_copy = false;
	char *template = NULL;
	bool foreign_mode = false;
	char *xattr = NULL;
	uint32_t type = LU_FOREIGN_TYPE_NONE, flags = 0;
	char *mode_opt = NULL;
	mode_t previous_umask = 0;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

	struct option long_opts[] = {
/* find { .val = '0',	.name = "null",		.has_arg = no_argument }, */
/* find	{ .val = 'A',	.name = "atime",	.has_arg = required_argument }*/
	/* --block is only valid in migrate mode */
	{ .val = 'b',	.name = "block",	.has_arg = no_argument },
/* find	{ .val = 'B',	.name = "btime",	.has_arg = required_argument }*/
	{ .val = LFS_COMP_ADD_OPT,
			.name = "comp-add",	.has_arg = no_argument },
	{ .val = LFS_COMP_ADD_OPT,
			.name = "component-add", .has_arg = no_argument },
	{ .val = LFS_COMP_DEL_OPT,
			.name = "comp-del",	.has_arg = no_argument },
	{ .val = LFS_COMP_DEL_OPT,
			.name = "component-del", .has_arg = no_argument },
	{ .val = LFS_COMP_FLAGS_OPT,
			.name = "comp-flags",	.has_arg = required_argument },
	{ .val = LFS_COMP_FLAGS_OPT,
			.name = "component-flags",
						.has_arg = required_argument },
	{ .val = LFS_COMP_SET_OPT,
			.name = "comp-set",	.has_arg = no_argument },
	{ .val = LFS_COMP_SET_OPT,
			.name = "component-set",
						.has_arg = no_argument},
	{ .val = LFS_COMP_NO_VERIFY_OPT,
			.name = "no-verify",	.has_arg = no_argument},
	{ .val = LFS_LAYOUT_FLAGS_OPT,
			.name = "flags",	.has_arg = required_argument},
	{ .val = LFS_LAYOUT_FOREIGN_OPT,
			.name = "foreign",	.has_arg = optional_argument},
	{ .val = LFS_MIRROR_ID_OPT,
			.name = "mirror-id",	.has_arg = required_argument},
	{ .val = LFS_MODE_OPT,
			.name = "mode",		.has_arg = required_argument},
	{ .val = LFS_LAYOUT_COPY,
			.name = "copy",		.has_arg = required_argument},
	{ .val = 'c',	.name = "stripe-count",	.has_arg = required_argument},
	{ .val = 'c',	.name = "stripe_count",	.has_arg = required_argument},
	{ .val = 'c',	.name = "mdt-count",	.has_arg = required_argument},
	{ .val = 'C',	.name = "overstripe-count",
						.has_arg = required_argument},
	{ .val = 'd',	.name = "delete",	.has_arg = no_argument},
	{ .val = 'd',	.name = "destroy",	.has_arg = no_argument},
	/* used with "lfs migrate -m" */
	{ .val = 'd',	.name = "directory",	.has_arg = no_argument},
	/* --non-direct is only valid in migrate mode */
	{ .val = 'D',	.name = "non-direct",	.has_arg = no_argument },
	{ .val = 'E',	.name = "comp-end",	.has_arg = required_argument},
	{ .val = 'E',	.name = "component-end",
						.has_arg = required_argument},
	{ .val = 'f',	.name = "file",		.has_arg = required_argument },
/* find	{ .val = 'F',	.name = "fid",		.has_arg = no_argument }, */
/* find	{ .val = 'g',	.name = "gid",		.has_arg = no_argument }, */
/* find	{ .val = 'G',	.name = "group",	.has_arg = required_argument }*/
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'H',	.name = "mdt-hash",	.has_arg = required_argument},
	{ .val = 'i',	.name = "stripe-index",	.has_arg = required_argument},
	{ .val = 'i',	.name = "stripe_index",	.has_arg = required_argument},
	{ .val = 'I',	.name = "comp-id",	.has_arg = required_argument},
	{ .val = 'I',	.name = "component-id",	.has_arg = required_argument},
/* find { .val = 'l',	.name = "lazy",		.has_arg = no_argument }, */
	{ .val = 'L',	.name = "layout",	.has_arg = required_argument },
	{ .val = 'm',	.name = "mdt",		.has_arg = required_argument},
	{ .val = 'm',	.name = "mdt-index",	.has_arg = required_argument},
	{ .val = 'm',	.name = "mdt_index",	.has_arg = required_argument},
	/* --non-block is only valid in migrate mode */
	{ .val = 'n',	.name = "non-block",	.has_arg = no_argument },
	{ .val = 'N',	.name = "mirror-count",	.has_arg = optional_argument},
	{ .val = 'o',	.name = "ost",		.has_arg = required_argument },
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
	{ .val = 'o',	.name = "ost-list",	.has_arg = required_argument },
	{ .val = 'o',	.name = "ost_list",	.has_arg = required_argument },
#endif
	{ .val = 'p',	.name = "pool",		.has_arg = required_argument },
/* find	{ .val = 'P',	.name = "print",	.has_arg = no_argument }, */
/* getstripe { .val = 'q', .name = "quiet",	.has_arg = no_argument }, */
/* getstripe { .val = 'R', .name = "raw",	.has_arg = no_argument }, */
	{ .val = 'S',	.name = "stripe-size",	.has_arg = required_argument },
	{ .val = 'S',	.name = "stripe_size",	.has_arg = required_argument },
/* find	{ .val = 't',	.name = "type",		.has_arg = required_argument }*/
/* dirstripe { .val = 'T', .name = "mdt-count", .has_arg = required_argument }*/
/* find	{ .val = 'u',	.name = "uid",		.has_arg = required_argument }*/
/* find	{ .val = 'U',	.name = "user",		.has_arg = required_argument }*/
	/* --verbose is only valid in migrate mode */
	{ .val = 'v',	.name = "verbose",	.has_arg = no_argument},
	{ .val = 'x',	.name = "xattr",	.has_arg = required_argument },
/* dirstripe { .val = 'X',.name = "max-inherit",.has_arg = required_argument }*/
	{ .val = 'y',	.name = "yaml",		.has_arg = required_argument },
	{ .val = 'z',   .name = "ext-size",	.has_arg = required_argument},
	{ .val = 'z',   .name = "extension-size", .has_arg = required_argument},
	{ .name = NULL } };

	setstripe_args_init(&lsa);

	migrate_mode = (opc == SO_MIGRATE);
	mirror_mode = (opc == SO_MIRROR_CREATE || opc == SO_MIRROR_EXTEND);
	setstripe_mode = (opc == SO_SETSTRIPE);
	if (opc == SO_MIRROR_DELETE) {
		delete = 1;
		mirror_flags = MF_DESTROY;
	}

	snprintf(cmd, sizeof(cmd), "%s %s", progname, argv[0]);
	progname = cmd;
	while ((c = getopt_long(argc, argv,
				"bc:C:dDE:f:hH:i:I:m:N::no:p:L:s:S:vx:y:z:",
				long_opts, NULL)) >= 0) {
		size_units = 1;
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
			result = comp_str2flags(optarg, &lsa.lsa_comp_flags,
						&lsa.lsa_comp_neg_flags);
			if (result != 0)
				goto usage_error;
			if (mirror_mode && lsa.lsa_comp_neg_flags) {
				fprintf(stderr,
					"%s: inverted flags are not supported\n",
					progname);
				goto usage_error;
			}
			break;
		case LFS_COMP_SET_OPT:
			comp_set = 1;
			break;
		case LFS_COMP_NO_VERIFY_OPT:
			mirror_flags |= MF_NO_VERIFY;
			break;
		case LFS_MIRROR_ID_OPT: {
			unsigned long int id;

			errno = 0;
			id = strtoul(optarg, &end, 0);
			if (errno != 0 || *end != '\0' || id == 0 ||
			    id > UINT16_MAX) {
				fprintf(stderr,
					"%s %s: invalid mirror ID '%s'\n",
					progname, argv[0], optarg);
				goto usage_error;
			}

			mirror_id = (__u16)id;
			break;
		}
		case LFS_LAYOUT_FLAGS_OPT: {
			uint32_t neg_flags;

			/* check for numeric flags (foreign and mirror cases) */
			if (setstripe_mode && !mirror_mode && !last_mirror) {
				errno = 0;
				flags = strtoul(optarg, &end, 16);
				if (errno != 0 || *end != '\0' ||
				    flags >= UINT32_MAX) {
					fprintf(stderr,
						"%s %s: invalid hex flags '%s'\n",
						progname, argv[0], optarg);
					return CMD_HELP;
				}
				if (!foreign_mode) {
					fprintf(stderr,
						"%s %s: hex flags must be specified with --foreign option\n",
						progname, argv[0]);
					return CMD_HELP;
				}
				break;
			}

			if (!mirror_mode || !last_mirror) {
				fprintf(stderr,
					"error: %s: --flags must be specified with --mirror-count|-N option\n",
					progname);
				goto usage_error;
			}

			result = comp_str2flags(optarg, &last_mirror->m_flags,
						&neg_flags);
			if (result != 0)
				goto usage_error;

			if (neg_flags) {
				fprintf(stderr,
					"%s: inverted flags are not supported\n",
					progname);
				result = -EINVAL;
				goto usage_error;
			}
			if (last_mirror->m_flags & ~LCME_USER_MIRROR_FLAGS) {
				fprintf(stderr,
					"%s: unsupported mirror flags: %s\n",
					progname, optarg);
				result = -EINVAL;
				goto error;
			}
			break;
		}
		case LFS_LAYOUT_FOREIGN_OPT:
			if (optarg) {
				/* check pure numeric */
				type = strtoul(optarg, &end, 0);
				if (*end) {
					/* check name */
					type = check_foreign_type_name(optarg);
					if (type == LU_FOREIGN_TYPE_UNKNOWN) {
						fprintf(stderr,
							"%s %s: unrecognized foreign type '%s'\n",
							progname, argv[0],
							optarg);
						return CMD_HELP;
					}
				} else if (type >= UINT32_MAX) {
					fprintf(stderr,
						"%s %s: invalid foreign type '%s'\n",
						progname, argv[0], optarg);
					return CMD_HELP;
				}
			}
			foreign_mode = true;
			break;
		case LFS_MODE_OPT:
			mode_opt = optarg;
			if (mode_opt) {
				mode = strtoul(mode_opt, &end, 8);
				if (*end != '\0') {
					fprintf(stderr,
						"%s %s: bad mode '%s'\n",
						progname, argv[0], mode_opt);
					return CMD_HELP;
				}
				previous_umask = umask(0);
			}
			break;
		case LFS_LAYOUT_COPY:
			from_copy = true;
			template = optarg;
			break;
		case 'b':
			if (!migrate_mode) {
				fprintf(stderr,
					"%s %s: -b|--block valid only for migrate command\n",
					progname, argv[0]);
				goto usage_error;
			}
			migration_block = true;
			break;
		case 'C':
			if (lsa.lsa_pattern == LLAPI_LAYOUT_MDT) {
				fprintf(stderr,
					"%s %s: -C|--overstripe-count incompatible with DoM layout\n",
					progname, argv[0]);
				goto usage_error;
			}
			lsa.lsa_pattern = LLAPI_LAYOUT_OVERSTRIPING;
			fallthrough;
		case 'c':
			errno = 0;
			lsa.lsa_stripe_count = strtoul(optarg, &end, 0);
			if (errno != 0 || *end != '\0'||
			    lsa.lsa_stripe_count < -1 ||
			    lsa.lsa_stripe_count > LOV_MAX_STRIPE_COUNT) {
				fprintf(stderr,
					"%s %s: invalid stripe count '%s'\n",
					progname, argv[0], optarg);
				goto usage_error;
			}

			if (lsa.lsa_stripe_count == -1)
				lsa.lsa_stripe_count = LLAPI_LAYOUT_WIDE;
			break;
		case 'd':
			if (migrate_mode) {
				migrate_mdt_param.fp_max_depth = 1;
			} else {
				/* delete the default striping pattern */
				delete = 1;
				if (opc == SO_MIRROR_SPLIT) {
					if (has_m_file) {
						fprintf(stderr,
						      "%s %s: -d cannot used with -f\n",
							progname, argv[0]);
						goto usage_error;
					}
					mirror_flags |= MF_DESTROY;
				}
			}
			break;
		case 'D':
			if (!migrate_mode) {
				fprintf(stderr,
					"%s %s: -D|--non-direct is valid only for migrate command\n",
					progname, argv[0]);
				goto usage_error;
			}
			migration_flags |= LLAPI_MIGRATION_NONDIRECT;
			break;
		case 'E':
			if (lsa.lsa_comp_end != 0) {
				result = comp_args_to_layout(lpp, &lsa, true);
				if (result) {
					fprintf(stderr, "%s: invalid layout\n",
						progname);
					goto usage_error;
				}

				setstripe_args_init_inherit(&lsa);
			}

			if (arg_is_eof(optarg)) {
				lsa.lsa_comp_end = LUSTRE_EOF;
			} else {
				result = llapi_parse_size(optarg,
							  &lsa.lsa_comp_end,
							  &size_units, 0);
				/* assume units of KB if too small */
				if (lsa.lsa_comp_end < 4096)
					lsa.lsa_comp_end *= 1024;
				if (result ||
				    lsa.lsa_comp_end & (LOV_MIN_STRIPE_SIZE - 1)) {
					fprintf(stderr,
						"%s %s: invalid component end '%s'\n",
						progname, argv[0], optarg);
					goto usage_error;
				}
			}
			break;
		case 'H':
			if (!migrate_mode) {
				fprintf(stderr,
					"--mdt-hash is valid only for migrate command\n");
				return CMD_HELP;
			}

			lsa.lsa_pattern = check_hashtype(optarg);
			if (lsa.lsa_pattern == 0) {
				fprintf(stderr,
					"%s %s: bad stripe hash type '%s'\n",
					progname, argv[0], optarg);
				return CMD_HELP;
			}
			break;
		case 'i':
			errno = 0;
			lsa.lsa_stripe_off = strtol(optarg, &end, 0);
			if (errno != 0 || *end != '\0' ||
			    lsa.lsa_stripe_off < -1 ||
			    lsa.lsa_stripe_off > LOV_V1_INSANE_STRIPE_COUNT) {
				fprintf(stderr,
					"%s %s: invalid stripe offset '%s'\n",
					progname, argv[0], optarg);
				goto usage_error;
			}
			if (lsa.lsa_stripe_off == -1)
				lsa.lsa_stripe_off = LLAPI_LAYOUT_DEFAULT;
			break;
		case 'I':
			comp_id = strtoul(optarg, &end, 0);
			if (*end != '\0' || comp_id == 0 ||
			    comp_id > LCME_ID_MAX) {
				fprintf(stderr,
					"%s %s: invalid component ID '%s'\n",
					progname, argv[0], optarg);
				goto usage_error;
			}
			break;
		case 'f':
			if (opc != SO_MIRROR_EXTEND && opc != SO_MIRROR_SPLIT) {
				fprintf(stderr,
					"error: %s: invalid option: %s\n",
					progname, argv[optopt + 1]);
				goto usage_error;
			}
			if (opc == SO_MIRROR_EXTEND) {
				if (!last_mirror) {
					fprintf(stderr,
				"error: %s: '-N' must exist in front of '%s'\n",
						progname, argv[optopt + 1]);
					goto usage_error;
				}
				last_mirror->m_file = optarg;
				last_mirror->m_count = 1;
			} else {
				/* mirror split */
				if (!mirror_list)
					mirror_list = lfs_mirror_alloc();
				mirror_list->m_file = optarg;
			}
			has_m_file = true;
			break;
		case 'L':
			if (strcmp(argv[optind - 1], "mdt") == 0) {
				/* Can be only the first component */
				if (layout) {
					result = -EINVAL;
					fprintf(stderr,
						"error: 'mdt' layout can be only the first one\n");
					goto error;
				}
				if (lsa.lsa_comp_end > (1ULL << 30)) { /* 1Gb */
					result = -EFBIG;
					fprintf(stderr,
						"error: 'mdt' layout size is too big\n");
					goto error;
				}
				lsa.lsa_pattern = LLAPI_LAYOUT_MDT;
				lsa.lsa_stripe_size = LLAPI_LAYOUT_DEFAULT;
			} else if (strcmp(argv[optind - 1], "raid0") != 0) {
				result = -EINVAL;
				fprintf(stderr,
					"error: layout '%s' is unknown, supported layouts are: 'mdt', 'raid0'\n",
					argv[optind]);
				goto error;
			}
			break;
		case 'm':
			if (!migrate_mode) {
				fprintf(stderr,
					"%s %s: -m|--mdt-index is valid only for migrate command\n",
					progname, argv[0]);
				goto usage_error;
			}
			migrate_mdt_mode = true;
			lsa.lsa_nr_tgts = parse_targets(tgts,
						sizeof(tgts) / sizeof(__u32),
						lsa.lsa_nr_tgts, optarg, NULL);
			if (lsa.lsa_nr_tgts < 0) {
				fprintf(stderr,
					"%s: invalid MDT target(s) '%s'\n",
					progname, optarg);
				goto usage_error;
			}

			lsa.lsa_tgts = tgts;
			if (lsa.lsa_stripe_off == LLAPI_LAYOUT_DEFAULT)
				lsa.lsa_stripe_off = tgts[0];
			break;
		case 'n':
			if (!migrate_mode) {
				fprintf(stderr,
					"%s %s: -n|--non-block valid only for migrate command\n",
					progname, argv[0]);
				goto usage_error;
			}
			migration_flags |= LLAPI_MIGRATION_NONBLOCK;
			break;
		case 'N':
			if (opc == SO_SETSTRIPE) {
				opc = SO_MIRROR_CREATE;
				mirror_mode = true;
			}
			mirror_count = 1;
			if (optarg) {
				errno = 0;
				mirror_count = strtoul(optarg, &end, 0);
				if (errno != 0 || *end != '\0' ||
				    mirror_count == 0 ||
				    mirror_count > LUSTRE_MIRROR_COUNT_MAX) {
					fprintf(stderr,
						"error: %s: bad mirror count: %s\n",
						progname, optarg);
					result = -EINVAL;
					goto error;
				}
			}

			new_mirror = lfs_mirror_alloc();
			new_mirror->m_count = mirror_count;

			if (!mirror_list)
				mirror_list = new_mirror;

			if (last_mirror) {
				/* wrap up last mirror */
				if (!setstripe_args_specified(&lsa))
					last_mirror->m_inherit = true;
				if (lsa.lsa_comp_end == 0)
					lsa.lsa_comp_end = LUSTRE_EOF;

				result = comp_args_to_layout(lpp, &lsa, true);
				if (result) {
					lfs_mirror_free(new_mirror);
					goto error;
				}

				setstripe_args_init_inherit(&lsa);

				last_mirror->m_next = new_mirror;
			}

			last_mirror = new_mirror;
			lpp = &last_mirror->m_layout;
			break;
		case 'o':
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
			if (strcmp(argv[optind - 1], "--ost-list") == 0)
				fprintf(stderr,
					"warning: '--ost-list' is deprecated, use '--ost' instead\n");
#endif
			if (lsa.lsa_pattern == LLAPI_LAYOUT_MDT) {
				fprintf(stderr,
					"%s %s: -o|--ost incompatible with DoM layout\n",
					progname, argv[0]);
				goto usage_error;
			}
			/*
			 * -o allows overstriping, and must note it because
			 * parse_targets is shared with MDT striping, which
			 * does not allow duplicates
			 */
			lsa.lsa_pattern = LLAPI_LAYOUT_OVERSTRIPING;
			lsa.lsa_nr_tgts = parse_targets(tgts,
						sizeof(tgts) / sizeof(__u32),
						lsa.lsa_nr_tgts, optarg,
						&lsa.lsa_pattern);
			if (lsa.lsa_nr_tgts < 0) {
				fprintf(stderr,
					"%s %s: invalid OST target(s) '%s'\n",
					progname, argv[0], optarg);
				goto usage_error;
			}

			lsa.lsa_tgts = tgts;
			if (lsa.lsa_stripe_off == LLAPI_LAYOUT_DEFAULT)
				lsa.lsa_stripe_off = tgts[0];
			break;
		case 'p':
			if (!optarg)
				goto usage_error;

			if (optarg[0] == '\0' || lov_pool_is_inherited(optarg))
				lsa.lsa_pool_name = NULL;
			else
				lsa.lsa_pool_name = optarg;
			break;
		case 'S':
			result = llapi_parse_size(optarg, &lsa.lsa_stripe_size,
						  &size_units, 0);
			/* assume units of KB if too small to be valid */
			if (lsa.lsa_stripe_size < 4096)
				lsa.lsa_stripe_size *= 1024;
			if (result ||
			    lsa.lsa_stripe_size & (LOV_MIN_STRIPE_SIZE - 1)) {
				fprintf(stderr,
					"%s %s: invalid stripe size '%s'\n",
					progname, argv[0], optarg);
				goto usage_error;
			}
			break;
		case 'v':
			if (!migrate_mode) {
				fprintf(stderr,
					"%s %s: -v|--verbose valid only for migrate command\n",
					progname, argv[0]);
				goto usage_error;
			}
			migrate_mdt_param.fp_verbose = VERBOSE_DETAIL;
			migration_flags = LLAPI_MIGRATION_VERBOSE;
			break;
		case 'x':
			xattr = optarg;
			break;
		case 'y':
			from_yaml = true;
			template = optarg;
			break;
		case 'z':
			result = llapi_parse_size(optarg,
						  &lsa.lsa_extension_size,
						  &size_units, 0);
			if (result) {
				fprintf(stderr,
					"%s %s: invalid extension size '%s'\n",
					progname, argv[0], optarg);
				goto usage_error;
			}

			lsa.lsa_extension_comp = true;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
		case 'h':
			goto usage_error;
		}
	}

	fname = argv[optind];

	if (optind == argc) {
		fprintf(stderr, "%s %s: FILE must be specified\n",
			progname, argv[0]);
		goto usage_error;
	}

	/* lfs migrate $filename should keep the file's layout by default */
	if (migrate_mode && !layout && !from_yaml &&
	    !setstripe_args_specified(&lsa) && !lsa.lsa_pool_name)
		from_copy = true;

	if (xattr && !foreign_mode) {
		/*
		 * only print a warning as this is harmless and will be ignored
		 */
		fprintf(stderr,
			"%s %s: xattr has been specified for non-foreign layout\n",
			progname, argv[0]);
	} else if (foreign_mode && !xattr) {
		fprintf(stderr,
			"%s %s: xattr must be provided in foreign mode\n",
			progname, argv[0]);
		goto usage_error;
	}

	if (foreign_mode && (!setstripe_mode || comp_add | comp_del ||
	    comp_set || comp_id || delete || from_copy ||
	    setstripe_args_specified(&lsa) || lsa.lsa_nr_tgts ||
	    lsa.lsa_tgts)) {
		fprintf(stderr,
			"%s %s: only --xattr/--flags/--mode options are valid with --foreign\n",
			progname, argv[0]);
		return CMD_HELP;
	}

	if (mirror_mode && mirror_count == 0) {
		fprintf(stderr,
			"error: %s: --mirror-count|-N option is required\n",
			progname);
		result = -EINVAL;
		goto error;
	}

	if (mirror_mode) {
		if (!setstripe_args_specified(&lsa))
			last_mirror->m_inherit = true;
		if (lsa.lsa_comp_end == 0)
			lsa.lsa_comp_end = LUSTRE_EOF;
	}

	if (lsa.lsa_comp_end != 0) {
		result = comp_args_to_layout(lpp, &lsa, true);
		if (result) {
			fprintf(stderr, "error: %s: invalid layout\n",
				progname);
			result = -EINVAL;
			goto error;
		}
	}

	if (mirror_flags & MF_NO_VERIFY) {
		if (opc != SO_MIRROR_EXTEND) {
			fprintf(stderr,
				"error: %s: --no-verify is valid only for lfs mirror extend command\n",
				progname);
			result = -EINVAL;
			goto error;
		} else if (!has_m_file) {
			fprintf(stderr,
				"error: %s: --no-verify must be specified with -f <victim_file> option\n",
				progname);
			result = -EINVAL;
			goto error;
		}
	}

	if (comp_set && !comp_id && !lsa.lsa_pool_name) {
		fprintf(stderr,
			"%s %s: --component-set doesn't have component-id set\n",
			progname, argv[0]);
		goto usage_error;
	}

	if ((delete + comp_set + comp_del + comp_add) > 1) {
		fprintf(stderr,
			"%s %s: options --component-set, --component-del, --component-add and -d are mutually exclusive\n",
			progname, argv[0]);
		goto usage_error;
	}

	if (delete && (setstripe_args_specified(&lsa) || comp_id != 0 ||
		       lsa.lsa_comp_flags != 0 || layout != NULL)) {
		fprintf(stderr,
			"%s %s: option -d is mutually exclusive with -s, -c, -o, -p, -I, -F and -E options\n",
			progname, argv[0]);
		goto usage_error;
	}

	if ((comp_set || comp_del) &&
	    (setstripe_args_specified(&lsa) || layout != NULL)) {
		fprintf(stderr,
			"%s %s: options --component-del and --component-set are mutually exclusive when used with -c, -E, -o, -p, or -s\n",
			progname, argv[0]);
		goto usage_error;
	}

	if (comp_del && comp_id != 0 && lsa.lsa_comp_flags != 0) {
		fprintf(stderr,
			"%s %s: options -I and -F are mutually exclusive when used with --component-del\n",
			progname, argv[0]);
		goto usage_error;
	}

	if (comp_add || comp_del) {
		struct stat st;

		result = lstat(fname, &st);
		if (result == 0 && S_ISDIR(st.st_mode)) {
			fprintf(stderr,
				"%s setstripe: cannot use --component-add or --component-del for directory\n",
				progname);
			goto usage_error;
		}

		if (mirror_mode) {
			fprintf(stderr,
				"error: %s: can't use --component-add or --component-del for mirror operation\n",
				progname);
			goto usage_error;
		}
	}

	if (comp_add) {
		if (!layout) {
			fprintf(stderr,
				"%s %s: option -E must be specified with --component-add\n",
				progname, argv[0]);
			goto usage_error;
		}
	}

	if (from_yaml && from_copy) {
		fprintf(stderr,
			"%s: can't specify --yaml and --copy together\n",
			progname);
		goto error;
	}

	if ((from_yaml || from_copy) &&
	    (setstripe_args_specified(&lsa) || layout != NULL)) {
		fprintf(stderr,
			"error: %s: can't specify --yaml or --copy with -c, -S, -i, -o, -p or -E options.\n",
			argv[0]);
		goto error;
	}

	if ((migration_flags & LLAPI_MIGRATION_NONBLOCK) && migration_block) {
		fprintf(stderr,
			"%s %s: options --non-block and --block are mutually exclusive\n",
			progname, argv[0]);
		goto usage_error;
	}

	if (!comp_del && !comp_set && opc != SO_MIRROR_SPLIT &&
	    opc != SO_MIRROR_DELETE && comp_id != 0) {
		fprintf(stderr,
			"%s: option -I can only be used with --component-del or --component-set or lfs mirror split\n",
			progname);
		goto usage_error;
	}

	if (migrate_mdt_mode) {
		struct lmv_user_md *lmu;

		/* initialize migrate mdt parameters */
		lmu = calloc(1, lmv_user_md_size(lsa.lsa_nr_tgts,
						 LMV_USER_MAGIC_SPECIFIC));
		if (!lmu) {
			fprintf(stderr,
				"%s %s: cannot allocate memory for lmv_user_md: %s\n",
				progname, argv[0], strerror(ENOMEM));
			result = -ENOMEM;
			goto error;
		}
		if (lsa.lsa_stripe_count != LLAPI_LAYOUT_DEFAULT)
			lmu->lum_stripe_count = lsa.lsa_stripe_count;
		if (lsa.lsa_stripe_off == LLAPI_LAYOUT_DEFAULT) {
			fprintf(stderr,
				"%s %s: migrate should specify MDT index\n",
				progname, argv[0]);
			free(lmu);
			goto usage_error;
		}
		lmu->lum_stripe_offset = lsa.lsa_stripe_off;
		if (lsa.lsa_pattern != LLAPI_LAYOUT_RAID0)
			lmu->lum_hash_type = lsa.lsa_pattern;
		else
			lmu->lum_hash_type = LMV_HASH_TYPE_UNKNOWN;
		if (lsa.lsa_pool_name) {
			strncpy(lmu->lum_pool_name, lsa.lsa_pool_name,
				sizeof(lmu->lum_pool_name) - 1);
			lmu->lum_pool_name[sizeof(lmu->lum_pool_name) - 1] = 0;
		}
		if (lsa.lsa_nr_tgts > 1) {
			int i;

			if (lsa.lsa_stripe_count > 0 &&
			    lsa.lsa_stripe_count != LLAPI_LAYOUT_DEFAULT &&
			    lsa.lsa_stripe_count != lsa.lsa_nr_tgts) {
				fprintf(stderr,
					"error: %s: stripe count %lld doesn't match the number of MDTs: %d\n",
					progname, lsa.lsa_stripe_count,
					lsa.lsa_nr_tgts);
				free(lmu);
				goto usage_error;
			}

			lmu->lum_magic = LMV_USER_MAGIC_SPECIFIC;
			lmu->lum_stripe_count = lsa.lsa_nr_tgts;
			for (i = 0; i < lsa.lsa_nr_tgts; i++)
				lmu->lum_objects[i].lum_mds = lsa.lsa_tgts[i];
		} else {
			lmu->lum_magic = LMV_USER_MAGIC;
		}

		migrate_mdt_param.fp_lmv_md = lmu;
		migrate_mdt_param.fp_migrate = 1;
	} else if (!layout) {
		if (lsa_args_stripe_count_check(&lsa))
			goto usage_error;

		/* initialize stripe parameters */
		param = calloc(1, offsetof(typeof(*param),
			       lsp_osts[lsa.lsa_nr_tgts]));
		if (!param) {
			fprintf(stderr,
				"%s %s: cannot allocate memory for parameters: %s\n",
				progname, argv[0], strerror(ENOMEM));
			result = -ENOMEM;
			goto error;
		}

		if (lsa.lsa_stripe_size != LLAPI_LAYOUT_DEFAULT)
			param->lsp_stripe_size = lsa.lsa_stripe_size;
		if (lsa.lsa_stripe_count != LLAPI_LAYOUT_DEFAULT) {
			if (lsa.lsa_stripe_count == LLAPI_LAYOUT_WIDE)
				param->lsp_stripe_count = -1;
			else
				param->lsp_stripe_count = lsa.lsa_stripe_count;
		}
		if (lsa.lsa_stripe_off == LLAPI_LAYOUT_DEFAULT)
			param->lsp_stripe_offset = -1;
		else
			param->lsp_stripe_offset = lsa.lsa_stripe_off;
		param->lsp_stripe_pattern =
				llapi_pattern_to_lov(lsa.lsa_pattern);
		if (param->lsp_stripe_pattern == EINVAL) {
			fprintf(stderr, "error: %s: invalid stripe pattern\n",
				argv[0]);
			free(param);
			goto usage_error;
		}
		param->lsp_pool = lsa.lsa_pool_name;
		param->lsp_is_specific = false;

		if (lsa.lsa_nr_tgts > 0) {
			param->lsp_is_specific = true;
			param->lsp_stripe_count = lsa.lsa_nr_tgts;
			memcpy(param->lsp_osts, tgts,
			       sizeof(*tgts) * lsa.lsa_nr_tgts);
		}
	}

	if (from_yaml) {
		/* generate a layout from a YAML template */
		result = lfs_comp_create_from_yaml(template, &layout,
						   &lsa, tgts);
		if (result) {
			fprintf(stderr,
				"error: %s: can't create composite layout from template file %s\n",
				argv[0], template);
			goto error;
		}
	}

	if (layout != NULL || mirror_list != NULL) {
		if (mirror_list)
			result = mirror_adjust_first_extents(mirror_list);
		else
			result = layout_adjust_first_extent(fname, layout,
							    comp_add);
		if (result == -ENODATA)
			comp_add = 0;
		else if (result != 0) {
			fprintf(stderr, "error: %s: invalid layout\n",
				progname);
			goto error;
		}
	}

	for (fname = argv[optind]; fname != NULL; fname = argv[++optind]) {
		if (from_copy) {
			layout = llapi_layout_get_by_path(template ?: fname, 0);
			if (!layout) {
				fprintf(stderr,
					"%s: can't create composite layout from file %s: %s\n",
					progname, template ?: fname,
					strerror(errno));
				result = -errno;
				goto error;
			}
		}

		if (migrate_mdt_mode) {
			result = llapi_migrate_mdt(fname, &migrate_mdt_param);
		} else if (migrate_mode) {
			result = lfs_migrate(fname, migration_flags, param,
					     layout);
		} else if (comp_set != 0) {
			result = lfs_component_set(fname, comp_id,
						   lsa.lsa_pool_name,
						   lsa.lsa_comp_flags,
						   lsa.lsa_comp_neg_flags);
		} else if (comp_del != 0) {
			result = lfs_component_del(fname, comp_id,
						   lsa.lsa_comp_flags,
						   lsa.lsa_comp_neg_flags);
		} else if (comp_add != 0) {
			result = lfs_component_add(fname, layout);
		} else if (opc == SO_MIRROR_CREATE) {
			result = mirror_create(fname, mirror_list);
		} else if (opc == SO_MIRROR_EXTEND) {
			result = mirror_extend(fname, mirror_list,
					       mirror_flags);
		} else if (opc == SO_MIRROR_SPLIT || opc == SO_MIRROR_DELETE) {
			if (!mirror_id && !comp_id && !lsa.lsa_pool_name) {
				fprintf(stderr,
					"%s: no mirror id, component id, or pool name specified to delete from '%s'\n",
					progname, fname);
				goto usage_error;
			}
			if (lsa.lsa_pool_name)
				mirror_flags |= MF_COMP_POOL;
			else if (mirror_id != 0)
				comp_id = mirror_id;
			else
				mirror_flags |= MF_COMP_ID;
			if (has_m_file && !strcmp(fname, mirror_list->m_file)) {
				fprintf(stderr,
					"%s: the file specified by -f cannot be same as the source file '%s'\n",
					progname, fname);
				goto usage_error;
			}
			result = mirror_split(fname, comp_id, lsa.lsa_pool_name,
					      mirror_flags,
					      has_m_file ? mirror_list->m_file :
					      NULL);
		} else if (layout) {
			result = lfs_component_create(fname, O_CREAT | O_WRONLY,
						      mode, layout);
			if (result >= 0) {
				close(result);
				result = 0;
			}
		} else if (foreign_mode) {
			result = llapi_file_create_foreign(fname, mode, type,
							   flags, xattr);
			if (result >= 0) {
				close(result);
				result = 0;
			}
		} else {
			result = llapi_file_open_param(fname,
						       O_CREAT | O_WRONLY,
						       mode, param);
			if (result >= 0) {
				close(result);
				result = 0;
			}
		}
		if (result) {
			/* Save the first error encountered. */
			if (result2 == 0)
				result2 = result;
			continue;
		}
	}

	if (mode_opt)
		umask(previous_umask);

	free(param);
	free(migrate_mdt_param.fp_lmv_md);
	llapi_layout_free(layout);
	lfs_mirror_list_free(mirror_list);
	return result2;
usage_error:
	result = CMD_HELP;
error:
	llapi_layout_free(layout);
	lfs_mirror_list_free(mirror_list);
	return result;
}

static int lfs_poollist(int argc, char **argv)
{
	if (argc != 2)
		return CMD_HELP;

	return llapi_poollist(argv[1]);
}

#define FP_DEFAULT_TIME_MARGIN (24 * 60 * 60)
static time_t set_time(struct find_param *param, time_t *time, time_t *set,
		       char *str)
{
	long long t = 0;
	int sign = 0;
	char *endptr = "AD";
	char *timebuf;

	if (str[0] == '+')
		sign = 1;
	else if (str[0] == '-')
		sign = -1;

	if (sign)
		str++;

	for (timebuf = str; *endptr && *(endptr + 1); timebuf = endptr + 1) {
		long long val = strtoll(timebuf, &endptr, 0);
		int unit = 1;

		switch (*endptr) {
		case  'y':
			unit *= 52; /* 52 weeks + 1 day below */
			fallthrough;
		case  'w':
			unit *= 7;
			if (param->fp_time_margin == FP_DEFAULT_TIME_MARGIN)
				param->fp_time_margin *= (1 + unit / 52);
			unit += (*endptr == 'y'); /* +1 day for 365 days/year */
			fallthrough;
		case '\0': /* days are default unit if none used */
			fallthrough;
		case  'd':
			unit *= 24;
			fallthrough;
		case  'h':
			unit *= 60;
			fallthrough;
		case  'm':
			unit *= 60;
			fallthrough;
		case  's':
			break;
			/* don't need to multiply by 1 for seconds */
		default:
			fprintf(stderr,
				"%s find: bad time string '%s': %s\n",
				progname, timebuf, strerror(EINVAL));
			return LONG_MAX;
		}

		if (param->fp_time_margin == 0 ||
		    (*endptr && unit < param->fp_time_margin))
			param->fp_time_margin = unit;

		t += val * unit;
	}
	if (*time < t) {
		if (sign != 0)
			str--;
		fprintf(stderr, "%s find: bad time '%s': too large\n",
			progname, str);
		return LONG_MAX;
	}

	*set = *time - t;

	return sign;
}

static int str2quotaid(__u32 *id, const char *arg)
{
	unsigned long int projid_tmp = 0;
	char *endptr = NULL;

	projid_tmp = strtoul(arg, &endptr, 10);
	if (*endptr != '\0')
		return -EINVAL;
	/* UINT32_MAX is not allowed - see projid_valid()/INVALID_PROJID */
	if (projid_tmp >= UINT32_MAX)
		return -ERANGE;

	*id = projid_tmp;
	return 0;
}

static int name2uid(unsigned int *id, const char *name)
{
	struct passwd *passwd;

	passwd = getpwnam(name);
	if (!passwd)
		return -ENOENT;
	*id = passwd->pw_uid;

	return 0;
}

static int name2gid(unsigned int *id, const char *name)
{
	struct group *group;

	group = getgrnam(name);
	if (!group)
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
	if (!passwd)
		return -ENOENT;
	*name = passwd->pw_name;

	return 0;
}

static inline int gid2name(char **name, unsigned int id)
{
	struct group *group;

	group = getgrgid(id);
	if (!group)
		return -ENOENT;
	*name = group->gr_name;

	return 0;
}

static int name2layout(__u32 *layout, char *name)
{
	char *ptr, *layout_name;

	*layout = 0;
	for (ptr = name; ; ptr = NULL) {
		layout_name = strtok(ptr, ",");
		if (!layout_name)
			break;
		if (strcmp(layout_name, "released") == 0)
			*layout |= LOV_PATTERN_F_RELEASED;
		else if (strcmp(layout_name, "raid0") == 0)
			*layout |= LOV_PATTERN_RAID0;
		else if (strcmp(layout_name, "mdt") == 0)
			*layout |= LOV_PATTERN_MDT;
		else if (strcmp(layout_name, "overstriping") == 0)
			*layout |= LOV_PATTERN_OVERSTRIPING;
		else
			return -1;
	}
	return 0;
}

static int parse_symbolic(const char *input, mode_t *outmode, const char **end)
{
	int loop;
	int user, group, other;
	int who, all;
	char c, op;
	mode_t perm;
	mode_t usermask;
	mode_t previous_flags;

	user = group = other = 0;
	all = 0;
	loop = 1;
	perm = 0;
	previous_flags = 0;
	*end = input;
	usermask = 0;

	while (loop) {
		switch (*input) {
		case 'u':
			user = 1;
			break;
		case 'g':
			group = 1;
			break;
		case 'o':
			other = 1;
			break;
		case 'a':
			user = group = other = 1;
			all = 1;
			break;
		default:
			loop = 0;
		}

		if (loop)
			input++;
	}

	who = user || group || other;
	if (!who) {
		/* get the umask */
		usermask = umask(0022);
		umask(usermask);
		usermask &= 07777;
	}

	if (*input == '-' || *input == '+' || *input == '=')
		op = *input++;
	else
		/* operation is required */
		return -1;

	/* get the flags in *outmode */
	switch (*input) {
	case 'u':
		previous_flags = (*outmode & 0700);
		perm |= user  ? previous_flags : 0;
		perm |= group ? (previous_flags >> 3) : 0;
		perm |= other ? (previous_flags >> 6) : 0;
		input++;
		goto write_perm;
	case 'g':
		previous_flags = (*outmode & 0070);
		perm |= user  ? (previous_flags << 3) : 0;
		perm |= group ? previous_flags : 0;
		perm |= other ? (previous_flags >> 3) : 0;
		input++;
		goto write_perm;
	case 'o':
		previous_flags = (*outmode & 0007);
		perm |= user  ? (previous_flags << 6) : 0;
		perm |= group ? (previous_flags << 3) : 0;
		perm |= other ? previous_flags : 0;
		input++;
		goto write_perm;
	default:
		break;
	}

	/* this part is optional,
	 * if empty perm = 0 and *outmode is not modified
	 */
	loop = 1;
	while (loop) {
		c = *input;
		switch (c) {
		case 'r':
			perm |= user  ? 0400 : 0;
			perm |= group ? 0040 : 0;
			perm |= other ? 0004 : 0;
			/* set read permission for uog except for umask's
			 * permissions
			 */
			perm |= who   ? 0 : (0444 & ~usermask);
			break;
		case 'w':
			perm |= user  ? 0200 : 0;
			perm |= group ? 0020 : 0;
			perm |= other ? 0002 : 0;
			/* set write permission for uog except for umask'
			 * permissions
			 */
			perm |= who   ? 0 : (0222 & ~usermask);
			break;
		case 'x':
			perm |= user  ? 0100 : 0;
			perm |= group ? 0010 : 0;
			perm |= other ? 0001 : 0;
			/* set execute permission for uog except for umask'
			 * permissions
			 */
			perm |= who   ? 0 : (0111 & ~usermask);
			break;
		case 'X':
			/*
			 * Adds execute permission to 'u', 'g' and/or 'g' if
			 * specified and either 'u', 'g' or 'o' already has
			 * execute permissions.
			 */
			if ((*outmode & 0111) != 0) {
				perm |= user  ? 0100 : 0;
				perm |= group ? 0010 : 0;
				perm |= other ? 0001 : 0;
				perm |= !who  ? 0111 : 0;
			}
			break;
		case 's':
			/* s is ignored if o is given, but it's not an error */
			if (other && !group && !user)
				break;
			perm |= user  ? S_ISUID : 0;
			perm |= group ? S_ISGID : 0;
			break;
		case 't':
			/* 't' should be used when 'a' is given
			 * or who is empty
			 */
			perm |= (!who || all) ? S_ISVTX : 0;
			/* using ugo with t is not an error */
			break;
		default:
			loop = 0;
			break;
		}
		if (loop)
			input++;
	}

write_perm:
	/* uog flags should be only one character long */
	if (previous_flags && (*input != '\0' && *input != ','))
		return -1;

	switch (op) {
	case '-':
		/* remove the flags from outmode */
		*outmode &= ~perm;
		break;
	case '+':
		/* add the flags to outmode */
		*outmode |= perm;
		break;
	case '=':
		/* set the flags of outmode to perm */
		if (perm != 0)
			*outmode = perm;
		break;
	}

	*end = input;
	return 0;
}

static int str2mode_t(const char *input, mode_t *outmode)
{
	int ret;
	const char *iter;

	ret = 0;

	if (*input >= '0' && *input <= '7') {
		/* parse octal representation */
		char *end;

		iter = input;

		/* look for invalid digits in octal representation */
		while (isdigit(*iter))
			if (*iter++ > '7')
				return -1;

		errno = 0;
		*outmode = strtoul(input, &end, 8);

		if (errno != 0 || *outmode > 07777) {
			*outmode = 0;
			ret = -1;
		}

	} else if (*input == '8' || *input == '9') {
		/* error: invalid octal number */
		ret = -1;
	} else {
		/* parse coma seperated list of symbolic representation */
		int rc;
		const char *end;

		*outmode = 0;
		rc = 0;
		end = NULL;

		do {
			rc = parse_symbolic(input, outmode, &end);
			if (rc)
				return -1;

			input = end+1;
		} while (*end == ',');

		if (*end != '\0')
			ret = -1;
	}
	return ret;
}

static int lfs_find(int argc, char **argv)
{
	int c, rc;
	int ret = 0;
	time_t t;
	struct find_param param = {
		.fp_max_depth = -1,
		.fp_quiet = 1,
		.fp_time_margin = FP_DEFAULT_TIME_MARGIN,
	};
	struct option long_opts[] = {
	{ .val = 'A',	.name = "atime",	.has_arg = required_argument },
	{ .val = 'b',	.name = "blocks",	.has_arg = required_argument },
	{ .val = 'B',	.name = "btime",	.has_arg = required_argument },
	{ .val = 'B',	.name = "Btime",	.has_arg = required_argument },
	{ .val = LFS_COMP_COUNT_OPT,
			.name = "comp-count",	.has_arg = required_argument },
	{ .val = LFS_COMP_COUNT_OPT,
			.name = "component-count",
						.has_arg = required_argument },
	{ .val = LFS_COMP_FLAGS_OPT,
			.name = "comp-flags",	.has_arg = required_argument },
	{ .val = LFS_COMP_FLAGS_OPT,
			.name = "component-flags",
						.has_arg = required_argument },
	{ .val = LFS_COMP_START_OPT,
			.name = "comp-start",	.has_arg = required_argument },
	{ .val = LFS_COMP_START_OPT,
			.name = "component-start",
						.has_arg = required_argument },
	{ .val = LFS_MIRROR_STATE_OPT,
			.name = "mirror-state",	.has_arg = required_argument },
	{ .val = LFS_NEWERXY_OPT,
			.name = "newer",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "neweraa",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "neweram",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerac",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerab",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerma",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newermm",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newermc",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newermb",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerca",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newercm",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newercc",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newercb",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerba",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerbm",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerbc",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerbb",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerBa",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerBm",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerBc",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerBB",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerat",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newermt",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerct",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerbt",	.has_arg = required_argument},
	{ .val = LFS_NEWERXY_OPT,
			.name = "newerBt",	.has_arg = required_argument},
	{ .val = 'c',	.name = "stripe-count",	.has_arg = required_argument },
	{ .val = 'c',	.name = "stripe_count",	.has_arg = required_argument },
	{ .val = 'C',	.name = "ctime",	.has_arg = required_argument },
/* getstripe { .val = 'd', .name = "directory",	.has_arg = no_argument }, */
	{ .val = 'D',	.name = "maxdepth",	.has_arg = required_argument },
	{ .val = 'E',	.name = "comp-end",	.has_arg = required_argument },
	{ .val = 'E',	.name = "component-end",
						.has_arg = required_argument },
/* find	{ .val = 'F',	.name = "fid",		.has_arg = no_argument }, */
	{ .val = LFS_LAYOUT_FOREIGN_OPT,
			.name = "foreign",	.has_arg = optional_argument},
	{ .val = 'g',	.name = "gid",		.has_arg = required_argument },
	{ .val = 'G',	.name = "group",	.has_arg = required_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'H',	.name = "mdt-hash",	.has_arg = required_argument },
	{ .val = 'i',	.name = "stripe-index",	.has_arg = required_argument },
	{ .val = 'i',	.name = "stripe_index",	.has_arg = required_argument },
/* getstripe { .val = 'I', .name = "comp-id",	.has_arg = required_argument }*/
	{ .val = 'l',	.name = "lazy",		.has_arg = no_argument },
	{ .val = 'L',	.name = "layout",	.has_arg = required_argument },
	{ .val = 'm',	.name = "mdt",		.has_arg = required_argument },
	{ .val = 'm',	.name = "mdt-index",	.has_arg = required_argument },
	{ .val = 'm',	.name = "mdt_index",	.has_arg = required_argument },
	{ .val = 'M',	.name = "mtime",	.has_arg = required_argument },
	{ .val = 'n',	.name = "name",		.has_arg = required_argument },
	{ .val = 'N',	.name = "mirror-count",	.has_arg = required_argument },
/* find	{ .val = 'o'	.name = "or", .has_arg = no_argument }, like find(1) */
	{ .val = 'O',	.name = "obd",		.has_arg = required_argument },
	{ .val = 'O',	.name = "ost",		.has_arg = required_argument },
	{ .val = LFS_FIND_PERM,
			.name = "perm",		.has_arg = required_argument },
	/* no short option for pool yet, can be 'p' after 2.18 */
	{ .val = LFS_POOL_OPT,
			.name = "pool",		.has_arg = required_argument },
	{ .val = '0',	.name = "print0",	.has_arg = no_argument },
	{ .val = 'P',	.name = "print",	.has_arg = no_argument },
	{ .val = LFS_PRINTF_OPT,
			.name = "printf",       .has_arg = required_argument },
	{ .val = LFS_PROJID_OPT,
			.name = "projid",	.has_arg = required_argument },
/* getstripe { .val = 'q', .name = "quiet",	.has_arg = no_argument }, */
/* getstripe { .val = 'r', .name = "recursive",	.has_arg = no_argument }, */
/* getstripe { .val = 'R', .name = "raw",	.has_arg = no_argument }, */
	{ .val = 's',	.name = "size",		.has_arg = required_argument },
	{ .val = 'S',	.name = "stripe-size",	.has_arg = required_argument },
	{ .val = 'S',	.name = "stripe_size",	.has_arg = required_argument },
	{ .val = 't',	.name = "type",		.has_arg = required_argument },
	{ .val = 'T',	.name = "mdt-count",	.has_arg = required_argument },
	{ .val = 'u',	.name = "uid",		.has_arg = required_argument },
	{ .val = 'U',	.name = "user",		.has_arg = required_argument },
/* getstripe { .val = 'v', .name = "verbose",	.has_arg = no_argument }, */
	{ .val = 'z',	.name = "extension-size",
						.has_arg = required_argument },
	{ .val = 'z',	.name = "ext-size",	.has_arg = required_argument },
	{ .name = NULL } };
	int optidx = 0;
	int pathstart = -1;
	int pathend = -1;
	int pathbad = -1;
	int neg_opt = 0;
	time_t *xtime;
	int *xsign;
	int isoption;
	char *endptr;

	time(&t);

	/* when getopt_long_only() hits '!' it returns 1, puts "!" in optarg */
	while ((c = getopt_long_only(argc, argv,
		"-0A:b:B:c:C:D:E:g:G:hH:i:L:m:M:n:N:O:Ppqrs:S:t:T:u:U:z:",
		long_opts, &optidx)) >= 0) {
		xtime = NULL;
		xsign = NULL;
		if (neg_opt)
			--neg_opt;
		/* '!' is part of option */
		/*
		 * when getopt_long_only() finds a string which is not
		 * an option nor a known option argument it returns 1
		 * in that case if we already have found pathstart and pathend
		 * (i.e. we have the list of pathnames),
		 * the only supported value is "!"
		 */
		isoption = (c != 1) || (strcmp(optarg, "!") == 0);
		if (!isoption && pathend != -1) {
			fprintf(stderr,
				"err: %s: filename|dirname must either precede options or follow options\n",
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
			/*
			 * unknown; opt is "!" or path component,
			 * checking done above.
			 */
			if (strcmp(optarg, "!") == 0)
				neg_opt = 2;
			break;
		case 'A':
			xtime = &param.fp_atime;
			xsign = &param.fp_asign;
			param.fp_exclude_atime = !!neg_opt;
			/* no break, this falls through to 'B' for btime */
			fallthrough;
		case 'B':
			if (c == 'B') {
				xtime = &param.fp_btime;
				xsign = &param.fp_bsign;
				param.fp_exclude_btime = !!neg_opt;
			}
			/* no break, this falls through to 'C' for ctime */
			fallthrough;
		case 'C':
			if (c == 'C') {
				xtime = &param.fp_ctime;
				xsign = &param.fp_csign;
				param.fp_exclude_ctime = !!neg_opt;
			}
			/* no break, this falls through to 'M' for mtime */
			fallthrough;
		case 'M':
			if (c == 'M') {
				xtime = &param.fp_mtime;
				xsign = &param.fp_msign;
				param.fp_exclude_mtime = !!neg_opt;
			}
			rc = set_time(&param, &t, xtime, optarg);
			if (rc == LONG_MAX) {
				ret = -1;
				goto err;
			}
			if (rc)
				*xsign = rc;
			break;
		case 'b':
			if (optarg[0] == '+') {
				param.fp_blocks_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param.fp_blocks_sign =  1;
				optarg++;
			}

			param.fp_blocks_units = 1024;
			ret = llapi_parse_size(optarg, &param.fp_blocks,
					       &param.fp_blocks_units, 0);
			if (ret) {
				fprintf(stderr, "error: bad blocks '%s'\n",
					optarg);
				goto err;
			}
			param.fp_check_blocks = 1;
			param.fp_exclude_blocks = !!neg_opt;
			break;
		case LFS_COMP_COUNT_OPT:
			if (optarg[0] == '+') {
				param.fp_comp_count_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param.fp_comp_count_sign =  1;
				optarg++;
			}

			errno = 0;
			param.fp_comp_count = strtoul(optarg, &endptr, 0);
			if (errno != 0 || *endptr != '\0' ||
			    param.fp_comp_count > UINT32_MAX) {
				fprintf(stderr,
					"error: bad component count '%s'\n",
					optarg);
				goto err;
			}
			param.fp_check_comp_count = 1;
			param.fp_exclude_comp_count = !!neg_opt;
			break;
		case LFS_COMP_FLAGS_OPT:
			rc = comp_str2flags(optarg, &param.fp_comp_flags,
					    &param.fp_comp_neg_flags);
			if (rc) {
				fprintf(stderr,
					"error: bad component flags '%s'\n",
					optarg);
				goto err;
			}
			param.fp_check_comp_flags = 1;
			if (neg_opt) {
				__u32 flags = param.fp_comp_neg_flags;

				param.fp_comp_neg_flags = param.fp_comp_flags;
				param.fp_comp_flags = flags;
			}
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
				fprintf(stderr,
					"error: bad component start '%s'\n",
					optarg);
				goto err;
			}
			param.fp_check_comp_start = 1;
			param.fp_exclude_comp_start = !!neg_opt;
			break;
		case LFS_MIRROR_STATE_OPT:
			rc = mirror_str2state(optarg, &param.fp_mirror_state,
					      &param.fp_mirror_neg_state);
			if (rc) {
				fprintf(stderr,
					"error: bad mirrored file state '%s'\n",
					optarg);
				goto err;
			}
			param.fp_check_mirror_state = 1;
			if (neg_opt) {
				__u16 state = param.fp_mirror_neg_state;

				param.fp_mirror_neg_state =
					param.fp_mirror_state;
				param.fp_mirror_state = state;
			}
			break;
		case 'c':
			if (optarg[0] == '+') {
				param.fp_stripe_count_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param.fp_stripe_count_sign =  1;
				optarg++;
			}

			errno = 0;
			param.fp_stripe_count = strtoul(optarg, &endptr, 0);
			if (errno != 0 || *endptr != '\0' ||
			    param.fp_stripe_count > LOV_MAX_STRIPE_COUNT) {
				fprintf(stderr,
					"error: bad stripe_count '%s'\n",
					optarg);
				ret = -1;
				goto err;
			}
			param.fp_check_stripe_count = 1;
			param.fp_exclude_stripe_count = !!neg_opt;
			break;
		case 'D':
			errno = 0;
			param.fp_max_depth = strtol(optarg, 0, 0);
			if (errno != 0 || param.fp_max_depth < 0) {
				fprintf(stderr,
					"error: bad maxdepth '%s'\n",
					optarg);
				ret = -1;
				goto err;
			}
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
				/* assume units of KB if too small */
				if (param.fp_comp_end < 4096)
					param.fp_comp_end *= 1024;
			}
			if (rc) {
				fprintf(stderr,
					"error: bad component end '%s'\n",
					optarg);
				goto err;
			}
			param.fp_check_comp_end = 1;
			param.fp_exclude_comp_end = !!neg_opt;
			break;
		case LFS_LAYOUT_FOREIGN_OPT: {
			/* all types by default */
			uint32_t type = LU_FOREIGN_TYPE_UNKNOWN;

			if (optarg) {
				/* check pure numeric */
				type = strtoul(optarg, &endptr, 0);
				if (*endptr) {
					/* check name */
					type = check_foreign_type_name(optarg);
					if (type == LU_FOREIGN_TYPE_UNKNOWN) {
						fprintf(stderr,
							"%s %s: unknown foreign type '%s'\n",
							progname, argv[0],
							optarg);
						return CMD_HELP;
					}
				} else if (type >= UINT32_MAX) {
					fprintf(stderr,
						"%s %s: invalid foreign type '%s'\n",
						progname, argv[0], optarg);
					return CMD_HELP;
				}
			}
			param.fp_foreign_type = type;
			param.fp_check_foreign = 1;
			param.fp_exclude_foreign = !!neg_opt;
			break;
		}
		case LFS_NEWERXY_OPT: {
			char x = 'm';
			char y = 'm';
			int xidx;
			int negidx;
			time_t *newery;
			time_t ref = time(NULL);

			/* no need to check bad options, they won't get here */
			if (strlen(long_opts[optidx].name) == 7) {
				x = long_opts[optidx].name[5];
				y = long_opts[optidx].name[6];
			}

			if (y == 't') {
				static const char *const fmts[] = {
					"%Y-%m-%d %H:%M:%S",
					"%Y-%m-%d %H:%M",
					"%Y-%m-%d",
					"%H:%M:%S", /* sometime today */
					"%H:%M",
					"@%s",
					"%s",
					NULL };
				struct tm tm;
				bool found = false;
				int i;

				for (i = 0; fmts[i] != NULL; i++) {
					char *ptr;

					/* Init for times relative to today */
					if (strncmp(fmts[i], "%H", 2) == 0)
						localtime_r(&ref, &tm);
					else
						memset(&tm, 0, sizeof(tm));
					ptr = strptime(optarg, fmts[i], &tm);
					/* Skip spaces */
					while (ptr && isspace(*ptr))
						ptr++;
					if (ptr == optarg + strlen(optarg)) {
						found = true;
						break;
					}
				}

				if (!found) {
					fprintf(stderr,
						"%s: invalid time '%s'\n",
						progname, optarg);
					fprintf(stderr,
						"supported formats are:\n  ");
					for (i = 0; fmts[i] != NULL; i++)
						fprintf(stderr, "'%s', ",
							fmts[i]);
					fprintf(stderr, "\n");
					ret = -EINVAL;
					goto err;
				}

				ref = mktime(&tm);
			} else if (y == 'b' || y == 'B') {
				lstatx_t stx;

				rc = llapi_get_lum_file(optarg, NULL, &stx,
							NULL, 0);
				if (rc || !(stx.stx_mask & STATX_BTIME)) {
					if (!(stx.stx_mask & STATX_BTIME))
						ret = -EOPNOTSUPP;
					else
						ret = -errno;
					fprintf(stderr,
						"%s: get btime failed '%s': %s\n",
						progname, optarg,
						strerror(-ret));
					goto err;
				}

				ref = stx.stx_btime.tv_sec;
			} else {
				struct stat statbuf;

				if (stat(optarg, &statbuf) < 0) {
					fprintf(stderr,
						"%s: cannot stat file '%s': %s\n",
						progname, optarg,
						strerror(errno));
					ret = -errno;
					goto err;
				}

				switch (y) {
				case 'a':
					ref = statbuf.st_atime;
					break;
				case 'm':
					ref = statbuf.st_mtime;
					break;
				case 'c':
					ref = statbuf.st_ctime;
					break;
				default:
					fprintf(stderr,
						"%s: invalid Y argument: '%c'\n",
						progname, x);
					ret = -EINVAL;
					goto err;
				}
			}

			switch (x) {
			case 'a':
				xidx = NEWERXY_ATIME;
				break;
			case 'm':
				xidx = NEWERXY_MTIME;
				break;
			case 'c':
				xidx = NEWERXY_CTIME;
				break;
			case 'b':
			case 'B':
				xidx = NEWERXY_BTIME;
				break;
			default:
				fprintf(stderr,
					"%s: invalid X argument: '%c'\n",
					progname, x);
				ret = -EINVAL;
				goto err;
			}

			negidx = !!neg_opt;
			newery = &param.fp_newery[xidx][negidx];

			if (*newery == 0) {
				*newery = ref;
			} else {
				if (negidx)
					*newery = *newery > ref ? ref : *newery;
				else
					*newery = *newery > ref ? *newery : ref;
			}
			param.fp_newerxy = 1;
			break;
		}
		case 'g':
		case 'G':
			rc = name2gid(&param.fp_gid, optarg);
			if (rc) {
				if (str2quotaid(&param.fp_gid, optarg)) {
					fprintf(stderr,
						"Group/GID: %s cannot be found.\n",
						optarg);
					ret = -1;
					goto err;
				}
			}
			param.fp_exclude_gid = !!neg_opt;
			param.fp_check_gid = 1;
			break;
		case 'H':
			rc = mdthash_input(optarg, &param.fp_hash_inflags,
					   &param.fp_hash_exflags,
					   &param.fp_hash_type);
			if (rc) {
				ret = -1;
				goto err;
			}
			if (param.fp_hash_inflags || param.fp_hash_exflags)
				param.fp_check_hash_flag = 1;
			param.fp_exclude_hash_type = !!neg_opt;
			break;
		case 'l':
			param.fp_lazy = 1;
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
				if (str2quotaid(&param.fp_uid, optarg)) {
					fprintf(stderr,
						"User/UID: %s cannot be found.\n",
						optarg);
					ret = -1;
					goto err;
				}
			}
			param.fp_exclude_uid = !!neg_opt;
			param.fp_check_uid = 1;
			break;
		case 'n':
			param.fp_pattern = (char *)optarg;
			param.fp_exclude_pattern = !!neg_opt;
			break;
		case 'N':
			if (optarg[0] == '+') {
				param.fp_mirror_count_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param.fp_mirror_count_sign =  1;
				optarg++;
			}

			errno = 0;
			param.fp_mirror_count = strtoul(optarg, &endptr, 0);
			if (errno != 0 || *endptr != '\0' ||
			    param.fp_mirror_count > LUSTRE_MIRROR_COUNT_MAX) {
				fprintf(stderr,
					"error: bad mirror count '%s'\n",
					optarg);
				goto err;
			}
			param.fp_check_mirror_count = 1;
			param.fp_exclude_mirror_count = !!neg_opt;
			break;
		case 'm':
		case 'i':
		case 'O': {
			char *buf, *token, *next, *p;
			int len = 1;
			void *tmp;

			buf = strdup(optarg);
			if (!buf) {
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
				if (!tmp) {
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
				if (!tmp) {
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
#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 18, 53, 0)
		case 'p':
#endif
		case LFS_POOL_OPT:
			if (strlen(optarg) > LOV_MAXPOOLNAME) {
				fprintf(stderr,
					"Pool name %s is too long (max %d)\n",
					optarg, LOV_MAXPOOLNAME);
				ret = -1;
				goto err;
			}
			/*
			 * We do check for empty pool because empty pool
			 * is used to find V1 LOV attributes
			 */
			strncpy(param.fp_poolname, optarg, LOV_MAXPOOLNAME);
			param.fp_poolname[LOV_MAXPOOLNAME] = '\0';
			param.fp_exclude_pool = !!neg_opt;
			param.fp_check_pool = 1;
			break;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 14, 53, 0)
		case 'p': /* want this for --pool, to match getstripe/find */
			fprintf(stderr,
				"warning: -p deprecated, use --print0 or -0\n");
#endif
		case '0':
			param.fp_zero_end = 1;
			break;
		case 'P': /* we always print, this option is a no-op */
			break;
		case LFS_PRINTF_OPT:
			param.fp_format_printf_str = optarg;
			break;
		case LFS_PROJID_OPT:
			rc = name2projid(&param.fp_projid, optarg);
			if (rc) {
				if (str2quotaid(&param.fp_projid, optarg)) {
					fprintf(stderr,
						"Invalid project ID: %s\n",
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
			/* assume units of KB if too small to be valid */
			if (param.fp_stripe_size < 4096)
				param.fp_stripe_size *= 1024;
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
				fprintf(stderr, "%s: bad type '%s'\n",
					progname, optarg);
				ret = CMD_HELP;
				goto err;
			}
			break;
		case LFS_FIND_PERM:
			param.fp_exclude_perm = !!neg_opt;
			param.fp_perm_sign = LFS_FIND_PERM_EXACT;
			if (*optarg == '/') {
				param.fp_perm_sign = LFS_FIND_PERM_ANY;
				optarg++;
			} else if (*optarg == '-') {
				param.fp_perm_sign = LFS_FIND_PERM_ALL;
				optarg++;
			}

			if (str2mode_t(optarg, &param.fp_perm)) {
				fprintf(stderr, "error: invalid mode '%s'\n",
					optarg);
				ret = -1;
				goto err;
			}
			break;
		case 'T':
			if (optarg[0] == '+') {
				param.fp_mdt_count_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param.fp_mdt_count_sign =  1;
				optarg++;
			}

			errno = 0;
			param.fp_mdt_count = strtoul(optarg, &endptr, 0);
			if (errno != 0 || *endptr != '\0' ||
			    param.fp_mdt_count >= UINT32_MAX) {
				fprintf(stderr, "error: bad mdt_count '%s'\n",
					optarg);
				ret = -1;
				goto err;
			}
			param.fp_check_mdt_count = 1;
			param.fp_exclude_mdt_count = !!neg_opt;
			break;
		case 'z':
			if (optarg[0] == '+') {
				param.fp_ext_size_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param.fp_ext_size_sign =  1;
				optarg++;
			}

			ret = llapi_parse_size(optarg, &param.fp_ext_size,
					       &param.fp_ext_size_units, 0);
			if (ret) {
				fprintf(stderr, "error: bad ext-size '%s'\n",
					optarg);
				goto err;
			}
			param.fp_ext_size /= SEL_UNIT_SIZE;
			param.fp_ext_size_units /= SEL_UNIT_SIZE;
			param.fp_check_ext_size = 1;
			param.fp_exclude_ext_size = !!neg_opt;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
		case 'h':
			ret = CMD_HELP;
			goto err;
		}
	}
	if (!param.fp_verbose)
		param.fp_verbose = VERBOSE_DEFAULT;

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
		if (rc && !ret) {
			ret = rc;
			pathbad = pathstart;
		}
	} while (++pathstart < pathend);

	if (ret)
		fprintf(stderr, "%s: failed for '%s': %s\n",
			progname, argv[pathbad], strerror(-rc));

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
/* find	{ .val = 'A',	.name = "atime",	.has_arg = required_argument }*/
/* find	{ .val = 'b',	.name = "blocks",	.has_arg = required_argument }*/
/* find	{ .val = 'B',	.name = "btime",	.has_arg = required_argument }*/
/* find	{ .val = 'B',	.name = "Btime",	.has_arg = required_argument }*/
	{ .val = LFS_COMP_COUNT_OPT,
			.name = "comp-count",	.has_arg = no_argument },
	{ .val = LFS_COMP_COUNT_OPT,
		.name = "component-count",	.has_arg = no_argument },
	{ .val = LFS_COMP_FLAGS_OPT,
			.name = "comp-flags",	.has_arg = optional_argument },
	{ .val = LFS_COMP_FLAGS_OPT,
		.name = "component-flags",	.has_arg = optional_argument },
	{ .val = LFS_COMP_START_OPT,
			.name = "comp-start",	.has_arg = optional_argument },
	{ .val = LFS_COMP_START_OPT,
		.name = "component-start",	.has_arg = optional_argument },
	{ .val = LFS_MIRROR_INDEX_OPT,
		.name = "mirror-index",		.has_arg = required_argument },
	{ .val = LFS_MIRROR_ID_OPT,
		.name = "mirror-id",		.has_arg = required_argument },
	{ .val = LFS_NO_FOLLOW_OPT,
		.name = "no-follow",		.has_arg = no_argument },
	{ .val = 'c',	.name = "stripe-count",	.has_arg = no_argument },
	{ .val = 'c',	.name = "stripe_count",	.has_arg = no_argument },
/* find	{ .val = 'C',	.name = "ctime",	.has_arg = required_argument }*/
	{ .val = 'd',	.name = "directory",	.has_arg = no_argument },
	{ .val = 'D',	.name = "default",	.has_arg = no_argument },
	{ .val = 'E',	.name = "comp-end",	.has_arg = optional_argument },
	{ .val = 'E',	.name = "component-end", .has_arg = optional_argument },
	{ .val = 'F',	.name = "fid",		.has_arg = no_argument },
	{ .val = 'g',	.name = "generation",	.has_arg = no_argument },
/* find	{ .val = 'G',	.name = "group",	.has_arg = required_argument }*/
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
/* dirstripe { .val = 'H', .name = "mdt-hash",	.has_arg = required_argument }*/
	{ .val = 'i',	.name = "stripe-index",	.has_arg = no_argument },
	{ .val = 'i',	.name = "stripe_index",	.has_arg = no_argument },
	{ .val = 'I',	.name = "comp-id",	.has_arg = optional_argument },
	{ .val = 'I',	.name = "component-id",	.has_arg = optional_argument },
/* find { .val = 'l',	.name = "lazy",		.has_arg = no_argument }, */
	{ .val = 'L',	.name = "layout",	.has_arg = no_argument },
	{ .val = 'm',	.name = "mdt",		.has_arg = no_argument },
	{ .val = 'm',	.name = "mdt-index",	.has_arg = no_argument },
	{ .val = 'm',	.name = "mdt_index",	.has_arg = no_argument },
/* find	{ .val = 'M',	.name = "mtime",	.has_arg = required_argument }*/
/* find	{ .val = 'n',	.name = "name",		.has_arg = required_argument }*/
	{ .val = 'N',	.name = "mirror-count",	.has_arg = no_argument },
	{ .val = 'O',	.name = "obd",		.has_arg = required_argument },
	{ .val = 'O',	.name = "ost",		.has_arg = required_argument },
	{ .val = 'p',	.name = "pool",		.has_arg = no_argument },
/* find	{ .val = 'P',	.name = "print",	.has_arg = no_argument }, */
	{ .val = 'q',	.name = "quiet",	.has_arg = no_argument },
	{ .val = 'r',	.name = "recursive",	.has_arg = no_argument },
	{ .val = 'R',	.name = "raw",		.has_arg = no_argument },
	{ .val = 'S',	.name = "stripe-size",	.has_arg = no_argument },
	{ .val = 'S',	.name = "stripe_size",	.has_arg = no_argument },
/* find	{ .val = 't',	.name = "type",		.has_arg = required_argument }*/
/* dirstripe { .val = 'T', .name = "mdt-count",	.has_arg = required_argument }*/
/* find	{ .val = 'u',	.name = "uid",		.has_arg = required_argument }*/
/* find	{ .val = 'U',	.name = "user",		.has_arg = required_argument }*/
	{ .val = 'v',	.name = "verbose",	.has_arg = no_argument },
/* dirstripe { .val = 'X',.name = "max-inherit",.has_arg = required_argument }*/
	{ .val = 'y',	.name = "yaml",		.has_arg = no_argument },
	{ .val = 'z',	.name = "extension-size", .has_arg = no_argument },
	{ .val = 'z',	.name = "ext-size",	.has_arg = no_argument },
	{ .name = NULL } };
	int c, rc;
	int neg_opt = 0;
	int pathstart = -1, pathend = -1;
	int isoption;
	char *end, *tmp;

	while ((c = getopt_long(argc, argv,
			"-cdDE::FghiI::LmMNoO:pqrRsSvyz",
			long_opts, NULL)) != -1) {
		if (neg_opt)
			--neg_opt;

		/* '!' is part of option */
		isoption = (c != 1) || (strcmp(optarg, "!") == 0);
		if (!isoption && pathend != -1) {
			fprintf(stderr,
				"error: %s: filename|dirname must either precede options or follow options\n",
				argv[0]);
			return CMD_HELP;
		}
		if (!isoption && pathstart == -1)
			pathstart = optind - 1;
		if (isoption && pathstart != -1 && pathend == -1)
			pathend = optind - 2;

		switch (c) {
		case 1:
			/* unknown: opt is "!" */
			if (strcmp(optarg, "!") == 0)
				neg_opt = 2;
			break;
		case 'c':
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
			if (optarg) {
				rc = comp_str2flags(optarg,
						    &param->fp_comp_flags,
						    &param->fp_comp_neg_flags);
				if (rc != 0) {
					fprintf(stderr,
						"error: %s bad component flags '%s'.\n",
						argv[0], optarg);
					return CMD_HELP;
				}
				param->fp_check_comp_flags = 1;
			} else {
				param->fp_verbose |= VERBOSE_COMP_FLAGS;
				param->fp_max_depth = 0;
			}
			break;
		case LFS_COMP_START_OPT:
			if (optarg) {
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
					fprintf(stderr,
						"error: %s bad component start '%s'.\n",
						argv[0], tmp);
					return CMD_HELP;
				}
				param->fp_check_comp_start = 1;
			} else {
				param->fp_verbose |= VERBOSE_COMP_START;
				param->fp_max_depth = 0;
			}
			break;
		case LFS_MIRROR_INDEX_OPT: {
			unsigned long int mirror_index;

			if (optarg[0] == '+') {
				param->fp_mirror_index_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param->fp_mirror_index_sign = 1;
				optarg++;
			}

			errno = 0;
			mirror_index = strtoul(optarg, &end, 0);
			if (errno != 0 || *end != '\0' ||
			    mirror_index > UINT16_MAX || (mirror_index == 0 &&
			    param->fp_mirror_index_sign == 0 && neg_opt == 0)) {
				fprintf(stderr,
					"%s %s: invalid mirror index '%s'\n",
					progname, argv[0], optarg);
				return CMD_HELP;
			}

			param->fp_mirror_index = (__u16)mirror_index;

			if (param->fp_mirror_id != 0) {
				fprintf(stderr,
					"%s %s: can't specify both mirror index and mirror ID\n",
					progname, argv[0]);
				return CMD_HELP;
			}
			param->fp_check_mirror_index = 1;
			param->fp_exclude_mirror_index = !!neg_opt;
			break;
		}
		case LFS_MIRROR_ID_OPT: {
			unsigned long int mirror_id;

			if (optarg[0] == '+') {
				param->fp_mirror_id_sign = -1;
				optarg++;
			} else if (optarg[0] == '-') {
				param->fp_mirror_id_sign = 1;
				optarg++;
			}

			errno = 0;
			mirror_id = strtoul(optarg, &end, 0);
			if (errno != 0 || *end != '\0' ||
			    mirror_id > UINT16_MAX || (mirror_id == 0 &&
			    param->fp_mirror_id_sign == 0 && neg_opt == 0)) {
				fprintf(stderr,
					"%s %s: invalid mirror ID '%s'\n",
					progname, argv[0], optarg);
				return CMD_HELP;
			}

			param->fp_mirror_id = (__u16)mirror_id;

			if (param->fp_mirror_index != 0) {
				fprintf(stderr,
					"%s %s: can't specify both mirror index and mirror ID\n",
					progname, argv[0]);
				return CMD_HELP;
			}
			param->fp_check_mirror_id = 1;
			param->fp_exclude_mirror_id = !!neg_opt;
			break;
		}
		case LFS_NO_FOLLOW_OPT:
			param->fp_no_follow = true;
			break;
		case 'd':
			param->fp_max_depth = 0;
			break;
		case 'D':
			param->fp_get_default_lmv = 1;
			break;
		case 'E':
			if (optarg) {
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
					/* assume units of KB if too small */
					if (param->fp_comp_end < 4096)
						param->fp_comp_end *= 1024;
				}
				if (rc != 0) {
					fprintf(stderr,
						"error: %s bad component end '%s'.\n",
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
		case 'i':
			if (!(param->fp_verbose & VERBOSE_DETAIL)) {
				param->fp_verbose |= VERBOSE_STRIPE_OFFSET;
				param->fp_max_depth = 0;
			}
			break;
		case 'I':
			if (optarg) {
				param->fp_comp_id = strtoul(optarg, &end, 0);
				if (*end != '\0' || param->fp_comp_id == 0 ||
				    param->fp_comp_id > LCME_ID_MAX) {
					fprintf(stderr,
						"error: %s bad component id '%s'\n",
						argv[0], optarg);
					return CMD_HELP;
				}
				param->fp_check_comp_id = 1;
			} else {
				param->fp_max_depth = 0;
				param->fp_verbose |= VERBOSE_COMP_ID;
			}
			break;
		case 'L':
			if (!(param->fp_verbose & VERBOSE_DETAIL)) {
				param->fp_verbose |= VERBOSE_PATTERN;
				param->fp_max_depth = 0;
			}
			break;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
		case 'M':
			fprintf(stderr,
				"warning: '-M' deprecated, use '--mdt-index' or '-m' instead\n");
#endif
		case 'm':
			if (!(param->fp_verbose & VERBOSE_DETAIL))
				param->fp_max_depth = 0;
			param->fp_verbose |= VERBOSE_MDTINDEX;
			break;
		case 'N':
			if (!(param->fp_verbose & VERBOSE_DETAIL)) {
				param->fp_verbose |= VERBOSE_MIRROR_COUNT;
				param->fp_max_depth = 0;
			}
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
		case 'S':
			if (!(param->fp_verbose & VERBOSE_DETAIL)) {
				param->fp_verbose |= VERBOSE_STRIPE_SIZE;
				param->fp_max_depth = 0;
			}
			break;
		case 'v':
			param->fp_verbose = VERBOSE_DEFAULT | VERBOSE_DETAIL;
			break;
		case 'y':
			param->fp_yaml = 1;
			break;
		case 'z':
			if (!(param->fp_verbose & VERBOSE_DETAIL)) {
				param->fp_verbose |= VERBOSE_EXT_SIZE;
				param->fp_max_depth = 0;
			}
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
		case 'h':
			return CMD_HELP;
		}
	}

	if (pathstart == -1) {
		fprintf(stderr, "error: %s: no filename|pathname\n",
				argv[0]);
		return CMD_HELP;
	} else if (pathend == -1) {
		/* no options */
		pathend = argc;
	}

	if (pathend > argc)
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
		rc = llapi_getstripe(argv[pathstart], param);
	} while (++pathstart < pathend && !rc);

	if (rc)
		fprintf(stderr, "error: %s failed for %s.\n",
			argv[0], argv[optind - 1]);
	return rc;
}

static int lfs_tgts(int argc, char **argv)
{
	char mntdir[PATH_MAX] = {'\0'}, path[PATH_MAX] = {'\0'};
	struct find_param param;
	int index = 0, rc = 0;

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
	{ .val = 'c',	.name = "mdt-count",	 .has_arg = no_argument },
	{ .val = 'D',	.name = "default",	 .has_arg = no_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'H',	.name = "mdt-hash",	 .has_arg = no_argument },
	{ .val = 'i',	.name = "mdt-index",	 .has_arg = no_argument },
	{ .val = 'm',	.name = "mdt-index",	 .has_arg = no_argument },
	{ .val = 'O',	.name = "obd",		 .has_arg = required_argument },
	{ .val = 'r',	.name = "recursive",	 .has_arg = no_argument },
	{ .val = 'T',	.name = "mdt-count",	 .has_arg = no_argument },
	{ .val = 'v',	.name = "verbose",	 .has_arg = no_argument },
	{ .val = 'X',	.name = "max-inherit",	 .has_arg = no_argument },
	{ .val = 'y',	.name = "yaml",		 .has_arg = no_argument },
	{ .val = LFS_INHERIT_RR_OPT,
			.name = "max-inherit-rr", .has_arg = no_argument },
	{ .name = NULL } };
	int c, rc;

	param.fp_get_lmv = 1;

	while ((c = getopt_long(argc, argv,
				"cDhHimO:rtTvXy", long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
		case 'T':
			param.fp_verbose |= VERBOSE_COUNT;
			break;
		case 'D':
			param.fp_get_default_lmv = 1;
			break;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
		case 't':
			fprintf(stderr,
				"warning: '-t' deprecated, use '--mdt-hash' or '-H' instead\n");
			fallthrough;
#endif
		case 'H':
			param.fp_verbose |= VERBOSE_HASH_TYPE;
			break;
		case 'i':
			fallthrough;
		case 'm':
			param.fp_verbose |= VERBOSE_STRIPE_OFFSET;
			break;
		case 'O':
			if (param.fp_obd_uuid) {
				fprintf(stderr,
					"%s: only one obduuid allowed",
					progname);
				return CMD_HELP;
			}
			param.fp_obd_uuid = (struct obd_uuid *)optarg;
			break;
		case 'r':
			param.fp_recursive = 1;
			break;
		case 'v':
			param.fp_verbose |= VERBOSE_DETAIL;
			break;
		case 'X':
			param.fp_verbose |= VERBOSE_INHERIT;
			break;
		case LFS_INHERIT_RR_OPT:
			param.fp_verbose |= VERBOSE_INHERIT_RR;
			break;
		case 'y':
			param.fp_yaml = 1;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
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

enum mntdf_flags {
	MNTDF_INODES	= 0x0001,
	MNTDF_COOKED	= 0x0002,
	MNTDF_LAZY	= 0x0004,
	MNTDF_VERBOSE	= 0x0008,
	MNTDF_SHOW	= 0x0010,
	MNTDF_DECIMAL	= 0x0020,
};

#define COOK(value, base)					\
({								\
	int radix = 0;						\
	while (value > base) {					\
		value /= base;					\
		radix++;					\
	}							\
	radix;							\
})
#define UUF     "%-20s"
#define CSF     "%11s"
#define CDF     "%11llu"
#define HDF     "%8.1f%c"
#define RSF     "%4s"
#define RDF     "%3d%%"

static inline int obd_statfs_ratio(const struct obd_statfs *st, bool inodes)
{
	double avail, used, ratio = 0;

	if (inodes) {
		avail = st->os_ffree;
		used = st->os_files - st->os_ffree;
	} else {
		avail = st->os_bavail;
		used = st->os_blocks - st->os_bfree;
	}
	if (avail + used > 0)
		ratio = used / (used + avail) * 100;

	/* Round up to match df(1) usage percentage */
	return (ratio - (int)ratio) > 0 ? (int)(ratio + 1) : (int)ratio;
}

/*
 * This is to identify various problem states for "lfs df" if .osn_err = true,
 * so only show flags reflecting those states by default. Informational states
 * are only shown with "-v" and use lower-case names to distinguish them.
 * UNUSED[12] were for "EROFS = 30" until 1.6 but are now available for use.
 */
static struct obd_statfs_state_names {
	enum obd_statfs_state	osn_state;
	const char		osn_name;
	bool			osn_err;
} oss_names[] = {
	{ .osn_state = OS_STATFS_DEGRADED,   .osn_name = 'D', .osn_err = true },
	{ .osn_state = OS_STATFS_READONLY,   .osn_name = 'R', .osn_err = true },
	{ .osn_state = OS_STATFS_NOPRECREATE,.osn_name = 'N', .osn_err = true },
	{ .osn_state = OS_STATFS_UNUSED1,    .osn_name = '?', .osn_err = true },
	{ .osn_state = OS_STATFS_UNUSED2,    .osn_name = '?', .osn_err = true },
	{ .osn_state = OS_STATFS_ENOSPC,     .osn_name = 'S', .osn_err = true },
	{ .osn_state = OS_STATFS_ENOINO,     .osn_name = 'I', .osn_err = true },
	{ .osn_state = OS_STATFS_SUM,	     .osn_name = 'a', /* aggregate */ },
	{ .osn_state = OS_STATFS_NONROT,     .osn_name = 'f', /* flash */     },
};

static int showdf(char *mntdir, struct obd_statfs *stat,
		  char *uuid, enum mntdf_flags flags,
		  char *type, int index, int rc)
{
	long long avail, used, total;
	int ratio = 0;
	char *suffix = flags & MNTDF_DECIMAL ? "kMGTPEZY" : "KMGTPEZY";
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

		ratio = obd_statfs_ratio(stat, flags & MNTDF_INODES);

		if (flags & MNTDF_COOKED) {
			int base = flags & MNTDF_DECIMAL ? 1000 : 1024;
			double cook_val;
			int i;

			cook_val = (double)total;
			i = COOK(cook_val, base);
			if (i > 0)
				snprintf(tbuf, sizeof(tbuf), HDF, cook_val,
					 suffix[i - 1]);
			else
				snprintf(tbuf, sizeof(tbuf), CDF, total);

			cook_val = (double)used;
			i = COOK(cook_val, base);
			if (i > 0)
				snprintf(ubuf, sizeof(ubuf), HDF, cook_val,
					 suffix[i - 1]);
			else
				snprintf(ubuf, sizeof(ubuf), CDF, used);

			cook_val = (double)avail;
			i = COOK(cook_val, base);
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

		sprintf(rbuf, RDF, ratio);
		printf(UUF" "CSF" "CSF" "CSF" "RSF" %-s",
		       uuid, tbuf, ubuf, abuf, rbuf, mntdir);
		if (type)
			printf("[%s:%d]", type, index);

		if (stat->os_state) {
			uint32_t i;

			printf(" ");
			for (i = 0; i < ARRAY_SIZE(oss_names); i++) {
				if (oss_names[i].osn_state & stat->os_state &&
				    (oss_names[i].osn_err ||
				     flags & MNTDF_VERBOSE))
					printf("%c", oss_names[i].osn_name);
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

#define LL_STATFS_MAX	LOV_MAX_STRIPE_COUNT

struct ll_statfs_data {
	int			sd_index;
	struct obd_statfs	sd_st;
};

struct ll_statfs_buf {
	int			sb_count;
	struct ll_statfs_data	sb_buf[LL_STATFS_MAX];
};

static int mntdf(char *mntdir, char *fsname, char *pool, enum mntdf_flags flags,
		 int ops, struct ll_statfs_buf *lsb)
{
	struct obd_statfs stat_buf, sum = { .os_bsize = 1 };
	struct obd_uuid uuid_buf;
	char *poolname = NULL;
	struct ll_stat_type types[] = {
		{ .st_op = LL_STATFS_LMV,	.st_name = "MDT" },
		{ .st_op = LL_STATFS_LOV,	.st_name = "OST" },
		{ .st_name = NULL } };
	struct ll_stat_type *tp;
	__u64 ost_files = 0;
	__u64 ost_ffree = 0;
	__u32 index;
	__u32 type;
	int fd;
	int rc = 0;
	int rc2;

	if (pool) {
		poolname = strchr(pool, '.');
		if (poolname) {
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

	if (flags & MNTDF_SHOW) {
		if (flags & MNTDF_INODES)
			printf(UUF" "CSF" "CSF" "CSF" "RSF" %-s\n",
			       "UUID", "Inodes", "IUsed", "IFree",
			       "IUse%", "Mounted on");
		else
			printf(UUF" "CSF" "CSF" "CSF" "RSF" %-s\n",
			       "UUID",
			       flags & MNTDF_COOKED ? "bytes" : "1K-blocks",
			       "Used", "Available", "Use%", "Mounted on");
	}

	for (tp = types; tp->st_name != NULL; tp++) {
		bool have_ost = false;

		if (!(tp->st_op & ops))
			continue;

		for (index = 0; index < LOV_ALL_STRIPES &&
		     (!lsb || lsb->sb_count < LL_STATFS_MAX); index++) {
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

			/*
			 * If we have OSTs then don't report MDT block counts.
			 * For MDT-only filesystems the expectation is that all
			 * layouts have a DoM component.  For filesystems with
			 * OSTs, files are not necessarily going to store data
			 * on MDTs, and MDT space is limited to a fraction of
			 * OST space, so don't include it in the summary.
			 */
			if (tp->st_op == LL_STATFS_LOV && !have_ost) {
				have_ost = true;
				sum.os_blocks = 0;
				sum.os_bfree = 0;
				sum.os_bavail = 0;
			}

			if (poolname && tp->st_op == LL_STATFS_LOV &&
			    llapi_search_ost(fsname, poolname,
					     obd_uuid2str(&uuid_buf)) != 1)
				continue;

			/*
			 * the llapi_obd_fstatfs() call may have returned with
			 * an error, but if it filled in uuid_buf we will at
			 * lease use that to print out a message for that OBD.
			 * If we didn't get anything in the uuid_buf, then fill
			 * it in so that we can print an error message.
			 */
			if (uuid_buf.uuid[0] == '\0')
				snprintf(uuid_buf.uuid, sizeof(uuid_buf.uuid),
					 "%s%04x", tp->st_name, index);
			if (!rc && lsb) {
				lsb->sb_buf[lsb->sb_count].sd_index = index;
				lsb->sb_buf[lsb->sb_count].sd_st = stat_buf;
				lsb->sb_count++;
			}
			if (flags & MNTDF_SHOW)
				showdf(mntdir, &stat_buf,
				       obd_uuid2str(&uuid_buf), flags,
				       tp->st_name, index, rc2);

			if (rc2)
				continue;

			if (tp->st_op == LL_STATFS_LMV) {
				sum.os_ffree += stat_buf.os_ffree;
				sum.os_files += stat_buf.os_files;
			} else /* if (tp->st_op == LL_STATFS_LOV) */ {
				ost_files += stat_buf.os_files;
				ost_ffree += stat_buf.os_ffree;
			}
			sum.os_blocks += stat_buf.os_blocks *
					 stat_buf.os_bsize;
			sum.os_bfree  += stat_buf.os_bfree *
					 stat_buf.os_bsize;
			sum.os_bavail += stat_buf.os_bavail *
					 stat_buf.os_bsize;
		}
	}

	close(fd);

	/*
	 * If we have _some_ OSTs, but don't have as many free objects on the
	 * OST as inodes on the MDTs, reduce the reported number of inodes
	 * to compensate, so that the "inodes in use" number is correct.
	 * This should be kept in sync with ll_statfs_internal().
	 */
	if (ost_files && ost_ffree < sum.os_ffree) {
		sum.os_files = (sum.os_files - sum.os_ffree) + ost_ffree;
		sum.os_ffree = ost_ffree;
	}
	if (flags & MNTDF_SHOW) {
		printf("\n");
		showdf(mntdir, &sum, "filesystem_summary:", flags, NULL, 0, 0);
		printf("\n");
	}

	return rc;
}

enum {
	LAYOUT_INHERIT_UNSET	= -2,
};

/* functions */
static int lfs_setdirstripe(int argc, char **argv)
{
	char *dname;
	struct lfs_setstripe_args lsa = { 0 };
	struct llapi_stripe_param *param = NULL;
	__u32 mdts[LMV_MAX_STRIPE_COUNT] = { 0 };
	char *end;
	int c;
	char *mode_opt = NULL;
	bool default_stripe = false;
	bool delete = false;
	bool foreign_mode = false;
	mode_t mode = S_IRWXU | S_IRWXG | S_IRWXO;
	mode_t previous_mode = 0;
	char *xattr = NULL;
	__u32 type = LU_FOREIGN_TYPE_SYMLINK, flags = 0;
	int max_inherit = LAYOUT_INHERIT_UNSET;
	int max_inherit_rr = LAYOUT_INHERIT_UNSET;
	struct option long_opts[] = {
	{ .val = 'c',	.name = "count",	.has_arg = required_argument },
	{ .val = 'c',	.name = "mdt-count",	.has_arg = required_argument },
	{ .val = 'd',	.name = "delete",	.has_arg = no_argument },
	{ .val = 'D',	.name = "default",	.has_arg = no_argument },
	{ .val = 'D',	.name = "default_stripe", .has_arg = no_argument },
	{ .val = LFS_LAYOUT_FLAGS_OPT,
			.name = "flags",	.has_arg = required_argument },
	{ .val = LFS_LAYOUT_FOREIGN_OPT,
			.name = "foreign",	.has_arg = optional_argument},
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'H',	.name = "mdt-hash",	.has_arg = required_argument },
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 17, 53, 0)
	{ .val = 'i',	.name = "mdt-index",	.has_arg = required_argument },
	{ .val = 'i',	.name = "mdt",		.has_arg = required_argument },
#else
/* find { .val = 'l',	.name = "lazy",		.has_arg = no_argument }, */
	{ .val = 'm',	.name = "mdt-index",	.has_arg = required_argument },
	{ .val = 'm',	.name = "mdt",		.has_arg = required_argument },
#endif
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
	{ .val = 'i',	.name = "index",	.has_arg = required_argument },
#endif
	{ .val = 'o',	.name = "mode",		.has_arg = required_argument },
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
	{ .val = 't',	.name = "hash-type",	.has_arg = required_argument },
#endif
	{ .val = 'T',	.name = "mdt-count",	.has_arg = required_argument },
	{ .val = 'x',	.name = "xattr",	.has_arg = required_argument },
	{ .val = 'X',	.name = "max-inherit",	.has_arg = required_argument },
	{ .val = LFS_INHERIT_RR_OPT,
			.name = "max-inherit-rr", .has_arg = required_argument},
/* setstripe { .val = 'y', .name = "yaml",	.has_arg = no_argument }, */
	{ .name = NULL } };
	int result = 0;

	setstripe_args_init(&lsa);

	while ((c = getopt_long(argc, argv, "c:dDi:hH:m:o:t:T:x:X:",
				long_opts, NULL)) >= 0) {
		switch (c) {
		case 0:
			/* Long options. */
			break;
		case 'c':
		case 'T':
			errno = 0;
			lsa.lsa_stripe_count = strtoul(optarg, &end, 0);
			if (errno != 0 || *end != '\0' ||
			    lsa.lsa_stripe_count < -1 ||
			    lsa.lsa_stripe_count > LOV_MAX_STRIPE_COUNT) {
				fprintf(stderr,
					"%s: invalid stripe count '%s'\n",
					progname, optarg);
				return CMD_HELP;
			}
			break;
		case 'd':
			delete = true;
			default_stripe = true;
			break;
		case 'D':
			default_stripe = true;
			break;
		case LFS_LAYOUT_FOREIGN_OPT:
			if (optarg) {
				/* check pure numeric */
				type = strtoul(optarg, &end, 0);
				if (*end) {
					/* check name */
					type = check_foreign_type_name(optarg);
					if (type == LU_FOREIGN_TYPE_UNKNOWN) {
						fprintf(stderr,
							"%s %s: unknown foreign type '%s'\n",
							progname, argv[0],
							optarg);
						return CMD_HELP;
					}
				} else if (type >= UINT32_MAX) {
					fprintf(stderr,
						"%s %s: invalid foreign type '%s'\n",
						progname, argv[0], optarg);
					return CMD_HELP;
				}
			}
			foreign_mode = true;
			break;
		case LFS_LAYOUT_FLAGS_OPT:
			errno = 0;
			flags = strtoul(optarg, &end, 16);
			if (errno != 0 || *end != '\0' ||
			    flags >= UINT32_MAX) {
				fprintf(stderr,
					"%s %s: invalid hex flags '%s'\n",
					progname, argv[0], optarg);
				return CMD_HELP;
			}
			if (!foreign_mode) {
				fprintf(stderr,
					"%s %s: hex flags must be specified with --foreign option\n",
					progname, argv[0]);
				return CMD_HELP;
			}
			break;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
		case 't':
			fprintf(stderr,
				"warning: '--hash-type' and '-t' deprecated, use '--mdt-hash' or '-H' instead\n");
			fallthrough;
#endif
		case 'H':
			lsa.lsa_pattern = check_hashtype(optarg);
			if (lsa.lsa_pattern == 0) {
				fprintf(stderr,
					"%s %s: bad stripe hash type '%s'\n",
					progname, argv[0], optarg);
				return CMD_HELP;
			}
			break;
		case 'i':
#if LUSTRE_VERSION_CODE >= OBD_OCD_VERSION(2, 17, 53, 0)
		case 'm':
#endif
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
			if (strcmp(argv[optind - 1], "--index") == 0)
				fprintf(stderr,
					"%s %s: warning: '--index' deprecated, use '--mdt-index' instead\n",
					progname, argv[0]);
#endif
			lsa.lsa_nr_tgts = parse_targets(mdts,
						sizeof(mdts) / sizeof(__u32),
						lsa.lsa_nr_tgts, optarg, NULL);
			if (lsa.lsa_nr_tgts < 0) {
				fprintf(stderr,
					"%s %s: invalid MDT target(s) '%s'\n",
					progname, argv[0], optarg);
				return CMD_HELP;
			}

			lsa.lsa_tgts = mdts;
			if (lsa.lsa_stripe_off == LLAPI_LAYOUT_DEFAULT)
				lsa.lsa_stripe_off = mdts[0];
			break;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 15, 53, 0)
		case 'm':
			fprintf(stderr,
				"warning: '-m' is deprecated, use '--mode' or '-o' instead\n");
#endif
		case 'o':
			mode_opt = optarg;
			break;
		case 'x':
			xattr = optarg;
			break;
		case 'X':
			errno = 0;
			max_inherit = strtol(optarg, &end, 10);
			if (errno != 0 || *end != '\0' || max_inherit < -2) {
				fprintf(stderr,
					"%s %s: invalid max-inherit '%s'\n",
					progname, argv[0], optarg);
				return CMD_HELP;
			}
			if (max_inherit == 0) {
				max_inherit = LMV_INHERIT_NONE;
			} else if (max_inherit == -1) {
				max_inherit = LMV_INHERIT_UNLIMITED;
			} else if (max_inherit > LMV_INHERIT_MAX) {
				fprintf(stderr,
					"%s %s: max-inherit %d exceeds maximum %u\n",
					progname, argv[0], max_inherit,
					LMV_INHERIT_MAX);
				return CMD_HELP;
			}
			break;
		case LFS_INHERIT_RR_OPT:
			if (!default_stripe) {
				fprintf(stderr,
					"%s %s: '--max-inherit-rr' must be specified with '-D'\n",
					progname, argv[0]);
				return CMD_HELP;
			}
			errno = 0;
			max_inherit_rr = strtol(optarg, &end, 10);
			if (errno != 0 || *end != '\0' || max_inherit_rr < -2) {
				fprintf(stderr,
					"%s %s: invalid max-inherit-rr '%s'\n",
					progname, argv[0], optarg);
				return CMD_HELP;
			}
			if (max_inherit_rr == 0) {
				max_inherit_rr = LMV_INHERIT_RR_NONE;
			} else if (max_inherit_rr == -1) {
				max_inherit_rr = LMV_INHERIT_RR_UNLIMITED;
			} else if (max_inherit_rr > LMV_INHERIT_RR_MAX) {
				fprintf(stderr,
					"%s %s: max-inherit-rr %d exceeds maximum %u\n",
					progname, argv[0], max_inherit_rr,
					LMV_INHERIT_RR_MAX);
				return CMD_HELP;
			}
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}

	if (optind == argc) {
		fprintf(stderr, "%s %s: DIR must be specified\n",
			progname, argv[0]);
		return CMD_HELP;
	}

	if (xattr && !foreign_mode) {
		/*
		 * only print a warning as this is armless and will be
		 * ignored
		 */
		fprintf(stderr,
			"%s %s: xattr has been specified for non-foreign layout\n",
			progname, argv[0]);
	} else if (foreign_mode && !xattr) {
		fprintf(stderr,
			"%s %s: xattr must be provided in foreign mode\n",
			progname, argv[0]);
		return CMD_HELP;
	}

	if (foreign_mode && (delete || default_stripe || lsa.lsa_nr_tgts ||
	    lsa.lsa_tgts || setstripe_args_specified(&lsa))) {
		fprintf(stderr,
			"%s %s: only --xattr/--flags/--mode options are valid with --foreign\n",
			progname, argv[0]);
		return CMD_HELP;
	}

	if (!delete && lsa.lsa_stripe_off == LLAPI_LAYOUT_DEFAULT &&
	    lsa.lsa_stripe_count == LLAPI_LAYOUT_DEFAULT && !foreign_mode) {
		/* if no parameters set, create directory on least-used MDTs */
		lsa.lsa_stripe_off = LMV_OFFSET_DEFAULT;
		lsa.lsa_stripe_count = 1;
	}

	if (delete &&
	    (lsa.lsa_stripe_off != LLAPI_LAYOUT_DEFAULT ||
	     lsa.lsa_stripe_count != LLAPI_LAYOUT_DEFAULT)) {
		fprintf(stderr,
			"%s %s: cannot specify -d with -c or -i options\n",
			progname, argv[0]);
		return CMD_HELP;
	}

	if (mode_opt) {
		mode = strtoul(mode_opt, &end, 8);
		if (*end != '\0') {
			fprintf(stderr,
				"%s %s: bad MODE '%s'\n",
				progname, argv[0], mode_opt);
			return CMD_HELP;
		}
		previous_mode = umask(0);
	}

	/* check max-inherit and warn user in some cases */
	if (default_stripe &&
	    (lsa.lsa_stripe_count < 0 || lsa.lsa_stripe_count > 1)) {
		if (max_inherit == LMV_INHERIT_UNLIMITED)
			fprintf(stderr,
			"%s %s: unrecommended max-inherit=-1 when default stripe-count=%lld\n",
			progname, argv[0], lsa.lsa_stripe_count);
		else if (max_inherit > LMV_INHERIT_DEFAULT_STRIPED + 2 &&
			 max_inherit != LMV_INHERIT_NONE)
			fprintf(stderr,
				"%s %s: unrecommended max-inherit=%d when default stripe-count=%lld\n",
				progname, argv[0], max_inherit,
				lsa.lsa_stripe_count);
	}

	if (max_inherit_rr != LAYOUT_INHERIT_UNSET &&
	    lsa.lsa_stripe_off != LLAPI_LAYOUT_DEFAULT &&
	    lsa.lsa_stripe_off != LMV_OFFSET_DEFAULT) {
		fprintf(stderr,
			"%s %s: max-inherit-rr needs mdt-index=-1, not %lld\n",
			progname, argv[0], lsa.lsa_stripe_off);
		return CMD_HELP;
	}

	/* foreign LMV/dir case */
	if (foreign_mode) {
		if (argc > optind + 1) {
			fprintf(stderr,
				"%s %s: cannot specify multiple foreign dirs\n",
				progname, argv[0]);
			return CMD_HELP;
		}

		dname = argv[optind];
		result = llapi_dir_create_foreign(dname, mode, type, flags,
						  xattr);
		if (result != 0)
			fprintf(stderr,
				"%s mkdir: can't create foreign dir '%s': %s\n",
				progname, dname, strerror(-result));
		return result;
	}

	/*
	 * initialize stripe parameters, in case param is converted to specific,
	 * i.e, 'lfs mkdir -i -1 -c N', always allocate space for lsp_tgts.
	 */
	param = calloc(1, offsetof(typeof(*param),
		       lsp_tgts[lsa.lsa_stripe_count != LLAPI_LAYOUT_DEFAULT ?
				lsa.lsa_stripe_count : lsa.lsa_nr_tgts]));
	if (!param) {
		fprintf(stderr,
			"%s %s: cannot allocate memory for parameters: %s\n",
			progname, argv[0], strerror(ENOMEM));
		return CMD_HELP;
	}

	/* if "lfs setdirstripe -D -i -1" is used, assume 1-stripe directory */
	if (default_stripe && lsa.lsa_stripe_off == LMV_OFFSET_DEFAULT &&
	    (lsa.lsa_stripe_count == LLAPI_LAYOUT_DEFAULT ||
	     lsa.lsa_stripe_count == 0))
		lsa.lsa_stripe_count = 1;
	if (lsa.lsa_stripe_count != LLAPI_LAYOUT_DEFAULT)
		param->lsp_stripe_count = lsa.lsa_stripe_count;
	if (lsa.lsa_stripe_off == LLAPI_LAYOUT_DEFAULT)
		param->lsp_stripe_offset = LMV_OFFSET_DEFAULT;
	else
		param->lsp_stripe_offset = lsa.lsa_stripe_off;
	if (lsa.lsa_pattern != LLAPI_LAYOUT_RAID0)
		param->lsp_stripe_pattern = lsa.lsa_pattern;
	else
		param->lsp_stripe_pattern = LMV_HASH_TYPE_UNKNOWN;
	param->lsp_pool = lsa.lsa_pool_name;
	param->lsp_is_specific = false;
	if (max_inherit == LAYOUT_INHERIT_UNSET) {
		if (lsa.lsa_stripe_count == 0 || lsa.lsa_stripe_count == 1)
			max_inherit = LMV_INHERIT_DEFAULT_PLAIN;
		else
			max_inherit = LMV_INHERIT_DEFAULT_STRIPED;
	}
	param->lsp_max_inherit = max_inherit;
	if (default_stripe) {

		if (max_inherit_rr == LAYOUT_INHERIT_UNSET)
			max_inherit_rr = LMV_INHERIT_RR_DEFAULT;
		param->lsp_max_inherit_rr = max_inherit_rr;
	}
	if (strcmp(argv[0], "mkdir") == 0)
		param->lsp_is_create = true;
	if (lsa.lsa_nr_tgts > 1) {
		if (lsa.lsa_stripe_count > 0 &&
		    lsa.lsa_stripe_count != LLAPI_LAYOUT_DEFAULT &&
		    lsa.lsa_stripe_count != lsa.lsa_nr_tgts) {
			fprintf(stderr,
				"error: %s: stripe count %lld doesn't match the number of MDTs: %d\n",
				argv[0], lsa.lsa_stripe_count,
				lsa.lsa_nr_tgts);
			free(param);
			return CMD_HELP;
		}

		param->lsp_is_specific = true;
		param->lsp_stripe_count = lsa.lsa_nr_tgts;
		memcpy(param->lsp_tgts, mdts, sizeof(*mdts) * lsa.lsa_nr_tgts);
	}

	dname = argv[optind];
	do {
		if (default_stripe) {
			result = llapi_dir_set_default_lmv(dname, param);
			if (result)
				fprintf(stderr,
					"%s setdirstripe: cannot set default stripe on dir '%s': %s\n",
					progname, dname, strerror(-result));
			continue;
		}

		result = llapi_dir_create(dname, mode, param);
		if (result)
			fprintf(stderr,
				"%s setdirstripe: cannot create dir '%s': %s\n",
				progname, dname, strerror(-result));
	} while (!result && (dname = argv[++optind]));

	if (mode_opt)
		umask(previous_mode);

	free(param);
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
	while (dname) {
		result = llapi_direntry_remove(dname);
		if (result) {
			fprintf(stderr,
				"error: %s: remove dir entry '%s' failed\n",
				argv[0], dname);
			break;
		}
		dname = argv[++index];
	}
	return result;
}

static int lfs_unlink_foreign(int argc, char **argv)
{
	char *name;
	int   index;
	int   result = 0;

	if (argc <= 1) {
		fprintf(stderr, "error: %s: missing pathname\n",
			argv[0]);
		return CMD_HELP;
	}

	index = 1;
	name = argv[index];
	while (name != NULL) {
		result = llapi_unlink_foreign(name);
		if (result) {
			fprintf(stderr,
				"error: %s: unlink foreign entry '%s' failed\n",
				argv[0], name);
			break;
		}
		name = argv[++index];
	}
	return result;
}

static int lfs_mv(int argc, char **argv)
{
	struct lmv_user_md lmu = { LMV_USER_MAGIC };
	struct find_param param = {
		.fp_max_depth = -1,
		.fp_mdt_index = -1,
	};
	char *end;
	int c;
	int rc = 0;
	struct option long_opts[] = {
	{ .val = 'm',	.name = "mdt",		.has_arg = required_argument },
	{ .val = 'm',	.name = "mdt-index",	.has_arg = required_argument },
	{ .val = 'v',	.name = "verbose",	.has_arg = no_argument },
	{ .name = NULL } };

	while ((c = getopt_long(argc, argv, "m:M:v", long_opts, NULL)) != -1) {
		switch (c) {
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
		case 'M':
			fprintf(stderr,
				"warning: '-M' deprecated, use '--mdt-index' or '-m' instead\n");
#endif
		case 'm':
			errno = 0;
			lmu.lum_stripe_offset = strtoul(optarg, &end, 0);
			if (errno != 0 || *end != '\0' ||
			    lmu.lum_stripe_offset >= UINT32_MAX) {
				fprintf(stderr, "%s mv: bad MDT index '%s'\n",
					progname, optarg);
				return CMD_HELP;
			}
			break;
		case 'v':
			param.fp_verbose = VERBOSE_DETAIL;
			break;
		default:
			fprintf(stderr, "%s mv: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			return CMD_HELP;
		}
	}

	if (lmu.lum_stripe_offset == LMV_OFFSET_DEFAULT) {
		fprintf(stderr, "%s mv: MDT index must be specified\n",
			progname);
		return CMD_HELP;
	}

	if (optind >= argc) {
		fprintf(stderr, "%s mv: DIR must be specified\n", progname);
		return CMD_HELP;
	}

	lmu.lum_hash_type = LMV_HASH_TYPE_UNKNOWN;

	/* initialize migrate mdt parameters */
	param.fp_lmv_md = &lmu;
	param.fp_migrate = 1;
	rc = llapi_migrate_mdt(argv[optind], &param);
	if (rc != 0)
		fprintf(stderr, "%s mv: cannot migrate '%s' to MDT%04x: %s\n",
			progname, argv[optind], lmu.lum_stripe_offset,
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

static int lfs_df(int argc, char **argv)
{
	char mntdir[PATH_MAX] = {'\0'}, path[PATH_MAX] = {'\0'};
	enum mntdf_flags flags = MNTDF_SHOW;
	int ops = LL_STATFS_LMV | LL_STATFS_LOV;
	int c, rc = 0, rc1 = 0, index = 0, arg_idx = 0;
	char fsname[PATH_MAX] = "", *pool_name = NULL;
	struct option long_opts[] = {
	{ .val = 'h',	.name = "human-readable", .has_arg = no_argument },
	{ .val = 'H',	.name = "si",		.has_arg = no_argument },
	{ .val = 'i',	.name = "inodes",	.has_arg = no_argument },
	{ .val = 'l',	.name = "lazy",		.has_arg = no_argument },
	{ .val = 'p',	.name = "pool",		.has_arg = required_argument },
	{ .val = 'v',	.name = "verbose",	.has_arg = no_argument },
	{ .name = NULL} };

	while ((c = getopt_long(argc, argv, "hHilp:v", long_opts, NULL)) != -1) {
		switch (c) {
		case 'h':
			flags = (flags & ~MNTDF_DECIMAL) | MNTDF_COOKED;
			break;
		case 'H':
			flags |= MNTDF_COOKED | MNTDF_DECIMAL;
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
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			return CMD_HELP;
		}
	}

	/* Handle case where path is not specified */
	if (optind == argc) {
		while (!llapi_search_mounts(path, index++, mntdir, fsname)) {
			/* Check if we have a mount point */
			if (mntdir[0] == '\0')
				continue;

			rc = mntdf(mntdir, fsname, pool_name, flags, ops, NULL);
			if (rc || path[0] != '\0')
				break;

			fsname[0] = '\0'; /* avoid matching in next loop */
			mntdir[0] = '\0'; /* avoid matching in next loop */
			path[0] = '\0'; /* clean for next loop */
		}
		return rc;
	}

	/* Loop through all the remaining arguments. These are Lustre FS
	 * paths.
	 */
	for (arg_idx = optind; arg_idx <= argc - 1; arg_idx++) {
		bool valid = false;

		fsname[0] = '\0'; /* start clean */
		mntdir[0] = '\0'; /* start clean */
		path[0] = '\0';   /* start clean */

		/* path does not exists at all */
		if (!realpath(argv[arg_idx], path)) {
			rc = -errno;
			fprintf(stderr, "error: invalid path '%s': %s\n",
				argv[arg_idx], strerror(-rc));
			/* save first seen error */
			if (!rc1)
				rc1 = rc;

			continue;
		}

		/* path exists but may not be a Lustre filesystem */
		while (!llapi_search_mounts(path, index++, mntdir, fsname)) {
			/* Check if we have a mount point */
			if (mntdir[0] == '\0')
				continue;

			rc = mntdf(mntdir, fsname, pool_name, flags, ops, NULL);
			if (rc || path[0] != '\0') {
				valid = true;

				/* save first seen error */
				if (!rc1)
					rc1 = rc;
				break;
			}
		}

		if (!valid) {
			llapi_printf(LLAPI_MSG_ERROR,
				     "%s:%s Not a Lustre filesystem\n",
				     argv[0], argv[arg_idx]);
			/* save first seen error */
			if (!rc1)
				rc1 = -EOPNOTSUPP;
		}
	}

	return rc1;
}

static int print_instance(const char *mntdir, char *buf, size_t buflen,
			  bool opt_instance, bool opt_fsname, bool opt_mntdir)
{
	int rc = 0;

	if (opt_fsname == opt_instance) { /* both true or both false */
		rc = llapi_getname(mntdir, buf, buflen);
	} else if (opt_fsname) {
		/*
		 * llapi_search_mounts() fills @buf with fsname, but that is not
		 * called if explicit paths are specified on the command-line
		 */
		if (buf[0] == '\0')
			rc = llapi_get_fsname(mntdir, buf, buflen);
	} else /* if (opt_instance) */ {
		rc = llapi_get_instance(mntdir, buf, buflen);
	}

	if (rc < 0) {
		fprintf(stderr, "cannot get instance for '%s': %s\n",
			mntdir, strerror(-rc));
		return rc;
	}

	if (opt_mntdir)
		printf("%s %s\n", buf, mntdir);
	else
		printf("%s\n", buf);

	return 0;
}

static int lfs_getname(int argc, char **argv)
{
	struct option long_opts[] = {
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'i',	.name = "instance",	.has_arg = no_argument },
	{ .val = 'n',	.name = "fsname",	.has_arg = no_argument },
	{ .name = NULL} };
	bool opt_instance = false, opt_fsname = false;
	char fsname[PATH_MAX] = "";
	int rc = 0, rc2, c;

	while ((c = getopt_long(argc, argv, "hin", long_opts, NULL)) != -1) {
		switch (c) {
		case 'i':
			opt_instance = true;
			break;
		case 'n':
			opt_fsname = true;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}

	if (optind == argc) { /* no paths specified, get all paths. */
		char mntdir[PATH_MAX] = "", path[PATH_MAX] = "";
		int index = 0;

		while (!llapi_search_mounts(path, index++, mntdir, fsname)) {
			rc2 = print_instance(mntdir, fsname, sizeof(fsname),
					     opt_instance, opt_fsname, true);
			if (!rc)
				rc = rc2;
			path[0] = fsname[0] = mntdir[0] = '\0';
		}
	} else { /* paths specified, only attempt to search these. */
		bool opt_mntdir;

		/* if only one path is given, print only requested info */
		opt_mntdir = argc - optind > 1 || (opt_instance == opt_fsname);

		for (; optind < argc; optind++) {
			rc2 = print_instance(argv[optind], fsname,
					     sizeof(fsname), opt_instance,
					     opt_fsname, opt_mntdir);
			if (!rc)
				rc = rc2;
			fsname[0] = '\0';
		}
	}

	return rc;
}

static int lfs_check(int argc, char **argv)
{
	char mntdir[PATH_MAX] = {'\0'}, path[PATH_MAX] = {'\0'};
	int num_types = 1;
	char *obd_types[3];
	char obd_type1[4];
	char obd_type2[4];
	char obd_type3[4];
	int rc;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "%s check: server type must be specified\n",
			progname);
		return CMD_HELP;
	}

	obd_types[0] = obd_type1;
	obd_types[1] = obd_type2;
	obd_types[2] = obd_type3;

	if (strcmp(argv[1], "osts") == 0) {
		strcpy(obd_types[0], "osc");
	} else if (strcmp(argv[1], "mdts") == 0 ||
		   strcmp(argv[1], "mds") == 0) {
		strcpy(obd_types[0], "mdc");
	} else if (strcmp(argv[1], "mgts") == 0) {
		strcpy(obd_types[0], "mgc");
	} else if (strcmp(argv[1], "all") == 0 ||
		   strcmp(argv[1], "servers") == 0) {
		num_types = 3;
		strcpy(obd_types[0], "osc");
		strcpy(obd_types[1], "mdc");
		strcpy(obd_types[2], "mgc");
	} else {
		fprintf(stderr, "%s check: unrecognized option '%s'\n",
			progname, argv[1]);
		return CMD_HELP;
	}

	if (argc >= 3 && !realpath(argv[2], path)) {
		rc = -errno;
		fprintf(stderr, "error: invalid path '%s': %s\n",
			argv[2], strerror(-rc));
		return rc;
	}

	rc = llapi_search_mounts(path, 0, mntdir, NULL);
	if (rc < 0 || mntdir[0] == '\0') {
		fprintf(stderr,
			"%s check: cannot find mounted Lustre filesystem: %s\n",
			progname, (rc < 0) ? strerror(-rc) : strerror(ENODEV));
		return rc;
	}

	rc = llapi_target_check(num_types, obd_types, path);
	if (rc)
		fprintf(stderr, "%s check: cannot check target '%s': %s\n",
			progname, argv[1], strerror(-rc));

	return rc;
}

#ifdef HAVE_SYS_QUOTA_H
#define ADD_OVERFLOW(a, b) \
		     ((((a) + (b)) < (a)) ? \
		      ((a) = ULONG_MAX) : ((a) = (a) + (b)))

/* Convert format time string "XXwXXdXXhXXmXXs" into seconds value
 * returns the value or ULONG_MAX on integer overflow or incorrect format
 * Notes:
 *        1. the order of specifiers is arbitrary (may be: 5w3s or 3s5w)
 *        2. specifiers may be encountered multiple times (2s3s is 5 seconds)
 *        3. empty integer value is interpreted as 0
 */
static unsigned long str2sec(const char *timestr)
{
	const char spec[] = "smhdw";
	const unsigned long mult[] = {1, 60, 60*60, 24*60*60, 7*24*60*60};
	unsigned long val = 0;
	char *tail;

	if (strpbrk(timestr, spec) == NULL) {
		/*
		 * no specifiers inside the time string,
		 * should treat it as an integer value
		 */
		val = strtoul(timestr, &tail, 10);
		return *tail ? ULONG_MAX : val;
	}

	/* format string is XXwXXdXXhXXmXXs */
	while (*timestr) {
		unsigned long v;
		int ind;
		char *ptr;

		v = strtoul(timestr, &tail, 10);
		if (v == ULONG_MAX || *tail == '\0')
			/*
			 * value too large (ULONG_MAX or more)
			 * or missing specifier
			 */
			goto error;

		ptr = strchr(spec, *tail);
		if (!ptr)
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
		fprintf(stderr, "%s: invalid limit '%s'\n",		\
			progname, str);					\
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

static inline int lfs_verify_poolarg(char *pool)
{
	if (strnlen(optarg, LOV_MAXPOOLNAME + 1) > LOV_MAXPOOLNAME) {
		fprintf(stderr,
			"Pool name '%.*s' is longer than %d\n",
			LOV_MAXPOOLNAME, pool, LOV_MAXPOOLNAME);
		return 1;
	}
	return 0;
}

/* special grace time, only notify the user when its quota is over soft limit
 * but doesn't block new writes until the hard limit is reached.
 */
#define NOTIFY_GRACE		"notify"
#define NOTIFY_GRACE_TIME	LQUOTA_GRACE_MASK

#ifndef toqb
static inline __u64 lustre_stoqb(size_t space)
{
	return (space + QIF_DQBLKSIZE - 1) >> QIF_DQBLKSIZE_BITS;
}
#else
#define lustre_stoqb   toqb
#endif

int lfs_setquota_times(int argc, char **argv, struct if_quotactl *qctl)
{
	int c, rc;
	char *mnt, *obd_type = (char *)qctl->obd_type;
	struct obd_dqblk *dqb = &qctl->qc_dqblk;
	struct obd_dqinfo *dqi = &qctl->qc_dqinfo;
	struct option long_opts[] = {
	{ .val = 'b',	.name = "block-grace",	.has_arg = required_argument },
	{ .val = 'g',	.name = "group",	.has_arg = no_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'i',	.name = "inode-grace",	.has_arg = required_argument },
	{ .val = 'p',	.name = "projid",	.has_arg = no_argument },
	{ .val = 't',	.name = "times",	.has_arg = no_argument },
	{ .val = 'u',	.name = "user",		.has_arg = no_argument },
	{ .val = LFS_POOL_OPT,
			.name = "pool",		.has_arg = required_argument },
	{ .name = NULL } };
	int qtype;

	qctl->qc_cmd  = LUSTRE_Q_SETINFO;
	qctl->qc_type = ALLQUOTA;

	while ((c = getopt_long(argc, argv, "b:ghi:ptu",
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
			if (qctl->qc_type != ALLQUOTA) {
				fprintf(stderr,
					"%s: -u/g/p cannot be used more than once\n",
					progname);
				return CMD_HELP;
			}
			qctl->qc_type = qtype;
			break;
		case 'b':
			if (strncmp(optarg, NOTIFY_GRACE,
				    strlen(NOTIFY_GRACE)) == 0) {
				dqi->dqi_bgrace = NOTIFY_GRACE_TIME;
			} else {
				dqi->dqi_bgrace = str2sec(optarg);
				if (dqi->dqi_bgrace >= NOTIFY_GRACE_TIME) {
					fprintf(stderr,
						"%s: bad block-grace: %s\n",
						progname, optarg);
					return CMD_HELP;
				}
			}
			dqb->dqb_valid |= QIF_BTIME;
			break;
		case 'i':
			if (strncmp(optarg, NOTIFY_GRACE,
				    strlen(NOTIFY_GRACE)) == 0) {
				dqi->dqi_igrace = NOTIFY_GRACE_TIME;
			} else {
				dqi->dqi_igrace = str2sec(optarg);
				if (dqi->dqi_igrace >= NOTIFY_GRACE_TIME) {
					fprintf(stderr,
						"%s: bad inode-grace: %s\n",
						progname, optarg);
					return CMD_HELP;
				}
			}
			dqb->dqb_valid |= QIF_ITIME;
			break;
		case 't': /* Yes, of course! */
			break;
		case LFS_POOL_OPT:
			if (lfs_verify_poolarg(optarg))
				return -1;
			strncpy(qctl->qc_poolname, optarg, LOV_MAXPOOLNAME);
			qctl->qc_cmd  = LUSTRE_Q_SETINFOPOOL;
			break;
		/* getopt prints error message for us when opterr != 0 */
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}

	if (qctl->qc_type == ALLQUOTA) {
		fprintf(stderr, "%s: neither -u, -g nor -p specified\n",
			progname);
		return CMD_HELP;
	}

	if (optind != argc - 1) {
		fprintf(stderr, "%s: unexpected parameter '%s'\n",
			progname, argv[optind + 1]);
		return CMD_HELP;
	}

	mnt = argv[optind];
	rc = llapi_quotactl(mnt, qctl);
	if (rc) {
		if (*obd_type)
			fprintf(stderr, "%s %s ", obd_type,
				obd_uuid2str(&qctl->obd_uuid));
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
	int c, rc = 0;
	struct if_quotactl *qctl;
	char *mnt, *obd_type;
	struct obd_dqblk *dqb;
	struct option long_opts[] = {
	{ .val = 'b',	.name = "block-softlimit",
						.has_arg = required_argument },
	{ .val = 'B',	.name = "block-hardlimit",
						.has_arg = required_argument },
	{ .val = 'd',	.name = "default",	.has_arg = no_argument },
	{ .val = LFS_SETQUOTA_DELETE,
			.name = "delete",	.has_arg = no_argument },
	{ .val = 'g',	.name = "group",	.has_arg = required_argument },
	{ .val = 'G',	.name = "default-grp",	.has_arg = no_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'i',	.name = "inode-softlimit",
						.has_arg = required_argument },
	{ .val = 'I',	.name = "inode-hardlimit",
						.has_arg = required_argument },
	{ .val = 'p',	.name = "projid",	.has_arg = required_argument },
	{ .val = 'P',	.name = "default-prj",	.has_arg = no_argument },
	{ .val = 'u',	.name = "user",		.has_arg = required_argument },
	{ .val = 'U',	.name = "default-usr",	.has_arg = no_argument },
	{ .val = LFS_POOL_OPT,
			.name = "pool",		.has_arg = required_argument },
	{ .name = NULL } };
	unsigned int limit_mask = 0;
	bool use_default = false;
	int qtype, qctl_len;

	qctl_len = sizeof(*qctl) + LOV_MAXPOOLNAME + 1;
	qctl = malloc(qctl_len);
	if (!qctl)
		return -ENOMEM;

	memset(qctl, 0, qctl_len);
	obd_type = (char *)qctl->obd_type;
	dqb = &qctl->qc_dqblk;

	if (has_times_option(argc, argv)) {
		rc = lfs_setquota_times(argc, argv, qctl);
		goto out;
	}

	qctl->qc_cmd  = LUSTRE_Q_SETQUOTA;
	qctl->qc_type = ALLQUOTA; /* ALLQUOTA makes no sense for setquota,
				   * so it can be used as a marker that qc_type
				   * isn't reinitialized from command line
				   */
	while ((c = getopt_long(argc, argv, "b:B:dDg:Ghi:I:p:Pu:U",
		long_opts, NULL)) != -1) {
		switch (c) {
		case 'U':
			qctl->qc_cmd = LUSTRE_Q_SETDEFAULT;
			qtype = USRQUOTA;
			qctl->qc_id = 0;
			goto quota_type_def;
		case 'u':
			qtype = USRQUOTA;
			rc = name2uid(&qctl->qc_id, optarg);
			goto quota_type;
		case 'G':
			qctl->qc_cmd = LUSTRE_Q_SETDEFAULT;
			qtype = GRPQUOTA;
			qctl->qc_id = 0;
			goto quota_type_def;
		case 'g':
			qtype = GRPQUOTA;
			rc = name2gid(&qctl->qc_id, optarg);
			goto quota_type;
		case 'P':
			qctl->qc_cmd = LUSTRE_Q_SETDEFAULT;
			qtype = PRJQUOTA;
			qctl->qc_id = 0;
			goto quota_type_def;
		case 'p':
			qtype = PRJQUOTA;
			rc = name2projid(&qctl->qc_id, optarg);
quota_type:
			if (rc) {
				if (str2quotaid(&qctl->qc_id, optarg)) {
					fprintf(stderr,
						"%s setquota: invalid id '%s'\n",
						progname, optarg);
					rc = -1;
					goto out;
				}
			}

			if (qctl->qc_id == 0) {
				fprintf(stderr,
					"%s setquota: can't set quota for root usr/group/project.\n",
					progname);
				rc = -1;
				goto out;
			}

quota_type_def:
			if (qctl->qc_type != ALLQUOTA) {
				fprintf(stderr,
					"%s setquota: only one of -u, -U, -g, -G, -p or -P may be specified\n",
					progname);
				rc = CMD_HELP;
				goto out;
			}
			qctl->qc_type = qtype;
			break;
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 0, 53, 0)
		case 'd':
#if LUSTRE_VERSION_CODE > OBD_OCD_VERSION(2, 15, 53, 0)
			fprintf(stderr, "'-d' deprecatd, use '-D' or '--default'\n");
#endif
			/* falltrrough */
#endif
		case 'D':
			use_default = true;
			qctl->qc_cmd = LUSTRE_Q_SETDEFAULT;
			break;
		case LFS_SETQUOTA_DELETE:
			qctl->qc_cmd = LUSTRE_Q_DELETEQID;
			break;
		case 'b':
			ARG2ULL(dqb->dqb_bsoftlimit, optarg, 1024);
			dqb->dqb_bsoftlimit >>= 10;
			limit_mask |= BSLIMIT;
			if (dqb->dqb_bsoftlimit &&
			    dqb->dqb_bsoftlimit <= 1024) /* <= 1M? */
				fprintf(stderr,
					"%s setquota: warning: block softlimit '%llu' smaller than minimum qunit size\nSee '%s help setquota' or Lustre manual for details\n",
					progname,
					(unsigned long long)dqb->dqb_bsoftlimit,
					progname);
			break;
		case 'B':
			ARG2ULL(dqb->dqb_bhardlimit, optarg, 1024);
			dqb->dqb_bhardlimit >>= 10;
			limit_mask |= BHLIMIT;
			if (dqb->dqb_bhardlimit &&
			    dqb->dqb_bhardlimit <= 1024) /* <= 1M? */
				fprintf(stderr,
					"%s setquota: warning: block hardlimit '%llu' smaller than minimum qunit size\n"
					"See '%s help setquota' or Lustre manual for details\n",
					progname,
					(unsigned long long)dqb->dqb_bhardlimit,
					progname);
			break;
		case 'i':
			ARG2ULL(dqb->dqb_isoftlimit, optarg, 1);
			limit_mask |= ISLIMIT;
			if (dqb->dqb_isoftlimit &&
			    dqb->dqb_isoftlimit <= 1024) /* <= 1K inodes? */
				fprintf(stderr,
					"%s setquota: warning: inode softlimit '%llu' smaller than minimum qunit size\nSee '%s help setquota' or Lustre manual for details\n",
					progname,
					(unsigned long long)dqb->dqb_isoftlimit,
					progname);
			break;
		case 'I':
			ARG2ULL(dqb->dqb_ihardlimit, optarg, 1);
			limit_mask |= IHLIMIT;
			if (dqb->dqb_ihardlimit &&
			    dqb->dqb_ihardlimit <= 1024) /* <= 1K inodes? */
				fprintf(stderr,
					"%s setquota: warning: inode hardlimit '%llu' smaller than minimum qunit size\nSee '%s help setquota' or Lustre manual for details\n",
					progname,
					(unsigned long long)dqb->dqb_ihardlimit,
					progname);
			break;
		case LFS_POOL_OPT:
			if (lfs_verify_poolarg(optarg)) {
				rc = -1;
				goto out;
			}
			strncpy(qctl->qc_poolname, optarg, LOV_MAXPOOLNAME);
			qctl->qc_cmd = qctl->qc_cmd == LUSTRE_Q_SETDEFAULT ?
						LUSTRE_Q_SETDEFAULT_POOL :
						LUSTRE_Q_SETQUOTAPOOL;
			break;
		default:
			fprintf(stderr,
				"%s setquota: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			rc = CMD_HELP;
			goto out;
		}
	}

	if (qctl->qc_type == ALLQUOTA) {
		fprintf(stderr,
			"%s setquota: either -u or -g must be specified\n",
			progname);
		rc = CMD_HELP;
		goto out;
	}

	if (!use_default && qctl->qc_cmd != LUSTRE_Q_DELETEQID &&
	    limit_mask == 0) {
		fprintf(stderr,
			"%s setquota: at least one limit must be specified\n",
			progname);
		rc = CMD_HELP;
		goto out;
	}

	if ((use_default || qctl->qc_cmd == LUSTRE_Q_DELETEQID)  &&
	    limit_mask != 0) {
		fprintf(stderr,
			"%s setquota: limits should not be specified when using default quota or deleting quota ID\n",
			progname);
		rc = CMD_HELP;
		goto out;
	}

	if (use_default && qctl->qc_id == 0) {
		fprintf(stderr,
			"%s setquota: can not set default quota for root user/group/project\n",
			progname);
		rc = CMD_HELP;
		goto out;
	}

	if (qctl->qc_cmd == LUSTRE_Q_DELETEQID  && qctl->qc_id == 0) {
		fprintf(stderr,
			"%s setquota: can not delete root user/group/project\n",
			progname);
		rc = CMD_HELP;
		goto out;
	}

	if (optind != argc - 1) {
		fprintf(stderr,
			"%s setquota: filesystem not specified or unexpected argument '%s'\n",
			progname, argv[optind]);
		rc = CMD_HELP;
		goto out;
	}

	mnt = argv[optind];

	if (use_default) {
		dqb->dqb_bhardlimit = 0;
		dqb->dqb_bsoftlimit = 0;
		dqb->dqb_ihardlimit = 0;
		dqb->dqb_isoftlimit = 0;
		dqb->dqb_itime = 0;
		dqb->dqb_btime = 0;
		dqb->dqb_valid |= QIF_LIMITS | QIF_TIMES;
		/* do not set inode limits for Pool Quotas */
		if (qctl->qc_cmd  == LUSTRE_Q_SETDEFAULT_POOL)
			dqb->dqb_valid ^= QIF_ILIMITS | QIF_ITIME;
	} else if ((!(limit_mask & BHLIMIT) ^ !(limit_mask & BSLIMIT)) ||
		   (!(limit_mask & IHLIMIT) ^ !(limit_mask & ISLIMIT))) {
		/* sigh, we can't just set blimits/ilimits */
		struct if_quotactl *tmp_qctl;

		tmp_qctl = calloc(1, sizeof(*qctl) + LOV_MAXPOOLNAME + 1);
		if (!tmp_qctl)
			goto out;

		if (qctl->qc_cmd == LUSTRE_Q_SETQUOTAPOOL) {
			tmp_qctl->qc_cmd = LUSTRE_Q_GETQUOTAPOOL;
			strncpy(tmp_qctl->qc_poolname, qctl->qc_poolname,
				LOV_MAXPOOLNAME);
		} else {
			tmp_qctl->qc_cmd  = LUSTRE_Q_GETQUOTA;
		}
		tmp_qctl->qc_type = qctl->qc_type;
		tmp_qctl->qc_id = qctl->qc_id;

		rc = llapi_quotactl(mnt, tmp_qctl);
		if (rc < 0) {
			free(tmp_qctl);
			goto out;
		}

		if (!(limit_mask & BHLIMIT))
			dqb->dqb_bhardlimit = tmp_qctl->qc_dqblk.dqb_bhardlimit;
		if (!(limit_mask & BSLIMIT))
			dqb->dqb_bsoftlimit = tmp_qctl->qc_dqblk.dqb_bsoftlimit;
		if (!(limit_mask & IHLIMIT))
			dqb->dqb_ihardlimit = tmp_qctl->qc_dqblk.dqb_ihardlimit;
		if (!(limit_mask & ISLIMIT))
			dqb->dqb_isoftlimit = tmp_qctl->qc_dqblk.dqb_isoftlimit;

		/* Keep grace times if we have got no softlimit arguments */
		if ((limit_mask & BHLIMIT) && !(limit_mask & BSLIMIT)) {
			dqb->dqb_valid |= QIF_BTIME;
			dqb->dqb_btime = tmp_qctl->qc_dqblk.dqb_btime;
		}

		if ((limit_mask & IHLIMIT) && !(limit_mask & ISLIMIT)) {
			dqb->dqb_valid |= QIF_ITIME;
			dqb->dqb_itime = tmp_qctl->qc_dqblk.dqb_itime;
		}
		free(tmp_qctl);
	}

	dqb->dqb_valid |= (limit_mask & (BHLIMIT | BSLIMIT)) ? QIF_BLIMITS : 0;
	dqb->dqb_valid |= (limit_mask & (IHLIMIT | ISLIMIT)) ? QIF_ILIMITS : 0;

	rc = llapi_quotactl(mnt, qctl);
	if (rc) {
		if (*obd_type)
			fprintf(stderr,
				"%s setquota: cannot quotactl '%s' '%s': %s\n",
				progname, obd_type,
				obd_uuid2str(&qctl->obd_uuid), strerror(-rc));
		else
			fprintf(stderr,
				"%s setquota: quotactl failed: %s\n",
				progname, strerror(-rc));
	}
out:
	if (rc)
		fprintf(stderr, "setquota failed: %s\n", strerror(-rc));

	free(qctl);
	return rc;
}

/* Converts seconds value into format string
 * result is returned in buf
 * Notes:
 *        1. result is in descenting order: 1w2d3h4m5s
 *        2. zero fields are not filled (except for p. 3): 5d1s
 *        3. zero seconds value is presented as "0s"
 */
static char *__sec2str(time_t seconds, char *buf)
{
	const char spec[] = "smhdw";
	const unsigned long mult[] = {1, 60, 60*60, 24*60*60, 7*24*60*60};
	unsigned long c;
	char *tail = buf;
	int i;

	for (i = ARRAY_SIZE(mult) - 1 ; i >= 0; i--) {
		c = seconds / mult[i];

		if (c > 0 || (i == 0 && buf == tail))
			tail += scnprintf(tail, 40-(tail-buf), "%lu%c", c,
					  spec[i]);

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
			      bool human_readable, bool show_default)
{
	if (show_default) {
		printf("Disk default %s quota:\n", qtype_name(qctl->qc_type));
		printf("%15s %8s%8s%8s %8s%8s%8s\n",
		       "Filesystem", "bquota", "blimit", "bgrace",
		       "iquota", "ilimit", "igrace");
	} else {
		printf("Disk quotas for %s %s (%cid %u):\n",
		       qtype_name(qctl->qc_type), name,
		       *qtype_name(qctl->qc_type), qctl->qc_id);
		printf("%15s%8s %7s%8s%8s%8s %7s%8s%8s\n",
		       "Filesystem", human_readable ? "used" : "kbytes",
		       "quota", "limit", "grace",
		       "files", "quota", "limit", "grace");
	}
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

#ifdef HAVE_NATIVE_CLIENT
/* In the current Lustre implementation, the grace time is either the time
 * or the timestamp to be used after some quota ID exceeds the soft limt,
 * 48 bits should be enough, its high 16 bits can be used as quota flags.
 */
#define LQUOTA_GRACE_BITS	48
#define LQUOTA_GRACE_MASK	((1ULL << LQUOTA_GRACE_BITS) - 1)
#define LQUOTA_GRACE_MAX	LQUOTA_GRACE_MASK
#define LQUOTA_GRACE(t)		(t & LQUOTA_GRACE_MASK)
#define LQUOTA_FLAG(t)		(t >> LQUOTA_GRACE_BITS)
#define LQUOTA_GRACE_FLAG(t, f)	((__u64)t | (__u64)f << LQUOTA_GRACE_BITS)
#endif

#define STRBUF_LEN	24
static void print_quota(char *mnt, struct if_quotactl *qctl, int type,
			int rc, bool h, bool show_default)
{
	time_t now;

	time(&now);

	if (qctl->qc_cmd == LUSTRE_Q_GETQUOTA || qctl->qc_cmd == Q_GETOQUOTA ||
	    qctl->qc_cmd == LUSTRE_Q_GETQUOTAPOOL ||
	    qctl->qc_cmd == LUSTRE_Q_GETDEFAULT ||
	    qctl->qc_cmd == LUSTRE_Q_GETDEFAULT_POOL) {
		int bover = 0, iover = 0;
		struct obd_dqblk *dqb = &qctl->qc_dqblk;
		char numbuf[3][STRBUF_LEN + 2]; /* 2 for brackets or wildcard */
		char timebuf[40];
		char strbuf[STRBUF_LEN];

		if (dqb->dqb_bhardlimit &&
		    lustre_stoqb(dqb->dqb_curspace) >= dqb->dqb_bhardlimit) {
			bover = 1;
		} else if (dqb->dqb_bsoftlimit && dqb->dqb_btime) {
			if (dqb->dqb_btime > now)
				bover = 2;
			else
				bover = 3;
		}

		if (dqb->dqb_ihardlimit &&
		    dqb->dqb_curinodes >= dqb->dqb_ihardlimit) {
			iover = 1;
		} else if (dqb->dqb_isoftlimit && dqb->dqb_itime) {
			if (dqb->dqb_itime > now)
				iover = 2;
			else
				iover = 3;
		}

		if (strlen(mnt) > 15)
			printf("%s\n%15s", mnt, "");
		else
			printf("%15s", mnt);

		if (bover)
			diff2str(dqb->dqb_btime, timebuf, now);
		else if (show_default)
			snprintf(timebuf, sizeof(timebuf), "%llu",
				 (unsigned long long)dqb->dqb_btime);

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

		if (show_default)
			printf(" %6s %7s %7s", numbuf[1], numbuf[2], timebuf);
		else
			printf(" %7s%c %6s %7s %7s",
			       numbuf[0], bover ? '*' : ' ', numbuf[1],
			       numbuf[2], bover > 1 ? timebuf : "-");

		if (iover)
			diff2str(dqb->dqb_itime, timebuf, now);
		else if (show_default)
			snprintf(timebuf, sizeof(timebuf), "%llu",
				 (unsigned long long)dqb->dqb_itime);

		snprintf(numbuf[0], sizeof(numbuf),
			 (dqb->dqb_valid & QIF_INODES) ? "%ju" : "[%ju]",
			 (uintmax_t)dqb->dqb_curinodes);

		if (type == QC_GENERAL)
			sprintf(numbuf[1], (dqb->dqb_valid & QIF_ILIMITS) ?
				"%ju" : "[%ju]",
				(uintmax_t)dqb->dqb_isoftlimit);
		else
			sprintf(numbuf[1], "%s", "-");

		sprintf(numbuf[2], (dqb->dqb_valid & QIF_ILIMITS) ?
			"%ju" : "[%ju]", (uintmax_t)dqb->dqb_ihardlimit);

		if (show_default)
			printf(" %6s %7s %7s", numbuf[1], numbuf[2], timebuf);
		else if (type != QC_OSTIDX)
			printf(" %7s%c %6s %7s %7s",
			       numbuf[0], iover ? '*' : ' ', numbuf[1],
			       numbuf[2], iover > 1 ? timebuf : "-");
		else
			printf(" %7s %7s %7s %7s", "-", "-", "-", "-");
		printf("\n");
	} else if (qctl->qc_cmd == LUSTRE_Q_GETINFO || LUSTRE_Q_GETINFOPOOL ||
		   qctl->qc_cmd == Q_GETOINFO) {
		char bgtimebuf[40];
		char igtimebuf[40];

		if (qctl->qc_dqinfo.dqi_bgrace == NOTIFY_GRACE_TIME)
			strncpy(bgtimebuf, NOTIFY_GRACE, 40);
		else
			sec2str(qctl->qc_dqinfo.dqi_bgrace, bgtimebuf, rc);
		if (qctl->qc_dqinfo.dqi_igrace == NOTIFY_GRACE_TIME)
			strncpy(igtimebuf, NOTIFY_GRACE, 40);
		else
			sec2str(qctl->qc_dqinfo.dqi_igrace, igtimebuf, rc);

		printf("Block grace time: %s; Inode grace time: %s\n",
		       bgtimebuf, igtimebuf);
	}
}

static int tgt_name2index(const char *tgtname, unsigned int *idx)
{
	char *dash, *endp;

	/* format is "lustre-OST0001" */
	dash = memchr(tgtname, '-', LUSTRE_MAXFSNAME + 1);
	if (!dash) {
		fprintf(stderr, "wrong tgtname format '%s'\n", tgtname);
		return -EINVAL;
	}
	dash += 4;

	*idx = strtoul(dash, &endp, 16);
	if (*idx > 0xffff) {
		fprintf(stderr, "wrong index %s\n", tgtname);
		return -ERANGE;
	}

	return 0;
}

static int print_obd_quota(char *mnt, struct if_quotactl *qctl, int is_mdt,
			   bool h, __u64 *total)
{
	int rc = 0, rc1 = 0, count = 0, i = 0;
	char **list = NULL, *buffer = NULL;
	__u32 valid = qctl->qc_valid;

	if (qctl->qc_cmd == LUSTRE_Q_GETQUOTAPOOL && is_mdt)
		return 0;

	/* Is it correct for the case OST0000, OST0002, OST0003 -
	 * we will ask OST0001 that is absent and won't ask OST0003? */
	rc = llapi_get_obd_count(mnt, &count, is_mdt);
	if (rc) {
		fprintf(stderr, "can not get %s count: %s\n",
			is_mdt ? "mdt" : "ost", strerror(-rc));
		return rc;
	}

	if (qctl->qc_cmd == LUSTRE_Q_GETQUOTAPOOL) {
		char fname[PATH_MAX];
		char fsname[LUSTRE_MAXFSNAME + 1];
		int bufsize = sizeof(struct obd_uuid) * count;

		rc = llapi_search_fsname(mnt, fsname);
		if (rc) {
			fprintf(stderr, "cannot get fsname for mountpoint %s\n",
				mnt);
			goto out;
		}
		buffer = malloc(bufsize + sizeof(*list) * count);
		if (!buffer)
			return -ENOMEM;
		list = (char **)(buffer + bufsize);
		snprintf(fname, PATH_MAX, "%s.%s", fsname, qctl->qc_poolname);
		count = llapi_get_poolmembers(fname, list, count,
					      buffer, bufsize);
		if (count <= 0)
			goto out;
	}

	for (i = 0; i < count; i++) {
		if (qctl->qc_cmd == LUSTRE_Q_GETQUOTAPOOL) {
			unsigned int index;

			if (tgt_name2index(list[i], &index))
				continue;
			qctl->qc_idx = index;
		} else {
			qctl->qc_idx = i;
		}

		qctl->qc_valid = is_mdt ? QC_MDTIDX : QC_OSTIDX;
		rc = llapi_quotactl(mnt, qctl);
		if (rc) {
			/* It is remote client case. */
			if (rc == -EOPNOTSUPP) {
				rc = 0;
				goto out;
			}

			/* no target for this index yet */
			if (rc == -ENODEV) {
				rc = 0;
				continue;
			}

			/* inactive target */
			if (rc == -ENODATA) {
				char name[UUID_MAX+8];

				snprintf(name, sizeof(name), "%s[inact]",
					obd_uuid2str(&qctl->obd_uuid));
				memset(&qctl->qc_dqinfo, 0,
				       sizeof(qctl->qc_dqinfo));
				memset(&qctl->qc_dqblk, 0,
				       sizeof(qctl->qc_dqblk));
				print_quota(name, qctl, qctl->qc_valid, 0, h,
					    false);
				rc = 0;
				continue;
			}

			if (!rc1)
				rc1 = rc;
			fprintf(stderr, "quotactl %s%d failed.\n",
				is_mdt ? "mdt" : "ost", qctl->qc_idx);
			continue;
		}

		print_quota(obd_uuid2str(&qctl->obd_uuid), qctl,
			    qctl->qc_valid, 0, h, false);
		*total += is_mdt ? qctl->qc_dqblk.dqb_ihardlimit :
				   qctl->qc_dqblk.dqb_bhardlimit;
	}
out:
	if (buffer)
		free(buffer);
	qctl->qc_valid = valid;
	return rc ? : rc1;
}

static int get_print_quota(char *mnt, char *name, struct if_quotactl *qctl,
			   int verbose, int quiet, bool human_readable,
			   bool show_default)
{
	int rc1 = 0, rc2 = 0, rc3 = 0;
	char *obd_type = (char *)qctl->obd_type;
	char *obd_uuid = (char *)qctl->obd_uuid.uuid;
	__u64 total_ialloc = 0, total_balloc = 0;
	bool use_default_for_blk = false;
	bool use_default_for_file = false;
	int inacc;

	rc1 = llapi_quotactl(mnt, qctl);
	if (rc1 < 0) {
		switch (rc1) {
		case -ESRCH:
			fprintf(stderr, "%s quotas are not enabled.\n",
				qtype_name(qctl->qc_type));
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

	if (!show_default && qctl->qc_id == 0) {
		qctl->qc_dqblk.dqb_bhardlimit = 0;
		qctl->qc_dqblk.dqb_bsoftlimit = 0;
		qctl->qc_dqblk.dqb_ihardlimit = 0;
		qctl->qc_dqblk.dqb_isoftlimit = 0;
		qctl->qc_dqblk.dqb_btime = 0;
		qctl->qc_dqblk.dqb_itime = 0;
		qctl->qc_dqblk.dqb_valid |= QIF_LIMITS | QIF_TIMES;
	}

	if (qctl->qc_dqblk.dqb_valid & QIF_BTIME &&
	    LQUOTA_FLAG(qctl->qc_dqblk.dqb_btime) & LQUOTA_FLAG_DEFAULT) {
		use_default_for_blk = true;
		qctl->qc_dqblk.dqb_btime &= LQUOTA_GRACE_MASK;
	}

	if (qctl->qc_dqblk.dqb_valid & QIF_ITIME &&
	    LQUOTA_FLAG(qctl->qc_dqblk.dqb_itime) & LQUOTA_FLAG_DEFAULT) {
		use_default_for_file = true;
		qctl->qc_dqblk.dqb_itime &= LQUOTA_GRACE_MASK;
	}

	if ((qctl->qc_cmd == LUSTRE_Q_GETQUOTA ||
	     qctl->qc_cmd == LUSTRE_Q_GETQUOTAPOOL ||
	     qctl->qc_cmd == LUSTRE_Q_GETDEFAULT_POOL ||
	     qctl->qc_cmd == LUSTRE_Q_GETDEFAULT) && !quiet)
		print_quota_title(name, qctl, human_readable, show_default);

	if (rc1 && *obd_type)
		fprintf(stderr, "%s %s ", obd_type, obd_uuid);

	if (qctl->qc_valid != QC_GENERAL)
		mnt = "";

	inacc = (qctl->qc_cmd == LUSTRE_Q_GETQUOTA ||
		 qctl->qc_cmd == LUSTRE_Q_GETQUOTAPOOL) &&
		((qctl->qc_dqblk.dqb_valid & (QIF_LIMITS|QIF_USAGE)) !=
		 (QIF_LIMITS|QIF_USAGE));

	print_quota(mnt, qctl, QC_GENERAL, rc1, human_readable, show_default);

	if (!show_default && verbose &&
	    qctl->qc_valid == QC_GENERAL && qctl->qc_cmd != LUSTRE_Q_GETINFO &&
	    qctl->qc_cmd != LUSTRE_Q_GETINFOPOOL) {
		char strbuf[STRBUF_LEN];

		rc2 = print_obd_quota(mnt, qctl, 1, human_readable,
				      &total_ialloc);
		rc3 = print_obd_quota(mnt, qctl, 0, human_readable,
				      &total_balloc);
		kbytes2str(total_balloc, strbuf, sizeof(strbuf),
			   human_readable);
		printf("Total allocated inode limit: %ju, total allocated block limit: %s\n",
		       (uintmax_t)total_ialloc, strbuf);
	}

	if (use_default_for_blk)
		printf("%cid %u is using default block quota setting\n",
		       *qtype_name(qctl->qc_type), qctl->qc_id);

	if (use_default_for_file)
		printf("%cid %u is using default file quota setting\n",
		       *qtype_name(qctl->qc_type), qctl->qc_id);

	if (rc1 || rc2 || rc3 || inacc)
		printf("Some errors happened when getting quota info. Some devices may be not working or deactivated. The data in \"[]\" is inaccurate.\n");
out:
	if (rc1)
		return rc1;
	if (rc2)
		return rc2;
	if (rc3)
		return rc3;
	if (inacc)
		return -EIO;

	return 0;
}

static int lfs_project(int argc, char **argv)
{
	int ret = 0, err = 0, c, i;
	struct project_handle_control phc = { 0 };
	enum lfs_project_ops_t op;

	phc.newline = true;
	phc.assign_projid = false;
	/* default action */
	op = LFS_PROJECT_LIST;

	while ((c = getopt(argc, argv, "p:cCsdkr0")) != -1) {
		switch (c) {
		case 'c':
			if (op != LFS_PROJECT_LIST) {
				fprintf(stderr,
					"%s: cannot specify '-c' '-C' '-s' together\n",
					progname);
				return CMD_HELP;
			}

			op = LFS_PROJECT_CHECK;
			break;
		case 'C':
			if (op != LFS_PROJECT_LIST) {
				fprintf(stderr,
					"%s: cannot specify '-c' '-C' '-s' together\n",
					progname);
				return CMD_HELP;
			}

			op = LFS_PROJECT_CLEAR;
			break;
		case 's':
			if (op != LFS_PROJECT_LIST) {
				fprintf(stderr,
					"%s: cannot specify '-c' '-C' '-s' together\n",
					progname);
				return CMD_HELP;
			}

			phc.set_inherit = true;
			op = LFS_PROJECT_SET;
			break;
		case 'd':
			phc.dironly = true;
			break;
		case 'k':
			phc.keep_projid = true;
			break;
		case 'r':
			phc.recursive = true;
			break;
		case 'p':
			if (str2quotaid(&phc.projid, optarg)) {
				fprintf(stderr,
					"Invalid project ID: %s\n",
					optarg);
				return CMD_HELP;
			}

			phc.assign_projid = true;

			break;
		case '0':
			phc.newline = false;
			break;
		default:
			fprintf(stderr, "%s: invalid option '%c'\n",
				progname, optopt);
			return CMD_HELP;
		}
	}

	if (phc.assign_projid && op == LFS_PROJECT_LIST) {
		op = LFS_PROJECT_SET;
		phc.set_projid = true;
	} else if (phc.assign_projid && op == LFS_PROJECT_SET) {
		phc.set_projid = true;
	}

	switch (op) {
	case LFS_PROJECT_CHECK:
		if (phc.keep_projid) {
			fprintf(stderr,
				"%s: '-k' is useless together with '-c'\n",
				progname);
			return CMD_HELP;
		}
		break;
	case LFS_PROJECT_CLEAR:
		if (!phc.newline) {
			fprintf(stderr,
				"%s: '-0' is useless together with '-C'\n",
				progname);
			return CMD_HELP;
		}
		if (phc.assign_projid) {
			fprintf(stderr,
				"%s: '-p' is useless together with '-C'\n",
				progname);
			return CMD_HELP;
		}
		break;
	case LFS_PROJECT_SET:
		if (!phc.newline) {
			fprintf(stderr,
				"%s: '-0' is useless together with '-s'\n",
				progname);
			return CMD_HELP;
		}
		if (phc.keep_projid) {
			fprintf(stderr,
				"%s: '-k' is useless together with '-s'\n",
				progname);
			return CMD_HELP;
		}
		break;
	default:
		if (!phc.newline) {
			fprintf(stderr,
				"%s: '-0' is useless for list operations\n",
				progname);
			return CMD_HELP;
		}
		break;
	}

	argv += optind;
	argc -= optind;
	if (argc == 0) {
		fprintf(stderr, "%s: missing file or directory target(s)\n",
			progname);
		return CMD_HELP;
	}

	for (i = 0; i < argc; i++) {
		switch (op) {
		case LFS_PROJECT_CHECK:
			err = lfs_project_check(argv[i], &phc);
			break;
		case LFS_PROJECT_LIST:
			err = lfs_project_list(argv[i], &phc);
			break;
		case LFS_PROJECT_CLEAR:
			err = lfs_project_clear(argv[i], &phc);
			break;
		case LFS_PROJECT_SET:
			err = lfs_project_set(argv[i], &phc);
			break;
		default:
			break;
		}
		if (err && !ret)
			ret = err;
	}

	return ret;
}

static int lfs_quota(int argc, char **argv)
{
	int c;
	char *mnt, *name = NULL;
	struct if_quotactl *qctl;
	char *obd_uuid;
	int rc = 0, rc1 = 0, verbose = 0, quiet = 0;
	__u32 valid = QC_GENERAL, idx = 0;
	bool human_readable = false;
	bool show_default = false;
	int qtype;
	bool show_pools = false;
	struct option long_opts[] = {
	{ .val = LFS_POOL_OPT, .name = "pool", .has_arg = optional_argument },
	{ .name = NULL } };
	char **poollist = NULL;
	char *buf = NULL;
	int poolcount, i;

	qctl = calloc(1, sizeof(*qctl) + LOV_MAXPOOLNAME + 1);
	if (!qctl)
		return -ENOMEM;

	qctl->qc_cmd = LUSTRE_Q_GETQUOTA;
	qctl->qc_type = ALLQUOTA;
	obd_uuid = (char *)qctl->obd_uuid.uuid;

	while ((c = getopt_long(argc, argv, "gGi:I:o:pPqtuUvh",
		long_opts, NULL)) != -1) {
		switch (c) {
		case 'U':
			show_default = true;
		case 'u':
			qtype = USRQUOTA;
			goto quota_type;
		case 'G':
			show_default = true;
		case 'g':
			qtype = GRPQUOTA;
			goto quota_type;
		case 'P':
			show_default = true;
		case 'p':
			qtype = PRJQUOTA;
quota_type:
			if (qctl->qc_type != ALLQUOTA) {
				fprintf(stderr,
					"%s quota: only one of -u, -g, or -p may be specified\n",
					progname);
				rc = CMD_HELP;
				goto out;
			}
			qctl->qc_type = qtype;
			break;
		case 't':
			qctl->qc_cmd = LUSTRE_Q_GETINFO;
			break;
		case 'o':
			valid = qctl->qc_valid = QC_UUID;
			snprintf(obd_uuid, sizeof(*obd_uuid), "%s", optarg);
			break;
		case 'i':
			valid = qctl->qc_valid = QC_MDTIDX;
			idx = qctl->qc_idx = atoi(optarg);
			if (idx == 0 && *optarg != '0') {
				fprintf(stderr,
					"%s quota: invalid MDT index '%s'\n",
					progname, optarg);
				rc = CMD_HELP;
				goto out;
			}
			break;
		case 'I':
			valid = qctl->qc_valid = QC_OSTIDX;
			idx = qctl->qc_idx = atoi(optarg);
			if (idx == 0 && *optarg != '0') {
				fprintf(stderr,
					"%s quota: invalid OST index '%s'\n",
					progname, optarg);
				rc = CMD_HELP;
				goto out;
			}
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
		case LFS_POOL_OPT:
			if ((!optarg) && (argv[optind] != NULL) &&
				(argv[optind][0] != '-') &&
				(argv[optind][0] != '/')) {
				optarg = argv[optind++];
				if (lfs_verify_poolarg(optarg)) {
					rc = -EINVAL;
					goto out;
				}
				strncpy(qctl->qc_poolname, optarg,
					LOV_MAXPOOLNAME);
				if (qctl->qc_cmd == LUSTRE_Q_GETINFO)
					qctl->qc_cmd = LUSTRE_Q_GETINFOPOOL;
				else
					qctl->qc_cmd = LUSTRE_Q_GETQUOTAPOOL;
				break;
			}

			/* optarg is NULL */
			show_pools = true;
			qctl->qc_cmd = LUSTRE_Q_GETQUOTAPOOL;
			break;
		default:
			fprintf(stderr, "%s quota: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			rc = CMD_HELP;
			goto out;
		}
	}

	/* current uid/gid info for "lfs quota /path/to/lustre/mount" */
	if ((qctl->qc_cmd == LUSTRE_Q_GETQUOTA ||
	     qctl->qc_cmd == LUSTRE_Q_GETQUOTAPOOL) &&
	     qctl->qc_type == ALLQUOTA &&
	     optind == argc - 1 && !show_default) {
		qctl->qc_idx = idx;

		for (qtype = USRQUOTA; qtype <= GRPQUOTA; qtype++) {
			qctl->qc_type = qtype;
			qctl->qc_valid = valid;
			if (qtype == USRQUOTA) {
				qctl->qc_id = geteuid();
				rc = uid2name(&name, qctl->qc_id);
			} else {
				qctl->qc_id = getegid();
				rc = gid2name(&name, qctl->qc_id);
				memset(&qctl->qc_dqblk, 0,
				       sizeof(qctl->qc_dqblk));
			}
			if (rc)
				name = "<unknown>";
			mnt = argv[optind];
			rc1 = get_print_quota(mnt, name, qctl, verbose, quiet,
					      human_readable, show_default);
			if (rc1 && !rc)
				rc = rc1;
		}
		goto out;
	/* lfs quota -u username /path/to/lustre/mount */
	} else if (qctl->qc_cmd == LUSTRE_Q_GETQUOTA ||
		   qctl->qc_cmd == LUSTRE_Q_GETQUOTAPOOL) {
		/* options should be followed by u/g-name and mntpoint */
		if ((!show_default && optind + 2 != argc) ||
		    (show_default && optind + 1 != argc) ||
		    qctl->qc_type == ALLQUOTA) {
			fprintf(stderr,
				"%s quota: name and mount point must be specified\n",
				progname);
			rc = CMD_HELP;
			goto out;
		}

		if (!show_default) {
			name = argv[optind++];
			switch (qctl->qc_type) {
			case USRQUOTA:
				rc = name2uid(&qctl->qc_id, name);
				break;
			case GRPQUOTA:
				rc = name2gid(&qctl->qc_id, name);
				break;
			case PRJQUOTA:
				rc = name2projid(&qctl->qc_id, name);
				break;
			default:
				rc = -ENOTSUP;
				break;
			}
		} else {
			qctl->qc_valid = QC_GENERAL;
			qctl->qc_cmd = qctl->qc_cmd == LUSTRE_Q_GETQUOTAPOOL ?
					LUSTRE_Q_GETDEFAULT_POOL :
					LUSTRE_Q_GETDEFAULT;
			qctl->qc_id = 0;
		}

		if (rc) {
			if (str2quotaid(&qctl->qc_id, name)) {
				fprintf(stderr, "%s quota: invalid id '%s'\n",
					progname, name);
				rc = CMD_HELP;
				goto out;
			}
		}
	} else if (optind + 1 != argc || qctl->qc_type == ALLQUOTA) {
		fprintf(stderr, "%s quota: missing quota info argument(s)\n",
			progname);
		rc = CMD_HELP;
		goto out;
	}

	mnt = argv[optind];
	if (show_pools) {
		char *p;

		i = 0;
		rc = llapi_get_poolbuf(mnt, &buf, &poollist, &poolcount);
		if (rc)
			goto out;

		for (i = 0; i < poolcount; i++) {
			p = memchr(poollist[i], '.', MAXNAMLEN);
			if (!p) {
				fprintf(stderr, "bad string format %.*s\n",
					MAXNAMLEN, poollist[i]);
				rc = -EINVAL;
				goto out;
			}
			p++;
			printf("Quotas for pool: %s\n", p);
			strncpy(qctl->qc_poolname, p, LOV_MAXPOOLNAME);
			rc = get_print_quota(mnt, name, qctl, verbose, quiet,
					     human_readable, show_default);
			if (rc)
				break;
		}
		goto out;
	}

	rc = get_print_quota(mnt, name, qctl, verbose, quiet,
			     human_readable, show_default);
out:
	free(buf);
	free(qctl);
	return rc;
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
	int     kdestroy = 0, reap = 0, c;
	char    mntdir[PATH_MAX] = {'\0'};
	int     index = 0;
	int     rc = 0;

	while ((c = getopt(argc, argv, "kr")) != -1) {
		switch (c) {
		case 'k':
			kdestroy = 1;
			break;
		case 'r':
			reap = 1;
			break;
		default:
			fprintf(stderr,
				"error: %s: option '-%c' unrecognized\n",
				argv[0], c);
			return CMD_HELP;
		}
	}

	if (kdestroy) {
		rc = system("kdestroy > /dev/null");
		if (rc) {
			rc = WEXITSTATUS(rc);
			fprintf(stderr,
				"error destroying tickets: %d, continuing\n",
				rc);
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

	if (reap) {
		rc = system("keyctl reap > /dev/null");
		if (rc != 0) {
			rc = WEXITSTATUS(rc);
			fprintf(stderr, "error reaping keyring: %d\n", rc);
		}
	}

	return rc;
}

static int lfs_changelog(int argc, char **argv)
{
	void *changelog_priv;
	struct changelog_rec *rec;
	long long startrec = 0, endrec = 0;
	char *mdd;
	struct option long_opts[] = {
		{ .val = 'f', .name = "follow", .has_arg = no_argument },
		{ .name = NULL } };
	char short_opts[] = "f";
	int rc, follow = 0;

	while ((rc = getopt_long(argc, argv, short_opts,
		long_opts, NULL)) != -1) {
		switch (rc) {
		case 'f':
			follow++;
			break;
		default:
			fprintf(stderr,
				"%s changelog: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			return CMD_HELP;
		}
	}
	if (optind >= argc) {
		fprintf(stderr, "%s changelog: mdtname must be specified\n",
			progname);
		return CMD_HELP;
	}

	mdd = argv[optind++];
	if (argc > optind) {
		errno = 0;
		startrec = strtoll(argv[optind++], NULL, 10);
		if (errno != 0 || startrec < 0) {
			fprintf(stderr,
				"%s changelog: bad startrec\n",
				progname);
			return CMD_HELP;
		}
	}

	if (argc > optind) {
		errno = 0;
		endrec = strtoll(argv[optind++], NULL, 10);
		if (errno != 0 || endrec < 0) {
			fprintf(stderr,
				"%s changelog: bad endrec\n",
				progname);
			return CMD_HELP;
		}
	}

	rc = llapi_changelog_start(&changelog_priv,
				   CHANGELOG_FLAG_BLOCK |
				   CHANGELOG_FLAG_JOBID |
				   CHANGELOG_FLAG_EXTRA_FLAGS |
				   (follow ? CHANGELOG_FLAG_FOLLOW : 0),
				   mdd, startrec);
	if (rc < 0) {
		fprintf(stderr, "%s changelog: cannot start changelog: %s\n",
			progname, strerror(errno = -rc));
		return rc;
	}

	rc = llapi_changelog_set_xflags(changelog_priv,
					CHANGELOG_EXTRA_FLAG_UIDGID |
					CHANGELOG_EXTRA_FLAG_NID |
					CHANGELOG_EXTRA_FLAG_OMODE |
					CHANGELOG_EXTRA_FLAG_XATTR);
	if (rc < 0) {
		fprintf(stderr,
			"%s changelog: cannot set xflags for changelog: %s\n",
			progname, strerror(errno = -rc));
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

		if (rec->cr_flags & CLF_EXTRA_FLAGS) {
			struct changelog_ext_extra_flags *ef =
				changelog_rec_extra_flags(rec);

			printf(" ef=0x%llx",
			       (unsigned long long)ef->cr_extra_flags);

			if (ef->cr_extra_flags & CLFE_UIDGID) {
				struct changelog_ext_uidgid *uidgid =
					changelog_rec_uidgid(rec);

				printf(" u=%llu:%llu",
				       (unsigned long long)uidgid->cr_uid,
				       (unsigned long long)uidgid->cr_gid);
			}
			if (ef->cr_extra_flags & CLFE_NID) {
				struct changelog_ext_nid *nid =
					changelog_rec_nid(rec);

				printf(" nid=%s",
				       libcfs_nid2str(nid->cr_nid));
			}

			if (ef->cr_extra_flags & CLFE_OPEN) {
				struct changelog_ext_openmode *omd =
					changelog_rec_openmode(rec);
				char mode[] = "---";

				/* exec mode must be exclusive */
				if (omd->cr_openflags & MDS_FMODE_EXEC) {
					mode[2] = 'x';
				} else {
					if (omd->cr_openflags & MDS_FMODE_READ)
						mode[0] = 'r';
					if (omd->cr_openflags &
					    (MDS_FMODE_WRITE |
					     MDS_OPEN_TRUNC |
					     MDS_OPEN_APPEND))
						mode[1] = 'w';
				}

				if (strcmp(mode, "---") != 0)
					printf(" m=%s", mode);
			}

			if (ef->cr_extra_flags & CLFE_XATTR) {
				struct changelog_ext_xattr *xattr =
					changelog_rec_xattr(rec);

				if (xattr->cr_xattr[0] != '\0')
					printf(" x=%s", xattr->cr_xattr);
			}
		}

		if (!fid_is_zero(&rec->cr_pfid))
			printf(" p="DFID, PFID(&rec->cr_pfid));
		if (rec->cr_namelen)
			printf(" %.*s", rec->cr_namelen,
			       changelog_rec_name(rec));

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
		fprintf(stderr, "%s changelog: cannot access changelog: %s\n",
			progname, strerror(errno = -rc));

	return (rc == 1 ? 0 : rc);
}

static int lfs_changelog_clear(int argc, char **argv)
{
	long long endrec;
	int rc;

	if (argc != 4)
		return CMD_HELP;

	errno = 0;
	endrec = strtoll(argv[3], NULL, 10);
	if (errno != 0 || endrec < 0) {
		fprintf(stderr,
			"%s: bad endrec '%s'\n",
			argv[0], argv[3]);
		return CMD_HELP;
	}

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

static void rstripc(char *str, int c)
{
	char *end = str + strlen(str);

	for (; str < end && end[-1] == c; --end)
		end[-1] = '\0';
}

static int lfs_fid2path(int argc, char **argv)
{
	struct option long_opts[] = {
		{ .val = 'c',	.name = "cur",	.has_arg = no_argument },
		{ .val = 'c',	.name = "current",	.has_arg = no_argument },
		{ .val = 'c',	.name = "print-link",	.has_arg = no_argument },
		{ .val = 'f',	.name = "print-fid",	.has_arg = no_argument },
		{ .val = 'l',	.name = "link",	.has_arg = required_argument },
		{ .name = NULL } };
	char short_opts[] = "cfl:pr:";
	bool print_link = false;
	bool print_fid = false;
	bool print_mnt_dir;
	char mnt_dir[PATH_MAX] = "";
	int mnt_fd = -1;
	char *path_or_fsname;
	long long recno = -1;
	int linkno = -1;
	char *endptr = NULL;
	int rc = 0;
	int c;
	int i;

	while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			print_link = true;
			break;
		case 'f':
			print_fid = true;
			break;
		case 'l':
			errno = 0;
			linkno = strtol(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || linkno < 0) {
				fprintf(stderr,
					"%s fid2path: invalid linkno '%s'\n",
					progname, optarg);
				return CMD_HELP;
			}
			break;
		case 'r':
			/* recno is something to do with changelogs
			 * that was never implemented. We just pass it
			 * through for the MDT to ignore.
			 */
			errno = 0;
			recno = strtoll(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || recno < 0) {
				fprintf(stderr,
					"%s fid2path: invalid recno '%s'\n",
					progname, optarg);
				return CMD_HELP;
			}
			break;
		default:
			fprintf(stderr,
				"%s fid2path: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			return CMD_HELP;
		}
	}

	if (argc - optind < 2) {
		fprintf(stderr,
			"Usage: %s fid2path FSNAME|ROOT FID...\n",
			progname);
		return CMD_HELP;
	}

	path_or_fsname = argv[optind];

	if (*path_or_fsname == '/') {
		print_mnt_dir = true;
		rc = llapi_search_mounts(path_or_fsname, 0, mnt_dir, NULL);
	} else {
		print_mnt_dir = false;
		rc = llapi_search_rootpath(mnt_dir, path_or_fsname);
	}

	if (rc < 0) {
		fprintf(stderr,
			"%s fid2path: cannot resolve mount point for '%s': %s\n",
			progname, path_or_fsname, strerror(-rc));
		goto out;
	}

	mnt_fd = open(mnt_dir, O_RDONLY | O_DIRECTORY);
	if (mnt_fd < 0) {
		fprintf(stderr,
			"%s fid2path: cannot open mount point for '%s': %s\n",
			progname, path_or_fsname, strerror(-rc));
		goto out;
	}

	/* Strip trailing slashes from mnt_dir. */
	rstripc(mnt_dir + 1, '/');

	for (i = optind + 1; i < argc; i++) {
		const char *fid_str = argv[i];
		struct lu_fid fid;
		int rc2;

		rc2 = llapi_fid_parse(fid_str, &fid, NULL);
		if (rc2 < 0) {
			fprintf(stderr,
				"%s fid2path: invalid FID '%s'\n",
				progname, fid_str);
			if (rc == 0)
				rc = rc2;

			continue;
		}

		int linktmp = (linkno >= 0) ? linkno : 0;
		while (1) {
			int oldtmp = linktmp;
			long long rectmp = recno;
			char path_buf[PATH_MAX];

			rc2 = llapi_fid2path_at(mnt_fd, &fid,
				path_buf, sizeof(path_buf), &rectmp, &linktmp);
			if (rc2 < 0) {
				fprintf(stderr,
					"%s fid2path: cannot find %s %s: %s\n",
					progname, path_or_fsname, fid_str,
					strerror(-rc2));
				if (rc == 0)
					rc = rc2;
				break;
			}

			if (print_fid)
				printf("%s ", fid_str);

			if (print_link)
				printf("%d ", linktmp);

			/* You may think this looks wrong or weird (and it is!)
			 * but we are actually trying to preserve the old quirky
			 * behaviors (enforced by our old quirky tests!) that
			 * make lfs so much fun to work on:
			 *
			 *   lustre 0x200000007:0x1:0x0 => "/"
			 *   /mnt/lustre 0x200000007:0x1:0x0 => "/mnt/lustre//"
			 *
			 * Note that llapi_fid2path() returns "" for the root
			 * FID. */

			printf("%s%s%s\n",
			       print_mnt_dir ? mnt_dir : "",
			       (print_mnt_dir || *path_buf == '\0') ? "/" : "",
			       path_buf);

			if (linkno >= 0)
				/* specified linkno */
				break;

			if (oldtmp == linktmp)
				/* no more links */
				break;
		}
	}
out:
	if (!(mnt_fd < 0))
		close(mnt_fd);

	return rc;
}

static int lfs_path2fid(int argc, char **argv)
{
	struct option long_opts[] = {
		{ .val = 'p', .name = "parents", .has_arg = no_argument },
		{ .name = NULL } };
	char		**path;
	const char	  short_opts[] = "p";
	const char	 *sep = "";
	struct lu_fid	  fid;
	int		  rc = 0;
	bool		  show_parents = false;

	while ((rc = getopt_long(argc, argv, short_opts,
				 long_opts, NULL)) != -1) {
		switch (rc) {
		case 'p':
			show_parents = true;
			break;
		default:
			fprintf(stderr,
				"%s path2fid: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			return CMD_HELP;
		}
	}

	if (optind > argc - 1) {
		fprintf(stderr, "%s path2fid: FILE... must be specified\n",
			progname);
		return CMD_HELP;
	} else if (optind < argc - 1) {
		sep = ": ";
	}

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
			fprintf(stderr,
				"%s path2fid: cannot get %sfid for '%s': %s\n",
				progname, show_parents ? "parent " : "", *path,
				strerror(-err));
			if (rc == 0) {
				rc = err;
				errno = -err;
			}
		}
	}

	return rc;
}

#define MAX_ERRNO	4095
#define IS_ERR_VALUE(x) ((unsigned long)(x) >= (unsigned long)-MAX_ERRNO)

static int lfs_rmfid_and_show_errors(const char *device, struct fid_array *fa)
{
	int rc, rc2, k;

	rc = llapi_rmfid(device, fa);
	if (rc < 0) {
		fprintf(stderr, "%s rmfid: cannot remove FIDs: %s\n",
			progname, strerror(-rc));
		return rc;
	}

	for (k = 0; k < fa->fa_nr; k++) {
		rc2 = (__s32)fa->fa_fids[k].f_ver;
		if (!IS_ERR_VALUE(rc2))
			continue;

		if (rc == 0)
			rc = rc2;

		fa->fa_fids[k].f_ver = 0;
		fprintf(stderr, "%s rmfid: cannot remove "DFID": %s\n",
			progname, PFID(&fa->fa_fids[k]), strerror(-rc2));
	}

	return rc;
}

static int lfs_rmfid(int argc, char **argv)
{
	char *fidstr, *device;
	int rc = 0, rc2, nr;
	struct fid_array *fa;

	if (optind > argc - 1) {
		fprintf(stderr, "%s rmfid: missing dirname\n", progname);
		return CMD_HELP;
	}

	device = argv[optind++];

	nr = argc - optind;
	fa = malloc(offsetof(struct fid_array, fa_fids[nr + 1]));
	if (!fa)
		return -ENOMEM;

	fa->fa_nr = 0;
	rc = 0;
	while (optind < argc) {
		int found;

		fidstr = argv[optind++];
		while (*fidstr == '[')
			fidstr++;
		found = sscanf(fidstr, SFID, RFID(&fa->fa_fids[fa->fa_nr]));
		if (found != 3) {
			fprintf(stderr, "unrecognized FID: %s\n",
				argv[optind - 1]);
			exit(1);
		}
		fa->fa_nr++;
		if (fa->fa_nr == OBD_MAX_FIDS_IN_ARRAY) {
			/* start another batch */
			rc2 = lfs_rmfid_and_show_errors(device, fa);
			if (rc2 && !rc)
				rc = rc2;
			fa->fa_nr = 0;
		}
	}
	if (fa->fa_nr) {
		rc2 = lfs_rmfid_and_show_errors(device, fa);
		if (rc2 && !rc)
			rc = rc2;
	}

	return rc;
}

static int lfs_data_version(int argc, char **argv)
{
	int data_version_flags = LL_DV_RD_FLUSH; /* Read by default */
	__u64 data_version;
	char *path;
	int fd;
	int rc;
	int c;

	if (argc < 2) {
		fprintf(stderr, "%s: FILE must be specified\n",
			progname);
		return CMD_HELP;
	}

	while ((c = getopt(argc, argv, "hnrw")) != -1) {
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
			fprintf(stderr,
				"%s data_version: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}
	if (optind == argc) {
		fprintf(stderr, "%s data_version: FILE must be specified\n",
			progname);
		return CMD_HELP;
	}

	path = argv[optind];
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		rc = -errno;
		fprintf(stderr, "%s data_version: cannot open file '%s': %s\n",
			progname, path, strerror(-rc));
		return rc;
	}

	rc = llapi_get_data_version(fd, &data_version, data_version_flags);
	if (rc < 0)
		fprintf(stderr,
			"%s data_version: cannot get version for '%s': %s\n",
			progname, path, strerror(-rc));
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
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'i',	.name = "archive-id",	.has_arg = required_argument },
	{ .val = 'l',	.name = "lost",		.has_arg = no_argument },
	{ .val = 'r',	.name = "norelease",	.has_arg = no_argument },
	{ .name = NULL } };
	__u64 mask = 0;
	int c, rc;
	char *path;
	__u32 archive_id = 0;
	char *end = NULL;

	if (argc < 3)
		return CMD_HELP;

	while ((c = getopt_long(argc, argv, "aAdehi:lr",
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
			errno = 0;
			archive_id = strtol(optarg, &end, 10);
			if (errno != 0 || *end != '\0' || archive_id < 0) {
				fprintf(stderr,
					"%s: invalid archive_id: '%s'\n",
					progname, end);
				return CMD_HELP;
			}
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
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
	/*
	 * Checking for regular file as archiving as posix copytool
	 * rejects archiving files other than regular files
	 */
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "error: \"%s\" is not a regular file\n", file);
		return CMD_HELP;
	}
	/* A request should be ... */
	if (*last_dev != st.st_dev && *last_dev != 0) {
		fprintf(stderr,
			"All files should be on the same filesystem: %s\n",
			file);
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

	if (mntpath) {
		rc = llapi_fid_parse(fname, &hui->hui_fid, NULL);
		if (rc)
			fprintf(stderr, "hsm: '%s' is not a valid FID\n",
				fname);
	} else {
		rc = lfs_hsm_prepare_file(fname, &hui->hui_fid, last_dev);
	}

	if (rc == 0)
		hur->hur_request.hr_itemcount++;

	return rc;
}

static int lfs_hsm_request(int argc, char **argv, int action)
{
	struct option long_opts[] = {
	{ .val = 'a',	.name = "archive",	.has_arg = required_argument },
	{ .val = 'D',	.name = "data",		.has_arg = required_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'l',	.name = "filelist",	.has_arg = required_argument },
	{ .val = 'm',	.name = "mntpath",	.has_arg = required_argument },
	{ .name = NULL } };
	dev_t last_dev = 0;
	struct hsm_user_request *hur, *oldhur;
	int c, i;
	size_t len;
	int nbfile;
	char *line = NULL;
	char *filelist = NULL;
	char fullpath[PATH_MAX];
	char *opaque = NULL;
	int opaque_len = 0;
	int archive_id = 0;
	FILE *fp;
	int nbfile_alloc = 0;
	char *some_file = NULL;
	char *mntpath = NULL;
	int rc;

	if (argc < 2)
		return CMD_HELP;

	while ((c = getopt_long(argc, argv, "a:D:hl:m:",
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
					"error: -a is supported only when archiving or removing\n");
				return CMD_HELP;
			}
			archive_id = atoi(optarg);
			break;
		case 'm':
			if (!some_file) {
				mntpath = optarg;
				some_file = strdup(optarg);
			}
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}

	/* All remaining args are files, so we have at least nbfile */
	nbfile = argc - optind;

	if ((nbfile == 0) && (!filelist))
		return CMD_HELP;

	if (opaque)
		opaque_len = strlen(opaque);

	/*
	 * Alloc the request structure with enough place to store all files
	 * from command line.
	 */
	hur = llapi_hsm_user_request_alloc(nbfile, opaque_len);
	if (!hur) {
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
	if (filelist) {
		fp = fopen(filelist, "r");
		if (!fp) {
			fprintf(stderr, "Cannot read the file list %s: %s\n",
				filelist, strerror(errno));
			rc = -errno;
			goto out_free;
		}

		while ((rc = getline(&line, &len, fp)) != -1) {
			/*
			 * If allocated buffer was too small, get something
			 * larger
			 */
			if (nbfile_alloc <= hur->hur_request.hr_itemcount) {
				ssize_t size;

				nbfile_alloc = nbfile_alloc * 2 + 1;
				oldhur = hur;
				hur = llapi_hsm_user_request_alloc(nbfile_alloc,
								   opaque_len);
				if (!hur) {
					fprintf(stderr,
						"hsm: cannot allocate the request: %s\n",
						strerror(errno));
					hur = oldhur;
					rc = -errno;
					fclose(fp);
					goto out_free;
				}
				size = hur_len(oldhur);
				if (size < 0) {
					fprintf(stderr,
						"hsm: cannot allocate %u files + %u bytes data\n",
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

			if (!some_file) {
				some_file = line;
				line = NULL;
			}
		}

		rc = fclose(fp);
		free(line);
	}

	/* If a --data was used, add it to the request */
	hur->hur_request.hr_data_len = opaque_len;
	if (opaque)
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

static const char *const lock_mode_names[] = LOCK_MODE_NAMES;

int lfs_get_mode(const char *string)
{
	enum lock_mode_user mode;

	for (mode = 0; mode < ARRAY_SIZE(lock_mode_names); mode++) {
		if (lock_mode_names[mode] == NULL)
			continue;
		if (strcasecmp(string, lock_mode_names[mode]) == 0)
			return mode;
	}

	return -EINVAL;
}

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
	struct option long_opts[] = {
	{ .val = 'a',	.name = "advice",	.has_arg = required_argument },
	{ .val = 'b',	.name = "background",	.has_arg = no_argument },
	{ .val = 'e',	.name = "end",		.has_arg = required_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'l',	.name = "length",	.has_arg = required_argument },
	{ .val = 'm',	.name = "mode",		.has_arg = required_argument },
	{ .val = 's',	.name = "start",	.has_arg = required_argument },
	{ .val = 'u',	.name = "unset",	.has_arg = no_argument },
	{ .name = NULL } };
	struct llapi_lu_ladvise advice;
	enum lu_ladvise_type advice_type = LU_LADVISE_INVALID;
	unsigned long long start = 0;
	unsigned long long end = LUSTRE_EOF;
	unsigned long long length = 0;
	unsigned long long size_units;
	unsigned long long flags = 0;
	int c, fd, rc = 0;
	const char *path;
	int mode = 0;

	optind = 0;
	while ((c = getopt_long(argc, argv, "a:be:hl:m:s:u",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'a':
			advice_type = lfs_get_ladvice(optarg);
			if (advice_type == LU_LADVISE_INVALID) {
				fprintf(stderr,
					"%s: invalid advice type '%s'\n",
					progname, optarg);
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
		case 'u':
			flags |= LF_UNSET;
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
				fprintf(stderr,
					"%s: bad start offset '%s'\n",
					argv[0], optarg);
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
		case 'm':
			mode = lfs_get_mode(optarg);
			if (mode < 0) {
				fprintf(stderr,
					"%s: bad mode '%s', valid modes are READ or WRITE\n",
					argv[0], optarg);
				return CMD_HELP;
			}
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
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

	if (advice_type == LU_LADVISE_LOCKNOEXPAND) {
		fprintf(stderr,
			"%s: Lock no expand advice is a per file descriptor advice, so when called from lfs, it does nothing.\n",
			argv[0]);
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

	if (advice_type != LU_LADVISE_LOCKAHEAD && mode != 0) {
		fprintf(stderr, "%s: mode is only valid with lockahead\n",
			argv[0]);
		return CMD_HELP;
	}

	if (advice_type == LU_LADVISE_LOCKAHEAD && mode == 0) {
		fprintf(stderr, "%s: mode is required with lockahead\n",
			argv[0]);
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
		if (advice_type == LU_LADVISE_LOCKAHEAD) {
			advice.lla_lockahead_mode = mode;
			advice.lla_peradvice_flags = flags;
		}

		rc2 = llapi_ladvise(fd, flags, 1, &advice);
		close(fd);
		if (rc2 < 0) {
			fprintf(stderr,
				"%s: cannot give advice '%s' to file '%s': %s\n",
				argv[0], ladvise_names[advice_type],
				path, strerror(errno));

			goto next;
		}

next:
		if (rc == 0 && rc2 < 0)
			rc = rc2;
	}
	return rc;
}

static const char *const heat_names[] = LU_HEAT_NAMES;

static int lfs_heat_get(int argc, char **argv)
{
	struct lu_heat *heat;
	int rc = 0, rc2;
	char *path;
	int fd;
	int i;

	if (argc <= 1)
		return CMD_HELP;

	heat = calloc(sizeof(*heat) + sizeof(__u64) * OBD_HEAT_COUNT, 1);
	if (!heat) {
		fprintf(stderr, "%s: memory allocation failed\n", argv[0]);
		return -ENOMEM;
	}

	optind = 1;
	while (optind < argc) {
		path = argv[optind++];

		fd = open(path, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "%s: cannot open file '%s': %s\n",
				argv[0], path, strerror(errno));
			rc2 = -errno;
			goto next;
		}

		heat->lh_count = OBD_HEAT_COUNT;
		rc2 = llapi_heat_get(fd, heat);
		close(fd);
		if (rc2 < 0) {
			fprintf(stderr,
				"%s: cannot get heat of file '%s': %s\n",
				argv[0], path, strerror(errno));
			goto next;
		}

		printf("flags: %x\n", heat->lh_flags);
		for (i = 0; i < heat->lh_count; i++)
			printf("%s: %llu\n", heat_names[i],
			       (unsigned long long)heat->lh_heat[i]);
next:
		if (rc == 0 && rc2 < 0)
			rc = rc2;
	}

	free(heat);
	return rc;
}

static int lfs_heat_set(int argc, char **argv)
{
	struct option long_opts[] = {
	{ .val = 'c',	.name = "clear",	.has_arg = no_argument },
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'o',	.name = "off",		.has_arg = no_argument },
	{ .val = 'O',	.name = "on",		.has_arg = no_argument },
	{ .name = NULL } };
	enum lu_heat_flag flags = 0;
	int rc = 0, rc2;
	char *path;
	int fd;
	int c;

	if (argc <= 1)
		return CMD_HELP;

	optind = 0;
	while ((c = getopt_long(argc, argv, "choO", long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			flags |= LU_HEAT_FLAG_CLEAR;
			break;
		case 'o':
			flags |= LU_HEAT_FLAG_CLEAR;
			flags |= LU_HEAT_FLAG_OFF;
			break;
		case 'O':
			flags &= ~LU_HEAT_FLAG_OFF;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}

	if (argc <= optind) {
		fprintf(stderr, "%s: please give one or more file names\n",
			argv[0]);
		return CMD_HELP;
	}

	while (optind < argc) {
		path = argv[optind++];

		fd = open(path, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "%s: cannot open file '%s': %s\n",
				argv[0], path, strerror(errno));
			rc2 = -errno;
			goto next;
		}

		rc2 = llapi_heat_set(fd, flags);
		close(fd);
		if (rc2 < 0) {
			fprintf(stderr,
				"%s: cannot setflags heat of file '%s': %s\n",
				argv[0], path, strerror(errno));
			goto next;
		}
next:
		if (rc == 0 && rc2 < 0)
			rc = rc2;
	}
	return rc;
}

/**
 * The input string contains a comma delimited list of component ids and
 * ranges, for example "1,2-4,7".
 */
static int parse_mirror_ids(__u16 *ids, int size, char *arg)
{
	bool end_of_loop = false;
	char *ptr = NULL;
	int nr = 0;
	int rc;

	if (!arg)
		return -EINVAL;

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

		for (i = start_index; i <= end_index && size > 0; i++) {
			int j;

			/* remove duplicate */
			for (j = 0; j < nr; j++) {
				if (ids[j] == i)
					break;
			}
			if (j == nr) { /* no duplicate */
				ids[nr++] = i;
				--size;
			}
		}

		if (size == 0 && i < end_index)
			break;

		*ptr = ',';
		arg = ++ptr;
		rc = 0;
	}
	if (!end_of_loop && ptr)
		*ptr = ',';

	return rc < 0 ? rc : nr;
}

/**
 * struct verify_mirror_id - Mirror id to be verified.
 * @mirror_id:   A specified mirror id.
 * @is_valid_id: @mirror_id is valid or not in the mirrored file.
 */
struct verify_mirror_id {
	__u16 mirror_id;
	bool is_valid_id;
};

/**
 * compare_mirror_ids() - Compare mirror ids.
 * @layout: Mirror component list.
 * @cbdata: Callback data in verify_mirror_id structure.
 *
 * This is a callback function called by llapi_layout_comp_iterate()
 * to compare the specified mirror id with the one in the current
 * component of @layout. If they are the same, then the specified
 * mirror id is valid.
 *
 * Return: a negative error code on failure or
 *	   LLAPI_LAYOUT_ITER_CONT: Proceed iteration
 *	   LLAPI_LAYOUT_ITER_STOP: Stop iteration
 */
static inline
int compare_mirror_ids(struct llapi_layout *layout, void *cbdata)
{
	struct verify_mirror_id *mirror_id_cbdata =
				 (struct verify_mirror_id *)cbdata;
	uint32_t mirror_id;
	int rc = 0;

	rc = llapi_layout_mirror_id_get(layout, &mirror_id);
	if (rc < 0) {
		rc = -errno;
		fprintf(stderr,
			"%s: llapi_layout_mirror_id_get failed: %s.\n",
			progname, strerror(errno));
		return rc;
	}

	if (mirror_id_cbdata->mirror_id == mirror_id) {
		mirror_id_cbdata->is_valid_id = true;
		return LLAPI_LAYOUT_ITER_STOP;
	}

	return LLAPI_LAYOUT_ITER_CONT;
}

/**
 * verify_mirror_ids() - Verify specified mirror ids.
 * @fname:      Mirrored file name.
 * @mirror_ids: Specified mirror ids to be verified.
 * @ids_nr:     Number of specified mirror ids.
 *
 * This function verifies that specified @mirror_ids are valid
 * in the mirrored file @fname.
 *
 * Return: 0 on success or a negative error code on failure.
 */
static inline
int verify_mirror_ids(const char *fname, __u16 *mirror_ids, int ids_nr)
{
	struct llapi_layout *layout = NULL;
	struct verify_mirror_id mirror_id_cbdata = { 0 };
	struct stat stbuf;
	uint32_t flr_state;
	int i;
	int fd;
	int rc = 0;
	int rc2 = 0;

	if (ids_nr <= 0)
		return -EINVAL;

	if (stat(fname, &stbuf) < 0) {
		fprintf(stderr, "%s: cannot stat file '%s': %s.\n",
			progname, fname, strerror(errno));
		rc = -errno;
		goto error;
	}

	if (!S_ISREG(stbuf.st_mode)) {
		fprintf(stderr, "%s: '%s' is not a regular file.\n",
			progname, fname);
		rc = -EINVAL;
		goto error;
	}

	fd = open(fname, O_DIRECT | O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: cannot open '%s': %s.\n",
			progname, fname, strerror(errno));
		rc = -errno;
		goto error;
	}

	rc = llapi_lease_acquire(fd, LL_LEASE_RDLCK);
	if (rc < 0) {
		fprintf(stderr, "%s: '%s' llapi_lease_acquire failed: %s.\n",
			progname, fname, strerror(errno));
		goto close_fd;
	}

	layout = llapi_layout_get_by_fd(fd, 0);
	if (!layout) {
		fprintf(stderr, "%s: '%s' llapi_layout_get_by_fd failed: %s.\n",
			progname, fname, strerror(errno));
		rc = -errno;
		llapi_lease_release(fd);
		goto close_fd;
	}

	rc = llapi_layout_flags_get(layout, &flr_state);
	if (rc < 0) {
		fprintf(stderr, "%s: '%s' llapi_layout_flags_get failed: %s.\n",
			progname, fname, strerror(errno));
		rc = -errno;
		goto free_layout;
	}

	flr_state &= LCM_FL_FLR_MASK;
	switch (flr_state) {
	case LCM_FL_NONE:
		rc = -EINVAL;
		fprintf(stderr, "%s: '%s' file state error: %s.\n",
			progname, fname, llapi_layout_flags_string(flr_state));
		goto free_layout;
	default:
		break;
	}

	rc2 = 0;
	for (i = 0; i < ids_nr; i++) {
		mirror_id_cbdata.mirror_id = mirror_ids[i];
		mirror_id_cbdata.is_valid_id = false;

		rc = llapi_layout_comp_iterate(layout, compare_mirror_ids,
					       &mirror_id_cbdata);
		if (rc < 0) {
			rc = -errno;
			fprintf(stderr,
				"%s: '%s' failed to verify mirror id: %u.\n",
				progname, fname, mirror_ids[i]);
			goto free_layout;
		}

		if (!mirror_id_cbdata.is_valid_id) {
			rc2 = -EINVAL;
			fprintf(stderr,
				"%s: '%s' invalid specified mirror id: %u.\n",
				progname, fname, mirror_ids[i]);
		}
	}
	rc = rc2;

free_layout:
	llapi_layout_free(layout);
	llapi_lease_release(fd);
close_fd:
	close(fd);
error:
	return rc;
}

static inline
int lfs_mirror_resync_file(const char *fname, struct ll_ioc_lease *ioc,
			   __u16 *mirror_ids, int ids_nr)
{
	struct llapi_resync_comp comp_array[1024] = { { 0 } };
	struct llapi_layout *layout;
	struct stat stbuf;
	uint32_t flr_state;
	uint64_t start;
	uint64_t end;
	int comp_size = 0;
	int idx;
	int fd;
	int rc;
	int rc2;

	if (stat(fname, &stbuf) < 0) {
		fprintf(stderr, "%s: cannot stat file '%s': %s.\n",
			progname, fname, strerror(errno));
		rc = -errno;
		goto error;
	}
	if (!S_ISREG(stbuf.st_mode)) {
		fprintf(stderr, "%s: '%s' is not a regular file.\n",
			progname, fname);
		rc = -EINVAL;
		goto error;
	}

	/* Allow mirror resync even without the key on encrypted files */
	fd = open(fname, O_DIRECT | O_RDWR | O_FILE_ENC);
	if (fd < 0) {
		fprintf(stderr, "%s: cannot open '%s': %s.\n",
			progname, fname, strerror(errno));
		rc = -errno;
		goto error;
	}

	layout = llapi_layout_get_by_fd(fd, 0);
	if (!layout) {
		fprintf(stderr, "%s: '%s' llapi_layout_get_by_fd failed: %s.\n",
			progname, fname, strerror(errno));
		rc = -errno;
		goto close_fd;
	}

	rc = llapi_layout_flags_get(layout, &flr_state);
	if (rc) {
		fprintf(stderr, "%s: '%s' llapi_layout_flags_get failed: %s.\n",
			progname, fname, strerror(errno));
		rc = -errno;
		goto free_layout;
	}

	flr_state &= LCM_FL_FLR_MASK;
	if (flr_state == LCM_FL_NONE) {
		rc = -EINVAL;
		fprintf(stderr, "%s: '%s' is not a FLR file.\n",
			progname, fname);
		goto free_layout;
	}

	/* get stale component info */
	comp_size = llapi_mirror_find_stale(layout, comp_array,
					    ARRAY_SIZE(comp_array),
					    mirror_ids, ids_nr);
	if (comp_size <= 0) {
		rc = comp_size;
		goto free_layout;
	}

	ioc->lil_mode = LL_LEASE_WRLCK;
	ioc->lil_flags = LL_LEASE_RESYNC;
	rc = llapi_lease_set(fd, ioc);
	if (rc < 0) {
		if (rc == -EALREADY)
			rc = 0;
		else
			fprintf(stderr,
			    "%s: '%s' llapi_lease_get_ext resync failed: %s.\n",
				progname, fname, strerror(-rc));
		goto free_layout;
	}

	/* get the read range [start, end) */
	start = comp_array[0].lrc_start;
	end = comp_array[0].lrc_end;
	for (idx = 1; idx < comp_size; idx++) {
		if (comp_array[idx].lrc_start < start)
			start = comp_array[idx].lrc_start;
		if (end < comp_array[idx].lrc_end)
			end = comp_array[idx].lrc_end;
	}

	rc = llapi_lease_check(fd);
	if (rc != LL_LEASE_WRLCK) {
		fprintf(stderr, "%s: '%s' lost lease lock.\n",
			progname, fname);
		goto free_layout;
	}

	rc = llapi_mirror_resync_many(fd, layout, comp_array, comp_size,
				      start, end);
	if (rc < 0)
		fprintf(stderr, "%s: '%s' llapi_mirror_resync_many: %s.\n",
			progname, fname, strerror(-rc));

	rc = migrate_set_timestamps(fd, &stbuf);
	if (rc < 0) {
		fprintf(stderr, "%s: '%s' cannot set timestamps: %s\n",
			progname, fname, strerror(-rc));
		goto free_layout;
	}

	/* need to do the lease unlock even resync fails */
	ioc->lil_mode = LL_LEASE_UNLCK;
	ioc->lil_flags = LL_LEASE_RESYNC_DONE;
	ioc->lil_count = 0;
	for (idx = 0; idx < comp_size; idx++) {
		if (comp_array[idx].lrc_synced) {
			ioc->lil_ids[ioc->lil_count] = comp_array[idx].lrc_id;
			ioc->lil_count++;
		}
	}

	rc2 = llapi_lease_set(fd, ioc);
	/**
	 * llapi_lease_set returns lease mode when it request to unlock
	 * the lease lock.
	 */
	if (rc2 <= 0) {
		/* rc2 == 0 means lost lease lock */
		if (rc2 == 0 && rc == 0)
			rc = -EBUSY;
		else
			rc = rc2;
		fprintf(stderr, "%s: resync file '%s' failed: %s.\n",
			progname, fname,
			rc2 == 0 ? "lost lease lock" : strerror(-rc2));

		llapi_lease_release(fd);
		goto free_layout;
	}

free_layout:
	llapi_layout_free(layout);
close_fd:
	close(fd);
error:
	return rc;
}

static inline int lfs_mirror_resync(int argc, char **argv)
{
	struct option long_opts[] = {
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'o',	.name = "only",		.has_arg = required_argument },
	{ .name = NULL } };
	struct ll_ioc_lease *ioc = NULL;
	__u16 mirror_ids[128] = { 0 };
	int ids_nr = 0;
	int c;
	int rc = 0;

	while ((c = getopt_long(argc, argv, "ho:", long_opts, NULL)) >= 0) {
		switch (c) {
		case 'o':
			rc = parse_mirror_ids(mirror_ids,
					sizeof(mirror_ids) / sizeof(__u16),
					optarg);
			if (rc < 0) {
				fprintf(stderr,
					"%s: bad mirror ids '%s'.\n",
					argv[0], optarg);
				goto error;
			}
			ids_nr = rc;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			rc = CMD_HELP;
			goto error;
		}
	}

	if (argc == optind) {
		fprintf(stderr, "%s: no file name given.\n", argv[0]);
		rc = CMD_HELP;
		goto error;
	}

	if (ids_nr > 0 && argc > optind + 1) {
		fprintf(stderr,
		    "%s: option '--only' cannot be used upon multiple files.\n",
			argv[0]);
		rc = CMD_HELP;
		goto error;
	}

	if (ids_nr > 0) {
		rc = verify_mirror_ids(argv[optind], mirror_ids, ids_nr);
		if (rc < 0)
			goto error;
	}

	/* set the lease on the file */
	ioc = calloc(sizeof(*ioc) + sizeof(__u32) * 4096, 1);
	if (!ioc) {
		fprintf(stderr, "%s: cannot alloc id array for ioc: %s.\n",
			argv[0], strerror(errno));
		rc = -errno;
		goto error;
	}

	for (; optind < argc; optind++) {
		rc = lfs_mirror_resync_file(argv[optind], ioc,
					    mirror_ids, ids_nr);
		/* ignore previous file's error, continue with next file */

		/* reset ioc */
		memset(ioc, 0, sizeof(*ioc) + sizeof(__u32) * 4096);
	}

	free(ioc);
error:
	return rc;
}

static inline int verify_mirror_id_by_fd(int fd, __u16 mirror_id)
{
	struct llapi_layout *layout;
	int rc;

	layout = llapi_layout_get_by_fd(fd, 0);
	if (!layout) {
		fprintf(stderr, "could not get layout.\n");
		return  -EINVAL;
	}

	rc = llapi_layout_comp_iterate(layout, find_mirror_id, &mirror_id);
	if (rc < 0) {
		fprintf(stderr, "failed to iterate layout\n");
		llapi_layout_free(layout);

		return rc;
	} else if (rc == LLAPI_LAYOUT_ITER_CONT) {
		fprintf(stderr, "does not find mirror with ID %u\n", mirror_id);
		llapi_layout_free(layout);

		return -EINVAL;
	}
	llapi_layout_free(layout);

	return 0;
}

/**
 * Check whether two files are the same file
 * \retval	0  same file
 * \retval	1  not the same file
 * \retval	<0 error code
 */
static inline int check_same_file(int fd, const char *f2)
{
	struct stat stbuf1;
	struct stat stbuf2;

	if (fstat(fd, &stbuf1) < 0)
		return -errno;

	if (stat(f2, &stbuf2) < 0)
		return 1;

	if (stbuf1.st_rdev == stbuf2.st_rdev &&
	    stbuf1.st_ino == stbuf2.st_ino)
		return 0;

	return 1;
}

static inline int lfs_mirror_read(int argc, char **argv)
{
	int rc = CMD_HELP;
	__u16 mirror_id = 0;
	const char *outfile = NULL;
	char *fname;
	int fd = 0;
	int outfd;
	int c;
	void *buf;
	const size_t buflen = 4 << 20;
	off_t pos;
	struct option long_opts[] = {
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'N',	.name = "mirror-id",	.has_arg = required_argument },
	{ .val = 'o',	.name = "outfile",	.has_arg = required_argument },
	{ .name = NULL } };

	while ((c = getopt_long(argc, argv, "hN:o:", long_opts, NULL)) >= 0) {
		char *end;

		switch (c) {
		case 'N': {
			unsigned long int id;

			errno = 0;
			id = strtoul(optarg, &end, 0);
			if (errno != 0 || *end != '\0' || id == 0 ||
			    id > UINT16_MAX) {
				fprintf(stderr,
					"%s %s: invalid mirror ID '%s'\n",
					progname, argv[0], optarg);
				return rc;
			}

			mirror_id = (__u16)id;
			break;
		}
		case 'o':
			outfile = optarg;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}

	if (argc == optind) {
		fprintf(stderr, "%s %s: no mirrored file provided\n",
			progname, argv[0]);
		return rc;
	} else if (argc > optind + 1) {
		fprintf(stderr, "%s %s: too many files\n", progname, argv[0]);
		return rc;
	}

	if (mirror_id == 0) {
		fprintf(stderr, "%s %s: no valid mirror ID is provided\n",
			progname, argv[0]);
		return rc;
	}

	/* open mirror file */
	fname = argv[optind];
	fd = open(fname, O_DIRECT | O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s %s: cannot open '%s': %s\n",
			progname, argv[0], fname, strerror(errno));
		return rc;
	}

	/* verify mirror id */
	rc = verify_mirror_id_by_fd(fd, mirror_id);
	if (rc) {
		fprintf(stderr,
			"%s %s: cannot find mirror with ID %u in '%s'\n",
			progname, argv[0], mirror_id, fname);
		goto close_fd;
	}

	/* open output file - O_EXCL ensures output is not the same as input */
	if (outfile) {
		outfd = open(outfile, O_EXCL | O_WRONLY | O_CREAT, 0644);
		if (outfd < 0) {
			fprintf(stderr, "%s %s: cannot create file '%s': %s\n",
				progname, argv[0], outfile, strerror(errno));
			rc = -errno;
			goto close_fd;
		}
	} else {
		outfd = STDOUT_FILENO;
	}

	/* allocate buffer */
	rc = posix_memalign(&buf, sysconf(_SC_PAGESIZE), buflen);
	if (rc) {
		fprintf(stderr, "%s %s: posix_memalign returns %d\n",
				progname, argv[0], rc);
		goto close_outfd;
	}

	pos = 0;
	while (1) {
		ssize_t bytes_read;
		ssize_t written = 0;

		bytes_read = llapi_mirror_read(fd, mirror_id, buf, buflen, pos);
		if (bytes_read < 0) {
			rc = bytes_read;
			fprintf(stderr,
				"%s %s: fail to read data from mirror %u: %s\n",
				progname, argv[0], mirror_id, strerror(-rc));
			goto free_buf;
		}

		/* EOF reached */
		if (bytes_read == 0)
			break;

		while (written < bytes_read) {
			ssize_t written2;

			written2 = write(outfd, buf + written,
					 bytes_read - written);
			if (written2 < 0) {
				fprintf(stderr,
					"%s %s: fail to write %s: %s\n",
					progname, argv[0], outfile ? : "STDOUT",
					strerror(errno));
				rc = -errno;
				goto free_buf;
			}
			written += written2;
		}

		if (written != bytes_read) {
			fprintf(stderr,
		"%s %s: written %ld bytes does not match with %ld read.\n",
				progname, argv[0], written, bytes_read);
			rc = -EIO;
			goto free_buf;
		}

		pos += bytes_read;
	}

	fsync(outfd);
	rc = 0;

free_buf:
	free(buf);
close_outfd:
	if (outfile)
		close(outfd);
close_fd:
	close(fd);

	return rc;
}

static inline int lfs_mirror_write(int argc, char **argv)
{
	int rc = CMD_HELP;
	__u16 mirror_id = 0;
	const char *inputfile = NULL;
	char *fname;
	int fd = 0;
	int inputfd;
	int c;
	void *buf;
	const size_t buflen = 4 << 20;
	off_t pos;
	size_t page_size = sysconf(_SC_PAGESIZE);
	struct ll_ioc_lease_id ioc;
	struct option long_opts[] = {
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'i',	.name = "inputfile",	.has_arg = required_argument },
	{ .val = 'N',	.name = "mirror-id",	.has_arg = required_argument },
	{ .name = NULL } };

	while ((c = getopt_long(argc, argv, "hi:N:", long_opts, NULL)) >= 0) {
		char *end;

		switch (c) {
		case 'N': {
			unsigned long int id;

			errno = 0;
			id = strtoul(optarg, &end, 0);
			if (errno != 0 || *end != '\0' || id == 0 ||
			    id > UINT16_MAX) {
				fprintf(stderr,
					"%s %s: invalid mirror ID '%s'\n",
					progname, argv[0], optarg);
				return rc;
			}

			mirror_id = (__u16)id;
			break;
		}
		case 'i':
			inputfile = optarg;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}

	if (argc == optind) {
		fprintf(stderr, "%s %s: no mirrored file provided\n",
			progname, argv[0]);
		return rc;
	} else if (argc > optind + 1) {
		fprintf(stderr, "%s %s: too many files\n", progname, argv[0]);
		return rc;
	}

	if (mirror_id == 0) {
		fprintf(stderr, "%s %s: no valid mirror ID is provided\n",
			progname, argv[0]);
		return rc;
	}

	/* open mirror file */
	fname = argv[optind];
	fd = open(fname, O_DIRECT | O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "%s %s: cannot open '%s': %s\n",
			progname, argv[0], fname, strerror(errno));
		return rc;
	}

	/* verify mirror id */
	rc = verify_mirror_id_by_fd(fd, mirror_id);
	if (rc) {
		fprintf(stderr,
			"%s %s: cannot find mirror with ID %u in '%s'\n",
			progname, argv[0], mirror_id, fname);
		goto close_fd;
	}

	/* open input file */
	if (inputfile) {
		rc = check_same_file(fd, inputfile);
		if (rc == 0) {
			fprintf(stderr,
			"%s %s: input file cannot be the mirrored file\n",
				progname, argv[0]);
			goto close_fd;
		}
		if (rc < 0)
			goto close_fd;

		inputfd = open(inputfile, O_RDONLY, 0644);
		if (inputfd < 0) {
			fprintf(stderr, "%s %s: cannot open file '%s': %s\n",
				progname, argv[0], inputfile, strerror(errno));
			rc = -errno;
			goto close_fd;
		}
	} else {
		inputfd = STDIN_FILENO;
	}

	/* allocate buffer */
	rc = posix_memalign(&buf, page_size, buflen);
	if (rc) {
		fprintf(stderr, "%s %s: posix_memalign returns %d\n",
			progname, argv[0], rc);
		goto close_inputfd;
	}

	/* prepare target mirror components instantiation */
	ioc.lil_mode = LL_LEASE_WRLCK;
	ioc.lil_flags = LL_LEASE_RESYNC;
	ioc.lil_mirror_id = mirror_id;
	rc = llapi_lease_set(fd, (struct ll_ioc_lease *)&ioc);
	if (rc < 0) {
		fprintf(stderr,
			"%s %s: '%s' llapi_lease_get_ext failed: %s\n",
			progname, argv[0], fname, strerror(errno));
		goto free_buf;
	}

	pos = 0;
	while (1) {
		ssize_t bytes_read;
		ssize_t written;
		size_t to_write;

		rc = llapi_lease_check(fd);
		if (rc != LL_LEASE_WRLCK) {
			fprintf(stderr, "%s %s: '%s' lost lease lock\n",
				progname, argv[0], fname);
			goto free_buf;
		}

		bytes_read = read(inputfd, buf, buflen);
		if (bytes_read < 0) {
			rc = bytes_read;
			fprintf(stderr,
				"%s %s: fail to read data from '%s': %s\n",
				progname, argv[0], inputfile ? : "STDIN",
				strerror(errno));
			rc = -errno;
			goto free_buf;
		}

		/* EOF reached */
		if (bytes_read == 0)
			break;

		/* round up to page align to make direct IO happy. */
		to_write = (bytes_read + page_size - 1) & ~(page_size - 1);

		written = llapi_mirror_write(fd, mirror_id, buf, to_write,
					     pos);
		if (written < 0) {
			rc = written;
			fprintf(stderr,
			      "%s %s: fail to write to mirror %u: %s\n",
				progname, argv[0], mirror_id,
				strerror(-rc));
			goto free_buf;
		}

		pos += bytes_read;
	}

	if (pos & (page_size - 1)) {
		rc = llapi_mirror_truncate(fd, mirror_id, pos);
		if (rc < 0)
			goto free_buf;
	}

	ioc.lil_mode = LL_LEASE_UNLCK;
	ioc.lil_flags = LL_LEASE_RESYNC_DONE;
	ioc.lil_count = 0;
	rc = llapi_lease_set(fd, (struct ll_ioc_lease *)&ioc);
	if (rc <= 0) {
		if (rc == 0)
			rc = -EBUSY;
		fprintf(stderr,
			"%s %s: release lease lock of '%s' failed: %s\n",
			progname, argv[0], fname, strerror(errno));
		goto free_buf;
	}

	rc = 0;

free_buf:
	free(buf);
close_inputfd:
	if (inputfile)
		close(inputfd);
close_fd:
	close(fd);

	return rc;
}

static inline int get_other_mirror_ids(int fd, __u16 *ids, __u16 exclude_id)
{
	struct llapi_layout *layout;
	struct collect_ids_data cid = {	.cid_ids = ids,
					.cid_count = 0,
					.cid_exclude = exclude_id, };
	int rc;

	layout = llapi_layout_get_by_fd(fd, 0);
	if (!layout) {
		fprintf(stderr, "could not get layout\n");
		return -EINVAL;
	}

	rc = llapi_layout_comp_iterate(layout, collect_mirror_id, &cid);
	if (rc < 0) {
		fprintf(stderr, "failed to iterate layout\n");
		llapi_layout_free(layout);

		return rc;
	}
	llapi_layout_free(layout);

	return cid.cid_count;
}

#ifndef MIRROR_ID_NEG
#define MIRROR_ID_NEG         0x8000
#endif

static inline int lfs_mirror_copy(int argc, char **argv)
{
	int rc = CMD_HELP;
	__u16 read_mirror_id = 0;
	__u16 ids[128] = { 0 };
	int count = 0;
	struct llapi_layout *layout = NULL;
	struct llapi_resync_comp comp_array[1024] = { { 0 } };
	int comp_size = 0;
	char *fname;
	int fd = 0;
	int c;
	int i;
	ssize_t copied;
	struct ll_ioc_lease *ioc = NULL;
	struct ll_ioc_lease_id *resync_ioc;
	struct option long_opts[] = {
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'i',	.name = "read-mirror",	.has_arg = required_argument },
	{ .val = 'o',	.name = "write-mirror",	.has_arg = required_argument },
	{ .name = NULL } };
	char cmd[PATH_MAX];

	snprintf(cmd, sizeof(cmd), "%s %s", progname, argv[0]);
	progname = cmd;
	while ((c = getopt_long(argc, argv, "hi:o:", long_opts, NULL)) >= 0) {
		char *end;

		switch (c) {
		case 'i': {
			unsigned long int id;

			errno = 0;
			id = strtoul(optarg, &end, 0);
			if (errno != 0 || *end != '\0' || id == 0 ||
			    id > UINT16_MAX) {
				fprintf(stderr,
					"%s: invalid read mirror ID '%s'\n",
					progname, optarg);
				return rc;
			}

			read_mirror_id = (__u16)id;
			break;
		}
		case 'o':
			if (!strcmp(optarg, "-1")) {
				/* specify all other mirrors */
				ids[0] = (__u16)-1;
				count = 1;
			} else {
				count = parse_mirror_ids((__u16 *)ids,
							 ARRAY_SIZE(ids),
							 optarg);
				if (count < 0)
					return rc;
			}
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}

	if (argc == optind) {
		fprintf(stderr, "%s %s: no mirrored file provided\n",
			progname, argv[0]);
		return rc;
	} else if (argc > optind + 1) {
		fprintf(stderr, "%s %s: too many files\n", progname, argv[0]);
		return rc;
	}

	if (read_mirror_id == 0) {
		fprintf(stderr,
			"%s %s: no valid read mirror ID %d is provided\n",
			progname, argv[0], read_mirror_id);
		return rc;
	}

	if (count == 0) {
		fprintf(stderr,
			"%s %s: no write mirror ID is provided\n",
			progname, argv[0]);
		return rc;
	}

	for (i = 0; i < count; i++) {
		if (read_mirror_id == ids[i]) {
			fprintf(stderr,
			"%s %s: read and write mirror ID cannot be the same\n",
				progname, argv[0]);
			return rc;
		}
	}

	/* open mirror file */
	fname = argv[optind];

	fd = open(fname, O_DIRECT | O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "%s %s: cannot open '%s': %s\n",
			progname, argv[0], fname, strerror(errno));
		return rc;
	}

	/* write to all other mirrors */
	if (ids[0] == (__u16)-1) {
		count = get_other_mirror_ids(fd, ids, read_mirror_id);
		if (count <= 0) {
			rc = count;
			fprintf(stderr,
			"%s %s: failed to get other mirror ids in '%s': %d\n",
				progname, argv[0], fname, rc);
			goto close_fd;
		}
	}

	/* verify mirror id */
	rc = verify_mirror_id_by_fd(fd, read_mirror_id);
	if (rc) {
		fprintf(stderr,
			"%s %s: cannot find mirror with ID %u in '%s'\n",
			progname, argv[0], read_mirror_id, fname);
		goto close_fd;
	}

	for (i = 0; i < count; i++) {
		rc = verify_mirror_id_by_fd(fd, ids[i]);
		if (rc) {
			fprintf(stderr,
			"%s %s: cannot find mirror with ID %u in '%s'\n",
				progname, argv[0], ids[i], fname);
			goto close_fd;
		}
	}

	ioc = calloc(sizeof(*ioc) + sizeof(__u32) * 4096, 1);
	if (!ioc) {
		fprintf(stderr,
			"%s %s: cannot alloc comp id array for ioc: %s\n",
			progname, argv[0], strerror(errno));
		rc = -errno;
		goto close_fd;
	}

	/* get stale component info */
	layout = llapi_layout_get_by_fd(fd, 0);
	if (!layout) {
		fprintf(stderr, "%s %s: failed to get layout of '%s': %s\n",
			progname, argv[0], fname, strerror(errno));
		rc = -errno;
		goto free_ioc;
	}
	comp_size = llapi_mirror_find_stale(layout, comp_array,
					    ARRAY_SIZE(comp_array),
					    ids, count);
	llapi_layout_free(layout);
	if (comp_size < 0) {
		rc = comp_size;
		goto free_ioc;
	}

	/* prepare target mirror components instantiation */
	resync_ioc = (struct ll_ioc_lease_id *)ioc;
	resync_ioc->lil_mode = LL_LEASE_WRLCK;
	resync_ioc->lil_flags = LL_LEASE_RESYNC;
	if (count == 1)
		resync_ioc->lil_mirror_id = ids[0];
	else
		resync_ioc->lil_mirror_id = read_mirror_id | MIRROR_ID_NEG;
	rc = llapi_lease_set(fd, ioc);
	if (rc < 0) {
		fprintf(stderr,
			"%s %s: '%s' llapi_lease_get_ext failed: %s\n",
			progname, argv[0], fname, strerror(errno));
		goto free_ioc;
	}

	copied = llapi_mirror_copy_many(fd, read_mirror_id, ids, count);
	if (copied < 0) {
		rc = copied;
		fprintf(stderr, "%s %s: copy error: %d\n",
			progname, argv[0], rc);
		goto free_ioc;
	}

	fprintf(stdout, "mirror copied successfully: ");
	for (i = 0; i < copied; i++)
		fprintf(stdout, "%d ", ids[i]);
	fprintf(stdout, "\n");

	ioc->lil_mode = LL_LEASE_UNLCK;
	ioc->lil_flags = LL_LEASE_RESYNC_DONE;
	ioc->lil_count = 0;
	for (i = 0; i < comp_size; i++) {
		int j;

		for (j = 0; j < copied; j++) {
			if (comp_array[i].lrc_mirror_id != ids[j])
				continue;

			ioc->lil_ids[ioc->lil_count] = comp_array[i].lrc_id;
			ioc->lil_count++;
		}
	}
	rc = llapi_lease_set(fd, ioc);
	if (rc <= 0) {
		if (rc == 0)
			rc = -EBUSY;
		fprintf(stderr,
			"%s %s: release lease lock of '%s' failed: %s\n",
			progname, argv[0], fname, strerror(errno));
		goto free_ioc;
	}

	rc = 0;

free_ioc:
	free(ioc);
close_fd:
	close(fd);

	return rc;
}

/**
 * struct verify_chunk - Mirror chunk to be verified.
 * @chunk:        [start, end) of the chunk.
 * @mirror_count: Number of mirror ids in @mirror_id array.
 * @mirror_id:    Array of valid mirror ids that cover the chunk.
 */
struct verify_chunk {
	struct lu_extent chunk;
	unsigned int mirror_count;
	__u16 mirror_id[LUSTRE_MIRROR_COUNT_MAX];
};

/**
 * print_chunks() - Print chunk information.
 * @fname:       Mirrored file name.
 * @chunks:      Array of chunks.
 * @chunk_count: Number of chunks in @chunks array.
 *
 * This function prints [start, end) of each chunk in @chunks
 * for mirrored file @fname, and also prints the valid mirror ids
 * that cover the chunk.
 *
 * Return: void.
 */
static inline
void print_chunks(const char *fname, struct verify_chunk *chunks,
		  int chunk_count)
{
	int i;
	int j;

	fprintf(stdout, "Chunks to be verified in %s:\n", fname);
	for (i = 0; i < chunk_count; i++) {
		fprintf(stdout, DEXT, PEXT(&chunks[i].chunk));

		if (chunks[i].mirror_count == 0)
			fprintf(stdout, "\t[");
		else {
			fprintf(stdout, "\t[%u", chunks[i].mirror_id[0]);
			for (j = 1; j < chunks[i].mirror_count; j++)
				fprintf(stdout, ", %u", chunks[i].mirror_id[j]);
		}
		fprintf(stdout, "]\t%u\n", chunks[i].mirror_count);
	}
	fprintf(stdout, "\n");
}

/**
 * print_checksums() - Print CRC-32 checksum values.
 * @chunk: A chunk and its corresponding valid mirror ids.
 * @crc:   CRC-32 checksum values on the chunk for each valid mirror.
 *
 * This function prints CRC-32 checksum values on @chunk for
 * each valid mirror that covers it.
 *
 * Return: void.
 */
static inline
void print_checksums(struct verify_chunk *chunk, unsigned long *crc)
{
	int i;

	fprintf(stdout,
		"CRC-32 checksum value for chunk "DEXT":\n",
		PEXT(&chunk->chunk));
	for (i = 0; i < chunk->mirror_count; i++)
		fprintf(stdout, "Mirror %u:\t%#lx\n",
			chunk->mirror_id[i], crc[i]);
	fprintf(stdout, "\n");
}

/**
 * filter_mirror_id() - Filter specified mirror ids.
 * @chunks:      Array of chunks.
 * @chunk_count: Number of chunks in @chunks array.
 * @mirror_ids:  Specified mirror ids to be verified.
 * @ids_nr:      Number of specified mirror ids.
 *
 * This function scans valid mirror ids that cover each chunk in @chunks
 * and filters specified mirror ids.
 *
 * Return: void.
 */
static inline
void filter_mirror_id(struct verify_chunk *chunks, int chunk_count,
		      __u16 *mirror_ids, int ids_nr)
{
	int i;
	int j;
	int k;
	__u16 valid_id[LUSTRE_MIRROR_COUNT_MAX] = { 0 };
	unsigned int valid_count = 0;

	for (i = 0; i < chunk_count; i++) {
		if (chunks[i].mirror_count == 0)
			continue;

		valid_count = 0;
		for (j = 0; j < ids_nr; j++) {
			for (k = 0; k < chunks[i].mirror_count; k++) {
				if (chunks[i].mirror_id[k] == mirror_ids[j]) {
					valid_id[valid_count] = mirror_ids[j];
					valid_count++;
					break;
				}
			}
		}

		memcpy(chunks[i].mirror_id, valid_id,
		       sizeof(__u16) * valid_count);
		chunks[i].mirror_count = valid_count;
	}
}

/**
 * lfs_mirror_prepare_chunk() - Find mirror chunks to be verified.
 * @layout:      Mirror component list.
 * @chunks:      Array of chunks.
 * @chunks_size: Array size of @chunks.
 *
 * This function scans the components in @layout from offset 0 to LUSTRE_EOF
 * to find out chunk segments and store them in @chunks array.
 *
 * The @mirror_id array in each element of @chunks will store the valid
 * mirror ids that cover the chunk. If a mirror component covering the
 * chunk has LCME_FL_STALE or LCME_FL_OFFLINE flag, then the mirror id
 * will not be stored into the @mirror_id array, and the chunk for that
 * mirror will not be verified.
 *
 * The @mirror_count in each element of @chunks will store the number of
 * mirror ids in @mirror_id array. If @mirror_count is 0, it indicates the
 * chunk is invalid in all of the mirrors. And if @mirror_count is 1, it
 * indicates the chunk is valid in only one mirror. In both cases, the
 * chunk will not be verified.
 *
 * Here is an example:
 *
 *  0      1M     2M     3M     4M           EOF
 *  +------+-------------+--------------------+
 *  |      |             |      S             |       mirror1
 *  +------+------+------+------+-------------+
 *  |             |   S  |   S  |             |       mirror2
 *  +-------------+------+------+-------------+
 *
 * prepared @chunks array will contain 5 elements:
 * (([0, 1M), [1, 2], 2),
 *  ([1M, 2M), [1, 2], 2),
 *  ([2M, 3M), [1], 1),
 *  ([3M, 4M], [], 0),
 *  ([4M, EOF), [2], 1))
 *
 * Return: the actual array size of @chunks on success
 *	   or a negative error code on failure.
 */
static inline
int lfs_mirror_prepare_chunk(struct llapi_layout *layout,
			     struct verify_chunk *chunks,
			     size_t chunks_size)
{
	uint64_t start;
	uint64_t end;
	uint32_t mirror_id;
	uint32_t flags;
	int idx = 0;
	int i = 0;
	int rc = 0;

	memset(chunks, 0, sizeof(*chunks) * chunks_size);

	while (1) {
		rc = llapi_layout_comp_use(layout, LLAPI_LAYOUT_COMP_USE_FIRST);
		if (rc < 0) {
			fprintf(stderr,
				"%s: move to the first layout component: %s.\n",
				progname, strerror(errno));
			goto error;
		}

		i = 0;
		rc = 0;
		chunks[idx].chunk.e_end = LUSTRE_EOF;
		while (rc == 0) {
			rc = llapi_layout_comp_extent_get(layout, &start, &end);
			if (rc < 0) {
				fprintf(stderr,
					"%s: llapi_layout_comp_extent_get failed: %s.\n",
					progname, strerror(errno));
				goto error;
			}

			if (start > chunks[idx].chunk.e_start ||
			    end <= chunks[idx].chunk.e_start)
				goto next;

			if (end < chunks[idx].chunk.e_end)
				chunks[idx].chunk.e_end = end;

			rc = llapi_layout_comp_flags_get(layout, &flags);
			if (rc < 0) {
				fprintf(stderr,
					"%s: llapi_layout_comp_flags_get failed: %s.\n",
					progname, strerror(errno));
				goto error;
			}

			if (flags & LCME_FL_STALE || flags & LCME_FL_OFFLINE)
				goto next;

			rc = llapi_layout_mirror_id_get(layout, &mirror_id);
			if (rc < 0) {
				fprintf(stderr,
					"%s: llapi_layout_mirror_id_get failed: %s.\n",
					progname, strerror(errno));
				goto error;
			}

			chunks[idx].mirror_id[i] = mirror_id;
			i++;
			if (i >= ARRAY_SIZE(chunks[idx].mirror_id)) {
				fprintf(stderr,
					"%s: mirror_id array is too small.\n",
					progname);
				rc = -EINVAL;
				goto error;
			}

next:
			rc = llapi_layout_comp_use(layout,
						   LLAPI_LAYOUT_COMP_USE_NEXT);
			if (rc < 0) {
				fprintf(stderr,
					"%s: move to the next layout component: %s.\n",
					progname, strerror(errno));
				goto error;
			}
		} /* loop through all components */

		chunks[idx].mirror_count = i;

		if (chunks[idx].chunk.e_end == LUSTRE_EOF)
			break;

		idx++;
		if (idx >= chunks_size) {
			fprintf(stderr, "%s: chunks array is too small.\n",
				progname);
			rc = -EINVAL;
			goto error;
		}

		chunks[idx].chunk.e_start = chunks[idx - 1].chunk.e_end;
	}

error:
	return rc < 0 ? rc : idx + 1;
}

/**
 * lfs_mirror_verify_chunk() - Verify a chunk.
 * @fd:        File descriptor of the mirrored file.
 * @file_size: Size of the mirrored file.
 * @chunk:     A chunk and its corresponding valid mirror ids.
 * @verbose:   Verbose mode.
 *
 * This function verifies a @chunk contains exactly the same data
 * ammong the mirrors that cover it.
 *
 * If @verbose is specified, then the function will print where the
 * differences are if the data do not match. Otherwise, it will
 * just return an error in that case.
 *
 * Return: 0 on success or a negative error code on failure.
 */
static inline
int lfs_mirror_verify_chunk(int fd, size_t file_size,
			    struct verify_chunk *chunk, int verbose)
{
	const size_t buflen = 4 * 1024 * 1024; /* 4M */
	void *buf;
	size_t page_size = sysconf(_SC_PAGESIZE);
	ssize_t bytes_read;
	ssize_t bytes_done;
	size_t count;
	off_t pos;
	unsigned long crc;
	unsigned long crc_array[LUSTRE_MIRROR_COUNT_MAX] = { 0 };
	int i;
	int rc = 0;

	if (file_size == 0)
		return 0;

	rc = posix_memalign(&buf, page_size, buflen);
	if (rc) /* error code is returned directly */
		return -rc;

	if (verbose > 1) {
		fprintf(stdout, "Verifying chunk "DEXT" on mirror:",
			PEXT(&chunk->chunk));
		for (i = 0; i < chunk->mirror_count; i++)
			fprintf(stdout, " %u", chunk->mirror_id[i]);
		fprintf(stdout, "\n");
	}

	bytes_done = 0;
	count = MIN(chunk->chunk.e_end, file_size) - chunk->chunk.e_start;
	pos = chunk->chunk.e_start;
	while (bytes_done < count) {
		/* compute initial CRC-32 checksum */
		crc = crc32(0L, Z_NULL, 0);
		memset(crc_array, 0, sizeof(crc_array));

		bytes_read = 0;
		for (i = 0; i < chunk->mirror_count; i++) {
			bytes_read = llapi_mirror_read(fd, chunk->mirror_id[i],
						       buf, buflen, pos);
			if (bytes_read < 0) {
				rc = bytes_read;
				fprintf(stderr,
					"%s: failed to read data from mirror %u: %s.\n",
					progname, chunk->mirror_id[i],
					strerror(-rc));
				goto error;
			}

			/* compute new CRC-32 checksum */
			crc_array[i] = crc32(crc, buf, bytes_read);
		}

		if (verbose)
			print_checksums(chunk, crc_array);

		/* compare CRC-32 checksum values */
		for (i = 1; i < chunk->mirror_count; i++) {
			if (crc_array[i] != crc_array[0]) {
				rc = -EINVAL;

				fprintf(stderr,
					"%s: chunk "DEXT" has different checksum value on mirror %u and mirror %u.\n",
					progname, PEXT(&chunk->chunk),
					chunk->mirror_id[0],
					chunk->mirror_id[i]);
			}
		}

		pos += bytes_read;
		bytes_done += bytes_read;
	}

	if (verbose > 1 && rc == 0) {
		fprintf(stdout, "Verifying chunk "DEXT" on mirror:",
			PEXT(&chunk->chunk));
		for (i = 0; i < chunk->mirror_count; i++)
			fprintf(stdout, " %u", chunk->mirror_id[i]);
		fprintf(stdout, " PASS\n\n");
	}

error:
	free(buf);
	return rc;
}

/**
 * lfs_mirror_verify_file() - Verify a mirrored file.
 * @fname:      Mirrored file name.
 * @mirror_ids: Specified mirror ids to be verified.
 * @ids_nr:     Number of specified mirror ids.
 * @verbose:    Verbose mode.
 *
 * This function verifies that each SYNC mirror of a mirrored file
 * specified by @fname contains exactly the same data.
 *
 * If @mirror_ids is specified, then the function will verify the
 * mirrors specified by @mirror_ids contain exactly the same data.
 *
 * If @verbose is specified, then the function will print where the
 * differences are if the data do not match. Otherwise, it will
 * just return an error in that case.
 *
 * Return: 0 on success or a negative error code on failure.
 */
static inline
int lfs_mirror_verify_file(const char *fname, __u16 *mirror_ids, int ids_nr,
			   int verbose)
{
	struct verify_chunk chunks_array[1024] = { };
	struct llapi_layout *layout = NULL;
	struct stat stbuf;
	uint32_t flr_state;
	int fd;
	int chunk_count = 0;
	int idx = 0;
	int rc = 0;
	int rc1 = 0;
	int rc2 = 0;

	if (stat(fname, &stbuf) < 0) {
		fprintf(stderr, "%s: cannot stat file '%s': %s.\n",
			progname, fname, strerror(errno));
		rc = -errno;
		goto error;
	}

	if (!S_ISREG(stbuf.st_mode)) {
		fprintf(stderr, "%s: '%s' is not a regular file.\n",
			progname, fname);
		rc = -EINVAL;
		goto error;
	}

	if (stbuf.st_size == 0) {
		if (verbose)
			fprintf(stdout, "%s: '%s' file size is 0.\n",
				progname, fname);
		rc = 0;
		goto error;
	}

	/* Allow mirror verify even without the key on encrypted files */
	fd = open(fname, O_DIRECT | O_RDONLY | O_FILE_ENC);
	if (fd < 0) {
		fprintf(stderr, "%s: cannot open '%s': %s.\n",
			progname, fname, strerror(errno));
		rc = -errno;
		goto error;
	}

	rc = llapi_lease_acquire(fd, LL_LEASE_RDLCK);
	if (rc < 0) {
		fprintf(stderr, "%s: '%s' llapi_lease_acquire failed: %s.\n",
			progname, fname, strerror(errno));
		goto close_fd;
	}

	layout = llapi_layout_get_by_fd(fd, 0);
	if (!layout) {
		fprintf(stderr, "%s: '%s' llapi_layout_get_by_fd failed: %s.\n",
			progname, fname, strerror(errno));
		rc = -errno;
		llapi_lease_release(fd);
		goto close_fd;
	}

	rc = llapi_layout_flags_get(layout, &flr_state);
	if (rc < 0) {
		fprintf(stderr, "%s: '%s' llapi_layout_flags_get failed: %s.\n",
			progname, fname, strerror(errno));
		rc = -errno;
		goto free_layout;
	}

	flr_state &= LCM_FL_FLR_MASK;
	switch (flr_state) {
	case LCM_FL_NONE:
		rc = -EINVAL;
		fprintf(stderr, "%s: '%s' file state error: %s.\n",
			progname, fname, llapi_layout_flags_string(flr_state));
		goto free_layout;
	default:
		break;
	}

	/* find out mirror chunks to be verified */
	chunk_count = lfs_mirror_prepare_chunk(layout, chunks_array,
					       ARRAY_SIZE(chunks_array));
	if (chunk_count < 0) {
		rc = chunk_count;
		goto free_layout;
	}

	if (ids_nr > 0)
		/* filter specified mirror ids */
		filter_mirror_id(chunks_array, chunk_count, mirror_ids, ids_nr);

	if (verbose > 2)
		print_chunks(fname, chunks_array, chunk_count);

	for (idx = 0; idx < chunk_count; idx++) {
		if (chunks_array[idx].chunk.e_start >= stbuf.st_size) {
			if (verbose)
				fprintf(stdout,
					"%s: '%s' chunk "DEXT" exceeds file size %#llx: skipped\n",
					progname, fname,
					PEXT(&chunks_array[idx].chunk),
					(unsigned long long)stbuf.st_size);
			break;
		}

		if (chunks_array[idx].mirror_count == 0) {
			fprintf(stderr,
				"%s: '%s' chunk "DEXT" is invalid in all of the mirrors: ",
				progname, fname,
				PEXT(&chunks_array[idx].chunk));
			if (verbose) {
				fprintf(stderr, "skipped\n");
				continue;
			}
			rc = -EINVAL;
			fprintf(stderr, "failed\n");
			goto free_layout;
		}

		if (chunks_array[idx].mirror_count == 1) {
			if (verbose)
				fprintf(stdout,
					"%s: '%s' chunk "DEXT" is only valid in mirror %u: skipped\n",
					progname, fname,
					PEXT(&chunks_array[idx].chunk),
					chunks_array[idx].mirror_id[0]);
			continue;
		}

		rc = llapi_lease_check(fd);
		if (rc != LL_LEASE_RDLCK) {
			fprintf(stderr, "%s: '%s' lost lease lock.\n",
				progname, fname);
			goto free_layout;
		}

		/* verify one chunk */
		rc1 = lfs_mirror_verify_chunk(fd, stbuf.st_size,
					      &chunks_array[idx], verbose);
		if (rc1 < 0) {
			rc2 = rc1;
			if (!verbose) {
				rc = rc1;
				goto free_layout;
			}
		}
	}

	if (rc2 < 0)
		rc = rc2;

free_layout:
	llapi_layout_free(layout);
	llapi_lease_release(fd);
close_fd:
	close(fd);
error:
	return rc;
}

/**
 * lfs_mirror_verify() - Parse and execute lfs mirror verify command.
 * @argc: The count of lfs mirror verify command line arguments.
 * @argv: Array of strings for lfs mirror verify command line arguments.
 *
 * This function parses lfs mirror verify command and verifies the
 * specified mirrored file(s).
 *
 * Return: 0 on success or a negative error code on failure.
 */
static inline int lfs_mirror_verify(int argc, char **argv)
{
	__u16 mirror_ids[LUSTRE_MIRROR_COUNT_MAX] = { 0 };
	int ids_nr = 0;
	int c;
	int verbose = 0;
	int rc = 0;
	int rc1 = 0;
	char cmd[PATH_MAX];

	struct option long_opts[] = {
	{ .val = 'h',	.name = "help",		.has_arg = no_argument },
	{ .val = 'o',	.name = "only",		.has_arg = required_argument },
	{ .val = 'v',	.name = "verbose",	.has_arg = no_argument },
	{ .name = NULL } };

	snprintf(cmd, sizeof(cmd), "%s %s", progname, argv[0]);
	progname = cmd;
	while ((c = getopt_long(argc, argv, "ho:v", long_opts, NULL)) >= 0) {
		switch (c) {
		case 'o':
			rc = parse_mirror_ids(mirror_ids,
					      ARRAY_SIZE(mirror_ids),
					      optarg);
			if (rc < 0) {
				fprintf(stderr,
					"%s: bad mirror ids '%s'.\n",
					progname, optarg);
				goto error;
			}
			ids_nr = rc;
			if (ids_nr < 2) {
				fprintf(stderr,
					"%s: at least 2 mirror ids needed with '--only' option.\n",
					progname);
				rc = CMD_HELP;
				goto error;
			}
			break;
		case 'v':
			verbose++;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			rc = CMD_HELP;
			goto error;
		}
	}

	if (argc == optind) {
		fprintf(stderr, "%s: no file name given.\n", progname);
		rc = CMD_HELP;
		goto error;
	}

	if (ids_nr > 0 && argc > optind + 1) {
		fprintf(stderr,
			"%s: '--only' cannot be used upon multiple files.\n",
			progname);
		rc = CMD_HELP;
		goto error;
	}

	if (ids_nr > 0) {
		rc = verify_mirror_ids(argv[optind], mirror_ids, ids_nr);
		if (rc < 0)
			goto error;
	}

	rc = 0;
	for (; optind < argc; optind++) {
		rc1 = lfs_mirror_verify_file(argv[optind], mirror_ids, ids_nr,
					     verbose);
		if (rc1 < 0)
			rc = rc1;
	}
error:
	return rc;
}

/**
 * lfs_mirror() - Parse and execute lfs mirror commands.
 * @argc: The count of lfs mirror command line arguments.
 * @argv: Array of strings for lfs mirror command line arguments.
 *
 * This function parses lfs mirror commands and performs the
 * corresponding functions specified in mirror_cmdlist[].
 *
 * Return: 0 on success or an error code on failure.
 */
static int lfs_mirror(int argc, char **argv)
{
	char cmd[PATH_MAX];
	int rc = 0;

	setlinebuf(stdout);

	Parser_init("lfs-mirror > ", mirror_cmdlist);

	snprintf(cmd, sizeof(cmd), "%s %s", progname, argv[0]);
	progname = cmd;
	program_invocation_short_name = cmd;
	if (argc > 1)
		rc = Parser_execarg(argc - 1, argv + 1, mirror_cmdlist);
	else
		rc = Parser_commands();

	return rc < 0 ? -rc : rc;
}

static void lustre_som_swab(struct lustre_som_attrs *attrs)
{
#if __BYTE_ORDER == __BIG_ENDIAN
	__swab16s(&attrs->lsa_valid);
	__swab64s(&attrs->lsa_size);
	__swab64s(&attrs->lsa_blocks);
#endif
}

enum lfs_som_type {
	LFS_SOM_SIZE = 0x1,
	LFS_SOM_BLOCKS = 0x2,
	LFS_SOM_FLAGS = 0x4,
	LFS_SOM_ATTR_ALL = LFS_SOM_SIZE | LFS_SOM_BLOCKS |
			   LFS_SOM_FLAGS,
};

static int lfs_getsom(int argc, char **argv)
{
	const char *path;
	struct lustre_som_attrs *attrs;
	char buf[sizeof(*attrs) + 64];
	enum lfs_som_type type = LFS_SOM_ATTR_ALL;
	int rc = 0, c;

	while ((c = getopt(argc, argv, "bfhs")) != -1) {
		switch (c) {
		case 'b':
			type = LFS_SOM_BLOCKS;
			break;
		case 'f':
			type = LFS_SOM_FLAGS;
			break;
		case 's':
			type = LFS_SOM_SIZE;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		fprintf(stderr, "%s: %s\n",
			progname, argc == 0 ? "miss file target" :
			"input more than 2 files");
		return CMD_HELP;
	}

	path = argv[0];
	attrs = (void *)buf;
	rc = lgetxattr(path, "trusted.som", attrs, sizeof(buf));
	if (rc < 0) {
		rc = -errno;
		fprintf(stderr, "%s failed to get som xattr: %s (%d)\n",
			argv[0], strerror(errno), errno);
		return rc;
	}

	lustre_som_swab(attrs);

	switch (type) {
	case LFS_SOM_ATTR_ALL:
		printf("file: %s size: %llu blocks: %llu flags: %x\n",
		       path, (unsigned long long)attrs->lsa_size,
		       (unsigned long long)attrs->lsa_blocks,
		       attrs->lsa_valid);
		break;
	case LFS_SOM_SIZE:
		printf("%llu\n", (unsigned long long)attrs->lsa_size);
		break;
	case LFS_SOM_BLOCKS:
		printf("%llu\n", (unsigned long long)attrs->lsa_blocks);
		break;
	case LFS_SOM_FLAGS:
		printf("%x\n", attrs->lsa_valid);
		break;
	default:
		fprintf(stderr, "%s: unknown option\n", progname);
		return CMD_HELP;
	}

	return 0;
}

/**
 * lfs_mirror_list_commands() - List lfs mirror commands.
 * @argc: The count of command line arguments.
 * @argv: Array of strings for command line arguments.
 *
 * This function lists lfs mirror commands defined in mirror_cmdlist[].
 *
 * Return: 0 on success.
 */
static int lfs_mirror_list_commands(int argc, char **argv)
{
	char buffer[81] = "";

	Parser_list_commands(mirror_cmdlist, buffer, sizeof(buffer),
			     NULL, 0, 4);

	return 0;
}

static int lfs_pcc_attach(int argc, char **argv)
{
	struct option long_opts[] = {
	{ .val = 'h',	.name = "help",	.has_arg = no_argument },
	{ .val = 'i',	.name = "id",	.has_arg = required_argument },
	{ .name = NULL } };
	int c;
	int rc = 0;
	__u32 archive_id = 0;
	const char *path;
	char *end;
	char fullpath[PATH_MAX];
	enum lu_pcc_type type = LU_PCC_READWRITE;

	optind = 0;
	while ((c = getopt_long(argc, argv, "hi:",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'i':
			errno = 0;
			archive_id = strtoul(optarg, &end, 0);
			if (errno != 0 || *end != '\0' ||
			    archive_id == 0 || archive_id > UINT32_MAX) {
				fprintf(stderr,
					"error: %s: bad archive ID '%s'\n",
					progname, optarg);
				return CMD_HELP;
			}
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}

	if (archive_id == 0) {
		fprintf(stderr, "%s: must specify attach ID\n", argv[0]);
		return CMD_HELP;
	}

	if (argc <= optind) {
		fprintf(stderr, "%s: must specify one or more file names\n",
			argv[0]);
		return CMD_HELP;
	}

	while (optind < argc) {
		int rc2;

		path = argv[optind++];
		if (!realpath(path, fullpath)) {
			fprintf(stderr, "%s: could not find path '%s': %s\n",
				argv[0], path, strerror(errno));
			if (rc == 0)
				rc = -EINVAL;
			continue;
		}

		rc2 = llapi_pcc_attach(fullpath, archive_id, type);
		if (rc2 < 0) {
			fprintf(stderr,
				"%s: cannot attach '%s' to PCC with archive ID '%u': %s\n",
				argv[0], path, archive_id, strerror(-rc2));
			if (rc == 0)
				rc = rc2;
		}
	}
	return rc;
}

static int lfs_pcc_attach_fid(int argc, char **argv)
{
	struct option long_opts[] = {
	{ .val = 'h',	.name = "help",	.has_arg = no_argument },
	{ .val = 'i',	.name = "id",	.has_arg = required_argument },
	{ .val = 'm',	.name = "mnt",	.has_arg = required_argument },
	{ .name = NULL } };
	int c;
	int rc = 0;
	__u32 archive_id = 0;
	char *end;
	const char *mntpath = NULL;
	const char *fidstr;
	enum lu_pcc_type type = LU_PCC_READWRITE;

	optind = 0;
	while ((c = getopt_long(argc, argv, "hi:m:",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'i':
			errno = 0;
			archive_id = strtoul(optarg, &end, 0);
			if (errno != 0 || *end != '\0' ||
			    archive_id > UINT32_MAX) {
				fprintf(stderr,
					"error: %s: bad archive ID '%s'\n",
					argv[0], optarg);
				return CMD_HELP;
			}
			break;
		case 'm':
			mntpath = optarg;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}

	if (archive_id == 0) {
		fprintf(stderr, "%s: must specify an archive ID\n", argv[0]);
		return CMD_HELP;
	}

	if (!mntpath) {
		fprintf(stderr, "%s: must specify Lustre mount point\n",
			argv[0]);
		return CMD_HELP;
	}

	if (argc <= optind) {
		fprintf(stderr, "%s: must specify one or more fids\n", argv[0]);
		return CMD_HELP;
	}

	while (optind < argc) {
		int rc2;

		fidstr = argv[optind++];

		rc2 = llapi_pcc_attach_fid_str(mntpath, fidstr,
					       archive_id, type);
		if (rc2 < 0) {
			fprintf(stderr,
				"%s: cannot attach '%s' on '%s' to PCC with archive ID '%u': %s\n",
				argv[0], fidstr, mntpath, archive_id,
				strerror(rc2));
		}
		if (rc == 0 && rc2 < 0)
			rc = rc2;
	}
	return rc;
}

static int lfs_pcc_detach(int argc, char **argv)
{
	struct option long_opts[] = {
	{ .val = 'h',	.name = "help",	.has_arg = no_argument },
	{ .val = 'k',	.name = "keep",	.has_arg = no_argument },
	{ .name = NULL } };
	int c;
	int rc = 0;
	const char *path;
	char fullpath[PATH_MAX];
	__u32 detach_opt = PCC_DETACH_OPT_UNCACHE;

	optind = 0;
	while ((c = getopt_long(argc, argv, "hk",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'k':
			detach_opt = PCC_DETACH_OPT_NONE;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}

	while (optind < argc) {
		int rc2;

		path = argv[optind++];
		if (!realpath(path, fullpath)) {
			fprintf(stderr, "%s: could not find path '%s': %s\n",
				argv[0], path, strerror(errno));
			if (rc == 0)
				rc = -EINVAL;
			continue;
		}

		rc2 = llapi_pcc_detach_file(fullpath, detach_opt);
		if (rc2 < 0) {
			rc2 = -errno;
			fprintf(stderr,
				"%s: cannot detach '%s' from PCC: %s\n",
				argv[0], path, strerror(errno));
			if (rc == 0)
				rc = rc2;
		}
	}
	return rc;
}

static int lfs_pcc_detach_fid(int argc, char **argv)
{
	struct option long_opts[] = {
	{ .val = 'h',	.name = "help",	.has_arg = no_argument },
	{ .val = 'k',	.name = "keep",	.has_arg = no_argument },
	{ .name = NULL } };
	int c;
	int rc = 0;
	const char *fid;
	const char *mntpath;
	__u32 detach_opt = PCC_DETACH_OPT_UNCACHE;

	optind = 0;
	while ((c = getopt_long(argc, argv, "hk",
				long_opts, NULL)) != -1) {
		switch (c) {
		case 'k':
			detach_opt = PCC_DETACH_OPT_NONE;
			break;
		default:
			fprintf(stderr, "%s: unrecognized option '%s'\n",
				progname, argv[optind - 1]);
			fallthrough;
		case 'h':
			return CMD_HELP;
		}
	}

	mntpath = argv[optind++];

	while (optind < argc) {
		int rc2;

		fid = argv[optind++];

		rc2 = llapi_pcc_detach_fid_str(mntpath, fid, detach_opt);
		if (rc2 < 0) {
			fprintf(stderr,
				"%s: cannot detach '%s' on '%s' from PCC: %s\n",
				argv[0], fid, mntpath, strerror(-rc2));
			if (rc == 0)
				rc = rc2;
		}
	}
	return rc;
}

static int lfs_pcc_state(int argc, char **argv)
{
	int rc = 0;
	const char *path;
	char fullpath[PATH_MAX];
	struct lu_pcc_state state;

	optind = 1;

	if (argc <= 1) {
		fprintf(stderr, "%s: must specify one or more file names\n",
			progname);
		return CMD_HELP;
	}

	while (optind < argc) {
		int rc2;

		path = argv[optind++];
		if (!realpath(path, fullpath)) {
			fprintf(stderr, "%s: could not find path '%s': %s\n",
				argv[0], path, strerror(errno));
			if (rc == 0)
				rc = -EINVAL;
			continue;
		}

		rc2 = llapi_pcc_state_get(fullpath, &state);
		if (rc2 < 0) {
			if (rc == 0)
				rc = rc2;
			fprintf(stderr,
				"%s: cannot get PCC state of '%s': %s\n",
				argv[0], path, strerror(-rc2));
			continue;
		}

		printf("file: %s", path);
		printf(", type: %s", pcc_type2string(state.pccs_type));
		if (state.pccs_type == LU_PCC_NONE &&
		    state.pccs_open_count == 0) {
			printf("\n");
			continue;
		}

		printf(", PCC file: %s", state.pccs_path);
		printf(", user number: %u", state.pccs_open_count);
		printf(", flags: %x", state.pccs_flags);
		printf("\n");
	}
	return rc;
}

/**
 * lfs_pcc_list_commands() - List lfs pcc commands.
 * @argc: The count of command line arguments.
 * @argv: Array of strings for command line arguments.
 *
 * This function lists lfs pcc commands defined in pcc_cmdlist[].
 *
 * Return: 0 on success.
 */
static int lfs_pcc_list_commands(int argc, char **argv)
{
	char buffer[81] = "";

	Parser_list_commands(pcc_cmdlist, buffer, sizeof(buffer),
			     NULL, 0, 4);

	return 0;
}

/**
 * lfs_pcc() - Parse and execute lfs pcc commands.
 * @argc: The count of lfs pcc command line arguments.
 * @argv: Array of strings for lfs pcc command line arguments.
 *
 * This function parses lfs pcc commands and performs the
 * corresponding functions specified in pcc_cmdlist[].
 *
 * Return: 0 on success or an error code on failure.
 */
static int lfs_pcc(int argc, char **argv)
{
	char cmd[PATH_MAX];
	int rc = 0;

	setlinebuf(stdout);

	Parser_init("lfs-pcc > ", pcc_cmdlist);

	snprintf(cmd, sizeof(cmd), "%s %s", progname, argv[0]);
	progname = cmd;
	program_invocation_short_name = cmd;
	if (argc > 1)
		rc = Parser_execarg(argc - 1, argv + 1, pcc_cmdlist);
	else
		rc = Parser_commands();

	return rc < 0 ? -rc : rc;
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
	if (!llapi_liblustreapi_initialized())
		fprintf(stderr, "liblustreapi was not properly initialized\n");

	setlinebuf(stdout);
	opterr = 0;

	Parser_init("lfs > ", cmdlist);

	progname = program_invocation_short_name; /* Used in error messages */
	if (argc > 1) {
		llapi_set_command_name(argv[1]);
		rc = Parser_execarg(argc - 1, argv + 1, cmdlist);
		llapi_clear_command_name();
	} else {
		rc = Parser_commands();
	}

	return rc < 0 ? -rc : rc;
}

#ifdef _LUSTRE_IDL_H_
/* Everything we need here should be included by lustreapi.h. */
# error "lfs should not depend on lustre_idl.h"
#endif /* _LUSTRE_IDL_H_ */
