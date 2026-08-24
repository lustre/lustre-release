/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 *
 * Copyright (c) 2026, The Lustre Collective.
 */

/*
 * What lfs find's command line is made of, in one place.  Nothing here is
 * exported by the library -- the file is compiled into each program that
 * wants it, as callvpe.c is.
 */
#ifndef _LFS_FIND_PARSE_H_
#define _LFS_FIND_PARSE_H_

#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

#include <lustre/lustreapi.h>

/*
 * The parse loop reports through this, as the code it came from did.  Every
 * program compiling this file defines it; declared here rather than reached
 * for through lfs_project.h, which the parser needs nothing else from.
 */
extern const char *progname;

/* how much slack a time predicate allows, in seconds */
#define FP_DEFAULT_TIME_MARGIN (24 * 60 * 60)

/* long-option values, which several lfs subcommands share */
enum {
	LFS_SETQUOTA_DELETE = (CHAR_MAX + 1),
	LFS_POOL_OPT,
	LFS_COMP_COUNT_OPT,
	LFS_COMP_START_OPT,
	LFS_COMP_FLAGS_OPT,
	LFS_COMP_DEL_OPT,
	LFS_COMP_SET_OPT,
	LFS_COMP_ADD_OPT,
	LFS_COMP_NO_VERIFY_OPT,
	LFS_NO_WARN_OPT,
	LFS_EC_STRIPE_COUNT_OPT,
	LFS_EC_EXPERT_OPT,
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
	LFS_PRINTF_LS,
	LFS_NO_FOLLOW_OPT,
	LFS_HEX_IDX_OPT,
	LFS_RESTRIPE_OPT,
	LFS_STATS_OPT,
	LFS_STATS_INTERVAL_OPT,
	LFS_LINKS_OPT,
	LFS_ATTRS_OPT,
	LFS_XATTRS_MATCH_OPT,
	LFS_MIGRATE_NOFIX,
	LFS_QUOTA_FILESYSTEM_OPT,
	LFS_QUOTA_SPACE_OPT,
	LFS_QUOTA_BGRACE_OPT,
	LFS_QUOTA_INODES_OPT,
	LFS_QUOTA_ISOFTLIMIT_OPT,
	LFS_QUOTA_IHARDLIMIT_OPT,
	LFS_QUOTA_IGRACE_OPT,
	LFS_QUOTA_SHOW_ROOT_OPT,
	LFS_FILES_FROM,
	LFS_THREAD_OPT,
	LFS_LUSTRE_DIR,
	LFS_MIN_FREE_OPT,
	LFS_MAX_FREE_OPT,
	LFS_LQA_OPT,
	LFS_QUOTA_DEFAULT_OPT,
	LFS_FORCE_NO_EC_OPT,
	LFS_EC_MAP_OPT,
};

/*
 * Parse lfs find's predicates into @param.  @pathstartp and @pathendp come
 * back as the range of argv that is not an option.  The two spell -1
 * differently: @pathstartp is -1 when there is no path at all, while
 * @pathendp is -1 when no option followed the paths -- the ordinary case
 * for "lfs find -type f /mnt/a /mnt/b" -- and the caller has to read that
 * as argc, or `while (++pathstart < pathend)` walks only the first path.
 * @stopped is set when the parse gave up, which the return value alone does
 * not always say.  All three are written at entry, so none of them reads
 * back what the caller left there.
 *
 * A parse that got as far as an argument may have left heap in @param
 * whether it succeeded or not, so lfs_find_parse_fini() is owed either way.
 *
 * The caller's optind and opterr are both read: optind has to be the index
 * of the first argument to examine, which is what getopt() and
 * cfs_parser_execarg() leave it at -- or 0, which getopt() reads as
 * "reinitialise" and this reads as the 1 getopt() will then start from.
 * opterr has to be 0 or getopt() prints its own diagnostic beside the one
 * this prints.
 *
 * Return: 0 on success, non-zero otherwise.  Treat the value as opaque and
 * test it against zero: the loop propagates whatever its helpers return --
 * CMD_HELP, -1, negative errnos, and regcomp()'s positive codes, which
 * overlap.  Zero alone is not the success test, though: a give-up path that
 * set no code returns it too, so @stopped is what tells the two apart.
 */
int lfs_find_parse(int argc, char **argv, struct find_param *param,
		   int *pathstartp, int *pathendp, bool *stopped);

/*
 * The other half of the contract: what @param has to hold going in.
 *
 * Two fields have to arrive non-zero.  set_time() only widens the margin
 * for a "-mtime +1y" while fp_time_margin is still FP_DEFAULT_TIME_MARGIN,
 * and llapi_find() stops descending where fp_depth == fp_max_depth, so a
 * caller handing over a zeroed structure walks the top directory only and
 * gives "-mtime +1y" a year's margin rather than the default.  This sets
 * fp_max_depth = -1 (no limit), fp_time_margin = FP_DEFAULT_TIME_MARGIN
 * and fp_quiet = 1, and zeroes the rest, so a second front end copies a
 * call rather than an initialiser.
 */
void lfs_find_parse_init(struct find_param *param);

/*
 * Free what lfs_find_parse() allocated in @param: the OST and MDT uuid
 * lists, the -printf format and the --xattr match info with its compiled
 * regexes.  Idempotent, and safe on a param it never reached.
 */
void lfs_find_parse_fini(struct find_param *param);

/* the pieces of that parsing which other lfs subcommands also use */
bool arg_is_eof(char *arg);
uint32_t check_foreign_type_name(const char *foreign_type_name);
enum lmv_hash_type check_hashtype(const char *hashtype);
int comp_str2flags(char *string, __u32 *flags, __u32 *neg_flags);
int name2gid(__u32 *id, const char *name);
int name2projid(__u32 *id, const char *name);
int name2uid(__u32 *id, const char *name);
int str2quotaid(__u32 *id, const char *arg);

#endif /* _LFS_FIND_PARSE_H_ */
