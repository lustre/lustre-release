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
 * version 2 along with this program; if not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2017, DDN Storage Corporation.
 */
/*
 * lustre/utils/llsom_sync.c
 *
 * Tool for sync the LSOM xattr.
 *
 * Author: Qian Yingjin <qian@ddn.com>
 */

#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <linux/unistd.h>
#include <linux/kernel.h>
#include <sys/sysinfo.h>
#include <linux/lustre/lustre_user.h>
#include <lustre/lustreapi.h>
#include <linux/lustre/lustre_idl.h>
#include <linux/lustre/lustre_fid.h>
#include <libcfs/util/hash.h>
#include <libcfs/util/list.h>
#include <libcfs/util/parser.h>

#define container_of(ptr, type, member) ({                      \
	const typeof(((type *) 0)->member) * __mptr = (ptr);     \
	(type *) ((char *) __mptr - offsetof(type, member)); })

#define CHLG_POLL_INTV	60
#define REC_MIN_AGE	600
#define DEF_CACHE_SIZE	(256 * 1048576) /* 256MB */

struct options {
	const char	*o_chlg_user;
	const char	*o_mdtname;
	const char	*o_mntpt;
	bool		 o_daemonize;
	bool		 o_data_sync;
	int		 o_verbose;
	int		 o_intv;
	int		 o_min_age;
	unsigned long	 o_cached_fid_hiwm; /* high watermark */
	unsigned long	 o_batch_sync_cnt;
};

struct options opt;

struct fid_rec {
	struct hlist_node	fr_node;
	struct list_head	fr_link;
	lustre_fid		fr_fid;
	__u64			fr_time;
	__u64			fr_index;
};

static const int fid_hash_shift = 6;

#define FID_HASH_ENTRIES	(1 << fid_hash_shift)
#define FID_ON_HASH(f)		(!hlist_unhashed(&(f)->fr_node))

struct lsom_head {
	struct hlist_head	*lh_hash;
	struct list_head	 lh_list; /* ordered list by record index */
	unsigned long		 lh_cached_count;
} head;

static void usage(char *prog)
{
	printf("\nUsage: %s [options] -u <userid> -m <mdtdev> <mntpt>\n"
	       "options:\n"
	       "\t-d, --daemonize\n"
	       "\t-i, --interval, poll interval in second\n"
	       "\t-a, --min-age, min age before a record is processed.\n"
	       "\t-c, --max-cache, percentage of the memroy used for cache.\n"
	       "\t-s, --sync, data sync when update LSOM xattr\n"
	       "\t-v, --verbose, produce more verbose ouput\n",
	       prog);
	exit(0);
}

static inline bool fid_eq(const lustre_fid *f1, const lustre_fid *f2)
{
	return f1->f_seq == f2->f_seq && f1->f_oid == f2->f_oid &&
	       f1->f_ver == f2->f_ver;
}

static void fid_hash_del(struct fid_rec *f)
{
	if (FID_ON_HASH(f))
		hlist_del_init(&f->fr_node);
}

static void fid_hash_add(struct fid_rec *f)
{
	assert(!FID_ON_HASH(f));
	hlist_add_head(&f->fr_node,
		       &head.lh_hash[llapi_fid_hash(&f->fr_fid,
					      fid_hash_shift)]);
}

static struct fid_rec *fid_hash_find(const lustre_fid *fid)
{
	struct hlist_head *hash_list;
	struct hlist_node *entry, *next;
	struct fid_rec *f;

	hash_list = &head.lh_hash[llapi_fid_hash(fid, fid_hash_shift)];
	hlist_for_each_entry_safe(f, entry, next, hash_list, fr_node) {
		assert(FID_ON_HASH(f));
		if (fid_eq(fid, &f->fr_fid))
			return f;
	}

	return NULL;
}

static int lsom_setup(void)
{
	int i;

	/* set llapi message level */
	llapi_msg_set_level(opt.o_verbose);

	memset(&head, 0, sizeof(head));
	head.lh_hash = malloc(sizeof(struct hlist_head) * FID_HASH_ENTRIES);
	if (head.lh_hash == NULL) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				 "failed to alloc memory for hash (%zu).",
				 sizeof(struct hlist_head) * FID_HASH_ENTRIES);
		return -ENOMEM;
	}

	for (i = 0; i < FID_HASH_ENTRIES; i++)
		INIT_HLIST_HEAD(&head.lh_hash[i]);

	INIT_LIST_HEAD(&head.lh_list);
	return 0;
}

static void lsom_cleanup(void)
{
	free(head.lh_hash);
}

static int lsom_update_one(struct fid_rec *f)
{
	struct stat st;
	int fd;
	int rc = 0;

	fd = llapi_open_by_fid(opt.o_mntpt, &f->fr_fid,
			       O_RDONLY | O_NOATIME);
	if (fd < 0) {
		rc = -errno;

		/* The file may be deleted, clean the corresponding
		 * changelog record and ignore this error.
		 */
		if (rc == -ENOENT)
			goto clean_up;

		llapi_error(LLAPI_MSG_ERROR, rc,
			    "llapi_open_by_fid for " DFID " failed",
			    PFID(&f->fr_fid));
		return rc;
	}

	if (opt.o_data_sync) {
		__u64 dv;

		/* Flush dirty pages from clients */
		rc = llapi_get_data_version(fd, &dv, LL_DV_RD_FLUSH);
		if (rc < 0)
			llapi_error(LLAPI_MSG_ERROR, errno,
				    "failed to sync data for " DFID,
				    PFID(&f->fr_fid));
		/* ignore this error, continue to sync lsom data */
	}

	rc = fstat(fd, &st);
	if (rc < 0) {
		llapi_error(LLAPI_MSG_ERROR, rc, "failed to stat FID: " DFID,
			    PFID(&f->fr_fid));
		return rc;
	}

	/* After call fstat(), it already gets OST attrs to the client,
	 * when close the file, MDS will update the LSOM data itself
	 * according the size and blocks information from the client.
	 */
	close(fd);

	llapi_printf(LLAPI_MSG_DEBUG,
		     "record %llu:%llu, updated LSOM for fid " DFID
		     " size:%lu blocks:%lu\n",
		     (unsigned long long)f->fr_time,
		     (unsigned long long)f->fr_index,
		     PFID(&f->fr_fid), st.st_size, st.st_blocks);

clean_up:
	rc = llapi_changelog_clear(opt.o_mdtname,
				   opt.o_chlg_user, f->fr_index);
	if (rc)
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "failed to clear changelog record: %s:%llu",
			    opt.o_chlg_user, (unsigned long long)f->fr_index);
	return rc;
}

static int lsom_start_update(int count)
{
	int rc = 0;
	int i = 0;

	llapi_printf(LLAPI_MSG_INFO, "Start to sync %d records.\n", count);

	while (i < count) {
		struct fid_rec *f;

		f = list_entry(head.lh_list.next, struct fid_rec, fr_link);
		rc = lsom_update_one(f);
		if (rc == 0) {
			list_del_init(&f->fr_link);
			fid_hash_del(f);
			free(f);
			head.lh_cached_count--;
			i++;
		} else {
			goto out;
		}
	}

out:
	return rc;
}

static int lsom_check_sync(void)
{
	int rc = 0;
	int count;

repeated:
	count = 0;
	if (list_empty(&head.lh_list))
		return 0;

	if (head.lh_cached_count > opt.o_cached_fid_hiwm)
		count = opt.o_batch_sync_cnt;
	else {
		struct fid_rec *f;
		time_t now;

		/* When the first record in the list was not being
		 * processed for a long time (more than o_min_age),
		 * pop the record, start to handle it immediately.
		 */
		now = time(NULL);
		f = list_entry(head.lh_list.next, struct fid_rec, fr_link);
		if (now > ((f->fr_time >> 30) + opt.o_min_age))
			count = 1;
	}

	if (count > 0)
		rc = lsom_start_update(count);

	if (rc == 0 && count == 1)
		goto repeated;

	return rc;
}

static void lsom_sort_record_list(struct fid_rec *f)
{
	struct list_head *pos;
	bool need_move = false;

	for (pos = f->fr_link.next; pos != &head.lh_list; pos = pos->next) {
		struct fid_rec *rec = list_entry(pos, struct fid_rec, fr_link);

		if (f->fr_index > rec->fr_index) {
			need_move = true;
			continue;
		} else {
			break;
		}
	}

	if (need_move)
		list_move_tail(&f->fr_link, pos);
}

static int process_record(struct changelog_rec *rec)
{
	__u64 index = rec->cr_index;
	int rc = 0;

	if (rec->cr_type == CL_CLOSE || rec->cr_type == CL_TRUNC ||
	    rec->cr_type == CL_SETATTR) {
		struct fid_rec *f;

		f = fid_hash_find(&rec->cr_tfid);
		if (f == NULL) {
			f = malloc(sizeof(struct fid_rec));
			if (f == NULL) {
				rc = -ENOMEM;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "failed to alloc memory for fid_rec");
				return rc;
			}

			f->fr_fid = rec->cr_tfid;
			f->fr_index = index;
			f->fr_time = rec->cr_time;
			INIT_HLIST_NODE(&f->fr_node);
			fid_hash_add(f);
			/*
			 * The newly changelog record index is processed in the
			 * ascending order, so it is safe to put the record at
			 * the tail of the ordered list.
			 */
			list_add_tail(&f->fr_link, &head.lh_list);
			head.lh_cached_count++;
		} else {
			f->fr_index = index;
			lsom_sort_record_list(f);
		}
	}

	llapi_printf(LLAPI_MSG_DEBUG,
		     "Processed changelog record index:%llu type:%s(0x%x) FID:"DFID"\n",
		     (unsigned long long)index,
		     changelog_type2str(__le32_to_cpu(rec->cr_type)),
		     __le32_to_cpu(rec->cr_type), PFID(&rec->cr_tfid));

	return rc;
}

static unsigned long get_fid_cache_size(int pct)
{
	struct sysinfo sinfo;
	unsigned long cache_size;
	int rc;

	rc = sysinfo(&sinfo);
	if (rc) {
		llapi_error(LLAPI_MSG_ERROR, rc, "failed to get sysinfo");
		/* ignore this error, just pick some reasonable static
		 * limit for the cache size (e.g. 256MB, default value).
		 */
		cache_size = DEF_CACHE_SIZE;
	} else {
		/* maximum cached fid size is tunned according to total
		 * memory size, e.g. 5% of the memroy.
		 */
		cache_size = sinfo.totalram * pct / 100;
	}

	return cache_size;
}

int main(int argc, char **argv)
{
	int			 c;
	int			 rc;
	void			*chglog_hdlr;
	struct changelog_rec	*rec;
	bool			 stop = 0;
	int			 ret = 0;
	unsigned long		 cache_size = DEF_CACHE_SIZE;
	char			 fsname[MAX_OBD_NAME + 1];
	static struct option options[] = {
		{ "mdt", required_argument, NULL, 'm' },
		{ "user", required_argument, 0, 'u'},
		{ "daemonize", no_argument, NULL, 'd'},
		{ "interval", required_argument, NULL, 'i'},
		{ "min-age", required_argument, NULL, 'a'},
		{ "max-cache", required_argument, NULL, 'c'},
		{ "verbose", no_argument, NULL, 'v'},
		{ "sync", no_argument, NULL, 's'},
		{ "help", no_argument, NULL, 'h' },
		{ NULL }
	};

	memset(&opt, 0, sizeof(opt));
	opt.o_data_sync = false;
	opt.o_verbose = LLAPI_MSG_INFO;
	opt.o_intv = CHLG_POLL_INTV;
	opt.o_min_age = REC_MIN_AGE;

	while ((c = getopt_long(argc, argv, "u:hm:dsi:a:c:v", options, NULL))
	       != EOF) {
		switch (c) {
		default:
			rc = -EINVAL;
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "%s: unknown option '%c'",
				    argv[0], optopt);
			return rc;
		case 'u':
			opt.o_chlg_user = optarg;
			break;
		case 'h':
			usage(argv[0]);
			break;
		case 'm':
			opt.o_mdtname = optarg;
			break;
		case 'd':
			opt.o_daemonize = true;
			break;
		case 'i':
			opt.o_intv = atoi(optarg);
			if (opt.o_intv < 0) {
				rc = -EINVAL;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "bad value for -i %s", optarg);
				return rc;
			}
			break;
		case 'a':
			opt.o_min_age = atoi(optarg);
			if (opt.o_min_age < 0) {
				rc = -EINVAL;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "bad value for -a %s", optarg);
				return rc;
			}
			break;
		case 'c':
			rc = Parser_size(&cache_size, optarg);
			if (rc < 0) {
				rc = -EINVAL;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "bad valud for -c '%s'", optarg);
				return rc;
			}

			/* For value < 100, it is taken as the percentage of
			 * total memory instead.
			 */
			if (cache_size < 100)
				cache_size = get_fid_cache_size(cache_size);
			llapi_printf(LLAPI_MSG_INFO, "Cache size: %lu\n",
				     cache_size);
			break;
		case 'v':
			opt.o_verbose++;
			break;
		case 's':
			opt.o_data_sync = true;
			break;
		}
	}

	if (argc != optind + 1) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "%s: no mount point specified\n", argv[0]);
		usage(argv[0]);
	}

	opt.o_mntpt = argv[optind];
	rc = llapi_search_fsname(opt.o_mntpt, fsname);
	if (rc < 0) {
		llapi_error(LLAPI_MSG_ERROR, rc,
			    "cannot find a Lustre file system mounted at '%s'",
			    opt.o_mntpt);
		return rc;
	}

	if (!opt.o_mdtname)
		usage(argv[0]);

	if (!opt.o_chlg_user)
		usage(argv[0]);

	if (opt.o_daemonize) {
		rc = daemon(1, 1);
		if (rc < 0) {
			rc = -errno;
			llapi_error(LLAPI_MSG_ERROR, rc, "cannot daemonize");
			return rc;
		}

		setbuf(stdout, NULL);
	}

	opt.o_cached_fid_hiwm = cache_size / sizeof(struct fid_rec);
	opt.o_batch_sync_cnt = opt.o_cached_fid_hiwm / 2;

	rc = lsom_setup();
	if (rc < 0)
		return rc;

	while (!stop) {
		bool eof = false;

		llapi_printf(LLAPI_MSG_DEBUG, "Start receiving records\n");
		rc = llapi_changelog_start(&chglog_hdlr,
					   CHANGELOG_FLAG_BLOCK |
					   CHANGELOG_FLAG_JOBID |
					   CHANGELOG_FLAG_EXTRA_FLAGS,
					   opt.o_mdtname, 0);
		if (rc) {
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "unable to open changelog of MDT '%s'",
				    opt.o_mdtname);
			return rc;
		}

		while (!eof && !stop) {
			rc = llapi_changelog_recv(chglog_hdlr, &rec);
			switch (rc) {
			case 0:
				rc = process_record(rec);
				if (rc) {
					llapi_error(LLAPI_MSG_ERROR, rc,
						    "failed to process record");
					ret = rc;
				}

				llapi_changelog_free(&rec);

				rc = lsom_check_sync();
				if (rc) {
					stop = true;
					ret = rc;
				}

				break;
			case 1: /* EOF */
				llapi_printf(LLAPI_MSG_DEBUG,
					     "finished reading [%s]\n",
					     opt.o_mdtname);
				eof = true;
				break;
			case -EINVAL: /* FS unmounted */
			case -EPROTO:  /* error in KUC channel */
			default:
				stop = true;
				llapi_error(LLAPI_MSG_ERROR, rc,
					    "failed to get changelog record");
				ret = rc;
				break;
			}
		}

		/* reach EOF of changelog */
		rc = llapi_changelog_fini(&chglog_hdlr);
		if (rc) {
			llapi_error(LLAPI_MSG_ERROR, rc,
				    "unable to close changelog of MDT '%s'",
				    opt.o_mdtname);
			ret = rc;
			return rc;
		}

		if (opt.o_daemonize) {
			sleep(opt.o_intv);

			rc = lsom_check_sync();
			if (rc) {
				stop = true;
				ret = rc;
			}
		} else {
			lsom_start_update(head.lh_cached_count);
			stop = true;
		}
	}

	lsom_cleanup();
	return ret;
}
