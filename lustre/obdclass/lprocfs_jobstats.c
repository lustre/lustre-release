// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2012, 2016, Intel Corporation.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Niu Yawei <niu@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd_class.h>
#include <lprocfs_status.h>

#ifdef CONFIG_PROC_FS

enum js_info_flags {
	JS_EXPIRED,		/* job is timed out and schedule for removal */
};

#define JOB_CLEANUP_BATCH 1024
/*
 * JobID formats & JobID environment variable names for supported
 * job schedulers:
 *
 * SLURM:
 *   JobID format:  32 bit integer.
 *   JobID env var: SLURM_JOB_ID.
 * SGE:
 *   JobID format:  Decimal integer range to 99999.
 *   JobID env var: JOB_ID.
 * LSF:
 *   JobID format:  6 digit integer by default (up to 999999), can be
 *		  increased to 10 digit (up to 2147483646).
 *   JobID env var: LSB_JOBID.
 * Loadleveler:
 *   JobID format:  String of machine_name.cluster_id.process_id, for
 *		  example: fr2n02.32.0
 *   JobID env var: LOADL_STEP_ID.
 * PBS:
 *   JobID format:  String of sequence_number[.server_name][@server].
 *   JobID env var: PBS_JOBID.
 * Maui/MOAB:
 *   JobID format:  Same as PBS.
 *   JobID env var: Same as PBS.
 */

struct job_stat {
	struct rb_node		js_idnode;	/* js_jobid sorted node */
	struct rb_node		js_posnode;	/* pos sorted node */
	struct list_head	js_lru;		/* on ojs_lru, with ojs_lock */
	unsigned long		js_flags;	/* JS_* flags */
	struct llist_node	js_deleted;	/* on ojs_deleted w/ojs_lock */
	u64			js_pos_id;	/* pos for job stats seq file */
	struct kref		js_refcount;	/* num users of this struct */
	char			js_jobid[LUSTRE_JOBID_SIZE]; /* job name + NUL*/
	ktime_t			js_time_init;	/* time of initial stat*/
	ktime_t			js_time_latest;	/* time of most recent stat*/
	struct lprocfs_stats	*js_stats;	/* per-job statistics */
	struct obd_job_stats	*js_jobstats;	/* for accessing ojs_lock */
	struct rcu_head		js_rcu;		/* RCU head for job_reclaim_rcu*/
};

static void job_reclaim_rcu(struct rcu_head *head)
{
	struct job_stat *job = container_of(head, typeof(*job), js_rcu);
	struct obd_job_stats *stats;

	stats = job->js_jobstats;
	lprocfs_stats_free(&job->js_stats);
	OBD_FREE_PTR(job);
	if (atomic64_dec_and_test(&stats->ojs_jobs))
		clear_bit(OJS_ACTIVE_JOBS, &stats->ojs_flags);
}

static void job_purge_locked(struct obd_job_stats *stats, unsigned int sched)
{
	struct job_stat *job, *n;
	struct llist_node *entry;
	unsigned int count = 0;

	entry = llist_del_all(&stats->ojs_deleted);
	if (!entry)
		return;

	/* ojs_rwsem lock is needed to project rbtree re-balance on erase */
	llist_for_each_entry_safe(job, n, entry, js_deleted) {
		rb_erase(&job->js_posnode, &stats->ojs_postree);
		rb_erase(&job->js_idnode, &stats->ojs_idtree);
		call_rcu(&job->js_rcu, job_reclaim_rcu);

		if (++count == sched) {
			sched = 0;
			up_write(&stats->ojs_rwsem);
			cond_resched();
			down_write(&stats->ojs_rwsem);
		}
	}
}

static void job_free(struct kref *kref)
{
	struct job_stat *job = container_of(kref, struct job_stat, js_refcount);
	struct obd_job_stats *stats;

	LASSERT(job->js_jobstats);

	stats = job->js_jobstats;
	spin_lock(&stats->ojs_lock);
	list_del_rcu(&job->js_lru);
	llist_add(&job->js_deleted, &stats->ojs_deleted);
	spin_unlock(&stats->ojs_lock);
}

static void job_putref(struct job_stat *job)
{
	LASSERT(kref_read(&job->js_refcount) > 0);
	kref_put(&job->js_refcount, job_free);
}

/**
 * Clean up jobstats that were updated more than \a before seconds ago.
 *
 * Since this function may be called frequently, do not scan all of the
 * jobstats on each call, only twice per cleanup interval.  That means stats
 * may be on average around cleanup_interval / 4 older than the cleanup
 * interval, but that is not considered harmful.
 *
 * The value stored in ojs_cleanup_interval is how often to perform a cleanup
 * scan, and 1/2 of the maximum age of the individual statistics.  This is
 * done rather than dividing the interval by two each time, because it is
 * much easier to do the division when the value is initially set (in seconds)
 * rather than after it has been converted to ktime_t, and maybe a bit faster.
 *
 * If \a clear is true then this will force clean up all jobstats
 * (e.g. at shutdown).
 *
 * If there is already another thread doing jobstats cleanup, don't try to
 * do this again in the current thread unless this is a force cleanup.
 *
 * \param[in] stats	stucture tracking all job stats for this device
 * \param[in] clear	clear all job stats if true
 */
static void lprocfs_job_cleanup(struct obd_job_stats *stats, bool clear)
{
	struct job_stat *job;
	ktime_t cleanup_interval = stats->ojs_cleanup_interval;
	ktime_t now = ktime_get_real();
	ktime_t oldest;
	unsigned int sched = JOB_CLEANUP_BATCH;

	if (unlikely(clear)) {
		/* user request or shutdown: block until safe to clear */
		do {
			wait_on_bit(&stats->ojs_flags, OJS_CLEANING,
				    TASK_UNINTERRUPTIBLE);
		} while (test_and_set_bit(OJS_CLEANING, &stats->ojs_flags));
		sched = UINT_MAX;
	} else {
		/* ojs_cleanup_interval of zero means never clean up stats */
		if (ktime_to_ns(cleanup_interval) == 0)
			return;

		if (ktime_before(now, ktime_add(stats->ojs_cleanup_last,
						cleanup_interval)))
			return;

		/* skip if clean is in progress */
		if (test_and_set_bit(OJS_CLEANING, &stats->ojs_flags))
			return;
	}

	cleanup_interval = ktime_add(cleanup_interval, cleanup_interval);
	if (likely(!clear))
		oldest = ktime_sub(now, cleanup_interval);
	else
		oldest = ktime_add(now, cleanup_interval);

	/* remove all jobs older oldest */
	rcu_read_lock();
	list_for_each_entry_rcu(job, &stats->ojs_lru, js_lru) {
		if (!ktime_before(job->js_time_latest, oldest))
			break;
		/* only put jobs that have not expired */
		if (test_and_set_bit(JS_EXPIRED, &job->js_flags))
			continue;
		job_putref(job); /* drop ref to initiate removal */
	}
	rcu_read_unlock();
	stats->ojs_cleanup_last = ktime_get_real();

	if (down_write_trylock(&stats->ojs_rwsem)) {
		job_purge_locked(stats, sched);
		up_write(&stats->ojs_rwsem);
	}
	clear_bit(OJS_CLEANING, &stats->ojs_flags);
}

static struct job_stat *job_alloc(char *jobid, struct obd_job_stats *jobs)
{
	struct job_stat *job;

	OBD_ALLOC_PTR(job);
	if (job == NULL)
		return NULL;

	job->js_stats = lprocfs_stats_alloc(jobs->ojs_cntr_num, 0);
	if (job->js_stats == NULL) {
		OBD_FREE_PTR(job);
		return NULL;
	}

	jobs->ojs_cntr_init_fn(job->js_stats, 0, 0);

	memcpy(job->js_jobid, jobid, sizeof(job->js_jobid));
	job->js_time_latest = job->js_stats->ls_init;
	job->js_jobstats = jobs;
	RB_CLEAR_NODE(&job->js_idnode);
	INIT_LIST_HEAD(&job->js_lru);
	clear_bit(JS_EXPIRED, &job->js_flags);
	/* open code init_llist_node */
	job->js_deleted.next = &job->js_deleted;
	kref_init(&job->js_refcount);
	if (atomic64_inc_return(&jobs->ojs_jobs) == 1)
		set_bit(OJS_ACTIVE_JOBS, &jobs->ojs_flags);

	return job;
}

static inline int cmp_key_jobid(const void *_key, const struct rb_node *node)
{
	struct job_stat *job = container_of(node, struct job_stat, js_idnode);
	const char *key = (const char *)_key;

	return strcmp(key, job->js_jobid);
}

/* return the next job in pos_id order or NULL*/
static struct job_stat *job_get_next_pos(struct job_stat *job)
{
	struct rb_node *next = rb_next(&job->js_posnode);

	while (next) {
		struct job_stat *next_job;

		next_job = container_of(next, struct job_stat, js_posnode);
		if (kref_get_unless_zero(&next_job->js_refcount))
			return next_job;

		/* 'next_job' is going away, try again */
		if (next)
			next = rb_next(next);
	}

	return NULL;
}

/* find and add a ref to a job with pos_id <= pos or NULL */
static struct job_stat *job_find_first_pos(struct obd_job_stats *stats, u64 pos)
{
	struct rb_node *node = stats->ojs_postree.rb_node;
	struct job_stat *found = NULL;

	while (node) {
		struct job_stat *job;

		job = container_of(node, struct job_stat, js_posnode);
		if (pos <= job->js_pos_id) {
			found = job;
			if (pos == job->js_pos_id)
				break;
			node = node->rb_left;
		} else {
			node = node->rb_right;
		}
	}
	if (found) {
		if (kref_get_unless_zero(&found->js_refcount))
			return found;
		return job_get_next_pos(found);
	}
	return NULL;
}

/* find and add a ref to a job, returns NULL if the job is being deleted */
static struct job_stat *job_find(struct obd_job_stats *stats,
				 const char *key)
{
	struct rb_node *node;
	struct job_stat *job;

	node = rb_find((void *)key, &stats->ojs_idtree, cmp_key_jobid);
	if (node) {
		job = container_of(node, struct job_stat, js_idnode);
		if (kref_get_unless_zero(&job->js_refcount))
			return job;
	}
	return NULL;
}

static inline int cmp_node_jobid(struct rb_node *left,
				 const struct rb_node *node)
{
	struct job_stat *key = container_of(left, struct job_stat, js_idnode);
	struct job_stat *job = container_of(node, struct job_stat, js_idnode);

	return strcmp(key->js_jobid, job->js_jobid);
}

/* insert a (newly allocated) job into the rbtree
 * In the case of a collision handle and existing job
 *  - is being deleted return -EAGAIN
 *  - is active increment the ref count and return it.
 * otherwise no collision and the job as added, add reference the new job
 * and return NULL.
 */
static struct job_stat *job_insert(struct obd_job_stats *stats,
				   struct job_stat *job)
{
	struct rb_node *node;

	node = rb_find_add(&job->js_idnode, &stats->ojs_idtree, cmp_node_jobid);
	if (node) {
		struct job_stat *existing_job;

		existing_job = container_of(node, struct job_stat, js_idnode);
		if (test_bit(JS_EXPIRED, &existing_job->js_flags))
			return ERR_PTR(-EAGAIN);
		if (kref_get_unless_zero(&existing_job->js_refcount))
			return existing_job;
		/* entry is being deleted */
		return ERR_PTR(-EAGAIN);
	}
	kref_get(&job->js_refcount);

	return NULL;
}

static inline int cmp_node_pos(struct rb_node *left, const struct rb_node *node)
{
	struct job_stat *key = container_of(left, struct job_stat, js_posnode);
	struct job_stat *job = container_of(node, struct job_stat, js_posnode);

	if (key->js_pos_id < job->js_pos_id)
		return -1;
	else if (key->js_pos_id > job->js_pos_id)
		return 1;
	return 0;
}

static inline void _next_pos_id(struct obd_job_stats *stats,
				struct job_stat *job)
{
	/* avoid pos clash with 'SEQ_START_TOKEN' */
	do {
		job->js_pos_id = atomic64_inc_return(&stats->ojs_next_pos);
	} while (job->js_pos_id < 2);
}

/* insert a job into the rbtree, return NULL if added otherwise existing job */
static void job_insert_pos(struct obd_job_stats *stats, struct job_stat *job)
{
	struct rb_node *node;

	/* on wrapping u64 insert could fail so advance pos_id need
	 * to fill in gaps
	 */
	do {
		_next_pos_id(stats, job);
		node = rb_find_add(&job->js_posnode, &stats->ojs_postree,
				   cmp_node_pos);
	} while (node);
}

int lprocfs_job_stats_log(struct obd_device *obd, char *jobid,
			  int event, long amount)
{
	struct obd_job_stats *stats = &obd2obt(obd)->obt_jobstats;
	struct job_stat *job, *existing_job;
	bool mru_last = false;
	ENTRY;

	LASSERT(stats);

	/* do not add jobs while shutting down */
	if (test_bit(OJS_FINI, &stats->ojs_flags))
		RETURN(0);

	if (event >= stats->ojs_cntr_num)
		RETURN(-EINVAL);

	if (jobid == NULL || strlen(jobid) == 0)
		RETURN(0);

	/* unterminated jobid should be handled in lustre_msg_get_jobid() */
	if (strlen(jobid) >= LUSTRE_JOBID_SIZE) {
		CERROR("%s: invalid jobid size %lu, expect %d\n", obd->obd_name,
		       (unsigned long)strlen(jobid) + 1, LUSTRE_JOBID_SIZE);
		RETURN(-EINVAL);
	}

	down_read(&stats->ojs_rwsem);
	job = job_find(stats, jobid);
	up_read(&stats->ojs_rwsem);
	if (job)
		goto found;

	lprocfs_job_cleanup(stats, false);

	job = job_alloc(jobid, stats);
	if (!job)
		RETURN(-ENOMEM);

try_insert:
	down_write(&stats->ojs_rwsem);
	job_purge_locked(stats, UINT_MAX);
	existing_job = job_insert(stats, job);
	if (IS_ERR(existing_job) && PTR_ERR(existing_job) == -EAGAIN) {
		up_write(&stats->ojs_rwsem);
		goto try_insert;
	}
	/* on collision drop the old job and proceed with the existing job */
	if (existing_job) {
		job_putref(job); /* duplicate job, remove */
		job = existing_job;
		up_write(&stats->ojs_rwsem);
		goto found;
	}
	job_insert_pos(stats, job);
	LASSERT(list_empty(&job->js_lru));
	spin_lock(&stats->ojs_lock);
	list_add_tail_rcu(&job->js_lru, &stats->ojs_lru);
	mru_last = true;
	spin_unlock(&stats->ojs_lock);
	up_write(&stats->ojs_rwsem);

found:
	LASSERT(stats == job->js_jobstats);
	job->js_time_latest = ktime_get_real();
	if (!mru_last) {
		spin_lock(&stats->ojs_lock);
		list_del_rcu(&job->js_lru);
		list_add_tail_rcu(&job->js_lru, &stats->ojs_lru);
		spin_unlock(&stats->ojs_lock);
	}
	lprocfs_counter_add(job->js_stats, event, amount);

	/* drop the extra ref from find | insert */
	job_putref(job);

	RETURN(0);
}
EXPORT_SYMBOL(lprocfs_job_stats_log);

void lprocfs_job_stats_fini(struct obd_device *obd)
{
	struct obd_job_stats *stats = &obd2obt(obd)->obt_jobstats;
	struct job_stat *job, *n;
	int retry = 0;
	bool purge = false;

	set_bit(OJS_FINI, &stats->ojs_flags);
	do {
		lprocfs_job_cleanup(stats, true);
		down_write(&stats->ojs_rwsem);
		job_purge_locked(stats, UINT_MAX);
		up_write(&stats->ojs_rwsem);
		rcu_barrier();
		purge = false;

		rbtree_postorder_for_each_entry_safe(job, n,
						     &stats->ojs_idtree,
						     js_idnode) {
			if (kref_read(&job->js_refcount) > 0) {
				job_putref(job); /* drop ref */
				purge = true;
			}
		}

		rbtree_postorder_for_each_entry_safe(job, n,
						     &stats->ojs_postree,
						     js_posnode) {
			if (kref_read(&job->js_refcount) > 0) {
				job_putref(job); /* drop ref */
				purge = true;
			}
		}

		if (atomic64_read(&stats->ojs_jobs))
			purge = true;
	} while (purge && retry++ < 3);
	wait_on_bit_timeout(&stats->ojs_flags, OJS_ACTIVE_JOBS,
			    TASK_UNINTERRUPTIBLE, cfs_time_seconds(30));
	rcu_barrier();
	LASSERTF(atomic64_read(&stats->ojs_jobs) == 0, "jobs:%llu flags:%lx\n",
		 (long long)atomic64_read(&stats->ojs_jobs), stats->ojs_flags);
	LASSERT(RB_EMPTY_ROOT(&stats->ojs_idtree));
	LASSERT(list_empty(&stats->ojs_lru));
	LASSERT(llist_empty(&stats->ojs_deleted));
}
EXPORT_SYMBOL(lprocfs_job_stats_fini);

static void *lprocfs_jobstats_seq_start(struct seq_file *p, loff_t *pos)
{
	struct obd_job_stats *stats = p->private;
	struct job_stat *start;

	down_read(&stats->ojs_rwsem);
	if (*pos == 0)
		set_bit(OJS_HEADER, &stats->ojs_flags);
	start = job_find_first_pos(stats, *pos);
	if (start)
		*pos = start->js_pos_id;

	return start;
}

static void *lprocfs_jobstats_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct job_stat *job = v, *next = NULL;

	++*pos;
	if (!job)
		return next;
	next = job_get_next_pos(job);
	if (next)
		*pos = next->js_pos_id;

	return next;
}

static void lprocfs_jobstats_seq_stop(struct seq_file *p, void *v)
{
	struct obd_job_stats *stats = p->private;

	up_read(&stats->ojs_rwsem);
}

/*
 * Example of output on MDT:
 *
 * job_stats:
 * - job_id:        dd.4854
 *   snapshot_time: 1322494486.123456789
 *   start_time:    1322494476.012345678
 *   elapsed_time:  10.111111111
 *   open:          { samples:	       1, unit: reqs }
 *   close:         { samples:	       1, unit: reqs }
 *   mknod:         { samples:	       0, unit: reqs }
 *   link:          { samples:	       0, unit: reqs }
 *   unlink:        { samples:	       0, unit: reqs }
 *   mkdir:         { samples:	       0, unit: reqs }
 *   rmdir:         { samples:	       0, unit: reqs }
 *   rename:        { samples:	       0, unit: reqs }
 *   getattr:       { samples:	       1, unit: reqs }
 *   setattr:       { samples:	       0, unit: reqs }
 *   getxattr:      { samples:	       0, unit: reqs }
 *   setxattr:      { samples:	       0, unit: reqs }
 *   statfs:        { samples:	       0, unit: reqs }
 *   sync:          { samples:	       0, unit: reqs }
 *
 * Example of output on OST:
 *
 * job_stats:
 * - job_id         dd.4854
 *   snapshot_time: 1322494602.123456789
 *   start_time:    1322494592.987654321
 *   elapsed_time:  9.135802468
 *   read:          { samples: 0, unit: bytes, min:  0, max:  0, sum:  0 }
 *   write:         { samples: 1, unit: bytes, min: 4096, max: 4096, sum: 4096 }
 *   setattr:       { samples: 0, unit: reqs }
 *   punch:         { samples: 0, unit: reqs }
 *   sync:          { samples: 0, unit: reqs }
 */

static const char spaces[] = "                    ";

static inline int width(const char *str, int len)
{
	return len - min((int)strlen(str), 15);
}

static int lprocfs_jobstats_seq_show(struct seq_file *p, void *v)
{
	struct obd_job_stats *stats = p->private;
	struct job_stat *job = v;
	struct lprocfs_stats *s;
	struct lprocfs_counter ret;
	struct lprocfs_counter_header *cntr_header;
	char escaped[LUSTRE_JOBID_SIZE * 4] = "";
	char *quote = "", *c, *end;
	int i, joblen = 0;

	if (v == SEQ_START_TOKEN)
		return 0;

	if (test_and_clear_bit(OJS_HEADER, &stats->ojs_flags))
		seq_puts(p, "job_stats:\n");

	/* Quote and escape jobid characters to escape hex codes "\xHH" if
	 * it contains any non-standard characters (space, newline, etc),
	 * so it will be confined to single line and not break parsing.
	 */
	for (c = job->js_jobid, end = job->js_jobid + sizeof(job->js_jobid);
	     c < end && *c != '\0';
	     c++, joblen++) {
		if (!isalnum(*c) && strchr(".@-_:/", *c) == NULL) {
			quote = "\"";
			snprintf(escaped + joblen, sizeof(escaped), "\\x%02X",
				 (unsigned char)*c);
			joblen += 3;
		} else {
			escaped[joblen] = *c;
			/* if jobid has ':', it should be quoted too */
			if (*c == ':')
				quote = "\"";
		}
	}
	/* '@' is reserved in YAML, so it cannot start a bare string. */
	if (escaped[0] == '@')
		quote = "\"";

	seq_printf(p, "- %-16s %s%*s%s\n",
		   "job_id:", quote, joblen, escaped, quote);
	lprocfs_stats_header(p, job->js_time_latest, job->js_stats->ls_init,
			     16, ":", true, "  ");

	s = job->js_stats;
	for (i = 0; i < s->ls_num; i++) {
		struct obd_histogram *hist;

		cntr_header = &s->ls_cnt_header[i];
		lprocfs_stats_collect(s, i, &ret);

		seq_printf(p, "  %s:%.*s { samples: %11llu",
			   cntr_header->lc_name,
			   width(cntr_header->lc_name, 15), spaces,
			   ret.lc_count);
		if (cntr_header->lc_units[0] != '\0')
			seq_printf(p, ", unit: %5s", cntr_header->lc_units);

		if (cntr_header->lc_config & LPROCFS_CNTR_AVGMINMAX) {
			seq_printf(p, ", min: %8llu, max: %8llu, sum: %16llu",
				   ret.lc_count ? ret.lc_min : 0,
				   ret.lc_count ? ret.lc_max : 0,
				   ret.lc_count ? ret.lc_sum : 0);
		}
		if (cntr_header->lc_config & LPROCFS_CNTR_STDDEV) {
			seq_printf(p, ", sumsq: %18llu",
				   ret.lc_count ? ret.lc_sumsquare : 0);
		}

		/* show obd_histogram */
		hist = s->ls_cnt_header[i].lc_hist;
		if (hist != NULL) {
			bool first = true;
			int j;

			seq_puts(p, ", hist: { ");
			for (j = 0; j < ARRAY_SIZE(hist->oh_buckets); j++) {
				unsigned long val = hist->oh_buckets[j];

				if (val == 0)
					continue;
				if (first)
					first = false;
				else
					seq_puts(p, ", ");

				if (j < 10)
					seq_printf(p, "%lu: %lu", BIT(j), val);
				else if (j < 20)
					seq_printf(p, "%luK: %lu", BIT(j - 10),
						   val);
				else if (j < 30)
					seq_printf(p, "%luM: %lu", BIT(j - 20),
						   val);
				else
					seq_printf(p, "%luG: %lu", BIT(j - 30),
						   val);
			}
			seq_puts(p, " }");
		}
		seq_puts(p, " }\n");
	}
	job_putref(job);

	return 0;
}

static const struct seq_operations lprocfs_jobstats_seq_sops = {
	.start	= lprocfs_jobstats_seq_start,
	.stop	= lprocfs_jobstats_seq_stop,
	.next	= lprocfs_jobstats_seq_next,
	.show	= lprocfs_jobstats_seq_show,
};

static int lprocfs_jobstats_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	struct obd_job_stats *stats;
	int rc;

	rc = seq_open(file, &lprocfs_jobstats_seq_sops);
	if (rc)
		return rc;

	stats = pde_data(inode);
	/* wait for any active cleaning to finish */
	set_bit(OJS_HEADER, &stats->ojs_flags);
	seq = file->private_data;
	seq->private = stats;

	return 0;
}

static ssize_t lprocfs_jobstats_seq_write(struct file *file,
					  const char __user *buf,
					  size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_job_stats *stats = seq->private;
	char jobid[4 * LUSTRE_JOBID_SIZE]; /* all escaped chars, plus ""\n\0 */
	char *p1, *p2, *last;
	unsigned int c;
	struct job_stat *job;

	if (len == 0 || len >= 4 * LUSTRE_JOBID_SIZE)
		return -EINVAL;

	if (!stats->ojs_cntr_num)
		return -ENODEV;

	if (copy_from_user(jobid, buf, len))
		return -EFAULT;
	jobid[len] = 0;
	last = jobid + len - 1;

	/* Trim '\n' if any */
	if (*last == '\n')
		*(last--) = 0;

	/* decode escaped chars if jobid is a quoted string */
	if (jobid[0] == '"' && *last == '"') {
		last--;

		for (p1 = jobid, p2 = jobid + 1; p2 <= last; p1++, p2++) {
			if (*p2 != '\\') {
				*p1 = *p2;
			} else if (p2 + 3 <= last && *(p2 + 1) == 'x' &&
				 sscanf(p2 + 2, "%02X", &c) == 1) {
				*p1 = c;
				p2 += 3;
			} else {
				return -EINVAL;
			}
		}
		*p1 = 0;

	}
	jobid[LUSTRE_JOBID_SIZE - 1] = 0;

	if (strcmp(jobid, "clear") == 0) {
		lprocfs_job_cleanup(stats, true);

		return len;
	}

	if (strlen(jobid) == 0)
		return -EINVAL;

	down_read(&stats->ojs_rwsem);
	job = job_find(stats, jobid);
	up_read(&stats->ojs_rwsem);
	if (!job)
		return -EINVAL;
	job_putref(job); /* drop ref from job_find() */
	job_putref(job); /* drop ref to initiate removal */

	return len;
}

/**
 * Clean up the seq file state when the /proc file is closed.
 *
 * This also expires old job stats from the cache after they have been
 * printed in case the system is idle and not generating new jobstats.
 *
 * \param[in] inode	struct inode for seq file being closed
 * \param[in] file	struct file for seq file being closed
 *
 * \retval		0 on success
 * \retval		negative errno on failure
 */
static int lprocfs_jobstats_seq_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct obd_job_stats *stats = seq->private;

	lprocfs_job_cleanup(stats, false);

	return lprocfs_seq_release(inode, file);
}

static const struct proc_ops lprocfs_jobstats_seq_fops = {
	PROC_OWNER(THIS_MODULE)
	.proc_open	= lprocfs_jobstats_seq_open,
	.proc_read	= seq_read,
	.proc_write	= lprocfs_jobstats_seq_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= lprocfs_jobstats_seq_release,
};

int lprocfs_job_stats_init(struct obd_device *obd, int cntr_num,
			   cntr_init_callback init_fn)
{
	struct proc_dir_entry *entry;
	struct obd_job_stats *stats;
	ENTRY;

	LASSERT(obd->obd_proc_entry != NULL);
	LASSERT(obd->obd_type->typ_name);

	if (cntr_num <= 0)
		RETURN(-EINVAL);

	if (init_fn == NULL)
		RETURN(-EINVAL);

	/* Currently needs to be a target due to the use of obt_jobstats. */
	if (strcmp(obd->obd_type->typ_name, LUSTRE_MDT_NAME) != 0 &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_OST_NAME) != 0) {
		CERROR("%s: invalid device type %s for job stats: rc = %d\n",
		       obd->obd_name, obd->obd_type->typ_name, -EINVAL);
		RETURN(-EINVAL);
	}
	stats = &obd2obt(obd)->obt_jobstats;
	stats->ojs_idtree = RB_ROOT;
	stats->ojs_postree = RB_ROOT;
	atomic64_set(&stats->ojs_next_pos, 2);
	init_rwsem(&stats->ojs_rwsem);
	INIT_LIST_HEAD(&stats->ojs_lru);
	init_llist_head(&stats->ojs_deleted);
	stats->ojs_flags = 0;
	atomic_set(&stats->ojs_readers, 0);
	spin_lock_init(&stats->ojs_lock);
	/* Store 1/2 the actual interval, since we use that the most, and
	 * it is easier to work with.
	 */
	stats->ojs_cleanup_interval = ktime_set(600 / 2, 0); /* default 10 min*/
	stats->ojs_cleanup_last = ktime_get_real();
	stats->ojs_cntr_num = cntr_num;
	stats->ojs_cntr_init_fn = init_fn;
	atomic64_set(&stats->ojs_jobs, 0);

	entry = lprocfs_add_simple(obd->obd_proc_entry, "job_stats", stats,
				   &lprocfs_jobstats_seq_fops);
	if (IS_ERR(entry)) {
		lprocfs_job_stats_fini(obd);
		RETURN(-ENOMEM);
	}
	RETURN(0);
}
EXPORT_SYMBOL(lprocfs_job_stats_init);
#endif /* CONFIG_PROC_FS*/

ssize_t job_cleanup_interval_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_job_stats *stats;
	struct timespec64 ts;

	stats = &obd2obt(obd)->obt_jobstats;
	ts = ktime_to_timespec64(stats->ojs_cleanup_interval);

	return scnprintf(buf, PAGE_SIZE, "%lld\n", (long long)ts.tv_sec * 2);
}
EXPORT_SYMBOL(job_cleanup_interval_show);

ssize_t job_cleanup_interval_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct obd_job_stats *stats;
	unsigned int val;
	int rc;

	stats = &obd2obt(obd)->obt_jobstats;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	stats->ojs_cleanup_interval = ktime_set(val / 2, 0);
	lprocfs_job_cleanup(stats, false);

	return count;
}
EXPORT_SYMBOL(job_cleanup_interval_store);
