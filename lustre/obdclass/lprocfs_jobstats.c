/* GPL HEADER START
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
 * Copyright (c) 2012, 2016, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Niu Yawei <niu@whamcloud.com>
 */
/*
 * lustre/obdclass/lprocfs_jobstats.c
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd_class.h>
#include <lprocfs_status.h>

#ifdef CONFIG_PROC_FS

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
	struct hlist_node	js_hash;	/* hash struct for this jobid */
	struct list_head	js_list;	/* on ojs_list, with ojs_lock */
	atomic_t		js_refcount;	/* num users of this struct */
	char			js_jobid[LUSTRE_JOBID_SIZE]; /* job name + NUL*/
	time64_t		js_timestamp;	/* seconds of most recent stat*/
	struct lprocfs_stats	*js_stats;	/* per-job statistics */
	struct obd_job_stats	*js_jobstats;	/* for accessing ojs_lock */
};

static unsigned
job_stat_hash(struct cfs_hash *hs, const void *key, unsigned mask)
{
	return cfs_hash_djb2_hash(key, strlen(key), mask);
}

static void *job_stat_key(struct hlist_node *hnode)
{
	struct job_stat *job;
	job = hlist_entry(hnode, struct job_stat, js_hash);
	return job->js_jobid;
}

static int job_stat_keycmp(const void *key, struct hlist_node *hnode)
{
	struct job_stat *job;
	job = hlist_entry(hnode, struct job_stat, js_hash);
	return (strlen(job->js_jobid) == strlen(key)) &&
	       !strncmp(job->js_jobid, key, strlen(key));
}

static void *job_stat_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct job_stat, js_hash);
}

static void job_stat_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct job_stat *job;
	job = hlist_entry(hnode, struct job_stat, js_hash);
	atomic_inc(&job->js_refcount);
}

static void job_free(struct job_stat *job)
{
	LASSERT(atomic_read(&job->js_refcount) == 0);
	LASSERT(job->js_jobstats != NULL);

	write_lock(&job->js_jobstats->ojs_lock);
	list_del_init(&job->js_list);
	write_unlock(&job->js_jobstats->ojs_lock);

	lprocfs_free_stats(&job->js_stats);
	OBD_FREE_PTR(job);
}

static void job_putref(struct job_stat *job)
{
	LASSERT(atomic_read(&job->js_refcount) > 0);
	if (atomic_dec_and_test(&job->js_refcount))
		job_free(job);
}

static void job_stat_put_locked(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct job_stat *job;
	job = hlist_entry(hnode, struct job_stat, js_hash);
	job_putref(job);
}

static void job_stat_exit(struct cfs_hash *hs, struct hlist_node *hnode)
{
	CERROR("should not have any items\n");
}

static struct cfs_hash_ops job_stats_hash_ops = {
	.hs_hash       = job_stat_hash,
	.hs_key        = job_stat_key,
	.hs_keycmp     = job_stat_keycmp,
	.hs_object     = job_stat_object,
	.hs_get        = job_stat_get,
	.hs_put_locked = job_stat_put_locked,
	.hs_exit       = job_stat_exit,
};

/**
 * Jobstats expiry iterator to clean up old jobids
 *
 * Called for each job_stat structure on this device, it should delete stats
 * older than the specified \a oldest_time in seconds.  If \a oldest_time is
 * in the future then this will delete all statistics (e.g. during shutdown).
 *
 * \param[in] hs	hash of all jobids on this device
 * \param[in] bd	hash bucket containing this jobid
 * \param[in] hnode	hash structure for this jobid
 * \param[in] data	pointer to stats expiry time in seconds
 */
static int job_cleanup_iter_callback(struct cfs_hash *hs,
				     struct cfs_hash_bd *bd,
				     struct hlist_node *hnode, void *data)
{
	time64_t oldest_time = *((time64_t *)data);
	struct job_stat *job;

	job = hlist_entry(hnode, struct job_stat, js_hash);
	if (job->js_timestamp < oldest_time)
		cfs_hash_bd_del_locked(hs, bd, hnode);

	return 0;
}

/**
 * Clean up jobstats that were updated more than \a before seconds ago.
 *
 * Since this function may be called frequently, do not scan all of the
 * jobstats on each call, only twice per cleanup interval.  That means stats
 * may be around on average cleanup_interval / 4 longer than necessary,
 * but that is not considered harmful.
 *
 * If \a before is negative then this will force clean up all jobstats due
 * to the expiry time being in the future (e.g. at shutdown).
 *
 * If there is already another thread doing jobstats cleanup, don't try to
 * do this again in the current thread unless this is a force cleanup.
 *
 * \param[in] stats	stucture tracking all job stats for this device
 * \param[in] before	expire jobstats updated more than this many seconds ago
 */
static void lprocfs_job_cleanup(struct obd_job_stats *stats, int before)
{
	time64_t now = ktime_get_real_seconds();
	time64_t oldest;

	if (likely(before >= 0)) {
		unsigned int cleanup_interval = stats->ojs_cleanup_interval;

		if (cleanup_interval == 0 || before == 0)
			return;

		if (now < stats->ojs_last_cleanup + cleanup_interval / 2)
			return;

		if (stats->ojs_cleaning)
			return;
	}

	write_lock(&stats->ojs_lock);
	if (before >= 0 && stats->ojs_cleaning) {
		write_unlock(&stats->ojs_lock);
		return;
	}

	stats->ojs_cleaning = true;
	write_unlock(&stats->ojs_lock);

	/* Can't hold ojs_lock over hash iteration, since it is grabbed by
	 * job_cleanup_iter_callback()
	 *   ->cfs_hash_bd_del_locked()
	 *     ->job_putref()
	 *       ->job_free()
	 *
	 * Holding ojs_lock isn't necessary for safety of the hash iteration,
	 * since locking of the hash is handled internally, but there isn't
	 * any benefit to having multiple threads doing cleanup at one time.
	 */
	oldest = now - before;
	cfs_hash_for_each_safe(stats->ojs_hash, job_cleanup_iter_callback,
			       &oldest);

	write_lock(&stats->ojs_lock);
	stats->ojs_cleaning = false;
	stats->ojs_last_cleanup = ktime_get_real_seconds();
	write_unlock(&stats->ojs_lock);
}

static struct job_stat *job_alloc(char *jobid, struct obd_job_stats *jobs)
{
	struct job_stat *job;

	OBD_ALLOC_PTR(job);
	if (job == NULL)
		return NULL;

	job->js_stats = lprocfs_alloc_stats(jobs->ojs_cntr_num, 0);
	if (job->js_stats == NULL) {
		OBD_FREE_PTR(job);
		return NULL;
	}

	jobs->ojs_cntr_init_fn(job->js_stats, 0);

	memcpy(job->js_jobid, jobid, sizeof(job->js_jobid));
	job->js_timestamp = ktime_get_real_seconds();
	job->js_jobstats = jobs;
	INIT_HLIST_NODE(&job->js_hash);
	INIT_LIST_HEAD(&job->js_list);
	atomic_set(&job->js_refcount, 1);

	return job;
}

int lprocfs_job_stats_log(struct obd_device *obd, char *jobid,
			  int event, long amount)
{
	struct obd_job_stats *stats = &obd->u.obt.obt_jobstats;
	struct job_stat *job, *job2;
	ENTRY;

	LASSERT(stats != NULL);
	LASSERT(stats->ojs_hash != NULL);

	if (event >= stats->ojs_cntr_num)
		RETURN(-EINVAL);

	if (jobid == NULL || strlen(jobid) == 0)
		RETURN(-EINVAL);

	if (strlen(jobid) >= LUSTRE_JOBID_SIZE) {
		CERROR("Invalid jobid size (%lu), expect(%d)\n",
		       (unsigned long)strlen(jobid) + 1, LUSTRE_JOBID_SIZE);
		RETURN(-EINVAL);
	}

	job = cfs_hash_lookup(stats->ojs_hash, jobid);
	if (job)
		goto found;

	lprocfs_job_cleanup(stats, stats->ojs_cleanup_interval);

	job = job_alloc(jobid, stats);
	if (job == NULL)
		RETURN(-ENOMEM);

	job2 = cfs_hash_findadd_unique(stats->ojs_hash, job->js_jobid,
				       &job->js_hash);
	if (job2 != job) {
		job_putref(job);
		job = job2;
		/* We cannot LASSERT(!list_empty(&job->js_list)) here,
		 * since we just lost the race for inserting "job" into the
		 * ojs_list, and some other thread is doing it _right_now_.
		 * Instead, be content the other thread is doing this, since
		 * "job2" was initialized in job_alloc() already. LU-2163 */
	} else {
		LASSERT(list_empty(&job->js_list));
		write_lock(&stats->ojs_lock);
		list_add_tail(&job->js_list, &stats->ojs_list);
		write_unlock(&stats->ojs_lock);
	}

found:
	LASSERT(stats == job->js_jobstats);
	job->js_timestamp = ktime_get_real_seconds();
	lprocfs_counter_add(job->js_stats, event, amount);

	job_putref(job);

	RETURN(0);
}
EXPORT_SYMBOL(lprocfs_job_stats_log);

void lprocfs_job_stats_fini(struct obd_device *obd)
{
	struct obd_job_stats *stats = &obd->u.obt.obt_jobstats;

	if (stats->ojs_hash == NULL)
		return;

	lprocfs_job_cleanup(stats, -99);
	cfs_hash_putref(stats->ojs_hash);
	stats->ojs_hash = NULL;
	LASSERT(list_empty(&stats->ojs_list));
}
EXPORT_SYMBOL(lprocfs_job_stats_fini);

static void *lprocfs_jobstats_seq_start(struct seq_file *p, loff_t *pos)
{
	struct obd_job_stats *stats = p->private;
	loff_t off = *pos;
	struct job_stat *job;

	read_lock(&stats->ojs_lock);
	if (off == 0)
		return SEQ_START_TOKEN;
	off--;
	list_for_each_entry(job, &stats->ojs_list, js_list) {
		if (!off--)
			return job;
	}
	return NULL;
}

static void lprocfs_jobstats_seq_stop(struct seq_file *p, void *v)
{
	struct obd_job_stats *stats = p->private;

	read_unlock(&stats->ojs_lock);
}

static void *lprocfs_jobstats_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct obd_job_stats *stats = p->private;
	struct job_stat *job;
	struct list_head *next;

	++*pos;
	if (v == SEQ_START_TOKEN) {
		next = stats->ojs_list.next;
	} else {
		job = (struct job_stat *)v;
		next = job->js_list.next;
	}

	return next == &stats->ojs_list ? NULL :
		list_entry(next, struct job_stat, js_list);
}

/*
 * Example of output on MDT:
 *
 * job_stats:
 * - job_id:        dd.4854
 *   snapshot_time: 1322494486
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
 *   snapshot_time: 1322494602
 *   read:          { samples: 0, unit: bytes, min:  0, max:  0, sum:  0 }
 *   write:         { samples: 1, unit: bytes, min: 4096, max: 4096, sum: 4096 }
 *   setattr:       { samples: 0, unit: reqs }
 *   punch:         { samples: 0, unit: reqs }
 *   sync:          { samples: 0, unit: reqs }
 */

static const char spaces[] = "                    ";

static int inline width(const char *str, int len)
{
	return len - min((int)strlen(str), 15);
}

static int lprocfs_jobstats_seq_show(struct seq_file *p, void *v)
{
	struct job_stat			*job = v;
	struct lprocfs_stats		*s;
	struct lprocfs_counter		ret;
	struct lprocfs_counter_header	*cntr_header;
	int				i;

	if (v == SEQ_START_TOKEN) {
		seq_printf(p, "job_stats:\n");
		return 0;
	}

	/* Replace the non-printable character in jobid with '?', so
	 * that the output of jobid will be confined in single line. */
	seq_printf(p, "- %-16s ", "job_id:");
	for (i = 0; i < strlen(job->js_jobid); i++) {
		if (isprint(job->js_jobid[i]) != 0)
			seq_putc(p, job->js_jobid[i]);
		else
			seq_putc(p, '?');
	}
	seq_putc(p, '\n');

	seq_printf(p, "  %-16s %lld\n", "snapshot_time:", job->js_timestamp);

	s = job->js_stats;
	for (i = 0; i < s->ls_num; i++) {
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

		seq_printf(p, " }\n");

	}
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
	int rc;

	rc = seq_open(file, &lprocfs_jobstats_seq_sops);
	if (rc)
		return rc;
	seq = file->private_data;
	seq->private = PDE_DATA(inode);
	return 0;
}

static ssize_t lprocfs_jobstats_seq_write(struct file *file,
					  const char __user *buf,
					  size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct obd_job_stats *stats = seq->private;
	char jobid[LUSTRE_JOBID_SIZE];
	struct job_stat *job;

	if (len == 0 || len >= LUSTRE_JOBID_SIZE)
		return -EINVAL;

	if (stats->ojs_hash == NULL)
		return -ENODEV;

	if (copy_from_user(jobid, buf, len))
		return -EFAULT;
	jobid[len] = 0;

	/* Trim '\n' if any */
	if (jobid[len - 1] == '\n')
		jobid[len - 1] = 0;

	if (strcmp(jobid, "clear") == 0) {
		lprocfs_job_cleanup(stats, -99);

		return len;
	}

	if (strlen(jobid) == 0)
		return -EINVAL;

	job = cfs_hash_lookup(stats->ojs_hash, jobid);
	if (!job)
		return -EINVAL;

	cfs_hash_del_key(stats->ojs_hash, jobid);

	job_putref(job);
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

	lprocfs_job_cleanup(stats, stats->ojs_cleanup_interval);

	return lprocfs_seq_release(inode, file);
}

static const struct file_operations lprocfs_jobstats_seq_fops = {
	.owner   = THIS_MODULE,
	.open    = lprocfs_jobstats_seq_open,
	.read    = seq_read,
	.write   = lprocfs_jobstats_seq_write,
	.llseek  = seq_lseek,
	.release = lprocfs_jobstats_seq_release,
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
	stats = &obd->u.obt.obt_jobstats;

	LASSERT(stats->ojs_hash == NULL);
	stats->ojs_hash = cfs_hash_create("JOB_STATS",
					  HASH_JOB_STATS_CUR_BITS,
					  HASH_JOB_STATS_MAX_BITS,
					  HASH_JOB_STATS_BKT_BITS, 0,
					  CFS_HASH_MIN_THETA,
					  CFS_HASH_MAX_THETA,
					  &job_stats_hash_ops,
					  CFS_HASH_DEFAULT);
	if (stats->ojs_hash == NULL)
		RETURN(-ENOMEM);

	INIT_LIST_HEAD(&stats->ojs_list);
	rwlock_init(&stats->ojs_lock);
	stats->ojs_cntr_num = cntr_num;
	stats->ojs_cntr_init_fn = init_fn;
	stats->ojs_cleanup_interval = 600; /* 10 mins by default */
	stats->ojs_last_cleanup = ktime_get_real_seconds();

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

	stats = &obd->u.obt.obt_jobstats;
	return scnprintf(buf, PAGE_SIZE, "%d\n", stats->ojs_cleanup_interval);
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

	stats = &obd->u.obt.obt_jobstats;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	stats->ojs_cleanup_interval = val;
	lprocfs_job_cleanup(stats, stats->ojs_cleanup_interval);
	return count;
}
EXPORT_SYMBOL(job_cleanup_interval_store);
