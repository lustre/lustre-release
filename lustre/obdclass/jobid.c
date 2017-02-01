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
 * Copyright (c) 2011, 2014, Intel Corporation.
 *
 * Copyright 2017 Cray Inc, all rights reserved.
 * Author: Ben Evans.
 *
 * Store PID->JobID mappings
 */

#define DEBUG_SUBSYSTEM S_RPC
#include <linux/user_namespace.h>
#ifdef HAVE_UIDGID_HEADER
#include <linux/uidgid.h>
#endif

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>

static struct cfs_hash *jobid_hash;
static struct cfs_hash_ops jobid_hash_ops;
spinlock_t jobid_hash_lock;

#define RESCAN_INTERVAL 30
#define DELETE_INTERVAL 300

char obd_jobid_var[JOBSTATS_JOBID_VAR_MAX_LEN + 1] = JOBSTATS_DISABLE;
char obd_jobid_node[LUSTRE_JOBID_SIZE + 1];

/**
 * Structure to store a single jobID/PID mapping
 */
struct jobid_to_pid_map {
	struct hlist_node	jp_hash;
	time64_t		jp_time;
	atomic_t		jp_refcount;
	spinlock_t		jp_lock; /* protects jp_jobid */
	char			jp_jobid[LUSTRE_JOBID_SIZE + 1];
	pid_t			jp_pid;
};

/* Get jobid of current process by reading the environment variable
 * stored in between the "env_start" & "env_end" of task struct.
 *
 * If some job scheduler doesn't store jobid in the "env_start/end",
 * then an upcall could be issued here to get the jobid by utilizing
 * the userspace tools/API. Then, the jobid must be cached.
 */
int get_jobid_from_environ(char *jobid_var, char *jobid, int jobid_len)
{
	int rc;

	rc = cfs_get_environ(jobid_var, jobid, &jobid_len);
	if (!rc)
		goto out;

	if (rc == -EOVERFLOW) {
		/* For the PBS_JOBID and LOADL_STEP_ID keys (which are
		 * variable length strings instead of just numbers), it
		 * might make sense to keep the unique parts for JobID,
		 * instead of just returning an error.  That means a
		 * larger temp buffer for cfs_get_environ(), then
		 * truncating the string at some separator to fit into
		 * the specified jobid_len.  Fix later if needed. */
		static bool printed;
		if (unlikely(!printed)) {
			LCONSOLE_ERROR_MSG(0x16b, "%s value too large "
					   "for JobID buffer (%d)\n",
					   obd_jobid_var, jobid_len);
			printed = true;
		}
	} else {
		CDEBUG((rc == -ENOENT || rc == -EINVAL ||
			rc == -EDEADLK) ? D_INFO : D_ERROR,
		       "Get jobid for (%s) failed: rc = %d\n",
		       obd_jobid_var, rc);
	}

out:
	return rc;
}

/*
 * jobid_should_free_item
 *
 * Each item is checked to see if it should be released
 * Removed from hash table by caller
 * Actually freed in jobid_put_locked
 *
 * Returns 1 if item is to be freed, 0 if it is to be kept
 */

static int jobid_should_free_item(void *obj, void *data)
{
	char *jobid = data;
	struct jobid_to_pid_map *pidmap = obj;
	int rc = 0;

	if (obj == NULL)
		return 0;

	spin_lock(&pidmap->jp_lock);
	if (jobid == NULL)
		rc = 1;
	else if (jobid[0] == '\0')
		rc = 1;
	else if (ktime_get_real_seconds() - pidmap->jp_time > DELETE_INTERVAL)
		rc = 1;
	else if (strcmp(pidmap->jp_jobid, jobid) == 0)
		rc = 1;
	spin_unlock(&pidmap->jp_lock);

	return rc;
}

/*
 * check_job_name
 *
 * Checks if the jobid is a Lustre process
 *
 * Returns true if jobid is valid
 * Returns false if jobid looks like it's a Lustre process
 */
static bool check_job_name(char *jobid)
{
	const char *const lustre_reserved[] = {"ll_ping", "ptlrpc",
						"ldlm", "ll_sa", NULL};
	int i;

	for (i = 0; lustre_reserved[i] != NULL; i++) {
		if (strncmp(jobid, lustre_reserved[i],
			    strlen(lustre_reserved[i])) == 0)
			return false;
	}
	return true;
}

/*
 * get_jobid
 *
 * Returns the jobid for the current pid.
 *
 * If no jobid is found in the table, the jobid is calculated based on
 * the value of jobid_var, using procname_uid as the default.
 *
 * Return: -ENOMEM if allocating a new pidmap fails
 *         0 for success
 */
int get_jobid(char *jobid)
{
	pid_t pid = current_pid();
	struct jobid_to_pid_map *pidmap = NULL;
	struct jobid_to_pid_map *pidmap2;
	char tmp_jobid[LUSTRE_JOBID_SIZE + 1];
	int rc = 0;
	ENTRY;

	pidmap = cfs_hash_lookup(jobid_hash, &pid);
	if (pidmap == NULL) {
		OBD_ALLOC_PTR(pidmap);
		if (pidmap == NULL)
			GOTO(out, rc = -ENOMEM);

		pidmap->jp_pid = pid;
		pidmap->jp_time = 0;
		pidmap->jp_jobid[0] = '\0';
		spin_lock_init(&pidmap->jp_lock);
		INIT_HLIST_NODE(&pidmap->jp_hash);

		/*
		 * Add the newly created map to the hash, on key collision we
		 * lost a racing addition and must destroy our newly allocated
		 * map.  The object which exists in the hash will be
		 * returned.
		 */
		pidmap2 = cfs_hash_findadd_unique(jobid_hash, &pid,
						  &pidmap->jp_hash);
		if (unlikely(pidmap != pidmap2)) {
			CDEBUG(D_INFO, "Duplicate jobid found\n");
			OBD_FREE_PTR(pidmap);
			pidmap = pidmap2;
		} else {
			cfs_hash_get(jobid_hash, &pidmap->jp_hash);
		}
	}

	spin_lock(&pidmap->jp_lock);
	if ((ktime_get_real_seconds() - pidmap->jp_time >= RESCAN_INTERVAL) ||
	    pidmap->jp_jobid[0] == '\0') {
		/* mark the pidmap as being up to date, if we fail to find
		 * a good jobid, revert to the old time and try again later
		 * prevent a race with deletion */

		time64_t tmp_time = pidmap->jp_time;
		pidmap->jp_time = ktime_get_real_seconds();

		spin_unlock(&pidmap->jp_lock);
		if (strcmp(obd_jobid_var, JOBSTATS_PROCNAME_UID) == 0) {
			rc = 1;
		} else {
			memset(tmp_jobid, '\0', LUSTRE_JOBID_SIZE + 1);
			rc = get_jobid_from_environ(obd_jobid_var,
						    tmp_jobid,
						    LUSTRE_JOBID_SIZE + 1);
		}

		/* Use process name + fsuid as jobid default, or when
		 * specified by "jobname_uid" */
		if (rc) {
			snprintf(tmp_jobid, LUSTRE_JOBID_SIZE, "%s.%u",
				 current_comm(),
				 from_kuid(&init_user_ns, current_fsuid()));
			rc = 0;
		}

		CDEBUG(D_INFO, "Jobid to pid mapping established: %d->%s\n",
		       pidmap->jp_pid, tmp_jobid);

		spin_lock(&pidmap->jp_lock);
		if (check_job_name(tmp_jobid))
			strncpy(pidmap->jp_jobid, tmp_jobid,
				LUSTRE_JOBID_SIZE);
		else
			pidmap->jp_time = tmp_time;
	}

	if (strlen(pidmap->jp_jobid) != 0)
		strncpy(jobid, pidmap->jp_jobid, LUSTRE_JOBID_SIZE);

	spin_unlock(&pidmap->jp_lock);

	cfs_hash_put(jobid_hash, &pidmap->jp_hash);

	EXIT;
out:
	return rc;
}

/*
 * Hash initialization, copied from server-side job stats bucket sizes
 */
#define HASH_JOBID_BKT_BITS 5
#define HASH_JOBID_CUR_BITS 7
#define HASH_JOBID_MAX_BITS 12

int jobid_cache_init(void)
{
	int rc = 0;
	struct cfs_hash *tmp_jobid_hash;
	ENTRY;

	spin_lock_init(&jobid_hash_lock);

	tmp_jobid_hash = cfs_hash_create("JOBID_HASH",
					 HASH_JOBID_CUR_BITS,
					 HASH_JOBID_MAX_BITS,
					 HASH_JOBID_BKT_BITS, 0,
					 CFS_HASH_MIN_THETA,
					 CFS_HASH_MAX_THETA,
					 &jobid_hash_ops,
					 CFS_HASH_DEFAULT);

	spin_lock(&jobid_hash_lock);
	if (jobid_hash == NULL) {
		jobid_hash = tmp_jobid_hash;
		spin_unlock(&jobid_hash_lock);
	} else {
		spin_unlock(&jobid_hash_lock);
		if (tmp_jobid_hash != NULL)
			cfs_hash_putref(tmp_jobid_hash);
	}

	if (!jobid_hash)
		rc = -ENOMEM;

	RETURN(rc);
}
EXPORT_SYMBOL(jobid_cache_init);

void jobid_cache_fini(void)
{
	struct cfs_hash *tmp_hash;
	ENTRY;

	spin_lock(&jobid_hash_lock);
	tmp_hash = jobid_hash;
	jobid_hash = NULL;
	spin_unlock(&jobid_hash_lock);

	if (tmp_hash != NULL) {
		cfs_hash_cond_del(tmp_hash, jobid_should_free_item, NULL);
		cfs_hash_putref(tmp_hash);
	}

	EXIT;
}
EXPORT_SYMBOL(jobid_cache_fini);

/*
 * Hash operations for pid<->jobid
 */
static unsigned jobid_hashfn(struct cfs_hash *hs, const void *key,
			     unsigned mask)
{
	return cfs_hash_djb2_hash(key, sizeof(pid_t), mask);
}

static void *jobid_key(struct hlist_node *hnode)
{
	struct jobid_to_pid_map *pidmap;

	pidmap = hlist_entry(hnode, struct jobid_to_pid_map, jp_hash);
	return &pidmap->jp_pid;
}

static int jobid_keycmp(const void *key, struct hlist_node *hnode)
{
	const pid_t *pid_key1;
	const pid_t *pid_key2;

	LASSERT(key != NULL);
	pid_key1 = (pid_t *)key;
	pid_key2 = (pid_t *)jobid_key(hnode);

	return *pid_key1 == *pid_key2;
}

static void *jobid_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct jobid_to_pid_map, jp_hash);
}

static void jobid_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct jobid_to_pid_map *pidmap;

	pidmap = hlist_entry(hnode, struct jobid_to_pid_map, jp_hash);

	atomic_inc(&pidmap->jp_refcount);
}

static void jobid_put_locked(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct jobid_to_pid_map *pidmap;

	if (hnode == NULL)
		return;

	pidmap = hlist_entry(hnode, struct jobid_to_pid_map, jp_hash);
	LASSERT(atomic_read(&pidmap->jp_refcount) > 0);
	if (atomic_dec_and_test(&pidmap->jp_refcount)) {
		CDEBUG(D_INFO, "Freeing: %d->%s\n",
		       pidmap->jp_pid, pidmap->jp_jobid);

		OBD_FREE_PTR(pidmap);
	}
}

static struct cfs_hash_ops jobid_hash_ops = {
	.hs_hash	= jobid_hashfn,
	.hs_keycmp	= jobid_keycmp,
	.hs_key		= jobid_key,
	.hs_object	= jobid_object,
	.hs_get		= jobid_get,
	.hs_put		= jobid_put_locked,
	.hs_put_locked	= jobid_put_locked,
};

/*
 * Return the jobid:
 *
 * Based on the value of obd_jobid_var
 * JOBSTATS_DISABLE:  none
 * JOBSTATS_NODELOCAL:  Contents of obd_jobid_name
 * JOBSTATS_PROCNAME_UID:  Process name/UID
 * anything else:  Look up the value in the processes environment
 * default: JOBSTATS_PROCNAME_UID
 */

int lustre_get_jobid(char *jobid)
{
	int rc = 0;
	int clear = 0;
	static time64_t last_delete;
	ENTRY;

	LASSERT(jobid_hash != NULL);

	spin_lock(&jobid_hash_lock);
	if (last_delete + DELETE_INTERVAL <= ktime_get_real_seconds()) {
		clear = 1;
		last_delete = ktime_get_real_seconds();
	}
	spin_unlock(&jobid_hash_lock);

	if (clear)
		cfs_hash_cond_del(jobid_hash, jobid_should_free_item,
				  "intentionally_bad_jobid");

	if (strcmp(obd_jobid_var, JOBSTATS_DISABLE) == 0)
		/* Jobstats isn't enabled */
		memset(jobid, 0, LUSTRE_JOBID_SIZE);
	else if (strcmp(obd_jobid_var, JOBSTATS_NODELOCAL) == 0)
		/* Whole node dedicated to single job */
		memcpy(jobid, obd_jobid_node, LUSTRE_JOBID_SIZE);
	else
		/* Get jobid from hash table */
		rc = get_jobid(jobid);

	RETURN(rc);
}
EXPORT_SYMBOL(lustre_get_jobid);

/*
 * lustre_jobid_clear
 *
 * uses value pushed in via jobid_name
 * If any entries in the hash table match the value, they are removed
 */
void lustre_jobid_clear(const char *data)
{
	char jobid[LUSTRE_JOBID_SIZE + 1];

	if (jobid_hash == NULL)
		return;

	strncpy(jobid, data, LUSTRE_JOBID_SIZE);
	/* trim \n off the end of the incoming jobid */
	if (jobid[strlen(jobid) - 1] == '\n')
		jobid[strlen(jobid) - 1] = '\0';

	CDEBUG(D_INFO, "Clearing Jobid: %s\n", jobid);
	cfs_hash_cond_del(jobid_hash, jobid_should_free_item, jobid);

	CDEBUG(D_INFO, "%d items remain in jobID table\n",
	       atomic_read(&jobid_hash->hs_count));
}
