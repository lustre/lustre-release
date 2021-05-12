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
#include <linux/uidgid.h>
#include <linux/utsname.h>

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <obd_class.h>
#include <lustre_net.h>

static struct cfs_hash *jobid_hash;
static struct cfs_hash_ops jobid_hash_ops;
spinlock_t jobid_hash_lock;

#define RESCAN_INTERVAL 30
#define DELETE_INTERVAL 300

char obd_jobid_var[JOBSTATS_JOBID_VAR_MAX_LEN + 1] = JOBSTATS_DISABLE;
char obd_jobid_name[LUSTRE_JOBID_SIZE] = "%e.%u";

/**
 * Structure to store a single PID->JobID mapping
 */
struct jobid_pid_map {
	struct hlist_node	jp_hash;
	time64_t		jp_time;
	spinlock_t		jp_lock; /* protects jp_jobid */
	char			jp_jobid[LUSTRE_JOBID_SIZE];
	unsigned int		jp_joblen;
	atomic_t		jp_refcount;
	pid_t			jp_pid;
};

/*
 * Jobid can be set for a session (see setsid(2)) by writing to
 * a sysfs file from any process in that session.
 * The jobids are stored in a hash table indexed by the relevant
 * struct pid.  We periodically look for entries where the pid has
 * no PIDTYPE_SID tasks any more, and prune them.  This happens within
 * 5 seconds of a jobid being added, and every 5 minutes when jobids exist,
 * but none are added.
 */
#define JOBID_EXPEDITED_CLEAN (5)
#define JOBID_BACKGROUND_CLEAN (5 * 60)

struct session_jobid {
	struct pid		*sj_session;
	struct rhash_head	sj_linkage;
	struct rcu_head		sj_rcu;
	char			sj_jobid[1];
};

static const struct rhashtable_params jobid_params = {
	.key_len	= sizeof(struct pid *),
	.key_offset	= offsetof(struct session_jobid, sj_session),
	.head_offset	= offsetof(struct session_jobid, sj_linkage),
};

static struct rhashtable session_jobids;

/*
 * jobid_current must be called with rcu_read_lock held.
 * if it returns non-NULL, the string can only be used
 * until rcu_read_unlock is called.
 */
char *jobid_current(void)
{
	struct pid *sid = task_session(current);
	struct session_jobid *sj;

	sj = rhashtable_lookup_fast(&session_jobids, &sid, jobid_params);
	if (sj)
		return sj->sj_jobid;
	return NULL;
}

static void jobid_prune_expedite(void);
/*
 * jobid_set_current will try to add a new entry
 * to the table.  If one exists with the same key, the
 * jobid will be replaced
 */
int jobid_set_current(char *jobid)
{
	struct pid *sid;
	struct session_jobid *sj, *origsj;
	int ret;
	int len = strlen(jobid);

	sj = kmalloc(sizeof(*sj) + len, GFP_KERNEL);
	if (!sj)
		return -ENOMEM;
	rcu_read_lock();
	sid = task_session(current);
	sj->sj_session = get_pid(sid);
	strncpy(sj->sj_jobid, jobid, len+1);
	origsj = rhashtable_lookup_get_insert_fast(&session_jobids,
						   &sj->sj_linkage,
						   jobid_params);
	if (origsj == NULL) {
		/* successful insert */
		rcu_read_unlock();
		jobid_prune_expedite();
		return 0;
	}

	if (IS_ERR(origsj)) {
		put_pid(sj->sj_session);
		kfree(sj);
		rcu_read_unlock();
		return PTR_ERR(origsj);
	}
	ret = rhashtable_replace_fast(&session_jobids,
				      &origsj->sj_linkage,
				      &sj->sj_linkage,
				      jobid_params);
	if (ret) {
		put_pid(sj->sj_session);
		kfree(sj);
		rcu_read_unlock();
		return ret;
	}
	put_pid(origsj->sj_session);
	rcu_read_unlock();
	kfree_rcu(origsj, sj_rcu);
	jobid_prune_expedite();

	return 0;
}

static void jobid_free(void *vsj, void *arg)
{
	struct session_jobid *sj = vsj;

	put_pid(sj->sj_session);
	kfree(sj);
}

static void jobid_prune(struct work_struct *work);
static DECLARE_DELAYED_WORK(jobid_prune_work, jobid_prune);
static int jobid_prune_expedited;
static void jobid_prune(struct work_struct *work)
{
	int remaining = 0;
	struct rhashtable_iter iter;
	struct session_jobid *sj;

	jobid_prune_expedited = 0;
	rhashtable_walk_enter(&session_jobids, &iter);
	rhashtable_walk_start(&iter);
	while ((sj = rhashtable_walk_next(&iter)) != NULL) {
		if (!hlist_empty(&sj->sj_session->tasks[PIDTYPE_SID])) {
			remaining++;
			continue;
		}
		if (rhashtable_remove_fast(&session_jobids,
					   &sj->sj_linkage,
					   jobid_params) == 0) {
			put_pid(sj->sj_session);
			kfree_rcu(sj, sj_rcu);
		}
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	if (remaining)
		schedule_delayed_work(&jobid_prune_work,
				      cfs_time_seconds(JOBID_BACKGROUND_CLEAN));
}

static void jobid_prune_expedite(void)
{
	if (!jobid_prune_expedited) {
		jobid_prune_expedited = 1;
		mod_delayed_work(system_wq, &jobid_prune_work,
				 cfs_time_seconds(JOBID_EXPEDITED_CLEAN));
	}
}

static int cfs_access_process_vm(struct task_struct *tsk,
				 struct mm_struct *mm,
				 unsigned long addr,
				 void *buf, int len, int write)
{
	/* Just copied from kernel for the kernels which doesn't
	 * have access_process_vm() exported
	 */
	struct vm_area_struct *vma;
	struct page *page;
	void *old_buf = buf;

	/* Avoid deadlocks on mmap_sem if called from sys_mmap_pgoff(),
	 * which is already holding mmap_sem for writes.  If some other
	 * thread gets the write lock in the meantime, this thread will
	 * block, but at least it won't deadlock on itself.  LU-1735
	 */
	if (!mmap_read_trylock(mm))
		return -EDEADLK;

	/* ignore errors, just check how much was successfully transferred */
	while (len) {
		int bytes, rc, offset;
		void *maddr;

#if defined(HAVE_GET_USER_PAGES_GUP_FLAGS)
		rc = get_user_pages(addr, 1, write ? FOLL_WRITE : 0, &page,
				    &vma);
#elif defined(HAVE_GET_USER_PAGES_6ARG)
		rc = get_user_pages(addr, 1, write, 1, &page, &vma);
#else
		rc = get_user_pages(tsk, mm, addr, 1, write, 1, &page, &vma);
#endif
		if (rc <= 0)
			break;

		bytes = len;
		offset = addr & (PAGE_SIZE-1);
		if (bytes > PAGE_SIZE-offset)
			bytes = PAGE_SIZE-offset;

		maddr = kmap(page);
		if (write) {
			copy_to_user_page(vma, page, addr,
					  maddr + offset, buf, bytes);
			set_page_dirty_lock(page);
		} else {
			copy_from_user_page(vma, page, addr,
					    buf, maddr + offset, bytes);
		}
		kunmap(page);
		put_page(page);
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	mmap_read_unlock(mm);

	return buf - old_buf;
}

/* Read the environment variable of current process specified by @key. */
static int cfs_get_environ(const char *key, char *value, int *val_len)
{
	struct mm_struct *mm;
	char *buffer;
	int buf_len = PAGE_SIZE;
	int key_len = strlen(key);
	unsigned long addr;
	int rc;
	bool skip = false;

	ENTRY;
	buffer = kmalloc(buf_len, GFP_USER);
	if (!buffer)
		RETURN(-ENOMEM);

	mm = get_task_mm(current);
	if (!mm) {
		kfree(buffer);
		RETURN(-EINVAL);
	}

	addr = mm->env_start;
	while (addr < mm->env_end) {
		int this_len, retval, scan_len;
		char *env_start, *env_end;

		memset(buffer, 0, buf_len);

		this_len = min_t(int, mm->env_end - addr, buf_len);
		retval = cfs_access_process_vm(current, mm, addr, buffer,
					       this_len, 0);
		if (retval < 0)
			GOTO(out, rc = retval);
		else if (retval != this_len)
			break;

		addr += retval;

		/* Parse the buffer to find out the specified key/value pair.
		 * The "key=value" entries are separated by '\0'.
		 */
		env_start = buffer;
		scan_len = this_len;
		while (scan_len) {
			char *entry;
			int entry_len;

			env_end = memscan(env_start, '\0', scan_len);
			LASSERT(env_end >= env_start &&
				env_end <= env_start + scan_len);

			/* The last entry of this buffer cross the buffer
			 * boundary, reread it in next cycle.
			 */
			if (unlikely(env_end - env_start == scan_len)) {
				/* Just skip the entry larger than page size,
				 * it can't be jobID env variable.
				 */
				if (unlikely(scan_len == this_len))
					skip = true;
				else
					addr -= scan_len;
				break;
			} else if (unlikely(skip)) {
				skip = false;
				goto skip;
			}
			entry = env_start;
			entry_len = env_end - env_start;
			CDEBUG(D_INFO, "key: %s, entry: %s\n", key, entry);

			/* Key length + length of '=' */
			if (entry_len > key_len + 1 &&
			    entry[key_len] == '='  &&
			    !memcmp(entry, key, key_len)) {
				entry += key_len + 1;
				entry_len -= key_len + 1;

				/* The 'value' buffer passed in is too small.
				 * Copy what fits, but return -EOVERFLOW.
				 */
				if (entry_len >= *val_len) {
					memcpy(value, entry, *val_len);
					value[*val_len - 1] = 0;
					GOTO(out, rc = -EOVERFLOW);
				}

				memcpy(value, entry, entry_len);
				*val_len = entry_len;
				GOTO(out, rc = 0);
			}
skip:
			scan_len -= (env_end - env_start + 1);
			env_start = env_end + 1;
		}
	}
	GOTO(out, rc = -ENOENT);

out:
	mmput(mm);
	kfree((void *)buffer);
	return rc;
}

/*
 * Get jobid of current process by reading the environment variable
 * stored in between the "env_start" & "env_end" of task struct.
 *
 * If some job scheduler doesn't store jobid in the "env_start/end",
 * then an upcall could be issued here to get the jobid by utilizing
 * the userspace tools/API. Then, the jobid must be cached.
 */
int jobid_get_from_environ(char *jobid_var, char *jobid, int *jobid_len)
{
	int rc;

	rc = cfs_get_environ(jobid_var, jobid, jobid_len);
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
		static ktime_t printed;

		if (unlikely(ktime_to_ns(printed) == 0 ||
			     ktime_after(ktime_get(),
					 ktime_add_ns(printed,
					     3600ULL * 24 * NSEC_PER_SEC)))) {
			LCONSOLE_WARN("jobid: '%s' value too large (%d)\n",
				      obd_jobid_var, *jobid_len);
			printed = ktime_get();
		}

		rc = 0;
	} else {
		CDEBUG_LIMIT((rc == -ENOENT || rc == -EINVAL ||
			      rc == -EDEADLK) ? D_INFO : D_ERROR,
			     "jobid: get '%s' failed: rc = %d\n",
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
	struct jobid_pid_map *pidmap = obj;
	int rc = 0;

	if (obj == NULL)
		return 0;

	if (jobid == NULL) {
		WARN_ON_ONCE(atomic_read(&pidmap->jp_refcount) != 1);
		return 1;
	}

	spin_lock(&pidmap->jp_lock);
	/* prevent newly inserted items from deleting */
	if (jobid[0] == '\0' && atomic_read(&pidmap->jp_refcount) == 1)
		rc = 1;
	else if (ktime_get_real_seconds() - pidmap->jp_time > DELETE_INTERVAL)
		rc = 1;
	else if (strcmp(pidmap->jp_jobid, jobid) == 0)
		rc = 1;
	spin_unlock(&pidmap->jp_lock);

	return rc;
}

/*
 * jobid_name_is_valid
 *
 * Checks if the jobid is a Lustre process
 *
 * Returns true if jobid is valid
 * Returns false if jobid looks like it's a Lustre process
 */
static bool jobid_name_is_valid(char *jobid)
{
	const char *const lustre_reserved[] = { "ll_ping", "ptlrpc",
						"ldlm", "ll_sa", NULL };
	int i;

	if (jobid[0] == '\0')
		return false;

	for (i = 0; lustre_reserved[i] != NULL; i++) {
		if (strncmp(jobid, lustre_reserved[i],
			    strlen(lustre_reserved[i])) == 0)
			return false;
	}
	return true;
}

/*
 * jobid_get_from_cache()
 *
 * Returns contents of jobid_var from process environment for current PID,
 * or from the per-session jobid table.
 * Values fetch from process environment will be cached for some time to avoid
 * the overhead of scanning the environment.
 *
 * Return: -ENOMEM if allocating a new pidmap fails
 *         -ENOENT if no entry could be found
 *         +ve string length for success (something was returned in jobid)
 */
static int jobid_get_from_cache(char *jobid, size_t joblen)
{
	static time64_t last_expire;
	bool expire_cache = false;
	pid_t pid = current->pid;
	struct jobid_pid_map *pidmap = NULL;
	time64_t now = ktime_get_real_seconds();
	int rc = 0;
	ENTRY;

	if (strcmp(obd_jobid_var, JOBSTATS_SESSION) == 0) {
		char *jid;

		rcu_read_lock();
		jid = jobid_current();
		if (jid) {
			strlcpy(jobid, jid, joblen);
			joblen = strlen(jobid);
		} else {
			rc = -ENOENT;
		}
		rcu_read_unlock();
		GOTO(out, rc);
	}

	LASSERT(jobid_hash != NULL);

	/* scan hash periodically to remove old PID entries from cache */
	spin_lock(&jobid_hash_lock);
	if (unlikely(last_expire + DELETE_INTERVAL <= now)) {
		expire_cache = true;
		last_expire = now;
	}
	spin_unlock(&jobid_hash_lock);

	if (expire_cache)
		cfs_hash_cond_del(jobid_hash, jobid_should_free_item,
				  "intentionally_bad_jobid");

	/* first try to find PID in the hash and use that value */
	pidmap = cfs_hash_lookup(jobid_hash, &pid);
	if (pidmap == NULL) {
		struct jobid_pid_map *pidmap2;

		OBD_ALLOC_PTR(pidmap);
		if (pidmap == NULL)
			GOTO(out, rc = -ENOMEM);

		pidmap->jp_pid = pid;
		pidmap->jp_time = 0;
		pidmap->jp_jobid[0] = '\0';
		spin_lock_init(&pidmap->jp_lock);
		INIT_HLIST_NODE(&pidmap->jp_hash);
		/*
		 * @pidmap might be reclaimed just after it is added into
		 * hash list, init @jp_refcount as 1 to make sure memory
		 * could be not freed during access.
		 */
		atomic_set(&pidmap->jp_refcount, 1);

		/*
		 * Add the newly created map to the hash, on key collision we
		 * lost a racing addition and must destroy our newly allocated
		 * map.  The object which exists in the hash will be returned.
		 */
		pidmap2 = cfs_hash_findadd_unique(jobid_hash, &pid,
						  &pidmap->jp_hash);
		if (unlikely(pidmap != pidmap2)) {
			CDEBUG(D_INFO, "jobid: duplicate found for PID=%u\n",
			       pid);
			OBD_FREE_PTR(pidmap);
			pidmap = pidmap2;
		}
	}

	/*
	 * If pidmap is old (this is always true for new entries) refresh it.
	 * If obd_jobid_var is not found, cache empty entry and try again
	 * later, to avoid repeat lookups for PID if obd_jobid_var missing.
	 */
	spin_lock(&pidmap->jp_lock);
	if (pidmap->jp_time + RESCAN_INTERVAL <= now) {
		char env_jobid[LUSTRE_JOBID_SIZE] = "";
		int env_len = sizeof(env_jobid);

		pidmap->jp_time = now;

		spin_unlock(&pidmap->jp_lock);
		rc = jobid_get_from_environ(obd_jobid_var, env_jobid, &env_len);

		CDEBUG(D_INFO, "jobid: PID mapping established: %d->%s\n",
		       pidmap->jp_pid, env_jobid);
		spin_lock(&pidmap->jp_lock);
		if (!rc) {
			pidmap->jp_joblen = env_len;
			strlcpy(pidmap->jp_jobid, env_jobid,
				sizeof(pidmap->jp_jobid));
			rc = 0;
		} else if (rc == -ENOENT) {
			/* It might have been deleted, clear out old entry */
			pidmap->jp_joblen = 0;
			pidmap->jp_jobid[0] = '\0';
		}
	}

	/*
	 * Regardless of how pidmap was found, if it contains a valid entry
	 * use that for now.  If there was a technical error (e.g. -ENOMEM)
	 * use the old cached value until it can be looked up again properly.
	 * If a cached missing entry was found, return -ENOENT.
	 */
	if (pidmap->jp_joblen) {
		strlcpy(jobid, pidmap->jp_jobid, joblen);
		joblen = pidmap->jp_joblen;
		rc = 0;
	} else if (!rc) {
		rc = -ENOENT;
	}
	spin_unlock(&pidmap->jp_lock);

	cfs_hash_put(jobid_hash, &pidmap->jp_hash);

	EXIT;
out:
	return rc < 0 ? rc : joblen;
}

/*
 * jobid_interpret_string()
 *
 * Interpret the jobfmt string to expand specified fields, like coredumps do:
 *   %e = executable
 *   %g = gid
 *   %h = hostname
 *   %H = short hostname
 *   %j = jobid from environment
 *   %p = pid
 *   %u = uid
 *
 * Unknown escape strings are dropped.  Other characters are copied through,
 * excluding whitespace (to avoid making jobid parsing difficult).
 *
 * Return: -EOVERFLOW if the expanded string does not fit within @joblen
 *         0 for success
 */
static int jobid_interpret_string(const char *jobfmt, char *jobid,
				  ssize_t joblen)
{
	char c;

	while ((c = *jobfmt++) && joblen > 1) {
		char f, *p;
		int l;

		if (isspace(c)) /* Don't allow embedded spaces */
			continue;

		if (c != '%') {
			*jobid = c;
			joblen--;
			jobid++;
			*jobid = '\0';
			continue;
		}

		switch ((f = *jobfmt++)) {
		case 'e': /* executable name */
			l = snprintf(jobid, joblen, "%s", current->comm);
			break;
		case 'g': /* group ID */
			l = snprintf(jobid, joblen, "%u",
				     from_kgid(&init_user_ns, current_fsgid()));
			break;
		case 'h': /* hostname */
			l = snprintf(jobid, joblen, "%s",
				     init_utsname()->nodename);
			break;
		case 'H': /* short hostname. Cut at first dot */
			l = snprintf(jobid, joblen, "%s",
				     init_utsname()->nodename);
			p = strnchr(jobid, joblen, '.');
			if (p) {
				*p = '\0';
				l = p - jobid;
			}
			break;
		case 'j': /* jobid stored in process environment */
			l = jobid_get_from_cache(jobid, joblen);
			if (l < 0)
				l = 0;
			break;
		case 'p': /* process ID */
			l = snprintf(jobid, joblen, "%u", current->pid);
			break;
		case 'u': /* user ID */
			l = snprintf(jobid, joblen, "%u",
				     from_kuid(&init_user_ns, current_fsuid()));
			break;
		case '\0': /* '%' at end of format string */
			l = 0;
			goto out;
		default: /* drop unknown %x format strings */
			l = 0;
			break;
		}
		jobid += l;
		joblen -= l;
	}
	/*
	 * This points at the end of the buffer, so long as jobid is always
	 * incremented the same amount as joblen is decremented.
	 */
out:
	jobid[joblen - 1] = '\0';

	return joblen < 0 ? -EOVERFLOW : 0;
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
	ENTRY;

	if (jobid_hash)
		return 0;

	spin_lock_init(&jobid_hash_lock);
	jobid_hash = cfs_hash_create("JOBID_HASH", HASH_JOBID_CUR_BITS,
				     HASH_JOBID_MAX_BITS, HASH_JOBID_BKT_BITS,
				     0, CFS_HASH_MIN_THETA, CFS_HASH_MAX_THETA,
				     &jobid_hash_ops, CFS_HASH_DEFAULT);
	if (!jobid_hash) {
		rc = -ENOMEM;
	} else {
		rc = rhashtable_init(&session_jobids, &jobid_params);
		if (rc) {
			cfs_hash_putref(jobid_hash);
			jobid_hash = NULL;
		}
	}

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

	cancel_delayed_work_sync(&jobid_prune_work);

	if (tmp_hash != NULL) {
		cfs_hash_cond_del(tmp_hash, jobid_should_free_item, NULL);
		cfs_hash_putref(tmp_hash);

		rhashtable_free_and_destroy(&session_jobids, jobid_free, NULL);
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
	struct jobid_pid_map *pidmap;

	pidmap = hlist_entry(hnode, struct jobid_pid_map, jp_hash);
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
	return hlist_entry(hnode, struct jobid_pid_map, jp_hash);
}

static void jobid_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct jobid_pid_map *pidmap;

	pidmap = hlist_entry(hnode, struct jobid_pid_map, jp_hash);

	atomic_inc(&pidmap->jp_refcount);
}

static void jobid_put_locked(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct jobid_pid_map *pidmap;

	if (hnode == NULL)
		return;

	pidmap = hlist_entry(hnode, struct jobid_pid_map, jp_hash);
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

/**
 * Generate the job identifier string for this process for tracking purposes.
 *
 * Fill in @jobid string based on the value of obd_jobid_var:
 * JOBSTATS_DISABLE:      none
 * JOBSTATS_NODELOCAL:    content of obd_jobid_name (jobid_interpret_string())
 * JOBSTATS_PROCNAME_UID: process name/UID
 * JOBSTATS_SESSION       per-session value set by
 *                            /sys/fs/lustre/jobid_this_session
 * anything else:         look up obd_jobid_var in the processes environment
 *
 * Return -ve error number, 0 on success.
 */
int lustre_get_jobid(char *jobid, size_t joblen)
{
	int rc = 0;
	ENTRY;

	if (unlikely(joblen < 2)) {
		if (joblen == 1)
			jobid[0] = '\0';
		RETURN(-EINVAL);
	}

	if (strcmp(obd_jobid_var, JOBSTATS_DISABLE) == 0) {
		/* Jobstats isn't enabled */
		memset(jobid, 0, joblen);
	} else if (strcmp(obd_jobid_var, JOBSTATS_NODELOCAL) == 0) {
		/* Whole node dedicated to single job */
		rc = jobid_interpret_string(obd_jobid_name, jobid, joblen);
	} else if (strcmp(obd_jobid_var, JOBSTATS_PROCNAME_UID) == 0) {
		rc = jobid_interpret_string("%e.%u", jobid, joblen);
	} else if (strcmp(obd_jobid_var, JOBSTATS_SESSION) == 0 ||
		   jobid_name_is_valid(current->comm)) {
		/*
		 * per-process jobid wanted, either from environment or from
		 * per-session setting.
		 * If obd_jobid_name contains "%j" or if getting the per-process
		 * jobid directly fails, fall back to using obd_jobid_name.
		 */
		rc = -EAGAIN;
		if (!strnstr(obd_jobid_name, "%j", joblen))
			rc = jobid_get_from_cache(jobid, joblen);

		/* fall back to jobid_name if jobid_var not available */
		if (rc < 0) {
			int rc2 = jobid_interpret_string(obd_jobid_name,
							 jobid, joblen);
			if (!rc2)
				rc = 0;
		}
	}

	RETURN(rc);
}
EXPORT_SYMBOL(lustre_get_jobid);

/*
 * lustre_jobid_clear
 *
 * Search cache for JobID given by @find_jobid.
 * If any entries in the hash table match the value, they are removed
 */
void lustre_jobid_clear(const char *find_jobid)
{
	char jobid[LUSTRE_JOBID_SIZE];
	char *end;

	if (jobid_hash == NULL)
		return;

	strlcpy(jobid, find_jobid, sizeof(jobid));
	/* trim \n off the end of the incoming jobid */
	end = strchr(jobid, '\n');
	if (end && *end == '\n')
		*end = '\0';

	CDEBUG(D_INFO, "Clearing Jobid: %s\n", jobid);
	cfs_hash_cond_del(jobid_hash, jobid_should_free_item, jobid);

	CDEBUG(D_INFO, "%d items remain in jobID table\n",
	       atomic_read(&jobid_hash->hs_count));
}
