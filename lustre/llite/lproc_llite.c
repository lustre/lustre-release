// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/version.h>
#include <linux/user_namespace.h>
#include <linux/uidgid.h>

#include <uapi/linux/lustre/lustre_param.h>
#include <lprocfs_status.h>
#include <obd_support.h>

#include "llite_internal.h"
#include "lprocfs_status.h"
#include "vvp_internal.h"

static struct kobject *llite_kobj;
static struct dentry *llite_root;

static void llite_kobj_release(struct kobject *kobj)
{
	if (!IS_ERR_OR_NULL(llite_root)) {
		debugfs_remove(llite_root);
		llite_root = NULL;
	}

	kfree(kobj);
}

static struct kobj_type llite_kobj_ktype = {
	.release	= llite_kobj_release,
	.sysfs_ops	= &lustre_sysfs_ops,
};

int llite_tunables_register(void)
{
	int rc;

	llite_kobj = kzalloc(sizeof(*llite_kobj), GFP_KERNEL);
	if (!llite_kobj)
		return -ENOMEM;

	llite_kobj->kset = lustre_kset;
	rc = kobject_init_and_add(llite_kobj, &llite_kobj_ktype,
				  &lustre_kset->kobj, "%s", "llite");
	if (rc)
		goto free_kobj;

	llite_root = debugfs_create_dir("llite", debugfs_lustre_root);
	return 0;

free_kobj:
	kobject_put(llite_kobj);
	llite_kobj = NULL;

	return rc;
}

void llite_tunables_unregister(void)
{
	kobject_put(llite_kobj);
	llite_kobj = NULL;
}

/* <debugfs>/lustre/llite mount point registration */
static const struct file_operations ll_rw_extents_stats_fops;
static const struct file_operations ll_rw_extents_stats_pp_fops;
static const struct file_operations ll_rw_offset_stats_fops;

/**
 * ll_stats_pid_write() - Determine if stats collection should be enabled
 * @buf: Buffer containing the data written
 * @len: Number of bytes in the buffer
 *
 * Several proc files begin collecting stats when a value is written, and stop
 * collecting when either '0' or 'disable' is written. This function checks the
 * written value to see if collection should be enabled or disabled.
 *
 * Return: If '0' or 'disable' is provided, 0 is returned. If the text
 * equivalent of a number is written, that number is returned. Otherwise,
 * 1 is returned. Non-zero return values indicate collection should be enabled.
 */
static s64 ll_stats_pid_write(const char __user *buf, size_t len)
{
	unsigned long long value = 1;
	char kernbuf[16];
	int rc;

	if (len == 0)
		return -EINVAL;
	rc = kstrtoull_from_user(buf, len, 0, &value);
	if (rc < 0 && len < sizeof(kernbuf)) {
		if (copy_from_user(kernbuf, buf, len))
			return -EFAULT;
		kernbuf[len] = 0;

		if (kernbuf[len - 1] == '\n')
			kernbuf[len - 1] = 0;

		if (strncasecmp(kernbuf, "disable", 7) == 0)
			value = 0;
	}

	return value;
}

static ssize_t blocksize_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct obd_statfs osfs;
	int rc;

	rc = ll_statfs_internal(sbi, &osfs, OBD_STATFS_NODELAY);
	if (rc)
		return rc;

	return scnprintf(buf, PAGE_SIZE, "%u\n", osfs.os_bsize);
}
LUSTRE_RO_ATTR(blocksize);

static ssize_t stat_blocksize_show(struct kobject *kobj, struct attribute *attr,
				   char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_stat_blksize);
}

static ssize_t stat_blocksize_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buffer,
				    size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	if (val != 0 && (val < PAGE_SIZE || (val & (val - 1))) != 0)
		return -ERANGE;

	sbi->ll_stat_blksize = val;

	return count;
}
LUSTRE_RW_ATTR(stat_blocksize);

static ssize_t kbytestotal_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct obd_statfs osfs;
	u32 blk_size;
	u64 result;
	int rc;

	rc = ll_statfs_internal(sbi, &osfs, OBD_STATFS_NODELAY);
	if (rc)
		return rc;

	blk_size = osfs.os_bsize >> 10;
	result = osfs.os_blocks;

	while (blk_size >>= 1)
		result <<= 1;

	return scnprintf(buf, PAGE_SIZE, "%llu\n", result);
}
LUSTRE_RO_ATTR(kbytestotal);

static ssize_t kbytesfree_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct obd_statfs osfs;
	u32 blk_size;
	u64 result;
	int rc;

	rc = ll_statfs_internal(sbi, &osfs, OBD_STATFS_NODELAY);
	if (rc)
		return rc;

	blk_size = osfs.os_bsize >> 10;
	result = osfs.os_bfree;

	while (blk_size >>= 1)
		result <<= 1;

	return scnprintf(buf, PAGE_SIZE, "%llu\n", result);
}
LUSTRE_RO_ATTR(kbytesfree);

static ssize_t kbytesavail_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct obd_statfs osfs;
	u32 blk_size;
	u64 result;
	int rc;

	rc = ll_statfs_internal(sbi, &osfs, OBD_STATFS_NODELAY);
	if (rc)
		return rc;

	blk_size = osfs.os_bsize >> 10;
	result = osfs.os_bavail;

	while (blk_size >>= 1)
		result <<= 1;

	return scnprintf(buf, PAGE_SIZE, "%llu\n", result);
}
LUSTRE_RO_ATTR(kbytesavail);

static ssize_t filestotal_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct obd_statfs osfs;
	int rc;

	rc = ll_statfs_internal(sbi, &osfs, OBD_STATFS_NODELAY);
	if (rc)
		return rc;

	return scnprintf(buf, PAGE_SIZE, "%llu\n", osfs.os_files);
}
LUSTRE_RO_ATTR(filestotal);

static ssize_t filesfree_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct obd_statfs osfs;
	int rc;

	rc = ll_statfs_internal(sbi, &osfs, OBD_STATFS_NODELAY);
	if (rc)
		return rc;

	return scnprintf(buf, PAGE_SIZE, "%llu\n", osfs.os_ffree);
}
LUSTRE_RO_ATTR(filesfree);

static ssize_t maxbytes_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct obd_statfs osfs;
	int rc;

	rc = ll_statfs_internal(sbi, &osfs, OBD_STATFS_NODELAY);
	if (rc)
		return rc;

	return scnprintf(buf, PAGE_SIZE, "%llu\n", osfs.os_maxbytes);
}
LUSTRE_RO_ATTR(maxbytes);

static ssize_t namelen_max_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_namelen);
}

static ssize_t namelen_max_store(struct kobject *kobj, struct attribute *attr,
				 const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct obd_statfs osfs;
	int val;
	int rc;

	rc = kstrtoint(buffer, 10, &val);
	if (rc)
		return rc;

	rc = ll_statfs_internal(sbi, &osfs, OBD_STATFS_NODELAY);
	if (rc)
		return rc;

	if (val < 12) { /* arbitrary sanity check, but 8.3 was OK for DOS :-) */
		CERROR("%s: cannot set max filename length %u below 12 chars\n",
		       sbi->ll_fsname, val);
		return -ERANGE;
	}

	/* NAME_MAX is not strictly a VFS limit, but more of a convention.
	 * It would be possible to allow filenames over NAME_MAX, if the
	 * code in the client and server was fixed to allow this as well.
	 */
	if (val > NAME_MAX) {
		CERROR("%s: cannot set max filename length %u over VFS limit of %u chars\n",
		       sbi->ll_fsname, val, NAME_MAX);
		return -EOVERFLOW;
	}
	if (val > osfs.os_namelen) {
		CERROR("%s: cannot set max filename length %u over MDT limit of %u chars\n",
		       sbi->ll_fsname, val, osfs.os_namelen);
		return -EOVERFLOW;
	}

	sbi->ll_namelen = val;

	return count;
}
LUSTRE_RW_ATTR(namelen_max);

static ssize_t statfs_state_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct obd_statfs osfs;
	int rc;

	rc = ll_statfs_internal(sbi, &osfs, OBD_STATFS_NODELAY);
	if (rc)
		return rc;

	return lprocfs_statfs_state(buf, PAGE_SIZE, osfs.os_state);
}
LUSTRE_RO_ATTR(statfs_state);

static ssize_t client_type_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	return sprintf(buf, "local client\n");
}
LUSTRE_RO_ATTR(client_type);

LUSTRE_RW_ATTR(foreign_symlink_enable);

LUSTRE_RW_ATTR(foreign_symlink_prefix);

LUSTRE_RW_ATTR(foreign_symlink_upcall);

LUSTRE_WO_ATTR(foreign_symlink_upcall_info);

static ssize_t fstype_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	return sprintf(buf, "lustre\n");
}
LUSTRE_RO_ATTR(fstype);

static ssize_t uuid_show(struct kobject *kobj, struct attribute *attr,
			 char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return sprintf(buf, "%s\n", sbi->ll_sb_uuid.uuid);
}
LUSTRE_RO_ATTR(uuid);

static int ll_site_stats_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;

	/*
	 * See description of statistical counters in struct cl_site, and
	 * struct lu_site.
	 */
	return cl_site_stats_print(lu2cl_site(ll_s2sbi(sb)->ll_site), m);
}

LDEBUGFS_SEQ_FOPS_RO(ll_site_stats);

static ssize_t max_read_ahead_mb_show(struct kobject *kobj,
				      struct attribute *attr, char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%lu\n",
			PAGES_TO_MiB(sbi->ll_ra_info.ra_max_pages));
}

static ssize_t max_read_ahead_mb_store(struct kobject *kobj,
				       struct attribute *attr,
				       const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	u64 ra_max_mb, pages_number;
	int rc;

	rc = sysfs_memparse(buffer, count, &ra_max_mb, "MiB");
	if (rc)
		return rc;

	pages_number = round_up(ra_max_mb, 1024 * 1024) >> PAGE_SHIFT;
	CDEBUG(D_INFO, "%s: set max_read_ahead_mb=%llu (%llu pages)\n",
	       sbi->ll_fsname, PAGES_TO_MiB(pages_number), pages_number);
	if (pages_number > cfs_totalram_pages() / 2) {
		/* 1/2 of RAM */
		CERROR("%s: cannot set max_read_ahead_mb=%llu > totalram/2=%luMB\n",
		       sbi->ll_fsname, PAGES_TO_MiB(pages_number),
		       PAGES_TO_MiB(cfs_totalram_pages() / 2));
		return -ERANGE;
	}

	spin_lock(&sbi->ll_lock);
	sbi->ll_ra_info.ra_max_pages = pages_number;
	spin_unlock(&sbi->ll_lock);

	return count;
}
LUSTRE_RW_ATTR(max_read_ahead_mb);

static ssize_t max_read_ahead_per_file_mb_show(struct kobject *kobj,
					       struct attribute *attr,
					       char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%lu\n",
			 PAGES_TO_MiB(sbi->ll_ra_info.ra_max_pages_per_file));
}

static ssize_t max_read_ahead_per_file_mb_store(struct kobject *kobj,
						struct attribute *attr,
						const char *buffer,
						size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	u64 ra_max_file_mb, pages_number;
	int rc;

	rc = sysfs_memparse(buffer, count, &ra_max_file_mb, "MiB");
	if (rc)
		return rc;

	pages_number = round_up(ra_max_file_mb, 1024 * 1024) >> PAGE_SHIFT;
	if (pages_number > sbi->ll_ra_info.ra_max_pages) {
		CERROR("%s: cannot set max_read_ahead_per_file_mb=%llu > max_read_ahead_mb=%lu\n",
		       sbi->ll_fsname, PAGES_TO_MiB(pages_number),
		       PAGES_TO_MiB(sbi->ll_ra_info.ra_max_pages));
		return -ERANGE;
	}

	spin_lock(&sbi->ll_lock);
	sbi->ll_ra_info.ra_max_pages_per_file = pages_number;
	spin_unlock(&sbi->ll_lock);

	return count;
}
LUSTRE_RW_ATTR(max_read_ahead_per_file_mb);

static ssize_t max_read_ahead_whole_mb_show(struct kobject *kobj,
					    struct attribute *attr, char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%lu\n",
			 PAGES_TO_MiB(sbi->ll_ra_info.ra_max_read_ahead_whole_pages));
}

static ssize_t max_read_ahead_whole_mb_store(struct kobject *kobj,
					     struct attribute *attr,
					     const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	u64 ra_max_whole_mb, pages_number;
	int rc;

	rc = sysfs_memparse(buffer, count, &ra_max_whole_mb, "MiB");
	if (rc)
		return rc;

	pages_number = round_up(ra_max_whole_mb, 1024 * 1024) >> PAGE_SHIFT;
	/* Cap this at the current max readahead window size, the readahead
	 * algorithm does this anyway so it's pointless to set it larger.
	 */
	if (pages_number > sbi->ll_ra_info.ra_max_pages_per_file) {
		CERROR("%s: cannot set max_read_ahead_whole_mb=%llu > max_read_ahead_per_file_mb=%lu\n",
		       sbi->ll_fsname, PAGES_TO_MiB(pages_number),
		       PAGES_TO_MiB(sbi->ll_ra_info.ra_max_pages_per_file));

		return -ERANGE;
	}

	spin_lock(&sbi->ll_lock);
	sbi->ll_ra_info.ra_max_read_ahead_whole_pages = pages_number;
	spin_unlock(&sbi->ll_lock);

	return count;
}
LUSTRE_RW_ATTR(max_read_ahead_whole_mb);

static int ll_max_cached_mb_seq_show(struct seq_file *m, void *v)
{
	struct super_block     *sb    = m->private;
	struct ll_sb_info      *sbi   = ll_s2sbi(sb);
	struct cl_client_cache *cache = sbi->ll_cache;
	struct ll_ra_info *ra = &sbi->ll_ra_info;
	long max_cached_mb;
	long unused_mb;
	long unevict_mb;

	mutex_lock(&cache->ccc_max_cache_mb_lock);
	max_cached_mb = PAGES_TO_MiB(cache->ccc_lru_max);
	unused_mb = PAGES_TO_MiB(atomic_long_read(&cache->ccc_lru_left));
	unevict_mb = PAGES_TO_MiB(
			atomic_long_read(&cache->ccc_unevict_lru_used));
	mutex_unlock(&cache->ccc_max_cache_mb_lock);

	seq_printf(m, "users: %d\n"
		      "max_cached_mb: %ld\n"
		      "used_mb: %ld\n"
		      "unused_mb: %ld\n"
		      "unevict_mb: %ld\n"
		      "reclaim_count: %u\n"
		      "max_read_ahead_mb: %lu\n"
		      "used_read_ahead_mb: %d\n",
		   refcount_read(&cache->ccc_users),
		   max_cached_mb,
		   max_cached_mb - unused_mb,
		   unused_mb,
		   unevict_mb,
		   cache->ccc_lru_shrinkers,
		   PAGES_TO_MiB(ra->ra_max_pages),
		   PAGES_TO_MiB(atomic_read(&ra->ra_cur_pages)));
	return 0;
}

static ssize_t ll_max_cached_mb_seq_write(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct cl_client_cache *cache = sbi->ll_cache;
	struct lu_env *env;
	long diff = 0;
	long nrpages = 0;
	__u16 refcheck;
	u64 value;
	u64 pages_number;
	int rc;
	char kernbuf[128], *ptr;

	ENTRY;
	if (count >= sizeof(kernbuf))
		RETURN(-EINVAL);

	if (copy_from_user(kernbuf, buffer, count))
		RETURN(-EFAULT);

	kernbuf[count] = '\0';
	ptr = lprocfs_find_named_value(kernbuf, "max_cached_mb:", &count);
	rc = sysfs_memparse_total(ptr, count, &value,
				  cfs_totalram_pages() << PAGE_SHIFT, "MiB");
	if (rc == -ERANGE) {
		CERROR("%s: can't set max cache more than %lu MB\n",
		       sbi->ll_fsname,
		       PAGES_TO_MiB(cfs_totalram_pages()));
		RETURN(rc);
	}
	if (rc)
		RETURN(rc);

	pages_number = value >> PAGE_SHIFT;
	/* Allow enough cache so clients can make well-formed RPCs */
	pages_number = max_t(long, pages_number, PTLRPC_MAX_BRW_PAGES);

	mutex_lock(&cache->ccc_max_cache_mb_lock);
	diff = pages_number - cache->ccc_lru_max;

	/* easy - add more LRU slots. */
	if (diff >= 0) {
		atomic_long_add(diff, &cache->ccc_lru_left);
		GOTO(out, rc = 0);
	}

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		GOTO(out_unlock, rc = PTR_ERR(env));

	diff = -diff;
	while (diff > 0) {
		long tmp;

		/* reduce LRU budget from free slots. */
		do {
			long lru_left_old, lru_left_new, lru_left_ret;

			lru_left_old = atomic_long_read(&cache->ccc_lru_left);
			if (lru_left_old == 0)
				break;

			lru_left_new = lru_left_old > diff ?
					lru_left_old - diff : 0;
			lru_left_ret =
				atomic_long_cmpxchg(&cache->ccc_lru_left,
						    lru_left_old,
						    lru_left_new);
			if (likely(lru_left_old == lru_left_ret)) {
				diff -= lru_left_old - lru_left_new;
				nrpages += lru_left_old - lru_left_new;
				break;
			}
		} while (1);

		if (diff <= 0)
			break;

		if (sbi->ll_dt_exp == NULL) { /* being initialized */
			rc = -ENODEV;
			break;
		}

		/* Request extra free slots to avoid them all being used
		 * by other processes before this can continue shrinking.
		 */
		tmp = diff + min_t(long, diff, MiB_TO_PAGES(1024));
		/* difficult - have to ask OSCs to drop LRU slots. */
		rc = obd_set_info_async(env, sbi->ll_dt_exp,
				sizeof(KEY_CACHE_LRU_SHRINK),
				KEY_CACHE_LRU_SHRINK,
				sizeof(tmp), &tmp, NULL);
		if (rc < 0)
			break;
	}
	cl_env_put(env, &refcheck);

out:
	if (rc >= 0) {
		cache->ccc_lru_max = pages_number;
		rc = count;
	} else {
		atomic_long_add(nrpages, &cache->ccc_lru_left);
	}
out_unlock:
	mutex_unlock(&cache->ccc_max_cache_mb_lock);
	return rc;
}
LDEBUGFS_SEQ_FOPS(ll_max_cached_mb);

static int ll_unevict_cached_mb_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct cl_client_cache *cache = sbi->ll_cache;
	long unevict_mb;

	mutex_lock(&cache->ccc_max_cache_mb_lock);
	unevict_mb = PAGES_TO_MiB(
			atomic_long_read(&cache->ccc_unevict_lru_used));
	mutex_unlock(&cache->ccc_max_cache_mb_lock);

	seq_printf(m, "%ld\n", unevict_mb);
	return 0;
}

static ssize_t ll_unevict_cached_mb_seq_write(struct file *file,
					      const char __user *buffer,
					      size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct lu_env *env;
	__u16 refcheck;
	char kernbuf[128];
	int rc;

	ENTRY;

	if (count >= sizeof(kernbuf))
		RETURN(-EINVAL);

	if (copy_from_user(kernbuf, buffer, count))
		RETURN(-EFAULT);

	kernbuf[count] = 0;
	if (count != 5 || strncmp(kernbuf, "clear", 5) != 0)
		RETURN(-EINVAL);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	/* being initialized */
	if (sbi->ll_dt_exp == NULL)
		GOTO(out, rc = -ENODEV);

	rc = obd_set_info_async(env, sbi->ll_dt_exp,
				sizeof(KEY_UNEVICT_CACHE_SHRINK),
				KEY_UNEVICT_CACHE_SHRINK,
				0, NULL, NULL);
out:
	cl_env_put(env, &refcheck);
	if (rc >= 0)
		rc = count;

	RETURN(rc);
}
LDEBUGFS_SEQ_FOPS(ll_unevict_cached_mb);

static int ll_enable_mlock_pages_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct cl_client_cache *cache = sbi->ll_cache;

	seq_printf(m, "%d\n", cache->ccc_mlock_pages_enable);
	return 0;
}

static ssize_t ll_enable_mlock_pages_seq_write(struct file *file,
					       const char __user *buffer,
					       size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct cl_client_cache *cache = sbi->ll_cache;
	bool val;
	int rc;

	rc = kstrtobool_from_user(buffer, count, &val);
	if (rc)
		return rc;

	cache->ccc_mlock_pages_enable = val;
	return count;
}
LDEBUGFS_SEQ_FOPS(ll_enable_mlock_pages);

static ssize_t pcc_async_threshold_show(struct kobject *kobj,
					struct attribute *attr, char *buffer)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct pcc_super *super = &sbi->ll_pcc_super;

	return scnprintf(buffer, PAGE_SIZE, "%llu\n",
			 super->pccs_async_threshold);
}

static ssize_t pcc_async_threshold_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct pcc_super *super = &sbi->ll_pcc_super;
	u64 threshold;
	int rc;

	rc = sysfs_memparse(buffer, count, &threshold, "B");
	if (rc)
		return rc;

	super->pccs_async_threshold = threshold;

	return count;
}
LUSTRE_RW_ATTR(pcc_async_threshold);

static ssize_t pcc_async_affinity_show(struct kobject *kobj,
				       struct attribute *attr, char *buffer)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct pcc_super *super = &sbi->ll_pcc_super;

	return scnprintf(buffer, PAGE_SIZE, "%d\n", super->pccs_async_affinity);
}

static ssize_t pcc_async_affinity_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct pcc_super *super = &sbi->ll_pcc_super;
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	super->pccs_async_affinity = val;

	return count;
}
LUSTRE_RW_ATTR(pcc_async_affinity);

static ssize_t pcc_mode_show(struct kobject *kobj, struct attribute *attr,
			      char *buffer)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct pcc_super *super = &sbi->ll_pcc_super;

	return sprintf(buffer, "0%o\n", super->pccs_mode);

}

static ssize_t pcc_mode_store(struct kobject *kobj, struct attribute *attr,
			       const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct pcc_super *super = &sbi->ll_pcc_super;
	__u32 mode;
	int rc;

	rc = kstrtouint(buffer, 8, &mode);
	if (rc)
		return rc;

	if (mode & ~S_IRWXUGO)
		return -EINVAL;

	super->pccs_mode = mode;
	return count;
}
LUSTRE_RW_ATTR(pcc_mode);

static ssize_t checksums_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 test_bit(LL_SBI_CHECKSUM, sbi->ll_flags));
}

static ssize_t checksums_store(struct kobject *kobj, struct attribute *attr,
			       const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int tmp;
	int rc;

	if (!sbi->ll_dt_exp)
		/* Not set up yet */
		return -EAGAIN;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;
	if (val)
		set_bit(LL_SBI_CHECKSUM, sbi->ll_flags);
	else
		clear_bit(LL_SBI_CHECKSUM, sbi->ll_flags);
	tmp = val;

	rc = obd_set_info_async(NULL, sbi->ll_dt_exp, sizeof(KEY_CHECKSUM),
				KEY_CHECKSUM, sizeof(tmp), &tmp, NULL);
	if (rc)
		CWARN("Failed to set OSC checksum flags: %d\n", rc);

	return count;
}
LUSTRE_RW_ATTR(checksums);

LUSTRE_ATTR(checksum_pages, 0644, checksums_show, checksums_store);

static ssize_t ll_rd_track_id(struct kobject *kobj, char *buf,
			      enum stats_track_type type)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	if (sbi->ll_stats_track_type == type)
		return sprintf(buf, "%d\n", sbi->ll_stats_track_id);
	else if (sbi->ll_stats_track_type == STATS_TRACK_ALL)
		return sprintf(buf, "0 (all)\n");

	return sprintf(buf, "untracked\n");
}

static ssize_t ll_wr_track_id(struct kobject *kobj, const char *buffer,
			      size_t count, enum stats_track_type type)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned long pid;
	int rc;

	rc = kstrtoul(buffer, 10, &pid);
	if (rc)
		return rc;

	sbi->ll_stats_track_id = pid;
	if (pid == 0)
		sbi->ll_stats_track_type = STATS_TRACK_ALL;
	else
		sbi->ll_stats_track_type = type;
	lprocfs_stats_clear(sbi->ll_stats);
	return count;
}

static ssize_t stats_track_pid_show(struct kobject *kobj,
				    struct attribute *attr,
				    char *buf)
{
	return ll_rd_track_id(kobj, buf, STATS_TRACK_PID);
}

static ssize_t stats_track_pid_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer,
				     size_t count)
{
	return ll_wr_track_id(kobj, buffer, count, STATS_TRACK_PID);
}
LUSTRE_RW_ATTR(stats_track_pid);

static ssize_t stats_track_ppid_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	return ll_rd_track_id(kobj, buf, STATS_TRACK_PPID);
}

static ssize_t stats_track_ppid_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer,
				      size_t count)
{
	return ll_wr_track_id(kobj, buffer, count, STATS_TRACK_PPID);
}
LUSTRE_RW_ATTR(stats_track_ppid);

static ssize_t stats_track_gid_show(struct kobject *kobj,
				    struct attribute *attr,
				    char *buf)
{
	return ll_rd_track_id(kobj, buf, STATS_TRACK_GID);
}

static ssize_t stats_track_gid_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer,
				     size_t count)
{
	return ll_wr_track_id(kobj, buffer, count, STATS_TRACK_GID);
}
LUSTRE_RW_ATTR(stats_track_gid);

static ssize_t enable_statahead_fname_show(struct kobject *kobj,
					   struct attribute *attr,
					   char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_enable_statahead_fname);
}

static ssize_t enable_statahead_fname_store(struct kobject *kobj,
					    struct attribute *attr,
					    const char *buffer,
					    size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	sbi->ll_enable_statahead_fname = val;

	return count;
}
LUSTRE_RW_ATTR(enable_statahead_fname);

static ssize_t statahead_running_max_show(struct kobject *kobj,
					  struct attribute *attr,
					  char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_sa_running_max);
}

static ssize_t statahead_running_max_store(struct kobject *kobj,
					   struct attribute *attr,
					   const char *buffer,
					   size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned long val;
	int rc;

	rc = kstrtoul(buffer, 0, &val);
	if (rc)
		return rc;

	if (val <= LL_SA_RUNNING_MAX) {
		sbi->ll_sa_running_max = val;
		return count;
	}

	CERROR("Bad statahead_running_max value %lu. Valid values "
	       "are in the range [0, %d]\n", val, LL_SA_RUNNING_MAX);

	return -ERANGE;
}
LUSTRE_RW_ATTR(statahead_running_max);

static ssize_t statahead_batch_max_show(struct kobject *kobj,
					struct attribute *attr,
					char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, 16, "%u\n", sbi->ll_sa_batch_max);
}

static ssize_t statahead_batch_max_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buffer,
					 size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned long val;
	int rc;

	rc = kstrtoul(buffer, 0, &val);
	if (rc)
		return rc;

	if (val > LL_SA_BATCH_MAX) {
		CWARN("%s: statahead_batch_max value %lu limited to maximum %d\n",
		      sbi->ll_fsname, val, LL_SA_BATCH_MAX);
		val = LL_SA_BATCH_MAX;
	}

	sbi->ll_sa_batch_max = val;
	return count;
}
LUSTRE_RW_ATTR(statahead_batch_max);

static ssize_t statahead_max_show(struct kobject *kobj,
				  struct attribute *attr,
				  char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return sprintf(buf, "%u\n", sbi->ll_sa_max);
}

static ssize_t statahead_max_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buffer,
				   size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned long val;
	int rc;

	rc = kstrtoul(buffer, 0, &val);
	if (rc)
		return rc;

	if (val > LL_SA_REQ_MAX) {
		CWARN("%s: statahead_max value %lu limited to maximum %d\n",
		      sbi->ll_fsname, val, LL_SA_REQ_MAX);
		val = LL_SA_REQ_MAX;
	}

	sbi->ll_sa_max = val;
	return count;
}
LUSTRE_RW_ATTR(statahead_max);

static ssize_t statahead_min_show(struct kobject *kobj,
				  struct attribute *attr,
				  char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_sa_min);
}

static ssize_t statahead_min_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buffer,
				   size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned long val;
	int rc;

	rc = kstrtoul(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < LL_SA_REQ_MIN)
		CERROR("%s: bad statahead_min %lu < min %u\n",
		       sbi->ll_fsname, val, LL_SA_REQ_MIN);
	else if (val > sbi->ll_sa_max)
		CERROR("%s: bad statahead_min %lu > max %u\n",
		       sbi->ll_fsname, val, sbi->ll_sa_max);
	else
		sbi->ll_sa_min = val;

	return count;
}
LUSTRE_RW_ATTR(statahead_min);

static ssize_t statahead_timeout_show(struct kobject *kobj,
				      struct attribute *attr,
				      char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%lu\n", sbi->ll_sa_timeout);
}

static ssize_t statahead_timeout_store(struct kobject *kobj,
				       struct attribute *attr,
				       const char *buffer,
				       size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned long val;
	int rc;

	rc = kstrtoul(buffer, 0, &val);
	if (rc)
		return rc;

	sbi->ll_sa_timeout = val;
	return count;
}
LUSTRE_RW_ATTR(statahead_timeout);

static ssize_t
statahead_fname_predict_hit_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_sa_fname_predict_hit);
}

static ssize_t
statahead_fname_predict_hit_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned long val;
	int rc;

	rc = kstrtoul(buffer, 0, &val);
	if (rc)
		return rc;

	sbi->ll_sa_fname_predict_hit = val;
	return count;
}
LUSTRE_RW_ATTR(statahead_fname_predict_hit);


static ssize_t
statahead_fname_match_hit_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_sa_fname_match_hit);
}

static ssize_t
statahead_fname_match_hit_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned long val;
	int rc;

	rc = kstrtoul(buffer, 0, &val);
	if (rc)
		return rc;

	sbi->ll_sa_fname_match_hit = val;
	return count;
}
LUSTRE_RW_ATTR(statahead_fname_match_hit);

static ssize_t statahead_agl_show(struct kobject *kobj,
				  struct attribute *attr,
				  char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 test_bit(LL_SBI_AGL_ENABLED, sbi->ll_flags));
}

static ssize_t statahead_agl_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buffer,
				   size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	if (val)
		set_bit(LL_SBI_AGL_ENABLED, sbi->ll_flags);
	else
		clear_bit(LL_SBI_AGL_ENABLED, sbi->ll_flags);

	return count;
}
LUSTRE_RW_ATTR(statahead_agl);

static int ll_statahead_stats_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	seq_printf(m, "statahead total: %u\n"
		      "statahead wrong: %u\n"
		      "agl total: %u\n"
		      "list_total: %u\n"
		      "fname_total: %u\n"
		      "hit_total: %u\n"
		      "miss_total: %u\n",
		   atomic_read(&sbi->ll_sa_total),
		   atomic_read(&sbi->ll_sa_wrong),
		   atomic_read(&sbi->ll_agl_total),
		   atomic_read(&sbi->ll_sa_list_total),
		   atomic_read(&sbi->ll_sa_fname_total),
		   atomic_read(&sbi->ll_sa_hit_total),
		   atomic_read(&sbi->ll_sa_miss_total));
	return 0;
}

static ssize_t ll_statahead_stats_seq_write(struct file *file,
					    const char __user *buffer,
					    size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	atomic_set(&sbi->ll_sa_total, 0);
	atomic_set(&sbi->ll_sa_wrong, 0);
	atomic_set(&sbi->ll_agl_total, 0);
	atomic_set(&sbi->ll_sa_list_total, 0);
	atomic_set(&sbi->ll_sa_fname_total, 0);
	atomic_set(&sbi->ll_sa_hit_total, 0);
	atomic_set(&sbi->ll_sa_miss_total, 0);

	return count;
}
LDEBUGFS_SEQ_FOPS(ll_statahead_stats);

static ssize_t lazystatfs_show(struct kobject *kobj,
			       struct attribute *attr,
			       char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 test_bit(LL_SBI_LAZYSTATFS, sbi->ll_flags));
}

static ssize_t lazystatfs_store(struct kobject *kobj,
				struct attribute *attr,
				const char *buffer,
				size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	if (val)
		set_bit(LL_SBI_LAZYSTATFS, sbi->ll_flags);
	else
		clear_bit(LL_SBI_LAZYSTATFS, sbi->ll_flags);

	return count;
}
LUSTRE_RW_ATTR(lazystatfs);

static ssize_t statfs_max_age_show(struct kobject *kobj, struct attribute *attr,
				   char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_statfs_max_age);
}

static ssize_t statfs_max_age_store(struct kobject *kobj,
				    struct attribute *attr, const char *buffer,
				    size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;
	if (val > OBD_STATFS_CACHE_MAX_AGE)
		return -EINVAL;

	sbi->ll_statfs_max_age = val;

	return count;
}
LUSTRE_RW_ATTR(statfs_max_age);

static ssize_t statfs_project_show(struct kobject *kobj,
				  struct attribute *attr,
				  char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 test_bit(LL_SBI_STATFS_PROJECT, sbi->ll_flags));
}

static ssize_t statfs_project_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buffer,
				   size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	if (val)
		set_bit(LL_SBI_STATFS_PROJECT, sbi->ll_flags);
	else
		clear_bit(LL_SBI_STATFS_PROJECT, sbi->ll_flags);

	return count;
}
LUSTRE_RW_ATTR(statfs_project);

static ssize_t max_easize_show(struct kobject *kobj,
			       struct attribute *attr,
			       char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned int ealen;
	int rc;

	rc = ll_get_max_mdsize(sbi, &ealen);
	if (rc)
		return rc;

	/* Limit xattr size returned to userspace based on kernel maximum */
	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 ealen > XATTR_SIZE_MAX ? XATTR_SIZE_MAX : ealen);
}
LUSTRE_RO_ATTR(max_easize);

/**
 * default_easize_show() - Show default_easize (EA size)
 * @kobj: seq_file handle
 * @attr: unused for single entry (attribute structure pointer)
 * @buf: xattr(EA) size returned to userspace
 *
 * Return:
 * * %0 on success
 * * %negative negated errno on failure
 */
static ssize_t default_easize_show(struct kobject *kobj,
				   struct attribute *attr,
				   char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned int ealen;
	int rc;

	rc = ll_get_default_mdsize(sbi, &ealen);
	if (rc)
		return rc;

	/* Limit xattr size returned to userspace based on kernel maximum */
	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 ealen > XATTR_SIZE_MAX ? XATTR_SIZE_MAX : ealen);
}

/**
 * default_easize_store() - Set default_easize.
 * @kobj: pointer to a kobject structure
 * @attr: unused for single entry (attribute structure pointer)
 * @buffer: string passed from user space
 * @count: buffer length
 *
 * Range checking on the passed value is handled by
 * ll_set_default_mdsize().
 *
 * Return:
 * * %positive count on success
 * * %negative negated errno on failure
 */
static ssize_t default_easize_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buffer,
				    size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned int val;
	int rc;

	if (count == 0)
		return 0;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	rc = ll_set_default_mdsize(sbi, val);
	if (rc)
		return rc;

	return count;
}
LUSTRE_RW_ATTR(default_easize);

LDEBUGFS_SEQ_FOPS_RO(ll_sbi_flags);

static ssize_t xattr_cache_show(struct kobject *kobj,
				struct attribute *attr,
				char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return sprintf(buf, "%u\n", sbi->ll_xattr_cache_enabled);
}

static ssize_t xattr_cache_store(struct kobject *kobj,
				 struct attribute *attr,
				 const char *buffer,
				 size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	if (val && !test_bit(LL_SBI_XATTR_CACHE, sbi->ll_flags))
		return -EOPNOTSUPP;

	sbi->ll_xattr_cache_enabled = val;
	sbi->ll_xattr_cache_set = 1;

	return count;
}
LUSTRE_RW_ATTR(xattr_cache);

static ssize_t intent_mkdir_show(struct kobject *kobj,
				 struct attribute *attr, char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_intent_mkdir_enabled);
}

static ssize_t intent_mkdir_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	sbi->ll_intent_mkdir_enabled = val;

	return count;
}
LUSTRE_RW_ATTR(intent_mkdir);

static ssize_t tiny_write_show(struct kobject *kobj,
			       struct attribute *attr,
			       char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 test_bit(LL_SBI_TINY_WRITE, sbi->ll_flags));
}

static ssize_t tiny_write_store(struct kobject *kobj,
				struct attribute *attr,
				const char *buffer,
				size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	spin_lock(&sbi->ll_lock);
	if (val)
		set_bit(LL_SBI_TINY_WRITE, sbi->ll_flags);
	else
		clear_bit(LL_SBI_TINY_WRITE, sbi->ll_flags);
	spin_unlock(&sbi->ll_lock);

	return count;
}
LUSTRE_RW_ATTR(tiny_write);

static ssize_t unaligned_dio_show(struct kobject *kobj,
				  struct attribute *attr,
				  char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 test_bit(LL_SBI_UNALIGNED_DIO, sbi->ll_flags));
}

static ssize_t unaligned_dio_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buffer,
				   size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	spin_lock(&sbi->ll_lock);
	if (val)
		set_bit(LL_SBI_UNALIGNED_DIO, sbi->ll_flags);
	else
		clear_bit(LL_SBI_UNALIGNED_DIO, sbi->ll_flags);
	spin_unlock(&sbi->ll_lock);

	return count;
}
LUSTRE_RW_ATTR(unaligned_dio);

static ssize_t parallel_dio_show(struct kobject *kobj,
				 struct attribute *attr,
				 char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n",
			test_bit(LL_SBI_PARALLEL_DIO, sbi->ll_flags));
}

static ssize_t parallel_dio_store(struct kobject *kobj,
				  struct attribute *attr,
				  const char *buffer,
				  size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	spin_lock(&sbi->ll_lock);
	if (val)
		set_bit(LL_SBI_PARALLEL_DIO, sbi->ll_flags);
	else
		clear_bit(LL_SBI_PARALLEL_DIO, sbi->ll_flags);
	spin_unlock(&sbi->ll_lock);

	return count;
}
LUSTRE_RW_ATTR(parallel_dio);

static ssize_t hybrid_io_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n",
			test_bit(LL_SBI_HYBRID_IO, sbi->ll_flags));
}

static ssize_t hybrid_io_store(struct kobject *kobj, struct attribute *attr,
			       const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	spin_lock(&sbi->ll_lock);
	if (val)
		set_bit(LL_SBI_HYBRID_IO, sbi->ll_flags);
	else
		clear_bit(LL_SBI_HYBRID_IO, sbi->ll_flags);
	spin_unlock(&sbi->ll_lock);

	return count;
}
LUSTRE_RW_ATTR(hybrid_io);

static ssize_t enable_setstripe_gid_show(struct kobject *kobj,
					 struct attribute *attr, char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%d\n", sbi->ll_enable_setstripe_gid);
}

static ssize_t enable_setstripe_gid_store(struct kobject *kobj,
					  struct attribute *attr,
					  const char *buffer, size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtoint(buffer, 10, &val);
	if (rc)
		return rc;

	sbi->ll_enable_setstripe_gid = val;

	return count;
}
LUSTRE_RW_ATTR(enable_setstripe_gid);

static ssize_t max_read_ahead_async_active_show(struct kobject *kobj,
					       struct attribute *attr,
					       char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 sbi->ll_ra_info.ra_async_max_active);
}

static ssize_t max_read_ahead_async_active_store(struct kobject *kobj,
						 struct attribute *attr,
						 const char *buffer,
						 size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	/**
	 * It doesn't make any sense to make it exceed what
	 * workqueue could acutally support. This can easily
	 * over subscripe the cores but Lustre internally
	 * throttles to avoid those impacts.
	 */
	if (val > WQ_UNBOUND_MAX_ACTIVE) {
		CERROR("%s: cannot set max_read_ahead_async_active=%u larger than %u\n",
		       sbi->ll_fsname, val, WQ_UNBOUND_MAX_ACTIVE);
		return -ERANGE;
	}

	spin_lock(&sbi->ll_lock);
	sbi->ll_ra_info.ra_async_max_active = val;
	spin_unlock(&sbi->ll_lock);

	return count;
}
LUSTRE_RW_ATTR(max_read_ahead_async_active);

static ssize_t read_ahead_async_file_threshold_mb_show(struct kobject *kobj,
						       struct attribute *attr,
						       char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%lu\n", PAGES_TO_MiB(
			 sbi->ll_ra_info.ra_async_pages_per_file_threshold));
}

static ssize_t
read_ahead_async_file_threshold_mb_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buffer, size_t count)
{
	unsigned long pages_number;
	unsigned long max_ra_per_file;
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	int rc;

	rc = kstrtoul(buffer, 10, &pages_number);
	if (rc)
		return rc;

	pages_number = MiB_TO_PAGES(pages_number);
	max_ra_per_file = sbi->ll_ra_info.ra_max_pages_per_file;
	if (pages_number < 0 || pages_number > max_ra_per_file) {
		CERROR("%s: can't set read_ahead_async_file_threshold_mb=%lu > "
		       "max_read_readahead_per_file_mb=%lu\n", sbi->ll_fsname,
		       PAGES_TO_MiB(pages_number),
		       PAGES_TO_MiB(max_ra_per_file));
		return -ERANGE;
	}
	sbi->ll_ra_info.ra_async_pages_per_file_threshold = pages_number;

	return count;
}
LUSTRE_RW_ATTR(read_ahead_async_file_threshold_mb);

static ssize_t read_ahead_range_kb_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, PAGE_SIZE, "%lu\n",
			sbi->ll_ra_info.ra_range_pages << (PAGE_SHIFT - 10));
}

static ssize_t
read_ahead_range_kb_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buffer, size_t count)
{
	unsigned long pages_number;
	unsigned long max_ra_per_file;
	u64 val;
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	int rc;

	rc = sysfs_memparse(buffer, count, &val, "KiB");
	if (rc < 0)
		return rc;

	pages_number = val >> PAGE_SHIFT;
	/* Disable mmap range read */
	if (pages_number == 0)
		goto out;

	max_ra_per_file = sbi->ll_ra_info.ra_max_pages_per_file;
	if (pages_number > max_ra_per_file ||
	    pages_number < RA_MIN_MMAP_RANGE_PAGES)
		return -ERANGE;

out:
	spin_lock(&sbi->ll_lock);
	sbi->ll_ra_info.ra_range_pages = pages_number;
	spin_unlock(&sbi->ll_lock);

	return count;
}
LUSTRE_RW_ATTR(read_ahead_range_kb);

static ssize_t fast_read_show(struct kobject *kobj,
			      struct attribute *attr,
			      char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 test_bit(LL_SBI_FAST_READ, sbi->ll_flags));
}

static ssize_t fast_read_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buffer,
			       size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	spin_lock(&sbi->ll_lock);
	if (val)
		set_bit(LL_SBI_FAST_READ, sbi->ll_flags);
	else
		clear_bit(LL_SBI_FAST_READ, sbi->ll_flags);
	spin_unlock(&sbi->ll_lock);

	return count;
}
LUSTRE_RW_ATTR(fast_read);

static ssize_t file_heat_show(struct kobject *kobj,
			      struct attribute *attr,
			      char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 test_bit(LL_SBI_FILE_HEAT, sbi->ll_flags));
}

static ssize_t file_heat_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buffer,
			       size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	spin_lock(&sbi->ll_lock);
	if (val)
		set_bit(LL_SBI_FILE_HEAT, sbi->ll_flags);
	else
		clear_bit(LL_SBI_FILE_HEAT, sbi->ll_flags);
	spin_unlock(&sbi->ll_lock);

	return count;
}
LUSTRE_RW_ATTR(file_heat);

static ssize_t heat_decay_percentage_show(struct kobject *kobj,
					  struct attribute *attr,
					  char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 (sbi->ll_heat_decay_weight * 100 + 128) / 256);
}

static ssize_t heat_decay_percentage_store(struct kobject *kobj,
					   struct attribute *attr,
					   const char *buffer,
					   size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned long val;
	int rc;

	rc = kstrtoul(buffer, 10, &val);
	if (rc)
		return rc;

	if (val < 0 || val > 100)
		return -ERANGE;

	sbi->ll_heat_decay_weight = (val * 256 + 50) / 100;

	return count;
}
LUSTRE_RW_ATTR(heat_decay_percentage);

static ssize_t heat_period_second_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_heat_period_second);
}

static ssize_t heat_period_second_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer,
					size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned long val;
	int rc;

	rc = kstrtoul(buffer, 10, &val);
	if (rc)
		return rc;

	if (val <= 0)
		return -ERANGE;

	sbi->ll_heat_period_second = val;

	return count;
}
LUSTRE_RW_ATTR(heat_period_second);

static ssize_t opencache_threshold_count_show(struct kobject *kobj,
					      struct attribute *attr,
					      char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	if (sbi->ll_oc_thrsh_count)
		return snprintf(buf, PAGE_SIZE, "%u\n",
				sbi->ll_oc_thrsh_count);
	else
		return snprintf(buf, PAGE_SIZE, "off\n");
}

static ssize_t opencache_threshold_count_store(struct kobject *kobj,
					       struct attribute *attr,
					       const char *buffer,
					       size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc) {
		bool enable;
		/* also accept "off" to disable and "on" to always cache */
		rc = kstrtobool(buffer, &enable);
		if (rc)
			return rc;
		val = enable;
	}
	sbi->ll_oc_thrsh_count = val;

	return count;
}
LUSTRE_RW_ATTR(opencache_threshold_count);

static ssize_t opencache_threshold_ms_show(struct kobject *kobj,
					   struct attribute *attr,
					   char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_oc_thrsh_ms);
}

static ssize_t opencache_threshold_ms_store(struct kobject *kobj,
					    struct attribute *attr,
					    const char *buffer,
					    size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	sbi->ll_oc_thrsh_ms = val;

	return count;
}
LUSTRE_RW_ATTR(opencache_threshold_ms);

static ssize_t opencache_max_ms_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_oc_max_ms);
}

static ssize_t opencache_max_ms_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer,
				      size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	sbi->ll_oc_max_ms = val;

	return count;
}
LUSTRE_RW_ATTR(opencache_max_ms);

static ssize_t inode_cache_show(struct kobject *kobj,
				struct attribute *attr,
				char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_inode_cache_enabled);
}

static ssize_t inode_cache_store(struct kobject *kobj,
				 struct attribute *attr,
				 const char *buffer,
				 size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	sbi->ll_inode_cache_enabled = val;

	return count;
}
LUSTRE_RW_ATTR(inode_cache);

/* an arbitrary but very large maximum value for sanity */
#define HYBRID_IO_THRESHOLD_BYTES_MAX (2 * 1024 * 1024 * 1024UL) /* 2 GiB */
static ssize_t hybrid_io_write_threshold_bytes_show(struct kobject *kobj,
						    struct attribute *attr,
						    char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n",
			sbi->ll_hybrid_io_write_threshold_bytes);
}

static ssize_t hybrid_io_write_threshold_bytes_store(struct kobject *kobj,
						     struct attribute *attr,
						     const char *buffer,
						     size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	u64 val;
	int rc;

	rc = sysfs_memparse(buffer, count, &val, "B");
	if (rc)
		return rc;

	if (val > HYBRID_IO_THRESHOLD_BYTES_MAX)
		return -ERANGE;

	sbi->ll_hybrid_io_write_threshold_bytes = val;

	return count;
}
LUSTRE_RW_ATTR(hybrid_io_write_threshold_bytes);

static ssize_t hybrid_io_read_threshold_bytes_show(struct kobject *kobj,
						   struct attribute *attr,
						   char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n",
			sbi->ll_hybrid_io_read_threshold_bytes);
}

static ssize_t hybrid_io_read_threshold_bytes_store(struct kobject *kobj,
						    struct attribute *attr,
						    const char *buffer,
						    size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	u64 val;
	int rc;

	rc = sysfs_memparse(buffer, count, &val, "B");
	if (rc)
		return rc;

	if (val > HYBRID_IO_THRESHOLD_BYTES_MAX)
		return -ERANGE;

	sbi->ll_hybrid_io_read_threshold_bytes = val;

	return count;
}
LUSTRE_RW_ATTR(hybrid_io_read_threshold_bytes);

static ssize_t dir_read_on_open_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);

	return snprintf(buf, PAGE_SIZE, "%u\n", sbi->ll_dir_open_read);
}


static ssize_t dir_read_on_open_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer,
				      size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	if (val)
		sbi->ll_dir_open_read = 1;
	else
		sbi->ll_dir_open_read = 0;

	return count;
}

LUSTRE_RW_ATTR(dir_read_on_open);

static int ll_unstable_stats_seq_show(struct seq_file *m, void *v)
{
	struct super_block	*sb    = m->private;
	struct ll_sb_info	*sbi   = ll_s2sbi(sb);
	struct cl_client_cache	*cache = sbi->ll_cache;
	long pages;
	int mb;

	pages = atomic_long_read(&cache->ccc_unstable_nr);
	mb    = (pages * PAGE_SIZE) >> 20;

	seq_printf(m, "unstable_check:     %8d\n"
		      "unstable_pages: %12ld\n"
		      "unstable_mb:        %8d\n",
		   cache->ccc_unstable_check, pages, mb);
	return 0;
}

static ssize_t ll_unstable_stats_seq_write(struct file *file,
					   const char __user *buffer,
					   size_t count, loff_t *unused)
{
	struct seq_file *seq = file->private_data;
	struct ll_sb_info *sbi = ll_s2sbi((struct super_block *)seq->private);
	char kernbuf[128];
	bool val;
	int rc;

	if (count == 0)
		return 0;
	if (count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	buffer += lprocfs_find_named_value(kernbuf, "unstable_check:", &count) -
		  kernbuf;
	rc = kstrtobool_from_user(buffer, count, &val);
	if (rc < 0)
		return rc;

	/* borrow lru lock to set the value */
	spin_lock(&sbi->ll_cache->ccc_lru_lock);
	sbi->ll_cache->ccc_unstable_check = val;
	spin_unlock(&sbi->ll_cache->ccc_lru_lock);

	return count;
}

LDEBUGFS_SEQ_FOPS(ll_unstable_stats);

static int ll_root_squash_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct root_squash_info *squash = &sbi->ll_squash;

	seq_printf(m, "%u:%u\n", squash->rsi_uid, squash->rsi_gid);
	return 0;
}

static ssize_t ll_root_squash_seq_write(struct file *file,
					const char __user *buffer,
					size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct root_squash_info *squash = &sbi->ll_squash;

	return lprocfs_wr_root_squash(buffer, count, squash, sbi->ll_fsname);
}

LDEBUGFS_SEQ_FOPS(ll_root_squash);

static int ll_nosquash_nids_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct root_squash_info *squash = &sbi->ll_squash;
	int len;

	spin_lock(&squash->rsi_lock);
	if (!list_empty(&squash->rsi_nosquash_nids)) {
		len = cfs_print_nidlist(m->buf + m->count, m->size - m->count,
					&squash->rsi_nosquash_nids);
		m->count += len;
		seq_putc(m, '\n');
	} else {
		seq_puts(m, "NONE\n");
	}
	spin_unlock(&squash->rsi_lock);

	return 0;
}

static ssize_t ll_nosquash_nids_seq_write(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct root_squash_info *squash = &sbi->ll_squash;
	int rc;

	rc = lprocfs_wr_nosquash_nids(buffer, count, squash, sbi->ll_fsname);
	if (rc < 0)
		return rc;

	ll_compute_rootsquash_state(sbi);

	return rc;
}

LDEBUGFS_SEQ_FOPS(ll_nosquash_nids);

#if defined(CONFIG_LL_ENCRYPTION)
static ssize_t enable_filename_encryption_show(struct kobject *kobj,
					       struct attribute *attr,
					       char *buffer)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct lustre_sb_info *lsi = sbi->lsi;

	return snprintf(buffer, PAGE_SIZE,  "%u\n",
			lsi->lsi_flags & LSI_FILENAME_ENC ? 1 : 0);
}

static ssize_t enable_filename_encryption_store(struct kobject *kobj,
						struct attribute *attr,
						const char *buffer,
						size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct lustre_sb_info *lsi = sbi->lsi;
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	if (val) {
		if (!ll_sbi_has_name_encrypt(sbi)) {
			/* server does not support name encryption,
			 * so force it to NULL on client
			 */
			CDEBUG(D_SEC, "%s: server does not support name encryption\n",
			       sbi->ll_fsname);
			lsi->lsi_flags &= ~LSI_FILENAME_ENC;
			return -EOPNOTSUPP;
		}

		lsi->lsi_flags |= LSI_FILENAME_ENC;
	} else {
		lsi->lsi_flags &= ~LSI_FILENAME_ENC;
	}

	return count;
}

LUSTRE_RW_ATTR(enable_filename_encryption);
#endif /* CONFIG_LL_ENCRYPTION */

#if defined(CONFIG_LL_ENCRYPTION) || defined(HAVE_LUSTRE_CRYPTO)
static ssize_t filename_enc_use_old_base64_show(struct kobject *kobj,
						struct attribute *attr,
						char *buffer)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct lustre_sb_info *lsi = sbi->lsi;

	return snprintf(buffer, PAGE_SIZE, "%u\n",
			lsi->lsi_flags & LSI_FILENAME_ENC_B64_OLD_CLI ? 1 : 0);
}

static ssize_t filename_enc_use_old_base64_store(struct kobject *kobj,
						 struct attribute *attr,
						 const char *buffer,
						 size_t count)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	struct lustre_sb_info *lsi = sbi->lsi;
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	if (val) {
		if (!ll_sbi_has_name_encrypt(sbi)) {
			/* server does not support name encryption,
			 * so force it to NULL on client
			 */
			CDEBUG(D_SEC,
			       "%s: server does not support name encryption\n",
			       sbi->ll_fsname);
			lsi->lsi_flags &= ~LSI_FILENAME_ENC_B64_OLD_CLI;
			return -EOPNOTSUPP;
		}

		lsi->lsi_flags |= LSI_FILENAME_ENC_B64_OLD_CLI;
	} else {
		lsi->lsi_flags &= ~LSI_FILENAME_ENC_B64_OLD_CLI;
	}

	return count;
}

LUSTRE_RW_ATTR(filename_enc_use_old_base64);
#endif /* CONFIG_LL_ENCRYPTION || HAVE_LUSTRE_CRYPTO */

static int ll_pcc_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	return pcc_super_dump(&sbi->ll_pcc_super, m);
}

static ssize_t ll_pcc_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	int rc;
	char *kernbuf;

	if (count >= LPROCFS_WR_PCC_MAX_CMD)
		return -EINVAL;

	if (!(exp_connect_flags2(sbi->ll_md_exp) & OBD_CONNECT2_PCC))
		return -EOPNOTSUPP;

	OBD_ALLOC(kernbuf, count + 1);
	if (kernbuf == NULL)
		return -ENOMEM;

	if (copy_from_user(kernbuf, buffer, count))
		GOTO(out_free_kernbuff, rc = -EFAULT);

	rc = pcc_cmd_handle(kernbuf, count, &sbi->ll_pcc_super);
out_free_kernbuff:
	OBD_FREE(kernbuf, count + 1);
	return rc ? rc : count;
}
LDEBUGFS_SEQ_FOPS(ll_pcc);

struct ldebugfs_vars lprocfs_llite_obd_vars[] = {
	{ .name	=	"site",
	  .fops	=	&ll_site_stats_fops			},
	{ .name	=	"max_cached_mb",
	  .fops	=	&ll_max_cached_mb_fops			},
	{ .name	=	"unevict_cached_mb",
	  .fops	=	&ll_unevict_cached_mb_fops		},
	{ .name	=	"enable_mlock_pages",
	  .fops	=	&ll_enable_mlock_pages_fops		},
	{ .name	=	"statahead_stats",
	  .fops	=	&ll_statahead_stats_fops		},
	{ .name	=	"unstable_stats",
	  .fops	=	&ll_unstable_stats_fops			},
	{ .name =	"sbi_flags",
	  .fops =	&ll_sbi_flags_fops			},
	{ .name	=	"root_squash",
	  .fops	=	&ll_root_squash_fops			},
	{ .name	=	"nosquash_nids",
	  .fops	=	&ll_nosquash_nids_fops			},
	{ .name =	"pcc",
	  .fops =	&ll_pcc_fops,				},
	{ NULL }
};

#define MAX_STRING_SIZE 128

static struct attribute *llite_attrs[] = {
	&lustre_attr_blocksize.attr,
	&lustre_attr_filestotal.attr,
	&lustre_attr_filesfree.attr,
	&lustre_attr_kbytestotal.attr,
	&lustre_attr_kbytesfree.attr,
	&lustre_attr_kbytesavail.attr,
	&lustre_attr_client_type.attr,
	&lustre_attr_foreign_symlink_enable.attr,
	&lustre_attr_foreign_symlink_prefix.attr,
	&lustre_attr_foreign_symlink_upcall.attr,
	&lustre_attr_foreign_symlink_upcall_info.attr,
	&lustre_attr_fstype.attr,
	&lustre_attr_heat_decay_percentage.attr,
	&lustre_attr_heat_period_second.attr,
	&lustre_attr_hybrid_io.attr,
	&lustre_attr_hybrid_io_write_threshold_bytes.attr,
	&lustre_attr_hybrid_io_read_threshold_bytes.attr,
	&lustre_attr_inode_cache.attr,
	&lustre_attr_checksums.attr,
	&lustre_attr_checksum_pages.attr,
	&lustre_attr_max_easize.attr,
	&lustre_attr_max_read_ahead_mb.attr,
	&lustre_attr_max_read_ahead_per_file_mb.attr,
	&lustre_attr_max_read_ahead_whole_mb.attr,
	&lustre_attr_max_read_ahead_async_active.attr,
	&lustre_attr_maxbytes.attr,
	&lustre_attr_namelen_max.attr,
	&lustre_attr_opencache_threshold_count.attr,
	&lustre_attr_opencache_threshold_ms.attr,
	&lustre_attr_opencache_max_ms.attr,
	&lustre_attr_parallel_dio.attr,
	&lustre_attr_pcc_async_threshold.attr,
	&lustre_attr_pcc_mode.attr,
	&lustre_attr_pcc_async_affinity.attr,
	&lustre_attr_read_ahead_async_file_threshold_mb.attr,
	&lustre_attr_read_ahead_range_kb.attr,
	&lustre_attr_stat_blocksize.attr,
	&lustre_attr_stats_track_pid.attr,
	&lustre_attr_stats_track_ppid.attr,
	&lustre_attr_stats_track_gid.attr,
	&lustre_attr_enable_statahead_fname.attr,
	&lustre_attr_statahead_running_max.attr,
	&lustre_attr_statahead_batch_max.attr,
	&lustre_attr_statahead_max.attr,
	&lustre_attr_statahead_min.attr,
	&lustre_attr_statahead_timeout.attr,
	&lustre_attr_statahead_fname_predict_hit.attr,
	&lustre_attr_statahead_fname_match_hit.attr,
	&lustre_attr_statahead_agl.attr,
	&lustre_attr_lazystatfs.attr,
	&lustre_attr_statfs_max_age.attr,
	&lustre_attr_statfs_project.attr,
	&lustre_attr_statfs_state.attr,
	&lustre_attr_default_easize.attr,
	&lustre_attr_xattr_cache.attr,
	&lustre_attr_intent_mkdir.attr,
	&lustre_attr_fast_read.attr,
	&lustre_attr_tiny_write.attr,
	&lustre_attr_unaligned_dio.attr,
	&lustre_attr_enable_setstripe_gid.attr,
	&lustre_attr_file_heat.attr,
#ifdef CONFIG_LL_ENCRYPTION
	&lustre_attr_enable_filename_encryption.attr,
#endif
#if defined(CONFIG_LL_ENCRYPTION) || defined(HAVE_LUSTRE_CRYPTO)
	&lustre_attr_filename_enc_use_old_base64.attr,
#endif
	&lustre_attr_uuid.attr,
	&lustre_attr_dir_read_on_open.attr,
	NULL,
};

KOBJ_ATTRIBUTE_GROUPS(llite); /* creates llite_groups */

static void sbi_kobj_release(struct kobject *kobj)
{
	struct ll_sb_info *sbi = container_of(kobj, struct ll_sb_info,
					      ll_kset.kobj);
	complete(&sbi->ll_kobj_unregister);
}

static struct kobj_type sbi_ktype = {
	.default_groups = KOBJ_ATTR_GROUPS(llite),
	.sysfs_ops      = &lustre_sysfs_ops,
	.release        = sbi_kobj_release,
};

static const struct llite_file_opcode {
	__u32				lfo_opcode;
	enum lprocfs_counter_config	lfo_config;
	const char			*lfo_opname;
} llite_opcode_table[LPROC_LL_FILE_OPCODES] = {
	/* file operation */
	{ LPROC_LL_READ_BYTES,	LPROCFS_TYPE_BYTES_FULL, "read_bytes" },
	{ LPROC_LL_WRITE_BYTES,	LPROCFS_TYPE_BYTES_FULL, "write_bytes" },
	{ LPROC_LL_HIO_READ,	LPROCFS_TYPE_BYTES_FULL, "hybrid_read_bytes" },
	{ LPROC_LL_HIO_WRITE,	LPROCFS_TYPE_BYTES_FULL, "hybrid_write_bytes" },
	{ LPROC_LL_READ,	LPROCFS_TYPE_LATENCY,	"read" },
	{ LPROC_LL_WRITE,	LPROCFS_TYPE_LATENCY,	"write" },
	{ LPROC_LL_IOCTL,	LPROCFS_TYPE_REQS,	"ioctl" },
	{ LPROC_LL_OPEN,	LPROCFS_TYPE_LATENCY,	"open" },
	{ LPROC_LL_RELEASE,	LPROCFS_TYPE_LATENCY,	"close" },
	{ LPROC_LL_MMAP,	LPROCFS_TYPE_LATENCY,	"mmap" },
	{ LPROC_LL_FAULT,	LPROCFS_TYPE_LATENCY,	"page_fault" },
	{ LPROC_LL_MKWRITE,	LPROCFS_TYPE_LATENCY,	"page_mkwrite" },
	{ LPROC_LL_LLSEEK,	LPROCFS_TYPE_LATENCY,	"seek" },
	{ LPROC_LL_FSYNC,	LPROCFS_TYPE_LATENCY,	"fsync" },
	{ LPROC_LL_READDIR,	LPROCFS_TYPE_LATENCY,	"readdir" },
	{ LPROC_LL_INODE_OCOUNT, LPROCFS_TYPE_REQS | LPROCFS_CNTR_AVGMINMAX |
				LPROCFS_CNTR_STDDEV,	"opencount" },
	{ LPROC_LL_INODE_OPCLTM, LPROCFS_TYPE_LATENCY,	"openclosetime" },
	/* inode operation */
	{ LPROC_LL_SETATTR,	LPROCFS_TYPE_LATENCY,	"setattr" },
	{ LPROC_LL_TRUNC,	LPROCFS_TYPE_LATENCY,	"truncate" },
	{ LPROC_LL_FLOCK,	LPROCFS_TYPE_LATENCY,	"flock" },
	{ LPROC_LL_GETATTR,	LPROCFS_TYPE_LATENCY,	"getattr" },
	{ LPROC_LL_FALLOCATE,	LPROCFS_TYPE_LATENCY,	"fallocate"},
	/* dir inode operation */
	{ LPROC_LL_CREATE,	LPROCFS_TYPE_LATENCY,	"create" },
	{ LPROC_LL_LINK,	LPROCFS_TYPE_LATENCY,	"link" },
	{ LPROC_LL_UNLINK,	LPROCFS_TYPE_LATENCY,	"unlink" },
	{ LPROC_LL_SYMLINK,	LPROCFS_TYPE_LATENCY,	"symlink" },
	{ LPROC_LL_MKDIR,	LPROCFS_TYPE_LATENCY,	"mkdir" },
	{ LPROC_LL_RMDIR,	LPROCFS_TYPE_LATENCY,	"rmdir" },
	{ LPROC_LL_MKNOD,	LPROCFS_TYPE_LATENCY,	"mknod" },
	{ LPROC_LL_RENAME,	LPROCFS_TYPE_LATENCY,	"rename" },
	/* special inode operation */
	{ LPROC_LL_STATFS,	LPROCFS_TYPE_LATENCY,	"statfs" },
	{ LPROC_LL_SETXATTR,	LPROCFS_TYPE_LATENCY,	"setxattr" },
	{ LPROC_LL_GETXATTR,	LPROCFS_TYPE_LATENCY,	"getxattr" },
	{ LPROC_LL_GETXATTR_HITS, LPROCFS_TYPE_REQS,	"getxattr_hits" },
	{ LPROC_LL_LISTXATTR,	LPROCFS_TYPE_LATENCY,	"listxattr" },
	{ LPROC_LL_REMOVEXATTR,	LPROCFS_TYPE_LATENCY,	"removexattr" },
	{ LPROC_LL_INODE_PERM,	LPROCFS_TYPE_LATENCY,	"inode_permission" },
	/* PCC I/O statistics */
	{ LPROC_LL_PCC_ATTACH,  LPROCFS_TYPE_REQS,	"pcc_attach" },
	{ LPROC_LL_PCC_DETACH,  LPROCFS_TYPE_REQS,	"pcc_detach" },
	{ LPROC_LL_PCC_AUTOAT, LPROCFS_TYPE_REQS,	"pcc_auto_attach" },
	{ LPROC_LL_PCC_HIT_BYTES, LPROCFS_TYPE_BYTES_FULL, "pcc_hit_bytes" },
	{ LPROC_LL_PCC_ATTACH_BYTES, LPROCFS_TYPE_BYTES_FULL,
		"pcc_attach_bytes" },
	/* hybrid IO switch from buffered I/O (BIO) to direct I/O (DIO) */
	{ LPROC_LL_HYBRID_NOSWITCH, LPROCFS_TYPE_REQS, "hybrid_noswitch" },
	{ LPROC_LL_HYBRID_WRITESIZE_SWITCH, LPROCFS_TYPE_REQS,
		"hybrid_writesize_switch" },
	{ LPROC_LL_HYBRID_READSIZE_SWITCH, LPROCFS_TYPE_REQS,
		"hybrid_readsize_switch" },
};

void ll_stats_ops_tally(struct ll_sb_info *sbi, int op, long count)
{
	if (!sbi->ll_stats)
		return;

	if (sbi->ll_stats_track_type == STATS_TRACK_ALL)
		lprocfs_counter_add(sbi->ll_stats, op, count);
	else if (sbi->ll_stats_track_type == STATS_TRACK_PID &&
		 sbi->ll_stats_track_id == current->pid)
		lprocfs_counter_add(sbi->ll_stats, op, count);
	else if (sbi->ll_stats_track_type == STATS_TRACK_PPID &&
		 sbi->ll_stats_track_id == current->real_parent->pid)
		lprocfs_counter_add(sbi->ll_stats, op, count);
	else if (sbi->ll_stats_track_type == STATS_TRACK_GID &&
		 sbi->ll_stats_track_id ==
			from_kgid(&init_user_ns, current_gid()))
		lprocfs_counter_add(sbi->ll_stats, op, count);
}
EXPORT_SYMBOL(ll_stats_ops_tally);

static const char *const ra_stat_string[] = {
	[RA_STAT_HIT]			= "hits",
	[RA_STAT_MISS]			= "misses",
	[RA_STAT_DISTANT_READPAGE]	= "readpage_not_consecutive",
	[RA_STAT_MISS_IN_WINDOW]	= "miss_inside_window",
	[RA_STAT_FAILED_GRAB_PAGE]	= "failed_grab_cache_page",
	[RA_STAT_FAILED_MATCH]		= "failed_lock_match",
	[RA_STAT_DISCARDED]		= "read_but_discarded",
	[RA_STAT_ZERO_LEN]		= "zero_length_file",
	[RA_STAT_ZERO_WINDOW]		= "zero_size_window",
	[RA_STAT_EOF]			= "readahead_to_eof",
	[RA_STAT_MAX_IN_FLIGHT]		= "hit_max_readahead_issue",
	[RA_STAT_WRONG_GRAB_PAGE]	= "wrong_page_from_grab_cache_page",
	[RA_STAT_FAILED_REACH_END]	= "failed_to_reach_end",
	[RA_STAT_ASYNC]			= "async_readahead",
	[RA_STAT_FAILED_FAST_READ]	= "failed_to_fast_read",
	[RA_STAT_MMAP_RANGE_READ]	= "mmap_range_read",
	[RA_STAT_READAHEAD_PAGES]	= "readahead_pages",
	[RA_STAT_FORCEREAD_PAGES]	= "forceread_pages"
};

int ll_debugfs_register_super(struct super_block *sb, const char *name)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	char param[MAX_OBD_NAME * 4];
	int err, id;

	ENTRY;
	LASSERT(sbi);

	/* Yes we also register sysfs mount kset here as well */
	sbi->ll_kset.kobj.parent = llite_kobj;
	sbi->ll_kset.kobj.ktype = &sbi_ktype;
	init_completion(&sbi->ll_kobj_unregister);
	err = kobject_set_name(&sbi->ll_kset.kobj, "%s", name);
	if (err)
		RETURN(err);

	err = kset_register(&sbi->ll_kset);
	if (err)
		RETURN(err);

	if (IS_ERR_OR_NULL(llite_root))
		RETURN(0);

	sbi->ll_debugfs_entry = debugfs_create_dir(name, llite_root);
	ldebugfs_add_vars(sbi->ll_debugfs_entry, lprocfs_llite_obd_vars, sb);

	debugfs_create_file("dump_page_cache", 0444, sbi->ll_debugfs_entry, sbi,
			    &vvp_dump_pgcache_file_ops);

	debugfs_create_file("extents_stats", 0644, sbi->ll_debugfs_entry, sbi,
				 &ll_rw_extents_stats_fops);

	debugfs_create_file("extents_stats_per_process", 0644,
			    sbi->ll_debugfs_entry, sbi,
			    &ll_rw_extents_stats_pp_fops);

	debugfs_create_file("offset_stats", 0644, sbi->ll_debugfs_entry, sbi,
			    &ll_rw_offset_stats_fops);

	/* File operations stats */
	scnprintf(param, sizeof(param), "llite.%s.stats", name);
	sbi->ll_stats = ldebugfs_stats_alloc(LPROC_LL_FILE_OPCODES, param,
					     sbi->ll_debugfs_entry,
					     LPROCFS_STATS_FLAG_NONE);
	if (!sbi->ll_stats)
		GOTO(out_debugfs, err = -ENOMEM);

	/* do counter init */
	for (id = 0; id < LPROC_LL_FILE_OPCODES; id++)
		lprocfs_counter_init(sbi->ll_stats,
				     llite_opcode_table[id].lfo_opcode,
				     llite_opcode_table[id].lfo_config,
				     llite_opcode_table[id].lfo_opname);

	sbi->ll_ra_stats = lprocfs_stats_alloc(ARRAY_SIZE(ra_stat_string),
					       LPROCFS_STATS_FLAG_NONE);
	if (sbi->ll_ra_stats == NULL)
		GOTO(out_stats, err = -ENOMEM);

	for (id = 0; id < ARRAY_SIZE(ra_stat_string); id++) {
		if (id == RA_STAT_READAHEAD_PAGES ||
		    id == RA_STAT_FORCEREAD_PAGES)
			lprocfs_counter_init(sbi->ll_ra_stats, id,
					     LPROCFS_TYPE_PAGES |
					     LPROCFS_CNTR_AVGMINMAX,
					     ra_stat_string[id]);
		else
			lprocfs_counter_init(sbi->ll_ra_stats, id,
					     LPROCFS_TYPE_PAGES,
					     ra_stat_string[id]);
	}

	debugfs_create_file("read_ahead_stats", 0644, sbi->ll_debugfs_entry,
			    sbi->ll_ra_stats, &ldebugfs_stats_seq_fops);

	RETURN(0);
out_stats:
	lprocfs_stats_free(&sbi->ll_stats);
out_debugfs:
	debugfs_remove_recursive(sbi->ll_debugfs_entry);

	RETURN(err);
}

void ll_debugfs_unregister_super(struct super_block *sb)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	debugfs_remove_recursive(sbi->ll_debugfs_entry);

	if (sbi->ll_dt_obd)
		sysfs_remove_link(&sbi->ll_kset.kobj,
				  sbi->ll_dt_obd->obd_type->typ_name);

	if (sbi->ll_md_obd)
		sysfs_remove_link(&sbi->ll_kset.kobj,
				  sbi->ll_md_obd->obd_type->typ_name);

	kset_unregister(&sbi->ll_kset);
	wait_for_completion(&sbi->ll_kobj_unregister);

	lprocfs_stats_free(&sbi->ll_ra_stats);
	lprocfs_stats_free(&sbi->ll_stats);
}
#undef MAX_STRING_SIZE

static void ll_display_extents_info(struct ll_rw_extents_info *rw_extents,
				    struct seq_file *seq, int which)
{
	unsigned long read_tot = 0, write_tot = 0, read_cum, write_cum;
	unsigned long start, end, r, w;
	char *unitp = "KMGTPEZY";
	int i, units = 10;
	struct per_process_info *pp_info;

	pp_info = &rw_extents->pp_extents[which];
	read_cum = 0;
	write_cum = 0;
	start = 0;

	for (i = 0; i < LL_HIST_MAX; i++) {
		read_tot += pp_info->pp_r_hist.oh_buckets[i];
		write_tot += pp_info->pp_w_hist.oh_buckets[i];
	}

	for (i = 0; i < LL_HIST_MAX; i++) {
		r = pp_info->pp_r_hist.oh_buckets[i];
		w = pp_info->pp_w_hist.oh_buckets[i];
		read_cum += r;
		write_cum += w;
		end = 1 << (i + LL_HIST_START - units);
		seq_printf(seq, "%4lu%c - %4lu%c%c: %14lu %4u %4u  | "
			   "%14lu %4u %4u\n", start, *unitp, end, *unitp,
			   (i == LL_HIST_MAX - 1) ? '+' : ' ',
			   r, pct(r, read_tot), pct(read_cum, read_tot),
			   w, pct(w, write_tot), pct(write_cum, write_tot));
		start = end;
		if (start == (1 << 10)) {
			start = 1;
			units += 10;
			unitp++;
		}
		if (read_cum == read_tot && write_cum == write_tot)
			break;
	}
}

static int ll_rw_extents_stats_pp_seq_show(struct seq_file *seq, void *v)
{
	struct ll_sb_info *sbi = seq->private;
	struct ll_rw_extents_info *rw_extents = sbi->ll_rw_extents_info;
	int k;

	if (!sbi->ll_rw_stats_on || !rw_extents) {
		seq_puts(seq, "disabled\n write anything to this file to activate, then '0' or 'disable' to deactivate\n");
		return 0;
	}

	spin_lock(&sbi->ll_pp_extent_lock);
	lprocfs_stats_header(seq, ktime_get_real(), rw_extents->pp_init, 25,
			     ":", true, "");
	seq_printf(seq, "%15s %19s       | %20s\n", " ", "read", "write");
	seq_printf(seq, "%13s   %14s %4s %4s  | %14s %4s %4s\n",
		   "extents", "calls", "%", "cum%", "calls", "%", "cum%");

	for (k = 0; k < LL_PROCESS_HIST_MAX; k++) {
		if (rw_extents->pp_extents[k].pid != 0) {
			seq_printf(seq, "\nPID: %d\n",
				   rw_extents->pp_extents[k].pid);
			ll_display_extents_info(rw_extents, seq, k);
		}
	}
	spin_unlock(&sbi->ll_pp_extent_lock);
	return 0;
}

static int alloc_rw_stats_info(struct ll_sb_info *sbi)
{
	struct ll_rw_extents_info *rw_extents;
	struct ll_rw_process_info *offset;
	struct ll_rw_process_info *process;
	int i, rc = 0;

	OBD_ALLOC(rw_extents, sizeof(*rw_extents));
	if (!rw_extents)
		return -ENOMEM;

	for (i = 0; i <= LL_PROCESS_HIST_MAX; i++) {
		spin_lock_init(&rw_extents->pp_extents[i].pp_r_hist.oh_lock);
		spin_lock_init(&rw_extents->pp_extents[i].pp_w_hist.oh_lock);
	}
	rw_extents->pp_init = ktime_get_real();

	spin_lock(&sbi->ll_pp_extent_lock);
	if (!sbi->ll_rw_extents_info)
		sbi->ll_rw_extents_info = rw_extents;
	spin_unlock(&sbi->ll_pp_extent_lock);
	/* another writer allocated the struct before we got the lock */
	if (sbi->ll_rw_extents_info != rw_extents)
		OBD_FREE(rw_extents, sizeof(*rw_extents));

	OBD_ALLOC(process, sizeof(*process) * LL_PROCESS_HIST_MAX);
	if (!process)
		GOTO(out, rc = -ENOMEM);
	OBD_ALLOC(offset, sizeof(*offset) * LL_OFFSET_HIST_MAX);
	if (!offset)
		GOTO(out_free, rc = -ENOMEM);

	spin_lock(&sbi->ll_process_lock);
	if (!sbi->ll_rw_process_info)
		sbi->ll_rw_process_info = process;
	if (!sbi->ll_rw_offset_info)
		sbi->ll_rw_offset_info = offset;
	spin_unlock(&sbi->ll_process_lock);
	sbi->ll_process_stats_init = ktime_get_real();

	/* another writer allocated the structs before we got the lock */
	if (sbi->ll_rw_offset_info != offset)
		OBD_FREE(offset, sizeof(*offset) * LL_OFFSET_HIST_MAX);
	if (sbi->ll_rw_process_info != process) {
out_free:
		OBD_FREE(process, sizeof(*process) * LL_PROCESS_HIST_MAX);
	}

out:
	return rc;
}

void ll_free_rw_stats_info(struct ll_sb_info *sbi)
{
	if (sbi->ll_rw_extents_info) {
		OBD_FREE(sbi->ll_rw_extents_info,
			 sizeof(*sbi->ll_rw_extents_info));
		sbi->ll_rw_extents_info = NULL;
	}
	if (sbi->ll_rw_offset_info) {
		OBD_FREE(sbi->ll_rw_offset_info,
			 sizeof(*sbi->ll_rw_offset_info) * LL_OFFSET_HIST_MAX);
		sbi->ll_rw_offset_info = NULL;
	}
	if (sbi->ll_rw_process_info) {
		OBD_FREE(sbi->ll_rw_process_info,
			sizeof(*sbi->ll_rw_process_info) * LL_PROCESS_HIST_MAX);
		sbi->ll_rw_process_info = NULL;
	}
}

static ssize_t ll_rw_extents_stats_pp_seq_write(struct file *file,
						const char __user *buf,
						size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct ll_sb_info *sbi = seq->private;
	struct ll_rw_extents_info *rw_extents;
	int i;
	__s64 value;

	if (len == 0)
		return -EINVAL;

	value = ll_stats_pid_write(buf, len);

	if (value == 0) {
		sbi->ll_rw_stats_on = 0;
	} else {
		if (!sbi->ll_rw_extents_info) {
			int rc = alloc_rw_stats_info(sbi);

			if (rc)
				return rc;
		}
		sbi->ll_rw_stats_on = 1;
	}


	spin_lock(&sbi->ll_pp_extent_lock);
	rw_extents = sbi->ll_rw_extents_info;
	if (rw_extents) {
		rw_extents->pp_init = ktime_get_real();
		for (i = 0; i < LL_PROCESS_HIST_MAX; i++) {
			rw_extents->pp_extents[i].pid = 0;
			lprocfs_oh_clear(&rw_extents->pp_extents[i].pp_r_hist);
			lprocfs_oh_clear(&rw_extents->pp_extents[i].pp_w_hist);
		}
	}
	spin_unlock(&sbi->ll_pp_extent_lock);

	return len;
}

LDEBUGFS_SEQ_FOPS(ll_rw_extents_stats_pp);

static int ll_rw_extents_stats_seq_show(struct seq_file *seq, void *v)
{
	struct ll_sb_info *sbi = seq->private;
	struct ll_rw_extents_info *rw_extents = sbi->ll_rw_extents_info;

	if (!sbi->ll_rw_stats_on || !rw_extents) {
		seq_puts(seq, "disabled\n write anything to this file to activate, then '0' or 'disable' to deactivate\n");
		return 0;
	}

	spin_lock(&sbi->ll_lock);
	lprocfs_stats_header(seq, ktime_get_real(), rw_extents->pp_init, 25,
			     ":", true, "");

	seq_printf(seq, "%15s %19s       | %20s\n", " ", "read", "write");
	seq_printf(seq, "%13s   %14s %4s %4s  | %14s %4s %4s\n",
		   "extents", "calls", "%", "cum%",
		   "calls", "%", "cum%");

	ll_display_extents_info(rw_extents, seq, LL_PROCESS_HIST_MAX);
	spin_unlock(&sbi->ll_lock);

	return 0;
}

static ssize_t ll_rw_extents_stats_seq_write(struct file *file,
					     const char __user *buf,
					     size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct ll_sb_info *sbi = seq->private;
	struct ll_rw_extents_info *rw_extents;
	int i;
	__s64 value;

	if (len == 0)
		return -EINVAL;

	value = ll_stats_pid_write(buf, len);

	if (value == 0) {
		sbi->ll_rw_stats_on = 0;
	} else {
		if (!sbi->ll_rw_extents_info) {
			int rc = alloc_rw_stats_info(sbi);

			if (rc)
				return rc;
		}
		sbi->ll_rw_stats_on = 1;
	}

	spin_lock(&sbi->ll_pp_extent_lock);
	rw_extents = sbi->ll_rw_extents_info;
	if (rw_extents) {
		rw_extents->pp_init = ktime_get_real();
		for (i = 0; i <= LL_PROCESS_HIST_MAX; i++) {
			rw_extents->pp_extents[i].pid = 0;
			lprocfs_oh_clear(&rw_extents->pp_extents[i].pp_r_hist);
			lprocfs_oh_clear(&rw_extents->pp_extents[i].pp_w_hist);
		}
	}
	spin_unlock(&sbi->ll_pp_extent_lock);

	return len;
}

LDEBUGFS_SEQ_FOPS(ll_rw_extents_stats);

void ll_rw_stats_tally(struct ll_sb_info *sbi, pid_t pid,
		       struct ll_file_data *lfd, loff_t pos,
		       size_t count, int rw)
{
	int i, cur = -1;
	struct ll_rw_process_info *process;
	struct ll_rw_process_info *offset;
	int *off_count = &sbi->ll_rw_offset_entry_count;
	int *process_count = &sbi->ll_offset_process_count;
	struct ll_rw_extents_info *rw_extents;

	if (!sbi->ll_rw_stats_on)
		return;

	spin_lock(&sbi->ll_pp_extent_lock);
	rw_extents = sbi->ll_rw_extents_info;
	if (!rw_extents) {
		spin_unlock(&sbi->ll_pp_extent_lock);
		return;
	}

	/* Extent statistics */
	for (i = 0; i < LL_PROCESS_HIST_MAX; i++) {
		if (rw_extents->pp_extents[i].pid == pid) {
			cur = i;
			break;
		}
	}

	if (cur == -1) {
		/* new process */
		sbi->ll_extent_process_count =
			(sbi->ll_extent_process_count + 1) %
			 LL_PROCESS_HIST_MAX;
		cur = sbi->ll_extent_process_count;
		rw_extents->pp_extents[cur].pid = pid;
		lprocfs_oh_clear(&rw_extents->pp_extents[cur].pp_r_hist);
		lprocfs_oh_clear(&rw_extents->pp_extents[cur].pp_w_hist);
	}

	for (i = 0; (count >= 1 << (LL_HIST_START + i)) &&
	     (i < (LL_HIST_MAX - 1)); i++);
	if (rw == 0) {
		rw_extents->pp_extents[cur].pp_r_hist.oh_buckets[i]++;
		rw_extents->pp_extents[LL_PROCESS_HIST_MAX].pp_r_hist.oh_buckets[i]++;
	} else {
		rw_extents->pp_extents[cur].pp_w_hist.oh_buckets[i]++;
		rw_extents->pp_extents[LL_PROCESS_HIST_MAX].pp_w_hist.oh_buckets[i]++;
	}
	spin_unlock(&sbi->ll_pp_extent_lock);

	spin_lock(&sbi->ll_process_lock);
	process = sbi->ll_rw_process_info;
	offset = sbi->ll_rw_offset_info;
	if (!process || !offset)
		goto out_unlock;

	/* Offset statistics */
	for (i = 0; i < LL_PROCESS_HIST_MAX; i++) {
		if (process[i].rw_pid == pid) {
			if (process[i].rw_last_file != lfd) {
				process[i].rw_range_start = pos;
				process[i].rw_last_file_pos = pos + count;
				process[i].rw_smallest_extent = count;
				process[i].rw_largest_extent = count;
				process[i].rw_offset = 0;
				process[i].rw_last_file = lfd;
				goto out_unlock;
			}
			if (process[i].rw_last_file_pos != pos) {
				*off_count =
					(*off_count + 1) % LL_OFFSET_HIST_MAX;
				offset[*off_count].rw_op = process[i].rw_op;
				offset[*off_count].rw_pid = pid;
				offset[*off_count].rw_range_start =
					process[i].rw_range_start;
				offset[*off_count].rw_range_end =
					process[i].rw_last_file_pos;
				offset[*off_count].rw_smallest_extent =
					process[i].rw_smallest_extent;
				offset[*off_count].rw_largest_extent =
					process[i].rw_largest_extent;
				offset[*off_count].rw_offset =
					process[i].rw_offset;
				process[i].rw_op = rw;
				process[i].rw_range_start = pos;
				process[i].rw_smallest_extent = count;
				process[i].rw_largest_extent = count;
				process[i].rw_offset = pos -
					process[i].rw_last_file_pos;
			}
			if (process[i].rw_smallest_extent > count)
				process[i].rw_smallest_extent = count;
			if (process[i].rw_largest_extent < count)
				process[i].rw_largest_extent = count;
			process[i].rw_last_file_pos = pos + count;
			goto out_unlock;
		}
	}
	*process_count = (*process_count + 1) % LL_PROCESS_HIST_MAX;
	process[*process_count].rw_pid = pid;
	process[*process_count].rw_op = rw;
	process[*process_count].rw_range_start = pos;
	process[*process_count].rw_last_file_pos = pos + count;
	process[*process_count].rw_smallest_extent = count;
	process[*process_count].rw_largest_extent = count;
	process[*process_count].rw_offset = 0;
	process[*process_count].rw_last_file = lfd;

out_unlock:
	spin_unlock(&sbi->ll_process_lock);
}

static int ll_rw_offset_stats_seq_show(struct seq_file *seq, void *v)
{
	struct ll_sb_info *sbi = seq->private;
	struct ll_rw_process_info *offset;
	struct ll_rw_process_info *process;
	int i;

	if (!sbi->ll_rw_stats_on) {
		seq_puts(seq,
			 "disabled\n write anything to this file to activate, then '0' or 'disable' to deactivate\n");
		return 0;
	}

	spin_lock(&sbi->ll_process_lock);
	lprocfs_stats_header(seq, ktime_get_real(), sbi->ll_process_stats_init,
			     25, ":", true, "");
	seq_printf(seq, "%3s %10s %14s %14s %17s %17s %14s\n",
		   "R/W", "PID", "RANGE START", "RANGE END",
		   "SMALLEST EXTENT", "LARGEST EXTENT", "OFFSET");

	/* We stored the discontiguous offsets here; print them first */
	offset = sbi->ll_rw_offset_info;
	for (i = 0; offset && i < LL_OFFSET_HIST_MAX; i++) {
		if (offset[i].rw_pid != 0)
			seq_printf(seq,
				  "%3c %10d %14llu %14llu %17lu %17lu %14lld\n",
				   offset[i].rw_op == READ ? 'R' : 'W',
				   offset[i].rw_pid,
				   offset[i].rw_range_start,
				   offset[i].rw_range_end,
				   (unsigned long)offset[i].rw_smallest_extent,
				   (unsigned long)offset[i].rw_largest_extent,
				   offset[i].rw_offset);
	}

	/* Then print the current offsets for each process */
	process = sbi->ll_rw_process_info;
	for (i = 0; process && i < LL_PROCESS_HIST_MAX; i++) {
		if (process[i].rw_pid != 0)
			seq_printf(seq,
				  "%3c %10d %14llu %14llu %17lu %17lu %14lld\n",
				   process[i].rw_op == READ ? 'R' : 'W',
				   process[i].rw_pid,
				   process[i].rw_range_start,
				   process[i].rw_last_file_pos,
				   (unsigned long)process[i].rw_smallest_extent,
				   (unsigned long)process[i].rw_largest_extent,
				   process[i].rw_offset);
	}
	spin_unlock(&sbi->ll_process_lock);

	return 0;
}

static ssize_t ll_rw_offset_stats_seq_write(struct file *file,
					    const char __user *buf,
					    size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct ll_sb_info *sbi = seq->private;
	__s64 value;

	if (len == 0)
		return -EINVAL;

	value = ll_stats_pid_write(buf, len);

	if (value == 0) {
		sbi->ll_rw_stats_on = 0;
	} else {
		if (!sbi->ll_rw_process_info || !sbi->ll_rw_offset_info) {
			int rc = alloc_rw_stats_info(sbi);

			if (rc)
				return rc;
		}
		sbi->ll_rw_stats_on = 1;
	}

	spin_lock(&sbi->ll_process_lock);
	sbi->ll_offset_process_count = 0;
	sbi->ll_rw_offset_entry_count = 0;
	sbi->ll_process_stats_init = ktime_get_real();
	if (sbi->ll_rw_process_info)
		memset(sbi->ll_rw_process_info, 0,
		       sizeof(struct ll_rw_process_info) * LL_PROCESS_HIST_MAX);
	if (sbi->ll_rw_offset_info)
		memset(sbi->ll_rw_offset_info, 0,
		       sizeof(struct ll_rw_process_info) * LL_OFFSET_HIST_MAX);
	spin_unlock(&sbi->ll_process_lock);

	return len;
}

LDEBUGFS_SEQ_FOPS(ll_rw_offset_stats);
