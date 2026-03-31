// SPDX-License-Identifier: GPL-2.0

/*
 * Lustre Unified Target lprocfs/sysfs code
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 * Copyright (c) 2026, Google Inc.
 *
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <obd.h>
#include <obd_target.h>
#include <upcall_cache.h>
#include "tgt_internal.h"

/* This must be longer than the longest string below */
#define SYNC_STATES_MAXLEN 16
static const char * const sync_lock_cancel_states[] = {
	[SYNC_LOCK_CANCEL_NEVER]	= "never",
	[SYNC_LOCK_CANCEL_BLOCKING]	= "blocking",
	[SYNC_LOCK_CANCEL_ALWAYS]	= "always",
};

/**
 * Show policy for handling dirty data under a lock being cancelled.
 *
 * \param[in] kobj	sysfs kobject
 * \param[in] attr	sysfs attribute
 * \param[in] buf	buffer for data
 *
 * \retval		0 and buffer filled with data on success
 * \retval		negative value on error
 */
static ssize_t sync_lock_cancel_show(struct kobject *kobj,
				     struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *tgt = obd2obt(obd)->obt_lut;

	return scnprintf(buf, PAGE_SIZE, "%s\n",
			 sync_lock_cancel_states[tgt->lut_sync_lock_cancel]);
}

/**
 * Change policy for handling dirty data under a lock being cancelled.
 *
 * This variable defines what action target takes upon lock cancel
 * There are three possible modes:
 * 1) never - never do sync upon lock cancel. This can lead to data
 *    inconsistencies if both the OST and client crash while writing a file
 *    that is also concurrently being read by another client. In these cases,
 *    this may allow the file data to "rewind" to an earlier state.
 * 2) blocking - do sync only if there is blocking lock, e.g. if another
 *    client is trying to access this same object
 * 3) always - do sync always
 *
 * \param[in] kobj	kobject
 * \param[in] attr	attribute to show
 * \param[in] buf	buffer for data
 * \param[in] count	buffer size
 *
 * \retval		\a count on success
 * \retval		negative value on error
 */
static ssize_t sync_lock_cancel_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *tgt = obd2obt(obd)->obt_lut;
	int val = -1;
	enum tgt_sync_lock_cancel slc;

	if (count == 0 || count >= SYNC_STATES_MAXLEN)
		return -EINVAL;

	for (slc = 0; slc < ARRAY_SIZE(sync_lock_cancel_states); slc++) {
		if (strcmp(buffer, sync_lock_cancel_states[slc]) == 0) {
			val = slc;
			break;
		}
	}

	/* Legacy numeric codes */
	if (val == -1) {
		int rc = kstrtoint(buffer, 0, &val);

		if (rc)
			return rc;
	}

	if (val < 0 || val > 2)
		return -EINVAL;

	spin_lock(&tgt->lut_flags_lock);
	tgt->lut_sync_lock_cancel = val;
	spin_unlock(&tgt->lut_flags_lock);
	return count;
}
LUSTRE_RW_ATTR(sync_lock_cancel);

/**
 * Show maximum number of Filter Modification Data (FMD) maintained.
 *
 * \param[in] kobj	kobject
 * \param[in] attr	attribute to show
 * \param[in] buf	buffer for data
 *
 * \retval		0 and buffer filled with data on success
 * \retval		negative value on error
 */
static ssize_t tgt_fmd_count_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *lut = obd2obt(obd)->obt_lut;

	return scnprintf(buf, PAGE_SIZE, "%u\n", lut->lut_fmd_max_num);
}

/**
 * Change number of FMDs maintained by target.
 *
 * This defines how large the list of FMDs can be.
 *
 * \param[in] kobj	kobject
 * \param[in] attr	attribute to show
 * \param[in] buf	buffer for data
 * \param[in] count	buffer size
 *
 * \retval		\a count on success
 * \retval		negative value on error
 */
static ssize_t tgt_fmd_count_store(struct kobject *kobj, struct attribute *attr,
				   const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *lut = obd2obt(obd)->obt_lut;
	int val, rc;

	rc = kstrtoint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < 1 || val > 65536)
		return -EINVAL;

	lut->lut_fmd_max_num = val;

	return count;
}
LUSTRE_RW_ATTR(tgt_fmd_count);

/**
 * Show the maximum age of FMD data in seconds.
 *
 * \param[in] kobj	kobject
 * \param[in] attr	attribute to show
 * \param[in] buf	buffer for data
 *
 * \retval		0 and buffer filled with data on success
 * \retval		negative value on error
 */
static ssize_t tgt_fmd_seconds_show(struct kobject *kobj,
				    struct attribute *attr,
				    char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *lut = obd2obt(obd)->obt_lut;

	return scnprintf(buf, PAGE_SIZE, "%lld\n", lut->lut_fmd_max_age);
}

/**
 * Set the maximum age of FMD data in seconds.
 *
 * This defines how long FMD data stays in the FMD list.
 *
 * \param[in] kobj	kobject
 * \param[in] attr	attribute to show
 * \param[in] buf	buffer for data
 * \param[in] count	buffer size
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t tgt_fmd_seconds_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *lut = obd2obt(obd)->obt_lut;
	time64_t val;
	int rc;

	rc = kstrtoll(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < 1 || val > 65536) /* ~ 18 hour max */
		return -EINVAL;

	lut->lut_fmd_max_age = val;

	return count;
}
LUSTRE_RW_ATTR(tgt_fmd_seconds);

/* These two aliases are old names and kept for compatibility, they were
 * changed to 'tgt_fmd_count' and 'tgt_fmd_seconds'.
 * This change was made in Lustre 2.13, so these aliases can be removed
 * when back compatibility is not needed with any Lustre version prior 2.13
 */
static struct lustre_attr tgt_fmd_count_compat = __ATTR(client_cache_count,
			0644, tgt_fmd_count_show, tgt_fmd_count_store);
static struct lustre_attr tgt_fmd_seconds_compat = __ATTR(client_cache_seconds,
			0644, tgt_fmd_seconds_show, tgt_fmd_seconds_store);

static const struct attribute *tgt_attrs[] = {
	&lustre_attr_sync_lock_cancel.attr,
	&lustre_attr_tgt_fmd_count.attr,
	&lustre_attr_tgt_fmd_seconds.attr,
	&tgt_fmd_count_compat.attr,
	&tgt_fmd_seconds_compat.attr,
	NULL,
};

int tgt_tunables_init(struct lu_target *lut)
{
	int rc;

	rc = sysfs_create_files(&lut->lut_obd->obd_kset.kobj, tgt_attrs);
	if (!rc)
		lut->lut_attrs = tgt_attrs;
	return rc;
}
EXPORT_SYMBOL(tgt_tunables_init);

void tgt_tunables_fini(struct lu_target *lut)
{
	if (lut->lut_attrs) {
		sysfs_remove_files(&lut->lut_obd->obd_kset.kobj,
				   lut->lut_attrs);
		lut->lut_attrs = NULL;
	}
}
EXPORT_SYMBOL(tgt_tunables_fini);

static ssize_t gssiam_auth_upcall_show(struct kobject *kobj,
				       struct attribute *attr, char *buf)
{
	int len;

	if (!tgt_gssiam_cache)
		return -EOPNOTSUPP;

	down_read(&tgt_gssiam_cache->uc_upcall_rwsem);
	len = scnprintf(buf, PAGE_SIZE, "%s\n", tgt_gssiam_cache->uc_upcall);
	up_read(&tgt_gssiam_cache->uc_upcall_rwsem);

	return len;
}

static ssize_t gssiam_auth_upcall_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buf, size_t count)
{
	int rc;

	if (!tgt_gssiam_cache)
		return -EOPNOTSUPP;

	rc = upcall_cache_set_upcall(tgt_gssiam_cache, buf, count, false);
	if (rc)
		CERROR("%s: failed to set gssiam auth upcall: rc = %d\n",
		       tgt_gssiam_cache->uc_name, rc);

	return rc ?: count;
}
LUSTRE_RW_ATTR(gssiam_auth_upcall);

static ssize_t gssiam_auth_downcall_store(struct kobject *kobj,
					  struct attribute *attr,
					  const char *buffer, size_t count)
{
	if (!tgt_gssiam_cache)
		return -EOPNOTSUPP;

	return tgt_gssiam_downcall(buffer, count);
}
LUSTRE_WO_ATTR(gssiam_auth_downcall);

static ssize_t gssiam_refresh_interval_show(struct kobject *kobj,
					    struct attribute *attr, char *buf)
{
	if (!tgt_gssiam_cache)
		return -EOPNOTSUPP;

	return scnprintf(buf, PAGE_SIZE, "%lld\n",
			 tgt_gssiam_cache->uc_entry_expire);
}

static ssize_t gssiam_refresh_interval_store(struct kobject *kobj,
					     struct attribute *attr,
					     const char *buffer, size_t count)
{
	time64_t val;
	int rc;

	if (!tgt_gssiam_cache)
		return -EOPNOTSUPP;

	rc = kstrtoll(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < 0)
		return -ERANGE;

	tgt_gssiam_cache->uc_entry_expire = val;

	return count;
}
LUSTRE_RW_ATTR(gssiam_refresh_interval);

static ssize_t gssiam_flush_store(struct kobject *kobj,
				  struct attribute *attr,
				  const char *buffer, size_t count)
{
	int val;
	int rc;

	if (!tgt_gssiam_cache)
		return -EOPNOTSUPP;

	rc = kstrtoint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val != -1)
		return -EINVAL;

	upcall_cache_flush_idle(tgt_gssiam_cache);
	return count;
}
LUSTRE_WO_ATTR(gssiam_flush);

static struct attribute *tgt_gssiam_attrs[] = {
	&lustre_attr_gssiam_auth_downcall.attr,
	&lustre_attr_gssiam_auth_upcall.attr,
	&lustre_attr_gssiam_flush.attr,
	&lustre_attr_gssiam_refresh_interval.attr,
	NULL
};

static struct attribute_group tgt_gssiam_attr_group = {
	.attrs = tgt_gssiam_attrs,
};

static struct kobject *tgt_gssiam_kobj;

int tgt_gssiam_tunables_init(void)
{
	int rc;

	tgt_gssiam_kobj = kobject_create_and_add(GSSIAM_TGT_CACHE_NAME,
						 sptlrpc_kobj);
	if (!tgt_gssiam_kobj)
		return -ENOMEM;

	rc = sysfs_create_group(tgt_gssiam_kobj, &tgt_gssiam_attr_group);
	if (rc) {
		kobject_put(tgt_gssiam_kobj);
		tgt_gssiam_kobj = NULL;
	}

	return rc;
}

void tgt_gssiam_tunables_fini(void)
{
	if (tgt_gssiam_kobj) {
		sysfs_remove_group(tgt_gssiam_kobj, &tgt_gssiam_attr_group);
		kobject_put(tgt_gssiam_kobj);
		tgt_gssiam_kobj = NULL;
	}
}
