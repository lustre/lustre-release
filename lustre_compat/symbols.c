// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (c) 2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Author: Timothy Day <timday@amazon.com>
 */

#include <linux/kprobes.h>
#include <linux/memcontrol.h>
#include <lustre_compat/linux/security.h>
#include <lustre_compat/linux/workqueue.h>

#include <linux/libcfs/libcfs.h>

static void *(*__cfs_kallsyms_lookup_name)(const char *name);

void *cfs_kallsyms_lookup_name(const char *name)
{
	return __cfs_kallsyms_lookup_name(name);
}
EXPORT_SYMBOL_GPL(cfs_kallsyms_lookup_name);

#ifdef HAVE_KALLSYMS_LOOKUP_NAME
static int find_kallsyms_lookup_name(void)
{
	__cfs_kallsyms_lookup_name = (void *(*)(const char *))kallsyms_lookup_name;

	return 0;
}
#else
static int find_kallsyms_lookup_name(void)
{
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
	};
	int rc;

	rc = register_kprobe(&kp);
	if (rc < 0)
		return rc;

	__cfs_kallsyms_lookup_name = (void *)kp.addr;
	if (!__cfs_kallsyms_lookup_name)
		return -EINVAL;

	unregister_kprobe(&kp);

	return 0;
}
#endif

static struct workqueue_attrs *(*__alloc_workqueue_attrs)(void);

struct workqueue_attrs *compat_alloc_workqueue_attrs(void)
{
	return __alloc_workqueue_attrs();
}
EXPORT_SYMBOL(compat_alloc_workqueue_attrs);

static void (*__free_workqueue_attrs)(struct workqueue_attrs *attrs);

void compat_free_workqueue_attrs(struct workqueue_attrs *attrs)
{
	return __free_workqueue_attrs(attrs);
}
EXPORT_SYMBOL(compat_free_workqueue_attrs);

static int (*__apply_workqueue_attrs)(struct workqueue_struct *wq,
				      const struct workqueue_attrs *attrs);

int compat_apply_workqueue_attrs(struct workqueue_struct *wq,
				  const struct workqueue_attrs *attrs)
{
	return __apply_workqueue_attrs(wq, attrs);
}
EXPORT_SYMBOL(compat_apply_workqueue_attrs);

#ifdef alloc_workqueue_attrs
# define ALLOC_WQ_ATTRS_FUNC	"alloc_workqueue_attrs_noprof"
#else
# define ALLOC_WQ_ATTRS_FUNC	"alloc_workqueue_attrs"
#endif

#if defined(CONFIG_MEMCG) && !defined(HAVE_FOLIO_MEMCG_LOCK_STATIC) \
 && defined(HAVE_FOLIO_MEMCG_LOCK) && !defined(FOLIO_MEMCG_LOCK_EXPORTED)
static void (*__folio_memcg_lock)(struct folio *folio);

void folio_memcg_lock(struct folio *folio)
{
	__folio_memcg_lock(folio);
}
EXPORT_SYMBOL_GPL(folio_memcg_lock);

static void (*__folio_memcg_unlock)(struct folio *folio);

void folio_memcg_unlock(struct folio *folio)
{
	__folio_memcg_unlock(folio);
}
EXPORT_SYMBOL_GPL(folio_memcg_unlock);
#endif

#ifdef CONFIG_SECURITY
static int (*__security_file_alloc)(struct file *file);
static void (*__security_file_free)(struct file *file);

int compat_security_file_alloc(struct file *file)
{
	return __security_file_alloc(file);
}
EXPORT_SYMBOL(compat_security_file_alloc);

void compat_security_file_free(struct file *file)
{
	return __security_file_free(file);
}
EXPORT_SYMBOL(compat_security_file_free);
#endif

int lustre_symbols_init(void)
{
	int rc;

	rc = find_kallsyms_lookup_name();
	if (rc < 0)
		return rc;

	if (!cfs_kallsyms_lookup_name("kallsyms_lookup_name"))
		return -EINVAL;

	__alloc_workqueue_attrs = cfs_kallsyms_lookup_name(ALLOC_WQ_ATTRS_FUNC);
	if (!__alloc_workqueue_attrs)
		return -EINVAL;

	__free_workqueue_attrs = cfs_kallsyms_lookup_name("free_workqueue_attrs");
	if (!__free_workqueue_attrs)
		return -EINVAL;

	__apply_workqueue_attrs = cfs_kallsyms_lookup_name("apply_workqueue_attrs");
	if (!__apply_workqueue_attrs)
		return -EINVAL;

#if defined(CONFIG_MEMCG) && !defined(HAVE_FOLIO_MEMCG_LOCK_STATIC) \
 && defined(HAVE_FOLIO_MEMCG_LOCK) && !defined(FOLIO_MEMCG_LOCK_EXPORTED)
	__folio_memcg_lock = cfs_kallsyms_lookup_name("folio_memcg_lock");
	if (!__folio_memcg_lock)
		return -EINVAL;

	__folio_memcg_unlock = cfs_kallsyms_lookup_name("folio_memcg_unlock");
	if (!__folio_memcg_unlock)
		return -EINVAL;
#endif
#ifdef CONFIG_SECURITY
	__security_file_alloc = cfs_kallsyms_lookup_name("security_file_alloc");
	if (!__security_file_alloc)
		return -EINVAL;

	__security_file_free = cfs_kallsyms_lookup_name("security_file_free");
	if (!__security_file_free)
		return -EINVAL;
#endif

	return 0;
}
