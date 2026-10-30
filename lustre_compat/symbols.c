// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (c) 2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Author: Timothy Day <timday@amazon.com>
 */

/* No you can't turn this into a Makefile variable since this
 * would be applied to the libcfs module.
 */
#define COMPAT_BUILD	1

#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/security.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include <linux/libcfs/libcfs.h>

#if defined(CONFIG_X86) && defined(CONFIG_HAVE_STATIC_CALL)
#include <linux/static_call.h>

/*
 * Call the functions looked up here through a static_call(): its call sites
 * are patched into direct calls, which avoid indirect branch mitigations and
 * need no ENDBR. With CONFIG_X86_KERNEL_IBT this is required, since the kernel
 * seals the ENDBR of functions whose address it never takes, so they cannot
 * be called through a pointer (LU-20995). Limited to x86, where the static
 * call trampoline in this module can always reach kernel text directly.
 */
#define CFS_DEFINE_SYMBOL(sym, func)	DEFINE_STATIC_CALL_NULL(sym, func)
#define cfs_symbol_call(sym)		static_call(sym)
#define cfs_symbol_set(sym, addr)					\
	static_call_update(sym, (typeof(&STATIC_CALL_TRAMP(sym)))(addr))
#else
#define CFS_DEFINE_SYMBOL(sym, func)	static struct { typeof(func) *fn; } sym
#define cfs_symbol_call(sym)		((sym).fn)
#define cfs_symbol_set(sym, addr)	((sym).fn = (addr))
#endif

CFS_DEFINE_SYMBOL(__cfs_kallsyms_lookup_name, kallsyms_lookup_name);

void *cfs_kallsyms_lookup_name(const char *name)
{
	return (void *)cfs_symbol_call(__cfs_kallsyms_lookup_name)(name);
}
EXPORT_SYMBOL_GPL(cfs_kallsyms_lookup_name);

#ifdef HAVE_KALLSYMS_LOOKUP_NAME
static int find_kallsyms_lookup_name(void)
{
	cfs_symbol_set(__cfs_kallsyms_lookup_name, kallsyms_lookup_name);

	return 0;
}
#else
static int find_kallsyms_lookup_name(void)
{
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
	};
	char buf[KSYM_SYMBOL_LEN];
	unsigned long addr;
	unsigned long off;
	char *p;
	int rc;

	rc = register_kprobe(&kp);
	if (rc < 0)
		return rc;

	addr = (unsigned long)kp.addr;
	unregister_kprobe(&kp);
	if (!addr)
		return -EINVAL;

	/*
	 * kp.addr is not necessarily the function entry: with
	 * CONFIG_X86_KERNEL_IBT the probe is placed after the ENDBR64
	 * (kallsyms_lookup_name+0x4), and on ppc64le (ELFv2) at the local entry
	 * point or the ftrace call site. Rewind to the start of the symbol.
	 * With IBT, kallsyms_lookup_name() has a sealed ENDBR and is called
	 * through a static_call(), i.e. with a direct call.
	 */
	sprint_symbol(buf, addr);
	p = strchr(buf, '+');
	if (!p || sscanf(p, "+%lx/", &off) != 1)
		return -EINVAL;
	addr -= off;

	cfs_symbol_set(__cfs_kallsyms_lookup_name, (void *)addr);

	return 0;
}
#endif

CFS_DEFINE_SYMBOL(__alloc_workqueue_attrs, compat_alloc_workqueue_attrs);

struct workqueue_attrs *compat_alloc_workqueue_attrs(void)
{
	return cfs_symbol_call(__alloc_workqueue_attrs)();
}
EXPORT_SYMBOL(compat_alloc_workqueue_attrs);

CFS_DEFINE_SYMBOL(__free_workqueue_attrs, compat_free_workqueue_attrs);

void compat_free_workqueue_attrs(struct workqueue_attrs *attrs)
{
	cfs_symbol_call(__free_workqueue_attrs)(attrs);
}
EXPORT_SYMBOL(compat_free_workqueue_attrs);

CFS_DEFINE_SYMBOL(__apply_workqueue_attrs, compat_apply_workqueue_attrs);

int compat_apply_workqueue_attrs(struct workqueue_struct *wq,
				  const struct workqueue_attrs *attrs)
{
	return cfs_symbol_call(__apply_workqueue_attrs)(wq, attrs);
}
EXPORT_SYMBOL(compat_apply_workqueue_attrs);

#ifdef alloc_workqueue_attrs
# define ALLOC_WQ_ATTRS_FUNC	"alloc_workqueue_attrs_noprof"
#else
# define ALLOC_WQ_ATTRS_FUNC	"alloc_workqueue_attrs"
#endif

#if defined(CONFIG_MEMCG) && !defined(HAVE_FOLIO_MEMCG_LOCK_STATIC) \
 && defined(HAVE_FOLIO_MEMCG_LOCK) && !defined(FOLIO_MEMCG_LOCK_EXPORTED)
CFS_DEFINE_SYMBOL(__folio_memcg_lock, folio_memcg_lock);

void folio_memcg_lock(struct folio *folio)
{
	cfs_symbol_call(__folio_memcg_lock)(folio);
}
EXPORT_SYMBOL_GPL(folio_memcg_lock);

CFS_DEFINE_SYMBOL(__folio_memcg_unlock, folio_memcg_unlock);

void folio_memcg_unlock(struct folio *folio)
{
	cfs_symbol_call(__folio_memcg_unlock)(folio);
}
EXPORT_SYMBOL_GPL(folio_memcg_unlock);
#endif

#ifdef CONFIG_SECURITY
CFS_DEFINE_SYMBOL(__security_file_alloc, compat_security_file_alloc);
CFS_DEFINE_SYMBOL(__security_file_free, compat_security_file_free);

int compat_security_file_alloc(struct file *file)
{
	return cfs_symbol_call(__security_file_alloc)(file);
}
EXPORT_SYMBOL(compat_security_file_alloc);

void compat_security_file_free(struct file *file)
{
	cfs_symbol_call(__security_file_free)(file);
}
EXPORT_SYMBOL(compat_security_file_free);
#endif

#if !defined(HAVE_ACCOUNT_PAGE_DIRTIED_EXPORT) && defined(HAVE_ACCOUNT_PAGE_DIRTIED)
CFS_DEFINE_SYMBOL(__account_page_dirtied, compat_account_page_dirtied);

unsigned int compat_account_page_dirtied(struct page *page,
					 struct address_space *mapping)
{
	return cfs_symbol_call(__account_page_dirtied)(page, mapping);
}
EXPORT_SYMBOL(compat_account_page_dirtied);
#endif

/* Look up @func and point the static call or pointer @sym at it. */
#define cfs_symbol_init(sym, func)					\
({									\
	void *__addr = cfs_kallsyms_lookup_name(func);			\
									\
	if (__addr)							\
		cfs_symbol_set(sym, __addr);				\
	__addr ? 0 : -EINVAL;						\
})

int __init lustre_symbols_init(void)
{
	int rc;

	rc = find_kallsyms_lookup_name();
	if (rc < 0)
		return rc;

	if (!cfs_kallsyms_lookup_name("kallsyms_lookup_name"))
		return -EINVAL;

	rc = cfs_symbol_init(__alloc_workqueue_attrs, ALLOC_WQ_ATTRS_FUNC);
	if (rc)
		return rc;

	rc = cfs_symbol_init(__free_workqueue_attrs, "free_workqueue_attrs");
	if (rc)
		return rc;

	rc = cfs_symbol_init(__apply_workqueue_attrs, "apply_workqueue_attrs");
	if (rc)
		return rc;

#if defined(CONFIG_MEMCG) && !defined(HAVE_FOLIO_MEMCG_LOCK_STATIC) \
 && defined(HAVE_FOLIO_MEMCG_LOCK) && !defined(FOLIO_MEMCG_LOCK_EXPORTED)
	rc = cfs_symbol_init(__folio_memcg_lock, "folio_memcg_lock");
	if (rc)
		return rc;

	rc = cfs_symbol_init(__folio_memcg_unlock, "folio_memcg_unlock");
	if (rc)
		return rc;
#endif
#if !defined(HAVE_ACCOUNT_PAGE_DIRTIED_EXPORT) && defined(HAVE_ACCOUNT_PAGE_DIRTIED)
	rc = cfs_symbol_init(__account_page_dirtied, "account_page_dirtied");
	if (rc)
		return rc;
#endif
#ifdef CONFIG_SECURITY
	rc = cfs_symbol_init(__security_file_alloc, "security_file_alloc");
	if (rc)
		return rc;

	rc = cfs_symbol_init(__security_file_free, "security_file_free");
	if (rc)
		return rc;
#endif

	return 0;
}
