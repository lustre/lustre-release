#ifndef __DARWIN_LUSTRE_COMPAT_H__
#define __DARWIN_LUSTRE_COMPAT_H__

#include <libcfs/libcfs.h>

#ifdef __KERNEL__

#ifndef HLIST_HEAD
#define hlist_entry                     list_entry
#define hlist_head                      list_head
#define hlist_node                      list_head
#define hlist_del_init                  list_del_init
#define hlist_add_head                  list_add
#define hlist_for_each_safe             list_for_each_safe

/* XXX */
#define LOOKUP_COBD 			4096

#endif

struct module;
static inline int try_module_get(struct module *module)
{
	return 1;
}

static inline void module_put(struct module *module)
{
}

#define THIS_MODULE                     NULL

static inline void lustre_daemonize_helper(void)
{
	return;
}

static inline int32_t ext2_set_bit(int nr, void *a)
{
	int32_t	old = test_bit(nr, a);
	set_bit(nr, a);
	return old;
}

static inline int32_t ext2_clear_bit(int nr, void *a)
{
	int32_t old = test_bit(nr, a);
	clear_bit(nr, a);
	return old;
}

struct nameidata;

#if !defined(__DARWIN8__)
static inline int ll_path_lookup(const char *path, unsigned int flags, struct nameidata *nd)
{
	int ret = 0;
	NDINIT(nd, LOOKUP, FOLLOW, UIO_SYSSPACE, (char *)path, current_proc());
	if (ret = namei(nd)){
		CERROR("ll_path_lookup fail!\n");
	}
	return ret;
}
#endif

#define to_kdev_t(dev)                  (dev)
#define kdev_t_to_nr(dev)               (dev)
#define val_to_kdev(dev)                (dev)

#define ext2_test_bit	test_bit

#endif	/* __KERNEL__ */

#endif
