// SPDX-License-Identifier: GPL-2.0
/* This is taken from kernel commit:
 *
 * 8a0e8bb11 ("mm: shrinker: convert shrinker_rwsem to mutex")
 *
 * at kernel verison 6.6-rc4
 */
#include <linux/idr.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/memcontrol.h>
#include <lustre_compat/linux/shrinker.h>

#ifndef CONFIG_SHRINKER_DEBUG
/* RHEL7 is sooooo old and we really don't support it */
#ifdef HAVE_SHRINKER_COUNT
static DEFINE_IDA(shrinker_debugfs_ida);
#else
static int seq;
#endif
static struct dentry *shrinker_debugfs_root;

#ifndef SHRINK_EMPTY
#define SHRINK_EMPTY (~0UL - 1)
#endif

static unsigned long shrinker_count_objects(struct shrinker *shrinker,
					    struct mem_cgroup *memcg,
					    unsigned long *count_per_node)
{
	unsigned long nr, total = 0;
	int node_id;

	for_each_node(node_id) {
#ifdef HAVE_SHRINKER_COUNT
		if (node_id == 0 || (shrinker->flags & SHRINKER_NUMA_AWARE)) {
			struct shrink_control sc = {
				.gfp_mask = GFP_KERNEL,
				.nid = node_id,
				.memcg = memcg,
			};

			nr = shrinker->count_objects(shrinker, &sc);
#else
		if (node_id == 0) {
			struct shrink_control sc = {
				.gfp_mask = GFP_KERNEL,
			};

			nr = shrinker->shrink(shrinker, &sc);
#endif
			if (nr == SHRINK_EMPTY)
				nr = 0;
		} else {
			nr = 0;
		}

		count_per_node[node_id] = nr;
		total += nr;
	}

	return total;
}

static int shrinker_debugfs_count_show(struct seq_file *m, void *v)
{
	struct shrinker *shrinker = m->private;
	unsigned long *count_per_node;
	unsigned long total;
	int node_id;

	count_per_node = kcalloc(nr_node_ids, sizeof(unsigned long),
				 GFP_KERNEL);
	if (!count_per_node)
		return -ENOMEM;

	rcu_read_lock();

	/* Lustre shrinker's don't support memcg aware shrinkers so
	 * we simplify this code for older platforms. Sadly newer
	 * kernels don't export the memcg functions we need so even
	 * for the latest kernels we can't support memcg.
	 */
	total = shrinker_count_objects(shrinker, NULL, count_per_node);
	if (total) {
		/* Lustre doesn't support memcg aware shrinkers
		 * so just print 0
		 */
		seq_putc(m, '0');
		for_each_node(node_id)
			seq_printf(m, " %lu", count_per_node[node_id]);
		seq_putc(m, '\n');
	}

	rcu_read_unlock();

	kfree(count_per_node);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(shrinker_debugfs_count);

static int shrinker_debugfs_scan_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return nonseekable_open(inode, file);
}

static ssize_t shrinker_debugfs_scan_write(struct file *file,
					   const char __user *buf,
					   size_t size, loff_t *pos)
{
	struct shrinker *shrinker = file->private_data;
	unsigned long nr_to_scan = 0, ino, read_len;
	struct shrink_control sc = {
		.gfp_mask = GFP_KERNEL,
	};
	char kbuf[72];
	int node_id;

	read_len = size < (sizeof(kbuf) - 1) ? size : (sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, buf, read_len))
		return -EFAULT;
	kbuf[read_len] = '\0';

	if (sscanf(kbuf, "%lu %d %lu", &ino, &node_id, &nr_to_scan) != 3)
		return -EINVAL;

	if (node_id < 0 || node_id >= nr_node_ids)
		return -EINVAL;

	if (nr_to_scan == 0)
		return size;

	/* Lustre doesn't support memcg aware shrinkers */
	if (ino != 0)
		return -EINVAL;

	sc.nr_to_scan = nr_to_scan;
#ifdef HAVE_SHRINKER_COUNT
	sc.nr_scanned = nr_to_scan;
	sc.nid = node_id;
	sc.memcg = NULL;

	shrinker->scan_objects(shrinker, &sc);
#else
	shrinker->shrink(shrinker, &sc);
#endif
	return size;
}

static const struct file_operations shrinker_debugfs_scan_fops = {
	.owner	= THIS_MODULE,
	.open	= shrinker_debugfs_scan_open,
	.write	= shrinker_debugfs_scan_write,
};

static int shrinker_add_debugfs(struct shrinker *shrinker)
{
#ifndef HAVE_SHRINKER_ALLOC
	struct ll_shrinker *s = container_of(shrinker, struct ll_shrinker,
					     ll_shrinker);
#else
	struct ll_shrinker *s = shrinker->private_data;
#endif
	struct dentry *entry;
	char buf[128];
	int id;

	/* debugfs isn't initialized yet, add debugfs entries later. */
	if (!shrinker_debugfs_root)
		return 0;

#ifdef HAVE_SHRINKER_COUNT
	id = ida_alloc(&shrinker_debugfs_ida, GFP_KERNEL);
	if (id < 0)
		return id;
#else
	id = seq++;
#endif
	s->debugfs_id = id;

	snprintf(buf, sizeof(buf), "%s-%d", s->name, id);

	/* create debugfs entry */
	entry = debugfs_create_dir(buf, shrinker_debugfs_root);
	if (IS_ERR(entry)) {
#ifdef HAVE_SHRINKER_COUNT
		ida_free(&shrinker_debugfs_ida, id);
#else
		seq--;
#endif
		return PTR_ERR(entry);
	}
	s->debugfs_entry = entry;

	debugfs_create_file("count", 0440, entry, shrinker,
			    &shrinker_debugfs_count_fops);
	debugfs_create_file("scan", 0220, entry, shrinker,
			    &shrinker_debugfs_scan_fops);
	return 0;
}
#endif /* !CONFIG_SHRINKER_DEBUG */

void ll_shrinker_free(struct shrinker *shrinker)
{
#ifndef CONFIG_SHRINKER_DEBUG
#ifndef HAVE_SHRINKER_ALLOC
	struct ll_shrinker *s = container_of(shrinker, struct ll_shrinker,
					     ll_shrinker);
#else
	struct ll_shrinker *s = shrinker->private_data;
#endif /* HAVE_SHRINKER_ALLOC */

#ifdef HAVE_SHRINKER_COUNT
	if (s->debugfs_entry)
		ida_free(&shrinker_debugfs_ida, s->debugfs_id);
#endif
	debugfs_remove_recursive(s->debugfs_entry);
	kfree(s->name);
#endif /* !CONFIG_SHRINKER_DEBUG */

#ifdef HAVE_SHRINKER_ALLOC
	shrinker_free(shrinker);
#else /* !HAVE_SHRINKER_ALLOC */
	unregister_shrinker(shrinker);
#endif /* !HAVE_SHRINKER_ALLOC */

#ifndef CONFIG_SHRINKER_DEBUG
	LIBCFS_FREE_PRE(s, sizeof(*s), "kfreed");
	kfree(s);
#endif
}
EXPORT_SYMBOL(ll_shrinker_free);

/* allocate and register a shrinker, return should be checked with IS_ERR() */
struct shrinker *ll_shrinker_create(struct ll_shrinker_ops *ops,
				    unsigned int flags,
				    const char *fmt, ...)
{
	struct shrinker *shrinker;
#ifndef CONFIG_SHRINKER_DEBUG
	struct ll_shrinker *s;
#endif
#if defined(HAVE_REGISTER_SHRINKER_FORMAT_NAMED) || defined(HAVE_SHRINKER_ALLOC)
	struct va_format vaf;
#endif
	va_list args;
	int rc = 0;

	va_start(args, fmt);
#ifdef HAVE_SHRINKER_ALLOC
	vaf.fmt = fmt;
	vaf.va = &args;
	shrinker = shrinker_alloc(flags, "%pV", &vaf);
	va_end(args);
 #ifndef CONFIG_SHRINKER_DEBUG
	LIBCFS_ALLOC(s, sizeof(*s));
	if (!s) {
		shrinker_free(shrinker);
		shrinker = NULL;
	} else {
		s->name = kvasprintf_const(GFP_KERNEL, fmt, args);
		shrinker->private_data = s;
	}
 #endif
#else /* !HAVE_SHRINKER_ALLOC */
	LIBCFS_ALLOC(s, sizeof(*s));
 #if !defined(CONFIG_SHRINKER_DEBUG)
	if (s)
		s->name = kvasprintf_const(GFP_KERNEL, fmt, args);
 #endif
	va_end(args);
	shrinker = (struct shrinker *)s;
#endif
	if (!shrinker)
		return ERR_PTR(-ENOMEM);

#ifdef HAVE_SHRINKER_COUNT
	shrinker->count_objects = ops->count_objects;
	shrinker->scan_objects = ops->scan_objects;
#else
	shrinker->shrink = ops->shrink;
#endif
	shrinker->seeks = ops->seeks;

#ifdef HAVE_SHRINKER_ALLOC
	shrinker_register(shrinker);
#else
 #ifdef HAVE_REGISTER_SHRINKER_FORMAT_NAMED
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	rc = register_shrinker(shrinker, "%pV", &vaf);
	va_end(args);
 #else
	if (rc == 0) {
  #if defined(HAVE_REGISTER_SHRINKER_RET)
		rc = register_shrinker(shrinker);
  #else
		register_shrinker(shrinker);
  #endif
	}
 #endif
#endif
  #ifndef CONFIG_SHRINKER_DEBUG
	if (rc == 0 && s->name &&
	    strncmp(s->name, "ldlm_pools", strlen("ldlm_pools")) != 0)
		rc = shrinker_add_debugfs(shrinker);
  #endif
	if (rc) {
		ll_shrinker_free(shrinker);
		shrinker = ERR_PTR(rc);
	}
	return shrinker;
}
EXPORT_SYMBOL(ll_shrinker_create);

#ifndef CONFIG_SHRINKER_DEBUG
void shrinker_debugfs_fini(void)
{
	debugfs_remove_recursive(shrinker_debugfs_root);
}

int __init shrinker_debugfs_init(void)
{
	struct dentry *dentry;
	int ret = 0;

	dentry = debugfs_create_dir("shrinker", NULL);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);

	shrinker_debugfs_root = dentry;

	return ret;
}
#endif /* CONFIG_SHRINKER_DEBUG */
