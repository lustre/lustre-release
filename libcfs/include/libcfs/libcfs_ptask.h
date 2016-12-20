#ifndef __LIBCFS_PTASK_H__
#define __LIBCFS_PTASK_H__

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/uaccess.h>
#include <linux/notifier.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#ifdef CONFIG_PADATA
#include <linux/padata.h>
#else
struct padata_priv {};
struct padata_instance {};
#endif

#define PTF_COMPLETE	BIT(0)
#define PTF_AUTOFREE	BIT(1)
#define PTF_ORDERED	BIT(2)
#define PTF_USER_MM	BIT(3)
#define PTF_ATOMIC	BIT(4)
#define PTF_RETRY	BIT(5)

struct cfs_ptask_engine {
	struct padata_instance	*pte_pinst;
	struct workqueue_struct	*pte_wq;
	struct notifier_block	 pte_notifier;
	int			 pte_weight;
};

struct cfs_ptask;
typedef int (*cfs_ptask_cb_t)(struct cfs_ptask *);

struct cfs_ptask {
	struct padata_priv	 pt_padata;
	struct completion	 pt_completion;
	mm_segment_t		 pt_fs;
	struct mm_struct	*pt_mm;
	unsigned int		 pt_flags;
	int			 pt_cbcpu;
	cfs_ptask_cb_t		 pt_cbfunc;
	void			*pt_cbdata;
	int			 pt_result;
};

static inline
struct padata_priv *cfs_ptask2padata(struct cfs_ptask *ptask)
{
	return &ptask->pt_padata;
}

static inline
struct cfs_ptask *cfs_padata2ptask(struct padata_priv *padata)
{
	return container_of(padata, struct cfs_ptask, pt_padata);
}

static inline
bool cfs_ptask_need_complete(struct cfs_ptask *ptask)
{
	return ptask->pt_flags & PTF_COMPLETE;
}

static inline
bool cfs_ptask_is_autofree(struct cfs_ptask *ptask)
{
	return ptask->pt_flags & PTF_AUTOFREE;
}

static inline
bool cfs_ptask_is_ordered(struct cfs_ptask *ptask)
{
	return ptask->pt_flags & PTF_ORDERED;
}

static inline
bool cfs_ptask_use_user_mm(struct cfs_ptask *ptask)
{
	return ptask->pt_flags & PTF_USER_MM;
}

static inline
bool cfs_ptask_is_atomic(struct cfs_ptask *ptask)
{
	return ptask->pt_flags & PTF_ATOMIC;
}

static inline
bool cfs_ptask_is_retry(struct cfs_ptask *ptask)
{
	return ptask->pt_flags & PTF_RETRY;
}

static inline
int cfs_ptask_result(struct cfs_ptask *ptask)
{
	return ptask->pt_result;
}

struct cfs_ptask_engine *cfs_ptengine_init(const char *, const struct cpumask *);
void cfs_ptengine_fini(struct cfs_ptask_engine *);
int  cfs_ptengine_set_cpumask(struct cfs_ptask_engine *, const struct cpumask *);
int  cfs_ptengine_weight(struct cfs_ptask_engine *);

int  cfs_ptask_submit(struct cfs_ptask *, struct cfs_ptask_engine *);
int  cfs_ptask_wait_for(struct cfs_ptask *);
int  cfs_ptask_init(struct cfs_ptask *, cfs_ptask_cb_t, void *,
		    unsigned int, int);

#endif /* __LIBCFS_PTASK_H__ */
