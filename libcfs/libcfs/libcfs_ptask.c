#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/mmu_context.h>

#define DEBUG_SUBSYSTEM S_UNDEFINED

#include <libcfs/libcfs.h>
#include <libcfs/libcfs_ptask.h>

/**
 * This API based on Linux kernel padada API which is used to perform
 * encryption and decryption on large numbers of packets without
 * reordering those packets.
 *
 * It was adopted for general use in Lustre for parallelization of
 * various functionality.
 *
 * The first step in using it is to set up a cfs_ptask structure to
 * control of how this task are to be run:
 *
 * #include <libcfs/libcfs_ptask.h>
 *
 * int cfs_ptask_init(struct cfs_ptask *ptask, cfs_ptask_cb_t cbfunc,
 *                    void *cbdata, unsigned int flags, int cpu);
 *
 * The cbfunc function with cbdata argument will be called in the process
 * of getting the task done. The cpu specifies which CPU will be used for
 * the final callback when the task is done.
 *
 * The submission of task is done with:
 *
 * int cfs_ptask_submit(struct cfs_ptask *ptask, struct cfs_ptask_engine *engine);
 *
 * The task is submitted to the engine for execution.
 *
 * In order to wait for result of task execution you should call:
 *
 * int cfs_ptask_wait_for(struct cfs_ptask *ptask);
 *
 * The tasks with flag PTF_ORDERED are executed in parallel but complete
 * into submission order. So, waiting for last ordered task you can be sure
 * that all previous tasks were done before this task complete.
 */

#ifndef HAVE_REINIT_COMPLETION
/**
 * reinit_completion - reinitialize a completion structure
 * @x:  pointer to completion structure that is to be reinitialized
 *
 * This inline function should be used to reinitialize a completion
 * structure so it can be reused. This is especially important after
 * complete_all() is used.
 */
static inline void reinit_completion(struct completion *x)
{
	x->done = 0;
}
#endif

#ifndef HAVE_CPUMASK_PRINT_TO_PAGEBUF
static inline void cpumap_print_to_pagebuf(bool unused, char *buf,
					   const struct cpumask *mask)
{
	cpulist_scnprintf(buf, PAGE_SIZE, mask);
}
#endif

#ifdef CONFIG_PADATA
static void cfs_ptask_complete(struct padata_priv *padata)
{
	struct cfs_ptask *ptask = cfs_padata2ptask(padata);

	if (cfs_ptask_need_complete(ptask)) {
		if (cfs_ptask_is_ordered(ptask))
			complete(&ptask->pt_completion);
	} else if (cfs_ptask_is_autofree(ptask)) {
		kfree(ptask);
	}
}

static void cfs_ptask_execute(struct padata_priv *padata)
{
	struct cfs_ptask *ptask = cfs_padata2ptask(padata);
	mm_segment_t old_fs = get_fs();
	bool bh_enabled = false;

	if (!cfs_ptask_is_atomic(ptask)) {
		local_bh_enable();
		bh_enabled = true;
	}

	if (cfs_ptask_use_user_mm(ptask) && ptask->pt_mm != NULL) {
		use_mm(ptask->pt_mm);
		set_fs(ptask->pt_fs);
	}

	if (ptask->pt_cbfunc != NULL)
		ptask->pt_result = ptask->pt_cbfunc(ptask);
	else
		ptask->pt_result = -ENOSYS;

	if (cfs_ptask_use_user_mm(ptask) && ptask->pt_mm != NULL) {
		set_fs(old_fs);
		unuse_mm(ptask->pt_mm);
		mmput(ptask->pt_mm);
		ptask->pt_mm = NULL;
	}

	if (cfs_ptask_need_complete(ptask) && !cfs_ptask_is_ordered(ptask))
		complete(&ptask->pt_completion);

	if (bh_enabled)
		local_bh_disable();

	padata_do_serial(padata);
}

static int cfs_do_parallel(struct cfs_ptask_engine *engine,
			   struct padata_priv *padata)
{
	struct cfs_ptask *ptask = cfs_padata2ptask(padata);
	int rc;

	if (cfs_ptask_need_complete(ptask))
		reinit_completion(&ptask->pt_completion);

	if (cfs_ptask_use_user_mm(ptask)) {
		ptask->pt_mm = get_task_mm(current);
		ptask->pt_fs = get_fs();
	}
	ptask->pt_result = -EINPROGRESS;

retry:
	rc = padata_do_parallel(engine->pte_pinst, padata, ptask->pt_cbcpu);
	if (rc == -EBUSY && cfs_ptask_is_retry(ptask)) {
		/* too many tasks already in queue */
		schedule_timeout_uninterruptible(1);
		goto retry;
	}

	if (rc) {
		if (cfs_ptask_use_user_mm(ptask) && ptask->pt_mm != NULL) {
			mmput(ptask->pt_mm);
			ptask->pt_mm = NULL;
		}
		ptask->pt_result = rc;
	}

	return rc;
}

/**
 * This function submit initialized task for async execution
 * in engine with specified id.
 */
int cfs_ptask_submit(struct cfs_ptask *ptask, struct cfs_ptask_engine *engine)
{
	struct padata_priv *padata = cfs_ptask2padata(ptask);

	if (IS_ERR_OR_NULL(engine))
		return -EINVAL;

	memset(padata, 0, sizeof(*padata));

	padata->parallel = cfs_ptask_execute;
	padata->serial   = cfs_ptask_complete;

	return cfs_do_parallel(engine, padata);
}

#else  /* !CONFIG_PADATA */

/**
 * If CONFIG_PADATA is not defined this function just execute
 * the initialized task in current thread. (emulate async execution)
 */
int cfs_ptask_submit(struct cfs_ptask *ptask, struct cfs_ptask_engine *engine)
{
	if (IS_ERR_OR_NULL(engine))
		return -EINVAL;

	if (ptask->pt_cbfunc != NULL)
		ptask->pt_result = ptask->pt_cbfunc(ptask);
	else
		ptask->pt_result = -ENOSYS;

	if (cfs_ptask_need_complete(ptask))
		complete(&ptask->pt_completion);
	else if (cfs_ptask_is_autofree(ptask))
		kfree(ptask);

	return 0;
}
#endif /* CONFIG_PADATA */

EXPORT_SYMBOL(cfs_ptask_submit);

/**
 * This function waits when task complete async execution.
 * The tasks with flag PTF_ORDERED are executed in parallel but completes
 * into submission order. So, waiting for last ordered task you can be sure
 * that all previous tasks were done before this task complete.
 */
int cfs_ptask_wait_for(struct cfs_ptask *ptask)
{
	if (!cfs_ptask_need_complete(ptask))
		return -EINVAL;

	wait_for_completion(&ptask->pt_completion);

	return 0;
}
EXPORT_SYMBOL(cfs_ptask_wait_for);

/**
 * This function initialize internal members of task and prepare it for
 * async execution.
 */
int cfs_ptask_init(struct cfs_ptask *ptask, cfs_ptask_cb_t cbfunc, void *cbdata,
		   unsigned int flags, int cpu)
{
	memset(ptask, 0, sizeof(*ptask));

	ptask->pt_flags  = flags;
	ptask->pt_cbcpu  = cpu;
	ptask->pt_mm     = NULL; /* will be set in cfs_do_parallel() */
	ptask->pt_fs     = get_fs();
	ptask->pt_cbfunc = cbfunc;
	ptask->pt_cbdata = cbdata;
	ptask->pt_result = -EAGAIN;

	if (cfs_ptask_need_complete(ptask)) {
		if (cfs_ptask_is_autofree(ptask))
			return -EINVAL;

		init_completion(&ptask->pt_completion);
	}

	if (cfs_ptask_is_atomic(ptask) && cfs_ptask_use_user_mm(ptask))
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL(cfs_ptask_init);

/**
 * This function set the mask of allowed CPUs for parallel execution
 * for engine with specified id.
 */
int cfs_ptengine_set_cpumask(struct cfs_ptask_engine *engine,
			     const struct cpumask *cpumask)
{
	int rc = 0;

#ifdef CONFIG_PADATA
	cpumask_var_t serial_mask;
	cpumask_var_t parallel_mask;

	if (IS_ERR_OR_NULL(engine))
		return -EINVAL;

	if (!alloc_cpumask_var(&serial_mask, GFP_KERNEL))
		return -ENOMEM;

	if (!alloc_cpumask_var(&parallel_mask, GFP_KERNEL)) {
		free_cpumask_var(serial_mask);
		return -ENOMEM;
	}

	cpumask_copy(parallel_mask, cpumask);
	cpumask_copy(serial_mask, cpu_online_mask);

	rc = padata_set_cpumask(engine->pte_pinst, PADATA_CPU_PARALLEL,
				parallel_mask);
	free_cpumask_var(parallel_mask);
	if (rc)
		goto out_failed_mask;

	rc = padata_set_cpumask(engine->pte_pinst, PADATA_CPU_SERIAL,
				serial_mask);
out_failed_mask:
	free_cpumask_var(serial_mask);
#endif /* CONFIG_PADATA */

	return rc;
}
EXPORT_SYMBOL(cfs_ptengine_set_cpumask);

/**
 * This function returns the count of allowed CPUs for parallel execution
 * for engine with specified id.
 */
int cfs_ptengine_weight(struct cfs_ptask_engine *engine)
{
	if (IS_ERR_OR_NULL(engine))
		return -EINVAL;

	return engine->pte_weight;
}
EXPORT_SYMBOL(cfs_ptengine_weight);

#ifdef CONFIG_PADATA
static int cfs_ptask_cpumask_change_notify(struct notifier_block *self,
					   unsigned long val, void *data)
{
	struct padata_cpumask *padata_cpumask = data;
	struct cfs_ptask_engine *engine;

	engine = container_of(self, struct cfs_ptask_engine, pte_notifier);

	if (val & PADATA_CPU_PARALLEL)
		engine->pte_weight = cpumask_weight(padata_cpumask->pcpu);

	return 0;
}

static int cfs_ptengine_padata_init(struct cfs_ptask_engine *engine,
				    const char *name,
				    const struct cpumask *cpumask)
{
	cpumask_var_t all_mask;
	cpumask_var_t par_mask;
	unsigned int wq_flags = WQ_MEM_RECLAIM | WQ_CPU_INTENSIVE;
	int rc;

	get_online_cpus();

	engine->pte_wq = alloc_workqueue(name, wq_flags, 1);
	if (engine->pte_wq == NULL)
		GOTO(err, rc = -ENOMEM);

	if (!alloc_cpumask_var(&all_mask, GFP_KERNEL))
		GOTO(err_destroy_workqueue, rc = -ENOMEM);

	if (!alloc_cpumask_var(&par_mask, GFP_KERNEL))
		GOTO(err_free_all_mask, rc = -ENOMEM);

	cpumask_copy(par_mask, cpumask);
	if (cpumask_empty(par_mask) ||
	    cpumask_equal(par_mask, cpu_online_mask)) {
		cpumask_copy(all_mask, cpu_online_mask);
		cpumask_clear(par_mask);
		while (!cpumask_empty(all_mask)) {
			int cpu = cpumask_first(all_mask);

			cpumask_set_cpu(cpu, par_mask);
			cpumask_andnot(all_mask, all_mask,
					topology_sibling_cpumask(cpu));
		}
	}

	cpumask_copy(all_mask, cpu_online_mask);

	{
		char *pa_mask_buff, *cb_mask_buff;

		pa_mask_buff = (char *)__get_free_page(GFP_KERNEL);
		if (pa_mask_buff == NULL)
			GOTO(err_free_par_mask, rc = -ENOMEM);

		cb_mask_buff = (char *)__get_free_page(GFP_KERNEL);
		if (cb_mask_buff == NULL) {
			free_page((unsigned long)pa_mask_buff);
			GOTO(err_free_par_mask, rc = -ENOMEM);
		}

		cpumap_print_to_pagebuf(true, pa_mask_buff, par_mask);
		pa_mask_buff[PAGE_SIZE - 1] = '\0';
		cpumap_print_to_pagebuf(true, cb_mask_buff, all_mask);
		cb_mask_buff[PAGE_SIZE - 1] = '\0';

		CDEBUG(D_INFO, "%s weight=%u plist='%s' cblist='%s'\n",
			name, cpumask_weight(par_mask),
			pa_mask_buff, cb_mask_buff);

		free_page((unsigned long)cb_mask_buff);
		free_page((unsigned long)pa_mask_buff);
	}

	engine->pte_weight = cpumask_weight(par_mask);
	engine->pte_pinst  = padata_alloc_possible(engine->pte_wq);
	if (engine->pte_pinst == NULL)
		GOTO(err_free_par_mask, rc = -ENOMEM);

	engine->pte_notifier.notifier_call = cfs_ptask_cpumask_change_notify;
	rc = padata_register_cpumask_notifier(engine->pte_pinst,
					      &engine->pte_notifier);
	if (rc)
		GOTO(err_free_padata, rc);

	rc = cfs_ptengine_set_cpumask(engine, par_mask);
	if (rc)
		GOTO(err_unregister, rc);

	rc = padata_start(engine->pte_pinst);
	if (rc)
		GOTO(err_unregister, rc);

	free_cpumask_var(par_mask);
	free_cpumask_var(all_mask);

	put_online_cpus();
	return 0;

err_unregister:
	padata_unregister_cpumask_notifier(engine->pte_pinst,
					   &engine->pte_notifier);
err_free_padata:
	padata_free(engine->pte_pinst);
err_free_par_mask:
	free_cpumask_var(par_mask);
err_free_all_mask:
	free_cpumask_var(all_mask);
err_destroy_workqueue:
	destroy_workqueue(engine->pte_wq);
err:
	put_online_cpus();
	return rc;
}

static void cfs_ptengine_padata_fini(struct cfs_ptask_engine *engine)
{
	padata_stop(engine->pte_pinst);
	padata_unregister_cpumask_notifier(engine->pte_pinst,
					   &engine->pte_notifier);
	padata_free(engine->pte_pinst);
	destroy_workqueue(engine->pte_wq);
}

#else  /* !CONFIG_PADATA */

static int cfs_ptengine_padata_init(struct cfs_ptask_engine *engine,
				    const char *name,
				    const struct cpumask *cpumask)
{
	engine->pte_weight = 1;

	return 0;
}

static void cfs_ptengine_padata_fini(struct cfs_ptask_engine *engine)
{
}
#endif /* CONFIG_PADATA */

struct cfs_ptask_engine *cfs_ptengine_init(const char *name,
					   const struct cpumask *cpumask)
{
	struct cfs_ptask_engine *engine;
	int rc;

	engine = kzalloc(sizeof(*engine), GFP_KERNEL);
	if (engine == NULL)
		GOTO(err, rc = -ENOMEM);

	rc = cfs_ptengine_padata_init(engine, name, cpumask);
	if (rc)
		GOTO(err_free_engine, rc);

	return engine;

err_free_engine:
	kfree(engine);
err:
	return ERR_PTR(rc);
}
EXPORT_SYMBOL(cfs_ptengine_init);

void cfs_ptengine_fini(struct cfs_ptask_engine *engine)
{
	if (IS_ERR_OR_NULL(engine))
		return;

	cfs_ptengine_padata_fini(engine);
	kfree(engine);
}
EXPORT_SYMBOL(cfs_ptengine_fini);
