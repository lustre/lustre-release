# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>
#include "tracefile.h"

void libcfs_debug_dumpstack(cfs_task_t *tsk)
{ 
	return;
}

void libcfs_run_lbug_upcall(char *file, const char *fn, const int line)
{
}

void lbug_with_loc(char *file, const char *func, const int line)
{
        libcfs_catastrophe = 1;
        CEMERG("LBUG: pid: %u thread: %#x\n",
	       (unsigned)cfs_curproc_pid(), (unsigned)current_thread());
        libcfs_debug_dumplog();
        libcfs_run_lbug_upcall(file, func, line);
        while (1)
                cfs_schedule();

	/* panic("lbug_with_loc(%s, %s, %d)", file, func, line) */
}

#if ENTRY_NESTING_SUPPORT

static inline struct cfs_debug_data *__current_cdd(void)
{
	struct cfs_debug_data *cdd;

	cdd = (struct cfs_debug_data *)current_uthread()->uu_nlminfo;
	if (cdd != NULL &&
	    cdd->magic1 == CDD_MAGIC1 && cdd->magic2 == CDD_MAGIC2 &&
	    cdd->nesting_level < 1000)
		return cdd;
	else
		return NULL;
}

static inline void __current_cdd_set(struct cfs_debug_data *cdd)
{
	current_uthread()->uu_nlminfo = (void *)cdd;
}

void __entry_nesting(struct cfs_debug_data *child)
{
	struct cfs_debug_data *parent;

	parent = __current_cdd();
	if (parent != NULL) {
		child->parent        = parent;
		child->nesting_level = parent->nesting_level + 1;
	}
	__current_cdd_set(child);
}

void __exit_nesting(struct cfs_debug_data *child)
{
	__current_cdd_set(child->parent);
}

unsigned int __current_nesting_level(void)
{
	struct cfs_debug_data *cdd;

	cdd = __current_cdd();
	if (cdd != NULL)
		return cdd->nesting_level;
	else
		return 0;
}
/* ENTRY_NESTING_SUPPORT */
#endif
