# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/kp30.h>
#include <libcfs/libcfs.h>
#include "tracefile.h"

void libcfs_debug_dumpstack(cfs_task_t *tsk)
{ 
	return;
}

cfs_task_t *libcfs_current(void)
{ 
	return cfs_current();
}

int portals_arch_debug_init(unsigned long bufsize)
{
	return 0;
}

int portals_arch_debug_cleanup(void)
{
	return 0;
}
