# define DEBUG_SUBSYSTEM S_PORTALS

#include <libcfs/kp30.h>
#include <libcfs/libcfs.h>
#include "tracefile.h"

void portals_debug_dumpstack(cfs_task_t *tsk)
{ 
	return;
}

cfs_task_t *portals_current(void)
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
