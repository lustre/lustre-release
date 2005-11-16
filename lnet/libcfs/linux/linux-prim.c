#define DEBUG_SUBSYSTEM S_LNET
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>

int
libcfs_arch_init(void)
{ 
	return 0;
}

void
libcfs_arch_cleanup(void)
{
	return; 
}

EXPORT_SYMBOL(libcfs_arch_init);
EXPORT_SYMBOL(libcfs_arch_cleanup);
