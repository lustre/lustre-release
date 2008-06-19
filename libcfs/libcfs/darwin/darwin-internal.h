#ifndef __LIBCFS_DARWIN_INTERNAL_H__
#define __LIBCFS_DARWIN_INTERNAL_H__

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

int cfs_sysctl_isvalid(void);
struct sysctl_oid *cfs_alloc_sysctl_node(struct sysctl_oid_list *parent, int nbr, int access,
		                         const char *name, int (*handler) SYSCTL_HANDLER_ARGS);
struct sysctl_oid *cfs_alloc_sysctl_int(struct sysctl_oid_list *parent, int n,
					const char *name, int *ptr, int val);
struct sysctl_oid * cfs_alloc_sysctl_long(struct sysctl_oid_list *parent, int nbr, int access,
		                          const char *name, int *ptr, int val);
struct sysctl_oid * cfs_alloc_sysctl_string(struct sysctl_oid_list *parent, int nbr, int access,
		                            const char *name, char *ptr, int len);
struct sysctl_oid * cfs_alloc_sysctl_struct(struct sysctl_oid_list *parent, int nbr, int access,
		                            const char *name, void *ptr, int size);

#endif
