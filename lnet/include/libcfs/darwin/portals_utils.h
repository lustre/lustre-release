#ifndef __LIBCFS_DARWIN_PORTALS_UTILS_H__
#define __LIBCFS_DARWIN_PORTALS_UTILS_H__

#ifndef __LIBCFS_PORTALS_UTILS_H__
#error Do not #include this file directly. #include <libcfs/portals_utils.h> instead
#endif

#include <libcfs/list.h>
#ifdef __KERNEL__
#include <mach/mach_types.h>
#include <libcfs/libcfs.h>
#else /* !__KERNEL__ */
#include <machine/endian.h>
#include <netinet/in.h>
#include <sys/syscall.h>
#endif /* !__KERNEL__ */

#endif
