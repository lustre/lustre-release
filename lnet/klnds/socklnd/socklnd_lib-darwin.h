#ifndef __XNU_SOCKNAL_LIB_H__
#define __XNU_SOCKNAL_LIB_H__

#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/ubc.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/lockf.h>
#include <sys/syslog.h>
#include <machine/spl.h>
#include <mach/mach_types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>

#include <libcfs/libcfs.h>

static inline
int ksocknal_nsched(void)
{ 
	/* XXX Liang: fix it */
	return 1;
}

#endif
