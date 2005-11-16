#define DEBUG_PORTAL_ALLOC
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#ifndef __LINUX_SOCKNAL_LIB_H__
#define __LINUX_SOCKNAL_LIB_H__

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/uio.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/irq.h>

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <linux/kmod.h>
#include <linux/sysctl.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <asm/div64.h>

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
# include <linux/syscalls.h>
#endif

#include <libcfs/kp30.h>
#include <libcfs/linux/portals_compat25.h>

#define SOCKNAL_TX_LOW_WATER(sk) (((sk)->sk_sndbuf*8)/10)

#define SOCKNAL_ARCH_EAGER_ACK	0

#ifndef CONFIG_SMP
static inline
int ksocknal_nsched(void)
{
        return 1;
}
#else
#include <linux/lustre_version.h>
# if !(defined(CONFIG_X86) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,4,21))) || defined(CONFIG_X86_64) || (LUSTRE_KERNEL_VERSION < 39) || ((LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)) && !defined(CONFIG_X86_HT))
static inline int
ksocknal_nsched(void)
{
        return num_online_cpus();
}

static inline int
ksocknal_sched2cpu(int i)
{
        return i;
}

static inline int
ksocknal_irqsched2cpu(int i)
{
        return i;
}
# else
static inline int
ksocknal_nsched(void)
{
        if (smp_num_siblings == 1)
                return (num_online_cpus());

        /* We need to know if this assumption is crap */
        LASSERT (smp_num_siblings == 2);
        return (num_online_cpus()/2);
}

static inline int
ksocknal_sched2cpu(int i)
{
        if (smp_num_siblings == 1)
                return i;

        return (i * 2);
}

static inline int
ksocknal_irqsched2cpu(int i)
{
        return (ksocknal_sched2cpu(i) + 1);
}
# endif
#endif

#endif
