/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _LIBCFS_H


#define PORTAL_DEBUG

#ifndef offsetof
# define offsetof(typ,memb)     ((int)((char *)&(((typ *)0)->memb)))
#endif

#define LOWEST_BIT_SET(x)       ((x) & ~((x) - 1))

/*
 *  Debugging
 */
extern unsigned int portal_subsystem_debug;
extern unsigned int portal_stack;
extern unsigned int portal_debug;
extern unsigned int portal_printk;
extern unsigned int portal_cerror;
/* Debugging subsystems (32 bits, non-overlapping) */
#define S_UNDEFINED   0x00000001
#define S_MDC         0x00000002
#define S_MDS         0x00000004
#define S_OSC         0x00000008
#define S_OST         0x00000010
#define S_CLASS       0x00000020
#define S_LOG         0x00000040
#define S_LLITE       0x00000080
#define S_RPC         0x00000100
#define S_MGMT        0x00000200
#define S_PORTALS     0x00000400
#define S_SOCKNAL     0x00000800
#define S_QSWNAL      0x00001000
#define S_PINGER      0x00002000
#define S_FILTER      0x00004000
#define S_PTLBD       0x00008000
#define S_ECHO        0x00010000
#define S_LDLM        0x00020000
#define S_LOV         0x00040000
#define S_GMNAL       0x00080000
#define S_PTLROUTER   0x00100000
#define S_COBD        0x00200000
#define S_IBNAL       0x00400000

/* If you change these values, please keep portals/utils/debug.c
 * up to date! */

/* Debugging masks (32 bits, non-overlapping) */
#define D_TRACE       0x00000001 /* ENTRY/EXIT markers */
#define D_INODE       0x00000002
#define D_SUPER       0x00000004
#define D_EXT2        0x00000008 /* anything from ext2_debug */
#define D_MALLOC      0x00000010 /* print malloc, free information */
#define D_CACHE       0x00000020 /* cache-related items */
#define D_INFO        0x00000040 /* general information */
#define D_IOCTL       0x00000080 /* ioctl related information */
#define D_BLOCKS      0x00000100 /* ext2 block allocation */
#define D_NET         0x00000200 /* network communications */
#define D_WARNING     0x00000400 /* CWARN(...) == CDEBUG (D_WARNING, ...) */
#define D_BUFFS       0x00000800
#define D_OTHER       0x00001000
#define D_DENTRY      0x00002000
#define D_PORTALS     0x00004000 /* ENTRY/EXIT markers */
#define D_PAGE        0x00008000 /* bulk page handling */
#define D_DLMTRACE    0x00010000
#define D_ERROR       0x00020000 /* CERROR(...) == CDEBUG (D_ERROR, ...) */
#define D_EMERG       0x00040000 /* CEMERG(...) == CDEBUG (D_EMERG, ...) */
#define D_HA          0x00080000 /* recovery and failover */
#define D_RPCTRACE    0x00100000 /* for distributed debugging */
#define D_VFSTRACE    0x00200000
#define D_READA       0x00400000 /* read-ahead */

#ifdef __KERNEL__
# include <linux/sched.h> /* THREAD_SIZE */
#else
# ifndef THREAD_SIZE /* x86_64 has THREAD_SIZE in userspace */
#  define THREAD_SIZE 8192
# endif
#endif

#define LUSTRE_TRACE_SIZE (THREAD_SIZE >> 5)

#ifdef __KERNEL__
# ifdef  __ia64__
#  define CDEBUG_STACK (THREAD_SIZE -                                      \
                        ((unsigned long)__builtin_dwarf_cfa() &            \
                         (THREAD_SIZE - 1)))
# else
#  define CDEBUG_STACK (THREAD_SIZE -                                      \
                        ((unsigned long)__builtin_frame_address(0) &       \
                         (THREAD_SIZE - 1)))
# endif

#define CHECK_STACK(stack)                                                    \
        do {                                                                  \
                if ((stack) > 3*THREAD_SIZE/4 && (stack) > portal_stack) {    \
                        portals_debug_msg(DEBUG_SUBSYSTEM, D_WARNING,         \
                                          __FILE__, __FUNCTION__, __LINE__,   \
                                          (stack),"maximum lustre stack %u\n",\
                                          portal_stack = (stack));            \
                      /*panic("LBUG");*/                                      \
                }                                                             \
        } while (0)
#else /* __KERNEL__ */
#define CHECK_STACK(stack) do { } while(0)
#define CDEBUG_STACK (0L)
#endif /* __KERNEL__ */

#if 1
#define CDEBUG(mask, format, a...)                                            \
do {                                                                          \
        if (portal_cerror == 0)                                               \
                break;                                                        \
        CHECK_STACK(CDEBUG_STACK);                                            \
        if (((mask) & (D_ERROR | D_EMERG | D_WARNING)) ||                     \
            (portal_debug & (mask) &&                                         \
             portal_subsystem_debug & DEBUG_SUBSYSTEM))                       \
                portals_debug_msg(DEBUG_SUBSYSTEM, mask,                      \
                                  __FILE__, __FUNCTION__, __LINE__,           \
                                  CDEBUG_STACK, format, ## a);                \
} while (0)

#define CWARN(format, a...) CDEBUG(D_WARNING, format, ## a)
#define CERROR(format, a...) CDEBUG(D_ERROR, format, ## a)
#define CEMERG(format, a...) CDEBUG(D_EMERG, format, ## a)

#define GOTO(label, rc)                                                 \
do {                                                                    \
        long GOTO__ret = (long)(rc);                                    \
        CDEBUG(D_TRACE,"Process leaving via %s (rc=%lu : %ld : %lx)\n", \
               #label, (unsigned long)GOTO__ret, (signed long)GOTO__ret,\
               (signed long)GOTO__ret);                                 \
        goto label;                                                     \
} while (0)

#define RETURN(rc)                                                      \
do {                                                                    \
        typeof(rc) RETURN__ret = (rc);                                  \
        CDEBUG(D_TRACE, "Process leaving (rc=%lu : %ld : %lx)\n",       \
               (long)RETURN__ret, (long)RETURN__ret, (long)RETURN__ret);\
        return RETURN__ret;                                             \
} while (0)

#define ENTRY                                                           \
do {                                                                    \
        CDEBUG(D_TRACE, "Process entered\n");                           \
} while (0)

#define EXIT                                                            \
do {                                                                    \
        CDEBUG(D_TRACE, "Process leaving\n");                           \
} while(0)
#else
#define CDEBUG(mask, format, a...)      do { } while (0)
#define CWARN(format, a...)             do { } while (0)
#define CERROR(format, a...)            printk("<3>" format, ## a)
#define CEMERG(format, a...)            printk("<0>" format, ## a)
#define GOTO(label, rc)                 do { (void)(rc); goto label; } while (0)
#define RETURN(rc)                      return (rc)
#define ENTRY                           do { } while (0)
#define EXIT                            do { } while (0)
#endif

struct portal_ioctl_data {
        __u32 ioc_len;
        __u32 ioc_version;
        __u64 ioc_nid;
        __u64 ioc_nid2;
        __u64 ioc_nid3;
        __u32 ioc_count;
        __u32 ioc_nal;
        __u32 ioc_nal_cmd;
        __u32 ioc_fd;
        __u32 ioc_id;

        __u32 ioc_flags;
        __u32 ioc_size;

        __u32 ioc_wait;
        __u32 ioc_timeout;
        __u32 ioc_misc;

        __u32 ioc_inllen1;
        char *ioc_inlbuf1;
        __u32 ioc_inllen2;
        char *ioc_inlbuf2;

        __u32 ioc_plen1; /* buffers in userspace */
        char *ioc_pbuf1;
        __u32 ioc_plen2; /* buffers in userspace */
        char *ioc_pbuf2;

        char ioc_bulk[0];
};

#ifdef __KERNEL__

#include <linux/list.h>

struct libcfs_ioctl_handler {
        struct list_head item;
        int (*handle_ioctl)(struct portal_ioctl_data *data,
                            unsigned int cmd, unsigned long args);
};

#define DECLARE_IOCTL_HANDLER(ident, func)              \
        struct libcfs_ioctl_handler ident = {           \
                .item = LIST_HEAD_INIT(ident.item),     \
                .handle_ioctl = func                    \
        }

int libcfs_register_ioctl(struct libcfs_ioctl_handler *hand);
int libcfs_deregister_ioctl(struct libcfs_ioctl_handler *hand);

#endif

#define _LIBCFS_H

#endif /* _LIBCFS_H */
