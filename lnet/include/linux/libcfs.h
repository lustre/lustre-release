/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _LIBCFS_H

#include <linux/list.h>

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
#define S_UNDEFINED    (1 << 0)
#define S_MDC          (1 << 1)
#define S_MDS          (1 << 2)
#define S_OSC          (1 << 3)
#define S_OST          (1 << 4)
#define S_CLASS        (1 << 5)
#define S_LOG          (1 << 6)
#define S_LLITE        (1 << 7)
#define S_RPC          (1 << 8)
#define S_MGMT         (1 << 9)
#define S_PORTALS     (1 << 10)
#define S_SOCKNAL     (1 << 11)
#define S_QSWNAL      (1 << 12)
#define S_PINGER      (1 << 13)
#define S_FILTER      (1 << 14)
#define S_PTLBD       (1 << 15)
#define S_ECHO        (1 << 16)
#define S_LDLM        (1 << 17)
#define S_LOV         (1 << 18)
#define S_GMNAL       (1 << 19)
#define S_PTLROUTER   (1 << 20)
#define S_COBD        (1 << 21)
#define S_IBNAL       (1 << 22)

/* If you change these values, please keep portals/utils/debug.c
 * up to date! */

/* Debugging masks (32 bits, non-overlapping) */
#define D_TRACE     (1 << 0) /* ENTRY/EXIT markers */
#define D_INODE     (1 << 1)
#define D_SUPER     (1 << 2)
#define D_EXT2      (1 << 3) /* anything from ext2_debug */
#define D_MALLOC    (1 << 4) /* print malloc, free information */
#define D_CACHE     (1 << 5) /* cache-related items */
#define D_INFO      (1 << 6) /* general information */
#define D_IOCTL     (1 << 7) /* ioctl related information */
#define D_BLOCKS    (1 << 8) /* ext2 block allocation */
#define D_NET       (1 << 9) /* network communications */
#define D_WARNING   (1 << 10) /* CWARN(...) == CDEBUG (D_WARNING, ...) */
#define D_BUFFS     (1 << 11)
#define D_OTHER     (1 << 12)
#define D_DENTRY    (1 << 13)
#define D_PORTALS   (1 << 14) /* ENTRY/EXIT markers */
#define D_PAGE      (1 << 15) /* bulk page handling */
#define D_DLMTRACE  (1 << 16)
#define D_ERROR     (1 << 17) /* CERROR(...) == CDEBUG (D_ERROR, ...) */
#define D_EMERG     (1 << 18) /* CEMERG(...) == CDEBUG (D_EMERG, ...) */
#define D_HA        (1 << 19) /* recovery and failover */
#define D_RPCTRACE  (1 << 20) /* for distributed debugging */
#define D_VFSTRACE  (1 << 21)
#define D_READA     (1 << 22) /* read-ahead */

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

#define _LIBCFS_H

#endif /* _LIBCFS_H */
