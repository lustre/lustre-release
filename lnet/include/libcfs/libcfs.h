/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __LIBCFS_LIBCFS_H__
#define __LIBCFS_LIBCFS_H__

#if !__GNUC__
#define __attribute__(x)
#endif

#if defined(__linux__)
#include <libcfs/linux/libcfs.h>
#elif defined(__APPLE__)
#include <libcfs/darwin/libcfs.h>
#elif defined(__WINNT__)
#include <libcfs/winnt/libcfs.h>
#else
#error Unsupported operating system.
#endif

#include "curproc.h"

#ifndef __KERNEL__
#include <stdio.h>
#endif

#define LIBCFS_DEBUG

#ifndef offsetof
# define offsetof(typ,memb)     ((unsigned long)((char *)&(((typ *)0)->memb)))
#endif

/* cardinality of array */
#define sizeof_array(a) ((sizeof (a)) / (sizeof ((a)[0])))

#if !defined(container_of)
/* given a pointer @ptr to the field @member embedded into type (usually
 * struct) @type, return pointer to the embedding instance of @type. */
#define container_of(ptr, type, member) \
        ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))
#endif

/*
 * true iff @i is power-of-2
 */
#define IS_PO2(i)                               \
({                                              \
        typeof(i) __i;                          \
                                                \
        __i = (i);                              \
        !(__i & (__i - 1));                     \
})

#define LOWEST_BIT_SET(x)       ((x) & ~((x) - 1))

/*
 *  Debugging
 */
extern unsigned int libcfs_subsystem_debug;
extern unsigned int libcfs_stack;
extern unsigned int libcfs_debug;
extern unsigned int libcfs_printk;
extern unsigned int libcfs_debug_binary;

/* Has there been an LBUG? */
extern unsigned int libcfs_catastrophe;

/*
 * struct ptldebug_header is defined in libcfs/<os>/libcfs.h
 */

#define PH_FLAG_FIRST_RECORD 1

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
#define S_LNET        0x00000400
#define S_LND         0x00000800 /* ALL LNDs */
#define S_PINGER      0x00001000
#define S_FILTER      0x00002000
#define S_PTLBD       0x00004000
#define S_ECHO        0x00008000
#define S_LDLM        0x00010000
#define S_LOV         0x00020000
/* unused */
#define S_COBD        0x00080000
#define S_SM          0x00100000
#define S_ASOBD       0x00200000
#define S_CONFOBD     0x00400000
#define S_LMV         0x00800000
#define S_CMOBD       0x01000000
#define S_SEC         0x02000000
#define S_GSS         0x04000000
#define S_GKS         0x08000000
#define S_MGC         0x10000000
#define S_MGS         0x20000000
/* If you change these values, please keep these files up to date...
 *    portals/utils/debug.c
 *    utils/lconf
 */

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
#define D_MMAP        0x00800000
#define D_CONFIG      0x01000000
#define D_CONSOLE     0x02000000
#define D_QUOTA       0x04000000
#define D_SEC         0x08000000
/* If you change these values, please keep these files up to date...
 *    portals/utils/debug.c
 *    utils/lconf
 */

#ifndef DEBUG_SUBSYSTEM
# define DEBUG_SUBSYSTEM S_UNDEFINED
#endif

#ifdef __KERNEL__
#define CDEBUG(mask, format, a...)                                            \
do {                                                                          \
        CHECK_STACK(CDEBUG_STACK);                                            \
        if (((mask) & (D_ERROR | D_EMERG | D_WARNING | D_CONSOLE)) ||         \
            (libcfs_debug & (mask) &&                                         \
             libcfs_subsystem_debug & DEBUG_SUBSYSTEM))                       \
                libcfs_debug_msg(DEBUG_SUBSYSTEM, mask,                       \
                                  __FILE__, __FUNCTION__, __LINE__,           \
                                  CDEBUG_STACK, format, ## a);                \
} while (0)

#define CDEBUG_MAX_LIMIT 600
#define CDEBUG_LIMIT(cdebug_mask, cdebug_format, a...)                        \
do {                                                                          \
        static cfs_time_t cdebug_next = 0;                                    \
        static int cdebug_count = 0;                                          \
        static cfs_duration_t cdebug_delay = CFS_TICK;                        \
                                                                              \
        CHECK_STACK(CDEBUG_STACK);                                            \
        if (cfs_time_after(cfs_time_current(), cdebug_next)) {                \
                libcfs_debug_msg(DEBUG_SUBSYSTEM, cdebug_mask, __FILE__,      \
                                  __FUNCTION__, __LINE__, CDEBUG_STACK,       \
                                  cdebug_format, ## a);                       \
                if (cdebug_count) {                                           \
                        libcfs_debug_msg(DEBUG_SUBSYSTEM, cdebug_mask,        \
                                         __FILE__, __FUNCTION__, __LINE__, 0, \
                                         "previously skipped %d similar "     \
                                         "messages\n", cdebug_count);         \
                        cdebug_count = 0;                                     \
                }                                                             \
                if (cfs_time_after(cfs_time_current(),                        \
                                   cdebug_next +                              \
                                   cfs_time_seconds(CDEBUG_MAX_LIMIT+10)))    \
                        cdebug_delay = cdebug_delay > (8 * CFS_TICK)?         \
                                       cdebug_delay/8 : CFS_TICK;             \
                else                                                          \
                        cdebug_delay = cdebug_delay*2 >= cfs_time_seconds(CDEBUG_MAX_LIMIT)?\
                                       cfs_time_seconds(CDEBUG_MAX_LIMIT) :   \
                                       cdebug_delay*2;                        \
                cdebug_next = cfs_time_current() + cdebug_delay;              \
        } else {                                                              \
                libcfs_debug_msg(DEBUG_SUBSYSTEM,                             \
                                 libcfs_debug &                               \
                                 ~(D_EMERG|D_ERROR|D_WARNING|D_CONSOLE),      \
                                 __FILE__, __FUNCTION__, __LINE__,            \
                                 CDEBUG_STACK, cdebug_format, ## a);          \
                cdebug_count++;                                               \
        }                                                                     \
} while (0)

#elif defined(__arch_lib__) && !defined(LUSTRE_UTILS)

#define CDEBUG(mask, format, a...)                                      \
do {                                                                    \
        if (((mask) & (D_ERROR | D_EMERG | D_WARNING | D_CONSOLE)) ||   \
            (libcfs_debug & (mask) &&                                   \
             libcfs_subsystem_debug & DEBUG_SUBSYSTEM)) {               \
                libcfs_debug_msg(DEBUG_SUBSYSTEM, mask, __FILE__,       \
                                __FUNCTION__, __LINE__, 0, format, ## a);\
        }                                                               \
} while (0)
#define CDEBUG_LIMIT CDEBUG

#else

#define CDEBUG(mask, format, a...)                                      \
do {                                                                    \
        if ((mask) & (D_ERROR | D_EMERG | D_WARNING | D_CONSOLE))       \
                fprintf(stderr, "(%s:%d:%s()) " format,                 \
                        __FILE__, __LINE__, __FUNCTION__, ## a);        \
} while (0)
#define CDEBUG_LIMIT CDEBUG

#endif /* !__KERNEL__ */

#define CWARN(format, a...)          CDEBUG_LIMIT(D_WARNING, format, ## a)
#define CERROR(format, a...)         CDEBUG_LIMIT(D_ERROR, format, ## a)
#define CEMERG(format, a...)         CDEBUG_LIMIT(D_EMERG, format, ## a)

#define LCONSOLE(mask, format, a...) CDEBUG(D_CONSOLE | (mask), format, ## a)
#define LCONSOLE_INFO(format, a...)  CDEBUG_LIMIT(D_CONSOLE, format, ## a)
#define LCONSOLE_WARN(format, a...)  CDEBUG_LIMIT(D_CONSOLE | D_WARNING, format, ## a)
#define LCONSOLE_ERROR(format, a...) CDEBUG_LIMIT(D_CONSOLE | D_ERROR, format, ## a)
#define LCONSOLE_EMERG(format, a...) CDEBUG(D_CONSOLE | D_EMERG, format, ## a)

#define GOTO(label, rc)                                                 \
do {                                                                    \
        long GOTO__ret = (long)(rc);                                    \
        CDEBUG(D_TRACE,"Process leaving via %s (rc=%lu : %ld : %lx)\n", \
               #label, (unsigned long)GOTO__ret, (signed long)GOTO__ret,\
               (signed long)GOTO__ret);                                 \
        goto label;                                                     \
} while (0)

#define CDEBUG_ENTRY_EXIT (1)
#if CDEBUG_ENTRY_EXIT

/*
 * if rc == NULL, we need to code as RETURN((void *)NULL), otherwise
 * there will be a warning in osx.
 */
#define RETURN(rc)                                                      \
do {                                                                    \
        typeof(rc) RETURN__ret = (rc);                                  \
        CDEBUG(D_TRACE, "Process leaving (rc=%lu : %ld : %lx)\n",       \
               (long)RETURN__ret, (long)RETURN__ret, (long)RETURN__ret);\
        EXIT_NESTING;                                                   \
        return RETURN__ret;                                             \
} while (0)

#define ENTRY                                                           \
ENTRY_NESTING;                                                          \
do {                                                                    \
        CDEBUG(D_TRACE, "Process entered\n");                           \
} while (0)

#define EXIT                                                            \
do {                                                                    \
        CDEBUG(D_TRACE, "Process leaving\n");                           \
        EXIT_NESTING;                                                   \
} while(0)
#else /* !CDEBUG_ENTRY_EXIT */

#define RETURN(rc) return (rc)
#define ENTRY                           do { } while (0)
#define EXIT                            do { } while (0)

#endif /* !CDEBUG_ENTRY_EXIT */

/*
 * Some (nomina odiosa sunt) platforms define NULL as naked 0. This confuses
 * Lustre RETURN(NULL) macro.
 */
#if defined(NULL)
#undef NULL
#endif

/*
 * Define lbug_with_loc for your own platform.
 */
void lbug_with_loc(char *file,
                   const char *func,
                   const int line) __attribute__((noreturn));

#define LBUG_WITH_LOC(file, func, line)                                 \
do {                                                                    \
        libcfs_catastrophe = 1;                                         \
        lbug_with_loc(file, func, line);                                \
} while (0)

#define NULL ((void *)0)

#define LUSTRE_SRV_LNET_PID      LUSTRE_LNET_PID

#ifdef __KERNEL__

#include <libcfs/list.h>

struct libcfs_ioctl_data;                       /* forward ref */

struct libcfs_ioctl_handler {
        struct list_head item;
        int (*handle_ioctl)(unsigned int cmd, struct libcfs_ioctl_data *data);
};

#define DECLARE_IOCTL_HANDLER(ident, func)                      \
        struct libcfs_ioctl_handler ident = {                   \
                /* .item = */ CFS_LIST_HEAD_INIT(ident.item),   \
                /* .handle_ioctl = */ func                      \
        }

int libcfs_register_ioctl(struct libcfs_ioctl_handler *hand);
int libcfs_deregister_ioctl(struct libcfs_ioctl_handler *hand);

/* libcfs tcpip */
#define LNET_ACCEPTOR_MIN_RESERVED_PORT    512
#define LNET_ACCEPTOR_MAX_RESERVED_PORT    1023

int libcfs_ipif_query(char *name, int *up, __u32 *ip, __u32 *mask);
int libcfs_ipif_enumerate(char ***names);
void libcfs_ipif_free_enumeration(char **names, int n);
int libcfs_sock_listen(cfs_socket_t **sockp, __u32 ip, int port, int backlog);
int libcfs_sock_accept(cfs_socket_t **newsockp, cfs_socket_t *sock);
void libcfs_sock_abort_accept(cfs_socket_t *sock);
int libcfs_sock_connect(cfs_socket_t **sockp, int *fatal,
                        __u32 local_ip, int local_port,
                        __u32 peer_ip, int peer_port);
int libcfs_sock_setbuf(cfs_socket_t *socket, int txbufsize, int rxbufsize);
int libcfs_sock_getbuf(cfs_socket_t *socket, int *txbufsize, int *rxbufsize);
int libcfs_sock_getaddr(cfs_socket_t *socket, int remote, __u32 *ip, int *port);
int libcfs_sock_write(cfs_socket_t *sock, void *buffer, int nob, int timeout);
int libcfs_sock_read(cfs_socket_t *sock, void *buffer, int nob, int timeout);
void libcfs_sock_release(cfs_socket_t *sock);

/* libcfs watchdogs */
struct lc_watchdog;

/* Just use the default handler (dumplog)  */
#define LC_WATCHDOG_DEFAULT_CB NULL

/* Add a watchdog which fires after "time" milliseconds of delay.  You have to
 * touch it once to enable it. */
struct lc_watchdog *lc_watchdog_add(int time,
                                    void (*cb)(struct lc_watchdog *,
                                               cfs_task_t *,
                                               void *),
                                    void *data);

/* Enables a watchdog and resets its timer. */
void lc_watchdog_touch(struct lc_watchdog *lcw);

/* Disable a watchdog; touch it to restart it. */
void lc_watchdog_disable(struct lc_watchdog *lcw);

/* Clean up the watchdog */
void lc_watchdog_delete(struct lc_watchdog *lcw);

/* Dump a debug log */
void lc_watchdog_dumplog(struct lc_watchdog *lcw,
                         cfs_task_t *tsk,
                         void *data);

/* __KERNEL__ */
#endif

/*
 * libcfs pseudo device operations
 *
 * struct cfs_psdev_t and
 * cfs_psdev_register() and
 * cfs_psdev_deregister() are declared in
 * libcfs/<os>/cfs_prim.h
 *
 * It's just draft now.
 */

struct cfs_psdev_file {
        unsigned long   off;
        void            *private_data;
        unsigned long   reserved1;
        unsigned long   reserved2;
};

struct cfs_psdev_ops {
        int (*p_open)(unsigned long, void *);
        int (*p_close)(unsigned long, void *);
        int (*p_read)(struct cfs_psdev_file *, char *, unsigned long);
        int (*p_write)(struct cfs_psdev_file *, char *, unsigned long);
        int (*p_ioctl)(struct cfs_psdev_file *, unsigned long, void *);
};

/*
 * generic time manipulation functions.
 */

static inline int cfs_time_after(cfs_time_t t1, cfs_time_t t2)
{
        return cfs_time_before(t2, t1);
}

static inline int cfs_time_aftereq(cfs_time_t t1, cfs_time_t t2)
{
        return cfs_time_beforeq(t2, t1);
}

/*
 * return seconds since UNIX epoch
 */
static inline time_t cfs_unix_seconds(void)
{
        cfs_fs_time_t t;

        cfs_fs_time_current(&t);
        return (time_t)cfs_fs_time_sec(&t);
}

static inline cfs_time_t cfs_time_shift(int seconds)
{
        return cfs_time_add(cfs_time_current(), cfs_time_seconds(seconds));
}

static inline long cfs_timeval_sub(struct timeval *large, struct timeval *small,
                                   struct timeval *result)
{
        long r = (long) (
                (large->tv_sec - small->tv_sec) * ONE_MILLION +
                (large->tv_usec - small->tv_usec));
        if (result != NULL) {
                result->tv_usec = do_div(r, ONE_MILLION);
                result->tv_sec = r;
        }
        return r;
}

#define CFS_RATELIMIT(seconds)                                  \
({                                                              \
        /*                                                      \
         * XXX nikita: non-portable initializer                 \
         */                                                     \
        static time_t __next_message = 0;                       \
        int result;                                             \
                                                                \
        if (cfs_time_after(cfs_time_current(), __next_message)) \
                result = 1;                                     \
        else {                                                  \
                __next_message = cfs_time_shift(seconds);       \
                result = 0;                                     \
        }                                                       \
        result;                                                 \
})

extern void libcfs_debug_msg(int subsys, int mask, char *file, const char *fn,
                             const int line, unsigned long stack,
                             char *format, ...)
            __attribute__ ((format (printf, 7, 8)));

extern void libcfs_assertion_failed(char *expr, char *file, 
                                    const char *fn, const int line);

static inline void cfs_slow_warning(cfs_time_t now, int seconds, char *msg)
{
        if (cfs_time_after(cfs_time_current(),
                           cfs_time_add(now, cfs_time_seconds(15))))
                CERROR("slow %s %lu sec\n", msg,
                       cfs_duration_sec(cfs_time_sub(cfs_time_current(), now)));
}

/*
 * helper function similar to do_gettimeofday() of Linux kernel
 */
static inline void cfs_fs_timeval(struct timeval *tv)
{
	cfs_fs_time_t time;

	cfs_fs_time_current(&time);
	cfs_fs_time_usec(&time, tv);
}

/*
 * return valid time-out based on user supplied one. Currently we only check
 * that time-out is not shorted than allowed.
 */
static inline cfs_duration_t cfs_timeout_cap(cfs_duration_t timeout)
{
	if (timeout < CFS_TICK)
		timeout = CFS_TICK;
	return timeout;
}

/*
 * Universal memory allocator API 
 */
enum cfs_alloc_flags {
        /* allocation is not allowed to block */
        CFS_ALLOC_ATOMIC = (1 << 0),
        /* allocation is allowed to block */
        CFS_ALLOC_WAIT = (1 << 1),
        /* allocation should return zeroed memory */
        CFS_ALLOC_ZERO   = (1 << 2),
        /* allocation is allowed to call file-system code to free/clean
         * memory */
        CFS_ALLOC_FS     = (1 << 3),
        /* allocation is allowed to do io to free/clean memory */
        CFS_ALLOC_IO     = (1 << 4),
        /* standard allocator flag combination */
        CFS_ALLOC_STD    = CFS_ALLOC_FS | CFS_ALLOC_IO,
        CFS_ALLOC_USER   = CFS_ALLOC_WAIT | CFS_ALLOC_FS | CFS_ALLOC_IO,
};

/* flags for cfs_page_alloc() in addition to enum cfs_alloc_flags */
enum cfs_alloc_page_flags {
        /* allow to return page beyond KVM. It has to be mapped into KVM by
         * cfs_page_map(); */
        CFS_ALLOC_HIGH   = (1 << 5),
        CFS_ALLOC_HIGHUSER = CFS_ALLOC_WAIT | CFS_ALLOC_FS | CFS_ALLOC_IO | CFS_ALLOC_HIGH,
};

/*
 * portable UNIX device file identification. (This is not _very_
 * portable. Probably makes no sense for Windows.)
 */
/*
 * Platform defines
 *
 * cfs_rdev_t
 */

typedef unsigned int cfs_major_nr_t;
typedef unsigned int cfs_minor_nr_t;

/*
 * Defined by platform.
 */
cfs_rdev_t     cfs_rdev_build(cfs_major_nr_t major, cfs_minor_nr_t minor);
cfs_major_nr_t cfs_rdev_major(cfs_rdev_t rdev);
cfs_minor_nr_t cfs_rdev_minor(cfs_rdev_t rdev);

/*
 * Generic on-wire rdev format.
 */

typedef __u32 cfs_wire_rdev_t;

cfs_wire_rdev_t cfs_wire_rdev_build(cfs_major_nr_t major, cfs_minor_nr_t minor);
cfs_major_nr_t  cfs_wire_rdev_major(cfs_wire_rdev_t rdev);
cfs_minor_nr_t  cfs_wire_rdev_minor(cfs_wire_rdev_t rdev);

/*
 * Drop into debugger, if possible. Implementation is provided by platform.
 */

void cfs_enter_debugger(void);

/*
 * Defined by platform
 */
void cfs_daemonize(char *str);
cfs_sigset_t cfs_get_blocked_sigs(void);
cfs_sigset_t cfs_block_allsigs(void);
cfs_sigset_t cfs_block_sigs(cfs_sigset_t bits);
void cfs_restore_sigs(cfs_sigset_t);
int cfs_signal_pending(void);
void cfs_clear_sigpending(void);
/*
 * XXX Liang: 
 * these macros should be removed in the future, 
 * we keep them just for keeping libcfs compatible
 * with other branches.
 */
#define libcfs_daemonize(s)     cfs_daemonize(s)
#define cfs_sigmask_lock(f)     do { f= 0; } while (0)
#define cfs_sigmask_unlock(f)   do { f= 0; } while (0)

int convert_server_error(__u64 ecode);
int convert_client_oflag(int cflag, int *result);

/*
 * Stack-tracing filling.
 */

/*
 * Platform-dependent data-type to hold stack frames.
 */
struct cfs_stack_trace;

/*
 * Fill @trace with current back-trace.
 */
void cfs_stack_trace_fill(struct cfs_stack_trace *trace);

/*
 * Return instruction pointer for frame @frame_no. NULL if @frame_no is
 * invalid.
 */
void *cfs_stack_trace_frame(struct cfs_stack_trace *trace, int frame_no);

/*
 * Universal open flags.
 */
#define CFS_O_ACCMODE           0003
#define CFS_O_CREAT             0100
#define CFS_O_EXCL              0200
#define CFS_O_NOCTTY            0400
#define CFS_O_TRUNC             01000
#define CFS_O_APPEND            02000
#define CFS_O_NONBLOCK          04000
#define CFS_O_NDELAY            CFS_O_NONBLOCK
#define CFS_O_SYNC              010000
#define CFS_O_ASYNC             020000
#define CFS_O_DIRECT            040000
#define CFS_O_LARGEFILE         0100000
#define CFS_O_DIRECTORY         0200000
#define CFS_O_NOFOLLOW          0400000
#define CFS_O_NOATIME           01000000

/* convert local open flags to universal open flags */
int cfs_oflags2univ(int flags);
/* convert universal open flags to local open flags */
int cfs_univ2oflags(int flags);

#define _LIBCFS_H

#endif /* _LIBCFS_H */
