/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _KP30_INCLUDED
#define _KP30_INCLUDED


#define PORTAL_DEBUG

#ifndef offsetof
# define offsetof(typ,memb)	((int)((char *)&(((typ *)0)->memb)))
#endif

#define LOWEST_BIT_SET(x)	((x) & ~((x) - 1))

#ifndef CONFIG_SMP
# define smp_processor_id() 0
#endif

/*
 *  Debugging
 */
extern unsigned int portal_subsystem_debug;
extern unsigned int portal_stack;
extern unsigned int portal_debug;
extern unsigned int portal_printk;
/* Debugging subsystems  (8 bit ID)
 *
 * If you add debug subsystem #32, you need to send email to phil, because
 * you're going to break kernel subsystem debug filtering. */
#define S_UNDEFINED    (0 << 24)
#define S_MDC          (1 << 24)
#define S_MDS          (2 << 24)
#define S_OSC          (3 << 24)
#define S_OST          (4 << 24)
#define S_CLASS        (5 << 24)
#define S_OBDFS        (6 << 24) /* obsolete */
#define S_LLITE        (7 << 24)
#define S_RPC          (8 << 24)
#define S_EXT2OBD      (9 << 24) /* obsolete */
#define S_PORTALS     (10 << 24)
#define S_SOCKNAL     (11 << 24)
#define S_QSWNAL      (12 << 24)
#define S_PINGER      (13 << 24)
#define S_FILTER      (14 << 24)
#define S_TRACE       (15 << 24) /* obsolete */
#define S_ECHO        (16 << 24)
#define S_LDLM        (17 << 24)
#define S_LOV         (18 << 24)
#define S_GMNAL       (19 << 24)
#define S_PTLROUTER   (20 << 24)
#define S_COBD        (21 << 24)
#define S_PTLBD       (22 << 24)
#define S_LOG         (23 << 24)

/* If you change these values, please keep portals/linux/utils/debug.c
 * up to date! */

/* Debugging masks (24 bits, non-overlapping) */
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
#define D_WARNING   (1 << 10)
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

#ifndef __KERNEL__
#define THREAD_SIZE 8192
#endif
#ifdef  __ia64__
#define CDEBUG_STACK() ((unsigned long)__builtin_dwarf_cfa()&(THREAD_SIZE - 1))
#else
#define CDEBUG_STACK() (THREAD_SIZE -                                      \
                        ((unsigned long)__builtin_frame_address(0) &       \
                         (THREAD_SIZE - 1)))
#endif

#ifdef __KERNEL__
#define CHECK_STACK(stack)                                                    \
        do {                                                                  \
                if ((stack) > 3*THREAD_SIZE/4 && (stack) > portal_stack) {    \
                        portals_debug_msg(DEBUG_SUBSYSTEM, D_ERROR,           \
                                          __FILE__, __FUNCTION__, __LINE__,   \
                                          (stack),                            \
                                          "maximum lustre stack %u\n",        \
                                          portal_stack = (stack));            \
                      /*panic("LBUG");*/                                      \
                }                                                             \
        } while (0)
#else
#define CHECK_STACK(stack) do { } while(0)
#endif

#if 1
#define CDEBUG(mask, format, a...)                                            \
do {                                                                          \
        CHECK_STACK(CDEBUG_STACK());                                          \
        if (!(mask) || ((mask) & (D_ERROR | D_EMERG)) ||                      \
            (portal_debug & (mask) &&                                         \
             portal_subsystem_debug & (1 << (DEBUG_SUBSYSTEM >> 24))))        \
                portals_debug_msg(DEBUG_SUBSYSTEM, mask,                      \
                                  __FILE__, __FUNCTION__, __LINE__,           \
                                  CDEBUG_STACK(), format , ## a);             \
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


#ifdef __KERNEL__
# include <linux/vmalloc.h>
# include <linux/time.h>
# include <linux/slab.h>
# include <linux/interrupt.h>
# include <linux/highmem.h>
# include <linux/module.h>
# include <linux/version.h>
# include <portals/lib-nal.h>
# include <linux/smp_lock.h>
# include <asm/atomic.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#define schedule_work schedule_task
#define prepare_work(wq,cb,cbdata)                                            \
do {                                                                          \
        INIT_TQUEUE((wq), 0, 0);                                              \
        PREPARE_TQUEUE((wq), (cb), (cbdata));                                 \
} while (0)

#define ll_invalidate_inode_pages invalidate_inode_pages
#define PageUptodate Page_Uptodate
#define our_recalc_sigpending(current) recalc_sigpending(current)
#define num_online_cpus() smp_num_cpus
static inline void our_cond_resched(void)
{
        if (current->need_resched)
               schedule ();
}

#else

#define prepare_work(wq,cb,cbdata)                                            \
do {                                                                          \
        INIT_WORK((wq), (void *)(cb), (void *)(cbdata));                      \
} while (0)
#define ll_invalidate_inode_pages(inode) invalidate_inode_pages((inode)->i_mapping)
#define wait_on_page wait_on_page_locked
#define our_recalc_sigpending(current) recalc_sigpending()
#define strtok(a,b) strpbrk(a, b)
static inline void our_cond_resched(void)
{
        cond_resched();
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0) */

#ifdef PORTAL_DEBUG
extern void kportal_assertion_failed(char *expr,char *file,char *func,int line);
#define LASSERT(e) ((e) ? 0 : kportal_assertion_failed( #e , __FILE__,  \
                                                        __FUNCTION__, __LINE__))
#else
#define LASSERT(e)
#endif

#ifdef __arch_um__
#define LBUG_WITH_LOC(file, func, line)                                 \
do {                                                                    \
        CEMERG("LBUG - trying to dump log to /tmp/lustre-log\n");       \
        portals_debug_dumplog();                                        \
        portals_run_lbug_upcall(file, func, line);                      \
        panic("LBUG");                                                  \
} while (0)
#else
#define LBUG_WITH_LOC(file, func, line)                                 \
do {                                                                    \
        CEMERG("LBUG\n");                                               \
        portals_debug_dumplog();                                        \
        portals_run_lbug_upcall(file, func, line);                      \
        set_task_state(current, TASK_UNINTERRUPTIBLE);                  \
        schedule();                                                     \
} while (0)
#endif /* __arch_um__ */

#define LBUG() LBUG_WITH_LOC(__FILE__, __FUNCTION__, __LINE__)

/*
 * Memory
 */
#ifdef PORTAL_DEBUG
extern atomic_t portal_kmemory;

# define portal_kmem_inc(ptr, size)                                           \
do {                                                                          \
        atomic_add(size, &portal_kmemory);                                    \
} while (0)

# define portal_kmem_dec(ptr, size) do {                                      \
        atomic_sub(size, &portal_kmemory);                                    \
} while (0)

#else
# define portal_kmem_inc(ptr, size) do {} while (0)
# define portal_kmem_dec(ptr, size) do {} while (0)
#endif /* PORTAL_DEBUG */

#define PORTAL_VMALLOC_SIZE        16384

#define PORTAL_ALLOC(ptr, size)                                           \
do {                                                                      \
        long s = size;                                                    \
        LASSERT (!in_interrupt());                                        \
        if (s > PORTAL_VMALLOC_SIZE)                                      \
                (ptr) = vmalloc(s);                                       \
        else                                                              \
                (ptr) = kmalloc(s, GFP_KERNEL);                           \
        if ((ptr) == NULL)                                                \
                CERROR("PORTALS: out of memory at %s:%d (tried to alloc"  \
                       " '" #ptr "' = %ld)\n", __FILE__, __LINE__, s);    \
        else {                                                            \
                portal_kmem_inc((ptr), s);                                \
                memset((ptr), 0, s);                                      \
        }                                                                 \
        CDEBUG(D_MALLOC, "kmalloced '" #ptr "': %ld at %p (tot %d).\n",   \
               s, (ptr), atomic_read (&portal_kmemory));                  \
} while (0)

#define PORTAL_FREE(ptr, size)                                          \
do {                                                                    \
        long s = (size);                                                \
        if ((ptr) == NULL) {                                            \
                CERROR("PORTALS: free NULL '" #ptr "' (%ld bytes) at "  \
                       "%s:%d\n", s, __FILE__, __LINE__);               \
                break;                                                  \
        }                                                               \
        if (s > PORTAL_VMALLOC_SIZE)                                    \
                vfree(ptr);                                             \
        else                                                            \
                kfree(ptr);                                             \
        portal_kmem_dec((ptr), s);                                      \
        CDEBUG(D_MALLOC, "kfreed '" #ptr "': %ld at %p (tot %d).\n",    \
               s, (ptr), atomic_read (&portal_kmemory));                \
} while (0)

#define PORTAL_SLAB_ALLOC(ptr, slab, size)                                \
do {                                                                      \
        long s = (size);                                                  \
        LASSERT (!in_interrupt());                                        \
        (ptr) = kmem_cache_alloc((slab), SLAB_KERNEL);                    \
        if ((ptr) == NULL) {                                              \
                CERROR("PORTALS: out of memory at %s:%d (tried to alloc"  \
                       " '" #ptr "' from slab '" #slab "')\n", __FILE__,  \
                       __LINE__);                                         \
        } else {                                                          \
                portal_kmem_inc((ptr), s);                                \
                memset((ptr), 0, s);                                      \
        }                                                                 \
        CDEBUG(D_MALLOC, "kmalloced '" #ptr "': %ld at %p (tot %d).\n",   \
               s, (ptr), atomic_read (&portal_kmemory));                  \
} while (0)

#define PORTAL_SLAB_FREE(ptr, slab, size)                               \
do {                                                                    \
        long s = (size);                                                \
        if ((ptr) == NULL) {                                            \
                CERROR("PORTALS: free NULL '" #ptr "' (%ld bytes) at "  \
                       "%s:%d\n", s, __FILE__, __LINE__);               \
                break;                                                  \
        }                                                               \
        memset((ptr), 0x5a, s);                                         \
        kmem_cache_free((slab), ptr);                                   \
        portal_kmem_dec((ptr), s);                                      \
        CDEBUG(D_MALLOC, "kfreed '" #ptr "': %ld at %p (tot %d).\n",    \
               s, (ptr), atomic_read (&portal_kmemory));                \
} while (0)

/* ------------------------------------------------------------------- */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))

#define PORTAL_SYMBOL_REGISTER(x) inter_module_register(#x, THIS_MODULE, &x)
#define PORTAL_SYMBOL_UNREGISTER(x) inter_module_unregister(#x)

#define PORTAL_SYMBOL_GET(x) ((typeof(&x))inter_module_get(#x))
#define PORTAL_SYMBOL_PUT(x) inter_module_put(#x)

#define PORTAL_MODULE_USE       MOD_INC_USE_COUNT
#define PORTAL_MODULE_UNUSE     MOD_DEC_USE_COUNT
#else

#define PORTAL_SYMBOL_REGISTER(x)
#define PORTAL_SYMBOL_UNREGISTER(x)

#define PORTAL_SYMBOL_GET(x) symbol_get(x)
#define PORTAL_SYMBOL_PUT(x) symbol_put(x)

#define PORTAL_MODULE_USE       try_module_get(THIS_MODULE)
#define PORTAL_MODULE_UNUSE     module_put(THIS_MODULE)

#endif

/******************************************************************************/
/* Kernel Portals Router interface */

typedef void (*kpr_fwd_callback_t)(void *arg, int error); // completion callback

/* space for routing targets to stash "stuff" in a forwarded packet */
typedef union {
        long long        _alignment;
        void            *_space[16];            /* scale with CPU arch */
} kprfd_scratch_t;

/* Kernel Portals Routing Forwarded message Descriptor */
typedef struct {
        struct list_head     kprfd_list;        /* stash in queues (routing target can use) */
        ptl_nid_t            kprfd_target_nid;  /* final destination NID */
        ptl_nid_t            kprfd_gateway_nid; /* gateway NID */
        int                  kprfd_nob;         /* # message bytes (including header) */
        int                  kprfd_niov;        /* # message frags (including header) */
        struct iovec        *kprfd_iov;         /* message fragments */
        void                *kprfd_router_arg;  // originating NAL's router arg
        kpr_fwd_callback_t   kprfd_callback;    /* completion callback */
        void                *kprfd_callback_arg; /* completion callback arg */
        kprfd_scratch_t      kprfd_scratch;    // scratchpad for routing targets
} kpr_fwd_desc_t;

typedef void  (*kpr_fwd_t)(void *arg, kpr_fwd_desc_t *fwd);

/* NAL's routing interface (Kernel Portals Routing Nal Interface) */
typedef const struct {
        int             kprni_nalid;    /* NAL's id */
        void           *kprni_arg;      /* Arg to pass when calling into NAL */
        kpr_fwd_t       kprni_fwd;      /* NAL's forwarding entrypoint */
} kpr_nal_interface_t;

/* Router's routing interface (Kernel Portals Routing Router Interface) */
typedef const struct {
        /* register the calling NAL with the router and get back the handle for
         * subsequent calls */
        int     (*kprri_register) (kpr_nal_interface_t *nal_interface,
                                   void **router_arg);

        /* ask the router to find a gateway that forwards to 'nid' and is a peer
         * of the calling NAL */
        int     (*kprri_lookup) (void *router_arg, ptl_nid_t nid,
                                 ptl_nid_t *gateway_nid);

        /* hand a packet over to the router for forwarding */
        kpr_fwd_t kprri_fwd_start;

        /* hand a packet back to the router for completion */
        void    (*kprri_fwd_done) (void *router_arg, kpr_fwd_desc_t *fwd,
                                   int error);

        /* the calling NAL is shutting down */
        void    (*kprri_shutdown) (void *router_arg);

        /* deregister the calling NAL with the router */
        void    (*kprri_deregister) (void *router_arg);

} kpr_router_interface_t;

/* Convenient struct for NAL to stash router interface/args */
typedef struct {
        kpr_router_interface_t  *kpr_interface;
        void                    *kpr_arg;
} kpr_router_t;

/* Router's control interface (Kernel Portals Routing Control Interface) */
typedef const struct {
        int     (*kprci_add_route)(int gateway_nal, ptl_nid_t gateway_nid,
                                   ptl_nid_t lo_nid, ptl_nid_t hi_nid);
        int     (*kprci_del_route)(ptl_nid_t nid);
        int     (*kprci_get_route)(int index, int *gateway_nal,
                                   ptl_nid_t *gateway, ptl_nid_t *lo_nid,
                                   ptl_nid_t *hi_nid);
} kpr_control_interface_t;

extern kpr_control_interface_t  kpr_control_interface;
extern kpr_router_interface_t   kpr_router_interface;

static inline int
kpr_register (kpr_router_t *router, kpr_nal_interface_t *nalif)
{
        int    rc;

        router->kpr_interface = PORTAL_SYMBOL_GET (kpr_router_interface);
        if (router->kpr_interface == NULL)
                return (-ENOENT);

        rc = (router->kpr_interface)->kprri_register (nalif, &router->kpr_arg);
        if (rc != 0)
                router->kpr_interface = NULL;

        PORTAL_SYMBOL_PUT (kpr_router_interface);
        return (rc);
}

static inline int
kpr_routing (kpr_router_t *router)
{
        return (router->kpr_interface != NULL);
}

static inline int
kpr_lookup (kpr_router_t *router, ptl_nid_t nid, ptl_nid_t *gateway_nid)
{
        if (!kpr_routing (router))
                return (-EHOSTUNREACH);

        return (router->kpr_interface->kprri_lookup(router->kpr_arg, nid,
                                                    gateway_nid));
}

static inline void
kpr_fwd_init (kpr_fwd_desc_t *fwd, ptl_nid_t nid, 
              int nob, int niov, struct iovec *iov, 
              kpr_fwd_callback_t callback, void *callback_arg)
{
        fwd->kprfd_target_nid   = nid;
        fwd->kprfd_gateway_nid  = nid;
        fwd->kprfd_nob          = nob;
        fwd->kprfd_niov         = niov;
        fwd->kprfd_iov          = iov;
        fwd->kprfd_callback     = callback;
        fwd->kprfd_callback_arg = callback_arg;
}

static inline void
kpr_fwd_start (kpr_router_t *router, kpr_fwd_desc_t *fwd)
{
        if (!kpr_routing (router))
                fwd->kprfd_callback (fwd->kprfd_callback_arg, -EHOSTUNREACH);
        else
                router->kpr_interface->kprri_fwd_start (router->kpr_arg, fwd);
}

static inline void
kpr_fwd_done (kpr_router_t *router, kpr_fwd_desc_t *fwd, int error)
{
        LASSERT (kpr_routing (router));
        router->kpr_interface->kprri_fwd_done (router->kpr_arg, fwd, error);
}

static inline void
kpr_shutdown (kpr_router_t *router)
{
        if (kpr_routing (router))
                router->kpr_interface->kprri_shutdown (router->kpr_arg);
}

static inline void
kpr_deregister (kpr_router_t *router)
{
        if (!kpr_routing (router))
                return;
        router->kpr_interface->kprri_deregister (router->kpr_arg);
        router->kpr_interface = NULL;
}

/******************************************************************************/

#ifdef PORTALS_PROFILING
#define prof_enum(FOO) PROF__##FOO
enum {
        prof_enum(our_recvmsg),
        prof_enum(our_sendmsg),
        prof_enum(socknal_recv),
        prof_enum(lib_parse),
        prof_enum(conn_list_walk),
        prof_enum(memcpy),
        prof_enum(lib_finalize),
        prof_enum(pingcli_time),
        prof_enum(gmnal_send),
        prof_enum(gmnal_recv),
        MAX_PROFS
};

struct prof_ent {
        char *str;
        /* hrmph.  wrap-tastic. */
        u32       starts;
        u32       finishes;
        cycles_t  total_cycles;
        cycles_t  start;
        cycles_t  end;
};

extern struct prof_ent prof_ents[MAX_PROFS];

#define PROF_START(FOO)                                         \
        do {                                                    \
                struct prof_ent *pe = &prof_ents[PROF__##FOO];  \
                pe->starts++;                                   \
                pe->start = get_cycles();                       \
        } while (0)

#define PROF_FINISH(FOO)                                        \
        do {                                                    \
                struct prof_ent *pe = &prof_ents[PROF__##FOO];  \
                pe->finishes++;                                 \
                pe->end = get_cycles();                         \
                pe->total_cycles += (pe->end - pe->start);      \
        } while (0)
#else /* !PORTALS_PROFILING */
#define PROF_START(FOO) do {} while(0)
#define PROF_FINISH(FOO) do {} while(0)
#endif /* PORTALS_PROFILING */

/* debug.c */
void portals_run_lbug_upcall(char * file, char *fn, int line);
void portals_debug_dumplog(void);
int portals_debug_init(unsigned long bufsize);
int portals_debug_cleanup(void);
int portals_debug_clear_buffer(void);
int portals_debug_mark_buffer(char *text);
int portals_debug_set_daemon(unsigned int cmd, unsigned int length,
                char *file, unsigned int size);
__s32 portals_debug_copy_to_user(char *buf, unsigned long len);
#if (__GNUC__)
/* Use the special GNU C __attribute__ hack to have the compiler check the
 * printf style argument string against the actual argument count and
 * types.
 */
#ifdef printf
# warning printf has been defined as a macro...
# undef printf
#endif
void portals_debug_msg (int subsys, int mask, char *file, char *fn, int line,
                        unsigned long stack, const char *format, ...)
        __attribute__ ((format (printf, 7, 8)));
#else
void portals_debug_msg (int subsys, int mask, char *file, char *fn,
                        int line, unsigned long stack,
                        const char *format, ...);
#endif /* __GNUC__ */
void portals_debug_set_level(unsigned int debug_level);

# define fprintf(a, format, b...) CDEBUG(D_OTHER, format , ## b)
# define printf(format, b...) CDEBUG(D_OTHER, format , ## b)
# define time(a) CURRENT_TIME

extern void kportal_daemonize (char *name);
extern void kportal_blockallsigs (void);

#else  /* !__KERNEL__ */
# include <stdio.h>
# include <stdlib.h>
#ifndef __CYGWIN__
# include <stdint.h>
#endif
# include <unistd.h>
# include <time.h>
# include <asm/types.h>
# ifndef DEBUG_SUBSYSTEM
#  define DEBUG_SUBSYSTEM S_UNDEFINED
# endif
# ifdef PORTAL_DEBUG
#  undef NDEBUG
#  include <assert.h>
#  define LASSERT(e)	assert(e)
# else
#  define LASSERT(e)
# endif
# define printk(format, args...) printf (format, ## args)
# define PORTAL_ALLOC(ptr, size) do { (ptr) = malloc(size); } while (0);
# define PORTAL_FREE(a, b) do { free(a); } while (0);
# define portals_debug_msg(subsys, mask, file, fn, line, stack, format, a...) \
    printf ("%02x:%06x (@%lu %s:%s,l. %d %d %lu): " format,                    \
            (subsys) >> 24, (mask), (long)time(0), file, fn, line,            \
            getpid() , stack, ## a);
#endif

#ifndef CURRENT_TIME
# define CURRENT_TIME time(0)
#endif

#include <linux/portals_lib.h>

/*
 * USER LEVEL STUFF BELOW
 */

#define PORTAL_IOCTL_VERSION 0x00010007
#define PING_SYNC       0
#define PING_ASYNC      1

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

struct portal_ioctl_hdr {
        __u32 ioc_len;
        __u32 ioc_version;
};

struct portals_debug_ioctl_data
{
        struct portal_ioctl_hdr hdr;
        unsigned int subs;
        unsigned int debug;
};

#define PORTAL_IOC_INIT(data)                           \
do {                                                    \
        memset(&data, 0, sizeof(data));                 \
        data.ioc_version = PORTAL_IOCTL_VERSION;        \
        data.ioc_len = sizeof(data);                    \
} while (0)

/* FIXME check conflict with lustre_lib.h */
#define PTL_IOC_DEBUG_MASK             _IOWR('f', 250, long)

static inline int portal_ioctl_packlen(struct portal_ioctl_data *data)
{
        int len = sizeof(*data);
        len += size_round(data->ioc_inllen1);
        len += size_round(data->ioc_inllen2);
        return len;
}

static inline int portal_ioctl_is_invalid(struct portal_ioctl_data *data)
{
        if (data->ioc_len > (1<<30)) {
                CERROR ("PORTALS ioctl: ioc_len larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inllen1 > (1<<30)) {
                CERROR ("PORTALS ioctl: ioc_inllen1 larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inllen2 > (1<<30)) {
                CERROR ("PORTALS ioctl: ioc_inllen2 larger than 1<<30\n");
                return 1;
        }
        if (data->ioc_inlbuf1 && !data->ioc_inllen1) {
                CERROR ("PORTALS ioctl: inlbuf1 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_inlbuf2 && !data->ioc_inllen2) {
                CERROR ("PORTALS ioctl: inlbuf2 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_pbuf1 && !data->ioc_plen1) {
                CERROR ("PORTALS ioctl: pbuf1 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_pbuf2 && !data->ioc_plen2) {
                CERROR ("PORTALS ioctl: pbuf2 pointer but 0 length\n");
                return 1;
        }
        if (data->ioc_plen1 && !data->ioc_pbuf1) {
                CERROR ("PORTALS ioctl: plen1 nonzero but no pbuf1 pointer\n");
                return 1;
        }
        if (data->ioc_plen2 && !data->ioc_pbuf2) {
                CERROR ("PORTALS ioctl: plen2 nonzero but no pbuf2 pointer\n");
                return 1;
        }
        if (portal_ioctl_packlen(data) != data->ioc_len ) {
                CERROR ("PORTALS ioctl: packlen != ioc_len\n");
                return 1;
        }
        if (data->ioc_inllen1 &&
            data->ioc_bulk[data->ioc_inllen1 - 1] != '\0') {
                CERROR ("PORTALS ioctl: inlbuf1 not 0 terminated\n");
                return 1;
        }
        if (data->ioc_inllen2 &&
            data->ioc_bulk[size_round(data->ioc_inllen1) +
                           data->ioc_inllen2 - 1] != '\0') {
                CERROR ("PORTALS ioctl: inlbuf2 not 0 terminated\n");
                return 1;
        }
        return 0;
}

#ifndef __KERNEL__
static inline int portal_ioctl_pack(struct portal_ioctl_data *data, char **pbuf,
                                    int max)
{
        char *ptr;
        struct portal_ioctl_data *overlay;
        data->ioc_len = portal_ioctl_packlen(data);
        data->ioc_version = PORTAL_IOCTL_VERSION;

        if (*pbuf && portal_ioctl_packlen(data) > max)
                return 1;
        if (*pbuf == NULL) {
                *pbuf = malloc(data->ioc_len);
        }
        if (!*pbuf)
                return 1;
        overlay = (struct portal_ioctl_data *)*pbuf;
        memcpy(*pbuf, data, sizeof(*data));

        ptr = overlay->ioc_bulk;
        if (data->ioc_inlbuf1)
                LOGL(data->ioc_inlbuf1, data->ioc_inllen1, ptr);
        if (data->ioc_inlbuf2)
                LOGL(data->ioc_inlbuf2, data->ioc_inllen2, ptr);
        if (portal_ioctl_is_invalid(overlay))
                return 1;

        return 0;
}
#else
#include <asm/uaccess.h>

/* buffer MUST be at least the size of portal_ioctl_hdr */
static inline int portal_ioctl_getdata(char *buf, char *end, void *arg)
{
        struct portal_ioctl_hdr *hdr;
        struct portal_ioctl_data *data;
        int err;
        ENTRY;

        hdr = (struct portal_ioctl_hdr *)buf;
        data = (struct portal_ioctl_data *)buf;

        err = copy_from_user(buf, (void *)arg, sizeof(*hdr));
        if ( err ) {
                EXIT;
                return err;
        }

        if (hdr->ioc_version != PORTAL_IOCTL_VERSION) {
                CERROR ("PORTALS: version mismatch kernel vs application\n");
                return -EINVAL;
        }

        if (hdr->ioc_len + buf >= end) {
                CERROR ("PORTALS: user buffer exceeds kernel buffer\n");
                return -EINVAL;
        }


        if (hdr->ioc_len < sizeof(struct portal_ioctl_data)) {
                CERROR ("PORTALS: user buffer too small for ioctl\n");
                return -EINVAL;
        }

        err = copy_from_user(buf, (void *)arg, hdr->ioc_len);
        if ( err ) {
                EXIT;
                return err;
        }

        if (portal_ioctl_is_invalid(data)) {
                CERROR ("PORTALS: ioctl not correctly formatted\n");
                return -EINVAL;
        }

        if (data->ioc_inllen1) {
                data->ioc_inlbuf1 = &data->ioc_bulk[0];
        }

        if (data->ioc_inllen2) {
                data->ioc_inlbuf2 = &data->ioc_bulk[0] +
                        size_round(data->ioc_inllen1);
        }

        EXIT;
        return 0;
}
#endif

/* ioctls for manipulating snapshots 30- */
#define IOC_PORTAL_TYPE                   'e'
#define IOC_PORTAL_MIN_NR                 30

#define IOC_PORTAL_PING                    _IOWR('e', 30, long)
#define IOC_PORTAL_GET_DEBUG               _IOWR('e', 31, long)
#define IOC_PORTAL_CLEAR_DEBUG             _IOWR('e', 32, long)
#define IOC_PORTAL_MARK_DEBUG              _IOWR('e', 33, long)
#define IOC_PORTAL_PANIC                   _IOWR('e', 34, long)
#define IOC_PORTAL_ADD_ROUTE               _IOWR('e', 35, long)
#define IOC_PORTAL_DEL_ROUTE               _IOWR('e', 36, long)
#define IOC_PORTAL_GET_ROUTE               _IOWR('e', 37, long)
#define IOC_PORTAL_NAL_CMD	           _IOWR('e', 38, long)
#define IOC_PORTAL_GET_NID                 _IOWR('e', 39, long)
#define IOC_PORTAL_FAIL_NID                _IOWR('e', 40, long)
#define IOC_PORTAL_SET_DAEMON              _IOWR('e', 41, long)

#define IOC_PORTAL_MAX_NR               41

enum {
        QSWNAL  =  1,
        SOCKNAL,
        GMNAL,
        TOENAL,
        TCPNAL,
        SCIMACNAL,
        NAL_ENUM_END_MARKER
};

#ifdef __KERNEL__
extern ptl_handle_ni_t  kqswnal_ni;
extern ptl_handle_ni_t  ksocknal_ni;
extern ptl_handle_ni_t  ktoenal_ni;
extern ptl_handle_ni_t  kgmnal_ni;
extern ptl_handle_ni_t  kscimacnal_ni;
#endif

#define NAL_MAX_NR (NAL_ENUM_END_MARKER - 1)

#define NAL_CMD_REGISTER_PEER_FD     100
#define NAL_CMD_CLOSE_CONNECTION     101
#define NAL_CMD_REGISTER_MYNID       102
#define NAL_CMD_PUSH_CONNECTION      103

enum {
        DEBUG_DAEMON_START       =  1,
        DEBUG_DAEMON_STOP        =  2,
        DEBUG_DAEMON_PAUSE       =  3,
        DEBUG_DAEMON_CONTINUE    =  4,
};

/* XXX remove to lustre ASAP */
struct lustre_peer {
        ptl_nid_t       peer_nid;
        ptl_handle_ni_t peer_ni;
};

/* module.c */
typedef int (*nal_cmd_handler_t)(struct portal_ioctl_data *, void * private);
int kportal_nal_register(int nal, nal_cmd_handler_t handler, void * private);
int kportal_nal_unregister(int nal);

ptl_handle_ni_t *kportal_get_ni (int nal);
void kportal_put_ni (int nal);

#ifdef __CYGWIN__
#ifndef BITS_PER_LONG
#if (~0UL) == 0xffffffffUL
#define BITS_PER_LONG 32
#else 
#define BITS_PER_LONG 64
#endif
#endif
#endif

#if (BITS_PER_LONG == 32 || __WORDSIZE == 32)
# define LPU64 "%Lu"
# define LPD64 "%Ld"
# define LPX64 "%#Lx"
# define LPSZ  "%u"
# define LPSSZ "%d"
#endif
#if (BITS_PER_LONG == 64 || __WORDSIZE == 64)
# define LPU64 "%lu"
# define LPD64 "%ld"
# define LPX64 "%#lx"
# define LPSZ  "%lu"
# define LPSSZ "%ld"
#endif
#ifndef LPU64
# error "No word size defined"
#endif

#endif
