/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __LIBCFS_KP30_H__
#define __LIBCFS_KP30_H__

#define PORTAL_DEBUG
#include <libcfs/libcfs.h>

#if defined(__linux__)
#include <libcfs/linux/kp30.h>
#elif defined(__APPLE__)
#include <libcfs/darwin/kp30.h>
#else
#error Unsupported operating system
#endif

#include <portals/types.h>

#ifdef __KERNEL__

# ifndef DEBUG_SUBSYSTEM
#  define DEBUG_SUBSYSTEM S_UNDEFINED
# endif

#ifdef PORTAL_DEBUG
extern void kportal_assertion_failed(char *expr, char *file, const char *func,
                                     const int line);
#define LASSERT(e) ((e) ? 0 : kportal_assertion_failed( #e , __FILE__,  \
                                                        __FUNCTION__, __LINE__))
#define LASSERTF(cond, fmt...)                                                \
        do {                                                                  \
                if (unlikely(!(cond))) {                                      \
                        portals_debug_msg(DEBUG_SUBSYSTEM, D_EMERG,  __FILE__,\
                                          __FUNCTION__,__LINE__, CDEBUG_STACK,\
                                          "ASSERTION(" #cond ") failed:" fmt);\
                        LBUG();                                               \
                }                                                             \
        } while (0)

#else
#define LASSERT(e)
#define LASSERTF(cond, fmt...) do { } while (0)
#endif

/* LBUG_WITH_LOC defined in portals/<os>/kp30.h */
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

#define PORTAL_ALLOC_GFP(ptr, size, mask)                                 \
do {                                                                      \
        LASSERT(!in_interrupt() ||                                        \
               (size <= PORTAL_VMALLOC_SIZE && mask == CFS_ALLOC_ATOMIC));\
        if ((size) > PORTAL_VMALLOC_SIZE)                                 \
                (ptr) = cfs_alloc_large(size);                            \
        else                                                              \
                (ptr) = cfs_alloc((size), (mask));                        \
        if ((ptr) == NULL) {                                              \
                CERROR("PORTALS: out of memory at %s:%d (tried to alloc '"\
                       #ptr "' = %d)\n", __FILE__, __LINE__, (int)(size));\
                CERROR("PORTALS: %d total bytes allocated by portals\n",  \
                       atomic_read(&portal_kmemory));                     \
        } else {                                                          \
                portal_kmem_inc((ptr), (size));                           \
                if (!((mask) & CFS_ALLOC_ZERO))                           \
                       memset((ptr), 0, (size));                          \
        }                                                                 \
        CDEBUG(D_MALLOC, "kmalloced '" #ptr "': %d at %p (tot %d).\n",    \
               (int)(size), (ptr), atomic_read (&portal_kmemory));        \
} while (0)

#define PORTAL_ALLOC(ptr, size) \
        PORTAL_ALLOC_GFP(ptr, size, CFS_ALLOC_IO)

#define PORTAL_ALLOC_ATOMIC(ptr, size) \
        PORTAL_ALLOC_GFP(ptr, size, CFS_ALLOC_ATOMIC)

#define PORTAL_FREE(ptr, size)                                          \
do {                                                                    \
        int s = (size);                                                 \
        if ((ptr) == NULL) {                                            \
                CERROR("PORTALS: free NULL '" #ptr "' (%d bytes) at "   \
                       "%s:%d\n", s, __FILE__, __LINE__);               \
                break;                                                  \
        }                                                               \
        if (s > PORTAL_VMALLOC_SIZE)                                    \
                cfs_free_large(ptr);                                    \
        else                                                            \
                cfs_free(ptr);                                          \
        portal_kmem_dec((ptr), s);                                      \
        CDEBUG(D_MALLOC, "kfreed '" #ptr "': %d at %p (tot %d).\n",     \
               s, (ptr), atomic_read(&portal_kmemory));                 \
} while (0)

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
extern spinlock_t stack_backtrace_lock;

void portals_debug_dumpstack(cfs_task_t *tsk);
void portals_run_upcall(char **argv);
void portals_run_lbug_upcall(char * file, const char *fn, const int line);
void portals_debug_dumplog(void);
int portals_debug_init(unsigned long bufsize);
int portals_debug_cleanup(void);
int portals_debug_clear_buffer(void);
int portals_debug_mark_buffer(char *text);
int portals_debug_set_daemon(unsigned int cmd, unsigned int length,
                             char *file, unsigned int size);
__s32 portals_debug_copy_to_user(char *buf, unsigned long len);
/* Use the special GNU C __attribute__ hack to have the compiler check the
 * printf style argument string against the actual argument count and
 * types.
 */
void portals_debug_msg(int subsys, int mask, char *file, const char *fn,
                       const int line, unsigned long stack,
                       char *format, ...)
        __attribute__ ((format (printf, 7, 8)));
void portals_debug_set_level(unsigned int debug_level);

extern void kportal_daemonize (char *name);
extern void kportal_blockallsigs (void);

#else  /* !__KERNEL__ */
# ifndef DEBUG_SUBSYSTEM
#  define DEBUG_SUBSYSTEM S_UNDEFINED
# endif
# ifdef PORTAL_DEBUG
#  undef NDEBUG
#  include <assert.h>
#  define LASSERT(e)     assert(e)
#  define LASSERTF(cond, args...)                                              \
do {                                                                           \
          if (!(cond))                                                         \
                CERROR(args);                                                  \
          assert(cond);                                                        \
} while (0)
# else
#  define LASSERT(e)
#  define LASSERTF(cond, args...) do { } while (0)
# endif
# define printk(format, args...) printf (format, ## args)
# define PORTAL_ALLOC(ptr, size) do { (ptr) = malloc(size); } while (0);
# define PORTAL_FREE(a, b) do { free(a); } while (0);
void portals_debug_dumplog(void);
# define portals_debug_msg(subsys, mask, file, fn, line, stack, format, a...) \
    printf("%02x:%06x (@%lu %s:%s,l. %d %d %lu): " format,                    \
           (subsys), (mask), (long)time(0), file, fn, line,                   \
           getpid(), (unsigned long)stack, ## a);

#undef CWARN
#undef CERROR
#define CWARN(format, a...) CDEBUG(D_WARNING, format, ## a)
#define CERROR(format, a...) CDEBUG(D_ERROR, format, ## a)
#endif

/*
 * compile-time assertions. @cond has to be constant expression.
 * ISO C Standard:
 *
 *        6.8.4.2  The switch statement
 *
 *       ....
 *
 *       [#3] The expression of each case label shall be  an  integer
 *       constant   expression  and  no  two  of  the  case  constant
 *       expressions in the same switch statement shall have the same
 *       value  after  conversion...
 *
 */
#define CLASSERT(cond) ({ switch(42) { case (cond): case 0: break; } })

/* support decl needed both by kernel and liblustre */
char *portals_nid2str(int nal, ptl_nid_t nid, char *str);
char *portals_id2str(int nal, ptl_process_id_t nid, char *str);

#ifndef CURRENT_TIME
# define CURRENT_TIME time(0)
#endif

/* --------------------------------------------------------------------
 * Light-weight trace
 * Support for temporary event tracing with minimal Heisenberg effect.
 * All stuff about lwt are put in arch/kp30.h
 * -------------------------------------------------------------------- */

struct portals_device_userstate
{
        int          pdu_memhog_pages;
        cfs_page_t   *pdu_memhog_root_page;
};

#include <libcfs/portals_lib.h>

/*
 * USER LEVEL STUFF BELOW
 */

#define PORTAL_IOCTL_VERSION 0x00010008
#define PING_SYNC       0
#define PING_ASYNC      1

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

extern int portal_ioctl_getdata(char *buf, char *end, void *arg);

#endif

/* ioctls for manipulating snapshots 30- */
#define IOC_PORTAL_TYPE                   'e'
#define IOC_PORTAL_MIN_NR                 30

#define IOC_PORTAL_PING                    _IOWR('e', 30, IOCTL_PORTAL_TYPE)

#define IOC_PORTAL_CLEAR_DEBUG             _IOWR('e', 32, IOCTL_PORTAL_TYPE)
#define IOC_PORTAL_MARK_DEBUG              _IOWR('e', 33, IOCTL_PORTAL_TYPE)
#define IOC_PORTAL_PANIC                   _IOWR('e', 34, IOCTL_PORTAL_TYPE)
#define IOC_PORTAL_NAL_CMD                 _IOWR('e', 35, IOCTL_PORTAL_TYPE)
#define IOC_PORTAL_GET_NID                 _IOWR('e', 36, IOCTL_PORTAL_TYPE)
#define IOC_PORTAL_FAIL_NID                _IOWR('e', 37, IOCTL_PORTAL_TYPE)
#define IOC_PORTAL_LOOPBACK                _IOWR('e', 38, IOCTL_PORTAL_TYPE)
#define IOC_PORTAL_LWT_CONTROL             _IOWR('e', 39, IOCTL_PORTAL_TYPE)
#define IOC_PORTAL_LWT_SNAPSHOT            _IOWR('e', 40, IOCTL_PORTAL_TYPE)
#define IOC_PORTAL_LWT_LOOKUP_STRING       _IOWR('e', 41, IOCTL_PORTAL_TYPE)
#define IOC_PORTAL_MEMHOG                  _IOWR('e', 42, IOCTL_PORTAL_TYPE)
#define IOC_PORTAL_DMSG                    _IOWR('e', 43, IOCTL_PORTAL_TYPE)
#define IOC_PORTAL_MAX_NR                             43

enum {
        QSWNAL    = 1,
        SOCKNAL   = 2,
        GMNAL     = 3,
        /*          4 unused */
        TCPNAL    = 5,
        ROUTER    = 6,
        OPENIBNAL = 7,
        IIBNAL    = 8,
        LONAL     = 9,
        RANAL     = 10,
        VIBNAL    = 11,
        NAL_ENUM_END_MARKER
};

#define PTL_NALFMT_SIZE             32 /* %u:%u.%u.%u.%u,%u (10+4+4+4+3+5+1) */
#ifndef CRAY_PORTALS
#define NALID_FROM_IFACE(nal) (nal)
#endif

#define NAL_MAX_NR (NAL_ENUM_END_MARKER - 1)

#define NAL_CMD_REGISTER_PEER_FD     100
#define NAL_CMD_CLOSE_CONNECTION     101
#define NAL_CMD_REGISTER_MYNID       102
#define NAL_CMD_PUSH_CONNECTION      103
#define NAL_CMD_GET_CONN             104
#define NAL_CMD_DEL_PEER             105
#define NAL_CMD_ADD_PEER             106
#define NAL_CMD_GET_PEER             107
#define NAL_CMD_GET_TXDESC           108
#define NAL_CMD_ADD_ROUTE            109
#define NAL_CMD_DEL_ROUTE            110
#define NAL_CMD_GET_ROUTE            111
#define NAL_CMD_NOTIFY_ROUTER        112
#define NAL_CMD_ADD_INTERFACE        113
#define NAL_CMD_DEL_INTERFACE        114
#define NAL_CMD_GET_INTERFACE        115


enum {
        DEBUG_DAEMON_START       =  1,
        DEBUG_DAEMON_STOP        =  2,
        DEBUG_DAEMON_PAUSE       =  3,
        DEBUG_DAEMON_CONTINUE    =  4,
};


enum cfg_record_type {
        PORTALS_CFG_TYPE = 1,
        LUSTRE_CFG_TYPE = 123,
};

typedef int (*cfg_record_cb_t)(enum cfg_record_type, int len, void *data);

/* lustre_id output helper macros */
#define DLID4   "%lu/%lu/%lu/%lu"

#define OLID4(id)                              \
    (unsigned long)(id)->li_fid.lf_id,         \
    (unsigned long)(id)->li_fid.lf_group,      \
    (unsigned long)(id)->li_stc.u.e3s.l3s_ino, \
    (unsigned long)(id)->li_stc.u.e3s.l3s_gen

#endif
