/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/libcfs_private.h
 *
 * Various defines for libcfs.
 *
 */

#ifndef __LIBCFS_PRIVATE_H__
#define __LIBCFS_PRIVATE_H__

/* XXX this layering violation is for nidstrings */
#include <lnet/types.h>

#ifndef DEBUG_SUBSYSTEM
# define DEBUG_SUBSYSTEM S_UNDEFINED
#endif

#ifdef __KERNEL__

#ifdef LIBCFS_DEBUG

/*
 * When this is on, LASSERT macro includes check for assignment used instead
 * of equality check, but doesn't have unlikely(). Turn this on from time to
 * time to make test-builds. This shouldn't be on for production release.
 */
#define LASSERT_CHECKED (0)

#if LASSERT_CHECKED
/*
 * Assertion.
 *
 * Strange construction with empty "then" clause is used to trigger compiler
 * warnings on the assertions of the form LASSERT(a = b);
 *
 * "warning: suggest parentheses around assignment used as truth value"
 *
 * requires -Wall. Unfortunately this rules out use of likely/unlikely.
 */
#define LASSERT(cond)                                           \
({                                                              \
        if (cond)                                               \
                ;                                               \
        else                                                    \
                libcfs_assertion_failed( #cond , __FILE__,      \
                        __FUNCTION__, __LINE__);                \
})

#define LASSERTF(cond, fmt, a...)                                       \
({                                                                      \
         if (cond)                                                      \
                 ;                                                      \
         else {                                                         \
                 libcfs_debug_msg(NULL, DEBUG_SUBSYSTEM, D_EMERG,       \
                                  __FILE__, __FUNCTION__,__LINE__,      \
                                  "ASSERTION(" #cond ") failed:" fmt,   \
                                  ## a);                                \
                 LBUG();                                                \
         }                                                              \
})


#else /* !LASSERT_CHECKED */

#define LASSERT(cond)                                           \
({                                                              \
        if (unlikely(!(cond)))                                  \
                libcfs_assertion_failed(#cond , __FILE__,       \
                        __FUNCTION__, __LINE__);                \
})

#define LASSERTF(cond, fmt, a...)                                       \
({                                                                      \
        if (unlikely(!(cond))) {                                        \
                libcfs_debug_msg(NULL, DEBUG_SUBSYSTEM, D_EMERG,        \
                                 __FILE__, __FUNCTION__,__LINE__,       \
                                 "ASSERTION(" #cond ") failed:" fmt,    \
                                 ## a);                                 \
                LBUG();                                                 \
        }                                                               \
})


#endif /* !LASSERT_CHECKED */


#else /* !LIBCFS_DEBUG */
#define LASSERT(e) ((void)(0))
#define LASSERTF(cond, fmt...) ((void)(0))
#endif /* !LIBCFS_DEBUG */

#define KLASSERT(e) LASSERT(e)

void lbug_with_loc(char *file, const char *func, const int line)
        __attribute__((noreturn));

#define LBUG() lbug_with_loc(__FILE__, __FUNCTION__, __LINE__)

extern atomic_t libcfs_kmemory;
/*
 * Memory
 */
#ifdef LIBCFS_DEBUG

# define libcfs_kmem_inc(ptr, size)             \
do {                                            \
        atomic_add(size, &libcfs_kmemory);      \
} while (0)

# define libcfs_kmem_dec(ptr, size) do {        \
        atomic_sub(size, &libcfs_kmemory);      \
} while (0)

#else
# define libcfs_kmem_inc(ptr, size) do {} while (0)
# define libcfs_kmem_dec(ptr, size) do {} while (0)
#endif /* LIBCFS_DEBUG */

#define LIBCFS_VMALLOC_SIZE        16384

#define LIBCFS_ALLOC_GFP(ptr, size, mask)                                 \
do {                                                                      \
        LASSERT(!in_interrupt() ||                                        \
               (size <= LIBCFS_VMALLOC_SIZE && mask == CFS_ALLOC_ATOMIC));\
        if (unlikely((size) > LIBCFS_VMALLOC_SIZE))                     \
                (ptr) = cfs_alloc_large(size);                            \
        else                                                              \
                (ptr) = cfs_alloc((size), (mask));                        \
        if (unlikely((ptr) == NULL)) {                                  \
                CERROR("LNET: out of memory at %s:%d (tried to alloc '"   \
                       #ptr "' = %d)\n", __FILE__, __LINE__, (int)(size));\
                CERROR("LNET: %d total bytes allocated by lnet\n",        \
                       atomic_read(&libcfs_kmemory));                     \
        } else {                                                          \
                libcfs_kmem_inc((ptr), (size));                           \
                if (!((mask) & CFS_ALLOC_ZERO))                           \
                       memset((ptr), 0, (size));                          \
        }                                                                 \
        CDEBUG(D_MALLOC, "kmalloced '" #ptr "': %d at %p (tot %d).\n",    \
               (int)(size), (ptr), atomic_read (&libcfs_kmemory));        \
} while (0)

#define LIBCFS_ALLOC(ptr, size) \
        LIBCFS_ALLOC_GFP(ptr, size, CFS_ALLOC_IO)

#define LIBCFS_ALLOC_ATOMIC(ptr, size) \
        LIBCFS_ALLOC_GFP(ptr, size, CFS_ALLOC_ATOMIC)

#define LIBCFS_FREE(ptr, size)                                          \
do {                                                                    \
        int s = (size);                                                 \
        if (unlikely((ptr) == NULL)) {                                  \
                CERROR("LIBCFS: free NULL '" #ptr "' (%d bytes) at "    \
                       "%s:%d\n", s, __FILE__, __LINE__);               \
                break;                                                  \
        }                                                               \
        libcfs_kmem_dec((ptr), s);                                      \
        CDEBUG(D_MALLOC, "kfreed '" #ptr "': %d at %p (tot %d).\n",     \
               s, (ptr), atomic_read(&libcfs_kmemory));                 \
        if (unlikely(s > LIBCFS_VMALLOC_SIZE))                          \
                cfs_free_large(ptr);                                    \
        else                                                            \
                cfs_free(ptr);                                          \
} while (0)

/******************************************************************************/

/* htonl hack - either this, or compile with -O2. Stupid byteorder/generic.h */
#if defined(__GNUC__) && (__GNUC__ >= 2) && !defined(__OPTIMIZE__)
#define ___htonl(x) __cpu_to_be32(x)
#define ___htons(x) __cpu_to_be16(x)
#define ___ntohl(x) __be32_to_cpu(x)
#define ___ntohs(x) __be16_to_cpu(x)
#define htonl(x) ___htonl(x)
#define ntohl(x) ___ntohl(x)
#define htons(x) ___htons(x)
#define ntohs(x) ___ntohs(x)
#endif

void libcfs_debug_dumpstack(cfs_task_t *tsk);
void libcfs_run_upcall(char **argv);
void libcfs_run_lbug_upcall(char * file, const char *fn, const int line);
void libcfs_debug_dumplog(void);
int libcfs_debug_init(unsigned long bufsize);
int libcfs_debug_cleanup(void);
int libcfs_debug_clear_buffer(void);
int libcfs_debug_mark_buffer(char *text);

void libcfs_debug_set_level(unsigned int debug_level);

#else  /* !__KERNEL__ */
# ifdef LIBCFS_DEBUG
#  undef NDEBUG
#  include <assert.h>
#  define LASSERT(e)     assert(e)
#  define LASSERTF(cond, args...)                                              \
do {                                                                           \
          if (!(cond))                                                         \
                CERROR(args);                                                  \
          assert(cond);                                                        \
} while (0)
#  define LBUG()   assert(0)
# else
#  define LASSERT(e) ((void)(0))
#  define LASSERTF(cond, args...) do { } while (0)
#  define LBUG()   ((void)(0))
# endif /* LIBCFS_DEBUG */
# define KLASSERT(e) do { } while (0)
# define printk(format, args...) printf (format, ## args)
# ifdef CRAY_XT3                                /* buggy calloc! */
#  define LIBCFS_ALLOC(ptr, size)               \
   do {                                         \
        (ptr) = malloc(size);                   \
        memset(ptr, 0, size);                   \
   } while (0)
# else
#  define LIBCFS_ALLOC(ptr, size) do { (ptr) = calloc(1,size); } while (0)
# endif
# define LIBCFS_FREE(a, b) do { free(a); } while (0)

void libcfs_debug_dumplog(void);
int libcfs_debug_init(unsigned long bufsize);
int libcfs_debug_cleanup(void);

/*
 * Generic compiler-dependent macros required for kernel
 * build go below this comment. Actual compiler/compiler version
 * specific implementations come from the above header files
 */

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

/* !__KERNEL__ */
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
int         libcfs_isknown_lnd(int type);
char       *libcfs_lnd2modname(int type);
char       *libcfs_lnd2str(int type);
int         libcfs_str2lnd(const char *str);
char       *libcfs_net2str(__u32 net);
char       *libcfs_nid2str(lnet_nid_t nid);
__u32       libcfs_str2net(const char *str);
lnet_nid_t  libcfs_str2nid(const char *str);
int         libcfs_str2anynid(lnet_nid_t *nid, const char *str);
char       *libcfs_id2str(lnet_process_id_t id);

/* how an LNET NID encodes net:address */
#define LNET_NIDADDR(nid)      ((__u32)((nid) & 0xffffffff))
#define LNET_NIDNET(nid)       ((__u32)(((nid) >> 32)) & 0xffffffff)
#define LNET_MKNID(net,addr)   ((((__u64)(net))<<32)|((__u64)(addr)))
/* how net encodes type:number */
#define LNET_NETNUM(net)       ((net) & 0xffff)
#define LNET_NETTYP(net)       (((net) >> 16) & 0xffff)
#define LNET_MKNET(typ,num)    ((((__u32)(typ))<<16)|((__u32)(num)))

/* implication */
#define ergo(a, b) (!(a) || (b))
/* logical equivalence */
#define equi(a, b) (!!(a) == !!(b))

#ifndef CURRENT_TIME
# define CURRENT_TIME time(0)
#endif

/* --------------------------------------------------------------------
 * Light-weight trace
 * Support for temporary event tracing with minimal Heisenberg effect.
 * All stuff about lwt are put in arch/kp30.h
 * -------------------------------------------------------------------- */

struct libcfs_device_userstate
{
        int           ldu_memhog_pages;
        cfs_page_t   *ldu_memhog_root_page;
};

/* what used to be in portals_lib.h */
#ifndef MIN
# define MIN(a,b) (((a)<(b)) ? (a): (b))
#endif
#ifndef MAX
# define MAX(a,b) (((a)>(b)) ? (a): (b))
#endif

#define MKSTR(ptr) ((ptr))? (ptr) : ""

static inline int size_round4 (int val)
{
        return (val + 3) & (~0x3);
}

static inline int size_round (int val)
{
        return (val + 7) & (~0x7);
}

static inline int size_round16(int val)
{
        return (val + 0xf) & (~0xf);
}

static inline int size_round32(int val)
{
        return (val + 0x1f) & (~0x1f);
}

static inline int size_round0(int val)
{
        if (!val)
                return 0;
        return (val + 1 + 7) & (~0x7);
}

static inline size_t round_strlen(char *fset)
{
        return (size_t)size_round((int)strlen(fset) + 1);
}

#define LOGL(var,len,ptr)                                       \
do {                                                            \
        if (var)                                                \
                memcpy((char *)ptr, (const char *)var, len);    \
        ptr += size_round(len);                                 \
} while (0)

#define LOGU(var,len,ptr)                                       \
do {                                                            \
        if (var)                                                \
                memcpy((char *)var, (const char *)ptr, len);    \
        ptr += size_round(len);                                 \
} while (0)

#define LOGL0(var,len,ptr)                              \
do {                                                    \
        if (!len)                                       \
                break;                                  \
        memcpy((char *)ptr, (const char *)var, len);    \
        *((char *)(ptr) + len) = 0;                     \
        ptr += size_round(len + 1);                     \
} while (0)

/**
 *  Lustre Network Driver types.
 */
enum {
        /* Only add to these values (i.e. don't ever change or redefine them):
         * network addresses depend on them... */
        QSWLND    = 1,
        SOCKLND   = 2,
        GMLND     = 3,
        PTLLND    = 4,
        O2IBLND   = 5,
        CIBLND    = 6,
        OPENIBLND = 7,
        IIBLND    = 8,
        LOLND     = 9,
        RALND     = 10,
        VIBLND    = 11,
        MXLND     = 12,
};

#endif
