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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
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
 * lnet/libcfs/user-prim.c
 *
 * Implementations of portable APIs for liblustre
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */


/*
 * liblustre is single-threaded, so most "synchronization" APIs are trivial.
 */

#ifndef __KERNEL__

#include <libcfs/libcfs.h>
#include <libcfs/kp30.h>

#include <sys/mman.h>
#ifndef  __CYGWIN__
#include <stdint.h>
#ifdef HAVE_ASM_PAGE_H
#include <asm/page.h>
#endif
#ifdef HAVE_SYS_USER_H
#include <sys/user.h>
#endif
#else
#include <sys/types.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#ifdef	HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif

/*
 * Sleep channel. No-op implementation.
 */

void cfs_waitq_init(struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        (void)waitq;
}

void cfs_waitlink_init(struct cfs_waitlink *link)
{
        LASSERT(link != NULL);
        (void)link;
}

void cfs_waitq_add(struct cfs_waitq *waitq, struct cfs_waitlink *link)
{
        LASSERT(waitq != NULL);
        LASSERT(link != NULL);
        (void)waitq;
        (void)link;
}

void cfs_waitq_add_exclusive(struct cfs_waitq *waitq, struct cfs_waitlink *link)
{
        LASSERT(waitq != NULL);
        LASSERT(link != NULL);
        (void)waitq;
        (void)link;
}

void cfs_waitq_forward(struct cfs_waitlink *link, struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        LASSERT(link != NULL);
        (void)waitq;
        (void)link;
}

void cfs_waitq_del(struct cfs_waitq *waitq, struct cfs_waitlink *link)
{
        LASSERT(waitq != NULL);
        LASSERT(link != NULL);
        (void)waitq;
        (void)link;
}

int cfs_waitq_active(struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        (void)waitq;
        return 0;
}

void cfs_waitq_signal(struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        (void)waitq;
}

void cfs_waitq_signal_nr(struct cfs_waitq *waitq, int nr)
{
        LASSERT(waitq != NULL);
        (void)waitq;
}

void cfs_waitq_broadcast(struct cfs_waitq *waitq)
{
        LASSERT(waitq != NULL);
        (void)waitq;
}

void cfs_waitq_wait(struct cfs_waitlink *link, int state)
{
        LASSERT(link != NULL);
        (void)link;
}

int64_t cfs_waitq_timedwait(struct cfs_waitlink *link, int state, int64_t timeout)
{
        LASSERT(link != NULL);
        (void)link;
        return 0;
}

#ifdef HAVE_LIBPTHREAD

/*
 * Threads
 */

struct lustre_thread_arg {
        cfs_thread_t f; 
        void *arg;
};
static void *cfs_thread_helper(void *data)
{
        struct lustre_thread_arg *targ = data;
        cfs_thread_t f  = targ->f;
        void *arg = targ->arg;

        free(targ);
        
        (void)f(arg);
        return NULL;
}
int cfs_create_thread(cfs_thread_t func, void *arg)
{
        pthread_t tid;
        pthread_attr_t tattr;
        int rc;
        struct lustre_thread_arg *targ_p = malloc(sizeof(struct lustre_thread_arg));

        if ( targ_p == NULL )
                return -ENOMEM;
        
        targ_p->f = func;
        targ_p->arg = arg;

        pthread_attr_init(&tattr); 
        pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
        rc = pthread_create(&tid, &tattr, cfs_thread_helper, targ_p);
        pthread_attr_destroy(&tattr);
        return -rc;
}
#endif

uid_t cfs_curproc_uid(void)
{
        return getuid();
}

int cfs_parse_int_tunable(int *value, char *name)
{
        char    *env = getenv(name);
        char    *end;

        if (env == NULL)
                return 0;

        *value = strtoull(env, &end, 0);
        if (*end == 0)
                return 0;

        CERROR("Can't parse tunable %s=%s\n", name, env);
        return -EINVAL;
}

/*
 * Allocator
 */

cfs_page_t *cfs_alloc_page(unsigned int flags)
{
        cfs_page_t *pg = malloc(sizeof(*pg));

        if (!pg)
                return NULL;
        pg->addr = malloc(CFS_PAGE_SIZE);

        if (!pg->addr) {
                free(pg);
                return NULL;
        }
        return pg;
}

void cfs_free_page(cfs_page_t *pg)
{
        free(pg->addr);
        free(pg);
}

void *cfs_page_address(cfs_page_t *pg)
{
        return pg->addr;
}

void *cfs_kmap(cfs_page_t *pg)
{
        return pg->addr;
}

void cfs_kunmap(cfs_page_t *pg)
{
}

/*
 * SLAB allocator
 */

cfs_mem_cache_t *
cfs_mem_cache_create(const char *name, size_t objsize, size_t off, unsigned long flags)
{
        cfs_mem_cache_t *c;

        c = malloc(sizeof(*c));
        if (!c)
                return NULL;
        c->size = objsize;
        CDEBUG(D_MALLOC, "alloc slab cache %s at %p, objsize %d\n",
               name, c, (int)objsize);
        return c;
}

int cfs_mem_cache_destroy(cfs_mem_cache_t *c)
{
        CDEBUG(D_MALLOC, "destroy slab cache %p, objsize %u\n", c, c->size);
        free(c);
        return 0;
}

void *cfs_mem_cache_alloc(cfs_mem_cache_t *c, int gfp)
{
        return cfs_alloc(c->size, gfp);
}

void cfs_mem_cache_free(cfs_mem_cache_t *c, void *addr)
{
        cfs_free(addr);
}

void cfs_enter_debugger(void)
{
        /*
         * nothing for now.
         */
}

void cfs_daemonize(char *str)
{
        return;
}

int cfs_daemonize_ctxt(char *str)
{
        return 0;
}

cfs_sigset_t cfs_block_allsigs(void)
{
        cfs_sigset_t   all;
        cfs_sigset_t   old;
        int            rc;

        sigfillset(&all);
        rc = sigprocmask(SIG_SETMASK, &all, &old);
        LASSERT(rc == 0);

        return old;
}

cfs_sigset_t cfs_block_sigs(cfs_sigset_t blocks)
{
        cfs_sigset_t   old;
        int   rc;
        
        rc = sigprocmask(SIG_SETMASK, &blocks, &old);
        LASSERT (rc == 0);

        return old;
}

void cfs_restore_sigs(cfs_sigset_t old)
{
        int   rc = sigprocmask(SIG_SETMASK, &old, NULL);

        LASSERT (rc == 0);
}

int cfs_signal_pending(void)
{
        cfs_sigset_t    empty;
        cfs_sigset_t    set;
        int  rc;

        rc = sigpending(&set);
        LASSERT (rc == 0);

        sigemptyset(&empty);

        return !memcmp(&empty, &set, sizeof(set));
}

void cfs_clear_sigpending(void)
{
        return;
}

#ifdef __linux__

/*
 * In glibc (NOT in Linux, so check above is not right), implement
 * stack-back-tracing through backtrace() function.
 */
#include <execinfo.h>

void cfs_stack_trace_fill(struct cfs_stack_trace *trace)
{
        backtrace(trace->frame, sizeof_array(trace->frame));
}

void *cfs_stack_trace_frame(struct cfs_stack_trace *trace, int frame_no)
{
        if (0 <= frame_no && frame_no < sizeof_array(trace->frame))
                return trace->frame[frame_no];
        else
                return NULL;
}

#else

void cfs_stack_trace_fill(struct cfs_stack_trace *trace)
{}
void *cfs_stack_trace_frame(struct cfs_stack_trace *trace, int frame_no)
{
        return NULL;
}

/* __linux__ */
#endif

void lbug_with_loc(const char *file, const char *func, const int line)
{
        /* No libcfs_catastrophe in userspace! */
        libcfs_debug_msg(NULL, 0, D_EMERG, file, func, line, "LBUG\n");
        abort();
}

/* !__KERNEL__ */
#endif

/*
 * Local variables:
 * c-indentation-style: "K&R"
 * c-basic-offset: 8
 * tab-width: 8
 * fill-column: 80
 * scroll-step: 1
 * End:
 */
