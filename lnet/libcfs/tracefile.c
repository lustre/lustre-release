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
 * lnet/libcfs/tracefile.c
 *
 * Author: Zach Brown <zab@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */


#define DEBUG_SUBSYSTEM S_LNET
#define LUSTRE_TRACEFILE_PRIVATE
#include "tracefile.h"

#include <libcfs/kp30.h>
#include <libcfs/libcfs.h>

/* XXX move things up to the top, comment */
union trace_data_union (*trace_data[TCD_MAX_TYPES])[NR_CPUS] __cacheline_aligned;

char tracefile[TRACEFILE_NAME_SIZE];
long long tracefile_size = TRACEFILE_SIZE;
static struct tracefiled_ctl trace_tctl;
struct semaphore trace_thread_sem;
static int thread_running = 0;

atomic_t tage_allocated = ATOMIC_INIT(0);

static void put_pages_on_tcd_daemon_list(struct page_collection *pc,
                                         struct trace_cpu_data *tcd);

static inline struct trace_page *tage_from_list(struct list_head *list)
{
        return list_entry(list, struct trace_page, linkage);
}

static struct trace_page *tage_alloc(int gfp)
{
        cfs_page_t        *page;
        struct trace_page *tage;

        /*
         * Don't spam console with allocation failures: they will be reported
         * by upper layer anyway.
         */
        gfp |= CFS_ALLOC_NOWARN;
        page = cfs_alloc_page(gfp);
        if (page == NULL)
                return NULL;

        tage = cfs_alloc(sizeof(*tage), gfp);
        if (tage == NULL) {
                cfs_free_page(page);
                return NULL;
        }

        tage->page = page;
        atomic_inc(&tage_allocated);
        return tage;
}

static void tage_free(struct trace_page *tage)
{
        __LASSERT(tage != NULL);
        __LASSERT(tage->page != NULL);

        cfs_free_page(tage->page);
        cfs_free(tage);
        atomic_dec(&tage_allocated);
}

static void tage_to_tail(struct trace_page *tage, struct list_head *queue)
{
        __LASSERT(tage != NULL);
        __LASSERT(queue != NULL);

        list_move_tail(&tage->linkage, queue);
}

int trace_refill_stock(struct trace_cpu_data *tcd, int gfp,
                       struct list_head *stock)
{
        int i;

        /*
         * XXX nikita: do NOT call portals_debug_msg() (CDEBUG/ENTRY/EXIT)
         * from here: this will lead to infinite recursion.
         */

        for (i = 0; i + tcd->tcd_cur_stock_pages < TCD_STOCK_PAGES ; ++ i) {
                struct trace_page *tage;

                tage = tage_alloc(gfp);
                if (tage == NULL)
                        break;
                list_add_tail(&tage->linkage, stock);
        }
        return i;
}

/* return a page that has 'len' bytes left at the end */
static struct trace_page *trace_get_tage_try(struct trace_cpu_data *tcd,
                                             unsigned long len)
{
        struct trace_page *tage;

        if (tcd->tcd_cur_pages > 0) {
                __LASSERT(!list_empty(&tcd->tcd_pages));
                tage = tage_from_list(tcd->tcd_pages.prev);
                if (tage->used + len <= CFS_PAGE_SIZE)
                        return tage;
        }

        if (tcd->tcd_cur_pages < tcd->tcd_max_pages) {
                if (tcd->tcd_cur_stock_pages > 0) {
                        tage = tage_from_list(tcd->tcd_stock_pages.prev);
                        -- tcd->tcd_cur_stock_pages;
                        list_del_init(&tage->linkage);
                } else {
                        tage = tage_alloc(CFS_ALLOC_ATOMIC);
                        if (tage == NULL) {
                                printk(KERN_WARNING
                                       "failure to allocate a tage (%ld)\n",
                                       tcd->tcd_cur_pages);
                                return NULL;
                        }
                }

                tage->used = 0;
                tage->cpu = smp_processor_id();
                tage->type = tcd->tcd_type;
                list_add_tail(&tage->linkage, &tcd->tcd_pages);
                tcd->tcd_cur_pages++;

                if (tcd->tcd_cur_pages > 8 && thread_running) {
                        struct tracefiled_ctl *tctl = &trace_tctl;
                        /*
                         * wake up tracefiled to process some pages.
                         */
                        cfs_waitq_signal(&tctl->tctl_waitq);
                }
                return tage;
        }
        return NULL;
}

static void tcd_shrink(struct trace_cpu_data *tcd)
{
        int pgcount = tcd->tcd_cur_pages / 10;
        struct page_collection pc;
        struct trace_page *tage;
        struct trace_page *tmp;

        /*
         * XXX nikita: do NOT call portals_debug_msg() (CDEBUG/ENTRY/EXIT)
         * from here: this will lead to infinite recursion.
         */

        if (printk_ratelimit())
                printk(KERN_WARNING "debug daemon buffer overflowed; "
                       "discarding  10%% of pages (%d of %ld)\n",
                       pgcount + 1, tcd->tcd_cur_pages);

        CFS_INIT_LIST_HEAD(&pc.pc_pages);
        spin_lock_init(&pc.pc_lock);

        list_for_each_entry_safe(tage, tmp, &tcd->tcd_pages, linkage) {
                if (pgcount-- == 0)
                        break;

                list_move_tail(&tage->linkage, &pc.pc_pages);
                tcd->tcd_cur_pages--;
        }
        put_pages_on_tcd_daemon_list(&pc, tcd);
}

/* return a page that has 'len' bytes left at the end */
static struct trace_page *trace_get_tage(struct trace_cpu_data *tcd,
                                         unsigned long len)
{
        struct trace_page *tage;

        /*
         * XXX nikita: do NOT call portals_debug_msg() (CDEBUG/ENTRY/EXIT)
         * from here: this will lead to infinite recursion.
         */

        if (len > CFS_PAGE_SIZE) {
                printk(KERN_ERR
                       "cowardly refusing to write %lu bytes in a page\n", len);
                return NULL;
        }

        tage = trace_get_tage_try(tcd, len);
        if (tage != NULL)
                return tage;
        if (thread_running)
                tcd_shrink(tcd);
        if (tcd->tcd_cur_pages > 0) {
                tage = tage_from_list(tcd->tcd_pages.next);
                tage->used = 0;
                tage_to_tail(tage, &tcd->tcd_pages);
        }
        return tage;
}

int libcfs_debug_vmsg2(cfs_debug_limit_state_t *cdls, int subsys, int mask,
                       const char *file, const char *fn, const int line,
                       const char *format1, va_list args,
                       const char *format2, ...)
{
        struct trace_cpu_data   *tcd = NULL;
        struct ptldebug_header   header;
        struct trace_page       *tage;
        /* string_buf is used only if tcd != NULL, and is always set then */
        char                    *string_buf = NULL;
        char                    *debug_buf;
        int                      known_size;
        int                      needed = 85; /* average message length */
        int                      max_nob;
        va_list                  ap;
        int                      depth;
        int                      i;
        int                      remain;

        if (strchr(file, '/'))
                file = strrchr(file, '/') + 1;


        set_ptldebug_header(&header, subsys, mask, line, CDEBUG_STACK());

        tcd = trace_get_tcd();
        if (tcd == NULL)                /* arch may not log in IRQ context */
                goto console;

        if (tcd->tcd_shutting_down) {
                trace_put_tcd(tcd);
                tcd = NULL;
                goto console;
        }

        depth = __current_nesting_level();
        known_size = strlen(file) + 1 + depth;
        if (fn)
                known_size += strlen(fn) + 1;

        if (libcfs_debug_binary)
                known_size += sizeof(header);

        /*/
         * '2' used because vsnprintf return real size required for output
         * _without_ terminating NULL.
         * if needed is to small for this format.
         */
        for (i=0;i<2;i++) {
                tage = trace_get_tage(tcd, needed + known_size + 1);
                if (tage == NULL) {
                        if (needed + known_size > CFS_PAGE_SIZE)
                                mask |= D_ERROR;

                        trace_put_tcd(tcd);
                        tcd = NULL;
                        goto console;
                }

                string_buf = (char *)cfs_page_address(tage->page)+tage->used+known_size;

                max_nob = CFS_PAGE_SIZE - tage->used - known_size;
                if (max_nob <= 0) {
                        printk(KERN_EMERG "negative max_nob: %i\n", max_nob);
                        mask |= D_ERROR;
                        trace_put_tcd(tcd);
                        tcd = NULL;
                        goto console;
                }

                needed = 0;
                if (format1) {
                        va_copy(ap, args);
                        needed = vsnprintf(string_buf, max_nob, format1, ap);
                        va_end(ap);
                }

                if (format2) {
                        remain = max_nob - needed;
                        if (remain < 0)
                                remain = 0;

                        va_start(ap, format2);
                        needed += vsnprintf(string_buf + needed, remain,
                                            format2, ap);
                        va_end(ap);
                }

                if (needed < max_nob) /* well. printing ok.. */
                        break;
        }

        if (*(string_buf+needed-1) != '\n')
                printk(KERN_INFO "format at %s:%d:%s doesn't end in newline\n",
                       file, line, fn);

        header.ph_len = known_size + needed;
        debug_buf = (char *)cfs_page_address(tage->page) + tage->used;

        if (libcfs_debug_binary) {
                memcpy(debug_buf, &header, sizeof(header));
                tage->used += sizeof(header);
                debug_buf += sizeof(header);
        }

        /* indent message according to the nesting level */
        while (depth-- > 0) {
                *(debug_buf++) = '.';
                ++ tage->used;
        }

        strcpy(debug_buf, file);
        tage->used += strlen(file) + 1;
        debug_buf += strlen(file) + 1;

        if (fn) {
                strcpy(debug_buf, fn);
                tage->used += strlen(fn) + 1;
                debug_buf += strlen(fn) + 1;
        }

        __LASSERT(debug_buf == string_buf);

        tage->used += needed;
        __LASSERT (tage->used <= CFS_PAGE_SIZE);

console:
        if ((mask & libcfs_printk) == 0) {
                /* no console output requested */
                if (tcd != NULL)
                        trace_put_tcd(tcd);
                return 1;
        }

        if (cdls != NULL) {
                if (libcfs_console_ratelimit &&
                    cdls->cdls_next != 0 &&     /* not first time ever */
                    !cfs_time_after(cfs_time_current(), cdls->cdls_next)) {
                        /* skipping a console message */
                        cdls->cdls_count++;
                        if (tcd != NULL)
                                trace_put_tcd(tcd);
                        return 1;
                }

                if (cfs_time_after(cfs_time_current(), cdls->cdls_next +
                                                       libcfs_console_max_delay
                                                       + cfs_time_seconds(10))) {
                        /* last timeout was a long time ago */
                        cdls->cdls_delay /= libcfs_console_backoff * 4;
                } else {
                        cdls->cdls_delay *= libcfs_console_backoff;

                        if (cdls->cdls_delay < libcfs_console_min_delay)
                                cdls->cdls_delay = libcfs_console_min_delay;
                        else if (cdls->cdls_delay > libcfs_console_max_delay)
                                cdls->cdls_delay = libcfs_console_max_delay;
                }

                /* ensure cdls_next is never zero after it's been seen */
                cdls->cdls_next = (cfs_time_current() + cdls->cdls_delay) | 1;
        }

        if (tcd != NULL) {
                print_to_console(&header, mask, string_buf, needed, file, fn);
                trace_put_tcd(tcd);
        } else {
                string_buf = trace_get_console_buffer();

                needed = 0;
                if (format1 != NULL) {
                        va_copy(ap, args);
                        needed = vsnprintf(string_buf, TRACE_CONSOLE_BUFFER_SIZE, format1, ap);
                        va_end(ap);
                }
                if (format2 != NULL) {
                        remain = TRACE_CONSOLE_BUFFER_SIZE - needed;
                        if (remain > 0) {
                                va_start(ap, format2);
                                needed += vsnprintf(string_buf+needed, remain, format2, ap);
                                va_end(ap);
                        }
                }
                print_to_console(&header, mask,
                                 string_buf, needed, file, fn);

                trace_put_console_buffer(string_buf);
        }

        if (cdls != NULL && cdls->cdls_count != 0) {
                string_buf = trace_get_console_buffer();

                needed = snprintf(string_buf, TRACE_CONSOLE_BUFFER_SIZE,
                         "Skipped %d previous similar message%s\n",
                         cdls->cdls_count, (cdls->cdls_count > 1) ? "s" : "");

                print_to_console(&header, mask,
                                 string_buf, needed, file, fn);

                trace_put_console_buffer(string_buf);
                cdls->cdls_count = 0;
        }

        return 0;
}
EXPORT_SYMBOL(libcfs_debug_vmsg2);

void
libcfs_assertion_failed(const char *expr, const char *file,
                        const char *func, const int line)
{
        libcfs_debug_msg(NULL, 0, D_EMERG, file, func, line,
                         "ASSERTION(%s) failed\n", expr);
        lbug_with_loc(file, func, line);
}
EXPORT_SYMBOL(libcfs_assertion_failed);

void
trace_assertion_failed(const char *str,
                       const char *fn, const char *file, int line)
{
        struct ptldebug_header hdr;

        libcfs_panic_in_progress = 1;
        libcfs_catastrophe = 1;
        mb();

        set_ptldebug_header(&hdr, DEBUG_SUBSYSTEM, D_EMERG, line,
                            CDEBUG_STACK());

        print_to_console(&hdr, D_EMERG, str, strlen(str), file, fn);

        LIBCFS_PANIC("Lustre debug assertion failure\n");

        /* not reached */
}

static void
panic_collect_pages(struct page_collection *pc)
{
        /* Do the collect_pages job on a single CPU: assumes that all other
         * CPUs have been stopped during a panic.  If this isn't true for some
         * arch, this will have to be implemented separately in each arch.  */
        int                    i;
        int                    j;
        struct trace_cpu_data *tcd;

        CFS_INIT_LIST_HEAD(&pc->pc_pages);

        tcd_for_each(tcd, i, j) {
                list_splice_init(&tcd->tcd_pages, &pc->pc_pages);
                tcd->tcd_cur_pages = 0;

                if (pc->pc_want_daemon_pages) {
                        list_splice_init(&tcd->tcd_daemon_pages, &pc->pc_pages);
                        tcd->tcd_cur_daemon_pages = 0;
                }
        }
}

static void collect_pages_on_all_cpus(struct page_collection *pc)
{
        struct trace_cpu_data *tcd;
        int i, cpu;

        spin_lock(&pc->pc_lock);
        for_each_possible_cpu(cpu) {
                tcd_for_each_type_lock(tcd, i, cpu) {
                        list_splice_init(&tcd->tcd_pages, &pc->pc_pages);
                        tcd->tcd_cur_pages = 0;
                        if (pc->pc_want_daemon_pages) {
                                list_splice_init(&tcd->tcd_daemon_pages,
                                                 &pc->pc_pages);
                                tcd->tcd_cur_daemon_pages = 0;
                        }
                }
        }
        spin_unlock(&pc->pc_lock);
}

static void collect_pages(struct page_collection *pc)
{
        CFS_INIT_LIST_HEAD(&pc->pc_pages);

        if (libcfs_panic_in_progress)
                panic_collect_pages(pc);
        else
                collect_pages_on_all_cpus(pc);
}

static void put_pages_back_on_all_cpus(struct page_collection *pc)
{
        struct trace_cpu_data *tcd;
        struct list_head *cur_head;
        struct trace_page *tage;
        struct trace_page *tmp;
        int i, cpu;

        spin_lock(&pc->pc_lock);
        for_each_possible_cpu(cpu) {
                tcd_for_each_type_lock(tcd, i, cpu) {
                        cur_head = tcd->tcd_pages.next;

                        list_for_each_entry_safe(tage, tmp, &pc->pc_pages,
                                                 linkage) {

                                __LASSERT_TAGE_INVARIANT(tage);

                                if (tage->cpu != cpu || tage->type != i)
                                        continue;

                                tage_to_tail(tage, cur_head);
                                tcd->tcd_cur_pages++;
                        }
                }
        }
        spin_unlock(&pc->pc_lock);
}

static void put_pages_back(struct page_collection *pc)
{
        if (!libcfs_panic_in_progress)
                put_pages_back_on_all_cpus(pc);
}

/* Add pages to a per-cpu debug daemon ringbuffer.  This buffer makes sure that
 * we have a good amount of data at all times for dumping during an LBUG, even
 * if we have been steadily writing (and otherwise discarding) pages via the
 * debug daemon. */
static void put_pages_on_tcd_daemon_list(struct page_collection *pc,
                                         struct trace_cpu_data *tcd)
{
        struct trace_page *tage;
        struct trace_page *tmp;

        spin_lock(&pc->pc_lock);
        list_for_each_entry_safe(tage, tmp, &pc->pc_pages, linkage) {

                __LASSERT_TAGE_INVARIANT(tage);

                if (tage->cpu != tcd->tcd_cpu || tage->type != tcd->tcd_type)
                        continue;

                tage_to_tail(tage, &tcd->tcd_daemon_pages);
                tcd->tcd_cur_daemon_pages++;

                if (tcd->tcd_cur_daemon_pages > tcd->tcd_max_pages) {
                        struct trace_page *victim;

                        __LASSERT(!list_empty(&tcd->tcd_daemon_pages));
                        victim = tage_from_list(tcd->tcd_daemon_pages.next);

                        __LASSERT_TAGE_INVARIANT(victim);

                        list_del(&victim->linkage);
                        tage_free(victim);
                        tcd->tcd_cur_daemon_pages--;
                }
        }
        spin_unlock(&pc->pc_lock);
}

static void put_pages_on_daemon_list(struct page_collection *pc)
{
        struct trace_cpu_data *tcd;
        int i, cpu;

        for_each_possible_cpu(cpu) {
                tcd_for_each_type_lock(tcd, i, cpu)
                        put_pages_on_tcd_daemon_list(pc, tcd);
        }
}

void trace_debug_print(void)
{
        struct page_collection pc;
        struct trace_page *tage;
        struct trace_page *tmp;

        spin_lock_init(&pc.pc_lock);

        pc.pc_want_daemon_pages = 1;
        collect_pages(&pc);
        list_for_each_entry_safe(tage, tmp, &pc.pc_pages, linkage) {
                char *p, *file, *fn;
                cfs_page_t *page;

                __LASSERT_TAGE_INVARIANT(tage);

                page = tage->page;
                p = cfs_page_address(page);
                while (p < ((char *)cfs_page_address(page) + tage->used)) {
                        struct ptldebug_header *hdr;
                        int len;
                        hdr = (void *)p;
                        p += sizeof(*hdr);
                        file = p;
                        p += strlen(file) + 1;
                        fn = p;
                        p += strlen(fn) + 1;
                        len = hdr->ph_len - (p - (char *)hdr);

                        print_to_console(hdr, D_EMERG, p, len, file, fn);

                        p += len;
                }

                list_del(&tage->linkage);
                tage_free(tage);
        }
}

int tracefile_dump_all_pages(char *filename)
{
        struct page_collection pc;
        cfs_file_t *filp;
        struct trace_page *tage;
        struct trace_page *tmp;
        int rc;

        CFS_DECL_MMSPACE;

        tracefile_write_lock();

        filp = cfs_filp_open(filename,
                             O_CREAT|O_EXCL|O_WRONLY|O_LARGEFILE, 0600, &rc);
        if (!filp) {
                if (rc != -EEXIST)
                        printk(KERN_ERR "LustreError: can't open %s for dump: rc %d\n",
                               filename, rc);
                goto out;
        }

        spin_lock_init(&pc.pc_lock);
        pc.pc_want_daemon_pages = 1;
        collect_pages(&pc);
        if (list_empty(&pc.pc_pages)) {
                rc = 0;
                goto close;
        }

        /* ok, for now, just write the pages.  in the future we'll be building
         * iobufs with the pages and calling generic_direct_IO */
        CFS_MMSPACE_OPEN;
        list_for_each_entry_safe(tage, tmp, &pc.pc_pages, linkage) {

                __LASSERT_TAGE_INVARIANT(tage);

                rc = cfs_filp_write(filp, cfs_page_address(tage->page),
                                    tage->used, cfs_filp_poff(filp));
                if (rc != (int)tage->used) {
                        printk(KERN_WARNING "wanted to write %u but wrote "
                               "%d\n", tage->used, rc);
                        put_pages_back(&pc);
                        __LASSERT(list_empty(&pc.pc_pages));
                        break;
                }
                list_del(&tage->linkage);
                tage_free(tage);
        }
        CFS_MMSPACE_CLOSE;
        rc = cfs_filp_fsync(filp);
        if (rc)
                printk(KERN_ERR "sync returns %d\n", rc);
 close:
        cfs_filp_close(filp);
 out:
        tracefile_write_unlock();
        return rc;
}

void trace_flush_pages(void)
{
        struct page_collection pc;
        struct trace_page *tage;
        struct trace_page *tmp;

        spin_lock_init(&pc.pc_lock);

        pc.pc_want_daemon_pages = 1;
        collect_pages(&pc);
        list_for_each_entry_safe(tage, tmp, &pc.pc_pages, linkage) {

                __LASSERT_TAGE_INVARIANT(tage);

                list_del(&tage->linkage);
                tage_free(tage);
        }
}

int trace_copyin_string(char *knl_buffer, int knl_buffer_nob,
                        const char *usr_buffer, int usr_buffer_nob)
{
        int    nob;

        if (usr_buffer_nob > knl_buffer_nob)
                return -EOVERFLOW;

        if (copy_from_user((void *)knl_buffer,
                           (void *)usr_buffer, usr_buffer_nob))
                return -EFAULT;

        nob = strnlen(knl_buffer, usr_buffer_nob);
        while (nob-- >= 0)                      /* strip trailing whitespace */
                if (!isspace(knl_buffer[nob]))
                        break;

        if (nob < 0)                            /* empty string */
                return -EINVAL;

        if (nob == knl_buffer_nob)              /* no space to terminate */
                return -EOVERFLOW;

        knl_buffer[nob + 1] = 0;                /* terminate */
        return 0;
}

int trace_copyout_string(char *usr_buffer, int usr_buffer_nob,
                         const char *knl_buffer, char *append)
{
        /* NB if 'append' != NULL, it's a single character to append to the
         * copied out string - usually "\n", for /proc entries and "" (i.e. a
         * terminating zero byte) for sysctl entries */
        int   nob = strlen(knl_buffer);

        if (nob > usr_buffer_nob)
                nob = usr_buffer_nob;

        if (copy_to_user(usr_buffer, knl_buffer, nob))
                return -EFAULT;

        if (append != NULL && nob < usr_buffer_nob) {
                if (copy_to_user(usr_buffer + nob, append, 1))
                        return -EFAULT;

                nob++;
        }

        return nob;
}
EXPORT_SYMBOL(trace_copyout_string);

int trace_allocate_string_buffer(char **str, int nob)
{
        if (nob > 2 * CFS_PAGE_SIZE)            /* string must be "sensible" */
                return -EINVAL;

        *str = cfs_alloc(nob, CFS_ALLOC_STD | CFS_ALLOC_ZERO);
        if (*str == NULL)
                return -ENOMEM;

        return 0;
}

void trace_free_string_buffer(char *str, int nob)
{
        cfs_free(str);
}

int trace_dump_debug_buffer_usrstr(void *usr_str, int usr_str_nob)
{
        char         *str;
        int           rc;

        rc = trace_allocate_string_buffer(&str, usr_str_nob + 1);
        if (rc != 0)
                return rc;

        rc = trace_copyin_string(str, usr_str_nob + 1,
                                 usr_str, usr_str_nob);
        if (rc != 0)
                goto out;

#if !defined(__WINNT__)
        if (str[0] != '/') {
                rc = -EINVAL;
                goto out;
        }
#endif
        rc = tracefile_dump_all_pages(str);
out:
        trace_free_string_buffer(str, usr_str_nob + 1);
        return rc;
}

int trace_daemon_command(char *str)
{
        int       rc = 0;

        tracefile_write_lock();

        if (strcmp(str, "stop") == 0) {
                tracefile_write_unlock();
                trace_stop_thread();
                tracefile_write_lock();
                memset(tracefile, 0, sizeof(tracefile));

        } else if (strncmp(str, "size=", 5) == 0) {
                tracefile_size = simple_strtoul(str + 5, NULL, 0);
                if (tracefile_size < 10 || tracefile_size > 20480)
                        tracefile_size = TRACEFILE_SIZE;
                else
                        tracefile_size <<= 20;

        } else if (strlen(str) >= sizeof(tracefile)) {
                rc = -ENAMETOOLONG;
#ifndef __WINNT__
        } else if (str[0] != '/') {
                rc = -EINVAL;
#endif
        } else {
                strcpy(tracefile, str);

                printk(KERN_INFO "Lustre: debug daemon will attempt to start writing "
                       "to %s (%lukB max)\n", tracefile,
                       (long)(tracefile_size >> 10));

                trace_start_thread();
        }

        tracefile_write_unlock();
        return rc;
}

int trace_daemon_command_usrstr(void *usr_str, int usr_str_nob)
{
        char *str;
        int   rc;

        rc = trace_allocate_string_buffer(&str, usr_str_nob + 1);
        if (rc != 0)
                return rc;

        rc = trace_copyin_string(str, usr_str_nob + 1,
                                 usr_str, usr_str_nob);
        if (rc == 0)
                rc = trace_daemon_command(str);

        trace_free_string_buffer(str, usr_str_nob + 1);

        return rc;
}

int trace_set_debug_mb(int mb)
{
        int i;
        int j;
        int pages;
        int limit = trace_max_debug_mb();
        struct trace_cpu_data *tcd;

        if (mb < num_possible_cpus())
                return -EINVAL;

        if (mb > limit) {
                printk(KERN_ERR "Lustre: Refusing to set debug buffer size to "
                       "%dMB - limit is %d\n", mb, limit);
                return -EINVAL;
        }

        mb /= num_possible_cpus();
        pages = mb << (20 - CFS_PAGE_SHIFT);

        tracefile_write_lock();

        tcd_for_each(tcd, i, j)
                tcd->tcd_max_pages = (pages * tcd->tcd_pages_factor) / 100;

        tracefile_write_unlock();

        return 0;
}

int trace_set_debug_mb_usrstr(void *usr_str, int usr_str_nob)
{
        char     str[32];
        int      rc;

        rc = trace_copyin_string(str, sizeof(str), usr_str, usr_str_nob);
        if (rc < 0)
                return rc;

        return trace_set_debug_mb(simple_strtoul(str, NULL, 0));
}

int trace_get_debug_mb(void)
{
        int i;
        int j;
        struct trace_cpu_data *tcd;
        int total_pages = 0;

        tracefile_read_lock();

        tcd_for_each(tcd, i, j)
                total_pages += tcd->tcd_max_pages;

        tracefile_read_unlock();

        return (total_pages >> (20 - CFS_PAGE_SHIFT)) + 1;
}

static int tracefiled(void *arg)
{
        struct page_collection pc;
        struct tracefiled_ctl *tctl = arg;
        struct trace_page *tage;
        struct trace_page *tmp;
        struct ptldebug_header *hdr;
        cfs_file_t *filp;
        int last_loop = 0;
        int rc;

        CFS_DECL_MMSPACE;

        /* we're started late enough that we pick up init's fs context */
        /* this is so broken in uml?  what on earth is going on? */
        cfs_daemonize("ktracefiled");

        spin_lock_init(&pc.pc_lock);
        complete(&tctl->tctl_start);

        while (1) {
                cfs_waitlink_t __wait;

                pc.pc_want_daemon_pages = 0;
                collect_pages(&pc);
                if (list_empty(&pc.pc_pages))
                        goto end_loop;

                filp = NULL;
                tracefile_read_lock();
                if (tracefile[0] != 0) {
                        filp = cfs_filp_open(tracefile,
                                             O_CREAT | O_RDWR | O_LARGEFILE,
                                             0600, &rc);
                        if (!(filp))
                                printk(KERN_WARNING "couldn't open %s: %d\n",
                                       tracefile, rc);
                }
                tracefile_read_unlock();
                if (filp == NULL) {
                        put_pages_on_daemon_list(&pc);
                        __LASSERT(list_empty(&pc.pc_pages));
                        goto end_loop;
                }

                CFS_MMSPACE_OPEN;

                /* mark the first header, so we can sort in chunks */
                tage = tage_from_list(pc.pc_pages.next);
                __LASSERT_TAGE_INVARIANT(tage);

                hdr = cfs_page_address(tage->page);
                hdr->ph_flags |= PH_FLAG_FIRST_RECORD;

                list_for_each_entry_safe(tage, tmp, &pc.pc_pages, linkage) {
                        static loff_t f_pos;

                        __LASSERT_TAGE_INVARIANT(tage);

                        if (f_pos >= (off_t)tracefile_size)
                                f_pos = 0;
                        else if (f_pos > cfs_filp_size(filp))
                                f_pos = cfs_filp_size(filp);

                        rc = cfs_filp_write(filp, cfs_page_address(tage->page),
                                            tage->used, &f_pos);
                        if (rc != (int)tage->used) {
                                printk(KERN_WARNING "wanted to write %u but "
                                       "wrote %d\n", tage->used, rc);
                                put_pages_back(&pc);
                                __LASSERT(list_empty(&pc.pc_pages));
                        }
                }
                CFS_MMSPACE_CLOSE;

                cfs_filp_close(filp);
                put_pages_on_daemon_list(&pc);
                if (!list_empty(&pc.pc_pages)) {
                        int i;

                        printk(KERN_ALERT "Lustre: trace pages aren't empty\n");
                        printk(KERN_ALERT "total cpus(%d): ", num_possible_cpus());
                        for (i = 0; i < num_possible_cpus(); i++)
                                if (cpu_online(i))
                                        printk(KERN_ALERT "%d(on) ", i);
                                else
                                        printk(KERN_ALERT "%d(off) ", i);
                        printk(KERN_ALERT "\n");

                        i = 0;
                        list_for_each_entry_safe(tage, tmp, &pc.pc_pages,
                                                 linkage)
                                printk(KERN_ALERT "page %d belongs to cpu %d\n",
                                       ++i, tage->cpu);
                        printk(KERN_ALERT "There are %d pages unwritten\n", i);
                }
                __LASSERT(list_empty(&pc.pc_pages));
end_loop:
                if (atomic_read(&tctl->tctl_shutdown)) {
                        if (last_loop == 0) {
                                last_loop = 1;
                                continue;
                        } else {
                                break;
                        }
                }
                cfs_waitlink_init(&__wait);
                cfs_waitq_add(&tctl->tctl_waitq, &__wait);
                set_current_state(TASK_INTERRUPTIBLE);
                cfs_waitq_timedwait(&__wait, CFS_TASK_INTERRUPTIBLE,
                                    cfs_time_seconds(1));
                cfs_waitq_del(&tctl->tctl_waitq, &__wait);
        }
        complete(&tctl->tctl_stop);
        return 0;
}

int trace_start_thread(void)
{
        struct tracefiled_ctl *tctl = &trace_tctl;
        int rc = 0;

        mutex_down(&trace_thread_sem);
        if (thread_running)
                goto out;

        init_completion(&tctl->tctl_start);
        init_completion(&tctl->tctl_stop);
        cfs_waitq_init(&tctl->tctl_waitq);
        atomic_set(&tctl->tctl_shutdown, 0);

        if (cfs_kernel_thread(tracefiled, tctl, 0) < 0) {
                rc = -ECHILD;
                goto out;
        }

        wait_for_completion(&tctl->tctl_start);
        thread_running = 1;
out:
        mutex_up(&trace_thread_sem);
        return rc;
}

void trace_stop_thread(void)
{
        struct tracefiled_ctl *tctl = &trace_tctl;

        mutex_down(&trace_thread_sem);
        if (thread_running) {
                printk(KERN_INFO "Lustre: shutting down debug daemon thread...\n");
                atomic_set(&tctl->tctl_shutdown, 1);
                wait_for_completion(&tctl->tctl_stop);
                thread_running = 0;
        }
        mutex_up(&trace_thread_sem);
}

int tracefile_init(int max_pages)
{
        struct trace_cpu_data *tcd;
        int                    i;
        int                    j;
        int                    rc;
        int                    factor;

        rc = tracefile_init_arch();
        if (rc != 0)
                return rc;

        tcd_for_each(tcd, i, j) {
                /* tcd_pages_factor is initialized int tracefile_init_arch. */
                factor = tcd->tcd_pages_factor;
                CFS_INIT_LIST_HEAD(&tcd->tcd_pages);
                CFS_INIT_LIST_HEAD(&tcd->tcd_stock_pages);
                CFS_INIT_LIST_HEAD(&tcd->tcd_daemon_pages);
                tcd->tcd_cur_pages = 0;
                tcd->tcd_cur_stock_pages = 0;
                tcd->tcd_cur_daemon_pages = 0;
                tcd->tcd_max_pages = (max_pages * factor) / 100;
                LASSERT(tcd->tcd_max_pages > 0);
                tcd->tcd_shutting_down = 0;
        }

        return 0;
}

static void trace_cleanup_on_all_cpus(void)
{
        struct trace_cpu_data *tcd;
        struct trace_page *tage;
        struct trace_page *tmp;
        int i, cpu;

        for_each_possible_cpu(cpu) {
                tcd_for_each_type_lock(tcd, i, cpu) {
                        tcd->tcd_shutting_down = 1;

                        list_for_each_entry_safe(tage, tmp, &tcd->tcd_pages,
                                                 linkage) {
                                __LASSERT_TAGE_INVARIANT(tage);

                                list_del(&tage->linkage);
                                tage_free(tage);
                        }

                        tcd->tcd_cur_pages = 0;
                }
        }
}

static void trace_cleanup(void)
{
        struct page_collection pc;

        CFS_INIT_LIST_HEAD(&pc.pc_pages);
        spin_lock_init(&pc.pc_lock);

        trace_cleanup_on_all_cpus();

        tracefile_fini_arch();
}

void tracefile_exit(void)
{
        trace_stop_thread();
        trace_cleanup();
}
