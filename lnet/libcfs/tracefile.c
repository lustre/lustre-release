/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *   Author: Zach Brown <zab@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#define DEBUG_SUBSYSTEM S_PORTALS
#define LUSTRE_TRACEFILE_PRIVATE
#include "tracefile.h"

#include <libcfs/kp30.h>
#include <libcfs/libcfs.h>

/* XXX move things up to the top, comment */
union trace_data_union trace_data[NR_CPUS] __cacheline_aligned;

struct rw_semaphore tracefile_sem;
char *tracefile = NULL;
long long tracefile_size = TRACEFILE_SIZE;
static struct tracefiled_ctl trace_tctl;
struct semaphore trace_thread_sem;
static int thread_running = 0;

static void put_pages_on_daemon_list_on_cpu(void *info);

static inline struct trace_page *tage_from_list(struct list_head *list)
{
        return list_entry(list, struct trace_page, linkage);
}

static struct trace_page *tage_alloc(int gfp)
{
        cfs_page_t        *page;
        struct trace_page *tage;

        page = cfs_alloc_page(gfp);
        if (page == NULL)
                return NULL;
        
        tage = cfs_alloc(sizeof(*tage), gfp);
        if (tage == NULL) {
                cfs_free_page(page);
                return NULL;
        }
        
        tage->page = page;
        return tage;
}

static void tage_free(struct trace_page *tage)
{
        LASSERT(tage != NULL);
        LASSERT(tage->page != NULL);

        cfs_free_page(tage->page);
        cfs_free(tage);
}

static void tage_to_tail(struct trace_page *tage, struct list_head *queue)
{
        LASSERT(tage != NULL);
        LASSERT(queue != NULL);

        list_move_tail(&tage->linkage, queue);
}

static int tage_invariant(struct trace_page *tage)
{
        return (tage != NULL &&
                tage->page != NULL &&
                tage->used <= CFS_PAGE_SIZE &&
                cfs_page_count(tage->page) > 0);
}

/* return a page that has 'len' bytes left at the end */
static struct trace_page *trace_get_tage(struct trace_cpu_data *tcd,
                                         unsigned long len)
{
        struct trace_page *tage;

        if (len > CFS_PAGE_SIZE) {
                printk(KERN_ERR "cowardly refusing to write %lu bytes in a "
                       "page\n", len);
                return NULL;
        }

        if (!list_empty(&tcd->tcd_pages)) {
                tage = tage_from_list(tcd->tcd_pages.prev);
                if (tage->used + len <= CFS_PAGE_SIZE)
                        return tage;
        }

        if (tcd->tcd_cur_pages < tcd->tcd_max_pages) {
                tage = tage_alloc(CFS_ALLOC_ATOMIC);
                if (tage == NULL) {
                        /* the kernel should print a message for us.  fall back
                         * to using the last page in the ring buffer. */
                        goto ring_buffer;
                }

                tage->used = 0;
                tage->cpu = smp_processor_id();
                list_add_tail(&tage->linkage, &tcd->tcd_pages);
                tcd->tcd_cur_pages++;

                if (tcd->tcd_cur_pages > 8 && thread_running) {
                        struct tracefiled_ctl *tctl = &trace_tctl;
                        cfs_waitq_signal(&tctl->tctl_waitq);
                }
                return tage;
        }

 ring_buffer:
        if (thread_running) {
                int pgcount = tcd->tcd_cur_pages / 10;
                struct page_collection pc;
                struct trace_page *tage;
                struct trace_page *tmp;

                printk(KERN_WARNING "debug daemon buffer overflowed; discarding"
                       " 10%% of pages (%d)\n", pgcount + 1);

                CFS_INIT_LIST_HEAD(&pc.pc_pages);
                spin_lock_init(&pc.pc_lock);

                list_for_each_entry_safe(tage, tmp, &tcd->tcd_pages, linkage) {
                        if (pgcount-- == 0)
                                break;

                        list_move_tail(&tage->linkage, &pc.pc_pages);
                        tcd->tcd_cur_pages--;
                }
                put_pages_on_daemon_list_on_cpu(&pc);

                LASSERT(!list_empty(&tcd->tcd_pages));
        }

        if (list_empty(&tcd->tcd_pages))
                return NULL;

        tage = tage_from_list(tcd->tcd_pages.next);
        tage->used = 0;
        tage_to_tail(tage, &tcd->tcd_pages);

        return tage;
}

void libcfs_debug_msg(int subsys, int mask, char *file, const char *fn,
                      const int line, unsigned long stack, char *format, ...)
{
        struct trace_cpu_data *tcd;
        struct ptldebug_header header;
        struct trace_page *tage;
        char *debug_buf = format;
        int known_size, needed = 85 /* average message length */, max_nob;
        va_list       ap;
        unsigned long flags;

        if (strchr(file, '/'))
                file = strrchr(file, '/') + 1;

        if (*(format + strlen(format) - 1) != '\n')
                printk(KERN_INFO "format at %s:%d:%s doesn't end in newline\n",
                       file, line, fn);

        tcd = trace_get_tcd(flags);
        if (tcd->tcd_shutting_down)
                goto out;

        set_ptldebug_header(&header, subsys, mask, line, stack);
        known_size = sizeof(header) + strlen(file) + strlen(fn) + 2; // nulls

 retry:
        tage = trace_get_tage(tcd, needed + known_size);
        if (tage == NULL) {
                debug_buf = format;
                if (needed + known_size > CFS_PAGE_SIZE)
                        mask |= D_ERROR;
                needed = strlen(format);
                goto out;
        }

        debug_buf = cfs_page_address(tage->page) + tage->used + known_size;

        max_nob = CFS_PAGE_SIZE - tage->used - known_size;
        if (max_nob <= 0) {
                printk(KERN_EMERG "negative max_nob: %i\n", max_nob);
                debug_buf = format;
                needed = strlen(format);
                mask |= D_ERROR;
                goto out;
        }
        va_start(ap, format);
        needed = vsnprintf(debug_buf, max_nob, format, ap);
        va_end(ap);

        if (needed > max_nob) /* overflow.  oh poop. */
                goto retry;

        header.ph_len = known_size + needed;
        debug_buf = cfs_page_address(tage->page) + tage->used;

        memcpy(debug_buf, &header, sizeof(header));
        tage->used += sizeof(header);
        debug_buf += sizeof(header);

        strcpy(debug_buf, file);
        tage->used += strlen(file) + 1;
        debug_buf += strlen(file) + 1;

        strcpy(debug_buf, fn);
        tage->used += strlen(fn) + 1;
        debug_buf += strlen(fn) + 1;

        tage->used += needed;
        if (tage->used > CFS_PAGE_SIZE)
                printk(KERN_EMERG
                       "tage->used == %u in libcfs_debug_msg\n", tage->used);

 out:
        if ((mask & (D_EMERG | D_ERROR | D_WARNING | D_CONSOLE)) || libcfs_printk)
                print_to_console(&header, mask, debug_buf, needed, file, fn);

        trace_put_tcd(tcd, flags);
}
EXPORT_SYMBOL(libcfs_debug_msg);

void
libcfs_assertion_failed(char *expr, char *file, 
                        const char *func, const int line)
{
        libcfs_debug_msg(0, D_EMERG, file, func, line, CDEBUG_STACK,
                         "ASSERTION(%s) failed\n", expr);
        LBUG();
}
EXPORT_SYMBOL(libcfs_assertion_failed);

static void collect_pages_on_cpu(void *info)
{
        struct trace_cpu_data *tcd;
        unsigned long flags;
        struct page_collection *pc = info;

        tcd = trace_get_tcd(flags);

        spin_lock(&pc->pc_lock);
        list_splice(&tcd->tcd_pages, &pc->pc_pages);
        CFS_INIT_LIST_HEAD(&tcd->tcd_pages);
        tcd->tcd_cur_pages = 0;
        if (pc->pc_want_daemon_pages) {
                list_splice(&tcd->tcd_daemon_pages, &pc->pc_pages);
                CFS_INIT_LIST_HEAD(&tcd->tcd_pages);
                tcd->tcd_cur_daemon_pages = 0;
        }
        spin_unlock(&pc->pc_lock);

        trace_put_tcd(tcd, flags);
}

static void collect_pages(struct page_collection *pc)
{
        /* needs to be fixed up for preempt */
        CFS_INIT_LIST_HEAD(&pc->pc_pages);
        collect_pages_on_cpu(pc);
        smp_call_function(collect_pages_on_cpu, pc, 0, 1);
}

static void put_pages_back_on_cpu(void *info)
{
        struct page_collection *pc = info;
        struct trace_cpu_data *tcd;
        struct list_head *cur_head;
        unsigned long flags;
        struct trace_page *tage;
        struct trace_page *tmp;

        tcd = trace_get_tcd(flags);

        cur_head = tcd->tcd_pages.next;

        spin_lock(&pc->pc_lock);
        list_for_each_entry_safe(tage, tmp, &pc->pc_pages, linkage) {

                LASSERT(tage_invariant(tage));

                if (tage->cpu != smp_processor_id())
                        continue;

                tage_to_tail(tage, cur_head);
                tcd->tcd_cur_pages++;
        }
        spin_unlock(&pc->pc_lock);

        trace_put_tcd(tcd, flags);
}

static void put_pages_back(struct page_collection *pc)
{
        /* needs to be fixed up for preempt */
        put_pages_back_on_cpu(pc);
        smp_call_function(put_pages_back_on_cpu, pc, 0, 1);
}

/* Add pages to a per-cpu debug daemon ringbuffer.  This buffer makes sure that
 * we have a good amount of data at all times for dumping during an LBUG, even
 * if we have been steadily writing (and otherwise discarding) pages via the
 * debug daemon. */
static void put_pages_on_daemon_list_on_cpu(void *info)
{
        struct page_collection *pc = info;
        struct trace_cpu_data *tcd;
        struct trace_page *tage;
        struct trace_page *tmp;
        unsigned long flags;

        tcd = trace_get_tcd(flags);

        spin_lock(&pc->pc_lock);
        list_for_each_entry_safe(tage, tmp, &pc->pc_pages, linkage) {

                LASSERT(tage_invariant(tage));

                if (tage->cpu != smp_processor_id())
                        continue;

                tage_to_tail(tage, &tcd->tcd_daemon_pages);
                tcd->tcd_cur_daemon_pages++;

                if (tcd->tcd_cur_daemon_pages > tcd->tcd_max_pages) {
                        struct trace_page *victim;

                        LASSERT(!list_empty(&tcd->tcd_daemon_pages));
                        victim = tage_from_list(tcd->tcd_daemon_pages.next);

                        LASSERT(tage_invariant(victim));

                        list_del(&victim->linkage);
                        tage_free(victim);
                        tcd->tcd_cur_daemon_pages--;
                }
        }
        spin_unlock(&pc->pc_lock);

        trace_put_tcd(tcd, flags);
}

static void put_pages_on_daemon_list(struct page_collection *pc)
{
        put_pages_on_daemon_list_on_cpu(pc);
        smp_call_function(put_pages_on_daemon_list_on_cpu, pc, 0, 1);
}

void trace_debug_print(void)
{
        struct page_collection pc;
        struct trace_page *tage;
        struct trace_page *tmp;

        spin_lock_init(&pc.pc_lock);

        collect_pages(&pc);
        list_for_each_entry_safe(tage, tmp, &pc.pc_pages, linkage) {
                char *p, *file, *fn;
                cfs_page_t *page;

                LASSERT(tage_invariant(tage));

                page = tage->page;
                p = cfs_page_address(page);
                while (p < ((char *)cfs_page_address(page) + CFS_PAGE_SIZE)) {
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
        CFS_DECL_MMSPACE;
        int rc;

        down_write(&tracefile_sem);

        filp = cfs_filp_open(filename,
                             O_CREAT|O_EXCL|O_WRONLY|O_LARGEFILE, 0600, &rc);
        if (!filp) {
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

                LASSERT(tage_invariant(tage));

                rc = cfs_filp_write(filp, cfs_page_address(tage->page),
                                    tage->used, cfs_filp_poff(filp));
                if (rc != tage->used) {
                        printk(KERN_WARNING "wanted to write %u but wrote "
                               "%d\n", tage->used, rc);
                        put_pages_back(&pc);
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
        up_write(&tracefile_sem);
        return rc;
}

void trace_flush_pages(void)
{
        struct page_collection pc;
        struct trace_page *tage;
        struct trace_page *tmp;

        spin_lock_init(&pc.pc_lock);

        collect_pages(&pc);
        list_for_each_entry_safe(tage, tmp, &pc.pc_pages, linkage) {

                LASSERT(tage_invariant(tage));

                list_del(&tage->linkage);
                tage_free(tage);
        }
}

int trace_dk(struct file *file, const char *buffer, unsigned long count,
             void *data)
{
        char *name;
        unsigned long off;
        int rc;

        name = cfs_alloc(count + 1, CFS_ALLOC_STD);
        if (name == NULL)
                return -ENOMEM;

        if (copy_from_user(name, buffer, count)) {
                rc = -EFAULT;
                goto out;
        }

        if (name[0] != '/') {
                rc = -EINVAL;
                goto out;
        }

        /* be nice and strip out trailing '\n' */
        for (off = count ; off > 2 && isspace(name[off - 1]); off--)
                ;

        name[off] = '\0';
        rc = tracefile_dump_all_pages(name);
out:
        if (name)
                cfs_free(name);
        return count;
}
EXPORT_SYMBOL(trace_dk);

static int tracefiled(void *arg)
{
        struct page_collection pc;
        struct tracefiled_ctl *tctl = arg;
        struct trace_page *tage;
        struct trace_page *tmp;
        struct ptldebug_header *hdr;
        cfs_file_t *filp;
        CFS_DECL_MMSPACE;
        int rc;

        /* we're started late enough that we pick up init's fs context */
        /* this is so broken in uml?  what on earth is going on? */
        libcfs_daemonize("ktracefiled");
        reparent_to_init();

        spin_lock_init(&pc.pc_lock);
        complete(&tctl->tctl_start);

        while (1) {
                cfs_waitlink_t __wait;

                cfs_waitlink_init(&__wait);
                cfs_waitq_add(&tctl->tctl_waitq, &__wait);
                set_current_state(TASK_INTERRUPTIBLE);
                cfs_waitq_timedwait(&__wait, cfs_time_seconds(1));
                cfs_waitq_del(&tctl->tctl_waitq, &__wait);

                if (atomic_read(&tctl->tctl_shutdown))
                        break;

                pc.pc_want_daemon_pages = 0;
                collect_pages(&pc);
                if (list_empty(&pc.pc_pages))
                        continue;

                filp = NULL;
                down_read(&tracefile_sem);
                if (tracefile != NULL) {
                        filp = cfs_filp_open(tracefile, O_CREAT|O_RDWR|O_LARGEFILE,
                                        0600, &rc);
                        if (!(filp))
                                printk("couldn't open %s: %d\n", tracefile, rc);
                }
                up_read(&tracefile_sem);
                if (filp == NULL) {
                        put_pages_on_daemon_list(&pc);
                        continue;
                }

                CFS_MMSPACE_OPEN;

                /* mark the first header, so we can sort in chunks */
                tage = tage_from_list(pc.pc_pages.next);
                LASSERT(tage_invariant(tage));

                hdr = cfs_page_address(tage->page);
                hdr->ph_flags |= PH_FLAG_FIRST_RECORD;

                list_for_each_entry_safe(tage, tmp, &pc.pc_pages, linkage) {
                        static loff_t f_pos;

                        LASSERT(tage_invariant(tage));

                        if (f_pos >= tracefile_size)
                                f_pos = 0;
                        else if (f_pos > cfs_filp_size(filp))
                                f_pos = cfs_filp_size(filp);

                        rc = cfs_filp_write(filp, cfs_page_address(tage->page),
                                            tage->used, &f_pos);
                        if (rc != tage->used) {
                                printk(KERN_WARNING "wanted to write %u but "
                                       "wrote %d\n", tage->used, rc);
                                put_pages_back(&pc);
                        }
                }
                CFS_MMSPACE_CLOSE;

                cfs_filp_close(filp);
                put_pages_on_daemon_list(&pc);
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
                printk(KERN_INFO "Shutting down debug daemon thread...\n");
                atomic_set(&tctl->tctl_shutdown, 1);
                wait_for_completion(&tctl->tctl_stop);
                thread_running = 0;
        }
        mutex_up(&trace_thread_sem);
}

int tracefile_init(void)
{
        struct trace_cpu_data *tcd;
        int i;

        for (i = 0; i < NR_CPUS; i++) {
                tcd = &trace_data[i].tcd;
                CFS_INIT_LIST_HEAD(&tcd->tcd_pages);
                CFS_INIT_LIST_HEAD(&tcd->tcd_daemon_pages);
                tcd->tcd_cur_pages = 0;
                tcd->tcd_cur_daemon_pages = 0;
                tcd->tcd_max_pages = TCD_MAX_PAGES;
                tcd->tcd_shutting_down = 0;
        }
        return 0;
}

static void trace_cleanup_on_cpu(void *info)
{
        struct trace_cpu_data *tcd;
        struct trace_page *tage;
        struct trace_page *tmp;
        unsigned long flags;

        tcd = trace_get_tcd(flags);

        tcd->tcd_shutting_down = 1;

        list_for_each_entry_safe(tage, tmp, &tcd->tcd_pages, linkage) {
                LASSERT(tage_invariant(tage));

                list_del(&tage->linkage);
                tage_free(tage);
        }
        tcd->tcd_cur_pages = 0;

        trace_put_tcd(tcd, flags);
}

static void trace_cleanup(void)
{
        struct page_collection pc;

        CFS_INIT_LIST_HEAD(&pc.pc_pages);
        spin_lock_init(&pc.pc_lock);

        trace_cleanup_on_cpu(&pc);
        smp_call_function(trace_cleanup_on_cpu, &pc, 0, 1);
}

void tracefile_exit(void)
{
        trace_stop_thread();
        trace_cleanup();
}
