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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/rwsem.h>
#include <linux/proc_fs.h>
#include <linux/file.h>
#include <linux/smp.h>
#include <linux/ctype.h>
#include <asm/uaccess.h>
#ifdef HAVE_MM_INLINE
#include <linux/mm_inline.h>
#endif

#define DEBUG_SUBSYSTEM S_PORTALS

#include <linux/kp30.h>
#include <linux/portals_compat25.h>
#include <linux/libcfs.h>

#define TCD_MAX_PAGES 1280

/* XXX move things up to the top, comment */

static union {
        struct trace_cpu_data {
                struct list_head        tcd_pages;
                unsigned long           tcd_cur_pages;

                struct list_head        tcd_daemon_pages;
                unsigned long           tcd_cur_daemon_pages;

                unsigned long           tcd_max_pages;
                int                     tcd_shutting_down;
        } tcd;
        char __pad[SMP_CACHE_BYTES];
} trace_data[NR_CPUS] __cacheline_aligned;

struct page_collection {
        struct list_head        pc_pages;
        spinlock_t              pc_lock;
        int                     pc_want_daemon_pages;
};

struct tracefiled_ctl {
        struct completion        tctl_start;
        struct completion        tctl_stop;
        wait_queue_head_t        tctl_waitq;
        pid_t                    tctl_pid;
        atomic_t                 tctl_shutdown;
};

static DECLARE_RWSEM(tracefile_sem);
static char *tracefile = NULL;
static struct tracefiled_ctl trace_tctl;
static DECLARE_MUTEX(trace_thread_sem);
static int thread_running = 0;

#ifndef get_cpu
#define get_cpu() smp_processor_id()
#define put_cpu() do { } while (0)
#endif

#define trace_get_tcd(FLAGS) ({                 \
        struct trace_cpu_data *__ret;           \
        int __cpu = get_cpu();                  \
        local_irq_save(FLAGS);                  \
        __ret = &trace_data[__cpu].tcd;         \
        __ret;                                  \
})

#define trace_put_tcd(TCD, FLAGS) do {          \
        local_irq_restore(FLAGS);               \
        put_cpu();                              \
} while (0)

static void put_pages_on_daemon_list_on_cpu(void *info);

/* return a page that has 'len' bytes left at the end */
static struct page *trace_get_page(struct trace_cpu_data *tcd,
                                   unsigned long len)
{
        struct page *page = NULL;

        if (len > PAGE_SIZE) {
                printk(KERN_ERR "cowardly refusing to write %lu bytes in a "
                       "page\n", len);
                return NULL;
        }

        if (!list_empty(&tcd->tcd_pages)) {
                page = list_entry(tcd->tcd_pages.prev, struct page,
                                  PAGE_LIST_ENTRY);
                if (page->index + len <= PAGE_SIZE)
                        return page;
        }

        if (tcd->tcd_cur_pages < tcd->tcd_max_pages) {
                page = alloc_page(GFP_ATOMIC);
                if (page == NULL) {
                        /* the kernel should print a message for us.  fall back
                         * to using the last page in the ring buffer. */
                        goto ring_buffer;
                        return NULL;
                }
                page->index = 0;
                page->mapping = (void *)smp_processor_id();
                list_add_tail(&PAGE_LIST(page), &tcd->tcd_pages);
                tcd->tcd_cur_pages++;

                if (tcd->tcd_cur_pages > 8 && thread_running) {
                        struct tracefiled_ctl *tctl = &trace_tctl;
                        wake_up(&tctl->tctl_waitq);
                }
                return page;
        }

 ring_buffer:
        if (thread_running) {
                int pgcount = tcd->tcd_cur_pages / 10;
                struct page_collection pc;
                struct list_head *pos, *tmp;
                printk(KERN_WARNING "debug daemon buffer overflowed; discarding"
                       " 10%% of pages (%d)\n", pgcount + 1);

                INIT_LIST_HEAD(&pc.pc_pages);
                spin_lock_init(&pc.pc_lock);

                list_for_each_safe(pos, tmp, &tcd->tcd_pages) {
                        struct page *page;

                        if (pgcount-- == 0)
                                break;

                        page = list_entry(pos, struct page, PAGE_LIST_ENTRY);
                        list_del(&PAGE_LIST(page));
                        list_add_tail(&PAGE_LIST(page), &pc.pc_pages);
                        tcd->tcd_cur_pages--;
                }
                put_pages_on_daemon_list_on_cpu(&pc);
        }
        LASSERT(!list_empty(&tcd->tcd_pages));

        page = list_entry(tcd->tcd_pages.next, struct page, PAGE_LIST_ENTRY);
        page->index = 0;

        list_del(&PAGE_LIST(page));
        list_add_tail(&PAGE_LIST(page), &tcd->tcd_pages);
        return page;
}

static void print_to_console(struct ptldebug_header *hdr, int mask, char *buf,
                             int len, char *file, const char *fn)
{
        char *prefix = NULL, *ptype = NULL;

        if ((mask & D_EMERG) != 0) {
                prefix = "LustreError";
                ptype = KERN_EMERG;
        } else if ((mask & D_ERROR) != 0) {
                prefix = "LustreError";
                ptype = KERN_ERR;
        } else if ((mask & D_WARNING) != 0) {
                prefix = "Lustre";
                ptype = KERN_WARNING;
        } else if (portal_printk) {
                prefix = "Lustre";
                ptype = KERN_INFO;
        }

        printk("%s%s: %d:%d:(%s:%d:%s()) %*s", ptype, prefix, hdr->ph_pid,
               hdr->ph_extern_pid, file, hdr->ph_line_num, fn, len, buf);
}

void portals_debug_msg(int subsys, int mask, char *file, const char *fn,
                       const int line, unsigned long stack, char *format, ...)
{
        struct trace_cpu_data *tcd;
        struct ptldebug_header header;
        struct page *page;
        char *debug_buf;
        int known_size, needed, max_nob;
        va_list       ap;
        unsigned long flags;
        struct timeval tv;

        if (*(format + strlen(format) - 1) != '\n')
                printk(KERN_INFO "format at %s:%d:%s doesn't end in newline\n",
                       file, line, fn);

        tcd = trace_get_tcd(flags);
        if (tcd->tcd_shutting_down)
                goto out;

        do_gettimeofday(&tv);

        header.ph_subsys = subsys;
        header.ph_mask = mask;
        header.ph_cpu_id = smp_processor_id();
        header.ph_sec = (__u32)tv.tv_sec;
        header.ph_usec = tv.tv_usec;
        header.ph_stack = stack;
        header.ph_pid = current->pid;
        header.ph_line_num = line;

#if defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,20))
        header.ph_extern_pid = current->thread.extern_pid;
#elif defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        header.ph_extern_pid = current->thread.mode.tt.extern_pid;
#else
        header.ph_extern_pid = 0;
#endif

        known_size = sizeof(header) + strlen(file) + strlen(fn) + 2; // nulls

        page = trace_get_page(tcd, known_size + 40); /* slop */
 retry:
        if (page == NULL)
                goto out;

        debug_buf = page_address(page) + page->index + known_size;

        va_start(ap, format);
        max_nob = PAGE_SIZE - page->index - known_size;
        LASSERT(max_nob > 0);
        needed = vsnprintf(debug_buf, max_nob, format, ap);
        va_end(ap);

        if (needed > max_nob) {
                /* overflow.  oh poop. */
                page = trace_get_page(tcd, needed + known_size);
                goto retry;
        }

        header.ph_len = known_size + needed;
        debug_buf = page_address(page) + page->index;

        memcpy(debug_buf, &header, sizeof(header));
        page->index += sizeof(header);
        debug_buf += sizeof(header);

        strcpy(debug_buf, file);
        page->index += strlen(file) + 1;
        debug_buf += strlen(file) + 1;

        strcpy(debug_buf, fn);
        page->index += strlen(fn) + 1;
        debug_buf += strlen(fn) + 1;

        page->index += needed;
        if (page->index > PAGE_SIZE)
                printk(KERN_EMERG "page->index == %lu in portals_debug_msg\n",
                       page->index);

        if ((mask & (D_EMERG | D_ERROR | D_WARNING)) || portal_printk)
                print_to_console(&header, mask, debug_buf, needed, file, fn);

 out:
        trace_put_tcd(tcd, flags);
}
EXPORT_SYMBOL(portals_debug_msg);

static void collect_pages_on_cpu(void *info)
{
        struct trace_cpu_data *tcd;
        unsigned long flags;
        struct page_collection *pc = info;

        tcd = trace_get_tcd(flags);

        spin_lock(&pc->pc_lock);
        list_splice(&tcd->tcd_pages, &pc->pc_pages);
        INIT_LIST_HEAD(&tcd->tcd_pages);
        tcd->tcd_cur_pages = 0;
        if (pc->pc_want_daemon_pages) {
                list_splice(&tcd->tcd_daemon_pages, &pc->pc_pages);
                INIT_LIST_HEAD(&tcd->tcd_daemon_pages);
                tcd->tcd_cur_daemon_pages = 0;
        }
        spin_unlock(&pc->pc_lock);

        trace_put_tcd(tcd, flags);
}

static void collect_pages(struct page_collection *pc)
{
        /* needs to be fixed up for preempt */
        INIT_LIST_HEAD(&pc->pc_pages);
        collect_pages_on_cpu(pc);
        smp_call_function(collect_pages_on_cpu, pc, 0, 1);
}

static void put_pages_back_on_cpu(void *info)
{
        struct page_collection *pc = info;
        struct trace_cpu_data *tcd;
        struct list_head *pos, *tmp, *cur_head;
        unsigned long flags;

        tcd = trace_get_tcd(flags);

        cur_head = tcd->tcd_pages.next;

        spin_lock(&pc->pc_lock);
        list_for_each_safe(pos, tmp, &pc->pc_pages) {
                struct page *page;

                page = list_entry(pos, struct page, PAGE_LIST_ENTRY);
                LASSERT(page->index <= PAGE_SIZE);
                LASSERT(page_count(page) > 0);

                if ((unsigned long)page->mapping != smp_processor_id())
                        continue;

                list_del(&PAGE_LIST(page));
                list_add_tail(&PAGE_LIST(page), cur_head);
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
        struct list_head *pos, *tmp;
        unsigned long flags;

        tcd = trace_get_tcd(flags);

        spin_lock(&pc->pc_lock);
        list_for_each_safe(pos, tmp, &pc->pc_pages) {
                struct page *page;

                page = list_entry(pos, struct page, PAGE_LIST_ENTRY);
                LASSERT(page->index <= PAGE_SIZE);
                LASSERT(page_count(page) > 0);
                if ((unsigned long)page->mapping != smp_processor_id())
                        continue;

                list_del(&PAGE_LIST(page));
                list_add_tail(&PAGE_LIST(page), &tcd->tcd_daemon_pages);
                tcd->tcd_cur_daemon_pages++;

                if (tcd->tcd_cur_daemon_pages > tcd->tcd_max_pages) {
                        LASSERT(!list_empty(&tcd->tcd_daemon_pages));
                        page = list_entry(tcd->tcd_daemon_pages.next,
                                          struct page, PAGE_LIST_ENTRY);

                        LASSERT(page->index <= PAGE_SIZE);
                        LASSERT(page_count(page) > 0);

                        page->index = 0;
                        list_del(&PAGE_LIST(page));
                        page->mapping = NULL;
                        __free_page(page);
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
        struct list_head *pos, *tmp;

        spin_lock_init(&pc.pc_lock);

        collect_pages(&pc);
        list_for_each_safe(pos, tmp, &pc.pc_pages) {
                struct page *page;
                char *p, *file, *fn;

                page = list_entry(pos, struct page, PAGE_LIST_ENTRY);
                LASSERT(page->index <= PAGE_SIZE);
                LASSERT(page_count(page) > 0);

                p = page_address(page);
                while (p < ((char *)page_address(page) + PAGE_SIZE)) {
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

                list_del(&PAGE_LIST(page));
                page->mapping = NULL;
                __free_page(page);
        }
}

int tracefile_dump_all_pages(char *filename)
{
        struct page_collection pc;
        struct file *filp;
        struct list_head *pos, *tmp;
        mm_segment_t oldfs;
        int rc;

        down_write(&tracefile_sem);

        filp = filp_open(filename, O_CREAT|O_EXCL|O_RDWR, 0600);
        if (IS_ERR(filp)) {
                rc = PTR_ERR(filp);
                printk(KERN_ERR "couldn't open %s: %d\n", filename, rc);
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
        oldfs = get_fs();
        set_fs(get_ds());
        list_for_each_safe(pos, tmp, &pc.pc_pages) {
                struct page *page;

                page = list_entry(pos, struct page, PAGE_LIST_ENTRY);
                LASSERT(page->index <= PAGE_SIZE);
                LASSERT(page_count(page) > 0);

                rc = filp->f_op->write(filp, page_address(page), page->index,
                                       &filp->f_pos);
                if (rc != page->index) {
                        printk(KERN_WARNING "wanted to write %lu but wrote "
                               "%d\n", page->index, rc);
                        put_pages_back(&pc);
                        break;
                }
                list_del(&PAGE_LIST(page));
                page->mapping = NULL;
                __free_page(page);
        }
        set_fs(oldfs);
        rc = filp->f_op->fsync(filp, filp->f_dentry, 1);
        if (rc)
                printk(KERN_ERR "sync returns %d\n", rc);
 close:
        filp_close(filp, 0);
 out:
        up_write(&tracefile_sem);
        return rc;
}

void trace_flush_pages(void)
{
        struct page_collection pc;
        struct list_head *pos, *tmp;

        spin_lock_init(&pc.pc_lock);

        collect_pages(&pc);
        list_for_each_safe(pos, tmp, &pc.pc_pages) {
                struct page *page;

                page = list_entry(pos, struct page, PAGE_LIST_ENTRY);
                LASSERT(page->index <= PAGE_SIZE);
                LASSERT(page_count(page) > 0);

                list_del(&PAGE_LIST(page));
                page->mapping = NULL;
                __free_page(page);
        }
}

int trace_dk(struct file *file, const char *buffer, unsigned long count,
             void *data)
{
        char *name;
        unsigned long off;
        int rc;

        name = kmalloc(count + 1, GFP_KERNEL);
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
                kfree(name);
        return count;
}
EXPORT_SYMBOL(trace_dk);

static int tracefiled(void *arg)
{
        struct page_collection pc;
        struct tracefiled_ctl *tctl = arg;
        struct list_head *pos, *tmp;
        struct ptldebug_header *hdr;
        struct file *filp;
        struct page *page;
        mm_segment_t oldfs;
        int rc;

        /* we're started late enough that we pick up init's fs context */
        /* this is so broken in uml?  what on earth is going on? */
        kportal_daemonize("ktracefiled");
        reparent_to_init();

        spin_lock_init(&pc.pc_lock);
        complete(&tctl->tctl_start);

        while (1) {
                wait_queue_t __wait;

                init_waitqueue_entry(&__wait, current);
                add_wait_queue(&tctl->tctl_waitq, &__wait);
                set_current_state(TASK_INTERRUPTIBLE);
                schedule_timeout(HZ);
                remove_wait_queue(&tctl->tctl_waitq, &__wait);

                if (atomic_read(&tctl->tctl_shutdown))
                        break;

                pc.pc_want_daemon_pages = 0;
                collect_pages(&pc);
                if (list_empty(&pc.pc_pages))
                        continue;

                filp = NULL;
                down_read(&tracefile_sem);
                if (tracefile != NULL) {
                        filp = filp_open(tracefile, O_CREAT|O_RDWR|O_APPEND,
                                        0600);
                        if (IS_ERR(filp)) {
                                printk("couldn't open %s: %ld\n", tracefile,
                                       PTR_ERR(filp));
                                filp = NULL;
                        }
                }
                up_read(&tracefile_sem);
                if (filp == NULL) {
                        put_pages_on_daemon_list(&pc);
                        continue;
                }

                oldfs = get_fs();
                set_fs(get_ds());

                /* mark the first header, so we can sort in chunks */
                page = list_entry(pc.pc_pages.next, struct page,
                                  PAGE_LIST_ENTRY);
                LASSERT(page->index <= PAGE_SIZE);
                LASSERT(page_count(page) > 0);

                hdr = page_address(page);
                hdr->ph_flags |= PH_FLAG_FIRST_RECORD;

                list_for_each_safe(pos, tmp, &pc.pc_pages) {
                        page = list_entry(pos, struct page, PAGE_LIST_ENTRY);
                        LASSERT(page->index <= PAGE_SIZE);
                        LASSERT(page_count(page) > 0);

                        rc = filp->f_op->write(filp, page_address(page),
                                        page->index, &filp->f_pos);
                        if (rc != page->index) {
                                printk(KERN_WARNING "wanted to write %lu but "
                                       "wrote %d\n", page->index, rc);
                                put_pages_back(&pc);
                        }
                }
                set_fs(oldfs);
                filp_close(filp, 0);

                put_pages_on_daemon_list(&pc);
        }
        complete(&tctl->tctl_stop);
        return 0;
}

int trace_start_thread(void)
{
        struct tracefiled_ctl *tctl = &trace_tctl;
        int rc = 0;

        down(&trace_thread_sem);
        if (thread_running)
                goto out;

        init_completion(&tctl->tctl_start);
        init_completion(&tctl->tctl_stop);
        init_waitqueue_head(&tctl->tctl_waitq);
        atomic_set(&tctl->tctl_shutdown, 0);

        if (kernel_thread(tracefiled, tctl, 0) < 0) {
                rc = -ECHILD;
                goto out;
        }

        wait_for_completion(&tctl->tctl_start);
        thread_running = 1;
out:
        up(&trace_thread_sem);
        return rc;
}

void trace_stop_thread(void)
{
        struct tracefiled_ctl *tctl = &trace_tctl;

        down(&trace_thread_sem);
        if (thread_running) {
                printk(KERN_INFO "Shutting down debug daemon thread...\n");
                atomic_set(&tctl->tctl_shutdown, 1);
                wait_for_completion(&tctl->tctl_stop);
                thread_running = 0;
        }
        up(&trace_thread_sem);
}

int trace_write_daemon_file(struct file *file, const char *buffer,
                            unsigned long count, void *data)
{
        char *name;
        unsigned long off;
        int rc;

        name = kmalloc(count + 1, GFP_KERNEL);
        if (name == NULL)
                return -ENOMEM;

        if (copy_from_user(name, buffer, count)) {
                rc = -EFAULT;
                goto out;
        }

        /* be nice and strip out trailing '\n' */
        for (off = count ; off > 2 && isspace(name[off - 1]); off--)
                ;

        name[off] = '\0';

        down_write(&tracefile_sem);
        if (strcmp(name, "stop") == 0) {
                tracefile = NULL;
                trace_stop_thread();
                goto out_sem;
        }

        if (name[0] != '/') {
                rc = -EINVAL;
                goto out_sem;
        }

        if (tracefile != NULL)
                kfree(tracefile);

        tracefile = name;
        name = NULL;
        trace_start_thread();

 out_sem:
        up_write(&tracefile_sem);

 out:
        if (name)
                kfree(name);
        return count;
}

int trace_read_daemon_file(char *page, char **start, off_t off, int count,
                           int *eof, void *data)
{
        int rc;

        down_read(&tracefile_sem);
        rc = snprintf(page, count, "%s", tracefile);
        up_read(&tracefile_sem);

        return rc;
}

int trace_write_debug_size(struct file *file, const char *buffer,
                           unsigned long count, void *data)
{
        char *string;
        int rc, i, max;

        string = kmalloc(count + 1, GFP_KERNEL);
        if (string == NULL)
                return -ENOMEM;

        if (copy_from_user(string, buffer, count)) {
                rc = -EFAULT;
                goto out;
        }

        max = simple_strtoul(string, NULL, 16);

        for (i = 0; i < NR_CPUS; i++) {
                struct trace_cpu_data *tcd;
                tcd = &trace_data[i].tcd;
                tcd->tcd_max_pages = max;
        }
 out:
        kfree(string);
        return count;
}

int trace_read_debug_size(char *page, char **start, off_t off, int count,
                          int *eof, void *data)
{
        struct trace_cpu_data *tcd;
        unsigned long flags;
        int rc;

        tcd = trace_get_tcd(flags);
        rc = snprintf(page, count, "%lu", tcd->tcd_max_pages);
        trace_put_tcd(tcd, flags);

        return rc;
}

int tracefile_init(void)
{
        struct trace_cpu_data *tcd;
        int i;

        for (i = 0; i < NR_CPUS; i++) {
                tcd = &trace_data[i].tcd;
                INIT_LIST_HEAD(&tcd->tcd_pages);
                INIT_LIST_HEAD(&tcd->tcd_daemon_pages);
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
        struct list_head *pos, *tmp;
        unsigned long flags;

        tcd = trace_get_tcd(flags);

        tcd->tcd_shutting_down = 1;

        list_for_each_safe(pos, tmp, &tcd->tcd_pages) {
                struct page *page;

                page = list_entry(pos, struct page, PAGE_LIST_ENTRY);
                LASSERT(page->index <= PAGE_SIZE);
                LASSERT(page_count(page) > 0);

                list_del(&PAGE_LIST(page));
                page->mapping = NULL;
                __free_page(page);
        }
        tcd->tcd_cur_pages = 0;

        trace_put_tcd(tcd, flags);
}

static void trace_cleanup(void)
{
        struct page_collection pc;

        INIT_LIST_HEAD(&pc.pc_pages);
        spin_lock_init(&pc.pc_lock);

        trace_cleanup_on_cpu(&pc);
        smp_call_function(trace_cleanup_on_cpu, &pc, 0, 1);
}

void tracefile_exit(void)
{
        trace_stop_thread();
        trace_cleanup();
}
