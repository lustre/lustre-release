/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Phil Schwan <phil@clusterfs.com>
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2.1 of the GNU Lesser General
 *   Public License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define EXPORT_SYMTAB

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/notifier.h>
#include <linux/kernel.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <linux/interrupt.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/completion.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/miscdevice.h>

# define DEBUG_SUBSYSTEM S_PORTALS

#include <linux/kp30.h>

#define DEBUG_OVERFLOW 1024
static char *debug_buf = NULL;
static unsigned long debug_size = 0;
static atomic_t debug_off_a = ATOMIC_INIT(0);
static int debug_wrapped;
wait_queue_head_t debug_ctlwq;
#define DAEMON_SND_SIZE      (64 << 10)

/*
 * used by the daemon to keep track the offset into debug_buffer for the next
 * write to the file.  Usually, the daemon is to write out buffer
 * from debug_daemon_next_write upto debug_off
 *  variable usage
 *      Reader - portals_debug_msg()
 *      Writer - portals_debug_daemon()
 *               portals_debug_daemon_start() during daemon init time
 *               portals_debug_daemon_continue() to reset to debug_off
 *               portals_debug_clear_buffer() reset to debug_off for clear
 *      Note that *_start(), *_continue() & *clear_buffer() should serialized;
 */
static atomic_t   debug_daemon_next_write;

/*
 * A debug_daemon can be in following states
 *      stopped - stopped state means there is no debug_daemon running.
 *                accordingly, it must be in paused state
 *                a daemon is in !stopped && !paused state after
 *                "lctl debug_daemon start" creates debug_daemon successfully
 *                Variable Usage
 *                      Reader - portals_debug_daemon()
 *                               portals_debug_set_daemon() routines
 *                      Writer - portals_debug_set_daemon() routines
 *                              portals_debug_daemon() on IO error
 *      paused -  a debug_daemon state is changed from !paused into paused
 *                when "lctl debug_daemon paused" is issued
 *                "lctl debug_daemon continue" gets a daemon into !paused mode
 *                      Reader - portals_debug_set_daemon() routines
 *                               portals_debug_msg()
 *                      Writer - portals_debug_set_daemon() on init
 *                               portals_debug_daemon()
 *
 *        Daemon  state diagram.
 *                      (stopped, paused)
 *                              |  <-- debug_daemon start
 *                              V
 *                      (!stopped, !paused)
 *                              |  <-- debug_daemon pause
 *                              V
 *                      (!stopped, paused)
 *                              |  <-- debug_daemon continue
 *                              V
 *                      (!stopped, !paused)
 *                              |  <-- debug_daemon stop
 *                              V
 *                      (stopped, paused)
 *      Overlapped - this is a state when CDEBUG is too fast for the daemon to
 *                   write out the debug_bufferr.  That is, debug_off is to
 *                   overlap debug_daemon_next_write;
 *                     Reader - portals_debug_msg()
 *                     Writer - portals_debug_msg()
 */

/*
 * Description on Trace Daemon Synchronization
 *
 * Three categories of code are synchronizing between each other
 * 1.   lctl, portals_debug_set_daemon(), the user debug control code, 
 *      as well as portals_debug_clear_buffer()
 * 2.   CDEBUG, portals_debug_msg(), the debug put messages routine
 * 3.   Daemon, portals_debug_daemon(), to write out debug log file
 *
 *
 * Three different controls for synchronizations
 *
 * 1.   debug_daemon_semaphore
 *      The usage of this semaphore is to serialize multiple lctl controls 
 *      in manipulating debug daemon state.  The semaphore serves as the 
 *      gatekeeper to allow only one user control thread, at any giving time, 
 *      to access debug daemon state and keeps the other user control requests 
 *      in wait state until the current control request is serviced.
 *
 * 2.   wait_queue_head_t lctl (paired with lctl_event flag)
 *      Lctl event is the event between portals_debug_set_daemon() and 
 *      portals_debug_daemon().  Lctl is an indicator for portals_debug_daemon()
 *      to flush data out to file.  portals_debug_daemon() is to use lctl event
 *      as signal channel to wakeup portals_debug_set_daemon() upon flush 
 *      operation is done.
 *
 *      Producer :
 *              portals_debug_daemon() uses to wake up 
 *              portals_debug_set_daemon(), pause and stop, routines
 *      Consumer :
 *              portals_debug_set_daemon(), stop and pause operations, 
 *              wait and sleep on the event
 *
 * 3.   wait_queue_head_t daemon (paired with daemon_event flag)
 *      This is an event channel to wakeup portals_debug_daemon.  Daemon 
 *      wakes up to run whenever there is an event posted.   Daemon handles 
 *      2 types of operations . 1. Writes data out to debug file, 2. Flushes 
 *      file and terminates base on lctl event. 
 *      File operation -
 *              Daemon is normally in a sleep state.  
 *              Daemon is woken up through daemon event whenever CDEBUG is 
 *              putting data over any 64K boundary. 
 *      File flush and termination -
 *              On portals_debug_daemon_stop/pause() operations, lctl control 
 *              is to wake up daemon through daemon event.
 *
 *      We can't use sleep_on() and wake_up() to replace daemon event because 
 *      portals_debug_daemon() must catch the wakeup operation posted by 
 *      portals_debug_daemon_stop/pause().  Otherwise, stop and pause may 
 *      stuck in lctl wait event.
 *
 *      Producer :
 *           a. portals_debug_daemon_pause() and portals_debug_daemon_stop() 
 *              uses the event to wake up portals_debug_daemon()
 *           b. portals_debug_msg() uses the event to wake up 
 *              portals_debug_daemon() whenever the data output is acrossing 
 *              a 64K bytes boundary.
 *      Consumer :
 *              portals_debug_daemon() wakes up upon daemon event.
 *
 * Sequence for portals_debug_daemon_stop() operation
 *
 * _Portals_debug_daemon_stop()_          _Daemon_
 *                                      Wait_event(daemon) or running
 *      Paused = 1;
 *      Wakeup_event (daemon)
 *      Wait_event(lctl)
 *                                      Set force_flush flag if lctlevnt
 *                                      Flush data
 *                                      Wakeup_event (lctl)
 *                                      Wait_event(daemon)
 *      Stopped = 1;
 *      Wakeup_event (daemon)
 *      Wait_event(lctl)
 *                                      Exit daemon loop if (Stopped)
 *                                      Wakeup_event (lctl)
 *                                      Exit
 *      Return to user application
 *
 *
 * _Portals_debug_msg()_                  _Daemon_
 *                                      Wait_event(daemon) or running
 *      If (WriteStart<64K<WriteEnd)
 *         Wakeup_event(daemon)
 *                                      Do file IO
 *                                      Wait_event(daemon)
 */
struct debug_daemon_state {
        unsigned long overlapped;
        unsigned long stopped;
        atomic_t paused;
        unsigned long   lctl_event;     /* event for lctl */
        wait_queue_head_t lctl;
        unsigned long   daemon_event;   /* event for daemon */
        wait_queue_head_t daemon;
};
static struct debug_daemon_state debug_daemon_state;
static DECLARE_MUTEX(debug_daemon_semaphore);

static loff_t daemon_file_size_limit;
char debug_daemon_file_path[1024] = "";

spinlock_t portals_debug_lock = SPIN_LOCK_UNLOCKED;
char debug_file_path[1024] = "/tmp/lustre-log";
char debug_file_name[1024];
int handled_panic; /* to avoid recursive calls to notifiers */
char portals_upcall[1024] = "/usr/lib/lustre/portals_upcall";


int portals_do_debug_dumplog(void *arg)
{
        struct file *file;
        void *journal_info;
        int rc;
        mm_segment_t oldfs;
        unsigned long debug_off;

        kportal_daemonize("");

        reparent_to_init();
        journal_info = current->journal_info;
        current->journal_info = NULL;
        sprintf(debug_file_name, "%s.%ld", debug_file_path, CURRENT_TIME);
        file = filp_open(debug_file_name, O_CREAT|O_TRUNC|O_RDWR, 0644);

        if (!file || IS_ERR(file)) {
                CERROR("cannot open %s for dumping: %ld\n", debug_file_name,
                       PTR_ERR(file));
                GOTO(out, PTR_ERR(file));
        } else {
                printk(KERN_ALERT "dumping log to %s ... writing ...\n",
                       debug_file_name);
        }

        debug_off = atomic_read(&debug_off_a);
        oldfs = get_fs();
        set_fs(get_ds());
        if (debug_wrapped) {
                rc = file->f_op->write(file, debug_buf + debug_off + 1,
                                       debug_size-debug_off-1, &file->f_pos);
                rc += file->f_op->write(file, debug_buf, debug_off + 1,
                                        &file->f_pos);
        } else {
                rc = file->f_op->write(file, debug_buf, debug_off,&file->f_pos);
        }
        printk("wrote %d bytes\n", rc);
        set_fs(oldfs);

        rc = file->f_op->fsync(file, file->f_dentry, 1);
        if (rc)
                CERROR("sync returns %d\n", rc);
        filp_close(file, 0);
out:
        current->journal_info = journal_info;
        wake_up(&debug_ctlwq);
        return 0;
}

int portals_debug_daemon(void *arg)
{
        struct file *file;
        void *journal_info;
        mm_segment_t oldfs;
        unsigned long force_flush = 0;
        unsigned long size, off, flags;
        int rc;

        kportal_daemonize("ldebug_daemon");
        reparent_to_init();
        journal_info = current->journal_info;
        current->journal_info = NULL;

        file = filp_open(debug_daemon_file_path,
                         O_CREAT|O_TRUNC|O_RDWR|O_LARGEFILE, 0644);

        if (!file || IS_ERR(file)) {
                CERROR("cannot open %s for logging", debug_daemon_file_path);
                GOTO(out1, PTR_ERR(file));
        } else {
                printk(KERN_ALERT "daemon dumping log to %s ... writing ...\n",
                       debug_daemon_file_path);
        }

        debug_daemon_state.overlapped = 0;
        debug_daemon_state.stopped = 0;

        spin_lock_irqsave(&portals_debug_lock, flags);
        off = atomic_read(&debug_off_a) + 1;
        if (debug_wrapped)
                off = (off >= debug_size)? 0 : off;
        else
                off = 0;
        atomic_set(&debug_daemon_next_write, off);
        atomic_set(&debug_daemon_state.paused, 0);
        spin_unlock_irqrestore(&portals_debug_lock, flags);

        oldfs = get_fs();
        set_fs(KERNEL_DS);
        while (1) {
                unsigned long ending;
                unsigned long start, tail;
                long delta;

                debug_daemon_state.daemon_event = 0;

                ending = atomic_read(&debug_off_a);
                start = atomic_read(&debug_daemon_next_write);

                /* check if paused is imposed by lctl ? */
                force_flush = !debug_daemon_state.lctl_event;

                delta = ending - start;
                tail = debug_size - start;
                size = (delta >= 0) ? delta : tail;
                while (size && (force_flush || (delta < 0) ||
                                (size >= DAEMON_SND_SIZE))) {
                        if (daemon_file_size_limit) {
                               int ssize = daemon_file_size_limit - file->f_pos;
                               if (size > ssize)
                                        size = ssize;
                        }

                        rc = file->f_op->write(file, debug_buf+start,
                                               size, &file->f_pos);
                        if (rc < 0) {
                                printk(KERN_ALERT
                                           "Debug_daemon write error %d\n", rc);
                                goto out;
                        }
                        start += rc;
                        delta = ending - start;
                        tail = debug_size - start;
                        if (tail == 0)
                                start = 0;
                        if (delta >= 0)
                                size = delta;
                        else
                                size = (tail == 0) ? ending : tail;
                        if (daemon_file_size_limit == file->f_pos) {
                                // file wrapped around
                                file->f_pos = 0;
                        }
                }
                atomic_set(&debug_daemon_next_write, start);
                if (force_flush) {
                        rc = file->f_op->fsync(file, file->f_dentry, 1);
                        if (rc < 0) {
                                printk(KERN_ALERT
                                       "Debug_daemon sync error %d\n", rc);
                                goto out;
                        }
                        if (debug_daemon_state.stopped)
                               break;           
                        debug_daemon_state.lctl_event = 1;
                        wake_up(&debug_daemon_state.lctl);
                }
                wait_event(debug_daemon_state.daemon, 
                           debug_daemon_state.daemon_event);
                }
out:
        atomic_set(&debug_daemon_state.paused, 1);
        debug_daemon_state.stopped = 1;
        set_fs(oldfs);
        filp_close(file, 0);
        current->journal_info = journal_info;
out1:
        debug_daemon_state.lctl_event = 1;
        wake_up(&debug_daemon_state.lctl);
        return 0;
}

void portals_debug_print(void)
{
        unsigned long dumplen = 64 * 1024;
        char *start1, *start2;
        char *end1, *end2;
        unsigned long debug_off = atomic_read(&debug_off_a);

        start1 = debug_buf + debug_off - dumplen;
        if (start1 < debug_buf) {
                start1 += debug_size;
                end1 = debug_buf + debug_size - 1;
                start2 = debug_buf;
                end2 = debug_buf + debug_off;
        } else {
                end1 = debug_buf + debug_off;
                start2 = debug_buf + debug_off;
                end2 = debug_buf + debug_off;
        }

        while (start1 < end1) {
                int count = MIN(1024, end1 - start1);
                printk("%*s", count, start1);
                start1 += 1024;
        }
        while (start2 < end2) {
                int count = MIN(1024, end2 - start2);
                printk("%*s", count, start2);
                start2 += 1024;
        }
}

void portals_debug_dumplog(void)
{
        int rc;
        ENTRY;

        init_waitqueue_head(&debug_ctlwq);

        rc = kernel_thread(portals_do_debug_dumplog,
                           NULL, CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0) {
                printk(KERN_ERR "cannot start dump thread\n");
                return;
        }
        sleep_on(&debug_ctlwq);
}

int portals_debug_daemon_start(char *file, unsigned int size)
{
        int rc;

        if (!debug_daemon_state.stopped)
                return -EALREADY;

        if (file != NULL)
                strncpy(debug_daemon_file_path, file, 1024);

        init_waitqueue_head(&debug_daemon_state.lctl);
        init_waitqueue_head(&debug_daemon_state.daemon);

        daemon_file_size_limit = size << 20;

        debug_daemon_state.lctl_event = 0;
        rc = kernel_thread(portals_debug_daemon, NULL, 0);
        if (rc < 0) {
                printk(KERN_ERR "cannot start debug daemon thread\n");
                strncpy(debug_daemon_file_path, "\0", 1);
                return rc;
        }
        wait_event(debug_daemon_state.lctl, debug_daemon_state.lctl_event);
        return 0;
}

int portals_debug_daemon_pause(void)
{
        if (atomic_read(&debug_daemon_state.paused))
                return -EALREADY;

        atomic_set(&debug_daemon_state.paused, 1);
        debug_daemon_state.lctl_event = 0;
        debug_daemon_state.daemon_event = 1;
        wake_up(&debug_daemon_state.daemon);
        wait_event(debug_daemon_state.lctl, debug_daemon_state.lctl_event);
        return 0;
}

int portals_debug_daemon_continue(void)
{
        if (!atomic_read(&debug_daemon_state.paused))
                return -EINVAL;
        if (debug_daemon_state.stopped)
                return -EINVAL;

        debug_daemon_state.overlapped = 0;
        atomic_set(&debug_daemon_next_write, atomic_read(&debug_off_a));
        atomic_set(&debug_daemon_state.paused, 0);
        return 0;
}

int portals_debug_daemon_stop(void)
{
        if (debug_daemon_state.stopped)
                return -EALREADY;

        if (!atomic_read(&debug_daemon_state.paused))
                portals_debug_daemon_pause();

        debug_daemon_state.lctl_event = 0;
        debug_daemon_state.stopped = 1;

        debug_daemon_state.daemon_event = 1;
        wake_up(&debug_daemon_state.daemon);
        wait_event(debug_daemon_state.lctl, debug_daemon_state.lctl_event);

        debug_daemon_file_path[0] = '\0';
        return 0;
}

int portals_debug_set_daemon(unsigned int cmd, unsigned int length,
                             char *filename, unsigned int size)
{
        int rc = -EINVAL;

        down(&debug_daemon_semaphore);
        switch (cmd) {
                case DEBUG_DAEMON_START:
                        if (length && (filename[length -1] != '\0')) {
                                CERROR("Invalid filename for debug_daemon\n");
                                rc = -EINVAL;
                                break;
                        }
                        rc = portals_debug_daemon_start(filename, size);
                        break;
                case DEBUG_DAEMON_STOP:
                        rc = portals_debug_daemon_stop();
                        break;
                case DEBUG_DAEMON_PAUSE:
                        rc = portals_debug_daemon_pause();
                        break;
                case DEBUG_DAEMON_CONTINUE:
                        rc = portals_debug_daemon_continue();
                        break;
                default:
                        CERROR("unknown set_daemon cmd\n");
        }
        up(&debug_daemon_semaphore);
        return rc;
}

static int panic_dumplog(struct notifier_block *self, unsigned long unused1,
                         void *unused2)
{
        if (handled_panic)
                return 0;
        else
                handled_panic = 1;

        if (in_interrupt()) {
                portals_debug_print();
                return 0;
        }

        while (current->lock_depth >= 0)
                unlock_kernel();
        portals_debug_dumplog();
        return 0;
}

static struct notifier_block lustre_panic_notifier = {
        notifier_call :     panic_dumplog,
        next :              NULL,
        priority :          10000
};

int portals_debug_init(unsigned long bufsize)
{
        unsigned long debug_off = atomic_read(&debug_off_a);
        if (debug_buf != NULL)
                return -EALREADY;

        atomic_set(&debug_daemon_state.paused, 1);
        debug_daemon_state.stopped = 1;

        debug_buf = vmalloc(bufsize + DEBUG_OVERFLOW);
        if (debug_buf == NULL)
                return -ENOMEM;
        memset(debug_buf, 0, debug_size);
        debug_wrapped = 0;

        printk(KERN_INFO "Portals: allocated %lu byte debug buffer at %p.\n",
               bufsize, debug_buf);
        atomic_set(&debug_off_a, debug_off);
        notifier_chain_register(&panic_notifier_list, &lustre_panic_notifier);
        debug_size = bufsize;

        return 0;
}

int portals_debug_cleanup(void)
{
        notifier_chain_unregister(&panic_notifier_list, &lustre_panic_notifier);
        if (debug_buf == NULL)
                return -EINVAL;

        down(&debug_daemon_semaphore);
        portals_debug_daemon_stop();

        vfree(debug_buf);
        atomic_set(&debug_off_a, 0);
        up(&debug_daemon_semaphore);

        return 0;
}

int portals_debug_clear_buffer(void)
{
        unsigned long flags;
        unsigned long state;

        if (debug_buf == NULL)
                return -EINVAL;

        down(&debug_daemon_semaphore);
        state = atomic_read(&debug_daemon_state.paused);
        if (!state)
                portals_debug_daemon_pause();
        spin_lock_irqsave(&portals_debug_lock, flags);
        atomic_set(&debug_off_a, 0);
        debug_wrapped = 0;
        atomic_set(&debug_daemon_next_write, 0);
        debug_daemon_state.overlapped = 0;
        spin_unlock_irqrestore(&portals_debug_lock, flags);

        if (!state)
                atomic_set(&debug_daemon_state.paused, 0);
        up(&debug_daemon_semaphore);

        return 0;
}

/* Debug markers, although printed by S_PORTALS
 * should not be be marked as such.
 */
#undef DEBUG_SUBSYSTEM
#define DEBUG_SUBSYSTEM S_UNDEFINED
int portals_debug_mark_buffer(char *text)
{
        if (debug_buf == NULL)
                return -EINVAL;

        CDEBUG(0, "*******************************************************************************\n");
        CDEBUG(0, "DEBUG MARKER: %s\n", text);
        CDEBUG(0, "*******************************************************************************\n");

        return 0;
}
#undef DEBUG_SUBSYSTEM
#define DEBUG_SUBSYSTEM S_PORTALS

__s32 portals_debug_copy_to_user(char *buf, unsigned long len)
{
        int rc;
        unsigned long debug_off;
        unsigned long flags;

        if (len < debug_size)
                return -ENOSPC;

        debug_off = atomic_read(&debug_off_a);
        spin_lock_irqsave(&portals_debug_lock, flags);
        if (debug_wrapped) {
                /* All of this juggling with the 1s is to keep the trailing nul
                 * (which falls at debug_buf + debug_off) at the end of what we
                 * copy into user space */
                copy_to_user(buf, debug_buf + debug_off + 1,
                             debug_size - debug_off - 1);
                copy_to_user(buf + debug_size - debug_off - 1,
                             debug_buf, debug_off + 1);
                rc = debug_size;
        } else {
                copy_to_user(buf, debug_buf, debug_off);
                rc = debug_off;
        }
        spin_unlock_irqrestore(&portals_debug_lock, flags);

        return rc;
}

/* FIXME: I'm not very smart; someone smarter should make this better. */
void
portals_debug_msg (int subsys, int mask, char *file, char *fn, int line,
                   unsigned long stack, const char *format, ...)
{
        va_list       ap;
        unsigned long flags;
        int           max_nob;
        int           prefix_nob;
        int           msg_nob;
        struct timeval tv;
        unsigned long base_offset;
        unsigned long debug_off;

        if (debug_buf == NULL) {
                printk("portals_debug_msg: debug_buf is NULL!\n");
                return;
        }

        spin_lock_irqsave(&portals_debug_lock, flags);
        debug_off = atomic_read(&debug_off_a);
        if (!atomic_read(&debug_daemon_state.paused)) {
                unsigned long available;
                long delta;
                long v = atomic_read(&debug_daemon_next_write);

                delta = debug_off - v;
                available = (delta>=0) ? debug_size-delta : -delta;
                // Check if we still have enough debug buffer for CDEBUG
                if (available < DAEMON_SND_SIZE) {
                        /* Drop CDEBUG packets until enough debug_buffer is
                         * available */
                        if (debug_daemon_state.overlapped)
                                 goto out;
                        /* If this is the first time, leave a marker in the
                         * output */
                        debug_daemon_state.overlapped = 1;
                        ap = NULL;
                        format = "DEBUG MARKER: Debug buffer overlapped\n";
                } else  /* More space just became available */
                        debug_daemon_state.overlapped = 0;
        }

        max_nob = debug_size - debug_off + DEBUG_OVERFLOW;
        if (max_nob <= 0) {
                spin_unlock_irqrestore(&portals_debug_lock, flags);
                printk("logic error in portals_debug_msg: <0 bytes to write\n");
                return;
        }

        /* NB since we pass a non-zero sized buffer (at least) on the first
         * print, we can be assured that by the end of all the snprinting,
         * we _do_ have a terminated buffer, even if our message got truncated.
         */

        do_gettimeofday(&tv);

        prefix_nob = snprintf(debug_buf + debug_off, max_nob,
                              "%02x:%06x:%d:%lu.%06lu ",
                              subsys >> 24, mask, smp_processor_id(),
                              tv.tv_sec, tv.tv_usec);
        max_nob -= prefix_nob;

#if defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,4,20))
        msg_nob = snprintf(debug_buf + debug_off + prefix_nob, max_nob,
                           "(%s:%d:%s() %d | %d+%lu): ",
                           file, line, fn, current->pid,
                           current->thread.extern_pid, stack);
#elif defined(__arch_um__) && (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        msg_nob = snprintf(debug_buf + debug_off + prefix_nob, max_nob,
                           "(%s:%d:%s() %d | %d+%lu): ",
                           file, line, fn, current->pid,
                           current->thread.mode.tt.extern_pid, stack);
#else
        msg_nob = snprintf(debug_buf + debug_off + prefix_nob, max_nob,
                           "(%s:%d:%s() %d+%lu): ",
                           file, line, fn, current->pid, stack);
#endif
        max_nob -= msg_nob;

        va_start(ap, format);
        msg_nob += vsnprintf(debug_buf + debug_off + prefix_nob + msg_nob,
                            max_nob, format, ap);
        max_nob -= msg_nob;
        va_end(ap);

        /* Print to console, while msg is contiguous in debug_buf */
        /* NB safely terminated see above */
        if ((mask & D_EMERG) != 0)
                printk(KERN_EMERG "%s", debug_buf + debug_off + prefix_nob);
        if ((mask & D_ERROR) != 0)
                printk(KERN_ERR   "%s", debug_buf + debug_off + prefix_nob);
        else if (portal_printk)
                printk("<%d>%s", portal_printk, debug_buf+debug_off+prefix_nob);
        base_offset = debug_off & 0xFFFF;

        debug_off += prefix_nob + msg_nob;
        if (debug_off > debug_size) {
                memcpy(debug_buf, debug_buf + debug_size,
                       debug_off - debug_size + 1);
                debug_off -= debug_size;
                debug_wrapped = 1;
        }

        atomic_set(&debug_off_a, debug_off);
        if (!atomic_read(&debug_daemon_state.paused) &&
            ((base_offset+prefix_nob+msg_nob) >= DAEMON_SND_SIZE)) {
                debug_daemon_state.daemon_event = 1;
                wake_up(&debug_daemon_state.daemon);
        }
out:
        spin_unlock_irqrestore(&portals_debug_lock, flags);
}

void portals_debug_set_level(unsigned int debug_level)
{
        printk("Setting portals debug level to %08x\n", debug_level);
        portal_debug = debug_level;
}

void portals_run_lbug_upcall(char * file, char *fn, int line)
{
        char *argv[6];
        char *envp[3];
        char buf[32];
        int rc;

        ENTRY;
        snprintf (buf, sizeof buf, "%d", line);

        argv[0] = portals_upcall;
        argv[1] = "LBUG";
        argv[2] = file;
        argv[3] = fn;
        argv[4] = buf;
        argv[5] = NULL;

        envp[0] = "HOME=/";
        envp[1] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
        envp[2] = NULL;

        rc = call_usermodehelper(argv[0], argv, envp);
        if (rc < 0) {
                CERROR("Error invoking lbug upcall %s %s %s %s %s: %d; check "
                       "/proc/sys/portals/upcall\n",                
                       argv[0], argv[1], argv[2], argv[3], argv[4], rc);
                
        } else {
                CERROR("Invoked upcall %s %s %s %s %s\n",
                       argv[0], argv[1], argv[2], argv[3], argv[4]);
        }
}


EXPORT_SYMBOL(portals_debug_dumplog);
EXPORT_SYMBOL(portals_debug_msg);
EXPORT_SYMBOL(portals_debug_set_level);
EXPORT_SYMBOL(portals_run_lbug_upcall);
