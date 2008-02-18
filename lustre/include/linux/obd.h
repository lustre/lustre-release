/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef __LINUX_OBD_H
#define __LINUX_OBD_H

#ifndef __OBD_H
#error Do not #include this file directly. #include <obd.h> instead
#endif

#ifdef __KERNEL__
# include <linux/fs.h>
# include <linux/list.h>
# include <linux/sched.h> /* for struct task_struct, for current.h */
# include <asm/current.h> /* for smp_lock.h */
# include <linux/smp_lock.h>
# include <linux/proc_fs.h>
# include <linux/mount.h>
#endif

typedef spinlock_t client_obd_lock_t;

static inline void client_obd_list_lock_init(client_obd_lock_t *lock)
{
        spin_lock_init(lock);
}

static inline void client_obd_list_lock_done(client_obd_lock_t *lock)
{}

static inline void client_obd_list_lock(client_obd_lock_t *lock)
{
        spin_lock(lock);
}

static inline void client_obd_list_unlock(client_obd_lock_t *lock)
{
        spin_unlock(lock);
}

#if defined(__KERNEL__) && !defined(HAVE_ADLER)
/* zlib_adler() is an inline function defined in zutil.h */
#define HAVE_ADLER
#endif
#endif /* __LINUX_OBD_H */
