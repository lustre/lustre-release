/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
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
 *
 * Basic Lustre library routines.
 *
 */

#ifndef _LINUX_LUSTRE_LIB_H
#define _LINUX_LUSTRE_LIB_H

#ifndef _LUSTRE_LIB_H
#error Do not #include this file directly. #include <lustre_lib.h> instead
#endif

#ifndef __KERNEL__
# include <string.h>
# include <sys/types.h>
#else
# include <asm/semaphore.h>
# include <linux/rwsem.h>
# include <linux/sched.h>
# include <linux/signal.h>
# include <linux/types.h>
#endif
#include <linux/lustre_compat25.h>

#ifndef LP_POISON
#if BITS_PER_LONG > 32
# define LI_POISON ((int)0x5a5a5a5a5a5a5a5a)
# define LL_POISON ((long)0x5a5a5a5a5a5a5a5a)
# define LP_POISON ((void *)(long)0x5a5a5a5a5a5a5a5a)
#else
# define LI_POISON ((int)0x5a5a5a5a)
# define LL_POISON ((long)0x5a5a5a5a)
# define LP_POISON ((void *)(long)0x5a5a5a5a)
#endif
#endif

#define OBD_IOC_DATA_TYPE               long

#define LUSTRE_FATAL_SIGS (sigmask(SIGKILL) | sigmask(SIGINT) |                \
                           sigmask(SIGTERM) | sigmask(SIGQUIT) |               \
                           sigmask(SIGALRM))

#ifdef __KERNEL__
static inline sigset_t l_w_e_set_sigs(int sigs)
{
        sigset_t old;
        unsigned long irqflags;

        SIGNAL_MASK_LOCK(current, irqflags);
        old = current->blocked;
        siginitsetinv(&current->blocked, sigs);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, irqflags);

        return old;
}
#endif

#ifdef __KERNEL__
/* initialize ost_lvb according to inode */
static inline void inode_init_lvb(struct inode *inode, struct ost_lvb *lvb)
{
        lvb->lvb_size = i_size_read(inode);
        lvb->lvb_blocks = inode->i_blocks;
        lvb->lvb_mtime = LTIME_S(inode->i_mtime);
        lvb->lvb_atime = LTIME_S(inode->i_atime);
        lvb->lvb_ctime = LTIME_S(inode->i_ctime);
}
#else
/* defined in liblustre/llite_lib.h */
#endif

#endif /* _LUSTRE_LIB_H */

