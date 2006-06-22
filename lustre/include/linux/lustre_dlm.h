/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * (visit-tags-table FILE)
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _LINUX_LUSTRE_DLM_H__
#define _LINUX_LUSTRE_DLM_H__

#ifndef _LUSTRE_DLM_H__
#error Do not #include this file directly. #include <lprocfs_status.h> instead
#endif

#ifdef __KERNEL__
# include <linux/proc_fs.h>
# ifdef HAVE_BIT_SPINLOCK_H
#  include <linux/bit_spinlock.h>
# endif
#endif

#endif
