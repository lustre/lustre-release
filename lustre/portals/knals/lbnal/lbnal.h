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
 * Basic library routines. 
 *
 */

#ifndef _LBNAL_H
#define _LBNAL_H
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/uio.h>

#define DEBUG_SUBSYSTEM S_LBNAL

#include <linux/kp30.h>
#include <portals/p30.h>
#include <portals/lib-p30.h>
#include <portals/nal.h>

#define KLBD_IOV        153401
#define KLBD_KIOV       153402

typedef struct
{
        unsigned int     klbd_type;
        unsigned int     klbd_niov;
        size_t           klbd_offset;
        size_t           klbd_nob;
        union {
                struct iovec  *iov;
                ptl_kiov_t    *kiov;
        }                klbd_iov;
                
} klb_desc_t;

typedef struct
{
        char               klb_init;            /* what's been initialised */
}  klbnal_data_t;

/* kqn_init state */
#define KLB_INIT_NOTHING        0               /* MUST BE ZERO so zeroed state is initialised OK */
#define KLB_INIT_LIB            1
#define KLB_INIT_ALL            2

extern lib_nal_t           klbnal_lib;
extern nal_t               klbnal_api;
extern klbnal_data_t       klbnal_data;

#endif /* _LBNAL_H */
