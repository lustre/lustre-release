/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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
 */

#ifndef _OBD_FILTER_H
#define _OBD_FILTER_H

#ifndef OBD_FILTER_DEVICENAME
#define OBD_FILTER_DEVICENAME "obdfilter"
#endif

/* In-memory access to client data from OST struct */
struct filter_export_data {
        struct list_head  fed_open_head; /* files to close on disconnect */
        spinlock_t        fed_lock;      /* protects fed_open_head */
};

/* file data for open files on OST */
struct filter_file_data {
        struct list_head  ffd_export_list;  /* export open list - fed_lock */
        struct file      *ffd_file;         /* file handle */
        __u64             ffd_servercookie; /* cookie for lustre handle */
};

struct filter_dentry_data {
        atomic_t         fdd_open_count;
        int              fdd_flags;
};

#define FILTER_FLAG_DESTROY 0x0001      /* destroy dentry on last file close */

#endif
