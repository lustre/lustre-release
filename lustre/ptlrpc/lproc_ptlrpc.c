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
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/lustre_lite.h>
#include <linux/lprocfs_status.h>

int rd_uuid(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        int len=0;
        len+=snprintf(page, count, "%s\n", 
                      ((struct obd_device*)data)->obd_uuid);
        return len;

}

struct lprocfs_vars status_var_nm_1[]={
        {"status/uuid", rd_uuid, 0},
        {0}
};
int rd_numdevices(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        struct obd_type* class=(struct obd_type*)data;
        int len=0;
        len+=snprintf(page, count, "%d\n", class->typ_refcnt);
        return len;
}

struct lprocfs_vars status_class_var[]={
        {"status/num_devices", rd_numdevices, 0},
        {0}
};
