/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_RPC

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/init.h>
# include <linux/list.h>
#else
# include <liblustre.h>
#endif
#include <linux/obd.h>
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_net.h>
#include <linux/lprocfs_status.h>

struct uuid_nid_data {
        struct list_head head;
        ptl_nid_t nid;
        char *uuid;
        __u32 nal;
};

/* FIXME: This should probably become more elegant than a global linked list */
static struct list_head g_uuid_list;
static spinlock_t       g_uuid_lock;

void class_init_uuidlist(void)
{
        INIT_LIST_HEAD(&g_uuid_list);
        spin_lock_init(&g_uuid_lock);
}

void class_exit_uuidlist(void)
{
        /* delete all */
        class_del_uuid(NULL);
}

int lustre_uuid_to_peer(char *uuid, __u32 *peer_nal, ptl_nid_t *peer_nid)
{
        struct list_head *tmp;

        spin_lock (&g_uuid_lock);

        list_for_each(tmp, &g_uuid_list) {
                struct uuid_nid_data *data =
                        list_entry(tmp, struct uuid_nid_data, head);

                if (strcmp(data->uuid, uuid) == 0) {
                        *peer_nid = data->nid;
                        *peer_nal = data->nal;

                        spin_unlock (&g_uuid_lock);
                        return 0;
                }
        }

        spin_unlock (&g_uuid_lock);
        return -1;
}

int class_add_uuid(char *uuid, __u64 nid, __u32 nal)
{
        struct uuid_nid_data *data;
        int rc;
        int nob = strnlen (uuid, PAGE_SIZE) + 1;

        if (nob > PAGE_SIZE)
                return -EINVAL;

        rc = -ENOMEM;
        OBD_ALLOC(data, sizeof(*data));
        if (data == NULL)
                return -ENOMEM;

        OBD_ALLOC(data->uuid, nob);
        if (data == NULL) {
                OBD_FREE(data, sizeof(*data));
                return -ENOMEM;
        }

        CDEBUG(D_INFO, "add uuid %s "LPX64" %u\n", uuid, nid, nal);
        memcpy(data->uuid, uuid, nob);
        data->nid = nid;
        data->nal = nal;

        spin_lock (&g_uuid_lock);

        list_add(&data->head, &g_uuid_list);

        spin_unlock (&g_uuid_lock);

        return 0;
}

/* delete only one entry if uuid is specified, otherwise delete all */
int class_del_uuid (char *uuid)
{
        struct list_head  deathrow;
        struct list_head *tmp;
        struct list_head *n;
        struct uuid_nid_data *data;

        INIT_LIST_HEAD (&deathrow);

        spin_lock (&g_uuid_lock);

        list_for_each_safe(tmp, n, &g_uuid_list) {
                data = list_entry(tmp, struct uuid_nid_data, head);

                if (uuid == NULL || strcmp(data->uuid, uuid) == 0) {
                        list_del (&data->head);
                        list_add (&data->head, &deathrow);
                        if (uuid)
                                break;
                }
        }

        spin_unlock (&g_uuid_lock);

        if (list_empty (&deathrow))
                return -EINVAL;

        do {
                data = list_entry(deathrow.next, struct uuid_nid_data, head);

                list_del (&data->head);

                OBD_FREE(data->uuid, strlen(data->uuid) + 1);
                OBD_FREE(data, sizeof(*data));
        } while (!list_empty (&deathrow));

        return 0;
}
