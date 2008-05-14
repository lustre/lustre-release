/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
 */

#define DEBUG_SUBSYSTEM S_RPC

#ifndef __KERNEL__
# include <liblustre.h>
#endif
#include <obd.h>
#include <obd_support.h>
#include <obd_class.h>
#include <lustre_lib.h>
#include <lustre_ha.h>
#include <lustre_net.h>
#include <lprocfs_status.h>

struct uuid_nid_data {
        struct list_head un_list;
        lnet_nid_t       un_nid;
        char            *un_uuid;
        int              un_count;  /* nid/uuid pair refcount */
};

/* FIXME: This should probably become more elegant than a global linked list */
static struct list_head g_uuid_list;
static spinlock_t       g_uuid_lock;

void class_init_uuidlist(void)
{
        CFS_INIT_LIST_HEAD(&g_uuid_list);
        spin_lock_init(&g_uuid_lock);
}

void class_exit_uuidlist(void)
{
        /* delete all */
        class_del_uuid(NULL);
}

int lustre_uuid_to_peer(const char *uuid, lnet_nid_t *peer_nid, int index)
{
        struct list_head *tmp;

        spin_lock (&g_uuid_lock);

        list_for_each(tmp, &g_uuid_list) {
                struct uuid_nid_data *data =
                        list_entry(tmp, struct uuid_nid_data, un_list);

                if (!strcmp(data->un_uuid, uuid) &&
                    index-- == 0) {
                        *peer_nid = data->un_nid;

                        spin_unlock (&g_uuid_lock);
                        return 0;
                }
        }

        spin_unlock (&g_uuid_lock);
        return -ENOENT;
}

/* Add a nid to a niduuid.  Multiple nids can be added to a single uuid;
   LNET will choose the best one. */
int class_add_uuid(const char *uuid, __u64 nid)
{
        struct uuid_nid_data *data, *entry;
        int nob = strnlen (uuid, CFS_PAGE_SIZE) + 1;
        int found = 0;

        LASSERT(nid != 0);  /* valid newconfig NID is never zero */

        if (nob > CFS_PAGE_SIZE)
                return -EINVAL;

        OBD_ALLOC(data, sizeof(*data));
        if (data == NULL)
                return -ENOMEM;

        OBD_ALLOC(data->un_uuid, nob);
        if (data == NULL) {
                OBD_FREE(data, sizeof(*data));
                return -ENOMEM;
        }

        memcpy(data->un_uuid, uuid, nob);
        data->un_nid = nid;
        data->un_count = 1;

        spin_lock (&g_uuid_lock);

        list_for_each_entry(entry, &g_uuid_list, un_list) {
                if (entry->un_nid == nid && 
                    (strcmp(entry->un_uuid, uuid) == 0)) {
                        found++;
                        entry->un_count++;
                        break;
                }
        }
        if (!found) 
                list_add(&data->un_list, &g_uuid_list);
        spin_unlock (&g_uuid_lock);

        if (found) {
                CDEBUG(D_INFO, "found uuid %s %s cnt=%d\n", uuid, 
                       libcfs_nid2str(nid), entry->un_count);
                OBD_FREE(data->un_uuid, nob);
                OBD_FREE(data, sizeof(*data));
        } else {
                CDEBUG(D_INFO, "add uuid %s %s\n", uuid, libcfs_nid2str(nid));
        }
        return 0;
}

/* Delete the nids for one uuid if specified, otherwise delete all */
int class_del_uuid(const char *uuid)
{
        CFS_LIST_HEAD(deathrow);
        struct uuid_nid_data *data;
        int found = 0;

        spin_lock (&g_uuid_lock);
        if (uuid == NULL) {
                list_splice_init(&g_uuid_list, &deathrow);
                found = 1;
        } else {
                list_for_each_entry(data, &g_uuid_list, un_list) {
                        if (strcmp(data->un_uuid, uuid))
                                continue;
                        --data->un_count;
                        LASSERT(data->un_count >= 0);
                        if (data->un_count == 0)
                                list_move(&data->un_list, &deathrow);
                        found = 1;
                        break;
                }
        }
        spin_unlock (&g_uuid_lock);

        if (!found) {
                if (uuid)
                        CERROR("Try to delete a non-existent uuid %s\n", uuid);
                return -EINVAL;
        }

        while (!list_empty(&deathrow)) {
                data = list_entry(deathrow.next, struct uuid_nid_data, un_list);
                list_del(&data->un_list);

                CDEBUG(D_INFO, "del uuid %s %s\n", data->un_uuid,
                       libcfs_nid2str(data->un_nid));

                OBD_FREE(data->un_uuid, strlen(data->un_uuid) + 1);
                OBD_FREE(data, sizeof(*data));
        }

        return 0;
}
