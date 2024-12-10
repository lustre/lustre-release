// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_RPC

#include <obd.h>
#include <obd_support.h>
#include <obd_class.h>
#include <lustre_lib.h>
#include <lustre_ha.h>
#include <lustre_net.h>
#include <lprocfs_status.h>

struct uuid_nid_data {
	struct list_head	un_list;
	struct obd_uuid		un_uuid;
	int			un_nid_count;
	struct lnet_nid		un_nids[MTI_NIDS_MAX];
};

/* FIXME: This should probably become more elegant than a global linked list */
static LIST_HEAD(g_uuid_list);
static DEFINE_SPINLOCK(g_uuid_lock);

int lustre_uuid_to_peer(const char *uuid, struct lnet_nid *peer_nid, int index)
{
	struct uuid_nid_data *data;
	struct obd_uuid tmp;
	int rc = -ENOENT;

	obd_str2uuid(&tmp, uuid);
	spin_lock(&g_uuid_lock);
	list_for_each_entry(data, &g_uuid_list, un_list) {
		if (obd_uuid_equals(&data->un_uuid, &tmp)) {
			if (index >= data->un_nid_count)
				break;

			rc = 0;
			*peer_nid = data->un_nids[index];
			break;
		}
	}
	spin_unlock(&g_uuid_lock);
	return rc;
}
EXPORT_SYMBOL(lustre_uuid_to_peer);

/* Add a nid to a niduuid.  Multiple nids can be added to a single uuid;
   LNET will choose the best one. */
int class_add_uuid(const char *uuid, struct lnet_nid *nid)
{
	struct uuid_nid_data *data, *entry;
	int found = 0;
	int rc;

	LASSERT(nid->nid_type != 0);  /* valid newconfig NID is never zero */

	if (strlen(uuid) > UUID_MAX - 1)
		return -EOVERFLOW;

	OBD_ALLOC_PTR(data);
	if (data == NULL)
		return -ENOMEM;

	obd_str2uuid(&data->un_uuid, uuid);
	data->un_nids[0] = *nid;
	data->un_nid_count = 1;

	spin_lock(&g_uuid_lock);
	list_for_each_entry(entry, &g_uuid_list, un_list) {
		if (obd_uuid_equals(&entry->un_uuid, &data->un_uuid)) {
			int i;

			found = 1;
			for (i = 0; i < entry->un_nid_count; i++)
				if (nid_same(nid, &entry->un_nids[i]))
					break;

			if (i == entry->un_nid_count) {
				LASSERT(entry->un_nid_count < MTI_NIDS_MAX);
				entry->un_nids[entry->un_nid_count++] = *nid;
			}
			break;
		}
	}
	if (!found)
		list_add(&data->un_list, &g_uuid_list);
	spin_unlock(&g_uuid_lock);

	if (found) {
		CDEBUG(D_INFO, "found uuid %s %s cnt=%d\n", uuid,
		       libcfs_nidstr(nid), entry->un_nid_count);
		rc = LNetAddPeer(entry->un_nids, entry->un_nid_count);
		CDEBUG(D_INFO, "Add peer %s rc = %d\n",
		       libcfs_nidstr(&data->un_nids[0]), rc);
		OBD_FREE(data, sizeof(*data));
	} else {
		CDEBUG(D_INFO, "add uuid %s %s\n", uuid, libcfs_nidstr(nid));
		rc = LNetAddPeer(data->un_nids, data->un_nid_count);
		CDEBUG(D_INFO, "Add peer %s rc = %d\n",
		       libcfs_nidstr(&data->un_nids[0]), rc);
	}

	return 0;
}
EXPORT_SYMBOL(class_add_uuid);

/* Delete the nids for one uuid if specified, otherwise delete all */
int class_del_uuid(const char *uuid)
{
	struct uuid_nid_data *data;
	LIST_HEAD(deathrow);

	spin_lock(&g_uuid_lock);
	if (uuid != NULL) {
		struct obd_uuid tmp;

		obd_str2uuid(&tmp, uuid);
		list_for_each_entry(data, &g_uuid_list, un_list) {
			if (obd_uuid_equals(&data->un_uuid, &tmp)) {
				list_move(&data->un_list, &deathrow);
				break;
			}
		}
	} else
		list_splice_init(&g_uuid_list, &deathrow);
	spin_unlock(&g_uuid_lock);

	if (uuid != NULL && list_empty(&deathrow)) {
		CDEBUG(D_INFO, "Try to delete a non-existent uuid %s\n", uuid);
		return -EINVAL;
	}

	while ((data = list_first_entry_or_null(&deathrow, struct uuid_nid_data,
						un_list)) != NULL) {
		list_del(&data->un_list);

		CDEBUG(D_INFO, "del uuid %s %s/%d\n",
		       obd_uuid2str(&data->un_uuid),
		       libcfs_nidstr(&data->un_nids[0]),
		       data->un_nid_count);

		OBD_FREE(data, sizeof(*data));
	}
	return 0;
}

int class_add_nids_to_uuid(struct obd_uuid *uuid, struct lnet_nid *nidlist,
			   int nid_count, int nid_size)
{
	struct uuid_nid_data *entry;
	int i, rc;
	bool matched = false;

	ENTRY;

	if (nid_count > MTI_NIDS_MAX) {
		CDEBUG(D_NET, "too many NIDs (%d) for UUID '%s'\n",
			nid_count, obd_uuid2str(uuid));
		return -ENOSPC;
	}

	spin_lock(&g_uuid_lock);
	list_for_each_entry(entry, &g_uuid_list, un_list) {
		CDEBUG(D_NET, "Comparing %s with %s\n",
		       obd_uuid2str(uuid), obd_uuid2str(&entry->un_uuid));

		if (!obd_uuid_equals(&entry->un_uuid, uuid))
			continue;

		matched = true;
		entry->un_nid_count = 0;
		CDEBUG(D_NET, "Updating UUID '%s'\n", obd_uuid2str(uuid));
		for (i = 0; i < nid_count; i++) {
			if (NID_BYTES(&nidlist[i]) > nid_size)
				continue;

			memset(&entry->un_nids[entry->un_nid_count], 0,
			       sizeof(entry->un_nids[entry->un_nid_count]));
			memcpy(&entry->un_nids[entry->un_nid_count],
			       &nidlist[i], nid_size);
			entry->un_nid_count++;
		}
		break;
	}
	spin_unlock(&g_uuid_lock);
	if (matched) {
		rc = LNetAddPeer(entry->un_nids, entry->un_nid_count);
		CDEBUG(D_INFO, "Add peer %s rc = %d\n",
		       libcfs_nidstr(&entry->un_nids[0]), rc);
	}

	RETURN(0);
}
EXPORT_SYMBOL(class_add_nids_to_uuid);

/* check if @nid exists in nid list of @uuid */
int class_check_uuid(struct obd_uuid *uuid, struct lnet_nid *nid)
{
	struct uuid_nid_data *entry;
	int found = 0;

	ENTRY;

	CDEBUG(D_INFO, "check if uuid %s has %s.\n",
	       obd_uuid2str(uuid), libcfs_nidstr(nid));

	spin_lock(&g_uuid_lock);
	list_for_each_entry(entry, &g_uuid_list, un_list) {
		int i;

		if (!obd_uuid_equals(&entry->un_uuid, uuid))
			continue;

		/* found the uuid, check if it has @nid */
		for (i = 0; i < entry->un_nid_count; i++) {
			if (nid_same(&entry->un_nids[i], nid)) {
				found = 1;
				break;
			}
		}
		break;
	}
	spin_unlock(&g_uuid_lock);
	RETURN(found);
}
EXPORT_SYMBOL(class_check_uuid);
