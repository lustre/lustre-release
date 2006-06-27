/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/osd/osd_oi.c
 *  Object Index.
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
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
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>
/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <obd.h>
#include <obd_support.h>

/* fid_is_local() */
#include <lustre_fid.h>

#include "osd_oi.h"
/* osd_lookup(), struct osd_thread_info */
#include "osd_internal.h"

static struct lu_fid *oi_fid_key(struct osd_thread_info *info,
                                 const struct lu_fid *fid);
static const char osd_oi_dirname[] = "oi";

int osd_oi_init(struct osd_oi *oi, struct dentry *root, struct lu_site *site)
{
        int result;

        oi->oi_dir = osd_open(root, osd_oi_dirname, S_IFDIR);
        if (IS_ERR(oi->oi_dir)) {
                result = PTR_ERR(oi->oi_dir);
                oi->oi_dir = NULL;
        } else {
                result = 0;
                init_rwsem(&oi->oi_lock);
                oi->oi_site = site;
        }
        return result;
}

void osd_oi_fini(struct osd_oi *oi)
{
        if (oi->oi_dir != NULL) {
                dput(oi->oi_dir);
                oi->oi_dir = NULL;
        }
}

void osd_oi_read_lock(struct osd_oi *oi)
{
        down_read(&oi->oi_lock);
}

void osd_oi_read_unlock(struct osd_oi *oi)
{
        up_read(&oi->oi_lock);
}

void osd_oi_write_lock(struct osd_oi *oi)
{
        down_write(&oi->oi_lock);
}

void osd_oi_write_unlock(struct osd_oi *oi)
{
        up_write(&oi->oi_lock);
}

static struct lu_fid *oi_fid_key(struct osd_thread_info *info,
                                 const struct lu_fid *fid)
{
        fid_to_le(&info->oti_fid, fid);
        return &info->oti_fid;
}

/****************************************************************************
 * XXX prototype.
 ****************************************************************************/

#if OI_IN_MEMORY
struct oi_entry {
        struct lu_fid       oe_key;
        struct osd_inode_id oe_rec;
        struct list_head    oe_linkage;
};

static CFS_LIST_HEAD(oi_head);

static struct oi_entry *oi_lookup(const struct lu_fid *fid)
{
        struct oi_entry *entry;

        list_for_each_entry(entry, &oi_head, oe_linkage) {
                if (lu_fid_eq(fid, &entry->oe_key))
                        return entry;
        }
        return NULL;
}

/*
 * Locking: requires at least read lock on oi.
 */
int osd_oi_lookup(struct osd_thread_info *info, struct osd_oi *oi,
                  const struct lu_fid *fid, struct osd_inode_id *id)
{
        struct oi_entry *entry;
        int result;

        LASSERT(fid_is_local(oi->oi_site, fid));
        entry = oi_lookup(fid);
        if (entry != NULL) {
                *id = entry->oe_rec;
                result = 0;
        } else
                result = -ENOENT;
        return result;
}

/*
 * Locking: requires write lock on oi.
 */
int osd_oi_insert(struct osd_thread_info *info, struct osd_oi *oi,
                  const struct lu_fid *fid, const struct osd_inode_id *id,
                  struct thandle *th)
{
        struct oi_entry *entry;
        int result;

        LASSERT(fid_is_local(oi->oi_site, fid));
        entry = oi_lookup(fid);
        if (entry == NULL) {
                OBD_ALLOC_PTR(entry);
                if (entry != NULL) {
                        entry->oe_key = *fid;
                        entry->oe_rec = *id;
                        list_add(&entry->oe_linkage, &oi_head);
                        result = 0;
                } else
                        result = -ENOMEM;
        } else
                result = -EEXIST;
        return result;
}

/*
 * Locking: requires write lock on oi.
 */
int osd_oi_delete(struct osd_thread_info *info,
                  struct osd_oi *oi, const struct lu_fid *fid,
                  struct thandle *th)
{
        struct oi_entry *entry;
        int result;

        LASSERT(fid_is_local(oi->oi_site, fid));
        entry = oi_lookup(fid);
        if (entry != NULL) {
                list_del(&entry->oe_linkage);
                OBD_FREE_PTR(entry);
                result = 0;
        } else
                result = -ENOENT;
        return result;
}

void osd_oi_init0(struct osd_oi *oi, const struct lu_fid *fid,
                  __u64 root_ino, __u32 root_gen)
{
        int result;
        const struct osd_inode_id root_id = {
                .oii_ino = root_ino,
                .oii_gen = root_gen
        };

        result = osd_oi_insert(NULL, oi, fid, &root_id, NULL);
        LASSERT(result == 0);
}

int osd_oi_find_fid(struct osd_oi *oi, __u64 ino, __u32 gen, struct lu_fid *fid)
{
        struct oi_entry *entry;
        int result;

        result = -ENOENT;
        osd_oi_read_lock(oi);
        list_for_each_entry(entry, &oi_head, oe_linkage) {
                if (entry->oe_rec.oii_ino == ino &&
                    entry->oe_rec.oii_gen == gen) {
                        *fid = entry->oe_key;
                        result = 0;
                        LASSERT(fid_is_local(oi->oi_site, fid));
                        break;
                }
        }
        osd_oi_read_unlock(oi);
        return result;
}

/* OI_IN_MEMORY */
#else

/*
 * Locking: requires at least read lock on oi.
 */
int osd_oi_lookup(struct osd_thread_info *info, struct osd_oi *oi,
                  const struct lu_fid *fid, struct osd_inode_id *id)
{
        id->oii_ino = fid_seq(fid);
        id->oii_gen = fid_oid(fid);
        return 0;
}

/*
 * Locking: requires write lock on oi.
 */
int osd_oi_insert(struct osd_thread_info *info, struct osd_oi *oi,
                  const struct lu_fid *fid, const struct osd_inode_id *id,
                  struct thandle *th)
{
        LASSERT(id->oii_ino == fid_seq(fid));
        LASSERT(id->oii_gen == fid_oid(fid));
        return 0;
}

/*
 * Locking: requires write lock on oi.
 */
int osd_oi_delete(struct osd_thread_info *info,
                  struct osd_oi *oi, const struct lu_fid *fid,
                  struct thandle *th)
{
        return 0;
}

/* OI_IN_MEMORY */
#endif
