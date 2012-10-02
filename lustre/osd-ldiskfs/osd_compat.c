/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd/osd_compat.c
 *
 * on-disk compatibility stuff for OST
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 */

/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>
/* prerequisite for linux/xattr.h */
#include <linux/types.h>
/* prerequisite for linux/xattr.h */
#include <linux/fs.h>

/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <obd_support.h>
#include <lvfs.h>

#include "osd_internal.h"
#include "osd_oi.h"

struct osd_compat_objid_seq {
        /* protects on-fly initialization */
        cfs_semaphore_t        dir_init_sem;
        /* file storing last created objid */
        struct osd_inode_id    last_id;
        struct dentry         *groot; /* O/<seq> */
        struct dentry        **dirs;  /* O/<seq>/d0-dXX */
};

#define MAX_OBJID_GROUP (FID_SEQ_ECHO + 1)

struct osd_compat_objid {
        int                          subdir_count;
        struct dentry               *root;
        struct osd_inode_id          last_rcvd_id;
        struct osd_inode_id          last_seq_id;
        struct osd_compat_objid_seq  groups[MAX_OBJID_GROUP];
};

static void osd_push_ctxt(const struct osd_device *dev,
                          struct lvfs_run_ctxt *newctxt,
                          struct lvfs_run_ctxt *save)
{
        OBD_SET_CTXT_MAGIC(newctxt);
        newctxt->pwdmnt = dev->od_mnt;
        newctxt->pwd = dev->od_mnt->mnt_root;
        newctxt->fs = get_ds();

        push_ctxt(save, newctxt, NULL);
}

void osd_compat_seq_fini(struct osd_device *osd, int seq)
{
        struct osd_compat_objid_seq *grp;
        struct osd_compat_objid     *map = osd->od_ost_map;
        int                          i;

        ENTRY;

        grp = &map->groups[seq];
        if (grp->groot ==NULL)
                RETURN_EXIT;
        LASSERT(grp->dirs);

        for (i = 0; i < map->subdir_count; i++) {
                if (grp->dirs[i] == NULL)
                        break;
                dput(grp->dirs[i]);
        }

        OBD_FREE(grp->dirs, sizeof(struct dentry *) * map->subdir_count);
        dput(grp->groot);
        EXIT;
}

int osd_compat_seq_init(struct osd_device *osd, int seq)
{
        struct osd_compat_objid_seq *grp;
        struct osd_compat_objid     *map;
        struct dentry               *d;
        int                          rc = 0;
        char                         name[32];
        int                          i;
        ENTRY;

        map = osd->od_ost_map;
        LASSERT(map);
        LASSERT(map->root);
        grp = &map->groups[seq];

        if (grp->groot != NULL)
                RETURN(0);

        cfs_down(&grp->dir_init_sem);

        sprintf(name, "%d", seq);
        d = simple_mkdir(map->root, osd->od_mnt, name, 0755, 1);
        if (IS_ERR(d)) {
                rc = PTR_ERR(d);
                GOTO(out, rc);
        } else if (d->d_inode == NULL) {
                rc = -EFAULT;
                dput(d);
                GOTO(out, rc);
        }

        LASSERT(grp->dirs == NULL);
        OBD_ALLOC(grp->dirs, sizeof(d) * map->subdir_count);
        if (grp->dirs == NULL) {
                dput(d);
                GOTO(out, rc = -ENOMEM);
        }

        grp->groot = d;
        for (i = 0; i < map->subdir_count; i++) {
                sprintf(name, "d%d", i);
                d = simple_mkdir(grp->groot, osd->od_mnt, name, 0755, 1);
                if (IS_ERR(d)) {
                        rc = PTR_ERR(d);
                        break;
                } else if (d->d_inode == NULL) {
                        rc = -EFAULT;
                        dput(d);
                        break;
                }

                grp->dirs[i] = d;
        }

        if (rc)
                osd_compat_seq_fini(osd, seq);
out:
        cfs_up(&grp->dir_init_sem);
        RETURN(rc);
}

int osd_last_rcvd_subdir_count(struct osd_device *osd)
{
        struct lr_server_data lsd;
        struct dentry        *dlast;
        loff_t                off;
        int                   rc = 0;
	int                   count = FILTER_SUBDIR_COUNT;

        ENTRY;

        dlast = ll_lookup_one_len(LAST_RCVD, osd_sb(osd)->s_root,
                                  strlen(LAST_RCVD));
        if (IS_ERR(dlast))
                return PTR_ERR(dlast);
        else if (dlast->d_inode == NULL)
                goto out;

        off = 0;
        rc = osd_ldiskfs_read(dlast->d_inode, &lsd, sizeof(lsd), &off);
        if (rc == sizeof(lsd)) {
                CDEBUG(D_INFO, "read last_rcvd header, uuid = %s, "
                       "subdir count = %d\n", lsd.lsd_uuid,
                       lsd.lsd_subdir_count);
		if (le16_to_cpu(lsd.lsd_subdir_count) > 0)
			count = le16_to_cpu(lsd.lsd_subdir_count);
	} else if (rc != 0) {
		CERROR("Can't read last_rcvd file, rc = %d\n", rc);
		if (rc > 0)
			rc = -EFAULT;
		dput(dlast);
		return rc;
	}
out:
	dput(dlast);
	LASSERT(count > 0);
	return count;
}

void osd_compat_fini(struct osd_device *dev)
{
        int i;

        ENTRY;

        if (dev->od_ost_map == NULL)
                RETURN_EXIT;

        for (i = 0; i < MAX_OBJID_GROUP; i++)
                osd_compat_seq_fini(dev, i);

        dput(dev->od_ost_map->root);
        OBD_FREE_PTR(dev->od_ost_map);
        dev->od_ost_map = NULL;

        EXIT;
}

/*
 * directory structure on legacy OST:
 *
 * O/<seq>/d0-31/<objid>
 * O/<seq>/LAST_ID
 * last_rcvd
 * LAST_GROUP
 * CONFIGS
 *
 */
int osd_compat_init(struct osd_device *dev)
{
	struct lvfs_run_ctxt  new;
	struct lvfs_run_ctxt  save;
	struct dentry	     *rootd = osd_sb(dev)->s_root;
	struct dentry	     *d;
	int		      rc;
	int		      i;

	ENTRY;

	OBD_ALLOC_PTR(dev->od_ost_map);
	if (dev->od_ost_map == NULL)
		RETURN(-ENOMEM);

	/* to get subdir count from last_rcvd */
	rc = osd_last_rcvd_subdir_count(dev);
	if (rc < 0) {
		OBD_FREE_PTR(dev->od_ost_map);
		RETURN(rc);
	}

        dev->od_ost_map->subdir_count = rc;
        rc = 0;

        LASSERT(dev->od_fsops);
        osd_push_ctxt(dev, &new, &save);

        d = simple_mkdir(rootd, dev->od_mnt, "O", 0755, 1);
        pop_ctxt(&save, &new, NULL);
        if (IS_ERR(d)) {
                OBD_FREE_PTR(dev->od_ost_map);
                RETURN(PTR_ERR(d));
        }

        dev->od_ost_map->root = d;

        /* Initialize all groups */
        for (i = 0; i < MAX_OBJID_GROUP; i++) {
                cfs_sema_init(&dev->od_ost_map->groups[i].dir_init_sem, 1);
                rc = osd_compat_seq_init(dev, i);
                if (rc) {
                        osd_compat_fini(dev);
                        break;
                }
        }

        RETURN(rc);
}

int osd_compat_del_entry(struct osd_thread_info *info, struct osd_device *osd,
                         struct dentry *dird, char *name, struct thandle *th)
{
        struct ldiskfs_dir_entry_2 *de;
        struct buffer_head         *bh;
        struct osd_thandle         *oh;
        struct dentry              *child;
        struct inode               *dir = dird->d_inode;
        int                         rc;

        ENTRY;

        oh = container_of(th, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle != NULL);
        LASSERT(oh->ot_handle->h_transaction != NULL);


        child = &info->oti_child_dentry;
        child->d_name.hash = 0;
        child->d_name.name = name;
        child->d_name.len = strlen(name);
        child->d_parent = dird;
        child->d_inode = NULL;

	mutex_lock(&dir->i_mutex);
	rc = -ENOENT;
	bh = osd_ldiskfs_find_entry(dir, child, &de, NULL);
	if (bh) {
		rc = ldiskfs_delete_entry(oh->ot_handle, dir, de, bh);
		brelse(bh);
	}
	mutex_unlock(&dir->i_mutex);

	RETURN(rc);
}

int osd_compat_add_entry(struct osd_thread_info *info, struct osd_device *osd,
                         struct dentry *dir, char *name,
                         const struct osd_inode_id *id, struct thandle *th)
{
        struct osd_thandle *oh;
        struct dentry *child;
        struct inode *inode;
        int rc;

        ENTRY;

        oh = container_of(th, struct osd_thandle, ot_super);
        LASSERT(oh->ot_handle != NULL);
        LASSERT(oh->ot_handle->h_transaction != NULL);

        inode = &info->oti_inode;
        inode->i_sb = osd_sb(osd);
	osd_id_to_inode(inode, id);

        child = &info->oti_child_dentry;
        child->d_name.hash = 0;
        child->d_name.name = name;
        child->d_name.len = strlen(name);
        child->d_parent = dir;
        child->d_inode = inode;

	mutex_lock(&dir->d_inode->i_mutex);
	rc = osd_ldiskfs_add_entry(oh->ot_handle, child, inode, NULL);
	mutex_unlock(&dir->d_inode->i_mutex);

	RETURN(rc);
}

int osd_compat_objid_lookup(struct osd_thread_info *info,
                            struct osd_device *dev, const struct lu_fid *fid,
                            struct osd_inode_id *id)
{
        struct osd_compat_objid    *map;
        struct dentry              *d;
        struct dentry              *d_seq;
        struct ost_id              *ostid = &info->oti_ostid;
        int                         dirn;
        char                        name[32];
        struct ldiskfs_dir_entry_2 *de;
        struct buffer_head         *bh;
        struct inode               *dir;
	struct inode		   *inode;
        ENTRY;

        /* on the very first lookup we find and open directories */

        map = dev->od_ost_map;
        LASSERT(map);
        LASSERT(map->root);

        fid_ostid_pack(fid, ostid);
        LASSERT(ostid->oi_seq < MAX_OBJID_GROUP);
        LASSERT(map->subdir_count > 0);
        LASSERT(map->groups[ostid->oi_seq].groot);

        dirn = ostid->oi_id & (map->subdir_count - 1);
        d = map->groups[ostid->oi_seq].dirs[dirn];
        LASSERT(d);

        sprintf(name, "%llu", ostid->oi_id);
        d_seq = &info->oti_child_dentry;
        d_seq->d_parent = d;
        d_seq->d_name.hash = 0;
        d_seq->d_name.name = name;
        /* XXX: we can use rc from sprintf() instead of strlen() */
        d_seq->d_name.len = strlen(name);

	dir = d->d_inode;
	mutex_lock(&dir->i_mutex);
	bh = osd_ldiskfs_find_entry(dir, d_seq, &de, NULL);
	mutex_unlock(&dir->i_mutex);

	if (bh == NULL)
		RETURN(-ENOENT);

	osd_id_gen(id, le32_to_cpu(de->inode), OSD_OII_NOGEN);
	brelse(bh);

	inode = osd_iget(info, dev, id);
	if (IS_ERR(inode))
		RETURN(PTR_ERR(inode));

	iput(inode);
	RETURN(0);
}

int osd_compat_objid_insert(struct osd_thread_info *info,
                            struct osd_device *osd,
                            const struct lu_fid *fid,
                            const struct osd_inode_id *id,
                            struct thandle *th)
{
        struct osd_compat_objid *map;
        struct dentry           *d;
        struct ost_id           *ostid = &info->oti_ostid;
        int                      dirn, rc = 0;
        char                     name[32];
        ENTRY;

        map = osd->od_ost_map;
        LASSERT(map);
        LASSERT(map->root);
        LASSERT(map->subdir_count > 0);
        LASSERT(map->groups[ostid->oi_seq].groot);

        /* map fid to group:objid */
        fid_ostid_pack(fid, ostid);
        dirn = ostid->oi_id & (map->subdir_count - 1);
        d = map->groups[ostid->oi_seq].dirs[dirn];
        LASSERT(d);

        sprintf(name, "%llu", ostid->oi_id);
        rc = osd_compat_add_entry(info, osd, d, name, id, th);

        RETURN(rc);
}

int osd_compat_objid_delete(struct osd_thread_info *info,
                            struct osd_device *osd,
                            const struct lu_fid *fid, struct thandle *th)
{
        struct osd_compat_objid *map;
        struct dentry           *d;
        struct ost_id           *ostid = &info->oti_ostid;
        int                      dirn, rc = 0;
        char                     name[32];
        ENTRY;

        map = osd->od_ost_map;
        LASSERT(map);
        LASSERT(map->root);
        LASSERT(map->subdir_count > 0);
        LASSERT(map->groups[ostid->oi_seq].groot);

        /* map fid to group:objid */
        fid_ostid_pack(fid, ostid);
        dirn = ostid->oi_id & (map->subdir_count - 1);
        d = map->groups[ostid->oi_seq].dirs[dirn];
        LASSERT(d);

        sprintf(name, "%llu", ostid->oi_id);
        rc = osd_compat_del_entry(info, osd, d, name, th);

        RETURN(rc);
}

struct named_oid {
        unsigned long  oid;
        char          *name;
};

static const struct named_oid oids[] = {
	{ FLD_INDEX_OID,        "fld" },
	{ FID_SEQ_CTL_OID,      "seq_ctl" },
	{ FID_SEQ_SRV_OID,      "seq_srv" },
	{ MDD_ROOT_INDEX_OID,   "" /* "ROOT" */ },
	{ MDD_ORPHAN_OID,       "" /* "PENDING" */ },
	{ MDD_LOV_OBJ_OID,      LOV_OBJID },
	{ MDD_CAPA_KEYS_OID,    "" /* CAPA_KEYS */ },
	{ MDT_LAST_RECV_OID,    LAST_RCVD },
	{ LFSCK_BOOKMARK_OID,   "" /* "lfsck_bookmark" */ },
	{ OTABLE_IT_OID,	"" /* "otable iterator" */},
	{ OFD_LAST_RECV_OID,    "" /* LAST_RCVD */ },
	{ OFD_LAST_GROUP_OID,   "LAST_GROUP" },
	{ LLOG_CATALOGS_OID,    "CATALOGS" },
	{ MGS_CONFIGS_OID,      "" /* MOUNT_CONFIGS_DIR */ },
	{ OFD_HEALTH_CHECK_OID, HEALTH_CHECK },
	{ 0,                    NULL }
};

static char *oid2name(const unsigned long oid)
{
        int i = 0;

        while (oids[i].oid) {
                if (oids[i].oid == oid)
                        return oids[i].name;
                i++;
        }
        return NULL;
}

int osd_compat_spec_insert(struct osd_thread_info *info,
                           struct osd_device *osd, const struct lu_fid *fid,
                           const struct osd_inode_id *id, struct thandle *th)
{
        struct osd_compat_objid *map = osd->od_ost_map;
        struct dentry           *root = osd_sb(osd)->s_root;
        char                    *name;
        int                      rc = 0;
        int                      seq;
        ENTRY;

        if (fid_oid(fid) >= OFD_GROUP0_LAST_OID &&
            fid_oid(fid) < OFD_GROUP4K_LAST_OID) {
                /* on creation of LAST_ID we create O/<group> hierarchy */
                LASSERT(map);
                seq = fid_oid(fid) - OFD_GROUP0_LAST_OID;
                LASSERT(seq < MAX_OBJID_GROUP);
                LASSERT(map->groups[seq].groot);
        } else {
                name = oid2name(fid_oid(fid));
                if (name == NULL)
                        CWARN("UNKNOWN COMPAT FID "DFID"\n", PFID(fid));
                else if (name[0])
                        rc = osd_compat_add_entry(info, osd, root, name, id,
                                                  th);
        }

        RETURN(rc);
}

int osd_compat_spec_lookup(struct osd_thread_info *info,
			   struct osd_device *osd, const struct lu_fid *fid,
			   struct osd_inode_id *id)
{
	struct dentry *dentry;
	struct inode  *inode;
	char	      *name;
	int	       rc = -ENOENT;
	ENTRY;

	name = oid2name(fid_oid(fid));
	if (name == NULL || strlen(name) == 0)
		RETURN(-ENOENT);

	dentry = ll_lookup_one_len(name, osd_sb(osd)->s_root, strlen(name));
	if (!IS_ERR(dentry)) {
		inode = dentry->d_inode;
		if (inode) {
			if (is_bad_inode(inode)) {
				rc = -EIO;
			} else {
				osd_id_gen(id, inode->i_ino,
					   inode->i_generation);
				rc = 0;
			}
		}
		dput(dentry);
	}

	RETURN(rc);
}
