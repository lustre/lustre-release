/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/super.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
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
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#define DEBUG_SUBSYSTEM S_SM

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>
#include "smfs_internal.h"

static int smfs_ost_get_id(obd_id *id, char *data, int size)
{
        /*for obdfilter obdid is the name of the filename*/
        char end;
        char *endp = &end;
        if (data)
                *id = simple_strtoull(data, &endp, 10);
        else
                return -EINVAL;
        CDEBUG(D_DENTRY,"name = %s\n", data);
        return 0;
}

/* Group 0 is no longer a legal group, to catch uninitialized IDs */
#define FILTER_MIN_GROUPS 3
static int smfs_ost_get_group(struct dentry *dentry, struct obdo *oa)
{
        struct smfs_super_info *sinfo = S2SMI(dentry->d_inode->i_sb);
        struct obd_device *obd = class_exp2obd(sinfo->smsi_exp);
        struct filter_obd *filter = &obd->u.filter;
        struct dentry *dparent_subdir = dentry->d_parent;
        struct dentry *dparent_group = dparent_subdir->d_parent;
        int i = 0;

        if (dparent_group == NULL || dparent_group == dparent_subdir)
                return -EINVAL;

        CDEBUG(D_DENTRY,"try to find group for dentry %p\n", dparent_group);
        for (i = 1; i < filter->fo_group_count; i++) {
                CDEBUG(D_DENTRY, "group[%i] = %p\n", i, filter->fo_groups[i]);
                if (filter->fo_groups[i] == dparent_group) {
                        oa->o_gr = i;
                        oa->o_valid |= OBD_MD_FLGROUP;
                        return 0;
                }
        }
        return -ENOENT;
}

static int ost_rec_create_pack(char *buffer, struct dentry *dentry,
                               struct inode *dir, void *data1, void *data2)
{
        struct obdo *oa = NULL;
        int    rc = 0;
       
        PACK_KML_REC_INIT(buffer, OST_CREATE);
        oa = (struct obdo*)buffer;
        if (data1 && data2) {
                struct obdo *create_oa = (struct obdo *)data2;  
                int    num = *((int *)data1);
                
                memcpy(oa, create_oa, sizeof(*oa));
                memcpy(oa->o_inline, &num, sizeof(int));
                oa->o_valid |= OBD_MD_REINT; 
        } else { 
                oa->o_uid = 0; /* must have 0 uid / gid on OST */
                oa->o_gid = 0;
                oa->o_valid = OBD_MD_FLID | OBD_MD_FLGENER | OBD_MD_FLTYPE |
                        OBD_MD_FLMODE | OBD_MD_FLUID | OBD_MD_FLGID;
                oa->o_size = 0;
                obdo_from_inode(oa, dentry->d_inode, OBD_MD_FLTYPE|OBD_MD_FLATIME|
                                OBD_MD_FLMTIME| OBD_MD_FLCTIME);
                rc = smfs_ost_get_id(&oa->o_id, (char*)dentry->d_name.name,
                                     dentry->d_name.len);
                if (rc) {
                        CERROR("Can not find id of node %lu\n", dentry->d_inode->i_ino);
                        GOTO(out, rc = -ENOMEM);
                }
                rc = smfs_ost_get_group(dentry, oa);
                if (rc) {
                        CERROR("Can not find group node %lu\n", dentry->d_inode->i_ino);
                        GOTO(out, rc = -ENOMEM); 
                }
        } 
        rc = sizeof(*oa) + sizeof(int);
out:
        RETURN(rc);
}

static int ost_rec_setattr_pack(char *buffer, struct dentry *dentry,
                                struct inode *dir, void *data1, void *data2)
{
        struct obdo *oa = NULL;
        struct iattr *attr = (struct iattr*)data1;
        int rc = 0;

        PACK_KML_REC_INIT(buffer, OST_SETATTR);
        oa = (struct obdo*)buffer;

        obdo_from_iattr(oa, attr, attr->ia_valid);

        rc = smfs_ost_get_id(&oa->o_id, (char *)dentry->d_name.name,
                             dentry->d_name.len);
        if (rc)
                GOTO(out, rc = -ENOMEM);
        rc = smfs_ost_get_group(dentry, oa);
        if (rc) {
                CERROR("Can not find group node %lu\n", dentry->d_inode->i_ino);
                GOTO(out, rc = -ENOMEM); 
        } 

        rc = sizeof(*oa) + sizeof(int);
out:
        RETURN(rc);
}

static int ost_rec_write_pack(char *buffer, struct dentry *dentry,
                              struct inode *dir, void *data1, void *data2)
{
        struct obdo *oa = NULL;
        int          rc = 0;

        PACK_KML_REC_INIT(buffer, OST_WRITE);
        oa = (struct obdo*)buffer;

        rc = smfs_ost_get_id(&oa->o_id, (char*)dentry->d_name.name,
                             dentry->d_name.len);
        if (rc)
                GOTO(out, rc = -ENOMEM);
        memcpy(oa->o_inline, &dentry->d_inode->i_ino, sizeof(unsigned long));
        
        rc = smfs_ost_get_group(dentry, oa);
        if (rc) {
                CERROR("Can not find group node %lu\n", dentry->d_inode->i_ino);
                GOTO(out, rc = -ENOMEM); 
        } 
        rc = sizeof(*oa) + sizeof(int);
out:
        RETURN(rc);
}

typedef int (*ost_pack_rec_func)(char *buffer, struct dentry *dentry,
                                 struct inode *dir, void *data1, void *data2);

static ost_pack_rec_func ost_kml_pack[REINT_MAX + 1] = {
        [REINT_SETATTR] ost_rec_setattr_pack,
        [REINT_CREATE]  ost_rec_create_pack,
        [REINT_WRITE]   ost_rec_write_pack,
};

int ost_rec_pack(int op, char *buffer, struct dentry *dentry,
                 struct inode *dir, void *data1, void *data2)
{
        if (op == REINT_SETATTR || op == REINT_CREATE || op == REINT_WRITE)
                return ost_kml_pack[op](buffer, dentry, dir, data1, data2);
        return 0;
}
