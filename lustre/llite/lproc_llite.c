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
#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_lite.h>
#include <linux/lprocfs_status.h>

/* /proc/lustre/llite mount point registration */

#ifndef LPROCFS
int lprocfs_register_mountpoint(struct proc_dir_entry *parent,
                                struct super_block* sb, char* osc, char* mdc)
{
        return 0;

}
#else

__u64 mnt_instance;

static inline 
int lprocfs_llite_statfs(void* data, struct statfs *sfs)
{
        struct super_block *sb = (struct super_block*)data;
        return (sb->s_op->statfs)(sb, sfs);
}

DEFINE_LPROCFS_STATFS_FCT(rd_blksize,     lprocfs_llite_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_kbytestotal, lprocfs_llite_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_kbytesfree,  lprocfs_llite_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_filestotal,  lprocfs_llite_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_filesfree,   lprocfs_llite_statfs);
DEFINE_LPROCFS_STATFS_FCT(rd_filegroups,  lprocfs_llite_statfs);

int rd_path(char* page, char **start, off_t off, int count, int *eof,
                  void *data)
{
        return 0;
}

int rd_fstype(char* page, char **start, off_t off, int count, int *eof,
                 void *data)
{
        struct super_block *sb = (struct super_block*)data;
        int rc = snprintf(page, count, "%s\n", sb->s_type->name);
        *eof = 1;
        return rc;
}

int rd_sb_uuid(char* page, char **start, off_t off, int count, int *eof,
            void *data)
{
        struct super_block *sb = (struct super_block*)data;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        int rc = snprintf(page, count, "%s\n", sbi->ll_sb_uuid);
        *eof = 1;
        return rc;
}

struct lprocfs_vars status_var_nm_1[] = {
        {"uuid", rd_sb_uuid, 0, 0},
        {"mntpt_path", rd_path, 0, 0},
        {"fstype", rd_fstype, 0, 0},
        {"blocksize",rd_blksize, 0, 0},
        {"kbytestotal",rd_kbytestotal, 0, 0},
        {"kbytesfree", rd_kbytesfree, 0, 0},
        {"filestotal", rd_filestotal, 0, 0},
        {"filesfree", rd_filesfree, 0, 0},
        {"filegroups", rd_filegroups, 0, 0},
        {0}
};

#define MAX_STRING_SIZE 128
int lprocfs_register_mountpoint(struct proc_dir_entry *parent,
                                struct super_block* sb, char* osc, char* mdc)
{
        struct lprocfs_vars lvars[2];
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_device* obd;
        int err;

        memset(lvars, 0, sizeof(lvars));

        OBD_ALLOC(lvars[0].name, MAX_STRING_SIZE);
        if (!lvars[0].name)
                return -ENOMEM;

        /* Mount info */
        snprintf(lvars[0].name, MAX_STRING_SIZE, "fs"LPU64, mnt_instance);

        mnt_instance++;
        sbi->ll_proc_root = lprocfs_register(lvars[0].name, parent,
                                             NULL, NULL);
        if (IS_ERR(sbi->ll_proc_root))
                GOTO(out, err = PTR_ERR(sbi->ll_proc_root));

        /* Static configuration info */
        err = lprocfs_add_vars(sbi->ll_proc_root, status_var_nm_1, sb);
        if (err) 
                GOTO(out, err);

        /* MDC info */
        obd = class_uuid2obd(mdc);
        snprintf(lvars[0].name, MAX_STRING_SIZE, "%s/common_name",
                 obd->obd_type->typ_name);
        lvars[0].read_fptr = lprocfs_rd_name;
        err = lprocfs_add_vars(sbi->ll_proc_root, lvars, obd);
        if (err) 
                GOTO(out, err);

        snprintf(lvars[0].name, MAX_STRING_SIZE, "%s/uuid",
                 obd->obd_type->typ_name);
        lvars[0].read_fptr = lprocfs_rd_uuid;
        err = lprocfs_add_vars(sbi->ll_proc_root, lvars, obd);
        if (err < 0) 
                GOTO(out, err);

        /* OSC */
        obd = class_uuid2obd(osc);

        snprintf(lvars[0].name, MAX_STRING_SIZE, "%s/common_name",
                 obd->obd_type->typ_name);
        lvars[0].read_fptr = lprocfs_rd_name;
        err = lprocfs_add_vars(sbi->ll_proc_root, lvars, obd);
        if (err) 
                GOTO(out, err);

        snprintf(lvars[0].name, MAX_STRING_SIZE, "%s/uuid",
                 obd->obd_type->typ_name);
        lvars[0].read_fptr = lprocfs_rd_uuid;
        err = lprocfs_add_vars(sbi->ll_proc_root, lvars, obd);

 out:
        OBD_FREE(lvars[0].name, MAX_STRING_SIZE); 
        return err;
}

#undef MAX_STRING_SIZE
#endif /* LPROCFS */
