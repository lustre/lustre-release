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

__u64 mnt_instance = 0;

int rd_path(char* page, char **start, off_t off, int count, int *eof, 
            void *data)
{
        return 0;
}
int rd_fstype(char* page, char **start, off_t off, int count, int *eof, 
              void *data)
{
        int len = 0;
        struct super_block *sb = (struct super_block*)data;
        
        len += snprintf(page, count, "%s\n", sb->s_type->name); 
        return len;
}
int rd_blksize(char* page, char **start, off_t off, int count, int *eof, 
               void *data)
{
        int len = 0;
        struct super_block *sb = (struct super_block*)data;
        struct statfs mystats;

        (sb->s_op->statfs)(sb, &mystats);
        len += snprintf(page, count, LPU64"\n", (__u64)(mystats.f_bsize)); 
        return len;

}
int rd_kbytestotal(char* page, char **start, off_t off, int count, int *eof, 
                   void *data)
{
        int len = 0;
        struct super_block *sb = (struct super_block*)data;
        struct statfs mystats;
        __u32 blk_size;
        __u64 result;

        (sb->s_op->statfs)(sb, &mystats);
        blk_size = mystats.f_bsize;
        blk_size >>= 10;
        result = mystats.f_blocks;
        
        while(blk_size >>= 1){
                result <<= 1;
        }
       
        len += snprintf(page, count, LPU64"\n", result); 
        return len;
        
}


int rd_kbytesfree(char* page, char **start, off_t off, int count, int *eof, 
                  void *data)
{
        int len = 0;
        struct super_block *sb = (struct super_block*)data;
        struct statfs mystats; 
        __u32 blk_size;
        __u64 result;

        (sb->s_op->statfs)(sb, &mystats);
        blk_size = mystats.f_bsize;
        blk_size >>= 10;
        result = mystats.f_bfree;
        
        while(blk_size >>= 1){
                result <<= 1;
        }
       
        len += snprintf(page, count, LPU64"\n", result); 
        return len;

        
}

int rd_filestotal(char* page, char **start, off_t off, int count, int *eof, 
                  void *data)
{
        
        int len = 0;
        struct super_block *sb = (struct super_block*)data;
        struct statfs mystats; 
        
        (sb->s_op->statfs)(sb, &mystats);
        len += snprintf(page, count, LPU64"\n", (__u64)(mystats.f_files)); 
        return len;
}

int rd_filesfree(char* page, char **start, off_t off, int count, int *eof, 
                 void *data)
{
        
        int len = 0;
        struct super_block *sb = (struct super_block*)data;
        struct statfs mystats; 
        
        (sb->s_op->statfs)(sb, &mystats);
        len += snprintf(page, count, LPU64"\n", (__u64)(mystats.f_ffree)); 
        return len;
}

int rd_filegroups(char* page, char **start, off_t off, int count, int *eof, 
                  void *data)
{
        return 0;
}
int rd_uuid(char* page, char **start, off_t off, int count, int *eof, 
            void *data)
{
        int len = 0;
        struct super_block *sb = (struct super_block*)data;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        len += snprintf(page, count, "%s\n", sbi->ll_sb_uuid); 
        return len;    

}
int rd_dev_name(char* page, char **start, off_t off, int count, int *eof, 
                void *data)
{
        int len = 0;
        struct obd_device* dev = (struct obd_device*)data;
        len += snprintf(page, count, "%s\n", dev->obd_name);
        return len;
}

int rd_dev_uuid(char* page, char **start, off_t off, int count, int *eof, 
                void *data)
{
        int len = 0;
        struct obd_device* dev = (struct obd_device*)data;
        len += snprintf(page, count, "%s\n", dev->obd_uuid);
        return len;
}


struct lprocfs_vars status_var_nm_1[] = {
        {"uuid", rd_uuid, 0, 0},
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

/* 
 * Proc registration function for Lustre
 * file system
 */


#define MAX_STRING_SIZE 100
void ll_proc_namespace(struct super_block* sb, char* osc, char* mdc)
{
        char mnt_name[MAX_STRING_SIZE+1];
        char uuid_name[MAX_STRING_SIZE+1];
        struct lprocfs_vars d_vars[3];
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_device* obd;
        int err;

        /* Register this mount instance with LProcFS */
        snprintf(mnt_name, MAX_STRING_SIZE, "fs"LPU64, mnt_instance);
        mnt_instance++;
        mnt_name[MAX_STRING_SIZE] = '\0';
        sbi->ll_proc_root = lprocfs_reg_mnt(mnt_name);
        if (sbi->ll_proc_root == NULL) {
                CDEBUG(D_OTHER, "Could not register FS");
                return;
        }
        /* Add the static configuration info */
        err = lprocfs_add_vars(sbi->ll_proc_root,status_var_nm_1, sb);
        if (err) {
                CDEBUG(D_OTHER, "Unable to add procfs variables\n");
                return;
        }
        /* MDC */
        obd = class_uuid2obd(mdc);
        snprintf(mnt_name, MAX_STRING_SIZE, "%s/common_name", 
                 obd->obd_type->typ_name);
        mnt_name[MAX_STRING_SIZE] = '\0';
        memset(d_vars, 0, sizeof(d_vars));
        d_vars[0].read_fptr = rd_dev_name;
        d_vars[0].write_fptr = NULL;
        d_vars[0].name = mnt_name;
        snprintf(uuid_name, MAX_STRING_SIZE, "%s/uuid",
                 obd->obd_type->typ_name);
        uuid_name[MAX_STRING_SIZE] = '\0';
        d_vars[1].read_fptr = rd_dev_uuid;
        d_vars[1].write_fptr = NULL;
        d_vars[1].name = uuid_name;

        err = lprocfs_add_vars(sbi->ll_proc_root, d_vars, obd);
        if (err) {
                CDEBUG(D_OTHER, "Unable to add fs proc dynamic variables\n");
                return;
        }
        /* OSC or LOV*/
        obd = class_uuid2obd(osc);

        /* Reuse mnt_name */
        snprintf(mnt_name, MAX_STRING_SIZE, 
                 "%s/common_name", obd->obd_type->typ_name);
        mnt_name[MAX_STRING_SIZE] = '\0';
        memset(d_vars, 0, sizeof(d_vars));
        d_vars[0].read_fptr = rd_dev_name;
        d_vars[0].write_fptr = NULL;
        d_vars[0].name = mnt_name;

        snprintf(uuid_name, MAX_STRING_SIZE, "%s/uuid",
                 obd->obd_type->typ_name);
        uuid_name[MAX_STRING_SIZE] = '\0';
        d_vars[1].read_fptr = rd_dev_uuid;
        d_vars[1].write_fptr = NULL;
        d_vars[1].name = uuid_name;

        err = lprocfs_add_vars(sbi->ll_proc_root, d_vars, obd);
        if (err) {
                CDEBUG(D_OTHER, "Unable to add fs proc dynamic variables\n");
                return;
        }
}
#undef MAX_STRING_SIZE
