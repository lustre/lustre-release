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
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_lite.h>
#include <linux/lprocfs.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/lustre_lib.h>


int rd_path(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        
        return 0;

}
int rd_fstype(char* page, char **start, off_t off,
                int count, int *eof, void *data)
{
        int len=0;
        struct super_block *sb=(struct super_block*)data;
        
        len+=snprintf(page, count, "%s\n", sb->s_type->name); 
        return len;
}
int rd_blksize(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        int len=0;
        struct super_block *sb=(struct super_block*)data;
        struct statfs mystats;
        (sb->s_op->statfs)(sb, &mystats);
        len+=snprintf(page, count, LPU64"\n", (__u64)(mystats.f_bsize)); 
        return len;

}
int rd_blktotal(char* page, char **start, off_t off,
                int count, int *eof, void *data)
{
        int len=0;
        struct super_block *sb=(struct super_block*)data;
        struct statfs mystats;
        (sb->s_op->statfs)(sb, &mystats);
        len+=snprintf(page, count, LPU64"\n", (__u64)(mystats.f_blocks)); 
        return len;
        
}

int rd_blkfree(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        int len=0;
        struct super_block *sb=(struct super_block*)data;
        struct statfs mystats;
        (sb->s_op->statfs)(sb, &mystats);
        len+=snprintf(page, count, LPU64"\n", (__u64)(mystats.f_bfree)); 
        return len;
        
        
}

int rd_kbfree(char* page, char **start, off_t off,
              int count, int *eof, void *data)
{
        int len=0;
        struct super_block *sb=(struct super_block*)data;
        struct statfs mystats; 
        long blk_size=0;
        
        (sb->s_op->statfs)(sb, &mystats);
        blk_size=mystats.f_bsize;
        
        len+=snprintf(page, count, LPU64"\n", \
                      (__u64)((mystats.f_bfree)/(blk_size*1024))); 
        return len; 
        
}

int rd_numobjects(char* page, char **start, off_t off,
                  int count, int *eof, void *data)
{
        
        int len=0;
        struct super_block *sb=(struct super_block*)data;
        
        struct statfs mystats; 
        
        
        (sb->s_op->statfs)(sb, &mystats);
                
        len+=snprintf(page, count, LPU64"\n", (__u64)(mystats.f_files)); 
        return len;
}

int rd_objfree(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        
        int len=0;
        struct super_block *sb=(struct super_block*)data;
        
        struct statfs mystats; 
        
        
        (sb->s_op->statfs)(sb, &mystats);
                
        len+=snprintf(page, count, LPU64"\n", (__u64)(mystats.f_ffree)); 
        return len;
}

int rd_objgroups(char* page, char **start, off_t off,
                 int count, int *eof, void *data)
{
        return 0;
}
int rd_uuid(char* page, char **start, off_t off,
            int count, int *eof, void *data)
{
        int len=0;
        struct super_block *sb=(struct super_block*)data;
        struct ll_sb_info *sbi=ll_s2sbi(sb);
        len+=snprintf(page, count, "%s\n", sbi->ll_sb_uuid); 
        return len;    

}
int rd_dev_name(char* page, char **start, off_t off,
                    int count, int *eof, void *data)
{
        int len=0;
        struct obd_device* dev=(struct obd_device*)data;
        len+=snprintf(page, count, "%s\n", dev->obd_name);
        return len;
}

int rd_dev_uuid(char* page, char **start, off_t off,
                    int count, int *eof, void *data)
{
        int len=0;
        struct obd_device* dev=(struct obd_device*)data;
        len+=snprintf(page, count, "%s\n", dev->obd_uuid);
        return len;
}


lprocfs_vars_t snmp_var_nm_1[]={
        {"snmp/uuid", rd_uuid, 0},
        {"snmp/mntpt_path", rd_path, 0},
        {"snmp/fs_type", rd_fstype, 0},
        {"snmp/f_blocksize",rd_blksize, 0},
        {"snmp/f_blockstotal",rd_blktotal, 0},
        {"snmp/f_blocksfree",rd_blkfree, 0},
        {"snmp/f_kbytesfree", rd_kbfree, 0},
        {"snmp/f_objects", rd_numobjects, 0},
        {"snmp/f_objectsfree", rd_objfree, 0},
        {"snmp/f_objectgroups", rd_objgroups, 0},
        {0}
};
