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
#define DEBUG_SUBSYSTEM S_OST

#include <linux/lustre_lite.h>
#include <linux/lprocfs_status.h>


int rd_uuid(char* page, char **start, off_t off, int count, int *eof, 
            void *data)
{
         
        struct obd_device* temp = (struct obd_device*)data;
        int len = 0;
        len += snprintf(page, count, "%s\n", temp->obd_uuid); 
        return len;
        

}
int rd_blksize(char* page, char **start, off_t off, int count, int *eof, 
               void *data)
{
        
        struct obd_device* temp = (struct obd_device*)data;
        struct ost_obd *ost = &temp->u.ost;
        struct lustre_handle *conn = &ost->ost_conn;
        struct obd_statfs mystats;
        int len = 0;
        
        obd_statfs(conn, &mystats);
        len += snprintf(page, count, "%d\n", mystats.os_bsize); 
        return len;
        
}
int rd_kbtotal(char* page, char **start, off_t off, int count, int *eof, 
               void *data)
{
        struct obd_device* temp = (struct obd_device*)data;
        struct ost_obd *ost = &temp->u.ost;
        struct lustre_handle *conn = &ost->ost_conn;
        struct obd_statfs mystats;
        int len = 0;
        __u32 blk_size;
        __u64 result;
                
        obd_statfs(conn, &mystats);
        blk_size = mystats.os_bsize;
        blk_size >>= 10;
        result = mystats.os_blocks;
        while(blk_size >>= 1){
                result <<= 1;
        }
        len += snprintf(page, count, LPU64"\n", result);
        return len;
                
}


int rd_kbfree(char* page, char **start, off_t off, int count, int *eof, 
              void *data)
{
        
        struct obd_device* temp = (struct obd_device*)data;
        struct ost_obd *ost = &temp->u.ost;
        struct lustre_handle *conn = &ost->ost_conn;
        struct obd_statfs mystats;
        int len = 0;
        __u32 blk_size;
        __u64 result;

        obd_statfs(conn, &mystats);
        blk_size = mystats.os_bsize;
        blk_size >>= 10;
        result = mystats.os_bfree;
        while(blk_size >>= 1){
                result <<= 1;
        }
        len += snprintf(page, count, LPU64"\n", result);
        return len;  
}

int rd_filestotal(char* page, char **start, off_t off, int count, int *eof, 
                  void *data)
{
        struct obd_device* temp = (struct obd_device*)data;
        struct ost_obd *ost = &temp->u.ost;
        struct lustre_handle *conn = &ost->ost_conn;
        struct obd_statfs mystats;
        int len = 0;
        
        obd_statfs(conn, &mystats);
        len += snprintf(page, count, LPU64"\n",mystats.os_files); 
        return len;
        
}

int rd_filesfree(char* page, char **start, off_t off, int count, int *eof, 
                 void *data)
{
        
        struct obd_device* temp = (struct obd_device*)data;
        struct ost_obd *ost = &temp->u.ost;
        struct lustre_handle *conn = &ost->ost_conn;
        struct obd_statfs mystats;
        int len = 0;
        
        obd_statfs(conn, &mystats);
        len += snprintf(page, count, LPU64"\n", mystats.os_ffree); 
        return len;
        
}

int rd_filegroups(char* page, char **start, off_t off, int count, int *eof, 
                  void *data)
{
        return 0;
}

struct lprocfs_vars status_var_nm_1[] = {
        {"status/uuid", rd_uuid, 0, 0},
        {"status/blocksize",rd_blksize, 0, 0},
        {"status/kbytesfree", rd_kbfree, 0, 0},
        {"status/kbytestotal", rd_kbtotal, 0, 0},
        {"status/filestotal", rd_filestotal, 0, 0},
        {"status/filesfree", rd_filesfree, 0, 0},
        {"status/filegroups", rd_filegroups, 0, 0},
        {0}
};

int rd_numrefs(char* page, char **start, off_t off, int count, int *eof, 
               void *data)
{
        struct obd_type* class = (struct obd_type*)data;
        int len = 0;
        len += snprintf(page, count, "%d\n", class->typ_refcnt);
        return len;
}

struct lprocfs_vars status_class_var[] = {
        {"status/num_refs", rd_numrefs, 0, 0},
        {0}
};
 
