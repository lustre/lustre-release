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
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lprocfs.h>
#include <linux/string.h>
#include <linux/lustre_lib.h>

/* Required for 64 bit division */
#include <asm/div64.h>

int rd_uuid(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
         
        struct obd_device* temp=(struct obd_device*)data;
        int len=0;
        len+=snprintf(page, count, "%s\n", temp->obd_uuid); 
        return len;
        

}
int rd_blksize(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        
        struct obd_device* temp=(struct obd_device*)data;
        struct ost_obd *ost=&temp->u.ost;
        struct lustre_handle *conn=&ost->ost_conn;
        struct obd_statfs mystats;
        int rc, len=0;
        
        rc = obd_statfs(conn, &mystats);
        if (rc) {
                CERROR("ost: statfs failed: rc %d\n", rc);
                return 0;
        }
        len+=snprintf(page, count, LPU64"\n", (__u64)(mystats.os_bsize)); 
        return len;
        
}
int rd_blktotal(char* page, char **start, off_t off,
                int count, int *eof, void *data)
{
        
        struct obd_device* temp=(struct obd_device*)data;
        struct ost_obd *ost=&temp->u.ost;
        struct lustre_handle *conn=&ost->ost_conn;
        struct obd_statfs mystats;
        int rc, len=0;
        
        rc = obd_statfs(conn, &mystats);
        if (rc) {
                CERROR("ost: statfs failed: rc %d\n", rc);
                return 0;
        }
        len+=snprintf(page, count, LPU64"\n", (__u64)(mystats.os_blocks)); 
        return len;
        
}

int rd_blkfree(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        
        struct obd_device* temp=(struct obd_device*)data;
        struct ost_obd *ost=&temp->u.ost;
        struct lustre_handle *conn=&ost->ost_conn;
        struct obd_statfs mystats;
        int rc, len=0;
        
        rc = obd_statfs(conn, &mystats);
        if (rc) {
                CERROR("ost: statfs failed: rc %d\n", rc);
                return 0;
        }
        len+=snprintf(page, count, LPU64"\n", (__u64)(mystats.os_bfree)); 
        return len;
        
}

int rd_kbfree(char* page, char **start, off_t off,
              int count, int *eof, void *data)
{
        
        struct obd_device* temp=(struct obd_device*)data;
        struct ost_obd *ost=&temp->u.ost;
        struct lustre_handle *conn=&ost->ost_conn;
        struct obd_statfs mystats;
        int rc, len=0;
        __u32 blk_size;
        __u64 result;
        __u32 remainder;

        rc = obd_statfs(conn, &mystats);
        if (rc) {
                CERROR("ost: statfs failed: rc %d\n", rc);
                return 0;
        }
        blk_size=mystats.os_bsize;
        blk_size*=1024;
        result=mystats.os_bfree;
        remainder=do_div(result, blk_size);

        len+=snprintf(page, count, LPU64"\n", \
                      result);
        
        return len;  
        
       
}

int rd_numobjects(char* page, char **start, off_t off,
                  int count, int *eof, void *data)
{
        
        struct obd_device* temp=(struct obd_device*)data;
        struct ost_obd *ost=&temp->u.ost;
        struct lustre_handle *conn=&ost->ost_conn;
        struct obd_statfs mystats;
        int rc, len=0;
        
        rc = obd_statfs(conn, &mystats);
        if (rc) {
                CERROR("ost: statfs failed: rc %d\n", rc);
                return 0;
        }
        len+=snprintf(page, count, LPU64"\n", (__u64)(mystats.os_files)); 
        return len;
        
}

int rd_objfree(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        
        struct obd_device* temp=(struct obd_device*)data;
        struct ost_obd *ost=&temp->u.ost;
        struct lustre_handle *conn=&ost->ost_conn;
        struct obd_statfs mystats;
        int rc, len=0;
        
        rc = obd_statfs(conn, &mystats);
        if (rc) {
                CERROR("ost: statfs failed: rc %d\n", rc);
                return 0;
        }
        len+=snprintf(page, count, LPU64"\n", (__u64)(mystats.os_ffree)); 
        return len;
        
}

int rd_objgroups(char* page, char **start, off_t off,
                 int count, int *eof, void *data)
{
        return 0;
}

lprocfs_vars_t snmp_var_nm_1[]={
        {"snmp/uuid", rd_uuid, 0},
        {"snmp/f_blocksize",rd_blksize, 0},
        {"snmp/f_blockstotal",rd_blktotal, 0},
        {"snmp/f_blocksfree",rd_blkfree, 0},
        {"snmp/f_kbytesfree", rd_kbfree, 0},
        {"snmp/f_objects", rd_numobjects, 0},
        {"snmp/f_objectsfree", rd_objfree, 0},
        {"snmp/f_objectgroups", rd_objgroups, 0},
        {0}
};
