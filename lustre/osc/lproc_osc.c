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
#define DEBUG_SUBSYSTEM S_CLASS
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lprocfs.h>
#include <linux/string.h>
#include <linux/lustre_lib.h>

int rd_uuid(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        int len=0;
        struct obd_device* dev=(struct obd_device*)data;
        len+=snprintf(page, count, "%s\n", dev->obd_uuid);
        return len;

}
int rd_blksize(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        return 0;
}
int rd_blktotal(char* page, char **start, off_t off,
                int count, int *eof, void *data)
{
        return 0;
}

int rd_blkfree(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        return 0;
}

int rd_kbfree(char* page, char **start, off_t off,
              int count, int *eof, void *data)
{
        return 0;
}

int rd_numobjects(char* page, char **start, off_t off,
                  int count, int *eof, void *data)
{
        return 0;
}

int rd_objfree(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        return 0;
}

int rd_objgroups(char* page, char **start, off_t off,
                 int count, int *eof, void *data)
{
        return 0;
}
int rd_server_uuid(char* page, char **start, off_t off,
                 int count, int *eof, void *data)
{
        
        struct obd_device* temp=(struct obd_device*)data;
        struct client_obd* cli=&temp->u.cli;
        int len=0;
        len+=snprintf(page, count, "%s\n",cli->cl_target_uuid);   
        return len;

        
}
int rd_conn_uuid(char* page, char **start, off_t off,
                 int count, int *eof, void *data)
{
        struct obd_device* temp=(struct obd_device*)data;
        struct client_obd* cli=&temp->u.cli;
        struct obd_import* imp=&cli->cl_import;
        int len=0;
        len+=snprintf(page, count, "%s\n",\
                      imp->imp_connection->c_remote_uuid);   
        return len;  
        
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
        {"snmp/ost_server_uuid", rd_server_uuid, 0},
        {"snmp/ost_conn_uuid", rd_conn_uuid, 0},
        {0}
};
