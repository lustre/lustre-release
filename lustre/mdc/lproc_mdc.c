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

#include <linux/lustre_lite.h>
#include <linux/lprocfs_status.h>


int rd_uuid(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{

       struct obd_device* temp=(struct obd_device*)data;
       int len=0;
       len+=snprintf(page, count, "%s\n",temp->obd_uuid);   
       return len;


}
int rd_blksize(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{

        return 0;

}
int rd_kbtotal(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        return 0;
}

int rd_kbfree(char* page, char **start, off_t off,
              int count, int *eof, void *data)
{
        return 0;
}


int rd_files(char* page, char **start, off_t off,
                  int count, int *eof, void *data)
{
        return 0;
}

int rd_filesfree(char* page, char **start, off_t off,
               int count, int *eof, void *data)
{
        return 0;
}

int rd_filegroups(char* page, char **start, off_t off,
                 int count, int *eof, void *data)
{
        return 0;
}
int rd_conn_uuid(char* page, char **start, off_t off,
                 int count, int *eof, void *data)
{
        struct obd_device* temp=(struct obd_device*)data;
        struct client_obd* cli=&temp->u.cli;
        struct obd_import* imp=&cli->cl_import;
        int len=0;
        len+=snprintf(page, count, "%s\n",imp->imp_connection->c_remote_uuid);   
        return len;
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

int rd_server_name(char* page, char **start, off_t off,
                 int count, int *eof, void *data)
{
        return 0;
        
}

lprocfs_vars_t status_var_nm_1[]={
        {"status/uuid", rd_uuid, 0},
        {"status/blocksize",rd_blksize, 0},
        {"status/kbytestotal",rd_kbtotal, 0},
        {"status/kbytesfree", rd_kbfree, 0},
        {"status/files", rd_files, 0},
        {"status/filesfree", rd_filesfree, 0},
        {"status/filegroups", rd_filegroups, 0},
        {"status/server_uuid", rd_server_uuid, 0},
        {"status/conn_uuid", rd_conn_uuid, 0},
        {0}
};
int rd_numdevices(char* page, char **start, off_t off,
                  int count, int *eof, void *data)
{
        struct obd_type* class=(struct obd_type*)data;
        int len=0;
        len+=snprintf(page, count, "%d\n", class->typ_refcnt);
        return len;
}

lprocfs_vars_t status_class_var[]={
        {"status/num_devices", rd_numdevices, 0},
        {0}
};
