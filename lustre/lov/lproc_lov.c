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

/*
 * Common STATUS namespace
 */

int rd_uuid(char* page, char **start, off_t off, int count, int *eof, 
            void *data)
{
        int len = 0;
        struct obd_device* dev = (struct obd_device*)data;
        len += snprintf(page, count, "%s\n", dev->obd_uuid);
        return len;
        

}
int rd_stripesize(char* page, char **start, off_t off, int count, int *eof, 
                  void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        int len = 0; 
        struct lov_obd* lov = &dev->u.lov;
        len += snprintf(page, count, LPU64"\n", 
                        (__u64)(lov->desc.ld_default_stripe_size));
        
        return len;
}

int rd_stripeoffset(char* page, char **start, off_t off, int count, int *eof, 
                    void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        int len = 0;
        struct lov_obd* lov = &dev->u.lov;
        len += snprintf(page, count, LPU64"\n", 
                        lov->desc.ld_default_stripe_offset);
        return len;

}

int rd_stripetype(char* page, char **start, off_t off, int count, int *eof, 
                  void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        int len = 0;
        struct lov_obd* lov = &dev->u.lov;
        len += snprintf(page, count, LPU64"\n", 
                        (__u64)(lov->desc.ld_pattern));
        return len;

}
int rd_stripecount(char* page, char **start, off_t off, int count, int *eof, 
                   void *data)
{       
        struct obd_device* dev = (struct obd_device*)data;
        int len = 0;
        struct lov_obd* lov = &dev->u.lov;
        len += snprintf(page, count, LPU64"\n", 
                        (__u64)(lov->desc.ld_default_stripe_count));
        return len;

}
int rd_numobd(char* page, char **start, off_t off, int count, int *eof, 
              void *data)
{       
        struct obd_device* dev = (struct obd_device*)data;
        int len = 0;
        struct lov_obd* lov=&dev->u.lov;
        len += snprintf(page, count, LPU64"\n", 
                        (__u64)(lov->desc.ld_tgt_count));
        return len;

}

int rd_activeobd(char* page, char **start, off_t off, int count, int *eof, 
                 void *data)
{       
        struct obd_device* dev = (struct obd_device*)data;
        int len = 0;
        struct lov_obd* lov = &dev->u.lov;
        len += snprintf(page, count, LPU64"\n", 
                        (__u64)(lov->desc.ld_active_tgt_count));
        return len;

}

int rd_blksize(char* page, char **start, off_t off, int count, int *eof, 
               void *data)
{
        return 0;
}


int rd_kbtotal(char* page, char **start, off_t off, int count, int *eof, 
               void *data)
{
        return 0;
}


int rd_kbfree(char* page, char **start, off_t off, int count, int *eof, 
              void *data)
{
        return 0;
}

int rd_numobjects(char* page, char **start, off_t off, int count, int *eof, 
                  void *data)
{
        return 0;
}

int rd_objfree(char* page, char **start, off_t off, int count, int *eof, 
               void *data)
{
        return 0;
}

int rd_objgroups(char* page, char **start, off_t off, int count, int *eof, 
                 void *data)
{
        return 0;
}

int rd_target(char* page, char **start, off_t off, int count, int *eof, 
              void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        int len = 0, i = 0;
        struct lov_obd* lov = &dev->u.lov;
        struct lov_tgt_desc* tgts = lov->tgts;
        while(i < lov->desc.ld_tgt_count){
                len += snprintf(page, count, "%d: %s\n", i, tgts->uuid);
                i++;
                tgts++;
        }
        
        return len;
}
int rd_mdc(char* page, char **start, off_t off, int count, int *eof, void *data)
{
        struct obd_device* dev = (struct obd_device*)data;
        int len = 0;
        struct lov_obd* lov = &dev->u.lov;
        len += snprintf(page, count, "%s\n", lov->mdcobd->obd_uuid);
        return len;
}

struct lprocfs_vars status_var_nm_1[] = {
        {"status/uuid", rd_uuid, 0, 0},
        {"status/stripesize",rd_stripesize, 0, 0},
        {"status/stripeoffset",rd_stripeoffset, 0, 0},
        {"status/stripecount",rd_stripecount, 0, 0},
        {"status/stripetype", rd_stripetype, 0, 0},
        {"status/numobd",rd_numobd, 0, 0},
        {"status/activeobd", rd_activeobd, 0, 0},
        {"status/objects", rd_numobjects, 0, 0},
        {"status/objectsfree", rd_objfree, 0, 0},
        {"status/objectgroups", rd_objgroups, 0, 0},
        {"status/blocksize", rd_blksize, 0, 0},
        {"status/kbytestotal", rd_kbtotal, 0, 0},
        {"status/kbytesfree", rd_kbfree, 0, 0},
        {"status/target_obd", rd_target, 0, 0},
        {"status/target_mdc", rd_mdc, 0, 0},
       
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

struct lprocfs_vars status_class_var[]={
        {"status/num_refs", rd_numrefs, 0, 0},
        {0}
};
