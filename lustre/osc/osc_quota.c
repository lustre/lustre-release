/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Cluster File Systems, Inc.
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
#define DEBUG_SUBSYSTEM S_OSC

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/obd_ost.h>
# include <linux/lustre_net.h>
# include <linux/lustre_dlm.h>
# include <linux/lustre_lib.h>
# include <linux/lustre_compat25.h>
# if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#  include <linux/workqueue.h>
#  include <linux/smp_lock.h>
# else
#  include <linux/locks.h>
# endif
#else
# include <liblustre.h>
#endif

#include <linux/obd.h>
#include "osc_internal.h"

struct osc_quota_info {
        struct list_head        oqi_hash;       /* hash list */
        struct client_obd      *oqi_cli;        /* osc obd */ 
        unsigned int            oqi_id;         /* uid/gid of a file */
        short                   oqi_type;       /* quota type */
        unsigned long           oqi_flag;       /* flag, NO_QUOTA */
};

spinlock_t qinfo_list_lock = SPIN_LOCK_UNLOCKED;

static struct list_head qinfo_hash[NR_DQHASH];
/* SLAB cache for client quota context */
kmem_cache_t *qinfo_cachep = NULL;

static inline int const hashfn(struct client_obd *cli, 
                               unsigned long id, 
                               int type)
{
        unsigned long tmp = ((unsigned long)cli>>6) ^ id;
        tmp = (tmp * (MAXQUOTAS - type)) % NR_DQHASH;
        return tmp;
}

static inline void insert_qinfo_hash(struct osc_quota_info *oqi)
{
        struct list_head *head = qinfo_hash + 
                hashfn(oqi->oqi_cli, oqi->oqi_id, oqi->oqi_type);
        list_add(&oqi->oqi_hash, head);
}

static inline void remove_qinfo_hash(struct osc_quota_info *oqi)
{
        list_del_init(&oqi->oqi_hash);
}

static inline struct osc_quota_info *find_qinfo(struct client_obd *cli,
                                                unsigned int id, int type)
{
        unsigned int hashent = hashfn(cli, id, type);
        struct list_head *head;
        struct osc_quota_info *oqi;

        for (head = qinfo_hash[hashent].next;
             head != qinfo_hash+hashent; head = head->next) {
                oqi = list_entry(head, struct osc_quota_info, oqi_hash);
                LASSERT(oqi->oqi_flag == NO_QUOTA);
                if (oqi->oqi_cli == cli &&
                    oqi->oqi_id == id && oqi->oqi_type == type)
                        return oqi;
        }
        return NULL;
}

static struct osc_quota_info *alloc_qinfo(struct client_obd *cli,
                                          unsigned int id, int type)
{
        struct osc_quota_info *oqi;
        ENTRY;

        OBD_SLAB_ALLOC(oqi, qinfo_cachep, SLAB_KERNEL, sizeof(*oqi));
        if(!oqi)
                RETURN(NULL);

        INIT_LIST_HEAD(&oqi->oqi_hash);
        oqi->oqi_cli = cli;
        oqi->oqi_id = id;
        oqi->oqi_type = type;

        RETURN(oqi);
}

static void free_qinfo(struct osc_quota_info *oqi)
{
        OBD_SLAB_FREE(oqi, qinfo_cachep, sizeof(*oqi));
}

int osc_get_quota_flag(struct client_obd *cli, 
                       unsigned int uid, unsigned int gid)
{
        unsigned int id;
        int cnt, rc = QUOTA_OK;
        ENTRY;

        spin_lock(&qinfo_list_lock);
        for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
                struct osc_quota_info *oqi = NULL;

                id = (cnt == USRQUOTA) ? uid : gid;
                oqi = find_qinfo(cli, id, cnt);
                if (oqi) {
                        rc = NO_QUOTA;
                        break;
                }
        }
        spin_unlock(&qinfo_list_lock);

        RETURN(rc);
}

int osc_set_quota_flag(struct client_obd *cli, 
                       unsigned int uid, unsigned int gid,
                       obd_flag valid, obd_flag flags)
{
        unsigned int id;
        obd_flag noquota;
        int cnt, rc = 0;
        ENTRY;

        spin_lock(&qinfo_list_lock);

        for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
                struct osc_quota_info *oqi = NULL;

                if (!(valid & ((cnt == USRQUOTA) ? 
                    OBD_MD_FLUSRQUOTA : OBD_MD_FLGRPQUOTA)))
                        continue; 

                id = (cnt == USRQUOTA) ? uid : gid;
                noquota = (cnt == USRQUOTA) ? 
                    (flags & OBD_FL_NO_USRQUOTA) : (flags & OBD_FL_NO_GRPQUOTA);
                
                oqi = find_qinfo(cli, id, cnt);
                
                if (oqi && !noquota) {
                        remove_qinfo_hash(oqi);
                        free_qinfo(oqi);
                } else if (!oqi && noquota) {
                        oqi = alloc_qinfo(cli, id, cnt);
                        if (!oqi) {
                                CERROR("not enough mem!\n");
                                rc = -ENOMEM;
                                break;
                        }
                        oqi->oqi_flag = NO_QUOTA;
                        insert_qinfo_hash(oqi);
                }
        }

        spin_unlock(&qinfo_list_lock);

        RETURN(rc);
}

int osc_qinfo_cleanup(struct client_obd *cli)
{
        struct osc_quota_info *oqi, *n;
        int i;
        ENTRY;

        spin_lock(&qinfo_list_lock);
        for (i = 0; i < NR_DQHASH; i++) {
                list_for_each_entry_safe(oqi, n, &qinfo_hash[i], oqi_hash) {
                        if (oqi->oqi_cli != cli)
                                continue;
                        remove_qinfo_hash(oqi);
                        free_qinfo(oqi);
                }
        }
        spin_unlock(&qinfo_list_lock);

        RETURN(0);
}

int osc_qinfo_init(void)
{
        int i;
        ENTRY;

        LASSERT(qinfo_cachep == NULL);
        qinfo_cachep = kmem_cache_create("osc_quota_info",
                                         sizeof(struct osc_quota_info),
                                         0, 0, NULL, NULL);
        if (!qinfo_cachep)
                RETURN(-ENOMEM);

        for (i = 0; i < NR_DQHASH; i++)
                INIT_LIST_HEAD(qinfo_hash + i);

        RETURN(0);        
}

void osc_qinfo_exit(void)
{
        struct osc_quota_info *oqi, *n;
        int i;
        ENTRY;
                                                                                                                             
        spin_lock(&qinfo_list_lock);
        for (i = 0; i < NR_DQHASH; i++) {
                list_for_each_entry_safe(oqi, n, &qinfo_hash[i], oqi_hash) {
                        remove_qinfo_hash(oqi);
                        free_qinfo(oqi);
                }
        }
        spin_unlock(&qinfo_list_lock);
        
        LASSERTF(kmem_cache_destroy(qinfo_cachep) == 0,
                 "couldn't destroy osc quota info slab\n"); 
}
