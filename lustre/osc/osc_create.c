/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *   Author Peter Braam <braam@clusterfs.com>
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
 *  For testing and management it is treated as an obd_device,
 *  although * it does not export a full OBD method table (the
 *  requests are coming * in over the wire, so object target modules
 *  do not have a full * method table.)
 *
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_OSC

#ifdef __KERNEL__
# include <linux/version.h>
# include <linux/module.h>
# include <linux/mm.h>
# include <linux/highmem.h>
# include <linux/lustre_dlm.h>
# if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#  include <linux/workqueue.h>
#  include <linux/smp_lock.h>
# else
#  include <linux/locks.h>
# endif
#else /* __KERNEL__ */
# include <liblustre.h>
#endif

#include <linux/kp30.h>
#include <linux/lustre_mds.h> /* for mds_objid */
#include <linux/lustre_otree.h>
#include <linux/obd_ost.h>
#include <linux/lustre_commit_confd.h>
#include <linux/obd_lov.h>

#ifndef  __CYGWIN__
# include <linux/ctype.h>
# include <linux/init.h>
#else
# include <ctype.h>
#endif

#include <linux/lustre_ha.h>
#include <linux/obd_support.h> /* for OBD_FAIL_CHECK */
#include <linux/lustre_lite.h> /* for ll_i2info */
#include <portals/lib-types.h> /* for PTL_MD_MAX_IOV */
#include <linux/lprocfs_status.h>
#include "osc_internal.h"

struct osc_created {
        wait_queue_head_t osccd_waitq;       /* the daemon sleeps on this */
        wait_queue_head_t osccd_ctl_waitq;   /* insmod rmmod sleep on this */
        spinlock_t osccd_lock;
        int osccd_flags;
        struct task_struct *osccd_thread;
        struct list_head osccd_queue_list_head;
        struct list_head osccd_work_list_head;
};


#define OSCCD_STOPPING          0x1
#define OSCCD_STOPPED           0x2
#define OSCCD_RUNNING           0x4
#define OSCCD_KICKED            0x8
#define OSCCD_PRECREATED         0x10


static struct osc_created osc_created;

static int oscc_has_objects(struct osc_creator *oscc, int count)
{
        int rc;
        spin_lock(&oscc->oscc_lock);
        rc = ((__s64)(oscc->oscc_last_id - oscc->oscc_next_id) >= count);
        spin_unlock(&oscc->oscc_lock);
        return rc;
}

static int oscc_precreate(struct osc_creator *oscc, struct osc_created *osccd,
                          int wait)
{
        int rc = 0;
        struct l_wait_info lwi = { 0 };
        ENTRY;

        if (oscc_has_objects(oscc, oscc->oscc_kick_barrier))
                RETURN(0);

        spin_lock(&osccd->osccd_lock);
        spin_lock(&oscc->oscc_lock);
        if (list_empty(&oscc->oscc_list)) {
                list_add(&oscc->oscc_list, &osccd->osccd_queue_list_head);
                osccd->osccd_flags |= OSCCD_KICKED;
                wake_up(&osccd->osccd_waitq);
        }
        spin_unlock(&oscc->oscc_lock);
        spin_unlock(&osccd->osccd_lock);

        /* an MDS using this call may time out on this. This is a
         *  recovery style wait.
         */
        if (wait)
                rc = l_wait_event(oscc->oscc_waitq, oscc_has_objects(oscc, 1),
                                  &lwi);
        if (rc || !wait)
                RETURN(rc);

        spin_lock(&oscc->oscc_lock);
        rc = oscc->oscc_status;
        spin_unlock(&oscc->oscc_lock);
        RETURN(rc);
}

int osc_create(struct lustre_handle *exph, struct obdo *oa,
               struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct lov_stripe_md *lsm;
        struct obd_export *export = class_conn2export(exph);
        struct osc_creator *oscc = &export->u.eu_osc_data.oed_oscc;
        struct osc_created *osccd = oscc->oscc_osccd;
        int try_again = 1, rc;
        ENTRY;

        class_export_put(export);
        LASSERT(oa);
        LASSERT(ea);

        lsm = *ea;
        if (lsm == NULL) {
                rc = obd_alloc_memmd(exph, &lsm);
                if (rc < 0)
                        RETURN(rc);
        }

	/* this is the special case where create removes orphans */
	if (oa->o_valid == (OBD_MD_FLID | OBD_MD_FLFLAGS) &&
	    oa->o_flags == OBD_FL_DELORPHAN) {
		oa->o_id = oscc->oscc_next_id;
                rc = osc_real_create(oscc->oscc_exph, oa, ea, NULL);
		RETURN(rc);
	}

        while (try_again) {
                spin_lock(&oscc->oscc_lock);
                if (oscc->oscc_last_id >= oscc->oscc_next_id) {
                        memcpy(oa, &oscc->oscc_oa, sizeof(*oa));
                        oa->o_id = oscc->oscc_next_id;
                        lsm->lsm_object_id = oscc->oscc_next_id;
                        *ea = lsm;
                        oscc->oscc_next_id++;
                        try_again = 0;
                }
                spin_unlock(&oscc->oscc_lock);
                rc = oscc_precreate(oscc, osccd, try_again);
        }

        if (rc == 0)
                CDEBUG(D_INFO, "returning objid "LPU64"\n", lsm->lsm_object_id);
        else if (*ea == NULL)
                obd_free_memmd(exph, &lsm);
        RETURN(rc);
}

void osccd_do_create(struct osc_created *osccd)
{
        struct list_head *tmp;

 next:
        spin_lock(&osccd->osccd_lock);
        list_for_each (tmp, &osccd->osccd_queue_list_head) {
                int rc;
                struct osc_creator *oscc = list_entry(tmp, struct osc_creator,
                                                      oscc_list);
                list_del_init(&oscc->oscc_list);
                list_add(&oscc->oscc_list, &osccd->osccd_work_list_head);
                spin_lock(&oscc->oscc_lock);
		oscc->oscc_oa.o_id = oscc->oscc_last_id + oscc->oscc_grow_count;
		oscc->oscc_oa.o_valid |= OBD_MD_FLID;
                spin_unlock(&oscc->oscc_lock);
                spin_unlock(&osccd->osccd_lock);

                rc = osc_real_create(oscc->oscc_exph, &oscc->oscc_oa,
                                     &oscc->oscc_ea, NULL);

                spin_lock(&osccd->osccd_lock);
                spin_lock(&oscc->oscc_lock);
                list_del_init(&oscc->oscc_list);
                oscc->oscc_status = rc;
                oscc->oscc_last_id = oscc->oscc_oa.o_id;
                spin_unlock(&oscc->oscc_lock);
                spin_unlock(&osccd->osccd_lock);

                CDEBUG(D_INFO, "preallocated through id "LPU64" (last used "
                       LPU64")\n", oscc->oscc_last_id, oscc->oscc_next_id);
                wake_up(&oscc->oscc_waitq);
                goto next;
        }
        spin_unlock(&osccd->osccd_lock);
}

static int osccd_main(void *arg)
{
        struct osc_created *osccd = (struct osc_created *)arg;
        unsigned long flags;
        ENTRY;

        lock_kernel();
        kportal_daemonize("lustre_created");

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        unlock_kernel();

        /* Record that the  thread is running */
        osccd->osccd_flags =  OSCCD_RUNNING;
        wake_up(&osccd->osccd_ctl_waitq);

        /* And now, loop forever on requests */
        while (1) {
                struct l_wait_info lwi = { 0 };
                l_wait_event(osccd->osccd_waitq,
                             osccd->osccd_flags & (OSCCD_STOPPING|OSCCD_KICKED),
                             &lwi);

                spin_lock(&osccd->osccd_lock);
                if (osccd->osccd_flags & OSCCD_STOPPING) {
                        spin_unlock(&osccd->osccd_lock);
                        EXIT;
                        break;
                } else {
                        osccd->osccd_flags &= ~OSCCD_KICKED;
                        spin_unlock(&osccd->osccd_lock);
                        osccd_do_create(osccd);
                }
                spin_unlock(&osccd->osccd_created_lock);
        }

        osccd->osccd_thread = NULL;
        osccd->osccd_flags = OSCCD_STOPPED;
        wake_up(&osccd->osccd_ctl_waitq);
        CDEBUG(D_NET, "commit callback daemon exiting %d\n", current->pid);
        RETURN(0);
}

void oscc_init(struct lustre_handle *exph)
{
        struct obd_export *exp = class_conn2export(exph);
        struct osc_export_data *oed = &exp->exp_osc_data;

        memset(oed, 0, sizeof(*oed));
        INIT_LIST_HEAD(&oed->oed_oscc.oscc_list);
        init_waitqueue_head(&oed->oed_oscc.oscc_waitq);
        oed->oed_oscc.oscc_exph = exph;
        oed->oed_oscc.oscc_osccd = &osc_created;
        oed->oed_oscc.oscc_kick_barrier = 50;
        oed->oed_oscc.oscc_grow_count = 100;
        oed->oed_oscc.oscc_initial_create_count = 100;

        oed->oed_oscc.oscc_next_id = 2;
        oed->oed_oscc.oscc_last_id = 1;
        /* XXX the export handle should give the oscc the last object */
        /* oed->oed_oscc.oscc_last_id = exph->....; */

        class_export_put(exp);
}

int osccd_setup(void)
{
        struct osc_created *osccd = &osc_created;
        int rc;
        struct l_wait_info lwi = { 0 };
        ENTRY;

        INIT_LIST_HEAD(&osccd->osccd_queue_list_head);
        INIT_LIST_HEAD(&osccd->osccd_work_list_head);
        init_waitqueue_head(&osccd->osccd_ctl_waitq);
        init_waitqueue_head(&osccd->osccd_waitq);
        rc = kernel_thread(osccd_main, osccd,
                           CLONE_VM | CLONE_FS | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread\n");
                RETURN(rc);
        }
        l_wait_event(osccd->osccd_ctl_waitq, osccd->osccd_flags & OSCCD_RUNNING,
                     &lwi);
        RETURN(0);
}

int osccd_cleanup(void)
{
        struct osc_created *osccd = &osc_created;
        struct l_wait_info lwi = { 0 };
        ENTRY;

        spin_lock(&osccd->osccd_lock);
        osccd->osccd_flags = OSCCD_STOPPING;
        spin_unlock(&osccd->osccd_lock);

        wake_up(&osccd->osccd_waitq);
        l_wait_event(osccd->osccd_ctl_waitq,
                     osccd->osccd_flags & OSCCD_STOPPED, &lwi);
        RETURN(0);
}
