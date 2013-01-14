/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_ECHO
#ifdef __KERNEL__
#include <libcfs/libcfs.h>
#else
#include <liblustre.h>
#endif

#include <obd.h>
#include <obd_support.h>
#include <obd_class.h>
#include <obd_echo.h>
#include <lustre_debug.h>
#include <lprocfs_status.h>

static obd_id last_object_id;

#if 0
static void
echo_printk_object (char *msg, struct ec_object *eco)
{
        struct lov_stripe_md *lsm = eco->eco_lsm;
        int                   i;

        printk (KERN_INFO "Lustre: %s: object %p: "LPX64", refs %d%s: "LPX64
                "=%u!%u\n", msg, eco, eco->eco_id, eco->eco_refcount,
                eco->eco_deleted ? "(deleted) " : "",
                lsm->lsm_object_id, lsm->lsm_stripe_size,
                lsm->lsm_stripe_count);

        for (i = 0; i < lsm->lsm_stripe_count; i++)
                printk (KERN_INFO "Lustre:   @%2u:"LPX64"\n",
                        lsm->lsm_oinfo[i].loi_ost_idx,
                        lsm->lsm_oinfo[i].loi_id);
}
#endif

static struct ec_object *
echo_find_object_locked (struct obd_device *obd, obd_id id)
{
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct ec_object       *eco = NULL;
        struct list_head       *el;

        list_for_each (el, &ec->ec_objects) {
                eco = list_entry (el, struct ec_object, eco_obj_chain);

                if (eco->eco_id == id)
                        return (eco);
        }
        return (NULL);
}

static int
echo_copyout_lsm (struct lov_stripe_md *lsm, void *_ulsm, int ulsm_nob)
{
        struct lov_stripe_md *ulsm = _ulsm;
        int nob, i;

        nob = offsetof (struct lov_stripe_md, lsm_oinfo[lsm->lsm_stripe_count]);
        if (nob > ulsm_nob)
                return (-EINVAL);

        if (copy_to_user (ulsm, lsm, sizeof(ulsm)))
                return (-EFAULT);

        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                if (copy_to_user (ulsm->lsm_oinfo[i], lsm->lsm_oinfo[i],
                                  sizeof(lsm->lsm_oinfo[0])))
                        return (-EFAULT);
        }
        return (0);
}

static int
echo_copyin_lsm (struct obd_device *obd, struct lov_stripe_md *lsm,
                 void *ulsm, int ulsm_nob)
{
        struct echo_client_obd *ec = &obd->u.echo_client;
        int                     i;

        if (ulsm_nob < sizeof (*lsm))
                return (-EINVAL);

        if (copy_from_user (lsm, ulsm, sizeof (*lsm)))
                return (-EFAULT);

        if (lsm->lsm_stripe_count > ec->ec_nstripes ||
            lsm->lsm_magic != LOV_MAGIC ||
            (lsm->lsm_stripe_size & (~CFS_PAGE_MASK)) != 0 ||
            ((__u64)lsm->lsm_stripe_size * lsm->lsm_stripe_count > ~0UL))
                return (-EINVAL);

        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                if (copy_from_user(lsm->lsm_oinfo[i],
                                   ((struct lov_stripe_md *)ulsm)->lsm_oinfo[i],
                                   sizeof(lsm->lsm_oinfo[0])))
                        return (-EFAULT);
        }

        return (0);
}

static struct ec_object *
echo_allocate_object (struct obd_device *obd)
{
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct ec_object       *eco;
        int rc;

        OBD_ALLOC(eco, sizeof (*eco));
        if (eco == NULL)
                return NULL;

        rc = obd_alloc_memmd(ec->ec_exp, &eco->eco_lsm);
        if (rc < 0) {
                OBD_FREE(eco, sizeof (*eco));
                return NULL;
        }

        eco->eco_device = obd;
        eco->eco_deleted = 0;
        eco->eco_refcount = 0;
        eco->eco_lsm->lsm_magic = LOV_MAGIC;
        /* leave stripe count 0 by default */

        return (eco);
}

static void
echo_free_object (struct ec_object *eco)
{
        struct obd_device      *obd = eco->eco_device;
        struct echo_client_obd *ec = &obd->u.echo_client;

        LASSERT (eco->eco_refcount == 0);
        if (!eco->eco_lsm)
                CERROR("No object %s\n", obd->obd_name);
        else
                obd_free_memmd(ec->ec_exp, &eco->eco_lsm);
        OBD_FREE (eco, sizeof (*eco));
}

static int echo_create_object(struct obd_device *obd, int on_target,
                              struct obdo *oa, void *ulsm, int ulsm_nob,
                              struct obd_trans_info *oti)
{
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct ec_object       *eco2;
        struct ec_object       *eco;
        struct lov_stripe_md   *lsm;
        int                     rc;
        int                     i, idx;

        if ((oa->o_valid & OBD_MD_FLID) == 0 && /* no obj id */
            (on_target ||                       /* set_stripe */
             ec->ec_nstripes != 0)) {           /* LOV */
                CERROR ("No valid oid\n");
                return (-EINVAL);
        }

        if (ulsm != NULL) {
                eco = echo_allocate_object (obd);
                if (eco == NULL)
                        return (-ENOMEM);

                lsm = eco->eco_lsm;

                rc = echo_copyin_lsm (obd, lsm, ulsm, ulsm_nob);
                if (rc != 0)
                        goto failed;

                /* setup object ID here for !on_target and LOV hint */
                if ((oa->o_valid & OBD_MD_FLID) != 0)
                        eco->eco_id = lsm->lsm_object_id = oa->o_id;

                if (lsm->lsm_stripe_count == 0)
                        lsm->lsm_stripe_count = ec->ec_nstripes;

                if (lsm->lsm_stripe_size == 0)
                        lsm->lsm_stripe_size = CFS_PAGE_SIZE;

                idx = ll_rand();

                /* setup stripes: indices + default ids if required */
                for (i = 0; i < lsm->lsm_stripe_count; i++) {
                        if (lsm->lsm_oinfo[i]->loi_id == 0)
                                lsm->lsm_oinfo[i]->loi_id = lsm->lsm_object_id;

                        lsm->lsm_oinfo[i]->loi_ost_idx =
                                (idx + i) % ec->ec_nstripes;
                }
        } else {
                OBD_ALLOC(eco, sizeof(*eco));
                if (!eco)
                        return (-ENOMEM);
                eco->eco_device = obd;
                lsm = NULL;
        }

        if (oa->o_id == 0)
                oa->o_id = ++last_object_id;

        if (on_target) {
                oa->o_gr = FILTER_GROUP_ECHO;
                oa->o_valid |= OBD_MD_FLGROUP;

                rc = obd_create(ec->ec_exp, oa, &lsm, oti);
                if (rc != 0)
                        goto failed;

                /* See what object ID we were given */
                eco->eco_id = oa->o_id = lsm->lsm_object_id;
                oa->o_valid |= OBD_MD_FLID;

                LASSERT(eco->eco_lsm == NULL || eco->eco_lsm == lsm);
                eco->eco_lsm = lsm;
        }

        spin_lock (&ec->ec_lock);

        eco2 = echo_find_object_locked (obd, oa->o_id);
        if (eco2 != NULL) {                     /* conflict */
                spin_unlock (&ec->ec_lock);

                CERROR ("Can't create object id "LPX64": id already exists%s\n",
                        oa->o_id, on_target ? " (undoing create)" : "");

                if (on_target)
                        obd_destroy(ec->ec_exp, oa, lsm, oti, NULL);

                rc = -EEXIST;
                goto failed;
        }

        list_add (&eco->eco_obj_chain, &ec->ec_objects);
        spin_unlock (&ec->ec_lock);
        CDEBUG (D_INFO,
                "created %p: "LPX64"=%u#%u@%u refs %d del %d\n",
                eco, eco->eco_id,
                eco->eco_lsm->lsm_stripe_size,
                eco->eco_lsm->lsm_stripe_count,
                eco->eco_lsm->lsm_oinfo[0]->loi_ost_idx,
                eco->eco_refcount, eco->eco_deleted);
        return (0);

 failed:
        echo_free_object (eco);
        if (rc)
                CERROR("%s: err %d on create\n", obd->obd_name, rc);
        return (rc);
}

static int
echo_get_object (struct ec_object **ecop, struct obd_device *obd,
                 struct obdo *oa)
{
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct ec_object       *eco;
        struct ec_object       *eco2;
        int                     rc;

        if ((oa->o_valid & OBD_MD_FLID) == 0 ||
            oa->o_id == 0)                      /* disallow use of object id 0 */
        {
                CERROR ("No valid oid\n");
                return (-EINVAL);
        }

        spin_lock (&ec->ec_lock);
        eco = echo_find_object_locked (obd, oa->o_id);
        if (eco != NULL) {
                if (eco->eco_deleted) {           /* being deleted */
                        spin_unlock(&ec->ec_lock);/* (see comment in cleanup) */
                        return (-EAGAIN);
                }

                eco->eco_refcount++;
                spin_unlock (&ec->ec_lock);
                *ecop = eco;
                CDEBUG (D_INFO,
                        "found %p: "LPX64"=%u#%u@%u refs %d del %d\n",
                        eco, eco->eco_id,
                        eco->eco_lsm->lsm_stripe_size,
                        eco->eco_lsm->lsm_stripe_count,
                        eco->eco_lsm->lsm_oinfo[0]->loi_ost_idx,
                        eco->eco_refcount, eco->eco_deleted);
                return (0);
        }
        spin_unlock (&ec->ec_lock);

        if (ec->ec_nstripes != 0)               /* striping required */
                return (-ENOENT);

        eco = echo_allocate_object (obd);
        if (eco == NULL)
                return (-ENOMEM);

        eco->eco_id = eco->eco_lsm->lsm_object_id = oa->o_id;

        spin_lock (&ec->ec_lock);

        eco2 = echo_find_object_locked (obd, oa->o_id);
        if (eco2 == NULL) {                     /* didn't race */
                list_add (&eco->eco_obj_chain, &ec->ec_objects);
                spin_unlock (&ec->ec_lock);
                eco->eco_refcount = 1;
                *ecop = eco;
                CDEBUG (D_INFO,
                        "created %p: "LPX64"=%u#%u@%d refs %d del %d\n",
                        eco, eco->eco_id,
                        eco->eco_lsm->lsm_stripe_size,
                        eco->eco_lsm->lsm_stripe_count,
                        eco->eco_lsm->lsm_oinfo[0]->loi_ost_idx,
                        eco->eco_refcount, eco->eco_deleted);
                return (0);
        }

        if (eco2->eco_deleted)
                rc = -EAGAIN;                   /* lose race */
        else {
                eco2->eco_refcount++;           /* take existing */
                *ecop = eco2;
                rc = 0;
                LASSERT (eco2->eco_id == eco2->eco_lsm->lsm_object_id);
                CDEBUG (D_INFO,
                        "found(2) %p: "LPX64"=%u#%u@%d refs %d del %d\n",
                        eco2, eco2->eco_id,
                        eco2->eco_lsm->lsm_stripe_size,
                        eco2->eco_lsm->lsm_stripe_count,
                        eco2->eco_lsm->lsm_oinfo[0]->loi_ost_idx,
                        eco2->eco_refcount, eco2->eco_deleted);
        }

        spin_unlock (&ec->ec_lock);

        echo_free_object (eco);
        return (rc);
}

static void
echo_put_object (struct ec_object *eco)
{
        struct obd_device      *obd = eco->eco_device;
        struct echo_client_obd *ec = &obd->u.echo_client;

        /* Release caller's ref on the object.
         * delete => mark for deletion when last ref goes
         */

        spin_lock (&ec->ec_lock);

        eco->eco_refcount--;
        LASSERT (eco->eco_refcount >= 0);

        CDEBUG(D_INFO, "put %p: "LPX64"=%u#%u@%d refs %d del %d\n",
               eco, eco->eco_id,
               eco->eco_lsm->lsm_stripe_size,
               eco->eco_lsm->lsm_stripe_count,
               eco->eco_lsm->lsm_oinfo[0]->loi_ost_idx,
               eco->eco_refcount, eco->eco_deleted);

        if (eco->eco_refcount != 0 || !eco->eco_deleted) {
                spin_unlock (&ec->ec_lock);
                return;
        }

        spin_unlock (&ec->ec_lock);

        /* NB leave obj in the object list.  We must prevent anyone from
         * attempting to enqueue on this object number until we can be
         * sure there will be no more lock callbacks.
         */
        obd_cancel_unused(ec->ec_exp, eco->eco_lsm, 0, NULL);

        /* now we can let it go */
        spin_lock (&ec->ec_lock);
        list_del (&eco->eco_obj_chain);
        spin_unlock (&ec->ec_lock);

        LASSERT (eco->eco_refcount == 0);

        echo_free_object (eco);
}

static void
echo_get_stripe_off_id (struct lov_stripe_md *lsm, obd_off *offp, obd_id *idp)
{
        unsigned long stripe_count;
        unsigned long stripe_size;
        unsigned long width;
        unsigned long woffset;
        int           stripe_index;
        obd_off       offset;

        if (lsm->lsm_stripe_count <= 1)
                return;

        offset       = *offp;
        stripe_size  = lsm->lsm_stripe_size;
        stripe_count = lsm->lsm_stripe_count;

        /* width = # bytes in all stripes */
        width = stripe_size * stripe_count;

        /* woffset = offset within a width; offset = whole number of widths */
        woffset = do_div (offset, width);

        stripe_index = woffset / stripe_size;

        *idp = lsm->lsm_oinfo[stripe_index]->loi_id;
        *offp = offset * stripe_size + woffset % stripe_size;
}

static void
echo_client_page_debug_setup(struct lov_stripe_md *lsm,
                             cfs_page_t *page, int rw, obd_id id,
                             obd_off offset, obd_off count)
{
        char    *addr;
        obd_off  stripe_off;
        obd_id   stripe_id;
        int      delta;

        /* no partial pages on the client */
        LASSERT(count == CFS_PAGE_SIZE);

        addr = cfs_kmap(page);

        for (delta = 0; delta < CFS_PAGE_SIZE; delta += OBD_ECHO_BLOCK_SIZE) {
                if (rw == OBD_BRW_WRITE) {
                        stripe_off = offset + delta;
                        stripe_id = id;
                        echo_get_stripe_off_id(lsm, &stripe_off, &stripe_id);
                } else {
                        stripe_off = 0xdeadbeef00c0ffeeULL;
                        stripe_id = 0xdeadbeef00c0ffeeULL;
                }
                block_debug_setup(addr + delta, OBD_ECHO_BLOCK_SIZE,
                                  stripe_off, stripe_id);
        }

        cfs_kunmap(page);
}

static int
echo_client_page_debug_check(struct lov_stripe_md *lsm,
                             cfs_page_t *page, obd_id id,
                             obd_off offset, obd_off count)
{
        obd_off stripe_off;
        obd_id  stripe_id;
        char   *addr;
        int     delta;
        int     rc;
        int     rc2;

        /* no partial pages on the client */
        LASSERT(count == CFS_PAGE_SIZE);

        addr = cfs_kmap(page);

        for (rc = delta = 0; delta < CFS_PAGE_SIZE; delta += OBD_ECHO_BLOCK_SIZE) {
                stripe_off = offset + delta;
                stripe_id = id;
                echo_get_stripe_off_id (lsm, &stripe_off, &stripe_id);

                rc2 = block_debug_check("test_brw",
                                        addr + delta, OBD_ECHO_BLOCK_SIZE,
                                        stripe_off, stripe_id);
                if (rc2 != 0) {
                        CERROR ("Error in echo object "LPX64"\n", id);
                        rc = rc2;
                }
        }

        cfs_kunmap(page);
        return rc;
}

static int echo_client_kbrw(struct obd_device *obd, int rw, struct obdo *oa,
                            struct lov_stripe_md *lsm, obd_off offset,
                            obd_size count, struct obd_trans_info *oti)
{
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct obd_info         oinfo = { { { 0 } } };
        obd_count               npages;
        struct ptlrpc_request_set *set = NULL;
        struct brw_page        *pga;
        struct brw_page        *pgp;
        obd_off                 off;
        int                     i;
        int                     rc;
        int                     verify;
        int                     gfp_mask;
        int                     brw_flags = 0;

        verify = ((oa->o_id) != ECHO_PERSISTENT_OBJID &&
                  (oa->o_valid & OBD_MD_FLFLAGS) != 0 &&
                  (oa->o_flags & OBD_FL_DEBUG_CHECK) != 0);

        gfp_mask = ((oa->o_id & 2) == 0) ? CFS_ALLOC_STD : CFS_ALLOC_HIGHUSER;

        LASSERT(rw == OBD_BRW_WRITE || rw == OBD_BRW_READ);
        LASSERT(lsm != NULL);
        LASSERT(lsm->lsm_object_id == oa->o_id);

        if (count <= 0 ||
            (count & (~CFS_PAGE_MASK)) != 0)
                return (-EINVAL);

        if (rw == OBD_BRW_WRITE)
                brw_flags = OBD_BRW_ASYNC;

        set =  ptlrpc_prep_set();
        if (set == NULL)
                RETURN(-ENOMEM);

        /* XXX think again with misaligned I/O */
        npages = count >> CFS_PAGE_SHIFT;

        OBD_ALLOC(pga, npages * sizeof(*pga));
        if (pga == NULL) {
                rc = -ENOMEM;
                goto out_set;
        }

        for (i = 0, pgp = pga, off = offset;
             i < npages;
             i++, pgp++, off += CFS_PAGE_SIZE) {

                LASSERT (pgp->pg == NULL);      /* for cleanup */

                rc = -ENOMEM;
                OBD_PAGE_ALLOC(pgp->pg, gfp_mask);
                if (pgp->pg == NULL)
                        goto out;

                pgp->count = CFS_PAGE_SIZE;
                pgp->off = off;
                pgp->flag = brw_flags;

                if (verify)
                        echo_client_page_debug_setup(lsm, pgp->pg, rw,
                                                     oa->o_id, off, pgp->count);
        }

        oinfo.oi_oa = oa;
        oinfo.oi_md = lsm;

        /* OST/filter device don't support o_brw_async ops, turn to o_brw ops */
        if (ec->ec_exp && ec->ec_exp->exp_obd &&
            OBT(ec->ec_exp->exp_obd) && OBP(ec->ec_exp->exp_obd, brw_async)) {
                rc = obd_brw_async(rw, ec->ec_exp, &oinfo, npages, pga, oti,
                                   set, 0);
                if (rc == 0) {
                        rc = ptlrpc_set_wait(set);
                        if (rc)
                                CERROR("error from callback: rc = %d\n", rc);
                }
        } else {
                rc = obd_brw(rw, ec->ec_exp, &oinfo, npages, pga, oti);
        }
        if (rc)
                CDEBUG_LIMIT(rc == -ENOSPC ? D_INODE : D_ERROR,
                             "error from obd_brw_async: rc = %d\n", rc);
 out:
        if (rc != 0 || rw != OBD_BRW_READ)
                verify = 0;

        for (i = 0, pgp = pga; i < npages; i++, pgp++) {
                if (pgp->pg == NULL)
                        continue;

                if (verify) {
                        int vrc;
                        vrc = echo_client_page_debug_check(lsm, pgp->pg, oa->o_id,
                                                           pgp->off, pgp->count);
                        if (vrc != 0 && rc == 0)
                                rc = vrc;
                }
                OBD_PAGE_FREE(pgp->pg);
        }
        OBD_FREE(pga, npages * sizeof(*pga));
 out_set:
        ptlrpc_set_destroy(set);
        return (rc);
}

struct echo_async_state;

#define EAP_MAGIC 79277927
struct echo_async_page {
        int                     eap_magic;
        cfs_page_t             *eap_page;
        void                    *eap_cookie;
        obd_off                 eap_off;
        struct echo_async_state *eap_eas;
        struct list_head        eap_item;
};

#define EAP_FROM_COOKIE(c)                                                      \
        (LASSERT(((struct echo_async_page *)(c))->eap_magic == EAP_MAGIC),      \
         (struct echo_async_page *)(c))

struct echo_async_state {
        spinlock_t              eas_lock;
        obd_off                 eas_next_offset;
        obd_off                 eas_end_offset;
        int                     eas_in_flight;
        int                     eas_rc;
        cfs_waitq_t             eas_waitq;
        struct list_head        eas_avail;
        struct obdo             eas_oa;
        struct lov_stripe_md    *eas_lsm;
};

static int eas_should_wake(struct echo_async_state *eas)
{
        int rc = 0;

        spin_lock(&eas->eas_lock);
        if (eas->eas_rc == 0 && !list_empty(&eas->eas_avail))
            rc = 1;
        spin_unlock(&eas->eas_lock);
        return rc;
};

static int ec_ap_make_ready(void *data, int cmd)
{
        /* our pages are issued ready */
        LBUG();
        return 0;
}
static int ec_ap_refresh_count(void *data, int cmd)
{
        /* our pages are issued with a stable count */
        LBUG();
        return CFS_PAGE_SIZE;
}
static void ec_ap_fill_obdo(void *data, int cmd, struct obdo *oa)
{
        struct echo_async_page *eap = EAP_FROM_COOKIE(data);

        lustre_set_wire_obdo(oa, &eap->eap_eas->eas_oa);
}

static int ec_ap_completion(void *data, int cmd, struct obdo *oa, int rc)
{
        struct echo_async_page *eap = EAP_FROM_COOKIE(data);
        struct echo_async_state *eas;

        eas = eap->eap_eas;

        if (cmd == OBD_BRW_READ &&
            eas->eas_oa.o_id != ECHO_PERSISTENT_OBJID &&
            (eas->eas_oa.o_valid & OBD_MD_FLFLAGS) != 0 &&
            (eas->eas_oa.o_flags & OBD_FL_DEBUG_CHECK) != 0)
                echo_client_page_debug_check(eas->eas_lsm, eap->eap_page,
                                             eas->eas_oa.o_id, eap->eap_off,
                                             CFS_PAGE_SIZE);

        spin_lock(&eas->eas_lock);
        if (rc && !eas->eas_rc)
                eas->eas_rc = rc;
        eas->eas_in_flight--;
        list_add(&eap->eap_item, &eas->eas_avail);
        cfs_waitq_signal(&eas->eas_waitq);
        spin_unlock(&eas->eas_lock);
        return 0;
}

static struct obd_async_page_ops ec_async_page_ops = {
        .ap_make_ready =        ec_ap_make_ready,
        .ap_refresh_count =     ec_ap_refresh_count,
        .ap_fill_obdo =         ec_ap_fill_obdo,
        .ap_completion =        ec_ap_completion,
};

static int echo_client_async_page(struct obd_export *exp, int rw,
                                   struct obdo *oa, struct lov_stripe_md *lsm,
                                   obd_off offset, obd_size count,
                                   obd_size batching)
{
        obd_count npages, i;
        struct echo_async_page *eap;
        struct echo_async_state *eas;
        int rc = 0;
        struct echo_async_page **aps = NULL;
        int brw_flags = 0;

        ENTRY;
#if 0
        int                     verify;
        int                     gfp_mask;

        verify = ((oa->o_id) != ECHO_PERSISTENT_OBJID &&
                  (oa->o_valid & OBD_MD_FLFLAGS) != 0 &&
                  (oa->o_flags & OBD_FL_DEBUG_CHECK) != 0);

        gfp_mask = ((oa->o_id & 2) == 0) ? GFP_KERNEL : GFP_HIGHUSER;
#endif

        LASSERT(rw == OBD_BRW_WRITE || rw == OBD_BRW_READ);

        if (count <= 0 ||
            (count & (~CFS_PAGE_MASK)) != 0 ||
            (lsm != NULL &&
             lsm->lsm_object_id != oa->o_id))
                return (-EINVAL);

        /* XXX think again with misaligned I/O */
        npages = batching >> CFS_PAGE_SHIFT;

        OBD_ALLOC_PTR(eas);
        if (NULL == eas)
                return(-ENOMEM);

        if (rw == OBD_BRW_WRITE)
                brw_flags = OBD_BRW_ASYNC;

        memcpy(&eas->eas_oa, oa, sizeof(*oa));
        eas->eas_next_offset = offset;
        eas->eas_end_offset = offset + count;
        spin_lock_init(&eas->eas_lock);
        cfs_waitq_init(&eas->eas_waitq);
        eas->eas_in_flight = 0;
        eas->eas_rc = 0;
        eas->eas_lsm = lsm;
        CFS_INIT_LIST_HEAD(&eas->eas_avail);

        OBD_ALLOC(aps, npages * sizeof aps[0]);
        if (aps == NULL)
                GOTO(free_eas, rc = -ENOMEM);

        /* prepare the group of pages that we're going to be keeping
         * in flight */
        for (i = 0; i < npages; i++) {
                cfs_page_t *page;
                OBD_PAGE_ALLOC(page, CFS_ALLOC_STD);
                if (page == NULL)
                        GOTO(out, rc = -ENOMEM);

                OBD_ALLOC(eap, sizeof(*eap));
                if (eap == NULL) {
                        OBD_PAGE_FREE(page);
                        GOTO(out, rc = -ENOMEM);
                }

                eap->eap_magic = EAP_MAGIC;
                eap->eap_page = page;
                eap->eap_eas = eas;
                list_add_tail(&eap->eap_item, &eas->eas_avail);
                aps[i] = eap;
        }

        /* first we spin queueing io and being woken by its completion */
        spin_lock(&eas->eas_lock);
        for(;;) {
                int rc;

                /* sleep until we have a page to send */
                spin_unlock(&eas->eas_lock);
                rc = wait_event_interruptible(eas->eas_waitq,
                                              eas_should_wake(eas));
                spin_lock(&eas->eas_lock);
                if (rc && !eas->eas_rc)
                        eas->eas_rc = rc;
                if (eas->eas_rc)
                        break;
                if (list_empty(&eas->eas_avail))
                        continue;
                eap = list_entry(eas->eas_avail.next, struct echo_async_page,
                                 eap_item);
                list_del(&eap->eap_item);
                spin_unlock(&eas->eas_lock);

                /* unbind the eap from its old page offset */
                if (eap->eap_cookie != NULL) {
                        obd_teardown_async_page(exp, lsm, NULL,
                                                eap->eap_cookie);
                        eap->eap_cookie = NULL;
                }

                eas->eas_next_offset += CFS_PAGE_SIZE;
                eap->eap_off = eas->eas_next_offset;

                rc = obd_prep_async_page(exp, lsm, NULL, eap->eap_page,
                                         eap->eap_off, &ec_async_page_ops,
                                         eap, &eap->eap_cookie,
                                         OBD_PAGE_NO_CACHE, NULL);
                if (rc) {
                        spin_lock(&eas->eas_lock);
                        eas->eas_rc = rc;
                        break;
                }

                if (oa->o_id != ECHO_PERSISTENT_OBJID &&
                    (oa->o_valid & OBD_MD_FLFLAGS) != 0 &&
                    (oa->o_flags & OBD_FL_DEBUG_CHECK) != 0)
                        echo_client_page_debug_setup(lsm, eap->eap_page, rw,
                                                     oa->o_id,
                                                     eap->eap_off, CFS_PAGE_SIZE);

                /* always asserts urgent, which isn't quite right */
                rc = obd_queue_async_io(exp, lsm, NULL, eap->eap_cookie,
                                        rw, 0, CFS_PAGE_SIZE, brw_flags,
                                        ASYNC_READY | ASYNC_URGENT |
                                        ASYNC_COUNT_STABLE);
                spin_lock(&eas->eas_lock);
                if (rc && !eas->eas_rc) {
                        eas->eas_rc = rc;
                        break;
                }
                eas->eas_in_flight++;
                if (eas->eas_next_offset == eas->eas_end_offset)
                        break;
        }

        /* still hold the eas_lock here.. */

        /* now we just spin waiting for all the rpcs to complete */
        while(eas->eas_in_flight) {
                spin_unlock(&eas->eas_lock);
                wait_event_interruptible(eas->eas_waitq,
                                         eas->eas_in_flight == 0);
                spin_lock(&eas->eas_lock);
        }
        spin_unlock(&eas->eas_lock);

out:
        if (aps != NULL) {
                for (i = 0; i < npages; ++ i) {
                        eap = aps[i];
                        if (eap != NULL) {
                                cfs_page_t *page;

                                page = eap->eap_page;
                                if (eap->eap_cookie != NULL)
                                        obd_teardown_async_page(exp, lsm, NULL,
                                                                eap->eap_cookie);
                                OBD_FREE(eap, sizeof(*eap));
                                OBD_PAGE_FREE(page);
                        }
                }
                OBD_FREE(aps, npages * sizeof aps[0]);
        }
free_eas:
        OBD_FREE_PTR(eas);

        RETURN(rc);
}

static int echo_client_prep_commit(struct obd_export *exp, int rw,
                                   struct obdo *oa, struct lov_stripe_md *lsm,
                                   obd_off offset, obd_size count,
                                   obd_size batch, struct obd_trans_info *oti)
{
        struct obd_ioobj ioo;
        struct niobuf_local *lnb;
        struct niobuf_remote *rnb;
        obd_off off;
        obd_size npages, tot_pages;
        int i, ret = 0;
        ENTRY;

        if (count <= 0 || (count & (~CFS_PAGE_MASK)) != 0 ||
            (lsm != NULL && lsm->lsm_object_id != oa->o_id))
                RETURN(-EINVAL);

        npages = batch >> CFS_PAGE_SHIFT;
        tot_pages = count >> CFS_PAGE_SHIFT;

        OBD_ALLOC(lnb, npages * sizeof(struct niobuf_local));
        OBD_ALLOC(rnb, npages * sizeof(struct niobuf_remote));

        if (lnb == NULL || rnb == NULL)
                GOTO(out, ret = -ENOMEM);

        obdo_to_ioobj(oa, &ioo);

        off = offset;

        for(; tot_pages; tot_pages -= npages) {
                int lpages;

                if (tot_pages < npages)
                        npages = tot_pages;

                for (i = 0; i < npages; i++, off += CFS_PAGE_SIZE) {
                        rnb[i].offset = off;
                        rnb[i].len = CFS_PAGE_SIZE;
                }

                ioo.ioo_bufcnt = npages;
                oti->oti_transno = 0;

                lpages = npages;
                ret = obd_preprw(rw, exp, oa, 1, &ioo, rnb, &lpages, lnb, oti);
                if (ret != 0)
                        GOTO(out, ret);
                LASSERT(lpages == npages);

                for (i = 0; i < lpages; i++) {
                        cfs_page_t *page = lnb[i].page;

                        /* read past eof? */
                        if (page == NULL && lnb[i].rc == 0)
                                continue;

                        if (oa->o_id == ECHO_PERSISTENT_OBJID ||
                            (oa->o_valid & OBD_MD_FLFLAGS) == 0 ||
                            (oa->o_flags & OBD_FL_DEBUG_CHECK) == 0)
                                continue;

                        if (rw == OBD_BRW_WRITE)
                                echo_client_page_debug_setup(lsm, page, rw,
                                                             oa->o_id,
                                                             rnb[i].offset,
                                                             rnb[i].len);
                        else
                                echo_client_page_debug_check(lsm, page,
                                                             oa->o_id,
                                                             rnb[i].offset,
                                                             rnb[i].len);
                }

                ret = obd_commitrw(rw, exp, oa, 1,&ioo,rnb,npages,lnb,oti,ret);
                if (ret != 0)
                        GOTO(out, ret);
        }

out:
        if (lnb)
                OBD_FREE(lnb, npages * sizeof(struct niobuf_local));
        if (rnb)
                OBD_FREE(rnb, npages * sizeof(struct niobuf_remote));
        RETURN(ret);
}

int echo_client_brw_ioctl(int rw, struct obd_export *exp,
                          struct obd_ioctl_data *data)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct obd_trans_info dummy_oti = { .oti_thread = NULL };
        struct ec_object *eco;
        int rc;
        ENTRY;

        rc = echo_get_object(&eco, obd, &data->ioc_obdo1);
        if (rc)
                RETURN(rc);

        data->ioc_obdo1.o_valid &= ~OBD_MD_FLHANDLE;
        data->ioc_obdo1.o_valid |= OBD_MD_FLGROUP;
        data->ioc_obdo1.o_gr = FILTER_GROUP_ECHO;

        switch((long)data->ioc_pbuf1) {
        case 1:
                rc = echo_client_kbrw(obd, rw, &data->ioc_obdo1,
                                      eco->eco_lsm, data->ioc_offset,
                                      data->ioc_count, &dummy_oti);
                break;
        case 2:
                rc = echo_client_async_page(ec->ec_exp, rw, &data->ioc_obdo1,
                                           eco->eco_lsm, data->ioc_offset,
                                           data->ioc_count, data->ioc_plen1);
                break;
        case 3:
                rc = echo_client_prep_commit(ec->ec_exp, rw, &data->ioc_obdo1,
                                            eco->eco_lsm, data->ioc_offset,
                                            data->ioc_count, data->ioc_plen1,
                                            &dummy_oti);
                break;
        default:
                rc = -EINVAL;
        }
        echo_put_object(eco);
        RETURN(rc);
}

static int
echo_ldlm_callback (struct ldlm_lock *lock, struct ldlm_lock_desc *new,
                    void *data, int flag)
{
        struct ec_object       *eco = (struct ec_object *)data;
        struct echo_client_obd *ec = &(eco->eco_device->u.echo_client);
        struct lustre_handle    lockh;
        struct list_head       *el;
        int                     found = 0;
        int                     rc;

        ldlm_lock2handle (lock, &lockh);

        /* #ifdef this out if we're not feeling paranoid */
        spin_lock (&ec->ec_lock);
        list_for_each (el, &ec->ec_objects) {
                found = (eco == list_entry(el, struct ec_object,
                                           eco_obj_chain));
                if (found)
                        break;
        }
        spin_unlock (&ec->ec_lock);
        LASSERT (found);

        switch (flag) {
        case LDLM_CB_BLOCKING:
                CDEBUG(D_INFO, "blocking callback on "LPX64", handle "LPX64"\n",
                       eco->eco_id, lockh.cookie);
                rc = ldlm_cli_cancel (&lockh);
                if (rc != ELDLM_OK)
                        CERROR ("ldlm_cli_cancel failed: %d\n", rc);
                break;

        case LDLM_CB_CANCELING:
                CDEBUG(D_INFO, "cancel callback on "LPX64", handle "LPX64"\n",
                       eco->eco_id, lockh.cookie);
                break;

        default:
                LBUG ();
        }

        return (0);
}

static int
echo_client_enqueue(struct obd_export *exp, struct obdo *oa,
                    int mode, obd_off offset, obd_size nob)
{
        struct obd_device      *obd = exp->exp_obd;
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct lustre_handle   *ulh = &oa->o_handle;
        struct ldlm_enqueue_info einfo = { 0 };
        struct obd_info oinfo = { { { 0 } } };
        struct ec_object       *eco;
        struct ec_lock         *ecl;
        int                     rc;

        if (!(mode == LCK_PR || mode == LCK_PW))
                return -EINVAL;

        if ((offset & (~CFS_PAGE_MASK)) != 0 ||
            (nob & (~CFS_PAGE_MASK)) != 0)
                return -EINVAL;

        rc = echo_get_object (&eco, obd, oa);
        if (rc != 0)
                return rc;

        rc = -ENOMEM;
        OBD_ALLOC (ecl, sizeof (*ecl));
        if (ecl == NULL)
                goto failed_0;

        ecl->ecl_mode = mode;
        ecl->ecl_object = eco;
        ecl->ecl_policy.l_extent.start = offset;
        ecl->ecl_policy.l_extent.end =
                (nob == 0) ? ((obd_off) -1) : (offset + nob - 1);

        einfo.ei_type = LDLM_EXTENT;
        einfo.ei_mode = mode;
        einfo.ei_cb_bl = echo_ldlm_callback;
        einfo.ei_cb_cp = ldlm_completion_ast;
        einfo.ei_cb_gl = NULL;
        einfo.ei_cbdata = eco;

        oinfo.oi_policy = ecl->ecl_policy;
        oinfo.oi_lockh = &ecl->ecl_lock_handle;
        oinfo.oi_md = eco->eco_lsm;
        rc = obd_enqueue(ec->ec_exp, &oinfo, &einfo, NULL);
        if (rc != 0)
                goto failed_1;

        CDEBUG(D_INFO, "enqueue handle "LPX64"\n", ecl->ecl_lock_handle.cookie);

        /* NB ecl takes object ref from echo_get_object() above */
        spin_lock(&ec->ec_lock);

        list_add(&ecl->ecl_exp_chain, &exp->exp_ec_data.eced_locks);
        ulh->cookie = ecl->ecl_cookie = ec->ec_unique++;

        spin_unlock(&ec->ec_lock);

        oa->o_valid |= OBD_MD_FLHANDLE;
        return 0;

 failed_1:
        OBD_FREE (ecl, sizeof (*ecl));
 failed_0:
        echo_put_object (eco);
        return (rc);
}

static int
echo_client_cancel(struct obd_export *exp, struct obdo *oa)
{
        struct obd_device      *obd = exp->exp_obd;
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct lustre_handle   *ulh = &oa->o_handle;
        struct ec_lock         *ecl = NULL;
        int                     found = 0;
        struct list_head       *el;
        int                     rc;

        if ((oa->o_valid & OBD_MD_FLHANDLE) == 0)
                return -EINVAL;

        spin_lock (&ec->ec_lock);

        list_for_each (el, &exp->exp_ec_data.eced_locks) {
                ecl = list_entry (el, struct ec_lock, ecl_exp_chain);
                found = (ecl->ecl_cookie == ulh->cookie);
                if (found) {
                        list_del (&ecl->ecl_exp_chain);
                        break;
                }
        }

        spin_unlock (&ec->ec_lock);

        if (!found)
                return (-ENOENT);

        rc = obd_cancel(ec->ec_exp, ecl->ecl_object->eco_lsm, ecl->ecl_mode,
                        &ecl->ecl_lock_handle, 0, 0);

        echo_put_object (ecl->ecl_object);
        OBD_FREE (ecl, sizeof (*ecl));

        return rc;
}

static int
echo_client_iocontrol(unsigned int cmd, struct obd_export *exp,
                      int len, void *karg, void *uarg)
{
        struct obd_device      *obd;
        struct echo_client_obd *ec;
        struct ec_object       *eco;
        struct obd_ioctl_data  *data = karg;
        struct obd_trans_info   dummy_oti;
        struct oti_req_ack_lock *ack_lock;
        struct obdo            *oa;
        int                     rw = OBD_BRW_READ;
        int                     rc = 0;
        int                     i;
        ENTRY;

#ifndef HAVE_UNLOCKED_IOCTL
        unlock_kernel();
#endif
        memset(&dummy_oti, 0, sizeof(dummy_oti));

        obd = exp->exp_obd;
        ec = &obd->u.echo_client;

        switch (cmd) {
        case OBD_IOC_CREATE:                    /* may create echo object */
                if (!cfs_capable(CFS_CAP_SYS_ADMIN))
                        GOTO (out, rc = -EPERM);

                rc = echo_create_object (obd, 1, &data->ioc_obdo1,
                                         data->ioc_pbuf1, data->ioc_plen1,
                                         &dummy_oti);
                GOTO(out, rc);

        case OBD_IOC_DESTROY:
                if (!cfs_capable(CFS_CAP_SYS_ADMIN))
                        GOTO (out, rc = -EPERM);
                rc = echo_get_object (&eco, obd, &data->ioc_obdo1);
                if (rc == 0) {
                        oa = &data->ioc_obdo1;
                        oa->o_gr = FILTER_GROUP_ECHO;
                        oa->o_valid |= OBD_MD_FLGROUP;
                        rc = obd_destroy(ec->ec_exp, oa, eco->eco_lsm,
                                         &dummy_oti, NULL);
                        if (rc == 0)
                                eco->eco_deleted = 1;
                        echo_put_object(eco);
                }
                GOTO(out, rc);

        case OBD_IOC_GETATTR:
                rc = echo_get_object (&eco, obd, &data->ioc_obdo1);
                if (rc == 0) {
                        struct obd_info oinfo = { { { 0 } } };
                        oinfo.oi_md = eco->eco_lsm;
                        oinfo.oi_oa = &data->ioc_obdo1;
                        rc = obd_getattr(ec->ec_exp, &oinfo);
                        echo_put_object(eco);
                }
                GOTO(out, rc);

        case OBD_IOC_SETATTR:
                if (!cfs_capable(CFS_CAP_SYS_ADMIN))
                        GOTO (out, rc = -EPERM);

                rc = echo_get_object (&eco, obd, &data->ioc_obdo1);
                if (rc == 0) {
                        struct obd_info oinfo = { { { 0 } } };
                        oinfo.oi_oa = &data->ioc_obdo1;
                        oinfo.oi_md = eco->eco_lsm;

                        rc = obd_setattr(ec->ec_exp, &oinfo, NULL);
                        echo_put_object(eco);
                }
                GOTO(out, rc);

        case OBD_IOC_BRW_WRITE:
                if (!cfs_capable(CFS_CAP_SYS_ADMIN))
                        GOTO (out, rc = -EPERM);

                rw = OBD_BRW_WRITE;
                /* fall through */
        case OBD_IOC_BRW_READ:
                rc = echo_client_brw_ioctl(rw, exp, data);
                GOTO(out, rc);

        case ECHO_IOC_GET_STRIPE:
                rc = echo_get_object(&eco, obd, &data->ioc_obdo1);
                if (rc == 0) {
                        rc = echo_copyout_lsm(eco->eco_lsm, data->ioc_pbuf1,
                                              data->ioc_plen1);
                        echo_put_object(eco);
                }
                GOTO(out, rc);

        case ECHO_IOC_SET_STRIPE:
                if (!cfs_capable(CFS_CAP_SYS_ADMIN))
                        GOTO (out, rc = -EPERM);

                if (data->ioc_pbuf1 == NULL) {  /* unset */
                        rc = echo_get_object(&eco, obd, &data->ioc_obdo1);
                        if (rc == 0) {
                                eco->eco_deleted = 1;
                                echo_put_object(eco);
                        }
                } else {
                        rc = echo_create_object(obd, 0, &data->ioc_obdo1,
                                                data->ioc_pbuf1,
                                                data->ioc_plen1, &dummy_oti);
                }
                GOTO (out, rc);

        case ECHO_IOC_ENQUEUE:
                if (!cfs_capable(CFS_CAP_SYS_ADMIN))
                        GOTO (out, rc = -EPERM);

                rc = echo_client_enqueue(exp, &data->ioc_obdo1,
                                         data->ioc_conn1, /* lock mode */
                                   data->ioc_offset, data->ioc_count);/*extent*/
                GOTO (out, rc);

        case ECHO_IOC_CANCEL:
                rc = echo_client_cancel(exp, &data->ioc_obdo1);
                GOTO (out, rc);

        default:
                CERROR ("echo_ioctl(): unrecognised ioctl %#x\n", cmd);
                GOTO (out, rc = -ENOTTY);
        }

        EXIT;
 out:

        /* XXX this should be in a helper also called by target_send_reply */
        for (ack_lock = dummy_oti.oti_ack_locks, i = 0; i < 4;
             i++, ack_lock++) {
                if (!ack_lock->mode)
                        break;
                ldlm_lock_decref(&ack_lock->lock, ack_lock->mode);
        }

#ifndef HAVE_UNLOCKED_IOCTL
        lock_kernel();
#endif
        return rc;
}

static int
echo_client_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct lustre_cfg* lcfg = buf;
        struct echo_client_obd *ec = &obddev->u.echo_client;
        struct obd_device *tgt;
        struct lustre_handle conn = {0, };
        struct obd_uuid echo_uuid = { "ECHO_UUID" };
        struct obd_connect_data *ocd = NULL;
        int rc;
        ENTRY;

        if (lcfg->lcfg_bufcount < 2 || LUSTRE_CFG_BUFLEN(lcfg, 1) < 1) {
                CERROR("requires a TARGET OBD name\n");
                RETURN(-EINVAL);
        }

        tgt = class_name2obd(lustre_cfg_string(lcfg, 1));
        if (!tgt || !tgt->obd_attached || !tgt->obd_set_up) {
                CERROR("device not attached or not set up (%s)\n",
                       lustre_cfg_string(lcfg, 1));
                RETURN(-EINVAL);
        }

        spin_lock_init (&ec->ec_lock);
        CFS_INIT_LIST_HEAD (&ec->ec_objects);
        ec->ec_unique = 0;

        ec->ec_exp = lustre_hash_lookup(tgt->obd_uuid_hash, &echo_uuid);
        if (ec->ec_exp)
                RETURN(0);

        OBD_ALLOC(ocd, sizeof(*ocd));
        if (ocd == NULL) {
                CERROR("Can't alloc ocd connecting to %s\n",
                       lustre_cfg_string(lcfg, 1));
                return -ENOMEM;
        }
        ocd->ocd_connect_flags = OBD_CONNECT_VERSION | OBD_CONNECT_REQPORTAL;
        ocd->ocd_version = LUSTRE_VERSION_CODE;

        if ((strncmp(tgt->obd_type->typ_name, LUSTRE_OSC_NAME,
                     strlen(LUSTRE_OSC_NAME)) == 0) ||
            (strncmp(tgt->obd_type->typ_name, LUSTRE_LOV_NAME,
                     strlen(LUSTRE_LOV_NAME)) == 0)) {
                rc = obd_connect(&conn, tgt, &echo_uuid, ocd, &ec->ec_exp);
        } else {
                rc = obd_connect(&conn, tgt, &echo_uuid, ocd, NULL);
                if (rc == 0) {
                        ec->ec_exp = class_conn2export(&conn);

                        /* Turn off pinger because it connects to tgt obd directly */
                        spin_lock(&tgt->obd_dev_lock);
                        list_del_init(&ec->ec_exp->exp_obd_chain_timed);
                        spin_unlock(&tgt->obd_dev_lock);
                }
        }

        OBD_FREE(ocd, sizeof(*ocd));

        if (rc == -EALREADY && (strncmp(tgt->obd_type->typ_name,LUSTRE_OSC_NAME,
                                        strlen(LUSTRE_OSC_NAME)) == 0)) {
                /* OSC obd forbid reconnect already connected import,
                 * so we hack creating another export here */
                down_write(&tgt->u.cli.cl_sem);
                rc = class_connect(&conn, tgt, &echo_uuid);
                if (rc == 0) {
                        ++tgt->u.cli.cl_conn_count;
                        ec->ec_exp = class_conn2export(&conn);
                }
                up_write(&tgt->u.cli.cl_sem);
        }

        if (rc != 0)
                CERROR("fail to connect to device %s\n",
                       lustre_cfg_string(lcfg, 1));

        RETURN(rc);
}

static int echo_client_cleanup(struct obd_device *obddev)
{
        struct list_head       *el;
        struct ec_object       *eco;
        struct echo_client_obd *ec = &obddev->u.echo_client;
        int rc;
        ENTRY;

        if (!list_empty(&obddev->obd_exports)) {
                CERROR("still has clients!\n");
                RETURN(-EBUSY);
        }

        /* XXX assuming sole access */
        while (!list_empty(&ec->ec_objects)) {
                el = ec->ec_objects.next;
                eco = list_entry(el, struct ec_object, eco_obj_chain);

                if (eco->eco_refcount > 0)
                        RETURN(-EBUSY);
                eco->eco_refcount = 1;
                eco->eco_deleted = 1;
                echo_put_object(eco);
        }

        rc = obd_disconnect(ec->ec_exp);
        if (rc != 0)
                CERROR("fail to disconnect device: %d\n", rc);

        RETURN(rc);
}

static int echo_client_connect(struct lustre_handle *conn,
                               struct obd_device *src, struct obd_uuid *cluuid,
                               struct obd_connect_data *data, void *localdata)
{
        struct obd_export *exp;
        int                rc;

        ENTRY;
        rc = class_connect(conn, src, cluuid);
        if (rc == 0) {
                exp = class_conn2export(conn);
                CFS_INIT_LIST_HEAD(&exp->exp_ec_data.eced_locks);
                class_export_put(exp);
        }

        RETURN (rc);
}

static int echo_client_disconnect(struct obd_export *exp)
{
        struct obd_device      *obd;
        struct echo_client_obd *ec;
        struct ec_lock         *ecl;
        int                     rc;
        ENTRY;

        if (exp == NULL)
                GOTO(out, rc = -EINVAL);

        obd = exp->exp_obd;
        ec = &obd->u.echo_client;

        /* no more contention on export's lock list */
        while (!list_empty (&exp->exp_ec_data.eced_locks)) {
                ecl = list_entry (exp->exp_ec_data.eced_locks.next,
                                  struct ec_lock, ecl_exp_chain);
                list_del (&ecl->ecl_exp_chain);

                rc = obd_cancel(ec->ec_exp, ecl->ecl_object->eco_lsm,
                                 ecl->ecl_mode, &ecl->ecl_lock_handle, 0, 0);

                CDEBUG (D_INFO, "Cancel lock on object "LPX64" on disconnect "
                        "(%d)\n", ecl->ecl_object->eco_id, rc);

                echo_put_object (ecl->ecl_object);
                OBD_FREE (ecl, sizeof (*ecl));
        }

        rc = class_disconnect(exp);
        GOTO(out, rc);
 out:
        return rc;
}

static struct obd_ops echo_obd_ops = {
        .o_owner       = THIS_MODULE,
        .o_setup       = echo_client_setup,
        .o_cleanup     = echo_client_cleanup,
        .o_iocontrol   = echo_client_iocontrol,
        .o_connect     = echo_client_connect,
        .o_disconnect  = echo_client_disconnect
};

int echo_client_init(void)
{
        struct lprocfs_static_vars lvars = { 0 };

        lprocfs_echo_init_vars(&lvars);
        return class_register_type(&echo_obd_ops, lvars.module_vars,
                                   LUSTRE_ECHO_CLIENT_NAME);
}

void echo_client_exit(void)
{
        class_unregister_type(LUSTRE_ECHO_CLIENT_NAME);
}
