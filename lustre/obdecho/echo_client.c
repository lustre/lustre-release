/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_ECHO
#ifdef __KERNEL__
#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/iobuf.h>
#endif
#include <asm/div64.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd.h>
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd_echo.h>
#include <linux/lustre_debug.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_lite.h>                  /* for LL_IOC_LOV_SETSTRIPE */

#if 0
static void
echo_printk_object (char *msg, struct ec_object *eco)
{
        struct lov_stripe_md *lsm = eco->eco_lsm;
        int                   i;

        printk (KERN_INFO "%s: object %p: "LPX64", refs %d%s: "LPX64
                "=%u!%u@%d\n", msg, eco, eco->eco_id, eco->eco_refcount,
                eco->eco_deleted ? "(deleted) " : "",
                lsm->lsm_object_id, lsm->lsm_stripe_size,
                lsm->lsm_stripe_count, lsm->lsm_stripe_offset);

        for (i = 0; i < lsm->lsm_stripe_count; i++)
                printk (KERN_INFO "   [%2u]"LPX64"\n",
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
echo_copyout_lsm (struct lov_stripe_md *lsm, void *ulsm, int ulsm_nob)
{
        int nob;

        nob = offsetof (struct lov_stripe_md, lsm_oinfo[lsm->lsm_stripe_count]);
        if (nob > ulsm_nob)
                return (-EINVAL);

        if (copy_to_user (ulsm, lsm, nob))
                return (-EFAULT);

        return (0);
}

static int
echo_copyin_lsm (struct obd_device *obd, struct lov_stripe_md *lsm,
                 void *ulsm, int ulsm_nob)
{
        struct echo_client_obd *ec = &obd->u.echo_client;
        int                     nob;

        if (ulsm_nob < sizeof (*lsm))
                return (-EINVAL);

        if (copy_from_user (lsm, ulsm, sizeof (*lsm)))
                return (-EFAULT);

        nob = lsm->lsm_stripe_count * sizeof (lsm->lsm_oinfo[0]);

        if (ulsm_nob < nob ||
            lsm->lsm_stripe_count > ec->ec_nstripes ||
            lsm->lsm_magic != LOV_MAGIC ||
            (lsm->lsm_stripe_offset != 0 &&
             lsm->lsm_stripe_offset != 0xffffffff &&
             lsm->lsm_stripe_offset >= ec->ec_nstripes) ||
            (lsm->lsm_stripe_size & (PAGE_SIZE - 1)) != 0 ||
            ((__u64)lsm->lsm_stripe_size * lsm->lsm_stripe_count > ~0UL))
                return (-EINVAL);

        LASSERT (ec->ec_lsmsize >= sizeof (*lsm) + nob);

        if (copy_from_user(lsm->lsm_oinfo,
                           ((struct lov_stripe_md *)ulsm)->lsm_oinfo, nob))
                return (-EFAULT);

        return (0);
}

static struct ec_object *
echo_allocate_object (struct obd_device *obd)
{
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct ec_object       *eco;

        OBD_ALLOC (eco, sizeof (*eco));
        if (eco == NULL)
                return (NULL);

        OBD_ALLOC (eco->eco_lsm, ec->ec_lsmsize);
        if (eco->eco_lsm == NULL) {
                OBD_FREE (eco, sizeof (*eco));
                return (NULL);
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
        OBD_FREE (eco->eco_lsm, ec->ec_lsmsize);
        OBD_FREE (eco, sizeof (*eco));
}

static int
echo_create_object (struct obd_device *obd, int on_target, struct obdo *oa,
                    void *ulsm, int ulsm_nob)
{
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct ec_object       *eco2;
        struct ec_object       *eco;
        struct lov_stripe_md   *lsm;
        int                     rc;
        int                     i;

        if ((oa->o_valid & OBD_MD_FLID) == 0 && /* no obj id */
            (on_target ||                       /* set_stripe */
             ec->ec_nstripes != 0)) {           /* LOV */
                CERROR ("No valid oid\n");
                return (-EINVAL);
        }

        eco = echo_allocate_object (obd);
        if (eco == NULL)
                return (-ENOMEM);

        lsm = eco->eco_lsm;

        if (ulsm != NULL) {
                rc = echo_copyin_lsm (obd, lsm, ulsm, ulsm_nob);
                if (rc != 0)
                        goto failed;
        }

        /* setup object ID here for !on_target and LOV hint */
        if ((oa->o_valid & OBD_MD_FLID) != 0)
                eco->eco_id = lsm->lsm_object_id = oa->o_id;

        /* defaults -> actual values */
        if (lsm->lsm_stripe_offset == 0xffffffff)
                lsm->lsm_stripe_offset = 0;

        if (lsm->lsm_stripe_count == 0)
                lsm->lsm_stripe_count = ec->ec_nstripes;

        if (lsm->lsm_stripe_size == 0)
                lsm->lsm_stripe_size = PAGE_SIZE;

        /* setup stripes: indices + default ids if required */
        for (i = 0; i < lsm->lsm_stripe_count; i++) {
                if (lsm->lsm_oinfo[i].loi_id == 0)
                        lsm->lsm_oinfo[i].loi_id = lsm->lsm_object_id;

                lsm->lsm_oinfo[i].loi_ost_idx =
                        (lsm->lsm_stripe_offset + i) % ec->ec_nstripes;
        }

        if (on_target) {
                rc = obd_create (&ec->ec_conn, oa, &lsm, NULL);
                if (rc != 0)
                        goto failed;

                /* See what object ID we were given */
                LASSERT ((oa->o_valid & OBD_MD_FLID) != 0);
                eco->eco_id = lsm->lsm_object_id = oa->o_id;
        }

        spin_lock (&ec->ec_lock);

        eco2 = echo_find_object_locked (obd, oa->o_id);
        if (eco2 != NULL) {                     /* conflict */
                spin_unlock (&ec->ec_lock);

                CERROR ("Can't create object id "LPX64": id already exists%s\n",
                        oa->o_id, on_target ? " (undoing create)" : "");

                if (on_target)
                        obd_destroy (&ec->ec_conn, oa, lsm, NULL);

                rc = -EEXIST;
                goto failed;
        }

        list_add (&eco->eco_obj_chain, &ec->ec_objects);
        spin_unlock (&ec->ec_lock);
        CDEBUG (D_INFO,
                "created %p: "LPX64"=%u#%u&%d refs %d del %d\n",
                eco, eco->eco_id,
                eco->eco_lsm->lsm_stripe_size,
                eco->eco_lsm->lsm_stripe_count,
                eco->eco_lsm->lsm_stripe_offset,
                eco->eco_refcount, eco->eco_deleted);
        return (0);

 failed:
        echo_free_object (eco);
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

        if ((oa->o_valid & OBD_MD_FLID) == 0)
        {
                CERROR ("No valid oid\n");
                return (-EINVAL);
        }

        spin_lock (&ec->ec_lock);
        eco = echo_find_object_locked (obd, oa->o_id);
        if (eco != NULL) {
                if (eco->eco_deleted)           /* being deleted */
                        return (-EAGAIN);       /* (see comment in cleanup) */

                eco->eco_refcount++;
                spin_unlock (&ec->ec_lock);
                *ecop = eco;
                CDEBUG (D_INFO,
                        "found %p: "LPX64"=%u#%u&%d refs %d del %d\n",
                        eco, eco->eco_id,
                        eco->eco_lsm->lsm_stripe_size,
                        eco->eco_lsm->lsm_stripe_count,
                        eco->eco_lsm->lsm_stripe_offset,
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
                        "created %p: "LPX64"=%u#%u&%d refs %d del %d\n",
                        eco, eco->eco_id,
                        eco->eco_lsm->lsm_stripe_size,
                        eco->eco_lsm->lsm_stripe_count,
                        eco->eco_lsm->lsm_stripe_offset,
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
                        "found(2) %p: "LPX64"=%u#%u&%d refs %d del %d\n",
                        eco2, eco2->eco_id,
                        eco2->eco_lsm->lsm_stripe_size,
                        eco2->eco_lsm->lsm_stripe_count,
                        eco2->eco_lsm->lsm_stripe_offset,
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

        if (eco->eco_refcount != 0 ||
            !eco->eco_deleted) {
                spin_unlock (&ec->ec_lock);
                return;
        }

        spin_unlock (&ec->ec_lock);

        /* NB leave obj in the object list.  We must prevent anyone from
         * attempting to enqueue on this object number until we can be
         * sure there will be no more lock callbacks.
         */
        obd_cancel_unused (&ec->ec_conn, eco->eco_lsm, 0);

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

        *idp = lsm->lsm_oinfo[stripe_index].loi_id;
        *offp = offset * stripe_size + woffset % stripe_size;
}

static int
echo_client_kbrw (struct obd_device *obd, int rw,
                  struct obdo *oa, struct lov_stripe_md *lsm,
                  obd_off offset, obd_size count)
{
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct obd_brw_set     *set;
        obd_count               npages;
        struct brw_page        *pga;
        struct brw_page        *pgp;
        obd_off                 off;
        int                     i;
        int                     rc;
        int                     verify;
        int                     gfp_mask;

        /* oa_id  == 0    => speed test (no verification) else...
         * oa & 1         => use HIGHMEM
         */
        verify = (oa->o_id != 0);
        gfp_mask = ((oa->o_id & 1) == 0) ? GFP_KERNEL : GFP_HIGHUSER;

        LASSERT(rw == OBD_BRW_WRITE || rw == OBD_BRW_READ);

        if (count <= 0 ||
            (count & (PAGE_SIZE - 1)) != 0 ||
            (lsm != NULL &&
             lsm->lsm_object_id != oa->o_id))
                return (-EINVAL);

        set = obd_brw_set_new();
        if (set == NULL)
                return (-ENOMEM);

        /* XXX think again with misaligned I/O */
        npages = count >> PAGE_SHIFT;

        rc = -ENOMEM;
        OBD_ALLOC(pga, npages * sizeof(*pga));
        if (pga == NULL)
                goto out_0;

        for (i = 0, pgp = pga, off = offset;
             i < npages;
             i++, pgp++, off += PAGE_SIZE) {

                LASSERT (pgp->pg == NULL);      /* for cleanup */

                rc = -ENOMEM;
                pgp->pg = alloc_pages (gfp_mask, 0);
                if (pgp->pg == NULL)
                        goto out_1;

                pgp->count = PAGE_SIZE;
                pgp->off = off;
                pgp->flag = 0;

                if (verify) {
                        void *addr = kmap(pgp->pg);
                        obd_off      stripe_off = off;
                        obd_id       stripe_id = oa->o_id;

                        if (rw == OBD_BRW_WRITE) {
                                echo_get_stripe_off_id(lsm, &stripe_off,
                                                       &stripe_id);
                                page_debug_setup(addr, pgp->count,
                                                 stripe_off, stripe_id);
                        } else {
                                page_debug_setup(addr, pgp->count,
                                                 0xdeadbeef00c0ffee,
                                                 0xdeadbeef00c0ffee);
                        }
                        kunmap(pgp->pg);
                }
        }

        set->brw_callback = ll_brw_sync_wait;
        rc = obd_brw(rw, &ec->ec_conn, lsm, npages, pga, set, NULL);
        if (rc == 0)
                rc = ll_brw_sync_wait(set, CB_PHASE_START);

 out_1:
        if (rc != 0)
                verify = 0;

        for (i = 0, pgp = pga; i < npages; i++, pgp++) {
                if (pgp->pg == NULL)
                        continue;

                if (verify) {
                        void    *addr = kmap(pgp->pg);
                        obd_off  stripe_off = pgp->off;
                        obd_id   stripe_id  = oa->o_id;
                        int      vrc;

                        echo_get_stripe_off_id (lsm, &stripe_off, &stripe_id);
                        vrc = page_debug_check("test_brw", addr, pgp->count,
                                               stripe_off, stripe_id);
                        if (vrc != 0 && rc == 0)
                                rc = vrc;

                        kunmap(pgp->pg);
                }
                __free_pages(pgp->pg, 0);
        }
        OBD_FREE(pga, npages * sizeof(*pga));
 out_0:
        obd_brw_set_decref(set);
        return (rc);
}

#ifdef __KERNEL__
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static int echo_client_ubrw(struct obd_device *obd, int rw,
                            struct obdo *oa, struct lov_stripe_md *lsm,
                            obd_off offset, obd_size count, char *buffer)
{
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct obd_brw_set     *set;
        obd_count               npages;
        struct brw_page        *pga;
        struct brw_page        *pgp;
        obd_off                 off;
        struct kiobuf          *kiobuf;
        int                     i;
        int                     rc;

        LASSERT (rw == OBD_BRW_WRITE ||
                 rw == OBD_BRW_READ);

        /* NB: for now, only whole pages, page aligned */

        if (count <= 0 ||
            ((long)buffer & (PAGE_SIZE - 1)) != 0 ||
            (count & (PAGE_SIZE - 1)) != 0 ||
            (lsm != NULL && lsm->lsm_object_id != oa->o_id))
                return (-EINVAL);

        set = obd_brw_set_new();
        if (set == NULL)
                return (-ENOMEM);

        /* XXX think again with misaligned I/O */
        npages = count >> PAGE_SHIFT;

        rc = -ENOMEM;
        OBD_ALLOC(pga, npages * sizeof(*pga));
        if (pga == NULL)
                goto out_0;

        rc = alloc_kiovec (1, &kiobuf);
        if (rc != 0)
                goto out_1;

        rc = map_user_kiobuf ((rw == OBD_BRW_READ) ? READ : WRITE,
                              kiobuf, (unsigned long)buffer, count);
        if (rc != 0)
                goto out_2;

        LASSERT (kiobuf->offset == 0);
        LASSERT (kiobuf->nr_pages == npages);

        for (i = 0, off = offset, pgp = pga;
             i < npages;
             i++, off += PAGE_SIZE, pgp++) {
                pgp->off = off;
                pgp->pg = kiobuf->maplist[i];
                pgp->count = PAGE_SIZE;
                pgp->flag = 0;
        }

        set->brw_callback = ll_brw_sync_wait;
        rc = obd_brw(rw, &ec->ec_conn, lsm, npages, pga, set, NULL);

        if (rc == 0)
                rc = ll_brw_sync_wait(set, CB_PHASE_START);

        //        if (rw == OBD_BRW_READ)
        //                mark_dirty_kiobuf (kiobuf, count);

        unmap_kiobuf (kiobuf);
 out_2:
        free_kiovec (1, &kiobuf);
 out_1:
        OBD_FREE(pga, npages * sizeof(*pga));
 out_0:
        obd_brw_set_decref(set);
        return (rc);
}
#else
static int echo_client_ubrw(struct obd_device *obd, int rw,
                            struct obdo *oa, struct lov_stripe_md *lsm,
                            obd_off offset, obd_size count, char *buffer)
{
        LBUG();
        return 0;
}
#endif
#endif

static int
echo_open (struct obd_export *exp, struct obdo *oa)
{
        struct obd_device      *obd = exp->exp_obd;
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct lustre_handle   *ufh = obdo_handle (oa);
        struct ec_open_object  *ecoo;
        struct ec_object       *eco;
        int                     rc;

        rc = echo_get_object (&eco, obd, oa);
        if (rc != 0)
                return (rc);

        rc = -ENOMEM;
        OBD_ALLOC (ecoo, sizeof (*ecoo));
        if (ecoo == NULL)
                goto failed_0;

        rc = obd_open (&ec->ec_conn, oa, eco->eco_lsm, NULL);
        if (rc != 0)
                goto failed_1;

        memcpy (&ecoo->ecoo_oa, oa, sizeof (*oa));
        ecoo->ecoo_object = eco;
        /* ecoo takes ref from echo_get_object() above */

        spin_lock (&ec->ec_lock);

        list_add (&ecoo->ecoo_exp_chain, &exp->exp_ec_data.eced_open_head);

        ufh->addr = (__u64)((long) ecoo);
        ufh->cookie = ecoo->ecoo_cookie = ec->ec_unique++;

        spin_unlock (&ec->ec_lock);
        return (0);

 failed_1:
        OBD_FREE (ecoo, sizeof (*ecoo));
 failed_0:
        echo_put_object (eco);
        return (rc);
}

static int
echo_close (struct obd_export *exp, struct obdo *oa)
{
        struct obd_device      *obd = exp->exp_obd;
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct lustre_handle   *ufh = obdo_handle (oa);
        struct ec_open_object  *ecoo = NULL;
        int                     found = 0;
        struct list_head       *el;
        int                     rc;

        if ((oa->o_valid & OBD_MD_FLHANDLE) == 0)
                return (-EINVAL);

        spin_lock (&ec->ec_lock);

        list_for_each (el, &exp->exp_ec_data.eced_open_head) {
                ecoo = list_entry (el, struct ec_open_object, ecoo_exp_chain);
                if ((__u64)((long)ecoo) == ufh->addr) {
                        found = (ecoo->ecoo_cookie == ufh->cookie);
                        if (found)
                                list_del (&ecoo->ecoo_exp_chain);
                        break;
                }
        }

        spin_unlock (&ec->ec_lock);

        if (!found)
                return (-EINVAL);

        rc = obd_close (&ec->ec_conn, &ecoo->ecoo_oa,
                        ecoo->ecoo_object->eco_lsm, NULL);

        echo_put_object (ecoo->ecoo_object);
        OBD_FREE (ecoo, sizeof (*ecoo));

        return (rc);
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
                CDEBUG (D_INFO, "blocking callback on "LPX64", handle "LPX64"."
                        LPX64"\n", eco->eco_id, lockh.addr, lockh.cookie);
                rc = ldlm_cli_cancel (&lockh);
                if (rc != ELDLM_OK)
                        CERROR ("ldlm_cli_cancel failed: %d\n", rc);
                break;

        case LDLM_CB_CANCELING:
                CDEBUG (D_INFO, "canceling callback on "LPX64", handle "LPX64"."
                        LPX64"\n", eco->eco_id, lockh.addr, lockh.cookie);
                break;

        default:
                LBUG ();
        }

        return (0);
}

static int
echo_enqueue (struct obd_export *exp, struct obdo *oa,
              int mode, obd_off offset, obd_size nob)
{
        struct obd_device      *obd = exp->exp_obd;
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct lustre_handle   *ulh = obdo_handle (oa);
        struct ec_object       *eco;
        struct ec_lock         *ecl;
        int                     flags;
        int                     rc;

        if (!(mode == LCK_PR || mode == LCK_PW))
                return (-EINVAL);

        if ((offset & (PAGE_SIZE - 1)) != 0 ||
            (nob & (PAGE_SIZE - 1)) != 0)
                return (-EINVAL);

        rc = echo_get_object (&eco, obd, oa);
        if (rc != 0)
                return (rc);

        rc = -ENOMEM;
        OBD_ALLOC (ecl, sizeof (*ecl));
        if (ecl == NULL)
                goto failed_0;

        ecl->ecl_mode = mode;
        ecl->ecl_object = eco;
        ecl->ecl_extent.start = offset;
        ecl->ecl_extent.end = (nob == 0) ? ((obd_off)-1) : (offset + nob - 1);

        flags = 0;
        rc = obd_enqueue (&ec->ec_conn, eco->eco_lsm, NULL, LDLM_EXTENT,
                          &ecl->ecl_extent,sizeof(ecl->ecl_extent), mode,
                          &flags, echo_ldlm_callback, eco, sizeof (*eco),
                          &ecl->ecl_handle);
        if (rc != 0)
                goto failed_1;

        CDEBUG (D_INFO, "enqueue handle "LPX64"."LPX64"\n",
                ecl->ecl_handle.addr, ecl->ecl_handle.cookie);

        /* NB ecl takes object ref from echo_get_object() above */

        spin_lock (&ec->ec_lock);

        list_add (&ecl->ecl_exp_chain, &exp->exp_ec_data.eced_locks);

        ulh->addr = (__u64)((long)ecl);
        ulh->cookie = ecl->ecl_cookie = ec->ec_unique++;

        spin_unlock (&ec->ec_lock);

        oa->o_valid |= OBD_MD_FLHANDLE;
        return (0);

 failed_1:
        OBD_FREE (ecl, sizeof (*ecl));
 failed_0:
        echo_put_object (eco);
        return (rc);
}

static int
echo_cancel (struct obd_export *exp, struct obdo *oa)
{
        struct obd_device      *obd = exp->exp_obd;
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct lustre_handle   *ulh = obdo_handle (oa);
        struct ec_lock         *ecl = NULL;
        int                     found = 0;
        struct list_head       *el;
        int                     rc;

        if ((oa->o_valid & OBD_MD_FLHANDLE) == 0)
                return (-EINVAL);

        spin_lock (&ec->ec_lock);

        list_for_each (el, &exp->exp_ec_data.eced_locks) {
                ecl = list_entry (el, struct ec_lock, ecl_exp_chain);

                if ((__u64)((long)ecl) == ulh->addr) {
                        found = (ecl->ecl_cookie == ulh->cookie);
                        if (found)
                                list_del (&ecl->ecl_exp_chain);
                        break;
                }
        }

        spin_unlock (&ec->ec_lock);

        if (!found)
                return (-ENOENT);

        rc = obd_cancel (&ec->ec_conn,
                         ecl->ecl_object->eco_lsm,
                         ecl->ecl_mode,
                         &ecl->ecl_handle);

        echo_put_object (ecl->ecl_object);
        OBD_FREE (ecl, sizeof (*ecl));

        return (rc);
}

static int echo_iocontrol(unsigned int cmd, struct lustre_handle *obdconn,
                          int len, void *karg, void *uarg)
{
        struct obd_export      *exp = class_conn2export (obdconn);
        struct obd_device      *obd;
        struct echo_client_obd *ec;
        struct ec_object       *eco;
        struct obd_ioctl_data  *data = karg;
        int                     rw = OBD_BRW_READ;
        int                     rc = 0;
        ENTRY;

        if (exp == NULL) {
                CERROR("ioctl: No device\n");
                GOTO(out, rc = -EINVAL);
        }

        obd = exp->exp_obd;
        ec = &obd->u.echo_client;

        switch (cmd) {
        case OBD_IOC_CREATE:                    /* may create echo object */
                if (!capable (CAP_SYS_ADMIN))
                        GOTO (out, rc = -EPERM);

                rc = echo_create_object (obd, 1, &data->ioc_obdo1,
                                         data->ioc_pbuf1, data->ioc_plen1);
                GOTO(out, rc);

        case OBD_IOC_DESTROY:
                if (!capable (CAP_SYS_ADMIN))
                        GOTO (out, rc = -EPERM);

                rc = echo_get_object (&eco, obd, &data->ioc_obdo1);
                if (rc == 0) {
                        rc = obd_destroy(&ec->ec_conn, &data->ioc_obdo1,
                                         eco->eco_lsm, NULL);
                        if (rc == 0)
                                eco->eco_deleted = 1;
                        echo_put_object(eco);
                }
                GOTO(out, rc);

        case OBD_IOC_GETATTR:
                rc = echo_get_object (&eco, obd, &data->ioc_obdo1);
                if (rc == 0) {
                        rc = obd_getattr(&ec->ec_conn, &data->ioc_obdo1,
                                         eco->eco_lsm);
                        echo_put_object(eco);
                }
                GOTO(out, rc);

        case OBD_IOC_SETATTR:
                if (!capable (CAP_SYS_ADMIN))
                        GOTO (out, rc = -EPERM);

                rc = echo_get_object (&eco, obd, &data->ioc_obdo1);
                if (rc == 0) {
                        rc = obd_setattr(&ec->ec_conn, &data->ioc_obdo1,
                                         eco->eco_lsm, NULL);
                        echo_put_object(eco);
                }
                GOTO(out, rc);

        case OBD_IOC_OPEN:
                rc = echo_open (exp, &data->ioc_obdo1);
                GOTO(out, rc);

        case OBD_IOC_CLOSE:
                rc = echo_close (exp, &data->ioc_obdo1);
                GOTO(out, rc);

        case OBD_IOC_BRW_WRITE:
                if (!capable (CAP_SYS_ADMIN))
                        GOTO (out, rc = -EPERM);

                rw = OBD_BRW_WRITE;
                /* fall through */
        case OBD_IOC_BRW_READ:
                rc = echo_get_object (&eco, obd, &data->ioc_obdo1);
                if (rc == 0) {
                        if (data->ioc_pbuf2 == NULL) // NULL user data pointer
                                rc = echo_client_kbrw(obd, rw, &data->ioc_obdo1,
                                                      eco->eco_lsm,
                                                      data->ioc_offset,
                                                      data->ioc_count);
                        else
#ifdef __KERNEL__
                                rc = echo_client_ubrw(obd, rw, &data->ioc_obdo1,
                                                      eco->eco_lsm,
                                                      data->ioc_offset,
                                                      data->ioc_count,
                                                      data->ioc_pbuf2);
#endif
                        echo_put_object(eco);
                }
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
                if (!capable (CAP_SYS_ADMIN))
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
                                                data->ioc_plen1);
                }
                GOTO (out, rc);

        case ECHO_IOC_ENQUEUE:
                if (!capable (CAP_SYS_ADMIN))
                        GOTO (out, rc = -EPERM);

                rc = echo_enqueue (exp, &data->ioc_obdo1,
                                   data->ioc_conn1, /* lock mode */
                                   data->ioc_offset, data->ioc_count);/*extent*/
                GOTO (out, rc);

        case ECHO_IOC_CANCEL:
                rc = echo_cancel (exp, &data->ioc_obdo1);
                GOTO (out, rc);

        default:
                CERROR ("echo_ioctl(): unrecognised ioctl %#x\n", cmd);
                GOTO (out, rc = -ENOTTY);
        }

 out:
        RETURN(rc);
}

static int echo_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct echo_client_obd *ec = &obddev->u.echo_client;
        struct obd_device *tgt;
        struct obd_uuid uuid;
        struct lov_stripe_md *lsm = NULL;
        struct obd_uuid echo_uuid = { "ECHO_UUID" };
        int rc;
        ENTRY;

        if (data->ioc_inllen1 < 1) {
                CERROR("requires a TARGET OBD UUID\n");
                RETURN(-EINVAL);
        }
        if (data->ioc_inllen1 > 37) {
                CERROR("OBD UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        obd_str2uuid(&uuid, data->ioc_inlbuf1);
        tgt = class_uuid2obd(&uuid);
        if (!tgt || !(tgt->obd_flags & OBD_ATTACHED) ||
            !(tgt->obd_flags & OBD_SET_UP)) {
                CERROR("device not attached or not set up (%d)\n",
                       data->ioc_dev);
                RETURN(rc = -EINVAL);
        }

        spin_lock_init (&ec->ec_lock);
        INIT_LIST_HEAD (&ec->ec_objects);
        ec->ec_unique = 0;

        rc = obd_connect(&ec->ec_conn, tgt, &echo_uuid, NULL, NULL);
        if (rc) {
                CERROR("fail to connect to device %d\n", data->ioc_dev);
                return (rc);
        }

        ec->ec_lsmsize = obd_alloc_memmd (&ec->ec_conn, &lsm);
        if (ec->ec_lsmsize < 0) {
                CERROR ("Can't get # stripes: %d\n", rc);
                obd_disconnect (&ec->ec_conn);
                rc = ec->ec_lsmsize;
        } else {
                ec->ec_nstripes = lsm->lsm_stripe_count;
                obd_free_memmd (&ec->ec_conn, &lsm);
        }

        RETURN(rc);
}

static int echo_cleanup(struct obd_device * obddev)
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
        while (!list_empty (&ec->ec_objects)) {
                el = ec->ec_objects.next;
                eco = list_entry (el, struct ec_object, eco_obj_chain);

                LASSERT (eco->eco_refcount == 0);
                eco->eco_refcount = 1;
                eco->eco_deleted = 1;
                echo_put_object (eco);
        }

        rc = obd_disconnect (&ec->ec_conn);
        if (rc != 0)
                CERROR("fail to disconnect device: %d\n", rc);

        RETURN (rc);
}

static int echo_connect(struct lustre_handle *conn, struct obd_device *src,
                        struct obd_uuid *cluuid, struct recovd_obd *recovd,
                        ptlrpc_recovery_cb_t recover)
{
        struct obd_export *exp;
        int                rc;

        rc = class_connect(conn, src, cluuid);
        if (rc == 0) {
                exp = class_conn2export (conn);
                INIT_LIST_HEAD (&exp->exp_ec_data.eced_open_head);
                INIT_LIST_HEAD (&exp->exp_ec_data.eced_locks);
        }

        RETURN (rc);
}

static int echo_disconnect(struct lustre_handle *conn)
{
        struct obd_export      *exp = class_conn2export (conn);
        struct obd_device      *obd;
        struct echo_client_obd *ec;
        struct ec_open_object  *ecoo;
        struct ec_lock         *ecl;
        int                     rc;

        if (exp == NULL)
                return (-EINVAL);

        obd = exp->exp_obd;
        ec = &obd->u.echo_client;

        /* no more contention on export's lock list */
        while (!list_empty (&exp->exp_ec_data.eced_locks)) {
                ecl = list_entry (exp->exp_ec_data.eced_locks.next,
                                  struct ec_lock, ecl_exp_chain);
                list_del (&ecl->ecl_exp_chain);

                rc = obd_cancel (&ec->ec_conn, ecl->ecl_object->eco_lsm,
                                 ecl->ecl_mode, &ecl->ecl_handle);

                CERROR ("Cancel lock on object "LPX64" on disconnect (%d)\n",
                        ecl->ecl_object->eco_id, rc);

                echo_put_object (ecl->ecl_object);
                OBD_FREE (ecl, sizeof (*ecl));
        }

        /* no more contention on export's open handle list  */
        while (!list_empty (&exp->exp_ec_data.eced_open_head)) {
                ecoo = list_entry (exp->exp_ec_data.eced_open_head.next,
                                   struct ec_open_object, ecoo_exp_chain);
                list_del (&ecoo->ecoo_exp_chain);

                rc = obd_close (&ec->ec_conn, &ecoo->ecoo_oa,
                                ecoo->ecoo_object->eco_lsm, NULL);

                CDEBUG (D_INFO, "Closed object "LPX64" on disconnect (%d)\n",
                        ecoo->ecoo_oa.o_id, rc);

                echo_put_object (ecoo->ecoo_object);
                OBD_FREE (ecoo, sizeof (*ecoo));
        }

        rc = class_disconnect (conn);
        RETURN (rc);
}

static struct obd_ops echo_obd_ops = {
        o_owner:       THIS_MODULE,
        o_setup:       echo_setup,
        o_cleanup:     echo_cleanup,
        o_iocontrol:   echo_iocontrol,
        o_connect:     echo_connect,
        o_disconnect:  echo_disconnect
};

int echo_client_init(void)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(&lvars);
        return class_register_type(&echo_obd_ops, lvars.module_vars,
                                   OBD_ECHO_CLIENT_DEVICENAME);
}

void echo_client_cleanup(void)
{
        class_unregister_type(OBD_ECHO_CLIENT_DEVICENAME);
}
