/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-md.c
 * Memory Descriptor management routines
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *  Copyright (c) 2001-2002 Sandia National Laboratories
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
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

#ifndef __KERNEL__
# include <stdio.h>
#else
# define DEBUG_SUBSYSTEM S_PORTALS
# include <linux/kp30.h>
#endif

#include <portals/lib-p30.h>
#include <portals/arg-blocks.h>

/*
 * must be called with state lock held
 */
void lib_md_unlink(nal_cb_t * nal, lib_md_t * md)
{
        lib_me_t *me = md->me;

        if (md->pending != 0) {
                CDEBUG(D_NET, "Queueing unlink of md %p\n", md);
                md->md_flags |= PTL_MD_FLAG_UNLINK;
                return;
        }

        CDEBUG(D_NET, "Unlinking md %p\n", md);

        if ((md->options & PTL_MD_KIOV) != 0) {
                if (nal->cb_unmap_pages != NULL)
                        nal->cb_unmap_pages (nal, md->md_niov, md->md_iov.kiov, 
                                             &md->md_addrkey);
        } else if (nal->cb_unmap != NULL)
                nal->cb_unmap (nal, md->md_niov, md->md_iov.iov, 
                               &md->md_addrkey);

        if (me) {
                me->md = NULL;
                if (me->unlink == PTL_UNLINK)
                        lib_me_unlink(nal, me);
        }

        if (md->eq != NULL)
        {
                md->eq->eq_refcount--;
                LASSERT (md->eq->eq_refcount >= 0);
        }

        lib_invalidate_handle (nal, &md->md_lh);
        list_del (&md->md_list);
        lib_md_free(nal, md);
}

/* must be called with state lock held */
static int lib_md_build(nal_cb_t *nal, lib_md_t *new, void *private,
                        ptl_md_t *md, ptl_handle_eq_t *eqh, int unlink)
{
        const int     max_size_opts = PTL_MD_AUTO_UNLINK |
                                      PTL_MD_MAX_SIZE;
        lib_eq_t     *eq = NULL;
        int           rc;
        int           i;

        /* NB we are passes an allocated, but uninitialised/active md.
         * if we return success, caller may lib_md_unlink() it.
         * otherwise caller may only lib_md_free() it.
         */

        if (!PtlHandleEqual (*eqh, PTL_EQ_NONE)) {
                eq = ptl_handle2eq(eqh, nal);
                if (eq == NULL)
                        return PTL_INV_EQ;
        }

        if ((md->options & PTL_MD_IOV) != 0 &&  /* discontiguous MD */
            md->niov > PTL_MD_MAX_IOV)          /* too many fragments */
                return PTL_IOV_TOO_MANY;

        if ((md->options & max_size_opts) != 0 && /* max size used */
            (md->max_size < 0 || md->max_size > md->length)) // illegal max_size
                return PTL_INV_MD;

        new->me = NULL;
        new->start = md->start;
        new->length = md->length;
        new->offset = 0;
        new->max_size = md->max_size;
        new->unlink = unlink;
        new->options = md->options;
        new->user_ptr = md->user_ptr;
        new->eq = eq;
        new->threshold = md->threshold;
        new->pending = 0;
        new->md_flags = 0;

        if ((md->options & PTL_MD_IOV) != 0) {
                int total_length = 0;

                if ((md->options & PTL_MD_KIOV) != 0) /* Can't specify both */
                        return PTL_INV_MD; 

                new->md_niov = md->niov;
                
                if (nal->cb_read (nal, private, new->md_iov.iov, md->start,
                                  md->niov * sizeof (new->md_iov.iov[0])))
                        return PTL_SEGV;

                for (i = 0; i < new->md_niov; i++) {
                        /* We take the base address on trust */
                        if (new->md_iov.iov[i].iov_len <= 0) /* invalid length */
                                return PTL_VAL_FAILED;

                        total_length += new->md_iov.iov[i].iov_len;
                }

                if (md->length > total_length)
                        return PTL_IOV_TOO_SMALL;
                
                if (nal->cb_map != NULL) {
                        rc = nal->cb_map (nal, new->md_niov, new->md_iov.iov, 
                                          &new->md_addrkey);
                        if (rc != PTL_OK)
                                return (rc);
                }
        } else if ((md->options & PTL_MD_KIOV) != 0) {
#ifndef __KERNEL__
                return PTL_INV_MD;
#else
                int total_length = 0;
                
                /* Trap attempt to use paged I/O if unsupported early. */
                if (nal->cb_send_pages == NULL ||
                    nal->cb_recv_pages == NULL)
                        return PTL_INV_MD;

                new->md_niov = md->niov;

                if (nal->cb_read (nal, private, new->md_iov.kiov, md->start,
                                  md->niov * sizeof (new->md_iov.kiov[0])))
                        return PTL_SEGV;
                
                for (i = 0; i < new->md_niov; i++) {
                        /* We take the page pointer on trust */
                        if (new->md_iov.kiov[i].kiov_offset + 
                            new->md_iov.kiov[i].kiov_len > PAGE_SIZE )
                                return PTL_VAL_FAILED; /* invalid length */

                        total_length += new->md_iov.kiov[i].kiov_len;
                }

                if (md->length > total_length)
                        return PTL_IOV_TOO_SMALL;

                if (nal->cb_map_pages != NULL) {
                        rc = nal->cb_map_pages (nal, new->md_niov, new->md_iov.kiov, 
                                                &new->md_addrkey);
                        if (rc != PTL_OK)
                                return (rc);
                }
#endif
        } else {   /* contiguous */
                new->md_niov = 1;
                new->md_iov.iov[0].iov_base = md->start;
                new->md_iov.iov[0].iov_len = md->length;

                if (nal->cb_map != NULL) {
                        rc = nal->cb_map (nal, new->md_niov, new->md_iov.iov, 
                                          &new->md_addrkey);
                        if (rc != PTL_OK)
                                return (rc);
                }
        } 

        if (eq != NULL)
                eq->eq_refcount++;

        /* It's good; let handle2md succeed and add to active mds */
        lib_initialise_handle (nal, &new->md_lh);
        list_add (&new->md_list, &nal->ni.ni_active_mds);

        return PTL_OK;
}

/* must be called with state lock held */
void lib_md_deconstruct(nal_cb_t * nal, lib_md_t * md, ptl_md_t * new)
{
        /* NB this doesn't copy out all the iov entries so when a
         * discontiguous MD is copied out, the target gets to know the
         * original iov pointer (in start) and the number of entries it had
         * and that's all.
         */
        new->start = md->start;
        new->length = md->length;
        new->threshold = md->threshold;
        new->max_size = md->max_size;
        new->options = md->options;
        new->user_ptr = md->user_ptr;
        ptl_eq2handle(&new->eventq, md->eq);
        new->niov = ((md->options & (PTL_MD_IOV | PTL_MD_KIOV)) == 0) ? 0 : md->md_niov;
}

int do_PtlMDAttach(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        /*
         * Incoming:
         *      ptl_handle_me_t current_in
         *      ptl_md_t md_in
         *      ptl_unlink_t unlink_in
         *
         * Outgoing:
         *      ptl_handle_md_t         * handle_out
         */

        PtlMDAttach_in *args = v_args;
        PtlMDAttach_out *ret = v_ret;
        lib_me_t *me;
        lib_md_t *md;
        unsigned long flags;

        md = lib_md_alloc (nal);
        if (md == NULL)
                return (ret->rc = PTL_NOSPACE);

        state_lock(nal, &flags);

        me = ptl_handle2me(&args->me_in, nal);
        if (me == NULL) {
                ret->rc = PTL_INV_ME;
        } else if (me->md != NULL) {
                ret->rc = PTL_INUSE;
        } else {
                ret->rc = lib_md_build(nal, md, private, &args->md_in,
                                       &args->eq_in, args->unlink_in);

                if (ret->rc == PTL_OK) {
                        me->md = md;
                        md->me = me;

                        ptl_md2handle(&ret->handle_out, md);

                        state_unlock (nal, &flags);
                        return (PTL_OK);
                }
        }

        lib_md_free (nal, md);

        state_unlock (nal, &flags);
        return (ret->rc);
}

int do_PtlMDBind(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        /*
         * Incoming:
         *      ptl_handle_ni_t ni_in
         *      ptl_md_t md_in
         *
         * Outgoing:
         *      ptl_handle_md_t         * handle_out
         */

        PtlMDBind_in *args = v_args;
        PtlMDBind_out *ret = v_ret;
        lib_md_t *md;
        unsigned long flags;

        md = lib_md_alloc (nal);
        if (md == NULL)
                return (ret->rc = PTL_NOSPACE);

        state_lock(nal, &flags);

        ret->rc = lib_md_build(nal, md, private,
                               &args->md_in, &args->eq_in, PTL_UNLINK);

        if (ret->rc == PTL_OK) {
                ptl_md2handle(&ret->handle_out, md);

                state_unlock(nal, &flags);
                return (PTL_OK);
        }

        lib_md_free (nal, md);

        state_unlock(nal, &flags);
        return (ret->rc);
}

int do_PtlMDUnlink(nal_cb_t * nal, void *private, void *v_args, void *v_ret)
{
        PtlMDUnlink_in *args = v_args;
        PtlMDUnlink_out *ret = v_ret;

        lib_md_t *md;
        unsigned long flags;

        state_lock(nal, &flags);

        md = ptl_handle2md(&args->md_in, nal);
        if (md == NULL) {
                ret->rc = PTL_INV_MD;
        } else if (md->pending != 0) {           /* being filled/spilled */
                ret->rc = PTL_MD_INUSE;
        } else {
                /* Callers attempting to unlink a busy MD which will get
                 * unlinked once the net op completes should see INUSE,
                 * before completion and INV_MD thereafter.  LASSERT we've
                 * got that right... */
                LASSERT ((md->md_flags & PTL_MD_FLAG_UNLINK) == 0);

                lib_md_deconstruct(nal, md, &ret->status_out);
                lib_md_unlink(nal, md);
                ret->rc = PTL_OK;
        }

        state_unlock(nal, &flags);

        return (ret->rc);
}

int do_PtlMDUpdate_internal(nal_cb_t * nal, void *private, void *v_args,
                            void *v_ret)
{
        /*
         * Incoming:
         *      ptl_handle_md_t md_in
         *      ptl_md_t                * old_inout
         *      ptl_md_t                * new_inout
         *      ptl_handle_eq_t testq_in
         *      ptl_seq_t               sequence_in
         *
         * Outgoing:
         *      ptl_md_t                * old_inout
         *      ptl_md_t                * new_inout
         */
        PtlMDUpdate_internal_in *args = v_args;
        PtlMDUpdate_internal_out *ret = v_ret;
        lib_md_t *md;
        lib_eq_t *test_eq = NULL;
        ptl_md_t *new = &args->new_inout;
        unsigned long flags;

        state_lock(nal, &flags);

        md = ptl_handle2md(&args->md_in, nal);
        if (md == NULL) {
                 ret->rc = PTL_INV_MD;
                 goto out;
        }

        if (args->old_inout_valid)
                lib_md_deconstruct(nal, md, &ret->old_inout);

        if (!args->new_inout_valid) {
                ret->rc = PTL_OK;
                goto out;
        }

        if (!PtlHandleEqual (args->testq_in, PTL_EQ_NONE)) {
                test_eq = ptl_handle2eq(&args->testq_in, nal);
                if (test_eq == NULL) {
                        ret->rc = PTL_INV_EQ;
                        goto out;
                }
        }

        if (md->pending != 0) {
                        ret->rc = PTL_NOUPDATE;
                        goto out;
        }

        if (test_eq == NULL ||
            test_eq->sequence == args->sequence_in) {
                lib_me_t *me = md->me;

#warning this does not track eq refcounts properly

                ret->rc = lib_md_build(nal, md, private,
                                       new, &new->eventq, md->unlink);

                md->me = me;
        } else {
                ret->rc = PTL_NOUPDATE;
        }

 out:
        state_unlock(nal, &flags);
        return (ret->rc);
}
