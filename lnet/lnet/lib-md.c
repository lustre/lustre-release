/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-md.c
 * Memory Descriptor management routines
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org
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

#define DEBUG_SUBSYSTEM S_PORTALS

#include <portals/lib-p30.h>

/* must be called with PTL_LOCK held */
void
ptl_md_unlink(ptl_libmd_t *md)
{
        if ((md->md_flags & PTL_MD_FLAG_ZOMBIE) == 0) {
                /* first unlink attempt... */
                ptl_me_t *me = md->md_me;

                md->md_flags |= PTL_MD_FLAG_ZOMBIE;

                /* Disassociate from ME (if any), and unlink it if it was created
                 * with PTL_UNLINK */
                if (me != NULL) {
                        me->me_md = NULL;
                        if (me->me_unlink == PTL_UNLINK)
                                ptl_me_unlink(me);
                }

                /* emsure all future handle lookups fail */
                ptl_invalidate_handle(&md->md_lh);
        }

        if (md->md_pending != 0) {
                CDEBUG(D_NET, "Queueing unlink of md %p\n", md);
                return;
        }

        CDEBUG(D_NET, "Unlinking md %p\n", md);

        if (md->md_eq != NULL) {
                md->md_eq->eq_refcount--;
                LASSERT (md->md_eq->eq_refcount >= 0);
        }

        list_del (&md->md_list);
        ptl_md_free(md);
}

/* must be called with PTL_LOCK held */
static int
lib_md_build(ptl_libmd_t *lmd, ptl_md_t *umd, int unlink)
{
        ptl_eq_t  *eq = NULL;
        int        i;
        int        niov;
        int        total_length = 0;

        /* NB we are passed an allocated, but uninitialised/active md.
         * if we return success, caller may ptl_md_unlink() it.
         * otherwise caller may only ptl_md_free() it.
         */

        if (!PtlHandleIsEqual (umd->eq_handle, PTL_EQ_NONE)) {
                eq = ptl_handle2eq(&umd->eq_handle);
                if (eq == NULL)
                        return PTL_EQ_INVALID;
        }

        /* This implementation doesn't know how to create START events or
         * disable END events.  Best to LASSERT our caller is compliant so
         * we find out quickly...  */
        LASSERT (eq == NULL ||
                 ((umd->options & PTL_MD_EVENT_START_DISABLE) != 0 &&
                  (umd->options & PTL_MD_EVENT_END_DISABLE) == 0));

        lmd->md_me = NULL;
        lmd->md_start = umd->start;
        lmd->md_offset = 0;
        lmd->md_max_size = umd->max_size;
        lmd->md_options = umd->options;
        lmd->md_user_ptr = umd->user_ptr;
        lmd->md_eq = eq;
        lmd->md_threshold = umd->threshold;
        lmd->md_pending = 0;
        lmd->md_flags = (unlink == PTL_UNLINK) ? PTL_MD_FLAG_AUTO_UNLINK : 0;

        if ((umd->options & PTL_MD_IOVEC) != 0) {

                if ((umd->options & PTL_MD_KIOV) != 0) /* Can't specify both */
                        return PTL_MD_ILLEGAL;

                lmd->md_niov = niov = umd->length;
                memcpy(lmd->md_iov.iov, umd->start,
                       niov * sizeof (lmd->md_iov.iov[0]));

                for (i = 0; i < niov; i++) {
                        /* We take the base address on trust */
                        if (lmd->md_iov.iov[i].iov_len <= 0) /* invalid length */
                                return PTL_MD_ILLEGAL;

                        total_length += lmd->md_iov.iov[i].iov_len;
                }

                lmd->md_length = total_length;

                if ((umd->options & PTL_MD_MAX_SIZE) != 0 && /* max size used */
                    (umd->max_size < 0 ||
                     umd->max_size > total_length)) // illegal max_size
                        return PTL_MD_ILLEGAL;

        } else if ((umd->options & PTL_MD_KIOV) != 0) {
#ifndef __KERNEL__
                return PTL_MD_ILLEGAL;
#else
                lmd->md_niov = niov = umd->length;
                memcpy(lmd->md_iov.kiov, umd->start,
                       niov * sizeof (lmd->md_iov.kiov[0]));

                for (i = 0; i < niov; i++) {
                        /* We take the page pointer on trust */
                        if (lmd->md_iov.kiov[i].kiov_offset +
                            lmd->md_iov.kiov[i].kiov_len > PAGE_SIZE )
                                return PTL_VAL_FAILED; /* invalid length */

                        total_length += lmd->md_iov.kiov[i].kiov_len;
                }

                lmd->md_length = total_length;

                if ((umd->options & PTL_MD_MAX_SIZE) != 0 && /* max size used */
                    (umd->max_size < 0 ||
                     umd->max_size > total_length)) // illegal max_size
                        return PTL_MD_ILLEGAL;
#endif
        } else {   /* contiguous */
                lmd->md_length = umd->length;
                lmd->md_niov = niov = 1;
                lmd->md_iov.iov[0].iov_base = umd->start;
                lmd->md_iov.iov[0].iov_len = umd->length;

                if ((umd->options & PTL_MD_MAX_SIZE) != 0 && /* max size used */
                    (umd->max_size < 0 ||
                     umd->max_size > umd->length)) // illegal max_size
                        return PTL_MD_ILLEGAL;
        }

        if (eq != NULL)
                eq->eq_refcount++;

        /* It's good; let handle2md succeed and add to active mds */
        ptl_initialise_handle (&lmd->md_lh, PTL_COOKIE_TYPE_MD);
        list_add (&lmd->md_list, &ptl_apini.apini_active_mds);

        return PTL_OK;
}

/* must be called with PTL_LOCK held */
void
ptl_md_deconstruct(ptl_libmd_t *lmd, ptl_md_t *umd)
{
        /* NB this doesn't copy out all the iov entries so when a
         * discontiguous MD is copied out, the target gets to know the
         * original iov pointer (in start) and the number of entries it had
         * and that's all.
         */
        umd->start = lmd->md_start;
        umd->length = ((lmd->md_options & (PTL_MD_IOVEC | PTL_MD_KIOV)) == 0) ?
                      lmd->md_length : lmd->md_niov;
        umd->threshold = lmd->md_threshold;
        umd->max_size = lmd->md_max_size;
        umd->options = lmd->md_options;
        umd->user_ptr = lmd->md_user_ptr;
        ptl_eq2handle(&umd->eq_handle, lmd->md_eq);
}

ptl_err_t
PtlMDAttach(ptl_handle_me_t meh, ptl_md_t umd,
            ptl_unlink_t unlink, ptl_handle_md_t *handle)
{
        ptl_me_t     *me;
        ptl_libmd_t  *md;
        unsigned long flags;
        int           rc;

        if (!ptl_init)
                return PTL_NO_INIT;

        if (ptl_apini.apini_refcount == 0)
                return PTL_NI_INVALID;
        
        if ((umd.options & (PTL_MD_KIOV | PTL_MD_IOVEC)) != 0 &&
            umd.length > PTL_MD_MAX_IOV) /* too many fragments */
                return PTL_IOV_INVALID;

        md = ptl_md_alloc(&umd);
        if (md == NULL)
                return PTL_NO_SPACE;

        PTL_LOCK(flags);

        me = ptl_handle2me(&meh);
        if (me == NULL) {
                rc = PTL_ME_INVALID;
        } else if (me->me_md != NULL) {
                rc = PTL_ME_IN_USE;
        } else {
                rc = lib_md_build(md, &umd, unlink);
                if (rc == PTL_OK) {
                        me->me_md = md;
                        md->md_me = me;

                        ptl_md2handle(handle, md);

                        PTL_UNLOCK(flags);
                        return (PTL_OK);
                }
        }

        ptl_md_free (md);

        PTL_UNLOCK(flags);
        return (rc);
}

ptl_err_t
PtlMDBind(ptl_handle_ni_t nih, ptl_md_t umd,
          ptl_unlink_t unlink, ptl_handle_md_t *handle)
{
        ptl_libmd_t  *md;
        unsigned long flags;
        int           rc;

        if (!ptl_init)
                return PTL_NO_INIT;

        if (ptl_apini.apini_refcount == 0)
                return PTL_NI_INVALID;
        
        if ((umd.options & (PTL_MD_KIOV | PTL_MD_IOVEC)) != 0 &&
            umd.length > PTL_MD_MAX_IOV) /* too many fragments */
                return PTL_IOV_INVALID;

        md = ptl_md_alloc(&umd);
        if (md == NULL)
                return PTL_NO_SPACE;

        PTL_LOCK(flags);

        rc = lib_md_build(md, &umd, unlink);

        if (rc == PTL_OK) {
                ptl_md2handle(handle, md);

                PTL_UNLOCK(flags);
                return (PTL_OK);
        }

        ptl_md_free (md);

        PTL_UNLOCK(flags);
        return (rc);
}

ptl_err_t
PtlMDUnlink (ptl_handle_md_t mdh)
{
        ptl_event_t      ev;
        ptl_libmd_t     *md;
        unsigned long    flags;

        if (!ptl_init)
                return PTL_NO_INIT;

        if (ptl_apini.apini_refcount == 0)
                return PTL_MD_INVALID;
        
        PTL_LOCK(flags);

        md = ptl_handle2md(&mdh);
        if (md == NULL) {
                PTL_UNLOCK(flags);
                return PTL_MD_INVALID;
        }

        /* If the MD is busy, ptl_md_unlink just marks it for deletion, and
         * when the NAL is done, the completion event flags that the MD was
         * unlinked.  Otherwise, we enqueue an event now... */

        if (md->md_eq != NULL &&
            md->md_pending == 0) {
                memset(&ev, 0, sizeof(ev));

                ev.type = PTL_EVENT_UNLINK;
                ev.ni_fail_type = PTL_OK;
                ev.unlinked = 1;
                ptl_md_deconstruct(md, &ev.md);
                ptl_md2handle(&ev.md_handle, md);

                ptl_enq_event_locked(NULL, md->md_eq, &ev);
        }

        ptl_md_unlink(md);

        PTL_UNLOCK(flags);
        return PTL_OK;
}

ptl_err_t
PtlMDUpdate(ptl_handle_md_t mdh, 
            ptl_md_t *oldumd, ptl_md_t *newumd, 
            ptl_handle_eq_t testqh)
{
        ptl_libmd_t  *md;
        ptl_eq_t     *test_eq = NULL;
        unsigned long flags;
        int           rc;

        if (!ptl_init)
                return PTL_NO_INIT;

        if (ptl_apini.apini_refcount == 0)
                return PTL_MD_INVALID;

        PTL_LOCK(flags);

        md = ptl_handle2md(&mdh);
        if (md == NULL) {
                 rc = PTL_MD_INVALID;
                 goto out;
        }

        if (oldumd != NULL)
                ptl_md_deconstruct(md, oldumd);

        if (newumd == NULL) {
                rc = PTL_OK;
                goto out;
        }

        /* XXX fttb, the new MD must be the same "shape" wrt fragmentation,
         * since we simply overwrite the old lib-md */
        if ((((newumd->options ^ md->md_options) &
              (PTL_MD_IOVEC | PTL_MD_KIOV)) != 0) ||
            ((newumd->options & (PTL_MD_IOVEC | PTL_MD_KIOV)) != 0 &&
             newumd->length != md->md_niov)) {
                rc = PTL_IOV_INVALID;
                goto out;
        }

        if (!PtlHandleIsEqual (testqh, PTL_EQ_NONE)) {
                test_eq = ptl_handle2eq(&testqh);
                if (test_eq == NULL) {
                        rc = PTL_EQ_INVALID;
                        goto out;
                }
        }

        if (md->md_pending != 0) {
                rc = PTL_MD_NO_UPDATE;
                goto out;
        }

        if (test_eq == NULL ||
            test_eq->eq_deq_seq == test_eq->eq_enq_seq) {
                ptl_me_t *me = md->md_me;
                int       unlink = (md->md_flags & PTL_MD_FLAG_AUTO_UNLINK) ?
                                   PTL_UNLINK : PTL_RETAIN;

                // #warning this does not track eq refcounts properly
                LBUG();
                rc = lib_md_build(md, newumd, unlink);

                md->md_me = me;
        } else {
                rc = PTL_MD_NO_UPDATE;
        }

 out:
        PTL_UNLOCK(flags);

        return rc;
}
