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

#ifndef __KERNEL__
# include <stdio.h>
#else
# define DEBUG_SUBSYSTEM S_PORTALS
# include <linux/kp30.h>
#endif

#include <portals/lib-p30.h>

/* must be called with state lock held */
void
lib_md_unlink(lib_nal_t *nal, lib_md_t *md)
{
        if ((md->md_flags & PTL_MD_FLAG_ZOMBIE) == 0) {
                /* first unlink attempt... */
                lib_me_t *me = md->me;

                md->md_flags |= PTL_MD_FLAG_ZOMBIE;

                /* Disassociate from ME (if any), and unlink it if it was created
                 * with PTL_UNLINK */
                if (me != NULL) {
                        me->md = NULL;
                        if (me->unlink == PTL_UNLINK)
                                lib_me_unlink(nal, me);
                }

                /* emsure all future handle lookups fail */
                lib_invalidate_handle(nal, &md->md_lh);
        }

        if (md->pending != 0) {
                CDEBUG(D_NET, "Queueing unlink of md %p\n", md);
                return;
        }

        CDEBUG(D_NET, "Unlinking md %p\n", md);

        if ((md->options & PTL_MD_KIOV) != 0) {
                if (nal->libnal_unmap_pages != NULL)
                        nal->libnal_unmap_pages (nal, 
                                                 md->md_niov, 
                                                 md->md_iov.kiov, 
                                                 &md->md_addrkey);
        } else if (nal->libnal_unmap != NULL) {
                nal->libnal_unmap (nal, 
                                   md->md_niov, md->md_iov.iov, 
                                   &md->md_addrkey);
        }

        if (md->eq != NULL) {
                md->eq->eq_refcount--;
                LASSERT (md->eq->eq_refcount >= 0);
        }

        list_del (&md->md_list);
        lib_md_free(nal, md);
}

/* must be called with state lock held */
static int
lib_md_build(lib_nal_t *nal, lib_md_t *lmd, ptl_md_t *umd, int unlink)
{
        lib_eq_t     *eq = NULL;
        int           rc;
        int           i;
        int           niov;
        int           total_length = 0;

        /* NB we are passed an allocated, but uninitialised/active md.
         * if we return success, caller may lib_md_unlink() it.
         * otherwise caller may only lib_md_free() it.
         */

        if (!PtlHandleIsEqual (umd->eq_handle, PTL_EQ_NONE)) {
                eq = ptl_handle2eq(&umd->eq_handle, nal);
                if (eq == NULL)
                        return PTL_EQ_INVALID;
        }

        /* This implementation doesn't know how to create START events or
         * disable END events.  Best to LASSERT our caller is compliant so
         * we find out quickly...  */
        LASSERT (eq == NULL ||
                 ((umd->options & PTL_MD_EVENT_START_DISABLE) != 0 &&
                  (umd->options & PTL_MD_EVENT_END_DISABLE) == 0));

        lmd->me = NULL;
        lmd->start = umd->start;
        lmd->offset = 0;
        lmd->max_size = umd->max_size;
        lmd->options = umd->options;
        lmd->user_ptr = umd->user_ptr;
        lmd->eq = eq;
        lmd->threshold = umd->threshold;
        lmd->pending = 0;
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

                lmd->length = total_length;

                if ((umd->options & PTL_MD_MAX_SIZE) != 0 && /* max size used */
                    (umd->max_size < 0 || 
                     umd->max_size > total_length)) // illegal max_size
                        return PTL_MD_ILLEGAL;

                if (nal->libnal_map != NULL) {
                        rc = nal->libnal_map (nal, niov, lmd->md_iov.iov, 
                                              &lmd->md_addrkey);
                        if (rc != PTL_OK)
                                return (rc);
                }
        } else if ((umd->options & PTL_MD_KIOV) != 0) {
#ifndef __KERNEL__
                return PTL_MD_ILLEGAL;
#else                
                /* Trap attempt to use paged I/O if unsupported early. */
                if (nal->libnal_send_pages == NULL ||
                    nal->libnal_recv_pages == NULL)
                        return PTL_MD_INVALID;

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

                lmd->length = total_length;

                if ((umd->options & PTL_MD_MAX_SIZE) != 0 && /* max size used */
                    (umd->max_size < 0 || 
                     umd->max_size > total_length)) // illegal max_size
                        return PTL_MD_ILLEGAL;

                if (nal->libnal_map_pages != NULL) {
                        rc = nal->libnal_map_pages (nal, niov, lmd->md_iov.kiov, 
                                                    &lmd->md_addrkey);
                        if (rc != PTL_OK)
                                return (rc);
                }
#endif
        } else {   /* contiguous */
                lmd->length = umd->length;
                lmd->md_niov = niov = 1;
                lmd->md_iov.iov[0].iov_base = umd->start;
                lmd->md_iov.iov[0].iov_len = umd->length;

                if ((umd->options & PTL_MD_MAX_SIZE) != 0 && /* max size used */
                    (umd->max_size < 0 || 
                     umd->max_size > umd->length)) // illegal max_size
                        return PTL_MD_ILLEGAL;

                if (nal->libnal_map != NULL) {
                        rc = nal->libnal_map (nal, niov, lmd->md_iov.iov, 
                                              &lmd->md_addrkey);
                        if (rc != PTL_OK)
                                return (rc);
                }
        } 

        if (eq != NULL)
                eq->eq_refcount++;

        /* It's good; let handle2md succeed and add to active mds */
        lib_initialise_handle (nal, &lmd->md_lh, PTL_COOKIE_TYPE_MD);
        list_add (&lmd->md_list, &nal->libnal_ni.ni_active_mds);

        return PTL_OK;
}

/* must be called with state lock held */
void
lib_md_deconstruct(lib_nal_t *nal, lib_md_t *lmd, ptl_md_t *umd)
{
        /* NB this doesn't copy out all the iov entries so when a
         * discontiguous MD is copied out, the target gets to know the
         * original iov pointer (in start) and the number of entries it had
         * and that's all.
         */
        umd->start = lmd->start;
        umd->length = ((lmd->options & (PTL_MD_IOVEC | PTL_MD_KIOV)) == 0) ?
                      lmd->length : lmd->md_niov;
        umd->threshold = lmd->threshold;
        umd->max_size = lmd->max_size;
        umd->options = lmd->options;
        umd->user_ptr = lmd->user_ptr;
        ptl_eq2handle(&umd->eq_handle, nal, lmd->eq);
}

int 
lib_api_md_attach(nal_t *apinal, ptl_handle_me_t *meh,
                  ptl_md_t *umd, ptl_unlink_t unlink, 
                  ptl_handle_md_t *handle)
{
        lib_nal_t    *nal = apinal->nal_data;
        lib_me_t     *me;
        lib_md_t     *md;
        unsigned long flags;
        int           rc;

        if ((umd->options & (PTL_MD_KIOV | PTL_MD_IOVEC)) != 0 &&
            umd->length > PTL_MD_MAX_IOV) /* too many fragments */
                return PTL_IOV_INVALID;

        md = lib_md_alloc(nal, umd);
        if (md == NULL)
                return PTL_NO_SPACE;

        LIB_LOCK(nal, flags);

        me = ptl_handle2me(meh, nal);
        if (me == NULL) {
                rc = PTL_ME_INVALID;
        } else if (me->md != NULL) {
                rc = PTL_ME_IN_USE;
        } else {
                rc = lib_md_build(nal, md, umd, unlink);
                if (rc == PTL_OK) {
                        me->md = md;
                        md->me = me;

                        ptl_md2handle(handle, nal, md);

                        LIB_UNLOCK(nal, flags);
                        return (PTL_OK);
                }
        }

        lib_md_free (nal, md);

        LIB_UNLOCK(nal, flags);
        return (rc);
}

int
lib_api_md_bind(nal_t *apinal, 
                ptl_md_t *umd, ptl_unlink_t unlink,
                ptl_handle_md_t *handle)
{
        lib_nal_t    *nal = apinal->nal_data;
        lib_md_t     *md;
        unsigned long flags;
        int           rc;

        if ((umd->options & (PTL_MD_KIOV | PTL_MD_IOVEC)) != 0 &&
            umd->length > PTL_MD_MAX_IOV) /* too many fragments */
                return PTL_IOV_INVALID;

        md = lib_md_alloc(nal, umd);
        if (md == NULL)
                return PTL_NO_SPACE;

        LIB_LOCK(nal, flags);

        rc = lib_md_build(nal, md, umd, unlink);

        if (rc == PTL_OK) {
                ptl_md2handle(handle, nal, md);

                LIB_UNLOCK(nal, flags);
                return (PTL_OK);
        }

        lib_md_free (nal, md);

        LIB_UNLOCK(nal, flags);
        return (rc);
}

int
lib_api_md_unlink (nal_t *apinal, ptl_handle_md_t *mdh)
{
        lib_nal_t       *nal = apinal->nal_data;
        ptl_event_t      ev;
        lib_md_t        *md;
        unsigned long    flags;

        LIB_LOCK(nal, flags);

        md = ptl_handle2md(mdh, nal);
        if (md == NULL) {
                LIB_UNLOCK(nal, flags);
                return PTL_MD_INVALID;
        }

        /* If the MD is busy, lib_md_unlink just marks it for deletion, and
         * when the NAL is done, the completion event flags that the MD was
         * unlinked.  Otherwise, we enqueue an event now... */

        if (md->eq != NULL &&
            md->pending == 0) {
                memset(&ev, 0, sizeof(ev));

                ev.type = PTL_EVENT_UNLINK;
                ev.ni_fail_type = PTL_OK;
                ev.unlinked = 1;
                lib_md_deconstruct(nal, md, &ev.md);
                ptl_md2handle(&ev.md_handle, nal, md);
                
                lib_enq_event_locked(nal, NULL, md->eq, &ev);
        }

        lib_md_unlink(nal, md);

        LIB_UNLOCK(nal, flags);
        return PTL_OK;
}

int
lib_api_md_update (nal_t *apinal,
                   ptl_handle_md_t *mdh,
                   ptl_md_t *oldumd, ptl_md_t *newumd,
                   ptl_handle_eq_t *testqh)
{
        lib_nal_t    *nal = apinal->nal_data;
        lib_md_t     *md;
        lib_eq_t     *test_eq = NULL;
        unsigned long flags;
        int           rc;

        LIB_LOCK(nal, flags);

        md = ptl_handle2md(mdh, nal);
        if (md == NULL) {
                 rc = PTL_MD_INVALID;
                 goto out;
        }

        if (oldumd != NULL)
                lib_md_deconstruct(nal, md, oldumd);

        if (newumd == NULL) {
                rc = PTL_OK;
                goto out;
        }

        /* XXX fttb, the new MD must be the same "shape" wrt fragmentation,
         * since we simply overwrite the old lib-md */
        if ((((newumd->options ^ md->options) & 
              (PTL_MD_IOVEC | PTL_MD_KIOV)) != 0) ||
            ((newumd->options & (PTL_MD_IOVEC | PTL_MD_KIOV)) != 0 && 
             newumd->length != md->md_niov)) {
                rc = PTL_IOV_INVALID;
                goto out;
        } 

        if (!PtlHandleIsEqual (*testqh, PTL_EQ_NONE)) {
                test_eq = ptl_handle2eq(testqh, nal);
                if (test_eq == NULL) {
                        rc = PTL_EQ_INVALID;
                        goto out;
                }
        }

        if (md->pending != 0) {
                rc = PTL_MD_NO_UPDATE;
                goto out;
        }

        if (test_eq == NULL ||
            test_eq->eq_deq_seq == test_eq->eq_enq_seq) {
                lib_me_t *me = md->me;
                int       unlink = (md->md_flags & PTL_MD_FLAG_AUTO_UNLINK) ?
                                   PTL_UNLINK : PTL_RETAIN;

                // #warning this does not track eq refcounts properly 
                rc = lib_md_build(nal, md, newumd, unlink);

                md->me = me;
        } else {
                rc = PTL_MD_NO_UPDATE;
        }

 out:
        LIB_UNLOCK(nal, flags);

        return rc;
}
