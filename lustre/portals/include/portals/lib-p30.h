/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib-p30.h
 *
 * Top level include for library side routines
 */

#ifndef _LIB_P30_H_
#define _LIB_P30_H_

#include "build_check.h"

#ifdef __KERNEL__
# include <asm/page.h>
# include <linux/string.h>
#else
# include <portals/list.h>
# include <string.h>
#endif
#include <portals/types.h>
#include <linux/kp30.h>
#include <portals/p30.h>
#include <portals/lib-types.h>
#include <portals/lib-nal.h>
#include <portals/lib-dispatch.h>

static inline int ptl_is_wire_handle_none (ptl_handle_wire_t *wh)
{
        return (wh->wh_interface_cookie == PTL_WIRE_HANDLE_NONE.wh_interface_cookie &&
                wh->wh_object_cookie == PTL_WIRE_HANDLE_NONE.wh_object_cookie);
}

#define state_lock(nal,flagsp)                          \
do {                                                    \
        CDEBUG(D_PORTALS, "taking state lock\n");       \
        nal->cb_cli(nal, flagsp);                       \
} while (0)

#define state_unlock(nal,flagsp)                        \
{                                                       \
        CDEBUG(D_PORTALS, "releasing state lock\n");    \
        nal->cb_sti(nal, flagsp);                       \
}

#ifdef PTL_USE_LIB_FREELIST

#define MAX_MES         2048
#define MAX_MDS         2048
#define MAX_MSGS        2048    /* Outstanding messages */
#define MAX_EQS         512

extern int lib_freelist_init (nal_cb_t *nal, lib_freelist_t *fl, int nobj, int objsize);
extern void lib_freelist_fini (nal_cb_t *nal, lib_freelist_t *fl);

static inline void *
lib_freelist_alloc (lib_freelist_t *fl)
{
        /* ALWAYS called with statelock held */
        lib_freeobj_t *o;

        if (list_empty (&fl->fl_list))
                return (NULL);
        
        o = list_entry (fl->fl_list.next, lib_freeobj_t, fo_list);
        list_del (&o->fo_list);
        return ((void *)&o->fo_contents);
}

static inline void
lib_freelist_free (lib_freelist_t *fl, void *obj)
{
        /* ALWAYS called with statelock held */
        lib_freeobj_t *o = list_entry (obj, lib_freeobj_t, fo_contents);
        
        list_add (&o->fo_list, &fl->fl_list);
}


static inline lib_eq_t *
lib_eq_alloc (nal_cb_t *nal)
{
        /* NEVER called with statelock held */
        unsigned long  flags;
        lib_eq_t      *eq;
        
        state_lock (nal, &flags);
        eq = (lib_eq_t *)lib_freelist_alloc (&nal->ni.ni_free_eqs);
        state_unlock (nal, &flags);

        return (eq);
}

static inline void
lib_eq_free (nal_cb_t *nal, lib_eq_t *eq)
{
        /* ALWAYS called with statelock held */
        lib_freelist_free (&nal->ni.ni_free_eqs, eq);
}

static inline lib_md_t *
lib_md_alloc (nal_cb_t *nal, ptl_md_t *umd)
{
        /* NEVER called with statelock held */
        unsigned long  flags;
        lib_md_t      *md;
        
        state_lock (nal, &flags);
        md = (lib_md_t *)lib_freelist_alloc (&nal->ni.ni_free_mds);
        state_unlock (nal, &flags);

        return (md);
}

static inline void
lib_md_free (nal_cb_t *nal, lib_md_t *md)
{
        /* ALWAYS called with statelock held */
        lib_freelist_free (&nal->ni.ni_free_mds, md);
}

static inline lib_me_t *
lib_me_alloc (nal_cb_t *nal)
{
        /* NEVER called with statelock held */
        unsigned long  flags;
        lib_me_t      *me;
        
        state_lock (nal, &flags);
        me = (lib_me_t *)lib_freelist_alloc (&nal->ni.ni_free_mes);
        state_unlock (nal, &flags);
        
        return (me);
}

static inline void
lib_me_free (nal_cb_t *nal, lib_me_t *me)
{
        /* ALWAYS called with statelock held */
        lib_freelist_free (&nal->ni.ni_free_mes, me);
}

static inline lib_msg_t *
lib_msg_alloc (nal_cb_t *nal)
{
        /* NEVER called with statelock held */
        unsigned long  flags;
        lib_msg_t     *msg;
        
        state_lock (nal, &flags);
        msg = (lib_msg_t *)lib_freelist_alloc (&nal->ni.ni_free_msgs);
        state_unlock (nal, &flags);

        if (msg != NULL) {
                /* NULL pointers, clear flags etc */
                memset (msg, 0, sizeof (*msg));
                msg->ack_wmd = PTL_WIRE_HANDLE_NONE;
        }
        return(msg);
}

static inline void
lib_msg_free (nal_cb_t *nal, lib_msg_t *msg)
{
        /* ALWAYS called with statelock held */
        lib_freelist_free (&nal->ni.ni_free_msgs, msg);
}

#else

static inline lib_eq_t *
lib_eq_alloc (nal_cb_t *nal)
{
        /* NEVER called with statelock held */
        lib_eq_t *eq;

        PORTAL_ALLOC(eq, sizeof(*eq));
        return (eq);
}

static inline void
lib_eq_free (nal_cb_t *nal, lib_eq_t *eq)
{
        /* ALWAYS called with statelock held */
        PORTAL_FREE(eq, sizeof(*eq));
}

static inline lib_md_t *
lib_md_alloc (nal_cb_t *nal, ptl_md_t *umd)
{
        /* NEVER called with statelock held */
        lib_md_t *md;
        int       size;
        int       niov;

        if ((umd->options & PTL_MD_KIOV) != 0) {
                niov = umd->niov;
                size = offsetof(lib_md_t, md_iov.kiov[niov]);
        } else {
                niov = ((umd->options & PTL_MD_IOVEC) != 0) ?
                       umd->niov : 1;
                size = offsetof(lib_md_t, md_iov.iov[niov]);
        }

        PORTAL_ALLOC(md, size);

        if (md != NULL) {
                /* Set here in case of early free */
                md->options = umd->options;
                md->md_niov = niov;
        }
        
        return (md);
}

static inline void 
lib_md_free (nal_cb_t *nal, lib_md_t *md)
{
        /* ALWAYS called with statelock held */
        int       size;

        if ((md->options & PTL_MD_KIOV) != 0)
                size = offsetof(lib_md_t, md_iov.kiov[md->md_niov]);
        else
                size = offsetof(lib_md_t, md_iov.iov[md->md_niov]);

        PORTAL_FREE(md, size);
}

static inline lib_me_t *
lib_me_alloc (nal_cb_t *nal)
{
        /* NEVER called with statelock held */
        lib_me_t *me;

        PORTAL_ALLOC(me, sizeof(*me));
        return (me);
}

static inline void 
lib_me_free(nal_cb_t *nal, lib_me_t *me)
{
        /* ALWAYS called with statelock held */
        PORTAL_FREE(me, sizeof(*me));
}

static inline lib_msg_t *
lib_msg_alloc(nal_cb_t *nal)
{
        /* NEVER called with statelock held; may be in interrupt... */
        lib_msg_t *msg;

        if (in_interrupt())
                PORTAL_ALLOC_ATOMIC(msg, sizeof(*msg));
        else
                PORTAL_ALLOC(msg, sizeof(*msg));

        if (msg != NULL) {
                /* NULL pointers, clear flags etc */
                memset (msg, 0, sizeof (*msg));
                msg->ack_wmd = PTL_WIRE_HANDLE_NONE;
        }
        return (msg);
}

static inline void 
lib_msg_free(nal_cb_t *nal, lib_msg_t *msg)
{
        /* ALWAYS called with statelock held */
        PORTAL_FREE(msg, sizeof(*msg));
}
#endif

extern lib_handle_t *lib_lookup_cookie (nal_cb_t *nal, __u64 cookie, int type);
extern void lib_initialise_handle (nal_cb_t *nal, lib_handle_t *lh, int type);
extern void lib_invalidate_handle (nal_cb_t *nal, lib_handle_t *lh);

static inline void
ptl_eq2handle (ptl_handle_eq_t *handle, lib_eq_t *eq)
{
        handle->cookie = eq->eq_lh.lh_cookie;
}

static inline lib_eq_t *
ptl_handle2eq (ptl_handle_eq_t *handle, nal_cb_t *nal)
{
        /* ALWAYS called with statelock held */
        lib_handle_t *lh = lib_lookup_cookie (nal, handle->cookie, 
                                              PTL_COOKIE_TYPE_EQ);
        if (lh == NULL)
                return (NULL);

        return (lh_entry (lh, lib_eq_t, eq_lh));
}

static inline void
ptl_md2handle (ptl_handle_md_t *handle, lib_md_t *md)
{
        handle->cookie = md->md_lh.lh_cookie;
}

static inline lib_md_t *
ptl_handle2md (ptl_handle_md_t *handle, nal_cb_t *nal)
{
        /* ALWAYS called with statelock held */
        lib_handle_t *lh = lib_lookup_cookie (nal, handle->cookie,
                                              PTL_COOKIE_TYPE_MD);
        if (lh == NULL)
                return (NULL);

        return (lh_entry (lh, lib_md_t, md_lh));
}

static inline lib_md_t *
ptl_wire_handle2md (ptl_handle_wire_t *wh, nal_cb_t *nal)
{
        /* ALWAYS called with statelock held */
        lib_handle_t *lh;
        
        if (wh->wh_interface_cookie != nal->ni.ni_interface_cookie)
                return (NULL);
        
        lh = lib_lookup_cookie (nal, wh->wh_object_cookie,
                                PTL_COOKIE_TYPE_MD);
        if (lh == NULL)
                return (NULL);

        return (lh_entry (lh, lib_md_t, md_lh));
}

static inline void
ptl_me2handle (ptl_handle_me_t *handle, lib_me_t *me)
{
        handle->cookie = me->me_lh.lh_cookie;
}

static inline lib_me_t *
ptl_handle2me (ptl_handle_me_t *handle, nal_cb_t *nal)
{
        /* ALWAYS called with statelock held */
        lib_handle_t *lh = lib_lookup_cookie (nal, handle->cookie,
                                              PTL_COOKIE_TYPE_ME);
        if (lh == NULL)
                return (NULL);

        return (lh_entry (lh, lib_me_t, me_lh));
}

extern int lib_init(nal_cb_t * cb, ptl_nid_t nid, ptl_pid_t pid, int gsize,
                    ptl_pt_index_t tbl_size, ptl_ac_index_t ac_size);
extern int lib_fini(nal_cb_t * cb);
extern void lib_dispatch(nal_cb_t * cb, void *private, int index,
                         void *arg_block, void *ret_block);
extern char *dispatch_name(int index);

/*
 * When the NAL detects an incoming message, it should call
 * lib_parse() decode it.  The NAL callbacks will be handed
 * the private cookie as a way for the NAL to maintain state
 * about which transaction is being processed.  An extra parameter,
 * lib_cookie will contain the necessary information for
 * finalizing the message.
 *
 * After it has finished the handling the message, it should
 * call lib_finalize() with the lib_cookie parameter.
 * Call backs will be made to write events, send acks or
 * replies and so on.
 */
extern void lib_enq_event_locked (nal_cb_t *nal, void *private,
                                  lib_eq_t *eq, ptl_event_t *ev);
extern void lib_finalize (nal_cb_t *nal, void *private, lib_msg_t *msg, 
                          ptl_ni_fail_t ni_fail_type);
extern void lib_parse (nal_cb_t *nal, ptl_hdr_t *hdr, void *private);
extern lib_msg_t *lib_create_reply_msg (nal_cb_t *nal, ptl_nid_t peer_nid, 
                                        lib_msg_t *get_msg);
extern void print_hdr (nal_cb_t * nal, ptl_hdr_t * hdr);


extern ptl_size_t lib_iov_nob (int niov, struct iovec *iov);
extern void lib_copy_iov2buf (char *dest, int niov, struct iovec *iov, 
                              ptl_size_t offset, ptl_size_t len);
extern void lib_copy_buf2iov (int niov, struct iovec *iov, ptl_size_t offset, 
                              char *src, ptl_size_t len);
extern int lib_extract_iov (int dst_niov, struct iovec *dst,
                            int src_niov, struct iovec *src,
                            ptl_size_t offset, ptl_size_t len);

extern ptl_size_t lib_kiov_nob (int niov, ptl_kiov_t *iov);
extern void lib_copy_kiov2buf (char *dest, int niov, ptl_kiov_t *kiov, 
                               ptl_size_t offset, ptl_size_t len);
extern void lib_copy_buf2kiov (int niov, ptl_kiov_t *kiov, ptl_size_t offset,
                               char *src, ptl_size_t len);
extern int lib_extract_kiov (int dst_niov, ptl_kiov_t *dst, 
                             int src_niov, ptl_kiov_t *src,
                             ptl_size_t offset, ptl_size_t len);

extern void lib_assert_wire_constants (void);

extern ptl_err_t lib_recv (nal_cb_t *nal, void *private, lib_msg_t *msg, lib_md_t *md,
                           ptl_size_t offset, ptl_size_t mlen, ptl_size_t rlen);
extern ptl_err_t lib_send (nal_cb_t *nal, void *private, lib_msg_t *msg,
                           ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
                           lib_md_t *md, ptl_size_t offset, ptl_size_t len);

extern void lib_md_deconstruct(nal_cb_t * nal, lib_md_t * md_in,
                               ptl_md_t * md_out);
extern void lib_md_unlink(nal_cb_t * nal, lib_md_t * md_in);
extern void lib_me_unlink(nal_cb_t * nal, lib_me_t * me_in);
#endif
