/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib-p30.h
 *
 * Top level include for library side routines
 */

#ifndef __PORTALS_LIB_P30_H__
#define __PORTALS_LIB_P30_H__

#include "build_check.h"

#if defined(__linux__)
#include <portals/linux/lib-p30.h>
#elif defined(__APPLE__)
#include <portals/darwin/lib-p30.h>
#else
#error Unsupported Operating System
#endif

#include <portals/types.h>
#include <libcfs/kp30.h>
#include <portals/p30.h>
#include <portals/lib-types.h>

extern ptl_apini_t   ptl_apini;                 /* THE network interface (at the API) */

static inline int ptl_is_wire_handle_none (ptl_handle_wire_t *wh)
{
        return (wh->wh_interface_cookie == PTL_WIRE_HANDLE_NONE.wh_interface_cookie &&
                wh->wh_object_cookie == PTL_WIRE_HANDLE_NONE.wh_object_cookie);
}

static inline int ptl_md_exhausted (ptl_libmd_t *md) 
{
        return (md->md_threshold == 0 ||
                ((md->md_options & PTL_MD_MAX_SIZE) != 0 &&
                 md->md_offset + md->md_max_size > md->md_length));
}

#ifdef __KERNEL__
#define PTL_LOCK(flags)                                                 \
        spin_lock_irqsave(&ptl_apini.apini_lock, flags)                 
#define PTL_UNLOCK(flags)                                               \
        spin_unlock_irqrestore(&ptl_apini.apini_lock, flags)               
#define PTL_MUTEX_DOWN(m) mutex_down(m)
#define PTL_MUTEX_UP(m)   mutex_up(m)
#else                                                                   
#define PTL_LOCK(flags)                                                 \
        (pthread_mutex_lock(&ptl_apini.apini_mutex), (flags) = 0)       
#define PTL_UNLOCK(flags)                                               \
        pthread_mutex_unlock(&ptl_apini.apini_mutex)
#define PTL_MUTEX_DOWN(m) pthread_mutex_lock(m)
#define PTL_MUTEX_UP(m)   pthread_mutex_up(m)
#endif

#ifdef PTL_USE_LIB_FREELIST

#define MAX_MES         2048
#define MAX_MDS         2048
#define MAX_MSGS        2048    /* Outstanding messages */
#define MAX_EQS         512

static inline void *
ptl_freelist_alloc (ptl_freelist_t *fl)
{
        /* ALWAYS called with liblock held */
        ptl_freeobj_t *o;

        if (list_empty (&fl->fl_list))
                return (NULL);
        
        o = list_entry (fl->fl_list.next, ptl_freeobj_t, fo_list);
        list_del (&o->fo_list);
        return ((void *)&o->fo_contents);
}

static inline void
ptl_freelist_free (ptl_freelist_t *fl, void *obj)
{
        /* ALWAYS called with liblock held */
        ptl_freeobj_t *o = list_entry (obj, ptl_freeobj_t, fo_contents);
        
        list_add (&o->fo_list, &fl->fl_list);
}


static inline ptl_eq_t *
ptl_eq_alloc (void)
{
        /* NEVER called with liblock held */
        unsigned long  flags;
        ptl_eq_t      *eq;
        
        PTL_LOCK(flags);
        eq = (ptl_eq_t *)ptl_freelist_alloc(&ptl_apini.apini_free_eqs);
        PTL_UNLOCK(flags);

        return (eq);
}

static inline void
ptl_eq_free (ptl_eq_t *eq)
{
        /* ALWAYS called with liblock held */
        ptl_freelist_free(&ptl_apini.apini_free_eqs, eq);
}

static inline ptl_libmd_t *
ptl_md_alloc (ptl_md_t *umd)
{
        /* NEVER called with liblock held */
        unsigned long  flags;
        ptl_libmd_t   *md;
        
        PTL_LOCK(flags);
        md = (ptl_libmd_t *)ptl_freelist_alloc(&ptl_apini.apini_free_mds);
        PTL_UNLOCK(flags);

        return (md);
}

static inline void
ptl_md_free (ptl_libmd_t *md)
{
        /* ALWAYS called with liblock held */
        ptl_freelist_free (&ptl_apini.apini_free_mds, md);
}

static inline ptl_me_t *
ptl_me_alloc (void)
{
        /* NEVER called with liblock held */
        unsigned long  flags;
        ptl_me_t      *me;
        
        PTL_LOCK(flags);
        me = (ptl_me_t *)ptl_freelist_alloc(&ptl_apini.apini_free_mes);
        PTL_UNLOCK(flags);
        
        return (me);
}

static inline void
ptl_me_free (ptl_me_t *me)
{
        /* ALWAYS called with liblock held */
        ptl_freelist_free (&ptl_apini.apini_free_mes, me);
}

static inline ptl_msg_t *
ptl_msg_alloc (void)
{
        /* NEVER called with liblock held */
        unsigned long  flags;
        ptl_msg_t     *msg;
        
        PTL_LOCK(flags);
        msg = (ptl_msg_t *)ptl_freelist_alloc(&ptl_apini.apini_free_msgs);
        PTL_UNLOCK(flags);

        if (msg != NULL) {
                /* NULL pointers, clear flags etc */
                memset (msg, 0, sizeof (*msg));
                msg->msg_ack_wmd = PTL_WIRE_HANDLE_NONE;
        }
        return(msg);
}

static inline void
ptl_msg_free (ptl_msg_t *msg)
{
        /* ALWAYS called with liblock held */
        ptl_freelist_free(&ptl_apini.apini_free_msgs, msg);
}

#else

static inline ptl_eq_t *
ptl_eq_alloc (void)
{
        /* NEVER called with liblock held */
        ptl_eq_t *eq;

        PORTAL_ALLOC(eq, sizeof(*eq));
        return (eq);
}

static inline void
ptl_eq_free (ptl_eq_t *eq)
{
        /* ALWAYS called with liblock held */
        PORTAL_FREE(eq, sizeof(*eq));
}

static inline ptl_libmd_t *
ptl_md_alloc (ptl_md_t *umd)
{
        /* NEVER called with liblock held */
        ptl_libmd_t *md;
        int          size;
        int          niov;

        if ((umd->options & PTL_MD_KIOV) != 0) {
                niov = umd->length;
                size = offsetof(ptl_libmd_t, md_iov.kiov[niov]);
        } else {
                niov = ((umd->options & PTL_MD_IOVEC) != 0) ?
                       umd->length : 1;
                size = offsetof(ptl_libmd_t, md_iov.iov[niov]);
        }

        PORTAL_ALLOC(md, size);

        if (md != NULL) {
                /* Set here in case of early free */
                md->md_options = umd->options;
                md->md_niov = niov;
        }
        
        return (md);
}

static inline void 
ptl_md_free (ptl_libmd_t *md)
{
        /* ALWAYS called with liblock held */
        int       size;

        if ((md->md_options & PTL_MD_KIOV) != 0)
                size = offsetof(ptl_libmd_t, md_iov.kiov[md->md_niov]);
        else
                size = offsetof(ptl_libmd_t, md_iov.iov[md->md_niov]);

        PORTAL_FREE(md, size);
}

static inline ptl_me_t *
ptl_me_alloc (void)
{
        /* NEVER called with liblock held */
        ptl_me_t *me;

        PORTAL_ALLOC(me, sizeof(*me));
        return (me);
}

static inline void 
ptl_me_free(ptl_me_t *me)
{
        /* ALWAYS called with liblock held */
        PORTAL_FREE(me, sizeof(*me));
}

static inline ptl_msg_t *
ptl_msg_alloc(void)
{
        /* NEVER called with liblock held; may be in interrupt... */
        ptl_msg_t *msg;

        if (in_interrupt())
                PORTAL_ALLOC_ATOMIC(msg, sizeof(*msg));
        else
                PORTAL_ALLOC(msg, sizeof(*msg));

        if (msg != NULL) {
                /* NULL pointers, clear flags etc */
                memset (msg, 0, sizeof (*msg));
                msg->msg_ack_wmd = PTL_WIRE_HANDLE_NONE;
        }
        return (msg);
}

static inline void 
ptl_msg_free(ptl_msg_t *msg)
{
        /* ALWAYS called with liblock held */
        PORTAL_FREE(msg, sizeof(*msg));
}
#endif

extern ptl_libhandle_t *ptl_lookup_cookie (__u64 cookie, int type);
extern void ptl_initialise_handle (ptl_libhandle_t *lh, int type);
extern void ptl_invalidate_handle (ptl_libhandle_t *lh);

static inline void
ptl_eq2handle (ptl_handle_eq_t *handle, ptl_eq_t *eq)
{
        if (eq == NULL) {
                *handle = PTL_EQ_NONE;
                return;
        }

        handle->cookie = eq->eq_lh.lh_cookie;
}

static inline ptl_eq_t *
ptl_handle2eq (ptl_handle_eq_t *handle)
{
        /* ALWAYS called with liblock held */
        ptl_libhandle_t *lh = ptl_lookup_cookie (handle->cookie, 
                                                 PTL_COOKIE_TYPE_EQ);
        if (lh == NULL)
                return (NULL);

        return (lh_entry (lh, ptl_eq_t, eq_lh));
}

static inline void
ptl_md2handle (ptl_handle_md_t *handle, ptl_libmd_t *md)
{
        handle->cookie = md->md_lh.lh_cookie;
}

static inline ptl_libmd_t *
ptl_handle2md (ptl_handle_md_t *handle)
{
        /* ALWAYS called with liblock held */
        ptl_libhandle_t *lh = ptl_lookup_cookie (handle->cookie,
                                                 PTL_COOKIE_TYPE_MD);
        if (lh == NULL)
                return (NULL);

        return (lh_entry (lh, ptl_libmd_t, md_lh));
}

static inline ptl_libmd_t *
ptl_wire_handle2md (ptl_handle_wire_t *wh)
{
        /* ALWAYS called with liblock held */
        ptl_libhandle_t *lh;
        
        if (wh->wh_interface_cookie != ptl_apini.apini_interface_cookie)
                return (NULL);
        
        lh = ptl_lookup_cookie (wh->wh_object_cookie,
                                PTL_COOKIE_TYPE_MD);
        if (lh == NULL)
                return (NULL);

        return (lh_entry (lh, ptl_libmd_t, md_lh));
}

static inline void
ptl_me2handle (ptl_handle_me_t *handle, ptl_me_t *me)
{
        handle->cookie = me->me_lh.lh_cookie;
}

static inline ptl_me_t *
ptl_handle2me (ptl_handle_me_t *handle)
{
        /* ALWAYS called with liblock held */
        ptl_libhandle_t *lh = ptl_lookup_cookie (handle->cookie,
                                                 PTL_COOKIE_TYPE_ME);
        if (lh == NULL)
                return (NULL);

        return (lh_entry (lh, ptl_me_t, me_lh));
}

/******************************************************************************/
/* Portals Router */

/* NI APIs */
int       kpr_forwarding(void);
ptl_nid_t kpr_lookup(ptl_ni_t **ni, ptl_nid_t nid, int nob);
void      kpr_fwd_start(ptl_ni_t *ni, kpr_fwd_desc_t *fwd);
void      kpr_fwd_done(ptl_ni_t *ni, kpr_fwd_desc_t *fwd, int error);
int       kpr_notify(ptl_ni_t *ni, ptl_nid_t peer, int alive, time_t when);

/* internal APIs */
int       kpr_ctl(unsigned int cmd, void *arg);
int       kpr_add_route(__u32 net, ptl_nid_t gateway_nid);
int       kpr_initialise(void);
void      kpr_finalise(void);

static inline void
kpr_fwd_init (kpr_fwd_desc_t *fwd, ptl_nid_t nid, ptl_hdr_t *hdr,
              int nob, int niov, ptl_kiov_t *kiov,
              kpr_fwd_callback_t callback, void *callback_arg)
{
        fwd->kprfd_target_nid   = nid;
        fwd->kprfd_gateway_nid  = nid;
        fwd->kprfd_hdr          = hdr;
        fwd->kprfd_nob          = nob;
        fwd->kprfd_niov         = niov;
        fwd->kprfd_kiov         = kiov;
        fwd->kprfd_callback     = callback;
        fwd->kprfd_callback_arg = callback_arg;
}

/******************************************************************************/

static inline void
ptl_ni_addref(ptl_ni_t *ni) 
{
        LASSERT (atomic_read(&ni->ni_refcount) > 0);
        atomic_inc(&ni->ni_refcount);
}

extern void ptl_queue_zombie_ni (ptl_ni_t *ni);

static inline void
ptl_ni_decref(ptl_ni_t *ni)
{
        /* CAVEAT EMPTOR! must NOT be holding PTL_LOCK() (deadlock) */
        LASSERT (atomic_read(&ni->ni_refcount) > 0);
        if (atomic_dec_and_test(&ni->ni_refcount))
                ptl_queue_zombie_ni(ni);
}

extern ptl_nal_t ptl_lonal;
extern ptl_ni_t  ptl_loni;

extern ptl_err_t ptl_get_apinih (ptl_handle_ni_t *nih);

extern ptl_ni_t *ptl_net2ni (__u32 net);
extern int ptl_islocalnid (ptl_nid_t nid);
extern void ptl_enq_event_locked (void *private,
                                  ptl_eq_t *eq, ptl_event_t *ev);
extern void ptl_finalize (ptl_ni_t *ni, void *private, ptl_msg_t *msg, 
                          ptl_ni_fail_t ni_fail_type);
extern ptl_err_t ptl_parse (ptl_ni_t *ni, ptl_hdr_t *hdr, void *private);
extern ptl_msg_t *ptl_create_reply_msg (ptl_ni_t *ni, ptl_nid_t peer_nid, 
                                        ptl_msg_t *get_msg);
extern void ptl_print_hdr (ptl_hdr_t * hdr);
extern ptl_err_t ptl_fail_nid(ptl_nid_t nid, unsigned int threshold);

extern ptl_size_t ptl_iov_nob (int niov, struct iovec *iov);
extern void ptl_copy_iov2buf (char *dest, int niov, struct iovec *iov, 
                              ptl_size_t offset, ptl_size_t len);
extern void ptl_copy_buf2iov (int niov, struct iovec *iov, ptl_size_t offset, 
                              char *src, ptl_size_t len);
extern int ptl_extract_iov (int dst_niov, struct iovec *dst,
                            int src_niov, struct iovec *src,
                            ptl_size_t offset, ptl_size_t len);

extern ptl_size_t ptl_kiov_nob (int niov, ptl_kiov_t *iov);
extern void ptl_copy_kiov2buf (char *dest, int niov, ptl_kiov_t *kiov, 
                               ptl_size_t offset, ptl_size_t len);
extern void ptl_copy_buf2kiov (int niov, ptl_kiov_t *kiov, ptl_size_t offset,
                               char *src, ptl_size_t len);
extern int ptl_extract_kiov (int dst_niov, ptl_kiov_t *dst, 
                             int src_niov, ptl_kiov_t *src,
                             ptl_size_t offset, ptl_size_t len);

extern ptl_err_t ptl_recv (ptl_ni_t *ni, void *private, ptl_msg_t *msg, ptl_libmd_t *md,
                           ptl_size_t offset, ptl_size_t mlen, ptl_size_t rlen);
extern ptl_err_t ptl_send (ptl_ni_t *ni, void *private, ptl_msg_t *msg,
                           ptl_hdr_t *hdr, int type, ptl_process_id_t target,
                           ptl_libmd_t *md, ptl_size_t offset, ptl_size_t len);

extern void ptl_me_unlink(ptl_me_t *me);

extern void ptl_md_unlink(ptl_libmd_t *md);
extern void ptl_md_deconstruct(ptl_libmd_t *lmd, ptl_md_t *umd);

#ifdef __KERNEL__
extern void ptl_register_nal(ptl_nal_t *nal);
extern void ptl_unregister_nal(ptl_nal_t *nal);
#endif

extern ptl_err_t ptl_read_route_table(char *route_table);
extern ptl_err_t ptl_parse_routes (char *route_str);
extern ptl_err_t ptl_parse_networks (struct list_head *nilist, char *networks);

#endif
