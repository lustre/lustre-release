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
# include <pthread.h>
#endif
#include <portals/types.h>
#include <linux/kp30.h>
#include <portals/p30.h>
#include <portals/nal.h>
#include <portals/lib-types.h>

static inline int ptl_is_wire_handle_none (ptl_handle_wire_t *wh)
{
        return (wh->wh_interface_cookie == PTL_WIRE_HANDLE_NONE.wh_interface_cookie &&
                wh->wh_object_cookie == PTL_WIRE_HANDLE_NONE.wh_object_cookie);
}

#ifdef __KERNEL__
#define LIB_LOCK(nal,flags)                                     \
        spin_lock_irqsave(&(nal)->libnal_ni.ni_lock, flags)
#define LIB_UNLOCK(nal,flags)                                   \
        spin_unlock_irqrestore(&(nal)->libnal_ni.ni_lock, flags)
#else
#define LIB_LOCK(nal,flags)                                             \
        (pthread_mutex_lock(&(nal)->libnal_ni.ni_mutex), (flags) = 0)
#define LIB_UNLOCK(nal,flags)                                   \
        pthread_mutex_unlock(&(nal)->libnal_ni.ni_mutex)
#endif


#ifdef PTL_USE_LIB_FREELIST

#define MAX_MES         2048
#define MAX_MDS         2048
#define MAX_MSGS        2048    /* Outstanding messages */
#define MAX_EQS         512

extern int lib_freelist_init (lib_nal_t *nal, lib_freelist_t *fl, int nobj, int objsize);
extern void lib_freelist_fini (lib_nal_t *nal, lib_freelist_t *fl);

static inline void *
lib_freelist_alloc (lib_freelist_t *fl)
{
        /* ALWAYS called with liblock held */
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
        /* ALWAYS called with liblock held */
        lib_freeobj_t *o = list_entry (obj, lib_freeobj_t, fo_contents);
        
        list_add (&o->fo_list, &fl->fl_list);
}


static inline lib_eq_t *
lib_eq_alloc (lib_nal_t *nal)
{
        /* NEVER called with liblock held */
        unsigned long  flags;
        lib_eq_t      *eq;
        
        LIB_LOCK (nal, flags);
        eq = (lib_eq_t *)lib_freelist_alloc (&nal->libnal_ni.ni_free_eqs);
        LIB_UNLOCK (nal, flags);

        return (eq);
}

static inline void
lib_eq_free (lib_nal_t *nal, lib_eq_t *eq)
{
        /* ALWAYS called with liblock held */
        lib_freelist_free (&nal->libnal_ni.ni_free_eqs, eq);
}

static inline lib_md_t *
lib_md_alloc (lib_nal_t *nal, ptl_md_t *umd)
{
        /* NEVER called with liblock held */
        unsigned long  flags;
        lib_md_t      *md;
        
        LIB_LOCK (nal, flags);
        md = (lib_md_t *)lib_freelist_alloc (&nal->libnal_ni.ni_free_mds);
        LIB_UNLOCK (nal, flags);

        return (md);
}

static inline void
lib_md_free (lib_nal_t *nal, lib_md_t *md)
{
        /* ALWAYS called with liblock held */
        lib_freelist_free (&nal->libnal_ni.ni_free_mds, md);
}

static inline lib_me_t *
lib_me_alloc (lib_nal_t *nal)
{
        /* NEVER called with liblock held */
        unsigned long  flags;
        lib_me_t      *me;
        
        LIB_LOCK (nal, flags);
        me = (lib_me_t *)lib_freelist_alloc (&nal->libnal_ni.ni_free_mes);
        LIB_UNLOCK (nal, flags);
        
        return (me);
}

static inline void
lib_me_free (lib_nal_t *nal, lib_me_t *me)
{
        /* ALWAYS called with liblock held */
        lib_freelist_free (&nal->libnal_ni.ni_free_mes, me);
}

static inline lib_msg_t *
lib_msg_alloc (lib_nal_t *nal)
{
        /* NEVER called with liblock held */
        unsigned long  flags;
        lib_msg_t     *msg;
        
        LIB_LOCK (nal, flags);
        msg = (lib_msg_t *)lib_freelist_alloc (&nal->libnal_ni.ni_free_msgs);
        LIB_UNLOCK (nal, flags);

        if (msg != NULL) {
                /* NULL pointers, clear flags etc */
                memset (msg, 0, sizeof (*msg));
                msg->ack_wmd = PTL_WIRE_HANDLE_NONE;
        }
        return(msg);
}

static inline void
lib_msg_free (lib_nal_t *nal, lib_msg_t *msg)
{
        /* ALWAYS called with liblock held */
        lib_freelist_free (&nal->libnal_ni.ni_free_msgs, msg);
}

#else

static inline lib_eq_t *
lib_eq_alloc (lib_nal_t *nal)
{
        /* NEVER called with liblock held */
        lib_eq_t *eq;

        PORTAL_ALLOC(eq, sizeof(*eq));
        return (eq);
}

static inline void
lib_eq_free (lib_nal_t *nal, lib_eq_t *eq)
{
        /* ALWAYS called with liblock held */
        PORTAL_FREE(eq, sizeof(*eq));
}

static inline lib_md_t *
lib_md_alloc (lib_nal_t *nal, ptl_md_t *umd)
{
        /* NEVER called with liblock held */
        lib_md_t *md;
        int       size;
        int       niov;

        if ((umd->options & PTL_MD_KIOV) != 0) {
                niov = umd->length;
                size = offsetof(lib_md_t, md_iov.kiov[niov]);
        } else {
                niov = ((umd->options & PTL_MD_IOVEC) != 0) ?
                       umd->length : 1;
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
lib_md_free (lib_nal_t *nal, lib_md_t *md)
{
        /* ALWAYS called with liblock held */
        int       size;

        if ((md->options & PTL_MD_KIOV) != 0)
                size = offsetof(lib_md_t, md_iov.kiov[md->md_niov]);
        else
                size = offsetof(lib_md_t, md_iov.iov[md->md_niov]);

        PORTAL_FREE(md, size);
}

static inline lib_me_t *
lib_me_alloc (lib_nal_t *nal)
{
        /* NEVER called with liblock held */
        lib_me_t *me;

        PORTAL_ALLOC(me, sizeof(*me));
        return (me);
}

static inline void 
lib_me_free(lib_nal_t *nal, lib_me_t *me)
{
        /* ALWAYS called with liblock held */
        PORTAL_FREE(me, sizeof(*me));
}

static inline lib_msg_t *
lib_msg_alloc(lib_nal_t *nal)
{
        /* NEVER called with liblock held; may be in interrupt... */
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
lib_msg_free(lib_nal_t *nal, lib_msg_t *msg)
{
        /* ALWAYS called with liblock held */
        PORTAL_FREE(msg, sizeof(*msg));
}
#endif

extern lib_handle_t *lib_lookup_cookie (lib_nal_t *nal, __u64 cookie, int type);
extern void lib_initialise_handle (lib_nal_t *nal, lib_handle_t *lh, int type);
extern void lib_invalidate_handle (lib_nal_t *nal, lib_handle_t *lh);

static inline void
ptl_eq2handle (ptl_handle_eq_t *handle, lib_nal_t *nal, lib_eq_t *eq)
{
        if (eq == NULL) {
                *handle = PTL_EQ_NONE;
                return;
        }

        handle->nal_idx = nal->libnal_ni.ni_api->nal_handle.nal_idx;
        handle->cookie = eq->eq_lh.lh_cookie;
}

static inline lib_eq_t *
ptl_handle2eq (ptl_handle_eq_t *handle, lib_nal_t *nal)
{
        /* ALWAYS called with liblock held */
        lib_handle_t *lh = lib_lookup_cookie (nal, handle->cookie, 
                                              PTL_COOKIE_TYPE_EQ);
        if (lh == NULL)
                return (NULL);

        return (lh_entry (lh, lib_eq_t, eq_lh));
}

static inline void
ptl_md2handle (ptl_handle_md_t *handle, lib_nal_t *nal, lib_md_t *md)
{
        handle->nal_idx = nal->libnal_ni.ni_api->nal_handle.nal_idx;
        handle->cookie = md->md_lh.lh_cookie;
}

static inline lib_md_t *
ptl_handle2md (ptl_handle_md_t *handle, lib_nal_t *nal)
{
        /* ALWAYS called with liblock held */
        lib_handle_t *lh = lib_lookup_cookie (nal, handle->cookie,
                                              PTL_COOKIE_TYPE_MD);
        if (lh == NULL)
                return (NULL);

        return (lh_entry (lh, lib_md_t, md_lh));
}

static inline lib_md_t *
ptl_wire_handle2md (ptl_handle_wire_t *wh, lib_nal_t *nal)
{
        /* ALWAYS called with liblock held */
        lib_handle_t *lh;
        
        if (wh->wh_interface_cookie != nal->libnal_ni.ni_interface_cookie)
                return (NULL);
        
        lh = lib_lookup_cookie (nal, wh->wh_object_cookie,
                                PTL_COOKIE_TYPE_MD);
        if (lh == NULL)
                return (NULL);

        return (lh_entry (lh, lib_md_t, md_lh));
}

static inline void
ptl_me2handle (ptl_handle_me_t *handle, lib_nal_t *nal, lib_me_t *me)
{
        handle->nal_idx = nal->libnal_ni.ni_api->nal_handle.nal_idx;
        handle->cookie = me->me_lh.lh_cookie;
}

static inline lib_me_t *
ptl_handle2me (ptl_handle_me_t *handle, lib_nal_t *nal)
{
        /* ALWAYS called with liblock held */
        lib_handle_t *lh = lib_lookup_cookie (nal, handle->cookie,
                                              PTL_COOKIE_TYPE_ME);
        if (lh == NULL)
                return (NULL);

        return (lh_entry (lh, lib_me_t, me_lh));
}

extern int lib_init(lib_nal_t *libnal, nal_t *apinal,
                    ptl_process_id_t pid,
                    ptl_ni_limits_t *desired_limits, 
                    ptl_ni_limits_t *actual_limits);
extern int lib_fini(lib_nal_t *libnal);

/*
 * When the NAL detects an incoming message header, it should call
 * lib_parse() decode it.  If the message header is garbage, lib_parse()
 * returns immediately with failure, otherwise the NAL callbacks will be
 * called to receive the message body.  They are handed the private cookie
 * as a way for the NAL to maintain state about which transaction is being
 * processed.  An extra parameter, lib_msg contains the lib-level message
 * state for passing to lib_finalize() when the message body has been
 * received.
 */
extern void lib_enq_event_locked (lib_nal_t *nal, void *private,
                                  lib_eq_t *eq, ptl_event_t *ev);
extern void lib_finalize (lib_nal_t *nal, void *private, lib_msg_t *msg, 
                          ptl_ni_fail_t ni_fail_type);
extern ptl_err_t lib_parse (lib_nal_t *nal, ptl_hdr_t *hdr, void *private);
extern lib_msg_t *lib_create_reply_msg (lib_nal_t *nal, ptl_nid_t peer_nid, 
                                        lib_msg_t *get_msg);
extern void print_hdr (lib_nal_t * nal, ptl_hdr_t * hdr);


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

extern ptl_err_t lib_recv (lib_nal_t *nal, void *private, lib_msg_t *msg, lib_md_t *md,
                           ptl_size_t offset, ptl_size_t mlen, ptl_size_t rlen);
extern ptl_err_t lib_send (lib_nal_t *nal, void *private, lib_msg_t *msg,
                           ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
                           lib_md_t *md, ptl_size_t offset, ptl_size_t len);

extern int lib_api_ni_status (nal_t *nal, ptl_sr_index_t sr_idx,
                              ptl_sr_value_t *status);
extern int lib_api_ni_dist (nal_t *nal, ptl_process_id_t *pid, 
                            unsigned long *dist);

extern int lib_api_eq_alloc (nal_t *nal, ptl_size_t count,
                             ptl_eq_handler_t callback, 
                             ptl_handle_eq_t *handle);
extern int lib_api_eq_free(nal_t *nal, ptl_handle_eq_t *eqh);
extern int lib_api_eq_poll (nal_t *nal, 
                            ptl_handle_eq_t *eventqs, int neq, int timeout_ms,
                            ptl_event_t *event, int *which);

extern int lib_api_me_attach(nal_t *nal,
                             ptl_pt_index_t portal,
                             ptl_process_id_t match_id, 
                             ptl_match_bits_t match_bits, 
                             ptl_match_bits_t ignore_bits,
                             ptl_unlink_t unlink, ptl_ins_pos_t pos,
                             ptl_handle_me_t *handle);
extern int lib_api_me_insert(nal_t *nal,
                             ptl_handle_me_t *current_meh,
                             ptl_process_id_t match_id, 
                             ptl_match_bits_t match_bits, 
                             ptl_match_bits_t ignore_bits,
                             ptl_unlink_t unlink, ptl_ins_pos_t pos,
                             ptl_handle_me_t *handle);
extern int lib_api_me_unlink (nal_t *nal, ptl_handle_me_t *meh);
extern void lib_me_unlink(lib_nal_t *nal, lib_me_t *me);

extern int lib_api_get_id(nal_t *nal, ptl_process_id_t *pid);

extern void lib_md_unlink(lib_nal_t *nal, lib_md_t *md);
extern void lib_md_deconstruct(lib_nal_t *nal, lib_md_t *lmd, ptl_md_t *umd);
extern int lib_api_md_attach(nal_t *nal, ptl_handle_me_t *meh,
                             ptl_md_t *umd, ptl_unlink_t unlink, 
                             ptl_handle_md_t *handle);
extern int lib_api_md_bind(nal_t *nal, ptl_md_t *umd, ptl_unlink_t unlink,
                           ptl_handle_md_t *handle);
extern int lib_api_md_unlink (nal_t *nal, ptl_handle_md_t *mdh);
extern int lib_api_md_update (nal_t *nal, ptl_handle_md_t *mdh,
                              ptl_md_t *oldumd, ptl_md_t *newumd,
                              ptl_handle_eq_t *testqh);

extern int lib_api_get(nal_t *apinal, ptl_handle_md_t *mdh, 
                       ptl_process_id_t *id,
                       ptl_pt_index_t portal, ptl_ac_index_t ac,
                       ptl_match_bits_t match_bits, ptl_size_t offset);
extern int lib_api_put(nal_t *apinal, ptl_handle_md_t *mdh, 
                       ptl_ack_req_t ack, ptl_process_id_t *id,
                       ptl_pt_index_t portal, ptl_ac_index_t ac,
                       ptl_match_bits_t match_bits, 
                       ptl_size_t offset, ptl_hdr_data_t hdr_data);
extern int lib_api_fail_nid(nal_t *apinal, ptl_nid_t nid, unsigned int threshold);

#endif
