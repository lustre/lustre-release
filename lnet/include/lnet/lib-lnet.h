/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib-p30.h
 *
 * Top level include for library side routines
 */

#ifndef _LIB_P30_H_
#define _LIB_P30_H_

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
#include <portals/errno.h>
#include <portals/lib-types.h>
#include <portals/lib-nal.h>
#include <portals/lib-dispatch.h>

static inline int ptl_is_wire_handle_none (ptl_handle_wire_t *wh)
{
        return (wh->wh_interface_cookie == PTL_WIRE_HANDLE_NONE.wh_interface_cookie &&
                wh->wh_object_cookie == PTL_WIRE_HANDLE_NONE.wh_object_cookie);
}

#ifdef __KERNEL__
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
#else
/* not needed in user space until we thread there */
#define state_lock(nal,flagsp)                          \
do {                                                    \
        CDEBUG(D_PORTALS, "taking state lock\n");       \
        CDEBUG(D_PORTALS, "%p:%p\n", nal, flagsp);      \
} while (0)

#define state_unlock(nal,flagsp)                        \
{                                                       \
        CDEBUG(D_PORTALS, "releasing state lock\n");    \
        CDEBUG(D_PORTALS, "%p:%p\n", nal, flagsp);      \
}
#endif /* __KERNEL__ */

#ifndef PTL_USE_SLAB_CACHE

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
lib_md_alloc (nal_cb_t *nal)
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
        /* ALWAYS called with statelock held */
        return ((lib_msg_t *)lib_freelist_alloc (&nal->ni.ni_free_msgs));
}

static inline void
lib_msg_free (nal_cb_t *nal, lib_msg_t *msg)
{
        /* ALWAYS called with statelock held */
        lib_freelist_free (&nal->ni.ni_free_msgs, msg);
}

#else

extern kmem_cache_t *ptl_md_slab; 
extern kmem_cache_t *ptl_msg_slab; 
extern kmem_cache_t *ptl_me_slab; 
extern kmem_cache_t *ptl_eq_slab; 
extern atomic_t      md_in_use_count;
extern atomic_t      msg_in_use_count;
extern atomic_t      me_in_use_count;
extern atomic_t      eq_in_use_count;

static inline lib_eq_t *
lib_eq_alloc (nal_cb_t *nal)
{
        /* NEVER called with statelock held */
        lib_eq_t *eq = kmem_cache_alloc(ptl_eq_slab, GFP_KERNEL);
        
        if (eq == NULL)
                return (NULL);
        
        atomic_inc (&eq_in_use_count);
        return (eq);
}

static inline void 
lib_eq_free (nal_cb_t *nal, lib_eq_t *eq)
{
        /* ALWAYS called with statelock held */
        atomic_dec (&eq_in_use_count);
        kmem_cache_free(ptl_eq_slab, eq); 
}

static inline lib_md_t *
lib_md_alloc (nal_cb_t *nal)
{
        /* NEVER called with statelock held */
        lib_md_t *md = kmem_cache_alloc(ptl_md_slab, GFP_KERNEL); 

        if (md == NULL)
                return (NULL);

        atomic_inc (&md_in_use_count);
        return (md);
}

static inline void 
lib_md_free (nal_cb_t *nal, lib_md_t *md)
{
        /* ALWAYS called with statelock held */
        atomic_dec (&md_in_use_count);
        kmem_cache_free(ptl_md_slab, md); 
}

static inline lib_me_t *
lib_me_alloc (nal_cb_t *nal)
{
        /* NEVER called with statelock held */
        lib_me_t *me = kmem_cache_alloc(ptl_me_slab, GFP_KERNEL);

        if (me == NULL)
                return (NULL);
        
        atomic_inc (&me_in_use_count);
        return (me);
}

static inline void 
lib_me_free(nal_cb_t *nal, lib_me_t *me)
{
        /* ALWAYS called with statelock held */
        atomic_dec (&me_in_use_count);
        kmem_cache_free(ptl_me_slab, me);
}

static inline lib_msg_t *
lib_msg_alloc(nal_cb_t *nal)
{
        /* ALWAYS called with statelock held */
        lib_msg_t *msg = kmem_cache_alloc(ptl_msg_slab, GFP_ATOMIC); 

        if (msg == NULL)
                return (NULL);
        
        atomic_inc (&msg_in_use_count);
        return (msg);
}

static inline void 
lib_msg_free(nal_cb_t *nal, lib_msg_t *msg)
{
        /* ALWAYS called with statelock held */
        atomic_dec (&msg_in_use_count);
        kmem_cache_free(ptl_msg_slab, msg); 
}
#endif

extern lib_handle_t *lib_lookup_cookie (nal_cb_t *nal, __u64 cookie);
extern void lib_initialise_handle (nal_cb_t *nal, lib_handle_t *lh);
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
        lib_handle_t *lh = lib_lookup_cookie (nal, handle->cookie);
        
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
        lib_handle_t *lh = lib_lookup_cookie (nal, handle->cookie);
        
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
        
        lh = lib_lookup_cookie (nal, wh->wh_object_cookie);
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
        lib_handle_t *lh = lib_lookup_cookie (nal, handle->cookie);
        
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
extern int lib_parse(nal_cb_t * nal, ptl_hdr_t * hdr, void *private);
extern int lib_finalize(nal_cb_t * nal, void *private, lib_msg_t * msg);
extern void print_hdr(nal_cb_t * nal, ptl_hdr_t * hdr);

extern ptl_size_t lib_iov_nob (int niov, struct iovec *iov);
extern void lib_copy_iov2buf (char *dest, int niov, struct iovec *iov, ptl_size_t len);
extern void lib_copy_buf2iov (int niov, struct iovec *iov, char *dest, ptl_size_t len);

extern ptl_size_t lib_kiov_nob (int niov, ptl_kiov_t *iov);
extern void lib_copy_kiov2buf (char *dest, int niov, ptl_kiov_t *iov, ptl_size_t len);
extern void lib_copy_buf2kiov (int niov, ptl_kiov_t *iov, char *src, ptl_size_t len);

extern void lib_recv (nal_cb_t *nal, void *private, lib_msg_t *msg, lib_md_t *md,
                      ptl_size_t offset, ptl_size_t mlen, ptl_size_t rlen);
extern int lib_send (nal_cb_t *nal, void *private, lib_msg_t *msg,
                     ptl_hdr_t *hdr, int type, ptl_nid_t nid, ptl_pid_t pid,
                     lib_md_t *md, ptl_size_t offset, ptl_size_t len);

extern void lib_md_deconstruct(nal_cb_t * nal, lib_md_t * md_in,
                               ptl_md_t * md_out);
extern void lib_md_unlink(nal_cb_t * nal, lib_md_t * md_in);
extern void lib_me_unlink(nal_cb_t * nal, lib_me_t * me_in);
#endif
