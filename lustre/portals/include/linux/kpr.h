/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _KPR_H
#define _KPR_H

# include <portals/lib-nal.h> /* for ptl_hdr_t */

/******************************************************************************/
/* Kernel Portals Router interface */

typedef void (*kpr_fwd_callback_t)(void *arg, int error); // completion callback

/* space for routing targets to stash "stuff" in a forwarded packet */
typedef union {
        long long        _alignment;
        void            *_space[16];            /* scale with CPU arch */
} kprfd_scratch_t;

/* Kernel Portals Routing Forwarded message Descriptor */
typedef struct {
        struct list_head     kprfd_list;        /* stash in queues (routing target can use) */
        ptl_nid_t            kprfd_target_nid;  /* final destination NID */
        ptl_nid_t            kprfd_gateway_nid; /* gateway NID */
        ptl_hdr_t           *kprfd_hdr;         /* header in wire byte order */
        int                  kprfd_nob;         /* # payload bytes */
        int                  kprfd_niov;        /* # payload frags */
        ptl_kiov_t          *kprfd_kiov;        /* payload fragments */
        void                *kprfd_router_arg;  /* originating NAL's router arg */
        kpr_fwd_callback_t   kprfd_callback;    /* completion callback */
        void                *kprfd_callback_arg; /* completion callback arg */
        kprfd_scratch_t      kprfd_scratch;     /* scratchpad for routing targets */
} kpr_fwd_desc_t;

typedef void  (*kpr_fwd_t)(void *arg, kpr_fwd_desc_t *fwd);
typedef void  (*kpr_notify_t)(void *arg, ptl_nid_t peer, int alive);

/* NAL's routing interface (Kernel Portals Routing Nal Interface) */
typedef const struct {
        int             kprni_nalid;    /* NAL's id */
        void           *kprni_arg;      /* Arg to pass when calling into NAL */
        kpr_fwd_t       kprni_fwd;      /* NAL's forwarding entrypoint */
        kpr_notify_t    kprni_notify;   /* NAL's notification entrypoint */
} kpr_nal_interface_t;

/* Router's routing interface (Kernel Portals Routing Router Interface) */
typedef const struct {
        /* register the calling NAL with the router and get back the handle for
         * subsequent calls */
        int     (*kprri_register) (kpr_nal_interface_t *nal_interface,
                                   void **router_arg);

        /* ask the router to find a gateway that forwards to 'nid' and is a
         * peer of the calling NAL; assume caller will send 'nob' bytes of
         * payload there */
        int     (*kprri_lookup) (void *router_arg, ptl_nid_t nid, int nob,
                                 ptl_nid_t *gateway_nid);

        /* hand a packet over to the router for forwarding */
        kpr_fwd_t kprri_fwd_start;

        /* hand a packet back to the router for completion */
        void    (*kprri_fwd_done) (void *router_arg, kpr_fwd_desc_t *fwd,
                                   int error);

        /* notify the router about peer state */
        void    (*kprri_notify) (void *router_arg, ptl_nid_t peer,
                                 int alive, time_t when);

        /* the calling NAL is shutting down */
        void    (*kprri_shutdown) (void *router_arg);

        /* deregister the calling NAL with the router */
        void    (*kprri_deregister) (void *router_arg);

} kpr_router_interface_t;

/* Convenient struct for NAL to stash router interface/args */
typedef struct {
        kpr_router_interface_t  *kpr_interface;
        void                    *kpr_arg;
} kpr_router_t;

/* Router's control interface (Kernel Portals Routing Control Interface) */
typedef const struct {
        int     (*kprci_add_route)(int gateway_nal, ptl_nid_t gateway_nid,
                                   ptl_nid_t lo_nid, ptl_nid_t hi_nid);
        int     (*kprci_del_route)(int gateway_nal, ptl_nid_t gateway_nid,
                                   ptl_nid_t lo_nid, ptl_nid_t hi_nid);
        int     (*kprci_get_route)(int index, int *gateway_nal,
                                   ptl_nid_t *gateway,
                                   ptl_nid_t *lo_nid, ptl_nid_t *hi_nid,
                                   int *alive);
        int     (*kprci_notify)(int gateway_nal, ptl_nid_t gateway_nid,
                                int alive, time_t when);
} kpr_control_interface_t;

extern kpr_control_interface_t  kpr_control_interface;
extern kpr_router_interface_t   kpr_router_interface;

static inline int
kpr_register (kpr_router_t *router, kpr_nal_interface_t *nalif)
{
        int    rc;

        router->kpr_interface = PORTAL_SYMBOL_GET (kpr_router_interface);
        if (router->kpr_interface == NULL)
                return (-ENOENT);

        rc = (router->kpr_interface)->kprri_register (nalif, &router->kpr_arg);
        if (rc != 0)
                router->kpr_interface = NULL;

        PORTAL_SYMBOL_PUT (kpr_router_interface);
        return (rc);
}

static inline int
kpr_routing (kpr_router_t *router)
{
        return (router->kpr_interface != NULL);
}

static inline int
kpr_lookup (kpr_router_t *router, ptl_nid_t nid, int nob, ptl_nid_t *gateway_nid)
{
        if (!kpr_routing (router))
                return (-ENETUNREACH);

        return (router->kpr_interface->kprri_lookup(router->kpr_arg, nid, nob,
                                                    gateway_nid));
}

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

static inline void
kpr_fwd_start (kpr_router_t *router, kpr_fwd_desc_t *fwd)
{
        if (!kpr_routing (router))
                fwd->kprfd_callback (fwd->kprfd_callback_arg, -ENETUNREACH);
        else
                router->kpr_interface->kprri_fwd_start (router->kpr_arg, fwd);
}

static inline void
kpr_fwd_done (kpr_router_t *router, kpr_fwd_desc_t *fwd, int error)
{
        LASSERT (kpr_routing (router));
        router->kpr_interface->kprri_fwd_done (router->kpr_arg, fwd, error);
}

static inline void
kpr_notify (kpr_router_t *router,
            ptl_nid_t peer, int alive, time_t when)
{
        if (!kpr_routing (router))
                return;

        router->kpr_interface->kprri_notify(router->kpr_arg, peer, alive, when);
}

static inline void
kpr_shutdown (kpr_router_t *router)
{
        if (kpr_routing (router))
                router->kpr_interface->kprri_shutdown (router->kpr_arg);
}

static inline void
kpr_deregister (kpr_router_t *router)
{
        if (!kpr_routing (router))
                return;
        router->kpr_interface->kprri_deregister (router->kpr_arg);
        router->kpr_interface = NULL;
}

#endif /* _KPR_H */
