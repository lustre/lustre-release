/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef LUSTRE_CACHE_H
#define LUSTRE_CACHE_H
#include <obd.h>
#include <lustre/lustre_idl.h>
#include <lustre_dlm.h>

struct lustre_cache;
struct osc_async_page;
struct page_removal_cb_element {
        struct list_head        prce_list;
        obd_page_removal_cb_t   prce_callback;
        atomic_t                prce_refcnt;
};

typedef int (*cache_iterate_extents_cb_t)(struct lustre_cache *,
                                          struct lustre_handle *,
                                          struct osc_async_page *,
                                          void *);
typedef int (*cache_iterate_locks_cb_t)(struct lustre_cache *,
                                        struct ldlm_res_id *,
                                        struct lustre_handle *, void *);

struct lustre_cache {
        struct list_head         lc_locks_list;
        spinlock_t               lc_locks_list_lock;
        struct list_head         lc_page_removal_callback_list;
        rwlock_t                 lc_page_removal_cb_lock; /* iterate vs modify list */
        struct obd_device       *lc_obd;
        obd_pin_extent_cb        lc_pin_extent_cb;
};

int cache_add_lock(struct lustre_cache *cache, struct lustre_handle *lockh);
int cache_add_extent(struct lustre_cache *cache, struct ldlm_res_id *res,
                     struct osc_async_page *extent,
                     struct lustre_handle *lockh);
void cache_remove_extent(struct lustre_cache *, struct osc_async_page *);
int cache_add_extent_removal_cb(struct lustre_cache *cache,
                                obd_page_removal_cb_t func_cb,
                                obd_pin_extent_cb pin_cb);
int cache_del_extent_removal_cb(struct lustre_cache *cache,
                                obd_page_removal_cb_t func_cb);
int cache_iterate_extents(struct lustre_cache *cache, struct lustre_handle *lockh,
                          cache_iterate_extents_cb_t cb_func, void *data);
int cache_remove_lock(struct lustre_cache *cache, struct lustre_handle *lockh);
int cache_iterate_locks(struct lustre_cache *cache, struct ldlm_res_id *res,
                        cache_iterate_locks_cb_t cb_fun, void *data);
struct lustre_cache *cache_create(struct obd_device *obd);
int cache_destroy(struct lustre_cache *cache);


#endif /* LUSTRE_CACHE_H */
