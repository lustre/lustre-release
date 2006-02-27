/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _OBD_ECHO_H
#define _OBD_ECHO_H

/* The persistent object (i.e. actually stores stuff!) */
#define ECHO_PERSISTENT_OBJID    1ULL
#define ECHO_PERSISTENT_SIZE     ((__u64)(1<<20))

/* block size to use for data verification */
#define OBD_ECHO_BLOCK_SIZE	(4<<10)

struct ec_object {
        struct list_head       eco_obj_chain;
        struct obd_device     *eco_device;
        int                    eco_refcount;
        int                    eco_deleted;
        obd_id                 eco_id;
        struct lov_stripe_md  *eco_lsm;
};

struct ec_lock {
        struct list_head       ecl_exp_chain;
        struct ec_object      *ecl_object;
        __u64                  ecl_cookie;
        struct lustre_handle   ecl_lock_handle;
        ldlm_policy_data_t     ecl_policy;
        __u32                  ecl_mode;
};

#endif
