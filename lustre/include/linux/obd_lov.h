/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _OBD_LOV_H__
#define _OBD_LOV_H__

#ifdef __KERNEL__

#define OBD_LOV_DEVICENAME "lov"

struct lov_object_id { /* per-child structure */
        __u64 l_object_id;
        __u32 l_device_id;
};

struct lov_md {
        __u64 lmd_object_id;     /* lov object id */
        __u64 lmd_stripe_count;
        __u32 lmd_stripe_size;
        __u32 lmd_stripe_pattern;  /* per-lov object stripe pattern */
        struct lov_object_id lmd_objects[0];
};

#endif
#endif
