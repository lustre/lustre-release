/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _OBD_LOV_H__
#define _OBD_LOV_H__

#define OBD_LOV_DEVICENAME "lov"

struct lov_brw_async_args {
        struct lov_stripe_md  *aa_lsm;
        struct obdo           *aa_obdos;
        struct obdo           *aa_oa;
        struct brw_page       *aa_ioarr;
        obd_count              aa_oa_bufs;
};

struct lov_getattr_async_args {
        struct lov_stripe_md  *aa_lsm;
        struct obdo           *aa_oa;
        struct obdo           *aa_obdos;
        struct lov_obd        *aa_lov;
};

static inline int lov_stripe_md_size(int stripes)
{
        return sizeof(struct lov_stripe_md) + stripes*sizeof(struct lov_oinfo);
}

static inline int lov_mds_md_v0_size(int stripes)
{
        return sizeof(struct lov_mds_md_v0) +
                stripes * sizeof(struct lov_ost_data_v0);
}

#define lov_mds_md_size(stripes) lov_mds_md_v1_size(stripes)
static inline int lov_mds_md_v1_size(int stripes)
{
        return sizeof(struct lov_mds_md_v1) +
                stripes * sizeof(struct lov_ost_data_v1);
}

#define IOC_LOV_TYPE                   'g'
#define IOC_LOV_MIN_NR                 50
#define IOC_LOV_SET_OSC_ACTIVE         _IOWR('g', 50, long)
#define IOC_LOV_MAX_NR                 50

#endif
