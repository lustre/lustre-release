/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _OBD_LOV_H__
#define _OBD_LOV_H__

#define OBD_LOV_DEVICENAME "lov"

struct lov_brw_async_args {
        obd_count        aa_oa_bufs;
        struct brw_page *aa_ioarr;
};

static inline int lov_stripe_md_size(int stripes)
{
        return sizeof(struct lov_stripe_md) + stripes*sizeof(struct lov_oinfo);
}

static inline int lov_mds_md_size(int stripes)
{
        return sizeof(struct lov_mds_md) + stripes*sizeof(struct lov_object_id);
}

extern int lov_packmd(struct lustre_handle *conn, struct lov_mds_md **lmm,
                       struct lov_stripe_md *lsm);
extern int lov_unpackmd(struct lustre_handle *conn, struct lov_stripe_md **lsm,
                         struct lov_mds_md *lmm, int lmmsize);
extern int lov_setstripe(struct lustre_handle *conn,
                         struct lov_stripe_md **lsmp, struct lov_mds_md *lmmu);
extern int lov_getstripe(struct lustre_handle *conn, 
                         struct lov_stripe_md *lsm, struct lov_mds_md *lmmu);

#define IOC_LOV_TYPE                   'g'
#define IOC_LOV_MIN_NR                 50
#define IOC_LOV_SET_OSC_ACTIVE         _IOWR('g', 50, long)
#define IOC_LOV_MAX_NR                 50

#endif
