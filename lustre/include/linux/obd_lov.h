/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _OBD_LOV_H__
#define _OBD_LOV_H__

#ifdef __KERNEL__

#define OBD_LOV_DEVICENAME "lov"

void lov_unpackdesc(struct lov_desc *ld);
void lov_packdesc(struct lov_desc *ld);

static inline int lov_stripe_md_size(int stripes)
{
        return sizeof(struct lov_stripe_md) + stripes*sizeof(struct lov_oinfo);
}
#endif

static inline int lov_mds_md_size(int stripes)
{
        return sizeof(struct lov_mds_md) + stripes*sizeof(struct lov_object_id);
}

#define IOC_LOV_TYPE                   'g'
#define IOC_LOV_MIN_NR                 50
#define IOC_LOV_SET_OSC_ACTIVE         _IOWR('g', 50, long)
#define IOC_LOV_MAX_NR                 50

#endif
