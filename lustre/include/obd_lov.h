/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _OBD_LOV_H__
#define _OBD_LOV_H__

static inline int lov_stripe_md_size(int stripes)
{
        return sizeof(struct lov_stripe_md) + stripes*sizeof(struct lov_oinfo*);
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

#define QOS_DEFAULT_THRESHOLD           10 /* MB */
#define QOS_DEFAULT_MAXAGE              5  /* Seconds */

#endif
