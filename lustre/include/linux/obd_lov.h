/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _OBD_LOV_H__
#define _OBD_LOV_H__

#ifdef __KERNEL__

#define OBD_LOV_DEVICENAME "lov"

void lov_unpackdesc(struct lov_desc *ld);
void lov_packdesc(struct lov_desc *ld);


#endif
#endif
