/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _MGC_INTERNAL_H
#define _MGC_INTERNAL_H

#include <libcfs/libcfs.h>
#include <lustre/lustre_idl.h>
#include <lustre_lib.h>
#include <lustre_dlm.h>
#include <lustre_log.h>
#include <lustre_export.h>

#ifdef LPROCFS
void lprocfs_mgc_init_vars(struct lprocfs_static_vars *lvars);
#else
static void lprocfs_mgc_init_vars(struct lprocfs_static_vars *lvars)
{
        memset(lvars, 0, sizeof(*lvars));
}
#endif  /* LPROCFS */

#endif  /* _MGC_INTERNAL_H */
