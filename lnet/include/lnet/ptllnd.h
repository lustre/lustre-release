/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc. All rights reserved.
 *   Author: PJ Kirner <pjkirner@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   This file is confidential source code owned by Cluster File Systems.
 *   No viewing, modification, compilation, redistribution, or any other
 *   form of use is permitted except through a signed license agreement.
 *
 *   If you have not signed such an agreement, then you have no rights to
 *   this file.  Please destroy it immediately and contact CFS.
 *
 */
 
/*
 * The PTLLND was designed to support Portals with
 * Lustre and non-lustre UNLINK semantics.
 * However for now the two targets are Cray Portals
 * on the XT3 and Lustre Portals (for testing) both
 * have Lustre UNLINK semantics, so this is defined
 * by default.
 */
#define LUSTRE_PORTALS_UNLINK_SEMANTICS
 
 
#ifdef _USING_LUSTRE_PORTALS_

/* NIDs are 64-bits on Lustre Portals */
#define FMT_NID LPU64
#define FMT_PID "%d"

/* When using Lustre Portals Lustre completion semantics are imlicit*/
#define PTL_MD_LUSTRE_COMPLETION_SEMANTICS      0

#else /* _USING_CRAY_PORTALS_ */

/* Explicit NULL function pointer for EQ handler */
#define PTL_EQ_HANDLER_NONE                     0

/* NIDs are integers on Cray Portals */
#define FMT_NID "%u"
#define FMT_PID "%d"

/* When using Cray Portals this is defined in the Cray Portals Header*/
/*#define PTL_MD_LUSTRE_COMPLETION_SEMANTICS */

/* Can compare handles directly on Cray Portals */
#define PtlHandleIsEqual(a,b) ((a) == (b))

/* Diffrent error types on Cray Portals*/
#define ptl_err_t ptl_ni_fail_t

/*
 * The Cray Portals has no maximum number of IOVs.  The
 * maximum is limited only my memory and size of the
 * int parameters (2^31-1).
 * Lustre only really require that the underyling
 * implemenation to support at least LNET_MAX_IOV,
 * so for Cray portals we can safely just use that
 * value here.
 *
 */
#define PTL_MD_MAX_IOV          LNET_MAX_IOV

#endif

#define FMT_PTLID "ptlid:"FMT_PID"-"FMT_NID

/* Align incoming small request messages to an 8 byte boundary if this is
 * supported to avoid alignment issues on some architectures */
#ifndef PTL_MD_LOCAL_ALIGN8
# define PTL_MD_LOCAL_ALIGN8 0
#endif
