/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef __LINUX_MDT_H
#define __LINUX_MDT_H

#include <lustre/lustre_idl.h>
#include <lustre_req_layout.h>
#include <md_object.h>
#include <dt_object.h>
#include <libcfs/libcfs.h>

/*
 * Common thread info for mdt, seq and fld
 */
struct com_thread_info {
        /*
         * for req-layout interface.
         */
        struct req_capsule *cti_pill;
};

enum {
        ESERIOUS = 0x0001000
};

static inline int err_serious(int rc)
{
        LASSERT(rc < 0);
        LASSERT(-rc < ESERIOUS);
        return -(-rc | ESERIOUS);
}

static inline int clear_serious(int rc)
{
        if (rc < 0)
                rc = -(-rc & ~ESERIOUS);
        return rc;
}

static inline int is_serious(int rc)
{
        return (rc < 0 && -rc & ESERIOUS);
}


#endif
