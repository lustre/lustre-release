/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * lib/lib-dispatch.c
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *  Copyright (c) 2001-2002 Sandia National Laboratories
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
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
 */

#define DEBUG_SUBSYSTEM S_PORTALS
#include <portals/lib-p30.h>
#include <portals/lib-dispatch.h>

typedef struct {
        int (*fun) (nal_cb_t * nal, void *private, void *in, void *out);
        char *name;
} dispatch_table_t;

static dispatch_table_t dispatch_table[] = {
        [PTL_GETID] {do_PtlGetId, "PtlGetId"},
        [PTL_NISTATUS] {do_PtlNIStatus, "PtlNIStatus"},
        [PTL_NIDIST] {do_PtlNIDist, "PtlNIDist"},
        [PTL_NIDEBUG] {do_PtlNIDebug, "PtlNIDebug"},
        [PTL_MEATTACH] {do_PtlMEAttach, "PtlMEAttach"},
        [PTL_MEINSERT] {do_PtlMEInsert, "PtlMEInsert"},
        [PTL_MEUNLINK] {do_PtlMEUnlink, "PtlMEUnlink"},
        [PTL_TBLDUMP] {do_PtlTblDump, "PtlTblDump"},
        [PTL_MEDUMP] {do_PtlMEDump, "PtlMEDump"},
        [PTL_MDATTACH] {do_PtlMDAttach, "PtlMDAttach"},
        [PTL_MDBIND] {do_PtlMDBind, "PtlMDBind"},
        [PTL_MDUPDATE] {do_PtlMDUpdate_internal, "PtlMDUpdate_internal"},
        [PTL_MDUNLINK] {do_PtlMDUnlink, "PtlMDUnlink"},
        [PTL_EQALLOC] {do_PtlEQAlloc_internal, "PtlEQAlloc_internal"},
        [PTL_EQFREE] {do_PtlEQFree_internal, "PtlEQFree_internal"},
        [PTL_PUT] {do_PtlPut, "PtlPut"},
        [PTL_GET] {do_PtlGet, "PtlGet"},
        [PTL_FAILNID] {do_PtlFailNid, "PtlFailNid"},
        /*    */ {0, ""}
};

/*
 * This really should be elsewhere, but lib-p30/dispatch.c is
 * an automatically generated file.
 */
void lib_dispatch(nal_cb_t * nal, void *private, int index, void *arg_block,
                  void *ret_block)
{
        lib_ni_t *ni = &nal->ni;

        if (index < 0 || index > LIB_MAX_DISPATCH ||
            !dispatch_table[index].fun) {
                CDEBUG(D_NET, LPU64": Invalid API call %d\n", ni->nid, index);
                return;
        }

        CDEBUG(D_NET, LPU64": API call %s (%d)\n", ni->nid,
               dispatch_table[index].name, index);

        dispatch_table[index].fun(nal, private, arg_block, ret_block);
}

char *dispatch_name(int index)
{
        return dispatch_table[index].name;
}
