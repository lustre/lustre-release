/* -*- MODE: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  fld/fld.c 
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */
#ifndef _MDD_INTERNAL_H
#define _MDD_INTERNAL_H

struct fld_cache {
        struct hlist_node fld_hash;
        __u64             fld_mds;
        __u64             fld_seq;
}
struct fld_cache_info {
        struct hlist_head *fld_list;
        spinlock_t fld_lock;
        int fld_hash_mask;
}
#define FLD_CREATE 0
#define FLD_DELETE 1
#define FLD_GET 3
#endif
