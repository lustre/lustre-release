/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Brian Behlendorf <behlendorf1@llnl.gov> 
 *   Author: Robert Read <rread@clusterfs.com> 
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
#ifndef _LIBLUSTREAPI_H_
#define _LIBLUSTREAPI_H_

#include <lustre/lustre_user.h>

/* liblustreapi.c */
extern int op_create_file(char *name, long stripe_size, int stripe_offset,
                          int stripe_count);
extern int op_find(char *path, struct obd_uuid *obduuid, int recursive,
                   int verbose, int quiet);
extern int op_check(int type_num, char **obd_type_p, char *dir);
extern int op_catinfo(char *dir, char *keyword, char *node_name);
extern int get_file_stripe(char *path, struct lov_user_md *lum);
extern int llapi_is_lustre_mnttype(char *type);

#endif
