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
extern int llapi_file_create(char *name, long stripe_size, int stripe_offset,
                             int stripe_count, int stripe_pattern);
extern int llapi_file_get_stripe(char *path, struct lov_user_md *lum);
extern int llapi_find(char *path, struct obd_uuid *obduuid, int recursive,
                      int verbose, int quiet, int showfid);
extern int llapi_target_check(int num_types, char **obd_types, char *dir);
extern int llapi_catinfo(char *dir, char *keyword, char *node_name);
extern int llapi_lov_get_uuids(int fd, struct obd_uuid *uuidp, int *ost_count);
extern int llapi_is_lustre_mnttype(char *type);

#endif
