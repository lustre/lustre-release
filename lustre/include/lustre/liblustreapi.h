/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 */
#ifndef _LIBLUSTREAPI_H_
#define _LIBLUSTREAPI_H_

#include <lustre/lustre_user.h>

/* liblustreapi.c */
extern int llapi_file_create(char *name, long stripe_size, int stripe_offset,
                             int stripe_count, int stripe_pattern);
extern int llapi_file_get_stripe(char *path, struct lov_user_md *lum);
extern int llapi_find(char *path, struct obd_uuid *obduuid, int recursive,
                      int verbose, int quiet);
extern int llapi_ping(char *obd_type, char *obd_name);
extern int llapi_target_check(int num_types, char **obd_types, char *dir);
extern int llapi_catinfo(char *dir, char *keyword, char *node_name);
extern int llapi_lov_get_uuids(int fd, struct obd_uuid *uuidp, int *ost_count);
extern int llapi_is_lustre_mnttype(char *type);
extern int llapi_quotacheck(char *mnt, int check_type);
extern int llapi_poll_quotacheck(char *mnt, struct if_quotacheck *qchk);
extern int llapi_quotactl(char *mnt, struct if_quotactl *qctl);
extern int llapi_quotachog(char *path, int flag);
#endif
