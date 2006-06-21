/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 */
#ifndef _LIBLUSTREAPI_H_
#define _LIBLUSTREAPI_H_

#include <lustre/lustre_user.h>

typedef void (*llapi_cb_t)(char *obd_type_name, char *obd_name, char *obd_uuid, void *args);

/* liblustreapi.c */
extern int llapi_file_create(const char *name, long stripe_size,
                             int stripe_offset, int stripe_count,
                             int stripe_pattern);
extern int llapi_file_get_stripe(char *path, struct lov_user_md *lum);
#define HAVE_LLAPI_FILE_LOOKUP
extern int llapi_file_lookup(int dirfd, const char *name);
 
struct find_param {
        unsigned int maxdepth;
        time_t atime;
        time_t mtime;
        time_t ctime;
        int asign;
        int csign;
        int msign;
        int zeroend;

        int     recursive;
        int     verbose;
        int     quiet;

        struct  obd_uuid        *obduuid;
        int     obdindex;

        int     lumlen;
        struct  lov_user_mds_data *lmd;

        /* In-precess parameters. */
        unsigned int depth;
        int     got_uuids;
        dev_t   st_dev;
};

extern int llapi_getstripe(char *path, struct find_param *param);
extern int llapi_find(char *path, struct find_param *param);

extern int llapi_obd_statfs(char *path, __u32 type, __u32 index,
                     struct obd_statfs *stat_buf,
                     struct obd_uuid *uuid_buf);
extern int llapi_ping(char *obd_type, char *obd_name);
extern int llapi_target_check(int num_types, char **obd_types, char *dir);
extern int llapi_catinfo(char *dir, char *keyword, char *node_name);
extern int llapi_lov_get_uuids(int fd, struct obd_uuid *uuidp, int *ost_count);
extern int llapi_is_lustre_mnttype(struct mntent *mnt);
extern int llapi_quotachown(char *path, int flag);
extern int llapi_quotacheck(char *mnt, int check_type);
extern int llapi_poll_quotacheck(char *mnt, struct if_quotacheck *qchk);
extern int llapi_quotactl(char *mnt, struct if_quotactl *qctl);
extern int llapi_target_iterate(int type_num, char **obd_type, void *args, llapi_cb_t cb);
#endif
