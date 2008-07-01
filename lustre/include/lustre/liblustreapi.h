/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 */
#ifndef _LIBLUSTREAPI_H_
#define _LIBLUSTREAPI_H_

#include <lustre/lustre_user.h>

/* Initially allocate for these many OSTs, realloc if needed */
#define INIT_ALLOC_NUM_OSTS     1024

/* Maximum number of osts that can be specified to lfs find */
#define FIND_MAX_OSTS   1024

typedef void (*llapi_cb_t)(char *obd_type_name, char *obd_name, char *obd_uuid, void *args);

/* liblustreapi message severity level */
enum llapi_message_level {
        LLAPI_MSG_OFF    = 0,
        LLAPI_MSG_FATAL  = 1,
        LLAPI_MSG_ERROR  = 2,
        LLAPI_MSG_WARN   = 3,
        LLAPI_MSG_NORMAL = 4,
        LLAPI_MSG_INFO   = 5,
        LLAPI_MSG_DEBUG  = 6,
        LLAPI_MSG_MAX
};

/* the bottom three bits reserved for llapi_message_level */
#define LLAPI_MSG_MASK          0x00000007
#define LLAPI_MSG_NO_ERRNO      0x00000010 

/* liblustreapi.c */
extern void llapi_msg_set_level(int level);
extern void llapi_err(int level, char *fmt, ...);
extern void llapi_printf(int level, char *fmt, ...);
extern int llapi_file_create(const char *name, unsigned long stripe_size,
                             int stripe_offset, int stripe_count,
                             int stripe_pattern);
extern int llapi_file_open(const char *name, int flags, int mode,
                           unsigned long stripe_size, int stripe_offset,
                           int stripe_count, int stripe_pattern);
extern int llapi_file_get_stripe(const char *path, struct lov_user_md *lum);
#define HAVE_LLAPI_FILE_LOOKUP
extern int llapi_file_lookup(int dirfd, const char *name);
 
struct find_param {
        unsigned int maxdepth;
        time_t  atime;
        time_t  mtime;
        time_t  ctime;
        int     asign;
        int     csign;
        int     msign;
        int     type;
        unsigned long long size;
        int     size_sign;
        unsigned long long size_units;

        unsigned long   zeroend:1,
                        recursive:1,
                        got_uuids:1,
                        obds_printed:1,
                        exclude_pattern:1,
                        exclude_type:1,
                        have_fileinfo:1;

        int     verbose;
        int     quiet;

        /* regular expression */
        char   *pattern;

        char   *print_fmt;

        struct  obd_uuid        *obduuid;
        int                     num_obds;
        int                     num_alloc_obds;
        int                     obdindex;
        int                     *obdindexes;

        int     lumlen;
        struct  lov_user_mds_data *lmd;

        /* In-precess parameters. */
        unsigned int depth;
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
extern int llapi_file_get_lov_uuid(const char *path, struct obd_uuid *lov_uuid);
extern int llapi_file_get_lov_fuuid(int fd, struct obd_uuid *lov_uuid);
extern int llapi_lov_get_uuids(int fd, struct obd_uuid *uuidp, int *ost_count);
extern int llapi_is_lustre_mnttype(const char *type);
extern int parse_size(char *optarg, unsigned long long *size,
                      unsigned long long *size_units);
struct mntent;
#define HAVE_LLAPI_IS_LUSTRE_MNT
extern int llapi_is_lustre_mnt(struct mntent *mnt);
extern int llapi_quotachown(char *path, int flag);
extern int llapi_quotacheck(char *mnt, int check_type);
extern int llapi_poll_quotacheck(char *mnt, struct if_quotacheck *qchk);
extern int llapi_quotactl(char *mnt, struct if_quotactl *qctl);
extern int llapi_target_iterate(int type_num, char **obd_type, void *args, llapi_cb_t cb);
extern int llapi_lsetfacl(int argc, char *argv[]);
extern int llapi_lgetfacl(int argc, char *argv[]);
extern int llapi_rsetfacl(int argc, char *argv[]);
extern int llapi_rgetfacl(int argc, char *argv[]);
extern int llapi_cp(int argc, char *argv[]);
extern int llapi_ls(int argc, char *argv[]);
#endif
