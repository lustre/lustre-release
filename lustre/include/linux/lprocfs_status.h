/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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
 *   Top level header file for LProc SNMP
 *   Author: Hariharan Thantry thantry@users.sourceforge.net
 */
#ifndef _LPROCFS_SNMP_H
#define _LPROCFS_SNMP_H

#ifdef __KERNEL__
#include <linux/autoconf.h>
#include <linux/proc_fs.h>
#endif

#ifndef LPROCFS
#ifdef  CONFIG_PROC_FS  /* Ensure that /proc is configured */
#define LPROCFS
#endif
#endif

struct lprocfs_vars {
        char *name;
        read_proc_t *read_fptr;
        write_proc_t *write_fptr;
        void *data;
};

struct lprocfs_static_vars {
        struct lprocfs_vars *module_vars;
        struct lprocfs_vars *obd_vars;
};

/* class_obd.c */
extern struct proc_dir_entry *proc_lustre_root;


#ifdef LPROCFS
#define LPROCFS_INIT_MULTI_VARS(array, size)                              \
void lprocfs_init_multi_vars(unsigned int idx,                            \
                             struct lprocfs_static_vars *x)               \
{                                                                         \
   struct lprocfs_static_vars *glob = (struct lprocfs_static_vars*)array; \
   LASSERT(glob != 0);                                                    \
   LASSERT(idx < (unsigned int)(size));                                   \
   x->module_vars = glob[idx].module_vars;                                \
   x->obd_vars = glob[idx].obd_vars;                                      \
}                                                                         \

#define LPROCFS_INIT_VARS(vclass, vinstance)           \
void lprocfs_init_vars(struct lprocfs_static_vars *x)  \
{                                                      \
        x->module_vars = vclass;                       \
        x->obd_vars = vinstance;                       \
}                                                      \

extern void lprocfs_init_vars(struct lprocfs_static_vars *var);
extern void lprocfs_init_multi_vars(unsigned int idx, 
                                    struct lprocfs_static_vars *var);
/* lprocfs_status.c */
extern int lprocfs_add_vars(struct proc_dir_entry *root,
                            struct lprocfs_vars *var,
                            void *data);

extern struct proc_dir_entry *lprocfs_register(const char *name,
                                               struct proc_dir_entry *parent,
                                               struct lprocfs_vars *list,
                                               void *data);

extern void lprocfs_remove(struct proc_dir_entry *root);

struct obd_device;
extern int lprocfs_obd_attach(struct obd_device *dev, struct lprocfs_vars *list);
extern int lprocfs_obd_detach(struct obd_device *dev);

/* Generic callbacks */

extern int lprocfs_rd_u64(char *page, char **start, off_t off,
                          int count, int *eof, void *data);
extern int lprocfs_rd_uuid(char *page, char **start, off_t off,
                           int count, int *eof, void *data);
extern int lprocfs_rd_name(char *page, char **start, off_t off,
                           int count, int *eof, void *data);
extern int lprocfs_rd_server_uuid(char *page, char **start, off_t off,
                                  int count, int *eof, void *data);
extern int lprocfs_rd_conn_uuid(char *page, char **start, off_t off,
                                int count, int *eof, void *data);
extern int lprocfs_rd_numrefs(char *page, char **start, off_t off,
                              int count, int *eof, void *data);

/* Statfs helpers */
struct statfs;
extern int lprocfs_rd_blksize(char *page, char **start, off_t off,
                              int count, int *eof, struct statfs *sfs);
extern int lprocfs_rd_kbytestotal(char *page, char **start, off_t off,
                                  int count, int *eof, struct statfs *sfs);
extern int lprocfs_rd_kbytesfree(char *page, char **start, off_t off,
                                 int count, int *eof, struct statfs *sfs);
extern int lprocfs_rd_filestotal(char *page, char **start, off_t off,
                                 int count, int *eof, struct statfs *sfs);
extern int lprocfs_rd_filesfree(char *page, char **start, off_t off,
                                int count, int *eof, struct statfs *sfs);
extern int lprocfs_rd_filegroups(char *page, char **start, off_t off,
                                 int count, int *eof, struct statfs *sfs);

#define DEFINE_LPROCFS_STATFS_FCT(fct_name, get_statfs_fct)      \
int fct_name(char *page, char **start, off_t off,                \
             int count, int *eof, void *data)                    \
{                                                                \
        struct statfs sfs;                                       \
        int rc = get_statfs_fct((struct obd_device*)data, &sfs); \
        return (rc==0                                            \
                ? lprocfs_##fct_name (page, start, off, count, eof, &sfs) \
                : rc);                                       \
}

#else

static inline struct proc_dir_entry *
lprocfs_register(const char *name, struct proc_dir_entry *parent,
                 struct lprocfs_vars *list, void *data) { return NULL; }
#define LPROCFS_INIT_MULTI_VARS(array, size)
static inline void lprocfs_init_multi_vars(unsigned int idx,
                                           struct lprocfs_static_vars *x) { return; }
#define LPROCFS_INIT_VARS(vclass, vinstance)
static inline void lprocfs_init_vars(struct lprocfs_static_vars *x) { return; }
static inline int lprocfs_add_vars(struct proc_dir_entry *root,
                                   struct lprocfs_vars *var,
                                   void *data) { return 0; }
static inline void lprocfs_remove(struct proc_dir_entry *root) {};
struct obd_device;
static inline int lprocfs_obd_attach(struct obd_device *dev,
                                     struct lprocfs_vars *list) { return 0; }
static inline int lprocfs_obd_detach(struct obd_device *dev)  { return 0; }
static inline int lprocfs_rd_u64(char *page, char **start, off_t off,
                                 int count, int *eof, void *data) { return 0; }
static inline int lprocfs_rd_uuid(char *page, char **start, off_t off,
                                  int count, int *eof, void *data) { return 0; }
static inline int lprocfs_rd_name(char *page, char **start, off_t off,
                                  int count, int *eof, void *data) { return 0; }
static inline int lprocfs_rd_server_uuid(char *page, char **start, off_t off,
                                         int count, int *eof, void *data) { return 0; }
static inline int lprocfs_rd_conn_uuid(char *page, char **start, off_t off,
                                       int count, int *eof, void *data) { return 0; }
static inline int lprocfs_rd_numrefs(char *page, char **start, off_t off,
                                     int count, int *eof, void *data) { return 0; }

/* Statfs helpers */
struct statfs;
static inline
int lprocfs_rd_blksize(char *page, char **start, off_t off,
                       int count, int *eof, struct statfs *sfs) { return 0; }
static inline
int lprocfs_rd_kbytestotal(char *page, char **start, off_t off,
                           int count, int *eof, struct statfs *sfs) { return 0; }
static inline
int lprocfs_rd_kbytesfree(char *page, char **start, off_t off,
                          int count, int *eof, struct statfs *sfs) { return 0; }
static inline
int lprocfs_rd_filestotal(char *page, char **start, off_t off,
                          int count, int *eof, struct statfs *sfs) { return 0; }
static inline
int lprocfs_rd_filesfree(char *page, char **start, off_t off,
                         int count, int *eof, struct statfs *sfs)  { return 0; }
static inline
int lprocfs_rd_filegroups(char *page, char **start, off_t off,
                          int count, int *eof, struct statfs *sfs) { return 0; }

#define DEFINE_LPROCFS_STATFS_FCT(fct_name, get_statfs_fct)  \
int fct_name(char *page, char **start, off_t off,            \
             int count, int *eof, void *data) { *eof = 1; return 0; }

#endif /* LPROCFS */

#endif /* LPROCFS_SNMP_H */
