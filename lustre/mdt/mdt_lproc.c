/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004-2006 Cluster File Systems, Inc.
 *   Author: Lai Siyao <lsy@clusterfs.com>
 *   Author: Fan Yong <fanyong@clusterfs.com>
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
 *
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <asm/statfs.h>
#endif

#include <linux/module.h>

/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>
/*
 * struct OBD_{ALLOC,FREE}*()
 * MDT_FAIL_CHECK
 */
#include <obd_support.h>
/* struct obd_export */
#include <lustre_export.h>
/* struct obd_device */
#include <obd.h>
#include <obd_class.h>
#include <lustre_mds.h>
#include <lustre_mdt.h>
#include <lprocfs_status.h>
#include "mdt_internal.h"


static int lprocfs_rd_identity_expire(char *page, char **start, off_t off,
                                      int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        *eof = 1;
        return snprintf(page, count, "%lu\n",
                        mdt->mdt_identity_cache->uc_entry_expire / HZ);
}

static int lprocfs_wr_identity_expire(struct file *file, const char *buffer,
                                      unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int rc, val;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        mdt->mdt_identity_cache->uc_entry_expire = val * HZ;
        return count;
}

static int lprocfs_rd_identity_acquire_expire(char *page, char **start,
                                              off_t off, int count, int *eof,
                                              void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        *eof = 1;
        return snprintf(page, count, "%lu\n",
                        mdt->mdt_identity_cache->uc_acquire_expire / HZ);
}

static int lprocfs_wr_identity_acquire_expire(struct file *file,
                                              const char *buffer,
                                              unsigned long count,
                                              void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int rc, val;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        mdt->mdt_identity_cache->uc_acquire_expire = val * HZ;
        return count;
}

static int lprocfs_rd_identity_upcall(char *page, char **start, off_t off,
                                      int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        *eof = 1;
        return snprintf(page, count, "%s\n",
                        mdt->mdt_identity_cache->uc_upcall);
}

static int lprocfs_wr_identity_upcall(struct file *file, const char *buffer,
                                      unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        struct upcall_cache *hash = mdt->mdt_identity_cache;
        char kernbuf[UC_CACHE_UPCALL_MAXPATH] = { '\0' };

        if (count >= UC_CACHE_UPCALL_MAXPATH) {
                CERROR("%s: identity upcall too long\n", obd->obd_name);
                return -EINVAL;
        }

        if (copy_from_user(kernbuf, buffer,
                           min(count, UC_CACHE_UPCALL_MAXPATH - 1)))
                return -EFAULT;

        /* Remove any extraneous bits from the upcall (e.g. linefeeds) */
        sscanf(kernbuf, "%s", hash->uc_upcall);

        if (strcmp(hash->uc_name, obd->obd_name) != 0)
                CWARN("%s: write to upcall name %s\n",
                      obd->obd_name, hash->uc_upcall);
        CWARN("%s: identity upcall set to %s\n", obd->obd_name, hash->uc_upcall);

        return count;
}

static int lprocfs_wr_identity_flush(struct file *file, const char *buffer,
                                     unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        upcall_cache_flush_idle(mdt->mdt_identity_cache);
        return count;
}

static int lprocfs_wr_identity_info(struct file *file, const char *buffer,
                                    unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        struct identity_downcall_data *tmp, *param = NULL;
        int size = sizeof(*param), rc = 0;

        if (count < sizeof(*tmp)) {
                CERROR("%s: invalid data size %lu\n", obd->obd_name, count);
                return count;
        }

        OBD_ALLOC_PTR(tmp);
        if (!tmp) {
                CERROR("%s: fail to alloc %d bytes\n", obd->obd_name, size);
                return -ENOMEM;
        }

        if (copy_from_user(tmp, buffer, size)) {
                CERROR("%s: bad identity data\n", obd->obd_name);
                GOTO(out, rc = -EFAULT);
        }

        if (tmp->idd_magic != IDENTITY_DOWNCALL_MAGIC) {
                CERROR("%s: MDS identity downcall bad params\n", obd->obd_name);
                GOTO(out, rc = -EINVAL);
        }

        if (tmp->idd_ngroups > NGROUPS_MAX) {
                CERROR("%s: group count %d more than maximum %d\n",
                       obd->obd_name, tmp->idd_ngroups, NGROUPS_MAX);
                GOTO(out, rc = -EINVAL);
        }

        if (tmp->idd_ngroups) {
                size = offsetof(struct identity_downcall_data,
                                idd_groups[tmp->idd_ngroups]);
                OBD_ALLOC(param, size);
                if (!param) {
                        CERROR("%s: fail to alloc %d bytes for uid %u"
                               " with %d groups\n", obd->obd_name, size,
                               tmp->idd_uid, tmp->idd_ngroups);
                        param = tmp;
                        param->idd_ngroups = 0;
                } else if (copy_from_user(param, buffer, size)) {
                        CERROR("%s: uid %u bad supplementary group data\n",
                               obd->obd_name, tmp->idd_uid);
                        OBD_FREE(param, size);
                        param = tmp;
                        param->idd_ngroups = 0;
                }
        } else {
                param = tmp;
        }

        LASSERT(param->idd_ngroups <= NGROUPS_MAX);
        LASSERT(param->idd_nperms <= N_SETXID_PERMS_MAX);

        rc = upcall_cache_downcall(mdt->mdt_identity_cache, param->idd_err,
                                   param->idd_uid, param);

out:
        if (param && (param != tmp))
                OBD_FREE(param, size);

        OBD_FREE_PTR(tmp);
        return rc ?: count;
}

static int lprocfs_rd_rmtacl_expire(char *page, char **start, off_t off,
                                    int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        *eof = 1;
        return snprintf(page, count, "%lu\n",
                        mdt->mdt_rmtacl_cache->uc_entry_expire / HZ);
}

static int lprocfs_wr_rmtacl_expire(struct file *file, const char *buffer,
                                    unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int rc, val;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        mdt->mdt_rmtacl_cache->uc_entry_expire = val * HZ;
        return count;
}

static int lprocfs_rd_rmtacl_acquire_expire(char *page, char **start,
                                            off_t off, int count, int *eof,
                                            void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        *eof = 1;
        return snprintf(page, count, "%lu\n",
                        mdt->mdt_rmtacl_cache->uc_acquire_expire / HZ);
}

static int lprocfs_wr_rmtacl_acquire_expire(struct file *file,
                                            const char *buffer,
                                            unsigned long count,
                                            void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int rc, val;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        mdt->mdt_rmtacl_cache->uc_acquire_expire = val * HZ;
        return count;
}

static int lprocfs_rd_rmtacl_upcall(char *page, char **start, off_t off,
                                      int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        *eof = 1;
        return snprintf(page, count, "%s\n",
                        mdt->mdt_rmtacl_cache->uc_upcall);
}

static int lprocfs_wr_rmtacl_upcall(struct file *file, const char *buffer,
                                      unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        struct upcall_cache *hash = mdt->mdt_rmtacl_cache;
        char kernbuf[UC_CACHE_UPCALL_MAXPATH] = { '\0' };

        if (count >= UC_CACHE_UPCALL_MAXPATH) {
                CERROR("%s: remote ACL upcall too long\n", obd->obd_name);
                return -EINVAL;
        }

        if (copy_from_user(kernbuf, buffer,
                           min(count, UC_CACHE_UPCALL_MAXPATH - 1)))
                return -EFAULT;

        /* Remove any extraneous bits from the upcall (e.g. linefeeds) */
        sscanf(kernbuf, "%s", hash->uc_upcall);

        if (strcmp(hash->uc_name, obd->obd_name) != 0)
                CWARN("%s: write to upcall name %s\n",
                      obd->obd_name, hash->uc_upcall);
        CWARN("%s: remote ACL upcall set to %s\n", obd->obd_name, hash->uc_upcall);

        return count;
}

static int lprocfs_wr_rmtacl_info(struct file *file, const char *buffer,
                                  unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        struct rmtacl_downcall_data sparam, *param = &sparam;
        int size = 0, rc = 0;

        if (count < sizeof(*param)) {
                CERROR("%s: invalid data size %lu\n", obd->obd_name, count);
                return count;
        }

        if (copy_from_user(&sparam, buffer, sizeof(sparam))) {
                CERROR("%s: bad remote acl data\n", obd->obd_name);
                GOTO(out, rc = -EFAULT);
        }

        if (sparam.add_magic != RMTACL_DOWNCALL_MAGIC) {
                CERROR("%s: MDT remote acl downcall bad params\n", obd->obd_name);
                GOTO(out, rc = -EINVAL);
        }

        if (sparam.add_buflen) {
                size = offsetof(struct rmtacl_downcall_data,
                                add_buf[sparam.add_buflen]);
                OBD_ALLOC(param, size);
                if (!param) {
                        CERROR("%s: fail to alloc %d bytes for ino "LPU64"\n",
                               obd->obd_name, size, sparam.add_ino);
                        param = &sparam;
                        param->add_buflen = 0;
                } else if (copy_from_user(param, buffer, size)) {
                        CERROR("%s: ino "LPU64" bad remote acl data\n",
                               obd->obd_name, sparam.add_ino);
                        OBD_FREE(param, size);
                        param = &sparam;
                        param->add_buflen = 0;
                }
        }

        rc = upcall_cache_downcall(mdt->mdt_rmtacl_cache, 0, param->add_ino,
                                   param);

out:
        if (param && (param != &sparam))
                OBD_FREE(param, size);

        return rc ?: count;
}

static int lprocfs_rd_rootsquash_uid(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        struct rootsquash_info *rsi = mdt->mdt_rootsquash_info;

        *eof = 1;
        return snprintf(page, count, "%u\n",
                        rsi ? rsi->rsi_uid : 0);
}

static int lprocfs_wr_rootsquash_uid(struct file *file, const char *buffer,
                                     unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int val, rc;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (!mdt->mdt_rootsquash_info)
                OBD_ALLOC_PTR(mdt->mdt_rootsquash_info);
        if (!mdt->mdt_rootsquash_info)
                RETURN(-ENOMEM);

        mdt->mdt_rootsquash_info->rsi_uid = val;
        return count;
}

static int lprocfs_rd_rootsquash_gid(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        struct rootsquash_info *rsi = mdt->mdt_rootsquash_info;

        *eof = 1;
        return snprintf(page, count, "%u\n",
                        rsi ? rsi->rsi_gid : 0);
}

static int lprocfs_wr_rootsquash_gid(struct file *file, const char *buffer,
                                     unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int val, rc;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (!mdt->mdt_rootsquash_info)
                OBD_ALLOC_PTR(mdt->mdt_rootsquash_info);
        if (!mdt->mdt_rootsquash_info)
                RETURN(-ENOMEM);

        mdt->mdt_rootsquash_info->rsi_gid = val;
        return count;
}

static int lprocfs_rd_rootsquash_skips(char *page, char **start, off_t off,
                                       int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        struct rootsquash_info *rsi = mdt->mdt_rootsquash_info;
        int i, ret;

        ret = snprintf(page, count, "rootsquash skip list:\n");
        for (i = 0; rsi && (i < rsi->rsi_n_nosquash_nids); i++) {
                ret += snprintf(page + ret, count - ret, "%s\n",
                                libcfs_nid2str(rsi->rsi_nosquash_nids[i]));
        }

        *eof = 1;
        return ret;
}

/* FIXME: this macro is copied from lnet/libcfs/nidstring.c */
#define LNET_NIDSTR_SIZE   32      /* size of each one (see below for usage) */
static void do_process_nosquash_nids(struct mdt_device *m, char *buf)
{
        struct rootsquash_info *rsi = m->mdt_rootsquash_info;
        char str[LNET_NIDSTR_SIZE], *end;
        lnet_nid_t nid;

        LASSERT(rsi);
        rsi->rsi_n_nosquash_nids = 0;
        while (rsi->rsi_n_nosquash_nids < N_NOSQUASH_NIDS) {
                end = strchr(buf, ',');
                memset(str, 0, sizeof(str));
                if (end)
                        strncpy(str, buf, min_t(int, sizeof(str), end - buf));
                else
                        strncpy(str, buf, min_t(int, sizeof(str), strlen(buf)));

                if (!strcmp(str, "*")) {
                        nid = LNET_NID_ANY;
                } else {
                        nid = libcfs_str2nid(str);
                        if (nid == LNET_NID_ANY)
                                goto ignore;
                }
                rsi->rsi_nosquash_nids[rsi->rsi_n_nosquash_nids++] = nid;
ignore:
                if (!end || (*(end + 1) == 0))
                        return;
                buf = end + 1;
        }
}

static int lprocfs_wr_rootsquash_skips(struct file *file, const char *buffer,
                                       unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        char skips[LNET_NIDSTR_SIZE * N_NOSQUASH_NIDS] = "";
        unsigned long size = sizeof(skips);

        if (count > size) {
                CERROR("parameter exceeds max limit %lu\n", size);
                return -EINVAL;
        }

        if (copy_from_user(skips, buffer, min(size, count)))
                return -EFAULT;

        if (!mdt->mdt_rootsquash_info)
                OBD_ALLOC_PTR(mdt->mdt_rootsquash_info);
        if (!mdt->mdt_rootsquash_info)
                RETURN(-ENOMEM);

        do_process_nosquash_nids(mdt, skips);
        return count;
}

/* for debug only */
static int lprocfs_rd_capa(char *page, char **start, off_t off,
                           int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        return snprintf(page, count, "capability on: %s %s\n",
                        mdt->mdt_opts.mo_oss_capa ? "oss" : "",
                        mdt->mdt_opts.mo_mds_capa ? "mds" : "");
}

static int lprocfs_wr_capa(struct file *file, const char *buffer,
                           unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        char mode[3] = "";

        if (count > 3) {
                CERROR("invalid capability mode, only m/o/mo/x is accepted.\n"
                       " m:  enable MDS fid capability\n"
                       " o:  enable OSS fid capability\n"
                       " mo: enable both MDS and OSS fid capability\n"
                       " x:  disable fid capability\n");
                return -EINVAL;
        }

        if (copy_from_user(mode, buffer, min(2UL, count)))
                return -EFAULT;

        mdt->mdt_opts.mo_mds_capa = 0;
        mdt->mdt_opts.mo_oss_capa = 0;
        if (strchr(mode, 'm'))
                mdt->mdt_opts.mo_mds_capa = 1;
        if (strchr(mode, 'o'))
                mdt->mdt_opts.mo_oss_capa = 1;
        mdt->mdt_capa_conf = 1;
        return count;
}

static int lprocfs_rd_capa_count(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        return snprintf(page, count, "%d %d\n",
                        capa_count[CAPA_SITE_CLIENT],
                        capa_count[CAPA_SITE_SERVER]);
}

static int lprocfs_rd_capa_timeout(char *page, char **start, off_t off,
                                   int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        return snprintf(page, count, "%lu\n", mdt->mdt_capa_timeout);
}

static int lprocfs_wr_capa_timeout(struct file *file, const char *buffer,
                                   unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int val, rc;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        mdt->mdt_capa_timeout = (unsigned long)val;
        mdt->mdt_capa_conf = 1;
        return count;
}

static int lprocfs_rd_ck_timeout(char *page, char **start, off_t off, int count,
                                 int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        return snprintf(page, count, "%lu\n", mdt->mdt_ck_timeout);
}

static int lprocfs_wr_ck_timeout(struct file *file, const char *buffer,
                                 unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int val, rc;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        mdt->mdt_ck_timeout = (unsigned long)val;
        mdt->mdt_capa_conf = 1;
        return count;
}

static struct lprocfs_vars lprocfs_mdt_obd_vars[] = {
        { "uuid",                       lprocfs_rd_uuid,                 0, 0 },
        { "recovery_status",            lprocfs_obd_rd_recovery_status,  0, 0 },
        { "num_exports",                lprocfs_rd_num_exports,          0, 0 },
        { "identity_expire",            lprocfs_rd_identity_expire,
                                        lprocfs_wr_identity_expire,         0 },
        { "identity_acquire_expire",    lprocfs_rd_identity_acquire_expire,
                                        lprocfs_wr_identity_acquire_expire, 0 },
        { "identity_upcall",            lprocfs_rd_identity_upcall,
                                        lprocfs_wr_identity_upcall,         0 },
        { "identity_flush",             0, lprocfs_wr_identity_flush,       0 },
        { "identity_info",              0, lprocfs_wr_identity_info,        0 },
        { "rmtacl_expire",              lprocfs_rd_rmtacl_expire,
                                        lprocfs_wr_rmtacl_expire,           0 },
        { "rmtacl_acquire_expire",      lprocfs_rd_rmtacl_acquire_expire,
                                        lprocfs_wr_rmtacl_acquire_expire,   0 },
        { "rmtacl_upcall",              lprocfs_rd_rmtacl_upcall,
                                        lprocfs_wr_rmtacl_upcall,           0 },
        { "rmtacl_info",                0, lprocfs_wr_rmtacl_info,          0 },
        { "rootsquash_uid",             lprocfs_rd_rootsquash_uid,
                                        lprocfs_wr_rootsquash_uid,          0 },
        { "rootsquash_gid",             lprocfs_rd_rootsquash_gid,
                                        lprocfs_wr_rootsquash_gid,          0 },
        { "rootsquash_skips",           lprocfs_rd_rootsquash_skips,
                                        lprocfs_wr_rootsquash_skips,        0 },
        { "capa",                       lprocfs_rd_capa,
                                        lprocfs_wr_capa,                    0 },
        { "capa_timeout",               lprocfs_rd_capa_timeout,
                                        lprocfs_wr_capa_timeout,            0 },
        { "capa_key_timeout",           lprocfs_rd_ck_timeout,
                                        lprocfs_wr_ck_timeout,              0 },
        { "capa_count",                 lprocfs_rd_capa_count,           0, 0 },
        { 0 }
};

static struct lprocfs_vars lprocfs_mdt_module_vars[] = {
        { "num_refs",                   lprocfs_rd_numrefs,              0, 0 },
        { 0 }
};

LPROCFS_INIT_VARS(mdt, lprocfs_mdt_module_vars, lprocfs_mdt_obd_vars);
