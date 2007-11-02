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
#include <asm/statfs.h>

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
#include <lu_time.h>
#include "mdt_internal.h"

static const char *mdt_proc_names[LPROC_MDT_NR] = {
};

int mdt_procfs_init(struct mdt_device *mdt, const char *name)
{
        struct lu_device *ld = &mdt->mdt_md_dev.md_lu_dev;
        int result;
        ENTRY;

        LASSERT(name != NULL);
        mdt->mdt_proc_entry = ld->ld_obd->obd_proc_entry;
        LASSERT(mdt->mdt_proc_entry != NULL);

        result = lu_time_init(&mdt->mdt_stats, mdt->mdt_proc_entry,
                              mdt_proc_names, ARRAY_SIZE(mdt_proc_names));
        if (result == 0)
                result = lu_time_named_init(&ld->ld_site->ls_time_stats,
                                            "site_time", mdt->mdt_proc_entry,
                                            lu_time_names,
                                            ARRAY_SIZE(lu_time_names));
        RETURN(result);
}

int mdt_procfs_fini(struct mdt_device *mdt)
{
        struct lu_device *ld = &mdt->mdt_md_dev.md_lu_dev;
        lu_time_fini(&ld->ld_site->ls_time_stats);
        lu_time_fini(&mdt->mdt_stats);
        mdt->mdt_proc_entry = NULL;
        RETURN(0);
}

void mdt_time_start(const struct mdt_thread_info *info)
{
        lu_lprocfs_time_start(info->mti_env);
}

void mdt_time_end(const struct mdt_thread_info *info, int idx)
{
        lu_lprocfs_time_end(info->mti_env, info->mti_mdt->mdt_stats, idx);
}

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
        int rc, uid;

        rc = lprocfs_write_helper(buffer, count, &uid);
        if (rc)
                return rc;

        mdt_flush_identity(mdt->mdt_identity_cache, uid);
        return count;
}

static int lprocfs_wr_identity_info(struct file *file, const char *buffer,
                                    unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        struct identity_downcall_data sparam, *param = &sparam;
        int size = 0, rc = 0;

        if (count < sizeof(*param)) {
                CERROR("%s: invalid data size %lu\n", obd->obd_name, count);
                return count;
        }

        if (copy_from_user(&sparam, buffer, sizeof(sparam))) {
                CERROR("%s: bad identity data\n", obd->obd_name);
                GOTO(out, rc = -EFAULT);
        }

        if (sparam.idd_magic != IDENTITY_DOWNCALL_MAGIC) {
                CERROR("%s: MDS identity downcall bad params\n", obd->obd_name);
                GOTO(out, rc = -EINVAL);
        }

        if (sparam.idd_nperms > N_SETXID_PERMS_MAX) {
                CERROR("%s: perm count %d more than maximum %d\n",
                       obd->obd_name, sparam.idd_nperms, N_SETXID_PERMS_MAX);
                GOTO(out, rc = -EINVAL);
        }

        if (sparam.idd_ngroups > NGROUPS_MAX) {
                CERROR("%s: group count %d more than maximum %d\n",
                       obd->obd_name, sparam.idd_ngroups, NGROUPS_MAX);
                GOTO(out, rc = -EINVAL);
        }

        if (sparam.idd_ngroups) {
                size = offsetof(struct identity_downcall_data,
                                idd_groups[sparam.idd_ngroups]);
                OBD_ALLOC(param, size);
                if (!param) {
                        CERROR("%s: fail to alloc %d bytes for uid %u"
                               " with %d groups\n", obd->obd_name, size,
                               sparam.idd_uid, sparam.idd_ngroups);
                        param = &sparam;
                        param->idd_ngroups = 0;
                } else if (copy_from_user(param, buffer, size)) {
                        CERROR("%s: uid %u bad supplementary group data\n",
                               obd->obd_name, sparam.idd_uid);
                        OBD_FREE(param, size);
                        param = &sparam;
                        param->idd_ngroups = 0;
                }
        }

        rc = upcall_cache_downcall(mdt->mdt_identity_cache, param->idd_err,
                                   param->idd_uid, param);

out:
        if (param && (param != &sparam))
                OBD_FREE(param, size);

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
                               obd->obd_name, size, sparam.add_key);
                        param = &sparam;
                        param->add_buflen = 0;
                } else if (copy_from_user(param, buffer, size)) {
                        CERROR("%s: ino "LPU64" bad remote acl data\n",
                               obd->obd_name, sparam.add_key);
                        OBD_FREE(param, size);
                        param = &sparam;
                        param->add_buflen = 0;
                }
        }

        rc = upcall_cache_downcall(mdt->mdt_rmtacl_cache, 0, param->add_key,
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
                return -ENOMEM;

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
                return -ENOMEM;

        mdt->mdt_rootsquash_info->rsi_gid = val;
        return count;
}

static int lprocfs_rd_nosquash_nids(char *page, char **start, off_t off,
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

static inline void remove_newline(char *str)
{
        int len = strlen(str);

        if (str[len - 1] == '\n')
                str[len - 1] = '\0';
}

/* XXX: This macro is copied from lnet/libcfs/nidstring.c */
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

static int lprocfs_wr_nosquash_nids(struct file *file, const char *buffer,
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
                return -ENOMEM;

        remove_newline(skips);
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
        int val, rc;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val < 0 || val > 3) {
                CERROR("invalid capability mode, only 0/2/3 is accepted.\n"
                       " 0:  disable fid capability\n"
                       " 2:  enable MDS fid capability\n"
                       " 3:  enable both MDS and OSS fid capability\n");
                return -EINVAL;
        }

        /* OSS fid capability needs enable both MDS and OSS fid capability on
         * MDS */
        if (val == 1) {
                CERROR("can't enable OSS fid capability only, you should use "
                       "'3' to enable both MDS and OSS fid capability.\n");
                return -EINVAL;
        }

        mdt->mdt_opts.mo_oss_capa = (val & 0x1);
        mdt->mdt_opts.mo_mds_capa = !!(val & 0x2);
        mdt->mdt_capa_conf = 1;
        LCONSOLE_INFO("MDS %s %s MDS fid capability.\n",
                      obd->obd_name,
                      mdt->mdt_opts.mo_mds_capa ? "enabled" : "disabled");
        LCONSOLE_INFO("MDS %s %s OSS fid capability.\n",
                      obd->obd_name,
                      mdt->mdt_opts.mo_oss_capa ? "enabled" : "disabled");
        return count;
}

static int lprocfs_rd_capa_count(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        return snprintf(page, count, "%d %d\n",
                        capa_count[CAPA_SITE_CLIENT],
                        capa_count[CAPA_SITE_SERVER]);
}

static int lprocfs_rd_site_stats(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        struct lu_site    *s   = mdt->mdt_md_dev.md_lu_dev.ld_site;
        int i;
        int populated;

        /*
         * How many hash buckets are not-empty? Don't bother with locks: it's
         * an estimation anyway.
         */
        for (i = 0, populated = 0; i < s->ls_hash_size; i++)
                populated += !hlist_empty(&s->ls_hash[i]);

        return snprintf(page, count, "%d %d %d/%d %d %d %d %d %d %d\n",
                        s->ls_total,
                        s->ls_busy,
                        populated,
                        s->ls_hash_size,
                        s->ls_stats.s_created,
                        s->ls_stats.s_cache_hit,
                        s->ls_stats.s_cache_miss,
                        s->ls_stats.s_cache_check,
                        s->ls_stats.s_cache_race,
                        s->ls_stats.s_lru_purged);
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

static int lprocfs_mdt_wr_evict_client(struct file *file, const char *buffer,
                                       unsigned long count, void *data)
{
        char tmpbuf[sizeof(struct obd_uuid)];

        sscanf(buffer, "%40s", tmpbuf);

        if (strncmp(tmpbuf, "nid:", 4) != 0)
                return lprocfs_wr_evict_client(file, buffer, count, data);

        CERROR("NOT implement evict client by nid %s\n", tmpbuf);

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
        { "nosquash_nids",              lprocfs_rd_nosquash_nids,
                                        lprocfs_wr_nosquash_nids,           0 },
        { "capa",                       lprocfs_rd_capa,
                                        lprocfs_wr_capa,                    0 },
        { "capa_timeout",               lprocfs_rd_capa_timeout,
                                        lprocfs_wr_capa_timeout,            0 },
        { "capa_key_timeout",           lprocfs_rd_ck_timeout,
                                        lprocfs_wr_ck_timeout,              0 },
        { "capa_count",                 lprocfs_rd_capa_count,           0, 0 },
        { "site_stats",                 lprocfs_rd_site_stats,           0, 0 },
        { "evict_client",               0, lprocfs_mdt_wr_evict_client,     0 },
        { 0 }
};

static struct lprocfs_vars lprocfs_mdt_module_vars[] = {
        { "num_refs",                   lprocfs_rd_numrefs,              0, 0 },
        { 0 }
};

LPROCFS_INIT_VARS(mdt, lprocfs_mdt_module_vars, lprocfs_mdt_obd_vars);
