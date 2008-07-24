/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lvfs/lustre_quota_fmt_convert.c
 *
 * convert quota format.
 * from linux/fs/quota_v2.c
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/quotaio_v1.h>

#include <asm/byteorder.h>
#include <asm/uaccess.h>

#include <lustre_quota.h>
#include <obd_support.h>
#include "lustre_quota_fmt.h"

static int admin_convert_dqinfo(struct file *fp_v1, struct file *fp_v2,
                                struct lustre_quota_info *lqi, int type)
{
        struct lustre_mem_dqinfo *info_old, *info_new = &lqi->qi_info[type];
        int rc;

        OBD_ALLOC_PTR(info_old);
        if (info_old == NULL)
                return -ENOMEM;

        rc = lustre_read_quota_file_info(fp_v1, info_old);
        if (!rc) {
                /* save essential fields: bgrace, igrace, flags */
                info_new->dqi_bgrace = info_old->dqi_bgrace;
                info_new->dqi_igrace = info_old->dqi_igrace;
                info_new->dqi_flags  = info_old->dqi_flags;
                rc = lustre_write_quota_info(lqi, type);
        }

        OBD_FREE_PTR(info_old);

        return rc;
}

static int quota_convert_v1_to_v2(struct file *fp_v1, struct file *fp_v2,
                                  struct lustre_quota_info *lqi, int type)
{
        struct list_head blk_list;
        struct dqblk *blk_item, *tmp;
        dqbuf_t buf = NULL;
        struct lustre_disk_dqblk *ddquot;
        struct lustre_dquot *dquot = NULL;
        int rc;

        ENTRY;

        INIT_LIST_HEAD(&blk_list);

        rc = admin_convert_dqinfo(fp_v1, fp_v2, lqi, type);
        if (rc) {
                CERROR("could not copy dqinfo!(%d)\n", rc);
                GOTO(out_free, rc);
        }

        rc = walk_tree_dqentry(fp_v1, NULL, type, LUSTRE_DQTREEOFF, 0, &blk_list);
        if (rc) {
                CERROR("walk through quota file failed!(%d)\n", rc);
                GOTO(out_free, rc);
        }
        if (list_empty(&blk_list))
                RETURN(0);

        buf = getdqbuf();
        if (!buf)
                GOTO(out_free, rc = -ENOMEM);

        ddquot = (struct lustre_disk_dqblk*)GETENTRIES(buf, LUSTRE_QUOTA_V1);

        OBD_ALLOC_PTR(dquot);
        if (dquot == NULL)
                GOTO(out_free, rc = -ENOMEM);

        list_for_each_entry(blk_item, &blk_list, link) {
                loff_t ret = 0;
                int i;
                struct lustre_disk_dqblk fakedquot;

                memset(buf, 0, LUSTRE_DQBLKSIZE);
                if ((ret = quota_read(fp_v1, NULL, type, blk_item->blk, buf))<0) {
                        CERROR("VFS: Can't read quota tree block %u.\n",
                               blk_item->blk);
                        GOTO(out_free, rc = ret);
                }

                memset(&fakedquot, 0, sizeof(struct lustre_disk_dqblk));
                for (i = 0; i < LUSTRE_DQSTRINBLK; i++) {
                        /* skip empty entry */
                        if (!memcmp
                            (&fakedquot, ddquot + i,
                             sizeof(struct lustre_disk_dqblk)))
                                continue;

                        memset(dquot, 0, sizeof(*dquot));

                        dquot->dq_id = le32_to_cpu(ddquot[i].dqb_id);
                        dquot->dq_type = type;
                        dquot->dq_info = lqi;

                        disk2memdqb(&dquot->dq_dqb, &ddquot[i], LUSTRE_QUOTA_V1);
                        rc = lustre_commit_dquot(dquot);
                        if (rc < 0)
                                GOTO(out_free, rc);
                }
        }

        EXIT;

out_free:
        list_for_each_entry_safe(blk_item, tmp, &blk_list, link) {
                list_del_init(&blk_item->link);
                kfree(blk_item);
        }
        if (buf)
                freedqbuf(buf);
        if (dquot)
                OBD_FREE_PTR(dquot);
        return rc;
}

int lustre_quota_convert(struct lustre_quota_info *lqi, int type)
{
        struct file *f_v2 = lqi->qi_files[type];
        const char *qf_v1[] = LUSTRE_ADMIN_QUOTAFILES_V1;
        char name[64];
        struct file *f_v1;
        int rc = 0;
        ENTRY;

        LASSERT(f_v2);

        rc = lustre_init_quota_info_generic(lqi, type, 1);
        if (rc) {
                CERROR("could not initialize new quota file(%d)\n", rc);
                RETURN(rc);
        }

        /* Open old quota file and copy to the new one */
        sprintf(name, "OBJECTS/%s", qf_v1[type]);
        f_v1 = filp_open(name, O_RDONLY, 0);
        if (!IS_ERR(f_v1)) {
                if (!check_quota_file(f_v1, NULL, type, LUSTRE_QUOTA_V1)) {
                        rc = quota_convert_v1_to_v2(f_v1, f_v2, lqi, type);
                        if (rc)
                                CERROR("failed to convert v1 quota file"
                                       " to v2 quota file.\n");
                        else
                                CDEBUG(D_INFO, "Found v1 quota file, "
                                               "successfully converted to v2.\n");
                }
                else
                        CERROR("old quota file is broken, "
                               "new quota file will be empty\n");

                filp_close(f_v1, 0);
        } else if (PTR_ERR(f_v1) != -ENOENT) /* No quota file is ok */
                CERROR("old quota file can not be open, "
                       "new quota file will be empty (%ld)\n", PTR_ERR(f_v1));

        /* mark corresponding quota file as correct */
        if (!rc)
                lustre_init_quota_header(lqi, type, 0);

        RETURN(rc);
}
EXPORT_SYMBOL(lustre_quota_convert);

#ifdef HAVE_QUOTA64
/*
 * convert operational quota files to the requested version 
 * returns: -ESTALE if upgrading to qfmt version is not supported
 *          -ENOMEM if memory was not allocated for conv. structures
 *
 *          other error codes can be returned by VFS and have the
 *          appropriate meaning
 */
int lustre_slave_quota_convert(lustre_quota_version_t qfmt, int type)
{
        struct lustre_quota_info *lqi;
        struct file *f_v1, *f_v2;
        const char *name[][MAXQUOTAS] = LUSTRE_OPQFILES_NAMES;
        int rc;

        ENTRY;

        /* we convert only to v2 version */
        if (qfmt != LUSTRE_QUOTA_V2)
                GOTO(out, rc = -ESTALE);

        OBD_ALLOC_PTR(lqi);
        if (lqi == NULL)
                GOTO(out, rc = -ENOMEM);

        /* now that we support only v1 and v2 formats,
         * only upgrade from v1 is possible,
         * let's check if v1 file exists so that we convert it to v2 */
        f_v1 = filp_open(name[LUSTRE_QUOTA_V1][type], O_RDONLY, 0);
        if (IS_ERR(f_v1))
                GOTO(out_free, rc = PTR_ERR(f_v1));

        /* make sure it is really a v1 file */
        if (check_quota_file(f_v1, NULL, type, LUSTRE_QUOTA_V1))
                GOTO(out_f_v1, rc = -EINVAL);

        /* create new quota file for v2 version, follow the same rationale as
         * mds_admin_quota_on: if the file already exists, then do not try to
         * overwrite it, user has to fix the quotaon issue manually,
         * e.g. through running quotacheck                                  */
        f_v2 = filp_open(name[LUSTRE_QUOTA_V2][type],
                         O_CREAT | O_EXCL | O_TRUNC | O_RDWR, 0644);
        if (IS_ERR(f_v2))
                GOTO(out_f_v1, rc = PTR_ERR(f_v2));

        lqi->qi_version = LUSTRE_QUOTA_V2;
        lqi->qi_files[type] = f_v2;

        /* initialize quota file with defaults, marking it invalid,
         * this will help us not to get confused with partially converted
         * operational quota files if we crash during conversion   */
        rc = lustre_init_quota_info_generic(lqi, type, 1);
        if (rc)
                GOTO(out_f_v2, rc);

        rc = quota_convert_v1_to_v2(f_v1, f_v2, lqi, type);
        if (!rc) {
                /* we dont want good magic to store before the quota data,
                 * just to be safe if ldiskfs is running in writeback mode */
                LOCK_INODE_MUTEX(f_v2->f_dentry->d_inode);
                rc = lustre_fsync(f_v2);
                if (rc)
                        CERROR("error from fsync, rc=%d\n", rc);
                UNLOCK_INODE_MUTEX(f_v2->f_dentry->d_inode);

                /* now that conversion successfully finished we mark
                 * this operational quota file with the correct magic,
                 * since this moment quotaon will treat it as a correct
                 * quota file */
                rc = lustre_init_quota_header(lqi, type, 0);
        }

        EXIT;

out_f_v2:
        filp_close(f_v2, 0);
out_f_v1:
        filp_close(f_v1, 0);
out_free:
        OBD_FREE_PTR(lqi);
out:
        return rc;
}
EXPORT_SYMBOL(lustre_slave_quota_convert);
#endif
