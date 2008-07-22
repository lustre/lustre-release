/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * convert quota format.
 *
 *  from
 *  linux/fs/quota_v2.c
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

static int admin_convert_v1_to_v2(struct file *fp_v1, struct file *fp_v2,
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
                        rc = admin_convert_v1_to_v2(f_v1, f_v2, lqi, type);
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
