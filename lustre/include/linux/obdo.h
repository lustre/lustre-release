#ifndef OBD_H
#define OBD_H
/*
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

struct obdfs_inode_info {
        int              oi_flags;
        struct list_head oi_inodes;
        struct list_head oi_pages;
        char             oi_inline[OBD_INLINESZ];
};

struct obdfs_sb_info {
        struct list_head         osi_list;      /* list of supers */
        struct obd_conn          osi_conn;
        struct super_block      *osi_super;
        struct obd_device       *osi_obd;
        struct obd_ops          *osi_ops;
        ino_t                    osi_rootino;   /* number of root inode */
        int                      osi_minor;     /* minor of /dev/obdX */
        struct list_head         osi_inodes;    /* list of dirty inodes */
        unsigned long            osi_cache_count;
        struct semaphore         osi_list_mutex;
};


static inline struct obdfs_inode_info *obdfs_i2info(struct inode *inode)
{
        return (struct obdfs_inode_info *)&(inode->u.generic_ip);
}

static inline int obdfs_has_inline(struct inode *inode)
{
        return (obdfs_i2info(inode)->oi_flags & OBD_FL_INLINEDATA);
}

static void inline obdfs_from_inode(struct obdo *oa, struct inode *inode)
{
        struct obdfs_inode_info *oinfo = obdfs_i2info(inode);

        CDEBUG(D_INFO, "src inode %ld, dst obdo %ld valid 0x%08x\n",
               inode->i_ino, (long)oa->o_id, oa->o_valid);
        obdo_from_inode(oa, inode);
        if (obdfs_has_inline(inode)) {
                CDEBUG(D_INODE, "copying inline data from inode to obdo\n");
                memcpy(oa->o_inline, oinfo->oi_inline, OBD_INLINESZ);
                oa->o_obdflags |= OBD_FL_INLINEDATA;
                oa->o_valid |= OBD_MD_FLINLINE;
        }
} /* obdfs_from_inode */

static void inline obdfs_to_inode(struct inode *inode, struct obdo *oa)
{
        struct obdfs_inode_info *oinfo = obdfs_i2info(inode);

        CDEBUG(D_INFO, "src obdo %ld valid 0x%08x, dst inode %ld\n",
               (long)oa->o_id, oa->o_valid, inode->i_ino);

        obdo_to_inode(inode, oa);

        if (obdo_has_inline(oa)) {
                CDEBUG(D_INODE, "copying inline data from obdo to inode\n");
                memcpy(oinfo->oi_inline, oa->o_inline, OBD_INLINESZ);
                oinfo->oi_flags |= OBD_FL_INLINEDATA;
        }
} /* obdfs_to_inode */

#define NOLOCK 0
#define LOCKED 1

#ifdef OPS
#warning "*** WARNING redefining OPS"
#else
#define OPS(sb,op) ((struct obdfs_sb_info *)(& ## sb ## ->u.generic_sbp))->osi_ops->o_ ## op
#define IOPS(inode,op) ((struct obdfs_sb_info *)(& ## inode->i_sb ## ->u.generic_sbp))->osi_ops->o_ ## op
#endif

#ifdef ID
#warning "*** WARNING redefining ID"
#else
#define ID(sb) (&((struct obdfs_sb_info *)( & ## sb ## ->u.generic_sbp))->osi_conn)
#define IID(inode) (&((struct obdfs_sb_info *)( & ## inode->i_sb ## ->u.generic_sbp))->osi_conn)
#endif

#define OBDFS_SUPER_MAGIC 0x4711

#endif
