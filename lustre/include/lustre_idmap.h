/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_IDMAP_H
#define _LUSTRE_IDMAP_H

#include <md_object.h>

#define CFS_NGROUPS_PER_BLOCK   ((int)(CFS_PAGE_SIZE / sizeof(gid_t)))

#define CFS_GROUP_AT(gi, i) \
        ((gi)->blocks[(i) / CFS_NGROUPS_PER_BLOCK][(i) % CFS_NGROUPS_PER_BLOCK])

enum {
        CFS_IC_NOTHING     = 0,    /* convert nothing */
        CFS_IC_ALL         = 1,    /* convert all items */
        CFS_IC_MAPPED      = 2,    /* convert mapped uid/gid */
        CFS_IC_UNMAPPED    = 3     /* convert unmapped uid/gid */
};

#define  CFS_IDMAP_NOTFOUND     (-1)

#define CFS_IDMAP_HASHSIZE      32

enum lustre_idmap_idx {
        RMT_UIDMAP_IDX,
        LCL_UIDMAP_IDX,
        RMT_GIDMAP_IDX,
        LCL_GIDMAP_IDX,
        CFS_IDMAP_N_HASHES
};

struct lustre_idmap_table {
        spinlock_t       lit_lock;
        struct list_head lit_idmaps[CFS_IDMAP_N_HASHES][CFS_IDMAP_HASHSIZE];
};

extern void lustre_groups_from_list(struct group_info *ginfo, gid_t *glist);
extern void lustre_groups_sort(struct group_info *group_info);
extern int lustre_in_group_p(struct md_ucred *mu, gid_t grp);

extern int lustre_idmap_add(struct lustre_idmap_table *t,
                            uid_t ruid, uid_t luid,
                            gid_t rgid, gid_t lgid);
extern int lustre_idmap_del(struct lustre_idmap_table *t,
                            uid_t ruid, uid_t luid,
                            gid_t rgid, gid_t lgid);
extern int lustre_idmap_lookup_uid(struct md_ucred *mu,
                                   struct lustre_idmap_table *t,
                                   int reverse, uid_t uid);
extern int lustre_idmap_lookup_gid(struct md_ucred *mu,
                                   struct lustre_idmap_table *t,
                                   int reverse, gid_t gid);
extern struct lustre_idmap_table *lustre_idmap_init(void);
extern void lustre_idmap_fini(struct lustre_idmap_table *t);

#endif
