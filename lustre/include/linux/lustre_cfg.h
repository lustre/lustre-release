/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
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
 */

#ifndef _LUSTRE_CFG_H
#define _LUSTRE_CFG_H

/*
 * 1cf6
 * lcfG
 */
#define LUSTRE_CFG_VERSION 0x1cf60001
#define LUSTRE_CFG_MAX_BUFCOUNT 8

#define LCFG_HDR_SIZE(count) \
    size_round(offsetof (struct lustre_cfg, lcfg_buflens[(count)]))

enum lcfg_command_type {
        LCFG_ATTACH         = 0x00cf001,
        LCFG_DETACH         = 0x00cf002,
        LCFG_SETUP          = 0x00cf003,
        LCFG_CLEANUP        = 0x00cf004,
        LCFG_ADD_UUID       = 0x00cf005,
        LCFG_DEL_UUID       = 0x00cf006,
        LCFG_MOUNTOPT       = 0x00cf007,
        LCFG_DEL_MOUNTOPT   = 0x00cf008,
        LCFG_SET_TIMEOUT    = 0x00cf009,
        LCFG_SET_UPCALL     = 0x00cf00a,
        LCFG_ADD_CONN       = 0x00cf00b,
        LCFG_DEL_CONN       = 0x00cf00c,
};

struct lustre_cfg_bufs {
        void    *lcfg_buf[LUSTRE_CFG_MAX_BUFCOUNT];
        uint32_t lcfg_buflen[LUSTRE_CFG_MAX_BUFCOUNT];
        uint32_t lcfg_bufcount;
};

struct lustre_cfg {
        uint32_t lcfg_version;
        uint32_t lcfg_command;

        uint32_t lcfg_num; 
        uint32_t lcfg_flags;
        uint64_t lcfg_nid;
        uint32_t lcfg_nal;

        uint32_t lcfg_bufcount;
        uint32_t lcfg_buflens[0];
};

#define LUSTRE_CFG_BUFLEN(lcfg, idx)            \
        ((lcfg)->lcfg_bufcount <= (idx)         \
         ? 0                                    \
         : (lcfg)->lcfg_buflens[(idx)])

static inline void lustre_cfg_bufs_set(struct lustre_cfg_bufs *bufs,
                                       uint32_t                index,
                                       void                   *buf,
                                       uint32_t                buflen)
{
        if (index >= LUSTRE_CFG_MAX_BUFCOUNT)
                return;
        if (bufs == NULL)
                return;

        if (bufs->lcfg_bufcount <= index)
                bufs->lcfg_bufcount = index + 1;

        bufs->lcfg_buf[index]    = buf;
        bufs->lcfg_buflen[index] = buflen;
}

static inline void lustre_cfg_bufs_set_string(struct lustre_cfg_bufs *bufs,
                                              uint32_t index,
                                              char *str)
{
        lustre_cfg_bufs_set(bufs, index, str, str ? strlen(str) + 1 : 0);
}

static inline void lustre_cfg_bufs_reset(struct lustre_cfg_bufs *bufs, char *name)
{
        memset((bufs), 0, sizeof(*bufs));
        if (name)
                lustre_cfg_bufs_set_string(bufs, 0, name);
}

static inline void *lustre_cfg_buf(struct lustre_cfg *lcfg, int index)
{
        int i;
        int offset;
        int bufcount;
        LASSERT (lcfg != NULL);
        LASSERT (index >= 0);

        bufcount = lcfg->lcfg_bufcount;
        if (index >= bufcount)
                return NULL;

        offset = LCFG_HDR_SIZE(lcfg->lcfg_bufcount);
        for (i = 0; i < index; i++)
                offset += size_round(lcfg->lcfg_buflens[i]);
        return (char *)lcfg + offset;
}

static inline void lustre_cfg_bufs_init(struct lustre_cfg_bufs *bufs,
                                        struct lustre_cfg *lcfg)
{
        int i;
        bufs->lcfg_bufcount = lcfg->lcfg_bufcount;
        for (i = 0; i < bufs->lcfg_bufcount; i++) {
                bufs->lcfg_buflen[i] = lcfg->lcfg_buflens[i];
                bufs->lcfg_buf[i] = lustre_cfg_buf(lcfg, i);
        }
}

static inline char *lustre_cfg_string(struct lustre_cfg *lcfg, int index)
{
        char *s;

        if (!lcfg->lcfg_buflens[index])
                return NULL;

        s = lustre_cfg_buf(lcfg, index);
        if (!s)
                return NULL;

        /* make sure it's NULL terminated, even if this kills a char
         * of data
         */
        s[lcfg->lcfg_buflens[index] - 1] = '\0';
        return s;
}

static inline int lustre_cfg_len(uint32_t bufcount, uint32_t *buflens)
{
        int i;
        int len;
        ENTRY;

        len = LCFG_HDR_SIZE(bufcount);
        for (i = 0; i < bufcount; i++)
                len += size_round(buflens[i]);

        RETURN(size_round(len));
}


#include <linux/obd_support.h>

static inline struct lustre_cfg *lustre_cfg_new(int cmd,
                                                struct lustre_cfg_bufs *bufs)
{
        struct lustre_cfg *lcfg;
        char *ptr;
        int i;

        ENTRY;

        OBD_ALLOC(lcfg, lustre_cfg_len(bufs->lcfg_bufcount,
                                       bufs->lcfg_buflen));
        if (!lcfg)
                RETURN(lcfg);

        lcfg->lcfg_version = LUSTRE_CFG_VERSION;
        lcfg->lcfg_command = cmd;
        lcfg->lcfg_bufcount = bufs->lcfg_bufcount;

        ptr = (char *)lcfg + LCFG_HDR_SIZE(lcfg->lcfg_bufcount);
        for (i = 0; i < lcfg->lcfg_bufcount; i++) {
                lcfg->lcfg_buflens[i] = bufs->lcfg_buflen[i];
                LOGL((char *)bufs->lcfg_buf[i], bufs->lcfg_buflen[i], ptr);
        }
        RETURN(lcfg);
}

static inline void lustre_cfg_free(struct lustre_cfg *lcfg)
{
        int len;

        len = lustre_cfg_len(lcfg->lcfg_bufcount, lcfg->lcfg_buflens);

        OBD_FREE(lcfg, len);
        EXIT;
        return;
}

static inline int lustre_cfg_sanity_check(void *buf, int len)
{
        struct lustre_cfg *lcfg = (struct lustre_cfg *)buf;
        ENTRY;
        if (!lcfg)
                RETURN(-EINVAL);

        /* check that the first bits of the struct are valid */
        if (len < LCFG_HDR_SIZE(0))
                RETURN(-EINVAL);

        if (lcfg->lcfg_version != LUSTRE_CFG_VERSION)
                RETURN(-EINVAL);
        if (lcfg->lcfg_bufcount >= LUSTRE_CFG_MAX_BUFCOUNT)
                RETURN(-EINVAL);

        /* check that the buflens are valid */
        if (len < LCFG_HDR_SIZE(lcfg->lcfg_bufcount))
                RETURN(-EINVAL);

        /* make sure all the pointers point inside the data */
        if (len < lustre_cfg_len(lcfg->lcfg_bufcount, lcfg->lcfg_buflens))
                RETURN(-EINVAL);

        RETURN(0);
}

/* Passed by mount */
struct lustre_mount_data {
        uint32_t lmd_magic;
        uint32_t lmd_version;
        uint64_t lmd_local_nid;
        uint64_t lmd_server_nid;
        uint32_t lmd_nal;
        uint32_t lmd_server_ipaddr;
        uint32_t lmd_port;
        char     lmd_mds[64];
        char     lmd_profile[64];
};


#endif // _LUSTRE_CFG_H
