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

/* If not LCFG_REQUIRED, we can ignore this cmd and go on. */
#define LCFG_REQUIRED         0x0001000

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
        LCFG_LOV_ADD_OBD    = 0x00cf00d,
        LCFG_LOV_DEL_OBD    = 0x00cf00e,
        LCFG_PARAM          = 0x00cf00f,
        LCFG_MARKER         = 0x00cf010,
        LCFG_LOG_START      = 0x00ce011,
        LCFG_LOG_END        = 0x00ce012,
        LCFG_LOV_ADD_INA    = 0x00ce013,
        LCFG_ADD_MDC        = 0x00cf014,
        LCFG_DEL_MDC        = 0x00cf015,
        LCFG_SPTLRPC_CONF   = 0x00ce016,
};

struct lustre_cfg_bufs {
        void    *lcfg_buf[LUSTRE_CFG_MAX_BUFCOUNT];
        __u32    lcfg_buflen[LUSTRE_CFG_MAX_BUFCOUNT];
        __u32    lcfg_bufcount;
};

/* Mountconf transitional hack, should go away after 1.6 */
#define LCFG_FLG_MOUNTCONF 0x400

struct lustre_cfg {
        __u32 lcfg_version;
        __u32 lcfg_command;

        __u32 lcfg_num; 
        __u32 lcfg_flags;
        __u64 lcfg_nid;
        __u32 lcfg_nal;                      /* not used any more */

        __u32 lcfg_bufcount;
        __u32 lcfg_buflens[0];
};

enum cfg_record_type {
        PORTALS_CFG_TYPE = 1,
        LUSTRE_CFG_TYPE = 123,
};

#define LUSTRE_CFG_BUFLEN(lcfg, idx)            \
        ((lcfg)->lcfg_bufcount <= (idx)         \
         ? 0                                    \
         : (lcfg)->lcfg_buflens[(idx)])

static inline void lustre_cfg_bufs_set(struct lustre_cfg_bufs *bufs,
                                       __u32                   index,
                                       void                   *buf,
                                       __u32                   buflen)
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
                                              __u32 index,
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
         * of data.  Try to use the padding first though.
         */
        if (s[lcfg->lcfg_buflens[index] - 1] != '\0') {
                int last = min((int)lcfg->lcfg_buflens[index], 
                               size_round(lcfg->lcfg_buflens[index]) - 1);
                char lost = s[last];
                s[last] = '\0';
                if (lost != '\0') {
                        CWARN("Truncated buf %d to '%s' (lost '%c'...)\n",
                              index, s, lost);
                }
        }
        return s;
}

static inline int lustre_cfg_len(__u32 bufcount, __u32 *buflens)
{
        int i;
        int len;
        ENTRY;

        len = LCFG_HDR_SIZE(bufcount);
        for (i = 0; i < bufcount; i++)
                len += size_round(buflens[i]);

        RETURN(size_round(len));
}


#include <obd_support.h>

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

#include <lustre/lustre_user.h>

#define INVALID_UID     (-1)

#endif // _LUSTRE_CFG_H
