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

#define LUSTRE_CFG_VERSION 0x00010001

enum lcfg_command_type {
        LCFG_ATTACH         = 0x00cf001,
        LCFG_DETACH         = 0x00cf002,
        LCFG_SETUP          = 0x00cf003,
        LCFG_CLEANUP        = 0x00cf004,
        LCFG_ADD_UUID       = 0x00cf005,
        LCFG_DEL_UUID       = 0x00cf006,
        LCFG_MOUNTOPT       = 0x00cf007,
        LCFG_DEL_MOUNTOPT   = 0x00cf008,
};

struct lustre_cfg {
        uint32_t lcfg_version;
        uint32_t lcfg_command;

        uint32_t lcfg_dev;
        uint32_t lcfg_flags;
        uint64_t lcfg_nid;
        uint32_t lcfg_nal;

        /* inline buffers for various arguments */
        uint32_t lcfg_dev_namelen;
        char    *lcfg_dev_name;
        uint32_t lcfg_inllen1;
        char    *lcfg_inlbuf1;
        uint32_t lcfg_inllen2;
        char    *lcfg_inlbuf2;
        uint32_t lcfg_inllen3;
        char    *lcfg_inlbuf3;
        uint32_t lcfg_inllen4;
        char    *lcfg_inlbuf4;

        char    lcfg_bulk[0];

};

#define LCFG_INIT(l, cmd, name)                                 \
do {                                                            \
        memset(&(l), 0, sizeof(l));                             \
        (l).lcfg_version = LUSTRE_CFG_VERSION;                  \
        (l).lcfg_command = (cmd);                               \
        if (name) {                                             \
                (l).lcfg_dev_namelen = strlen(name) + 1;        \
                (l).lcfg_dev_name = name;                       \
        }                                                       \
                                                                \
} while (0)

#ifndef __KERNEL__
static inline int lustre_cfg_packlen(struct lustre_cfg *lcfg)
{
        int len = size_round(sizeof(struct lustre_cfg));
        len += size_round(lcfg->lcfg_dev_namelen);
        len += size_round(lcfg->lcfg_inllen1);
        len += size_round(lcfg->lcfg_inllen2);
        len += size_round(lcfg->lcfg_inllen3);
        len += size_round(lcfg->lcfg_inllen4);
        return size_round(len);
}

static inline int lustre_cfg_pack(struct lustre_cfg *data, char **pbuf,
                                 int max, int *plen)
{
        char *ptr;
        struct lustre_cfg *overlay;
	int len;

        len = lustre_cfg_packlen(data);

        data->lcfg_version = LUSTRE_CFG_VERSION;

        if (*pbuf && len > max)
                return 1;
        if (*pbuf == NULL) {
                *pbuf = malloc(len);
        }
        if (!*pbuf)
                return 1;
        overlay = (struct lustre_cfg *)*pbuf;
        memcpy(*pbuf, data, sizeof(*data));

        ptr = overlay->lcfg_bulk;
        if (data->lcfg_dev_name)
                LOGL(data->lcfg_dev_name, data->lcfg_dev_namelen, ptr);
        if (data->lcfg_inlbuf1)
                LOGL(data->lcfg_inlbuf1, data->lcfg_inllen1, ptr);
        if (data->lcfg_inlbuf2)
                LOGL(data->lcfg_inlbuf2, data->lcfg_inllen2, ptr);
        if (data->lcfg_inlbuf3)
                LOGL(data->lcfg_inlbuf3, data->lcfg_inllen3, ptr);
        if (data->lcfg_inlbuf4)
                LOGL(data->lcfg_inlbuf4, data->lcfg_inllen4, ptr);
//        if (lustre_cfg_is_invalid(overlay))
//                return 1;

	*plen = len;

        return 0;
}

static inline int lustre_cfg_unpack(struct lustre_cfg *data, char *pbuf,
                                   int max)
{
        char *ptr;
        struct lustre_cfg *overlay;

        if (!pbuf)
                return 1;
        overlay = (struct lustre_cfg *)pbuf;

        /* Preserve the caller's buffer pointers */
        overlay->lcfg_dev_name = data->lcfg_dev_name;
        overlay->lcfg_inlbuf1 = data->lcfg_inlbuf1;
        overlay->lcfg_inlbuf2 = data->lcfg_inlbuf2;
        overlay->lcfg_inlbuf3 = data->lcfg_inlbuf3;
        overlay->lcfg_inlbuf4 = data->lcfg_inlbuf4;

        memcpy(data, pbuf, sizeof(*data));

        ptr = overlay->lcfg_bulk;
        if (data->lcfg_dev_name)
                LOGU(data->lcfg_dev_name, data->lcfg_dev_namelen, ptr);
        if (data->lcfg_inlbuf1)
                LOGU(data->lcfg_inlbuf1, data->lcfg_inllen1, ptr);
        if (data->lcfg_inlbuf2)
                LOGU(data->lcfg_inlbuf2, data->lcfg_inllen2, ptr);
        if (data->lcfg_inlbuf3)
                LOGU(data->lcfg_inlbuf3, data->lcfg_inllen3, ptr);
        if (data->lcfg_inlbuf4)
                LOGU(data->lcfg_inlbuf4, data->lcfg_inllen4, ptr);

        return 0;
}
#endif

#include <linux/obd_support.h>

static inline int lustre_cfg_getdata(char **buf, int len, void *arg, int kernel)
{
        struct lustre_cfg *lcfg;
        int err;
	int offset = 0;
        ENTRY;
        if (len > OBD_MAX_IOCTL_BUFFER) {
                CERROR("User buffer len %d exceeds %d max buffer\n",
                       len, OBD_MAX_IOCTL_BUFFER);
                return -EINVAL;
        }

        if (len < sizeof(struct lustre_cfg)) {
                CERROR("OBD: user buffer too small for lustre_cfg\n");
                return -EINVAL;
        }

        /* XXX allocate this more intelligently, using kmalloc when
         * appropriate */
        OBD_ALLOC(*buf, len);
        if (*buf == NULL) {
                CERROR("Cannot allocate control buffer of len %d\n", len);
                RETURN(-EINVAL);
        }

        if (kernel) {
                memcpy(*buf, (void *)arg, len);
        } else {
                err = copy_from_user(*buf, (void *)arg, len);
                if (err) 
                        RETURN(err);
        }

        lcfg = (struct lustre_cfg *)*buf;

        if (lcfg->lcfg_version != LUSTRE_CFG_VERSION) {
                CERROR("Version mismatch kernel vs application\n");
                return -EINVAL;
        }

//        if (lustre_cfg_is_invalid(data)) {
//                CERROR("ioctl not correctly formatted\n");
//                return -EINVAL;
//        }

        if (lcfg->lcfg_dev_name) {
                lcfg->lcfg_dev_name = &lcfg->lcfg_bulk[0];
		offset += size_round(lcfg->lcfg_dev_namelen);
        }

        if (lcfg->lcfg_inllen1) {
                lcfg->lcfg_inlbuf1 = &lcfg->lcfg_bulk[0] + offset;
		offset += size_round(lcfg->lcfg_inllen1);
        }

        if (lcfg->lcfg_inllen2) {
                lcfg->lcfg_inlbuf2 = &lcfg->lcfg_bulk[0] + offset;
		offset += size_round(lcfg->lcfg_inllen2);
        }

        if (lcfg->lcfg_inllen3) {
                lcfg->lcfg_inlbuf3 = &lcfg->lcfg_bulk[0] + offset;
		offset += size_round(lcfg->lcfg_inllen3);
        }

        if (lcfg->lcfg_inllen4) {
                lcfg->lcfg_inlbuf4 = &lcfg->lcfg_bulk[0] + offset;
        }

        EXIT;
        return 0;
}

static inline void lustre_cfg_freedata(char *buf, int len)
{
        ENTRY;

        OBD_FREE(buf, len);
        EXIT;
        return;
}

/* Passed by mount */
struct lustre_mount_data {
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
