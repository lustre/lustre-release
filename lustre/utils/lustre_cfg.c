/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Robert Read <rread@clusterfs.com>
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


#include <stdlib.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdarg.h>

#ifndef __KERNEL__
#include <liblustre.h>
#endif
#include <linux/lustre_lib.h>
#include <linux/lustre_cfg.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>
#include <linux/obd.h>          /* for struct lov_stripe_md */
#include <linux/lustre_build_version.h>

#include <unistd.h>
#include <sys/un.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>


#include "obdctl.h"
#include <portals/ptlctl.h>
#include "parser.h"
#include <stdio.h>

static char * lcfg_devname;

void lcfg_set_devname(char *name)
{
	if (lcfg_devname)
		free(lcfg_devname);
	lcfg_devname = strdup(name);
}


int jt_lcfg_device(int argc, char **argv)
{
	char *name;

        if (argc == 1) {
		printf("current device is %s\n", lcfg_devname? : "not set");
		return 0;
	} else if (argc != 2) {
                return CMD_HELP;
	}

	name = argv[1];

	/* quietly strip the unnecessary '$' */
	if (*name == '$')
		name++;

	lcfg_set_devname(name);

        return 0;
}

/* NOOP */
int jt_lcfg_newdev(int argc, char **argv)
{
        return 0;
}

int jt_lcfg_attach(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int rc;

        if (argc != 2 && argc != 3 && argc != 4)
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, NULL);

        lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);
        if (argc >= 3) {
                lustre_cfg_bufs_set_string(&bufs, 0, argv[2]);
        } else {
                fprintf(stderr, "error: %s: LCFG_ATTACH requires a name\n",
                        jt_cmdname(argv[0])); 
		return -EINVAL;
	}

        if (argc == 4) {
                lustre_cfg_bufs_set_string(&bufs, 2, argv[3]);
        }

        lcfg = lustre_cfg_new(LCFG_ATTACH, &bufs);
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0) {
                fprintf(stderr, "error: %s: LCFG_ATTACH %s\n",
                        jt_cmdname(argv[0]), strerror(rc = errno));
        } else if (argc == 3) {
                char name[1024];

		lcfg_set_devname(argv[2]);
                if (strlen(argv[2]) > 128) {
                        printf("Name too long to set environment\n");
                        return -EINVAL;
                }
                snprintf(name, 512, "LUSTRE_DEV_%s", argv[2]);
                rc = setenv(name, argv[1], 1);
                if (rc) {
                        printf("error setting env variable %s\n", name);
                }
        } else {
		lcfg_set_devname(argv[2]);
	}

        return rc;
}

int jt_lcfg_setup(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int i;
        int rc;

        if (lcfg_devname == NULL) {
                fprintf(stderr, "%s: please use 'cfg_device name' to set the "
                        "device name for config commands.\n", 
                        jt_cmdname(argv[0])); 
		return -EINVAL;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        if (argc > 5)
                return CMD_HELP;

        for (i = 1; i < argc; i++) {
                lustre_cfg_bufs_set_string(&bufs, i, argv[i]);
        }

        lcfg = lustre_cfg_new(LCFG_SETUP, &bufs);
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

int jt_obd_detach(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int rc;

        if (lcfg_devname == NULL) {
                fprintf(stderr, "%s: please use 'cfg_device name' to set the "
                        "device name for config commands.\n", 
                        jt_cmdname(argv[0])); 
		return -EINVAL;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        if (argc != 1)
                return CMD_HELP;

        lcfg = lustre_cfg_new(LCFG_DETACH, &bufs);
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

int jt_obd_cleanup(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        char force = 'F';
        char failover = 'A';
        char flags[3] = { 0 };
        int flag_cnt = 0, n;
        int rc;

        if (lcfg_devname == NULL) {
                fprintf(stderr, "%s: please use 'cfg_device name' to set the "
                        "device name for config commands.\n", 
                        jt_cmdname(argv[0])); 
		return -EINVAL;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        if (argc < 1 || argc > 3)
                return CMD_HELP;

        /* we are protected from overflowing our buffer by the argc
         * check above
         */
        for (n = 1; n < argc; n++) {
                if (strcmp(argv[n], "force") == 0) {
                        flags[flag_cnt++] = force;
                } else if (strcmp(argv[n], "failover") == 0) {
                        flags[flag_cnt++] = failover;
                } else {
                        fprintf(stderr, "unknown option: %s", argv[n]);
                        return CMD_HELP;
                }
        }

        if (flag_cnt) {
                lustre_cfg_bufs_set_string(&bufs, 1, flags);
        }

        lcfg = lustre_cfg_new(LCFG_CLEANUP, &bufs);
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0)
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));

        return rc;
}

static 
int do_add_uuid(char * func, char *uuid, ptl_nid_t nid, int nal) 
{
        char tmp[64];
        int rc;
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);
        if (uuid)
                lustre_cfg_bufs_set_string(&bufs, 1, uuid);

        lcfg = lustre_cfg_new(LCFG_ADD_UUID, &bufs);
        lcfg->lcfg_nid = nid;
        lcfg->lcfg_nal = nal;

#if 0
        fprintf(stderr, "adding\tnal: %d\tnid: %d\tuuid: %s\n",
               lcfg->lcfg_nid, lcfg->lcfg_nal, uuid);
#endif
        rc = lcfg_ioctl(func, OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_ADD_UUID failed: %s\n",
                        strerror(errno));
                return -1;
        }

        printf ("Added uuid %s: %s\n", uuid, ptl_nid2str (tmp, nid));
        return 0;
}

int jt_lcfg_add_uuid(int argc, char **argv)
{
        ptl_nid_t nid = 0;
        int nal;
        
        if (argc != 4) {                
                return CMD_HELP;
        }

        if (ptl_parse_nid (&nid, argv[2]) != 0) {
                fprintf (stderr, "Can't parse NID %s\n", argv[2]);
                        return (-1);
        }

        nal = ptl_name2nal(argv[3]);

        if (nal <= 0) {
                fprintf (stderr, "Can't parse NAL %s\n", argv[3]);
                return -1;
        }

        return do_add_uuid(argv[0], argv[1], nid, nal);
}

int obd_add_uuid(char *uuid, ptl_nid_t nid, int nal)
{
        return do_add_uuid("obd_add_uuid", uuid, nid, nal);
}

int jt_lcfg_del_uuid(int argc, char **argv)
{
        int rc;
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;

        if (argc != 2) {
                fprintf(stderr, "usage: %s <uuid>\n", argv[0]);
                return 0;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);
        if (strcmp (argv[1], "_all_"))
                lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);
        
        lcfg = lustre_cfg_new(LCFG_DEL_UUID, &bufs);
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc) {
                fprintf(stderr, "IOC_PORTAL_DEL_UUID failed: %s\n",
                        strerror(errno));
                return -1;
        }
        return 0;
}

int jt_lcfg_lov_setup(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        struct lov_desc desc;
        struct obd_uuid *uuidarray = NULL, *ptr;
        int rc, i;
        char *end;

        if (argc <= 6)
                return CMD_HELP;

        if (strlen(argv[1]) > sizeof(desc.ld_uuid) - 1) {
                fprintf(stderr,
                        "error: %s: LOV uuid '%s' longer than "LPSZ" chars\n",
                        jt_cmdname(argv[0]), argv[1], sizeof(desc.ld_uuid) - 1);
                return -EINVAL;
        }

        memset(&desc, 0, sizeof(desc));
        obd_str2uuid(&desc.ld_uuid, argv[1]);
        desc.ld_tgt_count = argc - 6;
        desc.ld_magic = LOV_DESC_MAGIC;
        desc.ld_default_stripe_count = strtoul(argv[2], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: bad default stripe count '%s'\n",
                        jt_cmdname(argv[0]), argv[2]);
                return CMD_HELP;
        }
        if (desc.ld_default_stripe_count > desc.ld_tgt_count) {
                fprintf(stderr,
                        "error: %s: default stripe count %u > OST count %u\n",
                        jt_cmdname(argv[0]), desc.ld_default_stripe_count,
                        desc.ld_tgt_count);
                return -EINVAL;
        }

        desc.ld_default_stripe_size = strtoull(argv[3], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: bad default stripe size '%s'\n",
                        jt_cmdname(argv[0]), argv[3]);
                return CMD_HELP;
        }
        if (desc.ld_default_stripe_size < 4096) {
                fprintf(stderr,
                        "error: %s: default stripe size "LPU64" too small\n",
                        jt_cmdname(argv[0]), desc.ld_default_stripe_size);
                return -EINVAL;
        } else if ((long)desc.ld_default_stripe_size <
                   desc.ld_default_stripe_size) {
                fprintf(stderr,
                        "error: %s: default stripe size "LPU64" too large\n",
                        jt_cmdname(argv[0]), desc.ld_default_stripe_size);
                return -EINVAL;
        }
        desc.ld_default_stripe_offset = strtoull(argv[4], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: bad default stripe offset '%s'\n",
                        jt_cmdname(argv[0]), argv[4]);
                return CMD_HELP;
        }
        desc.ld_pattern = strtoul(argv[5], &end, 0);
        if (*end) {
                fprintf(stderr, "error: %s: bad stripe pattern '%s'\n",
                        jt_cmdname(argv[0]), argv[5]);
                return CMD_HELP;
        }

        /* NOTE: it is possible to overwrite the default striping parameters,
         *       but EXTREME care must be taken when saving the OST UUID list.
         *       It must be EXACTLY the same, or have only additions at the
         *       end of the list, or only overwrite individual OST entries
         *       that are restored from backups of the previous OST.
         */
        uuidarray = calloc(desc.ld_tgt_count, sizeof(*uuidarray));
        if (!uuidarray) {
                fprintf(stderr, "error: %s: no memory for %d UUIDs\n",
                        jt_cmdname(argv[0]), desc.ld_tgt_count);
                rc = -ENOMEM;
                goto out;
        }
        for (i = 6, ptr = uuidarray; i < argc; i++, ptr++) {
                if (strlen(argv[i]) >= sizeof(*ptr)) {
                        fprintf(stderr, "error: %s: arg %d (%s) too long\n",
                                jt_cmdname(argv[0]), i, argv[i]);
                        rc = -EINVAL;
                        goto out;
                }
                strcpy((char *)ptr, argv[i]);
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);
        lustre_cfg_bufs_set(&bufs, 1, &desc, sizeof(desc));
        lustre_cfg_bufs_set(&bufs, 2, uuidarray,
                            desc.ld_tgt_count * sizeof(*uuidarray));

        lcfg = lustre_cfg_new(LCFG_SETUP, &bufs);
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc)
                fprintf(stderr, "error: %s: ioctl error: %s\n",
                        jt_cmdname(argv[0]), strerror(rc = errno));
out:
        free(uuidarray);
        return rc;
}

int jt_lcfg_mount_option(int argc, char **argv)
{
        int rc;
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int i;

        if (argc < 3 || argc > 4)
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        for (i = 1; i < argc; i++)
                lustre_cfg_bufs_set_string(&bufs, i, argv[i]);

        lcfg = lustre_cfg_new(LCFG_MOUNTOPT, &bufs);
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }
        return rc;
}

int jt_lcfg_del_mount_option(int argc, char **argv)
{
        int rc;
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;

        if (argc != 2)
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        /* profile name */
        lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);

        lcfg = lustre_cfg_new(LCFG_DEL_MOUNTOPT, &bufs);
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }
        return rc;
}

int jt_lcfg_set_timeout(int argc, char **argv)
{
        int rc;
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;

        if (argc != 2)
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);
        lcfg = lustre_cfg_new(LCFG_SET_TIMEOUT, &bufs);
        lcfg->lcfg_num = atoi(argv[1]);
        
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }
        return rc;
}


int jt_lcfg_set_lustre_upcall(int argc, char **argv)
{
        int rc;
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;

        if (argc != 2)
                return CMD_HELP;

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        /* profile name */
        lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);

        lcfg = lustre_cfg_new(LCFG_SET_UPCALL, &bufs);
        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }
        return rc;
}

int jt_lcfg_add_conn(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int priority;
        int rc;

        if (argc == 2)
                priority = 0;
        else if (argc == 3)
                priority = 1;
        else
                return CMD_HELP;

        if (lcfg_devname == NULL) {
                fprintf(stderr, "%s: please use 'cfg_device name' to set the "
                        "device name for config commands.\n", 
                        jt_cmdname(argv[0])); 
		return -EINVAL;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);

        lcfg = lustre_cfg_new(LCFG_ADD_CONN, &bufs);
        lcfg->lcfg_num = priority;

        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free (lcfg);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }

        return rc;
}

int jt_lcfg_del_conn(int argc, char **argv)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int rc;

        if (argc != 2)
                return CMD_HELP;

        if (lcfg_devname == NULL) {
                fprintf(stderr, "%s: please use 'cfg_device name' to set the "
                        "device name for config commands.\n", 
                        jt_cmdname(argv[0])); 
		return -EINVAL;
        }

        lustre_cfg_bufs_reset(&bufs, lcfg_devname);

        /* connection uuid */
        lustre_cfg_bufs_set_string(&bufs, 1, argv[1]);

        lcfg = lustre_cfg_new(LCFG_DEL_MOUNTOPT, &bufs);

        rc = lcfg_ioctl(argv[0], OBD_DEV_ID, lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0) {
                fprintf(stderr, "error: %s: %s\n", jt_cmdname(argv[0]),
                        strerror(rc = errno));
        }

        return rc;
}
