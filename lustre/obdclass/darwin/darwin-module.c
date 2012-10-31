/*
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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <mach/mach_types.h>
#include <string.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <obd_class.h>
#include <lprocfs_status.h>

#ifndef OBD_MAX_IOCTL_BUFFER
#ifdef CONFIG_LUSTRE_OBD_MAX_IOCTL_BUFFER
#define OBD_MAX_IOCTL_BUFFER	CONFIG_LUSTRE_OBD_MAX_IOCTL_BUFFER
#else
#define OBD_MAX_IOCTL_BUFFER	8192
#endif
#endif

/* buffer MUST be at least the size of obd_ioctl_hdr */
int obd_ioctl_getdata(char **buf, int *len, void *arg)
{
        struct obd_ioctl_hdr *hdr;
        struct obd_ioctl_data *data;
        int err = 0;
        int offset = 0;
        ENTRY;

	hdr = (struct obd_ioctl_hdr *)arg;
        if (hdr->ioc_version != OBD_IOCTL_VERSION) {
                CERROR("Version mismatch kernel vs application\n");
                RETURN(-EINVAL);
        }

        if (hdr->ioc_len > OBD_MAX_IOCTL_BUFFER) {
                CERROR("User buffer len %d exceeds %d max buffer\n",
                       hdr->ioc_len, OBD_MAX_IOCTL_BUFFER);
                RETURN(-EINVAL);
        }

        if (hdr->ioc_len < sizeof(struct obd_ioctl_data)) {
                CERROR("OBD: user buffer too small for ioctl (%d)\n", hdr->ioc_len);
                RETURN(-EINVAL);
        }

        OBD_ALLOC_LARGE(*buf, hdr->ioc_len);
        if (*buf == NULL) {
                CERROR("Cannot allocate control buffer of len %d\n",
                       hdr->ioc_len);
                RETURN(-EINVAL);
        }
        *len = hdr->ioc_len;
        data = (struct obd_ioctl_data *)*buf;

	bzero(data, hdr->ioc_len);
	memcpy(data, (void *)arg, sizeof(struct obd_ioctl_data));
	if (data->ioc_inlbuf1)
		err = copy_from_user(&data->ioc_bulk[0], (void *)data->ioc_inlbuf1,
				     hdr->ioc_len - ((void *)&data->ioc_bulk[0] - (void *)data));

        if (obd_ioctl_is_invalid(data)) {
                CERROR("ioctl not correctly formatted\n");
                OBD_FREE_LARGE(*buf, hdr->ioc_len);
                return -EINVAL;
        }

        if (data->ioc_inllen1) {
                data->ioc_inlbuf1 = &data->ioc_bulk[0];
                offset += size_round(data->ioc_inllen1);
        }

        if (data->ioc_inllen2) {
                data->ioc_inlbuf2 = &data->ioc_bulk[0] + offset;
                offset += size_round(data->ioc_inllen2);
        }

        if (data->ioc_inllen3) {
                data->ioc_inlbuf3 = &data->ioc_bulk[0] + offset;
                offset += size_round(data->ioc_inllen3);
        }

        if (data->ioc_inllen4) {
                data->ioc_inlbuf4 = &data->ioc_bulk[0] + offset;
        }

        EXIT;
        return 0;
}

int obd_ioctl_popdata(void *arg, void *data, int len)
{
	/* 
	 * Xnu ioctl copyout(uaddr, arg, sizeof(struct obd_ioctl_data)),
	 * we have to copyout data exceed sizeof(struct obd_ioctl_data)
	 * by ourself.
	 */
	if (len <= sizeof(struct obd_ioctl_data)) {
		memcpy(arg, data, len);
		return 0;
	} else {
		int err;
		struct obd_ioctl_data *u = (struct obd_ioctl_data *)arg;
		struct obd_ioctl_data *k = (struct obd_ioctl_data *)data;
		err = copy_to_user((void *)u->ioc_inlbuf1, &k->ioc_bulk[0],
				    len -((void *)&k->ioc_bulk[0] -(void *)k));
		memcpy(arg, data, sizeof(struct obd_ioctl_data));
		return err;
	}
}

static int
obd_class_open(dev_t dev, int flags, int devtype, struct proc *p)
{
	ENTRY;

	RETURN(0);
}

/*  closing /dev/obd */
static int
obd_class_release(dev_t dev, int flags, int mode, struct proc *p)
{
	ENTRY;

	RETURN(0);
}

static int
obd_class_ioctl(dev_t dev, u_long cmd, caddr_t arg, int flag, struct proc *p)
{
	int err = 0;
	ENTRY;

	if (!is_suser())
		RETURN (EPERM);

	err = class_handle_ioctl(cmd, (unsigned long)arg);

	RETURN(err);
}

static struct cdevsw obd_psdevsw = {
	obd_class_open,
	obd_class_release,
	NULL,
	NULL,
	obd_class_ioctl,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

cfs_psdev_t obd_psdev = {
	-1,
	NULL,
	"obd",
	&obd_psdevsw
};

int class_procfs_init(void)
{
	return 0;
}

int class_procfs_clean(void)
{
	return 0;
}
