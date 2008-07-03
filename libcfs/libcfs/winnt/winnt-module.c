/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *
 *  Copyright (c) 2004 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or modify it under
 *   the terms of version 2 of the GNU General Public License as published by
 *   the Free Software Foundation. Lustre is distributed in the hope that it
 *   will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details. You should have received a
 *   copy of the GNU General Public License along with Lustre; if not, write
 *   to the Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139,
 *   USA.
 */


#define DEBUG_SUBSYSTEM S_LIBCFS

#include <libcfs/libcfs.h>

#define LIBCFS_MINOR 240

int libcfs_ioctl_getdata(char *buf, char *end, void *arg)
{
        struct libcfs_ioctl_hdr *hdr;
        struct libcfs_ioctl_data *data;
        int err;
        ENTRY;

        hdr = (struct libcfs_ioctl_hdr *)buf;
        data = (struct libcfs_ioctl_data *)buf;

        err = copy_from_user(buf, (void *)arg, sizeof(*hdr));
        if (err)
                RETURN(err);

        if (hdr->ioc_version != LIBCFS_IOCTL_VERSION) {
                CERROR(("LIBCFS: version mismatch kernel vs application\n"));
                RETURN(-EINVAL);
        }

        if (hdr->ioc_len + buf >= end) {
                CERROR(("LIBCFS: user buffer exceeds kernel buffer\n"));
                RETURN(-EINVAL);
        }

        if (hdr->ioc_len < sizeof(struct libcfs_ioctl_data)) {
                CERROR(("LIBCFS: user buffer too small for ioctl\n"));
                RETURN(-EINVAL);
        }

        err = copy_from_user(buf, (void *)arg, hdr->ioc_len);
        if (err)
                RETURN(err);

        if (libcfs_ioctl_is_invalid(data)) {
                CERROR(("LIBCFS: ioctl not correctly formatted\n"));
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen1)
                data->ioc_inlbuf1 = &data->ioc_bulk[0];

        if (data->ioc_inllen2)
                data->ioc_inlbuf2 = &data->ioc_bulk[0] +
                        size_round(data->ioc_inllen1);

        RETURN(0);
}
                                                                                                                                                                        
extern struct cfs_psdev_ops          libcfs_psdev_ops;

static int 
libcfs_psdev_open(cfs_file_t * file)
{ 
	struct libcfs_device_userstate **pdu = NULL;
	int    rc = 0;

	pdu = (struct libcfs_device_userstate **)&file->private_data;
	if (libcfs_psdev_ops.p_open != NULL)
		rc = libcfs_psdev_ops.p_open(0, (void *)pdu);
	else
		return (-EPERM);
	return rc;
}

/* called when closing /dev/device */
static int 
libcfs_psdev_release(cfs_file_t * file)
{
	struct libcfss_device_userstate *pdu;
	int    rc = 0;

	pdu = file->private_data;
	if (libcfs_psdev_ops.p_close != NULL)
		rc = libcfs_psdev_ops.p_close(0, (void *)pdu);
	else
		rc = -EPERM;
	return rc;
}

static int 
libcfs_ioctl(cfs_file_t * file, unsigned int cmd, ulong_ptr arg)
{ 
	struct cfs_psdev_file	 pfile;
	int    rc = 0;

	if ( _IOC_TYPE(cmd) != IOC_LIBCFS_TYPE || 
	     _IOC_NR(cmd) < IOC_LIBCFS_MIN_NR  || 
	     _IOC_NR(cmd) > IOC_LIBCFS_MAX_NR ) { 
		CDEBUG(D_IOCTL, ("invalid ioctl ( type %d, nr %d, size %d )\n", 
		       _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd))); 
		return (-EINVAL); 
	} 
	
	/* Handle platform-dependent IOC requests */
	switch (cmd) { 
	case IOC_LIBCFS_PANIC: 
		if (!capable (CAP_SYS_BOOT)) 
			return (-EPERM); 
		CERROR(("debugctl-invoked panic"));
        KeBugCheckEx('LUFS', (ULONG_PTR)libcfs_ioctl, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)NULL);

		return (0);
	case IOC_LIBCFS_MEMHOG:

		if (!capable (CAP_SYS_ADMIN)) 
			return -EPERM;
        break;
	}

	pfile.off = 0;
	pfile.private_data = file->private_data;
	if (libcfs_psdev_ops.p_ioctl != NULL) 
		rc = libcfs_psdev_ops.p_ioctl(&pfile, cmd, (void *)arg); 
	else
		rc = -EPERM;
	return (rc);
}

static struct file_operations libcfs_fops = {
    /* lseek: */  NULL,
    /* read: */   NULL,
    /* write: */  NULL,
    /* ioctl: */  libcfs_ioctl,
    /* open: */   libcfs_psdev_open,
    /* release:*/ libcfs_psdev_release
};

cfs_psdev_t libcfs_dev = { 
	LIBCFS_MINOR, 
	"lnet", 
	&libcfs_fops
};

