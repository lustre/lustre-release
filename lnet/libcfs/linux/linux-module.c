#define DEBUG_SUBSYSTEM S_PORTALS

#include <libcfs/libcfs.h>
#include <libcfs/kp30.h>

#define LNET_MINOR 240


void
libcfs_daemonize (char *str)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,63)) 
	daemonize(str);
#else 
	daemonize(); 
	snprintf (current->comm, sizeof (current->comm), "%s", str);
#endif
}

void
libcfs_blockallsigs ()
{ 
	unsigned long  flags; 
	
	SIGNAL_MASK_LOCK(current, flags); 
	sigfillset(&current->blocked); 
	RECALC_SIGPENDING; 
	SIGNAL_MASK_UNLOCK(current, flags);
}

int portal_ioctl_getdata(char *buf, char *end, void *arg)
{
        struct portal_ioctl_hdr *hdr;
        struct portal_ioctl_data *data;
        int err;
        ENTRY;

        hdr = (struct portal_ioctl_hdr *)buf;
        data = (struct portal_ioctl_data *)buf;

        err = copy_from_user(buf, (void *)arg, sizeof(*hdr));
        if (err)
                RETURN(err);

        if (hdr->ioc_version != PORTAL_IOCTL_VERSION) {
                CERROR("PORTALS: version mismatch kernel vs application\n");
                RETURN(-EINVAL);
        }

        if (hdr->ioc_len + buf >= end) {
                CERROR("PORTALS: user buffer exceeds kernel buffer\n");
                RETURN(-EINVAL);
        }


        if (hdr->ioc_len < sizeof(struct portal_ioctl_data)) {
                CERROR("PORTALS: user buffer too small for ioctl\n");
                RETURN(-EINVAL);
        }

        err = copy_from_user(buf, (void *)arg, hdr->ioc_len);
        if (err)
                RETURN(err);

        if (portal_ioctl_is_invalid(data)) {
                CERROR("PORTALS: ioctl not correctly formatted\n");
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
libcfs_psdev_open(struct inode * inode, struct file * file)
{ 
	struct portals_device_userstate **pdu = NULL;
	int    rc = 0;

	if (!inode) 
		return (-EINVAL);
	pdu = (struct portals_device_userstate **)&file->private_data;
	if (libcfs_psdev_ops.p_open != NULL)
		rc = libcfs_psdev_ops.p_open(0, (void *)pdu);
	else
		return (-EPERM);
	return rc;
}

/* called when closing /dev/device */
static int 
libcfs_psdev_release(struct inode * inode, struct file * file)
{
	struct portals_device_userstate *pdu;
	int    rc = 0;

	if (!inode) 
		return (-EINVAL);
	pdu = file->private_data;
	if (libcfs_psdev_ops.p_close != NULL)
		rc = libcfs_psdev_ops.p_close(0, (void *)pdu);
	else
		rc = -EPERM;
	return rc;
}

static int 
libcfs_ioctl(struct inode *inode, struct file *file, 
	     unsigned int cmd, unsigned long arg)
{ 
	struct cfs_psdev_file	 pfile;
	int    rc = 0;

	if (current->fsuid != 0) 
		return -EACCES; 
	
	if ( _IOC_TYPE(cmd) != IOC_PORTAL_TYPE || 
	     _IOC_NR(cmd) < IOC_PORTAL_MIN_NR  || 
	     _IOC_NR(cmd) > IOC_PORTAL_MAX_NR ) { 
		CDEBUG(D_IOCTL, "invalid ioctl ( type %d, nr %d, size %d )\n", 
		       _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd)); 
		return (-EINVAL); 
	} 
	
	/* Handle platform-dependent IOC requests */
	switch (cmd) { 
	case IOC_PORTAL_PANIC: 
		if (!capable (CAP_SYS_BOOT)) 
			return (-EPERM); 
		panic("debugctl-invoked panic"); 
		return (0);
	case IOC_PORTAL_MEMHOG: 
		if (!capable (CAP_SYS_ADMIN)) 
			return -EPERM;
		/* go thought */
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
	ioctl:   libcfs_ioctl, 
	open:    libcfs_psdev_open, 
	release: libcfs_psdev_release
};

cfs_psdev_t libcfs_dev = { 
	LNET_MINOR, 
	"lnet", 
	&libcfs_fops
};

EXPORT_SYMBOL(libcfs_blockallsigs);
EXPORT_SYMBOL(libcfs_daemonize);


