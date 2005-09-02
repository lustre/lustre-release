#include <mach/mach_types.h>
#include <string.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>

#define DEBUG_SUBSYSTEM S_PORTALS
#include <libcfs/libcfs.h>
#include <libcfs/kp30.h>

int portal_ioctl_getdata(char *buf, char *end, void *arg)
{
        struct portal_ioctl_hdr *hdr;
        struct portal_ioctl_data *data;
        int err = 0;
        ENTRY;

        hdr = (struct portal_ioctl_hdr *)buf; 
        data = (struct portal_ioctl_data *)buf;
	/* portals_ioctl_data has been copied in by ioctl of osx */
	memcpy(buf, arg, sizeof(struct portal_ioctl_data));

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
	buf += size_round(sizeof(*data));

        if (data->ioc_inllen1) { 
                err = copy_from_user(buf, data->ioc_inlbuf1, size_round(data->ioc_inllen1)); 
		if (err)
			RETURN(err);
                data->ioc_inlbuf1 = buf; 
                buf += size_round(data->ioc_inllen1); 
        } 
        
        if (data->ioc_inllen2) { 
                copy_from_user(buf, data->ioc_inlbuf2, size_round(data->ioc_inllen2)); 
		if (err)
			RETURN(err);
                data->ioc_inlbuf2 = buf; 
        } 

        RETURN(err);
}

extern struct cfs_psdev_ops		libcfs_psdev_ops;
struct portals_device_userstate		*mdev_state[16];

static int 
libcfs_psdev_open(dev_t dev, int flags, int devtype, struct proc *p)
{ 
	struct	portals_device_userstate *mstat = NULL;
	int	rc = 0;
	int	devid; 
	devid = minor(dev);    

	if (devid > 16) return (-ENXIO);

	if (libcfs_psdev_ops.p_open != NULL)
		rc = libcfs_psdev_ops.p_open(0, &mstat);
	else
		rc = -EPERM;
	if (!rc)
		return rc;
	mdev_state[devid] = mstat;
	return rc;
}

static int 
libcfs_psdev_close(dev_t dev, int flags, int mode, struct proc *p)
{
	int	devid; 
	devid = minor(dev);    
	int	rc = 0;

	if (devid > 16) return (-ENXIO);

	if (libcfs_psdev_ops.p_close != NULL)
		rc = libcfs_psdev_ops.p_close(0, mdev_state[devid]);
	else
		rc = -EPERM;
	if (rc)
		return rc;
	mdev_state[devid] = NULL;
	return rc;
}

static int 
libcfs_ioctl (dev_t dev, u_long cmd, caddr_t arg, int flag, struct proc *p)
{ 
	int rc = 0; 
        struct cfs_psdev_file    pfile; 
	int     devid; 
	devid = minor(dev); 
	
	if (devid > 16) return (-ENXIO);

	if (suser(p->p_ucred, &p->p_acflag)) 
		return (-EPERM); 
	
	pfile.off = 0;
	pfile.private_data = mdev_state[devid];

	if (libcfs_psdev_ops.p_ioctl != NULL) 
		rc = libcfs_psdev_ops.p_ioctl(&pfile, cmd, (void *)arg);
	else 
		rc = -EPERM;
	return rc;
}

static struct cdevsw libcfs_devsw =
{ 
	libcfs_psdev_open,            /* open */ 
	libcfs_psdev_close,           /* close */ 
	NULL,			/* read */ 
	NULL,			/* write */ 
	libcfs_ioctl,		/* ioctl */ 
	NULL,			/* stop */ 
	NULL,			/* reset */ 
	NULL,			/* tty's */ 
	NULL,			/* select */ 
	NULL,			/* mmap */ 
	NULL,			/* strategy */ 
	NULL,			/* getc */ 
	NULL,			/* putc */ 
	0			/* type */ 
};

cfs_psdev_t libcfs_dev = { 
	-1, 
	NULL, 
	"portals", 
	&libcfs_devsw, 
	NULL
};

void
libcfs_daemonize (char *str)
{
	printf("Daemonize request: %s.\n", str);
	return;
}

void 
libcfs_blockallsigs(void)
{
	return;
}
