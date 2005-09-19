#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <liblustre.h>
#include <linux/lustre_lib.h>
#include <linux/obd.h>

int main(int argc, char **argv)
{
    struct obd_ioctl_data data;
    char rawbuf[8192], parent[4096], *buf = rawbuf, *base, *t;
    int max = sizeof(rawbuf), fd, offset, rc;

    if (argc != 2) {
        printf("usage: %s filename\n", argv[0]);
        return 1;
    }

    base = argv[1];
    t = strrchr(base, '/');
    if (!t) {
        strcpy(parent, ".");
        offset = -1;
    } else {
        strncpy(parent, base, t - base);
        offset = t - base - 1;
    }

    fd = open(parent, O_RDONLY);
    if (fd < 0) {
        printf("open(%s) error: %s\n", parent, strerror(errno));
        exit(errno);
    }

    memset(&data, 0, sizeof(data));
    data.ioc_version = OBD_IOCTL_VERSION;
    data.ioc_len = sizeof(data);
    if (offset >= 0)
        data.ioc_inlbuf1 = base + offset + 2;
    else
        data.ioc_inlbuf1 = base;
    data.ioc_inllen1 = strlen(data.ioc_inlbuf1) + 1;
    
    if (obd_ioctl_pack(&data, &buf, max)) {
        printf("ioctl_pack failed.\n");
        exit(1);
    }
    
    rc = ioctl(fd, IOC_MDC_LOOKUP, buf);
    if (rc < 0) {
        printf("ioctl(%s/%s) error: %s\n", parent,
               data.ioc_inlbuf1, strerror(errno));
        exit(errno);
    }

    return 0;
}
