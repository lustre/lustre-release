/*
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 * Copyright (c) 2014, Intel Corporation.
 *
 *   This file is part of Portals, http://www.sf.net/projects/lustre/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define __USE_FILE_OFFSET64

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <libcfs/libcfsutil.h>
#include <lnet/lnetctl.h>

static ioc_handler_t  do_ioctl;                 /* forward ref */
static ioc_handler_t *current_ioc_handler = &do_ioctl;

struct ioc_dev {
        const char * dev_name;
        int dev_fd;
        int dev_major;
        int dev_minor;
};

static struct ioc_dev ioc_dev_list[10];

struct dump_hdr {
        int magic;
        int dev_id;
        unsigned int opc;
};

char *dump_filename;

void
set_ioc_handler (ioc_handler_t *handler)
{
        if (handler == NULL)
                current_ioc_handler = do_ioctl;
        else
                current_ioc_handler = handler;
}

/* Catamount has no <linux/kdev_t.h>, so just define it here */
#ifndef MKDEV
# define MKDEV(a,b) (((a) << 8) | (b))
#endif

static int
open_ioc_dev(int dev_id) 
{
        const char * dev_name;

        if (dev_id < 0 || 
            dev_id >= sizeof(ioc_dev_list) / sizeof(ioc_dev_list[0]))
                return -EINVAL;

        dev_name = ioc_dev_list[dev_id].dev_name;
        if (dev_name == NULL) {
                fprintf(stderr, "unknown device id: %d\n", dev_id);
                return -EINVAL;
        }

        if (ioc_dev_list[dev_id].dev_fd < 0) {
		int fd = open(dev_name, O_RDWR);

		/* Make the /dev/ node if we need to */
		if (fd < 0 && errno == ENOENT) {
			if (mknod(dev_name, S_IFCHR|S_IWUSR|S_IRUSR,
				  MKDEV(ioc_dev_list[dev_id].dev_major,
					ioc_dev_list[dev_id].dev_minor)) == 0)
				fd = open(dev_name, O_RDWR);
                        else
                                fprintf(stderr, "mknod %s failed: %s\n",
                                        dev_name, strerror(errno));
                }

                if (fd < 0) {
                        fprintf(stderr, "opening %s failed: %s\n"
                                "hint: the kernel modules may not be loaded\n",
                                dev_name, strerror(errno));
                        return fd;
                }
                ioc_dev_list[dev_id].dev_fd = fd;
        }

        return ioc_dev_list[dev_id].dev_fd;
}


static int 
do_ioctl(int dev_id, unsigned int opc, void *buf)
{
        int fd, rc;
        
        fd = open_ioc_dev(dev_id);
        if (fd < 0) 
                return fd;

	rc = ioctl(fd, opc, buf);

	return rc;
}

static FILE *
get_dump_file() 
{
        FILE *fp = NULL;
        
        if (!dump_filename) {
                fprintf(stderr, "no dump filename\n");
        } else 
                fp = fopen(dump_filename, "a");
        return fp;
}

/*
 * The dump file should start with a description of which devices are
 * used, but for now it will assumed whatever app reads the file will
 * know what to do. */
int 
dump(int dev_id, unsigned int opc, void *buf)
{
        FILE *fp;
        struct dump_hdr dump_hdr;
        struct libcfs_ioctl_hdr * ioc_hdr = (struct  libcfs_ioctl_hdr *) buf;
        int rc;
        
        printf("dumping opc %x to %s\n", opc, dump_filename);
        

        dump_hdr.magic = 0xdeadbeef;
        dump_hdr.dev_id = dev_id;
        dump_hdr.opc = opc;

        fp = get_dump_file();
        if (fp == NULL) {
                fprintf(stderr, "%s: %s\n", dump_filename, 
                        strerror(errno));
                return -EINVAL;
        }
        
        rc = fwrite(&dump_hdr, sizeof(dump_hdr), 1, fp);
        if (rc == 1)
                rc = fwrite(buf, ioc_hdr->ioc_len, 1, fp);
        fclose(fp);
        if (rc != 1) {
                fprintf(stderr, "%s: %s\n", dump_filename,
                        strerror(errno));
                return -EINVAL;
        }

        return 0;
}

/* register a device to send ioctls to.  */
int 
register_ioc_dev(int dev_id, const char * dev_name, int major, int minor) 
{

        if (dev_id < 0 || 
            dev_id >= sizeof(ioc_dev_list) / sizeof(ioc_dev_list[0]))
                return -EINVAL;

        unregister_ioc_dev(dev_id);

        ioc_dev_list[dev_id].dev_name = dev_name;
        ioc_dev_list[dev_id].dev_fd = -1;
        ioc_dev_list[dev_id].dev_major = major;
        ioc_dev_list[dev_id].dev_minor = minor;
 
        return dev_id;
}

void
unregister_ioc_dev(int dev_id) 
{
	if (dev_id < 0 ||
	    dev_id >= sizeof(ioc_dev_list) / sizeof(ioc_dev_list[0]))
		return;

	if (ioc_dev_list[dev_id].dev_name != NULL &&
	    ioc_dev_list[dev_id].dev_fd >= 0)
		close(ioc_dev_list[dev_id].dev_fd);

	ioc_dev_list[dev_id].dev_name = NULL;
	ioc_dev_list[dev_id].dev_fd = -1;
}

/* If this file is set, then all ioctl buffers will be 
   appended to the file. */
int
set_ioctl_dump(char * file)
{
        if (dump_filename)
                free(dump_filename);
        
        dump_filename = strdup(file);
        if (dump_filename == NULL)
                abort();

        set_ioc_handler(&dump);
        return 0;
}

int
l_ioctl(int dev_id, unsigned int opc, void *buf)
{
        return current_ioc_handler(dev_id, opc, buf);
}

/* Read an ioctl dump file, and call the ioc_func for each ioctl buffer
 * in the file.  For example:
 *
 * parse_dump("lctl.dump", l_ioctl);
 *
 * Note: if using l_ioctl, then you also need to register_ioc_dev() for 
 * each device used in the dump.
 */
int 
parse_dump(char * dump_file, ioc_handler_t ioc_func)
{
        int line =0;
        char *start, *buf, *end;
        struct stat st;
        int fd;

        fd = open(dump_file, O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "couldn't open %s: %s\n", dump_file, 
                        strerror(errno));
                exit(1);
        }

        if (fstat(fd, &st)) { 
                perror("stat fails");
                exit(1);
        }

        if (st.st_size < 1) {
                fprintf(stderr, "KML is empty\n");
                exit(1);
        }

        start = buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE , fd, 0);
        end = start + st.st_size;
        close(fd);
        if (start == MAP_FAILED) {
                fprintf(stderr, "can't create file mapping\n");
                exit(1);
        }

        while (buf < end) {
                struct dump_hdr *dump_hdr = (struct dump_hdr *) buf;
                struct libcfs_ioctl_hdr * data;
                char tmp[8096];
                int rc;

                line++;

                data = (struct libcfs_ioctl_hdr *) (buf + sizeof(*dump_hdr));
                if (buf + data->ioc_len > end ) {
                        fprintf(stderr, "dump file overflow, %p + %d > %p\n", buf,
                                data->ioc_len, end);
                        return -1;
                }
#if 0
                printf ("dump_hdr: %lx data: %lx\n",
                        (unsigned long)dump_hdr - (unsigned long)buf, (unsigned long)data - (unsigned long)buf);

                printf("%d: opcode %x len: %d  ver: %x ", line, dump_hdr->opc,
                       data->ioc_len, data->ioc_version);
#endif

                memcpy(tmp, data, data->ioc_len);

                rc = ioc_func(dump_hdr->dev_id, dump_hdr->opc, tmp);
                if (rc) {
                        printf("failed: %d\n", rc);
                        exit(1);
                }

                buf += data->ioc_len + sizeof(*dump_hdr);
        }

	munmap(start, end - start);

	return 0;
}

int 
jt_ioc_dump(int argc, char **argv)
{
        if (argc > 2) {
                fprintf(stderr, "usage: %s [hostname]\n", argv[0]);
                return 0;
        }
        printf("setting dumpfile to: %s\n", argv[1]);
        
        set_ioctl_dump(argv[1]);
        return 0;
}

int libcfs_ioctl_pack(struct libcfs_ioctl_data *data, char **pbuf,
                                    int max)
{
	char *ptr;
	struct libcfs_ioctl_data *overlay;
	data->ioc_hdr.ioc_len = libcfs_ioctl_packlen(data);
	data->ioc_hdr.ioc_version = LIBCFS_IOCTL_VERSION;

	if (*pbuf != NULL && libcfs_ioctl_packlen(data) > max)
		return 1;
	if (*pbuf == NULL)
		*pbuf = malloc(data->ioc_hdr.ioc_len);
	if (*pbuf == NULL)
		return 1;
	overlay = (struct libcfs_ioctl_data *)*pbuf;
	memcpy(*pbuf, data, sizeof(*data));

	ptr = overlay->ioc_bulk;
	if (data->ioc_inlbuf1 != NULL)
		LOGL(data->ioc_inlbuf1, data->ioc_inllen1, ptr);
	if (data->ioc_inlbuf2 != NULL)
		LOGL(data->ioc_inlbuf2, data->ioc_inllen2, ptr);
	if (libcfs_ioctl_is_invalid(overlay))
		return 1;

	return 0;
}

void
libcfs_ioctl_unpack(struct libcfs_ioctl_data *data, char *pbuf)
{
	struct libcfs_ioctl_data *overlay = (struct libcfs_ioctl_data *)pbuf;
	char *ptr;

	/* Preserve the caller's buffer pointers */
	overlay->ioc_inlbuf1 = data->ioc_inlbuf1;
	overlay->ioc_inlbuf2 = data->ioc_inlbuf2;

	memcpy(data, pbuf, sizeof(*data));
	ptr = &overlay->ioc_bulk[0];

	if (data->ioc_inlbuf1 != NULL)
		LOGU(data->ioc_inlbuf1, data->ioc_inllen1, ptr);
	if (data->ioc_inlbuf2 != NULL)
		LOGU(data->ioc_inlbuf2, data->ioc_inllen2, ptr);
}
