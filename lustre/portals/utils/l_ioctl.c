/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <unistd.h>

#include <portals/api-support.h>
#include <portals/ptlctl.h>

struct ioc_dev {
	const char * dev_name;
	int dev_fd;
};

static struct ioc_dev ioc_dev_list[10];

struct dump_hdr {
	int magic;
	int dev_id;
	int opc;
};

char * dump_filename;

static int
open_ioc_dev(int dev_id) 
{
	const char * dev_name;

	if (dev_id < 0 || dev_id >= sizeof(ioc_dev_list))
		return -EINVAL;

	dev_name = ioc_dev_list[dev_id].dev_name;
	if (dev_name == NULL) {
                fprintf(stderr, "unknown device id: %d\n", dev_id);
		return -EINVAL;
	}

	if (ioc_dev_list[dev_id].dev_fd < 0) {
		int fd = open(dev_name, O_RDWR);
		
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
do_ioctl(int dev_id, int opc, void *buf)
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
dump(int dev_id, int opc, void *buf)
{
	FILE *fp;
	struct dump_hdr dump_hdr;
	struct portal_ioctl_hdr * ioc_hdr = (struct  portal_ioctl_hdr *) buf;
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
register_ioc_dev(int dev_id, const char * dev_name) 
{

	if (dev_id < 0 || dev_id >= sizeof(ioc_dev_list))
		return -EINVAL;

	unregister_ioc_dev(dev_id);

	ioc_dev_list[dev_id].dev_name = dev_name;
	ioc_dev_list[dev_id].dev_fd = -1;

	return dev_id;
}

void
unregister_ioc_dev(int dev_id) 
{

	if (dev_id < 0 || dev_id >= sizeof(ioc_dev_list))
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
	return 0;
}

int
l_ioctl(int dev_id, int opc, void *buf)
{
	if (dump_filename) 
		return dump(dev_id, opc, buf);
	else 
		return do_ioctl(dev_id, opc, buf);
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
parse_dump(char * dump_file, int (*ioc_func)(int dev_id, int opc, void *))
{
	int fd, line =0;
	struct stat st;
	char *buf, *end;
	
	fd = syscall(SYS_open, dump_file, O_RDONLY);

#warning FIXME: cleanup fstat issue here
#ifndef SYS_fstat64
#define __SYS_fstat__ SYS_fstat
#else
#define __SYS_fstat__ SYS_fstat64
#endif
	if (syscall(__SYS_fstat__, fd, &st)) { 
		perror("stat fails");
		exit(1);
	}

	if (st.st_size < 1) {
		fprintf(stderr, "KML is empty\n");
		exit(1);
	}

	buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE , fd, 0);
	end = buf + st.st_size;
	close(fd);
	while (buf < end) {
		struct dump_hdr *dump_hdr = (struct dump_hdr *) buf;
		struct portal_ioctl_hdr * data;
		char tmp[8096];
		int rc;
		
		line++;

		data = (struct portal_ioctl_hdr *) (buf + sizeof(*dump_hdr));
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
