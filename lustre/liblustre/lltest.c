/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light user test program
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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
 */

#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <sys/statvfs.h>

#include <sysio.h>
#include <mount.h>


int do_stat(const char *name)
{
	struct stat stat;

	if (lstat(name, &stat)) {
		perror("failed to stat: ");
		return -1;
	}
	printf("******* stat '%s' ********\n", name);
	printf("ino:\t\t%lu\n",stat.st_ino);
	printf("mode:\t\t%o\n",stat.st_mode);
	printf("nlink:\t\t%d\n",stat.st_nlink);
        printf("uid/gid:\t%d/%d\n", stat.st_uid, stat.st_gid);
        printf("size:\t\t%ld\n", stat.st_size);
        printf("blksize:\t%ld\n", stat.st_blksize);
        printf("block count:\t%ld\n", stat.st_blocks);
	printf("atime:\t\t%lu\n",stat.st_atime);
	printf("mtime:\t\t%lu\n",stat.st_mtime);
	printf("ctime:\t\t%lu\n",stat.st_ctime);
	printf("******* end stat ********\n");

	return 0;
}
/*
 * Get stats of file and file system.
 *
 * Usage: test_stats [-a] [-r <root-path>] [-m <root-driver>] [<path> ...]
 */

extern int lllib_init(char *arg);

char	*root_driver = "llite";
char	*root_path = "/";
unsigned mntflgs = 0;
struct mount root_mount;

extern int portal_debug;
extern int portal_subsystem_debug;

char* files[] = {"/dir1", "/dir1/file1", "/dir1/file2", "/dir1/dir2", "/dir1/dir2/file3"};

int
main(int argc, char * const argv[])
{
	struct stat statbuf;
	int rc, err, i, fd, written, readed;
	char pgbuf[4096], readbuf[4096];
	int npages;

	if (_sysio_init() != 0) {
		perror("init sysio");
		exit(1);
	}
	err = lllib_init(argv[1]);
	if (err) {
		perror("init llite driver");
		exit(1);
	}	

	err = _sysio_mount_root(root_path, root_driver, mntflgs, NULL);
	if (err) {
		errno = -err;
		perror(root_driver);
		exit(1);
	}
#if 0
	for (i=0; i< sizeof(files)/sizeof(char*); i++) {
		printf("******** stat %s *********\n", files[i]);
		/* XXX ugly, only for testing */
		err = fixme_lstat(files[i], &statbuf);
		if (err)
			perror(root_driver);
		printf("******** end stat %s: %d*********\n", files[i], err);
	}
#endif
#if 0
	portal_debug = 0;
	portal_subsystem_debug = 0;
	npages = 10;

	fd = open("/newfile01", O_RDWR|O_CREAT|O_TRUNC, 00664);
	printf("***************** open return %d ****************\n", fd);

	printf("***************** begin write pages ****************\n");
	for (i = 0; i < npages; i++ ) {
		memset(pgbuf, ('A'+ i%10), 4096);
		written = write(fd, pgbuf, 4096);
		printf(">>> page %d: %d bytes written\n", i, written);
	}

	printf("***************** begin read pages ****************\n");
	lseek(fd, 0, SEEK_SET);

	for (i = 0; i < npages; i++ ) {
		memset(readbuf, '8', 4096);
		readed = read(fd, readbuf, 4096);
		readbuf[10] = 0;
		printf("<<< page %d: %d bytes (%s)\n", i, readed, readbuf);
	}
        close(fd);
#endif

#if 1
        //rc = chown("/newfile01", 10, 20);
        rc = chmod("/newfile01", 0777);
        printf("-------------- chmod return %d -----------\n", rc);
        do_stat("/newfile01");
#endif

	printf("sysio is about shutdown\n");
	/*
	 * Clean up.
	 */
	_sysio_shutdown();

	printf("complete successfully\n");
	return 0;
}
