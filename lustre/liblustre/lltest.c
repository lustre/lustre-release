/*
 *    This Cplant(TM) source code is the property of Sandia National
 *    Laboratories.
 *
 *    This Cplant(TM) source code is copyrighted by Sandia National
 *    Laboratories.
 *
 *    The redistribution of this Cplant(TM) source code is subject to the
 *    terms of the GNU Lesser General Public License
 *    (see cit/LGPL or http://www.gnu.org/licenses/lgpl.html)
 *
 *    Cplant(TM) Copyright 1998-2003 Sandia Corporation. 
 *    Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 *    license for use of this work by or on behalf of the US Government.
 *    Export of this program may require a license from the United States
 *    Government.
 */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * Questions or comments about this library should be sent to:
 *
 * Lee Ward
 * Sandia National Laboratories, New Mexico
 * P.O. Box 5800
 * Albuquerque, NM 87185-1110
 *
 * lee@sandia.gov
 */

#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <sys/statvfs.h>

#include <sysio.h>
#include <mount.h>

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
	int	err, i, fd, written, read;
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
#if 1
	portal_debug = 0;
	portal_subsystem_debug = 0;
	npages = 1024;

	fd = fixme_open("/newfile3", O_RDWR|O_CREAT|O_TRUNC, 00664);
	printf("***************** open return %d ****************\n", fd);

	printf("***************** begin write pages ****************\n");
	for (i = 0; i < npages; i++ ) {
		memset(pgbuf, ('A'+ i%10), 4096);
		written = fixme_write(fd, pgbuf, 4096);
		printf(">>> page %d: %d bytes written\n", i, written);
	}

	printf("***************** begin read pages ****************\n");
	fixme_lseek(fd, 0, SEEK_SET);

	for (i = 0; i < npages; i++ ) {
		memset(readbuf, '8', 4096);
		read = fixme_read(fd, readbuf, 4096);
		readbuf[10] = 0;
		printf("<<< page %d: %d bytes (%s)", i, read, readbuf);
	}
#endif
	printf("sysio is about shutdown\n");
	/*
	 * Clean up.
	 */
	_sysio_shutdown();

	return 0;
}
