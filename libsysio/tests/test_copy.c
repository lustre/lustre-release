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
#ifndef REDSTORM
#include <getopt.h>
#endif
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/queue.h>

#include "sysio.h"
#include "mount.h"

#include "fs_native.h"

#include "test.h"

/*
 * Copy one file to another.
 *
 * Usage: test_copy [-o] <src> <dest>
 *
 * Destination will not be overwritten if it already exist.
 */

static int overwrite = 0;				/* over-write? */

void	usage(void);
int	copy_file(const char *spath, const char *dpath);

int
main(int argc, char * const argv[])
{
	int	i;
	int	err;
	const char *spath, *dpath;
	extern int _test_sysio_startup(void);

	/*
	 * Parse command-line args.
	 */
	while ((i = getopt(argc,
			   argv,
			   "o"
			   )) != -1)
		switch (i) {

		case 'o':
			overwrite = 1;
			break;
		default:
			usage();
		}

	if (!(argc - optind))
		usage();
	err = _test_sysio_startup();
	if (err) {
		errno = -err;
		perror("sysio startup");
		exit(1);
	}

	/*
	 * Source
	 */
	spath = argv[optind++];
	if (!(argc - optind))
		usage();
	/*
	 * Destination
	 */
	dpath = argv[optind++];
	if (argc - optind)
		usage();

	err = copy_file(spath, dpath);

	_sysio_shutdown();

	return err;
}

void
usage()
{

	(void )fprintf(stderr,
		       "Usage: test_copy "
		       " source destination\n");
	exit(1);
}

int
open_file(const char *path, int flags, mode_t mode)
{
	int	fd;

	fd = open(path, flags, mode);
	if (fd < 0)
		perror(path);

	return fd;
}

int
copy_file(const char *spath, const char *dpath)
{
	int	sfd, dfd;
	int	flags;
	int	rtn;
	static char buf[1024];
	ssize_t	cc, wcc;

	sfd = dfd = -1;
	rtn = -1;

	sfd = open_file(spath, O_RDONLY, 0);
	if (sfd < 0)
		goto out;
	flags = O_CREAT|O_WRONLY;
	if (!overwrite)
		flags |= O_EXCL;
	dfd = open_file(dpath, flags, 0666);
	if (dfd < 0)
		goto out;

	while ((cc = read(sfd, buf, sizeof(buf))) > 0)
		if ((wcc = write(dfd, buf, cc)) != cc) {
			if (wcc < 0) {
				perror(dpath);
				break;
			}
			(void )fprintf(stderr,
				       "%s: short write (%u/%u)\n",
				       dpath,
				       (unsigned )wcc,
				       (unsigned )cc);
			break;
		}
	if (cc < 0)
		perror(spath);

out:
	if (sfd >= 0 && close(sfd) != 0)
		perror(spath);
	if (dfd >= 0 && (fsync(dfd) != 0 || close(dfd) != 0))
		perror(dpath);

	return 0;
}
