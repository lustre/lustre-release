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

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include "sysio.h"
#include "sysio-symbols.h"

int
SYSIO_INTERFACE_NAME(access)(const char *path, int amode)
{
	gid_t	*list, *entry;
	size_t	n;
	int	err = 0;
	unsigned mask, mode;
	struct stat stbuf;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	err = 0;

	/*
	 * Check amode.
	 */
	if ((amode & (R_OK|W_OK|X_OK)) != amode)
		SYSIO_INTERFACE_RETURN(-1, -EINVAL);

	n = getgroups(0, NULL);
	list = NULL;
	if (n) {
		list = malloc(n * sizeof(gid_t));
		if (!list) {
			err = -ENOMEM;
			goto out;
		}
	}
	err = getgroups(n, list);
	if (err != (int ) n)
		goto out;

	err = SYSIO_INTERFACE_NAME(stat)(path, &stbuf);
	if (err) {
		err = -errno;
		goto out;
	}
	if (!amode)
		SYSIO_INTERFACE_RETURN(0, 0);


	mask = 0;
	if (amode & R_OK)
		mask |= S_IRUSR;
	if (amode & W_OK)
		mask |= S_IWUSR;
	if (amode & X_OK)
		mask |= S_IXUSR;

	mode = stbuf.st_mode;
	if (stbuf.st_uid == getuid() && (mode & mask) == mask) 
		goto out;

	mask >>= 3;
	if (stbuf.st_gid == getgid() && (mode & mask) == mask)
		goto out;

	entry = list;
	while (n--)
		if (stbuf.st_gid == *entry++ && (mode & mask) == mask)
			goto out;

	mask >>= 3;
	if ((mode & mask) == mask)
		goto out;

	err = -EACCES;

out:
	if (list)
		free(list);

	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifdef REDSTORM
#undef __access
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(access),
		     PREPEND(__, SYSIO_INTERFACE_NAME(access)))
#endif
