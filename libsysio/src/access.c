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
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include "sysio.h"
#include "inode.h"
#include "sysio-symbols.h"

/*
 * Check given access type on given inode.
 */
static int
_sysio_check_permission(struct inode *ino,
			uid_t uid, gid_t gid,
			gid_t gids[], size_t ngids,
			int amode)
{
	mode_t	mask;
	struct intnl_stat *stat;

	/*
	 * Check amode.
	 */
	if ((amode & (R_OK|W_OK|X_OK)) != amode)
		return -EINVAL;

	if (!amode)
		return 0;

	mask = 0;
	if (amode & R_OK)
		mask |= S_IRUSR;
	if (amode & W_OK)
		mask |= S_IWUSR;
	if (amode & X_OK)
		mask |= S_IXUSR;

	stat = &ino->i_stbuf;
	if (stat->st_uid == uid && (stat->st_mode & mask) == mask) 
		return 0;

	mask >>= 3;
	if (stat->st_gid == gid && (stat->st_mode & mask) == mask)
		return 0;

	while (ngids) {
		ngids--;
		if (stat->st_gid == *gids++ && (stat->st_mode & mask) == mask)
			return 0;
	}

	mask >>= 3;
	if ((stat->st_mode & mask) == mask)
		return 0;

	return -EACCES;
}

/*
 * Determine if a given access is permitted to a give file.
 */
int
_sysio_permitted(struct inode *ino, int amode)
{
	int	err;
	gid_t	*gids;
	int	n;
	void	*p;

	err = 0;
	gids = NULL;
	for (;;) {
		n = getgroups(0, NULL);
		if (!n)
			break;
		p = realloc(gids, n * sizeof(gid_t));
		if (!p && gids) {
			err = -ENOMEM;
			break;
		}
		gids = p;
		err = getgroups(n, gids);
		if (err < 0) {
			if (errno == EINVAL)
				continue;
			err = -errno;
			break;
		}
		err =
		    _sysio_check_permission(ino,
					    geteuid(), getegid(),
					    gids, (size_t )n,
					    amode);
		break;
	}
	if (!gids)
		return err;
	free(gids);
	return err;
}

int
SYSIO_INTERFACE_NAME(access)(const char *path, int amode)
{
	struct intent intent;
	int	err;
	struct pnode *pno;

	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;

	INTENT_INIT(&intent, INT_GETATTR, NULL, NULL);
	err = _sysio_namei(_sysio_cwd, path, 0, &intent, &pno);
	if (err)
		SYSIO_INTERFACE_RETURN(-1, err);
	err =
	    _sysio_check_permission(pno->p_base->pb_ino,
				    getuid(), getgid(),
				    NULL, 0,
				    amode);
	P_RELE(pno);
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifdef REDSTORM
#undef __access
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(access),
		     PREPEND(__, SYSIO_INTERFACE_NAME(access)))
#endif
