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
 *    Cplant(TM) Copyright 1998-2006 Sandia Corporation. 
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
#include "mount.h"
#include "fs.h"
#include "inode.h"
#include "sysio-symbols.h"

/*
 * Use a persistent buffer for gids. No, not a cache. We just want to
 * avoid calling malloc over, and over, and...
 */
static gid_t *gids = NULL;
static int gidslen = 0;

/*
 * Check given access type on given inode.
 */
int
_sysio_check_permission(struct pnode *pno, struct creds *crp, int amode)
{
	mode_t	mask;
	struct inode *ino;
	int	err;
	struct intnl_stat *stat;
	gid_t	*gids;
	int	ngids;
	int	group_matched;

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

	ino = pno->p_base->pb_ino;
	assert(ino);

	err = -EACCES;					/* assume error */
	stat = &ino->i_stbuf;
	do {
#ifdef _SYSIO_ROOT_UID
		/*
		 * Root?
		 */
		if (_sysio_is_root(crp)) {
			err = 0;
			break;
		}
#endif

		/*
		 * Owner?
		 */
		if (stat->st_uid == crp->creds_uid) {
			if ((stat->st_mode & mask) == mask)
				err = 0;
			break;
		}

		/*
		 * Group?
		 */
		mask >>= 3;
		group_matched = 0;
		gids = crp->creds_gids;
		ngids = crp->creds_ngids;
		while (ngids) {
			ngids--;
			if (stat->st_gid == *gids++) {
				group_matched = 1;
				if ((stat->st_mode & mask) == mask)
					err = 0;
			}
		}
		if (group_matched)
			break;

		/*
		 * Other?
		 */
		mask >>= 3;
		if ((stat->st_mode & mask) == mask)
			err = 0;
	} while (0);
	if (err)
		return err;

	/*
	 * Check for RO access to the file due to mount
	 * options.
	 */
	if (amode & W_OK && IS_RDONLY(pno))
		return -EROFS;

	return 0;
}

/*
 * Cache groups.
 */
static int
_sysio_ldgroups(gid_t gid0, gid_t **gidsp, int *gidslenp)
{
	int	n, i;
	void	*p;

	n = *gidslenp;
	if (n < 8) {
		*gidsp = NULL;
		n = 8;
	}
	for (;;) {
		/*
		 * This is far more expensive than I would like. Each time
		 * called it has to go to some length to acquire the
		 * current uid and groups membership. We can't just cache
		 * the result, either. The caller could have altered something
		 * asynchronously. Wish we had easy access to this info.
		 */
		if (n > *gidslenp) {
			p = realloc(*gidsp, (size_t )n * sizeof(gid_t));
			if (!p)
				return -errno;
			*gidsp = p;
			*gidslenp = n;
		}
		(*gidsp)[0] = gid0;
		i = getgroups(n - 1, *gidsp + 1);
		if (i < 0) {
			if (errno != EINVAL)
				return -errno;
			if (INT_MAX / 2 < n)
				return -EINVAL;
			n *= 2;
			continue;
		}
		break;
	}
	return i;
}

/*
 * Get current credentials.
 */
static int
_sysio_ldcreds(uid_t uid, gid_t gid, struct creds *crp)
{
	int	n;

	n = _sysio_ldgroups(gid, &gids, &gidslen);
	if (n < 0)
		return n;
	crp->creds_uid = uid;
	crp->creds_gids = gids;
	crp->creds_ngids = n;

	return 0;
}

static int
_sysio_getcreds(struct creds *crp)
{

	return _sysio_ldcreds(getuid(), getgid(), crp);
}

/*
 * Determine if a given access is permitted to a given file.
 */
int
_sysio_permitted(struct pnode *pno, int amode)
{
	struct creds cr;
	int	err;

	err = _sysio_ldcreds(geteuid(), getegid(), &cr);
	if (err < 0)
		return err;
	err = _sysio_check_permission(pno, &cr, amode);
	return err;
}

#ifdef ZERO_SUM_MEMORY
/*
 * Clean up persistent resource on shutdown.
 */
void
_sysio_access_shutdown()
{

	if (gids)
		free(gids);
	gids = NULL;
	gidslen = 0;
}
#endif

int
SYSIO_INTERFACE_NAME(access)(const char *path, int amode)
{
	struct intent intent;
	int	err;
	struct pnode *pno;
	struct creds cr;

	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;

	INTENT_INIT(&intent, INT_GETATTR, NULL, NULL);
	err = _sysio_namei(_sysio_cwd, path, 0, &intent, &pno);
	if (err)
		SYSIO_INTERFACE_RETURN(-1, err);
	err = _sysio_ldcreds(geteuid(), getegid(), &cr);
	if (err < 0)
		goto out;
	err =
	    _sysio_check_permission(pno, &cr, amode);
out:
	P_RELE(pno);
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifdef REDSTORM
#undef __access
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(access),
		     PREPEND(__, SYSIO_INTERFACE_NAME(access)))
#endif
