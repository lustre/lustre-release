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
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/queue.h>

#include "sysio.h"
#include "mount.h"
#include "inode.h"

int
SYSIO_INTERFACE_NAME(rename)(const char *oldpath, const char *newpath)
{
	struct intent intent;
	int	err;
	struct pnode *old, *new;
	struct pnode_base *nxtpb, *pb;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;

	/*
	 * Neither old nor new may be the empty string.
	 */
	if (*oldpath == '\0' || *newpath == '\0')
		SYSIO_INTERFACE_RETURN(-1, -ENOENT);

	/*
	 * Resolve oldpath to a path node.
	 */
	INTENT_INIT(&intent, INT_UPDPARENT, NULL, NULL);
	err = _sysio_namei(_sysio_cwd, oldpath, ND_NOFOLLOW, &intent, &old);
	if (err)
		goto error3;
	/*
	 * Resolve newpath to a path node.
	 */
	INTENT_INIT(&intent, INT_UPDPARENT, NULL, NULL);
	err =
	    _sysio_namei(_sysio_cwd,
			 newpath,
			 ND_NOFOLLOW | ND_NEGOK,
			 &intent,
			 &new);
	if (err)
		goto error2;

	/*
	 * Don't allow mount points to move.
	 */
	if (old->p_mount->mnt_root == old || old->p_cover ||
	    new->p_mount->mnt_root == new) {
		err = -EBUSY;
		goto error1;
	}

	/*
	 * No xdev renames either.
	 */
	if (old->p_mount->mnt_fs != new->p_mount->mnt_fs) {
		err = -EXDEV;
		goto error1;
	}

	/*
	 * Make sure the old pnode can't be found in the ancestor chain
	 * for the new. If it can, they are trying to move into a subdirectory
	 * of the old.
	 */
	nxtpb = new->p_base;
	do {
		pb = nxtpb;
		nxtpb = pb->pb_parent;
		if (pb == old->p_base) {
			err = -EINVAL;
			goto error1;
		}
	} while (nxtpb);

	/*
	 * If old == new, we're done.
	 */
	if (old->p_base->pb_ino == new->p_base->pb_ino)
		goto short_out;

	if (new->p_base->pb_ino) {
		/*
		 * Existing entry. We're replacing the new. Make sure that's
		 * ok.
		 */
		if (S_ISDIR(new->p_base->pb_ino->i_stbuf.st_mode)) {
			if (!S_ISDIR(old->p_base->pb_ino->i_stbuf.st_mode)) {
				err = -EISDIR;
				goto error1;
			}
			if (new->p_base->pb_ino->i_stbuf.st_nlink > 2) {
				err = -ENOTEMPTY;
				goto error1;
			}
		} else if (S_ISDIR(old->p_base->pb_ino->i_stbuf.st_mode)) {
			err = -ENOTDIR;
			goto error1;
		}
	}

	/*
	 * It's not impossible to clean up the altered name space after
	 * a rename. However, it is onerous and I don't want to do it right
	 * now. If it becomes an issue, we can do it later. For now, I've
	 * elected to use the semantic that says, basically, the entire
	 * sub-tree must be unreferenced. That's per POSIX, but it's a nasty
	 * thing to do to the caller.
	 */
	if (_sysio_p_prune(new) != 1) {
		err = -EBUSY;
		goto error1;
	}
	/*
	 * Use the parent node operations to request the task in case the
	 * driver is implemented using differentiated inode operations based
	 * on file type, such as incore does.
	 */
	err = old->p_parent->p_base->pb_ino->i_ops.inop_rename(old, new);
	if (err)
		goto error1;
	/*
	 * Reflect the successful rename in the active name space graph.
	 */
	if (new->p_base->pb_ino)
		I_GONE(new->p_base->pb_ino);
	new->p_base->pb_ino = old->p_base->pb_ino;
	old->p_base->pb_ino = NULL;

short_out:
error1:
	P_RELE(new);
error2:
	P_RELE(old);
error3:
	if (err)
		goto out;
out:
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}
