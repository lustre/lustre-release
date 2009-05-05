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
#include "sysio-symbols.h"

int
SYSIO_INTERFACE_NAME(link)(const char *oldpath, const char *newpath)
{
	struct intent intent;
	int	err;
	struct pnode *old, *new;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	INTENT_INIT(&intent, 0, NULL, NULL);
	err = _sysio_namei(_sysio_cwd, oldpath, 0, &intent, &old);
	if (err)
		goto out;
	if (S_ISDIR(old->p_base->pb_ino->i_stbuf.st_mode)) {
		err = -EPERM;
		goto error1;
	}
	INTENT_INIT(&intent, INT_UPDPARENT, NULL, NULL);
	new = NULL;
	err = _sysio_namei(_sysio_cwd, newpath, ND_NEGOK, &intent, &new);
	if (err)
		goto error1;
	if (new->p_base->pb_ino) {
		err = -EEXIST;
		goto error2;
	}
	if (old->p_mount->mnt_root != new->p_mount->mnt_root) {
		err = -EXDEV;
		goto error2;
	}
	/*
	 * Use the parent node operations to request the task in case the
	 * driver is implemented using differentiated inode operations based
	 * on file type, such as incore does.
	 */
	err = old->p_parent->p_base->pb_ino->i_ops.inop_link(old, new);
	if (err)
		goto error2;
	/*
	 * The new p-node must be pointed at the inode referenced by the old.
	 */
	assert(!new->p_base->pb_ino && old->p_base->pb_ino);
	new->p_base->pb_ino = old->p_base->pb_ino;
	I_REF(new->p_base->pb_ino);

error2:
	P_RELE(new);
error1:
	P_RELE(old);
out:
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifdef REDSTORM
#undef __link
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(link), 
		     PREPEND(__, SYSIO_INTERFACE_NAME(link)))
#endif
