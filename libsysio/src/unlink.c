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

#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include "sysio.h"
#include "inode.h"
#include "fs.h"
#include "mount.h"
#include "sysio-symbols.h"

int
SYSIO_INTERFACE_NAME(unlink)(const char *path)
{
	struct intent intent;
	int	err;
	struct pnode *pno;
	struct inode *ino;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	INTENT_INIT(&intent, INT_UPDPARENT, NULL, NULL);
	err = _sysio_namei(_sysio_cwd, path, ND_NOFOLLOW, &intent, &pno);
	if (err)
		goto out;

	err = _sysio_permitted(pno->p_parent, W_OK);
	if (err)
		goto error;

	ino = pno->p_base->pb_ino;
	/*
	 * Use the parent node operations to request the task in case the
	 * driver is implemented using differentiated inode operations based
	 * on file type, such as incore does.
	 */
	err = (*pno->p_parent->p_base->pb_ino->i_ops.inop_unlink)(pno);
	if (err)
		goto error;
	assert(pno->p_base->pb_ino);
	/*
	 * Invalidate the path node.
	 */
	ino = pno->p_base->pb_ino;
	pno->p_base->pb_ino = NULL;
	/*
	 * Kill the i-node. I've thought and thought about this. We
	 * can't allow it to be found via namei any longer because we
	 * can't count on generation numbers support and have no
	 * clue why there might be other soft-references -- Could
	 * be an open file.
	 */
	I_GONE(ino);

error:
	P_RELE(pno);
out:
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

#ifdef REDSTORM
#undef __unlink
sysio_sym_weak_alias(SYSIO_INTERFACE_NAME(unlink),
		     PREPEND(__, SYSIO_INTERFACE_NAME(unlink)))
#endif
