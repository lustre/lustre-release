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
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include "sysio.h"
#include "mount.h"
#include "inode.h"

/*
 * Parse next component in path.
 */
#ifndef AUTOMOUNT_FILE_NAME
static
#endif
void
_sysio_next_component(const char *path, struct qstr *name)
{
	while (*path == PATH_SEPARATOR)
		path++;
	name->name = path;
	name->len = 0;
	name->hashval = 0;
	while (*path && *path != PATH_SEPARATOR) {
		name->hashval =
		    37 * name->hashval + *path++;
		name->len++;
	}
}

/*
 * Given parent, look up component.
 */
static int
lookup(struct pnode *parent,
       struct qstr *name,
       struct pnode **pnop,
       struct intent *intnt,
       const char *path,
       int check_permissions)
{
	int	err;
	struct pnode *pno;

	if (!parent->p_base->pb_ino)
		return -ENOTDIR;

	/*
	 * Sometimes we don't want to check permissions. At initialization
	 * time, for instance.
	 */
	if (check_permissions) {
		err = _sysio_permitted(parent, X_OK);
		if (err)
			return err;
	}

	/*
	 * Short-circuit `.' and `..'; We don't cache those.
	 */
	pno = NULL;
	if (name->len == 1 && name->name[0] == '.')
		pno = parent;
	else if (name->len == 2 && name->name[0] == '.' && name->name[1] == '.')
		pno = parent->p_parent;
	if (pno)
		P_REF(pno);
	else {
		/*
		 * Get cache entry then.
		 */
		err = _sysio_p_find_alias(parent, name, &pno);
		if (err)
			return err;
	}

	/*
	 * While covered, move to the covering node.
	 */
	while (pno->p_cover && pno->p_cover != pno) {
		struct pnode *cover;

		cover = pno->p_cover;
		P_REF(cover);
		P_RELE(pno);
		pno = cover;
	}

	*pnop = pno;

	/*
	 * (Re)validate the pnode.
	 */
	err = _sysio_p_validate(pno, intnt, path);
	if (err)
		return err;

	return 0;
}

/*
 * The meat. Walk an absolute or relative path, looking up each
 * component. Various flags in the nameidata argument govern actions
 * and return values/state. They are:
 *
 * ND_NOFOLLOW		symbolic links are not followed
 * ND_NEGOK		if terminal/leaf does not exist, return
 * 			 path node (alias) anyway.
 * ND_NOPERMCHECK	do not check permissions
 */
int
_sysio_path_walk(struct pnode *parent, struct nameidata *nd)
{
	int	err;
	const char *path;
	struct qstr this, next;
	struct inode *ino;

	/*
	 * NULL path?
	 */
	if (!nd->nd_path)
		return -EFAULT;

	/*
	 * Empty path?
	 */
	if (!*nd->nd_path)
		return -ENOENT;

	/*
	 * Leading slash?
	 */
	if (*nd->nd_path == PATH_SEPARATOR) {
		/*
		 * Make parent the root of the name space.
		 */
		parent = nd->nd_root;
	}

#ifdef DEFER_INIT_CWD
	if (!parent) {
		const char *icwd;

		if (!_sysio_init_cwd && !nd->nd_root)
			abort();

		/*
		 * Finally have to set the current working directory. We can
		 * not tolerate errors here or else risk leaving the process
		 * in a very unexpected location. We abort then unless all goes
		 * well.
		 */
		icwd = _sysio_init_cwd;
		_sysio_init_cwd = NULL;
		parent = nd->nd_root;
		if (!parent)
			abort();
		(void )_sysio_namei(nd->nd_root, icwd, 0, NULL, &parent);
		if (_sysio_p_chdir(parent) != 0)
			abort();
	}
#endif

	/*
	 * (Re)Validate the parent.
	 */
	err = _sysio_p_validate(parent, NULL, NULL);
	if (err)
		return err;

	/*
	 * Prime everything for the loop. Will need another reference to the
	 * initial directory. It'll be dropped later.
	 */
	nd->nd_pno = parent;
	P_REF(nd->nd_pno);
	_sysio_next_component(nd->nd_path, &next);
	path = next.name;
	parent = NULL;
	err = 0;

	/*
	 * Derecurse the path tree-walk.
	 */
	for (;;) {
		ino = nd->nd_pno->p_base->pb_ino;
		if (S_ISLNK(ino->i_stbuf.st_mode) &&
		    (next.len || !(nd->nd_flags & ND_NOFOLLOW))) {
			char	*lpath;
			ssize_t	cc;
			struct nameidata nameidata;

			if (nd->nd_slicnt >= MAX_SYMLINK) {
				err = -ELOOP;
				break;
			}

			/*
			 * Follow symbolic link.
			 */
			lpath = malloc(MAXPATHLEN + 1);
			if (!lpath) {
				err = -ENOMEM;
				break;
			}
			cc =
			    ino->i_ops.inop_readlink(nd->nd_pno,
						     lpath,
						     MAXPATHLEN);
			if (cc < 0) {
				free(lpath);
				err = (int )cc;
				break;
			}
			lpath[cc] = '\0';			/* NUL term */
			/*
			 * Handle symbolic links with recursion. Yuck!
			 * Pass the NULL intent for recursive symlink
			 * except the last component.
			 */
			ND_INIT(&nameidata,
				nd->nd_flags,
				lpath,
				nd->nd_root,
				!next.len ? nd->nd_intent : NULL);
			nameidata.nd_slicnt = nd->nd_slicnt + 1;
			err =
			    _sysio_path_walk(nd->nd_pno->p_parent, &nameidata);
			free(lpath);
			if (err)
				break;
			P_RELE(nd->nd_pno);
			nd->nd_pno = nameidata.nd_pno;
			ino = nd->nd_pno->p_base->pb_ino;
		}
#ifdef AUTOMOUNT_FILE_NAME
		else if (ino &&
			 S_ISDIR(ino->i_stbuf.st_mode) &&
			 (nd->nd_pno->p_mount->mnt_flags & MOUNT_F_AUTO) &&
			 nd->nd_amcnt < MAX_MOUNT_DEPTH &&
			 ino->i_stbuf.st_mode & S_ISUID) {
			struct pnode *pno;

			/*
			 * We're committed to a lookup. It's time to see if
			 * we're going to do it in an automount-point and
			 * arrange the mount if so.
			 */
			assert(!nd->nd_pno->p_cover);
			err =
			    lookup(nd->nd_pno,
				   &_sysio_mount_file_name,
				   &pno,
				   NULL,
				   NULL,
				   1);
			if (pno)
				P_RELE(pno);
			if (!err && _sysio_automount(pno) == 0) {
				struct pnode *root;

				/*
				 * All went well. Need to switch
				 * parent pno and ino to the
				 * root of the newly mounted sub-tree.
				 *
				 * NB:
				 * We don't recurseively retry these
				 * things. It's OK to have the new root
				 * be an automount-point but it's going
				 * to take another lookup to accomplish it.
				 * The alternative could get us into an
				 * infinite loop.
				 */
				root = nd->nd_pno->p_cover;
				assert(root);
				P_RELE(nd->nd_pno);
				nd->nd_pno = root;
#if 0
				P_REF(nd->nd_pno);
#endif
				ino = nd->nd_pno->p_base->pb_ino;
				assert(ino);

				/*
				 * Must send the intent-path again.
				 */
				path = nd->nd_path;
				nd->nd_amcnt++;

				/*
				 * Must go back top and retry with this
				 * new pnode as parent.
				 */
				continue;
			}
			err = 0;			/* it never happened */
		}
#endif

		/*
		 * Set up for next component.
		 */
		this = next;
		if (path)
			path = this.name;
		if (!this.len)
			break;
		if (!ino) {
			/*
			 * Should only be here if final component was
			 * target of a symlink.
			 */
			nd->nd_path = this.name + this.len;
			err = -ENOENT;
			break;
		}
		nd->nd_path = this.name + this.len;
		_sysio_next_component(nd->nd_path, &next);
		parent = nd->nd_pno;
		nd->nd_pno = NULL;

		/*
		 * Parent must be a directory.
		 */
		if (ino && !S_ISDIR(ino->i_stbuf.st_mode)) {
			err = -ENOTDIR;
			break;
		}

		/*
		 * The extra path arg is passed only on the first lookup in the
		 * walk as we cross into each file system, anew. The intent is
		 * passed both on the first lookup and when trying to look up
		 * the final component -- Of the original path, not on the
		 * file system.
		 *
		 * Confused? Me too and I came up with this weirdness. It's
		 * hints to the file system drivers. Read on.
		 *
		 * The first lookup will give everything one needs to ready
		 * everything for the entire operation before the path is
		 * walked. The file system driver knows it's the first lookup
		 * in the walk because it has both the path and the intent.
		 *
		 * Alternatively, one could split the duties; The first lookup
		 * can be used to prime the file system inode cache with the
		 * interior nodes we'll want in the path-walk. Then, when
		 * looking up the last component, ready everything for the
		 * operations(s) to come. The file system driver knows it's
		 * the last lookup in the walk because it has the intent,
		 * again, but without the path.
		 *
		 * One special case; If we were asked to look up a single
		 * component, we treat it as the last component. The file
		 * system driver never sees the extra path argument. It should
		 * be noted that the driver always has the fully qualified
		 * path, on the target file system, available to it for any
		 * node it is looking up, including the last, via the base
		 * path node and it's ancestor chain.
		 */
		err =
		    lookup(parent,
			   &this,
			   &nd->nd_pno,
			   (path || !next.len)
			     ? nd->nd_intent
			     : NULL,
			   (path && next.len) ? path : NULL,
			   !(nd->nd_flags & ND_NOPERMCHECK));
		if (err) {
			if (err == -ENOENT &&
			    !next.len &&
			    (nd->nd_flags & ND_NEGOK))
				err = 0;
			break;
		}
		path = NULL;				/* Stop that! */
		if ((parent->p_mount->mnt_fs !=
		     nd->nd_pno->p_mount->mnt_fs)) {
			/*
			 * Crossed into a new fs. We'll want the next lookup
			 * to include the path again.
			 */
			path = nd->nd_path;
		}

		/*
		 * Release the parent.
		 */
		P_RELE(parent);
		parent = NULL;
	}

	/*
	 * Trailing separators cause us to break from the loop with
	 * a parent set but no pnode. Check for that.
	 */
	if (!nd->nd_pno) {
		nd->nd_pno = parent;
		parent = NULL;
		/*
		 * Make sure the last processed component was a directory. The
		 * trailing slashes are illegal behind anything else.
		 */
		if (!(err ||
		      S_ISDIR(nd->nd_pno->p_base->pb_ino->i_stbuf.st_mode)))
			err = -ENOTDIR;
	}

	/*
	 * Drop reference to parent if set. Either we have a dup of the original
	 * parent or an intermediate reference.
	 */
	if (parent)
		P_RELE(parent);

	/*
	 * On error, we will want to drop our reference to the current
	 * path node if at end.
	 */
	if (err && nd->nd_pno) {
		P_RELE(nd->nd_pno);
		nd->nd_pno = NULL;
	}

	return err;
}

#ifdef CPLANT_YOD
/* 
 * for backward compatibility w/protocol switch
 * remove everything up to the first ':'
 * fortran libs prepend cwd to path, so not much choice
 */
#define STRIP_PREFIX(p) strchr(p,':') ? strchr(p,':')+1 : p
#else
#define STRIP_PREFIX(p) p
#endif

/*
 * Expanded form of the path-walk routine, with the common arguments, builds
 * the nameidata bundle and calls path-walk.
 */
int
_sysio_namei(struct pnode *parent,
	     const char *path,
	     unsigned flags,
	     struct intent *intnt,
	     struct pnode **pnop)
{
	struct nameidata nameidata;
	int	err;

	ND_INIT(&nameidata, flags, STRIP_PREFIX(path), _sysio_root, intnt);
	err = _sysio_path_walk(parent, &nameidata);
	if (!err)
		*pnop = nameidata.nd_pno;
	return err;
}
