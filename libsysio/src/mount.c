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
 *    Cplant(TM) Copyright 1998-2004 Sandia Corporation. 
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
#ifdef AUTOMOUNT_FILE_NAME
#include <fcntl.h>
#include <sys/uio.h>
#endif
#include <sys/queue.h>

#include "sysio.h"
#include "xtio.h"
#include "fs.h"
#include "mount.h"
#include "inode.h"

/*
 * File system and volume mount support.
 */

#ifdef AUTOMOUNT_FILE_NAME
/*
 * Name of autmount specification file in a directory with
 * the sticky-bit set.
 */
struct qstr _sysio_mount_file_name = { "", 0, 0 };
#endif

/*
 * Active mounts.
 */
static LIST_HEAD(, mount) mounts;

static int _sysio_sub_fsswop_mount(const char *source,
				   unsigned flags,
				   const void *data,
				   struct pnode *tocover,
				   struct mount **mntp);

static struct fssw_ops _sysio_sub_fssw_ops = {
	_sysio_sub_fsswop_mount
};

/*
 * Initialization. Must be called before any other routine in this module.
 */
int
_sysio_mount_init()
{
	int	err;

	LIST_INIT(&mounts);
#ifdef AUTOMOUNT_FILE_NAME
	_sysio_next_component(AUTOMOUNT_FILE_NAME, &_sysio_mount_file_name);
#endif

	/*
	 * Register the sub-trees "file system" driver.
	 */
	err = _sysio_fssw_register("sub", &_sysio_sub_fssw_ops);
	if (err)
		return err;

	return 0;
}

/*
 * Mount rooted sub-tree somewhere in the existing name space.
 */
int
_sysio_do_mount(struct filesys *fs,
		struct pnode_base *rootpb,
		unsigned flags,
		struct pnode *tocover,
		struct mount **mntp)
{
	struct mount *mnt;
	int	err;

	/*
	 * It's really poor form to allow the new root to be a
	 * descendant of the pnode being covered.
	 */
	if (tocover) {
		struct pnode_base *pb;

		for (pb = rootpb;
		     pb && pb != tocover->p_base;
		     pb = pb->pb_parent)
			;
		if (pb == tocover->p_base)
			return -EBUSY;
	}

	/*
	 * Alloc
	 */
	mnt = malloc(sizeof(struct mount));
	if (!mnt)
		return -ENOMEM;
	err = 0;
	/*
	 * Init enough to make the mount record usable to the path node
	 * generation routines.
	 */
	mnt->mnt_fs = fs;
	if (fs->fs_flags & FS_F_RO) {
		/*
		 * Propagate the read-only flag -- Whether they set it or not.
		 */
		flags |= MOUNT_F_RO;
	}
	mnt->mnt_flags = flags;
	/*
	 * Get alias for the new root.
	 */
	mnt->mnt_root =
	    _sysio_p_new_alias(tocover ? tocover->p_parent : NULL, rootpb, mnt);
	if (!mnt->mnt_root) {
		err = -ENOMEM;
		goto error;
	}
	/*
	 * It may have been a while since the root inode was validated;
	 * better validate again.  And it better be a directory!
	 */
	err = _sysio_p_validate(mnt->mnt_root, NULL, NULL);
	if (err)
		goto error;

	if (!S_ISDIR(mnt->mnt_root->p_base->pb_ino->i_stbuf.st_mode)) {
		err = -ENOTDIR;
		goto error;
	}
	/*
	 * Cover up the mount point.
	 */
	mnt->mnt_covers = tocover;
	if (!mnt->mnt_covers) {
		/*
		 * New graph; It covers itself.
		 */
		mnt->mnt_covers = tocover = mnt->mnt_root;
	}
	assert(!tocover->p_cover);
	tocover->p_cover = mnt->mnt_root;

	LIST_INSERT_HEAD(&mounts, mnt, mnt_link);

	*mntp = mnt;
	return 0;

error:
	if (mnt->mnt_root) {
		P_RELE(mnt->mnt_root);
		_sysio_p_prune(mnt->mnt_root);
	}
	free(mnt);
	return err;
}

/*
 * Remove mounted sub-tree from the system.
 */
int
_sysio_do_unmount(struct mount *mnt)
{
	struct pnode *root;
	struct filesys *fs;

	root = mnt->mnt_root;
	if (root->p_cover && root->p_cover != root) {
		/*
		 * Active mount.
		 */
		return -EBUSY;
	}
	assert(mnt->mnt_covers->p_cover == root);
	if (_sysio_p_prune(root) != 1) {
		/*
		 * Active aliases.
		 */
		return -EBUSY;
	}
	/*
	 * We're committed.
	 *
	 * Drop ref of covered pnode and break linkage in name space.
	 */
	if (root->p_cover != root)
		P_RELE(mnt->mnt_covers);
	mnt->mnt_covers->p_cover = NULL;
	LIST_REMOVE(mnt, mnt_link);
	/*
	 * Kill the root.
	 */
	P_RELE(root);
	root->p_cover = NULL;
	_sysio_p_gone(root);
	/*
	 * Release mount record resource.
	 */
	fs = mnt->mnt_fs;
	free(mnt);
	FS_RELE(fs);

	return 0;
}

/*
 * Establish the system name space.
 */
int
_sysio_mount_root(const char *source,
		  const char *fstype,
		  unsigned flags,
		  const void *data)
{
	struct fsswent *fssw;
	int	err;
	struct mount *mnt;

	if (_sysio_root)
		return -EBUSY;

	fssw = _sysio_fssw_lookup(fstype);
	if (!fssw)
		return -ENODEV;

	err = (*fssw->fssw_ops.fsswop_mount)(source, flags, data, NULL, &mnt);
	if (err)
		return err;

	_sysio_root = mnt->mnt_root;
#ifndef DEFER_INIT_CWD
	/*
	 * It is very annoying to have to set the current working directory.
	 * So... If it isn't set, make it the root now.
	 */
	if (!_sysio_cwd) {
		_sysio_cwd = _sysio_root;
		P_REF(_sysio_cwd);
	}
#endif

	return 0;
}

int
_sysio_mount(struct pnode *cwd,
	     const char *source,
	     const char *target,
	     const char *filesystemtype,
	     unsigned long mountflags,
	     const void *data)
{
	int	err;
	struct fsswent *fssw;
	struct intent intent;
	struct pnode *tgt;
	struct mount *mnt;

	/*
	 * Find the file system switch entry specified.
	 */
	fssw = _sysio_fssw_lookup(filesystemtype);
	if (!fssw)
		return -ENODEV;

	/*
	 * Look up the target path node.
	 */
        INTENT_INIT(&intent, INT_GETATTR, NULL, NULL);
	err = _sysio_namei(cwd, target, 0, &intent, &tgt);
	if (err)
		return err;

	if (tgt == _sysio_root) {
		/*
		 * Attempting to mount over root.
		 */
		err = -EBUSY;
	} else {
		/*
		 * Do the deed.
		 */
		err =
		    (*fssw->fssw_ops.fsswop_mount)(source,
						   mountflags,
						   data,
						   tgt,
						   &mnt);
	}
	if (err)
		P_RELE(tgt);
	return err;
}

int
SYSIO_INTERFACE_NAME(mount)(const char *source,
      const char *target,
      const char *filesystemtype,
      unsigned long mountflags,
      const void *data)
{
	int	err;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	err =
	    _sysio_mount(_sysio_cwd,
			 source,
			 target,
			 filesystemtype,
			 mountflags,
			 data);
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

int
SYSIO_INTERFACE_NAME(umount)(const char *target)
{
	int	err;
	struct pnode *pno;
	SYSIO_INTERFACE_DISPLAY_BLOCK;

	SYSIO_INTERFACE_ENTER;
	/*
	 * Look up the target path node.
	 */
	err = _sysio_namei(_sysio_cwd, target, 0, NULL, &pno);
	if (err)
		goto out;
	P_RELE(pno);				/* was ref'd */

	/*
	 * Do the deed.
	 */
#if 0	
	if (!pno->p_cover) {
		err = -EINVAL;
		goto error;
	}
#endif
	assert(pno->p_mount);
	err = _sysio_do_unmount(pno->p_mount);

out:
	SYSIO_INTERFACE_RETURN(err ? -1 : 0, err);
}

/*
 * Unmount all file systems -- Usually as part of shutting everything down.
 */
int
_sysio_unmount_all()
{
	int	err;
	struct mount *mnt, *nxt;
	struct pnode *pno;

	err = 0;
	nxt = mounts.lh_first;
	while ((mnt = nxt)) {
		nxt = mnt->mnt_link.le_next;
		pno = mnt->mnt_root;
		/*
		 * If this is an automount generated mount, the root
		 * has no reference. We can cause the dismount with a
		 * simple prune.
		 */
		if (!_sysio_p_prune(pno))
			continue;
#ifdef notdef
		/*
		 * Need a ref but only if this is not the root of a
		 * disconnected graph. If it is, then it is covered by itself
		 * and, so, already referenced.
		 */
		if (pno->p_cover != pno)
			P_REF(pno);
#endif
		err = _sysio_do_unmount(mnt);
		if (err) {
#ifdef notdef
			if (pno->p_cover != pno)
				P_RELE(pno);
#endif
			break;
		}
		if (pno == _sysio_root)
			_sysio_root = NULL;
	}

	return err;
}

static int
_sysio_sub_fsswop_mount(const char *source,
			unsigned flags,
			const void *data __IS_UNUSED,
			struct pnode *tocover,
			struct mount **mntp)
{
	int	err;
	struct nameidata nameidata;
	struct mount *mnt;

	/*
	 * How can we make a sub-mount from nothing?
	 */
	if (!_sysio_root)
		return -EBUSY;

	/*
	 * Lookup the source.
	 */
	ND_INIT(&nameidata, 0, source, _sysio_root, NULL);
	err = _sysio_path_walk(_sysio_root, &nameidata);
	if (err)
		return err;

	/*
	 * Mount the rooted sub-tree at the given position.
	 */
	err =
	    _sysio_do_mount(nameidata.nd_pno->p_mount->mnt_fs,
			    nameidata.nd_pno->p_base,
			    nameidata.nd_pno->p_mount->mnt_flags & flags,
			    tocover,
			    &mnt);

	/*
	 * Clean up and return.
	 */
	if (!err) {
		FS_REF(nameidata.nd_pno->p_mount->mnt_fs);
		*mntp = mnt;
	}
	P_RELE(nameidata.nd_pno);
	return err;
}

#ifdef AUTOMOUNT_FILE_NAME
/*
 * Parse automount specification formatted as:
 *
 * <fstype>:<source>[[ \t]+<comma-separated-mount-options>]
 *
 * NB:
 * The buffer sent is (almost) always modified.
 */
static int
parse_automount_spec(char *s, char **fstyp, char **srcp, char **optsp)
{
	int	err;
	char	*cp;
	char	*fsty, *src, *opts;

	err = 0;

	/*
	 * Eat leading white.
	 */
	while (*s && *s == ' ' && *s == '\t')
		s++;
	/*
	 * Get fstype.
	 */
	fsty = cp = s;
	while (*cp &&
	       *cp != ':' &&
	       *cp != ' ' &&
	       *cp != '\t' &&
	       *cp != '\r' &&
	       *cp != '\n')
		cp++;
	if (fsty == cp || *cp != ':')
		goto error;
	*cp++ = '\0';

	s = cp;
	/*
	 * Eat leading white.
	 */
	while (*s && *s == ' ' && *s == '\t')
		s++;
	/*
	 * Get source.
	 */
	src = cp = s;
	while (*cp &&
	       *cp != ' ' &&
	       *cp != '\t' &&
	       *cp != '\r' &&
	       *cp != '\n')
		cp++;
	if (src == cp)
		goto error;
	if (*cp)
		*cp++ = '\0';

	s = cp;
	/*
	 * Eat leading white.
	 */
	while (*s && *s == ' ' && *s == '\t')
		s++;
	/*
	 * Get opts.
	 */
	opts = cp = s;
	while (*cp &&
	       *cp != ' ' &&
	       *cp != '\t' &&
	       *cp != '\r' &&
	       *cp != '\n')
		cp++;
	if (opts == cp)
		opts = NULL;
	if (*cp)
		*cp++ = '\0';

	if (*cp)
		goto error;

	*fstyp = fsty;
	*srcp = src;
	*optsp = opts;
	return 0;

error:
	return -EINVAL;
}

/*
 * Parse (and strip) system mount options.
 */
static char *
parse_opts(char *opts, unsigned *flagsp)
{
	unsigned flags;
	char	*src, *dst;
	char	*cp;

	flags = 0;
	src = dst = opts;
	for (;;) {
		cp = src;
		while (*cp && *cp != ',')
			cp++;
		if (src + 2 == cp && strncmp(src, "rw", 2) == 0) {
			/*
			 * Do nothing. This is the default.
			 */
			src += 2;
		} else if (src + 2 == cp && strncmp(src, "ro", 2) == 0) {
			/*
			 * Read-only.
			 */
			flags |= MOUNT_F_RO;
			src += 2;
		}
		else if (src + 4 == cp && strncmp(src, "auto", 4) == 0) {
			/*
			 * Enable automounts.
			 */
			flags |= MOUNT_F_AUTO;
			src += 4;
		}
		if (src < cp) {
			/*
			 * Copy what we didn't consume.
			 */
			if (dst != opts)
				*dst++ = ',';
			do
				*dst++ = *src++;
			while (src != cp);
		}
		if (!*src)
			break;
		*dst = '\0';
		src++;					/* skip comma */
	}
	*dst = '\0';

	*flagsp = flags;
	return opts;
}

/*
 * Attempt automount over the given directory.
 */
int
_sysio_automount(struct pnode *mntpno)
{
	int	err;
	struct inode *ino;
	struct iovec iovec;
	struct ioctx iocontext;
	struct intnl_xtvec xtvec;
	ssize_t	cc;
	char	*fstype, *source, *opts;
	unsigned flags;
	struct fsswent *fssw;
	struct mount *mnt;

	/*
	 * Revalidate -- Paranoia.
	 */
	err = _sysio_p_validate(mntpno, NULL, NULL);
	if (err)
		return err;

	/*
	 * Read file content.
	 */
	ino = mntpno->p_base->pb_ino;
	if (ino->i_stbuf.st_size > 64 * 1024) {
		/*
		 * Let's be reasonable.
		 */
		return -EINVAL;
	}
	iovec.iov_base = malloc(ino->i_stbuf.st_size + 1);
	if (!iovec.iov_base)
		return -ENOMEM;
	iovec.iov_len = ino->i_stbuf.st_size;
	err = _sysio_open(mntpno, O_RDONLY, 0);
	if (err)
		goto out;
	xtvec.xtv_off = 0;
	xtvec.xtv_len = ino->i_stbuf.st_size;
	IOCTX_INIT(&iocontext,
		   1,
		   0,
		   ino,
		   &iovec, 1,
		   &xtvec, 1);
	_sysio_ioctx_enter(&iocontext);
	err = (*ino->i_ops.inop_read)(ino, &iocontext);
	if (err) {
		_sysio_ioctx_complete(&iocontext);
		(void )(*ino->i_ops.inop_close)(ino);
		goto out;
	}
	cc = _sysio_ioctx_wait(&iocontext);
	err = (*ino->i_ops.inop_close)(ino);
	if (err)
		goto out;
	if (cc < 0) {
		err = (int )cc;
		goto out;
	}
	((char *)iovec.iov_base)[cc] = '\0';

	/*
	 * Parse.
	 */
	err = parse_automount_spec(iovec.iov_base, &fstype, &source, &opts);
	if (err)
		goto out;
	flags = 0;
	if (opts)
		opts = parse_opts(opts, &flags);

	/*
	 * Find the file system switch entry specified.
	 */
	fssw = _sysio_fssw_lookup(fstype);
	if (!fssw) {
		err = -ENODEV;
		goto out;
	}

	/*
	 * Do the deed.
	 */
	P_REF(mntpno->p_parent);
	err =
	    (*fssw->fssw_ops.fsswop_mount)(source,
					   flags,
					   opts,
					   mntpno->p_parent,
					   &mnt);
	if (err)
		P_RELE(mntpno->p_parent);

out:
	if (iovec.iov_base)
		free(iovec.iov_base);
	return err;
}
#endif
