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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include "sysio.h"
#include "fs.h"
#include "mount.h"
#include "inode.h"
#include "dev.h"

/*
 * Support for path and index nodes.
 */

/*
 * Size of all names bucket-hash table.
 */
#ifndef NAMES_TABLE_LEN
#define NAMES_TABLE_LEN		251
#endif

/*
 * Desired i-nodes cache size is MAX_INODES_MULTIPLIER times the number
 * of slots in the names hash table.
 */
#define MAX_INODES_MULTIPLIER	3

/*
 * Active i-nodes in the system and the number of same.
 */
struct inodes_head _sysio_inodes;
static size_t n_inodes = 0;
/*
 * Desired number of active i-nodes.
 */
static size_t max_inodes = (MAX_INODES_MULTIPLIER * NAMES_TABLE_LEN);

/*
 * System table for rapid access to component names.
 */
static LIST_HEAD(, pnode_base) names[NAMES_TABLE_LEN];
/*
 * Number of names tracked by the system.
 */
static size_t n_names = 0;
/*
 * Desired number of base path nodes to maintain.
 */
static size_t max_names = (2 * NAMES_TABLE_LEN);

/*
 * Number of pnodes to grab per memory allocation when filling the
 * free list.
 */
#define PNODES_PER_CHUNK ((8 * 1024) / sizeof(struct pnode) - 2)

#ifdef ZERO_SUM_MEMORY
/*
 * Allocation information for pnodes bulk allocation.
 */
struct pnodes_block {
	LIST_ENTRY(pnodes_block) pnblk_links;
	struct pnode pnblk_nodes[PNODES_PER_CHUNK];
};

static LIST_HEAD( ,pnodes_block) pnblocks;
#endif

/*
 * List of all path-nodes (aliases) referenced by any tree.
 */
struct pnodes_head _sysio_pnodes;

/*
 * Free path-nodes -- Not referenced by any tree for fas reuse.
 */
static LIST_HEAD( ,pnode) free_pnodes;

/*
 * The system root -- Aka `/'.
 */
struct pnode *_sysio_root = NULL;

/*
 * Initialize path and i-node support. Must be called before any other
 * routine in this module.
 */
int
_sysio_i_init()
{
	unsigned i;

	TAILQ_INIT(&_sysio_inodes);

	for (i = 0; i < NAMES_TABLE_LEN; i++)
		LIST_INIT(&names[i]);

#ifdef ZERO_SUM_MEMORY
	LIST_INIT(&pnblocks);
#endif
	TAILQ_INIT(&_sysio_pnodes);
	LIST_INIT(&free_pnodes);

	return 0;
}

/*
 * Garbage-collect idle i-nodes. We try to keep resource use limited to
 * MAX_INODES_MULTIPLIER * max_names.
 */
static void
i_reclaim()
{
	struct inode *next, *ino;
	size_t	t;

	/*
	 * I just can't figure out a good way to reclaim these well without
	 * getting really fancy and using complex algorithms. The
	 * base nodes hold references on them for a long time and then
	 * release them. Those will age to the front of the queue and
	 * we have to skip over them. Oh well...
	 */
	t = MAX_INODES_MULTIPLIER * max_names;
	if (max_inodes < t) {
		/*
		 * Oops. Nope. We want more inodes than names entries.
		 */
		max_inodes = t;
		return;
	}
	next = _sysio_inodes.tqh_first;
	if (!next)
		return;
	t = max_inodes / 2;
	do {
		ino = next;
		next = ino->i_nodes.tqe_next;
		if (ino->i_ref || ino->i_immune)
			continue;
		_sysio_i_gone(ino);
	} while (next && n_inodes > t);

	if (n_inodes > t)
		max_inodes += t;
}

static unsigned
hash(struct file_identifier *fid)
{
	size_t	n;
	unsigned char *ucp;
	unsigned hkey;

	n = fid->fid_len;
	ucp = fid->fid_data;
	hkey = 0;
	do {
		hkey <<= 1;
		hkey += *ucp++;
	} while (--n);
	return hkey;
}

/*
 * Allocate and initialize a new i-node. Returned i-node is referenced.
 *
 * NB: The passed file identifier is not copied. It is, therefor, up to the
 * caller to assure that the value is static until the inode is destroyed.
 */
struct inode *
_sysio_i_new(struct filesys *fs,
	     struct file_identifier *fid,
	     struct intnl_stat *stat,
	     unsigned immunity,
	     struct inode_ops *ops,
	     void *private)
{
	struct inode *ino;
	struct itable_entry *head;
	struct inode_ops operations;

	if (n_inodes > max_inodes) {
		/*
		 * Try to limit growth.
		 */
		i_reclaim();
	}

	ino = malloc(sizeof(struct inode));
	if (!ino)
		return NULL;
	ino->i_ops = *ops;
	operations = *ops;
	if (S_ISBLK(stat->st_mode) ||
	    S_ISCHR(stat->st_mode) ||
	    S_ISFIFO(stat->st_mode)) {
		struct inode_ops *o;

		/*
		 * Replace some operations sent with
		 * those from the device table.
		 */
		o = _sysio_dev_lookup(stat->st_mode, stat->st_rdev);
		operations.inop_open = o->inop_open;
		operations.inop_close = o->inop_close;
		operations.inop_read = o->inop_read;
		operations.inop_write = o->inop_write;
		operations.inop_pos = o->inop_pos;
		operations.inop_iodone = o->inop_iodone;
		operations.inop_fcntl = o->inop_fcntl;
		operations.inop_datasync = o->inop_datasync;
		operations.inop_ioctl = o->inop_ioctl;
	}
	I_INIT(ino, fs, stat, &operations, fid, immunity, private);
	ino->i_ref = 1;
	TAILQ_INSERT_TAIL(&_sysio_inodes, ino, i_nodes);
	head = &fs->fs_itbl[hash(fid) % FS_ITBLSIZ];
	LIST_INSERT_HEAD(head, ino, i_link);

	n_inodes++;
	assert(n_inodes);

	return ino;
}

/*
 * Find existing i-node given i-number and pointers to FS record
 * and identifier.
 */
struct inode *
_sysio_i_find(struct filesys *fs, struct file_identifier *fid)
{
	struct inode *ino;
	struct itable_entry *head;

	head = &fs->fs_itbl[hash(fid) % FS_ITBLSIZ];
	/*
	 * Look for existing.
	 */
	for (ino = head->lh_first; ino; ino = ino->i_link.le_next)
		if (ino->i_fid->fid_len == fid->fid_len &&
		    memcmp(ino->i_fid->fid_data,
			   fid->fid_data,
			   fid->fid_len) == 0) {
			I_REF(ino);
			break;
		}

	return ino;
}

/*
 * Force reclaim of idle i-node.
 */
void
_sysio_i_gone(struct inode *ino)
{

	if (ino->i_ref)
		abort();
	if (!ino->i_zombie) 
		LIST_REMOVE(ino, i_link);
	TAILQ_REMOVE(&_sysio_inodes, ino, i_nodes);
	(*ino->i_ops.inop_gone)(ino);
	free(ino);

	assert(n_inodes);
	n_inodes--;
}

/*
 * Stale inode, zombie it and move it out of the way 
 */
void
_sysio_i_undead(struct inode *ino)
{
	
	if (ino->i_zombie)
		return;
	LIST_REMOVE(ino, i_link);
	ino->i_zombie = 1;
}

/*
 * Garbage collect idle path (and base path) nodes tracked by the system.
 */
static void
p_reclaim()
{
	struct pnode *next, *pno;
	size_t	t;

	next = _sysio_pnodes.tqh_first;
	if (!next)
		return;
	t = max_names / 2;
	do {
		pno = next;
		if (pno->p_ref) {
			next = pno->p_nodes.tqe_next;
			continue;
		}
		pno->p_ref++;
		assert(pno->p_ref);
		(void )_sysio_p_prune(pno);
		next = pno->p_nodes.tqe_next;
		assert(pno->p_ref);
		pno->p_ref--;
		if (pno->p_ref)
			continue;
		(void )_sysio_p_prune(pno);
	} while (n_names > t && next);

	if (n_names > t)
		max_names += t;
}

/*
 * Allocate and initialize a new base path node.
 */
struct pnode_base *
_sysio_pb_new(struct qstr *name, struct pnode_base *parent, struct inode *ino)
{
	struct pnode_base *pb;

	if (n_names > max_names) {
		/*
		 * Try to limit growth.
		 */
		p_reclaim();
	}

	pb = malloc(sizeof(struct pnode_base) + name->len);
	if (!pb)
		return NULL;

	pb->pb_name.name = NULL;
	pb->pb_name.len = name->len;
	if (pb->pb_name.len) {
		char	*cp;

		/*
		 * Copy the passed name.
		 *
		 * We have put the space for the name immediately behind
		 * the record in order to maximize spatial locality.
		 */
		cp = (char *)pb + sizeof(struct pnode_base);
		(void )strncpy(cp, name->name, name->len);
		pb->pb_name.name = cp;
		assert(name->hashval);
		pb->pb_name.hashval = name->hashval;
		LIST_INSERT_HEAD(&names[name->hashval % NAMES_TABLE_LEN],
				 pb,
				 pb_names);
	}
	pb->pb_ino = ino;
	LIST_INIT(&pb->pb_children);
	LIST_INIT(&pb->pb_aliases);
	if (parent)
		LIST_INSERT_HEAD(&parent->pb_children, pb, pb_sibs);
	pb->pb_parent = parent;

	n_names++;
	assert(n_names);

	return pb;
}

/*
 * Destroy base path node, releasing resources back to the system.
 *
 * NB: Caller must release the inode referenced by the record.
 */
static void
pb_destroy(struct pnode_base *pb)
{

	assert(n_names);
	n_names--;

	assert(!pb->pb_aliases.lh_first);
	assert(!pb->pb_children.lh_first);
	assert(!pb->pb_ino);
	if (pb->pb_name.len)
		LIST_REMOVE(pb, pb_names);
	if (pb->pb_parent)
		LIST_REMOVE(pb, pb_sibs);

#ifndef NDEBUG
	/*
	 * This can help us catch pb-nodes that are free'd redundantly.
	 */
	pb->pb_name.hashval = 0;
#endif
	free(pb);
}

/*
 * Force reclaim of idle base path node.
 */
void
_sysio_pb_gone(struct pnode_base *pb)
{

	if (pb->pb_ino)
		I_RELE(pb->pb_ino);
	pb->pb_ino = NULL;

	pb_destroy(pb);
}

/*
 * Generate more path (alias) nodes for the fast allocator.
 */
static void
more_pnodes()
{
	size_t	n;
#ifdef ZERO_SUM_MEMORY
	struct pnodes_block *pnblk;
#endif
	struct pnode *pno;

#ifdef ZERO_SUM_MEMORY
	pnblk = malloc(sizeof(struct pnodes_block));
	pno = NULL;
	if (pnblk) {
		LIST_INSERT_HEAD(&pnblocks, pnblk, pnblk_links);
		pno = pnblk->pnblk_nodes;
	}
#else
	pno = malloc(PNODES_PER_CHUNK * sizeof(struct pnode));
#endif
	if (!pno)
		return;
	n = PNODES_PER_CHUNK;
	do {
		LIST_INSERT_HEAD(&free_pnodes, pno, p_links);
		pno++;
	} while (--n);
}

#ifdef ZERO_SUM_MEMORY
/*
 * Shutdown
 */
void
_sysio_i_shutdown()
{
	struct pnodes_block *pnblk;

	while ((pnblk = pnblocks.lh_first)) {
		LIST_REMOVE(pnblk, pnblk_links);
		free(pnblk);
	}
}
#endif

/*
 * Allocate, initialize and establish appropriate links for new path (alias)
 * node.
 */
struct pnode *
_sysio_p_new_alias(struct pnode *parent,
		   struct pnode_base *pb,
		   struct mount *mnt)
{
	struct pnode *pno;

	assert(!pb->pb_name.name || pb->pb_name.hashval);

	pno = free_pnodes.lh_first;
	if (!pno) {
		more_pnodes();
		pno = free_pnodes.lh_first;
	}
	if (!pno)
		return NULL;
	LIST_REMOVE(pno, p_links);

	pno->p_ref = 1;
	pno->p_parent = parent;
	if (!pno->p_parent)
		pno->p_parent = pno;
	pno->p_base = pb;
	pno->p_mount = mnt;
	pno->p_cover = NULL;
	LIST_INSERT_HEAD(&pb->pb_aliases, pno, p_links);
	TAILQ_INSERT_TAIL(&_sysio_pnodes, pno, p_nodes);

	return pno;
}

/*
 * For reclamation of idle path (alias) node.
 */
void
_sysio_p_gone(struct pnode *pno)
{
	struct pnode_base *pb;

	assert(!pno->p_ref);
	assert(!pno->p_cover);

	TAILQ_REMOVE(&_sysio_pnodes, pno, p_nodes);
	LIST_REMOVE(pno, p_links);

	pb = pno->p_base;
	if (!(pb->pb_aliases.lh_first || pb->pb_children.lh_first))
		_sysio_pb_gone(pb);

	LIST_INSERT_HEAD(&free_pnodes, pno, p_links);
}

/*
 * (Re)Validate passed path node.
 */
int
_sysio_p_validate(struct pnode *pno, struct intent *intnt, const char *path)
{
	struct inode *ino;
	struct pnode_base *rootpb;
	int	err;

	ino = pno->p_base->pb_ino;
	/*
	 * An invalid pnode will not have an associated inode. We'll use
	 * the FS root inode, then -- It *must* be valid.
	 */
	rootpb = pno->p_mount->mnt_root->p_base;
	assert(rootpb->pb_ino);
	err =
	    rootpb->pb_ino->i_ops.inop_lookup(pno,
					      &ino,
					      intnt,
					      path);
	/*
	 * If the inode lookup returns a different inode, release the old if
	 * present and point to the new.
	 */
	if (err || pno->p_base->pb_ino != ino) {
		if (pno->p_base->pb_ino)
			I_RELE(pno->p_base->pb_ino);
		pno->p_base->pb_ino = ino;
	}
	return err;
}

/*
 * Find (or create!) an alias for the given parent and name. A misnomer,
 * really -- This is a "get". Returned path node is referenced.
 */
int
_sysio_p_find_alias(struct pnode *parent,
		    struct qstr *name,
		    struct pnode **pnop)
{
	struct pnode_base *pb;
	int	err;
	struct pnode *pno;

	/*
	 * Find the named child.
	 */
	if (name->len) {
		/*
		 * Try the names table.
		 */
		pb = names[name->hashval % NAMES_TABLE_LEN].lh_first;
		while (pb) {
			if (pb->pb_parent == parent->p_base &&
			    pb->pb_name.len == name->len &&
			    strncmp(pb->pb_name.name,
				    name->name,
				    name->len) == 0)
				break;
			pb = pb->pb_names.le_next;
		}
	} else {
		/*
		 * Brute force through the parent's list of children.
		 */
		pb = parent->p_base->pb_children.lh_first;
		while (pb) {
			if (pb->pb_parent == parent->p_base &&
			    pb->pb_name.len == name->len &&
			    strncmp(pb->pb_name.name,
				    name->name,
				    name->len) == 0)
				break;
			pb = pb->pb_sibs.le_next;
		}
	}
	if (!pb) {
		/*
		 * None found, create new child.
		 */
		pb = _sysio_pb_new(name, parent->p_base, NULL);
		if (!pb)
			return -ENOMEM;
	}
	/*
	 * Now find the proper alias. It's the one with the passed
	 * parent.
	 */
	err = 0;
	pno = pb->pb_aliases.lh_first;
	while (pno) {
		if (pno->p_parent == parent) {
			P_REF(pno);
			break;
		}
		pno = pno->p_links.le_next;
	}
	if (!pno) {
		/*
		 * Hmm. No alias. Just create an invalid one, to be
		 * validated later.
		 */
		pno = _sysio_p_new_alias(parent, pb, parent->p_mount);
		if (!pno)
			err = -ENOMEM;
	}
	if (!err)
		*pnop = pno;
	return err;
}

/*
 * Prune idle path base nodes freom the passed sub-tree, including the root.
 */
static void
_sysio_prune(struct pnode_base *rpb)
{
	struct pnode_base *nxtpb, *pb;

	nxtpb = rpb->pb_children.lh_first;
	while ((pb = nxtpb)) {
		nxtpb = pb->pb_sibs.le_next;
		if (pb->pb_aliases.lh_first)
			continue;
		if (pb->pb_children.lh_first) {
			_sysio_prune(pb);
			continue;
		}
		_sysio_pb_gone(pb);
	}
	if (rpb->pb_children.lh_first)
		return;
	_sysio_pb_gone(rpb);
}

/*
 * Prune idle nodes from the passed sub-tree, including the root.
 *
 * Returns the number of aliases on the same mount that could not be pruned.
 * i.e. a zero return means the entire sub-tree is gone.
 */
size_t
_sysio_p_prune(struct pnode *root)
{
	size_t	count;
	struct pnode_base *nxtpb, *pb;
	struct pnode *nxtpno, *pno;

	count = 0;
	nxtpb = root->p_base->pb_children.lh_first;
	while ((pb = nxtpb)) {
		nxtpb = pb->pb_sibs.le_next;
		nxtpno = pb->pb_aliases.lh_first;
		if (!nxtpno) {
			_sysio_prune(pb);
			continue;
		}
		while ((pno = nxtpno)) {
			nxtpno = pno->p_links.le_next;
			if (pno->p_mount != root->p_mount) {
				/*
				 * Not the alias we were looking for.
				 */
				continue;
			}
			if (pno->p_base->pb_children.lh_first) {
				/*
				 * Node is interior. Recurse.
				 */
				count += _sysio_p_prune(pno);
				continue;
			}
			if (pno->p_ref) {
				/*
				 * Can't prune; It's active.
				 */
				count++;
				continue;
			}
			assert(!pno->p_cover);		/* covered => ref'd! */
			assert(!pno->p_base->pb_name.name ||
			       pno->p_base->pb_name.hashval);
			/*
			 * Ok to prune.
			 */
			if (pno->p_mount->mnt_root == pno) {
#ifndef AUTOMOUNT_FILE_NAME
				count++;
				continue;
#else
				/*
				 * This is an automount-point. Must
				 * unmount before relcaim.
				 */
				P_REF(pno);
				if (_sysio_do_unmount(pno->p_mount) != 0) {
					P_RELE(pno);
					count++;
				}
				continue;
#endif
			}
			_sysio_p_gone(pno);
		}
	}

	if (count) {
		/*
		 * Can't get the root or we disconnect the sub-trees.
		 */
		return count + (root->p_ref ? 1 : 0);
	}

	/*
	 * All that is left is the root. Try for it too.
	 */
	if (root->p_ref) {
		count++;
	} else if (root->p_mount->mnt_root == root) {
#ifndef AUTOMOUNT_FILE_NAME
		count++;
#else
		/*
		 * This is an automount-point. Must
		 * unmount before relcaim.
		 */
		P_REF(root);
		if (_sysio_do_unmount(root->p_mount) != 0) {
			P_RELE(root);
			count++;
		}
#endif
	} else
		_sysio_p_gone(root);

	return count;
}

/*
 * Return path tracked by the base path node ancestor chain.
 *
 * Remember, base path nodes track the path relative to the file system and
 * path (alias) nodes track path relative to our name space -- They cross
 * mount points.
 */
char *
_sysio_pb_path(struct pnode_base *pb, const char separator)
{
	char	*buf;
	size_t	len, n;
	struct pnode_base *tmp;
	char	*cp;

	/*
	 * First pass: Traverse to the root of the sub-tree, remembering
	 * lengths.
	 */
	len = 0;
	tmp = pb;
	do {
		n = tmp->pb_name.len;
		len += tmp->pb_name.len;
		if (n)
			len++;
		tmp = tmp->pb_parent;
	} while (tmp);
	if (!len)
		len++;
	/*
	 * Alloc space.
	 */
	buf = malloc(len + 1);
	if (!buf)
		return NULL;
	/*
	 * Fill in the path buffer -- Backwards, since we're starting
	 * from the end.
	 */
	cp = buf;
	*cp = separator;
	cp += len;
	*cp = '\0';					/* NUL term */
	tmp = pb;
	do {
		cp -= tmp->pb_name.len;
		n = tmp->pb_name.len;
		if (n) {
			(void )strncpy(cp, tmp->pb_name.name, n);
			*--cp = separator;
		}
		tmp = tmp->pb_parent;
	} while (tmp);

	return buf;
}

/*
 * Common set attributes routine.
 */
int
_sysio_setattr(struct pnode *pno,
	       struct inode *ino,
	       unsigned mask,
	       struct intnl_stat *stbuf)
{
	/*
	 * It is possible that pno is null (for ftruncate call).
	 */

	if (pno)
		assert(!ino || pno->p_base->pb_ino == ino);
	if (!ino)
		ino = pno->p_base->pb_ino;
	assert(ino);

	if (pno && IS_RDONLY(pno))
		return -EROFS;

	/*
	 * Determining permission to change the attributes is
	 * difficult, at best. Just try it.
	 */
	return (*ino->i_ops.inop_setattr)(pno, ino, mask, stbuf);
}

/*
 * Do nothing.
 */
void
_sysio_do_noop()
{

	return;
}

/*
 * Abort.
 */
void
_sysio_do_illop()
{

	abort();
}

/*
 * Return -EBADF
 */
int
_sysio_do_ebadf()
{

	return -EBADF;
}

/*
 * Return -EINVAL
 */
int
_sysio_do_einval()
{

	return -EINVAL;
}

/*
 * Return -ENOENT
 */
int
_sysio_do_enoent()
{

	return -ENOENT;
}

/*
 * Return -ESPIPE
 */
int
_sysio_do_espipe()
{

	return -ESPIPE;
}

/*
 * Return -EISDIR
 */
int
_sysio_do_eisdir()
{

	return -EISDIR;
}

/*
 * Return -ENOSYS
 */
int
_sysio_do_enosys()
{

	return -ENOSYS;
}


/*
 * Return -ENODEV
 */
int
_sysio_do_enodev()
{

	return -ENODEV;
}
