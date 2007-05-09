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

#if defined(AUTOMOUNT_FILE_NAME) && !defined(MAX_MOUNT_DEPTH)
/*
 * Maximum number of automounts to attempt in path traversal.
 */
#define MAX_MOUNT_DEPTH		64
#endif

/*
 * Each i-node is uniquely identified by a file identifier, supplied by
 * the relevant file system driver. The i-node number returned in the getattrs
 * call is not always enough.
 */
struct file_identifier {
    void    *fid_data;
    size_t  fid_len;
};

struct pnode;
struct inode;
struct intent;
struct intnl_dirent;
struct intnl_stat;
#ifdef _HAVE_STATVFS
struct intnl_statvfs;
#endif
struct io_arguments;
struct ioctx;

/*
 * Operations on i-nodes.
 *
 * Should this be split up into file and name space operations?
 */
struct inode_ops {
    int (*inop_lookup)(struct pnode *pno,
                       struct inode **inop,
                       struct intent *intnt,
                       const char *path);
    int (*inop_getattr)(struct pnode *pno,
                        struct inode *ino,
                        struct intnl_stat *stbuf);
    int (*inop_setattr)(struct pnode *pno,
                        struct inode *ino,
                        unsigned mask,
                        struct intnl_stat *stbuf);
    ssize_t (*inop_filldirentries)(struct inode *ino,
				   _SYSIO_OFF_T *posp,
				   char *buf,
				   size_t nbytes);
    int (*inop_mkdir)(struct pnode *pno, mode_t mode);
    int (*inop_rmdir)(struct pnode *pno);
    int (*inop_symlink)(struct pnode *pno, const char *data);
    int (*inop_readlink)(struct pnode *pno, char *buf, size_t bufsiz);
    int (*inop_open)(struct pnode *pno, int flags, mode_t mode);
    int (*inop_close)(struct inode *ino);
    int (*inop_link)(struct pnode *old, struct pnode *new);
    int (*inop_unlink)(struct pnode *pno);
    int (*inop_rename)(struct pnode *old, struct pnode *new);
    int (*inop_read)(struct inode *ino, struct ioctx *ioctx);
    int (*inop_write)(struct inode *ino, struct ioctx *ioctx);
    _SYSIO_OFF_T (*inop_pos)(struct inode *ino, _SYSIO_OFF_T off);
    int (*inop_iodone)(struct ioctx *iocp);
    int (*inop_fcntl)(struct inode *ino, int cmd, va_list ap, int *rtn);
    int (*inop_sync)(struct inode *ino);
    int (*inop_datasync)(struct inode *ino);
    int (*inop_ioctl)(struct inode *ino, unsigned long int request, va_list ap);
    int (*inop_mknod)(struct pnode *pno, mode_t mode, dev_t dev);
#ifdef _HAVE_STATVFS
    int (*inop_statvfs)(struct pnode *pno,
                        struct inode *ino,
                        struct intnl_statvfs *buf);
#endif
    void    (*inop_gone)(struct inode *ino);
};

/*
 * Values for the mask to inop_setattr.
 */
#define SETATTR_MODE        0x01
#define SETATTR_MTIME       0x02
#define SETATTR_ATIME       0x04
#define SETATTR_UID         0x08
#define SETATTR_GID         0x10
#define SETATTR_LEN         0x20

/*
 * An i-node record is maintained for each file object in the system.
 */
struct inode {
    LIST_ENTRY(inode) i_link;                           /* FS i-nodes link */
    unsigned
	i_immune			: 1,		/* immune from GC */
    	i_zombie			: 1;		/* stale inode */
    unsigned i_ref;                                     /* soft ref counter */
    struct inode_ops i_ops;                             /* operations */
    struct intnl_stat i_stbuf;				/* attrs */
    struct filesys *i_fs;                               /* file system ptr */
    struct file_identifier *i_fid;                      /* file ident */
    void    *i_private;                                 /* driver data */
    TAILQ_ENTRY(inode) i_nodes;                         /* all i-nodes link */
};

/*
 * Init an i-node record.
 */
#define I_INIT(ino, fs, stat, ops, fid, immunity, private) \
    do { \
        (ino)->i_immune = (immunity) ? 1 : 0; \
        (ino)->i_zombie = 0; \
        (ino)->i_ref = 0; \
        (ino)->i_ops = *(ops); \
        (ino)->i_stbuf = *(stat); \
        (ino)->i_fs = (fs); \
        (ino)->i_fid = (fid); \
        (ino)->i_private = (private); \
    } while (0)

/*
 * Take soft reference to i-node.
 */
#define I_REF(ino) \
    do { \
        TAILQ_REMOVE(&_sysio_inodes, (ino), i_nodes); \
        TAILQ_INSERT_TAIL(&_sysio_inodes, (ino), i_nodes); \
        (ino)->i_ref++; \
        assert((ino)->i_ref); \
    } while (0)

/*
 * Release soft reference to i-node.
 */
#define I_RELE(ino) \
    do { \
        assert((ino)->i_ref); \
	if (!--(ino)->i_ref && (ino)->i_zombie) \
		_sysio_i_gone(ino); \
    } while (0)

/*
 * Attempt to kill an inode.
 */
#define I_GONE(ino) \
    do { \
	_sysio_i_undead(ino); \
	I_RELE(ino); \
    } while (0)

/*
 * The "quick string" record (inspired by the structure of the same name
 * from Linux) is used to pass a string without delimiters as well as useful
 * information about the string.
 */
struct qstr {
    const char *name;
    size_t  len;
    unsigned hashval;
};

/*
 * A path node is an entry in a directory. It may have many aliases, one
 * for each name space in which it occurs. This record holds the
 * common information.
 */
struct pnode_base {
    struct qstr pb_name;                                /* entry name */
    struct inode *pb_ino;                               /* inode */
    LIST_HEAD(, pnode_base) pb_children;                /* children if a dir */
    LIST_ENTRY(pnode_base) pb_sibs;                     /* links to siblings */
    LIST_ENTRY(pnode_base) pb_names;                    /* near names links */
    LIST_HEAD(, pnode) pb_aliases;                      /* aliases */
    struct pnode_base *pb_parent;                       /* parent */
};

/*
 * Since a file system may be multiply mounted, in different parts of the local
 * tree, a file system object may appear in different places. We handle that
 * with aliases. There is one pnode for every alias the system is tracking.
 *
 * Name space traversal depends heavily on the interpretation of many
 * of the fields in this structure. For that reason a detailed discussion
 * of the various fields is given.
 *
 * The reference field records soft references to the record. For instance,
 * it tracks file and directory opens. It does not track sibling references,
 * though, as those are hard references and can be found by examining the
 * aliases list in the base part of the node.
 *
 * The parent value points to the parent directory for this entry, in the
 * *system* name space -- Not the mounted volumes. If you want to examine
 * the moutned volume name space, use the base record.
 *
 * The base value points to the base path node information. It is info common
 * to all of the aliases.
 *
 * The mount value points to the mount record for the rooted name space in
 * which the alias is found. Notably, if a node is the root of a sub-tree then
 * the mount record, among other things, indicates another node
 * (in another sub-tree) that is covered by this one.
 *
 * Another sub-tree, mounted on this node, is indicated by a non-null cover.
 * The pnode pointed to, then, is the root of the mounted sub-tree.
 *
 * The links list entry holds pointers to other aliases for the base path
 * node entry.
 *
 * The nodes link is bookkeeping.
 */
struct pnode {
    unsigned p_ref;                                     /* soft ref count */
    struct pnode *p_parent;                             /* parent */
    struct pnode_base *p_base;                          /* base part */
    struct mount *p_mount;                              /* mount info */
    struct pnode *p_cover;                              /* covering pnode */
    LIST_ENTRY(pnode) p_links;                          /* other aliases */
    TAILQ_ENTRY(pnode) p_nodes;                         /* all nodes links */
};

/*
 * Reference path-tree node.
 */
#define P_REF(pno) \
    do { \
        TAILQ_REMOVE(&_sysio_pnodes, (pno), p_nodes); \
        TAILQ_INSERT_TAIL(&_sysio_pnodes, (pno), p_nodes); \
        (pno)->p_ref++; \
        assert((pno)->p_ref); \
    } while (0)

/*
 * Release reference to path-tree node.
 */
#define P_RELE(pno) \
    do { \
        assert((pno)->p_ref); \
        --(pno)->p_ref; \
    } while (0)

/*
 * An intent record allows callers of namei and lookup to pass some information
 * about what they want to accomplish in the end.
 */
struct intent {
    unsigned int_opmask;                
    void    *int_arg1;
    void    *int_arg2;
};

/*
 * Intent operations.
 */
#define INT_GETATTR         0x01                        /* get attrs */
#define INT_SETATTR         0x02                        /* set attrs */
#define INT_UPDPARENT       0x04                        /* insert/delete */
#define INT_OPEN            0x08                        /* open */
#define INT_CREAT           (INT_UPDPARENT|0x10)        /* insert */
#define INT_READLINK        0x12                        /* readlink */

#define INTENT_INIT(intnt, mask, arg1, arg2) \
    do { \
        (intnt)->int_opmask = (mask); \
        (intnt)->int_arg1 = (arg1); \
        (intnt)->int_arg2 = (arg2); \
    } while (0)

/*
 * Bundled up arguments to _sysio_path_walk.
 */
struct nameidata {
    unsigned nd_flags;                                  /* flags (see below) */
    const char *nd_path;                                /* path arg */
    struct pnode *nd_pno;                               /* returned pnode */
    struct pnode *nd_root;                              /* system/user root */
    struct intent *nd_intent;                           /* intent (NULL ok) */
    unsigned nd_slicnt;					/* symlink indirects */
#ifdef AUTOMOUNT_FILE_NAME
    unsigned nd_amcnt;					/* automounts */
#endif
};

/*
 * Values for nameidata flags field.
 */
#define ND_NOFOLLOW	0x01				/* no follow symlinks */
#define ND_NEGOK	0x02				/* last missing is ok */
#define ND_NOPERMCHECK	0x04				/* don't check perms */

#ifdef AUTOMOUNT_FILE_NAME
#define _ND_INIT_AUTOMOUNT(nd)	((nd)->nd_amcnt = 0)
#else
#define _ND_INIT_AUTOMOUNT(nd)
#endif

#define _ND_INIT_OTHERS(nd) \
    _ND_INIT_AUTOMOUNT(nd)

/*
 * Init nameidata record.
 */
#define ND_INIT(nd, flags, path, root, intnt) \
    do { \
	(nd)->nd_flags = (flags); \
        (nd)->nd_path = (path); \
        (nd)->nd_pno = NULL; \
        (nd)->nd_root = (root); \
        (nd)->nd_intent = (intnt); \
        (nd)->nd_slicnt = 0; \
	_ND_INIT_OTHERS(nd); \
    } while (0)

/*
 * IO completion callback record.
 */
struct ioctx_callback {
    TAILQ_ENTRY(ioctx_callback) iocb_next;             /* list link */
    void    (*iocb_f)(struct ioctx *, void *);         /* cb func */
    void    *iocb_data;                                /* cb data */
};

/*
 * All IO internally is done with an asynchronous mechanism. This record
 * holds the completion information. It's too big :-(
 */
struct ioctx {
    LIST_ENTRY(ioctx) ioctx_link;                       /* AIO list link */
    unsigned
        ioctx_fast                      : 1,		/* from stack space */
	ioctx_done			: 1,		/* transfer complete */
	ioctx_write			: 1;		/* op is a write */
    struct inode *ioctx_ino;                            /* i-node */
    const struct iovec *ioctx_iov;                      /* scatter/gather vec */
    size_t  ioctx_iovlen;                               /* iovec length */
    const struct intnl_xtvec *ioctx_xtv;                /* extents */
    size_t  ioctx_xtvlen;                               /* xtv length */
    ssize_t ioctx_cc;                                   /* rtn char count */
    int ioctx_errno;                                    /* error number */
    TAILQ_HEAD(, ioctx_callback) ioctx_cbq;             /* callback queue */
    void *ioctx_private;				/* driver data */
};

/*
 * Init IO context record.
 */
#define IOCTX_INIT(ioctx, fast, wr, ino, iov, iovlen, xtv, xtvlen) \
    do { \
	(ioctx)->ioctx_fast = (fast); \
	(ioctx)->ioctx_done = 0; \
	(ioctx)->ioctx_write = (wr) ? 1 : 0; \
        (ioctx)->ioctx_ino = (ino); \
        (ioctx)->ioctx_iov = (iov); \
        (ioctx)->ioctx_iovlen = (iovlen); \
        (ioctx)->ioctx_xtv = (xtv); \
        (ioctx)->ioctx_xtvlen = (xtvlen); \
        (ioctx)->ioctx_cc = 0; \
        (ioctx)->ioctx_errno = 0; \
        TAILQ_INIT(&(ioctx)->ioctx_cbq); \
        (ioctx)->ioctx_private = NULL; \
    } while (0)

/*
 * Return whether access to a pnode is read-only.
 */
#define IS_RDONLY(pno) \
	((pno)->p_mount->mnt_flags & MOUNT_F_RO)

extern struct pnode *_sysio_root;

extern TAILQ_HEAD(inodes_head, inode) _sysio_inodes;
extern TAILQ_HEAD(pnodes_head, pnode) _sysio_pnodes;

extern int _sysio_i_init(void);
#ifdef ZERO_SUM_MEMORY
extern void _sysio_i_shutdown(void);
#endif
extern struct inode *_sysio_i_new(struct filesys *fs,
                                  struct file_identifier *fid,
				  struct intnl_stat *stat,
				  unsigned immunity,
                                  struct inode_ops *ops,
                                  void *private);
extern struct inode *_sysio_i_find(struct filesys *fs,
                                   struct file_identifier *fid);
extern void _sysio_i_gone(struct inode *ino);
extern void _sysio_i_undead(struct inode *ino);
extern int _sysio_p_find_alias(struct pnode *parent,
                               struct qstr *name,
                               struct pnode **pnop);
extern int _sysio_p_validate(struct pnode *pno,
                             struct intent *intnt,
                             const char *path);
extern struct pnode_base *_sysio_pb_new(struct qstr *name,
                                        struct pnode_base *parent,
                                        struct inode *ino);
extern void _sysio_pb_gone(struct pnode_base *pb);
extern struct pnode *_sysio_p_new_alias(struct pnode *parent,
                                        struct pnode_base *pb,
                                        struct mount *mnt);
extern void _sysio_p_gone(struct pnode *pno);
extern size_t _sysio_p_prune(struct pnode *root);
extern int _sysio_p_kill_all(struct pnode *root);
extern char *_sysio_pb_path(struct pnode_base *pb, char separator);
extern int _sysio_setattr(struct pnode *pno,
			  struct inode *ino,
			  unsigned mask,
			  struct intnl_stat *stbuf);
extern void _sysio_do_noop(void);
extern void _sysio_do_illop(void);
extern int _sysio_do_ebadf(void);
extern int _sysio_do_einval(void);
extern int _sysio_do_enoent(void);
extern int _sysio_do_enodev(void);
extern int _sysio_do_espipe(void);
extern int _sysio_do_eisdir(void);
extern int _sysio_do_enosys(void);
extern int _sysio_path_walk(struct pnode *parent, struct nameidata *nd);
#ifdef AUTOMOUNT_FILE_NAME
extern void _sysio_next_component(const char *path, struct qstr *name);
#endif
extern int _sysio_permitted(struct pnode *pno, int amode);
extern int _sysio_namei(struct pnode *pno,
                        const char *path,
                        unsigned flags,
                        struct intent *intnt,
                        struct pnode **pnop);
extern int _sysio_p_chdir(struct pnode *pno);
extern int _sysio_ioctx_init(void);
extern void _sysio_ioctx_enter(struct ioctx *ioctx);
extern struct ioctx *_sysio_ioctx_new(struct inode *ino,
				      int wr,
                                      const struct iovec *iov,
				      size_t iovlen,
                                      const struct intnl_xtvec *xtv,
				      size_t xtvlen);
extern int _sysio_ioctx_cb(struct ioctx *ioctx,
			   void (*f)(struct ioctx *, void *),
			   void *data);
extern void _sysio_ioctx_cb_free(struct ioctx_callback *cb);
extern struct ioctx *_sysio_ioctx_find(void *id);
extern int _sysio_ioctx_done(struct ioctx *ioctx);
extern ssize_t _sysio_ioctx_wait(struct ioctx *ioctx);
extern void _sysio_ioctx_complete(struct ioctx *ioctx);
extern int _sysio_open(struct pnode *pno, int flags, mode_t mode);
extern int _sysio_mkdir(struct pnode *where, mode_t mode);
extern int _sysio_mknod(struct pnode *where, mode_t mode, dev_t dev);
