/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/libcfs/darwin/darwin-fs.c
 *
 * Darwin porting library
 * Make things easy to port
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#include <mach/mach_types.h>
#include <string.h>
#include <sys/file.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/filedesc.h>
#include <sys/namei.h>

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>

/*
 * Kernel APIs for file system in xnu
 *
 * Public functions
 */

#ifdef __DARWIN8__
#include <sys/vnode.h>

extern int vn_rdwr(enum uio_rw, vnode_t, caddr_t, int, off_t, enum uio_seg, int, kauth_cred_t, int *, proc_t);

/* vnode_size() is not exported */
static errno_t
vnode_size(vnode_t vp, off_t *sizep, vfs_context_t ctx)
{
        struct vnode_attr       va;
        int                     error; 
        
        VATTR_INIT(&va);
        VATTR_WANTED(&va, va_data_size);
        error = vnode_getattr(vp, &va, ctx);
        if (!error)
                *sizep = va.va_data_size;
        return(error);
}

/*
 * XXX Liang:
 *
 * kern_file_*() are not safe for multi-threads now,
 * however, we need them only for tracefiled, so it's
 * not so important to implement for MT.
 */
int
kern_file_size(struct cfs_kern_file *fp, off_t *psize)
{
	int     error;
	off_t   size;

	error = vnode_size(fp->f_vp, &size, fp->f_ctxt);
	if (error)
		return error;

	if (psize)
		*psize = size;
	return 0;
}

struct cfs_kern_file *
kern_file_open(const char *filename, int uflags, int mode)
{
	struct cfs_kern_file	*fp;
	vnode_t			vp;
	int			error;

	fp = (struct cfs_kern_file *)_MALLOC(sizeof(struct cfs_kern_file),
					     M_TEMP, M_WAITOK);
	if (fp == NULL)
		return ERR_PTR(-ENOMEM);

	fp->f_flags = FFLAGS(uflags);
	fp->f_ctxt = vfs_context_create(NULL);

	error = vnode_open(filename, fp->f_flags, mode, 0, &vp, fp->f_ctxt);
	if (error != 0) {
		_FREE(fp, M_TEMP);
		return ERR_PTR(-error);
	} else {
		fp->f_vp = vp;
	}

	return fp;
}

int
kern_file_close(struct cfs_kern_file *fp)
{
        vnode_close(fp->f_vp, fp->f_flags, fp->f_ctxt);
        vfs_context_rele(fp->f_ctxt);
        _FREE(fp, M_TEMP);

        return 0;
}

int
kern_file_read(struct cfs_kern_file *fp, void *buf, size_t nbytes, loff_t *pos)
{
        struct proc *p = current_proc();
        int     resid;
        int     error;

        assert(buf != NULL);
        assert(fp != NULL && fp->f_vp != NULL);

        error = vn_rdwr(UIO_READ, fp->f_vp, buf, nbytes, *pos, 
                        UIO_SYSSPACE32, 0, vfs_context_ucred(fp->f_ctxt), &resid, p);
        if ((error) || (nbytes == resid)) {
                if (!error)
                        error = -EINVAL;
                return error;
        }
        *pos += nbytes - resid;

        return (int)(nbytes - resid);
}

int
kern_file_write(struct cfs_kern_file *fp, void *buf, size_t nbytes, loff_t *pos)
{
        struct proc *p = current_proc();
        int     resid;
        int     error;

        assert(buf != NULL);
        assert(fp != NULL && fp->f_vp != NULL);

        error = vn_rdwr(UIO_WRITE, fp->f_vp, buf, nbytes, *pos, 
                        UIO_SYSSPACE32, 0, vfs_context_ucred(fp->f_ctxt), &resid, p);
        if ((error) || (nbytes == resid)) {
                if (!error)
                        error = -EINVAL;
                return error;
        }
        *pos += nbytes - resid;

        return (int)(nbytes - resid);

}

int
kern_file_sync (struct cfs_kern_file *fp)
{
        return VNOP_FSYNC(fp->f_vp, MNT_WAIT, fp->f_ctxt);
}

#else  /* !__DARWIN8__ */

int
kern_file_size(struct file *fp, off_t *size)
{
        struct vnode *vp = (struct vnode *)fp->f_data;
        struct stat sb;
        int     rc;

        rc = vn_stat(vp, &sb, current_proc());
        if (rc) {
                *size = 0;
                return rc;
        }
        *size = sb.st_size;
        return 0;
}

struct file *
kern_file_open(const char *filename, int flags, int mode)
{
	struct nameidata	nd;
	struct file		*fp;
	register struct vnode	*vp;
	int			rc;
	extern struct fileops	vnops;
	extern int nfiles;
	CFS_DECL_CONE_DATA;

	CFS_CONE_IN;
	nfiles++;
	MALLOC_ZONE(fp, struct file *, sizeof(file_t), M_FILE, M_WAITOK|M_ZERO);
	bzero(fp, sizeof(*fp));
	fp->f_count = 1;
	LIST_CIRCLE(fp, f_list);
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, (char *)filename, current_proc());
	if ((rc = vn_open(&nd, flags, mode)) != 0){
		printf("filp_open failed at (%d)\n", rc);
		FREE_ZONE(fp, sizeof(*fp), M_FILE);
		CFS_CONE_EX;
		return ERR_PTR(rc);
	}
	vp = nd.ni_vp;
	fp->f_flag = flags & FMASK;
	fp->f_type = DTYPE_VNODE;
	fp->f_ops = &vnops;
	fp->f_data = (caddr_t)vp;
	fp->f_cred = current_proc()->p_ucred;
	/*
	 * Hold cred to increase reference
	 */
	crhold(fp->f_cred);
	/*
	 * vnode is locked inside vn_open for lookup,
	 * we should release the lock before return
	 */
	VOP_UNLOCK(vp, 0, current_proc());
	CFS_CONE_EX;

	return fp;
}

static int
frele_internal(struct file *fp)
{
	if (fp->f_count == (short)0xffff)
		panic("frele of lustre: stale");
	if (--fp->f_count < 0)
		panic("frele of lustre: count < 0");
	return ((int)fp->f_count);
}

int
kern_file_close(struct file *fp)
{
	struct vnode	*vp;
	CFS_DECL_CONE_DATA;
	
	if (fp == NULL)
		return 0;

        CFS_CONE_IN;
	if (frele_internal(fp) > 0)
                goto out;
	vp = (struct vnode *)fp->f_data;
	(void )vn_close(vp, fp->f_flag, fp->f_cred, current_proc());
        /*
	 * ffree(fp);
         * Dont use ffree to release fp!!!!
         * ffree will call LIST_REMOVE(fp),
         * but fp is not in any list, this will
         * cause kernel panic
         */
        struct ucred *cred;
        cred = fp->f_cred;
        if (cred != NOCRED) {
                fp->f_cred = NOCRED;
                crfree(cred);
        }
        extern int nfiles;
        nfiles--;
        memset(fp, 0xff, sizeof *fp);
        fp->f_count = (short)0xffff;
        FREE_ZONE(fp, sizeof *fp, M_FILE);
out:
        CFS_CONE_EX;
	return 0;
}

extern void bwillwrite(void);

/*
 * Write buffer to filp inside kernel
 */
int
kern_file_write(struct file *fp, void *buf, size_t nbyte, loff_t *pos)
{
	struct uio auio;
	struct iovec aiov;
	struct proc *p = current_proc();
	long cnt, error = 0;
        int flags = 0;
        CFS_DECL_CONE_DATA;

	aiov.iov_base = (void *)(uintptr_t)buf;
	aiov.iov_len = nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
        if (pos != NULL) {
	        auio.uio_offset = *pos;
                /* 
                 * Liang: If don't set FOF_OFFSET, vn_write()
                 * will use fp->f_offset as the the real offset.
                 * Same in vn_read()
                 */
                flags |= FOF_OFFSET;
        } else
                auio.uio_offset = (off_t)-1;
	if (nbyte > INT_MAX)
		return (EINVAL);
	auio.uio_resid = nbyte;
	auio.uio_rw = UIO_WRITE;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_procp = p;

	cnt = nbyte;
        CFS_CONE_IN;
	if (fp->f_type == DTYPE_VNODE)
		bwillwrite();	/* empty stuff now */
	if ((error = fo_write(fp, &auio, fp->f_cred, flags, p))) {
		if (auio.uio_resid != cnt && (error == ERESTART ||\
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
		/* The socket layer handles SIGPIPE */
		if (error == EPIPE && fp->f_type != DTYPE_SOCKET)
			psignal(p, SIGPIPE);
	}
        CFS_CONE_EX;
	if (error != 0)
		cnt = -error;
	else
		cnt -= auio.uio_resid;
        if (pos != NULL)
                *pos += cnt;
	return cnt;
}

/*
 * Read from filp inside kernel
 */
int
kern_file_read(struct file *fp, void *buf, size_t nbyte, loff_t *pos)
{
	struct uio auio;
	struct iovec aiov;
	struct proc *p = current_proc();
	long cnt, error = 0;
        int  flags = 0;
        CFS_DECL_CONE_DATA;

	aiov.iov_base = (caddr_t)buf;
	aiov.iov_len = nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
        if (pos != NULL) {
	        auio.uio_offset = *pos;
                flags |= FOF_OFFSET;
        } else
                auio.uio_offset = (off_t)-1;
	if (nbyte > INT_MAX)
		return (EINVAL);
	auio.uio_resid = nbyte;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_procp = p;

	cnt = nbyte;
        CFS_CONE_IN;
	if ((error = fo_read(fp, &auio, fp->f_cred, flags, p)) != 0) {
		if (auio.uio_resid != cnt && (error == ERESTART ||
		    error == EINTR || error == EWOULDBLOCK))
			error = 0;
	}
        CFS_CONE_EX;
	if (error != 0)
		cnt = -error;
	else
		cnt -= auio.uio_resid;
        if (pos != NULL)
                *pos += cnt;

	return cnt;
}

int
kern_file_sync(struct file *fp)
{
	struct vnode *vp = (struct vnode *)fp->f_data;
	struct proc *p = current_proc();
	int error = 0;
        CFS_DECL_CONE_DATA;
	
        CFS_CONE_IN;
	if (fref(fp) == -1) {
                CFS_CONE_EX;
		return (-EBADF);
        }
	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY, p);
	error = VOP_FSYNC(vp, fp->f_cred, MNT_WAIT, p);
	VOP_UNLOCK(vp, 0, p);
	frele(fp);
        CFS_CONE_EX;

	return error;
}

#endif /* !__DARWIN8__ */

struct posix_acl *posix_acl_alloc(int count, int flags)
{
        static struct posix_acl acl;
        return &acl;
}
