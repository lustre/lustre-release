/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 * Author: Phil Schwan <phil@clusterfs.com>
 *
 * This file is part of Lustre, http://www.lustre.org.
 *
 * Lustre is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * Lustre is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Lustre; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Darwin porting library
 * Make things easy to port
 */
#include <mach/mach_types.h>
#include <string.h>
#include <sys/file.h>
#include <sys/malloc.h>
#include <sys/conf.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/uio.h>
#include <sys/filedesc.h>
#include <sys/namei.h>

#define DEBUG_SUBSYSTEM S_PORTALS

#include <libcfs/libcfs.h>
#include <libcfs/kp30.h>

/*
 * Kernel APIs for file system in xnu
 *
 * Public functions
 */
int
filp_node_size(struct file *fp, off_t *size)
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

cfs_file_t *
filp_open(const char * filename, int flags, int mode, int *err)
{
	struct nameidata nd;
	register cfs_file_t	*fp;
	register struct vnode	*vp;
	cfs_file_t		*nfp;
	int			rc;
	extern struct fileops	vnops;
	extern int nfiles;
        CFS_DECL_CONE_DATA;

        CFS_CONE_IN;
	nfiles++;
	MALLOC_ZONE(nfp, cfs_file_t *, sizeof(cfs_file_t), M_FILE, M_WAITOK|M_ZERO);
	bzero(nfp, sizeof(cfs_file_t));
	nfp->f_count = 1;
	fp = nfp;
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, (char *)filename, current_proc());
	if ((rc = vn_open(&nd, flags, mode)) != 0){
                printf("filp_open failed at (%d)\n", rc);
                if (err != NULL)
                        *err = rc;
		ffree(fp);
                CFS_CONE_EX;
		return NULL;
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
frele_internal(cfs_file_t *fp)
{
	if (fp->f_count == (short)0xffff)
		panic("frele of lustre: stale");
	if (--fp->f_count < 0)
		panic("frele of lustre: count < 0");
	return ((int)fp->f_count);
}

int
filp_close (cfs_file_t *fp)
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
filp_write (cfs_file_t *fp, void *buf, size_t nbyte, off_t *pos)
{
	struct uio auio;
	struct iovec aiov;
	struct proc *p = current_proc();
	long cnt, error = 0;
        CFS_DECL_CONE_DATA;

	aiov.iov_base = (void *)(uintptr_t)buf;
	aiov.iov_len = nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
        if (pos != NULL)
	        auio.uio_offset = *pos;
        else
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
	if ((error = fo_write(fp, &auio, fp->f_cred, 0, p))) {
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
                *pos = auio.uio_offset;
	return cnt;
}

/*
 * Read from filp inside kernel
 */
int
filp_read (cfs_file_t *fp, void *buf, size_t nbyte, off_t *pos)
{
	struct uio auio;
	struct iovec aiov;
	struct proc *p = current_proc();
	long cnt, error = 0;
        CFS_DECL_CONE_DATA;

	aiov.iov_base = (caddr_t)buf;
	aiov.iov_len = nbyte;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
        if (pos != NULL)
	        auio.uio_offset = *pos;
        else
                auio.uio_offset = (off_t)-1;
	if (nbyte > INT_MAX)
		return (EINVAL);
	auio.uio_resid = nbyte;
	auio.uio_rw = UIO_READ;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_procp = p;

	cnt = nbyte;
        CFS_CONE_IN;
	if ((error = fo_read(fp, &auio, fp->f_cred, 0, p)) != 0) {
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
                *pos = auio.uio_offset;

	return cnt;
}

int
filp_fsync (cfs_file_t *fp)
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

int
ref_file(cfs_file_t *fp)
{
        CFS_DECL_CONE_DATA;

        CFS_CONE_IN;
        fref(fp);
        CFS_CONE_EX;
        return 0;
}

int 
rele_file(cfs_file_t *fp)
{
        CFS_DECL_CONE_DATA;

        CFS_CONE_IN;
        frele(fp);
        CFS_CONE_EX;
        return 0;
}

/*
 * Private functions
 */
void vrele_safe(struct vnode *nd)
{ 
        CFS_DECL_CONE_DATA; 
        
        CFS_CONE_IN; 
        vrele(nd); 
        CFS_CONE_EX;
}

int
path_lookup(const char *path, unsigned int flags, struct nameidata *nd)
{
	int ret = 0;
        CFS_DECL_CONE_DATA;

        CFS_CONE_IN;
	NDINIT(nd, LOOKUP, FOLLOW, UIO_SYSSPACE, (char *)path, current_proc());
	if ((ret = namei(nd)) != 0){
		CERROR("path_lookup fail!\n");
	}
        CFS_CONE_EX;

	return ret;
}

int 
file_count(struct file *fp)
{
        return fcount(fp);
}


