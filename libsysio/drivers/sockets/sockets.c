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

#ifdef __linux__
#define _BSD_SOURCE
#endif

#include <stdio.h>					/* for NULL */
#include <stdlib.h>
#ifdef __linux__
#include <string.h>
#endif
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#ifdef __linux__
#include <linux/net.h>
#endif
#include <sys/uio.h>
#include <sys/queue.h>

#include "sysio.h"
#include "xtio.h"
#include "native.h"
#include "fs.h"
#include "inode.h"
#include "file.h"
#include "dev.h"					/* _sysio_nodev_ops */

/*
 * Sockets interface driver
 */

/*
 * Sockets file identifiers format.
 */
struct sockets_ino_identifier {
	ino_t	inum;					/* i-number */
};

/*
 * Driver-private i-node information we keep about in-use sockets.
 */
struct socket_info {
	struct sockets_ino_identifier ski_ident;	/* unique identifier */
	struct file_identifier ski_fileid;		/* ditto */
	int	ski_fd;				/* host fildes */
};

static int sockets_inop_close(struct inode *ino);
static int sockets_inop_read(struct inode *ino,
			     struct ioctx *ioctx);
static int sockets_inop_write(struct inode *ino,
			      struct ioctx *ioctxp);
static _SYSIO_OFF_T sockets_inop_pos(struct inode *ino,
				     _SYSIO_OFF_T off);
static int sockets_inop_iodone(struct ioctx *ioctx);
static int sockets_inop_sync(struct inode *ino);
static int sockets_inop_datasync(struct inode *ino);
static int sockets_inop_fcntl(struct inode *ino, int cmd, va_list ap, int *rtn);
static int sockets_inop_ioctl(struct inode *ino,
			     unsigned long int request,
			     va_list ap);
static void sockets_inop_gone(struct inode *ino);
static void sockets_illop(void);

/*
 * Given i-node, return driver private part.
 */
#define I2SKI(ino)	((struct socket_info *)((ino)->i_private))

struct filesys_ops sockets_filesys_ops = {
	(void (*)(struct filesys *))sockets_illop
};

static struct filesys *sockets_fs = NULL;

static struct inode_ops sockets_i_ops;

/*
 * Initialize this driver.
 */
int
_sysio_sockets_init()
{

	assert(!sockets_fs);

	sockets_i_ops = _sysio_nodev_ops;
	sockets_i_ops.inop_close = sockets_inop_close;
	sockets_i_ops.inop_read = sockets_inop_read;
	sockets_i_ops.inop_write = sockets_inop_write;
	sockets_i_ops.inop_pos = sockets_inop_pos;
	sockets_i_ops.inop_iodone = sockets_inop_iodone;
	sockets_i_ops.inop_fcntl = sockets_inop_fcntl;
	sockets_i_ops.inop_sync = sockets_inop_sync;
	sockets_i_ops.inop_datasync = sockets_inop_datasync;
	sockets_i_ops.inop_ioctl = sockets_inop_ioctl;
	sockets_i_ops.inop_gone = sockets_inop_gone;

	sockets_fs = _sysio_fs_new(&sockets_filesys_ops, 0, NULL);
	if (!sockets_fs)
		return -ENOMEM;

	return 0;
}

static int
sockets_inop_close(struct inode *ino)
{
	struct socket_info *ski = I2SKI(ino);
	int	err;

	if (ski->ski_fd < 0)
		return -EBADF;

	err = syscall(SYSIO_SYS_close, ski->ski_fd);
	if (err)
		return -errno;
	ski->ski_fd = -1;
	return 0;
}

/*
 * A helper function performing the real IO operation work.
 *
 * We don't really have async IO. We'll just perform the function
 * now.
 */
static int
doio(ssize_t (*f)(int, const struct iovec *, int),
     struct inode *ino,
     struct ioctx *ioctx)
{
	struct socket_info *ski = I2SKI(ino);

	assert(ski->ski_fd >= 0);

	/* XXX there's no way to check the position
	 * here we only could ingore the extends
	 */
	if (ioctx->ioctx_xtvlen != 1)
		return -EINVAL;

	if (ioctx->ioctx_iovlen && (int) ioctx->ioctx_iovlen < 0)
		return -EINVAL;

	/*
	 * Call the appropriate (read/write) IO function to
	 * transfer the data now.
	 */
	ioctx->ioctx_cc =
	    (*f)(ski->ski_fd, ioctx->ioctx_iov, ioctx->ioctx_iovlen);
	if (ioctx->ioctx_cc < 0)
		ioctx->ioctx_errno = errno;

	ioctx->ioctx_done = 1;
	return 0;
}

/*
 * Helper function passed to doio(), above, to accomplish a real readv.
 */
static ssize_t
_readv(int fd, const struct iovec *vector, int count)
{

	return syscall(SYSIO_SYS_readv, fd, vector, count);
}

static int
sockets_inop_read(struct inode *ino,
		  struct ioctx *ioctx)
{

	return doio(_readv, ino, ioctx);
}

/*
 * Helper function passed to doio(), above, to accomplish a real writev.
 */
static ssize_t
_writev(int fd, const struct iovec *vector, int count)
{

	return syscall(SYSIO_SYS_writev, fd, vector, count);
}

static int
sockets_inop_write(struct inode *ino,
		   struct ioctx *ioctx)
{

	return doio(_writev, ino, ioctx);
}

static _SYSIO_OFF_T
sockets_inop_pos(struct inode *ino __IS_UNUSED, _SYSIO_OFF_T off __IS_UNUSED)
{
	return -EINVAL;
}

static int
sockets_inop_iodone(struct ioctx *ioctxp __IS_UNUSED)
{

	/*
	 * It's always done in this driver. It completed when posted.
	 */
	return 1;
}

static int
sockets_inop_fcntl(struct inode *ino __IS_UNUSED,
		  int cmd __IS_UNUSED,
		  va_list ap __IS_UNUSED,
		  int *rtn)
{
	long arg;

	assert(I2SKI(ino)->ski_fd >= 0);

	switch (cmd) {
	case F_GETFD:
	case F_GETFL:
	case F_GETOWN:
		*rtn = syscall(SYSIO_SYS_fcntl, I2SKI(ino)->ski_fd, cmd);
		break;
	case F_DUPFD:
	case F_SETFD:
	case F_SETFL:
	case F_GETLK:
	case F_SETLK:
	case F_SETLKW:
	case F_SETOWN:
		arg = va_arg(ap, long);
		*rtn = syscall(SYSIO_SYS_fcntl, I2SKI(ino)->ski_fd, cmd, arg);
		break;
	default:
		*rtn = -1;
		errno = EINVAL;
	}
	return *rtn == -1 ? -errno : 0;
}

static int
sockets_inop_sync(struct inode *ino)
{

	assert(I2SKI(ino)->ski_fd >= 0);

	return syscall(SYSIO_SYS_fsync, I2SKI(ino)->ski_fd);
}

static int
sockets_inop_datasync(struct inode *ino)
{

	assert(I2SKI(ino)->ski_fd >= 0);

	return syscall(SYSIO_SYS_fdatasync, I2SKI(ino)->ski_fd);
}

#ifdef HAVE_LUSTRE_HACK
/*
 * we blindly extract 4 params and pass to host kernel, the stack
 * should be ok. hope no ioctl will consume more then 4 params...
 */
static int
sockets_inop_ioctl(struct inode *ino,
		  unsigned long int request,
		  va_list ap)
{
	long arg1, arg2, arg3, arg4;

	assert(I2SKI(ino)->ski_fd >= 0);

	arg1 = va_arg(ap, long);
	arg2 = va_arg(ap, long);
	arg3 = va_arg(ap, long);
	arg4 = va_arg(ap, long);

	return syscall(SYSIO_SYS_ioctl, I2SKI(ino)->ski_fd, request,
		       arg1, arg2, arg3, arg4);
}
#else
static int
sockets_inop_ioctl(struct inode *ino __IS_UNUSED,
		  unsigned long int request __IS_UNUSED,
		  va_list ap __IS_UNUSED)
{
	/*
	 * I'm lazy. Maybe implemented later.
	 */
	return -ENOTTY;
}
#endif

static void
sockets_inop_gone(struct inode *ino)
{

	(void )sockets_inop_close(ino);
	free(ino->i_private);
}

static void
sockets_illop(void)
{

	abort();
}

static struct inode *
_sysio_sockets_inew()
{
	static ino_t inum = 1;
	struct socket_info *ski;
	struct inode *ino;
	static struct intnl_stat zero_stat;

	ski = malloc(sizeof(struct socket_info));
	if (!ski)
		return NULL;
	ski->ski_ident.inum = inum++;
	ski->ski_fileid.fid_data = &ski->ski_ident;
	ski->ski_fileid.fid_len = sizeof(ski->ski_ident);
	ski->ski_fd = -1;

	ino =
	    _sysio_i_new(sockets_fs,
			 &ski->ski_fileid,
			 &zero_stat,
			 0,
			 &sockets_i_ops,
			 ski);
	if (!ino)
		free(ski);

	return ino;
}

int
SYSIO_INTERFACE_NAME(socket)(int domain, int type, int protocol)
{
	int	err;
	struct inode *ino;
	struct socket_info *ski;
	struct file *fil;

	err = 0;
	fil = NULL;

	ino = _sysio_sockets_inew();
	if (!ino) {
		err = -ENOMEM;
		goto error;
	}

	ski = I2SKI(ino);
#ifndef SYSIO_SYS_socketcall
	ski->ski_fd = syscall(SYSIO_SYS_socket, domain, type, protocol);
#else
	{
		unsigned long avec[3] = {domain, type, protocol};
		ski->ski_fd =
		    syscall(SYSIO_SYS_socketcall, SYS_SOCKET, avec);
	}
#endif
	if (ski->ski_fd < 0) {
		err = -errno;
		goto error;
	}

	fil = _sysio_fnew(ino, O_RDWR);
	if (!fil) {
		err = -ENOMEM;
		goto error;
	}

#ifdef HAVE_LUSTRE_HACK
	err = _sysio_fd_set(fil, ski->ski_fd, 1);
#else
	err = _sysio_fd_set(fil, -1, 0);
#endif
	if (err < 0)
		goto error;

	return err;

error:
	if (fil)
		F_RELE(fil);
	if (ino)
		I_RELE(ino);

	errno = -err;
	return -1;
}

int
SYSIO_INTERFACE_NAME(accept)(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	int	err;
	struct inode *ino;
	struct socket_info *ski;
	struct file *ofil, *nfil;

	err = 0;
	nfil = NULL;
	ino = NULL;

	ofil = _sysio_fd_find(s);
	if (!ofil) {
		err = -EBADF;
		goto error;
	}

	ino = _sysio_sockets_inew();
	if (!ino) {
		err = -ENOMEM;
		goto error;
	}

	nfil = _sysio_fnew(ino, O_RDWR);
	if (!nfil) {
		err = -ENOMEM;
		goto error;
	}

	ski = I2SKI(ino);
#ifndef SYSIO_SYS_socketcall
	ski->ski_fd =
	    syscall(SYSIO_SYS_accept,
		    I2SKI(ofil->f_ino)->ski_fd,
		    addr,
		    addrlen);
#else
	{
		unsigned long avec[3] = {
			(unsigned long) I2SKI(ofil->f_ino)->ski_fd,
			(unsigned long) addr,
			(unsigned long) addrlen};
		ski->ski_fd =
		    syscall(SYSIO_SYS_socketcall, SYS_ACCEPT, avec);
	}
#endif
	if (ski->ski_fd < 0) {
		err = -errno;
		goto error;
	}

#ifdef HAVE_LUSTRE_HACK
	err = _sysio_fd_set(nfil, ski->ski_fd, 1);
#else
	err = _sysio_fd_set(nfil, -1, 0);
#endif
	if (err < 0)
		goto error;

	return err;

error:
	if (nfil)
		F_RELE(nfil);
	if (ino)
		I_RELE(ino);

	errno = -err;
	return -1;
}

int
SYSIO_INTERFACE_NAME(bind)(int sockfd,
			   const struct sockaddr *my_addr,
			   socklen_t addrlen)
{
	int	err;
	struct file *fil;
#ifdef SYSIO_SYS_socketcall
	unsigned long avec[3];
#endif

	err = 0;

	fil = _sysio_fd_find(sockfd);
	if (!fil) {
		err = -EBADF;
		goto out;
	}

#ifndef SYSIO_SYS_socketcall
	if (syscall(SYSIO_SYS_bind,
		    I2SKI(fil->f_ino)->ski_fd,
		    my_addr,
		    addrlen)) {
#else
	avec[0] = I2SKI(fil->f_ino)->ski_fd;
	avec[1] = (unsigned long )my_addr;
	avec[2] = addrlen;
	if (syscall(SYSIO_SYS_socketcall, SYS_BIND, avec) != 0) {
#endif
		err = -errno;
		goto out;
	}

	return 0;
out:
	errno = -err;
	return -1;
}

int
SYSIO_INTERFACE_NAME(listen)(int s, int backlog)
{
	int	err;
	struct file *fil;
#ifdef SYSIO_SYS_socketcall
	unsigned long avec[2];
#endif

	err = 0;

	fil = _sysio_fd_find(s);
	if (!fil) {
		err = -EBADF;
		goto out;
	}

#ifndef SYSIO_SYS_socketcall
	if (syscall(SYSIO_SYS_listen,
		    I2SKI(fil->f_ino)->ski_fd,
		    backlog) != 0) {
#else
	avec[0] = I2SKI(fil->f_ino)->ski_fd;
	avec[1] = backlog;
	if (syscall(SYSIO_SYS_socketcall, SYS_LISTEN, avec) != 0) {
#endif
		err = -errno;
		goto out;
	}

	return 0;
out:
	errno = -err;
	return -1;
}

int
SYSIO_INTERFACE_NAME(connect)(int sockfd,
			      const struct sockaddr *serv_addr,
			      socklen_t addrlen)
{
	int	err;
	struct file *fil;
#ifdef SYSIO_SYS_socketcall
	unsigned long avec[3];
#endif

	err = 0;

	fil = _sysio_fd_find(sockfd);
	if (!fil) {
		err = -EBADF;
		goto out;
	}

#ifndef SYSIO_SYS_socketcall
	if (syscall(SYSIO_SYS_connect,
		    I2SKI(fil->f_ino)->ski_fd,
		    serv_addr,
		    addrlen) != 0) {
#else
	avec[0] = I2SKI(fil->f_ino)->ski_fd;
	avec[1] = (unsigned long )serv_addr;
	avec[2] = addrlen;
	if (syscall(SYSIO_SYS_socketcall, SYS_CONNECT, avec) != 0) {
#endif
		err = -errno;
		goto out;
	}

	return 0;
out:
	errno = -err;
	return -1;
}
