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

#define _BSD_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/queue.h>

#include "xtio.h"
#include "sysio.h"
#include "inode.h"
#include "fs.h"
#include "mount.h"
#include "file.h"
#include "dev.h"

#ifdef STDFD_DEV
#include "stdfd.h"
#endif

/*
 * White space characters.
 */
#define IGNORE_WHITE		" \t\r\n"

/*
 * Sysio library initialization. Must be called before anything else in the
 * library.
 */
int
_sysio_init()
{
	int	err;
#ifdef WITH_SOCKETS
        int     _sysio_sockets_init(void);
#endif

	err = _sysio_ioctx_init();
	if (err)
		goto error;
	err = _sysio_i_init();
	if (err)
		goto error;
	err = _sysio_mount_init();
	if (err)
		goto error;

	err = _sysio_dev_init();
	if (err)
		goto error;
#ifdef STDFD_DEV
	err = _sysio_stdfd_init();
	if (err)
		goto error;
#endif
#ifdef WITH_SOCKETS
        err = _sysio_sockets_init();
        if (err)
                goto error;
#endif

	goto out;
error:
	errno = -err;
out:
	/*
	 * Unlike all other _sysio routines, this one returns with errno
	 * set. It also returns the error, as usual.
	 */
	return err;
}

/*
 * Sysio library shutdown.
 */
void
_sysio_shutdown()
{

	if (!(_sysio_fd_close_all() == 0 &&
	      _sysio_unmount_all() == 0))
			abort();

#if ZERO_SUM_MEMORY
	_sysio_fd_shutdown();
	_sysio_i_shutdown();
	_sysio_fssw_shutdown();
#endif
}

/* 
 * (kind of)Duplicates strtok function.
 *
 * Given a buffer, returns the longest string
 * that does not contain any delim characters.  Will
 * remove ws and any characters in the ignore string.  
 * Returns the token.  
 *
 * The parameter controlling acceptance controls whether a positive
 * match for some delimiter be made or not. If set, then either a delimiter
 * or NUL character is success.
 *
 */
const char *
_sysio_get_token(const char *buf,
	  int accepts,
	  const char *delim,
	  const char *ignore,
	  char *tbuf)
{
	char	c;
	int	escape, quote;

	/* 
	 * Find the first occurance of delim, recording how many
	 * characters lead up to it.  Ignore indicated characters.
	 */
	escape = quote = 0;
	while ((c = *buf) != '\0') {
		buf++;
		if (!escape) {
			if (c == '\\') {
				escape = 1;
				continue;
			}
			if (c == '\"') {
				quote ^= 1;
				continue;
			}
			if (!quote) {
				if (strchr(delim, c) != NULL) {
					accepts = 1;
					break;
				}
				if (strchr(ignore, c) != NULL)
					continue;
			}
		} else
			escape = 0;
		*tbuf++ = c;
	}
	if (!accepts)
		return NULL;
	*tbuf = '\0';						/* NUL term */
	return buf;
}

/*
 * Parse and record named arguments given as `name = value', comma-separated
 * pairs.
 *
 * NB: Alters the passed buffer.
 */
char *
_sysio_get_args(char *buf, struct option_value_info *vec)
{
	char	*nxt;
	char	*name, *value;
	struct option_value_info *v;

	for (;;) {
		nxt =
		    (char *)_sysio_get_token(buf,
					     1,
					     "=,",
					     IGNORE_WHITE,
					     name = buf);
		if (!nxt ||
		    (nxt != buf && *name == '\0' && buf + strlen(buf) == nxt)) {
			buf = NULL;
			break;
		}
		if (*name == '\0')
			break;
		buf =
		    (char *)_sysio_get_token(nxt,
					     1,
					     ",",
					     IGNORE_WHITE,
					     value = nxt);
		if (*value == '\0')
			value = NULL;
		for (v = vec; v->ovi_name; v++)
			if (strcmp(v->ovi_name, name) == 0)
				break;
		if (!v->ovi_name)
			return NULL;
		v->ovi_value = value;
	}

	return buf;
}

static int
parse_mm(const char *s, dev_t *devp)
{
	unsigned long ul;
	char	*cp;
	dev_t	dev;

	ul = strtoul(s, &cp, 0);
	if (*cp != '+' || ul > USHRT_MAX)
		return -EINVAL;
	dev = ul << 16;
	s = (const char *)++cp;
	ul = strtoul(s, &cp, 0);
	if (*cp != '\0' || ul > USHRT_MAX)
		return -EINVAL;
	dev |= ul & 0xffff;
	*devp = dev;
	return 0;
}

/*
 * Performs the creat command for the namespace assembly
 *
 * NB: Alters the passed buffer.
 */
static int 
do_creat(char *args) 
{
	size_t	len;
	struct option_value_info v[] = {
		{ "ft",		NULL },			/* file type */
		{ "nm",		NULL },			/* name */
		{ "pm",		NULL },			/* permissions */
		{ "ow",		NULL },			/* owner */
		{ "gr",		NULL },			/* group */
		{ "mm",		NULL },			/* major + minor */
		{ "str",	NULL },			/* file data */
		{ NULL,		NULL }
	};
	const char *cp;
	long	perms;
	long	owner, group;
	struct pnode *dir, *pno;
	mode_t	mode;
	struct intent intent;
	dev_t	dev;
	int	err;
  
	len = strlen(args);
	if (_sysio_get_args(args, v) - args != (ssize_t )len ||
	    !(v[0].ovi_value &&
	      v[1].ovi_value &&
	      v[2].ovi_value))
		return -EINVAL;
	perms = strtol(v[2].ovi_value, (char **)&cp, 0);
	if (*cp ||
	    perms < 0 ||
	    (perms == LONG_MAX && errno == ERANGE) ||
	    ((unsigned)perms & ~07777))
		return -EINVAL;
	if (v[3].ovi_value) {
		owner = strtol(v[3].ovi_value, (char **)&cp, 0);
		if (*cp ||
		    ((owner == LONG_MIN || owner == LONG_MAX)
		     && errno == ERANGE))
			return -EINVAL;
	} else
		owner = getuid();
	if (v[4].ovi_value) {
		group = strtol(v[4].ovi_value, (char **)&cp, 0);
		if (*cp ||
		    ((group == LONG_MIN || group == LONG_MAX) &&
		     errno == ERANGE))
			return -EINVAL;
	} else
		group = getegid();

	if (!(dir = _sysio_cwd) && !(dir = _sysio_root))
		return -ENOENT;
	err = 0;
	mode = perms;
	if (strcmp(v[0].ovi_value, "dir") == 0) {
		INTENT_INIT(&intent, INT_CREAT, &mode, 0);
		err =
		    _sysio_namei(dir, v[1].ovi_value, ND_NEGOK, &intent, &pno);
		if (err)
			return err;
		if (pno->p_base->pb_ino)
			err = -EEXIST;
		else if (IS_RDONLY(pno->p_parent,
				   pno->p_parent->p_base->pb_ino))
			err = -EROFS;
		else {
			struct inode *ino;

			ino = pno->p_parent->p_base->pb_ino;
			err = (*ino->i_ops.inop_mkdir)(pno, mode);
		}
		P_RELE(pno);
	} else if (strcmp(v[0].ovi_value, "chr") == 0) {
		if (!(v[5].ovi_value && parse_mm(v[5].ovi_value, &dev) == 0))
			return -EINVAL;
		mode |= S_IFCHR;
		INTENT_INIT(&intent, INT_CREAT, &mode, 0);
		err =
		    _sysio_namei(dir, v[1].ovi_value, ND_NEGOK, &intent, &pno);
		if (err)
			return err;
		if (pno->p_base->pb_ino)
			err = -EEXIST;
		else if (IS_RDONLY(pno->p_parent,
				   pno->p_parent->p_base->pb_ino))
			err = -EROFS;
		else {
			struct inode *ino;

			ino = pno->p_parent->p_base->pb_ino;
			err = (*ino->i_ops.inop_mknod)(pno, mode, dev);
		}
		P_RELE(pno);
	} else if (strcmp(v[0].ovi_value, "blk") == 0) {
		/*
		 * We don't support block special files yet.
		 */
		return -EINVAL;
	} else if (strcmp(v[0].ovi_value, "file") == 0) {
		int	i;
		struct inode *ino;

		i = O_CREAT|O_EXCL;
		INTENT_INIT(&intent, INT_CREAT, &mode, &i);
		err =
		    _sysio_namei(dir, v[1].ovi_value, ND_NEGOK, &intent, &pno);
		if (err)
			return err;
		err = _sysio_open(pno, O_CREAT|O_EXCL, mode);
		if (err) {
			P_RELE(pno);
			return err;
		}
		ino = pno->p_base->pb_ino;
		if (!err && v[6].ovi_value) {
			struct iovec iovec;
			struct intnl_xtvec xtvec;
			struct ioctx io_context;

			/*
			 * Deposit optional file content.
			 */
			iovec.iov_base = v[6].ovi_value;
			iovec.iov_len = strlen(v[6].ovi_value);
			xtvec.xtv_off = 0;
			xtvec.xtv_len = iovec.iov_len;
			IOCTX_INIT(&io_context,
				   1,
				   1,
				   ino,
				   &iovec, 1,
				   &xtvec, 1);
			_sysio_ioctx_enter(&io_context);
			err =
			    (*ino->i_ops.inop_write)(pno->p_base->pb_ino,
						     &io_context);
			if (!err) {
				ssize_t	cc;

				cc = _sysio_ioctx_wait(&io_context);
				if (cc < 0)
					err = cc;
				else if ((size_t )cc != iovec.iov_len)
					err = -EIO;		/* huh? */
			} else
				_sysio_ioctx_complete(&io_context);
		}
		i = (*ino->i_ops.inop_close)(ino);
		if (!err)
			err = i;
		P_RELE(pno);
	} else 
		err = -EINVAL;

	return err;
}

/*
 * Do mount.
 *
 * NB: The passed buffer is altered.
 */
static int 
do_mnt(char *args) 
{
	size_t	len;
	struct option_value_info v[] = {
		{ "dev",	NULL },			/* source (type:dev) */
		{ "dir",	NULL },			/* target dir */
		{ "fl",		NULL },			/* flags */
		{ "da",		NULL },			/* mount data */
		{ NULL,		NULL }
	};
	char	*ty, *name;
	unsigned long flags;
	struct pnode *dir;
  
	len = strlen(args);
	if (_sysio_get_args(args, v) - args != (ssize_t )len ||
	    !(v[0].ovi_value && v[1].ovi_value))
		return -EINVAL;
	ty =
	    (char *)_sysio_get_token(v[0].ovi_value,
				     1,
				     ":",
				     "",
				     name = v[0].ovi_value);
	flags = 0;
	if (v[2].ovi_value) {
		char	*cp;

		/*
		 * Optional flags.
		 */
		flags = strtoul(v[2].ovi_value, &cp, 0);
		if (*cp || (flags == ULONG_MAX && errno == ERANGE))
			return -EINVAL;
	}

	if (strlen(v[1].ovi_value) == 1 && v[1].ovi_value[0] == PATH_SEPARATOR) {
		/*
		 * Aha! It's root they want. Have to do that special.
		 */
		return _sysio_mount_root(ty, name, flags, v[3].ovi_value);
	}

	if (!(dir = _sysio_cwd) && !(dir = _sysio_root))
		return -ENOENT;
	return _sysio_mount(dir,
			    ty,
			    v[1].ovi_value,
			    name,
			    flags,
			    v[3].ovi_value);
}


#if 0
/*
 * Chdir
 *
 * NB: Alters the passed buffer.
 */
static int 
do_cd(char *args) 
{
	size_t	len;
	struct option_value_info v[] = {
		{ "dir",	NULL },			/* directory */
		{ NULL,		NULL }
	};
	int	err;
	struct pnode *dir, *pno;

	len = strlen(args);
	if (_sysio_get_args(args, v) - args != (ssize_t )len || !v[0].ovi_value)
		return -EINVAL;

	if (!(dir = _sysio_cwd) && !(dir = _sysio_root))
		return -ENOENT;
	err = _sysio_namei(dir, v[0].ovi_value, 0, NULL, &pno);
	if (err)
		return err;
	err = _sysio_p_chdir(pno);
	if (err)
		P_RELE(pno);
	return err;
}
#endif

/*
 * Does a chmod
 *
 * NB: Alters passed buffer.
 */
static int 
do_chmd(char *args)
{
	size_t	len;
	struct option_value_info v[] = {
		{ "src",	NULL },			/* path */
		{ "pm",		NULL },			/* perms */
		{ NULL,		NULL }
	};
	long	perms;
	char	*cp;
	struct intnl_stat stbuf;
	int	err;
	struct pnode *dir, *pno;
  
	len = strlen(args);
	if (_sysio_get_args(args, v) - args != (ssize_t )len ||
	    !(v[0].ovi_value && v[1].ovi_value))
		return -EINVAL;
	perms = strtol(v[1].ovi_value, &cp, 0);
	if (*cp ||
	    perms < 0 ||
	    (perms == LONG_MAX && errno == ERANGE) ||
	    ((unsigned)perms & ~07777))
		return -EINVAL;
	(void )memset(&stbuf, 0, sizeof(stbuf));
	stbuf.st_mode = (mode_t)perms;

	if (!(dir = _sysio_cwd) && !(dir = _sysio_root))
		return -ENOENT;
	err = _sysio_namei(dir, v[0].ovi_value, 0, NULL, &pno);
	if (err)
		return err;
	err = _sysio_setattr(pno, pno->p_base->pb_ino, SETATTR_MODE, &stbuf);
	P_RELE(pno);

	return err;
}

static int
do_open(char *args)
{
	size_t	len;
	struct option_value_info v[] = {
		{ "nm",		NULL },			/* path */
		{ "fd",		NULL },			/* fildes */
		{ "m",		NULL },			/* mode */
		{ NULL,		NULL }
	};
	char	*cp;
	long	l;
	int	fd;
	unsigned long ul;
	mode_t	m;
	struct pnode *dir, *pno;
	struct intent intent;
	int	err;
	struct file *fil;

/*
 * Check if long overflows integer range.
 */
#if LONG_MAX <= INT_MAX
#define _irecheck(_l, _e) \
	((_l) == LONG_MAX && (_e) == ERANGE)
#else
#define _irecheck(_l, _e) \
	((_l) > INT_MAX)
#endif

	len = strlen(args);
	if (_sysio_get_args(args, v) - args != (ssize_t )len ||
	    !(v[0].ovi_value && v[1].ovi_value && v[2].ovi_value))
		return -EINVAL;
	l = strtol(v[1].ovi_value, (char **)&cp, 0);
	if (*cp || l < 0 || _irecheck(l, errno))
		return -EINVAL;
	fd = (int )l;
	ul = strtoul(v[1].ovi_value, (char **)&cp, 0);
	if (*cp ||
	    (ul == ULONG_MAX && errno == ERANGE))
		return -EINVAL;
	m = (mode_t )ul & (O_RDONLY|O_WRONLY|O_RDWR);

	if (!(dir = _sysio_cwd) && !(dir = _sysio_root))
		return -ENOENT;
	INTENT_INIT(&intent, INT_OPEN, &m, NULL);
	pno = NULL;
	err = _sysio_namei(dir, v[0].ovi_value, 0, &intent, &pno);
	if (err)
		return err;
	fil = NULL;
	do {
		err = _sysio_open(pno, m, 0);
		if (err)
			break;
		fil = _sysio_fnew(pno->p_base->pb_ino, m);
		if (!fil) {
			err = -ENOMEM;
			break;
		}
		err = _sysio_fd_set(fil, fd, 1);
		if (err < 0)
			break;
		P_RELE(pno);
		return 0;
	} while (0);
	if (fil)
		F_RELE(fil);
	if (pno)
		P_RELE(pno);
	return err;

#undef _irecheck
}

/*
 * Execute the given cmd.
 *
 * NB: Buf is altered.
 */
static int 
do_command(char *buf)
{
	size_t	len;
	char	*args, *cmd;

	len = strlen(buf);
	args = (char *)_sysio_get_token(buf, 1, ",", IGNORE_WHITE, cmd = buf);
	if (args) {
		if (strcmp("creat", cmd) == 0)
			return do_creat(args);
		if (strcmp("mnt", cmd) == 0)
			return do_mnt(args);
#if 0
		if (strcmp("cd", cmd) == 0)
			return do_cd(args);
#endif
		if (strcmp("chmd", cmd) == 0)
			return do_chmd(args);
		if (strcmp("open", cmd) == 0)
			return do_open(args);
	}
	return -EINVAL;
}

/*
 * Given a command sequence buffer, parse it and run the given
 * commands 
 */
int 
_sysio_boot(const char *buf
#if DEFER_INIT_CWD
	    , const char *path
#endif
	   )
{
	char	c, *tok;
	ssize_t	len;
	int	err;

	if (!buf)
		buf = "";
	/*
	 * Allocate token buffer.
	 */
	len = strlen(buf);
	tok = malloc(len ? len : 1);
	if (!tok)
		return -ENOMEM;
	err = 0;
	while (1) {
		/*
		 * Discard leading white space.
		 */
		while ((c = *buf) != '\0' &&
		       !(c == '{' || strchr(IGNORE_WHITE, c) == NULL))
			buf++;
		if (c == '\0')
			break;
		if (c != '{') {
			err = -EINVAL;
			break;
		}
		/*
		 * Get the command.
		 */
		buf =
		    (char *)_sysio_get_token(buf + 1,
					     0,
					     "}",
					     IGNORE_WHITE,
					     tok);
		if (!buf) {
			err = -EINVAL;
			break;
		}
		/*
		 * Perform.
		 */
		err = do_command(tok);
		if (err)
			break;
	}
	free(tok);
#if DEFER_INIT_CWD
	if (err)
		return err;
	_sysio_init_cwd = path;
#endif
	return err;
}
