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

/* 
 * cplant yod I/O functions
 */
extern int chmod_yod(const char* path, mode_t);
extern int chown_yod(const char* path, uid_t, gid_t);
extern int stat_yod(const char *path, struct stat *sbuf);
extern int fstat_yod(int fd, struct stat *buf);
#ifdef _HAVE_STATVFS
extern int statfs_yod(const char *path, struct statfs *sbuf);
extern int fstatfs_yod(int fd, struct statfs *buf);
#endif
extern int mkdir_yod(const char *path, mode_t mode);
extern int rmdir_yod(const char *path);
extern int getdirentries_yod(int fd, char *buf, size_t nbytes, loff_t *basep);
extern int link_yod(const char *path1,  const char *path2);
extern int unlink_yod(const char *path);
extern int symlink_yod(const  char *path1, const char *path2 );
extern int rename_yod( const char *path1, const char *path2 );
extern int open_yod(const char *fname, int flags, mode_t mode);
extern int close_yod(int);
extern ssize_t write_yod(int fd, const void *buff, size_t nbytes);
extern ssize_t read_yod(int fd, void *buff, size_t nbytes);
extern int fsync_yod(int fd);
extern int truncate_yod(const char *path, off_t length);
extern int ftruncate_yod(int fd, long length);
extern off_t lseek_yod(int fd, off_t offset, int whence);
