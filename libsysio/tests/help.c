#include <stdio.h>
#include "test_driver.h"

void do_help() {
  int i, d, count = 0;

  fprintf(outfp, "libsysio test harness\n");
  fprintf(outfp, "To get help on a specific command, use HELP <cmd>\n");
  fprintf(outfp, "To exit, type exit or quit\n");
  
  fprintf(outfp, "\nTo save the result from a function, use \"$res = CALL command\"\n");
  fprintf(outfp, "To later use that res, do \"comm $res\"\n");

  fprintf(outfp, "\n\nAvailable commands are (always preceded by CALL):\n\n");
  
  /* Get total number of commands */
  while (cmd_list[count].cmd)  
    count++;

  d = count/4;
  if (count % 4)
    d++;
  for (i=0; i < d; i++) {
   
    if ( (i+d) < count ) {
      if ( (i + 2*d) < count) {
	if ( (i+3*d) < count) 
	  fprintf(outfp, "%-15s %-15s %-15s %-15s\n",
		 cmd_list[i].cmd, cmd_list[i+d].cmd, cmd_list[i+2*d].cmd, 
		 cmd_list[i+3*d].cmd);
	else
	  fprintf(outfp, "%-15s %-15s %-15s\n",
		 cmd_list[i].cmd, cmd_list[i+d].cmd, cmd_list[i+2*d].cmd);
      } else
	fprintf(outfp, "%-15s %-15s\n",
	       cmd_list[i].cmd, cmd_list[i+d].cmd);
    } else
      fprintf(outfp, "%-15s\n",
	       cmd_list[i].cmd);
  }
  fprintf(outfp, "\n");
}

void usage_setdebug()
{
  fprintf(outfp, "setdebug [level]: Set debugging level to level\n");
}

void usage_setbuf()
{
  fprintf(outfp, "setbuf [val] [size] [buf] [off]: fill size bytes of buf with byte val\n");
}


void usage_clear()
{
  fprintf(outfp, "clear buf: zero out the buffer\n");
}

void usage_printline()
{
  fprintf(outfp, "printline [0|1]: Turn off (0) or on (1) the printing of line number\n");
  fprintf(outfp, "               : and file name with debug output\n");
}

void usage_endian()
{
  fprintf(outfp, "endian: returns 1 for bigendian machines and 0 for little endian machines\n");
}


void usage_sizeof()
{
  fprintf(outfp, "sizeof [type]: returns the size of the data type.  Currently \n");
  fprintf(outfp, "             : supported types are char, int, long, flock, stat and \n");
  fprintf(outfp, "             : statvfs\n");
}


void usage_get_buffer()
{
  fprintf(outfp, "alloc [size] <align>: allocates a buffer of size bytes aligned to align\n");
  fprintf(outfp, "                    : align is optional.  If not there, buffer will be aligned on\n");
  fprintf(outfp, "                    : a one-byte boundary.  returns an index into an array that \n");
  fprintf(outfp, "                    : holds the buffer\n");
}



void usage_free_buffer()
{
  fprintf(outfp, "free [bufidx]: frees buffer at bufidx.  Returns 0 on success, -1 on failure\n"); 
}

void usage_do_fillbuff()
{
  fprintf(outfp, "fill [val] [type] [size] [offset] [buf] : Fills the buffer buf with size \n");
  fprintf(outfp, "                                        : bytes of val starting at buf+offset\n");
  fprintf(outfp, "                                        : The type of val is specified by type,\n");
  fprintf(outfp, "                                        : which can be UINT, STR, or PTR\n");
}

void usage_do_printbuf()
{
  fprintf(outfp, "printbuf [buf] : print out contents of the buffer stored in buf\n");
  fprintf(outfp, "               : Always returns 0\n");
}

void usage_cmpbufs()
{
  fprintf(outfp, "cmpstr [buf1] [buf2]: Compare the contents of buf1 with buf2 by issuing a \n");
  fprintf(outfp, "                      strcmp call.  Returns 0 if the buffers match\n");
}


void usage_init()
{
  fprintf(outfp, "init <driver> <path> <flags>: Without any arguments, initilizes libsysio\n");
  fprintf(outfp, "                            : to default values for root directory and\n");
  fprintf(outfp, "                            : current directory.  Accepts optional\n");
  fprintf(outfp, "                            : arguments for the root driver, the mount\n");
  fprintf(outfp, "                            : path, and the mount flags.  Must be called\n");
  fprintf(outfp, "                            : before any other libsysio calls.  Returns\n");
  fprintf(outfp,"                             : 0 on success, -1 on failure\n");
}
 
void usage_list()
{
  fprintf(outfp, "list <dir>: lists contents of dir.  If dir is ommitted, will list contents\n");
  fprintf(outfp, "          : of the current working directory\n");
  fprintf(outfp, "          : Returns 0 on success, -1 on failure\n");
}
 
void usage_chdir()
{
  fprintf(outfp, "chdir [dir]: change the current working directory to dir\n");
  fprintf(outfp, "           : Returns 0 on success, -1 on failure\n");
}
 
void usage_chmod()
{
  fprintf(outfp, "chmod [newmode] [file]: change mode of file to newmode.  newmode can be \n");
  fprintf(outfp, "                      : specifed symbolically (eg, a+x), numerically \n");
  fprintf(outfp, "                      : (eg, 0777), or using system defines \n"); 
  fprintf(outfp, "                      : (eg S_IRUSR|S_IWUSR|S_IRGRP)\n");
  fprintf(outfp, "                      : Returns 0 on success, -1 on failure\n");

}

void  usage_chown()
{
  fprintf(outfp, "chown [newown[:newgrp]] [file]: change the owner of file to newown, the group\n");
  fprintf(outfp, "                              : of file to newgrp, or both\n");
  fprintf(outfp, "                              : Returns 0 on success, -1 on failure\n");
}

void usage_open()
{
  fprintf(outfp, "open [file] [flags] <mode>: open file with given flags.  The mode is optional\n");
  fprintf(outfp, "                          : can use defines for open, (eg, open foo O_RDONLY)\n");
  fprintf(outfp, "                          : If flags are 0, file will be opened with O_RDWR\n");
  fprintf(outfp, "                          : Returns the file descriptor for the opened file\n");
}

void usage_close()
{
  fprintf(outfp, "close [file]: closes the file.  Returns 0 on success, -1 on failure\n");
}

void usage_mount()
{
  fprintf(outfp, "mount [fstype:source] [target]: mount source (which has fstype as its file\n");
  fprintf(outfp, "                              : system type) onto target.\n"); 
  fprintf(outfp, "                              : Returns 0 on success, -1 on failure\n");
}

void usage_dup()
{
  fprintf(outfp, "dup [oldfd]: Duplicate oldfd.  Returns the duplicated file descriptor\n");
  fprintf(outfp, "           : Returns -1 on failure\n");
}

void usage_dup2()
{
  fprintf(outfp, "dup2 [oldfd] [newfd]: Make newfd be a copy of oldfd.  Returns newfd on \n");
  fprintf(outfp, "                    : success and -1 on failure\n");
}

void usage_fcntl()
{
  fprintf(outfp, "fcntl [fd] [cmd] <args> : execute fcntl cmd on file with file descriptor fd\n");
  fprintf(outfp, "                        : using (optional) args.  Accepted (but not \n");
  fprintf(outfp, "                        : necesarily working) commands are F_DUPFD, \n");
  fprintf(outfp, "                        : F_GETFD, F_GETFL, F_GETOWN, F_SETFD, F_SETFL,\n");
  fprintf(outfp, "                        : F_SETOWN, F_SETLK, F_SETLKW, and F_GETLK. \n");
}

void usage_fstat()
{
  fprintf(outfp, "fstat [fd] [buf]: Get the stat structure for file descriptor fd and place it\n");
  fprintf(outfp, "                : in buf.  Returns 0 on success, -1 on failure\n");
}

void usage_fsync()
{
  fprintf(outfp, "fsync [fd]: ensure all parts of file with file descriptor fd are output to\n");
  fprintf(outfp, "          : stable storage.  Returns 0 on success, -1 on failure\n");
}

void usage_fdatasync()
{
  fprintf(outfp, "fdatasync [fd]: ensure all parts of file with file descriptor fd except the \n");
  fprintf(outfp, "              : metadata are output to stable storage.  Returns 0 on \n");
  fprintf(outfp, "              : success, -1 on failure\n");
}
 
void usage_ftruncate()
{
  fprintf(outfp, "ftruncate [fd] [len]: truncate file with file descriptor fd to have be \n");
  fprintf(outfp, "                    : len bytes in length.  Returns 0 on success, -1 on \n");
  fprintf(outfp, "                    : failure\n");
}

void usage_getcwd()
{
  fprintf(outfp, "getcwd [buf] [size]: get the current working directory and store it in buf\n");
  fprintf(outfp, "                   : buf is size bytes in length.  If buf is too short, an \n");
  fprintf(outfp, "                   : error of ERANGE is returned.  Returns 0 on success, -1\n");
  fprintf(outfp, "                   : on failure\n");
}

void usage_lseek()
{
  fprintf(outfp, "lseek [fd] [offset] [whence]: Sets the offset of the file descriptor fd to\n");
  fprintf(outfp, "                            : either offset if whence is SEEK_SET or offset\n");
  fprintf(outfp, "                            : plus the current location if whence is SEEK_CUR\n");
  fprintf(outfp, "                            : or offset plus the size of the file if whence\n");
  fprintf(outfp, "                            : is SEEK_END. Returns 0 on success and -1 on \n");
  fprintf(outfp, "                            : failure\n");
}
 
void usage_lstat()
{
  fprintf(outfp, "lstat [filename] [buf]: Get the stat structure for filename and return it in\n");
  fprintf(outfp, "                      : buf.  Returns 0 on success and -1 on failure\n");
}

void usage_getdirentries()
{
  fprintf(outfp, "getdirentries [fd] [buf] [nbytes] [basep]: Read dir entries from directory\n");
  fprintf(outfp, "                                         : with file descriptor fd into buf\n");
  fprintf(outfp, "                                         : At most nbytes are read.  Reading\n");
  fprintf(outfp, "                                         : starts at basep, and basep is set\n");
  fprintf(outfp, "                                         : to new pos. Returns the number of \n");
  fprintf(outfp, "                                         : bytes read on success or 0 on\n");
  fprintf(outfp, "                                         : failure\n");
  fprintf(outfp, "Note that basep does not have to be pre-allocated.  Executing cmd: \n");
  fprintf(outfp, "\"getdirentries $fd $buf 4096 $basep\", where $fd is the result of an open\n");
  fprintf(outfp, "and $buf is the result of an alloc (but $basep is totally new) will work\n");
  fprintf(outfp, "After the execution of the command, $basep holds the new offset and can be\n");
  fprintf(outfp, "used again for any further getdirentries calls\n");
}
 
void usage_mkdir()
{
  fprintf(outfp, "mkdir [newdir] [mode]: make a new directory, newdir, with the permissions \n");
  fprintf(outfp, "                     : specified in mode.  Permissions can be symbolic \n");
  fprintf(outfp, "                     : (eg, a+x), numeric (eg, 0777), or can use defines\n");
  fprintf(outfp, "                     : (eg S_IRUSR|S_IWUSR|S_IRGRP).  Returns 0 on success \n");
  fprintf(outfp, "                     : -1 on failure.\n");
}


void usage_creat()
{
  fprintf(outfp, "creat [newfile] [mode]: create a new file, newfile, with the permissions \n");
  fprintf(outfp, "                      : specified in mode.  Permissions can be symbolic \n");
  fprintf(outfp, "                      : (eg, a+x), numeric (eg, 0777), or can use defines\n");
  fprintf(outfp, "                      : (eg S_IRUSR|S_IWUSR|S_IRGRP).  Returns 0 on success \n");
  fprintf(outfp, "                      : -1 on failure.\n");
}

void usage_stat()
{
  fprintf(outfp, "stat [filename] [buf]: Get the stat structure for filename and return it in\n");
  fprintf(outfp, "                     : buf.  Returns 0 on success and -1 on failure\n");
}

void usage_statvfs()
{
  fprintf(outfp, "statvfs [filename] [buf]: Get the statvfs structure for filename and return\n");
  fprintf(outfp, "                        : it in buf.  Returns 0 on success and -1 on failure\n");
}

void usage_fstatvfs()
{
  fprintf(outfp, "fstatvfs [fd] [buf]: Get the stat structure for file with file descriptor fd\n");
  fprintf(outfp, "                   : and return it in buf.  Returns 0 on success and -1 on\n"); 
  fprintf(outfp, "                   : failure\n");
}

void usage_truncate()
{
  fprintf(outfp, "truncate [fname] [len]: truncate file with name fname to be exactly \n");
  fprintf(outfp, "                      : len bytes in length.  Returns 0 on success, -1 on \n");
  fprintf(outfp, "                      : failure\n");
}

void usage_rmdir()
{
  fprintf(outfp, "rmdir [dirname]: Remove directory at dirname.  Returns 0 on success, -1 on\n");
  fprintf(outfp, "               : failure.\n");
}

void usage_symlink()
{
  fprintf(outfp, "symlink [path1] [path2]: Make a symbolic link from path1 to path2.  Returns\n");
  fprintf(outfp, "                       : 0 on success, -1 on failure\n");
}

void usage_unlink()
{
  fprintf(outfp, "unlink [path]: Unlink path.  If path is the last name to a file, the file is \n");
  fprintf(outfp, "             : is removed.  If it was a symbolic link, the link is removed. \n");
  fprintf(outfp, "             : Returns 0 on success, -1 on failure\n");
}

void usage_ioctl()
{
  fprintf(outfp, "ioctl [fd] [cmd] <args> : Issue the ioctl command cmd on the file with file\n");
  fprintf(outfp, "                        : descriptor fd.  Any arguments are placed in args\n");
  fprintf(outfp, "                        : At the moment, the only commands understand are the \n");
  fprintf(outfp, "                        : ioctl commands found in /usr/include/linux/fs.h\n");
}

void usage_umask()
{
  fprintf(outfp, "ioctl [mask] : Sets the umask used by open to set initial file permissions on\n");
  fprintf(outfp, "             : a newly created file.  Returnds the previous value of the mask\n");
}

void usage_iodone()
{
  fprintf(outfp, "iodone [ioid] : Poll for completion of the asynchronous request identifed by\n");
  fprintf(outfp, "              : ioid.  Returns 1 if request finished\n");
}

void usage_iowait()
{
  fprintf(outfp, "iowait [ioid] : Wait for completion of the asynchronous request identifed by\n");
  fprintf(outfp, "              : ioid.  Returns result of asynchronous request \n");
}

void usage_ipreadv()
{
  fprintf(outfp, "ipreadv [fd] [buf] [count] [off]: Reads data asynchrously to file descriptor fd \n");
  fprintf(outfp, "                                : starting at offset off.  Data comes from \n");
  fprintf(outfp, "                                : buffer described by buf, which is a pointer to\n");
  fprintf(outfp, "                                : an iovec strucutre.  Number of buffers is \n");
  fprintf(outfp, "                                : specified by count.  Returns an iod_t on  \n");
  fprintf(outfp, "                                : success and -1 on failure\n");
}

void usage_ipread()
{
  fprintf(outfp, "ipread [fd] [buf] [count] [off]: Read asynchrously up to count bytes from file\n");
  fprintf(outfp, "                               : with file descriptor fd starting at offset off\n");
  fprintf(outfp, "                               : Read into buffer pointed at by buf.  Returns\n");
  fprintf(outfp, "                               : an iod_t on success and -1 on failure\n");
}

void usage_preadv()
{
  fprintf(outfp, "preadv [fd] [buf] [count] [off]: Reads data from file descriptor fd starting at\n");
  fprintf(outfp, "                               : offset off.  Data goes into buffer described\n");
  fprintf(outfp, "                               : by buf, which is a pointer to an iovec \n");
  fprintf(outfp, "                               : structure.  Number of buffers is specified by\n");
  fprintf(outfp, "                               : count. Returns the number of bytes read\n");
}

void usage_pread()
{
  fprintf(outfp, "preadv [fd] [buf] [count] [off]: Reads count bytes of data from file descriptor\n");
  fprintf(outfp, "                               : fd starting at offset off.  Data goes into buf.\n");
  fprintf(outfp, "                               : Returns number of bytes read or -1 on failure\n");
}

void usage_ireadv()
{
  fprintf(outfp, "ireadv [fd] [buf] [count] : Reads data asynchrously to file descriptor fd \n");
  fprintf(outfp, "                          : Data comes from buffer described by buf, which is \n");
  fprintf(outfp, "                          : an pointer to an iovec structure.  Number of\n");
  fprintf(outfp, "                          : buffers is specified by count.  Returns an iod_t\n");
  fprintf(outfp, "                          : on success and -1 on failure\n");
}

void usage_iread()
{
  fprintf(outfp, "iread [fd] [buf] [count]: Read asynchrously up to count bytes from file with\n");
  fprintf(outfp, "                        : file descriptor fd into buffer pointed at by buf\n");
  fprintf(outfp, "                        : Returns an iod_t on success and -1 on failure\n");
}

void usage_readv()
{
  fprintf(outfp, "readv [fd] [buf] [count] : Reads data from file descriptor fd.  Data comes from\n");
  fprintf(outfp, "                         : the buffer described by buf, which is a pointer to an\n");
  fprintf(outfp, "                         : an iovec structure.  Number of buffers is specified\n");
  fprintf(outfp, "                         : by count.  Returns the number of bytes read on \n");
  fprintf(outfp, "                         : on success and -1 on failure\n");
}

void usage_read()
{
  fprintf(outfp, "read [fd] [buf] [count]: Read up to count bytes from file with file \n");
  fprintf(outfp, "                       : descriptor fd into buffer pointed at by buf\n");
  fprintf(outfp, "                       : Returns number of bytes read on success or 0 on \n");
  fprintf(outfp, "                       : on failure\n");
}

void usage_ipwritev()
{
  fprintf(outfp, "ipwritev [fd] [buf] [count] [off]: writes data asynchronously to file with file\n");
  fprintf(outfp, "                                 : descriptor fd starting at offset off.  Data \n");
  fprintf(outfp, "                                 : comes from buffers described by buf, which\n");
  fprintf(outfp, "                                 : is a pointer to an iovec structure.  Number \n");
  fprintf(outfp, "                                 : of buffers is specified by count.  Returns\n");
  fprintf(outfp, "                                 : an iod_t on success and -1 on failure\n");
}

void usage_ipwrite()
{
  fprintf(outfp, "ipwrite [fd] [buf] [count] [off]: writes count bytes of data asynchronously to\n");
  fprintf(outfp, "                                : file with file descriptor fd starting at \n");
  fprintf(outfp, "                                : offset off.  Data comes from buf. Returns an\n"); 
  fprintf(outfp, "                                : iod_t on success and -1 on failure\n");
}

void usage_pwritev()
{
  fprintf(outfp, "pwritev [fd] [buf] [count] [off]: writes data to file with file descriptor fd\n");
  fprintf(outfp, "                                : starting at offset off.  Data comes from \n");
  fprintf(outfp, "                                : buffers described by buf, which is a pointer\n");
  fprintf(outfp, "                                : to an iovec structure.  Number of buffers is\n");
  fprintf(outfp, "                                : by count.  Returns number of bytes read on \n");
  fprintf(outfp, "                                : success and -1 on failure\n");
}

void usage_pwrite()
{
  fprintf(outfp, "pwrite [fd] [buf] [count] [off]: writes count bytes of data to file with file \n");
  fprintf(outfp, "                               : descriptor fd starting at offset off.  Data\n");
  fprintf(outfp, "                               : Data comes from buf. Returns number of bytes\n"); 
  fprintf(outfp, "                               : written on success and -1 on failure\n");
}

void usage_iwritev()
{
  fprintf(outfp, "iwritev [fd] [buf] [count] : writes data asynchronously to file with file\n");
  fprintf(outfp, "                           : descriptor fd.  Data comes from buffers described\n");
  fprintf(outfp, "                           : by buf, which is a pointer to an iovec structure.\n");
  fprintf(outfp, "                           : Number of buffers is specified by count.  Returns\n");
  fprintf(outfp, "                           : an iod_t on success and -1 on failure\n");
}

void usage_iwrite()
{
  fprintf(outfp, "iwrite [fd] [buf] [count] : writes count bytes of data asynchronously to\n");
  fprintf(outfp, "                          : file with file descriptor fd.  Data comes from buf.\n");
  fprintf(outfp, "                          : Returns an iod_t on success and -1 on failure.\n");
}

void usage_writev()
{
  fprintf(outfp, "writev [fd] [buf] [count]: writes data to file descriptor fd.  Data comes from\n");
  fprintf(outfp, "                         : buffers described by buf, which is a pointer to a \n");
  fprintf(outfp, "                         : iovec strucutre.  Number of buffers is specified by \n");
  fprintf(outfp, "                         : count \n");
}

void usage_write()
{
  fprintf(outfp, "write [fd] [buf] [count] : writes count bytes of data to file with file \n");
  fprintf(outfp, "                         : descriptor fd.  Data comes from buf.  Returns number\n");
  fprintf(outfp, "                         : of bytes written on success and -1 on failure.\n");
}

void usage_mknod()
{
  fprintf(outfp, "mknod [path] [mode] [dev] : creates a filesystem node named path with \n");
  fprintf(outfp, "                          : specified mode using device special file dev\n");
  fprintf(outfp, "                          : Returns 0 on sucess and -1 on failure\n");
}


void usage_umount()
{
  fprintf(outfp, "umount [path] : Umount file at path.  Returns 0 on success and -1 on failure\n");
}

void usage_init_iovec()
{
	fprintf(outfp, "init_iovec buf offset len num iov_buf: Init iovector. iov_uf points to an array of\n");
	fprintf(outfp, "                                       iovecs, num is the number of the iovec, \n");
	fprintf(outfp, "                                       buf is the buffer to be used, offset \n");
	fprintf(outfp, "                                       specifies how far into the buffer the iovec\n");
 	fprintf(outfp, "                                       should point and len is the iov length\n");
}

void usage_init_xtvec()
{
	fprintf(outfp, "init_xtvec offset len num buf: Init xtvector.  Buf points to an array of\n");
	fprintf(outfp, "                               xtvecs, num is the number of the xtvec, offset\n");
	fprintf(outfp, "                               is xtv_off and len is the iov lenghth\n");
	fprintf(outfp, "                               the iov length\n");
}

void usage_writex()
{
	fprintf(outfp, "writex fd iovs iov_cnt xtvs xtvcnt: Write iov_cnt iovecs out to file using\n");
	fprintf(outfp, "                                    xtvcnt xtvecs\n");
}

void usage_iwritex()
{
	fprintf(outfp, "iwritex fd iovs iov_cnt xtvs xtvcnt: Write iov_cnt iovecs out to file using\n");
	fprintf(outfp, "                                     xtvcnt xtvecs\n");
}

void usage_readx()
{
	fprintf(outfp, "readx fd iovs iov_cnt xtvs xtvcnt: Read iov_cnt iovecs out from file using\n");
	fprintf(outfp, "                                    xtvcnt xtvecs\n");
}

void usage_ireadx()
{
	fprintf(outfp, "ireadx fd iovs iov_cnt xtvs xtvcnt: Read iov_cnt iovecs out from file using\n");
	fprintf(outfp, "                                     xtvcnt xtvecs\n");
}
					

void usage_checkbuf()
{
	fprintf(outfp, "checkbuf [buf] [size] [val] [off]: Staring at offset off, checks to see\n");
	fprintf(outfp, "                                   if val is in first size bytes of buf\n");
}

void usage_exit()
{
}
