#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <dirent.h>

#include "sysio.h"
#include "mount.h"
#include "test.h"
#include "test_driver.h"

/*
 * ###################################################
 * # Test functions                                  #
 * #  These functions are used to test libsysio.     #
 * #  Eventually, there should be one of these for   #
 * #  every function document in sysio.h             #
 * ###################################################
 */
int initilize_sysio()
{
  char *wd;
 
  /* 
   * Attempt to set the cwd by getting it out of the
   * user's environment.  If that does not work, set
   * it to /
   */
  wd = getenv("PWD");
  if (wd == NULL) {
    wd = malloc(5);
    strcpy(wd, "/");
  }
  if (chdir(wd) != 0) {
    DBG(5, sprintf(output, "%schdir: errno %d\n", output, errno));
    my_perror(wd);
    my_errno = errno;
    last_ret_val = errno;
    return SUCCESS;
  }

  DBG(3, sprintf(output, "Your current working directory is %s\n", wd));
  last_ret_val = 0;
  return SUCCESS;
}


int sysio_list(char *path)
{
  int	fd;
  size_t	n;
  struct dirent *buf, *dp;
  __off_t	base;
  ssize_t	cc;
  int numfiles = 0;

  fd = open(path, O_RDONLY);
  if (fd < 0) {
    my_errno = errno;
    last_ret_val = fd;
    my_perror(path);
    return SUCCESS;
  }
  
  n = 16 * 1024;
  buf = malloc(n);
  if (!buf) {
    my_perror(path);
    cc = -1;
    goto out;
  }
  base = 0;
  DBG(5, sprintf(output, "About to call getdirentries\n"));
  while ((cc = getdirentries(fd, (char *)buf, n, &base)) > 0) {
    dp = buf;
    while (cc > 0) {
      DBG(4, fprintf(outfp, "\t%s: ino %#08x off %#08x type %#08x\n",
		     dp->d_name,
		     (unsigned int)dp->d_ino,
		     (unsigned int)dp->d_off,
		     (int )dp->d_type));
      
      sprintf(output, "%s\n", dp->d_name);
      cc -= dp->d_reclen;
      dp = (struct dirent *)((char *)dp + dp->d_reclen);
      numfiles++;
    }
    printf("Out of inner loop\n");
    if (!base)
      break;
  }

 out:
  if (cc < 0) {
    DBG(2, sprintf(output, "cc barfed\n"));
    my_perror(path);
  }
  
  free(buf);
  {
    int	oerrno = errno;
    
    if (close(fd) != 0) {
      DBG(2,sprintf(output, "close barfed\n"));
      my_perror(path);
      if (cc < 0)
	errno = oerrno;
      else
	cc = -1;
    }
  }

  last_ret_val = numfiles;
  my_errno = errno;

  return SUCCESS;
}

int sysio_mount(char *from, char *to)
{
  int	err;
  char	*s;
  char	*buf;
  char	*cp;
  char	*fstype, *source, *opts, *target;

  err = 0;

  /*
   * Copy everything to a buffer we can modify.
   */
  s = buf = malloc(strlen(from) + 1);
  if (!buf) {
    my_perror(from);
    last_ret_val = -1;
    my_errno = errno;
    return SUCCESS;
  }
  (void )strcpy(s, from);
  
  /*
   * Eat leading white.
   */
   while (*s && *s == ' ' && *s == '\t')
     s++;
  /*
   * Get fstype.
   */
   fstype = cp = s;
   while (*cp && *cp != ':' && *cp != ' ' && *cp != '\t')
     cp++;
   if (fstype == cp || *cp != ':') {
     DBG(1, sprintf(output, "%s: Missing FS type\n", from));
     err = -1;
     goto out;
   }
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
   source = cp = s;
   while (*cp && *cp != ' ' && *cp != '\t')
     cp++;
   if (source == cp) {
     DBG(1, sprintf(output, "%s: Missing source\n", from));
     err = -1;
     goto out;
   }
   if (*cp)
     *cp++ = '\0';

   s = to;
   /*
    * Eat leading white.
    */
    while (*s && *s == ' ' && *s == '\t')
      s++;
   /*
    * Get opts.
    */
    opts = cp = s;
    while (*cp && *cp != ' ' && *cp != '\t')
      cp++;
    if (opts == cp) {
      DBG(1,sprintf(output, "%s: Missing target\n", to));
      err = -1;
      goto out;
    }
    if (*cp)
      *cp++ = '\0';

    s = cp;
    /*
     * Eat leading white.
     */
     while (*s && *s == ' ' && *s == '\t')
       s++;
    /*
     * Get target
     */
     target = cp = s;
     while (*cp && *cp != ' ' && *cp != '\t')
       cp++;
     if (target == cp) {
       target = opts;
       opts = NULL;
     }
     if (*cp)
       *cp++ = '\0';

     err = mount(source, target, fstype, 0, opts);
     if (err)
       my_perror(from);

out:
     free(buf);
     last_ret_val = err;
     my_errno = errno;
     return SUCCESS;
}

int sysio_chdir(char *newdir) 
{

  if (chdir(newdir) != 0) {
    my_perror(newdir);
    return -1;
  }
  /*  
  buf = getcwd(NULL, 0);
  if (!buf) {
    my_perror(newdir);
    last_ret_val = -1;
    my_errno = errno;
    return SUCCESS;
  }
  DBG(4, sprintf(output, "New dir is %s\n", buf));

  free(buf);
  */
  return SUCCESS;
}

static mode_t get_mode(char *arg, int type, int start_mode);

#define SYMBOLIC 0
#define DEFINED  1
#define NUMERIC  2 
/*
 * Change the permissions on a given file
 *
 * sysio_chmod <filename> <permissions>
 *
 */
int sysio_chmod(char *mode_arg, const char *path) 
{
  int	err;
  mode_t mode;
  struct stat st;

  /* Get the current mode */
  err = stat(path, &st);

  /* Is the new mode symbolic? */
  if (isalpha(mode_arg[0])) {
    /* Could be specifying defines */
    if (mode_arg[0] == 'S')
      mode = get_mode(mode_arg, DEFINED, st.st_mode);
    else
      mode = get_mode(mode_arg, SYMBOLIC, st.st_mode);
  } else 
    mode = get_mode(mode_arg, NUMERIC, st.st_mode);
  DBG(3,sprintf(output, "Using a mode of %o and a file of %s\n", mode, path));

  if (mode == 0) {
    DBG(2,sprintf(output, "Invalid mode\n"));
    return INVALID_ARGS;
  }

  last_ret_val = chmod(path, mode);
  my_errno = errno;
  return SUCCESS;
  
}


#define USER_STATE 0 /* Specifies that the users are still being listed */
#define MODE_STATE_ADD 1 
#define MODE_STATE_REMOVE 2 
	
#define READ    00444
#define WRITE   00222
#define EXECUTE 00111

#define OWNER  00700
#define GROUP  00070
#define OTHER  00007

  
mode_t
get_mode(char *arg, int type, int start_mode) 
{
  int i, j,digit, total;
  char c;
  int state = USER_STATE;
  int len = strlen(arg);
  unsigned int users = 0;
  unsigned int modes = 0;


  if (type == DEFINED) {
    char curr_word[10];

    total = digit = 0;
    j = 0;
    DBG(4, sprintf(output, "len is %d\n", len));
    for (i=0; i < len; i++) {
      if (arg[i] == '|') {
	curr_word[j] = '\0';
	DBG(3, sprintf(output, "Got mode word %s\n", curr_word));
	digit = get_obj(curr_word);
	if (digit < 0 ) {
	  DBG(2, sprintf(output, "Unable to understand mode arg %s\n",
			 curr_word));
	  return -1;
	} 
	total |= digit;
	j = 0;
      } else 
	curr_word[j++] = arg[i];
    }
    curr_word[j] = '\0';
    DBG(3, sprintf(output, "Got mode word %s\n", curr_word));
    digit = get_obj(curr_word);
    if (digit < 0 ) {
      DBG(3, sprintf(output, "Unable to understand mode arg %s\n",
	     curr_word));
      return -1;
    } 
    total |= digit;
    return total;
  }
      
  if (type == SYMBOLIC) {
    for (i=0; i < len; i++) {
      c = arg[i];
      if (state == USER_STATE) {
	switch(c){
	case 'u':
	  users |= OWNER;
	  break;
	case 'g':
	  users |= GROUP;
	  break;
	case 'o':
	  users |= OTHER;
	  break;
	case 'a':
	  users |= (OWNER|GROUP|OTHER);
	  break;
	case '+':
	  state = MODE_STATE_ADD;
	  break;
	case '-':
	  state = MODE_STATE_REMOVE;
	  break;
	default:
	  return 0;
	}
      } else {

	switch(c){
	case 'r':
	  modes |= READ;
	  break;
	case 'w':
	  modes |= WRITE;
	  break;
	case 'x':
	  modes |= EXECUTE;
	  break;
	default:
	  return 0;
	}
      }
    }

    if (state == MODE_STATE_ADD) {
      return (start_mode | (users & modes));
    } else {
      return (start_mode & ~(users & modes));
    }

  } else {
    /* Digits should be octal digits, so should convert */
    total = 0;
    for (i=0; i < len; i++) {
      c = arg[i];
      digit = atoi(&c);
      if (digit > 7)
	return 0;
      for (j=len-i-1; j >0; j--)
	digit *= 8;
      total += digit;
    }
    return total;
  }
 
}

/*
 * Changes the ownership of the file.  The new_id
 * is of the format owner:group.  Either the owner
 * or the group may be omitted, but, in order to 
 * change the group, the : must preced the group.
 */
int sysio_chown(char *new_id, char *file)
{
  char *owner = NULL;
  char *group = NULL;
  uid_t o_id=-1, g_id=-1;
  int len, j, i=0;
  int state = 0; /* Correspond to getting owner name */
  
  len = strlen(new_id);
  for (i=0; i < len; i++) {

    if (new_id[i] == ':') {
      /* Group name */
      if (!group) 
				group = malloc(strlen(new_id) -i +2);
      state = 1; /* Now getting group name */
      j = 0;
      if (owner)
				owner[i] = '\0';
    }
		
    if (!state) {
      /* Getting owner name */
      if (!owner)
				owner = malloc(strlen(new_id) +1 ); 
      owner[i] = new_id[i];
    } else {
      /* Group name */
      group[j] = new_id[i];
      j++;
    }
  }
  if (group)
    group[i] = '\0';
  else
    owner[i] = '\0';

  /* Are the owner and/or group symbolic or numeric? */
  if (owner) {
    if (isdigit(owner[0])) {
      /* Numeric -- just convert */
      o_id = (uid_t) atoi(owner);

		} else {
      /* No longer support non-numeric ids */
			
			DBG(2, sprintf(output, "Error: non-numeric ids unsupported\n"));
			return INVALID_ARGS;
    }
  }



  if (group) {
    if (isdigit(group[0])) {
      /* Numeric -- just convert */
      g_id = (uid_t) atoi(group);
		} else {
      /* Don't support group names either */
			DBG(2, sprintf(output, "Error: non-numeric ids unsupported\n"));
			return INVALID_ARGS;
    }
  }

  /* Now issue the syscall */
  DBG(4, sprintf(output, "Changing owner of file %s to %d (group %d)\n",
		 file, o_id, g_id));
 
  last_ret_val = chown(file, o_id, g_id);
  my_errno = errno;
  return SUCCESS;
}

int sysio_open(char *path, int flags)
{
  last_ret_val = open(path, flags);
  my_errno = errno;
  DBG(3, sprintf(output, "Returning with errno set to %s (ret val is %d)\n", 
		 strerror(my_errno), (int)last_ret_val));
  return SUCCESS;
}

int sysio_open3(char *path, int flags, char *mode_arg)
{
  mode_t mode;

  /* Is the new mode symbolic? */
  if (isalpha(mode_arg[0])) {
    /* Could be specifying defines */
    if (mode_arg[0] == 'S')
      mode = get_mode(mode_arg, DEFINED, 0);
    else
      mode = get_mode(mode_arg, SYMBOLIC, 0);
  } else 
    mode = get_mode(mode_arg, NUMERIC, 0);
  
  last_ret_val = open(path, flags, mode);
  my_errno = errno;
  
  return SUCCESS;
}

int sysio_close(int fd)
{

  last_ret_val = close(fd);
  my_errno = errno;
  return SUCCESS;
}

int sysio_fcntl(int fd, struct cmd_map* cmdptr, char *arg)
{
  int fd_new, index, cmd, flag;
  char *cmdname;
  void *buf;

  cmd = cmdptr->cmd;
  cmdname = cmdptr->cmd_name;

  switch(cmd) {
  case F_DUPFD:
    fd_new = get_obj(arg);
    last_ret_val = fcntl(fd, F_DUPFD, fd_new);
    my_errno = errno;
    return SUCCESS;
    break;

  case F_GETFD:
  case F_GETFL:
  case F_GETOWN:
    /* case F_GETSIG:
       case F_GETLEASE: */

    last_ret_val= fcntl(fd, cmd);
    my_errno = errno;
    return SUCCESS;
    break;

  case F_SETFD:    
  case F_SETFL:
  case F_SETOWN:
    /*case F_SETSIG:
    case F_SETLEASE:
    case F_NOTIFY: */
    flag = atoi(arg);
    last_ret_val =  fcntl(fd, cmd, flag);
    my_errno = errno;
    return SUCCESS;
    break;

  case F_SETLK:
  case F_SETLKW:
  case F_GETLK:
  
     /* Get the buffer to hold the lock structure */
     index = get_obj(arg);
     if (index < 0) {
       sprintf(output, "Unable to find buffer %s\n", arg+1);
       return INVALID_VAR;
     }

     buf = buflist[index];
     if (!buf) {
       sprintf(output, "Buffer at index %d (mapped by %s) is null\n",
	      index, arg);
       return INVALID_VAR;
     }

     last_ret_val = fcntl(fd, cmd, (struct flock *)buf);
     my_errno = errno;
    return SUCCESS;
  default:
    /* THis should be impossible */
    return INVALID_ARGS;
  }

  return INVALID_ARGS;
}

void print_stat(struct stat *st)
{
  DBG(3, sprintf(output, "%sstruct stat: \n", output));
  DBG(3, sprintf(output, "%s  st_dev: %#16x\n", output, (unsigned int)st->st_dev));
  DBG(3, sprintf(output, "%s  st_ino: %#16x\n", output, (unsigned int) st->st_ino));
  DBG(3, sprintf(output, "%s  st_mode: %#16x\n", output, st->st_mode));
  DBG(3, sprintf(output, "%s  st_nlink: %#16x\n", output, (int)st->st_nlink));
  DBG(3, sprintf(output, "%s  st_uid: %#16x\n", output, st->st_uid));
  DBG(3, sprintf(output, "%s  st_gid: %#16x\n", output, st->st_gid));
  DBG(3, sprintf(output, "%s  st_rdev: %#16x\n", output, (int)st->st_rdev));
  DBG(3, sprintf(output, "%s  st_size: %#16x\n", output, (int) st->st_size));
  DBG(3, sprintf(output, "%s  st_blksize: %#16x\n", output, (int) st->st_blksize));
  DBG(3, sprintf(output, "%s  st_blocks: %#16x\n", output, (int) st->st_blocks));
  DBG(3, sprintf(output, "%s  st_atime: %#16x\n", output, (unsigned int) st->st_atime));
  DBG(3, sprintf(output, "%s  st_mtime: %#16x\n", output, (unsigned int) st->st_mtime));
  DBG(3, sprintf(output, "%s  st_ctime: %#16x", output, (unsigned int) st->st_ctime));
}

int sysio_fstat(int fd, void *buf)
{
  int err;
  struct stat *st = (struct stat *)buf;
  err = fstat(fd, st); 
  if (err < 0) {
    my_perror("fstat");
  }
  my_errno = errno;
  last_ret_val = err;
  print_stat(st);

  return SUCCESS;
}

int sysio_lstat(char *filename, void *buf)
{
  int err;
  struct stat *st = (struct stat *)buf;
  err = lstat(filename, st); 
  if (err < 0) {
    my_perror("lstat");
  }

  my_errno = errno;
  last_ret_val = err;
  print_stat(st);
  return SUCCESS;
}


int sysio_stat(char *filename, void *buf)
{
  int err;
  struct stat *st = (struct stat *)buf;

  err = stat(filename, st); 
  if (err < 0) {
    my_perror("stat");
  }

  my_errno = errno;
  last_ret_val = err;
  print_stat(st);
  return SUCCESS;
}


int sysio_getdirentries(int fd, char *buf, size_t nbytes, off_t *basep)
{
  int err;
  struct dirent *dp;

  err = getdirentries(fd, buf, nbytes, basep); 
  last_ret_val = err;
 
  DBG(4, sprintf(output, "%sRead %d bytes\n", output, err));

  dp = (struct dirent *)buf;
  while (err > 0) {
      DBG(3, sprintf(output, "%s\t%s: ino %llu off %llu len %x type %c\n",
		     output,
		     dp->d_name,
		     (unsigned long long )dp->d_ino,
		     (unsigned long long )dp->d_off,
		     dp->d_reclen,
		    (char )dp->d_type));
      err -= dp->d_reclen;
      dp = (struct dirent *)((char *)dp + dp->d_reclen);
  }

  my_errno = errno;
  return last_ret_val;
}


int sysio_mkdir(char *path, char *mode_arg) 
{
  int	err;
  mode_t mode;
  struct stat st;

  /* Is the new mode symbolic? */
  if (isalpha(mode_arg[0])) {
    /* Could be specifying defines */
    if (mode_arg[0] == 'S')
      mode = get_mode(mode_arg, DEFINED, st.st_mode);
    else
      mode = get_mode(mode_arg, SYMBOLIC, st.st_mode);
  } else 
    mode = get_mode(mode_arg, NUMERIC, st.st_mode);

  DBG(3, sprintf(output, "Using a mode of %o and a file of %s\n", mode, path));

  if (mode == 0) {
    DBG(2, sprintf(output, "Invalid mode\n"));
    return INVALID_ARGS;
  }

  err = mkdir(path, mode);
  my_errno = errno;
  last_ret_val = err;
  return SUCCESS;
  
}

int sysio_creat(char *path, char *mode_arg) 
{
  mode_t mode;
  int err;

  /* Is the new mode symbolic? */
  if (isalpha(mode_arg[0])) {
    /* Could be specifying defines */
    if (mode_arg[0] == 'S')
      mode = get_mode(mode_arg, DEFINED, 0);
    else
      mode = get_mode(mode_arg, SYMBOLIC, 0);
  } else 
    mode = get_mode(mode_arg, NUMERIC, 0);

  DBG(3, sprintf(output, "Using a mode of %o and a file of %s\n", mode, path));

  if (mode == 0) {
    DBG(2, sprintf(output, "Invalid mode\n"));
    return INVALID_ARGS;
  }

  err = creat(path, mode);
  my_errno = errno;
  last_ret_val = err;
  return SUCCESS;
}

void print_statvfs(struct statvfs *st)
{
  DBG(3, sprintf(output, "%sstruct statvfs: \n", output));
  DBG(3, sprintf(output, "%s  f_bsize: %x\n", output, (unsigned int) st->f_bsize));
  DBG(3, sprintf(output, "%s  f_frsize: %x\n", output, (unsigned int) st->f_frsize));
  DBG(3, sprintf(output, "%s  f_blocks: %x\n", output, (unsigned int) st->f_blocks));
  DBG(3, sprintf(output, "%s  f_bfree: %x\n", output, (unsigned int) st->f_bfree));
  DBG(3, sprintf(output, "%s  f_bavail: %x\n", output, (unsigned int) st->f_bavail));
  DBG(3, sprintf(output, "%s  f_files: %x\n", output, (unsigned int) st->f_files));
  DBG(3, sprintf(output, "%s  f_ffree: %x\n", output, (unsigned int) st->f_ffree));
  DBG(3, sprintf(output, "%s  f_favail: %x\n", output, (unsigned int) st->f_favail));
  DBG(3, sprintf(output, "%s  f_files: %x\n", output, (unsigned int) st->f_files));
#if (__GLIBC__  == 2 && __GLIBC_MINOR__ == 1)
  DBG(3, sprintf(output, "%s  f_fsid: %x\n", output, (unsigned int) st->f_fsid.__val[1]));
#else
 DBG(3, sprintf(output, "%s  f_fsid: %x\n", output, (unsigned int) st->f_fsid));
#endif
  DBG(3, sprintf(output, "%s  f_flag: %x\n", output, (unsigned int) st->f_flag));
  DBG(3, sprintf(output, "%s  f_fnamemax: %x\n", output, (unsigned int) st->f_namemax));
}


int sysio_statvfs(char *filename, void *buf)
{
  int err;
  struct statvfs *st = (struct statvfs *)buf;
  
  err = statvfs(filename, st); 
  if ( err == -1) { 
    my_perror("statvfs");
  }

  my_errno = errno;
  last_ret_val = err;

  print_statvfs(st);
  return SUCCESS;
}

int sysio_fstatvfs(int fd, void *buf)
{
  int err;
  struct statvfs *st = (struct statvfs *)buf;

  err = fstatvfs(fd, st);
  if (err == -1) { 
    my_perror("fstatvfs");
  }

  my_errno = errno;
  last_ret_val = err;

  print_statvfs(st);
  return SUCCESS;
}

int sysio_umask(char *mode_arg)
{
  mode_t mode;

   /* Is the new mode symbolic? */
  if (isalpha(mode_arg[0])) {
    /* Could be specifying defines */
    if (mode_arg[0] == 'S')
      mode = get_mode(mode_arg, DEFINED, 0);
    else
      mode = get_mode(mode_arg, SYMBOLIC, 0);
  } else 
    mode = get_mode(mode_arg, NUMERIC, 0);

  last_ret_val = umask(mode);
  my_errno = errno;
  return SUCCESS;
}

int sysio_mknod(char *path, char *mode_arg, dev_t dev)
{
  int err;
  int mode;

  mode = get_obj(mode_arg);
  
  if (mode < 0) {
    DBG(2,sprintf(output, "Cant get mode from %s\n", mode_arg));
    fprintf(stderr, "Cant get mode from %s\n", mode_arg);
    return INVALID_VAR;
  }

  err = mknod(path, (mode_t) mode, dev);
  if (err < 0)
    my_perror("mknod");

  last_ret_val = err;
  my_errno = errno;
  return SUCCESS;
}
