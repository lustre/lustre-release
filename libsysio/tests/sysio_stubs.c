#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/queue.h>

#include "xtio.h"
#include "sysio.h"
#include "test_driver.h"

/*
 * ################################################
 * # Function stubs                               #
 * #  These allow all of the different commands   #
 * #  to be called with the same format           #
 * ################################################
 */

int test_do_setdebug(int argc, char **argv) 
{
  int level;

  if (argc != 1) {
    DBG(2, fprintf(outfp, "Invalid number of args (%d) for setdebug\n",
		   argc));
    return INVALID_ARGS;
  }

  level = atoi(argv[0]);

  if (level < 0) {
    DBG(2, fprintf(outfp, "Invalid debug level %d\n", level));
    return INVALID_ARGS;
  }
  
  debug_level = level;
  return SUCCESS;
}

int test_do_printline(int argc, char **argv) 
{
  int on;

  
  if (argc != 1) {
    DBG(2, fprintf(outfp, "Invalid number of args (%d) for printline\n",
		   argc));
    return INVALID_ARGS;
  }

  on = atoi(argv[0]);
  if (on)
    print_line = 1;
  else
    print_line = 0;

  return SUCCESS;
}

/*
int test_do_setoutput(int argc, char **argv)
{
  FILE *newfp;

  if (argc != 1) {
    fprintf(outfp, "Invalid number of args (%d) for setoutput\n",
	    argc);
    return -1;
  }

  newfp = fopen(argv[0], "w");
  if (!newfp) {
    fprintf(outfp, "Unable to open new output file %s\n", argv[0]);
    return -1;
  }

  outfp = newfp;

  return 0;
}

*/


int test_do_fillbuff(int argc, char **argv) 
{
  char *typestr, *buf;
  void *valptr;
  int size, type, index, offset;

  if (argc != 5) {
    DBG(2, 
	fprintf(outfp, 
		"fillbuff requires a value, a type, a size, an offset, and the target buffer\n"));
    fprintf(stderr, "fillbuff requires 5 args, you gave %d\n", argc);
    return INVALID_ARGS;
  }

  offset = get_obj(argv[3]);
  if (offset < 0) {
    DBG(2, fprintf(outfp, "Do not understand offset %s\n", argv[3]));
    return INVALID_VAR;
  }

  index = get_obj(argv[4]);
  if (index < 0) {
    DBG(2, fprintf(outfp, "Can't find buffer at %s\n", argv[4]));
    return INVALID_VAR;
  }
  buf = (char *)(buflist[index]->buf)+offset;

  DBG(4, fprintf(outfp, "Buffer start is at %p\n", (void *)buflist[index]));

  typestr = argv[1];
  size = get_obj(argv[2]);
  if (size < 0) {
    DBG(2, fprintf(outfp, "Unable to understand size %s\n", argv[2]));
    return INVALID_VAR;
  }
  
  if ( (!strcmp(typestr, "UINT")) || (!strcmp(typestr, "SINT")) ){
    int val = get_obj(argv[0]);
    valptr = &val;
    type = UINT;
    if (val < 0) { /* FIX THIS */
      DBG(2, fprintf(outfp, "Can't understand value %s\n", argv[0]));
      return INVALID_VAR;
    }
    DBG(4, fprintf(outfp, "Copying %d bytes from %p. Val is %x\n",
		   size, buf, *((int *)valptr)));
    memcpy(buf, valptr, size);
         
  } else if (!strcmp(typestr,"STR")) {
    type = STR;
    valptr = argv[0];
    DBG(4, fprintf(outfp, "Copying %d bytes from %p. Val is %s\n",
		   size, buf, (char *)valptr));
    memcpy(buf, valptr, size);
  } else if (!strcmp(typestr, "PTR")) {
    unsigned long val;
    int index = get_obj(argv[0]);
    if (index < 0) {
      DBG(2, fprintf(outfp, "Unable to find buffer at %s\n", argv[0]));
      return INVALID_VAR;
    }
    
    val = (unsigned long)buflist[index]->buf;
    valptr = &val;
    DBG(4, fprintf(outfp, "Copying %d bytes from %p. Val is %p\n",
		   size, buf, valptr));
    memcpy(buf, valptr, size);
  } else {
    DBG(2, fprintf(outfp, "Unknown type %s.  Valid types are UINT, STR, and PTR\n", 
		   typestr));
    fprintf(stderr, "Unknown type %s.  Valid types are UINT, STR, and PTR\n", 
		   typestr);
    return INVALID_ARGS;
  }
 
  return SUCCESS;
}
    

#define STR_TYPE       1
#define INT_TYPE       2
#define SHORT_TYPE     3
#define CHAR_TYPE      4
#define LONG_TYPE      5

void print_partial(char *buf, int offset, int len, int type)
{
  int i;

  if (type == STR_TYPE) {
    sprintf(output, "%s%s", output, (char *)(buf+offset));
    DBG(4, fprintf(outfp, "Printing str %s\n", (char *)(buf+offset)));
  } else {
    if (type == SHORT_TYPE) {
      for (i = 0; i < len; i+= 2) {
	short *ibuf = (short *)(buf + offset + i);
	sprintf(output, "%s%#04x ", output, *ibuf);
	DBG(4, fprintf(outfp, "Printing short %#04x\n", *ibuf));
      }
    } else if (type == CHAR_TYPE) {
      for (i = 0; i < len; i++) {
	short *ibuf = (short *)(buf+offset+i);
	sprintf(output, "%s%#02x ", output, (*ibuf & 0x00ff));
	DBG(4, fprintf(outfp, "Printing char %c\n", (*ibuf & 0x00ff)));
      }
    } else if (type == INT_TYPE) {
      for (i = 0; i < len; i+= 4) {
	int *ibuf = (int *)(buf + offset + i);
	sprintf(output, "%s%#08x ", output, *ibuf);
	DBG(4, fprintf(outfp, "Printing int %#08x\n", *ibuf));
      }
    } else {
      for (i = 0; i < len; i += 8) {
	unsigned long *lbuf = (unsigned long *)(buf + offset +i);
	sprintf(output, "%s%#08lx ", output, *lbuf);
	DBG(4, fprintf(outfp, "Printing int %#016lx\n", *lbuf));
      }
    } 
  }
}
      
int test_do_printbuf(int argc, char **argv)
{
  int index, i, type, offset, len;
  struct buf_t *buf_st;
  void *buf;
  char *typestr;
  struct var_mapping *mobj;

  if (argv[0][0] == '$') {
    if (argv[0][1] == '$') {
      sprintf(output, "\n%#010x", (unsigned int)last_ret_val);
      return SUCCESS;
    } else if (!strcmp("errno", &argv[0][1])) {
      sprintf(output, "\n%#010x", my_errno);
      return SUCCESS;
    }
  }

  mobj = get_map(argv[0]);
  if (mobj == NULL) {
    DBG(2, fprintf(outfp, "Can't get var at %s\n", argv[0]));
    return INVALID_VAR;
  }

  if (mobj->type == UINT)
    sprintf(output, "\n%#010x", mobj->obj);
  else if (mobj->type == SINT)
    sprintf(output, "%d", mobj->obj);
  else if ((mobj->type == STR) || (mobj->type == PTR)) {
    index = mobj->obj;

    buf_st = buflist[index];
    DBG(2, fprintf(outfp, "buf_st is %p:\n", (void *)buf_st));
    buf = buf_st->buf;
    DBG(2, fprintf(outfp, "buf %s:\n", argv[0]));
    if (mobj->type == STR) {
      sprintf(output, "\n%s", (char *)buf);
     } else {
       sprintf(output,"%s\n", output);
       DBG(2, fprintf(outfp, "buf_st->len is %d, buf is %p\n", buf_st->len, buf));
       if (argc == 1) {
	 for (i = 0; i < buf_st->len/4; i++) 
	   DBG(2, fprintf(outfp, "%#x ", ((int *)buf)[i]));
	   sprintf(output, "%s%#x ", output, ((int *)buf)[i]);
	 
       }

       for (i = 1; i < argc; i++) {
	 offset = get_obj(argv[i++]);
	 len = get_obj(argv[i++]);
	 if ((offset < 0) || (len < 0)) {
	   DBG(2, fprintf(outfp, "Invalid offset (%s) or len (%s)\n",
			  argv[i-2], argv[i-1]));
	   return INVALID_VAR;
	 }
	 typestr = argv[i];
	 if (!strcmp("STR", typestr))
	   type = STR_TYPE;
	 else if (!strcmp("INT", typestr))
	   type = INT_TYPE;
	 else if (!strcmp("SHORT", typestr))
	   type = SHORT_TYPE;
	 else if (!strcmp("CHAR", typestr))
	   type = CHAR_TYPE;
	 else if (!strcmp("LONG", typestr))
	   type = LONG_TYPE;
	 else {
	   DBG(2, fprintf(outfp, "Unable to understand type %s\n",
			  typestr));
	   return INVALID_ARGS;
	 }
	 print_partial(buf, offset, len, type);
       }
     }
  }
  DBG(3, fprintf(outfp, "output: %s \n", output));
  return SUCCESS;
}

int test_do_mount(int argc, char **argv) 
{
  if (argc != 2) {
    DBG(2, fprintf(outfp, "Invalid number of args (%d) for test_do_mount\n",
		   argc));
    return INVALID_ARGS;
  }

  DBG(4, fprintf(outfp, "Calling mount with from %s and to %s\n",
		 argv[0], argv[1]));
  last_ret_val = sysio_mount(argv[0], argv[1]);
  my_errno = errno;
  last_type = SINT;
  return SUCCESS;
}

int test_do_clear(int argc, char **argv) 
{
  int index;
  struct buf_t *buf;

  if (argc != 1) {
    DBG(2, fprintf(outfp, "Invalid number of args (%d) for clear\n",
		   argc));
    return INVALID_ARGS;
  }
  index = get_obj(argv[0]);
  if (index < 0) {
    fprintf(outfp, "Unable to locate buffer %s\n",
	   argv[0]);
    return -1;
  }
  buf = buflist[index];
  bzero(buf->buf, buf->len);

  return SUCCESS;
}

int test_do_list(int argc, char **argv) 
{
  char *buf;

  if ((argc) && (argc != 1)) {
    DBG(2, fprintf(outfp, "Invalid number of args (%d) for list\n",
		   argc));
    return INVALID_ARGS;
  }

  DBG(5,fprintf(outfp, "In test_do_list with args %p\n", (void *)argv));
  if (!argv) {
    buf = getcwd(NULL, 0);
    DBG(4, fprintf(outfp, "Calling list with dir of %s\n", buf));
    last_ret_val =  sysio_list(buf);
    my_errno = errno;
    free(buf);
    return SUCCESS;
  } 
    
  last_type = SINT;
  return sysio_list(*argv);
}

/*
 * Initlizes sysio library.  Will use default initlization
 * unless arguments are given
 */
int test_do_init(int argc, char **argv) 
{
  if (argc > 0) {
    char *rdriver;
    char *mpath;
    int mflags, rsize, msize;
    if (argc != 3) {
      DBG(2, fprintf(outfp, "Invalid number of args (%d) for init\n",
		     argc));
      return INVALID_ARGS;
    } 

    rdriver = get_str(argv[0]);
    rsize = strlen(rdriver)+1;
    if (rsize > 75) {
      DBG(2, fprintf(outfp, "%s too long for root driver\n", rdriver));
      return INVALID_ARGS;
    }
    bzero(root_driver, 75);
    memcpy(root_driver, rdriver, rsize);
    
    mpath = get_str(argv[1]);
    msize = strlen(mpath)+1;
    if (msize > 250) {
      DBG(2, fprintf(outfp, "%s too long for mount path\n", mpath));
      return INVALID_ARGS;
    }
    bzero(mntpath, 250);
    memcpy(mntpath, mpath, msize);
    
    mflags = get_obj(argv[2]);
    if (mflags == -1) {
      DBG(2, fprintf(outfp, "Invalid flags argument %s\n", argv[2]));
      return INVALID_ARGS;
    } 
  }
  
  DBG(5, fprintf(outfp, "In test_do_init\n"));
  last_type = SINT;
  DBG(3, fprintf(outfp, "initializing\n"));
  return initilize_sysio();
}


/*
 * Returns 1 if the machine is big-endian, 0
 * otherwise
 */
int get_endian(int argc, char **argv) 
{
  int x = 1;
  
  if ((argc) || (argv)) {
    DBG(2, fprintf(outfp, "Expected no args for test_do_endian\n"));
    return INVALID_ARGS;
  }

  if(*(char *)&x == 1) {
    /* little-endian, return 0 */
    last_ret_val= 0;
  } else {
    /* big endian, return 1 */
    last_ret_val= 1;
  }
  last_type = UINT;
  return SUCCESS;
}

int do_setbuf(int argc, char **argv)
{
	int val, size, index, offset;
	void *buf;

	if (argc != 4) {
		DBG(2, fprintf(outfp, "Need val, size, buffer, and offset for setbuf\n"));
		return INVALID_ARGS;
	}
	val = get_obj(argv[0]);
	if (val < 0) {
		DBG(2, fprintf(outfp, "Unable to understand val of %s\n",
									 argv[0]));
		return INVALID_VAR;
	}

	size = get_obj(argv[1]);
	if( size <=0 ) {
		DBG(2, fprintf(outfp, "Size of %s is invalid\n", argv[1]));
		return INVALID_VAR;
	}

  index = get_obj(argv[2]);
  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer assocated with %s\n",
		   argv[2]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

	offset = get_obj(argv[3]);
	
	if (offset < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[3]));
    return INVALID_ARGS;
  }
	
	buf = (void *)((char *)buf +offset);

	memset(buf, val, size);

	return SUCCESS;
}

				
int get_sizeof(int argc, char **argv) 
{
  char *type;
  int size;

  if (argc != 1) {
    DBG(2, fprintf(outfp, "Number of args (%d) invalid for sizeof\n",
		   argc));
    return INVALID_ARGS;
  }

  type = argv[0];

  if (!strcmp(type, "char")) 
    size =  sizeof(char);
  else if (!strcmp(type, "int"))
    size =  sizeof(int);
  else if (!strcmp(type, "long"))
    size =  sizeof(long);
  else if (!strcmp(type, "flock"))
    size =  sizeof(struct flock);
  else if (!strcmp(type, "stat"))
    size =  sizeof(struct stat);
  else if (!strcmp(type, "statvfs"))
    size =  sizeof(struct statvfs);
  else if (!strcmp(type, "iovec"))
    size =  sizeof(struct iovec);
 else if (!strcmp(type, "xtvec"))
    size =  sizeof(struct xtvec);
  else
    return INVALID_ARGS;

  DBG(2, fprintf(outfp, "Size is %d\n", size));

  last_type = UINT;
  last_ret_val = size;
  return SUCCESS;
}

int test_do_exit(int argc, char **argv) 
{
  int val = 0;

  if (argc) {
    /* 
     * If argc is given, need to return the value of
     * the passed in variable 
     */
    val = get_obj(argv[0]);
  }
    
  /*
   * Clean up.
   */
  _sysio_shutdown();

  if (argc)
    DBG(3, printf("Exiting with %d from %s\n", val, argv[0]));

  exit(val);

  return 0;
}

int get_buffer(int argc, char **argv) 
{
  int size, align;
  struct buf_t *buf;

  if (argc == 1) /* Just put size, not alignment */
    align = 16;
  else if (argc == 2)
    align = get_obj(argv[1]);
  else {
    DBG(2, fprintf(outfp, "Number of args (%d) invalid for alloc\n",
		   argc));
    return INVALID_ARGS;
  }
    
  size = get_obj(argv[0]);
  if (size < 0) {
    DBG(2, fprintf(outfp, "Invalid size %s\n", argv[0]));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "Getting buffer of size %d and aligned at %d\n",
		 size, align));
  buf = (struct buf_t *)malloc(sizeof(struct buf_t));
  buf->buf = alloc_buff32(size, align);
  buf->len = size;
  buflist[next] = buf;
  DBG(3, fprintf(outfp, "Your buffer (%p) (%p) is at index %d\n",
		 (void *)buf, buf->buf, next));
  next++;

  last_type = PTR;
  last_ret_val = next-1;
  return SUCCESS;
}

int free_buffer(int argc, char **argv) 
{
  int index;
  char *name = argv[0];
  
  if (argc != 1) {
    DBG(2, fprintf(outfp, "Number of args (%d) invalid for free\n",
		   argc));
    return INVALID_ARGS;
  }

  /* 
   * Assume that there is one arg and it 
   * is a variable name which maps to an
   * index into the buffer array 
   */  
   index = get_obj(name);
   if (index < 0) {
     DBG(2, fprintf(outfp, "Can't find buffer %s\n",
		    name));
     return INVALID_VAR;
   }
   DBG(4, fprintf(outfp, "Freeing buffer at index %d\n", index));
   free(buflist[index]);

   free_obj(name);
   return SUCCESS;
}

int cmp_bufs(int argc, char **argv) 
{
  int res, index1, index2;
  char *buf1, *buf2;

  if (argc != 2) {
    fprintf(outfp, "Need two buffers to compare\n");
    return INVALID_ARGS;
  } 

  index1 = get_obj(argv[0]);
  if (index1 < 0) {
    fprintf(outfp, "Unable to locate buffer %s\n",
	   argv[0]);
    return INVALID_VAR;
  }
  buf1 = buflist[index1]->buf;

  index2 = get_obj(argv[1]);
  if (index2 < 0) {
    fprintf(outfp, "Unable to locate buffer %s\n",
	   argv[1]);
    return INVALID_VAR;
  }

  buf2 = buflist[index2]->buf;
  last_ret_val = strcmp(buf1, buf2);

  DBG(3, fprintf(outfp, "strcmp returned %d\n", res));
  return SUCCESS;
}

int test_do_chdir(int argc, char **argv) 
{
  if (argc != 1) {
    DBG(2, fprintf(outfp, "Number of args (%d) invalid for chdir\n",
		   argc));
    return INVALID_ARGS;
  }
  last_type = SINT;
  return sysio_chdir(argv[0]);
}


int test_do_chmod(int argc, char **argv) 
{
  if (argc != 2) {
    DBG(2, fprintf(outfp, "Number of args (%d) invalid for chmod\n",
		   argc));
    return INVALID_ARGS;
  }
  last_type = SINT;
  return sysio_chmod(argv[0], argv[1]);
}

int test_do_chown(int argc, char **argv) 
{
  if (argc != 2) {
    DBG(2, fprintf(outfp, "Number of args (%d) invalid for chown\n",
		   argc));
    return INVALID_ARGS;
  }
  last_type = SINT;
  return sysio_chown(argv[0], argv[1]);
}

int test_do_open(int argc, char **argv) 
{ 
  char *name = argv[0];
  int flags = O_RDWR;

  if (argc > 1) 
    flags = get_obj(argv[1]);

  if (name[0] == '$') {
    int index = get_obj(name);

    if (index < 0) {
      DBG(2, fprintf(outfp, "Unable to find buffer at %s\n",
		     name));
      return INVALID_VAR;
    }

    name = buflist[index]->buf;
  }

  DBG(4,  fprintf(outfp, "Opening file %s with flags %d\n", name, flags));
  if (argc == 2)
    return sysio_open(name, flags);
  else if (argc == 3)
    return sysio_open3(name, flags, argv[2]);
  else {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d)\n", argc));
    return INVALID_ARGS;
  }
  last_type = UINT;
  return SUCCESS;
}

int test_do_close(int argc, char **argv) 
{
  int fd;
  char *name = argv[0];

  if (argc != 1) {
    DBG(2, fprintf(outfp, "Number of args (%d) invalid for close\n",
		   argc));
    return INVALID_ARGS;
  }

  /* 
   * Assume that there is one arg and it 
   * is a variable name which maps to a file
   * descriptor 
   */
  fd = get_obj(name);
  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to map var %s to anything\n", name));
    return INVALID_VAR;
  }
  sysio_close(fd);
  free_obj(name);
  return SUCCESS;
}

int test_do_dup(int argc, char **argv) 
{
  int fd;
  char *var_name = argv[0];

  if (argc != 1) {
    DBG(2, fprintf(outfp, "Number of args (%d) invalid for dup\n",
		   argc));
    return INVALID_ARGS;
  }


  fd = get_obj(var_name);
  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to map var %s to any file\n", var_name));
    return INVALID_VAR;
  }

  last_ret_val = dup(fd);
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}

int test_do_dup2(int argc, char **argv) 
{
  int fd1, fd2;
  char *var_name1 = argv[0];
  char *var_name2 = argv[1];

  if (argc != 2) {
    DBG(2, fprintf(outfp, "Number of args (%d) invalid for dup2\n",
		   argc));
    return INVALID_ARGS;
  }

  fd1 = get_obj(var_name1);
  if (fd1 < 0) {
    DBG(2, fprintf(outfp, "Unable to map var %s to any file\n", var_name1));
    return INVALID_VAR;
  }

  fd2 = get_obj(var_name2);
  if (fd2 < 0) {
    DBG(2, fprintf(outfp, "Unable to map var %s to any file\n", var_name2));
    return INVALID_VAR;
  }

  last_ret_val = dup2(fd1, fd2);
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}

struct cmd_map fcntl_cmds[] = {
  { "F_DUPFD", F_DUPFD, 3 },
  { "F_GETFD", F_GETFD, 2 },
  { "F_SETFD", F_SETFD, 3 },
  { "F_GETFL", F_GETFL, 2 },
  { "F_SETFL", F_SETFL, 3 },
  { "F_SETLK", F_SETLK, 3 },
  { "F_SETLKW", F_SETLKW, 3 },
  { "F_GETLK", F_GETLK, 3 },
#if defined __USE_BSD || defined __USE_XOPEN2K
  { "F_GETOWN", F_GETOWN, 2 },
  { "F_SETOWN", F_SETOWN, 3 },
#endif
#ifdef __USE_GNU
  { "F_GETSIG", F_GETSIG, 2 },
  { "F_SETSIG", F_SETSIG, 3 },
  { "F_SETLEASE", F_SETLEASE, 3},
  { "F_GETLEASE", F_GETLEASE, 2},
  { "F_NOTIFY", F_NOTIFY, 3} ,
#endif
  { NULL, -1, 0 }
};

struct cmd_map* get_cmd(char *cmd_name, int argc)
{
  int i =0;

  while (fcntl_cmds[i].cmd_name) {
    if (!strcmp(fcntl_cmds[i].cmd_name, cmd_name)) {
      if (fcntl_cmds[i].num_args == argc)
	return &fcntl_cmds[i];
      else
	return NULL;
    }
    i++;
  }
  return NULL;
}

int test_do_fcntl(int argc, char **argv)
{
  
  struct cmd_map *cmd;
  int fd;

  /* 
   * get_cmd translates a symbolic command into
   * into its numerical equivalent. It also
   * verifies that the number of args is the
   * correct number for the command. It returns
   * NULL on failure
   */
  cmd = get_cmd(argv[1], argc);
  if (!cmd) {
    DBG(2, fprintf(outfp, "Unable to get command %s\n", argv[1]));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);
  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to map %s to file descriptor \n", argv[0]));
    return INVALID_VAR;
  }

  if (argc > 2)
    last_ret_val =  sysio_fcntl(fd, cmd, argv[2]);
  else
    last_ret_val = sysio_fcntl(fd, cmd, NULL);
  DBG(4, fprintf(outfp, "Got return value of %d\n", (int)last_ret_val));
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}

int test_do_fstat(int argc, char **argv)
{
  int fd, index;
  void *buf;

  if (argc != 2) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) for fstat\n",
		   argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file assocated with %s\n",
		   argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);
  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer assocated with %s\n",
		   argv[1]));
    return INVALID_VAR;
  }
  
  buf = buflist[index]->buf;
  
  last_ret_val = sysio_fstat(fd, buf);
  my_errno = errno;
  last_type = SINT;
  
  return SUCCESS;
}

int test_do_lstat(int argc, char **argv)
{
  char *name = argv[0];
  int index;
  void *buf;

  if (argc != 2) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) for lstat\n",
		   argc));
    return INVALID_ARGS;
  }

  index = get_obj(argv[1]);
  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer assocated with %s\n",
		   argv[1]));
    return INVALID_VAR;
  }
  
  buf = buflist[index]->buf;
  last_type = SINT;  

  return sysio_lstat(name, buf);
}

int test_do_fsync(int argc, char **argv)
{
  int fd;

  if (argc != 1) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to fsync\n", argc));
    return INVALID_ARGS;
  }

  
  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file assocated with %s\n",
		   argv[0]));
    return INVALID_VAR;
  }

  last_ret_val = fsync(fd);
  my_errno = errno;
  last_type = SINT;  

  return SUCCESS;
}


int test_do_fdatasync(int argc, char **argv)
{
  int fd;

  if (argc != 1) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to fdatasync\n", argc));
    return INVALID_ARGS;
  }

  
  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file assocated with %s\n",
		   argv[0]));
    return INVALID_VAR;
  }

  last_ret_val = fdatasync(fd);
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}


int test_do_ftruncate(int argc, char **argv)
{
  int fd;
  off_t length;

  if (argc != 2) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to ftruncate\n", argc));
    return INVALID_ARGS;
  }

  
  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file assocated with %s\n",
		   argv[0]));
    return INVALID_VAR;
  }

  length = (off_t)get_obj(argv[1]);

  DBG(3, fprintf(outfp, "Setting file %d to %d\n", fd, (int) length));

  last_ret_val = ftruncate(fd, length);
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}

int test_do_getcwd(int argc, char **argv)
{
  char *buf;
  int size, index;

  if (argc != 2) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to getcwd\n", argc));
    return INVALID_ARGS;
  }

  index = get_obj(argv[0]);
  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer assocated with %s\n",
		   argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  size = get_obj(argv[1]);

  DBG(4, fprintf(outfp, "Getting cwd with buffer size of %d\n", size));

  last_ret_val = 0;
  if (!getcwd(buf, size)) {
      last_ret_val = -1;
      if (errno == ERANGE) {
	  DBG(2, fprintf(outfp, "Need a bigger buffer!\n"));
      }
  }
 
  my_errno = errno;

  
  DBG(3, fprintf(outfp, "cwd: %s\n", buf));
  last_type = SINT;

  return SUCCESS;
}

int test_do_lseek(int argc, char **argv)
{
  int fd, whence;
  off_t offset;

  
  if (argc != 3) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to lseek\n", argc));
    return INVALID_ARGS;
  }

  
  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file assocated with %s\n",
		   argv[0]));
    return INVALID_VAR;
  }

  offset = (off_t)get_obj(argv[1]);
  whence = get_obj(argv[2]);

  if (whence < 0 ) {
    DBG(2, fprintf(outfp, "Not familiar with whence of %s\n",
		   argv[2]));
    return INVALID_ARGS;
  }

  last_ret_val = lseek(fd, offset, whence);
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}

int test_do_getdirentries(int argc, char **argv) 
{
  int fd, nbytes;
  int bufindex;
  off_t basep;
  char *buf;
  struct var_mapping *base_map;

  if (argc != 4) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to getdirentries\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file assocated with %s\n",
		   argv[0]));
    return INVALID_VAR;
  }

  bufindex = get_obj(argv[1]);
   
  if (bufindex < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer assocated with %s\n",
		   argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[bufindex]->buf;

  nbytes = get_obj(argv[2]);

  if (nbytes < 0) {
    DBG(2, fprintf(outfp, "I don't understand %s\n",
		   argv[2]));
    return INVALID_ARGS;
  }

  base_map = get_map(argv[3]);
  if (!base_map) {
    DBG(3, fprintf(outfp, "Resetting basep\n"));
    /* 
     * Assume that this is the first getdirentries call
     * and we need to setup the base pointer
     */
    basep = 0;
  } else 
    basep = base_map->obj;
      
  DBG(3, fprintf(outfp, "basep is (starting) %d\n", (int) basep));
  last_ret_val = sysio_getdirentries(fd, buf, nbytes, &basep);
  if (base_map)
    base_map->obj = basep;
  else
    store_result(argv[3]+1, basep);
  DBG(3, fprintf(outfp, "basep is (ending) %d\n", (int) basep));
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}

int test_do_mkdir(int argc, char **argv)
{
  if (argc !=2) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to mkdir\n", argc));
    return INVALID_ARGS;
  }

  last_type = SINT;
  return sysio_mkdir(argv[0], argv[1]);
}

int test_do_creat(int argc, char **argv)
{
  if (argc !=2) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to creat\n", argc));
    return INVALID_ARGS;
  }

  last_type = UINT;
  return sysio_creat(argv[0], argv[1]);
}

int test_do_stat(int argc, char **argv)
{
  int index;
  void *buf;
  char *str;

  if (argc != 2) {
    fprintf(outfp, "Invalid number of arguments (%d) for stat\n",
	   argc);
    return -1;
  }


  index = get_obj(argv[1]);
  if (index < 0) {
    fprintf(outfp, "Unable to find buffer assocated with %s\n",
	   argv[1]);
  }
  
  buf = buflist[index]->buf;
  last_type = SINT;
  
  str = get_str(argv[0]);
  return sysio_stat(str, buf);
}

int test_do_statvfs(int argc, char **argv)
{
  int index;
  void *buf;

  if (argc != 2) {
    fprintf(outfp, "Invalid number of arguments (%d) for statvfs\n",
	   argc);
    return -1;
  }


  index = get_obj(argv[1]);
  if (index < 0) {
    fprintf(outfp, "Unable to find buffer assocated with %s\n",
	   argv[1]);
  }
  
  buf = buflist[index]->buf;
  last_type = SINT;
  
  return sysio_statvfs(argv[0], buf);
}

int test_do_fstatvfs(int argc, char **argv)
{
  int index, fd;
  void *buf;

  if (argc != 2) {
    fprintf(outfp, "Invalid number of arguments (%d) for fstatvfs\n",
	   argc);
    return -1;
  }

  
  fd = get_obj(argv[0]);

  if (fd < 0) {
    fprintf(outfp, "Unable to find file assocated with %s\n",
	   argv[0]);
  }


  index = get_obj(argv[1]);
  if (index < 0) {
    fprintf(outfp, "Unable to find buffer assocated with %s\n",
	   argv[1]);
  }
  
  buf = buflist[index]->buf;
  last_type = SINT;
  
  return sysio_fstatvfs(fd, buf);
}

int test_do_truncate(int argc, char **argv)
{
  off_t length;

  if (argc != 2) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to truncate\n", argc));
    return INVALID_ARGS;
  }
  
  length = (off_t)get_obj(argv[1]);

  DBG(3, fprintf(outfp, "Setting file %s to %d\n", argv[0], (int) length));

  last_ret_val = truncate(argv[0], length);
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}

int test_do_rmdir(int argc, char **argv)
{

  if (argc != 1) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to rmdir\n", argc));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "Removing dir %s\n", argv[0]));

  last_ret_val = rmdir(argv[0]);
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}

int test_do_symlink(int argc, char **argv)
{
  if (argc != 2) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to symlink\n", argc));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "Linking %s to %s\n", argv[0], argv[1]));

  last_ret_val = symlink(argv[0], argv[1]);
  if (last_ret_val) {
    if (errno < 0) 
      errno = errno*-1;
    my_perror("symlink");
  } 
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}


struct cmd_map ioctl_cmds[] = {
#if 0
  { "BLKROSET", BLKROSET, 3 },
  { "BLKROGET", BLKROGET, 3 },
  { "BLKRRPART", BLKRRPART, 3 },
  { "BLKGETSIZE", BLKGETSIZE, 3 },
  { "BLKRASET", BLKRASET, 3 },
  { "BLKRAGET", BLKRAGET, 3 },
  { "BLKSECTSET", BLKSECTSET, 3 },
  { "BLKSECTGET", BLKSECTGET, 3 },
  { "BLKSSZGET", BLKSSZGET, 3 },
  { "BLKGETLASTSECT", BLKGETLASTSECT, 3 },
  { "BLKSETLASTSECT", BLKSETLASTSECT, 3 },
  { "BLKBSZGET", BLKBSZGET, 3 },
  { "BLKBSZSET", BLKBSZSET, 3 },
  { "FIBMAP", FIBMAP, 3 },
  { "FIGETBSZ", FIGETBSZ, 3},
#endif
  { NULL, -1, 0 }
};

int get_ioctl_cmd(char *cmd) 
{
  int i = 0;

  while (ioctl_cmds[i].cmd_name != NULL) {
    if (strcmp(ioctl_cmds[i].cmd_name, cmd))
      i++;
    else
      return ioctl_cmds[i].cmd;
  }

  return -1;
}

int test_do_ioctl(int argc, char **argv)
{
  int fd, cmd;

  if (argc != 3) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to ioctl\n", argc));
    return INVALID_ARGS;
  }


  fd = get_obj(argv[0]);
  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file %s\n", argv[0]));
    return INVALID_VAR;
  }

  cmd = get_ioctl_cmd(argv[1]);
  if (cmd == -1) {
    DBG(2, fprintf(outfp, "Do not understand command %s\n", argv[1]));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "Executing command %s\n", argv[1]));

  last_ret_val = ioctl(fd, cmd, argv[2]);
  my_errno = errno;
  if (last_ret_val) 
    my_perror("ioctl");
  last_type = SINT;

  return SUCCESS;
}

int test_do_unlink(int argc, char **argv)
{
  if (argc != 1) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to unlink\n", argc));
    return INVALID_ARGS;
  }

  DBG(4, fprintf(outfp, "Unlinking %s\n", argv[0]));

  last_ret_val = unlink(argv[0]);
  my_errno = errno;
  if (last_ret_val) 
    my_perror("unlink");
  last_type = SINT;

  return SUCCESS;
}

int test_do_umask(int argc, char **argv)
{
  mode_t old_mask;

  if (argc != 1) {
    DBG(2, fprintf(outfp, "Incorrect number of args (%d) for umask\n", argc));
    return INVALID_ARGS;
  }

  last_ret_val = old_mask = sysio_umask(argv[0]);
  my_errno = errno;
  DBG(3, fprintf(outfp, "Previous umask was %o\n", old_mask));
  last_type = UINT;
  
  return SUCCESS;
}

int test_do_iowait(int argc, char **argv)
{
  long err;
  ioid_t ioid;

  if (argc != 1) {
    DBG(2, fprintf(outfp, "Incorrect amount of args (%d) for iowait\n", argc));
    return INVALID_ARGS;
  }

  err = get_obj(argv[0]);
  if (err < 0) {
    DBG(2, fprintf(outfp, "Cannot find ioid at %s\n", argv[0]));
    return INVALID_VAR;
  }
  
  ioid = (ioid_t)err;

  last_ret_val =  iowait(ioid);
  my_errno = errno;
  if (last_ret_val < 0) {
    my_perror("iowait");
  }
  last_type = SINT;

  return SUCCESS;
}

int test_do_iodone(int argc, char **argv)
{
  long err;
  ioid_t ioid;

  if (argc != 1) {
    DBG(2, fprintf(outfp, "Incorrect amount of args (%d) for iodone\n", argc));
    return INVALID_ARGS;
  }

  err = get_obj(argv[0]);
  if (err < 0) {
    DBG(2, fprintf(outfp, "Cannot find ioid at %s\n", argv[0]));
    return INVALID_VAR;
  }
  ioid = (ioid_t)err;

  last_ret_val =  iowait(ioid);
  if (last_ret_val < 0) {
    my_perror("iodone");
  }
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;

}

int test_do_ipread(int argc, char **argv) 
{
  int fd, index, count, offset;
  char *buf;

  if (argc != 4) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to ipread\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);
  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file at %s\n", argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);
  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer at %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  count = get_obj(argv[2]);
  if (count < 0) {
    DBG(2, fprintf(outfp, "Do not understand count %s\n", argv[2]));
    return INVALID_ARGS;
  }

  offset = get_obj(argv[3]);
  if (offset < 0) {
    DBG(2, fprintf(outfp, "Unable to understand offset of %s\n", argv[3]));
    return INVALID_ARGS;
  }

  last_ret_val = (long)ipread(fd, buf, count, offset);
  if (last_ret_val < 0) {
    my_perror("ipread");
  }
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}

int test_do_iread(int argc, char **argv) 
{
  int fd, index, count;
  char *buf;

  if (argc != 3) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to iread\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);
  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file at %s\n", argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);
  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer at %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  count = get_obj(argv[2]);
  if (count < 0) {
    DBG(2, fprintf(outfp, "Do not understand count %s\n", argv[2]));
    return INVALID_ARGS;
  }

  last_ret_val = (long) iread(fd, buf, count);
  if (last_ret_val < 0) {
    my_perror("iread");
  }
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}


int test_do_ipreadv(int argc, char **argv)
{
  int fd, count, index;
  off_t offset;
  char *buf;
  struct iovec *iov;

  if (argc != 4) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to ipreadv\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  iov = (struct iovec *)buf;
  count = get_obj(argv[2]);

  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[2]));
    return INVALID_ARGS;
  }

  offset = get_obj(argv[3]);
  if (offset < 0) {
    DBG(2, fprintf(outfp, "Unable to understand offset value %s\n", argv[3]));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "ipreadv(fd: %d vector:{iov_base: %p iov_len %d} count: %d offset: %d\n",
		 fd, iov->iov_base, (int)iov->iov_len, count, (int) offset)); 

  last_ret_val = (long) ipreadv(fd, iov, count, offset);
  if (last_ret_val < 0)
    my_perror("ipreadv");
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}


int test_do_preadv(int argc, char **argv)
{
  int fd, count, index;
  off_t offset;
  char *buf;
  struct iovec *iov;

  if (argc != 4) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to preadv\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  iov = (struct iovec *)buf;
  count = get_obj(argv[2]);

  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[2]));
    return INVALID_ARGS;
  }

  offset = get_obj(argv[3]);
  if (offset < 0) {
    DBG(2, fprintf(outfp, "Unable to understand offset value %s\n", argv[3]));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "preadv(fd: %d vector:{iov_base: %p iov_len %d} count: %d offset: %d\n",
		 fd, iov->iov_base, (int) iov->iov_len, count, (int) offset)); 

  last_ret_val = preadv(fd, iov, count, offset);
  my_errno = errno;
  if (last_ret_val < 0)
    my_perror("preadv");
  last_type = SINT;

  return SUCCESS;
}


int test_do_pread(int argc, char **argv)
{
  int fd, count, index, numbytes, offset;
  char *buf;

  if (argc != 4) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to pread\n", argc));
    return INVALID_ARGS;
  }

  
  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file assocated with %s\n",
		   argv[0]));
    return INVALID_VAR;
  }
  
  index = get_obj(argv[1]);
    
  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer assocated with %s\n",
		   argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  count = get_obj(argv[2]);
  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand count of %s\n", argv[1]));
    return INVALID_ARGS;
  }

  offset = get_obj(argv[3]);
  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand offset of %s\n", argv[2]));
    return INVALID_ARGS;
  }


  last_ret_val = numbytes = (int) pread(fd, buf, count, offset);
  my_errno = errno;
  DBG(4, fprintf(outfp, "Read %d bytes out of %d starting at offset %x\n", 
		 numbytes, count, offset));
  DBG(3, fprintf(outfp, "Got %s\n", buf));
  last_type = SINT;

  return SUCCESS;
}


int test_do_ireadv(int argc, char **argv)
{
  int fd, count, index;
  char *buf;
  struct iovec *iov;

  if (argc != 3) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to ireadv\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  iov = (struct iovec *)buf;
  count = get_obj(argv[2]);

  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[2]));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "ireadv (fd: %d, vector:{ iov_base: %p iov_len %d }, count: %d\n",
		 fd, iov->iov_base, (int)iov->iov_len, count)); 

  last_ret_val = (long) ireadv(fd, iov, count);
  if (last_ret_val < 0)
    my_perror("ireadv");
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}

int test_do_readv(int argc, char **argv)
{
  int fd, count, index;
  char *buf;
  struct iovec *iov;

  if (argc != 3) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to readv\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  iov = (struct iovec *)buf;
  count = get_obj(argv[2]);

  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[2]));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "ireadv (fd: %d, vector:{ iov_base: %p iov_len %d }, count: %d\n",
		 fd, iov->iov_base, (int)iov->iov_len, count)); 

  last_ret_val = readv(fd, iov, count);
  if (last_ret_val < 0)
    my_perror("readv");
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}

int test_do_read(int argc, char **argv)
{
  int fd, count, index, numbytes=0;
  char *buf;

  if (argc < 3) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to read\n", argc));
    return INVALID_ARGS;
  }

  
  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file assocated with %s\n",
		   argv[0]));
    return INVALID_VAR;
  }
  
  index = get_obj(argv[1]);
  
  
  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer assocated with %s\n",
		   argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  count = get_obj(argv[2]);

  if ( (argc == 4) && (!strcmp(argv[3], "delay")) ){
    int i;
    /* Wait a little while for input */
    for (i=0; i < count; i++) {
      sleep(0.005);
      numbytes += (int) read(fd, buf, 1);
      last_ret_val = numbytes;
      
    }
  } else {
    last_ret_val = numbytes = (int) read(fd, buf, count);
  }
  my_errno = errno;

  DBG(3, fprintf(outfp, "Read %d bytes out of %d\n", numbytes, count));
  DBG(3, fprintf(outfp, "Got %s\n", buf));
  last_type = SINT;

  return SUCCESS;
}

int test_do_ipwritev(int argc, char **argv)
{
  int fd, count, index, offset;
  char *buf;
  struct iovec *iov;

  if (argc != 4) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to ipwritev\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  iov = (struct iovec *)buf;

  count = get_obj(argv[2]);
  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand count %s\n", argv[2]));
    return INVALID_ARGS;
  }

  offset = get_obj(argv[3]);
  if (offset < 0) {
    DBG(2, fprintf(outfp, "Unable to understand offset %s\n", argv[3]));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, 
		 "ipwritev(fd: %d, vector: { iov_base: %p iov_len %d }, count: %d, offset: %d\n",
		 fd, iov->iov_base, (int)iov->iov_len, count, offset)); 

  last_ret_val = (long) ipwritev(fd, iov, count, offset);
  my_errno = errno;
  if (last_ret_val < 0)
    my_perror("ipwritev");
  last_type = SINT;

  return SUCCESS;
}

int test_do_ipwrite(int argc, char **argv)
{
  int fd, count, index, offset;
  char *buf;

  if (argc != 4) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to ipwrite\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  count = get_obj(argv[2]);
  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand count %s\n", argv[2]));
    return INVALID_ARGS;
  }

  offset = get_obj(argv[3]);
  if (offset < 0) {
    DBG(2, fprintf(outfp, "Unable to understand offset %s\n", argv[3]));
    return INVALID_ARGS;
  }

  last_ret_val = (long) ipwrite(fd, buf, count, offset);
  if (last_ret_val < 0)
    my_perror("ipwrite");
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}

int test_do_pwritev(int argc, char **argv)
{
  int fd, count, index, offset;
  char *buf;
  struct iovec *iov;

  if (argc != 4) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to pwritev\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  iov = (struct iovec *)buf;

  count = get_obj(argv[2]);
  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand count %s\n", argv[2]));
    return INVALID_ARGS;
  }

  offset = get_obj(argv[3]);
  if (offset < 0) {
    DBG(2, fprintf(outfp, "Unable to understand offset %s\n", argv[3]));
    return INVALID_ARGS;
  }


  DBG(3, fprintf(outfp, 
		 "pwritev(fd: %d, vector: { iov_base: %p iov_len %d }, count: %d, offset: %d\n",
		 fd, iov->iov_base, (int)iov->iov_len, count, offset)); 

  last_ret_val = (long) pwritev(fd, iov, count, offset);
  if (last_ret_val < 0)
    my_perror("ipwritev");
  my_errno = errno;
  last_type = SINT;
  
  return SUCCESS;
}

int test_do_pwrite(int argc, char **argv)
{
  int fd, count, index, offset;
  char *buf;

  if (argc != 4) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to pwrite\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  count = get_obj(argv[2]);
  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand count %s\n", argv[2]));
    return INVALID_ARGS;
  }

  offset = get_obj(argv[3]);
  if (offset < 0) {
    DBG(2, fprintf(outfp, "Unable to understand offset %s\n", argv[3]));
    return INVALID_ARGS;
  }

  last_ret_val = pwrite(fd, buf, count, offset);
  my_errno = errno;
  if (last_ret_val < 0)
    my_perror("pwrite");
  last_type = SINT;

  return SUCCESS;
}


int test_do_iwritev(int argc, char **argv)
{
  int fd, count, index;
  char *buf;
  struct iovec *iov;

  if (argc != 3) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to iwritev\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  iov = (struct iovec *)buf;

  count = get_obj(argv[2]);
  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand count %s\n", argv[2]));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "iwritev(fd: %d, vector: { iov_base: %p iov_len %d }, count: %d\n",
		 fd, iov->iov_base, (int)iov->iov_len, count)); 

  last_ret_val = (long) iwritev(fd, iov, count);
  my_errno = errno;
  if (last_ret_val < 0)
    my_perror("iwritev");
  last_type = SINT;

  return SUCCESS;
}

int test_do_iwrite(int argc, char **argv)
{
  int fd, count, index;
  char *buf;

  if (argc != 3) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to iwrite\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  count = get_obj(argv[2]);
  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand count %s\n", argv[2]));
    return INVALID_ARGS;
  }

  last_ret_val = (long) iwrite(fd, buf, count);
  my_errno = errno;
  if (last_ret_val < 0)
    my_perror("iwrite");
  last_type = SINT;

  return SUCCESS;
}


int test_do_write(int argc, char **argv)
{
  int fd, count, index, err;
  char *buf;

  if (argc != 3) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to write\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_VAR;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  count = get_obj(argv[2]);
  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand count %s\n", argv[2]));
    return INVALID_ARGS;
  }

  DBG(4, fprintf(outfp, "Writing out %d bytes (%s) using fd of %x\n",
		 count, buf, fd));
  err = write(fd, buf, count);
  if (err < 0)
    my_perror("write");

  last_ret_val = err;
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}


int test_do_writev(int argc, char **argv)
{
  int fd, count, index;
  char *buf;
  struct iovec *iov;

  if (argc != 3) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to writev\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_ARGS;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  iov = (struct iovec *)buf;
  count = get_obj(argv[2]);

  if (count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[2]));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "writev(fd: %d, vector: { iov_base: %p iov_len %d }, count: %d\n",
		 fd, iov->iov_base, (int)iov->iov_len, count)); 

  last_ret_val = writev(fd, iov, count);
  if (last_ret_val < 0)
    my_perror("writev");
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}

int test_do_mknod(int argc, char **argv) 
{
  int dev;

  if (argc != 3) {
    DBG(2, fprintf(outfp, "Invalid number of args (%d) for mknod\n", argc));
    return INVALID_ARGS;
  }

  dev = get_obj(argv[2]);
  if (dev < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[2]));
    return INVALID_ARGS;
  }
  last_type = SINT;

  
  return sysio_mknod(argv[0], argv[1], (dev_t) dev);
}

int test_do_umount(int argc, char **argv) 
{
  int err;

  if (argc != 1) {
    DBG(2, fprintf(outfp, "Invalid number (%d) of args for umount\n", argc));
    return INVALID_ARGS;
  }

  err = umount(argv[0]);
  if (err)
    my_perror("umount");

  my_errno = errno;
  last_ret_val = err;
  last_type = SINT;

  return SUCCESS;
}
 
int test_do_init_iovec(int argc, char **argv)
{
	int iov_index, buf_index;
	int offset, len, pos;
	struct iovec *iov_ptr;
	char *base_ptr;

	if (argc != 5) {
		DBG(2, fprintf(outfp, "Need buffer, offset, len, array pos, and iov pointer\n"));
		return INVALID_ARGS;
	}

	if ((buf_index = get_obj(argv[0])) < 0) {
		DBG(2, fprintf(outfp, "Unable to find object %s\n", argv[0]));
		return INVALID_VAR;
	}
	base_ptr = buflist[buf_index]->buf;

	if ((offset = get_obj(argv[1])) < 0) {
		DBG(2, fprintf(outfp, "Cannot understand offset of %s\n", argv[1]));
		return INVALID_VAR;
	}
	
	if ((len = get_obj(argv[2])) < 0) {
		DBG(2, fprintf(outfp, "Cannot understand len of %s\n", argv[2]));
		return INVALID_VAR;
	}
	
	if ((pos = get_obj(argv[3])) < 0) {
		DBG(2, fprintf(outfp, "Cannot understand array pos of %s\n", argv[3]));
		return INVALID_VAR;
	}

	if ((iov_index = get_obj(argv[4])) < 0) {
		DBG(2, fprintf(outfp, "Unable to find object %s\n", argv[4]));
		return INVALID_VAR;
	}
	iov_ptr = (struct iovec *)(buflist[iov_index]->buf);	

	iov_ptr[pos].iov_len = len;
	iov_ptr[pos].iov_base = (void *)(base_ptr + offset);
	
	DBG(3, fprintf(outfp, "iov_ptr.len is %d and base is %p\n", 
		       (int)iov_ptr[pos].iov_len, iov_ptr[pos].iov_base));
   my_errno = errno;
  last_type = PTR;

	return SUCCESS;
}


int test_do_init_xtvec(int argc, char **argv)
{
	int xtv_index;
	int offset, len, pos;
	struct xtvec *xtv_ptr;

	if (argc != 4) {
		DBG(2, fprintf(outfp, "Need offset, len, array pos, and xtv pointer\n"));
		return INVALID_ARGS;
	}

	if ((offset = get_obj(argv[0])) < 0) {
		DBG(2, fprintf(outfp, "Cannot understand offset of %s\n", argv[0]));
		return INVALID_VAR;
	}
	
	if ((len = get_obj(argv[1])) < 0) {
		DBG(2, fprintf(outfp, "Cannot understand len of %s\n", argv[1]));
		return INVALID_VAR;
	}
	
	if ((pos = get_obj(argv[2])) < 0) {
		DBG(2, fprintf(outfp, "Cannot understand array pos of %s\n", argv[2]));
		return INVALID_VAR;
	}

	if ((xtv_index = get_obj(argv[3])) < 0) {
		DBG(2, fprintf(outfp, "Unable to find object %s\n", argv[3]));
		return INVALID_VAR;
	}
	xtv_ptr = (struct xtvec *)(buflist[xtv_index]->buf);	

	xtv_ptr[pos].xtv_len = len;
	xtv_ptr[pos].xtv_off = offset;
	
	DBG(3, fprintf(outfp, "xtv_ptr.len is %d and offset is %d\n", 
		       (int)xtv_ptr[pos].xtv_len, (int)xtv_ptr[pos].xtv_off));

	my_errno = errno;
  last_type = PTR;

	return SUCCESS;
}

int test_do_writex(int argc, char **argv)
{
  int fd, iov_count, xtv_count,index;
  char *buf;
  struct iovec *iov;
	struct xtvec *xtv;

  if (argc != 5) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to writex\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_ARGS;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  iov = (struct iovec *)buf;
  iov_count = get_obj(argv[2]);

  if (iov_count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[2]));
    return INVALID_ARGS;
  }

  index = get_obj(argv[3]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find xtvs described by %s\n", argv[3]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  xtv = (struct xtvec *)buf;
  xtv_count = get_obj(argv[4]);

  if (xtv_count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[4]));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "writex(fd: %d, iov: %p iov_cnt: %d, xtv: %p, xtv_cnt: %d\n",
		 fd, (void *)iov, iov_count, (void *)xtv, xtv_count)); 

  last_ret_val = writex(fd, iov, iov_count, xtv, xtv_count);
  if (last_ret_val < 0)
    my_perror("writex");
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}


int test_do_iwritex(int argc, char **argv)
{
  int fd, iov_count, xtv_count,index;
  char *buf;
  struct iovec *iov;
	struct xtvec *xtv;

  if (argc != 5) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to iwritex\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_ARGS;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  iov = (struct iovec *)buf;
  iov_count = get_obj(argv[2]);

  if (iov_count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[2]));
    return INVALID_ARGS;
  }

  index = get_obj(argv[3]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find xtvs described by %s\n", argv[3]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  xtv = (struct xtvec *)buf;
  xtv_count = get_obj(argv[4]);

  if (xtv_count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[4]));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "iwritex(fd: %d, iov: %p iov_cnt: %d, xtv: %p, xtv_cnt: %d\n",
		 fd, (void *)iov, iov_count, (void *)xtv, xtv_count)); 

  last_ret_val = (long) iwritex(fd, iov, iov_count, xtv, xtv_count);
  if (last_ret_val < 0)
    my_perror("iwritex");
  my_errno = errno;
  last_type = SINT;

	return SUCCESS;
}


int test_do_readx(int argc, char **argv)
{
  int fd, iov_count, xtv_count,index;
  char *buf;
  struct iovec *iov;
	struct xtvec *xtv;

  if (argc != 5) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to readx\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_ARGS;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  iov = (struct iovec *)buf;
  iov_count = get_obj(argv[2]);

  if (iov_count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[2]));
    return INVALID_ARGS;
  }

  index = get_obj(argv[3]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find xtvs described by %s\n", argv[3]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  xtv = (struct xtvec *)buf;
  xtv_count = get_obj(argv[4]);

  if (xtv_count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[4]));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "readx(fd: %d, iov: %p iov_cnt: %d, xtv: %p, xtv_cnt: %d\n",
		 fd, (void *)iov, iov_count, (void *)xtv, xtv_count)); 

  last_ret_val = readx(fd, iov, iov_count, xtv, xtv_count);
  if (last_ret_val < 0)
    my_perror("readx");
  my_errno = errno;
  last_type = SINT;

  return SUCCESS;
}


int test_do_ireadx(int argc, char **argv)
{
  int fd, iov_count, xtv_count,index;
  char *buf;
  struct iovec *iov;
	struct xtvec *xtv;

  if (argc != 5) {
    DBG(2, fprintf(outfp, "Invalid number of arguments (%d) to ireadx\n", argc));
    return INVALID_ARGS;
  }

  fd = get_obj(argv[0]);

  if (fd < 0) {
    DBG(2, fprintf(outfp, "Unable to find file described by %s\n", argv[0]));
    return INVALID_ARGS;
  }

  index = get_obj(argv[1]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buffer described by %s\n", argv[1]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  iov = (struct iovec *)buf;
  iov_count = get_obj(argv[2]);

  if (iov_count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[2]));
    return INVALID_ARGS;
  }

  index = get_obj(argv[3]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find xtvs described by %s\n", argv[3]));
    return INVALID_VAR;
  }

  buf = buflist[index]->buf;

  xtv = (struct xtvec *)buf;
  xtv_count = get_obj(argv[4]);

  if (xtv_count < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[4]));
    return INVALID_ARGS;
  }

  DBG(3, fprintf(outfp, "ireadx(fd: %d, iov: %p iov_cnt: %d, xtv: %p, xtv_cnt: %d\n",
		 fd, (void *)iov, iov_count, (void *)xtv, xtv_count)); 

  last_ret_val = (long) ireadx(fd, iov, iov_count, xtv, xtv_count);
  if (last_ret_val < 0)
    my_perror("ireadx");
  my_errno = errno;
  last_type = SINT;

	return SUCCESS;
}


int do_checkbuf(int argc, char **argv)
{
	 int size, val, index, i, offset;
	 int *ref_buf, *buf;
	
	if (argc != 4) {
		DBG(2, fprintf(outfp, "Need buffer, val, and offset for checkbuf\n"));
		return INVALID_ARGS;
	}

	index = get_obj(argv[0]);

  if (index < 0) {
    DBG(2, fprintf(outfp, "Unable to find buf described by %s\n", argv[0]));
    return INVALID_VAR;
  }

  buf = (int *)buflist[index]->buf;	


	size = get_obj(argv[1]);

	if (size < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[1]));
    return INVALID_ARGS;
  }

	val = get_obj(argv[2]);
	
  if (val < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[2]));
    return INVALID_ARGS;
  }

	
	offset = get_obj(argv[3]);
	
	if (offset < 0) {
    DBG(2, fprintf(outfp, "Unable to understand %s\n", argv[3]));
    return INVALID_ARGS;
  }
	

	ref_buf = (int *)malloc(size);
	memset((void *)ref_buf, val, size);

	last_ret_val =0;
	buf = (int *)((char *)buf + offset);
	for (i=0; (unsigned)i < size/sizeof(int); i++) {
		if (buf[i] != ref_buf[i]) {
			DBG(2, fprintf(stderr, "At pos %d I found a 0x%08x instead of 0x%08x\n",
										 i, buf[i], ref_buf[i]));
			fprintf(stderr, "At pos %d I found a 0x%08x instead of 0x%08x (val was %d)\n",
										 i, buf[i], ref_buf[i], val);
			last_ret_val = 1;
			break;
		}
	}

  my_errno = errno;
  last_type = SINT;

	return SUCCESS;
}
