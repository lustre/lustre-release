#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 500
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/uio.h>
#include <sys/queue.h>

#include "xtio.h"
#include "mount.h"
#include "test.h"
#include "test_driver.h"


struct queue_t;
    
typedef struct cmd_tree_t {
  char *res_name;
  char *val;
  int arg_count;
  struct queue_t *children;
} cmd_tree;

struct queue_t {
    char *val;
    cmd_tree *cmd;
    struct queue_t *next;
};

struct cmd_t cmd_list[] = {
  {"alloc", get_buffer, usage_get_buffer},
  {"chdir", test_do_chdir, usage_chdir},
  {"checkbuf", do_checkbuf, usage_checkbuf},
  {"chmod", test_do_chmod, usage_chmod},
  {"chown", test_do_chown, usage_chown},
  {"clear", test_do_clear, usage_clear},
  {"close", test_do_close, usage_close},
  {"cmpstr", cmp_bufs, usage_cmpbufs},
  {"creat", test_do_creat, usage_creat},
  {"debug", test_do_setdebug, usage_setdebug},
  {"dup", test_do_dup, usage_dup},
  {"dup2", test_do_dup2, usage_dup2},
  {"endian", get_endian, usage_endian},
  {"exit", test_do_exit, usage_exit},
  {"fcntl", test_do_fcntl, usage_fcntl},
  {"fdatasync", test_do_fdatasync, usage_fdatasync},
  {"fill", test_do_fillbuff, usage_do_fillbuff},
  {"free", free_buffer, usage_free_buffer},
  {"fstat", test_do_fstat, usage_fstat},
  {"fstatvfs", test_do_fstatvfs, usage_fstatvfs},
  {"fsync", test_do_fsync, usage_fsync},
  {"ftruncate", test_do_ftruncate, usage_ftruncate},
  {"getcwd", test_do_getcwd, usage_getcwd},
  {"getdirentries", test_do_getdirentries, usage_getdirentries},
  {"init", test_do_init, usage_init},
  {"init_iovec", test_do_init_iovec, usage_init_iovec},
  {"init_xtvec", test_do_init_xtvec, usage_init_xtvec}, 
  {"ioctl", test_do_ioctl, usage_ioctl},
  {"iodone", test_do_iodone, usage_iodone},
  {"iowait", test_do_iowait, usage_iowait},
  {"ipread", test_do_ipread, usage_ipread},
  {"ipreadv", test_do_ipreadv, usage_ipreadv},
  {"ipwrite", test_do_ipwrite, usage_ipwrite},
  {"ipwritev", test_do_ipwritev, usage_ipwritev},
  {"iread", test_do_iread, usage_iread},
  {"ireadv", test_do_ireadv, usage_ireadv},
	{"ireadx", test_do_ireadx, usage_ireadx},
  {"iwrite", test_do_iwrite, usage_iwrite},
  {"iwritev", test_do_iwritev, usage_iwritev},
  {"iwritex", test_do_iwritex, usage_iwritex},
  {"list", test_do_list, usage_list},
  {"lseek", test_do_lseek, usage_lseek},
  {"lstat", test_do_lstat, usage_lstat},
  {"mkdir", test_do_mkdir, usage_mkdir},
  {"mknod", test_do_mknod, usage_mknod},
  {"mount", test_do_mount, usage_mount},
  {"open", test_do_open, usage_open},
  {"printbuf", test_do_printbuf, usage_do_printbuf},
  {"printline", test_do_printline, usage_printline},
  {"pread", test_do_pread, usage_pread},
  {"preadv", test_do_preadv, usage_preadv},
  {"pwritev", test_do_pwritev, usage_pwritev},
  {"pwrite", test_do_pwrite, usage_pwrite},
  {"quit", test_do_exit, usage_exit},
  {"read", test_do_read, usage_read},
  {"readv", test_do_readv, usage_readv},
	{"readx", test_do_readx, usage_readx},
  {"rmdir", test_do_rmdir, usage_rmdir},
  {"setbuf", do_setbuf, usage_setbuf},
  {"sizeof", get_sizeof, usage_sizeof},
  /*  {"setoutput", test_do_setoutput, usage_setoutput}, */
  {"stat", test_do_stat, usage_stat},
  {"statvfs", test_do_statvfs, usage_statvfs},
  {"symlink", test_do_symlink, usage_symlink},
  {"truncate", test_do_truncate, usage_truncate},
  {"umask", test_do_umask, usage_umask},
  {"umount", test_do_umount, usage_umount},
  {"unlink", test_do_unlink, usage_unlink},
  {"write", test_do_write, usage_write},
  {"writev", test_do_writev, usage_writev},
  {"writex", test_do_writex, usage_writex},
  {NULL, NULL, NULL}
};

int run_cmd(cmd_tree *cmd_arg);
cmd_tree* build_tree(char **cmd, int *length, int total);
/*
 * ##################################################
 * # Memory functions                               #
 * #  Intended to allow users to gain access to     #
 * #  buffers of memory to be manipulated later     #
 * ##################################################
 */

void * alloc_buff32(unsigned int size, int align)
{
  void* buf;
  long buf_ptr;

  /*
  if ((err = memalign(&buf, align, size)) != 0) {
    perror("memalign");
    return 0;
  }
  */
  size += align;
  buf = malloc(size);
  align--;
  DBG(3, fprintf(outfp, "Buf is at %p\n", (void *)buf));
  buf_ptr = (long)buf + ((long)buf & align);

  DBG(3, fprintf(outfp, "Buf is at %p\n", (void *)buf_ptr));
  return (void *)buf_ptr;
}

void free_buf32(void * ptr)
{
  free(ptr);
}

long alloc_buff64(unsigned int size, int align)
{
  char * buf;
  long ret_value;

  /*  
      if (memalign((void **)&buf, align, size))
      return 0;
  */
  size += align;
  buf = malloc(size);
  align--;
  ret_value = (long)buf  + ((long)buf & align);
  return ret_value;
}

void free_buf64(long ptr)
{
  free((char *)ptr);
}

  
/* 
 * Hash function for variables. Shamelessly stolen
 * from the ext3 code
 */
unsigned int dx_hack_hash (const char *name, int len)
{
  unsigned int hash0 = 0x12a3fe2d, hash1 = 0x37abe8f9;
  while (len--)
    {
      unsigned int hash = hash1 + (hash0 ^ (*name++ * 7152373));
      if (hash & 0x80000000) hash -= 0x7fffffff;
      hash1 = hash0;
      hash0 = hash;
    }
  return hash0;
}

struct var_mapping *get_map(char *var_name)
{
  int index;
  struct var_mapping_list *curr;
  

 if (var_name[0] == '$') {
    /* It is a name--chop off the initial and get the mapping $ */
    var_name++;
  }
   
  index = dx_hack_hash(var_name, strlen(var_name));
  index %= MAX_VARS -1;

  DBG(5, fprintf(outfp, "Got index of %d for %s\n", index, var_name));
  curr = &map[index];
  
  while ((curr) && (curr->map.obj != -1) ) {
    if ( (curr->map.name == NULL) || (strcmp(curr->map.name, var_name)) )
      curr = curr->next;
    else
      return &curr->map;
  }

  return NULL;
}

char *get_str(char *var_name) 
{
  /* See if it is a quoted string */
  if (var_name[0] == '"') {
    /* Chop off the beginning and end quotes and return the string */
    int len = strlen(var_name);
    var_name[len-1] = '\0';
    var_name++;
  }

  return var_name;
}

static char* 
get_or_part(char **str, int* did_alloc)
{
	char *tmp_str = *str;
	int i, norm_str=0;

	if (tmp_str == NULL)
		return NULL;

	if (tmp_str[0] == '|') {
		tmp_str++;
		norm_str=1;
	}

	for (i=0; (unsigned int)i < strlen(tmp_str); i++) {
		if (tmp_str[i] == '|') {
			char *new_str = (char *)malloc(i+1);
			memcpy(new_str, tmp_str, i);
			new_str[i] = '\0';
			*did_alloc = 1;
			*str = &tmp_str[i];
			return new_str;
		}
	}

	if (norm_str) {
		*did_alloc = 0;
		*str = NULL;
		return tmp_str;
	} 

	return NULL;
}

int get_obj(char *var_name) 
{
	char** str = &var_name;
	char *str1;
  struct var_mapping *var_map;
  int did_alloc=0;
	int obj=0, got_obj=0;

  DBG(5, fprintf(outfp, "Getting object for %s\n", var_name));
  
  /* If var_name is a digit, we assume it is a literal */
  if (isdigit(var_name[0])) 
    return atoi(var_name); 
 
  /* 
   * Check for '|', indicates that one or more values are or'd
   * together
   */
	while ((str1 = get_or_part(str, &did_alloc)) != NULL) {

		if (isdigit(str1[0])) {
			if (str1[0] == '0') {
				/* Assume octal format */
				obj |= strtol(str1, NULL, 8);
			} else 
				obj |= atoi(str1);
		} else {
			var_map = get_map(str1);
			if (!var_map) {
				if (did_alloc)
					free(str1);
				return -1;
			}
			obj |= var_map->obj;
		}

		if (did_alloc) {
			did_alloc = 0;
			free(str1);
		}
		got_obj++;
	}

	if (got_obj)
		return obj;
 
  var_map = get_map(var_name);
  if (!var_map)
    return -1;
  else
    return var_map->obj;
}

     
void store_result(char *var_name, int result)
{
  int index = dx_hack_hash(var_name, strlen(var_name));
  struct var_mapping_list *map_obj;
  struct var_mapping_list *new_map;
  index %= MAX_VARS -1 ;

  if (map[index].map.obj >= 0) {

    /* Got a collision --just chain it*/ 
    new_map = malloc(sizeof(struct var_mapping_list));
		     
    map_obj = &map[index];
    while (map_obj->next != NULL)
      map_obj = map_obj->next;
    
    map_obj->next = new_map;
  } else
    new_map = &map[index];

  new_map->map.name = malloc(strlen(var_name) + 1);
  strcpy(new_map->map.name, var_name);
  new_map->map.obj = result;
  new_map->map.type = last_type;
  new_map->next = NULL;
  DBG(3, fprintf(outfp, "Stored %d in index %d hashed with %s\n",
		result, index, var_name));
}

void free_obj(char *obj_name)
{
  int index;
  struct var_mapping_list *prev, *curr;


  /* See if it is a variable name */
  if (obj_name[0] == '$') {
    /* It is a name--chop off the initial $ */
    obj_name++;
  }
  index = dx_hack_hash(obj_name, strlen(obj_name));
  index %= MAX_VARS -1;

  DBG(5, fprintf(outfp, "Got index of %d\n", index));
  curr = &map[index];

  prev = NULL;

  while ((curr) && (curr->map.obj != -1) ) {
    if (strcmp(curr->map.name, obj_name)) {
      prev = curr;
      curr = curr->next;
    } else
      break;
  }

  /* Remove the object from the chain */
  if (prev) 
    prev->next = curr->next;
  
  curr->map.obj = -1;
  free(curr->map.name);
  if (prev) 
    free(curr);
}


/*
 * Given a long string, returns the string divided into
 * whitespace seperated words in list.  Returns the number
 * of words
 */
int parser(char *str, char** list)
{
  int len, i=0, j=0, counter=-1;
  int in_quotes = 0;
  char *new_str;


  len = strlen(str);
  DBG(5, fprintf(outfp, "str is %s len is %d\n", str, len));
  while (i < len) {
   
    if ((i==0) || ((str[i] == ' ') && (in_quotes == 0)) ) {
      if (i != 0) {
	new_str[j] = '\0';
	DBG(5, fprintf(outfp, "Got word %s\n", list[counter]));
	i++;
      } 
      while ((str[i] == ' ') && (in_quotes == 0))
	i++;
      counter++;
      new_str = list[counter] = malloc(MAX_WORD);
      j = 0;
      
    }
    
    new_str[j] = str[i];
    if (str[i] == '"') {
      if (in_quotes)
	in_quotes = 0;
      else
	in_quotes = 1;
    }
    if ((str[i] == ' ') && (in_quotes==0)){
      while (str[i+1] == ' ')
				i++;
      new_str[j] = '\0';
    }
    i++;
    j++;

  }
  new_str[j] = '\0';
  DBG(5, fprintf(outfp, "Got word %s\n", list[counter]));
  return counter +1;
}


int execute_cmd(char *cmd, char **args, int arg_count)
{
  int i = 0;

  if (!strcmp(cmd, "help")) {
    if (arg_count > 0) {
			while(cmd_list[i].cmd != NULL) {
				if (!strcmp(cmd_list[i].cmd, args[0])) {
					(cmd_list[i].usage)();
					return 0;
				}
				i++;
      }
    } else {
      do_help();
      return 0;
    }
    return -1;
  } 
  while(cmd_list[i].cmd != NULL) {
    if (!strcmp(cmd_list[i].cmd, cmd)) {
      return (cmd_list[i].func)(arg_count, args);
		}
    i++;
  }
  DBG(2, fprintf(outfp, "Command %s was invalid\n", cmd));
  return INVALID_CMD;
}

int get_args(struct queue_t *child, char** list, int num_args, int argnum)
{
  char *argval;

  if (child->val != NULL) {
    argval = child->val;
  } else if (child->cmd != NULL) {
    run_cmd(child->cmd);
    if (child->cmd->res_name != NULL)
      argval = child->cmd->res_name;
    else {
      char tmpstr[50];
      int val = last_ret_val;
      sprintf(tmpstr, "%x", val);
      argval = tmpstr;
    }
  } else {
    DBG(2, fprintf(outfp, "I am confused\n"));
    return INVALID_ARGS;
  }
  
  list[argnum] = malloc(strlen(argval) + 1);
  strcpy(list[argnum], argval);
  argnum++;

  if (argnum == num_args)
    return SUCCESS;
  else if (child->next == NULL) {
    DBG(2, fprintf(outfp, "Only on arg number %d out of %d, but ran out of children\n",
		   argnum, num_args));
    return INVALID_ARGS;
  } else 
    return get_args(child->next, list, num_args, argnum);

  return SUCCESS;
}

int run_cmd(cmd_tree *cmd_arg)
{
  char cmdstr[MAX_COMMAND];
  char *cmdptr;
  char **args;
  int res, i;
  struct buf_t *buf;
  char *cmd;
  struct queue_t *child;

  if (cmd_arg == NULL)
    return INVALID_CMD;

  cmd = cmd_arg->val;
  cmdptr = cmdstr;
  child = cmd_arg->children;
  if ( (!strcmp("exit", cmd)) || (!strcmp("quit", cmd)) ||
       (!strcmp("EXIT", cmd)) || (!strcmp("QUIT", cmd)) )
    strcpy(cmdstr, "exit");
  else if (!strcmp("ALLOC", cmd)) 
    strcpy(cmdstr, "alloc");
  else if (!strcmp("FREE", cmd))
    strcpy(cmdstr, "free");
 else if (!strcmp("HELP", cmd))
    strcpy(cmdstr, "help");
  else if (!strcmp("CALL", cmd)) {
    if (cmd_arg->arg_count < 1) {
      DBG(2, fprintf(outfp, "Need at least one command\n"));
      return INVALID_CMD;
    }

    cmd_arg->arg_count--;
    if (child->val != NULL) 
      cmdptr = child->val;
    else {
      DBG(2, fprintf(outfp, "Need to specify command\n"));
      return INVALID_CMD;
    }

    DBG(3, fprintf(outfp, "Got cmd %s\n", child->val));
    if (cmd_arg->arg_count != 0)
      child = child->next;

   
  } else if (!strcmp("DEPOSIT", cmd))
    strcpy(cmdstr, "fill");
  else if (!strcmp("PRINT", cmd))
    strcpy(cmdstr, "printbuf");
  else {
    if (cmd_arg->res_name != NULL) {
      /* 
       * If the cmd is not a valid command, just store it
       */
      res = get_obj(cmd_arg->children->val);
      last_type = UINT;
      if (res < 0) {
				/* Just store it as a string */
				buf = (struct buf_t *)malloc(sizeof(struct buf_t));
				buf->len = strlen(cmd);
				buf->buf = (char *)malloc(buf->len+1);
				strcpy(buf->buf, cmd_arg->children->val);
				buflist[next] = buf;
				res = next;
				DBG(3, fprintf(outfp, "Stored %s in index %d\n", (char *)buf->buf, next));
				next++;
				last_type = STR;
      }
      store_result(cmd_arg->res_name, res);
      return SUCCESS;
    } else
      return INVALID_CMD;
  }


  if (cmd_arg->arg_count == 0)
    args = NULL;
  else {
    args = (char **)malloc(sizeof(char *)*cmd_arg->arg_count);
    get_args(child, args, cmd_arg->arg_count, 0);
  } 

  DBG(3, fprintf(outfp, "CMD: %s\n ARGS: ",cmdptr));
  for (i=0; i < cmd_arg->arg_count; i++)
    DBG(3, fprintf(outfp, "%s ", args[i]));
  DBG(3, fprintf(outfp, "\n"));
  res = execute_cmd(cmdptr, args, cmd_arg->arg_count);
  if (cmd_arg->res_name != NULL)
    store_result(cmd_arg->res_name, last_ret_val);

  return res;
} 


int is_command(char *name)
{
    if ( (strcmp(name, "CALL"))  && (strcmp(name, "FILL"))  &&
	 (strcmp(name, "ALLOC")) && (strcmp(name, "PRINT")) &&
	 (strcmp(name, "FREE"))  && (strcmp(name, "exit"))  && 
	 (strcmp(name, "HELP"))  && (strcmp(name, "help"))  && 
	 (strcmp(name, "quit"))  && (strcmp(name, "EXIT"))  &&
	 (strcmp(name, "QUIT"))  && (strcmp(name, "DEPOSIT")) )
	return 0;

    return 1;
}

#define ARGS 1
int get_type(char *arg0)
{
    if ((arg0[0] == '(') || (is_command(arg0)) ){
	return 2;
    }

    return ARGS;
}
		     
	
int add_args(char **cmd, int length, int total, cmd_tree *tree)
{
    int new_len, type;
    struct queue_t *old, *new;

    old = tree->children;
    while ((old) && (old->next))
	old = old->next;
    new = (struct queue_t *)malloc(sizeof(struct queue_t));
    if (old)
	old->next = new;
    else
	tree->children = new;
    new->next = NULL;

    type = get_type(cmd[0]);
    if (type < 0) {
	DBG(2, fprintf(outfp, "Don't understand %s\n", cmd[0]));
	return INVALID_CMD;
    }
    if (type == ARGS) {
	new->val = (char *)malloc(strlen(cmd[0])+1);
	strcpy(new->val, cmd[0]);
	new->cmd = NULL;
	total = 1;
    } else {
	new_len = length;
	if (cmd[0][0] == '(') {
	    new_len--;
	}

	new->val = NULL;
	new->cmd = build_tree(&cmd[1], &new_len, total);
	if (new->cmd == NULL) { /* Invalid command */
	  return length; /* Pretend we used everything up */
	}
	total = (length - new_len);
	DBG(4, fprintf(outfp, "Used %d bytes\n", total));
    }
 
    return total;
}

void free_tree(cmd_tree* tree) 
{
  if (!tree)
    return;

  if (tree->children) {
   struct queue_t *child = tree->children;
   struct queue_t *next;
   do {
     next = child->next;  
     if (child->cmd) 
       free_tree(child->cmd);
     free(child->val);
     free(child);
     child = next;
   } while (child);
 }

 if (tree->res_name)
   free(tree->res_name);

 if (tree->val)
   free(tree->val);

 free(tree);
}

cmd_tree* build_tree(char **cmd, int *length, int total)
{
    int index = 0, used_args = 0;
    cmd_tree *tree;
    if ((*length < 0) || (!cmd) || (*cmd == NULL)) 
			return NULL;

   
    DBG(4, fprintf(outfp, "length is %d\n", *length));
    tree = (cmd_tree *)malloc(sizeof(cmd_tree));
    tree->res_name = NULL;
    tree->children = NULL;
    if (cmd[index][0] == '$') {
			tree->res_name = (char *)malloc(strlen(cmd[index])+1);
			strcpy(tree->res_name, (char*)(cmd[index]+1));
			index++;
			if (cmd[index][0] == '=')
				index++;
    } else
      tree->res_name = NULL;

    if (is_command(cmd[index]) == 0) {
      if (tree->res_name == NULL) {
				DBG(2, fprintf(outfp, "command %s is invalid \n", cmd[index]));
        return NULL;
      }
    }

    tree->val = (char *)malloc(strlen(cmd[index])+1);
    strcpy(tree->val, cmd[index]);    
    index++;
    *length -= index;
    tree->arg_count = 0;

    if (*length == 0) {
			/* All done! */
			return tree;
    }
    
    /* Got to get the arguments */
    while (*length > 0) {

			if (cmd[index][0] == ')') {
				*length = *length-1;
				DBG(4, fprintf(outfp, "and now len is %d\n", *length));
				return tree;
			}
			
			used_args = add_args(&cmd[index], *length, total, tree);
			tree->arg_count++;
			*length -= used_args;
			index += used_args;
    }
	
    return tree;
}

char *line;
char *getline(char *prompt)
{
  int i=-1;
  int count=0;

  line = malloc(MAX_LINE);
  if ((do_prompt) && (infp == stdin)) 
    printf(prompt);

  do {
    /* If we get an end of file, just wait */
    if (feof(infp)) {
      while (feof(infp) && (line[i] != '\n')) {
				clearerr(infp);
				count++;
				fseek(infp, 0, SEEK_CUR);
      }
    } else {
      i++;
    }
    fread(&line[i], 1, 1, infp);
  } while(line[i] != '\n');

  line[i] = '\0';

  /*  fprintf(stderr, "Got word %s\n", line); */
  DBG(5, fprintf(outfp, "Got word %s\n", line));
  return line;
}

void my_perror(char *msg) 
{
  char *errmsg = strerror(errno);
  
  DBG(2, fprintf(outfp, "%s: %s\n", msg, errmsg));
}
  
/* Static list of flag names */
struct var_mapping flags_map[] = {
  {"O_RDONLY", O_RDONLY, UINT },
  {"O_WRONLY", O_WRONLY, UINT },
  {"O_RDWR", O_RDWR, UINT },
  {"O_CREAT", O_CREAT, UINT },
  {"O_EXCL", O_EXCL, UINT },
  {"O_NOCTTY", O_NOCTTY, UINT },
  {"O_TRUNC", O_TRUNC, UINT },
  {"O_APPEND", O_APPEND, UINT },
  {"O_SYNC", O_NONBLOCK, UINT },
  {"O_NDELAY", O_NDELAY, UINT },
  {"O_SYNC", O_SYNC, UINT },
  {"O_FSYNC", O_FSYNC, UINT },
  {"O_ASYNC", O_ASYNC, UINT },
  {"SEEK_SET", SEEK_SET, UINT },
  {"SEEK_CUR", SEEK_CUR, UINT },
  {"SEEK_END", SEEK_END, UINT },
  {"S_ISUID", S_ISUID, UINT },
  {"S_ISGID", S_ISGID, UINT },
  {"S_ISVTX", S_ISVTX, UINT },
  {"S_IRWXU", S_IRWXU, UINT },
  {"S_IRUSR", S_IRUSR, UINT },
  {"S_IREAD", S_IREAD, UINT },
  {"S_IWUSR", S_IWUSR, UINT },
  {"S_IWRITE", S_IWRITE, UINT },
  {"S_IXUSR", S_IXUSR, UINT },
  {"S_IEXEC", S_IEXEC, UINT },
  {"S_IRWXG", S_IRWXG, UINT },
  {"S_IRGRP", S_IRGRP, UINT },
  {"S_IWGRP", S_IWGRP, UINT },
  {"S_IXGRP", S_IXGRP, UINT },
  {"S_IRWXO", S_IRWXO, UINT },
  {"S_IROTH", S_IROTH, UINT },
  {"S_IWOTH", S_IWOTH, UINT },
  {"S_IXOTH", S_IXOTH, UINT },
  {"S_IFCHR", S_IFCHR, UINT },
  {"S_IFMT", S_IFMT, UINT },
  {"S_IFBLK", S_IFBLK, UINT },
  {"S_IFREG", S_IFREG, UINT },
  {"S_IFIFO", S_IFIFO, UINT },
  {"S_IFLNK", S_IFLNK, UINT },
  { NULL, -1, SINT }
};
 
void init_map()
{
  int index = 0;

  while (flags_map[index].obj != -1) {
    store_result(flags_map[index].name, flags_map[index].obj);
    index++;
  }
}

int getquotedlen(char *str)
{
	int i;
	
	if (str[0] != '"' && str[0] != '\'')
		return -1;
	
	for (i=1; str[i] != '\0' && str[i] != '"' && str[i] != '\''; i++);

	return i;
}

int perform_op(int num1, int num2, char op) 
{
	switch(op) {
		
	case '+':
		return num1 + num2;
		break;

	case '*':
		return num1 * num2;
		break;

	case '/':
		return num1 / num2;
		break;

	case '-':
		return num1 - num2;
		break;
		
	case '%':
		return num1%num2;
		break;
		
	default:
		return num1;
	}
	return 0;
}

int get_constant_val(char **str_ptr, int type)
{
	struct buf_t *buf;
	char *buf_ptr;
	char *str = *str_ptr;
	char ch;
	int i, j, num1, num2, size;

	printf("Getting constant val from %s\n", str);
	switch(type) {
	case 1:
		size = getquotedlen(str);
		buf = (struct buf_t *)malloc(sizeof(struct buf_t));
		buf->buf = alloc_buff32(size, 8);
		buf->len = size;
		buf_ptr = buf->buf;
		buflist[next] = buf;
		j=0;
		for (i=1; i < size; i++) {
			buf_ptr[j] = str[i];
			j++;
		}
		buf_ptr[j] = '\0';

		DBG(3, fprintf(outfp, "Your buffer (%p) (%p) is at index %d\n",
									 (void *)buf, buf->buf, next));
		next++;

		last_type = PTR;
		last_ret_val = next-1;
		return last_ret_val;
		break;

	case 2:
		if (str[0] == '$') {
			num1 = get_obj(str);
		} else {	
			num1 = atoi(str);
		}
		str = str_ptr[1];
		ch = str_ptr[1][0];
		if ((ch == '+') || (ch == '/') || (ch == '*') || 
				(ch == '-') || (ch == '%')) {
			if (str_ptr[2][0] == '$') 
				num2 = get_obj(str_ptr[2]);
			else
				num2 = atoi(str_ptr[2]);
			num1 = perform_op(num1, num2, ch);
		}

		last_type = UINT;
		last_ret_val = num1;

		break;

	default:
		DBG(2, fprintf(outfp, "Can't understand type of %d\n", type));
		return INVALID_ARGS;
	}

	return last_ret_val;
}

int is_constant(char *str) 
{
	if ((str[0] == '"') || (str[0] == '\''))
		return 1;

	
	if ( (str[0] == '$') || 
			 ( ((int)str[0] > 47) && ((int)str[0] < 57) ) ) 
		return 2;

	return 0;
}

int main(int argc, char *argv[])
{
  int count, err, i, orig_count;
  char *input, *name;
  char **cmd;
  cmd_tree *tree;
	extern int _test_sysio_startup(void);

  /*
   * Init sysio lib.
   */
  err = _test_sysio_startup();
  
  infp = stdin;
  outfp = stdout;

  do_prompt = 1;

  errno = 0;
  /* Get the input/output streams */
  for (i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--input")) {
      i++;
      infp = fopen(argv[i], "r");
      if (!infp) {
				fprintf(outfp, "Unable to open file %s for reading\n", argv[i]);
				return -1;
      }
    } else if (!strcmp(argv[i], "--output")) {
      i++;
      outfp = fopen(argv[i], "w");
      if (!outfp) {
				fprintf(stderr, "Unable to open file %s for writing\n", argv[i]);
				return -1;
      }
    } else if (!strcmp(argv[i], "--np")) {
      do_prompt = 0;
    } else {
      fprintf(stderr, "%s: Invalid arg\n", argv[i]);
      return -1;
    }
  }
  /* Initilize the mapping */
  for (i=0; i < MAX_VARS; i++)
    map[i].map.obj = -1;
  
  /* Debug defaults */
  debug_level = 1;
  print_line = 0;


#if 0
  /* sysio defaults */
  strcpy(root_driver, DEFAULT_DRIVER);
  strcpy(mntpath, "/");
  mntflgs = 0;
#endif

  my_errno = 0;

  /* Set up line buffering */
  setlinebuf(outfp);
  setlinebuf(infp);

  /* 
   * This sets up some common flags so that the string
   * names can be used (for instance 0_RDWR, SEEK_SET, etc
   */
  init_map();
  i=0;
  next = 0;
  while (1) {
    bzero(output, 4096);

    input = getline("> ");
    cmd = malloc(MAX_COMMAND * sizeof(char *));
    count = orig_count = parser(input, cmd);
    name = NULL;
    if ((!count) || (count > MAX_COMMAND)){
      fprintf(outfp, "%s: invalid command\n", input);
    } else {
      i = 0;
      if (cmd[0][0] == '$') {
				/* Need to store output of command in var name */
				name = cmd[0]+1;
				DBG(4, fprintf(outfp, "name is %s\n", name));
				count--;
				/* The '=' is not necessary, but available */
				if (!strcmp(cmd[1], "=")){
					i++;
					count--;
				}
				i++;
				if ((err=is_constant(cmd[i])) != 0) {
					store_result((char *)(&cmd[0][1]), get_constant_val(&cmd[i], err));
					tree = NULL;
					err = 0;
				} else {

					tree = build_tree(&cmd[i], &count, 0);
					if (tree != NULL) {
						err = run_cmd(tree);
						store_result((char *)(&cmd[0][1]), last_ret_val);
					}
				}
			} else {
				
				tree = build_tree(cmd, &count, 0);
				if (tree != NULL)
					err = run_cmd(tree);
      }
      /* Print out return code and any string from command */
      fprintf(outfp, "%#04x %s\n", err, output);
      if (tree)
				free_tree(tree);
      /* fprintf(stderr, "%#04x %s\n", err, output); */
      for (i=0; i < count; i++)
				free(cmd[i]);
    }
    free(cmd);
    free(line);
  }
}
