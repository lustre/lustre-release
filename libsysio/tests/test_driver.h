/*
 * I feel like I should be putting a comment here...
 */
#include <sys/types.h>
#include "test.h"

/* Debugging stuff.. */
#define PRINT_LINE 0
int debug_level;
int print_line;

FILE *outfp; /* output file */
FILE *infp;

#define DBG(level, _x) \
 do { \
if (((level) <= (debug_level))) {  \
  if (print_line) \
   fprintf(outfp, "From file %s line %d: \n", __FILE__, __LINE__); \
			  (void)((_x)); \
} \
} while(0)  

/* Maximum size of a command or command argument */
#define MAX_WORD 150 

/* Maximum size of an input line */
#define MAX_LINE 300

/* Structure to hold commands in */
struct cmd_t {
  char *cmd;
  int (*func)(int, char **);
  void (*usage)();
};

extern struct cmd_t cmd_list[];

/* Maximum number of words in a command (command + command args) */
#define MAX_COMMAND 50

/* 
 * Holds list of allocated buffers.  To use a pre-allocated
 * buffer, the index number needs to be passed in.  This should
 * probably be smarter--perhaps a hash table could store the
 * list, with the hash being sent back to the user 
 */
#define MAX_BUFFERS 50
struct buf_t {
  void *buf;
  int len;
};

struct buf_t *buflist[MAX_BUFFERS];

int next; /* Next available buffer slot */


/* Defaults for libsysio */
char root_driver[75];
char mntpath[250];
unsigned int  mntflgs;



#define MAX_VARS 250

/* 
 * Valid types for fill buff and variables.
 */
#define UINT 0
#define SINT 1
#define STR  2
#define PTR  3
/* 
 * This defines a mapping from a variable name to
 * some object known by the test harness.  Variable
 * names are distinguished by '$'. Variables are used
 * in two possible ways: to capture the output of
 * a function, as in $my_fd = open name, or to gain
 * access to that variable, as in open $my_fd.  Variables
 * do not necessarily have to be initilized before use
 */
struct var_mapping {
  char *name; /* Variable name */
  int obj;  /* Object will always be an integer -- either a
	       file descriptor or an index into the buffer 
	       array 
	    */
  int type;
};

int last_type; 

struct var_mapping_list {
  struct var_mapping map;
  struct var_mapping_list *next;
};

/* 
 * Again, I am lazy and just use a static array
 * This should be dynamically remappable
 */
struct var_mapping_list map[MAX_VARS];
char output[4096];
int pos; /* Pos in output string */

struct cmd_map {
  char *cmd_name;
  int cmd;
  int num_args;
};

extern struct cmd_map fcntl_cmds[];

/* Return code information */
#define SUCCESS       0x000
#define INVALID_ARGS  0x001
#define INVALID_CMD   0x002
#define INVALID_VAR   0x004

int do_prompt; /* Prompt for interactive run? */
int last_ret_val; /* Last return value returned by libsysio call */
extern int errno;
int my_errno; /* Not sure what the difference will be */

/* Functions defined in test_driver.c */
extern unsigned int dx_hack_hash (const char *name, int len);
extern int get_obj(char *var_name);
extern void *alloc_buff32(unsigned int size, int align);
extern void store_result(char *var_name, int result);
extern struct var_mapping *get_map(char *var_name);
extern void free_obj(char *obj_name);
extern void my_perror(char *msg);
extern char *get_str(char *var_name); 
  
/* Stub functions defined in sysio_stubs.c */
extern int test_do_setdebug(int argc, char **argv);
extern int test_do_printline(int argc, char **argv);
extern int cmp_bufs(int argc, char **argv);
extern int test_do_printbuf(int argc, char **argv);
extern int test_do_fillbuff(int argc, char **argv);
extern int test_do_mount(int argc, char **args);
extern int test_do_list(int argc, char **args);
extern int test_do_init(int argc, char **args);
extern int get_endian(int argc, char **args);
extern int get_sizeof(int argc, char **args);
extern int do_setbuf(int argc, char **argv);
extern int test_do_exit(int argc, char **args);
extern int get_buffer(int argc, char **args);
extern int free_buffer(int argc, char **args);
extern int test_do_chdir(int argc, char **args);
extern int do_checkbuf(int argc, char **argv);
extern int test_do_chmod(int argc, char **args);
extern int test_do_chown(int argc, char **args);
extern int test_do_open(int argc, char **args);
extern int test_do_close(int argc, char **args);
extern int test_do_clear(int argc, char **argv);
extern int test_do_dup(int argc, char **args);
extern int test_do_dup2(int argc, char **args);
extern int test_do_fcntl(int argc, char **args);
extern int test_do_fstat(int argc, char **argv);
extern int test_do_fsync(int argc, char **argv);
extern int test_do_ftruncate(int argc, char **argv);
extern int test_do_getcwd(int argc, char **argv);
extern int test_do_init_iovec(int argc, char **argv);
extern int test_do_init_xtvec(int argc, char **argv);
extern int test_do_lseek(int argc, char **argv);
extern int test_do_lstat(int argc, char **argv);
extern int test_do_getdirentries(int argc, char **argv); 
extern int test_do_mkdir(int argc, char **argv);
extern int test_do_creat(int argc, char **argv);
extern int test_do_stat(int argc, char **argv);
extern int test_do_statvfs(int argc, char **argv);
extern int test_do_fstatvfs(int argc, char **argv);
extern int test_do_truncate(int argc, char **argv);
extern int test_do_rmdir(int argc, char **argv);
extern int test_do_symlink(int argc, char **argv);
extern int test_do_unlink(int argc, char **argv);
extern int test_do_fdatasync(int argc, char **argv);
extern int test_do_ioctl(int argc, char **argv);
extern int test_do_umask(int argc, char **argv);
extern int test_do_iodone(int argc, char **argv);
extern int test_do_iowait(int argc, char **argv);
extern int test_do_ipreadv(int argc, char **argv);
extern int test_do_ipread(int argc, char **argv);
extern int test_do_preadv(int argc, char **argv);
extern int test_do_pread(int argc, char **argv);
extern int test_do_ireadv(int argc, char **argv);
extern int test_do_ireadx(int argc, char **argv);
extern int test_do_iread(int argc, char **argv); 
extern int test_do_readv(int argc, char **argv);
extern int test_do_readx(int argc, char **argv);
extern int test_do_read(int argc, char **argv);
extern int test_do_ipwritev(int argc, char **argv);
extern int test_do_ipwrite(int argc, char **argv);
extern int test_do_pwritev(int argc, char **argv);
extern int test_do_pwrite(int argc, char **argv);
extern int test_do_iwritev(int argc, char **argv);
extern int test_do_iwrite(int argc, char **argv);
extern int test_do_iwritex(int argc, char **argv);
extern int test_do_writev(int argc, char **argv);
extern int test_do_writex(int argc, char **argv);
extern int test_do_write(int argc, char **argv);
extern int test_do_mknod(int argc, char **argv);
extern int test_do_umount(int argc, char **argv);


/* Functions defined in sysio_tests.c */
extern int sysio_mount(char *from, char *to);
extern int sysio_list(char *path);
extern int initilize_sysio(void);
extern int sysio_chdir(char *newdir);
extern int sysio_chmod(char *mode_arg, const char *path);
extern int sysio_chown(char *new_id, char *file);
extern int sysio_open(char *path, int flags);
extern int sysio_open3(char *path, int flags, char *mode_arg);
extern int sysio_close(int fd);
extern int sysio_fcntl(int fd, struct cmd_map* cmdptr, char *arg);
extern int sysio_fstat(int fd, void *buf);
extern int sysio_lstat(char *filename, void *buf);
extern int sysio_getdirentries(int fd, char *buf, size_t nbytes, off_t *basep);
extern int sysio_mkdir(char *path, char *mode); 
extern int sysio_creat(char *path, char *mode_arg);
extern int sysio_stat(char *filename, void *buf);
extern int sysio_statvfs(char *filename, void *buf);
extern int sysio_fstatvfs(int fd, void *buf);
extern int sysio_umask(char *mode_arg);
extern int sysio_mknod(char *path, char *mode_arg, dev_t dev);

/* Usage functions defined in help.c */
extern void do_help();
extern void usage_setdebug();
extern void usage_printline();
extern void usage_endian();
extern void usage_sizeof();
extern void usage_get_buffer();
extern void usage_free_buffer();
extern void usage_do_printbuf();
extern void usage_do_fillbuff();
extern void usage_init();
extern void usage_list();
extern void usage_chdir();
extern void usage_chmod();
extern void  usage_chown();
extern void usage_open();
extern void usage_close();
extern void usage_clear();
extern void usage_mount();
extern void usage_dup();
extern void usage_dup2();
extern void usage_fcntl();
extern void usage_fstat();
extern void usage_fsync();
extern void usage_ftruncate();
extern void usage_getcwd();
extern void usage_init_iovec();
extern void usage_init_xtvec();
extern void usage_lseek();
extern void usage_lstat();
extern void usage_getdirentries();
extern void usage_mkdir();
extern void usage_checkbuf();
extern void usage_cmpbufs();
extern void usage_creat();
extern void usage_setbuf();
extern void usage_stat();
extern void usage_statvfs();
extern void usage_fstatvfs();
extern void usage_truncate();
extern void usage_rmdir();
extern void usage_symlink();
extern void usage_unlink();
extern void usage_fdatasync();
extern void usage_ioctl();
extern void usage_umask();
extern void usage_iowait();
extern void usage_iodone();
extern void usage_ipreadv();
extern void usage_ipread();
extern void usage_preadv();
extern void usage_pread();
extern void usage_ireadv();
extern void usage_iread();
extern void usage_ireadx();
extern void usage_readv();
extern void usage_readx();
extern void usage_read();
extern void usage_ipwritev();
extern void usage_ipwrite();
extern void usage_pwritev();
extern void usage_pwrite();
extern void usage_iwritev();
extern void usage_iwrite();
extern void usage_iwritex();
extern void usage_writev();
extern void usage_write();
extern void usage_writex();
extern void usage_mknod();
extern void usage_umount();
extern void usage_exit();
