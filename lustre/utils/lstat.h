###################################################################
#Girish C
#lstat.h ver 0.1
#Displays information from lproc
##################################################################
#include <sys/types.h>
#include <sys/vfs.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

#define ARRAY_SIZE              ( 256 )
#define MAX_PATH_SIZE           ( 512 )

// File Type
#define DIRECTORY_TYPE          ( 1 )
#define FILE_TYPE               ( 0 )

#define ERR_READ_FROM_PROC_FILE ( -1 )
#define SUCCESS                 ( 0 )

// Defining the proc paths

#define OSD_PATH                ( "/proc/fs/lustre/osd" )
#define OST_PATH                ( "/proc/fs/lustre/ost" )
#define MDS_PATH                ( "/proc/fs/lustre/mds" )
#define CLIENT_PATH             ( "/proc/fs/lustre/llite" )
#define MDC_PATH                ( "/proc/fs/lustre/mdc" )
#define OSC_PATH                ( "/proc/fs/lustre/osc" )
#define LOV_PATH                ( "/proc/fs/lustre/lov" )
#define LDLM_PATH               ( "/proc/fs/lustre/ldlm" )

#define FILENAME_NUM_REF        ( "num_refs" )

/* function prototypes */
char	*GetFileList (char * dirname, int) ;
int 	IsDirectory (char * filename) ;
int 	GetFileCount (char * dirname, int);
int 	ReadFromProcFile(const char*, char*);
