###################################################################
#Girish C
#lstat.c ver 0.1
#Displays information from lproc
##################################################################
#include "lstat.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <string.h>
#include <errno.h>

/*********************************************************************
 * Function: 	GetFileList
 *
 * Description: For the given valid directory  path, returns the list 
 * 		all directories or files in that path.
 *	
 * Input:	'dirname' the directory path.
 *		'file_type' if this takes the value DIRECTORY_TYPE
 *		returns the list of directories in that path.
 *		If its of type FILE_TYPE returns the list of files
 *		in that path.
 * 
 * Output:	List of  directories/files in that path. 
 *
 *********************************************************************/

char *GetFileList(char *dirname, int file_type)
{
	DIR * pdir;
	struct dirent * pdirent;
	int curr_offset = 0;
	int byte_count = 0;
	int line_count = 0;
	char * retstr = NULL;
	char * filename = NULL;  
 
	if( (dirname == NULL) || ((pdir = opendir(dirname)) == NULL )) {
		if(dirname == NULL){
			fprintf(stderr,"GetFileList(): NULL directory is passed as parameter to funtion\n");
		}else 
			fprintf(stderr,"GetFileList(): Unable to open the directory %s\n", dirname);
  	return NULL;
  	}
 
	while(1)
  	{
		if( (pdirent = readdir(pdir)) == NULL) 
			break;
		if((pdirent->d_name[0] == '.') || !strcmp( pdirent->d_name, FILENAME_NUM_REF) ) 
			continue ;
		byte_count = byte_count + strlen(pdirent->d_name) + 1;
     		line_count++;
  	}

	if(line_count) {
  		retstr = (char *) malloc(byte_count+1);
 	 	if( retstr == NULL ) {
			closedir(pdir);  
			return NULL;
  		}
		rewinddir(pdir);

		while(line_count != 0)
		{
			if( (pdirent = readdir(pdir)) == NULL) 
				break;
			if((pdirent->d_name[0] == '.') || !strcmp( pdirent->d_name, FILENAME_NUM_REF) ) 
				continue ;
			filename = (char*) malloc(strlen(dirname)+strlen(pdirent->d_name)+2);

			if(filename == NULL) {
				closedir(pdir);
		 		return NULL;
			}
			sprintf(filename,"%s/%s",dirname,pdirent->d_name );
			if((file_type == FILE_TYPE ) && IsDirectory(filename))  
				continue ;
			if((file_type == DIRECTORY_TYPE ) && (!IsDirectory(filename))) 
				continue;
			if ( filename )
				free(filename);
			strcpy(retstr+curr_offset,pdirent->d_name);
			curr_offset = curr_offset + strlen(pdirent->d_name) + 1;
			line_count--;

  		}
  		retstr[byte_count] = '\0';
  	}
  	closedir(pdir);
  	return retstr;
}

/*********************************************************************
 * Function:    IsDirectory	
 *
 * Description: Checks if given filename is a directory or not.
 * 		all directories or files in that path.
 *	
 * Input:	'filename' the directory path to be checked.
 * 
 * Output:	Returns 1 if its a directory else 0.
 *
 *********************************************************************/

int IsDirectory(char * filename)
{
	struct stat statf;
	int result;
    
	result = stat(filename, &statf);
   	if((result == SUCCESS) && (statf.st_mode &  S_IFDIR ))
        	return 1;
   	return 0;
}


/*********************************************************************
 * Function: 	GetFileCount
 *
 * Description: For the given valid directory  path, returns the number 
 * 		directories or files in that path.
 *	
 * Input:	'dirname' the directory path.
 *		'file_type' if this takes the value DIRECTORY_TYPE
 *		returns the count of directories in that path.
 *		If its of type FILE_TYPE returns the count of files
 *		in that path.
 * 
 * Output:	Total number of files/directories in that path. 
 *
 *********************************************************************/

int GetFileCount(char * dirname, int file_type)
{
	DIR * pdir;
	struct dirent * pdirent;
	int file_count = 0;
	char * filename = NULL; 
	
	if ( (pdir = opendir(dirname)) == NULL) {
		fprintf(stderr,"GetFileCount(): %s Unable to open.\n",dirname);
		return 0;
	}
	while(1)
  	{
		if( (pdirent = readdir(pdir)) == NULL) 
			break;
		if( (pdirent->d_name[0] == '.') || !strcmp( pdirent->d_name, FILENAME_NUM_REF) )  
			continue ;
		filename = (char*) malloc(strlen(dirname)+strlen(pdirent->d_name)+2);
     		sprintf(filename, "%s/%s", dirname, pdirent->d_name );
     		if((file_type == FILE_TYPE) && !(IsDirectory(filename)))
		        file_count++;
		else
			if( (file_type == DIRECTORY_TYPE ) && IsDirectory(filename) )
        			file_count++;
  	}
	closedir (pdir);
	return file_count;
}

/*********************************************************************
 * Function: 	ReadFromProcFile
 *
 * Description: For the given valid file path, returns the data in
 * 		that file.
 *	
 * Input:	'filepath' the file whose data is to be accessed.
 *		'lustre_val' the data from the file is written into  
 *		this variable, accesed by the requestor.
 * 
 * Output:	Returns SUCCESS if file access was a success else 
 *		ERR_READ_FROM_PROC_FILE if file does not exist or if
 *		data is invalid in given path. 
 *
 *********************************************************************/

int  ReadFromProcFile ( const char* filepath, char* lustre_var)
{
	FILE* fptr = NULL;
	int ret_val = SUCCESS;
	int len = 0;

	if ( (filepath == NULL) || (lustre_var == NULL)) {
		fprintf(stderr, "ReadFromProcFile(): one or both of the i/p param is null\n");
		ret_val = ERR_READ_FROM_PROC_FILE;
	}
	else {
		fptr = fopen (filepath, "r");
		if (fptr == NULL) {
			fprintf(stderr, "ReadFromProcFile(): %s Unable to open the file\n", filepath);
			ret_val = ERR_READ_FROM_PROC_FILE;
		}
		else {
			if (fgets (lustre_var,ARRAY_SIZE, fptr) == NULL) {  
				/* fgets includes '\n' also in the returned string */
				fprintf (stderr, "ReadFromProcFile(): Error reading file %s \n",filepath);
				ret_val = ERR_READ_FROM_PROC_FILE;
			}else {
				len = strlen (lustre_var);
				/* Last char is EOF,before string ends, so '\0' is moved to last but one.*/
				lustre_var[len-1] = lustre_var[len];
			}
			fclose (fptr);
		}
	}
	return ret_val; 
}

int parse_dir_info(char *dirpath)
{
	char *dir_list = NULL, *tmp_list;	
	int current_dptr = 0, tmp_ptr = 0, dcount, dindex, tcount, tindex, rc;
	char name[ARRAY_SIZE], tname[ARRAY_SIZE];	

	if(!IsDirectory(dirpath))
		return -1;

	 /* Obtain the number of instances */
        if ( (dcount = GetFileCount (dirpath, DIRECTORY_TYPE)) == 0)
                return dcount;
//	printf("\n dcount is %d", dcount);
	
//	printf("\n%s", dirpath);
	if ( (dir_list = GetFileList(dirpath, DIRECTORY_TYPE)) == '\0')
                return -1;
	
	for ( dindex = 0; dindex < dcount; dindex++) {
		sprintf(name, "%s/%s", dirpath, dir_list + current_dptr);
		printf("\n>> %s >>\n", dir_list + current_dptr);
		
		if ( (tcount = GetFileCount (name, DIRECTORY_TYPE)) == 0) {
			if(!(rc = parse_file_info(name)))
        	                continue;
		} else {
			rc = parse_file_info(name);
			if ( (tmp_list = GetFileList(name, DIRECTORY_TYPE)) == '\0') 
				break;
//			printf("\n %s", name);
	
			for ( tindex = 0; tindex < tcount; tindex++) {
				printf("\n\t>>>> %s>>>>\n", tmp_list + tmp_ptr);
				sprintf(tname, "%s/%s", name, tmp_list + tmp_ptr);
//	                	printf("\n tname is %s", tname);
			
				tmp_ptr += strlen (tmp_list + tmp_ptr) + 1;
				if((rc = parse_file_info(tname)) == -1)
					break;
			}	
			current_dptr += strlen (dir_list + current_dptr) + 1;
		}
	}

	return rc;
}

int parse_file_info(char * node_path)
{
	char file_path [MAX_PATH_SIZE];
	char name[ARRAY_SIZE], fname[ARRAY_SIZE];
        char file_data [ARRAY_SIZE];
        char *file_list = NULL;
	int  fcount, findex;
	int  current_fptr = 0;
	char data[ARRAY_SIZE];

        memset (file_path, '\0', MAX_PATH_SIZE );
        memset (file_data, '\0', ARRAY_SIZE );
	
//	printf(" \n PFI node_path %s ", node_path);

	/* Obtain the number of instances */
	if ( (fcount = GetFileCount (node_path, FILE_TYPE)) == 0)
	        return fcount;

//	printf("\n PFI  Number of PFILES %d", fcount);

	if ( (file_list = GetFileList(node_path, FILE_TYPE)) == '\0')
	       	return -1;

	for ( findex = 0; findex < fcount; findex++) {
	        printf("\n[%s", file_list + current_fptr);
                sprintf(fname, "%s/%s", node_path, file_list + current_fptr);
		
                if (ReadFromProcFile (fname, data) == ERR_READ_FROM_PROC_FILE) {
        	        fprintf(stderr, "File read error %s for fname not found\n", file_path);
                	return -1;
                }
                printf(" -> \t%s]", data);

                current_fptr += strlen (file_list + current_fptr) + 1;
        }
	free (file_list);
	file_list = NULL;		
	return 0;
}

main()
{
	int rc = -1;

	printf("\n/********* CLIENT info ******/\n");
       	if (rc = parse_dir_info(CLIENT_PATH)) 
	       	printf("\n Client doesn't exist");
	printf("\n/********* MDC info *********/\n");
	if (rc = parse_dir_info(MDC_PATH))
		printf("\n MDC doesn't exist");

	printf("\n/********* OSC info *********/\n");
        if (rc = parse_dir_info(OSC_PATH))
		 printf("\n OSC doesn't exist");

	printf("\n/********* LOV info *********/\n");
        if (rc = parse_dir_info(LOV_PATH) == -1)
		printf("\n LOV doesn't exist");        
	
	printf("\n/********* LDLM info ********/\n");
        if (rc = parse_dir_info(LDLM_PATH))
		 printf("\n LDLM doesn't exist");
	
	printf("\n/********* OSD info *********/\n");
	if(rc = parse_dir_info(OSD_PATH))
		printf("\n OSD doesn't exist");
	printf("\n/********* OST info *********/\n");
        if(rc = parse_dir_info(OST_PATH))
		printf("\n OST doesn't exist");
	printf("\n/********* MDS info *********/\n");
	if (rc = parse_dir_info(MDS_PATH))
		printf("\n MDS doesn't exist");	

	return 0;
}
