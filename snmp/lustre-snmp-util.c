/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * snmp/lustre-snmp-util.c
 *
 * Author: PJ Kirner <pjkirner@clusterfs.com>
 */

/*
 *   include important headers
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

/*
 *  include our .h file
 */ 

#include <sys/types.h>
#include <sys/vfs.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "lustre-snmp-util.h"

/*********************************************************************
 * Function:    get_file_list
 *
 * Description: For the given valid directory  path, returns the list
 *              all directories or files in that path.
 *
 * Input:   'dirname' the directory path.
 *          'file_type' if this takes the value DIR_TYPE then
 *              returns the list of directories in that path.
 *          If its of type FILE_TYPE then returns the list of files
 *          in that path.
 *          'count' pointer to number of elements returned in the
 *          return string. 
 *
 * Output:  List of  directories/files in that path.
 *
 *********************************************************************/

char *get_file_list(const char *dirname, int file_type, uint32_t *count)
{

    DIR           *pdir = NULL;
    struct dirent *pdirent = NULL;
    int           curr_offset = 0;
    int           byte_count = 0;
    int           file_count = 0;
    char          *ret_str = NULL;
    char          filename[MAX_PATH_SIZE];
    int           cond1, cond2;

    if ((dirname == NULL) || ((pdir = opendir(dirname)) == NULL )) {
        if (dirname == NULL) {
            report("%s %s:line %d %s", __FILE__, __FUNCTION__, __LINE__,
                   "NULL directory is passed as parameter to funtion");
        } else {
            report("%s %s:line %d Error in opening the dir %s", __FILE__,
                   __FUNCTION__, __LINE__, dirname);
        }
        if (count)
            *count = 0;
        return NULL;
    }

    while (1) {
        if ((pdirent = readdir(pdir)) == NULL)
            break;

        /* Skip over '.' and '..' directores */
        if ((pdirent->d_name[0] == '.') ||
            !strcmp(pdirent->d_name, FILENAME_NUM_REF))
            continue;
        
        sprintf(filename, "%s/%s", dirname, pdirent->d_name);
        cond1 = (file_type == FILE_TYPE) && is_directory(filename);
        cond2 = (file_type == DIR_TYPE) && (!is_directory(filename));

        if (cond1 || cond2)
            continue;

        /* Calculate the number of bytes for this new entry.*/                    
        byte_count += strlen(pdirent->d_name) + 1;
        file_count++;
    }
    if (count)
        *count = file_count;
    
    if (file_count != 0) {
        
        /* need one extra one for the finall NULL terminator*/
        if ((ret_str = (char *) malloc(byte_count + 1)) == NULL) {
            report("get_file_list() failed to malloc(%d)",byte_count+1);
            closedir(pdir);
            return NULL;
        }    
        
        rewinddir(pdir);
        
        while (file_count != 0) {
            if ((pdirent = readdir(pdir)) == NULL)
                break;

            if ((pdirent->d_name[0] == '.') ||
                !strcmp(pdirent->d_name, FILENAME_NUM_REF))
                continue;
            
            sprintf(filename, "%s/%s", dirname, pdirent->d_name);
            cond1 = (file_type == FILE_TYPE) && is_directory(filename);
            cond2 = (file_type == DIR_TYPE) && (!is_directory(filename));

            if (cond1 || cond2)
                continue;

            strcpy(ret_str + curr_offset, pdirent->d_name);
            curr_offset = curr_offset + strlen(pdirent->d_name) + 1;
            file_count--;
        }
        /* Put in the finall null terminator*/
        ret_str[byte_count] = '\0';
    }
    closedir(pdir);
    return ret_str;
}


/*********************************************************************
 * Function:    is_directory
 *
 * Description: Checks if given filename is a directory or not.
 *              all directories or files in that path.
 *
 * Input:   'filename' the directory path to be checked.
 *
 * Output:  Returns 1 if its a directory else 0.
 *
 *********************************************************************/

int is_directory(const char *filename)
{

    struct stat statf;
    int result;

    result = stat(filename, &statf);
    return ((result == SUCCESS) && (statf.st_mode & S_IFDIR));
}

/*********************************************************************
 * Function:    read_string
 *
 * Description: For the given valid file path, reads the data in
 *              that file.
 *
 * Input:   'filepath' the file whose data is to be accessed.
 *          'lustre_var' the data from the file is read into
 *           this variable, returned to the requestor.
 *          'var_max_size' the max size of the string
 *          'report_error' boolean if error should be reported on 
 *           missing filepath
 *
 * Output:  Returns SUCCESS if read successfully from file else
 *          returns ERROR.
 *********************************************************************/
 
int  read_string(const char *filepath, char *lustre_var, size_t var_max_size)
{
    FILE    *fptr = NULL;
    int     len = 0;
    int     ret_val = SUCCESS;
    int     report_error = 1;

    if ((filepath == NULL) || (lustre_var == NULL)) {
        report("%s %s:line %d %s", __FILE__, __FUNCTION__, __LINE__,
               "Input parameter is NULL");
        ret_val = ERROR;
    } else {
        fptr = fopen(filepath, "r");

        if (fptr == NULL) {
            if(report_error)
                report("%s %s:line %d Unable to open the file %s", __FILE__,
                       __FUNCTION__, __LINE__, filepath);
            ret_val = ERROR;
        } else {
            if (fgets(lustre_var, var_max_size, fptr) == NULL) {
                report("%s %s:line %d read failed for file %s", __FILE__,
                       __FUNCTION__, __LINE__, filepath);
                 ret_val = ERROR;
            } else {
                len = strlen(lustre_var);
                /*
                    Last char is EOF, before string ends,
                    so '\0' is moved to last but one.
                */
                lustre_var[len-1] = lustre_var[len];
            }
            fclose(fptr);
        }
    }
    return ret_val;
}

/**************************************************************************
 * Function:   lustrefs_ctrl
 *
 * Description: Execute /etc/init.d/lustre script for starting,
 *              stopping and restarting Lustre services in child process.
 *
 * Input:  Start/Stop/Restart Command Number.
 * Output: Returns  void
 *
 **************************************************************************/

void lustrefs_ctrl(int command)
{
    char *cmd[3];

    cmd[0] = LUSTRE_SERVICE;
    switch (command) {
    case ONLINE:
        cmd[1] = "start";
        break;
    case OFFLINE:
        cmd[1] = "stop";
        break;
    case RESTART:
        cmd[1] = "restart";
        break;
    default:
        return;
    }

    cmd[2] = (char *)0;

    if (fork() == 0) {
        execvp(cmd[0], cmd);
        report("failed to execvp(\'%s %s\')",cmd[0],cmd[1]);
    }
}

/*****************************************************************************
 * Function:     get_sysstatus
 *
 * Description:  Read /var/lustre/sysStatus file, and based on file contents
 *               return the status of Lustre services.
 *
 * Input:   void
 * Output:  Return ONLINE/OFFLINE/ONLINE PENDING/OFFLINE PENDING status
 *          values.
 *
 ****************************************************************************/

int get_sysstatus(void)
{
    int     ret_val = ERROR ;
    char    sys_status[50] = {0};
    
    if(SUCCESS == read_string(FILENAME_SYS_STATUS,sys_status,sizeof(sys_status)))
    {
        if (memcmp(sys_status, STR_ONLINE_PENDING,strlen(STR_ONLINE_PENDING)) == 0)
            ret_val = ONLINE_PENDING;
        else if (memcmp(sys_status, STR_ONLINE, strlen(STR_ONLINE)) == 0)
            ret_val = ONLINE;
        else if (memcmp(sys_status, STR_OFFLINE_PENDING,strlen(STR_OFFLINE_PENDING)) == 0)
            ret_val = OFFLINE_PENDING;
        else if (memcmp(sys_status, STR_OFFLINE, strlen(STR_OFFLINE)) == 0)
            ret_val = OFFLINE;
        else
            report("%s %s:line %d Bad Contents in file %s \'%s\'", __FILE__,
                __FUNCTION__, __LINE__, FILENAME_SYS_STATUS,sys_status);
    }
    return ret_val;
}


/*****************************************************************************
 * Function:     read_ulong
 *
 * Description:  Read long values from lproc and copy to the location
 *               pointed by input parameter.
 *
 * Input:   file path, and pointer for data to be copied
 *
 * Output:  Return ERROR or SUCCESS.
 *
 ****************************************************************************/

int read_ulong(const char *file_path, unsigned long *valuep)
{
    char    file_data[MAX_LINE_SIZE];
    int     ret_val;

    if ((ret_val = read_string(file_path, file_data,sizeof(file_data))) == SUCCESS){
        *valuep = strtoul(file_data,NULL,10);
    }
    return ret_val;
}

/*****************************************************************************
 * Function:     read_counter64
 *
 * Description:  Read counter64 values from lproc and copy to the location
 *               pointed by input parameter.
 *
 * Input:   file path, and pointer for data to be copied
 *
 * Output:  Return ERROR or SUCCESS.
 *
 ****************************************************************************/

int read_counter64(const char *file_path, counter64 *c64,int factor)
{
    char    file_data[MAX_LINE_SIZE];
    int     ret_val;
    unsigned long long tmp = 0;

    if ((ret_val = read_string(file_path, file_data,sizeof(file_data))) == SUCCESS) {
        tmp = atoll(file_data) * factor;
        c64->low = (unsigned long) (0x0FFFFFFFF & tmp);
        tmp >>= 32; /* Shift right by 4 bytes */
        c64->high = (unsigned long) (0x0FFFFFFFF & tmp);
    }
    return ret_val;
}

/*****************************************************************************
 * Function:     get_nth_entry_from_list
 *
 * Description:  Find the n'th entry from a null terminated list of string
 *
 * Input:   dir_list - the list
 *          num - the number of elements in the list
 *          index - the index we are looking for
 *
 * Output:  Return NULL on failure, or the string name on success.
 *
 ****************************************************************************/

const char *get_nth_entry_from_list(const char* dir_list,int num,int index)
{
    int i;
    int cur_ptr = 0;
    for(i=0;i<num;i++){
        
        /* 
         * if we've reached the end of the list for some reason
         * because num was wrong then stop processing
         */
        if( *(dir_list+cur_ptr) == 0)
            break;
            
        /* If we've found the right one */    
        if( i == index )
            return dir_list+cur_ptr;
            
        /* Move to the next one*/            
        cur_ptr += strlen(dir_list + cur_ptr)+1;
    }
    return NULL;
}

/*****************************************************************************
 * Function:    report
 *
 * Description: This function used to report error msg to stderr and log into
 *    log file(default file:/var/log/snmpd.log) when agent is started with
 *    debug option -Dlsnmpd
 * Input:   format string and variable arguments.
 * Output:  void
 ****************************************************************************/

void report(const char *fmt, ...)
{
    char buf[1024];

    va_list arg_list;
    va_start(arg_list, fmt);
    vsprintf(buf, fmt, arg_list);
    va_end(arg_list);

    DEBUGMSGTL(("lsnmpd", "%s\n", buf));
    fprintf(stderr, "%s\n", buf);
}



/**************************************************************************
 * Function:   oid_table_ulong_handler
 *
 * Description: Fetch a unsigned long from the given location.
 *              Setup var_len, and return a pointer to the data.
 *
 * Input:  file_path, and var_len pointer
 *
 * Output: NULL on failure, or pointer to data
 *
 **************************************************************************/

unsigned char* 
    oid_table_ulong_handler(
        const char* file_path,
        size_t  *var_len)
{
    static unsigned long ulong_ret;
    if (SUCCESS != read_ulong(file_path,&ulong_ret))
        return NULL;
    *var_len = sizeof(ulong_ret);
    return  (unsigned char *) &ulong_ret;
}

/**************************************************************************
 * Function:   oid_table_c64_handler
 *
 * Description: Fetch a counter64 from the given location.
 *              Setup var_len, and return a pointer to the data.
 *
 * Input:  file_path, and var_len pointer
 *
 * Output: NULL on failure, or pointer to data
 *
 **************************************************************************/

unsigned char* oid_table_c64_handler(const char* file_path,size_t  *var_len)
{
    static counter64 c64;
    if (SUCCESS != read_counter64(file_path,&c64,1))
        return NULL;
    *var_len = sizeof(c64);
    return (unsigned char *) &c64;
}

/**************************************************************************
 * Function:   oid_table_c64_kb_handler
 *
 * Description: Fetch a counter64 from the given location.
 *              Setup var_len, and return a pointer to the data.
 *              Different than oid_table_c64_handler in that
 *              the original value is multiplied by 1024 before converting
 *              to a counter64.  (e.g. turn KB into a Byte scaled value)
 *
 * Input:  file_path, and var_len pointer
 *
 * Output: NULL on failure, or pointer to data
 *
 **************************************************************************/

unsigned char* oid_table_c64_kb_handler(const char* file_path,size_t  *var_len)
{
    static counter64 c64;
    /* scale by factor of 1024*/
    if (SUCCESS != read_counter64(file_path,&c64,1024))
        return NULL;
    *var_len = sizeof(c64);
    return (unsigned char *) &c64;
}

/**************************************************************************
 * Function:   oid_table_obj_name_handler
 *
 * Description: Just copy the file_path and return as the output value.
 *
 * Input:  file_path, and var_len pointer
 *
 * Output: NULL on failure, or pointer to data
 *
 **************************************************************************/

unsigned char* 
    oid_table_obj_name_handler(
        const char* file_path,
        size_t  *var_len)
{
    static unsigned char string[SPRINT_MAX_LEN];
    *var_len = strlen(file_path);
    *var_len = MIN_LEN(*var_len, sizeof(string));
    memcpy(string, file_path, *var_len);
    return (unsigned char *) string;
}

/**************************************************************************
 * Function:   oid_table_string_handler
 *
 * Description: Fetch a string from the given location.
 *              Setup var_len, and return a pointer to the data.
 *
 * Input:  file_path, and var_len pointer
 *
 * Output: NULL on failure, or pointer to data
 *
 **************************************************************************/

unsigned char* 
    oid_table_string_handler(
        const char* file_path,
        size_t  *var_len)
{
    static unsigned char string[SPRINT_MAX_LEN];
    if( SUCCESS != read_string(file_path, (char *)string,sizeof(string)))
        return NULL;
    *var_len = strlen((char *)string);
    return (unsigned char *) string;
}


/**************************************************************************
 * Function:   oid_table_is_directory_handler
 *
 * Description: Determine if the file_path is a directory.  
 *              Setup a boolean return value.
 *              Setup var_len, and return a pointer to the data.
 *
 * Input:  file_path, and var_len pointer
 *
 * Output: NULL on failure, or pointer to data
 *
 **************************************************************************/

unsigned char* 
    oid_table_is_directory_handler(
        const char* file_path,
        size_t *var_len)
{
    static long long_ret;
    long_ret =  is_directory(file_path);
    *var_len = sizeof(long_ret);
    return (unsigned char *) &long_ret;
}

/**************************************************************************
 * Function:   var_genericTable
 *
 * Description: Handle Table driven OID processing
 *
 **************************************************************************/

unsigned char *
var_genericTable(struct variable *vp,
    	    oid     *name,
    	    size_t  *length,
    	    int     exact,
    	    size_t  *var_len,
    	    WriteMethod **write_method,
            const char *path,
            struct oid_table *ptable)
{
    char *dir_list;
    uint32_t num;
    int  deviceindex;
    unsigned char *ret_val = NULL;
    int i=0;
    const char* obj_name;
    
    
    /*
     * Get the list of file.  If there are no elements
     * return nothing
     */
    if( 0 == (dir_list = get_file_list(path, DIR_TYPE, &num)))
        return NULL;

    /*
     * Setup the table
     */
    if (header_simple_table(vp,name,length,exact,var_len,write_method, num)
                                                == MATCH_FAILED )
        goto cleanup_and_exit;

    /*
     * The number of the device we're looking at
     */
    deviceindex = name[*length - 1] - 1;

    /*
     * If we couldn't find this element
     * something must have recently changed return
     * nothing
     */
    if(deviceindex >= num){
        report("deviceindex=%d exceeds number of elements=%d",deviceindex,num);
        goto cleanup_and_exit;
    }

    /*
     * Fetch the object name from the list
     */
    obj_name = get_nth_entry_from_list(dir_list,num,deviceindex);
    if(obj_name == NULL){
        /*
         * Note this should never really happen because we check deviceindex >=num
         * above.  And dir_list should be consitent with num
         * but just in case...
         */
        report("object name not found in list",deviceindex,num);
        goto cleanup_and_exit;
    }

    /*
     * Find the matching magic - or the end of the list
     */
    while(ptable[i].magic != vp->magic && ptable[i].magic != 0)
        i++;

    /*
     * If we didn't find a matching entry return
     */
    if(ptable[i].magic==0)
        goto cleanup_and_exit;

    /*
     * If the name is NULL is a special case and 
     * just just pass the obj_name as the file_path
     * otherwise we create a file path from the given components
     */
    if(ptable[i].name != 0){
        char file_path[MAX_PATH_SIZE];
        sprintf(file_path, "%s%s/%s",path,obj_name,ptable[i].name);
        ret_val =  ptable[i].fhandler(file_path,var_len);
    }
    else
        ret_val =  ptable[i].fhandler(obj_name,var_len);

cleanup_and_exit:
    free(dir_list);
    return ret_val;
};

/**************************************************************************
 * Function:   stats_values
 *
 * Description: Setup nb_sample, min, max, sum and sum_square stats values
                for name_value from filepath.
 *
 * Input:  filepath, name_value,
 *         pointer to nb_sample, min, max, sum, sum_square
 *
 * Output: SUCCESS or ERROR on failure
 *
 **************************************************************************/
int stats_values(char * filepath,char * name_value, unsigned long long * nb_sample, unsigned long long * min, unsigned long long * max, unsigned long long * sum, unsigned long long * sum_square)
{
  FILE * statfile;
  char line[MAX_LINE_SIZE];
  int nbReadValues = 0;

  if( (statfile=fopen(filepath,"r")) == NULL) {
    report("stats_value() failed to open %s",filepath);
    return ERROR;
  }
/*find the good line for name_value*/
  do {
    if( fgets(line,MAX_LINE_SIZE,statfile) == NULL ) {
      report("stats_values() failed to find %s values in %s stat_file",name_value,statfile);
      goto error_out;
    }
  } while ( strstr(line,name_value) == NULL );
/*get stats*/
  if((nbReadValues=sscanf(line,"%*s %llu %*s %*s %llu %llu %llu %llu",nb_sample,min,max,sum,sum_square)) == 5) {
    goto success_out;
  } else if( nbReadValues == 1 && *nb_sample == 0) {
    *min = *max = *sum = *sum_square = 0;
    goto success_out;
  } else {
    report("stats_values() failed to read stats_values for %s value in %s stat_file",name_value,statfile);
    goto error_out;
  }

success_out :
  fclose(statfile);
  return SUCCESS;
error_out :
  fclose(statfile);
  return ERROR;
}

/**************************************************************************
 * Function:   mds_stats_values
 *
 * Description: Setup nb_sample, min, max, sum and sum_square stats values
                for mds stats name_value .
 *
 * Input:  name_value,
 *         pointer to nb_sample, min, max, sum, sum_square
 *
 * Output: SUCCESS or ERROR on failure
 *
 **************************************************************************/
extern int mds_stats_values(char * name_value, unsigned long long * nb_sample, unsigned long long * min, unsigned long long * max, unsigned long long * sum, unsigned long long * sum_square)
{
  unsigned long long tmp_nb_sample=0,tmp_min=0,tmp_max=0,tmp_sum=0,tmp_sum_square=0;
  glob_t path;

/*we parse the three MDS stat files and sum values*/
  if (cfs_get_param_paths(&path, "mdt/MDS/mds/stats") != 0)
    return ERROR;
  if( stats_values(path.gl_pathv[0],name_value,&tmp_nb_sample,&tmp_min,&tmp_max,&tmp_sum,&tmp_sum_square) == ERROR ) {
    cfs_free_param_data(&path);
    return ERROR;
  } else {
    *nb_sample=tmp_nb_sample;
    *min=tmp_min;
    *max=tmp_max;
    *sum=tmp_sum;
    *sum_square=tmp_sum_square;
  }
  cfs_free_param_data(&path);

  if (cfs_get_param_paths(&path, "mdt/MDS/mds_readpage/stats") != 0)
    return ERROR;
  if( stats_values(path.gl_pathv[0],name_value,&tmp_nb_sample,&tmp_min,&tmp_max,&tmp_sum,&tmp_sum_square) == ERROR ) {
    cfs_free_param_data(&path);
    return ERROR;
  } else {
    *nb_sample += tmp_nb_sample;
    *min += tmp_min;
    *max += tmp_max;
    *sum += tmp_sum;
    *sum_square += tmp_sum_square;
  }
  cfs_free_param_data(&path);

  if (cfs_get_param_paths(&path, "mdt/MDS/mds_setattr/stats") != 0)
    return ERROR;
  if( stats_values(path.gl_pathv[0],name_value,&tmp_nb_sample,&tmp_min,&tmp_max,&tmp_sum,&tmp_sum_square) == ERROR ) {
    cfs_free_param_data(&path);
    return ERROR;
  } else {
    *nb_sample += tmp_nb_sample;
    *min += tmp_min;
    *max += tmp_max;
    *sum += tmp_sum;
    *sum_square += tmp_sum_square;
  }
  cfs_free_param_data(&path);
  
  return SUCCESS;
}

void convert_ull(counter64 *c64, unsigned long long ull, size_t *var_len)
{
	*var_len  = sizeof(*c64);
        c64->low  = (unsigned long long) (0x0ffffffff & ull);
        ull >>= 32;
        c64->high = (unsigned long long) (0x0ffffffff & ull);
}

