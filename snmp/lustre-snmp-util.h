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
 * snmp/lustre-snmp-util.h
 *
 * Author: PJ Kirner <pjkirner@clusterfs.com>
 */

#ifndef LUSTRE_SNMP_UTIL_H
#define LUSTRE_SNMP_UTIL_H

#include <libcfs/util/param.h>

/*
 * Definitions of magic values
 */

#define SYSVERSION          20
#define SYSKERNELVERSION    21
#define SYSHEALTHCHECK      22
#define SYSSTATUS           23

#define OSDNUMBER           30
#define OSDUUID             31
#define OSDCOMMONNAME       32
#define OSDCAPACITY         33
#define OSDFREECAPACITY     34
#define OSDOBJECTS          35
#define OSDFREEOBJECTS      36

#define OSCNUMBER           40
#define OSCUUID             41
#define OSCCOMMONNAME       42
#define OSCOSTSERVERUUID    43
#define OSCCAPACITY         44
#define OSCFREECAPACITY     45
#define OSCOBJECTS          46
#define OSCFREEOBJECTS      47

#define MDDNUMBER           50
#define MDDUUID             51
#define MDDCOMMONNAME       52
#define MDDCAPACITY         53
#define MDDFREECAPACITY     54
#define MDDFILES            55
#define MDDFREEFILES        56
#define MDSNBSAMPLEDREQ     57

#define MDCNUMBER           60
#define MDCUUID             61
#define MDCCOMMONNAME       62
#define MDCMDSSERVERUUID    63
#define MDCCAPACITY         64
#define MDCFREECAPACITY     65
#define MDCOBJECTS          66
#define MDCFREEOBJECTS      67

#define CLIMOUNTNUMBER      70
#define CLIUUID             71
#define CLICOMMONNAME       72
#define CLIMDCUUID          73
#define CLIMDCCOMMONNAME    74
#define CLIUSESLOV          75
#define CLILOVUUID          76
#define CLILOVCOMMONNAME    77

#define LOVNUMBER           80
#define LOVUUID             81
#define LOVCOMMONNAME       82
#define LOVNUMOBD           83
#define LOVNUMACTIVEOBD     84
#define LOVCAPACITY         85
#define LOVFREECAPACITY     86
#define LOVFILES            87
#define LOVFREEFILES        88
#define LOVSTRIPECOUNT      89
#define LOVSTRIPEOFFSET     90
#define LOVSTRIPESIZE       91
#define LOVSTRIPETYPE       92

#define LDLMNUMBER          100
#define LDLMNAMESPACE       101
#define LDLMLOCKCOUNT       102
#define LDLMUNUSEDLOCKCOUNT 103
#define LDLMRESOURCECOUNT   104

#define LNETNUMBER          110
#define LNETMSGSALLOC       111
#define LNETMSGSMAX         112
#define LNETERRORS          113
#define LNETSENDCOUNT       114
#define LNETRECVCOUNT       115
#define LNETROUTECOUNT      116
#define LNETDROPCOUNT       117
#define LNETSENDBYTES       118
#define LNETRECVBYTES       119
#define LNETROUTEBYTES      120
#define LNETDROPBYTES       121

/* Common procfs file entries that are refrenced in mulitple locations*/
#define FILENAME_SYS_STATUS         "/var/lustre/sysStatus"

#define FILENAME_NUM_REF            "num_refs"
#define FILENAME_UUID               "uuid"
#define FILENAME_COMMON_NAME        "common_name"
#define FILENAME_KBYTES_TOTAL       "kbytestotal"
#define FILENAME_KBYTES_FREE        "kbytesfree"
#define FILENAME_FILES_TOTAL        "filestotal"
#define FILENAME_FILES_FREE         "filesfree"
#define STR_REQ_WAITIME             "req_waittime"

/* strings which the file /var/lustre/sysStatus can hold */
#define STR_ONLINE                  "online"
#define STR_ONLINE_PENDING          "online pending"
#define STR_OFFLINE                 "offline"
#define STR_OFFLINE_PENDING         "offline pending"


/* Script required for starting/stopping lustre services */
#define LUSTRE_SERVICE              "/etc/init.d/lustre"

#define MIN_LEN(val1,val2)          (((val1)>(val2))?(val2):(val1))

/* The max size of a lustre procfs path name*/
#define MAX_PATH_SIZE               512

/* The max size of a string read from procfs */
#define MAX_LINE_SIZE               512

/* Types passed to get_file_list() */
#define DIR_TYPE                    1
#define FILE_TYPE                   0

/* Defining return values */
#define SUCCESS                     0
#define ERROR                       -1

typedef struct counter64 counter64;

typedef enum {
    ONLINE = 1,
    OFFLINE,
    ONLINE_PENDING,
    OFFLINE_PENDING,
    RESTART
} lustre_sysstatus;

/* File operation related functions */
char *get_file_list(const char *dirname, int file_type, uint32_t *count);
extern int  is_directory(const char *filename);
extern int  read_string(const char *filepath, char *lustre_var,size_t var_size);
int read_counter64(const char *file_path, counter64 *c64,int factor);
int read_ulong(const char *file_path,unsigned long* valuep);

/* Start/Stop/Restart Lustre Services */
extern void lustrefs_ctrl(int command);
extern int get_sysstatus();

extern void report(const char *fmt, ...);

/* Table Driven SNMP OID Handler support*/
typedef unsigned char* (*f_oid_handler_t)(
    const char* file_path,
    size_t  *var_len);

struct oid_table
{
    int magic;                  /*The magic number*/ 
    const char *name;           /*The procfs name*/
    f_oid_handler_t fhandler;   /*The handler */
};

unsigned char* oid_table_ulong_handler(const char* file_path,size_t  *var_len);
unsigned char* oid_table_c64_handler(const char* file_path,size_t  *var_len);
unsigned char* oid_table_c64_kb_handler(const char* file_path,size_t  *var_len);
unsigned char* oid_table_obj_name_handler(const char* file_path,size_t  *var_len);
unsigned char* oid_table_string_handler(const char* file_path,size_t *var_len);
unsigned char* oid_table_is_directory_handler(const char* file_path,size_t *var_len);
unsigned char *
    var_genericTable(struct variable *vp,
        oid     *name,
        size_t  *length,
        int     exact,
        size_t  *var_len,
        WriteMethod **write_method,
        const char *path,
        struct oid_table *ptable);

void convert_ull(counter64 *c64, unsigned long long ull, size_t *var_len);
int stats_values(char * filepath,char * name_value, unsigned long long * nb_sample, unsigned long long * min, unsigned long long * max, unsigned long long * sum, unsigned long long * sum_square);
extern int mds_stats_values(char * name_value, unsigned long long * nb_sample, unsigned long long * min, unsigned long long * max, unsigned long long * sum, unsigned long long * sum_square);

 /* export for net-snmp util-funcs */
int             header_simple_table(struct variable *, oid *, size_t *,
                                    int, size_t *,
                                    WriteMethod ** write_method, int);
int             header_generic(struct variable *, oid *, size_t *, int,
                               size_t *, WriteMethod **);

#endif /* LUSTRE_SNMP_UTIL_H */
