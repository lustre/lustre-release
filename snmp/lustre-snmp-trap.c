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
 * snmp/lustre-snmp-trap.c
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
#include <ctype.h>
#include "lustre-snmp-util.h"

/**************************************************************************
 * Constants
 *************************************************************************/

#define DEFAULT_POLL_INTERVAL_SECONDS   60
#define POLL_INTERVAL_ENV_VAR           "LSNMP_POLL_INTERVAL"
#define SNMP_HEALTH_CHECK_TEST_FILE     "LSNMP_HEALTH_CHECK_TEST_FILE"

/**************************************************************************
 * Trap OIDS
 *************************************************************************/

static oid objid_snmptrap[] =                       
    { 1,3,6,1,6,3,1,1,4,1,0};
static oid lustre_portals_trap[] = 
    { 1,3,6,1,4,1,13140,2,1,0,1};
static oid lustre_portals_trap_string[]= 
    { 1,3,6,1,4,1,13140,2,1,0,2};
static oid lustre_unhealthy_trap[] = 
    { 1,3,6,1,4,1,13140,2,1,0,3};
static oid lustre_unhealthy_trap_device_name_string[]= 
    { 1,3,6,1,4,1,13140,2,1,0,4};
static oid lustre_unhealthy_trap_reason_string[]= 
    { 1,3,6,1,4,1,13140,2,1,0,5};

/**************************************************************************
 * Data structures
 *************************************************************************/

typedef struct obd_unhealthy_entry_struct{

    /*1-if seen as part of the the is_unhealthy scan, otherwise 0*/
    int seen;                         

    /*single linked list pointer*/
    struct obd_unhealthy_entry_struct *next; 

    /*obdname - variable size*/
    char name[0];                     

}obd_unhealthy_entry;

/**************************************************************************
 * Local functions
 *************************************************************************/

int get_poll_interval_seconds();
void health_poll_worker(unsigned int registration_number, void *clientarg);
void send_portals_catastrophe_trap(char *reason_string);
void send_obd_unhealthy_trap(char *obd_name,char *reason_string);
int is_obd_newly_unhealthy(const char* obd_name);
void obd_unhealthy_scan(void);
void health_entry_parser(void);

/**************************************************************************
 * Global variables
 *************************************************************************/

static int g_sent_portals_catastrophe = 0;
static obd_unhealthy_entry* g_obd_unhealthy_list = NULL;
static int g_poll_interval_seconds;
static unsigned int g_registration_handle;
static char *g_health_check_test_file = 0;

/*****************************************************************************
 * Function: initialize_trap_handler
 *
 * Description: Initlized the trap poll haalder.
 *
 * Input:   void
 *
 * Output:  Global g_poll_interval_seconds is set.
 *
 ****************************************************************************/
 
void initialize_trap_handler(void)
{
    g_poll_interval_seconds = get_poll_interval_seconds();

    g_registration_handle = snmp_alarm_register(g_poll_interval_seconds, 0, health_poll_worker, NULL);
    if (g_registration_handle == 0)
        report("%s %s: line %d %s", __FILE__, __FUNCTION__, __LINE__,
            "snmp_alarm_register failed");
            
    DEBUGMSGTL(("lsnmpd","lsnmp alarm registered poll interval = %d seconds\n",g_poll_interval_seconds));
    
    g_health_check_test_file = getenv(SNMP_HEALTH_CHECK_TEST_FILE);    
    if(g_health_check_test_file != 0)
        DEBUGMSGTL(("lsnmpd","lsnmp health check test file set to  \'%s\'\n",g_health_check_test_file));
}

/*****************************************************************************
 * Function: terminate_trap_handler
 *
 * Description: Terminate the trap poll haalder.
 *
 * Input:   void
 *
 * Output:  Global g_poll_interval_seconds is set.
 *
 ****************************************************************************/

void terminate_trap_handler(void)
{
    snmp_alarm_unregister(g_registration_handle);
}

/*****************************************************************************
 * Function: get_poll_interval_seconds
 *
 * Description: This function used to get the poll period for timer, which 
 *              is used to read throughput values periodically.
 * Input:   void
 * Output:  Alarm period, default value(if env var not set) otherwise.
 ****************************************************************************/

int get_poll_interval_seconds()
{
    char *alarm_period;
    int ret_val = DEFAULT_POLL_INTERVAL_SECONDS;

    /* Get Alarm period for reading the Lustre client table. */

    alarm_period = getenv(POLL_INTERVAL_ENV_VAR);
    if (alarm_period != NULL) {
        char *ptr = alarm_period;
        while(isdigit(*ptr)) ptr++;

        /* if we have only digits then conver it*/
        if (*ptr == '\0') {
            int time = atoi(alarm_period);
            if (time > 0)
                ret_val = time; /* Alarm period in seconds */
        }
    }
    return ret_val;
}

/*****************************************************************************
 * Function:  health_poll_worker
 *
 * Description: This is the routine registered to system timer for updating
 *     the throughput values for all the clients and its respective osc(s).
 *
 * Input:  'registration_number` value obtained during the alarm registration
 *         'clientarg' pointing to user defined data type.
 * Output: void
 *****************************************************************************/

void health_poll_worker(unsigned int registration_number, void *clientarg)
{
    health_entry_parser();

    /* Register the function again to call after lustre_alarm_period */
    if (!snmp_alarm_register(g_poll_interval_seconds, 0, health_poll_worker, NULL)) {
        report("%s %s:line %d %s", __FILE__, __FUNCTION__, __LINE__,
               "snmp_alarm_register failed");
    }
}

/*****************************************************************************
 * Function:  health_entry_parser
 *
 * Description: This routine is called to parse the health_check entry
 *              and send traps
 * Input:  'None
 * Output: void
 *****************************************************************************/
 
 void health_entry_parser(void)
{
    FILE    *fptr = NULL;
    char string[MAX_LINE_SIZE];
    int b_seen_portals_catastrophe = 0;
    char *filename;
    glob_t path;

    if (cfs_get_param_paths(&path, "health_check") != 0)
        return;

    filename = g_health_check_test_file == 0 ? path.gl_pathv[0] : g_health_check_test_file;

    /*DEBUGMSGTL(("lsnmpd","health_entry_parser(%s)\n",filename));*/

    /* Open the file.  Use the test file env variable if
       there is one */    
    fptr = fopen(filename,"r");
        
    /* Free parameter's path string */
    cfs_free_param_data(&path);

    /* If the path is not found do nothing */
    if( NULL == fptr)
        return;
       
    while( NULL != fgets(string, sizeof(string), fptr)){
        
        /*DEBUGMSGTL(("lsnmpd","health_entry_parser() looking at = \'%s\'\n",string));*/
       
        /*
         * First handle the portals catastrophe 
         * Look for the string "LBUG"
         */
        if(0 == strncmp(string,"LBUG",4)){
            /*
             * If we haven't sent the catastrophe message yet
             * send it now.  And keep track that we've sent it
             */
            if(!g_sent_portals_catastrophe){
                send_portals_catastrophe_trap("LBUG");
                g_sent_portals_catastrophe = 1;
            }
            b_seen_portals_catastrophe = 1;
        }
            
        /*
         * Now handle any of the OBD object failures
         * look for "device <OBDNAME> reported unhealthy"
         */
        else if(0 == strncmp(string,"device ",7)){
            char *obd_name = string+7;
            char *space_after_obd_name;
            
            /*
             * Now find the space after the obd name
             * Again if there is no space we're in trouble
             */
            space_after_obd_name = strchr(obd_name,' ');
            if(space_after_obd_name == 0)
                break;

            /*
             * Null terminate the obd_name
             */
            *space_after_obd_name = 0;
            
            DEBUGMSGTL(("lsnmpd","Looking at obd=%s\n",obd_name));

            /*
             * If we haven't sent a trap for this one
             * then send it now
             */
            if(is_obd_newly_unhealthy(obd_name))
                send_obd_unhealthy_trap(obd_name,"unhealthy");
        }
    }        
    
    /* If we don't find it reset the catastrope flag*/            
    if(!b_seen_portals_catastrophe && g_sent_portals_catastrophe)
    {
        DEBUGMSGTL(("lsnmpd","LBUG has been cleared\n"));
        g_sent_portals_catastrophe = 0;
    }
                
    /*
     *  Any <OBDNAMES> that weren't queried above are now unhealthy. 
     * Scan through and cleanup the newly healthy obds
     */
    obd_unhealthy_scan();
    
    fclose(fptr);
}

/*****************************************************************************
 * Function:  send_portals_catastrophe_trap
 *
 * Description: Send the SNMP V2 trap
 *
 * Input:  'reason_string' the reason for the catastrope.
 
 * Output: none
 *****************************************************************************/
 
void send_portals_catastrophe_trap(char *reason_string)
{
    /*
     * Setup the trap variables.  
     * It's a linked list of netsnmp_variable_list items.
     */
    netsnmp_variable_list var_trap[2];

    DEBUGMSGTL(("lsnmpd","Sending portals catastrophe trap reason=%s\n",reason_string));

    /* 
     * Setup the first variable in the trap data. 
     * Have it chain to another variable.
     */
    var_trap[0].next_variable = &var_trap[1];

    /*The "name" must be the standard snmp "trap" OID.*/
    var_trap[0].name = objid_snmptrap;
    var_trap[0].name_length = sizeof(objid_snmptrap) / sizeof(oid);

    /*But the data contained in this variable, is an OID that is the trap OID.*/
    var_trap[0].type = ASN_OBJECT_ID;
    var_trap[0].val.objid = lustre_portals_trap;
    var_trap[0].val_len = sizeof(lustre_portals_trap);

    /* 
     * Setup the second variable in the trap data. 
     * It is the last in the chain so set next to NULL
     */
    var_trap[1].next_variable = NULL;

    /* The "name" is the OID of the portals trap reason string */
    var_trap[1].name = lustre_portals_trap_string;
    var_trap[1].name_length = sizeof(lustre_portals_trap_string) / sizeof(oid);

    /* And the data is an octet string, that contains the actually reason
     * string */
    var_trap[1].type = ASN_OCTET_STR;
    var_trap[1].val.string = (unsigned char *)reason_string;
    var_trap[1].val_len = strlen(reason_string);

    /*And now send off the trap*/
    send_v2trap(var_trap);
}


/*****************************************************************************
 * Function:  send_obd_unhealthy_trap
 *
 * Description: Send the SNMP V2 trap
 *
 * Input:  'obd_name' the name of the obd
 *         'reason_string' the reason for the catastrope.
 * Output: none
 *****************************************************************************/
 
void send_obd_unhealthy_trap(char *obd_name,char *reason_string)
{
    /*
     * Setup the trap variables.  
     * It's a linked list of netsnmp_variable_list items.
     */
    netsnmp_variable_list var_trap[3];

    DEBUGMSGTL(("lsnmpd","Sending OBD unhealthy trap obd=%s reason=%s\n",obd_name,reason_string));

    /* 
     * Setup the first variable in the trap data. 
     * Have it chain to another variable.
     */
    var_trap[0].next_variable = &var_trap[1];

    /*The "name" must be the standard snmp "trap" OID.*/
    var_trap[0].name = objid_snmptrap;
    var_trap[0].name_length = sizeof(objid_snmptrap) / sizeof(oid);

    /*But the data contained in this variable, is an OID that is the trap OID.*/
    var_trap[0].type = ASN_OBJECT_ID;
    var_trap[0].val.objid = lustre_unhealthy_trap;
    var_trap[0].val_len = sizeof(lustre_unhealthy_trap);

    /* 
     * Setup the second variable in the trap data. 
     * Have it chain to another variable.
     */
    var_trap[1].next_variable = &var_trap[2];;

    /* The "name" is the OID of the portals trap reason string */
    var_trap[1].name = lustre_unhealthy_trap_device_name_string;
    var_trap[1].name_length = sizeof(lustre_unhealthy_trap_device_name_string) / sizeof(oid);

    /* And the data is an octet string, that contains the actual reason
     * string */
    var_trap[1].type = ASN_OCTET_STR;
    var_trap[1].val.string = (unsigned char *)obd_name;
    var_trap[1].val_len = strlen(obd_name);

    /*
     * Setup the third variable in the trap data.
     * It is the last in the chain so set next to NULL
     */
    var_trap[2].next_variable = NULL;

    /* The "name" is the OID of the portals trap reason string */
    var_trap[2].name = lustre_unhealthy_trap_reason_string;
    var_trap[2].name_length = sizeof(lustre_unhealthy_trap_reason_string) / sizeof(oid);

    /* And the data is an octet string, that contains the actual reason
     * string */
    var_trap[2].type = ASN_OCTET_STR;
    var_trap[2].val.string = (unsigned char *)reason_string;
    var_trap[2].val_len = strlen(reason_string);

    /*And now send off the trap*/
    send_v2trap(var_trap);
}


/*****************************************************************************
 * Function:  is_obd_newly_unhealthy
 *
 * Description: Deterime if the obd is going from health->unhealth
 *              Also mark all unhealhy (new and old) as seen.
 *
 * Input:  'obd_name' the name of the obd
 *
 * Output: 1 if newly unhealthy 0 if previolsy unhealthy
 *****************************************************************************/

int is_obd_newly_unhealthy(const char* obd_name)
{
    /*for all elements in g_obd_unhealthy_list*/
    obd_unhealthy_entry* walker;
    obd_unhealthy_entry* entry;
    int name_len;

    for(walker = g_obd_unhealthy_list; walker != 0; walker = walker->next)
    {
        /*If the names match*/
        if(0 == strcmp (walker->name,obd_name))
        {
            /* Commented out because it was just to noisy!
             * DEBUGMSGTL(("lsnmpd","obd %s was already unhealthy\n",obd_name));
             */
            
            /*Mark the entry as seen, and return that it was previously unhealthy*/
            walker->seen =1;
            return 0;
        }
    }

    DEBUGMSGTL(("lsnmpd","obd %s is now unhealthy\n",obd_name));

    /*We didn't find an entry so we need to create a new one. */
    /*Calculate the obd_name length*/
    name_len = strlen(obd_name)+1;

    /*Allocate a new entry*/
    entry = malloc(sizeof(*entry) + name_len);

    /*Put this element at the front of the list*/
    entry->next = g_obd_unhealthy_list;
    g_obd_unhealthy_list = entry;

    /*Mark it initially as seen*/
    entry->seen = 1;

    /*And copy the entry name*/
    memcpy(entry->name,obd_name,name_len);

    /*return this obd as newly unhealthy.*/
    return 1;
}


/*****************************************************************************
 * Function:  obd_unhealthy_scan
 *
 * Description: Deterime if any obd is going from unhealthy->healthy
 *              Any of the obds that weren't "seen" by the 
 *              is_obd_newly_unhealthy() pass are now health so 
 *              remove them from the lists
 *              Also clear all "seen" flags.
 *
 * Input:  None
 * Output: None
 *****************************************************************************/
 
void obd_unhealthy_scan(void)
{
    /*fore all elements in g_obd_unhealthy_list*/
    obd_unhealthy_entry* walker = g_obd_unhealthy_list;
    obd_unhealthy_entry* prev = 0;
    while(walker != 0)
    {
        /*remove any that was not seen as unhealthy the last time*/
        if(walker->seen == 0)
        {
            /*Remove element from the list, but first fix up the walker pointer*/
            obd_unhealthy_entry* temp = walker;

            DEBUGMSGTL(("lsnmpd","obd %s is now healthy\n",walker->name));

            walker = walker->next;

            /*Now adjust the pointers to effectively remove this entry*/
            if(prev == 0)
                g_obd_unhealthy_list = walker;
            else
                prev->next = walker;

            /*And free the pointer. */
            free(temp);
            /*walker and prev are correctly setup so we can go around the loop again.*/
        }

        /*Mark all other entries as NOT seen for next pass through*/
        else 
        {
            walker->seen = 0;
            /*Go onto the next entry*/
            prev = walker;
            walker = walker->next;
        }
    }
}
