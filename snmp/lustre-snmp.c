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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * snmp/lustre-snmp.c
 *
 * Author: PJ Kirner <pjkirner@clusterfs.com>
 */
 
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/utilities.h>
#include <pthread.h>
#include "lustre-snmp.h"

#define LNET_CHECK_INTERVAL 500

/* 
 * clusterFileSystems_variables_oid:
 *   this is the top level oid that we want to register under.  This
 *   is essentially a prefix, with the suffix appearing in the
 *   variable below.
 */


oid clusterFileSystems_variables_oid[] = { 1,3,6,1,4,1,13140 };


/* 
 * variable7 clusterFileSystems_variables:
 *   this variable defines function callbacks and type return information 
 *   for the clusterFileSystems mib section 
 */


struct variable7 clusterFileSystems_variables[] = {
/*  magic number        , variable type , ro/rw , callback fn  , L, oidsuffix */

  /* sytemInformation 2.1.1. */
  { SYSVERSION          , ASN_OCTET_STR , RONLY , var_clusterFileSystems, 4, { 2,1,1,1 } },
  { SYSKERNELVERSION    , ASN_OCTET_STR , RONLY , var_clusterFileSystems, 4, { 2,1,1,2 } },
  { SYSHEALTHCHECK      , ASN_OCTET_STR , RONLY , var_clusterFileSystems, 4, { 2,1,1,3 } },
  { SYSSTATUS           , ASN_INTEGER   , RWRITE, var_clusterFileSystems, 4, { 2,1,1,4 } },

  /* objectStorageTargets 2.1.2 */
  { OSDNUMBER           , ASN_UNSIGNED  , RONLY , var_clusterFileSystems, 4, { 2,1,2,1 } },

  /* objectStorageTargets.osdTable.osdEntry 2.1.2.2.1 */
  { OSDUUID             , ASN_OCTET_STR , RONLY , var_osdTable, 6, { 2,1,2,2,1,2 } },
  { OSDCOMMONNAME       , ASN_OCTET_STR , RONLY , var_osdTable, 6, { 2,1,2,2,1,3 } },
  { OSDCAPACITY         , ASN_COUNTER64 , RONLY , var_osdTable, 6, { 2,1,2,2,1,4 } },
  { OSDFREECAPACITY     , ASN_COUNTER64 , RONLY , var_osdTable, 6, { 2,1,2,2,1,5 } },
  { OSDOBJECTS          , ASN_COUNTER64 , RONLY , var_osdTable, 6, { 2,1,2,2,1,6 } },
  { OSDFREEOBJECTS      , ASN_COUNTER64 , RONLY , var_osdTable, 6, { 2,1,2,2,1,7 } },

  /* objectStorageClients 2.1.3 */
  { OSCNUMBER           , ASN_UNSIGNED  , RONLY , var_clusterFileSystems, 4, { 2,1,3,1 } },

  /* objectStorageClients.oscTable.oscEntry 2.1.3.2.1 */
  { OSCUUID             , ASN_OCTET_STR , RONLY , var_oscTable, 6, { 2,1,3,2,1,2 } },
  { OSCCOMMONNAME       , ASN_OCTET_STR , RONLY , var_oscTable, 6, { 2,1,3,2,1,3 } },
  { OSCOSTSERVERUUID    , ASN_OCTET_STR , RONLY , var_oscTable, 6, { 2,1,3,2,1,4 } },
  { OSCCAPACITY         , ASN_COUNTER64 , RONLY , var_oscTable, 6, { 2,1,3,2,1,5 } },
  { OSCFREECAPACITY     , ASN_COUNTER64 , RONLY , var_oscTable, 6, { 2,1,3,2,1,6 } },
  { OSCOBJECTS          , ASN_COUNTER64 , RONLY , var_oscTable, 6, { 2,1,3,2,1,7 } },
  { OSCFREEOBJECTS      , ASN_COUNTER64 , RONLY , var_oscTable, 6, { 2,1,3,2,1,8 } },


  /* metaDataServers 2.1.4 */
  { MDDNUMBER           , ASN_UNSIGNED  , RONLY , var_clusterFileSystems, 4, { 2,1,4,1 } },

  /* metaDataServers.mddTable.mddEntry 2.1.4.2.1 */
  { MDDUUID             , ASN_OCTET_STR , RONLY , var_mdsTable, 6, { 2,1,4,2,1,2 } },
  { MDDCOMMONNAME       , ASN_OCTET_STR , RONLY , var_mdsTable, 6, { 2,1,4,2,1,3 } },
  { MDDCAPACITY         , ASN_COUNTER64 , RONLY , var_mdsTable, 6, { 2,1,4,2,1,4 } },
  { MDDFREECAPACITY     , ASN_COUNTER64 , RONLY , var_mdsTable, 6, { 2,1,4,2,1,5 } },
  { MDDFILES            , ASN_COUNTER64 , RONLY , var_mdsTable, 6, { 2,1,4,2,1,6 } },
  { MDDFREEFILES        , ASN_COUNTER64 , RONLY , var_mdsTable, 6, { 2,1,4,2,1,7 } },
  { MDSNBSAMPLEDREQ     , ASN_COUNTER64 , RONLY , var_mdsNbSampledReq, 4, { 2,1,4,3 } },

  /* metaDataClients 2.1.5 */
  { MDCNUMBER           , ASN_UNSIGNED  , RONLY , var_clusterFileSystems, 4, { 2,1,5,1 } },

  /* metaDataClients.mdcTable.mdcEntry 2.1.5.2.1 */
  { MDCUUID             , ASN_OCTET_STR , RONLY , var_mdcTable, 6, { 2,1,5,2,1,2 } },
  { MDCCOMMONNAME       , ASN_OCTET_STR , RONLY , var_mdcTable, 6, { 2,1,5,2,1,3 } },
  { MDCMDSSERVERUUID    , ASN_OCTET_STR , RONLY , var_mdcTable, 6, { 2,1,5,2,1,4 } },
  { MDCCAPACITY         , ASN_COUNTER64 , RONLY , var_mdcTable, 6, { 2,1,5,2,1,5 } },
  { MDCFREECAPACITY     , ASN_COUNTER64 , RONLY , var_mdcTable, 6, { 2,1,5,2,1,6 } },
  { MDCOBJECTS          , ASN_COUNTER64 , RONLY , var_mdcTable, 6, { 2,1,5,2,1,7 } },
  { MDCFREEOBJECTS      , ASN_COUNTER64 , RONLY , var_mdcTable, 6, { 2,1,5,2,1,8 } },

  /* lustreClients 2.1.6 */
  { CLIMOUNTNUMBER           , ASN_UNSIGNED  , RONLY , var_clusterFileSystems, 4, { 2,1,6,1 } },

  /* lustreClients.cliMountTable.cliMountEntry 2.1.6.2.1 */
  { CLIUUID             , ASN_OCTET_STR , RONLY , var_cliTable, 6, { 2,1,6,2,1,2 } },
  { CLICOMMONNAME       , ASN_OCTET_STR , RONLY , var_cliTable, 6, { 2,1,6,2,1,3 } },
  { CLIMDCUUID          , ASN_OCTET_STR , RONLY , var_cliTable, 6, { 2,1,6,2,1,4 } },
  { CLIMDCCOMMONNAME    , ASN_OCTET_STR , RONLY , var_cliTable, 6, { 2,1,6,2,1,5 } },
  { CLIUSESLOV          , ASN_INTEGER ,   RONLY , var_cliTable, 6, { 2,1,6,2,1,6 } },
  { CLILOVUUID          , ASN_OCTET_STR , RONLY , var_cliTable, 6, { 2,1,6,2,1,7 } },
  { CLILOVCOMMONNAME    , ASN_OCTET_STR , RONLY , var_cliTable, 6, { 2,1,6,2,1,8 } },

  /* logicalObjectVolume 2.1.7 */
  { LOVNUMBER           , ASN_UNSIGNED  , RONLY , var_clusterFileSystems, 4, { 2,1,7,1 } },

  /* logicalObjectVolume.osdTable.lovTable 2.1.7.2.1 */
  { LOVUUID             , ASN_OCTET_STR , RONLY , var_lovTable, 6, { 2,1,7,2,1,2 } },
  { LOVCOMMONNAME       , ASN_OCTET_STR , RONLY , var_lovTable, 6, { 2,1,7,2,1,3 } },
  { LOVNUMOBD           , ASN_UNSIGNED ,  RONLY , var_lovTable, 6, { 2,1,7,2,1,4 } },
  { LOVNUMACTIVEOBD     , ASN_UNSIGNED ,  RONLY , var_lovTable, 6, { 2,1,7,2,1,5 } },
  { LOVCAPACITY         , ASN_COUNTER64 , RONLY , var_lovTable, 6, { 2,1,7,2,1,6 } },
  { LOVFREECAPACITY     , ASN_COUNTER64 , RONLY , var_lovTable, 6, { 2,1,7,2,1,7 } },
  { LOVFILES            , ASN_COUNTER64 , RONLY , var_lovTable, 6, { 2,1,7,2,1,8 } },
  { LOVFREEFILES        , ASN_COUNTER64 , RONLY , var_lovTable, 6, { 2,1,7,2,1,9 } },
  { LOVSTRIPECOUNT      , ASN_UNSIGNED ,  RONLY , var_lovTable, 6, { 2,1,7,2,1,10} },
  { LOVSTRIPEOFFSET     , ASN_UNSIGNED ,  RONLY , var_lovTable, 6, { 2,1,7,2,1,11} },
  { LOVSTRIPESIZE       , ASN_UNSIGNED ,  RONLY , var_lovTable, 6, { 2,1,7,2,1,12} },
  { LOVSTRIPETYPE       , ASN_UNSIGNED ,  RONLY , var_lovTable, 6, { 2,1,7,2,1,13} },

  /* lustreLDLM 2.1.8 */
  { LDLMNUMBER          , ASN_UNSIGNED  , RONLY , var_clusterFileSystems, 4, { 2,1,8,1 } },

  /* lustreLDLM.ldlmTable.ldlmEntry 2.1.8.2.1 */
  { LDLMNAMESPACE       , ASN_OCTET_STR , RONLY , var_ldlmTable, 6, { 2,1,8,2,1,2 } },
  { LDLMLOCKCOUNT       , ASN_UNSIGNED  , RONLY , var_ldlmTable, 6, { 2,1,8,2,1,3 } },
  { LDLMUNUSEDLOCKCOUNT , ASN_UNSIGNED  , RONLY , var_ldlmTable, 6, { 2,1,8,2,1,4 } },
  { LDLMRESOURCECOUNT   , ASN_UNSIGNED  , RONLY , var_ldlmTable, 6, { 2,1,8,2,1,5 } },

  /* lnetInformation 2.1.9 */
  { LNETMSGSALLOC,  ASN_UNSIGNED,  RONLY, var_lnetInformation, 4, { 2,1,9,1 } },
  { LNETMSGSMAX,    ASN_UNSIGNED,  RONLY, var_lnetInformation, 4, { 2,1,9,2 } },
  { LNETERRORS,     ASN_UNSIGNED,  RONLY, var_lnetInformation, 4, { 2,1,9,3 } },
  { LNETSENDCOUNT,  ASN_UNSIGNED,  RONLY, var_lnetInformation, 4, { 2,1,9,4 } },
  { LNETRECVCOUNT,  ASN_UNSIGNED,  RONLY, var_lnetInformation, 4, { 2,1,9,5 } },
  { LNETROUTECOUNT, ASN_UNSIGNED,  RONLY, var_lnetInformation, 4, { 2,1,9,6 } },
  { LNETDROPCOUNT,  ASN_UNSIGNED,  RONLY, var_lnetInformation, 4, { 2,1,9,7 } },
  { LNETSENDBYTES,  ASN_COUNTER64, RONLY, var_lnetInformation, 4, { 2,1,9,8 } },
  { LNETRECVBYTES,  ASN_COUNTER64, RONLY, var_lnetInformation, 4, { 2,1,9,9 } },
  { LNETROUTEBYTES, ASN_COUNTER64, RONLY, var_lnetInformation, 4, { 2,1,9,10 } },
  { LNETDROPBYTES,  ASN_COUNTER64, RONLY, var_lnetInformation, 4, { 2,1,9,11 } },
};

/*****************************************************************************
 * Function: init_cfsNetSNMPPlugin
 *
 * Description: Called when the agent starts up
 *
 * Input:   void
 *
 * Output:  None
 *
 ****************************************************************************/
 
void init_lustresnmp(void) {

	/* register ourselves with the agent to handle our mib tree */
	REGISTER_MIB("clusterFileSystems",
		     clusterFileSystems_variables, variable7,
		     clusterFileSystems_variables_oid);

	initialize_trap_handler();

	DEBUGMSGTL(("lsnmpd", "%s %s\n", __func__, "Initialization Done"));
}

/*****************************************************************************
 * Function: deinit_cfsNetSNMPPlugin
 *
 * Description: Called when the agent terminates up
 *
 * Input:   void
 *
 * Output:  None
 *
 ****************************************************************************/

void deinit_lustresnmp(void) {

	/* deregister ourselves with the agent */
	unregister_mib(clusterFileSystems_variables_oid,
		       sizeof(clusterFileSystems_variables_oid)/
		       sizeof(clusterFileSystems_variables_oid));

	terminate_trap_handler();

	DEBUGMSGTL(("lsnmpd", "%s %s\n", __func__, "Termination Done"));
}

/*****************************************************************************
 * Function: var_clusterFileSystems
 *
 ****************************************************************************/
unsigned char *
var_clusterFileSystems(struct variable *vp, 
                oid     *name, 
                size_t  *length, 
                int     exact, 
                size_t  *var_len, 
                WriteMethod **write_method)
{


  /* variables we may use later */
  static long long_ret;
  static u_long ulong_ret;
  static unsigned char string[SPRINT_MAX_LEN];
  char file_path[MAX_PATH_SIZE];
  uint32_t num;
  char *dir_list;

  if (header_generic(vp,name,length,exact,var_len,write_method)
                                  == MATCH_FAILED )
    return NULL;


  /* 
   * this is where we do the value assignments for the mib results.
   */
  switch(vp->magic) {

    case SYSVERSION:
        sprintf(file_path, "%s%s", LUSTRE_PATH,"version");
        if( SUCCESS != read_string(file_path, (char *)string,sizeof(string)))
            return NULL;
        *var_len = strlen((char *)string);
        return (unsigned char *) string;

    case SYSKERNELVERSION:
        sprintf(file_path, "%s%s", LUSTRE_PATH,"kernel_version");
        if( SUCCESS != read_string(file_path, (char *)string,sizeof(string)))
            return NULL;
        *var_len = strlen((char *)string);
        return (unsigned char *) string;

    case SYSHEALTHCHECK:
        sprintf(file_path, "%s%s", LUSTRE_PATH,FILENAME_SYSHEALTHCHECK);
        if( SUCCESS != read_string(file_path, (char *)string,sizeof(string)))
            return NULL;
        *var_len = strlen((char*)string);
        return (unsigned char *) string;

    case SYSSTATUS:
        *write_method = write_sysStatus;
        long_ret = (long) get_sysstatus();
        if (long_ret != ERROR)
          return (unsigned char *) &long_ret;
        return NULL;
                      
    case OSDNUMBER:
        if( 0 == (dir_list = get_file_list(OSD_PATH, DIR_TYPE, &num)))
            return NULL;
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",OSD_PATH,num));  
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    case OSCNUMBER:
        if( 0 == (dir_list = get_file_list(OSC_PATH, DIR_TYPE, &num)))
            return NULL;
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",OSC_PATH,num));  
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    case MDDNUMBER:
        if( 0 == (dir_list = get_file_list(MDS_PATH, DIR_TYPE, &num)))
            return NULL;
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",MDS_PATH,num));  
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    case MDCNUMBER:
        if( 0 == (dir_list = get_file_list(MDC_PATH, DIR_TYPE, &num)))
            return NULL;
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",MDC_PATH,num));  
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    case CLIMOUNTNUMBER:
        if( 0 == (dir_list = get_file_list(CLIENT_PATH, DIR_TYPE, &num)))
            return NULL;
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",CLIENT_PATH,num));  
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    case LOVNUMBER:
        if( 0 == (dir_list = get_file_list(LOV_PATH, DIR_TYPE, &num)))
            return NULL;
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",LOV_PATH,num));  
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    case LDLMNUMBER:
        if( 0 == (dir_list = get_file_list(LDLM_PATH, DIR_TYPE, &num)))
            return NULL;
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",LDLM_PATH,num));  
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    default:
      ERROR_MSG("");
  }
  return NULL;
}

struct oid_table osd_table[] =
{ 
    { OSDUUID,FILENAME_UUID,oid_table_string_handler},
    { OSDCOMMONNAME,0,oid_table_obj_name_handler},
    { OSDCAPACITY,FILENAME_KBYTES_TOTAL, oid_table_c64_kb_handler},
    { OSDFREECAPACITY,FILENAME_KBYTES_FREE, oid_table_c64_kb_handler},
    { OSDOBJECTS,FILENAME_FILES_TOTAL, oid_table_c64_kb_handler},
    { OSDFREEOBJECTS,FILENAME_FILES_FREE, oid_table_c64_kb_handler},
    { 0,0,0 } /*End of table*/
};


/*****************************************************************************
 * Function: var_osdTable
 *
 ****************************************************************************/
unsigned char *
var_osdTable(struct variable *vp,
    	    oid     *name,
    	    size_t  *length,
    	    int     exact,
    	    size_t  *var_len,
    	    WriteMethod **write_method)
{
    return var_genericTable(vp,name,length,exact,var_len,write_method,
        OSD_PATH,osd_table);
}

struct oid_table osc_table[] =
{ 
    { OSCUUID,FILENAME_UUID,oid_table_string_handler},
    { OSCCOMMONNAME,0,oid_table_obj_name_handler},
    { OSCOSTSERVERUUID,"ost_server_uuid",oid_table_string_handler},
    { OSCCAPACITY,FILENAME_KBYTES_TOTAL, oid_table_c64_kb_handler},
    { OSCFREECAPACITY,FILENAME_KBYTES_FREE, oid_table_c64_kb_handler},
    { OSCOBJECTS,FILENAME_FILES_TOTAL, oid_table_c64_kb_handler},
    { OSCFREEOBJECTS,FILENAME_FILES_FREE, oid_table_c64_kb_handler},
    { 0,0,0 } /*End of table*/
};

/*****************************************************************************
 * Function: var_oscTable
 *
 ****************************************************************************/
unsigned char *
var_oscTable(struct variable *vp,
    	    oid     *name,
    	    size_t  *length,
    	    int     exact,
    	    size_t  *var_len,
    	    WriteMethod **write_method)
{
    return var_genericTable(vp,name,length,exact,var_len,write_method,
        OSC_PATH,osc_table);
}

struct oid_table mds_table[] =
{ 
    { MDDUUID,FILENAME_UUID,oid_table_string_handler},
    { MDDCOMMONNAME,0,oid_table_obj_name_handler},
    { MDDCAPACITY,FILENAME_KBYTES_TOTAL, oid_table_c64_kb_handler},
    { MDDFREECAPACITY,FILENAME_KBYTES_FREE, oid_table_c64_kb_handler},
    { MDDFILES,FILENAME_FILES_TOTAL, oid_table_c64_kb_handler},
    { MDDFREEFILES,FILENAME_FILES_FREE, oid_table_c64_kb_handler},
    { 0,0,0 } /*End of table*/
};

/*****************************************************************************
 * Function: var_mdsTable
 *
 ****************************************************************************/
unsigned char *
var_mdsTable(struct variable *vp,
    	    oid     *name,
    	    size_t  *length,
    	    int     exact,
    	    size_t  *var_len,
    	    WriteMethod **write_method)
{
    return var_genericTable(vp,name,length,exact,var_len,write_method,
        MDS_PATH,mds_table);
}

struct oid_table mdc_table[] =
{ 
    { MDCUUID,FILENAME_UUID,oid_table_string_handler},
    { MDCCOMMONNAME,0,oid_table_obj_name_handler},
    { MDCMDSSERVERUUID,"mds_server_uuid",oid_table_string_handler},
    { MDCCAPACITY,FILENAME_KBYTES_TOTAL, oid_table_c64_kb_handler},
    { MDCFREECAPACITY,FILENAME_KBYTES_FREE, oid_table_c64_kb_handler},
    { MDCOBJECTS,FILENAME_FILES_TOTAL, oid_table_c64_kb_handler},
    { MDCFREEOBJECTS,FILENAME_FILES_FREE, oid_table_c64_kb_handler},
    { 0,0,0 } /*End of table*/
};


/*****************************************************************************
 * Function: var_mdcTable
 *
 ****************************************************************************/
unsigned char *
var_mdcTable(struct variable *vp,
    	    oid     *name,
    	    size_t  *length,
    	    int     exact,
    	    size_t  *var_len,
    	    WriteMethod **write_method)
{
    return var_genericTable(vp,name,length,exact,var_len,write_method,
        MDC_PATH,mdc_table);
}


struct oid_table cli_table[] =
{ 
    { CLIUUID,FILENAME_UUID,oid_table_string_handler},
    { CLICOMMONNAME,0,oid_table_obj_name_handler},
    { CLIMDCUUID,"mdc/" FILENAME_UUID,oid_table_string_handler},
    { CLIMDCCOMMONNAME,"mdc/" FILENAME_COMMON_NAME,oid_table_string_handler},
    { CLIUSESLOV,"lov/",oid_table_is_directory_handler},
    { CLILOVUUID,"lov/" FILENAME_UUID,oid_table_string_handler},
    { CLILOVCOMMONNAME,"lov/" FILENAME_COMMON_NAME,oid_table_string_handler},
    { 0,0,0 } /*End of table*/
};

/*****************************************************************************
 * Function: var_cliTable
 *
 ****************************************************************************/
unsigned char *
var_cliTable(struct variable *vp,
    	    oid     *name,
    	    size_t  *length,
    	    int     exact,
    	    size_t  *var_len,
    	    WriteMethod **write_method)
{
    return var_genericTable(vp,name,length,exact,var_len,write_method,
        CLIENT_PATH,cli_table);
}


struct oid_table lov_table[] =
{ 
    { LOVUUID,FILENAME_UUID,oid_table_string_handler},
    { LOVCOMMONNAME,0,oid_table_obj_name_handler},
    { LOVNUMOBD,"numobd", oid_table_ulong_handler},
    { LOVNUMACTIVEOBD,"activeobd", oid_table_ulong_handler},
    { LOVCAPACITY,FILENAME_KBYTES_TOTAL, oid_table_c64_kb_handler},
    { LOVFREECAPACITY,FILENAME_KBYTES_FREE, oid_table_c64_kb_handler},
    { LOVFILES,FILENAME_FILES_TOTAL, oid_table_c64_kb_handler},
    { LOVFREEFILES,FILENAME_FILES_FREE, oid_table_c64_kb_handler},
    { LOVSTRIPECOUNT,"stripecount", oid_table_ulong_handler},
    { LOVSTRIPEOFFSET,"stripeoffset", oid_table_ulong_handler},
    { LOVSTRIPESIZE,"stripesize", oid_table_ulong_handler},
    { LOVSTRIPETYPE,"stripetype", oid_table_ulong_handler},
    { 0,0,0 } /*End of table*/
};


/*****************************************************************************
 * Function: var_lovTable
 *
 ****************************************************************************/
unsigned char *
var_lovTable(struct variable *vp,
    	    oid     *name,
    	    size_t  *length,
    	    int     exact,
    	    size_t  *var_len,
    	    WriteMethod **write_method)
{
    return var_genericTable(vp,name,length,exact,var_len,write_method,
        LOV_PATH,lov_table);
}

struct oid_table ldlm_table[] =
{ 
    { LDLMNAMESPACE,0,oid_table_obj_name_handler},
    { LDLMLOCKCOUNT,"lock_count", oid_table_ulong_handler},
    { LDLMUNUSEDLOCKCOUNT,"lock_unused_count", oid_table_ulong_handler},
    { LDLMRESOURCECOUNT,"resource_count", oid_table_ulong_handler},
    { 0,0,0 } /*End of table*/
};


/*****************************************************************************
 * Function: var_ldlmTable
 *
 ****************************************************************************/
unsigned char *
var_ldlmTable(struct variable *vp,
    	    oid     *name,
    	    size_t  *length,
    	    int     exact,
    	    size_t  *var_len,
    	    WriteMethod **write_method)
{
    return var_genericTable(vp,name,length,exact,var_len,write_method,
        LDLM_PATH,ldlm_table);
}

/*****************************************************************************
 * Function: var_lnetInformation
 *
 ****************************************************************************/
unsigned char *
var_lnetInformation(struct variable *vp,
                    oid             *name,
                    size_t          *length,
                    int              exact,
                    size_t          *var_len,
                    WriteMethod    **write_method)
{
        /* variables we may use later */
        static unsigned char      string[SPRINT_MAX_LEN];
        static unsigned int       i[7];
        static unsigned long long ull[4];
        static unsigned long      next_update;
        static counter64          c64;
        static unsigned int       c32;
        struct timeval            current_tv;
        unsigned long             current;
        char                      file_path[MAX_PATH_SIZE];

        /* Update at most every LNET_STATS_INTERVAL milliseconds */
        gettimeofday(&current_tv, NULL);
        current = current_tv.tv_sec * 1000000 + current_tv.tv_usec;
        if (current >= next_update) {
                sprintf(file_path, "%s%s", LNET_PATH, "stats");
                if (read_string(file_path, (char *) string, sizeof(string))
                    != SUCCESS)
                        return NULL;

                sscanf((char *) string,
                       "%u %u %u %u %u %u %u %llu %llu %llu %llu",
                       &i[0], &i[1], &i[2], &i[3], &i[4], &i[5], &i[6],
                       &ull[0], &ull[1], &ull[2], &ull[3]);

                next_update = current + (LNET_CHECK_INTERVAL * 1000);
        }

        if (header_generic(vp, name, length, exact, var_len, write_method)
            == MATCH_FAILED)
                return NULL;

        switch (vp->magic) {
        case LNETMSGSALLOC:
                *var_len = sizeof(c32);
                c32 = i[0];
                return (unsigned char *) &c32;
        case LNETMSGSMAX:
                *var_len = sizeof(c32);
                c32 = i[1];
                return (unsigned char *) &c32;
        case LNETERRORS:
                *var_len = sizeof(c32);
                c32 = i[2];
                return (unsigned char *) &c32;
        case LNETSENDCOUNT:
                *var_len = sizeof(c32);
                c32 = i[3];
                return (unsigned char *) &c32;
        case LNETRECVCOUNT:
                *var_len = sizeof(c32);
                c32 = i[4];
                return (unsigned char *) &c32;
        case LNETROUTECOUNT:
                *var_len = sizeof(c32);
                c32 = i[5];
                return (unsigned char *) &c32;
        case LNETDROPCOUNT:
                *var_len = sizeof(c32);
                c32 = i[6];
                return (unsigned char *) &c32;
        case LNETSENDBYTES:
                convert_ull(&c64, ull[0], var_len);
                return (unsigned char *) &c64;
        case LNETRECVBYTES:
                convert_ull(&c64, ull[1], var_len);
                return (unsigned char *) &c64;
        case LNETROUTEBYTES:
                convert_ull(&c64, ull[2], var_len);
                return (unsigned char *) &c64;
        case LNETDROPBYTES:
                convert_ull(&c64, ull[3], var_len);
                return (unsigned char *) &c64;
        default:
                return NULL;
        }
}

/*****************************************************************************
 * Function: var_mdsNbSampledReq
 *
 ****************************************************************************/
unsigned char *
var_mdsNbSampledReq(struct variable *vp,
            oid     *name,
            size_t  *length,
            int     exact,
            size_t  *var_len,
            WriteMethod **write_method)
{
  unsigned long long nb_sample=0,min=0,max=0,sum=0,sum_square=0;
  static counter64 c64;

  if (header_generic(vp,name,length,exact,var_len,write_method)
                                  == MATCH_FAILED )
    return NULL;

  if( mds_stats_values(STR_REQ_WAITIME,&nb_sample,&min,&max,&sum,&sum_square) == ERROR) return NULL;

  c64.low = (u_long) (0x0FFFFFFFF & nb_sample);
  nb_sample >>= 32;
  c64.high = (u_long) (0x0FFFFFFFF & nb_sample);

  *var_len = sizeof(c64);
  return (unsigned char *) &c64;
}


/*****************************************************************************
 * Function: write_sysStatus
 *
 ****************************************************************************/
int
write_sysStatus(int      action,
            u_char   *var_val,
            u_char   var_val_type,
            size_t   var_val_len,
            u_char   *statP,
            oid      *name,
            size_t   name_len)
{
  static long *long_ret;
  int new_value;



  switch ( action ) {
        case RESERVE1:
          if (var_val_type != ASN_INTEGER){
              fprintf(stderr, "write to sysStatus not ASN_INTEGER\n");
              return SNMP_ERR_WRONGTYPE;
          }
          if (var_val_len > sizeof(long_ret)){
              fprintf(stderr,"write to sysStatus: bad length\n");
              return SNMP_ERR_WRONGLENGTH;
          }
          if ((*var_val != ONLINE) &&
              (*var_val !=  OFFLINE) &&
              (*var_val !=  RESTART)){
              report("%s %s:line %d %s", __FILE__, __FUNCTION__, __LINE__,
                     "sysStatus value is invalid.");
              return SNMP_ERR_WRONGVALUE;
          }
          break;


        case RESERVE2:
          long_ret = (long *) var_val;


          break;


        case FREE:
             /* Release any resources that have been allocated */
          break;


        case ACTION:
             /* The variable has been stored in long_ret for
             you to use, and you have just been asked to do something with
             it.  Note that anything done here must be reversable in the UNDO case */
          new_value = *(int *) var_val;
          switch (new_value) {
            case ONLINE:
                lustrefs_ctrl(ONLINE);
                break;

            case OFFLINE:
                lustrefs_ctrl(OFFLINE);
                break;

            case RESTART:
                lustrefs_ctrl(RESTART);
                break;

            default:
                break;
          }
          break;


        case UNDO:
             /* Back out any changes made in the ACTION case */
          break;


        case COMMIT:
             /* Things are working well, so it's now safe to make the change
             permanently.  Make sure that anything done here can't fail! */
          break;
  }
  return SNMP_ERR_NOERROR;
}
