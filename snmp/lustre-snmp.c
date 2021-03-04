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
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
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

#include <libcfs/util/param.h>

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
	/* systemInformation 2.1.1. */
	{
		.magic		= SYSVERSION,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_clusterFileSystems,
		.namelen	= 4,
		.name		= { 2, 1, 1, 1 }
	},
	{
		.magic		= SYSKERNELVERSION,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_clusterFileSystems,
		.namelen	= 4,
		.name		= { 2, 1, 1, 2 }
	},
	{
		.magic		= SYSHEALTHCHECK,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_clusterFileSystems,
		.namelen	= 4,
		.name		= { 2, 1, 1, 3 }
	},
	{
		.magic		= SYSSTATUS,
		.type		= ASN_INTEGER,
		.acl		= RWRITE,
		.findVar	= var_clusterFileSystems,
		.namelen	= 4,
		.name		= { 2, 1, 1, 4 }
	},

	/* objectStorageTargets 2.1.2 */
	{
		.magic		= OSDNUMBER,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_clusterFileSystems,
		.namelen	= 4,
		.name		= { 2, 1, 2, 1 }
	},

	/* objectStorageTargets.osdTable.osdEntry 2.1.2.2.1 */
	{
		.magic		= OSDUUID,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_osdTable,
		.namelen	= 6,
		.name		= { 2, 1, 2, 2, 1, 2 }
	},
	{
		.magic		= OSDCOMMONNAME,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_osdTable,
		.namelen	= 6,
		.name		= { 2, 1, 2, 2, 1, 3 }
	},
	{
		.magic		= OSDCAPACITY,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_osdTable,
		.namelen	= 6,
		.name		= { 2, 1, 2, 2, 1, 4 }
	},
	{
		.magic		= OSDFREECAPACITY,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_osdTable,
		.namelen	= 6,
		.name		= { 2, 1, 2, 2, 1, 5 }
	},
	{
		.magic		= OSDOBJECTS,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_osdTable,
		.namelen	= 6,
		.name		= { 2, 1, 2, 2, 1, 6 }
	},
	{
		.magic		= OSDFREEOBJECTS,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_osdTable,
		.namelen	= 6,
		.name		= { 2, 1, 2, 2, 1, 7 }
	},

	/* objectStorageClients 2.1.3 */
	{
		.magic		= OSCNUMBER,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_clusterFileSystems,
		.namelen	= 4,
		.name		= { 2, 1, 3, 1 }
	},

	/* objectStorageClients.oscTable.oscEntry 2.1.3.2.1 */
	{
		.magic		= OSCUUID,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_oscTable,
		.namelen	= 6,
		.name		= { 2, 1, 3, 2, 1, 2 }
	},
	{
		.magic		= OSCCOMMONNAME,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_oscTable,
		.namelen	= 6,
		.name		= { 2, 1, 3, 2, 1, 3 }
	},
	{
		.magic		= OSCOSTSERVERUUID,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_oscTable,
		.namelen	= 6,
		.name		= { 2, 1, 3, 2, 1, 4 }
	},
	{
		.magic		= OSCCAPACITY,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_oscTable,
		.namelen	= 6,
		.name		= { 2, 1, 3, 2, 1, 5 }
	},
	{
		.magic		= OSCFREECAPACITY,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_oscTable,
		.namelen	= 6,
		.name		= { 2, 1, 3, 2, 1, 6 }
	},
	{
		.magic		= OSCOBJECTS,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_oscTable,
		.namelen	= 6,
		.name		= { 2, 1, 3, 2, 1, 7 }
	},
	{
		.magic		= OSCFREEOBJECTS,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_oscTable,
		.namelen	= 6,
		.name		= { 2, 1, 3, 2, 1, 8 }
	},


	/* metaDataServers 2.1.4 */
	{
		.magic		= MDDNUMBER,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_clusterFileSystems,
		.namelen	= 4,
		.name		= { 2, 1, 4, 1 }
	},

	/* metaDataServers.mddTable.mddEntry 2.1.4.2.1 */
	{
		.magic		= MDDUUID,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_mdsTable,
		.namelen	= 6,
		.name		= { 2, 1, 4, 2, 1, 2 }
	},
	{
		.magic		= MDDCOMMONNAME,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_mdsTable,
		.namelen	= 6,
		.name		= { 2, 1, 4, 2, 1, 3 }
	},
	{
		.magic		= MDDCAPACITY,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_mdsTable,
		.namelen	= 6,
		.name		= { 2, 1, 4, 2, 1, 4 }
	},
	{
		.magic		= MDDFREECAPACITY,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_mdsTable,
		.namelen	= 6,
		.name		= { 2, 1, 4, 2, 1, 5 }
	},
	{
		.magic		= MDDFILES,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_mdsTable,
		.namelen	= 6,
		.name		= { 2, 1, 4, 2, 1, 6 }
	},
	{
		.magic		= MDDFREEFILES,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_mdsTable,
		.namelen	= 6,
		.name		= { 2, 1, 4, 2, 1, 7 }
	},
	{
		.magic		= MDSNBSAMPLEDREQ,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_mdsNbSampledReq,
		.namelen	= 4,
		.name		= { 2, 1, 4, 3 }
	},

	/* metaDataClients 2.1.5 */
	{
		.magic		= MDCNUMBER,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_clusterFileSystems,
		.namelen	= 4,
		.name		= { 2, 1, 5, 1 }
	},

	/* metaDataClients.mdcTable.mdcEntry 2.1.5.2.1 */
	{
		.magic		= MDCUUID,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_mdcTable,
		.namelen	= 6,
		.name		= { 2, 1, 5, 2, 1, 2 }
	},
	{
		.magic		= MDCCOMMONNAME,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_mdcTable,
		.namelen	= 6,
		.name		= { 2, 1, 5, 2, 1, 3 }
	},
	{
		.magic		= MDCMDSSERVERUUID,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_mdcTable,
		.namelen	= 6,
		.name		= { 2, 1, 5, 2, 1, 4 }
	},
	{
		.magic		= MDCCAPACITY,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_mdcTable,
		.namelen	= 6,
		.name		= { 2, 1, 5, 2, 1, 5 }
	},
	{
		.magic		= MDCFREECAPACITY,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_mdcTable,
		.namelen	= 6,
		.name		= { 2, 1, 5, 2, 1, 6 }
	},
	{
		.magic		= MDCOBJECTS,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_mdcTable,
		.namelen	= 6,
		.name		= { 2, 1, 5, 2, 1, 7 }
	},
	{
		.magic		= MDCFREEOBJECTS,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_mdcTable,
		.namelen	= 6,
		.name		= { 2, 1, 5, 2, 1, 8 }
	},

	/* lustreClients 2.1.6 */
	{
		.magic		= CLIMOUNTNUMBER,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_clusterFileSystems,
		.namelen	= 4,
		.name		= { 2, 1, 6, 1 }
	},

	/* lustreClients.cliMountTable.cliMountEntry 2.1.6.2.1 */
	{
		.magic		= CLIUUID,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_cliTable,
		.namelen	= 6,
		.name		= { 2, 1, 6, 2, 1, 2 }
	},
	{
		.magic		= CLICOMMONNAME,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_cliTable,
		.namelen	= 6,
		.name		= { 2, 1, 6, 2, 1, 3 }
	},
	{
		.magic		= CLIMDCUUID,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_cliTable,
		.namelen	= 6,
		.name		= { 2, 1, 6, 2, 1, 4 }
	},
	{
		.magic		= CLIMDCCOMMONNAME,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_cliTable,
		.namelen	= 6,
		.name		= { 2, 1, 6, 2, 1, 5 }
	},
	{
		.magic		= CLIUSESLOV,
		.type		= ASN_INTEGER,
		.acl		= RONLY,
		.findVar	= var_cliTable,
		.namelen	= 6,
		.name		= { 2, 1, 6, 2, 1, 6 }
	},
	{
		.magic		= CLILOVUUID,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_cliTable,
		.namelen	= 6,
		.name		= { 2, 1, 6, 2, 1, 7 }
	},
	{
		.magic		= CLILOVCOMMONNAME,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_cliTable,
		.namelen	= 6,
		.name		= { 2, 1, 6, 2, 1, 8 }
	},

	/* logicalObjectVolume 2.1.7 */
	{
		.magic		= LOVNUMBER,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_clusterFileSystems,
		.namelen	= 4,
		.name		= { 2, 1, 7, 1 }
	},

	/* logicalObjectVolume.osdTable.lovTable 2.1.7.2.1 */
	{
		.magic		= LOVUUID,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_lovTable,
		.namelen	= 6,
		.name		= { 2, 1, 7, 2, 1, 2 }
	},
	{
		.magic		= LOVCOMMONNAME,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_lovTable,
		.namelen	= 6,
		.name		= { 2, 1, 7, 2, 1, 3 }
	},
	{
		.magic		= LOVNUMOBD,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_lovTable,
		.namelen	= 6,
		.name		= { 2, 1, 7, 2, 1, 4 }
	},
	{
		.magic		= LOVNUMACTIVEOBD,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_lovTable,
		.namelen	= 6,
		.name		= { 2, 1, 7, 2, 1, 5 }
	},
	{
		.magic		= LOVCAPACITY,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_lovTable,
		.namelen	= 6,
		.name		= { 2, 1, 7, 2, 1, 6 }
	},
	{
		.magic		= LOVFREECAPACITY,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_lovTable,
		.namelen	= 6,
		.name		= { 2, 1, 7, 2, 1, 7 }
	},
	{
		.magic		= LOVFILES,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_lovTable,
		.namelen	= 6,
		.name		= { 2, 1, 7, 2, 1, 8 }
	},
	{
		.magic		= LOVFREEFILES,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_lovTable,
		.namelen	= 6,
		.name		= { 2, 1, 7, 2, 1, 9 }
	},
	{
		.magic		= LOVSTRIPECOUNT,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_lovTable,
		.namelen	= 6,
		.name		= { 2, 1, 7, 2, 1, 10}
	},
	{
		.magic		= LOVSTRIPEOFFSET,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_lovTable,
		.namelen	= 6,
		.name		= { 2, 1, 7, 2, 1, 11}
	},
	{
		.magic		= LOVSTRIPESIZE,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_lovTable,
		.namelen	= 6,
		.name		= { 2, 1, 7, 2, 1, 12}
	},
	{
		.magic		= LOVSTRIPETYPE,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_lovTable,
		.namelen	= 6,
		.name		= { 2, 1, 7, 2, 1, 13}
	},

	/* lustreLDLM 2.1.8 */
	{
		.magic		= LDLMNUMBER,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_clusterFileSystems,
		.namelen	= 4,
		.name		= { 2, 1, 8, 1 }
	},

	/* lustreLDLM.ldlmTable.ldlmEntry 2.1.8.2.1 */
	{
		.magic		= LDLMNAMESPACE,
		.type		= ASN_OCTET_STR,
		.acl		= RONLY,
		.findVar	= var_ldlmTable,
		.namelen	= 6,
		.name		= { 2, 1, 8, 2, 1, 2 }
	},
	{
		.magic		= LDLMLOCKCOUNT,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_ldlmTable,
		.namelen	= 6,
		.name		= { 2, 1, 8, 2, 1, 3 }
	},
	{
		.magic		= LDLMUNUSEDLOCKCOUNT,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_ldlmTable,
		.namelen	= 6,
		.name		= { 2, 1, 8, 2, 1, 4 }
	},
	{
		.magic		= LDLMRESOURCECOUNT,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_ldlmTable,
		.namelen	= 6,
		.name		= { 2, 1, 8, 2, 1, 5 }
	},

	/* lnetInformation 2.1.9 */
	{
		.magic		= LNETMSGSALLOC,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_lnetInformation,
		.namelen	= 4,
		.name		= { 2, 1, 9, 1 }
	},
	{
		.magic		= LNETMSGSMAX,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_lnetInformation,
		.namelen	= 4,
		.name		= { 2, 1, 9, 2 }
	},
	{
		.magic		= LNETERRORS,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_lnetInformation,
		.namelen	= 4,
		.name		= { 2, 1, 9, 3 }
	},
	{
		.magic		= LNETSENDCOUNT,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_lnetInformation,
		.namelen	= 4,
		.name		= { 2, 1, 9, 4 }
	},
	{
		.magic		= LNETRECVCOUNT,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_lnetInformation,
		.namelen	= 4,
		.name		= { 2, 1, 9, 5 }
	},
	{
		.magic		= LNETROUTECOUNT,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_lnetInformation,
		.namelen	= 4,
		.name		= { 2, 1, 9, 6 }
	},
	{
		.magic		= LNETDROPCOUNT,
		.type		= ASN_UNSIGNED,
		.acl		= RONLY,
		.findVar	= var_lnetInformation,
		.namelen	= 4,
		.name		= { 2, 1, 9, 7 }
	},
	{
		.magic		= LNETSENDBYTES,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_lnetInformation,
		.namelen	= 4,
		.name		= { 2, 1, 9, 8 }
	},
	{
		.magic		= LNETRECVBYTES,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_lnetInformation,
		.namelen	= 4,
		.name		= { 2, 1, 9, 9 }
	},
	{
		.magic		= LNETROUTEBYTES,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_lnetInformation,
		.namelen	= 4,
		.name		= { 2, 1, 9, 10 }
	},
	{
		.magic		= LNETDROPBYTES,
		.type		= ASN_COUNTER64,
		.acl		= RONLY,
		.findVar	= var_lnetInformation,
		.namelen	= 4,
		.name		= { 2, 1, 9, 11 }
	},
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
  glob_t path;
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
        if (cfs_get_param_paths(&path, "version") != 0)
            return NULL;
        if( SUCCESS != read_string(path.gl_pathv[0], (char *)string,sizeof(string))){
            cfs_free_param_data(&path);
            return NULL;
        }
        cfs_free_param_data(&path);
        *var_len = strlen((char *)string);
        return (unsigned char *) string;

    case SYSKERNELVERSION:
        if (cfs_get_param_paths(&path, "kernel_version") != 0)
            return NULL;
        if( SUCCESS != read_string(path.gl_pathv[0], (char *)string,sizeof(string))){
            cfs_free_param_data(&path);
            return NULL;
        }
        cfs_free_param_data(&path);
        *var_len = strlen((char *)string);
        return (unsigned char *) string;

    case SYSHEALTHCHECK:
        if (cfs_get_param_paths(&path, "health_check") != 0)
            return NULL;
        if( SUCCESS != read_string(path.gl_pathv[0], (char *)string,sizeof(string))){
            cfs_free_param_data(&path);
            return NULL;
        }
        cfs_free_param_data(&path);
        *var_len = strlen((char*)string);
        return (unsigned char *) string;

    case SYSSTATUS:
        *write_method = write_sysStatus;
        long_ret = (long) get_sysstatus();
        if (long_ret != ERROR)
          return (unsigned char *) &long_ret;
        return NULL;
                      
    case OSDNUMBER:
        if (cfs_get_param_paths(&path, "obdfilter") != 0)
            return NULL;
        if( 0 == (dir_list = get_file_list(path.gl_pathv[0], DIR_TYPE, &num))){
            cfs_free_param_data(&path);
            return NULL;
        }
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",path.gl_pathv[0],num));
        cfs_free_param_data(&path);
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    case OSCNUMBER:
        if (cfs_get_param_paths(&path, "osc") != 0)
            return NULL;
        if( 0 == (dir_list = get_file_list(path.gl_pathv[0], DIR_TYPE, &num))){
            cfs_free_param_data(&path);
            return NULL;
        }
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",path.gl_pathv[0],num));
        cfs_free_param_data(&path);
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    case MDDNUMBER:
        if (cfs_get_param_paths(&path, "mds") != 0)
            return NULL;
        if( 0 == (dir_list = get_file_list(path.gl_pathv[0], DIR_TYPE, &num))){
            cfs_free_param_data(&path);
            return NULL;
        }
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",path.gl_pathv[0],num));
        cfs_free_param_data(&path);
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    case MDCNUMBER:
        if (cfs_get_param_paths(&path, "mdc") != 0)
            return NULL;
        if( 0 == (dir_list = get_file_list(path.gl_pathv[0], DIR_TYPE, &num))){
            cfs_free_param_data(&path);
            return NULL;
        }
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",path.gl_pathv[0],num));
        cfs_free_param_data(&path);
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    case CLIMOUNTNUMBER:
        if (cfs_get_param_paths(&path, "llite") != 0)
            return NULL;
        if( 0 == (dir_list = get_file_list(path.gl_pathv[0], DIR_TYPE, &num))){
            cfs_free_param_data(&path);
            return NULL;
        }
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",path.gl_pathv[0],num));
        cfs_free_param_data(&path);
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    case LOVNUMBER:
        if (cfs_get_param_paths(&path, "lov") != 0)
            return NULL;
        if( 0 == (dir_list = get_file_list(path.gl_pathv[0], DIR_TYPE, &num))){
            cfs_free_param_data(&path);
            return NULL;
        }
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",path.gl_pathv[0],num));
        cfs_free_param_data(&path);
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    case LDLMNUMBER:
        if (cfs_get_param_paths(&path, "ldlm/namespaces") != 0)
            return NULL;
        if( 0 == (dir_list = get_file_list(path.gl_pathv[0], DIR_TYPE, &num))){
            cfs_free_param_data(&path);
            return NULL;
        }
        DEBUGMSGTL(("lsnmpd","num(%s)=%d\n",path.gl_pathv[0],num));
        cfs_free_param_data(&path);
        ulong_ret =  num;
        free(dir_list);
        return (unsigned char *) &ulong_ret;

    default:
      ERROR_MSG("");
  }
  return NULL;
}

struct oid_table osd_table[] = {
	{
		.magic		= OSDUUID,
		.name		= FILENAME_UUID,
		.fhandler	= oid_table_string_handler
	},
	{
		.magic		= OSDCOMMONNAME,
		.name		= NULL,
		.fhandler	= oid_table_obj_name_handler
	},
	{
		.magic		= OSDCAPACITY,
		.name		= FILENAME_KBYTES_TOTAL,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= OSDFREECAPACITY,
		.name		= FILENAME_KBYTES_FREE,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= OSDOBJECTS,
		.name		= FILENAME_FILES_TOTAL,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= OSDFREEOBJECTS,
		.name		= FILENAME_FILES_FREE,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= 0,
		.name		= NULL,
		.fhandler	= NULL
	} /*End of table*/
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
    unsigned char *table;
    glob_t path;

    if (cfs_get_param_paths(&path, "obdfilter") != 0)
        return NULL;

    table = var_genericTable(vp,name,length,exact,var_len,write_method,
                             path.gl_pathv[0],osd_table);
    cfs_free_param_data(&path);
    return table;
}

struct oid_table osc_table[] = {
	{
		.magic		= OSCUUID,
		.name		= FILENAME_UUID,
		.fhandler	= oid_table_string_handler
	},
	{
		.magic		= OSCCOMMONNAME,
		.name		= NULL,
		.fhandler	= oid_table_obj_name_handler
	},
	{
		.magic		= OSCOSTSERVERUUID,
		.name		= "ost_server_uuid",
		.fhandler	= oid_table_string_handler
	},
	{
		.magic		= OSCCAPACITY,
		.name		= FILENAME_KBYTES_TOTAL,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= OSCFREECAPACITY,
		.name		= FILENAME_KBYTES_FREE,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= OSCOBJECTS,
		.name		= FILENAME_FILES_TOTAL,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= OSCFREEOBJECTS,
		.name		= FILENAME_FILES_FREE,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= 0,
		.name		= NULL,
		.fhandler	= NULL
	} /*End of table*/
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
    unsigned char *table;
    glob_t path;

    if (cfs_get_param_paths(&path, "osc") != 0)
        return NULL;

    table = var_genericTable(vp,name,length,exact,var_len,write_method,
                             path.gl_pathv[0],osd_table);
    cfs_free_param_data(&path);
    return table;
}

struct oid_table mds_table[] = {
	{
		.magic		= MDDUUID,
		.name		= FILENAME_UUID,
		.fhandler	= oid_table_string_handler
	},
	{
		.magic		= MDDCOMMONNAME,
		.name		= NULL,
		.fhandler	= oid_table_obj_name_handler
	},
	{
		.magic		= MDDCAPACITY,
		.name		= FILENAME_KBYTES_TOTAL,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= MDDFREECAPACITY,
		.name		= FILENAME_KBYTES_FREE,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= MDDFILES,
		.name		= FILENAME_FILES_TOTAL,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= MDDFREEFILES,
		.name		= FILENAME_FILES_FREE,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= 0,
		.name		= NULL,
		.fhandler	= NULL
	} /*End of table*/
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
    unsigned char *table;
    glob_t path;

    if (cfs_get_param_paths(&path, "mds") != 0)
        return NULL;

    table = var_genericTable(vp,name,length,exact,var_len,write_method,
                             path.gl_pathv[0],osd_table);
    cfs_free_param_data(&path);
    return table;
}

struct oid_table mdc_table[] = {
	{
		.magic		= MDCUUID,
		.name		= FILENAME_UUID,
		.fhandler	= oid_table_string_handler
	},
	{
		.magic		= MDCCOMMONNAME,
		.name		= NULL,
		.fhandler	= oid_table_obj_name_handler
	},
	{
		.magic		= MDCMDSSERVERUUID,
		.name		= "mds_server_uuid",
		.fhandler	= oid_table_string_handler
	},
	{
		.magic		= MDCCAPACITY,
		.name		= FILENAME_KBYTES_TOTAL,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= MDCFREECAPACITY,
		.name		= FILENAME_KBYTES_FREE,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= MDCOBJECTS,
		.name		= FILENAME_FILES_TOTAL,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= MDCFREEOBJECTS,
		.name		= FILENAME_FILES_FREE,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= 0,
		.name		= NULL,
		.fhandler	= NULL
	} /*End of table*/
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
    unsigned char *table;
    glob_t path;

    if (cfs_get_param_paths(&path, "mdc") != 0)
        return NULL;

    table = var_genericTable(vp,name,length,exact,var_len,write_method,
                             path.gl_pathv[0],osd_table);
    cfs_free_param_data(&path);
    return table;
}

struct oid_table cli_table[] = {
	{
		.magic		= CLIUUID,
		.name		= FILENAME_UUID,
		.fhandler	= oid_table_string_handler
	},
	{
		.magic		= CLICOMMONNAME,
		.name		= NULL,
		.fhandler	= oid_table_obj_name_handler
	},
	{
		.magic		= CLIMDCUUID,
		.name		= "mdc/" FILENAME_UUID,
		.fhandler	= oid_table_string_handler
	},
	{
		.magic		= CLIMDCCOMMONNAME,
		.name		= "mdc/" FILENAME_COMMON_NAME,
		.fhandler	= oid_table_string_handler
	},
	{
		.magic		= CLIUSESLOV,
		.name		= "lov/",
		.fhandler	= oid_table_is_directory_handler
	},
	{
		.magic		= CLILOVUUID,
		.name		= "lov/" FILENAME_UUID,
		.fhandler	= oid_table_string_handler
	},
	{
		.magic		= CLILOVCOMMONNAME,
		.name		= "lov/" FILENAME_COMMON_NAME,
		.fhandler	= oid_table_string_handler
	},
	{
		.magic		= 0,
		.name		= NULL,
		.fhandler	= NULL
	} /*End of table*/
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
    unsigned char *table;
    glob_t path;

    if (cfs_get_param_paths(&path, "llite") != 0)
        return NULL;

    table = var_genericTable(vp,name,length,exact,var_len,write_method,
                             path.gl_pathv[0],osd_table);
    cfs_free_param_data(&path);
    return table;
}

struct oid_table lov_table[] = {
	{
		.magic		= LOVUUID,
		.name		= FILENAME_UUID,
		.fhandler	= oid_table_string_handler
	},
	{
		.magic		= LOVCOMMONNAME,
		.name		= NULL,
		.fhandler	= oid_table_obj_name_handler
	},
	{
		.magic		= LOVNUMOBD,
		.name		= "numobd",
		.fhandler	= oid_table_ulong_handler
	},
	{
		.magic		= LOVNUMACTIVEOBD,
		.name		= "activeobd",
		.fhandler	= oid_table_ulong_handler
	},
	{
		.magic		= LOVCAPACITY,
		.name		= FILENAME_KBYTES_TOTAL,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= LOVFREECAPACITY,
		.name		= FILENAME_KBYTES_FREE,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= LOVFILES,
		.name		= FILENAME_FILES_TOTAL,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= LOVFREEFILES,
		.name		= FILENAME_FILES_FREE,
		.fhandler	= oid_table_c64_kb_handler
	},
	{
		.magic		= LOVSTRIPECOUNT,
		.name		= "stripecount",
		.fhandler	= oid_table_ulong_handler
	},
	{
		.magic		= LOVSTRIPEOFFSET,
		.name		= "stripeoffset",
		.fhandler	= oid_table_ulong_handler
	},
	{
		.magic		= LOVSTRIPESIZE,
		.name		= "stripesize",
		.fhandler	= oid_table_ulong_handler
	},
	{
		.magic		= LOVSTRIPETYPE,
		.name		= "stripetype",
		.fhandler	= oid_table_ulong_handler
	},
	{
		.magic		= 0,
		.name		= NULL,
		.fhandler	= NULL
	} /*End of table*/
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
    unsigned char *table;
    glob_t path;

    if (cfs_get_param_paths(&path, "lov") != 0)
        return NULL;

    table = var_genericTable(vp,name,length,exact,var_len,write_method,
                             path.gl_pathv[0],osd_table);
    cfs_free_param_data(&path);
    return table;
}

struct oid_table ldlm_table[] = {
	{
		.magic		= LDLMNAMESPACE,
		.name		= NULL,
		.fhandler	= oid_table_obj_name_handler
	},
	{
		.magic		= LDLMLOCKCOUNT,
		.name		= "lock_count",
		.fhandler	= oid_table_ulong_handler
	},
	{
		.magic		= LDLMUNUSEDLOCKCOUNT,
		.name		= "lock_unused_count",
		.fhandler	= oid_table_ulong_handler
	},
	{
		.magic		= LDLMRESOURCECOUNT,
		.name		= "resource_count",
		.fhandler	= oid_table_ulong_handler
	},
	{
		.magic		= 0,
		.name		= NULL,
		.fhandler	= NULL
	} /*End of table*/
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
    unsigned char *table;
    glob_t path;

    if (cfs_get_param_paths(&path, "ldlm/namespaces") != 0)
        return NULL;

    table = var_genericTable(vp,name,length,exact,var_len,write_method,
                             path.gl_pathv[0],osd_table);
    cfs_free_param_data(&path);
    return table;
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
        glob_t                    file_path;

        /* Update at most every LNET_STATS_INTERVAL milliseconds */
        gettimeofday(&current_tv, NULL);
        current = current_tv.tv_sec * 1000000 + current_tv.tv_usec;
        if (current >= next_update) {
                if (cfs_get_param_paths(&file_path, "stats") != 0)
                        return NULL;
                if (read_string(file_path.gl_pathv[0], (char *) string, sizeof(string))
                    != SUCCESS) {
                        cfs_free_param_data(&file_path);
                        return NULL;
                }
                cfs_free_param_data(&file_path);

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
