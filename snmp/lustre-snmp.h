/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2005 Cluster File Systems, Inc.
 *   Author: PJ Kirner <pjkirner@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef LUSTRE_SNMP_H
#define LUSTRE_SNMP_H

#include "lustre-snmp-util.h"

config_require(util_funcs)
config_add_mib(LUSTRE-MIB)
config_require(lustre/cfs_util)
config_require(lustre/cfs_trap)

/* function prototypes */
void   init_cfsNetSNMPPlugin(void);
FindVarMethod var_clusterFileSystems;
FindVarMethod var_osdTable;
FindVarMethod var_oscTable;
FindVarMethod var_mdsTable;
FindVarMethod var_mdcTable;
FindVarMethod var_cliTable;
FindVarMethod var_ldlmTable;
FindVarMethod var_lovTable;
FindVarMethod var_mdsNbSampledReq;
WriteMethod write_sysStatus;

#endif /* LUSTRE_SNMP_H */
