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
 * snmp/lustre-snmp.h
 *
 * Author: PJ Kirner <pjkirner@clusterfs.com>
 */

#ifndef LUSTRE_SNMP_H
#define LUSTRE_SNMP_H

#include "lustre-snmp-util.h"
#include "lustre-snmp-trap.h"

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
FindVarMethod var_lnetInformation;
FindVarMethod var_mdsNbSampledReq;
WriteMethod write_sysStatus;

#endif /* LUSTRE_SNMP_H */
