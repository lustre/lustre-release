/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *     alternatives
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 or (at your discretion) any later version.
 * (LGPL) version 2.1 accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * LGPL HEADER END
 */
/*
 *
 * lustre/utils/lustreapi_internal.h
 *
 */
/*
 *
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 * Author: JC Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 * Author: Thomas Leibovici <thomas.leibovici@cea.fr>
 */

#ifndef _LUSTREAPI_INTERNAL_H_
#define _LUSTREAPI_INTERNAL_H_

#define WANT_PATH   0x1
#define WANT_FSNAME 0x2
#define WANT_FD     0x4
#define WANT_INDEX  0x8
#define WANT_ERROR  0x10
int get_root_path(int want, char *fsname, int *outfd, char *path, int index);
int root_ioctl(const char *mdtname, int opc, void *data, int *mdtidxp,
	       int want_error);


#endif /* _LUSTREAPI_INTERNAL_H_ */
