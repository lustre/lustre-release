/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   Author: Peter J. Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Robert Read <rread@clusterfs.com> 
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
 *
 */
#ifndef _OBDCTL_H_
#define _OBDCTL_H_

int do_disconnect(char *func, int verbose);
int obd_initialize(int argc, char **argv);
void obd_cleanup(int argc, char **argv);

int jt_opt_device(int argc, char **argv);
int jt_opt_threads(int argc, char **argv);

int jt_obd_device(int argc, char **argv);
int jt_obd_connect(int argc, char **argv);
int jt_obd_disconnect(int argc, char **argv);
int jt_obd_detach(int argc, char **argv);
int jt_obd_cleanup(int argc, char **argv);
int jt_obd_newdev(int argc, char **argv);
int jt_obd_list(int argc, char **argv);
int jt_obd_attach(int argc, char **argv);
int jt_obd_name2dev(int argc, char **argv);
int jt_obd_setup(int argc, char **argv);
int jt_obd_create(int argc, char **argv);
int jt_obd_setattr(int argc, char **argv);
int jt_obd_destroy(int argc, char **argv);
int jt_obd_getattr(int argc, char **argv);
int jt_obd_test_getattr(int argc, char **argv);
int jt_obd_test_brw(int argc, char **argv);
int jt_obd_lov_setconfig(int argc, char **argv);
int jt_obd_lov_getconfig(int argc, char **argv);
int jt_obd_test_ldlm(int argc, char **argv);
int jt_obd_ldlm_regress_start(int argc, char **argv);
int jt_obd_ldlm_regress_stop(int argc, char **argv);
int jt_obd_dump_ldlm(int argc, char **argv);
int jt_obd_lov_set_osc_active(int argc, char **argv);
int jt_obd_newconn(int argc, char **argv);
int jt_obd_failconn(int argc, char **argv);
int jt_obd_mdc_lookup(int argc, char **argv);
int jt_get_version(int argc, char **argv);

#endif
