/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/lustre/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * header for libptlctl.a
 */
#ifndef _PTLCTL_H_
#define _PTLCTL_H_

#define PORTALS_DEV_ID 0
#define PORTALS_DEV_PATH "/dev/portals"
#define OBD_DEV_ID 1
#define OBD_DEV_PATH "/dev/obd"

int ptl_name2nal(char *str);
int ptl_parse_nid (ptl_nid_t *nidp, char *str);
char * ptl_nid2str (char *buffer, ptl_nid_t nid);

int ptl_initialize(int argc, char **argv);
int jt_ptl_network(int argc, char **argv);
int jt_ptl_connect(int argc, char **argv);
int jt_ptl_disconnect(int argc, char **argv);
int jt_ptl_push_connection(int argc, char **argv);
int jt_ptl_ping(int argc, char **argv);
int jt_ptl_shownid(int argc, char **argv);
int jt_ptl_mynid(int argc, char **argv);
int jt_ptl_add_uuid(int argc, char **argv);
int jt_ptl_add_uuid_old(int argc, char **argv); /* backwards compatibility  */
int jt_ptl_close_uuid(int argc, char **argv);
int jt_ptl_del_uuid(int argc, char **argv);
int jt_ptl_rxmem (int argc, char **argv);
int jt_ptl_txmem (int argc, char **argv);
int jt_ptl_nagle (int argc, char **argv);
int jt_ptl_add_route (int argc, char **argv);
int jt_ptl_del_route (int argc, char **argv);
int jt_ptl_print_routes (int argc, char **argv);
int jt_ptl_fail_nid (int argc, char **argv);

int dbg_initialize(int argc, char **argv);
int jt_dbg_filter(int argc, char **argv);
int jt_dbg_show(int argc, char **argv);
int jt_dbg_list(int argc, char **argv);
int jt_dbg_debug_kernel(int argc, char **argv);
int jt_dbg_debug_daemon(int argc, char **argv);
int jt_dbg_debug_file(int argc, char **argv);
int jt_dbg_clear_debug_buf(int argc, char **argv);
int jt_dbg_mark_debug_buf(int argc, char **argv);
int jt_dbg_modules(int argc, char **argv);
int jt_dbg_panic(int argc, char **argv);

/* l_ioctl.c */
int register_ioc_dev(int dev_id, const char * dev_name);
void unregister_ioc_dev(int dev_id);
int set_ioctl_dump(char * file);
int l_ioctl(int dev_id, int opc, void *buf);
int parse_dump(char * dump_file, int (*ioc_func)(int dev_id, int opc, void *));
int jt_ioc_dump(int argc, char **argv);

#endif
