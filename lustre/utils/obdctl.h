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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _OBDCTL_H_
#define _OBDCTL_H_

#define MAX_IOC_BUFLEN 8192

/* ptlctl.a */
int ptl_initialize(int argc, char **argv);
int jt_ptl_network(int argc, char **argv);
int jt_ptl_list_nids(int argc, char **argv);
int jt_ptl_which_nid(int argc, char **argv);
int jt_ptl_print_interfaces(int argc, char **argv);
int jt_ptl_add_interface(int argc, char **argv);
int jt_ptl_del_interface(int argc, char **argv);
int jt_ptl_print_peers(int argc, char **argv);
int jt_ptl_add_peer(int argc, char **argv);
int jt_ptl_del_peer(int argc, char **argv);
int jt_ptl_print_connections(int argc, char **argv);
int jt_ptl_disconnect(int argc, char **argv);
int jt_ptl_push_connection(int argc, char **argv);
int jt_ptl_ping(int argc, char **argv);
int jt_ptl_mynid(int argc, char **argv);
int jt_ptl_add_uuid(int argc, char **argv);
int jt_ptl_add_uuid_old(int argc, char **argv); /* backwards compatibility  */
int jt_ptl_close_uuid(int argc, char **argv);
int jt_ptl_del_uuid(int argc, char **argv);
int jt_ptl_add_route(int argc, char **argv);
int jt_ptl_del_route(int argc, char **argv);
int jt_ptl_notify_router(int argc, char **argv);
int jt_ptl_print_routes(int argc, char **argv);
int jt_ptl_fail_nid(int argc, char **argv);
int jt_ptl_testprotocompat(int argc, char **argv);
int jt_ptl_drop_add(int argc, char **argv);
int jt_ptl_drop_del(int argc, char **argv);
int jt_ptl_drop_reset(int argc, char **argv);
int jt_ptl_drop_list(int argc, char **argv);
int jt_ptl_delay_add(int argc, char **argv);
int jt_ptl_delay_del(int argc, char **argv);
int jt_ptl_delay_reset(int argc, char **argv);
int jt_ptl_delay_list(int argc, char **argv);

/* debug.c */
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

/* obd.c */
int do_disconnect(char *func, int verbose);
int obd_initialize(int argc, char **argv);
void obd_finalize(int argc, char **argv);


int jt_opt_device(int argc, char **argv);
int jt_opt_threads(int argc, char **argv);
int jt_opt_net(int argc, char **argv);

int jt_obd_get_device();
int jt_obd_device(int argc, char **argv);
int jt_obd_detach(int argc, char **argv);
int jt_obd_cleanup(int argc, char **argv);
int jt_obd_no_transno(int argc, char **argv);
int jt_obd_set_readonly(int argc, char **argv);
int jt_obd_abort_recovery(int argc, char **argv);
int jt_obd_list(int argc, char **argv);
int jt_obd_create(int argc, char **argv);
int jt_obd_test_create(int argc, char **argv);
int jt_obd_test_mkdir(int argc, char **argv);
int jt_obd_test_destroy(int argc, char **argv);
int jt_obd_test_rmdir(int argc, char **argv);
int jt_obd_test_lookup(int argc, char **argv);
int jt_obd_test_setxattr(int argc, char **argv);
int jt_obd_test_md_getattr(int argc, char **argv);

int jt_obd_setattr(int argc, char **argv);
int jt_obd_test_setattr(int argc, char **argv);
int jt_obd_destroy(int argc, char **argv);
int jt_obd_getattr(int argc, char **argv);
int jt_obd_test_getattr(int argc, char **argv);
int jt_obd_test_brw(int argc, char **argv);
int jt_obd_lov_getconfig(int argc, char **argv);
int jt_obd_test_ldlm(int argc, char **argv);
int jt_obd_ldlm_regress_start(int argc, char **argv);
int jt_obd_ldlm_regress_stop(int argc, char **argv);
int jt_replace_nids(int arc, char **argv);
int jt_obd_activate(int argc, char **argv);
int jt_obd_deactivate(int argc, char **argv);
int jt_obd_recover(int argc, char **argv);
int jt_obd_mdc_lookup(int argc, char **argv);
int jt_get_version(int argc, char **argv);
int jt_get_obj_version(int argc, char **argv);

int jt_llog_catlist(int argc, char **argv);
int jt_llog_info(int argc, char **argv);
int jt_llog_print(int argc, char **argv);
int jt_llog_cancel(int argc, char **argv);
int jt_llog_remove(int argc, char **argv);
int jt_llog_check(int argc, char **argv);

struct lustre_cfg;
int lcfg_ioctl(char * func, int dev_id, struct lustre_cfg *lcfg);
int lcfg_mgs_ioctl(char *func, int dev_id, struct lustre_cfg *lcfg);
int parse_devname(char *func, char *name);
char *jt_cmdname(char *func);


/* lustre_cfg.c */
int lcfg_set_devname(char *name);
char *lcfg_get_devname(void);
int jt_lcfg_device(int argc, char **argv);
int jt_lcfg_newdev(int argc, char **argv);
int jt_lcfg_attach(int argc, char **argv);
int jt_lcfg_setup(int argc, char **argv);
int jt_lcfg_add_uuid(int argc, char **argv);
int jt_lcfg_del_uuid(int argc, char **argv);
int jt_lcfg_del_mount_option(int argc, char **argv);
int jt_lcfg_set_timeout(int argc, char **argv);
int jt_lcfg_add_conn(int argc, char **argv);
int jt_lcfg_del_conn(int argc, char **argv);
int jt_lcfg_param(int argc, char **argv);
int jt_lcfg_mgsparam(int argc, char **argv);
int jt_lcfg_getparam(int argc, char **argv);
int jt_lcfg_setparam(int argc, char **argv);
int jt_lcfg_listparam(int argc, char **argv);

int jt_blockdev_attach(int argc, char **argv);
int jt_blockdev_detach(int argc, char **argv);
int jt_blockdev_info(int argc, char **argv);

int jt_pool_cmd(int argc, char **argv);
int jt_nodemap_activate(int argc, char **argv);
int jt_nodemap_add(int argc, char **argv);
int jt_nodemap_del(int argc, char **argv);
int jt_nodemap_modify(int argc, char **argv);
int jt_nodemap_add_range(int argc, char **argv);
int jt_nodemap_test_nid(int argc, char **argv);
int jt_nodemap_del_range(int argc, char **argv);
int jt_nodemap_add_idmap(int argc, char **argv);
int jt_nodemap_del_idmap(int argc, char **argv);
int jt_nodemap_test_id(int argc, char **argv);
int jt_nodemap_info(int argc, char **argv);
int jt_changelog_register(int argc, char **argv);
int jt_changelog_deregister(int argc, char **argv);

/* lustre_lfsck.c */
int jt_lfsck_start(int argc, char **argv);
int jt_lfsck_stop(int argc, char **argv);
int jt_lfsck_query(int argc, char **argv);

#endif
