/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 */
#ifndef _MOUNT_UTILS_H_
#define _MOUNT_UTILS_H_

#include <lustre_disk.h>

void fatal(void);
int run_command(char *, int);
int get_mountdata(char *, struct lustre_disk_data *);
void register_service_tags(char *, char *, char *);

#endif
