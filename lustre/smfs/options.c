/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/options.c
 *  Lustre filesystem abstraction routines
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_SM

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_smfs.h>
#include <linux/lustre_fsfilt.h>
#include "smfs_internal.h"

static struct list_head option_list;
static char *options = NULL;
static char *opt_left = NULL;

int init_option(char *data)
{
        INIT_LIST_HEAD(&option_list);
        OBD_ALLOC(options, strlen(data) + 1);
        if (!options) {
                CERROR("Can not allocate memory \n");
                return -ENOMEM;
        }
        memcpy(options, data, strlen(data));
        opt_left = options;
        return 0;
}

/*cleanup options*/
void cleanup_option(void)
{
        struct option *option;
        while (!list_empty(&option_list)) {
                option = list_entry(option_list.next, struct option, list);
                list_del(&option->list);
                OBD_FREE(option->opt, strlen(option->opt) + 1);
                if (option->value)
                        OBD_FREE(option->value, strlen(option->value) + 1);
                OBD_FREE(option, sizeof(struct option));
        }
        OBD_FREE(options, strlen(options) + 1);
}

int get_opt(struct option **option, char **pos)
{
        char *name, *value, *left, *tmp;
        struct option *tmp_opt;
        int length = 0;

        *pos = opt_left;

        if (!*opt_left)
                return -ENODATA;
        
        left = strchr(opt_left, ',');
        if (left == opt_left)
                return -EINVAL;
        if (!left)
                left = opt_left + strlen(opt_left);

        OBD_ALLOC(tmp_opt, sizeof(struct option));
        tmp_opt->opt = NULL;
        tmp_opt->value = NULL;

        tmp = opt_left;
        while(tmp != left && *tmp != '=') {
                length++;
                tmp++;
        }
        OBD_ALLOC(name, length + 1);
        tmp_opt->opt = name;
        while (opt_left != tmp) *name++ = *opt_left++;

        if (*tmp == '=') {
                /*this option has value*/
                opt_left ++; /*after '='*/
                if (left == opt_left) {
                        OBD_FREE(tmp_opt->opt, strlen(tmp_opt->opt) + 1);
                        OBD_FREE(tmp_opt, sizeof(struct option));
                        opt_left = *pos;
                        return -EINVAL;
                }
                length = left - opt_left;
                OBD_ALLOC(value, length + 1);
                if (!value) {
                        OBD_FREE(tmp_opt->opt, strlen(tmp_opt->opt) + 1);
                        OBD_FREE(tmp_opt, sizeof(struct option));
                        return -ENOMEM;
                }
                tmp_opt->value = value;
                while (opt_left != left) *value++ = *opt_left++;
        }
        list_add(&tmp_opt->list, &option_list);
        if (*opt_left == ',') opt_left ++; /*after ','*/
        *option = tmp_opt;
        printk("Option: %s=%s\n", tmp_opt->opt, tmp_opt->value);
        return 0;
}

char *smfs_options(char *data, char **devstr, char **namestr,
                   char *opts, int *flags)  
{
        struct option *opt_value = NULL;
        char   *pos;
        
        LASSERT(opts && flags);
        init_option(data);
        
        while (!(get_opt(&opt_value, &pos))) {
                if (!strcmp(opt_value->opt, "dev")) {
                        if (devstr != NULL)
                                *devstr = opt_value->value;
                } else if (!strcmp(opt_value->opt, "type")) {
                        if (namestr != NULL)
                                *namestr = opt_value->value;
                } else if (!strcmp(opt_value->opt, "kml")) {
                        *flags |= SM_DO_REC;
                } else if (!strcmp(opt_value->opt, "cache")) {
                        *flags |= SM_CACHE_HOOK;
                } else if (!strcmp(opt_value->opt, "snap")) {
                        *flags |= SM_DO_COW;
                } else if (!strcmp(opt_value->opt, "options")) {
                        if (strlen(opts) == 0)
                                sprintf((char *)opts + strlen(opts), "%s",
                                        opt_value->value);
                        else  
                                sprintf((char *)opts + strlen(opts), ",%s",
                                        opt_value->value);
                } else {
                        /* FIXME-WANGDI: how about the opt_value->value */
                        if (strlen(opts) == 0)
                                sprintf((char *)opts + strlen(opts), "%s",
                                        opt_value->opt);
                        else  
                                sprintf((char *)opts + strlen(opts), ",%s",
                                        opt_value->opt);
                }
        }
        return pos;
}

