/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
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
 *   Author: Hariharan Thantry thantry@users.sourceforge.net
 */
#define EXPORT_SYMTAB
#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/types.h>

#define DEBUG_SUBSYSTEM S_CLASS
#include <linux/lustre_lite.h>
#include <linux/lprocfs_status.h>

#ifdef LPROC_SNMP

#define DEFAULT_MODE 0444
/*
 * Tokenizer array. Change this array to include special
 * characters for string tokenizing
 */
const char tok[] = {'/', '\0'};

/*
 * Externs
 */
extern struct proc_dir_entry proc_root; /* Defined in proc/root.c */

/*
 * Globals
 */
struct proc_dir_entry *proc_lustre_root;
struct proc_dir_entry *proc_lustre_dev_root;
struct proc_dir_entry *proc_lustre_fs_root;

struct proc_dir_entry* lprocfs_mkdir(const char* dname,
                                     struct proc_dir_entry *parent)
{
        struct proc_dir_entry *child_dir_entry;
        child_dir_entry = proc_mkdir(dname, parent);
        if (!child_dir_entry)
                CERROR("lustre: failed to create /proc entry %s\n", dname);
        return child_dir_entry;
}

struct proc_dir_entry* lprocfs_srch(struct proc_dir_entry* head,
                                    const char* name)
{
        struct proc_dir_entry* temp;
        if (!head)
                return NULL;
        temp = head->subdir;
        while (temp != NULL) {
                if (!strcmp(temp->name, name))
                        return temp;
                temp = temp->next;
        }
        return NULL;
}

void lprocfs_remove_all(struct proc_dir_entry* root)
{
        struct proc_dir_entry *temp = root;
        struct proc_dir_entry *rm_entry;
        struct proc_dir_entry *parent = root->parent;

        while (1) {
                while (temp->subdir)
                        temp = temp->subdir;

                rm_entry = temp;
                temp = temp->parent;
                remove_proc_entry(rm_entry->name, rm_entry->parent);
                if (temp == parent) break;
        }
}

#define MAX_STRING_SIZE 100
struct proc_dir_entry* lprocfs_new_dir(struct proc_dir_entry* root,
                                       const char* string, const char* tok)
{
        struct proc_dir_entry* new_root;
        struct proc_dir_entry* temp_entry;
        char temp_string[MAX_STRING_SIZE+1];
        char* my_str;
        char* mover_str;

        strncpy(temp_string, string, MAX_STRING_SIZE);
        temp_string[MAX_STRING_SIZE] = '\0';

        new_root = root;
        mover_str = temp_string;
        while ((my_str = strsep(&mover_str, tok))) {
                if(!*my_str)
                        continue;
                CDEBUG(D_OTHER, "SEARCH= %s\t, ROOT=%s\n", my_str,
                       new_root->name);
                temp_entry = lprocfs_srch(new_root, my_str);
                if (temp_entry == NULL) {
                        CDEBUG(D_OTHER, "Adding: %s\n", my_str);
                        temp_entry = lprocfs_mkdir(my_str, new_root);
                        if (temp_entry == NULL) {
                                CDEBUG(D_OTHER, 
                                       "! Did not create new dir %s !!\n",
                                       my_str);
                                return temp_entry;
                        }
                }
                new_root = temp_entry;
        }
        return new_root;
}

int lprocfs_new_vars(struct proc_dir_entry* root, 
                     struct lprocfs_vars* list,
                     const char* tok, void* data)
{
        struct proc_dir_entry *temp_root;
        struct proc_dir_entry *new_leaf;
        struct proc_dir_entry *new_parent;
        char temp_string[MAX_STRING_SIZE+1];

        if (list == NULL)
                return 0;

        while (list->name) {
                temp_root = lprocfs_new_dir(root, list->name, tok);
                if (temp_root == NULL) {
                        CDEBUG(D_OTHER, "!LProcFS: Mods: No root!");
                        return -ENOMEM;
                }

                /* Convert the last element into a leaf-node */
                strncpy(temp_string, temp_root->name, MAX_STRING_SIZE);
                temp_string[MAX_STRING_SIZE] = '\0';
                new_parent = temp_root->parent;
                remove_proc_entry(temp_root->name, new_parent);
                new_leaf = create_proc_entry(temp_string, DEFAULT_MODE,
                                             new_parent);
                if (new_leaf == NULL) {
                        CERROR("LprocFS: No memory to create /proc entry %s",
                                temp_string);
                        return -ENOMEM;
                }
                new_leaf->read_proc = list->read_fptr;
                new_leaf->write_proc = list->write_fptr;
                if (data)
                        new_leaf->data=data;
                else
                        new_leaf->data=list->data;
                list++;
        }
        return 0;

}
#undef MAX_STRING_SIZE
/*
 *  API implementations
 */
int lprocfs_add_vars(struct proc_dir_entry *root, struct lprocfs_vars *var,
                     void *data)
{
        return lprocfs_new_vars(root, var, tok, data);
}

int lprocfs_reg_obd(struct obd_device *device, struct lprocfs_vars *list,
                    void *data)
{
        struct proc_dir_entry* this_dev_root;
        int retval;
        
        if(lprocfs_srch(device->obd_type->typ_procroot, device->obd_name)){
                CDEBUG(D_OTHER, "Device with name [%s] exists!", 
                                device->obd_name);
                return 0;
        }

        /* Obtain this device root */
        this_dev_root = lprocfs_mkdir(device->obd_name,
                                      device->obd_type->typ_procroot);

        device->obd_proc_entry = this_dev_root;
        retval = lprocfs_add_vars(this_dev_root, list, data);

        return retval;
}

int lprocfs_dereg_obd(struct obd_device* device)
{
        CDEBUG(D_OTHER, "LPROCFS removing device = %s\n", device->obd_name);

        if (device == NULL) {
                CDEBUG(D_OTHER, "! LProcfs:  Null pointer !\n");
                return 0;
        }
        if (device->obd_proc_entry == NULL) {
                CDEBUG(D_OTHER, "! Proc entry non-existent !");
                return 0;
        }
        lprocfs_remove_all(device->obd_proc_entry);
        device->obd_proc_entry = NULL;
        if (device->counters)
                OBD_FREE(device->counters, device->cntr_mem_size);

        return 0;
}

struct proc_dir_entry* lprocfs_reg_mnt(char* mnt_name)
{
        if(lprocfs_srch(proc_lustre_fs_root, mnt_name)){
                CDEBUG(D_OTHER, "Mount with same name exists!");
                return 0;
        }
        return lprocfs_mkdir(mnt_name, proc_lustre_fs_root);
}

int lprocfs_dereg_mnt(struct proc_dir_entry* root)
{
        if(root == NULL){
                CDEBUG(D_OTHER, "Non-existent root!");
                return 0;
        }
        lprocfs_remove_all(root);
        return 0;
}

int lprocfs_reg_class(struct obd_type* type, struct lprocfs_vars* list,
                      void* data)
{
        
        struct proc_dir_entry* root;
        int retval;
        root = lprocfs_mkdir(type->typ_name, proc_lustre_dev_root);
        lprocfs_add_vars(root, list, data);
        type->typ_procroot = root;
        retval = lprocfs_add_vars(root, list, data);
        return retval;
}

int lprocfs_dereg_class(struct obd_type* class)
{
        if(class == NULL){
                CDEBUG(D_OTHER, "Non-existent class",
                       class->typ_name);
                return 0;
        }
        lprocfs_remove_all(class->typ_procroot);
        class->typ_procroot = NULL;
        CDEBUG(D_OTHER, "LPROCFS removed = %s\n", class->typ_name);
        return 0;

}
int lprocfs_reg_main()
{
        proc_lustre_root = lprocfs_mkdir("lustre", &proc_root);
        if (proc_lustre_root == NULL) {
                CERROR(" !! Cannot create /proc/lustre !! \n");
                return -EINVAL;
        }

        proc_lustre_dev_root = lprocfs_mkdir("devices", proc_lustre_root);
        if (proc_lustre_dev_root == NULL) {
                CERROR(" !! Cannot create /proc/lustre/devices !! \n");
                return -EINVAL;
        }
        proc_lustre_fs_root = lprocfs_mkdir("mnt_pnt", proc_lustre_root);

        if (proc_lustre_fs_root == NULL) {
                CERROR(" !! Cannot create /proc/lustre/mnt_pnt !! \n");
                return -EINVAL;
        }

        return 0;
}

int lprocfs_dereg_main()
{
        lprocfs_remove_all(proc_lustre_root);
        proc_lustre_root = NULL;
        proc_lustre_dev_root = NULL;
        proc_lustre_fs_root = NULL;
        return 0;
}


/*
 * Needs to go...
 */
int lprocfs_ll_rd(char *page, char **start, off_t off,
                  int count, int *eof, void *data)
{
        __u64 *temp = (__u64 *)data;
        int len;
        len = snprintf(page, count, LPU64"\n", *temp);
        return len;
}

#endif /* LPROC_SNMP */

EXPORT_SYMBOL(lprocfs_reg_obd);
EXPORT_SYMBOL(lprocfs_dereg_obd);
EXPORT_SYMBOL(lprocfs_reg_main);
EXPORT_SYMBOL(lprocfs_dereg_main);
EXPORT_SYMBOL(lprocfs_reg_mnt);
EXPORT_SYMBOL(lprocfs_dereg_mnt);
EXPORT_SYMBOL(lprocfs_add_vars);
EXPORT_SYMBOL(lprocfs_reg_class);
EXPORT_SYMBOL(lprocfs_dereg_class);
EXPORT_SYMBOL(lprocfs_ll_rd);


