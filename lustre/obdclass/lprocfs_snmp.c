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
 */

#define EXPORT_SYMTAB
#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/types.h>

#define DEBUG_SUBSYSTEM S_CLASS
#define MAX_STRING_SIZE 100

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lprocfs.h>
#include <linux/string.h>
#include <linux/lustre_lib.h>

#ifdef LPROCFS_EXISTS

#define DEFAULT_MODE 0644
/*
 * Tokenizer array. Change this array to include special
 * characters for string tokenizing
 */
char tok[] = {'/', (char)0};



/*
 * Externs
 */
extern struct proc_dir_entry proc_root; /* Defined in proc/root.c */
extern struct obd_type *class_nm_to_type(char *nm);

/*
 * Globals
 */
struct proc_dir_entry *proc_lustre_root = 0;
struct proc_dir_entry *proc_lustre_dev_root = 0;

/*
 *  API implementations
 */
/*
 * lprocfs_reg_obd: Registers an instance of the OBD device in the
 *                  proc hierarchy
 */

int lprocfs_reg_obd(struct obd_device* device, 
                    lprocfs_vars_t* list, 
                    void* data)
{
        
        int retval = 0;
        struct proc_dir_entry* this_dev_root=0;
        

        /* Obtain this device root */
        this_dev_root = lprocfs_mkinitdir(device);
        if (this_dev_root == 0) {
                CERROR("Could not create initial directory");
                return LPROCFS_FAILURE;
        }
        
        device->obd_proc_entry=this_dev_root;
        retval=lprocfs_new_vars(device,             \
                                this_dev_root, list, \
                                (const char*)tok, 
                                data);
                
        return retval;
}

int lprocfs_add_new_vars(struct obd_device* device,
                         lprocfs_vars_t* var, 
                         void* data)
{
        int retval=0;
        if(!device) {
                CERROR("Null pointer passed!");
                return LPROCFS_FAILURE;
        }
        if(!(device->obd_proc_entry)){
                CDEBUG(D_OTHER, \
                       "Device instance not registered yet!!");
                return LPROCFS_FAILURE;
      
        }
        retval=lprocfs_new_vars(device,
                                device->obd_proc_entry, \
                                var, (const char*) tok, data);
        return retval;
}

int lprocfs_dereg_obd(struct obd_device* device)
{
        struct proc_dir_entry* parent;

        CDEBUG(D_OTHER, "LPROCFS removing device = %s\n", \
               device->obd_name);

        if (!device) {
                CDEBUG(D_OTHER, "! LProcfs:  Null pointer !\n");
                return LPROCFS_SUCCESS;
        }

        if (!(device->obd_name)) {
                CERROR(" !! Device does not have a name !! \n");
                return LPROCFS_FAILURE;
        }
        if(!(device->obd_proc_entry)){
                CERROR("This device has not been registered\n");
                return LPROCFS_FAILURE;
        }
        parent=device->obd_proc_entry->parent;
        lprocfs_remove_all(device->obd_proc_entry);

        /*
         * Free the memory held by counters
         */
        if (device->counters)
                OBD_FREE(device->counters, device->cntr_mem_size);

        
        while((!(parent->subdir) && \
               memcmp(parent, &proc_root, sizeof(*parent)))) {
                remove_proc_entry(parent->name, parent->parent);
                parent=parent->parent;
        }

        CDEBUG(D_OTHER, "LPROCFS removed device = %s\n", \
               device->obd_name);

        return LPROCFS_SUCCESS;
}
struct proc_dir_entry* lprocfs_mkinitdir(struct obd_device* device)
{
        struct proc_dir_entry* this_dev_root = 0;
        struct proc_dir_entry* temp_proc = 0;

        /*
         * First check if /proc/lustre exits. If it does not,
         * instantiate the same and the devices directory
         */
        if (proc_lustre_root==0) {
                proc_lustre_root = lprocfs_mkdir("lustre", &proc_root);
                if (!proc_lustre_root) {
                        CERROR(" !! Cannot create /proc/lustre !! \n");
                        return 0;
                }
        }
        if (proc_lustre_dev_root==0) {
                proc_lustre_dev_root =
                        lprocfs_mkdir("devices", proc_lustre_root);
                
                if (!proc_lustre_dev_root) {
                        CERROR(" !! Cannot create /proc/lustre/devices !! \n");
                        return 0;
                }
                
        }

        /*
         * Check if this is the first instance for a device of
         * this class in the lprocfs hierarchy.
         */
        temp_proc = lprocfs_srch(proc_lustre_dev_root,
                                 device->obd_type->typ_name);

        if (!temp_proc) {
                temp_proc = lprocfs_mkdir(device->obd_type->typ_name,
                                          proc_lustre_dev_root);
                if (!temp_proc) {
                        CERROR("! Proc dir for device class %s !!\n",
                               device->obd_type->typ_name);
                        return 0;
                }
        }

        /* Next create the proc_dir_entry for this instance */
        this_dev_root = lprocfs_mkdir(device->obd_name, temp_proc);
        if (!this_dev_root) {
                CERROR("!Can't create proc entry for instance %s !! \n",
                       device->obd_name);
                return 0;
        }

        return this_dev_root;
}

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
                return 0;
        temp = head->subdir;
        while (temp != NULL) {
                if (!strcmp(temp->name, name))
                        return temp;
                temp = temp->next;
        }
        
        return 0;
}

#warning FIXME: recursive code is VERY bad in the kernel because of stack limit
struct proc_dir_entry* lprocfs_bfs_srch(struct proc_dir_entry* root,
                                        const char* name)
{
        struct proc_dir_entry* temp = root;

        if (!temp)
                return 0;

        if (!strcmp(temp->name, name))
                return temp;

        if ((temp = lprocfs_bfs_srch(root->next, name)) != 0)
                return temp;

        if ((temp = lprocfs_bfs_srch(root->subdir, name)) != 0)
                return temp;

        return temp;
}
void lprocfs_remove_all(struct proc_dir_entry* root)
{
        if (root->subdir != 0)
                lprocfs_remove_all(root->subdir);

        if (root->next != 0)
                lprocfs_remove_all(root->next);

        if (root->parent != 0)
                remove_proc_entry(root->name, root->parent);
        else
                remove_proc_entry(root->name, NULL);
}
/*
 * This function will be invoked during a module loading. The path parameter
 * is relative to /proc/lustre, and hence needs to begin as 
 * dir_1/dir_2 etc
 * The list is a simple variable list of names, which will be created under
 * the "path". If none is specified, no variable entries will be created.
 * Returns: The root for this module.
 */

struct proc_dir_entry* lprocfs_reg_module(char* name, char* path, 
                                          lprocfs_vars_t* list, 
                                          void* data)
{
        struct proc_dir_entry* root=0;
        int retVal=0;
        if(!name){
                CERROR("LProcFS: Null pointer for name\n");
                return 0;
        }
        if(!path){
                CERROR("LProcFS: Insertion path not provided\n");
                return 0;
        }
        if (proc_lustre_root==0) {
                proc_lustre_root = lprocfs_mkdir("lustre", &proc_root);
                if (!proc_lustre_root) {
                        CERROR(" !! Cannot create /proc/lustre !! \n");
                        return 0;
                }
        }
        if((root=lprocfs_new_dir(proc_lustre_root, \
                                 path, (const char*)tok))==0){

                CERROR("!! LProcFS: Failed to create dirs");
                return 0;
        }

        root=lprocfs_mkdir(name, root);        
        retVal=lprocfs_new_vars(NULL, root, list, \
                                (const char*)tok, data);
        if(retVal==LPROCFS_FAILURE) 
                return 0;
        return root;
        
}

int lprocfs_dereg_module(char* name)
{
        struct proc_dir_entry* temp=0;
        struct proc_dir_entry* parent=0;
        if (proc_lustre_root==0) {
                CERROR(" !! LProc Does not exist !! \n");
                return 0;
        }
        temp = lprocfs_bfs_srch(proc_lustre_root->subdir, \
                                name);
        if (temp == 0) {
                CDEBUG(D_OTHER, "!! Module not inserted!!");
                return LPROCFS_FAILURE;
        }
        parent=temp->parent;
        lprocfs_remove_all(temp);
        while((!(parent->subdir) && \
               memcmp(parent, &proc_root, sizeof(*parent)))) {
                remove_proc_entry(parent->name, parent->parent);
                parent=parent->parent;
        }

        CDEBUG(D_OTHER, "LPROCFS removed = %s\n", \
               name);
        

        return LPROCFS_SUCCESS;

}

struct proc_dir_entry* lprocfs_new_dir(struct proc_dir_entry* root,
                                       const char* string, 
                                       const char* tok)
{
        struct proc_dir_entry* new_root = 0;
        struct proc_dir_entry* temp_entry = 0;
        
        char temp_string[MAX_STRING_SIZE];
        char* my_str;
        char* mover_str;

        /*
         * Remove trailing escaping character
         */
        memset(temp_string, 0, MAX_STRING_SIZE);
        if (strlen(string) >= MAX_STRING_SIZE) {
                CDEBUG(D_OTHER, "Directory namespace too long");
                return 0;
        }
       
        strcpy(temp_string, string);
        temp_string[strlen(string) + 1] = '\0';
        
        new_root=root;
        mover_str=temp_string;
        while ((my_str = strsep(&mover_str, tok))) {
                if(!*my_str)
                        continue;
                CDEBUG(D_OTHER, "SEARCH= %s\t, ROOT=%s\n", \
                       my_str, new_root->name);
                temp_entry = lprocfs_srch(new_root, my_str);
                if (temp_entry == 0) {
                        CDEBUG(D_OTHER, "Adding: %s\n", my_str);
                        temp_entry = lprocfs_mkdir(my_str, new_root);
                        if (temp_entry == 0) {
                                CDEBUG(D_OTHER, 
                                       "! Did not create new dir %s !!\n",
                                       my_str);
                                return 0;
                        }
                }
                new_root = temp_entry;
        }

        return new_root;
}


int lprocfs_add_mod_vars(struct proc_dir_entry* root, 
                         lprocfs_vars_t* list,
                         void* data)
{
        int retval=0;
        retval=lprocfs_new_vars(NULL, root, list, \
                                (const char*) tok, data);
        return retval;
}

int lprocfs_new_vars(struct obd_device* dev, 
                     struct proc_dir_entry* root,
                     lprocfs_vars_t* list,
                     const char* tok, 
                     void* data)
{
        struct proc_dir_entry* temp_root=0;
        struct proc_dir_entry* new_leaf=0;
        struct proc_dir_entry* new_parent=0;
        char temp_string[MAX_STRING_SIZE];
        
        if(!list)
                return LPROCFS_SUCCESS;

        while(list->name){
                temp_root=lprocfs_new_dir(root, \
                                          list->name, \
                                          tok);
                
                if(!temp_root){
                        CDEBUG(D_OTHER, "!LProcFS: Mods: No root!");
                        return LPROCFS_FAILURE;
                }
                /* Convert the last element into a leaf-node */
                memset(temp_string, 0, MAX_STRING_SIZE);
                strcpy(temp_string, temp_root->name);
                temp_string[strlen(temp_root->name) + 1] = '\0';
                new_parent=temp_root->parent;
                if (new_parent != 0){
                        remove_proc_entry(temp_root->name, new_parent);
                } else {
                        remove_proc_entry(temp_root->name, NULL);
                }
                new_leaf = create_proc_entry(temp_string, \
                                             DEFAULT_MODE, \
                                             new_parent);
                new_leaf->read_proc = list->read_fptr;
                new_leaf->write_proc = list->write_fptr;
                new_leaf->data=data;
                if(dev)
                        new_leaf->data=dev;
                list++;
        }
        return LPROCFS_SUCCESS;

}
int lprocfs_ll_rd(char *page, char **start, off_t off,
                  int count, int *eof, void *data)
{
        __u64 *temp = (__u64 *)data;
        int len;

        len = snprintf(page, count, LPU64"\n", *temp);

        return len;
}

#endif /* LPROCFS_EXISTS */


EXPORT_SYMBOL(lprocfs_reg_obd);
EXPORT_SYMBOL(lprocfs_dereg_obd);
EXPORT_SYMBOL(lprocfs_add_new_vars);
EXPORT_SYMBOL(lprocfs_reg_module);
EXPORT_SYMBOL(lprocfs_dereg_module);
EXPORT_SYMBOL(lprocfs_ll_rd);
EXPORT_SYMBOL(lprocfs_add_mod_vars);

