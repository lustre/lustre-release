/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Intel Corporation
 *
 */

/*
 * Author: Hariharan Thantry
 * File Name: lprocfs.c 
 * 
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * During initialization (of lustre), the following directory materializes
 *          /proc/lustre
 * When the first OBD device of a class is created (due to insmod)
 * the directory
 *         /proc/lustre/devices/<device-class> is created.
 * When an instance of a device is created (during attach) the 
 * directory entry for that instance along with the variables for
 * that entry gets created. These variables could be counters, string
 * variables etc.
 * Each API further describes the functionality offered. 
 * 
 */

#define EXPORT_SYMTAB
#include <linux/config.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>

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
char tok[]={'/', (char)0};
char enum_char = '_';
/*
 * Escape character. To be used in directories that 
 * should not have any counter/variable entries under
 * them. Used for hierarchical directories
 */

char escape_char='%';

/*
 * Externs
 */
extern struct proc_dir_entry proc_root; /* Defined in proc/root.c */
extern void l_lock_init(struct lustre_lock* );
extern void l_lock(struct lustre_lock* );
extern void l_unlock(struct lustre_lock* );

/*
 * Globals
 */

static struct proc_dir_entry *proc_lustre_root = 0;
static struct proc_dir_entry *proc_lustre_dev_root = 0;

struct lustre_lock proc_lustre_lock;
/* static struct proc_dir_entry *proc_lustre_conn_root = 0; */
char* testStr="General..";

/*
 * Link the namespace with the internal array indices for
 * each device class, only if proc lustre is defined 
 */


struct namespace_index dir_mdc_index[] = {
        LPROCFS_DIR_INDEX(mdc, mgmt_setup),
        LPROCFS_DIR_INDEX(mdc, mgmt_cleanup),
        LPROCFS_DIR_INDEX(mdc, mgmt_connect),
        LPROCFS_DIR_INDEX(mdc, mgmt_disconnect),
        LPROCFS_DIR_INDEX(mdc, reint),
        LPROCFS_DIR_INDEX(mdc, getstatus),
        LPROCFS_DIR_INDEX(mdc, getattr),
        LPROCFS_DIR_INDEX(mdc, setattr),
        LPROCFS_DIR_INDEX(mdc, open),
        LPROCFS_DIR_INDEX(mdc, readpage),
        LPROCFS_DIR_INDEX(mdc, create),
        LPROCFS_DIR_INDEX(mdc, unlink),
        LPROCFS_DIR_INDEX(mdc, link),
        LPROCFS_DIR_INDEX(mdc, rename)
        /* Maintain this last comma */
        ,

};
struct namespace_index dir_mds_index[] = {
        LPROCFS_DIR_INDEX(mds, mgmt_setup),
        LPROCFS_DIR_INDEX(mds, mgmt_cleanup),
        LPROCFS_DIR_INDEX(mds, mgmt_connect),
        LPROCFS_DIR_INDEX(mds, mgmt_disconnect),
        LPROCFS_DIR_INDEX(mds, getstatus),
        LPROCFS_DIR_INDEX(mds, connect),
        LPROCFS_DIR_INDEX(mds, disconnect_callback),
        LPROCFS_DIR_INDEX(mds, getattr),
        LPROCFS_DIR_INDEX(mds, readpage),
        LPROCFS_DIR_INDEX(mds, open),
        LPROCFS_DIR_INDEX(mds, close),
        LPROCFS_DIR_INDEX(mds, create),
        LPROCFS_DIR_INDEX(mds, unlink),
        LPROCFS_DIR_INDEX(mds, link),
        LPROCFS_DIR_INDEX(mds, rename),
        LPROCFS_DIR_INDEX(mds, reint_summary),
        LPROCFS_DIR_INDEX(mds, reint_setattr),
        LPROCFS_DIR_INDEX(mds, reint_create),
        LPROCFS_DIR_INDEX(mds, reint_unlink),
        LPROCFS_DIR_INDEX(mds, reint_link),
        LPROCFS_DIR_INDEX(mds, reint_rename),
        LPROCFS_DIR_INDEX(mds, reint_recreate)
        /* Maintain this last comma */
        ,


};

struct namespace_index dir_osc_index[] = {
        LPROCFS_DIR_INDEX(osc, mgmt_setup),
        LPROCFS_DIR_INDEX(osc, mgmt_cleanup),
        LPROCFS_DIR_INDEX(osc, mgmt_connect),
        LPROCFS_DIR_INDEX(osc, mgmt_disconnect),
        LPROCFS_DIR_INDEX(osc, create),
        LPROCFS_DIR_INDEX(osc, destroy),
        LPROCFS_DIR_INDEX(osc, getattr),
        LPROCFS_DIR_INDEX(osc, setattr),
        LPROCFS_DIR_INDEX(osc, open),
        LPROCFS_DIR_INDEX(osc, close),
        LPROCFS_DIR_INDEX(osc, brw),
        LPROCFS_DIR_INDEX(osc, punch),
        LPROCFS_DIR_INDEX(osc, summary),
        LPROCFS_DIR_INDEX(osc, cancel)
        /* Maintain this last comma */
        ,

};

struct namespace_index dir_ost_index[] = {
        LPROCFS_DIR_INDEX(ost, mgmt_setup),
        LPROCFS_DIR_INDEX(ost, mgmt_cleanup),
        LPROCFS_DIR_INDEX(ost, mgmt_connect),
        LPROCFS_DIR_INDEX(ost, mgmt_disconnect),
        LPROCFS_DIR_INDEX(ost, create),
        LPROCFS_DIR_INDEX(ost, destroy),
        LPROCFS_DIR_INDEX(ost, getattr),
        LPROCFS_DIR_INDEX(ost, setattr),
        LPROCFS_DIR_INDEX(ost, open),
        LPROCFS_DIR_INDEX(ost, close),
        LPROCFS_DIR_INDEX(ost, brw),
        LPROCFS_DIR_INDEX(ost, punch),
        LPROCFS_DIR_INDEX(ost, summary),
        LPROCFS_DIR_INDEX(ost, cancel),
        LPROCFS_DIR_INDEX(ost, getinfo)
        /* Maintain this last comma */
        ,

};
struct namespace_index dir_lov_index[] = {
        LPROCFS_DIR_INDEX(lov, mgmt_setup),
        LPROCFS_DIR_INDEX(lov, mgmt_cleanup),
        LPROCFS_DIR_INDEX(lov, mgmt_connect),
        LPROCFS_DIR_INDEX(lov, mgmt_disconnect),
        LPROCFS_DIR_INDEX(lov, create),
        LPROCFS_DIR_INDEX(lov, destroy),
        LPROCFS_DIR_INDEX(lov, getattr),
        LPROCFS_DIR_INDEX(lov, setattr),
        LPROCFS_DIR_INDEX(lov, open),
        LPROCFS_DIR_INDEX(lov, close),
        LPROCFS_DIR_INDEX(lov, brw),
        LPROCFS_DIR_INDEX(lov, punch),
        LPROCFS_DIR_INDEX(lov, summary),
        LPROCFS_DIR_INDEX(lov, cancel),
        LPROCFS_DIR_INDEX(lov, getinfo)
        /* Maintain this last comma */
        ,

};
struct namespace_index dir_obdfilter_index[] = {

        LPROCFS_DIR_INDEX(obdfilter, mgmt_setup),
        LPROCFS_DIR_INDEX(obdfilter, mgmt_cleanup),
        LPROCFS_DIR_INDEX(obdfilter, mgmt_connect),
        LPROCFS_DIR_INDEX(obdfilter, mgmt_disconnect),
        LPROCFS_DIR_INDEX(obdfilter, create),
        LPROCFS_DIR_INDEX(obdfilter, destroy),
        LPROCFS_DIR_INDEX(obdfilter, getattr),
        LPROCFS_DIR_INDEX(obdfilter, setattr),
        LPROCFS_DIR_INDEX(obdfilter, open),
        LPROCFS_DIR_INDEX(obdfilter, close),
        LPROCFS_DIR_INDEX(obdfilter, brw),
        LPROCFS_DIR_INDEX(obdfilter, punch),
        LPROCFS_DIR_INDEX(obdfilter, summary),
        LPROCFS_DIR_INDEX(obdfilter, cancel),
        LPROCFS_DIR_INDEX(obdfilter, getinfo)
        /* Maintain this last comma */
        ,
};  

struct namespace_index dir_ldlm_index[] = {

        LPROCFS_DIR_INDEX(ldlm, mgmt_setup),
        LPROCFS_DIR_INDEX(ldlm, mgmt_cleanup),
        LPROCFS_DIR_INDEX(ldlm, mgmt_connect),
        LPROCFS_DIR_INDEX(ldlm, mgmt_disconnect),
        LPROCFS_DIR_INDEX(ldlm, locks_enqueus),
        LPROCFS_DIR_INDEX(ldlm, locks_cancels),
        LPROCFS_DIR_INDEX(ldlm, locks_converts),
        LPROCFS_DIR_INDEX(ldlm, locks_matches)
        /* Maintain this last comma */
        ,
};  
struct namespace_index dir_ptlrpc_index[] = {

        LPROCFS_DIR_INDEX(ptlrpc, mgmt_setup),
        LPROCFS_DIR_INDEX(ptlrpc, mgmt_cleanup),
        LPROCFS_DIR_INDEX(ptlrpc, mgmt_connect),
        LPROCFS_DIR_INDEX(ptlrpc, mgmt_disconnect),
        LPROCFS_DIR_INDEX(ptlrpc, counters)
        
        /* Maintain this last comma */
        ,
};  




struct namespace_index prof_mdc_index[] = {
        
        LPROCFS_CNTR_INDEX(mdc, min_time),
        LPROCFS_CNTR_INDEX(mdc, max_time),
        LPROCFS_CNTR_INDEX(mdc, sum_time),
        LPROCFS_CNTR_INDEX(mdc, num_ops)
        /* Maintain this comma */
        ,


};
struct namespace_index prof_mds_index[]= {

  
        LPROCFS_CNTR_INDEX(mds, min_time),
        LPROCFS_CNTR_INDEX(mds, max_time),
        LPROCFS_CNTR_INDEX(mds, sum_time),
        LPROCFS_CNTR_INDEX(mds, num_ops)
        /* Maintain this comma */
        ,
};
struct namespace_index prof_osc_index[]= {

  
        LPROCFS_CNTR_INDEX(osc, min_time),
        LPROCFS_CNTR_INDEX(osc, max_time),
        LPROCFS_CNTR_INDEX(osc, sum_time),
        LPROCFS_CNTR_INDEX(osc, num_ops)
        /* Maintain this comma */
        ,
};
struct namespace_index prof_ost_index[]= {

  
        LPROCFS_CNTR_INDEX(ost, min_time),
        LPROCFS_CNTR_INDEX(ost, max_time),
        LPROCFS_CNTR_INDEX(ost, sum_time),
        LPROCFS_CNTR_INDEX(ost, num_ops)
        /* Maintain this comma */
        ,
};
struct namespace_index prof_lov_index[]= {

  
        LPROCFS_CNTR_INDEX(lov, min_time),
        LPROCFS_CNTR_INDEX(lov, max_time),
        LPROCFS_CNTR_INDEX(lov, sum_time),
        LPROCFS_CNTR_INDEX(lov, num_ops)
        /* Maintain this comma */
        ,
};
struct namespace_index prof_obdfilter_index[]= {

  
        LPROCFS_CNTR_INDEX(obdfilter, min_time),
        LPROCFS_CNTR_INDEX(obdfilter, max_time),
        LPROCFS_CNTR_INDEX(obdfilter, sum_time),
        LPROCFS_CNTR_INDEX(obdfilter, num_ops)
        /* Maintain this comma */
        ,
};

struct namespace_index prof_ldlm_index[] = {
        LPROCFS_CNTR_INDEX(ldlm, min_time),
        LPROCFS_CNTR_INDEX(ldlm, max_time),
        LPROCFS_CNTR_INDEX(ldlm, sum_time),
        LPROCFS_CNTR_INDEX(ldlm, num_ops),
        LPROCFS_CNTR_INDEX(ldlm, num_total),
        LPROCFS_CNTR_INDEX(ldlm, num_zerolatency),
        LPROCFS_CNTR_INDEX(ldlm, num_zerolatency_inflight),
        LPROCFS_CNTR_INDEX(ldlm, num_zerolatency_done),
        LPROCFS_CNTR_INDEX(ldlm, nonzero_mintime),
        LPROCFS_CNTR_INDEX(ldlm, nonzero_maxtime),
        LPROCFS_CNTR_INDEX(ldlm, nonzero_sumtime)
         /* Maintain this comma */ 
        ,


};

struct namespace_index prof_ptlrpc_index[] = {
        LPROCFS_CNTR_INDEX(ptlrpc, min_time),
        LPROCFS_CNTR_INDEX(ptlrpc, max_time),
        LPROCFS_CNTR_INDEX(ptlrpc, sum_time),
        LPROCFS_CNTR_INDEX(ptlrpc, num_ops),
        LPROCFS_CNTR_INDEX(ptlrpc, msgs_alloc),
        LPROCFS_CNTR_INDEX(ptlrpc, msgs_max),
        LPROCFS_CNTR_INDEX(ptlrpc, recv_count),
        LPROCFS_CNTR_INDEX(ptlrpc, recv_length),
        LPROCFS_CNTR_INDEX(ptlrpc, send_count),
        LPROCFS_CNTR_INDEX(ptlrpc, send_length),
        LPROCFS_CNTR_INDEX(ptlrpc, portal_kmemory)
        /* Maintain this comma */
        ,


};

/*
 * Group the device class name, its directory hierarchy and
 * leaf nodes together
 */

struct groupspace_index class_index[] = {

        LPROCFS_GROUP_CREATE(mdc),
        LPROCFS_GROUP_CREATE(mds),
        LPROCFS_GROUP_CREATE(osc),
        LPROCFS_GROUP_CREATE(ost),
        LPROCFS_GROUP_CREATE(lov),
        LPROCFS_GROUP_CREATE(obdfilter),
        LPROCFS_GROUP_CREATE(ldlm),
        LPROCFS_GROUP_CREATE(ptlrpc)
        /* Retain this comma */
        ,

};


/* 
 *  API implementations
 */

/*
 * lprocfs_register_dev: Registers an instance of the OBD device in the
 *                       proc hierarchy
 */

int lprocfs_register_dev(struct obd_device* device, \
                         lprocfs_group_t* namespace, \
                         unsigned int cnt_struct_size)
{
        
        
        unsigned int num_directories=0;
        int class_array_index=0;
        int retval=0; 
        
        struct proc_dir_entry* this_dev_root=0; 
        
        unsigned int i=0, j=0; 
        
        /*
         * Obtain this device root
         */
        
        this_dev_root=lprocfs_mkinitdir(device);
        if(this_dev_root==0){
                CERROR("Could not create initial directory");
                return LPROCFS_FAILURE;
                
        }
        l_lock_init(&proc_lustre_lock); 
        
        /*
         * Obtain the class-array index
         */
        
        class_array_index=lprocfs_util_getclass_idx(class_index, device->obd_type->typ_name);
        
        if(class_array_index==LPROCFS_FAILURE){
                CERROR("!! Could not find class !! \n");
                return LPROCFS_FAILURE;
        }
        
        
        /*
         * Create the directory namespace
         */
        
        retval=lprocfs_create_dir_namespace(this_dev_root, namespace, &num_directories);
        if(retval==LPROCFS_FAILURE){
                CERROR("!!Could not create proc directory structure !!\n");
                return LPROCFS_FAILURE;
        }
        
        
        
        /* 
         * Allocate memory managed by LProcFS for the device.
         */
        
        if(cnt_struct_size!=0){
                device->counters=kmalloc(num_directories*cnt_struct_size, \
                                         GFP_KERNEL);
                if(!device->counters){
                        CERROR("!!Could not allocate memory for proc counters!!");
                        return LPROCFS_FAILURE;
                        
                }
                memset(device->counters, 0, num_directories*cnt_struct_size);
        } 
        
        
        /*
         * Iterate the proc-dir-namespace, obtain corresponding directory(attribute)
         * entries. Create the proc-counters from namespace, link them into 
         * dev counters
         */
        
        retval=lprocfs_link_dir_counters(device, \
                                         this_dev_root, \
                                         namespace, \
                                         cnt_struct_size, \
                                         class_array_index);
        
        
        if(retval==LPROCFS_FAILURE){
                CERROR("!! Could not link proc counters to device !!");
                return LPROCFS_FAILURE;
                
        }
        

        /*
         * Test code: This goes into individual modules. strcmp is
         * unnecessary, since device knows its class. To see the values
         * from the user space, do a cat on the respective variable
         */
        
        if(!(strcmp(device->obd_type->typ_name, "mds"))){
                DEV_PROF_START(mds, device, gen, mgmt_setup); 
                
                for(i=0; i<100; i++)
                        for(j=0; j<100; j++)
                                continue;
                
                DEV_PROF_END(mds, device, gen, mgmt_setup);
                
                DEV_PROF_START(mds, device, gen, mgmt_setup); 
                
                for(i=0; i<1000; i++)
                        for(j=0; j<1000; j++)
                                continue;
                
                DEV_PROF_END(mds, device, gen, mgmt_setup);
                
                
                DEV_PROF_START(mds, device, gen, open);
                for(i=0; i<50; i++){
                        DEV_PROF_START(mds, device, gen, close);
                        for(j=0; j<2000; j++)
                                continue;
                        DEV_PROF_END(mds, device, gen, close);
                }
                DEV_PROF_END(mds, device, gen, open);
                
                
        }
        
        
        if(!(strcmp(device->obd_type->typ_name, "ldlm"))){
                
                DEV_PROF_START(ldlm, device, ldlm, mgmt_connect);
                for(i=0; i<200; i++){
                        DEV_PROF_START(ldlm, device, ldlm, mgmt_disconnect);
                        for(j=0; j<2000; j++)
                                continue;
                        DEV_PROF_END(ldlm, device, ldlm, mgmt_disconnect);
                }
                DEV_PROF_END(ldlm, device, ldlm, mgmt_connect);        
        }
        
        
        return LPROCFS_SUCCESS;
}

int lprocfs_link_dir_counters(struct obd_device* device, \
                              struct proc_dir_entry* this_dev_root, \
                              lprocfs_group_t* namespace, \
                              unsigned int cnt_struct_size, \
                              unsigned int class_array_index)
{
        
        
        unsigned int i=0;
        unsigned int j=0;
        unsigned int k=0;
        unsigned int escape=0;
        int dir_array_index=-1;
        int cnt_array_index=-1;
        
        struct proc_dir_entry* this_dir_root=0;
        lprocfs_group_t* temp;
        lprocfs_vars_t* func_n_counters;
        
        while(1) {
                temp=&namespace[i];
                dir_array_index=-1;
                if(temp->count_func_namespace==0) break;
                while((temp->dir_namespace)[j]!=0){
                        this_dir_root=lprocfs_util_add_dir_node(this_dev_root, (temp->dir_namespace)[j], (const char*)tok, &escape);
                        if(escape){
                                j++;
                                continue;
                        }
                        dir_array_index=lprocfs_util_get_index(class_index[class_array_index].directory,(temp->dir_namespace)[j]);
                        /* printk("Class name=%s, Directory name=%s, index=%d\t", device->obd_type->typ_name, (temp->dir_namespace)[j], dir_array_index); */
                        while(1){
                                cnt_array_index=-1;
                                func_n_counters=&((temp->count_func_namespace)[k]);
                                if(func_n_counters->read_fptr==0)break;
                                cnt_array_index=lprocfs_util_get_index(class_index[class_array_index].counters, func_n_counters->name);
                                /* printk("Counter name=%s, index=%d\n", func_n_counters->name, cnt_array_index); */
                                if(lprocfs_util_add_var_node(device, \
                                                             this_dir_root, \
                                                             func_n_counters, \
                                                             dir_array_index, \
                                                             cnt_array_index, \
                                                             cnt_struct_size, \
                                                             temp->prof_type)==LPROCFS_FAILURE){
                                        CERROR("Could not create leaf node!");
                                        return LPROCFS_FAILURE;
                                        
                                }
                                
                                k++;
                        }
                        
                        k=0;      
                        j++;
                        
                }
                k=0;
                j=0;
                i++;         
        }
        
        return LPROCFS_SUCCESS;
        
}




int lprocfs_create_dir_namespace(struct proc_dir_entry* this_dev_root, \
                                 lprocfs_group_t* namespace, \
                                 unsigned int *num_dirs)

{
        unsigned int i=0;
        unsigned int j=0;
        struct proc_dir_entry* this_dir_root=0;
        lprocfs_group_t* temp;
        unsigned int escape=0;

        while(1) {
                temp=&namespace[i];
                if(temp->count_func_namespace==0) break;
                while((temp->dir_namespace)[j]!=0){
                        this_dir_root=lprocfs_util_add_dir_node(this_dev_root, (temp->dir_namespace)[j], (const char*)tok, &escape);
                        if(this_dir_root==0){
                                CERROR("!! Could not create directory entry %s !! \n", (temp->dir_namespace)[j]);
                                return LPROCFS_FAILURE;
                        }
                        if(temp->prof_type!=e_specific && !escape)
                                (*num_dirs)++;
                        j++;
                        
                }
                j=0;
                i++;         
        }

        return LPROCFS_SUCCESS;

}




int lprocfs_util_getclass_idx(struct groupspace_index* group, const char* classname)
{
        unsigned int idx=0;
        while(group[idx].name!=""){
                if(!strcmp(group[idx].name, classname))
                        return idx;
                
                idx++;
        }

        return LPROCFS_FAILURE;

}

struct proc_dir_entry* lprocfs_mkinitdir(struct obd_device* device)
{

        struct proc_dir_entry* this_dev_root=0;
        struct proc_dir_entry* temp_proc=0;
        /*
         * First check if /proc/lustre exits. If it does not,
         * instantiate the same and the devices directory
         */
        
        if (!proc_lustre_root) {
                proc_lustre_root = 
                        lprocfs_util_mkdir("lustre", &proc_root);
                if (!proc_lustre_root){
                        CERROR(" !! Cannot create /proc/lustre !! \n");
                        return 0;
                }
                proc_lustre_dev_root = 
                        lprocfs_util_mkdir("devices", proc_lustre_root);
                
                if(!proc_lustre_dev_root){
                        CERROR(" !! Cannot create /proc/lustre/devices !! \n");
                        return 0;
                }
                
        } 
        /*
         * Check if this is the first instance for a device of
         * this class in the lprocfs hierarchy. 
         */
        
        temp_proc=lprocfs_search(proc_lustre_dev_root, device->obd_type->typ_name);
        
        if(!temp_proc){
                temp_proc=lprocfs_util_mkdir(device->obd_type->typ_name, proc_lustre_dev_root);
                if(!temp_proc){
                        CERROR("!! Could not create proc for device class %s !!\n", device->obd_type->typ_name);
                        return 0;
                }
        }
        /*
         * Next create the proc_dir_entry for this instance
         */
        
        this_dev_root=lprocfs_util_mkdir(device->obd_name, temp_proc);
        if(!this_dev_root){
                CERROR("!! Cannot create proc entry for device instance %s !! \n", device->obd_name);
                return 0;
        }
        
        return this_dev_root;
        

}



int lprocfs_util_get_index(struct namespace_index* class, const char* dir_name)
{

        unsigned int index = 0;
        char temp_string[MAX_STRING_SIZE];
        
        /*
         * First replace the string tokenizer with
         * enum character
         */

        memset(temp_string, 0, MAX_STRING_SIZE);
        while(dir_name[index]!='\0' && index<MAX_STRING_SIZE){
                if(dir_name[index]!=tok[0])
                        temp_string[index]=dir_name[index];
                else
                        temp_string[index]=enum_char;
                index++;
        }
        temp_string[index]='\0';
        
        index=0;
        while(class[index].name){
                if(!strcmp(class[index].name, temp_string))
                        return index;
                index++;

        }

        printk("No profiling for %s\n", temp_string);
        return -1;
}




struct proc_dir_entry* lprocfs_util_mkdir(const char* dname, struct proc_dir_entry *parent)
{
	struct proc_dir_entry *child_dir_entry;
        
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)	/*0x20300 */
	child_dir_entry = proc_mkdir(dname, parent);
#else
	child_dir_entry = create_proc_entry(dname,
					    S_IFDIR | S_IRUGO | S_IXUGO,
					    &proc_root);
#endif
	if (!child_dir_entry)
                CERROR("lustre: failed to create /proc entry %s\n", dname);
	
	return child_dir_entry;
}

/* 
 * Create the variable struct entry for /proc. This will also
 * register the read/write function pointers with
 * /proc/lustre. 
 * Returns non-zero on success, zero on failure
 */

unsigned int lprocfs_util_add_var_node(struct obd_device* device, \
                                       struct proc_dir_entry* root, \
                                       lprocfs_vars_t* variable, \
                                       int dir_arr_index, \
                                       int cnt_arr_index, \
                                       unsigned int cnt_struct_size, \
                                       lprocfs_profilers_e type \
                                       )
{
        struct proc_dir_entry* new_proc_entry;
        unsigned long long* temp;
        unsigned int actual_idx;
                       
        new_proc_entry=create_proc_entry(variable->name, \
                                         DEFAULT_MODE,
                                         root);
        if(!new_proc_entry) return LPROCFS_FAILURE;

       
        new_proc_entry->read_proc=variable->read_fptr;
        new_proc_entry->write_proc=variable->write_fptr;
       
        switch(type){
        case e_generic:
                if(device->counters) {
                        if(dir_arr_index!=-1 && cnt_arr_index!=-1){
                                temp=(unsigned long long*)device->counters;
                                actual_idx=(dir_arr_index*((cnt_struct_size)/(sizeof(unsigned long long))))+cnt_arr_index;
                                temp+=actual_idx;
                                new_proc_entry->data = (unsigned long long*)temp;
                        }
                }
                break;
        case e_specific:


                              
                break;
        }
        
      
        return LPROCFS_SUCCESS;
}



/*
 * Tokenize name, based on tok and end-of-string. Create and return the
 * new directory entry. Set escape variable if the directory name contained
 * the escaping character (#)
 */

struct proc_dir_entry* lprocfs_util_add_dir_node(struct proc_dir_entry *root, \
                                                 const char* string,          \
                                                 const char* tok,             \
                                                 unsigned int* escape)
{
        struct proc_dir_entry* new_root=0;
        struct proc_dir_entry* temp_entry=0;
        struct proc_dir_entry* new_entry=0;
        

        char temp_string[MAX_STRING_SIZE];
        char* my_str;

        /*
         * Remove trailing escaping character
         */

        memset(temp_string, 0, MAX_STRING_SIZE);
        if(strlen(string)>= MAX_STRING_SIZE){
                CERROR("Directory namespace too long");
                return 0;

        }
        if(strchr(string, escape_char)!=NULL){
                *escape=1;
                strncpy(temp_string,string,strlen(string)-1);
                temp_string[strlen(string)]='\0';
                
        } else {
                *escape=0;
                strcpy(temp_string, string);
                temp_string[strlen(string)+1]='\0';

        }
        
        my_str=strtok(temp_string, tok);

        new_root=root;
        while(my_str!=NULL){
                temp_entry=lprocfs_search(new_root, my_str);
                if(temp_entry==0){
                        new_entry=lprocfs_util_mkdir(my_str, new_root);
                        if(new_entry==0){
                                CERROR("!! LPROCFS: Failed to create new directory %s !!\n", \
                                       my_str);
                                return 0;
                                }
                        return new_entry;
                }
                
                new_root=temp_entry;
                my_str=strtok(NULL, tok);
                
        }
        return new_root;
}


struct proc_dir_entry* lprocfs_search(struct proc_dir_entry* head, const char* name)
{
        struct proc_dir_entry* temp;

        if(!head) return 0;
        temp=head->subdir;
        while(temp!=NULL){
                if(!strcmp(temp->name, name))
                        return temp;
                temp=temp->next;
        }
        return 0;
} 



struct proc_dir_entry* lprocfs_bfs_search(struct proc_dir_entry* root, const char* name)
{                                                          
    
        struct proc_dir_entry* temp=root;    
        
        if(!temp){
                return 0;
        }
        if(!strcmp(temp->name, name)){
                return temp;
        }
        if((temp=lprocfs_bfs_search(root->next, name))!=0){
                return temp;
        }
        if((temp=lprocfs_bfs_search(root->subdir, name))!=0){
                return temp;
        }
        return temp;
} 

int  lprocfs_get_namespace(char* name, \
                           lprocfs_obd_namespace_t* collection)
{
        int i=0;
        while(collection[i].obd_namespace!=0){
                if(!strcmp(collection[i].obd_classname, name)){
                        return i;
                }
                i++;
        }
        return -1;

}

int lprocfs_deregister_dev (struct obd_device* device)
{

        struct proc_dir_entry* temp;
        
        
        if(!device){
                CERROR("!! Null pointer passed !!\n");
                return LPROCFS_FAILURE;
        }
        if(!(device->obd_name)){
                CERROR(" !! Device does not have a name !! \n");
                return LPROCFS_FAILURE;
                
        }
        printk("SEARCH: Device = %s\n", device->obd_name);
        
        l_lock(&proc_lustre_lock);
        
        temp=lprocfs_bfs_search(proc_lustre_dev_root->subdir, device->obd_name);
        if(temp==0){
                CERROR("!! No root obtained, device does not exist !!\n");
                return LPROCFS_FAILURE;
        }
        
        lprocfs_remove_all(temp);
        l_unlock(&proc_lustre_lock);

        /*
         * Free the memory held by counters
         */
        if(device->counters)
                kfree(device->counters);
        
        
        return LPROCFS_SUCCESS;
           
           
}

void lprocfs_remove_all(struct proc_dir_entry* root)
{
        if(root->subdir!=0)
                lprocfs_remove_all(root->subdir);
  
       if(root->next!=0)
                lprocfs_remove_all(root->next);
        
        if(root->parent!=0)
                remove_proc_entry(root->name, root->parent);
        else
                remove_proc_entry(root->name, NULL);

}


int lprocfs_longlong_read(char* page, char **start, off_t off,
		 int count, int *eof, void *data)
{
        int len;
        unsigned long long* temp=(unsigned long long*)data;
        
        len=sprintf(page, "%lld\n", *temp);
        
        return len;
}

int read_other(char* page, char **start, off_t off,
		 int count, int *eof, void *data)
{
  printk("Hello other");
  return 0;

}
int read_string(char* page, char **start, off_t off,
		 int count, int *eof, void *data)
{
  printk("Hello string");
  return 0;
}
int lprocfs_longlong_write(struct file* file, const char *buffer,
		  unsigned long count, void *data)
{
  printk("Write default");
  return 0;

}

int write_other(struct file* file, const char *buffer,
		  unsigned long count, void *data)
{
  printk("Write other");
  return 0;

}

int write_string(struct file* file, const char *buffer,
		  unsigned long count, void *data)
{
        printk("Write string");
        return 0;

}

int lprocfs_register_conn(unsigned int conn_number, \
                          struct lprocfs_conn_namespace* namespace)
{
        return 0;
}
int lprocfs_deregister_conn(unsigned int conn_number)
{
        return 0;
}

/*
 * Import/Export APIs
 */
int lprocfs_add_export(unsigned int conn_number, struct obd_device* device)
{
        return 0;
}
int lprocfs_add_import(unsigned int conn_number, struct obd_device* device)
{
        return 0;
}
int lprocfs_remove_export(unsigned int conn_number, struct obd_device* device)
{
        return 0;
}
int lprocfs_remove_import(unsigned int conn_number, struct obd_device* device)
{
        return 0;
}

#endif 
