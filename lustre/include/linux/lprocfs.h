/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Intel Corporation
 *
 */

/*
 * Author: Hariharan Thantry
 * File Name: lprocfs.h
 *
 * Header file for the LProcFS file system
 */

#ifndef _LPROCFS_H
#define _LPROCFS_H

#ifndef LPROCFS_EXISTS
#define LPROCFS_EXISTS
#endif

#define LPROCFS_SUCCESS 1
#define LPROCFS_FAILURE -1

#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/config.h>
#include <linux/param.h>
/* #include <linux/msr.h> */

typedef enum lprofilers {
        e_generic=0,
        e_specific
} lprofilers_e;

typedef struct lprocfs_vars{
        char* name;
        read_proc_t* read_fptr;
        write_proc_t* write_fptr;
} lprocfs_vars_t;

typedef struct lprocfs_group {
        char** dir_namespace;
        lprocfs_vars_t* count_func_namespace;
        lprofilers_e prof_type;
} lprocfs_group_t;

typedef struct lprocfs_obd_nm {
        char* obd_clname;
        lprocfs_group_t* obd_names;
        unsigned int cntr_blk_sz;
} lprocfs_obd_nm_t;



/*
 * Structure defining the variables to be maintained
 * on a per attribute basis for entries. The size of
 * the profiling entry needs to be passed during registration
 * with LProcFS, to enable it to allocate space. It is expected
 * that on a per-device class basis, there would exist only
 * one signature.
 */

struct lprofiler_gen {
        __u64 min_time;
        __u64 max_time;
        __u64 sum_time;
        __u64 num_ops;
        /* Default, used for storing intermediate value */
        unsigned long long start_time;
};

struct lprofiler_ldlm {
        __u64 min_time;
        __u64 max_time;
        __u64 sum_time;
        __u64 num_ops;
        __u64 start_time;

        __u64 num_total;
        __u64 num_zerolatency;
        __u64 num_zerolatency_inflight;
        __u64 num_zerolatency_done;
        __u64 non_zero_mintime;
        __u64 non_zero_maxtime;
        __u64 non_zero_sumtime;
};

struct lprofiler_ptlrpc {
        __u64 min_time;
        __u64 max_time;
        __u64 sum_time;
        __u64 num_ops;
        /* Default, used for storing intermediate value */
        __u64 start_time;
        __u64 msgs_alloc;

        __u64 msgs_max;
        __u64 recv_count;

        __u64 recv_length;
        __u64 send_count;
        __u64 send_length;
        __u64 portal_kmemory;
};



struct namespace_index {
        char* name;
};

struct groupspace_index {
        char* name;
        struct namespace_index* directory;
        struct namespace_index* counters;
};

/*
 * Used for connections and such
 */


typedef enum te_leafType {
        e_String=0,
        e_longlong

}e_varType;



struct lprocfs_conn_namespace {
        char* leaf_name;
        e_varType type;
        union {
                char* string_val;
                __u64 cntr_val;
        } x;
};

#ifdef LPROCFS_EXISTS
/*
 * Utility functions to return the timeofday
 *
 */
static inline unsigned long lprocfs_util_gettime(void)
{
        return 0;
        /*
        struct timeval myTime;
        __u64 temp;
        do_gettimeofday(&myTime);
        temp=((__u64)(myTime.tv_usec))&0xFFFFFFFF;
        temp|=(((__u64)(myTime.tv_sec))<<(8*sizeof(unsigned long)));
        return temp;
        */

}
static inline unsigned long lprocfs_util_getdiff(unsigned long x,
                                                 unsigned long y)
{
        return ((x>y)?(x-y):(y-x));
        /*
        __u64 tempSec=0;
        __u64 tempuSec=0;
        tempSec=((y>>8*sizeof(unsigned long))-(x>>8*sizeof(unsigned long)));
        if(tempSec<0)tempSec=-tempSec;
        tempuSec=((y&0xFFFFFFFF)-(x&0xFFFFFFFF));
        if(tempuSec<0)tempuSec=-tempuSec;
        return(tempSec*1000000+tempuSec);
        */

}

#define LPROCFS_NAMESPACE_ENUM(CLASS, NAME) e_ ##CLASS## _##NAME


#define DEV_PROF_START(DEV_CLASS, OBD, PROF_CLASS, ATTRIBUTE)         \
do {                                                                  \
        struct lprofiler_##PROF_CLASS *x;                             \
        int index=LPROCFS_NAMESPACE_ENUM(DEV_CLASS, ATTRIBUTE);       \
        x=(struct lprofiler_##PROF_CLASS *)((OBD)->counters);         \
        x+=index;                                                     \
        /* rdtscl(x->start_time); */                                  \
        x->start_time=lprocfs_util_gettime();                         \
}while(0)                                                             \


#define DEV_PROF_END(DEV_CLASS, OBD, PROF_CLASS, ATTRIBUTE)                   \
do{                                                                           \
        unsigned long end_time, delta;                                        \
        int index=LPROCFS_NAMESPACE_ENUM(DEV_CLASS, ATTRIBUTE);               \
        struct lprofiler_##PROF_CLASS *x=                                     \
                (struct lprofiler_##PROF_CLASS*)((OBD)->counters);            \
        x+=index;                                                             \
        end_time=lprocfs_util_gettime();                                      \
        delta=lprocfs_util_getdiff(x->start_time, end_time);                  \
        if((delta<x->min_time)||(x->min_time==0))x->min_time=delta;           \
        if(delta>x->max_time)x->max_time=delta;                               \
        x->sum_time+=delta;                                                   \
        (x->num_ops)++;                                                       \
}while(0)                                                                     \

/*
#define DEV_PROF_END(DEV_CLASS, OBD, PROF_CLASS, ATTRIBUTE)                   \
do{                                                                           \
        __u64 end_time, delta;                                   \
        int index=LPROCFS_NAMESPACE_ENUM(DEV_CLASS, ATTRIBUTE);               \
        struct lprofiler_##PROF_CLASS *x=                              \
                (struct lprofiler_##PROF_CLASS*)((OBD)->counters);     \
        x+=index;                                                             \
        end_time=lprocfs_util_gettime();                                      \
        delta=lprocfs_util_getdiff(x->start_time, end_time);                  \
        if((delta<x->min_time)||(x->min_time==0))x->min_time=delta;           \
        if(delta>x->max_time)x->max_time=delta;                               \
        x->sum_time+=delta;                                                   \
        (x->num_ops)++;                                                       \
}while(0)                                                                     \
*/
/*
#define DEV_PRINT_CNTR(DEV_CLASS, OBD, PROF_CLASS, ATTRIBUTE)                 \
do{                                                                           \
        int index=LPROCFS_NAMESPACE_ENUM(DEV_CLASS, ATTRIBUTE);               \
        struct lprofiler_##PROF_CLASS *x=                              \
                (struct lprofiler_##PROF_CLASS *)&((OBD)->counters);   \
        x+=index;                                                             \
        printk("Max_time=%lld(usec)\n", x->max_time);                         \
        printk("Min_time=%lld(usec)\n", x->min_time);                         \
        printk("Sum_time=%lld(usec)\n", x->sum_time);                         \
        printk("Num_ops=%lld\n", x->num_ops);                                 \
} while(0)                                                                    \
*/


/*
 * This enum is used as an array index into the counts
 * that are maintained for the MDS device. The number of
 * entries here determine the amount of memory allocated
 * for counters for every instance of this class of
 * device
 */
enum {
        LPROCFS_NAMESPACE_ENUM(mdc, mgmt_setup),
        LPROCFS_NAMESPACE_ENUM(mdc, mgmt_cleanup),
        LPROCFS_NAMESPACE_ENUM(mdc, mgmt_connect),
        LPROCFS_NAMESPACE_ENUM(mdc, mgmt_disconnect),
        LPROCFS_NAMESPACE_ENUM(mdc, reint),
        LPROCFS_NAMESPACE_ENUM(mdc, getstatus),
        LPROCFS_NAMESPACE_ENUM(mdc, getattr),
        LPROCFS_NAMESPACE_ENUM(mdc, setattr),
        LPROCFS_NAMESPACE_ENUM(mdc, open),
        LPROCFS_NAMESPACE_ENUM(mdc, readpage),
        LPROCFS_NAMESPACE_ENUM(mdc, create),
        LPROCFS_NAMESPACE_ENUM(mdc, unlink),
        LPROCFS_NAMESPACE_ENUM(mdc, link),
        LPROCFS_NAMESPACE_ENUM(mdc, rename),
        LPROCFS_MAX_ENUM_DIR_MDC
};

enum {
        LPROCFS_NAMESPACE_ENUM(mds, mgmt_setup),
        LPROCFS_NAMESPACE_ENUM(mds, mgmt_cleanup),
        LPROCFS_NAMESPACE_ENUM(mds, mgmt_connect),
        LPROCFS_NAMESPACE_ENUM(mds, mgmt_disconnect),
        LPROCFS_NAMESPACE_ENUM(mds, getstatus),
        LPROCFS_NAMESPACE_ENUM(mds, connect),
        LPROCFS_NAMESPACE_ENUM(mds, disconnect_callback),
        LPROCFS_NAMESPACE_ENUM(mds, getattr),
        LPROCFS_NAMESPACE_ENUM(mds, readpage),
        LPROCFS_NAMESPACE_ENUM(mds, open),
        LPROCFS_NAMESPACE_ENUM(mds, close),
        LPROCFS_NAMESPACE_ENUM(mds, create),
        LPROCFS_NAMESPACE_ENUM(mds, unlink),
        LPROCFS_NAMESPACE_ENUM(mds, link),
        LPROCFS_NAMESPACE_ENUM(mds, rename),
        LPROCFS_NAMESPACE_ENUM(mds, reint_summary),
        LPROCFS_NAMESPACE_ENUM(mds, reint_setattr),
        LPROCFS_NAMESPACE_ENUM(mds, reint_create),
        LPROCFS_NAMESPACE_ENUM(mds, reint_unlink),
        LPROCFS_NAMESPACE_ENUM(mds, reint_link),
        LPROCFS_NAMESPACE_ENUM(mds, reint_rename),
        LPROCFS_NAMESPACE_ENUM(mds, reint_recreate),
        LPROCFS_MAX_ENUM_DIR_MDS

};

enum {
        LPROCFS_NAMESPACE_ENUM(mdt, mgmt_setup),
        LPROCFS_NAMESPACE_ENUM(mdt, mgmt_cleanup),
        LPROCFS_NAMESPACE_ENUM(mdt, mgmt_connect),
        LPROCFS_NAMESPACE_ENUM(mdt, mgmt_disconnect),
};

enum {
        LPROCFS_NAMESPACE_ENUM(osc, mgmt_setup),
        LPROCFS_NAMESPACE_ENUM(osc, mgmt_cleanup),
        LPROCFS_NAMESPACE_ENUM(osc, mgmt_connect),
        LPROCFS_NAMESPACE_ENUM(osc, mgmt_disconnect),
        LPROCFS_NAMESPACE_ENUM(osc, create),
        LPROCFS_NAMESPACE_ENUM(osc, destroy),
        LPROCFS_NAMESPACE_ENUM(osc, getattr),
        LPROCFS_NAMESPACE_ENUM(osc, setattr),
        LPROCFS_NAMESPACE_ENUM(osc, open),
        LPROCFS_NAMESPACE_ENUM(osc, close),
        LPROCFS_NAMESPACE_ENUM(osc, brw),
        LPROCFS_NAMESPACE_ENUM(osc, punch),
        LPROCFS_NAMESPACE_ENUM(osc, summary),
        LPROCFS_NAMESPACE_ENUM(osc, cancel),
        LPROCFS_MAX_ENUM_DIR_OSC
};

enum {
        LPROCFS_NAMESPACE_ENUM(ost, mgmt_setup),
        LPROCFS_NAMESPACE_ENUM(ost, mgmt_cleanup),
        LPROCFS_NAMESPACE_ENUM(ost, mgmt_connect),
        LPROCFS_NAMESPACE_ENUM(ost, mgmt_disconnect),
        LPROCFS_NAMESPACE_ENUM(ost, create),
        LPROCFS_NAMESPACE_ENUM(ost, destroy),
        LPROCFS_NAMESPACE_ENUM(ost, getattr),
        LPROCFS_NAMESPACE_ENUM(ost, setattr),
        LPROCFS_NAMESPACE_ENUM(ost, open),
        LPROCFS_NAMESPACE_ENUM(ost, close),
        LPROCFS_NAMESPACE_ENUM(ost, brw),
        LPROCFS_NAMESPACE_ENUM(ost, punch),
        LPROCFS_NAMESPACE_ENUM(ost, summary),
        LPROCFS_NAMESPACE_ENUM(ost, cancel),
        LPROCFS_NAMESPACE_ENUM(ost, getinfo),
        LPROCFS_MAX_ENUM_DIR_OST
};

enum {
        LPROCFS_NAMESPACE_ENUM(lov, mgmt_setup),
        LPROCFS_NAMESPACE_ENUM(lov, mgmt_cleanup),
        LPROCFS_NAMESPACE_ENUM(lov, mgmt_connect),
        LPROCFS_NAMESPACE_ENUM(lov, mgmt_disconnect),
        LPROCFS_NAMESPACE_ENUM(lov, create),
        LPROCFS_NAMESPACE_ENUM(lov, destroy),
        LPROCFS_NAMESPACE_ENUM(lov, getattr),
        LPROCFS_NAMESPACE_ENUM(lov, setattr),
        LPROCFS_NAMESPACE_ENUM(lov, open),
        LPROCFS_NAMESPACE_ENUM(lov, close),
        LPROCFS_NAMESPACE_ENUM(lov, brw),
        LPROCFS_NAMESPACE_ENUM(lov, punch),
        LPROCFS_NAMESPACE_ENUM(lov, summary),
        LPROCFS_NAMESPACE_ENUM(lov, cancel),
        LPROCFS_NAMESPACE_ENUM(lov, getinfo),
        LPROCFS_MAX_ENUM_DIR_LOV
};

enum {
        LPROCFS_NAMESPACE_ENUM(obdfilter, mgmt_setup),
        LPROCFS_NAMESPACE_ENUM(obdfilter, mgmt_cleanup),
        LPROCFS_NAMESPACE_ENUM(obdfilter, mgmt_connect),
        LPROCFS_NAMESPACE_ENUM(obdfilter, mgmt_disconnect),
        LPROCFS_NAMESPACE_ENUM(obdfilter, create),
        LPROCFS_NAMESPACE_ENUM(obdfilter, destroy),
        LPROCFS_NAMESPACE_ENUM(obdfilter, getattr),
        LPROCFS_NAMESPACE_ENUM(obdfilter, setattr),
        LPROCFS_NAMESPACE_ENUM(obdfilter, open),
        LPROCFS_NAMESPACE_ENUM(obdfilter, close),
        LPROCFS_NAMESPACE_ENUM(obdfilter, brw),
        LPROCFS_NAMESPACE_ENUM(obdfilter, punch),
        LPROCFS_NAMESPACE_ENUM(obdfilter, summary),
        LPROCFS_NAMESPACE_ENUM(obdfilter, cancel),
        LPROCFS_NAMESPACE_ENUM(obdfilter, getinfo),
        LPROCFS_MAX_ENUM_DIR_OBDFILTER
};

enum {
        LPROCFS_NAMESPACE_ENUM(ldlm, mgmt_setup),
        LPROCFS_NAMESPACE_ENUM(ldlm, mgmt_cleanup),
        LPROCFS_NAMESPACE_ENUM(ldlm, mgmt_connect),
        LPROCFS_NAMESPACE_ENUM(ldlm, mgmt_disconnect),
        LPROCFS_NAMESPACE_ENUM(ldlm, locks_enqueus),
        LPROCFS_NAMESPACE_ENUM(ldlm, locks_cancels),
        LPROCFS_NAMESPACE_ENUM(ldlm, locks_converts),
        LPROCFS_NAMESPACE_ENUM(ldlm, locks_matches),
        LPROCFS_MAX_ENUM_DIR_LDLM
};

enum {
        LPROCFS_NAMESPACE_ENUM(ptlrpc, mgmt_setup),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, mgmt_cleanup),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, mgmt_connect),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, mgmt_disconnect),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, counters),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, network),
        LPROCFS_MAX_ENUM_DIR_PTLRPC
};

#define LPROCFS_DIR_INDEX(CLASS, DIR) \
                         [LPROCFS_NAMESPACE_ENUM(CLASS, DIR)]={#DIR}

/*
 * Similar rule for profiling counters
 */


enum {
        LPROCFS_NAMESPACE_ENUM(mdc, min_time),
        LPROCFS_NAMESPACE_ENUM(mdc, max_time),
        LPROCFS_NAMESPACE_ENUM(mdc, sum_time),
        LPROCFS_NAMESPACE_ENUM(mdc, num_ops),
        LPROF_MDC_MAX
};

enum {
        LPROCFS_NAMESPACE_ENUM(mds, min_time),
        LPROCFS_NAMESPACE_ENUM(mds, max_time),
        LPROCFS_NAMESPACE_ENUM(mds, sum_time),
        LPROCFS_NAMESPACE_ENUM(mds, num_ops),
        LPROF_MDS_MAX
};

enum {
        LPROCFS_NAMESPACE_ENUM(osc, min_time),
        LPROCFS_NAMESPACE_ENUM(osc, max_time),
        LPROCFS_NAMESPACE_ENUM(osc, sum_time),
        LPROCFS_NAMESPACE_ENUM(osc, num_ops),
        LPROF_OSC_MAX
};

enum {
        LPROCFS_NAMESPACE_ENUM(ost, min_time),
        LPROCFS_NAMESPACE_ENUM(ost, max_time),
        LPROCFS_NAMESPACE_ENUM(ost, sum_time),
        LPROCFS_NAMESPACE_ENUM(ost, num_ops),
        LPROF_OST_MAX
};

enum {
        LPROCFS_NAMESPACE_ENUM(lov, min_time),
        LPROCFS_NAMESPACE_ENUM(lov, max_time),
        LPROCFS_NAMESPACE_ENUM(lov, sum_time),
        LPROCFS_NAMESPACE_ENUM(lov, num_ops),
        LPROF_LOV_MAX
};

enum {
        LPROCFS_NAMESPACE_ENUM(obdfilter, min_time),
        LPROCFS_NAMESPACE_ENUM(obdfilter, max_time),
        LPROCFS_NAMESPACE_ENUM(obdfilter, sum_time),
        LPROCFS_NAMESPACE_ENUM(obdfilter, num_ops),
        LPROF_OBDFILTER_MAX
};


enum {
        LPROCFS_NAMESPACE_ENUM(ldlm, min_time),
        LPROCFS_NAMESPACE_ENUM(ldlm, max_time),
        LPROCFS_NAMESPACE_ENUM(ldlm, sum_time),
        LPROCFS_NAMESPACE_ENUM(ldlm, num_ops),
        LPROCFS_NAMESPACE_ENUM(ldlm, num_total),
        LPROCFS_NAMESPACE_ENUM(ldlm, num_zerolatency),
        LPROCFS_NAMESPACE_ENUM(ldlm, num_zerolatency_inflight),
        LPROCFS_NAMESPACE_ENUM(ldlm, num_zerolatency_done),
        LPROCFS_NAMESPACE_ENUM(ldlm, nonzero_mintime),
        LPROCFS_NAMESPACE_ENUM(ldlm, nonzero_maxtime),
        LPROCFS_NAMESPACE_ENUM(ldlm, nonzero_sumtime),
        LPROF_LDLM_MAX
};

enum {
        LPROCFS_NAMESPACE_ENUM(ptlrpc, min_time),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, max_time),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, sum_time),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, num_ops),

        LPROCFS_NAMESPACE_ENUM(ptlrpc, msgs_alloc),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, msgs_max),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, recv_count),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, recv_length),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, send_count),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, send_length),
        LPROCFS_NAMESPACE_ENUM(ptlrpc, portal_kmemory),
        LPROF_PTLRPC_MAX

};

/*
 * and for groups
 */
#define LPROCFS_ENUM(X) e_##X

enum {
        LPROCFS_ENUM(mdc),
        LPROCFS_ENUM(mds),
        LPROCFS_ENUM(mdt),
        LPROCFS_ENUM(osc),
        LPROCFS_ENUM(ost),
        LPROCFS_ENUM(lov),
        LPROCFS_ENUM(obdfilter),
        LPROCFS_ENUM(ldlm),
        LPROCFS_ENUM(ptlrpc),
        LPROCFS_GROUP_MAX
};

#define LPROCFS_CNTR_INDEX(CLASS, NAME) \
                   [LPROCFS_NAMESPACE_ENUM(CLASS, NAME)]={#NAME}

#define LPROCFS_GROUP_CREATE(CLASS) \
      [LPROCFS_ENUM(CLASS)]={#CLASS, dir_##CLASS##_index, prof_##CLASS##_index}

/*
 * OBD Namespace API: Obtain the namespace group index, given a name
 */
int lprocfs_get_nm(char* name, lprocfs_obd_nm_t* collection);



/*
 * OBD device APIs
 */

int lprocfs_reg_dev(struct obd_device* device, lprocfs_group_t* namespace,
                    unsigned int cnt_struct_size);

int lprocfs_dereg_dev(struct obd_device* device);

/*
 * Connections API
 */
int lprocfs_reg_conn(unsigned int conn_number,
                     struct lprocfs_conn_namespace* namespace);
int lprocfs_dereg_conn(unsigned int conn_number);

/*
 * Import/Export APIs
 */
int lprocfs_add_export(unsigned int conn_number,
                       struct obd_device* device);
int lprocfs_add_import(unsigned int conn_number,
                       struct obd_device* device);
int lprocfs_remove_export(unsigned int conn_number,
                          struct obd_device* device);
int lprocfs_remove_import(unsigned int conn_number,
                          struct obd_device* device);

/*
 * Utility functions
 */

struct proc_dir_entry* lprocfs_add_dir(struct proc_dir_entry* root,
                                       const char* name,
                                       const char* tok,
                                       unsigned int* escape);


struct proc_dir_entry* lprocfs_mkdir(const char* dname,
                                     struct proc_dir_entry *parent);


struct proc_dir_entry* lprocfs_bfs_srch(struct proc_dir_entry* root,
                                        const char* name);

struct proc_dir_entry* lprocfs_srch(struct proc_dir_entry* head,
                                    const char* name);

int lprocfs_link_dir_counters(struct obd_device* device,
                              struct proc_dir_entry* this_dev_root,
                              lprocfs_group_t* namespace,
                              unsigned int cnt_struct_size,
                              unsigned int class_array_index);

int lprocfs_create_dir_namespace(struct proc_dir_entry* this_dev_root,
                                 lprocfs_group_t* namespace,
                                 unsigned int *num_dirs);

int lprocfs_getclass_idx(struct groupspace_index* group,
                         const char* classname);
struct proc_dir_entry* lprocfs_mkinitdir(struct obd_device* device);
int lprocfs_get_idx(struct namespace_index* class, const char* dir_name);
unsigned int lprocfs_add_var(struct obd_device* device,
                             struct proc_dir_entry* root,
                             lprocfs_vars_t* variable,
                             int dir_arr_index,
                             int cnt_arr_index,
                             unsigned int cnt_arr_size,
                             lprofilers_e type);


void lprocfs_remove_all(struct proc_dir_entry* root);

/*
 * List of read/write functions that will implement reading
 * or writing to counters/other variables from userland
 * processes. Note that the definition allows as many different
 * functions to be defined as there are counter-variables.
 * In practice, however, the module implementor is expected
 * to have a different function only when the variable types are
 * different, for e.g counter types will have one read/write
 * function, while strings will have another.
 *
 */

int lprocfs_ll_rd(char* page, char **start, off_t off,
		 int count, int *eof, void *data);
int lprocfs_ll_wr(struct file* file, const char *buffer,
		  unsigned long count, void *data);

int rd_other(char* page, char **start, off_t off,
             int count, int *eof, void *data);
int wr_other(struct file* file, const char *buffer,
             unsigned long count, void *data);

int rd_string(char* page, char **start, off_t off,
              int count, int *eof, void *data);
int wr_string(struct file* file, const char *buffer,
              unsigned long count, void *data);

int rd_fs_type(char* page, char **start, off_t off,
              int count, int *eof, void *data);

int rd_uuid(char* page, char **start, off_t off,
             int count, int *eof, void *data);
int wr_uuid(struct file* file, const char *buffer,
             unsigned long count, void *data);

int rd_uuid(char* page, char **start, off_t off,
             int count, int *eof, void *data);

int rd_blksize(char* page, char **start, off_t off,
             int count, int *eof, void *data);
int rd_blktotal(char* page, char **start, off_t off,
             int count, int *eof, void *data);
int rd_blkfree(char* page, char **start, off_t off,
             int count, int *eof, void *data);
int rd_kbfree(char* page, char **start, off_t off,
             int count, int *eof, void *data);

int rd_numobjects(char* page, char **start, off_t off,
             int count, int *eof, void *data);
int rd_objfree(char* page, char **start, off_t off,
             int count, int *eof, void *data);

int rd_objgroups(char* page, char **start, off_t off,
             int count, int *eof, void *data);


#else /* LProcFS not compiled */

#define DEV_PROF_START(DEV_CLASS, OBD, PROF_CLASS, ATTRIBUTE) 0
#define DEV_PROF_END(DEV_CLASS, OBD, PROF_CLASS, ATTRIBUTE) 0
#define DEV_PRINT_CNTR(DEV_CLASS, OBD, PROF_CLASS, ATTRIBUTE) 0

static inline int lprocfs_get_nm(char* name, lprocfs_obd_nm_t* collection)
{
        return -1;
}

static inline int lprocfs_reg_dev(struct obd_device* device,
                                  lprocfs_group_t* namespace,
                                  unsigned int cnt_struct_size)
{
        return 0;
}

static inline int lprocfs_dereg_dev(struct obd_device* device)
{
        return LPROCFS_SUCCESS;
}

static inline int lprocfs_reg_conn(unsigned int conn_number,
                                   struct lprocfs_conn_namespace* nm)
{
        return 0;
}

static inline int lprocfs_dereg_conn(unsigned int conn_number)
{
        return 0;
}

static inline int lprocfs_add_export(unsigned int conn_number,
                                     struct obd_device* device)
{
        return 0;
}

static inline int lprocfs_add_import(unsigned int conn_number,
                                     struct obd_device* device)
{
        return 0;
}

static inline int lprocfs_remove_export(unsigned int conn_number,
                                        struct obd_device* device)
{
        return 0;
}

static inline int lprocfs_remove_import(unsigned int conn_number,
                                        struct obd_device* device)
{
        return 0;
}

#endif /* LPROCFS_EXISTS */

#endif /* __LPROCFS_H__ */
