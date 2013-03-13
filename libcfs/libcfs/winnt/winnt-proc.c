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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>
#include "tracefile.h"
#include <lustre_lib.h>

#ifdef __KERNEL__


/*
 *  /proc emulator routines ...
 */

/* The root node of the proc fs emulation: / */
cfs_proc_entry_t *              cfs_proc_root = NULL;

/* The root node of the proc fs emulation: /proc */
cfs_proc_entry_t *              cfs_proc_proc = NULL;

/* The fs sys directory: /proc/fs */
cfs_proc_entry_t *              cfs_proc_fs = NULL;

/* The sys root: /proc/sys */
cfs_proc_entry_t *              cfs_proc_sys = NULL;

/* The sys root: /proc/dev | to implement misc device */
cfs_proc_entry_t *              cfs_proc_dev = NULL;


/* SLAB object for cfs_proc_entry_t allocation */
cfs_mem_cache_t *               proc_entry_cache = NULL;

/* root node for sysctl table */
cfs_sysctl_table_header_t       root_table_header;

/* The global lock to protect all the access */

#if LIBCFS_PROCFS_SPINLOCK
spinlock_t			proc_fs_lock;

#define INIT_PROCFS_LOCK()	spin_lock_init(&proc_fs_lock)
#define LOCK_PROCFS()		spin_lock(&proc_fs_lock)
#define UNLOCK_PROCFS()		spin_unlock(&proc_fs_lock)

#else

struct mutex				proc_fs_lock;

#define INIT_PROCFS_LOCK()      cfs_init_mutex(&proc_fs_lock)
#define LOCK_PROCFS()           cfs_mutex_down(&proc_fs_lock)
#define UNLOCK_PROCFS()         cfs_mutex_up(&proc_fs_lock)

#endif

static ssize_t
proc_file_read(struct file * file, const char * buf, size_t nbytes, loff_t *ppos)
{
    char    *page;
    ssize_t retval=0;
    int eof=0;
    ssize_t n, count;
    char    *start;
    cfs_proc_entry_t * dp;

    dp = (cfs_proc_entry_t  *) file->f_inode->i_priv;
    if (!(page = (char*) cfs_alloc(CFS_PAGE_SIZE, 0)))
        return -ENOMEM;

    while ((nbytes > 0) && !eof) {

        count = min_t(size_t, PROC_BLOCK_SIZE, nbytes);

        start = NULL;
        if (dp->read_proc) {
            n = dp->read_proc( page, &start, (long)*ppos,
                               count, &eof, dp->data);
        } else
            break;

        if (!start) {
            /*
             * For proc files that are less than 4k
             */
            start = page + *ppos;
            n -= (ssize_t)(*ppos);
            if (n <= 0)
                break;
            if (n > count)
                n = count;
        }
        if (n == 0)
            break;  /* End of file */
        if (n < 0) {
            if (retval == 0)
                retval = n;
            break;
        }
        
        n -= cfs_copy_to_user((void *)buf, start, n);
        if (n == 0) {
            if (retval == 0)
                retval = -EFAULT;
            break;
        }

        *ppos += n;
        nbytes -= n;
        buf += n;
        retval += n;
    }
    cfs_free(page);

    return retval;
}

static ssize_t
proc_file_write(struct file * file, const char * buffer,
                size_t count, loff_t *ppos)
{
    cfs_proc_entry_t  * dp;
    
    dp = (cfs_proc_entry_t *) file->f_inode->i_priv;

    if (!dp->write_proc)
        return -EIO;

    /* FIXME: does this routine need ppos?  probably... */
    return dp->write_proc(file, buffer, count, dp->data);
}

struct file_operations proc_file_operations = {
    /*owner*/       THIS_MODULE,
    /*lseek:*/      NULL, //proc_file_lseek,
    /*read:*/       proc_file_read,
    /*write:*/      proc_file_write,
    /*ioctl:*/      NULL,
    /*open:*/       NULL,
    /*release:*/    NULL
};

/* allocate proc entry block */

cfs_proc_entry_t *
proc_alloc_entry()
{
    cfs_proc_entry_t * entry = NULL;

    entry = cfs_mem_cache_alloc(proc_entry_cache, 0);
    if (!entry) {
        return NULL;
    }

    memset(entry, 0, sizeof(cfs_proc_entry_t));

    entry->magic = CFS_PROC_ENTRY_MAGIC;
    RtlInitializeSplayLinks(&(entry->s_link));
    entry->proc_fops = &proc_file_operations;

    return entry;
}

/* free the proc entry block */

void
proc_free_entry(cfs_proc_entry_t * entry)

{
    ASSERT(entry->magic == CFS_PROC_ENTRY_MAGIC);

    cfs_mem_cache_free(proc_entry_cache, entry);
}

/* dissect the path string for a given full proc path */

void
proc_dissect_name(
    const char *path,
    char **first,
    int  *first_len,
    char **remain
    )
{
    int i = 0, j = 0, len = 0;

    *first = *remain = NULL;
    *first_len = 0;

    len = strlen(path);

    while (i < len && (path[i] == '/')) i++;

    if (i < len) {

        *first = (char *)path + i;
        while (i < len && (path[i] != '/')) i++;
        *first_len = (int)(path + i - *first);

        if (i + 1 < len) {
            *remain = (char *)path + i + 1;
        }
    }
}

/* search the children entries of the parent entry */

cfs_proc_entry_t *
proc_search_splay (
    cfs_proc_entry_t *  parent,
    char *              name
    )
{
    cfs_proc_entry_t *  node;
    PRTL_SPLAY_LINKS    link;

    ASSERT(parent->magic == CFS_PROC_ENTRY_MAGIC);
    ASSERT(cfs_is_flag_set(parent->flags, CFS_PROC_FLAG_DIRECTORY));

    link = parent->root;

    while (link) {

        ANSI_STRING ename,nname;
        long        result;

        node = CONTAINING_RECORD(link, cfs_proc_entry_t, s_link);

        ASSERT(node->magic == CFS_PROC_ENTRY_MAGIC);

        /*  Compare the prefix in the tree with the full name */

        RtlInitAnsiString(&ename, name);
        RtlInitAnsiString(&nname, node->name);

        result = RtlCompareString(&nname, &ename,TRUE);

        if (result > 0) {

            /*  The prefix is greater than the full name
                so we go down the left child          */

            link = RtlLeftChild(link);

        } else if (result < 0) {

            /*  The prefix is less than the full name
                so we go down the right child      */

            link = RtlRightChild(link);

        } else {

            /*  We got the entry in the splay tree and
                make it root node instead           */

            parent->root = RtlSplay(link);

            return node;
        }

        /* we need continue searching down the tree ... */
    }

    /*  There's no the exptected entry in the splay tree */

    return NULL;
}

int
proc_insert_splay (
    cfs_proc_entry_t * parent,
    cfs_proc_entry_t * child
    )
{
    cfs_proc_entry_t * entry;

    ASSERT(parent != NULL && child != NULL);
    ASSERT(parent->magic == CFS_PROC_ENTRY_MAGIC);
    ASSERT(child->magic == CFS_PROC_ENTRY_MAGIC);
    ASSERT(cfs_is_flag_set(parent->flags, CFS_PROC_FLAG_DIRECTORY));

    if (!parent->root) {
        parent->root = &(child->s_link);
    } else {
        entry = CONTAINING_RECORD(parent->root, cfs_proc_entry_t, s_link);
        while (TRUE) {
            long        result;
            ANSI_STRING ename, cname;

            ASSERT(entry->magic == CFS_PROC_ENTRY_MAGIC);

            RtlInitAnsiString(&ename, entry->name);
            RtlInitAnsiString(&cname, child->name);

            result = RtlCompareString(&ename, &cname,TRUE);

            if (result == 0) {
                cfs_enter_debugger();
                if (entry == child) {
                    break;
                }
                return FALSE;
            }

            if (result > 0) {
                if (RtlLeftChild(&entry->s_link) == NULL) {
                    RtlInsertAsLeftChild(&entry->s_link, &child->s_link);
                    break;
                } else {
                    entry = CONTAINING_RECORD( RtlLeftChild(&entry->s_link),
                                               cfs_proc_entry_t, s_link);
                }
            } else {
                if (RtlRightChild(&entry->s_link) == NULL) {
                    RtlInsertAsRightChild(&entry->s_link, &child->s_link);
                    break;
                } else {
                    entry = CONTAINING_RECORD( RtlRightChild(&entry->s_link),
                                               cfs_proc_entry_t, s_link );
                }
            }
        }
    }

    cfs_set_flag(child->flags, CFS_PROC_FLAG_ATTACHED);
    parent->nlink++;
    child->parent = parent;

    return TRUE;
}


/* remove a child entry from the splay tree */
int
proc_remove_splay (
    cfs_proc_entry_t *  parent,
    cfs_proc_entry_t *  child
    )
{
    cfs_proc_entry_t * entry = NULL;

    ASSERT(parent != NULL && child != NULL);
    ASSERT(parent->magic == CFS_PROC_ENTRY_MAGIC);
    ASSERT(child->magic == CFS_PROC_ENTRY_MAGIC);
    ASSERT(cfs_is_flag_set(parent->flags, CFS_PROC_FLAG_DIRECTORY));
    ASSERT(cfs_is_flag_set(child->flags, CFS_PROC_FLAG_ATTACHED));
    ASSERT(child->parent == parent);

    entry = proc_search_splay(parent, child->name);

    if (entry) {
        ASSERT(entry == child);
        parent->root = RtlDelete(&(entry->s_link));
        parent->nlink--;
    } else {
        cfs_enter_debugger();
        return FALSE;
    }

    return TRUE;
}


/* search a node inside the proc fs tree */

cfs_proc_entry_t *
proc_search_entry(
    const char *        name,
    cfs_proc_entry_t *  root
    )
{
    cfs_proc_entry_t *  entry;
    cfs_proc_entry_t *  parent;
    char *first, *remain;
    int   flen;
    char *ename = NULL;

    parent = root;
    entry = NULL;

    ename = cfs_alloc(0x21, CFS_ALLOC_ZERO);

    if (ename == NULL) {
        goto errorout;
    }

again:

    /* dissect the file name string */
    proc_dissect_name(name, &first, &flen, &remain);

    if (first) {

        if (flen >= 0x20) {
            cfs_enter_debugger();
            entry = NULL;
            goto errorout;
        }

        memset(ename, 0, 0x20);
        memcpy(ename, first, flen);

        entry = proc_search_splay(parent, ename);

        if (!entry) {
            goto errorout;
        }

        if (remain) {
            name = remain;
            parent = entry;

            goto again;
        }
    }

errorout:

    if (ename) {
        cfs_free(ename);
    }

    return entry;   
}

/* insert the path nodes to the proc fs tree */

cfs_proc_entry_t *
proc_insert_entry(
    const char *        name,
    cfs_proc_entry_t *  root
    )
{
    cfs_proc_entry_t *entry;
    cfs_proc_entry_t *parent;
    char *first, *remain;
    int flen;
    char ename[0x20];

    parent = root;
    entry = NULL;

again:

    proc_dissect_name(name, &first, &flen, &remain);

    if (first) {

        if (flen >= 0x20) {
            return NULL;
        }

        memset(ename, 0, 0x20);
        memcpy(ename, first, flen);

        entry = proc_search_splay(parent, ename);

        if (!entry) {
            entry = proc_alloc_entry();
            memcpy(entry->name, ename, flen);

            if (entry) {
                if(!proc_insert_splay(parent, entry)) {
                    proc_free_entry(entry);
                    entry = NULL;
                }
            }
        }

        if (!entry) {
            return NULL;
        }

        if (remain) {
            entry->mode |= S_IFDIR | S_IRUGO | S_IXUGO;
            cfs_set_flag(entry->flags, CFS_PROC_FLAG_DIRECTORY);
            name = remain;
            parent = entry;
            goto again;
        }
    }

    return entry;   
}

/* remove the path nodes from the proc fs tree */

void
proc_remove_entry(
    const char *        name,
    cfs_proc_entry_t *  root
    )
{
    cfs_proc_entry_t *entry;
    char *first, *remain;
    int  flen;
    char ename[0x20];

    entry  = NULL;

    proc_dissect_name(name, &first, &flen, &remain);

    if (first) {

        memset(ename, 0, 0x20);
        memcpy(ename, first, flen);

        entry = proc_search_splay(root, ename);

        if (entry) {

            if (remain) {
                ASSERT(S_ISDIR(entry->mode));
                proc_remove_entry(remain, entry);
            }

            if (!entry->nlink) {
                proc_remove_splay(root, entry);
                proc_free_entry(entry);
            }
        }
    } else {
        cfs_enter_debugger();
    }
}

/* create proc entry and insert it into the proc fs */

cfs_proc_entry_t *
create_proc_entry (
    const char *        name,
    mode_t              mode,
    cfs_proc_entry_t *  parent
    )
{
    cfs_proc_entry_t *entry  = NULL;

    if (S_ISDIR(mode)) {
        if ((mode & S_IALLUGO) == 0)
        mode |= S_IRUGO | S_IXUGO;
    } else {
        if ((mode & S_IFMT) == 0)
            mode |= S_IFREG;
        if ((mode & S_IALLUGO) == 0)
            mode |= S_IRUGO;
    }

    LOCK_PROCFS();
    ASSERT(NULL != cfs_proc_root);

    if (!parent) {
        if (name[0] == '/') {
            parent = cfs_proc_root;
        } else {
            ASSERT(NULL != cfs_proc_proc);
            parent = cfs_proc_proc;
        }
    }

    entry = proc_search_entry(name, parent);

    if (!entry) {
        entry = proc_insert_entry(name, parent);
        if (!entry) {
            /* Failed to create/insert the splay node ... */
            cfs_enter_debugger();
            goto errorout;
        }
        /* Initializing entry ... */
        entry->mode = mode;

        if (S_ISDIR(mode)) {
            cfs_set_flag(entry->flags, CFS_PROC_FLAG_DIRECTORY);
        }
    }

errorout:

    UNLOCK_PROCFS();

    return entry;
}


/* search the specified entry form the proc fs */

cfs_proc_entry_t *
search_proc_entry(
    const char *        name,
    cfs_proc_entry_t *  root
    )
{
    cfs_proc_entry_t * entry;

    LOCK_PROCFS();
    ASSERT(cfs_proc_root != NULL);
    if (root == NULL) {
        if (name[0] == '/') {
            root = cfs_proc_root;
        } else {
            ASSERT(cfs_proc_proc != NULL);
            root = cfs_proc_proc;
        }
    }
    entry = proc_search_entry(name, root);
    UNLOCK_PROCFS();

    return entry;    
}

/* remove the entry from the proc fs */

void
remove_proc_entry(
    const char *        name,
    cfs_proc_entry_t *  parent
    )
{
    LOCK_PROCFS();
    ASSERT(cfs_proc_root != NULL);
    if (parent == NULL) {
        if (name[0] == '/') {
            parent = cfs_proc_root;
        } else {
            ASSERT(cfs_proc_proc != NULL);
            parent = cfs_proc_proc;
        }
    }
    proc_remove_entry(name, parent);
    UNLOCK_PROCFS();
}


void proc_destroy_splay(cfs_proc_entry_t * entry)
{
    cfs_proc_entry_t * node;

    if (S_ISDIR(entry->mode)) {

        while (entry->root) {
            node = CONTAINING_RECORD(entry->root, cfs_proc_entry_t, s_link);
            entry->root = RtlDelete(&(node->s_link));
            proc_destroy_splay(node);
        }
    }

    proc_free_entry(entry);
}

cfs_proc_entry_t *proc_symlink(
    const char *name,
	cfs_proc_entry_t *parent,
    const char *dest
    )
{
    cfs_enter_debugger();
    return NULL;
}

cfs_proc_entry_t *proc_mkdir(
    const char *name,
	cfs_proc_entry_t *parent)
{
    return create_proc_entry((char *)name, S_IFDIR, parent);
}

void proc_destory_subtree(cfs_proc_entry_t *entry)
{
    LOCK_PROCFS();
    entry->root = NULL;
    proc_destroy_splay(entry);
    UNLOCK_PROCFS();
}

/* destory the whole proc fs tree */

void proc_destroy_fs()
{
    LOCK_PROCFS();

    if (cfs_proc_root) {
        proc_destroy_splay(cfs_proc_root);
    }

    if (proc_entry_cache) {
        cfs_mem_cache_destroy(proc_entry_cache);
    }
   
    UNLOCK_PROCFS();
}

static char proc_item_path[512];


void proc_show_tree(cfs_proc_entry_t * node);
void proc_print_node(cfs_proc_entry_t * node)
{
    if (node != cfs_proc_root) {
        if (S_ISDIR(node->mode)) {
            printk("%s/%s/\n", proc_item_path, node->name);
        } else {
            printk("%s/%s\n", proc_item_path, node->name);
        }
    } else {
         printk("%s\n", node->name);
    }

    if (S_ISDIR(node->mode)) {
        proc_show_tree(node);
    }
}

void proc_show_child(PRTL_SPLAY_LINKS link)
{
    cfs_proc_entry_t * entry  = NULL;

    if (!link) {
        return;
    }

    proc_show_child(link->LeftChild);
    entry = CONTAINING_RECORD(link, cfs_proc_entry_t, s_link);
    proc_print_node(entry);
    proc_show_child(link->RightChild);
}

void proc_show_tree(cfs_proc_entry_t * node)
{
    PRTL_SPLAY_LINKS link = NULL;
    cfs_proc_entry_t * entry = NULL;
    int i;

    link = node->root;
    i = strlen(proc_item_path);
    ASSERT(S_ISDIR(node->mode));
    if (node != cfs_proc_root) {
        strcat(proc_item_path, "/");
        strcat(proc_item_path, node->name);
    }
    proc_show_child(link);
    proc_item_path[i] = 0;
}

void proc_print_splay()
{
    printk("=================================================\n");
    printk("Lustre virtual proc entries:\n");
    printk("-------------------------------------------------\n");
    LOCK_PROCFS();
    proc_show_tree(cfs_proc_root);
    UNLOCK_PROCFS();
    printk("=================================================\n");
}


/* initilaize / build the proc fs tree */
int proc_init_fs()
{
    cfs_proc_entry_t * root = NULL;

    memset(&(root_table_header), 0, sizeof(struct ctl_table_header));
    CFS_INIT_LIST_HEAD(&(root_table_header.ctl_entry));

    INIT_PROCFS_LOCK();
    proc_entry_cache = cfs_mem_cache_create(
                            NULL,
                            sizeof(cfs_proc_entry_t),
                            0,
                            0
                            );

    if (!proc_entry_cache) {
        return (-ENOMEM);
    }

    root = proc_alloc_entry();
    if (!root) {
        proc_destroy_fs();
        return (-ENOMEM);
    }
    root->magic = CFS_PROC_ENTRY_MAGIC;
    root->flags = CFS_PROC_FLAG_DIRECTORY;
    root->mode  = S_IFDIR | S_IRUGO | S_IXUGO;
    root->nlink = 3; // root should never be deleted.
    root->name[0]='/';
    root->name[1]= 0;
    cfs_proc_root = root;

    cfs_proc_dev = create_proc_entry("dev", S_IFDIR, root);
    if (!cfs_proc_dev) {
        goto errorout;
    }
    cfs_proc_dev->nlink = 1;

    cfs_proc_proc  = create_proc_entry("proc", S_IFDIR, root);
    if (!cfs_proc_proc) {
        goto errorout;
    }
    cfs_proc_proc->nlink = 1;

    cfs_proc_fs = create_proc_entry("fs",  S_IFDIR, cfs_proc_proc);
    if (!cfs_proc_fs) {
        goto errorout;
    }
    cfs_proc_fs->nlink = 1;

    cfs_proc_sys = create_proc_entry("sys",  S_IFDIR, cfs_proc_proc);
    if (!cfs_proc_sys) {
        goto errorout;
    }
    cfs_proc_sys->nlink = 1;

  
    return 0;

errorout:

    proc_destroy_fs();
    return (-ENOMEM);
}


static ssize_t do_rw_proc(int write, struct file * file, char * buf,
              size_t count, loff_t *ppos)
{
    int op;
    cfs_proc_entry_t *de;
    struct ctl_table *table;
    size_t res;
    ssize_t error;
    
    de = (cfs_proc_entry_t *) file->proc_dentry; 

    if (!de || !de->data)
        return -ENOTDIR;
    table = (struct ctl_table *) de->data;
    if (!table || !table->proc_handler)
        return -ENOTDIR;
    op = (write ? 002 : 004);

    res = count;

    /*
     * FIXME: we need to pass on ppos to the handler.
     */

    error = (*table->proc_handler) (table, write, file, buf, &res);
    if (error)
        return error;
    return res;
}

static ssize_t proc_readsys(struct file * file, char * buf,
                size_t count, loff_t *ppos)
{
    return do_rw_proc(0, file, buf, count, ppos);
}

static ssize_t proc_writesys(struct file * file, const char * buf,
                 size_t count, loff_t *ppos)
{
    return do_rw_proc(1, file, (char *) buf, count, ppos);
}


struct file_operations proc_sys_file_operations = {
    /*owner*/       THIS_MODULE,
    /*lseek:*/      NULL,
    /*read:*/       proc_readsys,
    /*write:*/      proc_writesys,
    /*ioctl:*/      NULL,
    /*open:*/       NULL,
    /*release:*/    NULL
};


/* Scan the sysctl entries in table and add them all into /proc */
void register_proc_table(cfs_sysctl_table_t * table, cfs_proc_entry_t * root)
{
    cfs_proc_entry_t * de;
    int len;
    mode_t mode;
    
    for (; table->ctl_name; table++) {
        /* Can't do anything without a proc name. */
        if (!table->procname)
            continue;
        /* Maybe we can't do anything with it... */
        if (!table->proc_handler && !table->child) {
            printk(CFS_KERN_WARNING "SYSCTL: Can't register %s\n",
                table->procname);
            continue;
        }

        len = strlen(table->procname);
        mode = table->mode;

        de = NULL;
        if (table->proc_handler)
            mode |= S_IFREG;
        else {
            de = search_proc_entry(table->procname, root);
            if (de) {
                break;
            }
            /* If the subdir exists already, de is non-NULL */
        }

        if (!de) {

            de = create_proc_entry((char *)table->procname, mode, root);
            if (!de)
                continue;
            de->data = (void *) table;
            if (table->proc_handler) {
                de->proc_fops = &proc_sys_file_operations;
            }
        }
        table->de = de;
        if (de->mode & S_IFDIR)
            register_proc_table(table->child, de);
    }
}


/*
 * Unregister a /proc sysctl table and any subdirectories.
 */
void unregister_proc_table(cfs_sysctl_table_t * table, cfs_proc_entry_t *root)
{
    cfs_proc_entry_t *de;
    for (; table->ctl_name; table++) {
        if (!(de = table->de))
            continue;
        if (de->mode & S_IFDIR) {
            if (!table->child) {
                printk (CFS_KERN_ALERT "Help- malformed sysctl tree on free\n");
                continue;
            }
            unregister_proc_table(table->child, de);

            /* Don't unregister directories which still have entries.. */
            if (de->nlink)
                continue;
        }

        /* Don't unregister proc entries that are still being used.. */
        if (de->nlink)
            continue;

        table->de = NULL;
        remove_proc_entry((char *)table->procname, root);
    }
}

/* The generic string strategy routine: */
int sysctl_string(cfs_sysctl_table_t *table, int *name, int nlen,
          void *oldval, size_t *oldlenp,
          void *newval, size_t newlen, void **context)
{
    int l, len;
    
    if (!table->data || !table->maxlen) 
        return -ENOTDIR;
    
    if (oldval && oldlenp) {
        if(get_user(len, oldlenp))
            return -EFAULT;
        if (len) {
            l = strlen(table->data);
            if (len > l) len = l;
            if (len >= table->maxlen)
                len = table->maxlen;
            if(cfs_copy_to_user(oldval, table->data, len))
                return -EFAULT;
            if(put_user(0, ((char *) oldval) + len))
                return -EFAULT;
            if(put_user(len, oldlenp))
                return -EFAULT;
        }
    }
    if (newval && newlen) {
        len = newlen;
        if (len > table->maxlen)
            len = table->maxlen;
        if(cfs_copy_from_user(table->data, newval, len))
            return -EFAULT;
        if (len == table->maxlen)
            len--;
        ((char *) table->data)[len] = 0;
    }
    return 0;
}

/**
 * simple_strtoul - convert a string to an unsigned long
 * @cp: The start of the string
 * @endp: A pointer to the end of the parsed string will be placed here
 * @base: The number base to use
 */
unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base)
{
    unsigned long result = 0, value;

    if (!base) {
        base = 10;
        if (*cp == '0') {
            base = 8;
            cp++;
            if ((*cp == 'x') && cfs_isxdigit(cp[1])) {
                cp++;
                base = 16;
            }
        }
    }
    while (cfs_isxdigit(*cp) &&
           (value = cfs_isdigit(*cp) ? *cp-'0' : toupper(*cp)-'A'+10) < base) {
        result = result*base + value;
        cp++;
    }
    if (endp)
        *endp = (char *)cp;
    return result;
}

#define OP_SET  0
#define OP_AND  1
#define OP_OR   2
#define OP_MAX  3
#define OP_MIN  4


static int do_proc_dointvec(cfs_sysctl_table_t *table, int write, struct file *filp,
          void *buffer, size_t *lenp, int conv, int op)
{
    int *i, vleft, first=1, neg, val;
    size_t left, len;
    
    #define TMPBUFLEN 20
    char buf[TMPBUFLEN], *p;
    
    if (!table->data || !table->maxlen || !*lenp)
    {
        *lenp = 0;
        return 0;
    }
    
    i = (int *) table->data;
    vleft = table->maxlen / sizeof(int);
    left = *lenp;
    
    for (; left && vleft--; i++, first=0) {
        if (write) {
            while (left) {
                char c;
                if(get_user(c,(char *) buffer))
                    return -EFAULT;
                if (!isspace(c))
                    break;
                left--;
                ((char *) buffer)++;
            }
            if (!left)
                break;
            neg = 0;
            len = left;
            if (len > TMPBUFLEN-1)
                len = TMPBUFLEN-1;
            if(cfs_copy_from_user(buf, buffer, len))
                return -EFAULT;
            buf[len] = 0;
            p = buf;
            if (*p == '-' && left > 1) {
                neg = 1;
                left--, p++;
            }
            if (*p < '0' || *p > '9')
                break;
            val = simple_strtoul(p, &p, 0) * conv;
            len = p-buf;
            if ((len < left) && *p && !isspace(*p))
                break;
            if (neg)
                val = -val;
            (char *)buffer += len;
            left -= len;
            switch(op) {
            case OP_SET:    *i = val; break;
            case OP_AND:    *i &= val; break;
            case OP_OR: *i |= val; break;
            case OP_MAX:    if(*i < val)
                        *i = val;
                    break;
            case OP_MIN:    if(*i > val)
                        *i = val;
                    break;
            }
        } else {
            p = buf;
            if (!first)
                *p++ = '\t';
            sprintf(p, "%d", (*i) / conv);
            len = strlen(buf);
            if (len > left)
                len = left;
            if(cfs_copy_to_user(buffer, buf, len))
                return -EFAULT;
            left -= len;
            (char *)buffer += len;
        }
    }

    if (!write && !first && left) {
        if(put_user('\n', (char *) buffer))
            return -EFAULT;
        left--, ((char *)buffer)++;
    }
    if (write) {
        p = (char *) buffer;
        while (left) {
            char c;
            if(get_user(c, p++))
                return -EFAULT;
            if (!isspace(c))
                break;
            left--;
        }
    }
    if (write && first)
        return -EINVAL;
    *lenp -= left;
    memset(&(filp->f_pos) , 0, sizeof(loff_t));
    filp->f_pos += (loff_t)(*lenp);
    return 0;
}

/**
 * proc_dointvec - read a vector of integers
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @filp: the file structure
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 *
 * Reads/writes up to table->maxlen/sizeof(unsigned int) integer
 * values from/to the user buffer, treated as an ASCII string. 
 *
 * Returns 0 on success.
 */
int proc_dointvec(cfs_sysctl_table_t *table, int write, struct file *filp,
             void *buffer, size_t *lenp)
{
    return do_proc_dointvec(table,write,filp,buffer,lenp,1,OP_SET);
}


/**
 * proc_dostring - read a string sysctl
 * @table: the sysctl table
 * @write: %TRUE if this is a write to the sysctl file
 * @filp: the file structure
 * @buffer: the user buffer
 * @lenp: the size of the user buffer
 *
 * Reads/writes a string from/to the user buffer. If the kernel
 * buffer provided is not large enough to hold the string, the
 * string is truncated. The copied string is %NULL-terminated.
 * If the string is being read by the user process, it is copied
 * and a newline '\n' is added. It is truncated if the buffer is
 * not large enough.
 *
 * Returns 0 on success.
 */
int proc_dostring(cfs_sysctl_table_t *table, int write, struct file *filp,
          void *buffer, size_t *lenp)
{
    size_t len;
    char *p, c;
    
    if (!table->data || !table->maxlen || !*lenp ||
        (filp->f_pos && !write)) {
        *lenp = 0;
        return 0;
    }
    
    if (write) {
        len = 0;
        p = buffer;
        while (len < *lenp) {
            if(get_user(c, p++))
                return -EFAULT;
            if (c == 0 || c == '\n')
                break;
            len++;
        }
        if (len >= (size_t)table->maxlen)
            len = (size_t)table->maxlen-1;
        if(cfs_copy_from_user(table->data, buffer, len))
            return -EFAULT;
        ((char *) table->data)[len] = 0;
        filp->f_pos += *lenp;
    } else {
        len = (size_t)strlen(table->data);
        if (len > (size_t)table->maxlen)
            len = (size_t)table->maxlen;
        if (len > *lenp)
            len = *lenp;
        if (len)
            if(cfs_copy_to_user(buffer, table->data, len))
                return -EFAULT;
        if (len < *lenp) {
            if(put_user('\n', ((char *) buffer) + len))
                return -EFAULT;
            len++;
        }
        *lenp = len;
        filp->f_pos += len;
    }
    return 0;
}

/* Perform the actual read/write of a sysctl table entry. */
int do_sysctl_strategy (cfs_sysctl_table_t *table, 
            int *name, int nlen,
            void *oldval, size_t *oldlenp,
            void *newval, size_t newlen, void **context)
{
    int op = 0, rc;
    size_t len;

    if (oldval)
        op |= 004;
    if (newval) 
        op |= 002;

    if (table->strategy) {
        rc = table->strategy(table, name, nlen, oldval, oldlenp,
                     newval, newlen, context);
        if (rc < 0)
            return rc;
        if (rc > 0)
            return 0;
    }

    /* If there is no strategy routine, or if the strategy returns
     * zero, proceed with automatic r/w */
    if (table->data && table->maxlen) {
        if (oldval && oldlenp) {
            get_user(len, oldlenp);
            if (len) {
                if (len > (size_t)table->maxlen)
                    len = (size_t)table->maxlen;
                if(cfs_copy_to_user(oldval, table->data, len))
                    return -EFAULT;
                if(put_user(len, oldlenp))
                    return -EFAULT;
            }
        }
        if (newval && newlen) {
            len = newlen;
            if (len > (size_t)table->maxlen)
                len = (size_t)table->maxlen;
            if(cfs_copy_from_user(table->data, newval, len))
                return -EFAULT;
        }
    }
    return 0;
}

static int parse_table(int *name, int nlen,
               void *oldval, size_t *oldlenp,
               void *newval, size_t newlen,
               cfs_sysctl_table_t *table, void **context)
{
    int n;

repeat:

    if (!nlen)
        return -ENOTDIR;
    if (get_user(n, name))
        return -EFAULT;
    for ( ; table->ctl_name; table++) {
        if (n == table->ctl_name || table->ctl_name == CTL_ANY) {
            int error;
            if (table->child) {
/*
                if (ctl_perm(table, 001))
                    return -EPERM;
*/
                if (table->strategy) {
                    error = table->strategy(
                        table, name, nlen,
                        oldval, oldlenp,
                        newval, newlen, context);
                    if (error)
                        return error;
                }
                name++;
                nlen--;
                table = table->child;
                goto repeat;
            }
            error = do_sysctl_strategy(table, name, nlen,
                           oldval, oldlenp,
                           newval, newlen, context);
            return error;
        }
    }
    return -ENOTDIR;
}

int do_sysctl(int *name, int nlen, void *oldval, size_t *oldlenp,
           void *newval, size_t newlen)
{
    cfs_list_t *tmp;

    if (nlen <= 0 || nlen >= CTL_MAXNAME)
        return -ENOTDIR;
    if (oldval) {
        int old_len;
        if (!oldlenp || get_user(old_len, oldlenp))
            return -EFAULT;
    }
    tmp = &root_table_header.ctl_entry;
    do {
        struct ctl_table_header *head =
            cfs_list_entry(tmp, struct ctl_table_header, ctl_entry);
        void *context = NULL;
        int error = parse_table(name, nlen, oldval, oldlenp, 
                    newval, newlen, head->ctl_table,
                    &context);
        if (context)
            cfs_free(context);
        if (error != -ENOTDIR)
            return error;
        tmp = tmp->next;
    } while (tmp != &root_table_header.ctl_entry);
    return -ENOTDIR;
}

/**
 * register_sysctl_table - register a sysctl heirarchy
 * @table: the top-level table structure
 * @insert_at_head: whether the entry should be inserted in front or at the end
 *
 * Register a sysctl table heirarchy. @table should be a filled in ctl_table
 * array. An entry with a ctl_name of 0 terminates the table. 
 *
 * The members of the &ctl_table structure are used as follows:
 *
 * ctl_name - This is the numeric sysctl value used by sysctl(2). The number
 *            must be unique within that level of sysctl
 *
 * procname - the name of the sysctl file under /proc/sys. Set to %NULL to not
 *            enter a sysctl file
 *
 * data - a pointer to data for use by proc_handler
 *
 * maxlen - the maximum size in bytes of the data
 *
 * mode - the file permissions for the /proc/sys file, and for sysctl(2)
 *
 * child - a pointer to the child sysctl table if this entry is a directory, or
 *         %NULL.
 *
 * proc_handler - the text handler routine (described below)
 *
 * strategy - the strategy routine (described below)
 *
 * de - for internal use by the sysctl routines
 *
 * extra1, extra2 - extra pointers usable by the proc handler routines
 *
 * Leaf nodes in the sysctl tree will be represented by a single file
 * under /proc; non-leaf nodes will be represented by directories.
 *
 * sysctl(2) can automatically manage read and write requests through
 * the sysctl table.  The data and maxlen fields of the ctl_table
 * struct enable minimal validation of the values being written to be
 * performed, and the mode field allows minimal authentication.
 *
 * More sophisticated management can be enabled by the provision of a
 * strategy routine with the table entry.  This will be called before
 * any automatic read or write of the data is performed.
 *
 * The strategy routine may return
 *
 * < 0 - Error occurred (error is passed to user process)
 *
 * 0   - OK - proceed with automatic read or write.
 *
 * > 0 - OK - read or write has been done by the strategy routine, so
 *       return immediately.
 *
 * There must be a proc_handler routine for any terminal nodes
 * mirrored under /proc/sys (non-terminals are handled by a built-in
 * directory handler).  Several default handlers are available to
 * cover common cases -
 *
 * proc_dostring(), proc_dointvec(), proc_dointvec_jiffies(),
 * proc_dointvec_minmax(), proc_doulongvec_ms_jiffies_minmax(),
 * proc_doulongvec_minmax()
 *
 * It is the handler's job to read the input buffer from user memory
 * and process it. The handler should return 0 on success.
 *
 * This routine returns %NULL on a failure to register, and a pointer
 * to the table header on success.
 */
struct ctl_table_header *register_sysctl_table(cfs_sysctl_table_t * table, 
                           int insert_at_head)
{
    struct ctl_table_header *tmp;
    tmp = cfs_alloc(sizeof(struct ctl_table_header), 0);
    if (!tmp)
        return NULL;
    tmp->ctl_table = table;

    CFS_INIT_LIST_HEAD(&tmp->ctl_entry);
    if (insert_at_head)
        cfs_list_add(&tmp->ctl_entry, &root_table_header.ctl_entry);
    else
        cfs_list_add_tail(&tmp->ctl_entry, &root_table_header.ctl_entry);
#ifdef CONFIG_PROC_FS
    register_proc_table(table, cfs_proc_sys);
#endif
    return tmp;
}

/**
 * unregister_sysctl_table - unregister a sysctl table heirarchy
 * @header: the header returned from register_sysctl_table
 *
 * Unregisters the sysctl table and all children. proc entries may not
 * actually be removed until they are no longer used by anyone.
 */
void unregister_sysctl_table(struct ctl_table_header * header)
{
    cfs_list_del(&header->ctl_entry);
#ifdef CONFIG_PROC_FS
    unregister_proc_table(header->ctl_table, cfs_proc_sys);
#endif
    cfs_free(header);
}


int cfs_psdev_register(cfs_psdev_t * psdev)
{
    cfs_proc_entry_t *  entry;

    entry = create_proc_entry (
                (char *)psdev->name,
                S_IFREG,
                cfs_proc_dev
            );

    if (!entry) {
        return -ENOMEM;
    }

    entry->flags |= CFS_PROC_FLAG_MISCDEV;

    entry->proc_fops = psdev->fops;
    entry->data = (void *)psdev;

    return 0;
}

int cfs_psdev_deregister(cfs_psdev_t * psdev)
{
    cfs_proc_entry_t *  entry;

    entry = search_proc_entry (
                (char *)psdev->name,
                cfs_proc_dev
            );

    if (entry) {

        ASSERT(entry->data == (void *)psdev);
        ASSERT(entry->flags & CFS_PROC_FLAG_MISCDEV);

        remove_proc_entry(
            (char *)psdev->name,
            cfs_proc_dev
            );
    }

    return 0;
}

#define PSDEV_LNET  (0x100)
enum {
        PSDEV_DEBUG = 1,          /* control debugging */
        PSDEV_SUBSYSTEM_DEBUG,    /* control debugging */
        PSDEV_PRINTK,             /* force all messages to console */
        PSDEV_CONSOLE_RATELIMIT,  /* rate limit console messages */
        PSDEV_DEBUG_PATH,         /* crashdump log location */
        PSDEV_DEBUG_DUMP_PATH,    /* crashdump tracelog location */
        PSDEV_LIBCFS_MEMUSED,     /* bytes currently PORTAL_ALLOCated */
};

static struct ctl_table lnet_table[] = {
        {PSDEV_DEBUG, "debug", &libcfs_debug, sizeof(int), 0644, NULL,
         &proc_dointvec},
        {PSDEV_SUBSYSTEM_DEBUG, "subsystem_debug", &libcfs_subsystem_debug,
         sizeof(int), 0644, NULL, &proc_dointvec},
        {PSDEV_PRINTK, "printk", &libcfs_printk, sizeof(int), 0644, NULL,
         &proc_dointvec},
        {PSDEV_CONSOLE_RATELIMIT, "console_ratelimit", &libcfs_console_ratelimit,
         sizeof(int), 0644, NULL, &proc_dointvec},
/*
        {PSDEV_PORTALS_UPCALL, "upcall", portals_upcall,
         sizeof(portals_upcall), 0644, NULL, &proc_dostring,
         &sysctl_string},
*/
        {PSDEV_LIBCFS_MEMUSED, "memused", (int *)&libcfs_kmemory.counter,
         sizeof(int), 0644, NULL, &proc_dointvec},
        {0}
};

static struct ctl_table top_table[2] = {
        {PSDEV_LNET, "lnet", NULL, 0, 0555, lnet_table},
        {0}
};


int trace_write_dump_kernel(struct file *file, const char *buffer,
                             unsigned long count, void *data)
{
        int rc = cfs_trace_dump_debug_buffer_usrstr((void *)buffer, count);
        
        return (rc < 0) ? rc : count;
}

int trace_write_daemon_file(struct file *file, const char *buffer,
                            unsigned long count, void *data)
{
        int rc = cfs_trace_daemon_command_usrstr((void *)buffer, count);

        return (rc < 0) ? rc : count;
}

int trace_read_daemon_file(char *page, char **start, off_t off, int count,
                           int *eof, void *data)
{
        int rc;
        cfs_tracefile_read_lock();
        rc = cfs_trace_copyout_string(page, count, cfs_tracefile, "\n");
        cfs_tracefile_read_unlock();
        return rc;
}

int trace_write_debug_mb(struct file *file, const char *buffer,
                         unsigned long count, void *data)
{
        int rc = 0; /*trace_set_debug_mb_userstr((void *)buffer, count);*/
        
        return (rc < 0) ? rc : count;
}

int trace_read_debug_mb(char *page, char **start, off_t off, int count,
                        int *eof, void *data)
{
        char   str[32];

        snprintf(str, sizeof(str), "%d\n", cfs_trace_get_debug_mb());

        return cfs_trace_copyout_string(page, count, str, NULL);
}

int insert_proc(void)
{
        cfs_proc_entry_t *ent;

        ent = create_proc_entry("sys/lnet/dump_kernel", 0, NULL);
        if (ent == NULL) {
                CERROR("couldn't register dump_kernel\n");
                return -1;
        }
        ent->write_proc = trace_write_dump_kernel;

        ent = create_proc_entry("sys/lnet/daemon_file", 0, NULL);
        if (ent == NULL) {
                CERROR("couldn't register daemon_file\n");
                return -1;
        }
        ent->write_proc = trace_write_daemon_file;
        ent->read_proc = trace_read_daemon_file;

        ent = create_proc_entry("sys/lnet/debug_mb", 0, NULL);
        if (ent == NULL) {
                CERROR("couldn't register debug_mb\n");
                return -1;
        }
        ent->write_proc = trace_write_debug_mb;
        ent->read_proc = trace_read_debug_mb;

        return 0;
}

void remove_proc(void)
{
        remove_proc_entry("sys/lnet/dump_kernel", NULL);
        remove_proc_entry("sys/lnet/daemon_file", NULL);
        remove_proc_entry("sys/lnet/debug_mb", NULL);
}


/*
 *  proc process routines of kernel space
 */

struct file *
lustre_open_file(char *filename)
{
	int rc = 0;
	struct file *fh = NULL;
	cfs_proc_entry_t *fp = NULL;

	fp = search_proc_entry(filename, cfs_proc_root);
	if (fp == NULL)
		return NULL;

	fh = cfs_alloc(sizeof(*fh), CFS_ALLOC_ZERO);
	if (fh == NULL)
		return NULL;

    fh->f_inode = cfs_alloc(sizeof(struct inode), CFS_ALLOC_ZERO);
    if (!fh->f_inode) {
        cfs_free(fh);
        return NULL;
    }

    fh->f_inode->i_priv = (void *)fp;
    fh->f_op = fp->proc_fops;

    if (fh->f_op->open) {
        rc = (fh->f_op->open)(fh->f_inode, fh);
    } else {
        fp->nlink++;
    }

    if (0 != rc) {
        cfs_free(fh->f_inode);
        cfs_free(fh);
        return NULL;
    }

    return fh;
}

int
lustre_close_file(struct file *fh)
{
	int rc = 0;
	cfs_proc_entry_t *fp = NULL;

    fp = (cfs_proc_entry_t *) fh->f_inode->i_priv;
    if (fh->f_op->release) {
        rc = (fh->f_op->release)(fh->f_inode, fh);
    } else {
        fp->nlink--;
    }

    cfs_free(fh->f_inode);
    cfs_free(fh);

    return rc;
}

int
lustre_do_ioctl(struct file *fh, unsigned long cmd, ulong_ptr_t arg)
{
	int rc = 0;

	if (fh->f_op->ioctl)
		rc = (fh->f_op->ioctl)(fh, cmd, arg);

	return rc;
}

int
lustre_ioctl_file(struct file *fh, PCFS_PROC_IOCTL devctl)
{
    int         rc = 0;
    ulong_ptr_t data;

    data = (ulong_ptr_t)devctl + sizeof(CFS_PROC_IOCTL);
#if defined(_X86_)    
    CLASSERT(sizeof(struct obd_ioctl_data) == 528);
#else
    CLASSERT(sizeof(struct obd_ioctl_data) == 576);
#endif

    /* obd ioctl code */
    if (_IOC_TYPE(devctl->cmd) == 'f') {

        struct obd_ioctl_data * obd = (struct obd_ioctl_data *) data;

        if ( devctl->cmd != (ULONG)OBD_IOC_BRW_WRITE  &&
             devctl->cmd != (ULONG)OBD_IOC_BRW_READ ) {

            unsigned long off = obd->ioc_len;

            if (obd->ioc_plen1) {
                obd->ioc_pbuf1 = (char *)(data + off);
                off += cfs_size_round(obd->ioc_plen1);
            } else {
                obd->ioc_pbuf1 = NULL;
            }

            if (obd->ioc_plen2) {
                obd->ioc_pbuf2 = (char *)(data + off);
                off += cfs_size_round(obd->ioc_plen2);
            } else {
                obd->ioc_pbuf2 = NULL;
            }
        }
    }

    rc = lustre_do_ioctl(fh, devctl->cmd, data);

    return rc;
}

size_t
lustre_read_file(struct file *fh, loff_t off, size_t size, char *buf)
{
    size_t  rc = 0;
    off_t   low, high;

    low = (off_t) size;
    high = (off_t)(off >> 32);

    if (fh->f_op->read) {
        rc = (fh->f_op->read) (fh, buf, size, &off);
    }

    if (rc) {
        fh->f_pos = off + rc;
    }

    return rc;
}

size_t
lustre_write_file(struct file *fh, loff_t off, size_t size, char *buf)
{
	size_t rc = 0;

	off = 0;
	if (fh->f_op->write)
		rc = (fh->f_op->write)(fh, buf, size, &off);

	return rc;
}


/*
 *  seq file routines
 */

/**
 *	seq_open -	initialize sequential file
 *	@file: file we initialize
 *	@op: method table describing the sequence
 *
 *	seq_open() sets @file, associating it with a sequence described
 *	by @op.  @op->start() sets the iterator up and returns the first
 *	element of sequence. @op->stop() shuts it down.  @op->next()
 *	returns the next element of sequence.  @op->show() prints element
 *	into the buffer.  In case of error ->start() and ->next() return
 *	ERR_PTR(error).  In the end of sequence they return %NULL. ->show()
 *	returns 0 in case of success and negative number in case of error.
 */
int seq_open(struct file *file, const struct seq_operations *op)
{
	struct seq_file *p = file->private_data;

	if (!p) {
		p = kmalloc(sizeof(*p), GFP_KERNEL);
		if (!p)
			return -ENOMEM;
		file->private_data = p;
	}
	memset(p, 0, sizeof(*p));
	mutex_init(&p->lock);
	p->op = op;

	/*
	 * Wrappers around seq_open(e.g. swaps_open) need to be
	 * aware of this. If they set f_version themselves, they
	 * should call seq_open first and then set f_version.
	 */
	file->f_version = 0;

	/* SEQ files support lseek, but not pread/pwrite */
	file->f_mode &= ~(FMODE_PREAD | FMODE_PWRITE);
	return 0;
}
EXPORT_SYMBOL(seq_open);

/**
 *	seq_read -	->read() method for sequential files.
 *	@file: the file to read from
 *	@buf: the buffer to read to
 *	@size: the maximum number of bytes to read
 *	@ppos: the current position in the file
 *
 *	Ready-made ->f_op->read()
 */
ssize_t seq_read(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	struct seq_file *m = (struct seq_file *)file->private_data;
	size_t copied = 0;
	loff_t pos;
	size_t n;
	void *p;
	int err = 0;

	mutex_lock(&m->lock);
	/*
	 * seq_file->op->..m_start/m_stop/m_next may do special actions
	 * or optimisations based on the file->f_version, so we want to
	 * pass the file->f_version to those methods.
	 *
	 * seq_file->version is just copy of f_version, and seq_file
	 * methods can treat it simply as file version.
	 * It is copied in first and copied out after all operations.
	 * It is convenient to have it as  part of structure to avoid the
	 * need of passing another argument to all the seq_file methods.
	 */
	m->version = file->f_version;
	/* grab buffer if we didn't have one */
	if (!m->buf) {
		m->buf = kmalloc(m->size = PAGE_SIZE, GFP_KERNEL);
		if (!m->buf)
			goto Enomem;
	}
	/* if not empty - flush it first */
	if (m->count) {
		n = min(m->count, size);
		err = cfs_copy_to_user(buf, m->buf + m->from, n);
		if (err)
			goto Efault;
		m->count -= n;
		m->from += n;
		size -= n;
		buf += n;
		copied += n;
		if (!m->count)
			m->index++;
		if (!size)
			goto Done;
	}
	/* we need at least one record in buffer */
	while (1) {
		pos = m->index;
		p = m->op->start(m, &pos);
		err = PTR_ERR(p);
		if (!p || IS_ERR(p))
			break;
		err = m->op->show(m, p);
		if (err)
			break;
		if (m->count < m->size)
			goto Fill;
		m->op->stop(m, p);
		cfs_free(m->buf);
		m->buf = kmalloc(m->size <<= 1, GFP_KERNEL);
		if (!m->buf)
			goto Enomem;
		m->count = 0;
		m->version = 0;
	}
	m->op->stop(m, p);
	m->count = 0;
	goto Done;
Fill:
	/* they want more? let's try to get some more */
	while (m->count < size) {
		size_t offs = m->count;
		loff_t next = pos;
		p = m->op->next(m, p, &next);
		if (!p || IS_ERR(p)) {
			err = PTR_ERR(p);
			break;
		}
		err = m->op->show(m, p);
		if (err || m->count == m->size) {
			m->count = offs;
			break;
		}
		pos = next;
	}
	m->op->stop(m, p);
	n = min(m->count, size);
	err = cfs_copy_to_user(buf, m->buf, n);
	if (err)
		goto Efault;
	copied += n;
	m->count -= n;
	if (m->count)
		m->from = n;
	else
		pos++;
	m->index = pos;
Done:
	if (!copied)
		copied = err;
	else
		*ppos += copied;
	file->f_version = m->version;
	mutex_unlock(&m->lock);
	return copied;
Enomem:
	err = -ENOMEM;
	goto Done;
Efault:
	err = -EFAULT;
	goto Done;
}
EXPORT_SYMBOL(seq_read);

static int traverse(struct seq_file *m, loff_t offset)
{
	loff_t pos = 0, index;
	int error = 0;
	void *p;

	m->version = 0;
	index = 0;
	m->count = m->from = 0;
	if (!offset) {
		m->index = index;
		return 0;
	}
	if (!m->buf) {
		m->buf = kmalloc(m->size = PAGE_SIZE, GFP_KERNEL);
		if (!m->buf)
			return -ENOMEM;
	}
	p = m->op->start(m, &index);
	while (p) {
		error = PTR_ERR(p);
		if (IS_ERR(p))
			break;
		error = m->op->show(m, p);
		if (error)
			break;
		if (m->count == m->size)
			goto Eoverflow;
		if (pos + (loff_t)(m->count) > offset) {
			m->from = (size_t)(offset - pos);
			m->count -= m->from;
			m->index = index;
			break;
		}
		pos += m->count;
		m->count = 0;
		if (pos == offset) {
			index++;
			m->index = index;
			break;
		}
		p = m->op->next(m, p, &index);
	}
	m->op->stop(m, p);
	return error;

Eoverflow:
	m->op->stop(m, p);
	cfs_free(m->buf);
	m->buf = cfs_alloc(m->size <<= 1, CFS_ALLOC_KERNEL | CFS_ALLOC_ZERO);
	return !m->buf ? -ENOMEM : -EAGAIN;
}

/**
 *	seq_lseek -	->llseek() method for sequential files.
 *	@file: the file in question
 *	@offset: new position
 *	@origin: 0 for absolute, 1 for relative position
 *
 *	Ready-made ->f_op->llseek()
 */
loff_t seq_lseek(struct file *file, loff_t offset, int origin)
{
	struct seq_file *m = (struct seq_file *)file->private_data;
	long long retval = -EINVAL;

	mutex_lock(&m->lock);
	m->version = file->f_version;
	switch (origin) {
		case 1:
			offset += file->f_pos;
		case 0:
			if (offset < 0)
				break;
			retval = offset;
			if (offset != file->f_pos) {
				while ((retval=traverse(m, offset)) == -EAGAIN)
					;
				if (retval) {
					/* with extreme prejudice... */
					file->f_pos = 0;
					m->version = 0;
					m->index = 0;
					m->count = 0;
				} else {
					retval = file->f_pos = offset;
				}
			}
	}
	file->f_version = m->version;
	mutex_unlock(&m->lock);
	return retval;
}
EXPORT_SYMBOL(seq_lseek);

/**
 *	seq_release -	free the structures associated with sequential file.
 *	@file: file in question
 *	@inode: file->f_path.dentry->d_inode
 *
 *	Frees the structures associated with sequential file; can be used
 *	as ->f_op->release() if you don't have private data to destroy.
 */
int seq_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = (struct seq_file *)file->private_data;
    if (m) {
        if (m->buf)
	        cfs_free(m->buf);
	    cfs_free(m);
    }
	return 0;
}
EXPORT_SYMBOL(seq_release);

/**
 *	seq_escape -	print string into buffer, escaping some characters
 *	@m:	target buffer
 *	@s:	string
 *	@esc:	set of characters that need escaping
 *
 *	Puts string into buffer, replacing each occurrence of character from
 *	@esc with usual octal escape.  Returns 0 in case of success, -1 - in
 *	case of overflow.
 */
int seq_escape(struct seq_file *m, const char *s, const char *esc)
{
	char *end = m->buf + m->size;
        char *p;
	char c;

        for (p = m->buf + m->count; (c = *s) != '\0' && p < end; s++) {
		if (!strchr(esc, c)) {
			*p++ = c;
			continue;
		}
		if (p + 3 < end) {
			*p++ = '\\';
			*p++ = '0' + ((c & 0300) >> 6);
			*p++ = '0' + ((c & 070) >> 3);
			*p++ = '0' + (c & 07);
			continue;
		}
		m->count = m->size;
		return -1;
        }
	m->count = p - m->buf;
        return 0;
}
EXPORT_SYMBOL(seq_escape);

int seq_printf(struct seq_file *m, const char *f, ...)
{
	va_list args;
	int len;

	if (m->count < m->size) {
		va_start(args, f);
		len = vsnprintf(m->buf + m->count, m->size - m->count, f, args);
		va_end(args);
		if (m->count + len < m->size) {
			m->count += len;
			return 0;
		}
	}
	m->count = m->size;
	return -1;
}
EXPORT_SYMBOL(seq_printf);

char *d_path(struct path *p, char *buffer, int buflen)
{
	cfs_enter_debugger();
	return ERR_PTR(-ENAMETOOLONG);
}

int seq_path(struct seq_file *m, struct path *path, char *esc)
{
	if (m->count < m->size) {
		char *s = m->buf + m->count;
		char *p = d_path(path, s, m->size - m->count);
		if (!IS_ERR(p)) {
			while (s <= p) {
				char c = *p++;
				if (!c) {
					p = m->buf + m->count;
					m->count = s - m->buf;
					return (int)(s - p);
				} else if (!strchr(esc, c)) {
					*s++ = c;
				} else if (s + 4 > p) {
					break;
				} else {
					*s++ = '\\';
					*s++ = '0' + ((c & 0300) >> 6);
					*s++ = '0' + ((c & 070) >> 3);
					*s++ = '0' + (c & 07);
				}
			}
		}
	}
	m->count = m->size;
	return -1;
}
EXPORT_SYMBOL(seq_path);

static void *single_start(struct seq_file *p, loff_t *pos)
{
	return (void *) (INT_PTR) (*pos == 0);
}

static void *single_next(struct seq_file *p, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void single_stop(struct seq_file *p, void *v)
{
}

int single_open(struct file *file, int (*show)(struct seq_file *, void *),
		void *data)
{
	struct seq_operations *op = kmalloc(sizeof(*op), GFP_KERNEL);
	int res = -ENOMEM;

	if (op) {
		op->start = single_start;
		op->next = single_next;
		op->stop = single_stop;
		op->show = show;
		res = seq_open(file, op);
		if (!res)
			((struct seq_file *)file->private_data)->private = data;
		else
			cfs_free(op);
	}
	return res;
}
EXPORT_SYMBOL(single_open);

int single_release(struct inode *inode, struct file *file)
{
	const struct seq_operations *op = ((struct seq_file *)file->private_data)->op;
	int res = seq_release(inode, file);
	cfs_free((void *)op);
	return res;
}
EXPORT_SYMBOL(single_release);

int seq_release_private(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;

	cfs_free(seq->private);
	seq->private = NULL;
	return seq_release(inode, file);
}
EXPORT_SYMBOL(seq_release_private);

void *__seq_open_private(struct file *f, const struct seq_operations *ops,
		int psize)
{
	int rc;
	void *private;
	struct seq_file *seq;

	private = cfs_alloc(psize, CFS_ALLOC_KERNEL | CFS_ALLOC_ZERO);
	if (private == NULL)
		goto out;

	rc = seq_open(f, ops);
	if (rc < 0)
		goto out_free;

	seq = f->private_data;
	seq->private = private;
	return private;

out_free:
	cfs_free(private);
out:
	return NULL;
}
EXPORT_SYMBOL(__seq_open_private);

int seq_open_private(struct file *filp, const struct seq_operations *ops,
		int psize)
{
	return __seq_open_private(filp, ops, psize) ? 0 : -ENOMEM;
}
EXPORT_SYMBOL(seq_open_private);

int seq_putc(struct seq_file *m, char c)
{
	if (m->count < m->size) {
		m->buf[m->count++] = c;
		return 0;
	}
	return -1;
}
EXPORT_SYMBOL(seq_putc);

int seq_puts(struct seq_file *m, const char *s)
{
	int len = strlen(s);
	if (m->count + len < m->size) {
		memcpy(m->buf + m->count, s, len);
		m->count += len;
		return 0;
	}
	m->count = m->size;
	return -1;
}
EXPORT_SYMBOL(seq_puts);

cfs_list_t *seq_list_start(cfs_list_t *head, loff_t pos)
{
	cfs_list_t *lh;

	cfs_list_for_each(lh, head)
		if (pos-- == 0)
			return lh;

	return NULL;
}

EXPORT_SYMBOL(seq_list_start);

cfs_list_t *seq_list_start_head(cfs_list_t *head,
                                loff_t pos)
{
	if (!pos)
		return head;

	return seq_list_start(head, pos - 1);
}

EXPORT_SYMBOL(seq_list_start_head);

cfs_list_t *seq_list_next(void *v, cfs_list_t *head,
                          loff_t *ppos)
{
	cfs_list_t *lh;

	lh = ((cfs_list_t *)v)->next;
	++*ppos;
	return lh == head ? NULL : lh;
}

EXPORT_SYMBOL(seq_list_next);

struct proc_dir_entry *PDE(const struct inode *inode)
{
	return (struct proc_dir_entry *)inode->i_priv;
}


#endif /* __KERNEL__ */
