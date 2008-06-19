/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=4:tabstop=4:
 *
 *
 *  Copyright (c) 2004 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or modify it under
 *   the terms of version 2 of the GNU General Public License as published by
 *   the Free Software Foundation. Lustre is distributed in the hope that it
 *   will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details. You should have received a
 *   copy of the GNU General Public License along with Lustre; if not, write
 *   to the Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139,
 *   USA.
 */


#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

# define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>
#include <libcfs/kp30.h>
#include "tracefile.h"

#ifdef __KERNEL__


/*
 *  /proc emulator routines ...
 */

/* The root node of the proc fs emulation: /proc */
cfs_proc_entry_t *              proc_fs_root = NULL;


/* The sys root: /proc/sys */
cfs_proc_entry_t *              proc_sys_root = NULL;


/* The sys root: /proc/dev | to implement misc device */

cfs_proc_entry_t *              proc_dev_root = NULL;


/* SLAB object for cfs_proc_entry_t allocation */

cfs_mem_cache_t *               proc_entry_cache = NULL;

/* root node for sysctl table */

cfs_sysctl_table_header_t       root_table_header;

/* The global lock to protect all the access */

#if LIBCFS_PROCFS_SPINLOCK
spinlock_t                      proc_fs_lock;

#define INIT_PROCFS_LOCK()      spin_lock_init(&proc_fs_lock)
#define LOCK_PROCFS()           spin_lock(&proc_fs_lock)
#define UNLOCK_PROCFS()         spin_unlock(&proc_fs_lock)

#else

mutex_t                         proc_fs_lock;

#define INIT_PROCFS_LOCK()      init_mutex(&proc_fs_lock)
#define LOCK_PROCFS()           mutex_down(&proc_fs_lock)
#define UNLOCK_PROCFS()         mutex_up(&proc_fs_lock)

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

    dp = (cfs_proc_entry_t  *) file->private_data;
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
        
        n -= copy_to_user((void *)buf, start, n);
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
    
    dp = (cfs_proc_entry_t *) file->private_data;

    if (!dp->write_proc)
        return -EIO;

    /* FIXME: does this routine need ppos?  probably... */
    return dp->write_proc(file, buffer, count, dp->data);
}

struct file_operations proc_file_operations = {
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
    char *path,
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

        *first = path + i;
        while (i < len && (path[i] != '/')) i++;
        *first_len = (path + i - *first);

        if (i + 1 < len) {
            *remain = path + i + 1;
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
            //

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
    char *              name,
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
    char *              name,
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
    char *              name,
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
    char *              name,
    mode_t              mode,
    cfs_proc_entry_t *  root
    )
{
    cfs_proc_entry_t *parent = root;
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

    ASSERT(NULL != proc_fs_root);

    if (!parent) {
        parent = proc_fs_root;
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
    char *              name,
    cfs_proc_entry_t *  root
    )
{
    cfs_proc_entry_t * entry;

    LOCK_PROCFS();
    if (root == NULL) {
        root = proc_fs_root;
    }
    entry = proc_search_entry(name, root);
    UNLOCK_PROCFS();

    return entry;    
}

/* remove the entry from the proc fs */

void
remove_proc_entry(
    char *              name,
    cfs_proc_entry_t *  parent
    )
{
    LOCK_PROCFS();
    if (parent == NULL) {
        parent = proc_fs_root;
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


/* destory the whole proc fs tree */

void proc_destroy_fs()
{
    LOCK_PROCFS();

    if (proc_fs_root) {
        proc_destroy_splay(proc_fs_root);
    }

    if (proc_entry_cache) {
        cfs_mem_cache_destroy(proc_entry_cache);
    }
   
    UNLOCK_PROCFS();
}

/* initilaize / build the proc fs tree */

int proc_init_fs()
{
    cfs_proc_entry_t * root = NULL;

    memset(&(root_table_header), 0, sizeof(struct ctl_table_header));
    INIT_LIST_HEAD(&(root_table_header.ctl_entry));

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

    root->name[0]='p';
    root->name[1]='r';
    root->name[2]='o';
    root->name[3]='c';

    proc_fs_root = root;

    proc_sys_root = create_proc_entry("sys", S_IFDIR, root);

    if (!proc_sys_root) {
        proc_free_entry(root);
        proc_fs_root = NULL;
        proc_destroy_fs();
        return (-ENOMEM);
    }

    proc_sys_root->nlink = 1;

    proc_dev_root = create_proc_entry("dev", S_IFDIR, root);

    if (!proc_dev_root) {
        proc_free_entry(proc_sys_root);
        proc_sys_root = NULL;
        proc_free_entry(proc_fs_root);
        proc_fs_root = NULL;
        proc_destroy_fs();
        return (-ENOMEM);
    }

    proc_dev_root->nlink = 1;
   
    return 0;
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

//  if (ctl_perm(table, op))
//      return -EPERM;
    
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
            printk(KERN_WARNING "SYSCTL: Can't register %s\n",
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
                printk (KERN_ALERT "Help - malformed sysctl tree on free\n");
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
            if(copy_to_user(oldval, table->data, len))
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
        if(copy_from_user(table->data, newval, len))
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
            if ((*cp == 'x') && isxdigit(cp[1])) {
                cp++;
                base = 16;
            }
        }
    }
    while (isxdigit(*cp) &&
           (value = isdigit(*cp) ? *cp-'0' : toupper(*cp)-'A'+10) < base) {
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
            if(copy_from_user(buf, buffer, len))
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
            if(copy_to_user(buffer, buf, len))
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
        if(copy_from_user(table->data, buffer, len))
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
            if(copy_to_user(buffer, table->data, len))
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
                if(copy_to_user(oldval, table->data, len))
                    return -EFAULT;
                if(put_user(len, oldlenp))
                    return -EFAULT;
            }
        }
        if (newval && newlen) {
            len = newlen;
            if (len > (size_t)table->maxlen)
                len = (size_t)table->maxlen;
            if(copy_from_user(table->data, newval, len))
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
    struct list_head *tmp;

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
            list_entry(tmp, struct ctl_table_header, ctl_entry);
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

    INIT_LIST_HEAD(&tmp->ctl_entry);
    if (insert_at_head)
        list_add(&tmp->ctl_entry, &root_table_header.ctl_entry);
    else
        list_add_tail(&tmp->ctl_entry, &root_table_header.ctl_entry);
#ifdef CONFIG_PROC_FS
    register_proc_table(table, proc_sys_root);
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
    list_del(&header->ctl_entry);
#ifdef CONFIG_PROC_FS
    unregister_proc_table(header->ctl_table, proc_sys_root);
#endif
    cfs_free(header);
}


int cfs_psdev_register(cfs_psdev_t * psdev)
{
    cfs_proc_entry_t *  entry;

    entry = create_proc_entry (
                (char *)psdev->name,
                S_IFREG,
                proc_dev_root
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
                proc_dev_root
            );

    if (entry) {

        ASSERT(entry->data == (void *)psdev);
        ASSERT(entry->flags & CFS_PROC_FLAG_MISCDEV);

        remove_proc_entry(
            (char *)psdev->name,
            proc_dev_root
            );
    }

    return 0;
}

extern char debug_file_path[1024];

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
        {PSDEV_DEBUG_PATH, "debug_path", debug_file_path,
         sizeof(debug_file_path), 0644, NULL, &proc_dostring, &sysctl_string},
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
        int rc = trace_dump_debug_buffer_usrstr(buffer, count);
        
        return (rc < 0) ? rc : count;
}

int trace_write_daemon_file(struct file *file, const char *buffer,
                            unsigned long count, void *data)
{
        int rc = trace_daemon_command_usrstr(buffer, count);

        return (rc < 0) ? rc : count;
}

int trace_read_daemon_file(char *page, char **start, off_t off, int count,
                           int *eof, void *data)
{
	int rc;

	tracefile_read_lock();

        rc = trace_copyout_string(page, count, tracefile, "\n");

        tracefile_read_unlock();

	return rc;
}

int trace_write_debug_mb(struct file *file, const char *buffer,
                         unsigned long count, void *data)
{
        int rc = trace_set_debug_mb_userstr(buffer, count);
        
        return (rc < 0) ? rc : count;
}

int trace_read_debug_mb(char *page, char **start, off_t off, int count,
                        int *eof, void *data)
{
        char   str[32];

        snprintf(str, sizeof(str), "%d\n", trace_get_debug_mb());

        return trace_copyout_string(page, count, str, NULL);
}

int insert_proc(void)
{
        cfs_proc_entry_t *ent;

        ent = create_proc_entry("sys/lnet/dump_kernel", 0, NULL);
        if (ent == NULL) {
                CERROR(("couldn't register dump_kernel\n"));
                return -1;
        }
        ent->write_proc = trace_write_dump_kernel;

        ent = create_proc_entry("sys/lnet/daemon_file", 0, NULL);
        if (ent == NULL) {
                CERROR(("couldn't register daemon_file\n"));
                return -1;
        }
        ent->write_proc = trace_write_daemon_file;
        ent->read_proc = trace_read_daemon_file;

        ent = create_proc_entry("sys/lnet/debug_mb", 0, NULL);
        if (ent == NULL) {
                CERROR(("couldn't register debug_mb\n"));
                return -1;
        }
        ent->write_proc = trace_write_debug_mb;
        ent->read_proc = trace_read_debug_mb;

        return 0;
}

void remove_proc(void)
{
        remove_proc_entry("sys/portals/dump_kernel", NULL);
        remove_proc_entry("sys/portals/daemon_file", NULL);
        remove_proc_entry("sys/portals/debug_mb", NULL);

#ifdef CONFIG_SYSCTL
        if (portals_table_header)
                unregister_sysctl_table(portals_table_header);
        portals_table_header = NULL;
#endif
}


/*
 *  proc process routines of kernel space
 */

cfs_file_t *
lustre_open_file(char * filename)
{
    int rc = 0;
    cfs_file_t * fh = NULL;
    cfs_proc_entry_t * fp = NULL;

    fp = search_proc_entry(filename, proc_fs_root);

    if (!fp) {
        rc =  -ENOENT;
        return NULL;
    }

    fh = cfs_alloc(sizeof(cfs_file_t), CFS_ALLOC_ZERO);

    if (!fh) {
        rc =  -ENOMEM;
        return NULL;
    }

    fh->private_data = (void *)fp;
    fh->f_op = fp->proc_fops;

    if (fh->f_op->open) {
        rc = (fh->f_op->open)(fh);
    } else {
        fp->nlink++;
    }

    if (0 != rc) {
        cfs_free(fh);
        return NULL;
    }

    return fh;
}

int
lustre_close_file(cfs_file_t * fh)
{
    int rc = 0;
    cfs_proc_entry_t * fp = NULL;

    fp = (cfs_proc_entry_t *) fh->private_data;

    if (fh->f_op->release) {
        rc = (fh->f_op->release)(fh);
    } else {
        fp->nlink--;
    }

    cfs_free(fh);

    return rc;
}

int
lustre_do_ioctl( cfs_file_t * fh,
                 unsigned long cmd,
                 ulong_ptr arg )
{
    int rc = 0;

    if (fh->f_op->ioctl) {
        rc = (fh->f_op->ioctl)(fh, cmd, arg);
    }

    if (rc != 0) {
        printk("lustre_do_ioctl: fialed: cmd = %xh arg = %xh rc = %d\n",
                cmd, arg, rc);
    }

    return rc;
}
    
int
lustre_ioctl_file(cfs_file_t * fh, PCFS_PROC_IOCTL devctl)
{
    int         rc = 0;
    ulong_ptr   data;

    data = (ulong_ptr)devctl + sizeof(CFS_PROC_IOCTL);

    /* obd ioctl code */
    if (_IOC_TYPE(devctl->cmd) == 'f') {
#if 0
        struct obd_ioctl_data * obd = (struct obd_ioctl_data *) data;

        if ( devctl->cmd != (ULONG)OBD_IOC_BRW_WRITE  &&
             devctl->cmd != (ULONG)OBD_IOC_BRW_READ ) {

            unsigned long off = obd->ioc_len;

            if (obd->ioc_pbuf1) {
                obd->ioc_pbuf1 = (char *)(data + off);
                off += size_round(obd->ioc_plen1);
            }

            if (obd->ioc_pbuf2) {
                obd->ioc_pbuf2 = (char *)(data + off);
            }
        }
 #endif
   }

    rc = lustre_do_ioctl(fh, devctl->cmd, data);

    return rc;
} 


size_t
lustre_read_file(
    cfs_file_t *    fh,
    loff_t          off,
    size_t          size,
    char *          buf
    )
{
    size_t rc = 0;

    if (fh->f_op->read) {
        rc = (fh->f_op->read) (fh, buf, size, &off);
    }

    return rc;
}
 

size_t
lustre_write_file(
    cfs_file_t *    fh,
    loff_t          off,
    size_t          size,
    char *          buf
    )
{
    size_t rc = 0;

    if (fh->f_op->write) {
        rc = (fh->f_op->write)(fh, buf, size, &off);
    }

    return rc;
}  

#else /* !__KERNEL__ */

#include <lnet/api-support.h>
#include <liblustre.h>
#include <lustre_lib.h>

/*
 * proc process routines of user space
 */

HANDLE cfs_proc_open (char * filename, int oflag)
{
    NTSTATUS            status;
    IO_STATUS_BLOCK     iosb;
    int                 rc;

    HANDLE              FileHandle = INVALID_HANDLE_VALUE;
    OBJECT_ATTRIBUTES   ObjectAttributes;
    ACCESS_MASK         DesiredAccess;
    ULONG               CreateDisposition;
    ULONG               ShareAccess;
    ULONG               CreateOptions;
    UNICODE_STRING      UnicodeName;
    USHORT              NameLength;

    PFILE_FULL_EA_INFORMATION Ea = NULL;
    ULONG               EaLength;
    UCHAR               EaBuffer[EA_MAX_LENGTH];

    /* Check the filename: should start with "/proc" or "/dev" */
    NameLength = (USHORT)strlen(filename);
    if (NameLength > 0x05) {
        if (_strnicmp(filename, "/proc/", 6) == 0) {
            filename += 6;
            NameLength -=6;
            if (NameLength <= 0) {
                rc = -EINVAL;
                goto errorout;
            }
        } else if (_strnicmp(filename, "/dev/", 5) == 0) {
        } else {
            rc = -EINVAL;
            goto errorout;
        }
    } else {
        rc = -EINVAL;
        goto errorout;
    }

    /* Analyze the flags settings */

    if (cfs_is_flag_set(oflag, O_WRONLY)) {
        DesiredAccess = (GENERIC_WRITE | SYNCHRONIZE);
        ShareAccess = 0;
    }  else if (cfs_is_flag_set(oflag, O_RDWR)) {
        DesiredAccess = (GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE);
        ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
    } else {
        DesiredAccess = (GENERIC_READ | SYNCHRONIZE);
        ShareAccess = FILE_SHARE_READ;
    }

    if (cfs_is_flag_set(oflag, O_CREAT)) {
        if (cfs_is_flag_set(oflag, O_EXCL)) {
            CreateDisposition = FILE_CREATE;
            rc = -EINVAL;
            goto errorout;
        } else {
            CreateDisposition = FILE_OPEN_IF;
        }
    } else {
        CreateDisposition = FILE_OPEN;
    }

    if (cfs_is_flag_set(oflag, O_TRUNC)) {
        if (cfs_is_flag_set(oflag, O_EXCL)) {
            CreateDisposition = FILE_OVERWRITE;
        } else {
            CreateDisposition = FILE_OVERWRITE_IF;
        }
    }

    CreateOptions = 0;

    if (cfs_is_flag_set(oflag, O_DIRECTORY)) {
        cfs_set_flag(CreateOptions,  FILE_DIRECTORY_FILE);
    }

    if (cfs_is_flag_set(oflag, O_SYNC)) {
         cfs_set_flag(CreateOptions, FILE_WRITE_THROUGH);
    }

    if (cfs_is_flag_set(oflag, O_DIRECT)) {
         cfs_set_flag(CreateOptions, FILE_NO_INTERMEDIATE_BUFFERING);
    }

    /* Initialize the unicode path name for the specified file */
    RtlInitUnicodeString(&UnicodeName, LUSTRE_PROC_SYMLNK);

    /* Setup the object attributes structure for the file. */
    InitializeObjectAttributes(
            &ObjectAttributes,
            &UnicodeName,
            OBJ_CASE_INSENSITIVE,
            NULL,
            NULL );

    /* building EA for the proc entry ...  */
    Ea = (PFILE_FULL_EA_INFORMATION)EaBuffer;
    Ea->NextEntryOffset = 0;
    Ea->Flags = 0;
    Ea->EaNameLength = (UCHAR)NameLength;
    Ea->EaValueLength = 0;
    RtlCopyMemory(
        &(Ea->EaName),
        filename,
        NameLength + 1
        );
    EaLength =	sizeof(FILE_FULL_EA_INFORMATION) - 1 +
				Ea->EaNameLength + 1;

    /* Now to open or create the file now */
    status = ZwCreateFile(
                &FileHandle,
                DesiredAccess,
                &ObjectAttributes,
                &iosb,
                0,
                FILE_ATTRIBUTE_NORMAL,
                ShareAccess,
                CreateDisposition,
                CreateOptions,
                Ea,
                EaLength );

    /* Check the returned status of Iosb ... */

    if (!NT_SUCCESS(status)) {
        rc = cfs_error_code(status);
        goto errorout;
    }

errorout:

    return FileHandle;
}

int cfs_proc_close(HANDLE handle)
{
    if (handle) {
        NtClose((HANDLE)handle);
    }

    return 0;
}

int cfs_proc_read(HANDLE handle, void *buffer, unsigned int count)
{
    NTSTATUS            status;
    IO_STATUS_BLOCK     iosb;
    LARGE_INTEGER       offset;


    offset.QuadPart = 0;

    /* read file data */
    status = NtReadFile(
                (HANDLE)handle,
                0,
                NULL,
                NULL,
                &iosb,
                buffer,
                count,
                &offset,
                NULL);                     

    /* check the return status */
    if (!NT_SUCCESS(status)) {
        printf("NtReadFile request failed 0x%0x\n", status);
        goto errorout;
    }

errorout:

    if (NT_SUCCESS(status)) {
        return iosb.Information;
    }

    return cfs_error_code(status);
}


int cfs_proc_write(HANDLE handle, void *buffer, unsigned int count)
{
    NTSTATUS            status;
    IO_STATUS_BLOCK     iosb;
    LARGE_INTEGER       offset;

    offset.QuadPart = -1;

    /* write buffer to the opened file */
    status = NtWriteFile(
                (HANDLE)handle,
                0,
                NULL,
                NULL,
                &iosb,
                buffer,
                count,
                &offset,
                NULL);                     

    /* check the return status */
    if (!NT_SUCCESS(status)) {
        printf("NtWriteFile request failed 0x%0x\n", status);
        goto errorout;
    }

errorout:

    if (NT_SUCCESS(status)) {
        return iosb.Information;
    }

    return cfs_error_code(status);
}

int cfs_proc_ioctl(HANDLE handle, int cmd, void *buffer)
{
    PUCHAR          procdat = NULL;
    CFS_PROC_IOCTL  procctl;
    ULONG           length = 0;
    ULONG           extra = 0;

    NTSTATUS        status;
    IO_STATUS_BLOCK iosb;

    procctl.cmd = cmd;

    if(_IOC_TYPE(cmd) == IOC_LIBCFS_TYPE) {
        struct libcfs_ioctl_data * portal;
        portal = (struct libcfs_ioctl_data *) buffer;
        length = portal->ioc_len;
    } else if (_IOC_TYPE(cmd) == 'f') {
        struct obd_ioctl_data * obd;
        obd = (struct obd_ioctl_data *) buffer;
        length = obd->ioc_len;
        extra = size_round(obd->ioc_plen1) + size_round(obd->ioc_plen2);
    } else if(_IOC_TYPE(cmd) == 'u') {
        length = 4;
        extra  = 0;
    } else {
        printf("user:winnt-proc:cfs_proc_ioctl: un-supported ioctl type ...\n");
        cfs_enter_debugger();
        status = STATUS_INVALID_PARAMETER;
        goto errorout;
    }

    procctl.len = length + extra;
    procdat = malloc(length + extra + sizeof(CFS_PROC_IOCTL));

    if (NULL == procdat) {
        printf("user:winnt-proc:cfs_proc_ioctl: no enough memory ...\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        cfs_enter_debugger();
        goto errorout;
    }
    memset(procdat, 0, length + extra + sizeof(CFS_PROC_IOCTL));
    memcpy(procdat, &procctl, sizeof(CFS_PROC_IOCTL));
    memcpy(&procdat[sizeof(CFS_PROC_IOCTL)], buffer, length);
    length += sizeof(CFS_PROC_IOCTL);

    if (_IOC_TYPE(cmd) == 'f') {

        char *ptr;
        struct obd_ioctl_data * data;
        struct obd_ioctl_data * obd;

        data = (struct obd_ioctl_data *) buffer;
        obd  = (struct obd_ioctl_data *) (procdat + sizeof(CFS_PROC_IOCTL));
        ptr = obd->ioc_bulk;

        if (data->ioc_inlbuf1) {
                obd->ioc_inlbuf1 = ptr;
                LOGL(data->ioc_inlbuf1, data->ioc_inllen1, ptr);
        }

        if (data->ioc_inlbuf2) {
                obd->ioc_inlbuf2 = ptr;
                LOGL(data->ioc_inlbuf2, data->ioc_inllen2, ptr);
        }
        if (data->ioc_inlbuf3) {
                obd->ioc_inlbuf3 = ptr;
                LOGL(data->ioc_inlbuf3, data->ioc_inllen3, ptr);
        }
        if (data->ioc_inlbuf4) {
                obd->ioc_inlbuf4 = ptr;
                LOGL(data->ioc_inlbuf4, data->ioc_inllen4, ptr);
        }
    
        if ( cmd != (ULONG)OBD_IOC_BRW_WRITE  &&
             cmd != (ULONG)OBD_IOC_BRW_READ ) {

            if (data->ioc_pbuf1 && data->ioc_plen1) {
                obd->ioc_pbuf1 = &procdat[length];
                memcpy(obd->ioc_pbuf1, data->ioc_pbuf1, data->ioc_plen1); 
                length += size_round(data->ioc_plen1);
            }

            if (data->ioc_pbuf2 && data->ioc_plen2) {
                obd->ioc_pbuf2 = &procdat[length];
                memcpy(obd->ioc_pbuf2, data->ioc_pbuf2, data->ioc_plen2);
                length += size_round(data->ioc_plen2);
            }
        }

        if (obd_ioctl_is_invalid(obd)) {
            cfs_enter_debugger();
        }
    }

    status = NtDeviceIoControlFile(
                (HANDLE)handle,
                NULL, NULL, NULL, &iosb,
                IOCTL_LIBCFS_ENTRY,
                procdat, length,
                procdat, length );


    if (NT_SUCCESS(status)) {
        memcpy(buffer, &procdat[sizeof(CFS_PROC_IOCTL)], procctl.len); 
    }

errorout:

    if (procdat) {
        free(procdat);
    }

    return cfs_error_code(status);
}

#endif /* __KERNEL__ */
