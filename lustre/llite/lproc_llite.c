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
#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
#include <asm/statfs.h>
#endif
#include <linux/lustre_lite.h>
#include <linux/lprocfs_status.h>

/* /proc/lustre/llite mount point registration */

#ifndef LPROCFS
int lprocfs_register_mountpoint(struct proc_dir_entry *parent,
                                struct super_block *sb, char *osc, char *mdc)
{
        return 0;
}
void lprocfs_unregister_mountpoint(struct ll_sb_info *sbi){}
#else

#define LPROC_LLITE_STAT_FCT(fct_name, get_statfs_fct)                    \
int fct_name(char *page, char **start, off_t off,                         \
             int count, int *eof, void *data)                             \
{                                                                         \
        struct statfs sfs;                                                \
        int rc;                                                           \
        LASSERT(data != NULL);                                            \
        rc = get_statfs_fct((struct super_block*)data, &sfs);             \
        return (rc==0                                                     \
                ? lprocfs_##fct_name (page, start, off, count, eof, &sfs) \
                : rc);                                                    \
}

long long mnt_instance;

LPROC_LLITE_STAT_FCT(rd_blksize,     vfs_statfs);
LPROC_LLITE_STAT_FCT(rd_kbytestotal, vfs_statfs);
LPROC_LLITE_STAT_FCT(rd_kbytesfree,  vfs_statfs);
LPROC_LLITE_STAT_FCT(rd_filestotal,  vfs_statfs);
LPROC_LLITE_STAT_FCT(rd_filesfree,   vfs_statfs);
LPROC_LLITE_STAT_FCT(rd_filegroups,  vfs_statfs);

int rd_path(char *page, char **start, off_t off, int count, int *eof,
            void *data)
{
        return 0;
}

int rd_fstype(char *page, char **start, off_t off, int count, int *eof,
              void *data)
{
        struct super_block *sb = (struct super_block*)data;

        LASSERT(sb != NULL);
        *eof = 1;
        return snprintf(page, count, "%s\n", sb->s_type->name);
}

int rd_sb_uuid(char *page, char **start, off_t off, int count, int *eof,
               void *data)
{
        struct super_block *sb = (struct super_block *)data;

        LASSERT(sb != NULL);
        *eof = 1;
        return snprintf(page, count, "%s\n", ll_s2sbi(sb)->ll_sb_uuid.uuid);
}

struct lprocfs_vars lprocfs_obd_vars[] = {
        { "uuid",        rd_sb_uuid,     0, 0 },
        { "mntpt_path",  rd_path,        0, 0 },
        { "fstype",      rd_fstype,      0, 0 },
        { "blocksize",   rd_blksize,     0, 0 },
        { "kbytestotal", rd_kbytestotal, 0, 0 },
        { "kbytesfree",  rd_kbytesfree,  0, 0 },
        { "filestotal",  rd_filestotal,  0, 0 },
        { "filesfree",   rd_filesfree,   0, 0 },
        { "filegroups",  rd_filegroups,  0, 0 },
        { 0 }
};

#define MAX_STRING_SIZE 128

struct llite_file_opcode {
        __u32       opcode;
        __u32       type;
        const char *opname;
} llite_opcode_table[LPROC_LL_FILE_OPCODES] = {
        /* file operation */
        { LPROC_LL_DIRTY_PAGES,    LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_PAGES, 
                                   "dirty_pages" }, 
        { LPROC_LL_DIRTY_HITS,     LPROCFS_TYPE_REGS, "dirty_pages_hits" }, 
        { LPROC_LL_DIRTY_MISSES,   LPROCFS_TYPE_REGS, "dirty_pages_misses" }, 
        { LPROC_LL_WB_WRITEPAGE,   LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_PAGES,
                                   "writeback_from_writepage" }, 
        { LPROC_LL_WB_PRESSURE,    LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_PAGES,
                                   "writeback_from_pressure" }, 
        { LPROC_LL_WB_OK,          LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_PAGES,
                                   "writeback_ok_pages" }, 
        { LPROC_LL_WB_FAIL,        LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_PAGES,
                                   "writeback_failed_pages" }, 
        { LPROC_LL_READ,           LPROCFS_TYPE_REGS, "read" }, 
        { LPROC_LL_READ_BYTES,     LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_BYTES,
                                   "read_bytes" }, 
        { LPROC_LL_WRITE,          LPROCFS_TYPE_REGS, "write" }, 
        { LPROC_LL_WRITE_BYTES,    LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_BYTES,
                                   "write_bytes" }, 
        { LPROC_LL_BRW_READ,       LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_PAGES, 
                                   "brw_read" }, 
        { LPROC_LL_BRW_WRITE,      LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_PAGES, 
                                   "brw_write" }, 

        { LPROC_LL_IOCTL,          LPROCFS_TYPE_REGS, "ioctl" }, 
        { LPROC_LL_OPEN,           LPROCFS_TYPE_REGS, "open" }, 
        { LPROC_LL_RELEASE,        LPROCFS_TYPE_REGS, "close" }, 
        { LPROC_LL_MAP,            LPROCFS_TYPE_REGS, "mmap" }, 
        { LPROC_LL_LLSEEK,         LPROCFS_TYPE_REGS, "seek" }, 
        { LPROC_LL_FSYNC,          LPROCFS_TYPE_REGS, "fsync" }, 
        /* inode operation */ 
        { LPROC_LL_SETATTR_RAW,    LPROCFS_TYPE_REGS, "setattr_raw" }, 
        { LPROC_LL_SETATTR,        LPROCFS_TYPE_REGS, "setattr" }, 
        { LPROC_LL_TRUNCT,         LPROCFS_TYPE_REGS, "punch" },
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        { LPROC_LL_GETATTR,        LPROCFS_TYPE_REGS, "getattr" },
#else
        { LPROC_LL_REVALIDATE,     LPROCFS_TYPE_REGS, "getattr" },
#endif
        /* special inode operation */
        { LPROC_LL_STAFS,          LPROCFS_TYPE_REGS, "statfs" },
        { LPROC_LL_ALLOC_INODE,    LPROCFS_TYPE_REGS, "alloc_inode" },
        { LPROC_LL_DIRECT_READ,    LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_PAGES,
                                   "direct_read" }, 
        { LPROC_LL_DIRECT_WRITE,   LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_PAGES,
                                   "direct_write" }, 

};

int lprocfs_register_mountpoint(struct proc_dir_entry *parent,
                                struct super_block *sb, char *osc, char *mdc)
{
        struct lprocfs_vars lvars[2];
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_device *obd;
        char name[MAX_STRING_SIZE + 1];
        struct obd_uuid uuid;
        int err, id; 
        struct lprocfs_counters *svc_cntrs = NULL;
        ENTRY;

        memset(lvars, 0, sizeof(lvars));

        name[MAX_STRING_SIZE] = '\0';
        lvars[0].name = name;

        LASSERT(sbi != NULL);
        LASSERT(mdc != NULL);
        LASSERT(osc != NULL);

        /* Mount info */
        snprintf(name, MAX_STRING_SIZE, "fs%llu", mnt_instance);

        mnt_instance++;
        sbi->ll_proc_root = lprocfs_register(name, parent, NULL, NULL);
        if (IS_ERR(sbi->ll_proc_root)) {
                err = PTR_ERR(sbi->ll_proc_root);
                sbi->ll_proc_root = NULL;
                RETURN(err);
        }

        svc_cntrs = lprocfs_alloc_counters(LPROC_LL_FILE_OPCODES);
        if (svc_cntrs == NULL) {
                err = -ENOMEM; 
                goto out;
        }
        /* do counter init */
        for (id=0; id < LPROC_LL_FILE_OPCODES; id++) {
                __u32 type = llite_opcode_table[id].type;
                void *ptr=NULL;
                if (type & LPROCFS_TYPE_REGS)
                        ptr = "regs";
                else {
                        if (type & LPROCFS_TYPE_BYTES)
                                ptr = "bytes";
                        else {
                                if (type & LPROCFS_TYPE_PAGES)
                                        ptr = "pages";
                        }
                }
                LPROCFS_COUNTER_INIT(svc_cntrs, llite_opcode_table[id].opcode, 
                        (type & LPROCFS_CNTR_AVGMINMAX), 
                        llite_opcode_table[id].opname, ptr); 
        }
        err = lprocfs_register_counters(sbi->ll_proc_root, "stats", 
                        svc_cntrs);
        if (err)
                goto out;
        else
                sbi->ll_lprocfs_cntrs = svc_cntrs;
        /* need place to keep svc_cntrs */

        /* Static configuration info */
        err = lprocfs_add_vars(sbi->ll_proc_root, lprocfs_obd_vars, sb);
        if (err)
                goto out;

        /* MDC info */
        strncpy(uuid.uuid, mdc, sizeof(uuid.uuid));
        obd = class_uuid2obd(&uuid);

        LASSERT(obd != NULL);
        LASSERT(obd->obd_type != NULL);
        LASSERT(obd->obd_type->typ_name != NULL);

        snprintf(name, MAX_STRING_SIZE, "%s/common_name",
                 obd->obd_type->typ_name);
        lvars[0].read_fptr = lprocfs_rd_name;
        err = lprocfs_add_vars(sbi->ll_proc_root, lvars, obd);
        if (err)
                goto out;

        snprintf(name, MAX_STRING_SIZE, "%s/uuid", obd->obd_type->typ_name);
        lvars[0].read_fptr = lprocfs_rd_uuid;
        err = lprocfs_add_vars(sbi->ll_proc_root, lvars, obd);
        if (err)
                goto out;

        /* OSC */
        strncpy(uuid.uuid, osc, sizeof(uuid.uuid));
        obd = class_uuid2obd(&uuid);

        LASSERT(obd != NULL);
        LASSERT(obd->obd_type != NULL);
        LASSERT(obd->obd_type->typ_name != NULL);

        snprintf(name, MAX_STRING_SIZE, "%s/common_name",
                 obd->obd_type->typ_name);
        lvars[0].read_fptr = lprocfs_rd_name;
        err = lprocfs_add_vars(sbi->ll_proc_root, lvars, obd);
        if (err)
                goto out;

        snprintf(name, MAX_STRING_SIZE, "%s/uuid", obd->obd_type->typ_name);
        lvars[0].read_fptr = lprocfs_rd_uuid;
        err = lprocfs_add_vars(sbi->ll_proc_root, lvars, obd);
out:
        if (err) {
                if (svc_cntrs)
                        lprocfs_free_counters(svc_cntrs);
                if (sbi->ll_proc_root)
                        lprocfs_remove(sbi->ll_proc_root);
        }
        RETURN(err);
}

void lprocfs_unregister_mountpoint(struct ll_sb_info *sbi)
{
        if (sbi->ll_proc_root) {
                struct proc_dir_entry *file_stats = 
                        lprocfs_srch(sbi->ll_proc_root, "stats");

                if (file_stats) {
                        lprocfs_free_counters(sbi->ll_lprocfs_cntrs);
                        lprocfs_remove(file_stats);
                }
        }
}
#undef MAX_STRING_SIZE
#endif /* LPROCFS */
