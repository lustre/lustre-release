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
#include <lustre_lite.h>
#include <lprocfs_status.h>
#include <linux/seq_file.h>
#include <obd_support.h>

#include "llite_internal.h"

struct proc_dir_entry *proc_lustre_fs_root;

#ifdef LPROCFS
/* /proc/lustre/llite mount point registration */
struct file_operations llite_dump_pgcache_fops;
struct file_operations ll_ra_stats_fops;

static int ll_rd_blksize(char *page, char **start, off_t off, int count,
                         int *eof, void *data)
{
        struct super_block *sb = (struct super_block *)data;
        struct obd_statfs osfs;
        int rc;

        LASSERT(sb != NULL);
        rc = ll_statfs_internal(sb, &osfs, cfs_time_current_64() - HZ);
        if (!rc) {
              *eof = 1;
              rc = snprintf(page, count, "%u\n", osfs.os_bsize);
        }

        return rc;
}

static int ll_rd_kbytestotal(char *page, char **start, off_t off, int count,
                             int *eof, void *data)
{
        struct super_block *sb = (struct super_block *)data;
        struct obd_statfs osfs;
        int rc;

        LASSERT(sb != NULL);
        rc = ll_statfs_internal(sb, &osfs, cfs_time_current_64() - HZ);
        if (!rc) {
                __u32 blk_size = osfs.os_bsize >> 10;
                __u64 result = osfs.os_blocks;

                while (blk_size >>= 1)
                        result <<= 1;

                *eof = 1;
                rc = snprintf(page, count, LPU64"\n", result);
        }
        return rc;

}

static int ll_rd_kbytesfree(char *page, char **start, off_t off, int count,
                            int *eof, void *data)
{
        struct super_block *sb = (struct super_block *)data;
        struct obd_statfs osfs;
        int rc;

        LASSERT(sb != NULL);
        rc = ll_statfs_internal(sb, &osfs, cfs_time_current_64() - HZ);
        if (!rc) {
                __u32 blk_size = osfs.os_bsize >> 10;
                __u64 result = osfs.os_bfree;

                while (blk_size >>= 1)
                        result <<= 1;

                *eof = 1;
                rc = snprintf(page, count, LPU64"\n", result);
        }
        return rc;
}

static int ll_rd_kbytesavail(char *page, char **start, off_t off, int count,
                             int *eof, void *data)
{
        struct super_block *sb = (struct super_block *)data;
        struct obd_statfs osfs;
        int rc;

        LASSERT(sb != NULL);
        rc = ll_statfs_internal(sb, &osfs, cfs_time_current_64() - HZ);
        if (!rc) {
                __u32 blk_size = osfs.os_bsize >> 10;
                __u64 result = osfs.os_bavail;

                while (blk_size >>= 1)
                        result <<= 1;

                *eof = 1;
                rc = snprintf(page, count, LPU64"\n", result);
        }
        return rc;
}

static int ll_rd_filestotal(char *page, char **start, off_t off, int count,
                            int *eof, void *data)
{
        struct super_block *sb = (struct super_block *)data;
        struct obd_statfs osfs;
        int rc;

        LASSERT(sb != NULL);
        rc = ll_statfs_internal(sb, &osfs, cfs_time_current_64() - HZ);
        if (!rc) {
                 *eof = 1;
                 rc = snprintf(page, count, LPU64"\n", osfs.os_files);
        }
        return rc;
}

static int ll_rd_filesfree(char *page, char **start, off_t off, int count,
                           int *eof, void *data)
{
        struct super_block *sb = (struct super_block *)data;
        struct obd_statfs osfs;
        int rc;

        LASSERT(sb != NULL);
        rc = ll_statfs_internal(sb, &osfs, cfs_time_current_64() - HZ);
        if (!rc) {
                 *eof = 1;
                 rc = snprintf(page, count, LPU64"\n", osfs.os_ffree);
        }
        return rc;

}

static int ll_rd_fstype(char *page, char **start, off_t off, int count,
                        int *eof, void *data)
{
        struct super_block *sb = (struct super_block*)data;

        LASSERT(sb != NULL);
        *eof = 1;
        return snprintf(page, count, "%s\n", sb->s_type->name);
}

static int ll_rd_sb_uuid(char *page, char **start, off_t off, int count,
                         int *eof, void *data)
{
        struct super_block *sb = (struct super_block *)data;

        LASSERT(sb != NULL);
        *eof = 1;
        return snprintf(page, count, "%s\n", ll_s2sbi(sb)->ll_sb_uuid.uuid);
}

static int ll_rd_max_readahead_mb(char *page, char **start, off_t off,
                                   int count, int *eof, void *data)
{
        struct super_block *sb = data;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        long pages_number;
        int mult;

        spin_lock(&sbi->ll_lock);
        pages_number = sbi->ll_ra_info.ra_max_pages;
        spin_unlock(&sbi->ll_lock);

        mult = 1 << (20 - PAGE_CACHE_SHIFT);
        return lprocfs_read_frac_helper(page, count, pages_number, mult);
}

static int ll_wr_max_readahead_mb(struct file *file, const char *buffer,
                                   unsigned long count, void *data)
{
        struct super_block *sb = data;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        int mult, rc, pages_number;

        mult = 1 << (20 - PAGE_CACHE_SHIFT);
        rc = lprocfs_write_frac_helper(buffer, count, &pages_number, mult);
        if (rc)
                return rc;

        if (pages_number < 0 || pages_number > num_physpages / 2) {
                CERROR("can't set file readahead more than %lu MB\n",
                        num_physpages >> (20 - PAGE_CACHE_SHIFT + 1)); /*1/2 of RAM*/
                return -ERANGE;
        }

        spin_lock(&sbi->ll_lock);
        sbi->ll_ra_info.ra_max_pages = pages_number;
        spin_unlock(&sbi->ll_lock);

        return count;
}

static int ll_rd_max_read_ahead_whole_mb(char *page, char **start, off_t off,
                                       int count, int *eof, void *data)
{
        struct super_block *sb = data;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        long pages_number;
        int mult;

        spin_lock(&sbi->ll_lock);
        pages_number = sbi->ll_ra_info.ra_max_read_ahead_whole_pages;
        spin_unlock(&sbi->ll_lock);

        mult = 1 << (20 - PAGE_CACHE_SHIFT);
        return lprocfs_read_frac_helper(page, count, pages_number, mult);
}

static int ll_wr_max_read_ahead_whole_mb(struct file *file, const char *buffer,
                                       unsigned long count, void *data)
{
        struct super_block *sb = data;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        int mult, rc, pages_number;

        mult = 1 << (20 - PAGE_CACHE_SHIFT);
        rc = lprocfs_write_frac_helper(buffer, count, &pages_number, mult);
        if (rc)
                return rc;

        /* Cap this at the current max readahead window size, the readahead
         * algorithm does this anyway so it's pointless to set it larger. */
        if (pages_number < 0 || pages_number > sbi->ll_ra_info.ra_max_pages) {
                CERROR("can't set max_read_ahead_whole_mb more than "
                       "max_read_ahead_mb: %lu\n",
                       sbi->ll_ra_info.ra_max_pages >> (20 - PAGE_CACHE_SHIFT));
                return -ERANGE;
        }

        spin_lock(&sbi->ll_lock);
        sbi->ll_ra_info.ra_max_read_ahead_whole_pages = pages_number;
        spin_unlock(&sbi->ll_lock);

        return count;
}

static int ll_rd_max_cached_mb(char *page, char **start, off_t off,
                               int count, int *eof, void *data)
{
        struct super_block *sb = data;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        long pages_number;
        int mult;

        spin_lock(&sbi->ll_lock);
        pages_number = sbi->ll_async_page_max;
        spin_unlock(&sbi->ll_lock);

        mult = 1 << (20 - PAGE_CACHE_SHIFT);
        return lprocfs_read_frac_helper(page, count, pages_number, mult);;
}

static int ll_wr_max_cached_mb(struct file *file, const char *buffer,
                                  unsigned long count, void *data)
{
        struct super_block *sb = data;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        int mult, rc, pages_number;

        mult = 1 << (20 - PAGE_CACHE_SHIFT);
        rc = lprocfs_write_frac_helper(buffer, count, &pages_number, mult);
        if (rc)
                return rc;

        if (pages_number < 0 || pages_number > num_physpages) {
                CERROR("can't set max cache more than %lu MB\n",
                        num_physpages >> (20 - PAGE_CACHE_SHIFT));
                return -ERANGE;
        }

        spin_lock(&sbi->ll_lock);
        sbi->ll_async_page_max = pages_number ;
        spin_unlock(&sbi->ll_lock);
        
        if (!sbi->ll_dt_exp)
                /* Not set up yet, don't call llap_shrink_cache */
                return count;

        if (sbi->ll_async_page_count >= sbi->ll_async_page_max)
                llap_shrink_cache(sbi, 0);

        return count;
}

static int ll_rd_checksum(char *page, char **start, off_t off,
                          int count, int *eof, void *data)
{
        struct super_block *sb = data;
        struct ll_sb_info *sbi = ll_s2sbi(sb);

        return snprintf(page, count, "%u\n",
                        (sbi->ll_flags & LL_SBI_CHECKSUM) ? 1 : 0);
}

static int ll_wr_checksum(struct file *file, const char *buffer,
                          unsigned long count, void *data)
{
        struct super_block *sb = data;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        int val, rc;

        if (!sbi->ll_dt_exp)
                /* Not set up yet */
                return -EAGAIN;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;
        if (val)
                sbi->ll_flags |= LL_SBI_CHECKSUM;
        else
                sbi->ll_flags &= ~LL_SBI_CHECKSUM;

        rc = obd_set_info_async(sbi->ll_dt_exp, strlen("checksum"), "checksum",
                                sizeof(val), &val, NULL);
        if (rc)
                CWARN("Failed to set OSC checksum flags: %d\n", rc);

        return count;
}

static int ll_rd_max_rw_chunk(char *page, char **start, off_t off,
                          int count, int *eof, void *data)
{
        struct super_block *sb = data;

        return snprintf(page, count, "%lu\n", ll_s2sbi(sb)->ll_max_rw_chunk);
}

static int ll_wr_max_rw_chunk(struct file *file, const char *buffer,
                          unsigned long count, void *data)
{
        struct super_block *sb = data;
        int rc, val;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;
        ll_s2sbi(sb)->ll_max_rw_chunk = val;
        return count;
}

static struct lprocfs_vars lprocfs_obd_vars[] = {
        { "uuid",         ll_rd_sb_uuid,          0, 0 },
        //{ "mntpt_path",   ll_rd_path,             0, 0 },
        { "fstype",       ll_rd_fstype,           0, 0 },
        { "blocksize",    ll_rd_blksize,          0, 0 },
        { "kbytestotal",  ll_rd_kbytestotal,      0, 0 },
        { "kbytesfree",   ll_rd_kbytesfree,       0, 0 },
        { "kbytesavail",  ll_rd_kbytesavail,      0, 0 },
        { "filestotal",   ll_rd_filestotal,       0, 0 },
        { "filesfree",    ll_rd_filesfree,        0, 0 },
        //{ "filegroups",   lprocfs_rd_filegroups,  0, 0 },
        { "max_read_ahead_mb", ll_rd_max_readahead_mb,
                               ll_wr_max_readahead_mb, 0 },
        { "max_read_ahead_whole_mb", ll_rd_max_read_ahead_whole_mb,
                                     ll_wr_max_read_ahead_whole_mb, 0 },
        { "max_cached_mb", ll_rd_max_cached_mb, ll_wr_max_cached_mb, 0 },
        { "checksum_pages", ll_rd_checksum, ll_wr_checksum, 0 },
        { "max_rw_chunk", ll_rd_max_rw_chunk, ll_wr_max_rw_chunk, 0 },
        { 0 }
};

#define MAX_STRING_SIZE 128

struct llite_file_opcode {
        __u32       opcode;
        __u32       type;
        const char *opname;
} llite_opcode_table[LPROC_LL_FILE_OPCODES] = {
        /* file operation */
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
        { LPROC_LL_READ_BYTES,     LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_BYTES,
                                   "read_bytes" },
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
        { LPROC_LL_SETATTR,        LPROCFS_TYPE_REGS, "setattr" },
        { LPROC_LL_TRUNC,          LPROCFS_TYPE_REGS, "punch" },
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        { LPROC_LL_GETATTR,        LPROCFS_TYPE_REGS, "getattr" },
#else
        { LPROC_LL_REVALIDATE,     LPROCFS_TYPE_REGS, "getattr" },
#endif
        /* special inode operation */
        { LPROC_LL_STAFS,          LPROCFS_TYPE_REGS, "statfs" },
        { LPROC_LL_ALLOC_INODE,    LPROCFS_TYPE_REGS, "alloc_inode" },
        { LPROC_LL_SETXATTR,       LPROCFS_TYPE_REGS, "setxattr" },
        { LPROC_LL_GETXATTR,       LPROCFS_TYPE_REGS, "getxattr" },
        { LPROC_LL_DIRECT_READ,    LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_PAGES,
                                   "direct_read" },
        { LPROC_LL_DIRECT_WRITE,   LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_PAGES,
                                   "direct_write" },

};

int lprocfs_register_mountpoint(struct proc_dir_entry *parent,
                                struct super_block *sb, char *osc, char *mdc)
{
        struct lprocfs_vars lvars[2];
        struct lustre_sb_info *lsi = s2lsi(sb);
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_device *obd;
        char name[MAX_STRING_SIZE + 1], *ptr;
        int err, id, len;
        struct lprocfs_stats *svc_stats = NULL;
        struct proc_dir_entry *entry;
        ENTRY;

        memset(lvars, 0, sizeof(lvars));

        name[MAX_STRING_SIZE] = '\0';
        lvars[0].name = name;

        LASSERT(sbi != NULL);
        LASSERT(mdc != NULL);
        LASSERT(osc != NULL);

        /* Get fsname */
        len = strlen(lsi->lsi_lmd->lmd_profile);
        ptr = strrchr(lsi->lsi_lmd->lmd_profile, '-');
        if (ptr && (strcmp(ptr, "-client") == 0))
                len -= 7; 
        
        /* Mount info */
        snprintf(name, MAX_STRING_SIZE, "%.*s-%p", len,
                 lsi->lsi_lmd->lmd_profile, sb);
        
        sbi->ll_proc_root = lprocfs_register(name, parent, NULL, NULL);
        if (IS_ERR(sbi->ll_proc_root)) {
                err = PTR_ERR(sbi->ll_proc_root);
                sbi->ll_proc_root = NULL;
                RETURN(err);
        }

        entry = create_proc_entry("dump_page_cache", 0444, sbi->ll_proc_root);
        if (entry == NULL)
                GOTO(out, err = -ENOMEM);
        entry->proc_fops = &llite_dump_pgcache_fops;
        entry->data = sbi;

        entry = create_proc_entry("read_ahead_stats", 0444, sbi->ll_proc_root);
        if (entry == NULL)
                GOTO(out, err = -ENOMEM);
        entry->proc_fops = &ll_ra_stats_fops;
        entry->data = sbi;

        svc_stats = lprocfs_alloc_stats(LPROC_LL_FILE_OPCODES);
        if (svc_stats == NULL) {
                err = -ENOMEM;
                goto out;
        }
        /* do counter init */
        for (id = 0; id < LPROC_LL_FILE_OPCODES; id++) {
                __u32 type = llite_opcode_table[id].type;
                void *ptr = NULL;
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
                lprocfs_counter_init(svc_stats, llite_opcode_table[id].opcode,
                                     (type & LPROCFS_CNTR_AVGMINMAX),
                                     llite_opcode_table[id].opname, ptr);
        }
        err = lprocfs_register_stats(sbi->ll_proc_root, "stats", svc_stats);
        if (err)
                goto out;
        else
                sbi->ll_stats = svc_stats;
        /* need place to keep svc_stats */

        /* Static configuration info */
        err = lprocfs_add_vars(sbi->ll_proc_root, lprocfs_obd_vars, sb);
        if (err)
                goto out;

        /* MDC info */
        obd = class_name2obd(mdc);

        LASSERT(obd != NULL);
        LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
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
        obd = class_name2obd(osc);

        LASSERT(obd != NULL);
        LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
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
                if (svc_stats)
                        lprocfs_free_stats(svc_stats);
                if (sbi->ll_proc_root)
                        lprocfs_remove(sbi->ll_proc_root);
                sbi->ll_proc_root = NULL;
        }
        RETURN(err);
}

void lprocfs_unregister_mountpoint(struct ll_sb_info *sbi)
{
        if (sbi->ll_proc_root) {
                struct proc_dir_entry *file_stats =
                        lprocfs_srch(sbi->ll_proc_root, "stats");
                if (file_stats) 
                        lprocfs_free_stats(sbi->ll_stats);
                lprocfs_remove(sbi->ll_proc_root);
                sbi->ll_proc_root = NULL;
        }
}
#undef MAX_STRING_SIZE

#define seq_page_flag(seq, page, flag, has_flags) do {                  \
                if (test_bit(PG_##flag, &(page)->flags)) {              \
                        if (!has_flags)                                 \
                                has_flags = 1;                          \
                        else                                            \
                                seq_putc(seq, '|');                     \
                        seq_puts(seq, #flag);                           \
                }                                                       \
        } while(0);

static void *llite_dump_pgcache_seq_start(struct seq_file *seq, loff_t *pos)
{
        struct ll_async_page *dummy_llap = seq->private;

        if (dummy_llap->llap_magic == 2)
                return NULL;

        return (void *)1;
}

static int llite_dump_pgcache_seq_show(struct seq_file *seq, void *v)
{
        struct ll_async_page *llap, *dummy_llap = seq->private;
        struct ll_sb_info *sbi = dummy_llap->llap_cookie;

        /* 2.4 doesn't seem to have SEQ_START_TOKEN, so we implement
         * it in our own state */
        if (dummy_llap->llap_magic == 0) {
                seq_printf(seq, "gener |  llap  cookie  origin wq du | page "
                                "inode index count [ page flags ]\n");
                return 0;
        }

        spin_lock(&sbi->ll_lock);

        llap = llite_pglist_next_llap(sbi, &dummy_llap->llap_pglist_item);
        if (llap != NULL)  {
                int has_flags = 0;
                struct page *page = llap->llap_page;

                LASSERTF(llap->llap_origin < LLAP__ORIGIN_MAX, "%u\n",
                         llap->llap_origin);

                seq_printf(seq, "%5lu | %p %p %s %s %s | %p %p %lu %u [",
                           sbi->ll_pglist_gen,
                           llap, llap->llap_cookie,
                           llap_origins[llap->llap_origin],
                           llap->llap_write_queued ? "wq" : "- ",
                           llap->llap_defer_uptodate ? "du" : "- ",
                           page, page->mapping->host, page->index,
                           page_count(page));
                seq_page_flag(seq, page, locked, has_flags);
                seq_page_flag(seq, page, error, has_flags);
                seq_page_flag(seq, page, referenced, has_flags);
                seq_page_flag(seq, page, uptodate, has_flags);
                seq_page_flag(seq, page, dirty, has_flags);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,12))
                seq_page_flag(seq, page, highmem, has_flags);
#endif
                if (!has_flags)
                        seq_puts(seq, "-]\n");
                else 
                        seq_puts(seq, "]\n");
        }

        spin_unlock(&sbi->ll_lock);

        return 0;
}

static void *llite_dump_pgcache_seq_next(struct seq_file *seq, void *v, 
                                         loff_t *pos)
{
        struct ll_async_page *llap, *dummy_llap = seq->private;
        struct ll_sb_info *sbi = dummy_llap->llap_cookie;

        /* bail if we just displayed the banner */
        if (dummy_llap->llap_magic == 0) {
                dummy_llap->llap_magic = 1;
                return dummy_llap;
        }

        /* we've just displayed the llap that is after us in the list.
         * we advance to a position beyond it, returning null if there
         * isn't another llap in the list beyond that new position. */
        spin_lock(&sbi->ll_lock);
        llap = llite_pglist_next_llap(sbi, &dummy_llap->llap_pglist_item);
        list_del_init(&dummy_llap->llap_pglist_item);
        if (llap) {
                list_add(&dummy_llap->llap_pglist_item,&llap->llap_pglist_item);
                llap =llite_pglist_next_llap(sbi,&dummy_llap->llap_pglist_item);
        }
        spin_unlock(&sbi->ll_lock);

        ++*pos;
        if (llap == NULL) {
                dummy_llap->llap_magic = 2;
                return NULL;
        }
        return dummy_llap;
}

static void llite_dump_pgcache_seq_stop(struct seq_file *seq, void *v)
{
}

struct seq_operations llite_dump_pgcache_seq_sops = {
        .start = llite_dump_pgcache_seq_start,
        .stop = llite_dump_pgcache_seq_stop,
        .next = llite_dump_pgcache_seq_next,
        .show = llite_dump_pgcache_seq_show,
};

/* we're displaying llaps in a list_head list.  we don't want to hold a lock
 * while we walk the entire list, and we don't want to have to seek into
 * the right position in the list as an app advances with many syscalls.  we
 * allocate a dummy llap and hang it off file->private.  its position in
 * the list records where the app is currently displaying.  this way our
 * seq .start and .stop don't actually do anything.  .next returns null
 * when the dummy hits the end of the list which eventually leads to .release
 * where we tear down.  this kind of displaying is super-racey, so we put
 * a generation counter on the list so the output shows when the list
 * changes between reads.
 */
static int llite_dump_pgcache_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct ll_async_page *dummy_llap;
        struct seq_file *seq;
        struct ll_sb_info *sbi = dp->data;
        int rc;

        OBD_ALLOC_GFP(dummy_llap, sizeof(*dummy_llap), GFP_KERNEL);
        if (dummy_llap == NULL)
                return -ENOMEM;
        dummy_llap->llap_page = NULL;
        dummy_llap->llap_cookie = sbi;
        dummy_llap->llap_magic = 0;

        rc = seq_open(file, &llite_dump_pgcache_seq_sops);
        if (rc) {
                OBD_FREE(dummy_llap, sizeof(*dummy_llap));
                return rc;
        }
        seq = file->private_data;
        seq->private = dummy_llap;

        spin_lock(&sbi->ll_lock);
        list_add(&dummy_llap->llap_pglist_item, &sbi->ll_pglist);
        spin_unlock(&sbi->ll_lock);

        return 0;
}

static int llite_dump_pgcache_seq_release(struct inode *inode,
                                          struct file *file)
{
        struct seq_file *seq = file->private_data;
        struct ll_async_page *dummy_llap = seq->private;
        struct ll_sb_info *sbi = dummy_llap->llap_cookie;

        spin_lock(&sbi->ll_lock);
        if (!list_empty(&dummy_llap->llap_pglist_item))
                list_del_init(&dummy_llap->llap_pglist_item);
        spin_unlock(&sbi->ll_lock);
        OBD_FREE(dummy_llap, sizeof(*dummy_llap));

        return seq_release(inode, file);
}

struct file_operations llite_dump_pgcache_fops = {
        .owner   = THIS_MODULE,
        .open    = llite_dump_pgcache_seq_open,
        .read    = seq_read,
        .release = llite_dump_pgcache_seq_release,
};

static int ll_ra_stats_seq_show(struct seq_file *seq, void *v)
{
        struct timeval now;
        struct ll_sb_info *sbi = seq->private;
        struct ll_ra_info *ra = &sbi->ll_ra_info;
        int i;
        static char *ra_stat_strings[] = {
                [RA_STAT_HIT] = "hits",
                [RA_STAT_MISS] = "misses",
                [RA_STAT_DISTANT_READPAGE] = "readpage not consecutive",
                [RA_STAT_MISS_IN_WINDOW] = "miss inside window",
                [RA_STAT_FAILED_GRAB_PAGE] = "failed grab_cache_page",
                [RA_STAT_FAILED_MATCH] = "failed lock match",
                [RA_STAT_DISCARDED] = "read but discarded",
                [RA_STAT_ZERO_LEN] = "zero length file",
                [RA_STAT_ZERO_WINDOW] = "zero size window",
                [RA_STAT_EOF] = "read-ahead to EOF",
                [RA_STAT_MAX_IN_FLIGHT] = "hit max r-a issue",
                [RA_STAT_WRONG_GRAB_PAGE] = "wrong page from grab_cache_page",
        };

        do_gettimeofday(&now);

        spin_lock(&sbi->ll_lock);

        seq_printf(seq, "snapshot_time:         %lu.%lu (secs.usecs)\n",
                   now.tv_sec, now.tv_usec);
        seq_printf(seq, "pending issued pages:           %lu\n",
                   ra->ra_cur_pages);

        for(i = 0; i < _NR_RA_STAT; i++)
                seq_printf(seq, "%-25s %lu\n", ra_stat_strings[i], 
                           ra->ra_stats[i]);

        spin_unlock(&sbi->ll_lock);

        return 0;
}

static void *ll_ra_stats_seq_start(struct seq_file *p, loff_t *pos)
{
        if (*pos == 0)
                return (void *)1;
        return NULL;
}
static void *ll_ra_stats_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
        ++*pos;
        return NULL;
}
static void ll_ra_stats_seq_stop(struct seq_file *p, void *v)
{
}
struct seq_operations ll_ra_stats_seq_sops = {
        .start = ll_ra_stats_seq_start,
        .stop = ll_ra_stats_seq_stop,
        .next = ll_ra_stats_seq_next,
        .show = ll_ra_stats_seq_show,
};

static int ll_ra_stats_seq_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file *seq;
        int rc;

        rc = seq_open(file, &ll_ra_stats_seq_sops);
        if (rc)
                return rc;
        seq = file->private_data;
        seq->private = dp->data;
        return 0;
}

static ssize_t ll_ra_stats_seq_write(struct file *file, const char *buf,
                                       size_t len, loff_t *off)
{
        struct seq_file *seq = file->private_data;
        struct ll_sb_info *sbi = seq->private;
        struct ll_ra_info *ra = &sbi->ll_ra_info;

        spin_lock(&sbi->ll_lock);
        memset(ra->ra_stats, 0, sizeof(ra->ra_stats));
        spin_unlock(&sbi->ll_lock);

        return len;
}

struct file_operations ll_ra_stats_fops = {
        .owner   = THIS_MODULE,
        .open    = ll_ra_stats_seq_open,
        .read    = seq_read,
        .write   = ll_ra_stats_seq_write,
        .llseek  = seq_lseek,
        .release = seq_release,
};

LPROCFS_INIT_VARS(llite, NULL, lprocfs_obd_vars)
#endif /* LPROCFS */
