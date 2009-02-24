#if 1
/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/dmu/udmu.c
 *  Module that interacts with the ZFS DMU and provides an abstraction
 *  to the rest of Lustre.
 *
 *  Copyright (c) 2007 Cluster File Systems, Inc.
 *   Author: Alex Tomas <alex@clusterfs.com>
 *   Author: Atul Vidwansa <atul.vidwansa@sun.com>
 *   Author: Manoj Joseph <manoj.joseph@sun.com>
 *   Author: Mike Pershin <tappro@sun.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#include <sys/dnode.h>
#include <sys/dbuf.h>
#include <sys/spa.h>
#include <sys/stat.h>
#include <sys/zap.h>
#include <sys/spa_impl.h>
#include <sys/zfs_znode.h>
#include <sys/dmu_tx.h>
#include <sys/dmu_objset.h>
#include "udmu.h"
#include <linux/statfs.h>

enum vtype iftovt_tab[] = {
        VNON, VFIFO, VCHR, VNON, VDIR, VNON, VBLK, VNON,
        VREG, VNON, VLNK, VNON, VSOCK, VNON, VNON, VNON
};

ushort_t vttoif_tab[] = {
        0, S_IFREG, S_IFDIR, S_IFBLK, S_IFCHR, S_IFLNK, S_IFIFO,
        S_IFDOOR, 0, S_IFSOCK, S_IFPORT, 0
};

#define MODEMASK        07777

#define IFTOVT(M)       (iftovt_tab[((M) & S_IFMT) >> 12])
#define VTTOIF(T)       (vttoif_tab[(int)(T)])
#define MAKEIMODE(T, M) (VTTOIF(T) | ((M) & ~S_IFMT))

/*
 * Debug levels. Default is LEVEL_CRITICAL.
 */
#define LEVEL_CRITICAL  1
#define LEVEL_INFO      2
#define LEVEL_DEBUG     3

static int debug_level = LEVEL_CRITICAL;

#define CONFIG_DIR "/var/run/zfs/udmu"
//static char config_path[MAXPATHLEN];

static void udmu_gethrestime(struct timespec *tp)
{
        struct timeval time;
        do_gettimeofday(&time);
        tp->tv_nsec = 0;
        tp->tv_sec = time.tv_sec;
}

#if 0
static void udmu_printf(int level, FILE *stream, char *message, ...)
{
        va_list args;

        if (level <= debug_level) {
                va_start(args, message);
                (void) vfprintf(stream, message, args);
                va_end(args);
        }
}
#else
#define udmu_printf(level,stream,msg, a...)      \
        printk(msg, ## a)
#endif

void udmu_debug(int level)
{
        debug_level = level;
}

int udmu_objset_open(char *osname, char *import_dir, int import, int force,
                     udmu_objset_t *uos)
{
        int error;
        //char cmd[MAXPATHLEN];
        char *c;
        uint64_t version = ZPL_VERSION;
        //int tried_import = FALSE;

        memset(uos, 0, sizeof(udmu_objset_t));

        c = strchr(osname, '/');

        /* Let's try to open the objset */
        error = dmu_objset_open(osname, DMU_OST_ZFS, DS_MODE_OWNER, &uos->os);

#if 0
        if (error == ENOENT && import && !tried_import) {
                /* objset not found, let's try to import the pool */
                udmu_printf(LEVEL_INFO, stdout, "Importing pool %s\n", osname);

                if (c != NULL)
                        *c = '\0';

                snprintf(cmd, sizeof(cmd), "lzpool import%s%s%s %s",
                    force ? " -F" : "", import_dir ? " -d " : "",
                    import_dir ? import_dir : "", osname);

                if (c != NULL)
                        *c = '/';

                error = system(cmd);

                if (error) {
                        udmu_printf(LEVEL_CRITICAL, stderr, "\"%s\" failed:"
                            " %d\n", cmd, error);
                        return(error);
                }

                tried_import = TRUE;
                goto top;
        }
#endif

        if (error) {
                uos->os = NULL;
                goto out;
        }

        /* Check ZFS version */
        error = zap_lookup(uos->os, MASTER_NODE_OBJ, ZPL_VERSION_STR, 8, 1,
                           &version);
        if (error) {
                udmu_printf(LEVEL_CRITICAL, stderr,
                            "Error looking up ZPL VERSION");
                /*
                 * We can't return ENOENT because that would mean the objset
                 * didn't exist.
                 */
                error = EIO;
                goto out;
#if 0
        } else if (version != LUSTRE_ZPL_VERSION) {
                udmu_printf(LEVEL_CRITICAL, stderr,
                            "Mismatched versions:  File system "
                            "is version %lld on-disk format, which is "
                            "incompatible with this software version %lld!",
                            (u_longlong_t)version, LUSTRE_ZPL_VERSION);
                error = ENOTSUP;
                goto out;
#endif
        }

        error = zap_lookup(uos->os, MASTER_NODE_OBJ, ZFS_ROOT_OBJ,
                           8, 1, &uos->root);
        if (error) {
                udmu_printf(LEVEL_CRITICAL, stderr,
                            "Error looking up ZFS root object.");
                error = EIO;
                goto out;
        }
        ASSERT(uos->root != 0);

out:
#if 0
        if (error) {
                if (uos->os == NULL && tried_import) {
                        if (c != NULL)
                                *c = '\0';
                        spa_export(osname, NULL, B_TRUE);
                        if (c != NULL)
                                *c = '/';
                } else if(uos->os != NULL)
                        udmu_objset_close(uos, tried_import);
        }
#endif

        return (error);
}

void udmu_wait_synced(udmu_objset_t *uos, dmu_tx_t *tx)
{
        /* Wait for the pool to be synced */
        txg_wait_synced(dmu_objset_pool(uos->os),
                        tx ? tx->tx_txg : 0ULL);
}

void udmu_objset_close(udmu_objset_t *uos, int export_pool)
{

        ASSERT(uos->os != NULL);

#if 0
        spa_t *spa;
        char pool_name[MAXPATHLEN];
        spa = uos->os->os->os_spa;
        spa_config_enter(spa, RW_READER, FTAG);
        strncpy(pool_name, spa_name(spa), sizeof(pool_name));
        spa_config_exit(spa, FTAG);
#endif

        udmu_wait_synced(uos, NULL);
        /* close the object set */
        dmu_objset_close(uos->os);

        uos->os = NULL;

#if 0
        if (export_pool)
                spa_export(pool_name, NULL, B_TRUE);
#endif
}

int udmu_objset_statfs(udmu_objset_t *uos, struct statfs64 *statp)
{
        uint64_t refdbytes, availbytes, usedobjs, availobjs;

        dmu_objset_space(uos->os, &refdbytes, &availbytes, &usedobjs,
                         &availobjs);

        /*
         * The underlying storage pool actually uses multiple block sizes.
         * We report the fragsize as the smallest block size we support,
         * and we report our blocksize as the filesystem's maximum blocksize.
         */
        statp->f_frsize = 1ULL << SPA_MINBLOCKSHIFT;
        statp->f_bsize = 1ULL << SPA_MAXBLOCKSHIFT;

        /*
         * The following report "total" blocks of various kinds in the
         * file system, but reported in terms of f_frsize - the
         * "fragment" size.
         */

        statp->f_blocks = (refdbytes + availbytes) >> SPA_MINBLOCKSHIFT;
        statp->f_bfree = availbytes >> SPA_MINBLOCKSHIFT;
        statp->f_bavail = statp->f_bfree; /* no root reservation */

        /*
         * statvfs() should really be called statufs(), because it assumes
         * static metadata.  ZFS doesn't preallocate files, so the best
         * we can do is report the max that could possibly fit in f_files,
         * and that minus the number actually used in f_ffree.
         * For f_ffree, report the smaller of the number of object available
         * and the number of blocks (each object will take at least a block).
         */
        statp->f_ffree = MIN(availobjs, statp->f_bfree);
        //statp->f_favail = statp->f_ffree; /* no "root reservation" */
        statp->f_files = statp->f_ffree + usedobjs;

        /* ZFSFUSE: not necessary? see 'man statfs' */
        /*(void) cmpldev(&d32, vfsp->vfs_dev);
        statp->f_fsid = d32;*/

        /*
         * We're a zfs filesystem.
         */
        /* ZFSFUSE: not necessary */
        /*(void) strcpy(statp->f_basetype, vfssw[vfsp->vfs_fstype].vsw_name);

        statp->f_flag = vf_to_stf(vfsp->vfs_flag);*/

        statp->f_namelen = 256;

        return (0);
}

static int udmu_obj2dbuf(udmu_objset_t *uos, uint64_t oid, dmu_buf_t **dbp,
                         void *tag)
{
        dmu_object_info_t doi;
        int err;

        ASSERT(tag);

        err = dmu_bonus_hold(uos->os, oid, tag, dbp);
        if (err) {
                return (err);
        }

        dmu_object_info_from_db(*dbp, &doi);
        if (doi.doi_bonus_type != DMU_OT_ZNODE ||
            doi.doi_bonus_size < sizeof (znode_phys_t)) {
                dmu_buf_rele(*dbp, tag);
                return (EINVAL);
        }

        ASSERT(*dbp);
        ASSERT((*dbp)->db_object == oid);
        ASSERT((*dbp)->db_offset == -1);
        ASSERT((*dbp)->db_data != NULL);

        return (0);
}

int udmu_objset_root(udmu_objset_t *uos, dmu_buf_t **dbp, void *tag)
{
        return (udmu_obj2dbuf(uos, uos->root, dbp, tag));
}

int udmu_zap_lookup(udmu_objset_t *uos, dmu_buf_t *zap_db, const char *name,
                    void *value, int value_size, int intsize)
{
        uint64_t oid;
        oid = zap_db->db_object;

        /*
         * value_size should be a multiple of intsize.
         * intsize is 8 for micro ZAP and 1, 2, 4 or 8 for a fat ZAP.
         */
        ASSERT(value_size % intsize == 0);
        return (zap_lookup(uos->os, oid, name, intsize,
                           value_size / intsize, value));
}

/*
 * The transaction passed to this routine must have
 * udmu_tx_hold_bonus(tx, DMU_NEW_OBJECT) called and then assigned
 * to a transaction group.
 */
void udmu_object_create(udmu_objset_t *uos, dmu_buf_t **dbp, dmu_tx_t *tx,
                        void *tag)
{
        znode_phys_t    *zp;
        uint64_t        oid;
        uint64_t        gen;
        timestruc_t     now;

        ASSERT(tag);

        /* Assert that the transaction has been assigned to a
           transaction group. */
        ASSERT(tx->tx_txg != 0);

        udmu_gethrestime(&now);
        gen = dmu_tx_get_txg(tx);

        /* Create a new DMU object. */
        oid = dmu_object_alloc(uos->os, DMU_OT_PLAIN_FILE_CONTENTS, 0,
                               DMU_OT_ZNODE, sizeof (znode_phys_t), tx);

        dmu_object_set_blocksize(uos->os, oid, 128ULL << 10, 0, tx);

        VERIFY(0 == dmu_bonus_hold(uos->os, oid, tag, dbp));

        dmu_buf_will_dirty(*dbp, tx);

        /* Initialize the znode physical data to zero. */
        ASSERT((*dbp)->db_size >= sizeof (znode_phys_t));
        bzero((*dbp)->db_data, (*dbp)->db_size);
        zp = (*dbp)->db_data;
        zp->zp_gen = gen;
        zp->zp_links = 1;
        ZFS_TIME_ENCODE(&now, zp->zp_crtime);
        ZFS_TIME_ENCODE(&now, zp->zp_ctime);
        ZFS_TIME_ENCODE(&now, zp->zp_atime);
        ZFS_TIME_ENCODE(&now, zp->zp_mtime);
        zp->zp_mode = MAKEIMODE(VREG, 0007);
}


/*
 * The transaction passed to this routine must have
 * udmu_tx_hold_zap(tx, DMU_NEW_OBJECT, ...) called and then assigned
 * to a transaction group.
 */
void udmu_zap_create(udmu_objset_t *uos, dmu_buf_t **zap_dbp, dmu_tx_t *tx,
                     void *tag)
{
        znode_phys_t    *zp;
        uint64_t        oid;
        timestruc_t     now;
        uint64_t        gen;

        ASSERT(tag);

        /* Assert that the transaction has been assigned to a
           transaction group. */
        ASSERT(tx->tx_txg != 0);

        oid = 0;
        udmu_gethrestime(&now);
        gen = dmu_tx_get_txg(tx);

        oid = zap_create(uos->os, DMU_OT_DIRECTORY_CONTENTS, DMU_OT_ZNODE,
                         sizeof (znode_phys_t), tx);

        VERIFY(0 == dmu_bonus_hold(uos->os, oid, tag, zap_dbp));

        dmu_buf_will_dirty(*zap_dbp, tx);

        bzero((*zap_dbp)->db_data, (*zap_dbp)->db_size);
        zp = (*zap_dbp)->db_data;
        zp->zp_size = 2;
        zp->zp_links = 1;
        zp->zp_gen = gen;
        zp->zp_mode = MAKEIMODE(VDIR, 0007);

        ZFS_TIME_ENCODE(&now, zp->zp_crtime);
        ZFS_TIME_ENCODE(&now, zp->zp_ctime);
        ZFS_TIME_ENCODE(&now, zp->zp_atime);
        ZFS_TIME_ENCODE(&now, zp->zp_mtime);
}

int udmu_object_get_dmu_buf(udmu_objset_t *uos, uint64_t object,
                            dmu_buf_t **dbp, void *tag)
{
        return (udmu_obj2dbuf(uos, object, dbp, tag));
}


/*
 * The transaction passed to this routine must have
 * udmu_tx_hold_bonus(tx, oid) and
 * udmu_tx_hold_zap(tx, oid, ...)
 * called and then assigned to a transaction group.
 */
int udmu_zap_insert(udmu_objset_t *uos, dmu_buf_t *zap_db, dmu_tx_t *tx,
                    const char *name, void *value, int len)
{
        uint64_t oid = zap_db->db_object;

        /* Assert that the transaction has been assigned to a
           transaction group. */
        ASSERT(tx->tx_txg != 0);

        dmu_buf_will_dirty(zap_db, tx);
        return (zap_add(uos->os, oid, name, 8, 1, value, tx));
}

/*
 * The transaction passed to this routine must have
 * udmu_tx_hold_zap(tx, oid, ...) called and then
 * assigned to a transaction group.
 */
int udmu_zap_delete(udmu_objset_t *uos, dmu_buf_t *zap_db, dmu_tx_t *tx,
                    const char *name)
{
        uint64_t oid = zap_db->db_object;

        /* Assert that the transaction has been assigned to a
           transaction group. */
        ASSERT(tx->tx_txg != 0);

        return (zap_remove(uos->os, oid, name, tx));
}

/*
 * Zap cursor APIs
 * */

int udmu_zap_cursor_init(zap_cursor_t **zc, udmu_objset_t *uos, uint64_t zapobj)
{
        zap_cursor_t * t;

        t = kmem_alloc(sizeof(*t), KM_NOSLEEP);
        if (t) {
                zap_cursor_init(t, uos->os, zapobj);
                *zc = t;
                return 0;
        }
        return (ENOMEM);
}

void udmu_zap_cursor_fini(zap_cursor_t *zc)
{
        zap_cursor_fini(zc);
        kmem_free(zc, sizeof(*zc));
}

int udmu_zap_cursor_retrieve_key(zap_cursor_t *zc, char *key)
{
        int err;
        zap_attribute_t za;

        if ((err = zap_cursor_retrieve(zc, &za)))
                return err;

        if (key)
                strncpy(key, za.za_name, MAXNAMELEN);

        return 0;
}

/*
 * zap_cursor_retrieve read from current record.
 * to read bytes we need to call zap_lookup explicitly.
 */

int udmu_zap_cursor_retrieve_value(zap_cursor_t *zc,  char *buf,
                int buf_size, int *bytes_read)
{
        int err, actual_size;
        zap_attribute_t za;


        if ((err = zap_cursor_retrieve(zc, &za)))
                return err;

        if (za.za_integer_length <= 0)
                return (ERANGE);

        actual_size = za.za_integer_length * za.za_num_integers;

        if (actual_size > buf_size) {
                actual_size = buf_size;
                buf_size = actual_size / za.za_integer_length;
        } else {
                buf_size = za.za_num_integers;
        }

        err = zap_lookup(zc->zc_objset, zc->zc_zapobj,
                        za.za_name, za.za_integer_length, buf_size, buf);

        if (!err)
                *bytes_read = actual_size;

        return err;
}

void udmu_zap_cursor_advance(zap_cursor_t *zc)
{
        zap_cursor_advance(zc);
}

uint64_t udmu_zap_cursor_serialize(zap_cursor_t *zc)
{
        return zap_cursor_serialize(zc);
}

int udmu_zap_cursor_move_to_key(zap_cursor_t *zc, const char *name)
{
        return zap_cursor_move_to_key(zc, name, MT_EXACT);
}

void udmu_zap_cursor_init_serialized(zap_cursor_t *zc, udmu_objset_t *uos,
                            uint64_t zapobj, uint64_t serialized)
{
        zap_cursor_init_serialized(zc, uos->os, zapobj, serialized);
}


/*
 * Read data from a DMU object
 */
int udmu_object_read(udmu_objset_t *uos, dmu_buf_t *db, uint64_t offset,
                     uint64_t size, void *buf)
{
        uint64_t oid = db->db_object;
        vnattr_t va;
        int rc;

        udmu_printf(LEVEL_INFO, stdout, "udmu_read(%lld, %lld, %lld)\n",
                    oid, offset, size);

        udmu_object_getattr(db, &va);
        if (offset + size > va.va_size) {
                if (va.va_size < offset)
                        size = 0;
                else
                        size = va.va_size - offset;
        }

        rc = dmu_read(uos->os, oid, offset, size, buf);
        if (rc == 0)
                return size;
        else 
                return (-rc);
}

/*
 * Write data to a DMU object
 *
 * The transaction passed to this routine must have had
 * udmu_tx_hold_write(tx, oid, offset, size) called and then
 * assigned to a transaction group.
 */
void udmu_object_write(udmu_objset_t *uos, dmu_buf_t *db, struct dmu_tx *tx,
                       uint64_t offset, uint64_t size, void *buf)
{
        uint64_t oid = db->db_object;

        udmu_printf(LEVEL_INFO, stdout, "udmu_write(%lld, %lld, %lld\n",
                    oid, offset, size);

        dmu_write(uos->os, oid, offset, size, buf, tx);
}

/*
 * Retrieve the attributes of a DMU object
 */
void udmu_object_getattr(dmu_buf_t *db, vnattr_t *vap)
{
        dnode_t *dn = ((dmu_buf_impl_t *)db)->db_dnode;
        znode_phys_t *zp = db->db_data;

        vap->va_mask = DMU_AT_ATIME | DMU_AT_MTIME | DMU_AT_CTIME | DMU_AT_MODE | DMU_AT_SIZE |
                       DMU_AT_UID | DMU_AT_GID | DMU_AT_TYPE | DMU_AT_NLINK | DMU_AT_RDEV;
        vap->va_atime.tv_sec    = zp->zp_atime[0];
        vap->va_atime.tv_nsec   = 0;
        vap->va_mtime.tv_sec    = zp->zp_mtime[0];
        vap->va_mtime.tv_nsec   = 0;
        vap->va_ctime.tv_sec    = zp->zp_ctime[0];
        vap->va_ctime.tv_nsec   = 0;
        vap->va_mode     = zp->zp_mode & MODEMASK;;
        vap->va_size     = zp->zp_size;
        vap->va_uid      = zp->zp_uid;
        vap->va_gid      = zp->zp_gid;
        vap->va_type     = IFTOVT((mode_t)zp->zp_mode);
        vap->va_nlink    = zp->zp_links;
        vap->va_rdev     = zp->zp_rdev;

        vap->va_blksize = dn->dn_datablksz;
        vap->va_blkbits = dn->dn_datablkshift;
        /* in 512-bytes units*/
        vap->va_nblocks = DN_USED_BYTES(dn->dn_phys) >> SPA_MINBLOCKSHIFT;
        vap->va_mask |= DMU_AT_NBLOCKS | DMU_AT_BLKSIZE;
}

/*
 * Set the attributes of an object
 *
 * The transaction passed to this routine must have
 * udmu_tx_hold_bonus(tx, oid) called and then assigned
 * to a transaction group.
 */
void udmu_object_setattr(dmu_buf_t *db, dmu_tx_t *tx, vnattr_t *vap)
{
        znode_phys_t *zp = db->db_data;
        uint_t mask = vap->va_mask;

        /* Assert that the transaction has been assigned to a
           transaction group. */
        ASSERT(tx->tx_txg != 0);

        if (mask == 0) {
                return;
        }

        dmu_buf_will_dirty(db, tx);

        /*
         * Set each attribute requested.
         * We group settings according to the locks they need to acquire.
         *
         * Note: you cannot set ctime directly, although it will be
         * updated as a side-effect of calling this function.
         */

        if (mask & DMU_AT_MODE)
                zp->zp_mode = MAKEIMODE(vap->va_type, vap->va_mode);

        if (mask & DMU_AT_UID)
                zp->zp_uid = (uint64_t)vap->va_uid;

        if (mask & DMU_AT_GID)
                zp->zp_gid = (uint64_t)vap->va_gid;

        if (mask & DMU_AT_SIZE)
                zp->zp_size = vap->va_size;

        if (mask & DMU_AT_ATIME)
                ZFS_TIME_ENCODE(&vap->va_atime, zp->zp_atime);

        if (mask & DMU_AT_MTIME)
                ZFS_TIME_ENCODE(&vap->va_mtime, zp->zp_mtime);

        if (mask & DMU_AT_CTIME)
                ZFS_TIME_ENCODE(&vap->va_ctime, zp->zp_ctime);

        if (mask & DMU_AT_NLINK)
                zp->zp_links = vap->va_nlink;
}

/*
 * Punch/truncate an object
 *
 *      IN:     db      - dmu_buf of the object to free data in.
 *              off     - start of section to free.
 *              len     - length of section to free (0 => to EOF).
 *
 *      RETURN: 0 if success
 *              error code if failure
 *
 * The transaction passed to this routine must have
 * udmu_tx_hold_bonus(tx, oid) and
 * if off < size, udmu_tx_hold_free(tx, oid, off, len ? len : DMU_OBJECT_END)
 * called and then assigned to a transaction group.
 */
void udmu_object_punch(udmu_objset_t *uos, dmu_buf_t *db, dmu_tx_t *tx,
                      uint64_t off, uint64_t len)
{
        znode_phys_t *zp = db->db_data;
        uint64_t oid = db->db_object;
        uint64_t end = off + len;
        uint64_t size = zp->zp_size;

        /* Assert that the transaction has been assigned to a
           transaction group. */
        ASSERT(tx->tx_txg != 0);

        /*
         * Nothing to do if file already at desired length.
         */
        if (len == 0 && size == off) {
                return;
        }

        if (end > size || len == 0) {
                zp->zp_size = end;
        }

        if (off < size) {
                uint64_t rlen = len;

                if (len == 0)
                        rlen = -1;
                else if (end > size)
                        rlen = size - off;

                VERIFY(0 == dmu_free_range(uos->os, oid, off, rlen, tx));
        }
}

/*
 * Delete a DMU object
 *
 * The transaction passed to this routine must have
 * udmu_tx_hold_free(tx, oid, 0, DMU_OBJECT_END) called
 * and then assigned to a transaction group.
 *
 * This will release db and set it to NULL to prevent further dbuf releases.
 */
int udmu_object_delete(udmu_objset_t *uos, dmu_buf_t **db, dmu_tx_t *tx,
                       void *tag)
{
        int error;
        uint64_t oid = (*db)->db_object;

        /* Assert that the transaction has been assigned to a
           transaction group. */
        ASSERT(tx->tx_txg != 0);

        udmu_object_put_dmu_buf(*db, tag);
        *db = NULL;

        error = dmu_object_free(uos->os, oid, tx);

        return (error);
}

/*
 * Get the object id from dmu_buf_t
 */
uint64_t udmu_object_get_id(dmu_buf_t *db)
{
        ASSERT(db != NULL);
        return (db->db_object);
}

int udmu_object_is_zap(dmu_buf_t *_db)
{
        dmu_buf_impl_t *db = (dmu_buf_impl_t *) _db;
        if (db->db_dnode->dn_type == DMU_OT_DIRECTORY_CONTENTS)
                return 1;
        return 0;
}

/*
 * Release the reference to a dmu_buf object.
 */
void udmu_object_put_dmu_buf(dmu_buf_t *db, void *tag)
{
        ASSERT(tag);
        dmu_buf_rele(db, tag);
}

dmu_tx_t *udmu_tx_create(udmu_objset_t *uos)
{
        return (dmu_tx_create(uos->os));
}

void udmu_tx_hold_write(dmu_tx_t *tx, uint64_t object, uint64_t off, int len)
{
        dmu_tx_hold_write(tx, object, off, len);
}

void udmu_tx_hold_free(dmu_tx_t *tx, uint64_t object, uint64_t off,
                       uint64_t len)
{
        dmu_tx_hold_free(tx, object, off, len);
}

void udmu_tx_hold_zap(dmu_tx_t *tx, uint64_t object, int add, char *name)
{
        dmu_tx_hold_zap(tx, object, add, name);
}

void udmu_tx_hold_bonus(dmu_tx_t *tx, uint64_t object)
{
        dmu_tx_hold_bonus(tx, object);
}

void udmu_tx_abort(dmu_tx_t *tx)
{
        dmu_tx_abort(tx);
}

int udmu_tx_assign(dmu_tx_t *tx, uint64_t txg_how)
{
        return (dmu_tx_assign(tx, txg_how));
}

void udmu_tx_wait(dmu_tx_t *tx)
{
        dmu_tx_wait(tx);
}

void udmu_tx_commit(dmu_tx_t *tx)
{
        dmu_tx_commit(tx);
}

/* commit callback API */
void * udmu_tx_cb_create(size_t bytes)
{
        return NULL;
        //return dmu_tx_callback_data_create(bytes);
}

int udmu_tx_cb_add(dmu_tx_t *tx, void *func, void *data)
{
        return 0;
        //return dmu_tx_callback_commit_add(tx, func, data);
}

int udmu_tx_cb_destroy(void *data)
{
        return 0;
        //return dmu_tx_callback_data_destroy(data);
}

int udmu_indblk_overhead(dmu_buf_t *db, unsigned long *used,
                         unsigned long *overhead)
{
        dnode_t *dn = ((dmu_buf_impl_t *)db)->db_dnode;

        *overhead = (2 * (*used))/(1 << dn->dn_phys->dn_indblkshift);

        return 0;
}

int udmu_get_blocksize(dmu_buf_t *db, long *blksz)
{
        dnode_t *dn = ((dmu_buf_impl_t *)db)->db_dnode;

        *blksz = (dn->dn_datablksz);

        return 0;
}

uint64_t udmu_object_get_links(dmu_buf_t *db)
{
        znode_phys_t *zp = db->db_data;

        return zp->zp_links;
}

void udmu_object_links_inc(dmu_buf_t *db, dmu_tx_t *tx)
{
        znode_phys_t *zp = db->db_data;

        if(tx)
                dmu_buf_will_dirty(db, tx);
        zp->zp_links++;
}

void udmu_object_links_dec(dmu_buf_t *db, dmu_tx_t *tx)
{
        znode_phys_t *zp = db->db_data;

        ASSERT(zp->zp_links!=0);
        if(tx)
                dmu_buf_will_dirty(db, tx);
        zp->zp_links--;
}


int udmu_get_xattr(dmu_buf_t *db, void *val, int vallen, const char *name)
{
        /* XXX: not implemented yet */
        BUG_ON(1);
        return 0;
}

int udmu_set_xattr(dmu_buf_t *db, void *val, int vallen, const char *name,
                   dmu_tx_t *tx)
{
        /* XXX: not implemented yet */
        BUG_ON(1);
        return 0;
}

int udmu_del_xattr(dmu_buf_t *db, const char *name, dmu_tx_t *tx)
{
        /* XXX: not implemented yet */
        BUG_ON(1);
        return 0;
}

int udmu_list_xattr(dmu_buf_t *db, void *val, int vallen)
{
        /* XXX: not implemented yet */
        BUG_ON(1);
        return 0;
}

#endif
