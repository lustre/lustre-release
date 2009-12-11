/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/llog_osd.c - low level llog routines on top of OSD API
 *
 * Author: Alexey Zhuravlev <bzzz@sun.com>
 */

#define DEBUG_SUBSYSTEM S_LOG

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#include <obd.h>
#include <obd_class.h>
#include <lustre_log.h>
#include <obd_ost.h>
#include <libcfs/list.h>
#include <lustre_fsfilt.h>
#include <lustre_disk.h>
#include "llog_internal.h"
#include <lustre_fid.h>
#include <dt_object.h>

/*
 * - multi-chunks or big-declaration approach
 * - use unique sequence instead of llog sb tracking unique ids
 * - re-use existing environment
 * - named llog support (can be used for testing only at the present)
 * - llog_origin_connect() work with OSD API
 */


/*
 * on-disk structure describing llogs belonging to this specific device
 */
struct llog_superblock_ondisk {
        __u32   magic;
        __u32   next_id;
};

struct llog_name {
        struct llog_logid ln_logid;
        char              ln_name[128];
        struct list_head  ln_list;
};

/*
 * on-core representation of per-device llog system
 *
 */
struct llog_superblock {
        /* how many handle's reference this llog system */
        atomic_t                lsb_refcount;
        struct dt_device       *lsb_dev;
        struct dt_object       *lsb_obj;
        /* all initialized llog systems on this node linked by this */
        struct list_head        lsb_list;

        /* data used to generate new fids */
        spinlock_t              lsb_id_lock;
        __u64                   lsb_seq;
        __u64                   lsb_last_oid;

        /* named llogs support */
        struct list_head        lsb_named_list;
};

/* all initialized llog systems on this node linked on this */
static LIST_HEAD(lsb_list_head);
static DEFINE_MUTEX(lsb_list_mutex);

static void logid_to_fid(struct llog_logid *id, struct lu_fid *fid)
{
        fid->f_seq = id->lgl_ogr;
        fid->f_oid = id->lgl_oid;
        fid->f_ver = 0;
}

static void fid_to_logid(struct lu_fid *fid, struct llog_logid *id)
{
        id->lgl_ogr = fid->f_seq;
        id->lgl_oid = fid->f_oid;
}

static struct llog_superblock *llog_osd_get_sb(const struct lu_env *env,
                                               struct dt_device *dev,
                                               struct thandle *th)
{
        struct llog_superblock_ondisk  sbd;
        struct llog_superblock        *lsb;
        struct dt_object              *o;
        struct thandle                *_th;
        struct lu_fid                  fid;
        struct lu_attr                 attr;
        struct dt_object_format        dof;
        struct lu_buf                  lb;
        loff_t                         pos;
        int                            rc;

        mutex_lock(&lsb_list_mutex);
        list_for_each_entry(lsb, &lsb_list_head, lsb_list) {
                if (lsb->lsb_dev == dev) {
                        atomic_inc(&lsb->lsb_refcount);
                        GOTO(out, lsb);
                }
        }

        /* not found, then create */
        OBD_ALLOC_PTR(lsb);
        if (lsb == NULL)
                GOTO(out, lsb = ERR_PTR(-ENOMEM));

        atomic_set(&lsb->lsb_refcount, 1);
        spin_lock_init(&lsb->lsb_id_lock);
        lsb->lsb_dev = dev;
        CFS_INIT_LIST_HEAD(&lsb->lsb_named_list);
        list_add(&lsb->lsb_list, &lsb_list_head);

        /* initialize data allowing to generate new fids,
         * literally we need a sequece */
        lsb->lsb_seq = LU_LLOG_LUSTRE_SEQ;

        fid.f_seq = LU_LLOG_LUSTRE_SEQ;
        fid.f_oid = 1;
        fid.f_ver = 0;

        o = dt_locate(env, dev, &fid);
        LASSERT(!IS_ERR(o));

        pos = 0;
        lb.lb_vmalloc = 0;
        lb.lb_buf = &sbd;
        lb.lb_len = sizeof(sbd);

        if (!dt_object_exists(o)) {

                LASSERT(th == NULL);

                attr.la_valid = LA_TYPE | LA_MODE;
                attr.la_mode = S_IFREG | 0666;
                dof.dof_type = dt_mode_to_dft(S_IFREG);

                _th = dt_trans_create(env, dev);
                LASSERT(!IS_ERR(_th));

                rc = dt_declare_create(env, o, &attr, NULL, &dof, _th);
                LASSERT(rc == 0);

                rc = dt_declare_record_write(env, o, sizeof(sbd), 0, _th);
                LASSERT(rc == 0);

                rc = dt_trans_start(env, dev, _th);
                LASSERT(rc == 0);

                dt_write_lock(env, o, 0);
                LASSERT(!dt_object_exists(o));

                rc = dt_create(env, o, &attr, NULL, &dof, _th);
                LASSERT(rc == 0);
                LASSERT(dt_object_exists(o));
                dt_write_unlock(env, o);

                sbd.next_id = 2;

                rc = dt_record_write(env, o, &lb, &pos, _th);
                LASSERT(rc == 0);

                rc = dt_trans_stop(env, dev, _th);
                _th = NULL;
        } else {
                rc = dt_record_read(env, o, &lb, &pos);
                LASSERT(rc == 0);
        }

        lsb->lsb_last_oid = sbd.next_id;
        lsb->lsb_obj = o;

out:
        mutex_unlock(&lsb_list_mutex);

        return lsb;
}

static int llog_osd_lookup(struct llog_superblock *lsb, char *name,
                           struct llog_logid *logid)
{
        struct llog_name *ln;

        list_for_each_entry(ln, &lsb->lsb_named_list, ln_list) {
                if (!strcmp(name, ln->ln_name)) {
                        *logid = ln->ln_logid;
                        return 0;
                }
        }
        return -ENOENT;
}

static void llog_osd_add_name(struct llog_superblock *lsb, char *name,
                              struct llog_logid *logid)
{
        struct llog_name *ln;

        LASSERT(name);
        LASSERT(logid);

        OBD_ALLOC_PTR(ln);
        LASSERT(ln);

        strcpy(ln->ln_name, name);
        ln->ln_logid = *logid;

        list_add(&ln->ln_list, &lsb->lsb_named_list);
}

static void llog_osd_put_names(struct llog_superblock *lsb)
{
        struct llog_name *ln, *tmp;

        list_for_each_entry_safe(ln, tmp, &lsb->lsb_named_list, ln_list) {
                list_del(&ln->ln_list);
                OBD_FREE_PTR(ln);
        }
}

static void llog_osd_put_sb(const struct lu_env *env, struct llog_superblock *lsb)
{
        if (atomic_dec_and_test(&lsb->lsb_refcount)) {
                mutex_lock(&lsb_list_mutex);
                if (atomic_read(&lsb->lsb_refcount) == 0) {
                        if (lsb->lsb_obj)
                                lu_object_put(env, &lsb->lsb_obj->do_lu);
                        list_del(&lsb->lsb_list);
                        llog_osd_put_names(lsb);
                        OBD_FREE_PTR(lsb);
                }
                mutex_unlock(&lsb_list_mutex);
        }
}

static int llog_osd_generate_fid(const struct lu_env *env,
                                 struct llog_superblock *lsb,
                                 struct lu_fid *fid,
                                 struct thandle *th)
{
        struct llog_superblock_ondisk  sbd;
        struct thandle                *_th = NULL;
        struct dt_device              *dev;
        struct dt_object              *o;
        struct lu_buf                  lb;
        loff_t                         pos;
        int                            rc;
        ENTRY;

        spin_lock(&lsb->lsb_id_lock);
        fid->f_seq = lsb->lsb_seq;
        fid->f_oid = lsb->lsb_last_oid++;
        spin_unlock(&lsb->lsb_id_lock);
        fid->f_ver = 0;

        dev = lsb->lsb_dev;
        o = lsb->lsb_obj;

        /* update next id on a disk to make it unique over remounts */
        if (th == NULL) {
                _th = dt_trans_create(env, dev);
                LASSERT(!IS_ERR(_th));

                rc = dt_declare_record_write(env, o, sizeof(sbd), 0, _th);
                LASSERT(rc == 0);

                rc = dt_trans_start(env, dev, _th);
        } else
                _th = th;

        pos = 0;
        sbd.next_id = lsb->lsb_last_oid;
        lb.lb_vmalloc = 0;
        lb.lb_buf = &sbd;
        lb.lb_len = sizeof(sbd);

        rc = dt_record_write(env, o, &lb, &pos, _th);
        LASSERT(rc == 0);

        if (th == NULL) {
                LASSERT(_th);
                rc = dt_trans_stop(env, dev, _th);
                LASSERT(rc == 0);
        }

        RETURN(rc);
}

static int llog_osd_pad(const struct lu_env *env,
                        struct dt_object *o,
                        loff_t *off, int len, int index,
                        struct thandle *th)
{
        struct llog_rec_hdr  rec = { 0 };
        struct llog_rec_tail tail;
        struct lu_buf        lb;
        int                  rc;
        ENTRY;

        LASSERT(th);
        LASSERT(off);
        LASSERT(len >= LLOG_MIN_REC_SIZE && (len & 0x7) == 0);

        tail.lrt_len = rec.lrh_len = len;
        tail.lrt_index = rec.lrh_index = index;
        rec.lrh_type = LLOG_PAD_MAGIC;

        lb.lb_vmalloc = 0;
        lb.lb_buf = &rec;
        lb.lb_len = sizeof(rec);
        rc = dt_record_write(env, o, &lb, off, th);
        if (rc) {
                CERROR("error writing padding record: rc %d\n", rc);
                goto out;
        }

        lb.lb_buf = &tail;
        lb.lb_len = sizeof(tail);
        *off += len - sizeof(rec) - sizeof(tail);
        rc = dt_record_write(env, o, &lb, off, th);
        if (rc) {
                CERROR("error writing padding record: rc %d\n", rc);
                goto out;
        }

 out:
        RETURN(rc);
}

static int llog_osd_write_blob(const struct lu_env *env, struct dt_object *o,
                               struct llog_rec_hdr *rec, void *buf, loff_t off,
                               struct thandle *th)
{
        struct llog_rec_tail end;
        struct lu_buf        lb;
        int                  buflen = rec->lrh_len;
        int                  rc;
        ENTRY;

        LASSERT(env);
        LASSERT(o);

        if (buflen == 0)
                CWARN("0-length record\n");
      
        CDEBUG(D_OTHER, "write blob with type %x, buf %p/%u at off %u\n", 
               (unsigned) rec->lrh_type, buf, buflen, (unsigned) off);

        lb.lb_vmalloc = 0;

        if (!buf) {
                lb.lb_len = buflen;
                lb.lb_buf = rec;
                rc = dt_record_write(env, o, &lb, &off, th);
                if (rc) {
                        CERROR("error writing log record: rc %d\n", rc);
                        goto out;
                }
                GOTO(out, rc = 0);
        }

        /* the buf case */
        rec->lrh_len = sizeof(*rec) + buflen + sizeof(end);
        lb.lb_len = sizeof(*rec);
        lb.lb_buf = rec;
        rc = dt_record_write(env, o, &lb, &off, th);
        if (rc) {
                CERROR("error writing log hdr: rc %d\n", rc);
                goto out;
        }

        lb.lb_len = buflen;
        lb.lb_buf = buf;
        rc = dt_record_write(env, o, &lb, &off, th);
        if (rc) {
                CERROR("error writing log buffer: rc %d\n", rc);
                goto out;
        }

        end.lrt_len = rec->lrh_len;
        end.lrt_index = rec->lrh_index;
        lb.lb_len = sizeof(end);
        lb.lb_buf = &end;
        rc = dt_record_write(env, o, &lb, &off, th);
        if (rc) {
                CERROR("error writing log tail: rc %d\n", rc);
                goto out;
        }

        rc = 0;
 out:
        LASSERT(rc <= 0);

        RETURN(rc);
}

static int llog_osd_read_blob(const struct lu_env *env, struct dt_object *o,
                              void *buf, int size, loff_t off)
{
        struct lu_buf lb;
        int           rc;

        LASSERT(env);
        LASSERT(o);
        LASSERT(buf);

        lb.lb_vmalloc = 0;
        lb.lb_buf = buf;
        lb.lb_len = size;
        rc = dt_record_read(env, o, &lb, &off);

        RETURN(rc);
}

static int llog_osd_read_header(struct llog_handle *handle)
{
        struct obd_device       *obd;
        struct dt_object        *o;
        struct lu_attr           attr;
        struct dt_device        *dt;
        struct lu_env            env;
        int                      rc;
        ENTRY;

        LASSERT(sizeof(*handle->lgh_hdr) == LLOG_CHUNK_SIZE);

        obd = handle->lgh_ctxt->loc_exp->exp_obd;
        LASSERT(obd);
        dt = obd->obd_lvfs_ctxt.dt;
        LASSERT(dt);

        o = handle->lgh_obj;
        LASSERT(o);

        rc = lu_env_init(&env, dt->dd_lu_dev.ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                RETURN(rc);
        }

        rc = dt_attr_get(&env, o, &attr, NULL);
        LASSERT(rc == 0);
        LASSERT(attr.la_valid & LA_SIZE);

        if (attr.la_size == 0) {
                CDEBUG(D_HA, "not reading header from 0-byte log\n");
                GOTO(out, rc = LLOG_EEMPTY);
        }

        rc = llog_osd_read_blob(&env, o, handle->lgh_hdr,
                                 LLOG_CHUNK_SIZE, 0);
        if (rc) {
                CERROR("error reading log header from "DFID"\n",
                       PFID(lu_object_fid(&o->do_lu)));
        } else {
                struct llog_rec_hdr *llh_hdr = &handle->lgh_hdr->llh_hdr;

                if (LLOG_REC_HDR_NEEDS_SWABBING(llh_hdr))
                        lustre_swab_llog_hdr(handle->lgh_hdr);

                if (llh_hdr->lrh_type != LLOG_HDR_MAGIC) {
                        CERROR("bad log %.*s header magic: %#x (expected %#x)\n",
                               handle->lgh_file->f_dentry->d_name.len,
                               handle->lgh_file->f_dentry->d_name.name,
                               llh_hdr->lrh_type, LLOG_HDR_MAGIC);
                        rc = -EIO;
                } else if (llh_hdr->lrh_len != LLOG_CHUNK_SIZE) {
                        CERROR("incorrectly sized log %.*s header: %#x "
                               "(expected %#x)\n",
                               handle->lgh_file->f_dentry->d_name.len,
                               handle->lgh_file->f_dentry->d_name.name,
                               llh_hdr->lrh_len, LLOG_CHUNK_SIZE);
                        CERROR("you may need to re-run lconf --write_conf.\n");
                        rc = -EIO;
                }
        }

        handle->lgh_last_idx = handle->lgh_hdr->llh_tail.lrt_index;

out:
        lu_env_fini(&env);

        RETURN(rc);
}

static int llog_osd_declare_write_rec_2(struct llog_handle *loghandle,
                                        struct llog_rec_hdr *rec,
                                        int idx, struct thandle *th)
{
        struct dt_object *o;
        struct lu_attr    attr;
        struct lu_env     env;
        loff_t            pos;
        int               rc;
        ENTRY;

        LASSERT(th);
        /* XXX: LASSERT(rec); */
        LASSERT(loghandle);
        
        o = loghandle->lgh_obj;
        LASSERT(o);

        rc = lu_env_init(&env, o->do_lu.lo_dev->ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                RETURN(rc);
        }

        if (dt_object_exists(o)) {
                rc = dt_attr_get(&env, o, &attr, BYPASS_CAPA);
                if (rc)
                        GOTO(out, rc);
                LASSERT(attr.la_valid & LA_SIZE);
                pos = attr.la_size;
        } else
                pos = 0;

        /* XXX: implement declared window or multi-chunks approach */
        rc = dt_declare_record_write(&env, o, 1024 * 1024, pos, th);
        if (rc)
                GOTO(out, rc);

        /* each time we update header */
        rc = dt_declare_record_write(&env, o,
                                     sizeof(struct llog_rec_hdr), 0, th);

out:
        lu_env_fini(&env);

        RETURN(rc);
}

/* returns negative in on error; 0 if success && reccookie == 0; 1 otherwise */
/* appends if idx == -1, otherwise overwrites record idx. */
static int llog_osd_write_rec_2(struct llog_handle *loghandle,
                                struct llog_rec_hdr *rec,
                                struct llog_cookie *reccookie, int cookiecount,
                                void *buf, int idx, struct thandle *th)
{
        struct llog_log_hdr       *llh;
        int                        reclen = rec->lrh_len;
        int                        index, rc;
        struct llog_rec_tail      *lrt;
        struct dt_object          *o;
        struct lu_env              env;
        size_t                     left;
        struct lu_attr             attr;
        loff_t                     off;
        ENTRY;

        llh = loghandle->lgh_hdr;
        LASSERT(llh);
        o = loghandle->lgh_obj;
        LASSERT(o);
        LASSERT(th);

        CDEBUG(D_OTHER, "new record %x to "DFID"\n",
               (unsigned) rec->lrh_type, PFID(lu_object_fid(&o->do_lu)));

        rc = lu_env_init(&env, o->do_lu.lo_dev->ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                GOTO(out, rc);
        }

        /* record length should not bigger than LLOG_CHUNK_SIZE */
        if (buf)
                rc = (reclen > LLOG_CHUNK_SIZE - sizeof(struct llog_rec_hdr) -
                      sizeof(struct llog_rec_tail)) ? -E2BIG : 0;
        else
                rc = (reclen > LLOG_CHUNK_SIZE) ? -E2BIG : 0;
        if (rc)
                GOTO(out, rc);

        rc = dt_attr_get(&env, o, &attr, NULL);
        LASSERT(rc == 0);
        LASSERT(attr.la_valid & LA_SIZE);
        off = attr.la_size;

        if (buf)
                /* write_blob adds header and tail to lrh_len. */
                reclen = sizeof(*rec) + rec->lrh_len +
                         sizeof(struct llog_rec_tail);

        if (idx != -1) {
                loff_t saved_offset;
                /* no header: only allowed to insert record 1 */
                if (idx != 1 && !attr.la_size)
                        LBUG();

                if (idx && llh->llh_size && llh->llh_size != rec->lrh_len)
                        GOTO(out, rc = -EINVAL);

                if (!ext2_test_bit(idx, llh->llh_bitmap))
                        CERROR("Modify unset record %u\n", idx);
                if (idx != rec->lrh_index)
                        CERROR("Index mismatch %d %u\n", idx, rec->lrh_index);

                rc = llog_osd_write_blob(&env, o, &llh->llh_hdr, NULL, 0, th);
                /* we are done if we only write the header or on error */
                if (rc || idx == 0)
                        GOTO(out, rc);

                /* Assumes constant lrh_len */
                saved_offset = sizeof(*llh) + (idx - 1) * reclen;

                if (buf) {
                        //struct llog_rec_hdr check;

                        /* We assume that caller has set lgh_cur_* */
                        saved_offset = loghandle->lgh_cur_offset;
                        CDEBUG(D_OTHER,
                               "modify record "LPX64": idx:%d/%u/%d, len:%u "
                               "offset %llu\n",
                               loghandle->lgh_id.lgl_oid, idx, rec->lrh_index,
                               loghandle->lgh_cur_idx, rec->lrh_len,
                               (long long)(saved_offset - sizeof(*llh)));
                        if (rec->lrh_index != loghandle->lgh_cur_idx) {
                                CERROR("modify idx mismatch %u/%d\n",
                                       idx, loghandle->lgh_cur_idx);
                                GOTO(out, rc = -EFAULT);
                        }
#if 0  /* FIXME remove this safety check at some point */
                        /* Verify that the record we're modifying is the
                           right one. */
                        rc = llog_osd_read_blob(&env, o, &check, sizeof(check),
                                                saved_offset);
                        if (check.lrh_index != idx || check.lrh_len != reclen) {
                                CERROR("Bad modify idx %u/%u size %u/%u (%d)\n",
                                       idx, check.lrh_index, reclen,
                                       check.lrh_len, rc);
                                RETURN(-EFAULT);
                        }
#endif
                }

                rc = llog_osd_write_blob(&env, o, rec, buf, saved_offset, th);
                if (rc == 0 && reccookie) {
                        reccookie->lgc_lgl = loghandle->lgh_id;
                        reccookie->lgc_index = idx;
                        rc = 1;
                }
                GOTO(out, rc);
        }

        /* Make sure that records don't cross a chunk boundary, so we can
         * process them page-at-a-time if needed.  If it will cross a chunk
         * boundary, write in a fake (but referenced) entry to pad the chunk.
         *
         * We know that llog_current_log() will return a loghandle that is
         * big enough to hold reclen, so all we care about is padding here.
         */
        left = LLOG_CHUNK_SIZE - (off & (LLOG_CHUNK_SIZE - 1));

        /* NOTE: padding is a record, but no bit is set */
        if (left != 0 && left != reclen &&
            left < (reclen + LLOG_MIN_REC_SIZE)) {
                 index = loghandle->lgh_last_idx + 1;
                 rc = llog_osd_pad(&env, o, &off, left, index, th);
                 if (rc)
                        GOTO(out, rc);
                 loghandle->lgh_last_idx++; /*for pad rec*/
         }
         /* if it's the last idx in log file, then return -ENOSPC */
         if (loghandle->lgh_last_idx >= LLOG_BITMAP_SIZE(llh) - 1)
                 GOTO(out, rc = -ENOSPC);
        loghandle->lgh_last_idx++;
        index = loghandle->lgh_last_idx;
        LASSERT(index < LLOG_BITMAP_SIZE(llh));
        rec->lrh_index = index;
        if (buf == NULL) {
                lrt = (struct llog_rec_tail *)
                        ((char *)rec + rec->lrh_len - sizeof(*lrt));
                lrt->lrt_len = rec->lrh_len;
                lrt->lrt_index = rec->lrh_index;
        }
        /*The caller should make sure only 1 process access the lgh_last_idx,
         *Otherwise it might hit the assert.*/
        LASSERT(index < LLOG_BITMAP_SIZE(llh));
        if (ext2_set_bit(index, llh->llh_bitmap)) {
                CERROR("argh, index %u already set in log bitmap?\n", index);
                LBUG(); /* should never happen */
        }
        llh->llh_count++;
        llh->llh_tail.lrt_index = index;

        rc = llog_osd_write_blob(&env, o, &llh->llh_hdr, NULL, 0, th);
        if (rc)
                GOTO(out, rc);

        rc = dt_attr_get(&env, o, &attr, NULL);
        LASSERT(rc == 0);
        LASSERT(attr.la_valid & LA_SIZE);
        off = attr.la_size;

        rc = llog_osd_write_blob(&env, o, rec, buf, off, th);
        if (rc)
                GOTO(out, rc);

        CDEBUG(D_RPCTRACE, "added record "LPX64": idx: %u, %u \n",
               loghandle->lgh_id.lgl_oid, index, rec->lrh_len);
        if (rc == 0 && reccookie) {
                reccookie->lgc_lgl = loghandle->lgh_id;
                reccookie->lgc_index = index;
                if ((rec->lrh_type == MDS_UNLINK_REC) ||
                                (rec->lrh_type == MDS_SETATTR_REC))
                        reccookie->lgc_subsys = LLOG_MDS_OST_ORIG_CTXT;
                else if (rec->lrh_type == OST_SZ_REC)
                        reccookie->lgc_subsys = LLOG_SIZE_ORIG_CTXT;
                else if (rec->lrh_type == OST_RAID1_REC)
                        reccookie->lgc_subsys = LLOG_RD1_ORIG_CTXT;
                else
                        reccookie->lgc_subsys = -1;
                rc = 1;
        }
        if (rc == 0 && rec->lrh_type == LLOG_GEN_REC)
                rc = 1;
out: 

        lu_env_fini(&env);

        RETURN(rc);
}

int llog_osd_record_read(const struct lu_env *env, struct dt_object *dt,
                         void *buf, int len, loff_t *pos)
{
        struct lu_buf lb;
        int rc;

        lb.lb_buf = &buf;
        lb.lb_len = len;
        lb.lb_vmalloc = 0;

        rc = dt->do_body_ops->dbo_read(env, dt, buf, pos, BYPASS_CAPA);

        return (rc >= 0 ? 0 : rc);
}
/* We can skip reading at least as many log blocks as the number of
* minimum sized log records we are skipping.  If it turns out
* that we are not far enough along the log (because the
* actual records are larger than minimum size) we just skip
* some more records. */

static void llog_skip_over(__u64 *off, int curr, int goal)
{
        if (goal <= curr)
                return;
        *off = (*off + (goal-curr-1) * LLOG_MIN_REC_SIZE) &
                ~(LLOG_CHUNK_SIZE - 1);
}


/* sets:
 *  - cur_offset to the furthest point read in the log file
 *  - cur_idx to the log index preceeding cur_offset
 * returns -EIO/-EINVAL on error
 */
static int llog_osd_next_block(struct llog_handle *loghandle, int *cur_idx,
                                int next_idx, __u64 *cur_offset, void *buf,
                                int len)
{
        struct dt_object *o;
        struct dt_device *dt;
        struct lu_env     env;
        struct lu_attr    attr;
        int               rc;
        ENTRY;

        if (len == 0 || len & (LLOG_CHUNK_SIZE - 1))
                RETURN(-EINVAL);

        CDEBUG(D_OTHER, "looking for log index %u (cur idx %u off "LPU64")\n",
               next_idx, *cur_idx, *cur_offset);

        LASSERT(loghandle);
        LASSERT(loghandle->lgh_ctxt);
        dt = loghandle->lgh_ctxt->loc_exp->exp_obd->obd_lvfs_ctxt.dt;
        LASSERT(dt);

        o = loghandle->lgh_obj;
        LASSERT(o);
        LASSERT(dt_object_exists(o));

        rc = lu_env_init(&env, o->do_lu.lo_dev->ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                RETURN(rc);
        }

        rc = dt_attr_get(&env, o, &attr, BYPASS_CAPA);
        if (rc)
                GOTO(out, rc);

        while (*cur_offset < attr.la_size) {
                struct llog_rec_hdr *rec;
                struct llog_rec_tail *tail;
                loff_t ppos;

                llog_skip_over(cur_offset, *cur_idx, next_idx);

                ppos = *cur_offset;
                
                rc = llog_osd_record_read(&env, o, &buf, len, &ppos);
                if (rc) {
                        CERROR("Cant read llog block at log id "LPU64
                               "/%u offset "LPU64"\n",
                               loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen,
                               *cur_offset);
                        GOTO(out, rc);
                }

                /* put number of bytes read into rc to make code simpler */
                rc = ppos - *cur_offset;
                *cur_offset = ppos;

                if (rc < len) {
                        /* signal the end of the valid buffer to llog_process */
                        memset(buf + rc, 0, len - rc);
                }

                if (rc == 0) /* end of file, nothing to do */
                        GOTO(out, rc);

                if (rc < sizeof(*tail)) {
                        CERROR("Invalid llog block at log id "LPU64"/%u offset "
                               LPU64"\n", loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen, *cur_offset);
                        GOTO(out, rc = -EINVAL);
                }

                rec = buf;
                tail = (struct llog_rec_tail *)((char *)buf + rc -
                                                sizeof(struct llog_rec_tail));

                if (LLOG_REC_HDR_NEEDS_SWABBING(rec)) {
                        lustre_swab_llog_rec(rec, tail);
                }

                *cur_idx = tail->lrt_index;

                /* this shouldn't happen */
                if (tail->lrt_index == 0) {
                        CERROR("Invalid llog tail at log id "LPU64"/%u offset "
                               LPU64"\n", loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen, *cur_offset);
                        GOTO(out, rc = -EINVAL);
                }
                if (tail->lrt_index < next_idx)
                        continue;

                /* sanity check that the start of the new buffer is no farther
                 * than the record that we wanted.  This shouldn't happen. */
                if (rec->lrh_index > next_idx) {
                        CERROR("missed desired record? %u > %u\n",
                               rec->lrh_index, next_idx);
                        GOTO(out, rc = -ENOENT);
                }
                GOTO(out, rc = 0);
        }
        GOTO(out, rc = -EIO);

out:
        lu_env_fini(&env);
        RETURN(rc);
}

static int llog_osd_prev_block(struct llog_handle *loghandle,
                                int prev_idx, void *buf, int len)
{
        struct dt_object *o;
        struct dt_device *dt;
        struct lu_env     env;
        struct lu_attr    attr;
        __u64             cur_offset;
        int               rc;
        ENTRY;

        if (len == 0 || len & (LLOG_CHUNK_SIZE - 1))
                RETURN(-EINVAL);

        CDEBUG(D_OTHER, "looking for log index %u\n", prev_idx);

        LASSERT(loghandle);
        LASSERT(loghandle->lgh_ctxt);
        dt = loghandle->lgh_ctxt->loc_exp->exp_obd->obd_lvfs_ctxt.dt;
        LASSERT(dt);

        o = loghandle->lgh_obj;
        LASSERT(o);
        LASSERT(dt_object_exists(o));

        rc = lu_env_init(&env, o->do_lu.lo_dev->ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                RETURN(rc);
        }

        cur_offset = LLOG_CHUNK_SIZE;
        llog_skip_over(&cur_offset, 0, prev_idx);

        rc = dt_attr_get(&env, o, &attr, BYPASS_CAPA);
        if (rc)
                GOTO(out, rc);

        while (cur_offset < attr.la_size) {
                struct llog_rec_hdr *rec;
                struct llog_rec_tail *tail;
                loff_t ppos;

                ppos = cur_offset;

                rc = llog_osd_record_read(&env, o, &buf, len, &ppos);
                if (rc) {
                        CERROR("Cant read llog block at log id "LPU64
                               "/%u offset "LPU64"\n",
                               loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen,
                               cur_offset);
                        GOTO(out, rc);
                }

                /* put number of bytes read into rc to make code simpler */
                rc = ppos - cur_offset;
                cur_offset = ppos;

                if (rc == 0) /* end of file, nothing to do */
                        GOTO(out, rc);

                if (rc < sizeof(*tail)) {
                        CERROR("Invalid llog block at log id "LPU64"/%u offset "
                               LPU64"\n", loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen, cur_offset);
                        GOTO(out, rc = -EINVAL);
                }

                tail = buf + rc - sizeof(struct llog_rec_tail);

                /* this shouldn't happen */
                if (tail->lrt_index == 0) {
                        CERROR("Invalid llog tail at log id "LPU64"/%u offset "
                               LPU64"\n", loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen, cur_offset);
                        GOTO(out, rc = -EINVAL);
                }
                if (le32_to_cpu(tail->lrt_index) < prev_idx)
                        continue;

                /* sanity check that the start of the new buffer is no farther
                 * than the record that we wanted.  This shouldn't happen. */
                rec = buf;
                if (le32_to_cpu(rec->lrh_index) > prev_idx) {
                        CERROR("missed desired record? %u > %u\n",
                               le32_to_cpu(rec->lrh_index), prev_idx);
                        GOTO(out, rc = -ENOENT);
                }
                GOTO(out, rc = 0);
        }
        GOTO(out, rc = -EIO);

out:
        lu_env_fini(&env);
        RETURN(rc);
}

/*
 *
 */
static int llog_osd_open_2(struct llog_ctxt *ctxt, struct llog_handle **res,
                           struct llog_logid *logid, char *name)
{
        struct llog_handle        *handle = NULL;
        struct dt_object          *o;
        struct obd_device         *obd;
        struct dt_device          *dt;
        struct llog_superblock    *lsb = NULL;
        struct lu_env              env;
        struct lu_fid              fid;
        struct llog_logid          tlogid;
        int                        rc;
        ENTRY;

        LASSERT(ctxt);
        LASSERT(ctxt->loc_exp);
        obd = ctxt->loc_exp->exp_obd;
        LASSERT(obd);
        dt = obd->obd_lvfs_ctxt.dt;
        LASSERT(dt);

        rc = lu_env_init(&env, dt->dd_lu_dev.ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                RETURN(rc);
        }

        lsb = llog_osd_get_sb(&env, dt, NULL);
        LASSERT(lsb);

        handle = llog_alloc_handle();
        if (handle == NULL)
                GOTO(out, rc = -ENOMEM);
        *res = handle;

        if (logid != NULL) {
                logid_to_fid(logid, &fid);

                o = dt_locate(&env, dt, &fid);
                if (IS_ERR(o))
                        GOTO(out, rc = PTR_ERR(o));

                if (!dt_object_exists(o)) {
                        lu_object_put(&env, &o->do_lu);
                        GOTO(out, -ENOENT);
                }
                handle->lgh_id = *logid;

        } else if (name) {
                /* XXX */
                logid = &tlogid;

                rc = llog_osd_lookup(lsb, name, logid);
                if (rc == 0) {
                        logid_to_fid(logid, &fid);
                } else {
                        /* generate fid for new llog */
                        llog_osd_generate_fid(&env, lsb, &fid, NULL);
                        fid_to_logid(&fid, logid);
                        llog_osd_add_name(lsb, name, logid);
                        rc = 0;
                }

                o = dt_locate(&env, dt, &fid);
                if (IS_ERR(o))
                        GOTO(out, rc = PTR_ERR(o));
                
                fid_to_logid(&fid, &handle->lgh_id);
        } else {

                /* generate fid for new llog */
                llog_osd_generate_fid(&env, lsb, &fid, NULL);
                
                o = dt_locate(&env, dt, &fid);
                if (IS_ERR(o))
                        GOTO(out, rc = PTR_ERR(o));
                LASSERT(!dt_object_exists(o));

                fid_to_logid(&fid, &handle->lgh_id);
        }
        
        if (rc == 0) {
                handle->lgh_obj = o;
                handle->lgh_ctxt = ctxt;
                atomic_inc(&lsb->lsb_refcount);
                handle->private_data = lsb;
        } else {
                if (handle)
                        llog_free_handle(handle);
        }

        if (lsb)
                llog_osd_put_sb(&env, lsb);
       
out:
        lu_env_fini(&env);

        RETURN(rc);
}

static int llog_osd_exist_2(struct llog_handle *handle)
{
        LASSERT(handle->lgh_obj);
        if (dt_object_exists(handle->lgh_obj))
                return 1;
        else
                return 0;
}

static int llog_osd_declare_create_2(struct llog_handle *res,
                                     struct thandle *th)
{
        struct dt_object_format dof;
        struct lu_attr          attr;
        struct lu_env           env;
        struct dt_object       *o;
        int                     rc;
        ENTRY;
        
        LASSERT(res->lgh_obj);
        LASSERT(th);

        /* object can be created by another thread */
        o = res->lgh_obj;
        if (dt_object_exists(o))
                RETURN(0);

        rc = lu_env_init(&env, o->do_lu.lo_dev->ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                RETURN(rc);
        }

        attr.la_valid = LA_TYPE | LA_MODE;
        attr.la_mode = S_IFREG | 0666;
        dof.dof_type = dt_mode_to_dft(S_IFREG);

        rc = dt_declare_create(&env, o, &attr, NULL, &dof, th);
        LASSERT(rc == 0);

        rc = dt_declare_record_write(&env, o, LLOG_CHUNK_SIZE, 0, th);
        LASSERT(rc == 0);

        lu_env_fini(&env);

        RETURN(rc);
}

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
static int llog_osd_create_2(struct llog_handle *res, struct thandle *th)
{
        struct dt_object          *o;
        struct lu_env              env;
        struct lu_attr             attr;
        struct dt_object_format    dof;
        int                        rc = 0;
        ENTRY;

        o = res->lgh_obj;
        LASSERT(o);

        /* llog can be already created */
        if (dt_object_exists(o))
                RETURN(-EEXIST);

        rc = lu_env_init(&env, o->do_lu.lo_dev->ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                RETURN(rc);
        }

        dt_write_lock(&env, o, 0);
        if (!dt_object_exists(o)) {
                attr.la_valid = LA_TYPE | LA_MODE;
                attr.la_mode = S_IFREG | 0666;
                dof.dof_type = dt_mode_to_dft(S_IFREG);

                rc = dt_create(&env, o, &attr, NULL, &dof, th);
                LASSERT(rc == 0);
                LASSERT(dt_object_exists(o));
        } else
                rc = -EEXIST;
        dt_write_unlock(&env, o);

        lu_env_fini(&env);

        RETURN(rc);
}

static int llog_osd_close(struct llog_handle *handle)
{
        struct dt_object  *o;
        struct obd_device *obd;
        struct llog_ctxt  *ctxt;
        struct dt_device  *dt;
        int                rc;
        struct lu_env      env;
        struct llog_superblock *lsb;

        ctxt = handle->lgh_ctxt;
        LASSERT(ctxt);
        LASSERT(ctxt->loc_exp);

        obd = ctxt->loc_exp->exp_obd;
        LASSERT(obd);

        dt = obd->obd_lvfs_ctxt.dt;
        LASSERT(dt);

        rc = lu_env_init(&env, dt->dd_lu_dev.ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                GOTO(out, rc);
        }
        o = handle->lgh_obj;
        LASSERT(o);

        lsb = handle->private_data;
        LASSERT(lsb);
        llog_osd_put_sb(&env, lsb);

        lu_object_put(&env, &o->do_lu);

out:
        lu_env_fini(&env);

        RETURN(rc);
}

static int llog_osd_destroy(struct llog_handle *loghandle)
{
        struct llog_superblock *lsb;
        struct lu_env      env;
        struct dt_object  *o;
        struct dt_device  *d;
        struct thandle    *th;
        int                rc;
        ENTRY;

        o = loghandle->lgh_obj;
        LASSERT(o);

        d = loghandle->lgh_ctxt->loc_exp->exp_obd->obd_lvfs_ctxt.dt;
        LASSERT(d);

        rc = lu_env_init(&env, o->do_lu.lo_dev->ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                RETURN(rc);
        }

        th = dt_trans_create(&env, d);
        if (IS_ERR(th))
                GOTO(out, rc = PTR_ERR(th));

        dt_declare_ref_del(&env, o, th);

        rc = dt_trans_start(&env, d, th);
        if (rc == 0) {
                dt_write_lock(&env, o, 0);
                if (dt_object_exists(o))
                        dt_ref_del(&env, o, th);
                dt_write_unlock(&env, o);
        }

        rc = dt_trans_stop(&env, d, th);

out:
        lsb = loghandle->private_data;
        LASSERT(lsb);
        llog_osd_put_sb(&env, lsb);

        lu_object_put(&env, &o->do_lu);

        lu_env_fini(&env);

        RETURN(rc);
}

static int llog_osd_create(struct llog_ctxt *ctxt, struct llog_handle **res,
                           struct llog_logid *logid, char *name)
{
        struct obd_device *obd;
        struct dt_device  *dt;
        struct thandle    *th;
        struct lu_env      env;
        int rc;
        ENTRY;

        LASSERT(res);
        LASSERT(ctxt);
        LASSERT(ctxt->loc_exp);
        obd = ctxt->loc_exp->exp_obd;
        LASSERT(obd);
        dt = obd->obd_lvfs_ctxt.dt;
        LASSERT(dt);

        rc = lu_env_init(&env, dt->dd_lu_dev.ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                RETURN(rc);
        }

        rc = llog_osd_open_2(ctxt, res, logid, name);
        if (rc)
                GOTO(out, rc);

        /* XXX: no need to create each time */
        th = dt_trans_create(&env, dt);
        if (IS_ERR(th))
                GOTO(out, rc = PTR_ERR(th));

        rc = llog_osd_declare_create_2(*res, th);
        if (rc == 0) {
                rc = dt_trans_start(&env, dt, th);
                if (rc == 0)
                        rc = llog_osd_create_2(*res, th);
                if (rc == -EEXIST)
                        rc = 0;
        }

        dt_trans_stop(&env, dt, th);

out:
        lu_env_fini(&env);
        RETURN(rc);
}

static int llog_osd_write_rec(struct llog_handle *loghandle,
                              struct llog_rec_hdr *rec,
                              struct llog_cookie *reccookie, int cookiecount,
                              void *buf, int idx)
{
        struct dt_device  *dt;
        struct thandle    *th;
        struct lu_env      env;
        int rc;
        ENTRY;

        LASSERT(loghandle);
        LASSERT(loghandle->lgh_ctxt);
        dt = loghandle->lgh_ctxt->loc_exp->exp_obd->obd_lvfs_ctxt.dt;
        LASSERT(dt);

        rc = lu_env_init(&env, dt->dd_lu_dev.ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                RETURN(rc);
        }

        /* XXX: no need to create each time */
        th = dt_trans_create(&env, dt);
        if (IS_ERR(th))
                GOTO(out, rc = PTR_ERR(th));

        if (!llog_exist_2(loghandle)) {
                rc = llog_osd_declare_create_2(loghandle, th);
                if (rc)
                        GOTO(out_trans, rc);
        }

        rc = llog_osd_declare_write_rec_2(loghandle, rec, idx, th);
        if (rc)
                GOTO(out_trans, rc);

        rc = dt_trans_start(&env, dt, th);
        if (rc)
                GOTO(out_trans, rc);

        if (!llog_exist_2(loghandle)) {
                rc = llog_osd_create_2(loghandle, th);
                if (rc)
                        GOTO(out_trans, rc);
        }

        rc = llog_osd_write_rec_2(loghandle, rec, reccookie, cookiecount,
                                  buf, idx, th);

out_trans:
        dt_trans_stop(&env, dt, th);

out:
        lu_env_fini(&env);
        RETURN(rc);
}


struct llog_operations llog_osd_ops = {
        lop_write_rec:           llog_osd_write_rec,
        lop_next_block:          llog_osd_next_block,
        lop_prev_block:          llog_osd_prev_block,
        lop_read_header:         llog_osd_read_header,
        lop_create:              llog_osd_create,
        lop_destroy:             llog_osd_destroy,
        lop_close:               llog_osd_close,

        lop_open_2:              llog_osd_open_2,
        lop_exist_2:             llog_osd_exist_2,
        lop_declare_create_2:    llog_osd_declare_create_2,
        lop_create_2:            llog_osd_create_2,
        lop_declare_write_rec_2: llog_osd_declare_write_rec_2,
        lop_write_rec_2:         llog_osd_write_rec_2,
};

EXPORT_SYMBOL(llog_osd_ops);

/* reads the catalog list */
int llog_get_cat_list(struct obd_device *disk_obd,
                      char *name, int idx, int count, struct llog_catid *idarray)
{
        int               size = sizeof(*idarray) * count;
        loff_t            off = idx *  sizeof(*idarray);
        struct dt_object *o = NULL;
        struct dt_device *d;
        struct thandle   *th;
        struct lu_env     env;
        struct lu_fid     fid;
        struct lu_attr    attr;
        struct lu_buf     lb;
        int               rc;
        ENTRY;

        if (!count)
                RETURN(0);
        
        d = disk_obd->obd_lvfs_ctxt.dt;
        LASSERT(d);

        rc = lu_env_init(&env, d->dd_lu_dev.ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                RETURN(rc);
        }

        lu_local_obj_fid(&fid, LLOG_CATALOGS_OID);
        o = dt_locate(&env, d, &fid);
        if (IS_ERR(o))
                GOTO(out, rc = PTR_ERR(o));

        if (!dt_object_exists(o)) {
                struct dt_object_format  dof;

                memset(&attr, 0, sizeof(attr));
                attr.la_valid = LA_MODE;
                attr.la_mode = S_IFREG | 0666;
                dof.dof_type = dt_mode_to_dft(S_IFREG);

                th = dt_trans_create(&env, d);
                if (IS_ERR(th))
                        GOTO(out, rc = PTR_ERR(th));

                rc = dt_declare_create(&env, o, &attr, NULL, &dof, th);
                if (rc)
                        GOTO(out_trans, rc);

                rc = dt_trans_start(&env, d, th);
                if (rc)
                        GOTO(out_trans, rc);

                dt_write_lock(&env, o, 0);
                LASSERT(!dt_object_exists(o));

                rc = dt_create(&env, o, &attr, NULL, &dof, th);

                dt_write_unlock(&env, o);

out_trans:
                dt_trans_stop(&env, d, th);
                if (rc)
                        GOTO(out, rc);
        }

        rc = dt_attr_get(&env, o, &attr, BYPASS_CAPA);
        if (rc)
                GOTO(out, rc);

        if (!S_ISREG(attr.la_mode)) {
                CERROR("CATALOGS is not a regular file!: mode = %o\n",
                       attr.la_mode);
                GOTO(out, rc = -ENOENT);
        }

        CDEBUG(D_CONFIG, "cat list: disk size=%d, read=%d\n",
               (int) attr.la_size, size);

        /* read for new ost index or for empty file */
        memset(idarray, 0, size);
        if (attr.la_size < off + size)
                GOTO(out, rc = 0);

        lb.lb_vmalloc = 0;
        lb.lb_buf = idarray;
        lb.lb_len = size;
        rc = dt_record_read(&env, o, &lb, &off);
        if (rc) {
                CERROR("error reading CATALOGS: rc %d\n", rc);
                GOTO(out, rc);
        }

        EXIT;
 out:
        if (o && !IS_ERR(o))
                lu_object_put(&env, &o->do_lu);
        lu_env_fini(&env);

        RETURN(rc);
}
EXPORT_SYMBOL(llog_get_cat_list);

/* writes the cat list */
int llog_put_cat_list(struct obd_device *disk_obd,
                      char *name, int idx, int count, struct llog_catid *idarray)
{
        int               size = sizeof(*idarray) * count;
        loff_t            off = idx * sizeof(*idarray);
        struct dt_object *o = NULL;
        struct dt_device *d;
        struct thandle   *th;
        struct lu_env     env;
        struct lu_fid     fid;
        struct lu_attr    attr;
        struct lu_buf     lb;
        int               rc;

        if (!count)
                RETURN(0);

        d = disk_obd->obd_lvfs_ctxt.dt;
        LASSERT(d);

        rc = lu_env_init(&env, d->dd_lu_dev.ld_type->ldt_ctx_tags);
        if (rc) {
                CERROR("can't initialize env: %d\n", rc);
                RETURN(rc);
        }

        lu_local_obj_fid(&fid, LLOG_CATALOGS_OID);
        o = dt_locate(&env, d, &fid);
        if (IS_ERR(o))
                GOTO(out, rc = PTR_ERR(o));

        if (!dt_object_exists(o))
                GOTO(out, rc = -ENOENT);

        rc = dt_attr_get(&env, o, &attr, BYPASS_CAPA);
        if (rc)
                GOTO(out, rc);

        if (!S_ISREG(attr.la_mode)) {
                CERROR("CATALOGS is not a regular file!: mode = %o\n",
                       attr.la_mode);
                GOTO(out, rc = -ENOENT);
        }

        th = dt_trans_create(&env, d);
        if (IS_ERR(th))
                GOTO(out, rc = PTR_ERR(th));

        rc = dt_declare_record_write(&env, o, size, off, th);
        if (rc)
                GOTO(out, rc);

        rc = dt_trans_start(&env, d, th);
        if (rc)
                GOTO(out_trans, rc);

        lb.lb_vmalloc = 0;
        lb.lb_buf = idarray;
        lb.lb_len = size;

        rc = dt_record_write(&env, o, &lb, &off, th);
        if (rc)
                CDEBUG(D_INODE,"error writeing CATALOGS: %d\n", rc);

out_trans:
        dt_trans_stop(&env, d, th);
        
out:
        if (o && !IS_ERR(o))
                lu_object_put(&env, &o->do_lu);
        lu_env_fini(&env);

        RETURN(rc);
}
EXPORT_SYMBOL(llog_put_cat_list);


