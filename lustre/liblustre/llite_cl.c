/*
 *   Copyright (c) 2007 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
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
 *   Copyright (c) 2011, 2013, Intel Corporation.
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/queue.h>
#ifndef __CYGWIN__
# include <sys/statvfs.h>
#else
# include <sys/statfs.h>
#endif

#include <liblustre.h>

#include <obd.h>
#include <obd_support.h>
#include <lustre_fid.h>
#include <lustre_lite.h>
#include <lustre_dlm.h>
#include <lustre_ver.h>
#include <lustre_mdc.h>
#include <cl_object.h>

#include "llite_lib.h"

/*
 * slp_ prefix stands for "Sysio Library Posix". It corresponds to historical
 * "llu_" prefix.
 */

static int   slp_type_init     (struct lu_device_type *t);
static void  slp_type_fini     (struct lu_device_type *t);

static int slp_page_init(const struct lu_env *env, struct cl_object *obj,
			 struct cl_page *page, struct page *vmpage);
static int   slp_attr_get     (const struct lu_env *env, struct cl_object *obj,
                               struct cl_attr *attr);

static struct lu_device  *slp_device_alloc(const struct lu_env *env,
                                           struct lu_device_type *t,
                                           struct lustre_cfg *cfg);

static int slp_io_init(const struct lu_env *env, struct cl_object *obj,
                       struct cl_io *io);
static struct slp_io *cl2slp_io(const struct lu_env *env,
                                const struct cl_io_slice *slice);


static void llu_free_user_page(struct page *page);

static const struct lu_object_operations      slp_lu_obj_ops;
static const struct lu_device_operations      slp_lu_ops;
static const struct cl_device_operations      slp_cl_ops;
static const struct cl_io_operations          ccc_io_ops;
static const struct lu_device_type_operations slp_device_type_ops;
             //struct lu_device_type            slp_device_type;
static const struct cl_page_operations        slp_page_ops;
static const struct cl_page_operations        slp_transient_page_ops;
static const struct cl_lock_operations        slp_lock_ops;


/*****************************************************************************
 *
 * Slp device and device type functions.
 *
 */

void *slp_session_key_init(const struct lu_context *ctx,
                                  struct lu_context_key *key)
{
        struct slp_session *session;

        OBD_ALLOC_PTR(session);
        if (session == NULL)
                session = ERR_PTR(-ENOMEM);
        return session;
}

void slp_session_key_fini(const struct lu_context *ctx,
                                 struct lu_context_key *key, void *data)
{
        struct slp_session *session = data;
        OBD_FREE_PTR(session);
}

struct lu_context_key slp_session_key = {
        .lct_tags = LCT_SESSION,
        .lct_init = slp_session_key_init,
        .lct_fini = slp_session_key_fini
};

/* type constructor/destructor: slp_type_{init,fini,start,stop}(). */
LU_TYPE_INIT_FINI(slp, &ccc_key, &ccc_session_key, &slp_session_key);

static struct lu_device *slp_device_alloc(const struct lu_env *env,
                                          struct lu_device_type *t,
                                          struct lustre_cfg *cfg)
{
        return ccc_device_alloc(env, t, cfg, &slp_lu_ops, &slp_cl_ops);
}

static int slp_lock_init(const struct lu_env *env,
                         struct cl_object *obj, struct cl_lock *lock,
                         const struct cl_io *io)
{
        return ccc_lock_init(env, obj, lock, io, &slp_lock_ops);
}

static const struct cl_object_operations slp_ops = {
        .coo_page_init = slp_page_init,
        .coo_lock_init = slp_lock_init,
        .coo_io_init   = slp_io_init,
        .coo_attr_get  = slp_attr_get,
        .coo_attr_set  = ccc_attr_set,
        .coo_conf_set  = ccc_conf_set,
        .coo_glimpse   = ccc_object_glimpse
};

static int slp_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *o)
{
        struct ccc_object *obj   = lu2ccc(o);
        struct inode      *inode = obj->cob_inode;
        struct intnl_stat *st = NULL;

        if (inode)
                st = llu_i2stat(inode);

        return (*p)(env, cookie, LUSTRE_SLP_NAME"-object@%p(%p:%lu/%u)",
                    obj, inode,
                    st ? (unsigned long)st->st_ino : 0UL,
                    inode ? (unsigned int)llu_i2info(inode)->lli_st_generation
                    : 0);
}

static const struct lu_object_operations slp_lu_obj_ops = {
        .loo_object_init      = ccc_object_init,
        .loo_object_start     = NULL,
        .loo_object_delete    = NULL,
        .loo_object_release   = NULL,
        .loo_object_free      = ccc_object_free,
        .loo_object_print     = slp_object_print,
        .loo_object_invariant = NULL
};

static struct lu_object *slp_object_alloc(const struct lu_env *env,
                                          const struct lu_object_header *hdr,
                                          struct lu_device *dev)
{
        return ccc_object_alloc(env, hdr, dev, &slp_ops, &slp_lu_obj_ops);
}

static const struct lu_device_operations slp_lu_ops = {
        .ldo_object_alloc      = slp_object_alloc
};

static const struct cl_device_operations slp_cl_ops = {
        .cdo_req_init = ccc_req_init
};

static const struct lu_device_type_operations slp_device_type_ops = {
        .ldto_init = slp_type_init,
        .ldto_fini = slp_type_fini,

        .ldto_start = slp_type_start,
        .ldto_stop  = slp_type_stop,

        .ldto_device_alloc = slp_device_alloc,
        .ldto_device_free  = ccc_device_free,
        .ldto_device_init  = ccc_device_init,
        .ldto_device_fini  = ccc_device_fini
};

struct lu_device_type slp_device_type = {
        .ldt_tags     = LU_DEVICE_CL,
        .ldt_name     = LUSTRE_SLP_NAME,
        .ldt_ops      = &slp_device_type_ops,
        .ldt_ctx_tags = LCT_CL_THREAD
};

int slp_global_init(void)
{
        int result;

        result = ccc_global_init(&slp_device_type);
        return result;
}

void slp_global_fini(void)
{
        ccc_global_fini(&slp_device_type);
}

/*****************************************************************************
 *
 * Object operations.
 *
 */

static int slp_page_init(const struct lu_env *env, struct cl_object *obj,
			struct cl_page *page, struct page *vmpage)
{
        struct ccc_page *cpg = cl_object_page_slice(obj, page);

        CLOBINVRNT(env, obj, ccc_object_invariant(obj));

	cpg->cpg_page = vmpage;

	if (page->cp_type == CPT_CACHEABLE) {
		LBUG();
	} else {
		struct ccc_object *clobj = cl2ccc(obj);

		cl_page_slice_add(page, &cpg->cpg_cl, obj,
				&slp_transient_page_ops);
		clobj->cob_transient_pages++;
	}

        return 0;
}

static int slp_io_init(const struct lu_env *env, struct cl_object *obj,
                       struct cl_io *io)
{
        struct ccc_io      *vio   = ccc_env_io(env);
        int result = 0;

        CLOBINVRNT(env, obj, ccc_object_invariant(obj));

        cl_io_slice_add(io, &vio->cui_cl, obj, &ccc_io_ops);
        if (io->ci_type == CIT_READ || io->ci_type == CIT_WRITE) {
                size_t count;

                count = io->u.ci_rw.crw_count;
                /* "If nbyte is 0, read() will return 0 and have no other
                 *  results."  -- Single Unix Spec */
                if (count == 0)
                        result = 1;
                else {
                        vio->cui_tot_count = count;
                        vio->cui_tot_nrsegs = 0;
                }

        }
        return result;
}

static int slp_attr_get(const struct lu_env *env, struct cl_object *obj,
                        struct cl_attr *attr)
{
        struct inode *inode = ccc_object_inode(obj);
        struct intnl_stat *st = llu_i2stat(inode);

        attr->cat_size = st->st_size;
        attr->cat_blocks = st->st_blocks;
        attr->cat_mtime  = st->st_mtime;
        attr->cat_atime  = st->st_atime;
        attr->cat_ctime  = st->st_ctime;
        /* KMS is not known by this layer */
        return 0; /* layers below have to fill in the rest */
}

/*****************************************************************************
 *
 * Page operations.
 *
 */

static void slp_page_fini_common(struct ccc_page *cp)
{
	struct page *vmpage = cp->cpg_page;

        LASSERT(vmpage != NULL);
        llu_free_user_page(vmpage);
        OBD_FREE_PTR(cp);
}

static void slp_page_completion_common(const struct lu_env *env,
                                       struct ccc_page *cp, int ioret)
{
        LASSERT(cp->cpg_cl.cpl_page->cp_sync_io != NULL);
}

static void slp_page_completion_read(const struct lu_env *env,
                                     const struct cl_page_slice *slice,
                                     int ioret)
{
        struct ccc_page *cp      = cl2ccc_page(slice);
        ENTRY;

        slp_page_completion_common(env, cp, ioret);

        EXIT;
}

static void slp_page_completion_write_common(const struct lu_env *env,
                                             const struct cl_page_slice *slice,
                                             int ioret)
{
        struct ccc_page *cp     = cl2ccc_page(slice);

        if (ioret == 0) {
                cp->cpg_write_queued = 0;
                /*
                 * Only ioret == 0, write succeed, then this page could be
                 * deleted from the pending_writing count.
                 */
        }
        slp_page_completion_common(env, cp, ioret);
}

static int slp_page_is_vmlocked(const struct lu_env *env,
                                const struct cl_page_slice *slice)
{
        return -EBUSY;
}

static void slp_transient_page_fini(const struct lu_env *env,
                                    struct cl_page_slice *slice)
{
        struct ccc_page *cp = cl2ccc_page(slice);
        struct cl_page *clp = slice->cpl_page;
        struct ccc_object *clobj = cl2ccc(clp->cp_obj);

        slp_page_fini_common(cp);
        clobj->cob_transient_pages--;
}


static const struct cl_page_operations slp_transient_page_ops = {
        .cpo_own           = ccc_transient_page_own,
        .cpo_assume        = ccc_transient_page_assume,
        .cpo_unassume      = ccc_transient_page_unassume,
        .cpo_disown        = ccc_transient_page_disown,
        .cpo_discard       = ccc_transient_page_discard,
        .cpo_vmpage        = ccc_page_vmpage,
        .cpo_is_vmlocked   = slp_page_is_vmlocked,
        .cpo_fini          = slp_transient_page_fini,
        .cpo_is_under_lock = ccc_page_is_under_lock,
        .io = {
                [CRT_READ] = {
                        .cpo_completion  = slp_page_completion_read,
                },
                [CRT_WRITE] = {
                        .cpo_completion  = slp_page_completion_write_common,
                }
        }
};

/*****************************************************************************
 *
 * Lock operations.
 *
 */

static int slp_lock_enqueue(const struct lu_env *env,
                           const struct cl_lock_slice *slice,
                           struct cl_io *unused, __u32 enqflags)
{
        CLOBINVRNT(env, slice->cls_obj, ccc_object_invariant(slice->cls_obj));

        liblustre_wait_event(0);
        return 0;
}

static const struct cl_lock_operations slp_lock_ops = {
        .clo_delete    = ccc_lock_delete,
        .clo_fini      = ccc_lock_fini,
        .clo_enqueue   = slp_lock_enqueue,
        .clo_wait      = ccc_lock_wait,
        .clo_unuse     = ccc_lock_unuse,
        .clo_fits_into = ccc_lock_fits_into,
};

/*****************************************************************************
 *
 * io operations.
 *
 */

static int slp_io_rw_lock(const struct lu_env *env,
                          const struct cl_io_slice *ios)
{
        struct ccc_io *cio = ccc_env_io(env);
        struct cl_io *io   = ios->cis_io;
        loff_t start;
        loff_t end;

        if (cl_io_is_append(io)) {
                start = 0;
                end   = OBD_OBJECT_EOF;
        } else {
                start = io->u.ci_wr.wr.crw_pos;
                end   = start + io->u.ci_wr.wr.crw_count - 1;
        }

        ccc_io_update_iov(env, cio, io);

        /*
         * This acquires real DLM lock only in O_APPEND case, because of
         * the io->ci_lockreq setting in llu_io_init().
         */
        LASSERT(ergo(cl_io_is_append(io), io->ci_lockreq == CILR_MANDATORY));
        LASSERT(ergo(!cl_io_is_append(io), io->ci_lockreq == CILR_NEVER));
        return ccc_io_one_lock(env, io, 0,
                               io->ci_type == CIT_READ ? CLM_READ : CLM_WRITE,
                               start, end);

}

static int slp_io_setattr_iter_init(const struct lu_env *env,
                                    const struct cl_io_slice *ios)
{
        return 0;
}

static int slp_io_setattr_start(const struct lu_env *env,
                                const struct cl_io_slice *ios)
{
        return 0;
}

static struct page *llu_get_user_page(int index, void *addr, int offset,
                                      int count)
{
        struct page *page;

        OBD_ALLOC_PTR(page);
        if (!page)
                return NULL;
        page->index = index;
        page->addr = addr;
        page->_offset = offset;
        page->_count = count;

        CFS_INIT_LIST_HEAD(&page->list);
        CFS_INIT_LIST_HEAD(&page->_node);

        return page;
}

static void llu_free_user_page(struct page *page)
{
        OBD_FREE_PTR(page);
}


static int llu_queue_pio(const struct lu_env *env, struct cl_io *io,
                         struct llu_io_group *group,
                         char *buf, size_t count, loff_t pos)
{
        struct cl_object *obj = io->ci_obj;
        struct inode *inode = ccc_object_inode(obj);
        struct intnl_stat *st = llu_i2stat(inode);
        struct obd_export *exp = llu_i2obdexp(inode);
        struct page *page;
        int  rc = 0, ret_bytes = 0;
        struct cl_page *clp;
        struct cl_2queue *queue;
        ENTRY;

        if (!exp)
                RETURN(-EINVAL);

        queue = &io->ci_queue;
        cl_2queue_init(queue);


        /* prepare the pages array */
        do {
                unsigned long index, offset, bytes;

                offset = (pos & ~CFS_PAGE_MASK);
		index = pos >> PAGE_CACHE_SHIFT;
		bytes = PAGE_CACHE_SIZE - offset;
                if (bytes > count)
                        bytes = count;

                /* prevent read beyond file range */
                if (/* local_lock && */
                    io->ci_type == CIT_READ && pos + bytes >= st->st_size) {
                        if (pos >= st->st_size)
                                break;
                        bytes = st->st_size - pos;
                }

                /* prepare page for this index */
                page = llu_get_user_page(index, buf - offset, offset, bytes);
                if (!page) {
                        rc = -ENOMEM;
                        break;
                }

                clp = cl_page_find(env, obj,
                                   cl_index(obj, pos),
                                   page, CPT_TRANSIENT);

                if (IS_ERR(clp)) {
                        rc = PTR_ERR(clp);
                        break;
                }

                rc = cl_page_own(env, io, clp);
                if (rc) {
                        LASSERT(clp->cp_state == CPS_FREEING);
                        cl_page_put(env, clp);
                        break;
                }

                cl_2queue_add(queue, clp);

                /* drop the reference count for cl_page_find, so that the page
                 * will be freed in cl_2queue_fini. */
                cl_page_put(env, clp);

                cl_page_clip(env, clp, offset, offset+bytes);

                count -= bytes;
                pos += bytes;
                buf += bytes;

                group->lig_rwcount += bytes;
                ret_bytes += bytes;
                page++;
        } while (count);

        if (rc == 0) {
                enum cl_req_type iot;
                iot = io->ci_type == CIT_READ ? CRT_READ : CRT_WRITE;
		rc = cl_io_submit_sync(env, io, iot, queue, 0);
        }

        group->lig_rc = rc;

        cl_2queue_discard(env, io, queue);
        cl_2queue_disown(env, io, queue);
        cl_2queue_fini(env, queue);

        RETURN(ret_bytes);
}

static
struct llu_io_group * get_io_group(struct inode *inode, int maxpages,
                                   struct lustre_rw_params *params)
{
        struct llu_io_group *group;

        OBD_ALLOC_PTR(group);
        if (!group)
                return ERR_PTR(-ENOMEM);

        group->lig_params = params;

        return group;
}

static int max_io_pages(ssize_t len, int iovlen)
{
	return ((len + PAGE_CACHE_SIZE - 1) / PAGE_CACHE_SIZE) +
		2 + iovlen - 1;
}

void put_io_group(struct llu_io_group *group)
{
        OBD_FREE_PTR(group);
}

/**
 * True, if \a io is a normal io, False for sendfile() / splice_{read|write}
 */
int cl_is_normalio(const struct lu_env *env, const struct cl_io *io)
{
        return 1;
}

static int slp_io_start(const struct lu_env *env, const struct cl_io_slice *ios)
{
        struct ccc_io     *cio   = cl2ccc_io(env, ios);
        struct cl_io      *io    = ios->cis_io;
        struct cl_object  *obj   = io->ci_obj;
        struct inode      *inode = ccc_object_inode(obj);
        int    err, ret;
        loff_t pos;
        long   cnt;
        struct llu_io_group *iogroup;
        struct lustre_rw_params p = {0};
        int iovidx;
        struct intnl_stat *st = llu_i2stat(inode);
        struct llu_inode_info *lli = llu_i2info(inode);
        struct llu_io_session *session = cl2slp_io(env, ios)->sio_session;
        int write = io->ci_type == CIT_WRITE;
        int exceed = 0;

        CLOBINVRNT(env, obj, ccc_object_invariant(obj));

        if (write) {
                pos = io->u.ci_wr.wr.crw_pos;
                cnt = io->u.ci_wr.wr.crw_count;
        } else {
                pos = io->u.ci_rd.rd.crw_pos;
                cnt = io->u.ci_rd.rd.crw_count;
        }
        if (io->u.ci_wr.wr_append) {
                p.lrp_lock_mode = LCK_PW;
        } else {
                p.lrp_brw_flags = OBD_BRW_SRVLOCK;
                p.lrp_lock_mode = LCK_NL;
        }

        iogroup = get_io_group(inode, max_io_pages(cnt, cio->cui_nrsegs), &p);
        if (IS_ERR(iogroup))
                RETURN(PTR_ERR(iogroup));

        err = ccc_prep_size(env, obj, io, pos, cnt, &exceed);
        if (err != 0 || (write == 0 && exceed != 0))
                GOTO(out, err);

        CDEBUG(D_INODE,
               "%s ino %lu, %lu bytes, offset "LPU64", i_size "LPU64"\n",
               write ? "Write" : "Read", (unsigned long)st->st_ino,
               cnt, (__u64)pos, (__u64)st->st_size);

        if (write && io->u.ci_wr.wr_append)
                pos = io->u.ci_wr.wr.crw_pos = st->st_size; /* XXX? Do we need to change io content too here? */
                /* XXX What about if one write syscall writes at 2 different offsets? */

        for (iovidx = 0; iovidx < cio->cui_nrsegs; iovidx++) {
                char *buf = (char *) cio->cui_iov[iovidx].iov_base;
                long count = cio->cui_iov[iovidx].iov_len;

                if (!count)
                        continue;
                if (cnt < count)
                        count = cnt;
                if (IS_BAD_PTR(buf) || IS_BAD_PTR(buf + count)) {
                        GOTO(out, err = -EFAULT);
                }

                if (io->ci_type == CIT_READ) {
                        if (/* local_lock && */ pos >= st->st_size)
                                break;
                } else if (io->ci_type == CIT_WRITE) {
                        if (pos >= lli->lli_maxbytes) {
                                GOTO(out, err = -EFBIG);
                        }
                        if (pos + count >= lli->lli_maxbytes)
                                count = lli->lli_maxbytes - pos;
                } else {
                        LBUG();
                }

                ret = llu_queue_pio(env, io, iogroup, buf, count, pos);
                if (ret < 0) {
                        GOTO(out, err = ret);
                } else {
                        io->ci_nob += ret;
                        pos += ret;
                        cnt -= ret;
                        if (io->ci_type == CIT_WRITE) {
//                                obd_adjust_kms(exp, lsm, pos, 0); // XXX
                                if (pos > st->st_size)
                                        st->st_size = pos;
                        }
                        if (!cnt)
                                break;
                }
        }
        LASSERT(cnt == 0 || io->ci_type == CIT_READ); /* libsysio should guarantee this */

        if (!iogroup->lig_rc)
                session->lis_rwcount += iogroup->lig_rwcount;
        else if (!session->lis_rc)
                session->lis_rc = iogroup->lig_rc;
        err = 0;

out:
        put_io_group(iogroup);
        return err;
}

static const struct cl_io_operations ccc_io_ops = {
        .op = {
                [CIT_READ] = {
                        .cio_fini      = ccc_io_fini,
                        .cio_lock      = slp_io_rw_lock,
                        .cio_start     = slp_io_start,
                        .cio_end       = ccc_io_end,
                        .cio_advance   = ccc_io_advance
                },
                [CIT_WRITE] = {
                        .cio_fini      = ccc_io_fini,
                        .cio_lock      = slp_io_rw_lock,
                        .cio_start     = slp_io_start,
                        .cio_end       = ccc_io_end,
                        .cio_advance   = ccc_io_advance
                },
                [CIT_SETATTR] = {
                        .cio_fini       = ccc_io_fini,
                        .cio_iter_init  = slp_io_setattr_iter_init,
                        .cio_start      = slp_io_setattr_start
                },
                [CIT_MISC] = {
                        .cio_fini   = ccc_io_fini
                }
        }
};

static struct slp_io *cl2slp_io(const struct lu_env *env,
                                const struct cl_io_slice *slice)
{
        /* We call it just for assertion here */
        cl2ccc_io(env, slice);

        return slp_env_io(env);
}

/*****************************************************************************
 *
 * Temporary prototype thing: mirror obd-devices into cl devices.
 *
 */

int cl_sb_init(struct llu_sb_info *sbi)
{
        struct cl_device  *cl;
        struct lu_env     *env;
        int rc = 0;
        int refcheck;

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        cl = cl_type_setup(env, NULL, &slp_device_type,
                           sbi->ll_dt_exp->exp_obd->obd_lu_dev);
        if (IS_ERR(cl))
                GOTO(out, rc = PTR_ERR(cl));

        sbi->ll_cl = cl;
        sbi->ll_site = cl2lu_dev(cl)->ld_site;
out:
        cl_env_put(env, &refcheck);
        RETURN(rc);
}

int cl_sb_fini(struct llu_sb_info *sbi)
{
        struct lu_env *env;
        int refcheck;

        ENTRY;

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        if (sbi->ll_cl != NULL) {
                cl_stack_fini(env, sbi->ll_cl);
                sbi->ll_cl = NULL;
                sbi->ll_site = NULL;
        }
        cl_env_put(env, &refcheck);
        /*
         * If mount failed (sbi->ll_cl == NULL), and this there are no other
         * mounts, stop device types manually (this usually happens
         * automatically when last device is destroyed).
         */
        lu_types_stop();
        cl_env_cache_purge(~0);
        RETURN(0);
}
