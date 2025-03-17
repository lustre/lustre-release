// SPDX-License-Identifier: GPL-2.0

/*
 * wbcFS OSD module
 *
 * Author: Yingjin Qian <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM	S_OSD

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <md_object.h>
#include <obd_class.h>

#include "osd_internal.h"
#include "wbcfs.h"

struct kmem_cache *osd_it_cachep;
struct kmem_cache *osd_hash_it_cachep;

static struct lu_kmem_descr wbcfs_caches[] = {
	{
		.ckd_cache = &osd_it_cachep,
		.ckd_name  = "osd_it_cache",
		.ckd_size  = sizeof(struct osd_it)
	},
	{
		.ckd_cache = &osd_hash_it_cachep,
		.ckd_name  = "osd_hash_it_cache",
		.ckd_size  = sizeof(struct osd_hash_it)
	},
	{
		.ckd_cache = NULL
	}
};

/* Copied form osd-ldiskfs to open/put file handle in kenrel. */
struct work_struct flush_fput;
atomic_t descriptors_cnt;
unsigned int wbcfs_flush_descriptors_cnt = 5000;

#ifdef HAVE_FLUSH_DELAYED_FPUT
# define cfs_flush_delayed_fput() flush_delayed_fput()
#else
void (*cfs_flush_delayed_fput)(void);
#endif /* HAVE_FLUSH_DELAYED_FPUT */

static void osd_flush_fput(struct work_struct *work)
{
	/* flush file descriptors when too many files */
	CDEBUG_LIMIT(D_HA, "Flushing file descriptors limit %d\n",
		     wbcfs_flush_descriptors_cnt);

	/* descriptors_cnt triggers the threshold when a flush is started,
	 * but all pending descriptors will be flushed each time, so it
	 * doesn't need to exactly match the number of descriptors.
	 */
	atomic_set(&descriptors_cnt, 0);
	cfs_flush_delayed_fput();
}

static struct lu_object *osd_object_alloc(const struct lu_env *env,
					  const struct lu_object_header *hdr,
					  struct lu_device *d)
{
	struct osd_object *obj;
	struct lu_object *l;

	OBD_ALLOC_PTR(obj);
	if (!obj)
		return NULL;

	l = &obj->oo_dt.do_lu;
	dt_object_init(&obj->oo_dt, NULL, d);
	obj->oo_header = NULL;
	obj->oo_dt.do_ops = &osd_obj_ops;
	l->lo_ops = &osd_lu_obj_ops;
	spin_lock_init(&obj->oo_guard);
	init_rwsem(&obj->oo_dt.dd_sem);
	init_rwsem(&obj->oo_sem);
	return l;
}

static int osd_shutdown(const struct lu_env *env, struct osd_device *osd)
{
	seq_target_fini(env, &osd->od_dt_dev);
	return 0;
}

static int osd_mount(const struct lu_env *env,
		     struct osd_device *osd, struct lustre_cfg *cfg)
{
	struct file_system_type *type;
	struct inode *inode;
	unsigned long flags = 0;
	struct lu_fid fid;
	int rc = 0;

	ENTRY;

	if (osd->od_mnt != NULL)
		RETURN(0);

	type = get_fs_type("wbcfs");
	if (type == NULL) {
		CERROR("%s: Cannot find wbcfs FS type.\n", osd_name(osd));
		RETURN(-ENODEV);
	}

	flags |= SB_KERNMOUNT;
	osd->od_mnt = vfs_kern_mount(type, flags, NULL, NULL);
	module_put(type->owner);

	if (IS_ERR(osd->od_mnt)) {
		rc = PTR_ERR(osd->od_mnt);
		osd->od_mnt = NULL;
		CERROR("%s: Failed to mount wbcfs in kernel: rc=%d\n",
		       osd_name(osd), rc);
		RETURN(rc);
	}

	inode = osd_sb(osd)->s_root->d_inode;
	lu_local_obj_fid(&fid, OSD_FS_ROOT_OID);
	inode->i_ino = lu_fid_build_ino(&fid, 0);
	inode->i_generation = lu_fid_build_gen(&fid);
	MEMFS_I(inode)->mei_fid = fid;
	__insert_inode_hash(inode, inode->i_ino);

	RETURN(rc);
}

static int osd_process_config(const struct lu_env *env,
			      struct lu_device *d, struct lustre_cfg *cfg)
{
	struct osd_device *osd = osd_dev(d);
	int count;
	int rc;

	ENTRY;

	switch (cfg->lcfg_command) {
	case LCFG_SETUP:
		rc = osd_mount(env, osd, cfg);
		break;
	case LCFG_CLEANUP:
		/*
		 * For the case LCFG_PRE_CLEANUP is not called in advance,
		 * that may happen if hit failure during mount process.
		 */
		lu_dev_del_linkage(d->ld_site, d);
		rc = osd_shutdown(env, osd);
		break;
	case LCFG_PARAM:
		LASSERT(&osd->od_dt_dev);
		count = class_modify_config(cfg, PARAM_OSD,
					    &osd->od_dt_dev.dd_kobj);
		if (count < 0)
			count = class_modify_config(cfg, PARAM_OST,
						    &osd->od_dt_dev.dd_kobj);
		rc = count > 0 ? 0 : count;
		break;
	case LCFG_PRE_CLEANUP:
		rc = 0;
		break;
	default:
		rc = -EOPNOTSUPP;
	}

	RETURN(rc);
}

static int osd_recovery_complete(const struct lu_env *env, struct lu_device *d)
{
	RETURN(0);
}

static int osd_prepare(const struct lu_env *env, struct lu_device *pdev,
		       struct lu_device *dev)
{
	struct osd_device *osd = osd_dev(dev);
	int rc = 0;

	rc = seq_target_init(env, &osd->od_dt_dev, osd->od_svname,
			     osd->od_is_ost);

	RETURN(rc);
}

const struct lu_device_operations osd_lu_ops = {
	.ldo_object_alloc	= osd_object_alloc,
	.ldo_process_config	= osd_process_config,
	.ldo_recovery_complete	= osd_recovery_complete,
	.ldo_prepare		= osd_prepare,
	.ldo_fid_alloc		= fid_alloc_generic,
};

static int osd_root_get(const struct lu_env *env,
			struct dt_device *dev, struct lu_fid *f)
{
	lu_local_obj_fid(f, OSD_FS_ROOT_OID);
	return 0;
}

static int osd_statfs(const struct lu_env *env, struct dt_device *d,
		      struct obd_statfs *sfs, struct obd_statfs_info *info)
{
	struct osd_device *osd = osd_dt_dev(d);
	struct super_block *sb = osd_sb(osd);
	struct kstatfs ksfs;
	int rc;

	if (unlikely(!sb))
		return -EINPROGRESS;

	memset(&ksfs, 0, sizeof(ksfs));
	rc = sb->s_op->statfs(sb->s_root, &ksfs);
	if (rc)
		RETURN(rc);

	statfs_pack(sfs, &ksfs);
	if (unlikely(sb->s_flags & SB_RDONLY))
		sfs->os_state |= OS_STATFS_READONLY;

	if (sfs->os_blocks == 0) {
		sfs->os_blocks = memfs_default_max_blocks();
		sfs->os_bfree = sfs->os_blocks;
		sfs->os_bavail = sfs->os_bfree;
	}

	if (sfs->os_files == 0) {
		sfs->os_files = memfs_default_max_inodes();
		sfs->os_ffree = sfs->os_files;
	}

	sfs->os_state |= OS_STATFS_NONROT;
	sfs->os_namelen = NAME_MAX;
	sfs->os_maxbytes = sb->s_maxbytes;

	return 0;
}

static struct thandle *osd_trans_create(const struct lu_env *env,
					struct dt_device *d)
{
	struct osd_thandle *oh;
	struct thandle *th;

	ENTRY;

	if (d->dd_rdonly) {
		CERROR("%s: someone try to start transaction under readonly mode, should be disabled.\n",
		       osd_name(osd_dt_dev(d)));
		dump_stack();
		RETURN(ERR_PTR(-EROFS));
	}

	sb_start_write(osd_sb(osd_dt_dev(d)));

	OBD_ALLOC_PTR(oh);
	if (!oh) {
		sb_end_write(osd_sb(osd_dt_dev(d)));
		RETURN(ERR_PTR(-ENOMEM));
	}

	th = &oh->ot_super;
	th->th_dev = d;
	th->th_result = 0;
	INIT_LIST_HEAD(&oh->ot_commit_dcb_list);
	INIT_LIST_HEAD(&oh->ot_stop_dcb_list);

	RETURN(th);
}

static int osd_trans_start(const struct lu_env *env, struct dt_device *d,
			   struct thandle *th)
{
	int rc;

	ENTRY;

	rc = dt_txn_hook_start(env, d, th);
	RETURN(rc);
}

static void osd_trans_commit_cb(struct osd_thandle *oh, int result)
{
	struct thandle *th = &oh->ot_super;
	struct dt_txn_commit_cb *dcb, *tmp;

	/* call per-transaction callbacks if any */
	list_for_each_entry_safe(dcb, tmp, &oh->ot_commit_dcb_list,
				 dcb_linkage) {
		LASSERTF(dcb->dcb_magic == TRANS_COMMIT_CB_MAGIC,
			 "commit callback entry: magic=%x name='%s'\n",
			 dcb->dcb_magic, dcb->dcb_name);
		list_del_init(&dcb->dcb_linkage);
		dcb->dcb_func(NULL, th, dcb, result);
	}
}

static void osd_trans_stop_cb(struct osd_thandle *oh, int result)
{
	struct thandle *th = &oh->ot_super;
	struct dt_txn_commit_cb *dcb, *tmp;

	/* call per-transaction stop callbacks if any */
	list_for_each_entry_safe(dcb, tmp, &oh->ot_stop_dcb_list,
				 dcb_linkage) {
		LASSERTF(dcb->dcb_magic == TRANS_COMMIT_CB_MAGIC,
			 "commit callback entry: magic=%x name='%s'\n",
			 dcb->dcb_magic, dcb->dcb_name);
		list_del_init(&dcb->dcb_linkage);
		dcb->dcb_func(NULL, th, dcb, result);
	}
}

static int osd_trans_stop(const struct lu_env *env, struct dt_device *dt,
			  struct thandle *th)
{
	struct osd_device *osd = osd_dt_dev(th->th_dev);
	struct osd_thandle *oh;
	int rc = 0;

	ENTRY;
	oh = container_of(th, struct osd_thandle, ot_super);

	rc = dt_txn_hook_stop(env, th);
	if (rc)
		CERROR("%s: failed in transaction hook: rc=%d\n",
		       osd_name(osd), rc);

	osd_trans_stop_cb(oh, rc);
	/* FIXME: using th->th_result? */
	osd_trans_commit_cb(oh, rc);
	sb_end_write(osd_sb(osd));

	th->th_dev = NULL;
	OBD_FREE_PTR(oh);
	RETURN(rc);
}

static int osd_trans_cb_add(struct thandle *th, struct dt_txn_commit_cb *dcb)
{
	struct osd_thandle *oh = container_of(th, struct osd_thandle,
					      ot_super);

	LASSERT(dcb->dcb_magic == TRANS_COMMIT_CB_MAGIC);
	LASSERT(&dcb->dcb_func != NULL);

	if (dcb->dcb_flags & DCB_TRANS_STOP)
		list_add(&dcb->dcb_linkage, &oh->ot_stop_dcb_list);
	else
		list_add(&dcb->dcb_linkage, &oh->ot_commit_dcb_list);

	return 0;
}

static void osd_conf_get(const struct lu_env *env,
			 const struct dt_device *dev,
			 struct dt_device_param *param)
{
	struct osd_device *osd = osd_dt_dev(dev);
	struct super_block *sb = osd_sb(osd);

	param->ddp_max_name_len	= NAME_MAX;
	param->ddp_max_nlink = 1 << 31;
	param->ddp_symlink_max = sb->s_blocksize;
	param->ddp_mount_type = LDD_MT_WBCFS;
	param->ddp_maxbytes = sb->s_maxbytes;
	param->ddp_max_extent_blks = 1024;
	param->ddp_extent_tax = 1024;

	param->ddp_mntopts = MNTOPT_USERXATTR;

	/* TODO: Add support for MNTOPT_ACL. */

	param->ddp_max_ea_size = OBD_MAX_EA_SIZE;
	param->ddp_inodespace = 1024;
	param->ddp_brw_size = DT_DEF_BRW_SIZE;

	param->ddp_has_lseek_data_hole = true;
}

static int osd_ro(const struct lu_env *env, struct dt_device *d)
{
	int rc = -EOPNOTSUPP;

	ENTRY;

	CERROR("%s: cannot be set readonly: rc=%d\n",
	       osd_dt_dev(d)->od_svname, rc);

	RETURN(rc);
}

static int osd_reserve_or_free_quota(const struct lu_env *env,
				     struct dt_device *dev,
				     struct lquota_id_info *qi)
{
	RETURN(0);
}

static int osd_sync(const struct lu_env *env, struct dt_device *d)
{
	RETURN(0);
}

static int osd_commit_async(const struct lu_env *env, struct dt_device *dev)
{
	RETURN(0);
}

static const struct dt_device_operations osd_dt_ops = {
	.dt_root_get		  = osd_root_get,
	.dt_statfs		  = osd_statfs,
	.dt_trans_create	  = osd_trans_create,
	.dt_trans_start		  = osd_trans_start,
	.dt_trans_stop		  = osd_trans_stop,
	.dt_trans_cb_add	  = osd_trans_cb_add,
	.dt_conf_get		  = osd_conf_get,
	.dt_ro			  = osd_ro,
	.dt_reserve_or_free_quota = osd_reserve_or_free_quota,
	.dt_sync		  = osd_sync,
	.dt_commit_async	  = osd_commit_async,
};

static void osd_umount(const struct lu_env *env, struct osd_device *dev)
{
	ENTRY;

	if (dev->od_mnt) {
		shrink_dcache_sb(osd_sb(dev));
		mntput(dev->od_mnt);
		dev->od_mnt = NULL;
	}

	/* to be sure all delayed fput are finished. */
	cfs_flush_delayed_fput();

	EXIT;
}

static int __osd_device_init(const struct lu_env *env, struct osd_device *osd,
			     struct lustre_cfg *cfg)
{
	struct lu_device *ld = osd2lu_dev(osd);
	int cplen = 0;
	int rc;

	rc = lu_env_refill((struct lu_env *)env);
	if (rc)
		RETURN(rc);

	ld->ld_ops = &osd_lu_ops;
	osd->od_dt_dev.dd_ops = &osd_dt_ops;

	cplen = strscpy(osd->od_svname, lustre_cfg_string(cfg, 4),
			sizeof(osd->od_svname));
	if (cplen < 0)
		GOTO(out, rc = cplen);

	/* -1 means that index is invalid. */
	osd->od_index = -1;
	rc = server_name2index(osd->od_svname, &osd->od_index, NULL);
	if (rc == LDD_F_SV_TYPE_OST)
		osd->od_is_ost = 1;

	rc = osd_mount(env, osd, cfg);
	if (rc)
		GOTO(out, rc);

	rc = lu_site_init(&osd->od_site, ld);
	if (rc)
		GOTO(out_mnt, rc);
	osd->od_site.ls_bottom_dev = ld;

	rc = lu_site_init_finish(&osd->od_site);
	if (rc)
		GOTO(out_site, rc);

	RETURN(0);

out_site:
	lu_site_fini(&osd->od_site);
out_mnt:
	osd_umount(env, osd);
out:
	return rc;
}

static struct lu_device *osd_device_alloc(const struct lu_env *env,
					  struct lu_device_type *t,
					  struct lustre_cfg *cfg)
{
	struct osd_device *osd;
	int rc;

	ENTRY;

	OBD_ALLOC_PTR(osd);
	if (osd == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	rc = dt_device_init(&osd->od_dt_dev, t);
	if (unlikely(rc)) {
		OBD_FREE_PTR(osd);
		GOTO(out, rc);
	}

	rc = __osd_device_init(env, osd, cfg);
out:
	RETURN(rc == 0 ? osd2lu_dev(osd) : ERR_PTR(rc));
}

static struct lu_device *osd_device_free(const struct lu_env *env,
					 struct lu_device *d)
{
	struct osd_device *osd = osd_dev(d);

	ENTRY;

	/* XXX: make osd top device in order to release reference */
	d->ld_site->ls_top_dev = d;
	lu_site_purge(env, d->ld_site, -1);
	lu_site_print(env, d->ld_site, &d->ld_site->ls_obj_hash.nelems,
		      D_ERROR, lu_cdebug_printer);

	lu_site_fini(&osd->od_site);
	dt_device_fini(&osd->od_dt_dev);
	OBD_FREE_PTR(osd);

	RETURN(NULL);
}

static int osd_device_init(const struct lu_env *env, struct lu_device *d,
			   const char *name, struct lu_device *next)
{
	return 0;
}

static struct lu_device *osd_device_fini(const struct lu_env *env,
					 struct lu_device *d)
{
	struct osd_device *osd = osd_dev(d);

	ENTRY;

	osd_shutdown(env, osd);
	osd_umount(env, osd);
	RETURN(NULL);
}

static const struct lu_device_type_operations osd_device_type_ops = {
	.ldto_device_alloc	= osd_device_alloc,
	.ldto_device_free	= osd_device_free,
	.ldto_device_init	= osd_device_init,
	.ldto_device_fini	= osd_device_fini
};

static struct lu_device_type osd_device_type = {
	.ldt_tags	= LU_DEVICE_DT,
	.ldt_name	= LUSTRE_OSD_WBCFS_NAME,
	.ldt_ops	= &osd_device_type_ops,
	.ldt_ctx_tags	= LCT_LOCAL
};

/* We use exports to track all osd users. */
static int osd_obd_connect(const struct lu_env *env, struct obd_export **exp,
			   struct obd_device *obd, struct obd_uuid *cluuid,
			   struct obd_connect_data *data, void *localdata)
{
	struct osd_device *osd = osd_dev(obd->obd_lu_dev);
	struct lustre_handle conn;
	int rc;

	ENTRY;

	CDEBUG(D_CONFIG, "connect #%d\n", atomic_read(&osd->od_connects));

	rc = class_connect(&conn, obd, cluuid);
	if (rc)
		RETURN(rc);

	*exp = class_conn2export(&conn);
	atomic_inc(&osd->od_connects);

	RETURN(0);
}

/*
 * Once last export (we do not count self-export) disappeared,
 * OSD can be released.
 */
static int osd_obd_disconnect(struct obd_export *exp)
{
	struct obd_device *obd = exp->exp_obd;
	struct osd_device *osd = osd_dev(obd->obd_lu_dev);
	int rc, release = 0;

	ENTRY;

	/* Only disconnect the underlying layers on the final disconnect. */
	release = atomic_dec_and_test(&osd->od_connects);
	rc = class_disconnect(exp);

	if (rc == 0 && release)
		class_manual_cleanup(obd);

	RETURN(rc);
}

static int osd_health_check(const struct lu_env *env, struct obd_device *obd)
{
	struct osd_device *osd = osd_dev(obd->obd_lu_dev);
	struct super_block *sb = osd_sb(osd);

	return (!sb || sb->s_flags & SB_RDONLY);
}

static const struct obd_ops osd_obd_device_ops = {
	.o_owner	= THIS_MODULE,
	.o_connect	= osd_obd_connect,
	.o_disconnect	= osd_obd_disconnect,
	.o_health_check = osd_health_check,
};

static int __init osd_init(void)
{
	int rc;

	rc = libcfs_setup();
	if (rc)
		return rc;

	rc = lu_kmem_init(wbcfs_caches);
	if (rc)
		return rc;

	rc = memfs_init();
	if (rc)
		GOTO(out_kmem, rc);

	rc = class_register_type(&osd_obd_device_ops, NULL, true,
				 LUSTRE_OSD_WBCFS_NAME, &osd_device_type);
	if (rc)
		GOTO(out_memfs, rc);

#ifndef HAVE_FLUSH_DELAYED_FPUT
	if (unlikely(cfs_flush_delayed_fput == NULL))
		cfs_flush_delayed_fput =
			cfs_kallsyms_lookup_name("flush_delayed_fput");
#endif

	INIT_WORK(&flush_fput, osd_flush_fput);

	return 0;

out_memfs:
	memfs_fini();
out_kmem:
	lu_kmem_fini(wbcfs_caches);
	return rc;
}

static void __exit osd_exit(void)
{
	cancel_work_sync(&flush_fput);
	class_unregister_type(LUSTRE_OSD_WBCFS_NAME);
	memfs_fini();
	lu_kmem_fini(wbcfs_caches);
}

MODULE_AUTHOR("Yingjin Qian <qian@ddn.com>");
MODULE_DESCRIPTION("Lustre Object Storage Device ("LUSTRE_OSD_WBCFS_NAME")");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(osd_init);
module_exit(osd_exit);
