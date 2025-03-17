// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2025-2026, DDN/Whamcloud, Inc.
 */

/*
 * Author: Yingjin Qian <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM	S_OSD

#include <lustre_crypto.h>

#include "osd_internal.h"
#include "wbcfs.h"

/* Lookup the directory entry (dentry) specified by @key. */
static int osd_index_dir_lookup(const struct lu_env *env, struct dt_object *dt,
				struct dt_rec *rec, const struct dt_key *key)
{
	struct osd_object *pobj = osd_dt_obj(dt);
	struct inode *dir = pobj->oo_inode;
	struct lu_fid *fid = (struct lu_fid *)rec;
	char *name = (char *)key;
	struct dentry *parent;
	struct dentry *dchild;
	struct qstr qstr;
	int rc = 0;

	ENTRY;

	LASSERT(S_ISDIR(dir->i_mode));
	parent = d_find_any_alias(dir);
	if (IS_ERR(parent))
		RETURN(PTR_ERR(parent));

	/* FIXME: more checking for ".." lookup. */
	if (strcmp(name, "..") == 0) {
		*fid = MEMFS_I(d_inode(parent->d_parent))->mei_fid;
		GOTO(out, rc = 1);
	}

	qstr.name = name;
	qstr.len = strlen(name);
	qstr.hash = ll_full_name_hash(parent, qstr.name, qstr.len);
	dchild = d_lookup(parent, &qstr);
	if (dchild) {
		*fid = MEMFS_I(d_inode(dchild))->mei_fid;
		dput(dchild);
		rc = 1;
	}

out:
	CDEBUG(D_CACHE, "%s: lookup '%s' from parent %pd@%pK "DFID": rc=%d\n",
	       osd_name(osd_obj2dev(pobj)), name, parent, parent,
	       PFID(fid), rc);
	dput(parent);
	RETURN(rc);
}

/**
 * osd_index_dir_insert() - Index add function.
 * @key: it is key i.e. file entry to be inserted
 * @record: it is value of given key i.e. fid
 *
 * It will add the directory entry.This entry is needed to
 * maintain name->fid mapping.
 *
 * Return:
 * * %0 - on success
 * * %-ve - on error
 */
static int osd_index_dir_insert(const struct lu_env *env, struct dt_object *dt,
				const struct dt_rec *record,
				const struct dt_key *key,
				struct thandle *th)
{
	struct osd_object *pobj = osd_dt_obj(dt);
	struct osd_device *osd = osd_dev(dt->do_lu.lo_dev);
	struct dt_insert_rec *rec = (struct dt_insert_rec *)record;
	const struct lu_fid *fid = rec->rec_fid;
	const char *name = (const char *)key;
	struct inode *dir = pobj->oo_inode;
	struct dentry *parent;
	struct dentry *dentry;
	struct dentry *dchild = NULL;
	struct inode *inode;
	struct qstr dname;
	bool nedir_rename = false;
	int rc = 0;

	ENTRY;

	if (!dt_object_exists(dt))
		RETURN(-ENOENT);

	LASSERT(!dt_object_remote(dt));
	LASSERTF(fid_is_sane(fid), "fid "DFID" is insane!\n", PFID(fid));

	/* Skip "." and ".." in MemFS. */
	if (name[0] == '.' && (name[1] == '\0' ||
			       (name[1] == '.' && name[2] == '\0')))
		RETURN(0);

	/* FIXME: handle remote object in DNE environment. */
	/* TODO: Store inode in @osd_thread_info? */
	inode = ilookup5(osd_sb(osd), lu_fid_build_ino(fid, 0),
			 memfs_test_inode_by_fid, (void *)fid);
	if (!inode) {
		rc = -EINVAL;
		CERROR("%s: lookup "DFID" from icache failed: rc=%d\n",
		       osd_name(osd_obj2dev(pobj)), PFID(fid), rc);
		RETURN(rc);
	}

	parent = d_find_any_alias(dir);
	if (parent == NULL) {
		rc = -ENOENT;
		CERROR("%s: Cannot find dentry for inode@%pK "DFID": rc=%d\n",
		       osd_name(osd_obj2dev(pobj)), dir,
		       PFID(lu_object_fid(&pobj->oo_dt.do_lu)), rc);
		GOTO(out_iput, rc);
	}

	dname.name = name;
	dname.len = strlen(name);
	dname.hash = ll_full_name_hash(parent, dname.name, dname.len);

	dentry = d_alloc(parent, &dname);
	if (!dentry)
		GOTO(out_dput, rc = -ENOMEM);

	switch (inode->i_mode & S_IFMT) {
	case S_IFDIR:
		/*
		 * TODO: Store these info into OSD thread info @osd_thread_info,
		 * thus we can do undo (recovery) operations upon failure.
		 */
		dchild = d_find_any_alias(inode);
		/* mv (rename) a non-empty directory. */
		if (dchild && !simple_empty(dchild))
			nedir_rename = true;
		fallthrough;
	case S_IFREG:
		dir->i_size += BOGO_DIRENT_SIZE;
		inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
		break;
	case S_IFLNK:
		/* FIXME: symlink support. */
		CERROR("%s: symlink does not support\n",
		       osd_name(osd_obj2dev(pobj)));
		break;
	default:
		LBUG();
	}

	inode_inc_iversion(dir);
	if (nedir_rename) {
		d_move(dchild, dentry);
		/* Put the refcount obtained by @d_find_any_alias() */
		dput(dchild);
		/* Finally release the @dentry. */
		dput(dentry);
	} else {
		/* Add dentry into dentry hashtable for VFS lookup. */
		d_add(dentry, inode);
		ihold(inode);
	}
	/* Extra count (already obtain in @d_alloc) - pin the dentry in core */
	/* dget(dentry); */

	CDEBUG(D_CACHE,
	       "%s: Insert dirent "DFID"/%pd@%pK inode@%pK nlink=%d\n",
	       osd_name(osd_obj2dev(pobj)), PFID(fid), dentry, dentry,
	       inode, inode->i_nlink);
out_dput:

	dput(parent);
out_iput:
	iput(inode);

	RETURN(rc);
}

/*
 * Index delete funtion.
 * It will remove the directory entry added by index insert.
 * This entry is needed to maintain name->fid mapping.
 */
static int osd_index_dir_delete(const struct lu_env *env, struct dt_object *dt,
				const struct dt_key *key, struct thandle *th)
{
	struct osd_object *pobj = osd_dt_obj(dt);
	struct inode *dir = pobj->oo_inode;
	char *name = (char *)key;
	struct dentry *parent;
	struct dentry *dentry;
	struct inode *inode;
	struct qstr qstr;
	bool nedir_rename = false;
	int rc = 0;

	ENTRY;

	/* Skip "." and ".." in MemFS. */
	if (name[0] == '.' && (name[1] == '\0' ||
			       (name[1] == '.' && name[2] == '\0')))
		RETURN(0);

	parent = d_find_any_alias(dir);
	if (parent == NULL && strcmp(name, "..") == 0) {
		CDEBUG(D_CACHE, "%s: delete name %s from an empty dir@%pK\n",
		       osd_name(osd_obj2dev(pobj)), name, dir);
		RETURN(0);
	}

	if (parent == NULL) {
		CDEBUG(D_CACHE, "%s: delete name %s from an empty dir@%pK\n",
		       osd_name(osd_obj2dev(pobj)), name, dir);
		RETURN(-ENOENT);
	}

	LASSERTF(parent != NULL, "dir@%pK name %s\n", dir, name);

	qstr.name = name;
	qstr.len = strlen(name);
	qstr.hash = ll_full_name_hash(parent, qstr.name, qstr.len);
	dentry = d_lookup(parent, &qstr);
	if (dentry == NULL) {
		CDEBUG(D_CACHE, "%s: cannot find %s from parent@%pK %pd\n",
		       osd_name(osd_obj2dev(pobj)), name, dir, parent);
		GOTO(out_dput_parent, rc = -ENOENT);
	}

	LASSERT(dentry != NULL);
	inode = d_inode(dentry);

	switch (inode->i_mode & S_IFMT) {
	case S_IFDIR:
		/*
		 * FIXME: rename() operation, @dentry may be not empty:
		 * (sanity/214).
		 * TODO: Put @dir_rename and @dentry into OSD thread info.
		 */
		if (!simple_empty(dentry))
			nedir_rename = true;

		/*
		 * MDD layer drops @nlink later via @dt_ref_del().
		 * drop_nlink(inode);
		 * drop_nlink(dir);
		 */
		fallthrough;
	case S_IFREG:
	case S_IFLNK:
		dir->i_size -= BOGO_DIRENT_SIZE;
		inode_set_mtime_to_ts(dir, inode_set_ctime_current(dir));
		inode_set_mtime_to_ts(dir, inode_set_ctime_to_ts(dir,
					inode_set_ctime_current(inode)));
		inode_inc_iversion(dir);
		/* MDD layer drops @nlink later via @dt_ref_del(). */
		/* drop_nlink(inode); */
		/*
		 * Undo the count from "create".
		 * Unhash the dentry from the parent dentry hashtable which is
		 * add by @d_add(), so that it would not be found through a VFS
		 * lookup anymore.
		 * Unpin/drop the dentry from dcache.
		 */
		if (!nedir_rename)
			dput(dentry);
		break;
	default:
		LBUG();
	}

	CDEBUG(D_CACHE,
	       "%s: Delete %s from dir@%pK %pd inode@%pK nlink=%d %d: rc=%d.\n",
	       osd_name(osd_obj2dev(pobj)), name, dir, parent, inode,
	       inode->i_nlink, dentry->d_lockref.count, rc);
	dput(dentry);
out_dput_parent:
	dput(parent);
	RETURN(rc);
}

static struct osd_it *
__osd_dir_it_init(const struct lu_env *env, struct osd_device *dev,
		  struct inode *inode, u32 attr)
{
	struct osd_it *oit;
	struct file *file;
	int rc;

	ENTRY;

	OBD_SLAB_ALLOC_PTR_GFP(oit, osd_it_cachep, GFP_NOFS);
	if (oit == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	/* TODO: store buffer as thread context data @osd_thread_info. */
	OBD_ALLOC(oit->oit_buf, OSD_IT_BUFSIZE);
	if (!oit->oit_buf)
		GOTO(out_free, rc = -ENOMEM);

	oit->oit_obj = NULL;
	file = &oit->oit_file;
	/* Only FMODE_64BITHASH or FMODE_32BITHASH should be set, NOT both. */
	if (attr & LUDA_64BITHASH)
		file->f_mode |= FMODE_64BITHASH;
	else
		file->f_mode |= FMODE_32BITHASH;
	file->f_path.dentry = d_find_any_alias(inode);
	file->f_flags = O_NOATIME | __FMODE_NONOTIFY;
	file->f_mapping = inode->i_mapping;
	file->f_op = inode->i_fop;
	file->f_inode = inode;

	if (file->f_op->open) {
		rc = file->f_op->open(inode, file);
		if (rc) {
			dput(file->f_path.dentry);
			GOTO(out_free, rc);
		}
	}

	RETURN(oit);

out_free:
	OBD_SLAB_FREE_PTR(oit, osd_it_cachep);
	return ERR_PTR(rc);
}

/**
 * osd_dir_it_init() - Creates or initializes iterator context.
 *
 * Returns: struct osd_it, iterator structure on success
 */
static struct dt_it *osd_dir_it_init(const struct lu_env *env,
				     struct dt_object *dt, __u32 attr)
{
	struct osd_object *obj = osd_dt_obj(dt);
	struct osd_device *dev = osd_obj2dev(obj);
	struct lu_object *lo = &dt->do_lu;
	struct osd_it *oit;

	ENTRY;

	if (!dt_object_exists(dt) || obj->oo_destroyed)
		RETURN(ERR_PTR(-ENOENT));

	oit = __osd_dir_it_init(env, dev, obj->oo_inode, attr);
	if (IS_ERR(oit))
		RETURN(ERR_CAST(oit));

	oit->oit_obj = obj;
	lu_object_get(lo);
	RETURN((struct dt_it *)oit);
}

/**
 * osd_dir_it_fini() - Destroy or finishes iterator context.
 * @di: iterator structure to be destroyed
 */
static void osd_dir_it_fini(const struct lu_env *env, struct dt_it *di)
{
	struct osd_it *oit = (struct osd_it *)di;
	struct osd_object *obj = oit->oit_obj;
	struct inode *inode = obj->oo_inode;

	ENTRY;

	dput(oit->oit_file.f_path.dentry);
	oit->oit_file.f_op->release(inode, &oit->oit_file);
	OBD_FREE(oit->oit_buf, OSD_IT_BUFSIZE);
	OBD_SLAB_FREE_PTR(oit, osd_it_cachep);

	osd_object_put(env, obj);

	EXIT;
}


/*
 * It position the iterator at given key, so that next lookup continues from
 * that key Or it is similar to dio_it->load() but based on a key,
 * rather than file position.
 *
 * As a special convention, osd_it_ea_get(env, di, "") has to rewind iterator
 * to the beginning.
 *
 * TODO: Presently return 1 considering it is only used by mdd_dir_is_empty().
 */
static int osd_dir_it_get(const struct lu_env *env,
			  struct dt_it *di, const struct dt_key *key)
{
	struct osd_it *it = (struct osd_it *)di;
	struct file *file = &it->oit_file;

	ENTRY;

	LASSERT(((const char *)key)[0] == '\0');
	if (file->f_op->llseek) {
		loff_t offset;

		offset = file->f_op->llseek(file, 0, 0);
		if (offset != 0)
			CWARN("Failed to llseek(): offset %lld != 0\n", offset);
	} else {
		it->oit_file.f_pos = 0;
	}

	it->oit_rd_dirent = 0;
	it->oit_it_dirent = 0;
	it->oit_dirent = NULL;

	RETURN(1);
}

/* Does nothing */
static void osd_dir_it_put(const struct lu_env *env, struct dt_it *di)
{
}

/**
 * osd_memfs_filldir() - It is called internally by ->iterate*()
 * @buf: in which information to be filled in.
 * @name: name of the file in given dir
 *
 * It fills the iterator's in-memory data structure with required
 * information i.e. name, namelen, rec_size etc.
 *
 * Returns:
 * * %0 - on success
 * * %1 - on buffer full
 */
#ifdef HAVE_FILLDIR_USE_CTX
static FILLDIR_TYPE do_osd_memfs_filldir(struct dir_context *ctx,
#else
static int osd_memfs_filldir(void *ctx,
#endif
			     const char *name, int namelen,
			     loff_t offset, __u64 ino, unsigned int d_type)
{
	struct memfs_dir_context *mctx = (struct memfs_dir_context *)ctx;
	struct osd_it *oit = (struct osd_it *)mctx->cbdata;
	struct osd_object *obj = oit->oit_obj;
	struct osd_it_dirent *ent = oit->oit_dirent;
	struct lu_fid *fid = &ent->oitd_fid;
	char *buf = oit->oit_buf;

	ENTRY;

	/* This should never happen */
	if (unlikely(namelen == 0 || namelen > NAME_MAX)) {
		CERROR("MemFS return invalid namelen %d\n", namelen);
		RETURN(-EIO);
	}

	/* Check for enough space. Note oitd_name is not NUL terminated. */
	if (&ent->oitd_name[namelen] > buf + OSD_IT_BUFSIZE)
		RETURN(1);

	/* "." is just the object itself. */
	if (namelen == 1 && name[0] == '.') {
		if (obj != NULL)
			*fid = obj->oo_dt.do_lu.lo_header->loh_fid;
	} else if (namelen == 2 && name[0] == '.' && name[1] == '.') {
		if (obj != NULL) {
			struct inode *inode = obj->oo_inode;
			struct dentry *dentry;
			struct dentry *parent;

			LASSERT(S_ISDIR(inode->i_mode));
			dentry = d_find_any_alias(inode);
			parent = dentry->d_parent;
			*fid = MEMFS_I(d_inode(parent))->mei_fid;
			dput(dentry);
		}
	} else if (mctx->dentry) {
		*fid = MEMFS_I(d_inode(mctx->dentry))->mei_fid;
	} else {
		fid_zero(fid);
	}

	/* NOT export local root. */
	if (obj != NULL &&
	    unlikely(osd_sb(osd_obj2dev(obj))->s_root->d_inode->i_ino == ino)) {
		ino = obj->oo_inode->i_ino;
		*fid = obj->oo_dt.do_lu.lo_header->loh_fid;
	}

	if (obj == NULL || !(obj->oo_lma_flags & LUSTRE_ENCRYPT_FL)) {
		ent->oitd_namelen = namelen;
		memcpy(ent->oitd_name, name, namelen);
	} else {
		int encoded_namelen = critical_chars(name, namelen);

		/* Check again for enough space. */
		if (&ent->oitd_name[encoded_namelen] > buf + OSD_IT_BUFSIZE)
			RETURN(1);

		ent->oitd_namelen = encoded_namelen;

		if (encoded_namelen == namelen)
			memcpy(ent->oitd_name, name, namelen);
		else
			critical_encode(name, namelen, ent->oitd_name);
	}

	ent->oitd_ino = ino;
	ent->oitd_off = offset;
	ent->oitd_type = d_type;

	oit->oit_rd_dirent++;
	oit->oit_dirent = (void *)ent +
			  round_up(sizeof(*ent) + ent->oitd_namelen, 8);
	CDEBUG(D_DENTRY, "Filldir: fid="DFID" name=%s off=%llu rd_dirent=%u\n",
	       PFID(fid), name, offset, oit->oit_rd_dirent);
	RETURN(0);
}

WRAP_FILLDIR_FN(do_, osd_memfs_filldir)

/**
 * osd_memfs_it_fill() - Calls ->iterate*() to load a directory entry at
 * a time and stored it in iterator's in-memory data structure.
 * @di: iterator's in memory structure
 *
 * Returns:
 * * %0 - on success
 * * %-ve - on error
 * * %1 - reach the end of entry
 */
static int osd_memfs_it_fill(const struct lu_env *env, const struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;
	struct file *filp = &it->oit_file;
	struct inode *dir = file_inode(filp);
	struct memfs_dir_context mctx = {
		.super.actor = osd_memfs_filldir,
		.dentry = NULL,
		.cbdata = it
	};
	int rc = 0;

	ENTRY;

	it->oit_dirent = it->oit_buf;
	it->oit_rd_dirent = 0;

#ifdef HAVE_FOP_ITERATE_SHARED
	inode_lock_shared(dir);
#else
	inode_lock(dir);
#endif
	if (!IS_DEADDIR(dir)) {
		if (filp->f_op->iterate_shared) {
			mctx.super.pos = filp->f_pos;
			rc = filp->f_op->iterate_shared(filp, &mctx.super);
			filp->f_pos = mctx.super.pos;
		} else {
#ifdef HAVE_FOP_READDIR
			rc = filp->f_op->readdir(filp, &mctx.super,
						 mctx.super.actor);
			mctx.super.pos = filp->f_pos;
#else
			rc = -ENOTDIR;
#endif
		}
	}
#ifdef HAVE_FOP_ITERATE_SHARED
	inode_unlock_shared(dir);
#else
	inode_unlock(dir);
#endif
	if (rc)
		RETURN(rc);

	if (it->oit_rd_dirent == 0) {
		/*
		 * If it does not get any dirent, it means it has been reached
		 * to the end of the dir
		 */
		it->oit_file.f_pos = MEMFS_DIR_EOF;
		rc = 1;
	} else {
		it->oit_dirent = it->oit_buf;
		it->oit_it_dirent = 1;
	}

	RETURN(rc);
}

/**
 * osd_dir_it_next() - It calls osd_memfs_it_fill() which will use
 * ->iterate*() to load a directory entry at a time and stored it in
 * iterator's in-memory data structure.
 * @di: iterator's in memory structure
 *
 * Returns:
 * * %ve - iterator reached to end
 * * %0 - iterator not reached to end
 * * %-ve - on error
 */
static int osd_dir_it_next(const struct lu_env *env, struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;
	int rc;

	ENTRY;

	if (it->oit_it_dirent < it->oit_rd_dirent) {
		it->oit_dirent =
			(void *)it->oit_dirent +
			round_up(sizeof(struct osd_it_dirent) +
				       it->oit_dirent->oitd_namelen, 8);
		it->oit_it_dirent++;
		rc = 0;
	} else {
		if (it->oit_file.f_pos == MEMFS_DIR_EOF)
			rc = 1;
		else
			rc = osd_memfs_it_fill(env, di);
	}

	RETURN(rc);
}

/**
 * osd_dir_it_key() - Returns the key at current position from
 * iterator's in memory structure.
 * @di: iterator's in memory structure
 *
 * Returns: key i.e. struct dt_key on success
 */
static struct dt_key *osd_dir_it_key(const struct lu_env *env,
				     const struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;

	return (struct dt_key *)it->oit_dirent->oitd_name;
}

/**
 * osd_dir_it_key_size() - Returns key's size at current position
 * from iterator's in memory structure.
 * @di: iterator's in memory structure
 *
 * Returns: key_size i.e. struct dt_key on success
 */
static int osd_dir_it_key_size(const struct lu_env *env, const struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;

	return it->oit_dirent->oitd_namelen;
}

static inline void
osd_it_append_attrs(struct lu_dirent *ent, int len, __u16 type)
{
	/* check if file type is required */
	if (ent->lde_attrs & LUDA_TYPE) {
		struct luda_type *lt;
		int align = sizeof(*lt) - 1;

		len = (len + align) & ~align;
		lt = (struct luda_type *)(ent->lde_name + len);
		lt->lt_type = cpu_to_le16(DTTOIF(type));
	}

	ent->lde_attrs = cpu_to_le32(ent->lde_attrs);
}

/*
 * build lu direct from backend fs dirent.
 */
static inline void
osd_it_pack_dirent(struct lu_dirent *ent, struct lu_fid *fid, __u64 offset,
		   char *name, __u16 namelen, __u16 type, __u32 attr)
{
	ent->lde_attrs = attr | LUDA_FID;
	fid_cpu_to_le(&ent->lde_fid, fid);

	ent->lde_hash = cpu_to_le64(offset);
	ent->lde_reclen = cpu_to_le16(lu_dirent_calc_size(namelen, attr));

	strncpy(ent->lde_name, name, namelen);
	ent->lde_name[namelen] = '\0';
	ent->lde_namelen = cpu_to_le16(namelen);

	/* append lustre attributes */
	osd_it_append_attrs(ent, namelen, type);
}

/**
 * osd_dir_it_rec() - Returns the value at current position from
 * iterator's in memory structure.
 * @di:	struct osd_it, iterator's in memory structure
 * @dtrec: lustre dirent
 * @attr: attr requested for dirent.
 *
 * Returns:
 * %0 - no error and \param lde has correct lustre dirent.
 * %-ve - on error
 */
static inline int osd_dir_it_rec(const struct lu_env *env,
				 const struct dt_it *di,
				 struct dt_rec *dtrec, __u32 attr)
{
	struct osd_it *it = (struct osd_it *)di;
	struct lu_fid *fid = &it->oit_dirent->oitd_fid;
	struct lu_dirent *lde = (struct lu_dirent *)dtrec;

	ENTRY;

	/* TODO: lfsck checking support.*/

	attr &= ~LU_DIRENT_ATTRS_MASK;
	/* Pack the entry anyway, at least the offset is right. */
	osd_it_pack_dirent(lde, fid, it->oit_dirent->oitd_off,
			   it->oit_dirent->oitd_name,
			   it->oit_dirent->oitd_namelen,
			   it->oit_dirent->oitd_type, attr);

	RETURN(0);
}

/**
 * osd_dir_it_rec_size() - Returns the record size at current position.
 * @env: execution environment
 * @di: iterator's in memory structure
 * @attr: attribute of the entry, only requires LUDA_TYPE to
 *        calculate the lu_dirent size.
 *
 * This function will return record(lu_dirent) size in bytes.
 *
 * Returns: record size(in bytes & in memory) of the current lu_dirent
 *          entry.
 */
static int osd_dir_it_rec_size(const struct lu_env *env, const struct dt_it *di,
			       __u32 attr)
{
	struct osd_it *it = (struct osd_it *)di;

	return lu_dirent_calc_size(it->oit_dirent->oitd_namelen, attr);
}

/**
 * osd_dir_it_store() - Returns a cookie for current position of the iterator
 * head, so that user can use this cookie to load/start the iterator next
 * time.
 * @di: iterator's in memory structure
 *
 * Returns: cookie for current position, on success
 */
static __u64 osd_dir_it_store(const struct lu_env *env, const struct dt_it *di)
{
	struct osd_it *it = (struct osd_it *)di;

	return it->oit_dirent->oitd_off;
}

/**
 * osd_dir_it_load() - It calls osd_memfs_it_fill() which will use
 * ->iterate*() to load a directory entry at a time and stored it
 * in iterator's in-memory data structure.
 * @di: struct osd_it, iterator's in memory structure
 *
 * Returns:
 * * %ve - on success
 * * %-ve - on error
 */
static int osd_dir_it_load(const struct lu_env *env,
			   const struct dt_it *di, __u64 hash)
{
	struct osd_it *it = (struct osd_it *)di;
	struct file *file = &it->oit_file;
	loff_t offset;
	int rc;

	ENTRY;

	if (file->f_op->llseek) {
		offset = file->f_op->llseek(file, hash, 0);
		if (offset != hash)
			CWARN("Failed to llseek(): offset %lld != hash %llu\n",
			      offset, hash);
	} else {
		it->oit_file.f_pos = hash;
	}

	rc = osd_memfs_it_fill(env, di);
	if (rc > 0)
		rc = -ENODATA;

	if (rc == 0)
		rc = 1;

	RETURN(rc);
}

const struct dt_index_operations osd_dir_ops = {
	.dio_lookup		= osd_index_dir_lookup,
	.dio_insert		= osd_index_dir_insert,
	.dio_delete		= osd_index_dir_delete,
	.dio_it = {
		.init		= osd_dir_it_init,
		.fini		= osd_dir_it_fini,
		.get		= osd_dir_it_get,
		.put		= osd_dir_it_put,
		.next		= osd_dir_it_next,
		.key		= osd_dir_it_key,
		.key_size	= osd_dir_it_key_size,
		.rec		= osd_dir_it_rec,
		.rec_size	= osd_dir_it_rec_size,
		.store		= osd_dir_it_store,
		.load		= osd_dir_it_load
	}
};
