/*
 *      	An implementation of a loadable kernel mode driver providing
 *		multiple kernel/user space bidirectional communications links.
 *
 * 		Author: 	Alan Cox <alan@cymru.net>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 * 
 *              Adapted to become the Linux 2.0 Coda pseudo device
 *              Peter  Braam  <braam@maths.ox.ac.uk> 
 *              Michael Callahan <mjc@emmy.smith.edu>           
 *
 *              Changes for Linux 2.1
 *              Copyright (c) 1997 Carnegie-Mellon University
 *
 *              Redone again for Intermezzo
 *              Copyright (c) 1998 Peter J. Braam
 *
 *              Hacked up again for simulated OBD
 *              Copyright (c) 1999 Stelias Computing, Inc.
 *                (authors {pschwan,braam}@stelias.com)
 *              Copyright (C) 1999 Seagate Technology, Inc.
 *
 * 
 */

#define EXPORT_SYMTAB

#include <linux/config.h> /* for CONFIG_PROC_FS */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/sched.h>
#include <linux/lp.h>
#include <linux/malloc.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/list.h>
#include <asm/io.h>
#include <asm/segment.h>
#include <asm/system.h>
#include <asm/poll.h>
#include <asm/uaccess.h>

#include <linux/obd_support.h>
#include <linux/obd_class.h>

static int obd_init_magic;
int           obd_print_entry = 1;
int           obd_debug_level = 4095;
struct obd_device obd_dev[MAX_OBD_DEVICES];
struct list_head obd_types;

/* called when opening /dev/obdNNN */
static int obd_class_open(struct inode * inode, struct file * file)
{
	int dev;
        ENTRY;

	if (!inode)
		return -EINVAL;
	dev = MINOR(inode->i_rdev);
	if (dev >= MAX_OBD_DEVICES)
		return -ENODEV;
	obd_dev[dev].obd_refcnt++;
	CDEBUG(D_PSDEV, "Refcount now %d\n", obd_dev[dev].obd_refcnt);

        MOD_INC_USE_COUNT;
        EXIT;
        return 0;
}

/* called when closing /dev/obdNNN */
static int obd_class_release(struct inode * inode, struct file * file)
{
	int dev;
        ENTRY;

	if (!inode)
		return -EINVAL;
	dev = MINOR(inode->i_rdev);
	if (dev >= MAX_OBD_DEVICES)
		return -ENODEV;
	fsync_dev(inode->i_rdev);
	if (obd_dev[dev].obd_refcnt <= 0)
		printk(KERN_ALERT "obd_class_release: refcount(%d) <= 0\n",
		       obd_dev[dev].obd_refcnt);
	obd_dev[dev].obd_refcnt--;

	CDEBUG(D_PSDEV, "Refcount now %d\n", obd_dev[dev].obd_refcnt);
        MOD_DEC_USE_COUNT;

        EXIT;
        return 0;
}

/* support function */
static struct obd_type *obd_nm_to_type(char *nm) 
{
	struct list_head *tmp;
	struct obd_type *type;
	CDEBUG(D_IOCTL, "SEARCH %s\n", nm);
	
	tmp = &obd_types;
	while ( (tmp = tmp->next) != &obd_types ) {
		type = list_entry(tmp, struct obd_type, typ_chain);
		CDEBUG(D_IOCTL, "TYP %s\n", type->typ_name);
		if (strlen(type->typ_name) == strlen(nm) &&
		    strcmp(type->typ_name, nm) == 0 ) {
			return type;
		}
	}
	return NULL;
}


static int getdata(int len, void **data)
{
	void *tmp = NULL;

	if (!len) 
		return 0;

	CDEBUG(D_IOCTL, "getdata: len %d, add %p\n", len, *data);

	OBD_ALLOC(tmp, void *, len);
	if ( !tmp )
		return -ENOMEM;
	
	memset(tmp, 0, len);
	if ( copy_from_user(tmp, *data, len)) {
		OBD_FREE(tmp,len);
		return -EFAULT;
	}
	*data = tmp;

	return 0;
}

/* to control /dev/obdNNN */
static int obd_class_ioctl (struct inode * inode, struct file * filp, 
			    unsigned int cmd, unsigned long arg)
{
	int err, i_ino, dev;
	struct obd_device *obddev;
	struct obd_conn conn;
	long int cli_id; /* connect, disconnect */

	if (!inode)
		return -EINVAL;

	dev = MINOR(inode->i_rdev);
	if (dev > MAX_OBD_DEVICES)
		return -ENODEV;
	obddev = &obd_dev[dev];
	conn.oc_dev = obddev;

	switch (cmd) {
	case TCGETS:
		return -EINVAL;
	case OBD_IOC_ATTACH: {
		struct obd_type *type;
		struct oic_generic input;

		/* have we attached a type to this device */
		if ( obddev->obd_type || (obddev->obd_flags & OBD_ATTACHED) ){
			CDEBUG(D_IOCTL, "OBD Device %d already attached to type %s.\n", dev, obddev->obd_type->typ_name);
			return -EINVAL;
		}

		/* get data structures */
		err = copy_from_user(&input, (void *) arg, sizeof(input));
		if (err)
			return err;

		if ( (err = getdata(input.att_typelen + 1, &input.att_type)) )
			return err;

		/* find the type */
		err = -EINVAL;
		type = obd_nm_to_type(input.att_type);
		OBD_FREE(input.att_type, input.att_typelen + 1);
		if ( !type ) {
			printk("Unknown obd type dev %d\n", dev);
			return err;
		}
		obddev->obd_type = type;
		
		/* get the attach data */
		if ( (err = getdata(input.att_datalen, &input.att_data)) ) {
			return err;
		}

		INIT_LIST_HEAD(&obddev->obd_gen_clients);
		obddev->obd_multi_count = 0;

		CDEBUG(D_IOCTL, "Attach %d,  datalen %d, type %s\n", 
		       dev, input.att_datalen, obddev->obd_type->typ_name);
		if (!obddev->obd_type->typ_ops || !OBP(obddev,attach)) {
			obddev->obd_flags |=  OBD_ATTACHED;
			type->typ_refcnt++;
			MOD_INC_USE_COUNT;
			return 0;
		}

		/* do the attach */
		err = OBP(obddev,attach)(obddev,  
					 input.att_datalen, input.att_data);
		OBD_FREE(input.att_data, input.att_datalen);

		if ( err ) {
			obddev->obd_flags &= ~OBD_ATTACHED;
			obddev->obd_type = NULL;
		} else {
			obddev->obd_flags |=  OBD_ATTACHED;
			type->typ_refcnt++;
			MOD_INC_USE_COUNT;
		}
		return err;
	}

	case OBD_IOC_DETACH: {

		if (obddev->obd_flags & OBD_SET_UP)
			return -EINVAL;
		if (! (obddev->obd_flags & OBD_ATTACHED) )
			return -EINVAL;
		if ( !list_empty(&obddev->obd_gen_clients) ) 
			return -EINVAL;

		obddev->obd_flags &= ~OBD_ATTACHED;
		obddev->obd_type->typ_refcnt--;
		obddev->obd_type = NULL;
		MOD_DEC_USE_COUNT;
		return 0;
	}


	case OBD_IOC_FORMAT: {
		struct ioc_format {
			int format_datalen;
			void *format_data;
		} input;

		/* have we attached a type to this device */
		if ( !obddev->obd_type ) {
			CDEBUG(D_IOCTL, "OBD Device %d has no type.\n", dev);
			return -EINVAL;
		}

		/* get main structure */
		err = copy_from_user(&input, (void *) arg, sizeof(input));
		if (err) 
			return err;

		err = getdata(input.format_datalen, &input.format_data);
		if (err) 
			return err;

		if (!obddev->obd_type->typ_ops || 
		    !obddev->obd_type->typ_ops->o_format )
			return -EOPNOTSUPP;

		/* do the format */
		CDEBUG(D_IOCTL, "Format %d, type %s\n", dev, 
		       obddev->obd_type->typ_name);
		err = obddev->obd_type->typ_ops->o_format
			(obddev, input.format_datalen, input.format_data);

		OBD_FREE(input.format_data, input.format_datalen);
		return err;
	}
	case OBD_IOC_PARTITION: {
		struct ioc_part {
			int part_datalen;
			void *part_data;
		} input;

		/* have we attached a type to this device */
		if ( !obddev->obd_type ) {
			CDEBUG(D_IOCTL, "OBD Device %d has no type.\n", dev);
			return -EINVAL;
		}

		/* get main structure */
		err = copy_from_user(&input, (void *) arg, sizeof(input));
		if (err) 
			return err;

		err = getdata(input.part_datalen, &input.part_data);
		if (err) 
			return err;

		if (!obddev->obd_type->typ_ops || 
		    !obddev->obd_type->typ_ops->o_partition )
			return -EOPNOTSUPP;

		/* do the partition */
		CDEBUG(D_IOCTL, "Partition %d, type %s\n", dev, 
		       obddev->obd_type->typ_name);
		err = obddev->obd_type->typ_ops->o_partition
			(obddev, input.part_datalen, input.part_data);

		OBD_FREE(input.part_data, input.part_datalen);
		return err;
	}

	case OBD_IOC_COPY: {
		struct ioc_mv_s mvdata;
		struct ioc_part {
			int part_datalen;
			void *part_data;
		} input;
		obdattr *srcoa, *tgtoa;

		if ( (!(obddev->obd_flags & OBD_SET_UP)) ||
		     (!(obddev->obd_flags & OBD_ATTACHED))) {
			CDEBUG(D_IOCTL, "Device not attached or set up\n");
			return -EINVAL;
		}

		/* get main structure */
		err = copy_from_user(&input, (void *) arg, sizeof(input));
		if (err) 
			return err;


		err = copy_from_user(&mvdata, input.part_data, sizeof(mvdata));
		if (err) 
			return err;

		if (!obddev->obd_type->typ_ops || 
		    !obddev->obd_type->typ_ops->o_copy )
			return -EOPNOTSUPP;

		/* do the partition */
		CDEBUG(D_IOCTL, "Copy %d, type %s src %ld tgt %ld\n", dev, 
		       obddev->obd_type->typ_name, mvdata.src, mvdata.tgt);

		conn.oc_id = mvdata.conn_id;
		srcoa = obd_oa_fromid(&conn, mvdata.src);
		if ( !srcoa ) 
			return -ENOENT;
		tgtoa = obd_oa_fromid(&conn, mvdata.tgt);
		if ( ! tgtoa ) {
			obd_free_oa(srcoa);
			return -ENOMEM;
		}

		err = obddev->obd_type->typ_ops->o_copy(&conn,srcoa, tgtoa);

		obd_free_oa(srcoa);
		obd_free_oa(tgtoa);
		return err;
	}
	case OBD_IOC_MIGR: {
		struct ioc_mv_s mvdata;
		struct ioc_part {
			int part_datalen;
			void *part_data;
		} input;
		obdattr *srcoa, *tgtoa;

		if ( (!(obddev->obd_flags & OBD_SET_UP)) ||
		     (!(obddev->obd_flags & OBD_ATTACHED))) {
			CDEBUG(D_IOCTL, "Device not attached or set up\n");
			return -EINVAL;
		}

		/* get main structure */
		err = copy_from_user(&input, (void *) arg, sizeof(input));
		if (err) 
			return err;


		CDEBUG(D_IOCTL, "Migrate copying %d\n", sizeof(mvdata));
		err = copy_from_user(&mvdata, input.part_data, sizeof(mvdata));
		if (err) 
			return err;

		if (!obddev->obd_type->typ_ops || 
		    !obddev->obd_type->typ_ops->o_copy )
			return -EOPNOTSUPP;

		/* do the partition */
		CDEBUG(D_IOCTL, "Migrate %d, type %s conn %d src %ld tgt %ld\n", dev, 
		       obddev->obd_type->typ_name, mvdata.conn_id, mvdata.src, mvdata.tgt);


		if ( ! (srcoa = obd_empty_oa()) ) 
			return -ENOMEM;
		if ( ! (tgtoa = obd_empty_oa()) ) {
			obd_free_oa(srcoa);
			return -ENOMEM;
		}

		srcoa->i_ino = mvdata.src;
		tgtoa->i_ino = mvdata.tgt;

		conn.oc_id = mvdata.conn_id;

		err = obddev->obd_type->typ_ops->o_migrate(&conn, tgtoa, srcoa);

		obd_free_oa(srcoa);
		obd_free_oa(tgtoa);
		return err;
	}

	case OBD_IOC_SETUP: {
		struct ioc_setup {
			int setup_datalen;
			void *setup_data;
		} input;

		/* have we attached a type to this device */
		if (!(obddev->obd_flags & OBD_ATTACHED)) {
			CDEBUG(D_IOCTL, "OBD Device %d has no type.\n", dev);
			return -EINVAL;
		}

		/* has this been done already? */
		if ( obddev->obd_flags & OBD_SET_UP ) {
			CDEBUG(D_IOCTL, "Device %d already setup (type %s)\n",
			       dev, obddev->obd_type->typ_name);
			return -EINVAL;
		}

		/* get main structure */
		err = copy_from_user(&input, (void *) arg, sizeof(input));
		if (err) 
			return err;

		err = getdata(input.setup_datalen, &input.setup_data);
		if (err) 
			return err;


		/* do the setup */
		CDEBUG(D_IOCTL, "Setup %d, type %s\n", dev, 
		       obddev->obd_type->typ_name);
		if ( !obddev->obd_type->typ_ops || 
		     !obddev->obd_type->typ_ops->o_setup ) {
			obddev->obd_flags |= OBD_SET_UP;
			return 0;
		}

		err = obddev->obd_type->typ_ops->o_setup
			(obddev, input.setup_datalen, input.setup_data);

		if ( err ) 
			obddev->obd_flags &= ~OBD_SET_UP;
		else {
			obddev->obd_type->typ_refcnt++;
			obddev->obd_flags |= OBD_SET_UP;
		}
		return err;
	}
	case OBD_IOC_CLEANUP: {
		int rc;

		/* has this minor been registered? */
		if (!obddev->obd_type)
			return -ENODEV;

		if ( !obddev->obd_type->typ_refcnt ) 
			printk("OBD_CLEANUP: refcount wrap!\n");

		if ( !obddev->obd_flags & OBD_SET_UP ) 
			return -EINVAL;

		if ( !obddev->obd_type->typ_ops->o_cleanup )
			goto cleanup_out;

		/* cleanup has no argument */
		rc = OBP(obddev, cleanup)(obddev);
		if ( rc )
			return rc;

	cleanup_out: 
		obddev->obd_flags &= ~OBD_SET_UP;
		obddev->obd_type->typ_refcnt--;
		return 0;
	}
	case OBD_IOC_CONNECT:
	{

		if ( (!(obddev->obd_flags & OBD_SET_UP)) ||
		     (!(obddev->obd_flags & OBD_ATTACHED))) {
			CDEBUG(D_IOCTL, "Device not attached or set up\n");
			return -EINVAL;
		}

		
		if (obddev->obd_type->typ_ops->o_connect(&conn))
			return -EINVAL;

		return copy_to_user((int *)arg, &conn.oc_id,
				    sizeof(int));
	}
	case OBD_IOC_DISCONNECT:
		/* frees data structures */
		/* has this minor been registered? */
		if (!obddev->obd_type)
			return -ENODEV;

		get_user(cli_id, (int *) arg);
		conn.oc_id = cli_id;

		OBP(obddev, disconnect)(&conn);
		return 0;

	case OBD_IOC_SYNC: {
		/* sync doesn't need a connection ID, because it knows
		 * what device it was called on, and can thus get the
		 * superblock that it needs. */
		/* has this minor been registered? */
		if (!obddev->obd_type)
			return -ENODEV;

		if (!obddev->u.ext2.ext2_sb || !obddev->u.ext2.ext2_sb->s_dev) {
			CDEBUG(D_IOCTL, "fatal: device not initialized.\n");
			err = -EINVAL;
		} else {
			if ((err = fsync_dev(obddev->u.ext2.ext2_sb->s_dev)))
				CDEBUG(D_IOCTL, "sync: fsync_dev failure\n");
			else
				CDEBUG(D_IOCTL, "sync: success\n");
		}

		return put_user(err, (int *) arg);
	}
	case OBD_IOC_CREATE: {
		int err;
		struct oic_create_s foo;

		if ( copy_from_user(&foo, (const void *)arg, sizeof(foo)) )
			return -EFAULT;

		/* has this minor been registered? */
		if ( !(obddev->obd_flags & OBD_ATTACHED) ||
		     !(obddev->obd_flags & OBD_SET_UP))
			return -ENODEV;
		conn.oc_id = foo.conn_id;

		i_ino = OBP(obddev, create)(&conn, foo.prealloc, &err);
		if (err) {
			CDEBUG(D_IOCTL, "create: obd_inode_new failure\n");
			/* 0 is the only error value */
			return put_user(0, (int *) arg);
		}

		return put_user(i_ino, (int *) arg);
	}
	case OBD_IOC_DESTROY:
	{
		struct destroy_s {
			unsigned int conn_id;
			unsigned int ino;
		} destroy;
		obdattr *oa;
		int rc;
		
		if ( ! (oa = obd_empty_oa()) ) 
			return -ENOMEM;

		/* has this minor been registered? */
		if (!obddev->obd_type)
			return -ENODEV;


		copy_from_user(&destroy, (int *)arg, sizeof(struct destroy_s));
		if ( !obddev->obd_type ||
		     !obddev->obd_type->typ_ops->o_destroy)
			return -EINVAL;

		oa->i_ino = destroy.ino;
		conn.oc_id = destroy.conn_id;
		rc = obddev->obd_type->typ_ops->o_destroy(&conn, oa);
		OBD_FREE(oa, sizeof(*oa));
		return rc;
	}
	case OBD_IOC_SETATTR:
	{
		struct oic_attr_s foo;
		obdattr *oa;
		int rc;

		if ( ! (oa = obd_empty_oa()) ) 
			return -ENOMEM;

		/* has this minor been registered? */
		if (!obddev->obd_type)
			return -ENODEV;

		rc = copy_from_user(&foo, (int *)arg, sizeof(foo));
		if (rc)
			return rc;

		if ( !obddev->obd_type ||
		     !obddev->obd_type->typ_ops->o_setattr)
			return -EINVAL;
		
		oa->i_ino = foo.ino;
		inode_setattr(oa, &foo.iattr);
		conn.oc_id = foo.conn_id;
		rc = obddev->obd_type->typ_ops->o_setattr(&conn, oa);
		OBD_FREE(oa, sizeof(*oa));
		return rc;
	}

	case OBD_IOC_GETATTR:
	{
		int rc;
		struct oic_getattr {
			unsigned int conn_id;
			unsigned long ino;
		} foo;
		struct iattr iattr;
		obdattr *oa;

		rc = copy_from_user(&foo, (int *)arg, sizeof(foo));
		if (rc)
			return rc;

		conn.oc_id = foo.conn_id;
		oa = obd_oa_fromid(&conn, foo.ino);
		if ( !oa ) 
			return -ENOENT;

		inode_to_iattr(oa, &iattr);
		rc = copy_to_user((int *)arg, &iattr, sizeof(iattr));
		return rc;
	}

	case OBD_IOC_READ:
	{
		obdattr *oa = NULL;
		int rc;
		struct oic_rw_s rw_s;  /* read, write ioctl str */

		rc = copy_from_user(&rw_s, (int *)arg, sizeof(rw_s));
		if ( rc ) 
			goto READ_OUT;

		
		conn.oc_id = rw_s.conn_id;
		if ( ! (oa = obd_oa_fromid(&conn, rw_s.id)) ) 
			return -ENOENT;

		rc = -EINVAL;
		if ( !obddev->obd_type->typ_ops || 
		     !obddev->obd_type->typ_ops->o_read ) 
			goto READ_OUT;

		rc = obddev->obd_type->typ_ops->o_read
			(&conn, oa, rw_s.buf, &rw_s.count, rw_s.offset);
		if ( rc ) 
			goto READ_OUT;

		rc = copy_to_user((int*)arg, &rw_s.count, sizeof(rw_s.count));

	READ_OUT:
		if ( oa ) 
			OBD_FREE(oa, sizeof(*oa));
		return rc;
	}

	case OBD_IOC_WRITE: {
		obdattr *oa = NULL;
		int rc;
		struct oic_rw_s rw_s;  /* read, write ioctl str */

		rc = copy_from_user(&rw_s, (int *)arg, sizeof(rw_s));
		if ( rc ) 
			goto WRITE_OUT;

		conn.oc_id = rw_s.conn_id;
		oa = obd_oa_fromid(&conn, rw_s.id);
		if ( !oa ) 
			return -ENOENT;

		rc = -EINVAL;
		if ( !obddev->obd_type->typ_ops || 
		     !obddev->obd_type->typ_ops->o_write ) 
			goto WRITE_OUT;

		rc = obddev->obd_type->typ_ops->o_write
			(&conn, oa, rw_s.buf, &rw_s.count, rw_s.offset);
		if ( rc ) 
			goto WRITE_OUT;

		rc = copy_to_user((int*)arg, &rw_s.count, sizeof(rw_s.count));

	WRITE_OUT:
		OBD_FREE(oa, sizeof(*oa));
		return rc;
	}
	case OBD_IOC_PREALLOCATE: {
		struct oic_prealloc_s prealloc;
		int rc;

		/* has this minor been registered? */
		if (!obddev->obd_type)
			return -ENODEV;


		rc = copy_from_user(&prealloc, (int *)arg, sizeof(prealloc));
		if (rc) 
			return -ENOMEM;

		if ( !(obddev->obd_flags & OBD_ATTACHED) ||
		     !(obddev->obd_flags & OBD_SET_UP)) {
			CDEBUG(D_IOCTL, "fatal: device not initialized.\n");
			return -EINVAL;
		}

		if (!obddev->obd_type || 
		    !obddev->obd_type->typ_ops->o_preallocate)
			return -EOPNOTSUPP;
		conn.oc_id = prealloc.cli_id;
		rc = obddev->obd_type->typ_ops->o_preallocate
			(&conn, &prealloc.alloc, prealloc.inodes);
		if ( rc ) 
			return rc;

		return copy_to_user((int *)arg, &prealloc, sizeof(prealloc));
	}
	case OBD_IOC_STATFS:
	{
		struct statfs *tmp;
		unsigned int conn_id;
		struct statfs buf;
		int rc;

		/* has this minor been registered? */
		if (!obddev->obd_type)
			return -ENODEV;

		tmp = (void *)arg + sizeof(unsigned int);
		get_user(conn_id, (int *) arg);
		if ( !obddev->obd_type ||
		     !obddev->obd_type->typ_ops->o_statfs)
			return -EINVAL;

		conn.oc_id = conn_id;
		rc = obddev->obd_type->typ_ops->o_statfs(&conn, &buf);
		if ( rc ) 
			return rc;
		rc = copy_to_user(tmp, &buf, sizeof(buf));
		return rc;
		
	}
	default: {
		struct obd_type *type;
		struct oic_generic input;
		void *karg;

		/* get data structures */
		err = copy_from_user(&input, (void *) arg, sizeof(input));
		if (err) {
			EXIT;
			return err;
		}

		if ( (err = getdata(input.att_typelen + 1, &input.att_type))){
			EXIT;
			return err;
		}

		/* find the type */
		err = -EINVAL;
		type = obd_nm_to_type(input.att_type);
		OBD_FREE(input.att_type, input.att_typelen + 1);
		if ( !type ) {
			printk("Unknown obd type dev %d\n", dev);
			EXIT;
			return err;
		}
		
		if ( !type->typ_ops->o_iocontrol ) {
			EXIT;
			return -EINVAL;
		}
		conn.oc_id = input.att_connid;
		
		CDEBUG(D_IOCTL, "Calling ioctl %x for type %s, len %d\n",
		       cmd, type->typ_name, input.att_datalen);

		/* get the generic data */
		karg = input.att_data;
		if ( (err = getdata(input.att_datalen, &karg)) ) {
			EXIT;
			return err;
		}

		err = type->typ_ops->o_iocontrol
			(cmd, &conn, input.att_datalen, 
			 karg, input.att_data);
		OBD_FREE(karg, input.att_datalen);

		EXIT;
		return err;
	}
	}
}

/* Driver interface done, utility functions follow */

int obd_register_type(struct obd_ops *ops, char *nm)
{
	struct obd_type *type;


	if (obd_init_magic != 0x11223344) {
		EXIT;
		return -EINVAL;
	}

	if  ( obd_nm_to_type(nm) ) {
		CDEBUG(D_IOCTL, "Type %s already registered\n", nm);
		EXIT;
		return -1;
	}
	
	OBD_ALLOC(type, struct obd_type * , sizeof(*type));
	if ( !type ) {
		EXIT;
		return -ENOMEM;
	}
	memset(type, 0, sizeof(*type));
	INIT_LIST_HEAD(&type->typ_chain);
	MOD_INC_USE_COUNT;
	list_add(&type->typ_chain, obd_types.next);
	type->typ_ops = ops;
	type->typ_name = nm;
	EXIT;
	return 0;
}
	
int obd_unregister_type(char *nm)
{
	struct obd_type *type = obd_nm_to_type(nm);

	if ( !type ) {
		MOD_DEC_USE_COUNT;
		printk("OBD: NO TYPE\n");
		EXIT;
		return -1;
	}

	if ( type->typ_refcnt ) {
		MOD_DEC_USE_COUNT;
		printk("OBD: refcount wrap\n");
		EXIT;
		return -1;
	}

	list_del(&type->typ_chain);
	OBD_FREE(type, sizeof(*type));
	MOD_DEC_USE_COUNT;
	return 0;
}

/* declare character device */
static struct file_operations obd_psdev_fops = {
	NULL,                  /* llseek */
	NULL,                  /* read */
	NULL,                  /* write */
	NULL,		       /* presto_psdev_readdir */
        NULL,                  /* poll */
	obd_class_ioctl,       /* ioctl */
	NULL,		       /* presto_psdev_mmap */
	obd_class_open,        /* open */
	NULL,
	obd_class_release,     /* release */
	NULL,                  /* fsync */
	NULL,                  /* fasync */
	NULL,                  /* check_media_change */
	NULL,                  /* revalidate */
	NULL                   /* lock */
};


/* modules setup */

int init_obd(void)
{
	int i;

	printk(KERN_INFO "OBD class driver  v0.002, braam@stelias.com\n");
	
	INIT_LIST_HEAD(&obd_types);
	
	if (register_chrdev(OBD_PSDEV_MAJOR,"obd_psdev", 
			    &obd_psdev_fops)) {
		printk(KERN_ERR "obd_psdev: unable to get major %d\n", 
		       OBD_PSDEV_MAJOR);
		return -EIO;
	}

	for (i = 0; i < MAX_OBD_DEVICES; i++) {
		memset(&(obd_dev[i]), 0, sizeof(obd_dev[i]));
		obd_dev[i].obd_minor = i;
		INIT_LIST_HEAD(&obd_dev[i].obd_gen_clients);
	}

	obd_sysctl_init();
	obd_init_magic = 0x11223344;
	return 0;
}

EXPORT_SYMBOL(obd_register_type);
EXPORT_SYMBOL(obd_unregister_type);

EXPORT_SYMBOL(obd_print_entry);
EXPORT_SYMBOL(obd_debug_level);
EXPORT_SYMBOL(obd_dev);

EXPORT_SYMBOL(gen_connect);
EXPORT_SYMBOL(gen_client);
EXPORT_SYMBOL(gen_cleanup);
EXPORT_SYMBOL(gen_disconnect);
EXPORT_SYMBOL(gen_copy_data); 

/* EXPORT_SYMBOL(gen_multi_attach); */
EXPORT_SYMBOL(gen_multi_setup);
EXPORT_SYMBOL(gen_multi_cleanup);


#ifdef MODULE
int init_module(void)
{
	return init_obd();
}

void cleanup_module(void)
{
	int i;
        ENTRY;

        unregister_chrdev(OBD_PSDEV_MAJOR, "obd_psdev");
	for (i = 0; i < MAX_OBD_DEVICES; i++) {
		struct obd_device *obddev = &obd_dev[i];
		if ( obddev->obd_type && 
		     (obddev->obd_flags & OBD_SET_UP) &&
		     obddev->obd_type->typ_ops->o_detach ) {
			OBP(obddev, detach)(obddev);
		} 
	}


	obd_sysctl_clean();
	obd_init_magic = 0;
}
#endif
