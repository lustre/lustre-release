/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *              An implementation of a loadable kernel mode driver providing
 *              multiple kernel/user space bidirectional communications links.
 *
 *              Author:         Alan Cox <alan@cymru.net>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              version 2 as published by the Free Software Foundation.
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
 *              Copyright (C) 2001 Cluster File Systems, Inc.
 *
 * 
 */

#define EXPORT_SYMTAB
#include <linux/config.h> /* for CONFIG_PROC_FS */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/kmod.h>   /* for request_module() */
#include <linux/sched.h>
#include <linux/lp.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/list.h>
#include <asm/io.h>
#include <asm/system.h>
#include <asm/poll.h>
#include <asm/uaccess.h>
#include <linux/miscdevice.h>

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/obd_support.h>
#include <linux/obd_class.h>

static int obd_init_magic;
int obd_print_entry = 1;
int obd_debug_level = ~0;
unsigned long obd_memory = 0;
struct obd_device obd_dev[MAX_OBD_DEVICES];
struct list_head obd_types;

/*  opening /dev/obd */
static int obd_class_open(struct inode * inode, struct file * file)
{
        ENTRY;

	file->private_data = NULL;
        MOD_INC_USE_COUNT;
        EXIT;
        return 0;
}

/*  closing /dev/obd */
static int obd_class_release(struct inode * inode, struct file * file)
{
        ENTRY;

	if (file->private_data)
		file->private_data = NULL;

        MOD_DEC_USE_COUNT;
        EXIT;
        return 0;
}

/* 
 * support functions: we could use inter-module communication, but this 
 * is more portable to other OS's
 */
static struct obd_type *obd_search_type(char *nm)
{
        struct list_head *tmp;
        struct obd_type *type;
        CDEBUG(D_INFO, "SEARCH %s\n", nm);
        
        tmp = &obd_types;
        while ( (tmp = tmp->next) != &obd_types ) {
                type = list_entry(tmp, struct obd_type, typ_chain);
                CDEBUG(D_INFO, "TYP %s\n", type->typ_name);
                if (strlen(type->typ_name) == strlen(nm) &&
                    strcmp(type->typ_name, nm) == 0 ) {
                        return type;
                }
        }
	return NULL;
}

static struct obd_type *obd_nm_to_type(char *nm) 
{
        struct obd_type *type = obd_search_type(nm);

#ifdef CONFIG_KMOD
	if ( !type ) {
		if ( !request_module(nm) ) {
			CDEBUG(D_INFO, "Loaded module '%s'\n", nm);
			type = obd_search_type(nm);
		} else {
			CDEBUG(D_INFO, "Can't load module '%s'\n", nm);
		}
	}
#endif
        return type;
}

/* to control /dev/obd */
static int obd_class_ioctl (struct inode * inode, struct file * filp, 
                            unsigned int cmd, unsigned long arg)
{
        /* NOTE this must be larger than any of the ioctl data structs */
        char buf[1024];
	struct obd_ioctl_data *data;
	struct obd_device *obd = filp->private_data;
	struct obd_conn conn;
	int rw = OBD_BRW_READ;
        int err = 0;
	ENTRY;

	memset(buf, 0, sizeof(buf));

	if (!obd && cmd != OBD_IOC_DEVICE && cmd != TCGETS) {
		CERROR("OBD ioctl: No device\n");
		return -EINVAL;
	} 
	if (obd_ioctl_getdata(buf, buf + 800, (void *)arg)) { 
		CERROR("OBD ioctl: data error\n");
		return -EINVAL;
	}
	data = (struct obd_ioctl_data *)buf;

        switch (cmd) {
        case TCGETS: { 
		EXIT;
                return -EINVAL;
	}
	case OBD_IOC_DEVICE: { 
		CDEBUG(D_IOCTL, "\n");
		if (data->ioc_dev >= MAX_OBD_DEVICES ||
		    data->ioc_dev < 0) { 
			CERROR("OBD ioctl: DEVICE insufficient devices\n");
			return -EINVAL;
		}
		CDEBUG(D_IOCTL, "device %d\n", data->ioc_dev);

		filp->private_data = &obd_dev[data->ioc_dev];
		EXIT;
		return 0;
	}

        case OBD_IOC_ATTACH: {
                struct obd_type *type;

                ENTRY;
                /* have we attached a type to this device */
                if ( obd->obd_flags & OBD_ATTACHED ) {
                        CERROR("OBD: Device %d already typed as  %s.\n",
                               obd->obd_minor, MKSTR(obd->obd_type->typ_name));
                        return -EBUSY;
                }

		CDEBUG(D_IOCTL, "attach %s %s\n",  MKSTR(data->ioc_inlbuf1), 
		       MKSTR(data->ioc_inlbuf2));

                /* find the type */
                type = obd_nm_to_type(data->ioc_inlbuf1);
                if ( !type ) {
                        CERROR("OBD: unknown type dev %d\n", obd->obd_minor);
                        return -EINVAL;
                }

                obd->obd_type = type;
                obd->obd_multi_count = 0;
                INIT_LIST_HEAD(&obd->obd_gen_clients);
                INIT_LIST_HEAD(&obd->obd_req_list);

                /* do the attach */
                if ( OBT(obd) && OBP(obd, attach) ) {
			err = OBP(obd, attach)(obd, sizeof(*data), data);
		}

                if ( err ) {
                        obd->obd_type = NULL;
                        EXIT;
                } else {
                        obd->obd_flags |=  OBD_ATTACHED;
                        type->typ_refcnt++;
                        CDEBUG(D_IOCTL, "OBD: dev %d attached type %s\n", 
			       obd->obd_minor, data->ioc_inlbuf1);
			obd->obd_proc_entry = 
				proc_lustre_register_obd_device(obd);
                        MOD_INC_USE_COUNT;
                        EXIT;
                }

                return err;
        }

        case OBD_IOC_DETACH: {
                ENTRY;
                if (obd->obd_flags & OBD_SET_UP) {
                        CERROR("OBD device %d still set up\n", obd->obd_minor);
                        return -EBUSY;
                }
                if (! (obd->obd_flags & OBD_ATTACHED) ) {
                        CERROR("OBD device %d not attached\n", obd->obd_minor);
                        return -ENODEV;
                }
                if ( !list_empty(&obd->obd_gen_clients) ) {
                        CERROR("OBD device %d has connected clients\n",
                               obd->obd_minor);
                        return -EBUSY;
                }
                if ( !list_empty(&obd->obd_req_list) ) {
                        CERROR("OBD device %d has hanging requests\n",
                               obd->obd_minor);
                        return -EBUSY;
                }

		if (obd->obd_proc_entry)
			proc_lustre_release_obd_device(obd);

                obd->obd_flags &= ~OBD_ATTACHED;
                obd->obd_type->typ_refcnt--;
                obd->obd_type = NULL;
                MOD_DEC_USE_COUNT;
                EXIT;
                return 0;
        }

        case OBD_IOC_SETUP: {
                ENTRY;
                /* have we attached a type to this device? */
                if (!(obd->obd_flags & OBD_ATTACHED)) {
                        CERROR("Device %d not attached\n", obd->obd_minor);
                        return -ENODEV;
                }

                /* has this been done already? */
                if ( obd->obd_flags & OBD_SET_UP ) {
                        CERROR("Device %d already setup (type %s)\n",
                               obd->obd_minor, obd->obd_type->typ_name);
                        return -EBUSY;
                }

                if ( OBT(obd) && OBP(obd, setup) )
			err = obd_setup(obd, sizeof(*data), data);

		if (!err) { 
			obd->obd_type->typ_refcnt++;
			obd->obd_flags |= OBD_SET_UP;
			EXIT;
		}

                return err;
        }
        case OBD_IOC_CLEANUP: {
                ENTRY;

                /* have we attached a type to this device? */
                if (!(obd->obd_flags & OBD_ATTACHED)) {
                        CERROR("Device %d not attached\n", obd->obd_minor);
                        return -ENODEV;
                }

                if ( OBT(obd) && OBP(obd, cleanup) )
			err = obd_cleanup(obd);

		if (!err) {
			obd->obd_flags &= ~OBD_SET_UP;
			obd->obd_type->typ_refcnt--;
			EXIT;
		}
                return err;
        }

        case OBD_IOC_CONNECT:
        {
		conn.oc_id = data->ioc_conn1;
		conn.oc_dev = obd; 

                err = obd_connect(&conn);

		CDEBUG(D_IOCTL, "assigned connection %d\n", conn.oc_id);
		data->ioc_conn1 = conn.oc_id;
                if ( err )
                        return err;

                return copy_to_user((int *)arg, data, sizeof(*data));
        }

        case OBD_IOC_DISCONNECT: { 
		conn.oc_id = data->ioc_conn1;
		conn.oc_dev = obd;

                err = obd_disconnect(&conn);
                return err;
	}		

	case OBD_IOC_DEC_USE_COUNT: { 
		MOD_DEC_USE_COUNT;
		return 0;
	}

        case OBD_IOC_CREATE: {
                conn.oc_id = data->ioc_conn1;
		conn.oc_dev = obd;

                err = obd_create(&conn, &data->ioc_obdo1);
                if (err) {
                        EXIT;
                        return err;
                }

                err = copy_to_user((int *)arg, data, sizeof(*data));
                EXIT;
                return err;
        }

        case OBD_IOC_GETATTR: {
                conn.oc_id = data->ioc_conn1;
		conn.oc_dev = obd;

                err = obd_getattr(&conn, &data->ioc_obdo1);
                if (err) {
                        EXIT;
                        return err;
                }

                err = copy_to_user((int *)arg, data, sizeof(*data));
                EXIT;
                return err;
        }

        case OBD_IOC_SETATTR: {
                conn.oc_id = data->ioc_conn1;
		conn.oc_dev = obd;

                err = obd_setattr(&conn, &data->ioc_obdo1);
                if (err) {
                        EXIT;
                        return err;
                }

                err = copy_to_user((int *)arg, data, sizeof(*data));
                EXIT;
                return err;
	}

        case OBD_IOC_DESTROY: {
                conn.oc_id = data->ioc_conn1;
		conn.oc_dev = obd;

                err = obd_destroy(&conn, &data->ioc_obdo1);
                if (err) {
                        EXIT;
                        return err;
                }

                err = copy_to_user((int *)arg, data, sizeof(*data));
                EXIT;
                return err;
	}

	case OBD_IOC_BRW_WRITE:
		rw = OBD_BRW_WRITE;
	case OBD_IOC_BRW_READ: {
		/* FIXME: use a better ioctl data struct than obd_ioctl_data */
                struct obd_conn conns[2];
                struct obdo     *obdos[2];
                obd_count       oa_bufs[2];
                struct page     **bufs;
                obd_size        counts[2];
                obd_off         offsets[2];
                obd_flag        flags[2];
                int             pages;
                int             i, j;

                oa_bufs[0] = data->ioc_plen1 / PAGE_SIZE;
                oa_bufs[1] = data->ioc_plen2 / PAGE_SIZE;
                pages = oa_bufs[0] + oa_bufs[1];

                CDEBUG(D_INODE, "BRW %s with %d+%d pages\n",
                       rw == OBD_BRW_READ ? "read" : "write",
                       oa_bufs[0], oa_bufs[1]);
                bufs = kmalloc(pages * sizeof(struct page *), GFP_KERNEL);
                if (!bufs) {
                        CERROR("no memory for %d BRW bufs\n", pages);
                        EXIT;
                        return -ENOMEM;
                }

                obdos[0] = &data->ioc_obdo1;
                obdos[1] = &data->ioc_obdo2;

                pages = 0;
                for (i = 0; i < 2; i++) {
                        void *from;

                        conns[i].oc_id = (&data->ioc_conn1)[i];
                        conns[i].oc_dev = obd;

                        from = (&data->ioc_pbuf1)[i];

                        for (j = 0; j < oa_bufs[i]; j++) {
                                unsigned long to;

                                to = __get_free_pages(GFP_KERNEL, 0);
                                if (!to) {
                                /*      ||
                                    copy_from_user((void *)to,from,PAGE_SIZE))
                                        free_pages(to, 0);
                                 */
                                        CERROR("no memory for brw pages\n");
                                        EXIT;
                                        goto brw_cleanup;
                                }
                                bufs[pages++] = virt_to_page(to);
                                from += PAGE_SIZE;
                        }

                        counts[i] = data->ioc_count;
                        offsets[i] = data->ioc_offset;
                        flags[i] = 0;
                }

                err = obd_brw(rw, conns, 2, obdos, oa_bufs, bufs,
                              counts, offsets, flags);

                EXIT;
        brw_cleanup:
                while (pages-- > 0)
                        free_pages((unsigned long)page_address(bufs[pages]), 0);
                kfree(bufs);
                return err;
        }
#if 0
        case OBD_IOC_SYNC: {
                struct oic_range_s *range = tmp_buf;

                if (!obd->obd_type)
                        return -ENODEV;

                err = copy_from_user(range, (const void *)arg,  sizeof(*range));

                if ( err ) {
                        EXIT;
                        return err;
                }
                        
                if ( !OBT(obd) || !OBP(obd, sync) ) {
                        err = -EOPNOTSUPP;
                        EXIT;
                        return err;
                }

                /* XXX sync needs to be tested/verified */
                err = OBP(obd, sync)(&conn, &range->obdo, range->count,
                                        range->offset);

                if ( err ) {
                        EXIT;
                        return err;
                }
                        
                return put_user(err, (int *) arg);
        }

        case OBD_IOC_READ: {
                int err;
                struct oic_rw_s *rw_s = tmp_buf;  /* read, write ioctl str */

                err = copy_from_user(rw_s, (int *)arg, sizeof(*rw_s));
                if ( err ) {
                        EXIT;
                        return err;
                }

                conn.oc_id = rw_s->conn_id;

                if ( !OBT(obd) || !OBP(obd, read) ) {
                        err = -EOPNOTSUPP;
                        EXIT;
                        return err;
                }


                err = OBP(obd, read)(&conn, &rw_s->obdo, rw_s->buf, 
                                        &rw_s->count, rw_s->offset);
                
                CDEBUG(D_INFO, "READ: conn %d, count %Ld, offset %Ld, '%s'\n",
                       rw_s->conn_id, rw_s->count, rw_s->offset, rw_s->buf);
                if ( err ) {
                        EXIT;
                        return err;
                }
                        
                err = copy_to_user((int*)arg, &rw_s->count, sizeof(rw_s->count));
                EXIT;
                return err;
        }

        case OBD_IOC_WRITE: {
                struct oic_rw_s *rw_s = tmp_buf;  /* read, write ioctl str */

                err = copy_from_user(rw_s, (int *)arg, sizeof(*rw_s));
                if ( err ) {
                        EXIT;
                        return err;
                }

                conn.oc_id = rw_s->conn_id;

                if ( !OBT(obd) || !OBP(obd, write) ) {
                        err = -EOPNOTSUPP;
                        return err;
                }

                CDEBUG(D_INFO, "WRITE: conn %d, count %Ld, offset %Ld, '%s'\n",
                       rw_s->conn_id, rw_s->count, rw_s->offset, rw_s->buf);

                err = OBP(obd, write)(&conn, &rw_s->obdo, rw_s->buf, 
                                         &rw_s->count, rw_s->offset);
                if ( err ) {
                        EXIT;
                        return err;
                }

                err = copy_to_user((int *)arg, &rw_s->count,
                                   sizeof(rw_s->count));
                EXIT;
                return err;
        }
        case OBD_IOC_PREALLOCATE: {
                struct oic_prealloc_s *prealloc = tmp_buf;

                /* has this minor been registered? */
                if (!obd->obd_type)
                        return -ENODEV;

                err = copy_from_user(prealloc, (int *)arg, sizeof(*prealloc));
                if (err) 
                        return -EFAULT;

                if ( !(obd->obd_flags & OBD_ATTACHED) ||
                     !(obd->obd_flags & OBD_SET_UP)) {
                        CDEBUG(D_IOCTL, "Device not attached or set up\n");
                        return -ENODEV;
                }

                if ( !OBT(obd) || !OBP(obd, preallocate) )
                        return -EOPNOTSUPP;

                conn.oc_id = prealloc->conn_id;
                err = OBP(obd, preallocate)(&conn, &prealloc->alloc,
                                               prealloc->ids);
                if ( err ) {
                        EXIT;
                        return err;
                }

                err =copy_to_user((int *)arg, prealloc, sizeof(*prealloc));
                EXIT;
                return err;
        }
        case OBD_IOC_STATFS: {
                struct statfs *tmp;
                unsigned int conn_id;
                struct statfs buf;

                /* has this minor been registered? */
                if (!obd->obd_type)
                        return -ENODEV;

                tmp = (void *)arg + sizeof(unsigned int);
                get_user(conn_id, (int *) arg);

                if ( !OBT(obd) || !OBP(obd, statfs) )
                        return -EOPNOTSUPP;

                conn.oc_id = conn_id;
                err = OBP(obd, statfs)(&conn, &buf);
                if ( err ) {
                        EXIT;
                        return err;
                }
                err = copy_to_user(tmp, &buf, sizeof(buf));
                EXIT;
                return err;
                
        }
        case OBD_IOC_COPY: {
                struct ioc_mv_s *mvdata = tmp_buf;

                if ( (!(obd->obd_flags & OBD_SET_UP)) ||
                     (!(obd->obd_flags & OBD_ATTACHED))) {
                        CDEBUG(D_IOCTL, "Device not attached or set up\n");
                        return -ENODEV;
                }

                /* get main structure */
                err = copy_from_user(mvdata, (void *) arg, sizeof(*mvdata));
                if (err) {
                        EXIT;
                        return err;
                }

                if ( !OBT(obd) || !OBP(obd, copy) )
                        return -EOPNOTSUPP;

                /* do the partition */
                CDEBUG(D_INFO, "Copy %d, type %s dst %Ld src %Ld\n", dev, 
                       obd->obd_type->typ_name, mvdata->dst.o_id, 
                       mvdata->src.o_id);

                conn.oc_id = mvdata->src_conn_id;

                err = OBP(obd, copy)(&conn, &mvdata->dst, 
                                        &conn, &mvdata->src, 
                                        mvdata->src.o_size, 0);
                return err;
        }

        case OBD_IOC_MIGR: {
                struct ioc_mv_s *mvdata = tmp_buf;

                if ( (!(obd->obd_flags & OBD_SET_UP)) ||
                     (!(obd->obd_flags & OBD_ATTACHED))) {
                        CDEBUG(D_IOCTL, "Device not attached or set up\n");
                        return -ENODEV;
                }

                err = copy_from_user(mvdata, (void *) arg, sizeof(*mvdata));
                if (err) {
                        EXIT;
                        return err;
                }

                CDEBUG(D_INFO, "Migrate copying %d bytes\n", sizeof(*mvdata));

                if ( !OBT(obd) || !OBP(obd, migrate) )
                        return -EOPNOTSUPP;

                /* do the partition */
                CDEBUG(D_INFO, "Migrate %d, type %s conn %d src %Ld dst %Ld\n",
                       dev, obd->obd_type->typ_name, mvdata->src_conn_id,
                       mvdata->src.o_id, mvdata->dst.o_id);

                conn.oc_id = mvdata->src_conn_id;
                err = OBP(obd, migrate)(&conn, &mvdata->dst, &mvdata->src, 
                                           mvdata->src.o_size, 0);

                return err;
        }
        case OBD_IOC_PUNCH: {
                struct oic_rw_s *rw_s = tmp_buf;  /* read, write ioctl str */

                err = copy_from_user(rw_s, (int *)arg, sizeof(*rw_s));
                if ( err ) {
                        EXIT;
                        return err;
                }

                conn.oc_id = rw_s->conn_id;

                if ( !OBT(obd) || !OBP(obd, punch) ) {
                        err = -EOPNOTSUPP;
                        return err;
                }

                CDEBUG(D_INFO, "PUNCH: conn %d, count %Ld, offset %Ld\n",
                       rw_s->conn_id, rw_s->count, rw_s->offset);
                err = OBP(obd, punch)(&conn, &rw_s->obdo, rw_s->count,
                                         rw_s->offset);
                if ( err ) {
                        EXIT;
                        return err;
                }
                EXIT;
                return err;
        }

        default: {
                struct obd_type *type;
                struct oic_generic input;
                char *nm;
                void *karg;

                /* get data structures */
                err = copy_from_user(&input, (void *)arg, sizeof(input));
                if ( err ) {
                        EXIT;
                        return err;
                }

                err = getdata(input.att_typelen + 1, &input.att_type);
                if ( err ) {
                        EXIT;
                        return err;
                }

                /* find the type */
                nm = input.att_type;
                type = obd_nm_to_type(nm);
#ifdef CONFIG_KMOD
                if ( !type ) {
                        if ( !request_module(nm) ) {
                                CDEBUG(D_INFO, "Loaded module '%s'\n", nm);
                                type = obd_nm_to_type(nm);
                        } else {
                                CDEBUG(D_INFO, "Can't load module '%s'\n", nm);
                        }
                }
#endif
                OBD_FREE(input.att_type, input.att_typelen + 1);
                if ( !type ) {
                        CERROR("unknown obd type dev %d\n", dev);
                        EXIT;
                        return -EINVAL;
                }
                
                if ( !type->typ_ops || !type->typ_ops->o_iocontrol ) {
                        EXIT;
                        return -EOPNOTSUPP;
                }
                conn.oc_id = input.att_connid;
                
                CDEBUG(D_INFO, "Calling ioctl %x for type %s, len %d\n",
                       cmd, type->typ_name, input.att_datalen);

                /* get the generic data */
                karg = input.att_data;
                err = getdata(input.att_datalen, &karg);
                if ( err ) {
                        EXIT;
                        return err;
                }

                err = type->typ_ops->o_iocontrol(cmd, &conn, input.att_datalen, 
                                                 karg, input.att_data);
                OBD_FREE(karg, input.att_datalen);

                EXIT;
                return err;
        }
#endif 
	default:
		return -EINVAL;

        }
} /* obd_class_ioctl */


/* Driver interface done, utility functions follow */
int obd_register_type(struct obd_ops *ops, char *nm)
{
        struct obd_type *type;

        if (obd_init_magic != 0x11223344) {
                CERROR("bad magic for type\n");
                EXIT;
                return -EINVAL;
        }

        if  ( obd_nm_to_type(nm) ) {
                CDEBUG(D_IOCTL, "Type %s already registered\n", nm);
                EXIT;
                return -EEXIST;
        }
        
        OBD_ALLOC(type, sizeof(*type));
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
                CERROR("unknown obd type\n");
                EXIT;
                return -EINVAL;
        }

        if ( type->typ_refcnt ) {
                MOD_DEC_USE_COUNT;
                CERROR("type %s has refcount (%d)\n", nm, type->typ_refcnt);
                EXIT;
                return -EBUSY;
        }

        list_del(&type->typ_chain);
        OBD_FREE(type, sizeof(*type));
        MOD_DEC_USE_COUNT;
        return 0;
} /* obd_unregister_type */

/* declare character device */
static struct file_operations obd_psdev_fops = {
        ioctl: obd_class_ioctl,       /* ioctl */
        open: obd_class_open,        /* open */
        release: obd_class_release,     /* release */
};

/* modules setup */
#define OBD_MINOR 241
static struct miscdevice obd_psdev = {
        OBD_MINOR,
        "obd_psdev",
        &obd_psdev_fops
};


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
EXPORT_SYMBOL(obdo_cachep);

/* EXPORT_SYMBOL(gen_multi_attach); */
EXPORT_SYMBOL(gen_multi_setup);
EXPORT_SYMBOL(gen_multi_cleanup);
EXPORT_SYMBOL(obd_memory);

static int __init init_obdclass(void)
{
        int err;
        int i;

        printk(KERN_INFO "OBD class driver  v0.01, braam@stelias.com\n");
        
        INIT_LIST_HEAD(&obd_types);
        
	if ( (err = misc_register(&obd_psdev)) ) { 
                CERROR("cannot register %d err %d\n", OBD_MINOR, err);
                return -EIO;
        }

        for (i = 0; i < MAX_OBD_DEVICES; i++) {
                memset(&(obd_dev[i]), 0, sizeof(obd_dev[i]));
                obd_dev[i].obd_minor = i;
                INIT_LIST_HEAD(&obd_dev[i].obd_gen_clients);
                INIT_LIST_HEAD(&obd_dev[i].obd_req_list);
		init_waitqueue_head(&obd_dev[i].obd_req_waitq);
        }

        err = obd_init_obdo_cache();
        if (err)
                return err;
        obd_sysctl_init();
        obd_init_magic = 0x11223344;
        return 0;
}

static void __exit cleanup_obdclass(void)
{
        int i;
        ENTRY;

        misc_deregister(&obd_psdev);
        for (i = 0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if ( obd->obd_type && 
                     (obd->obd_flags & OBD_SET_UP) &&
                     OBT(obd) && OBP(obd, detach) ) {
                        /* XXX should this call generic detach otherwise? */
                        OBP(obd, detach)(obd);
                } 
        }

        obd_cleanup_obdo_cache();
        obd_sysctl_clean();
        CERROR("obd memory leaked: %ld bytes\n", obd_memory);
        obd_init_magic = 0;
        EXIT;
}

MODULE_AUTHOR("Cluster File Systems, Inc. <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Class Driver v1.0");
MODULE_LICENSE("GPL"); 

module_init(init_obdclass);
module_exit(cleanup_obdclass);
