/*
 *  linux/fs/ext2_obd/sim_obd.c
 *
 * These are the only exported functions; they provide the simulated object-
 * oriented disk.
 *
 */

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/segment.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>

#include <linux/obd_support.h>
#include <linux/obd_class.h>


extern struct obd_device obd_dev[MAX_OBD_DEVICES];
kmem_cache_t *obdo_cachep;

int obd_init_obdo_cache(void)
{
	/* XXX need to free this somewhere? */
	ENTRY;
	obdo_cachep = kmem_cache_create("obdo_cache",
					      sizeof(struct obdo),
					      0, SLAB_HWCACHE_ALIGN,
					      NULL, NULL);
	if (obdo_cachep == NULL) {
		EXIT;
		return -ENOMEM;
	}
	EXIT;
	return 0;
}


/* map connection to client */
struct obd_client *gen_client(struct obd_conn *conn)
{
	struct obd_device * obddev = conn->oc_dev;
	struct list_head * lh, * next;
	struct obd_client * cli;

	lh = next = &obddev->obd_gen_clients;
	while ((lh = lh->next) != &obddev->obd_gen_clients) {
		cli = list_entry(lh, struct obd_client, cli_chain);
		
		if (cli->cli_id == conn->oc_id)
			return cli;
	}

	return NULL;
} /* obd_client */



/* a connection defines a context in which preallocation can be managed. */ 
int gen_connect (struct obd_conn *conn)
{
	struct obd_client * cli;

	OBD_ALLOC(cli, struct obd_client *, sizeof(struct obd_client));
	if ( !cli ) {
		printk("obd_connect (minor %d): no memory!\n", 
		       conn->oc_dev->obd_minor);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&cli->cli_prealloc_inodes);
	/* this should probably spinlocked? */
	cli->cli_id = ++conn->oc_dev->obd_gen_last_id;
	cli->cli_prealloc_quota = 0;
	cli->cli_obd = conn->oc_dev;
	list_add(&(cli->cli_chain), conn->oc_dev->obd_gen_clients.prev);

	CDEBUG(D_IOCTL, "connect: new ID %u\n", cli->cli_id);
	conn->oc_id = cli->cli_id;
	return 0;
} /* gen_obd_connect */


int gen_disconnect(struct obd_conn *conn)
{
	struct obd_client * cli;
	ENTRY;

	if (!(cli = gen_client(conn))) {
		CDEBUG(D_IOCTL, "disconnect: attempting to free "
		       "nonexistent client %u\n", conn->oc_id);
		return -EINVAL;
	}


	list_del(&(cli->cli_chain));
	OBD_FREE(cli, sizeof(struct obd_client));

	CDEBUG(D_IOCTL, "disconnect: ID %u\n", conn->oc_id);

	EXIT;
	return 0;
} /* gen_obd_disconnect */


/* 
 *   raid1 defines a number of connections to child devices,
 *   used to make calls to these devices.
 *   data holds nothing
 */ 
int gen_multi_setup(struct obd_device *obddev, uint32_t len, void *data)
{
	int i;

	for (i = 0 ; i < obddev->obd_multi_count ; i++ ) {
		int rc;
		struct obd_conn *ch_conn = &obddev->obd_multi_conn[i];
		rc  = OBP(ch_conn->oc_dev, connect)(ch_conn);

		if ( rc != 0 ) {
			/* XXX disconnect others */
			return -EINVAL;
		}
	}		
	return 0;
}


#if 0
int gen_multi_attach(struct obd_device *obddev, int len, void *data)
{
	int i;
	int count;
	struct obd_device *rdev = obddev->obd_multi_dev[0];

	count = len/sizeof(int);
	obddev->obd_multi_count = count;
	for (i=0 ; i<count ; i++) {
		rdev = &obd_dev[*((int *)data + i)];
		rdev = rdev + 1;
		CDEBUG(D_IOCTL, "OBD RAID1: replicator %d is of type %s\n", i,
		       (rdev + i)->obd_type->typ_name);
	}
	return 0;
}
#endif


/*
 *    remove all connections to this device
 *    close all connections to lower devices
 *    needed for forced unloads of OBD client drivers
 */
int gen_multi_cleanup(struct obd_device *obddev)
{
	int i;

	for (i = 0 ; i < obddev->obd_multi_count ; i++ ) {
		struct obd_conn *ch_conn = &obddev->obd_multi_conn[i];
		int rc;
		rc  = OBP(ch_conn->oc_dev, disconnect)(ch_conn);

		if ( rc != 0 ) {
			printk("OBD multi cleanup dev: disconnect failure %d\n", ch_conn->oc_dev->obd_minor);
		}
	}		
	return 0;
} /* gen_multi_cleanup_device */


/*
 *    forced cleanup of the device:
 *    - remove connections from the device
 *    - cleanup the device afterwards
 */
int gen_cleanup(struct obd_device * obddev)
{
	struct list_head * lh, * tmp;
	struct obd_client * cli;

	ENTRY;

	lh = tmp = &obddev->obd_gen_clients;
	while ((tmp = tmp->next) != lh) {
		cli = list_entry(tmp, struct obd_client, cli_chain);
		CDEBUG(D_IOCTL, "Disconnecting obd_connection %d, at %p\n",
		       cli->cli_id, cli);
	}
	return 0;
} /* sim_cleanup_device */

void ___wait_on_page(struct page *page)
{
        struct task_struct *tsk = current;
        DECLARE_WAITQUEUE(wait, tsk);

        add_wait_queue(&page->wait, &wait);
        do {
                run_task_queue(&tq_disk);
                set_task_state(tsk, TASK_UNINTERRUPTIBLE);
                if (!PageLocked(page))
                        break;
                schedule();
        } while (PageLocked(page));
        tsk->state = TASK_RUNNING;
        remove_wait_queue(&page->wait, &wait);
}

void lck_page(struct page *page)
{
        while (TryLockPage(page))
                ___wait_on_page(page);
}

/* XXX this should return errors correctly, so should migrate!!! */
int gen_copy_data(struct obd_conn *dst_conn, struct obdo *dst,
		  struct obd_conn *src_conn, struct obdo *src)
{
	struct page *page;
	unsigned long index = 0;
	int rc;
	ENTRY;

	CDEBUG(D_INODE, "src: ino %Ld blocks %Ld, size %Ld, dst: ino %Ld\n", 
	       src->o_id, src->o_blocks, src->o_size, dst->o_id);
	page = alloc_page(GFP_USER);
	if ( !page ) {
		EXIT;
		return -ENOMEM;
	}
	
	lck_page(page);
	
	while (index < ((src->o_size + PAGE_SIZE - 1) >> PAGE_SHIFT)) {
		
		page->index = index;
		rc = OBP(src_conn->oc_dev, brw)
			(READ, src_conn, src, (char *)page_address(page), 
			 PAGE_SIZE, (page->index) << PAGE_SHIFT, 0);

		if ( rc != PAGE_SIZE ) 
			break;
		CDEBUG(D_INODE, "Read page %ld ...\n", page->index);

		rc = OBP(dst_conn->oc_dev, brw)
			(WRITE, dst_conn, dst,  (char *)page_address(page), 
			 PAGE_SIZE, (page->index) << PAGE_SHIFT, 1);
		if ( rc != PAGE_SIZE)
			break;

		CDEBUG(D_INODE, "Wrote page %ld ...\n", page->index);
		
		index ++;
	}
	dst->o_size = src->o_size;
	dst->o_blocks = src->o_blocks;
	UnlockPage(page);
	__free_page(page);

	EXIT;
	return 0;
}
