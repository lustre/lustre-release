/*
 *  pack.c
 *  Copyright (C) 2001  Cluster File Systems, Inc.
 *
 *  This code is issued under the GNU General Public License.
 *  See the file COPYING in this distribution
 *
 *  
 */


#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd_lib.h>


void obd_req_pack(char **buf, int max, struct obd_req *req)
{
	char *ptr;

	ptr = *buf;

	LOGP(ptr, struct obdo, obd req->oa);
	LOGP(ptr, struct obd_conn, obd req->obd);

}
