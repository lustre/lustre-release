/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Helper routines for dumping data structs for debugging.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copryright (C) 2002 Cluster File Systems, Inc.
 *
 */

#define DEBUG_SUBSYSTEM D_OTHER

#define EXPORT_SYMTAB
#include <linux/obd_ost.h>
#include <linux/lustre_debug.h>
#include <linux/lustre_net.h>

int dump_ioo(struct obd_ioobj *ioo)
{
        CERROR("obd_ioobj: ioo_id=%Ld, ioo_gr=%Ld, ioo_type=%d, ioo_bufct=%d\n",
               ioo->ioo_id, ioo->ioo_gr, ioo->ioo_type, ioo->ioo_bufcnt);
        return -EINVAL;
}

int dump_lniobuf(struct niobuf_local *nb)
{
        CERROR("niobuf_local: addr=%p, offset=%Ld, len=%d, xid=%d, page=%p\n",
               nb->addr, nb->offset, nb->len, nb->xid, nb->page);
        CERROR("nb->page: index = %ld\n", nb->page ? nb->page->index : -1);

        return -EINVAL;
}

int dump_rniobuf(struct niobuf_remote *nb)
{
        CERROR("niobuf_remote: offset=%Ld, len=%d, flags=%x, xid=%d\n",
               nb->offset, nb->len, nb->flags, nb->xid);

        return -EINVAL;
}

int dump_obdo(struct obdo *oa)
{
        CERROR("obdo: o_valid = %08x\n", oa->o_valid);
        if (oa->o_valid & OBD_MD_FLID)
                CERROR("obdo: o_id = %Ld\n", oa->o_id);
        if (oa->o_valid & OBD_MD_FLATIME)
                CERROR("obdo: o_atime = %Ld\n", oa->o_atime);
        if (oa->o_valid & OBD_MD_FLMTIME)
                CERROR("obdo: o_mtime = %Ld\n", oa->o_mtime);
        if (oa->o_valid & OBD_MD_FLCTIME)
                CERROR("obdo: o_ctime = %Ld\n", oa->o_ctime);
        if (oa->o_valid & OBD_MD_FLSIZE)
                CERROR("obdo: o_size = %Ld\n", oa->o_size);
        if (oa->o_valid & OBD_MD_FLBLOCKS)   /* allocation of space */
                CERROR("obdo: o_blocks = %Ld\n", oa->o_blocks);
        if (oa->o_valid & OBD_MD_FLBLKSZ)
                CERROR("obdo: o_blksize = %d\n", oa->o_blksize);
        if (oa->o_valid & OBD_MD_FLMODE)
                CERROR("obdo: o_mode = %o\n", oa->o_mode);
        if (oa->o_valid & OBD_MD_FLUID)
                CERROR("obdo: o_uid = %d\n", oa->o_uid);
        if (oa->o_valid & OBD_MD_FLGID)
                CERROR("obdo: o_gid = %d\n", oa->o_gid);
        if (oa->o_valid & OBD_MD_FLFLAGS)
                CERROR("obdo: o_flags = %x\n", oa->o_flags);
        if (oa->o_valid & OBD_MD_FLNLINK)
                CERROR("obdo: o_nlink = %d\n", oa->o_nlink);
        if (oa->o_valid & OBD_MD_FLGENER)
                CERROR("obdo: o_generation = %d\n", oa->o_generation);

        return -EINVAL;
}

/* XXX assumes only a single page in request */
/*
int dump_req(struct ptlrpc_request *req)
{
        struct ost_body *body = lustre_msg_buf(req->rq_reqmsg, 0);
        struct obd_ioobj *ioo = lustre_msg_buf(req->rq_reqmsg, 1);
        //struct niobuf *nb = lustre_msg_buf(req->rq_reqmsg, 2);

        dump_obdo(&body->oa);
        //dump_niobuf(nb);
        dump_ioo(ioo);

        return -EINVAL;
}
*/

#define LPDS sizeof(__u64)
int page_debug_setup(void *addr, int len, __u64 off, __u64 id)
{
        LASSERT(addr);

        off = HTON__u64(off);
        id = HTON__u64(id);
        memcpy(addr, (char *)&off, LPDS);
        memcpy(addr + LPDS, (char *)&id, LPDS);

        addr += len - LPDS - LPDS;
        memcpy(addr, (char *)&off, LPDS);
        memcpy(addr + LPDS, (char *)&id, LPDS);

        return 0;
}

int page_debug_check(char *who, void *addr, int end, __u64 off, __u64 id)
{
        __u64 ne_off;
        int err = 0;

        LASSERT(addr);

        ne_off = HTON__u64(off);
        id = HTON__u64(id);
        if (memcmp(addr, (char *)&ne_off, LPDS)) {
                CERROR("%s: offset "LPU64" off: "LPX64" != "LPX64"\n",
                       who, off, *(__u64 *)addr, ne_off);
                err = -EINVAL;
        }
        if (memcmp(addr + LPDS, (char *)&id, LPDS)) {
                CERROR("%s: offset "LPU64" id: "LPX64" != "LPX64"\n",
                       who, off, *(__u64 *)(addr + LPDS), id);
                err = -EINVAL;
        }

        addr += end - LPDS - LPDS;
        if (memcmp(addr, (char *)&ne_off, LPDS)) {
                CERROR("%s: offset "LPU64" end off: "LPX64" != "LPX64"\n",
                       who, off, *(__u64 *)addr, ne_off);
                err = -EINVAL;
        }
        if (memcmp(addr + LPDS, (char *)&id, LPDS)) {
                CERROR("%s: offset "LPU64" end id: "LPX64" != "LPX64"\n",
                       who, off, *(__u64 *)(addr + LPDS), id);
                err = -EINVAL;
        }

        return err;
}
#undef LPDS

EXPORT_SYMBOL(dump_lniobuf);
EXPORT_SYMBOL(dump_rniobuf);
EXPORT_SYMBOL(dump_ioo);
//EXPORT_SYMBOL(dump_req);
EXPORT_SYMBOL(dump_obdo);
EXPORT_SYMBOL(page_debug_setup);
EXPORT_SYMBOL(page_debug_check);
