
/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_LOG

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif

#ifdef __KERNEL__
#include <linux/fs.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd_class.h>
#include <linux/lustre_log.h>
#include <linux/lustre_mds.h>
#include <portals/list.h>

/* helper functions for calling the llog obd methods */

int obd_llog_setup(struct obd_device *obd, struct obd_llogs *llogs, 
                   int index, struct obd_device *disk_obd, int count, 
                   struct llog_logid *logid, struct llog_operations *op)
{
        int rc = 0;
        struct llog_ctxt *ctxt;
        ENTRY;

        LASSERT(llogs);

        if (index < 0 || index >= LLOG_MAX_CTXTS)
                RETURN(-EFAULT);

        OBD_ALLOC(ctxt, sizeof(*ctxt));
        if (!ctxt)
                RETURN(-ENOMEM);

        llogs->llog_ctxt[index] = ctxt;
        obd->obd_llog_ctxt[index] = ctxt;
        ctxt->loc_logops = op;
        ctxt->loc_obd = obd;
        ctxt->loc_llogs = llogs;
        ctxt->loc_idx = index;
        ctxt->loc_alone = 0;
        ctxt->loc_exp = class_export_get(disk_obd->obd_self_export);
        sema_init(&ctxt->loc_sem, 1);

        if (op->lop_close == llog_lvfs_ops.lop_close) {
                ctxt->loc_fsops = disk_obd->obd_fsops;
                ctxt->loc_lvfs_ctxt = &disk_obd->obd_lvfs_ctxt;
                if (!strcmp(disk_obd->obd_type->typ_name, LUSTRE_MDS_NAME)) {
                        struct mds_obd *mds = &disk_obd->u.mds;
                        ctxt->loc_objects_dir = mds->mds_objects_dir;
                        ctxt->loc_logs_dir = mds->mds_logs_dir;
                }
        }

        if (op->lop_setup)
                rc = op->lop_setup(obd, llogs, index, disk_obd, count, logid);
        if (ctxt && rc) {
                obd->obd_llog_ctxt[index] = NULL;
                OBD_FREE(ctxt, sizeof(*ctxt));
        }

        RETURN(rc);
}
EXPORT_SYMBOL(obd_llog_setup);

int obd_llog_cleanup(struct llog_ctxt *ctxt)
{
        int rc = 0;
        ENTRY;

        if (ctxt == NULL)
                RETURN(0);

        if (CTXTP(ctxt, cleanup))  
                rc = CTXTP(ctxt, cleanup)(ctxt);
                
        ctxt->loc_obd->obd_llog_ctxt[ctxt->loc_idx] = NULL;
        ctxt->loc_llogs->llog_ctxt[ctxt->loc_idx] = NULL;
        class_export_put(ctxt->loc_exp);
        ctxt->loc_exp = NULL;
        OBD_FREE(ctxt, sizeof(*ctxt));
        RETURN(rc);
}
EXPORT_SYMBOL(obd_llog_cleanup);

/* callback func for llog_process in llog_obd_origin_setup */
static int cat_cancel_cb(struct llog_handle *cathandle,
                          struct llog_rec_hdr *rec, void *data)
{
        struct llog_logid_rec *lir = (struct llog_logid_rec *)rec;
        struct llog_handle *loghandle;
        int rc;
        ENTRY;

        if (rec->lrh_type != LLOG_LOGID_MAGIC) {
                CERROR("invalid record in catalog\n");
                RETURN(-EINVAL);
        }
        CDEBUG(D_HA, "processing log "LPX64":%x at index %u of catalog "LPX64"\n",
               lir->lid_id.lgl_oid, lir->lid_id.lgl_ogen,
               rec->lrh_index, cathandle->lgh_id.lgl_oid);

        rc = llog_cat_id2handle(cathandle, &loghandle, &lir->lid_id);
        if (rc) {
                CERROR("Cannot find handle for log "LPX64"\n",
                       lir->lid_id.lgl_oid);
                RETURN(rc);
        }

        if (cathandle->lgh_last_idx == loghandle->u.phd.phd_cookie.lgc_index)
                cathandle->u.chd.chd_current_log = loghandle;

        RETURN(rc);
}

/* lop_setup method for filter/osc */
// XXX how to set exports
int llog_obd_origin_setup(struct obd_device *obd, struct obd_llogs *llogs,
                          int index, struct obd_device *disk_obd, int count,
                          struct llog_logid *logid)
{
        struct llog_ctxt *ctxt;
        struct llog_handle *handle;
        struct lvfs_run_ctxt saved;
        int rc;
        ENTRY;

        if (count == 0)
                RETURN(0);

        LASSERT(count == 1);

        ctxt = llog_get_context(llogs, index);
        LASSERT(ctxt);
        llog_gen_init(ctxt);

        if (logid->lgl_oid) {
                rc = llog_open(ctxt, &handle, logid, NULL, 0);
        } else {
                rc = llog_open(ctxt, &handle, NULL, NULL, 0);
                if (!rc)
                        *logid = handle->lgh_id;
        }
        if (rc)
                RETURN(rc);

        ctxt->loc_handle = handle;
        push_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);
        rc = llog_init_handle(handle, LLOG_F_IS_CAT, NULL);
        pop_ctxt(&saved, &disk_obd->obd_lvfs_ctxt, NULL);
        if (rc)
                RETURN(rc);

        rc = llog_process(handle, (llog_cb_t)cat_cancel_cb, NULL, NULL);
        if (rc)
                CERROR("llog_process with cat_cancel_cb failed: %d\n", rc);

        if (ctxt && rc) {
                llogs->llog_ctxt[index] = NULL;
                OBD_FREE(ctxt, sizeof(*ctxt));
        }
        RETURN(rc);
}
EXPORT_SYMBOL(llog_obd_origin_setup);

int obd_llog_cat_initialize(struct obd_device *obd, struct obd_llogs *llogs, 
                            int count, const char *name)
{
        struct llog_catid *idarray;
        int size = sizeof(*idarray) * count;
        int rc;
        ENTRY;

        OBD_ALLOC(idarray, size);
        if (!idarray)
                RETURN(-ENOMEM);

        rc = llog_get_cat_list(&obd->obd_lvfs_ctxt, obd->obd_fsops,
                               name, count, idarray);
        if (rc) {
                CERROR("rc: %d\n", rc);
                GOTO(out, rc);
        }

        rc = obd_llog_init(obd, llogs, obd, count, idarray);
        if (rc) {
                CERROR("rc: %d\n", rc);
                GOTO(out, rc);
        }

        rc = llog_put_cat_list(&obd->obd_lvfs_ctxt, obd->obd_fsops,
                               name, count, idarray);
        if (rc) {
                CERROR("rc: %d\n", rc);
                GOTO(out, rc);
        }

 out:
        OBD_FREE(idarray, size);
        RETURN(rc);
}
EXPORT_SYMBOL(obd_llog_cat_initialize);

int obd_llog_init(struct obd_device *obd, struct obd_llogs *llogs,
                  struct obd_device *disk_obd, int count,
                  struct llog_catid *logid)
{
        int rc;
        ENTRY;
        OBD_CHECK_OP(obd, llog_init, 0);
        OBD_COUNTER_INCREMENT(obd, llog_init);

        rc = OBP(obd, llog_init)(obd, llogs, disk_obd, count, logid);
        RETURN(rc);
}
EXPORT_SYMBOL(obd_llog_init);

int obd_llog_finish(struct obd_device *obd, struct obd_llogs *llogs, int count)
{
        int rc;
        ENTRY;
        OBD_CHECK_OP(obd, llog_finish, 0);
        OBD_COUNTER_INCREMENT(obd, llog_finish);

        rc = OBP(obd, llog_finish)(obd, llogs, count);
        RETURN(rc);
}
EXPORT_SYMBOL(obd_llog_finish);
