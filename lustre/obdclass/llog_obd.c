
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

#include <linux/fs.h>
#include <linux/obd_class.h>
#include <linux/lustre_log.h>
#include <portals/list.h>
#include "llog_internal.h"

/* helper functions for calling the llog obd methods */

int llog_setup(struct obd_device *obd, int index, struct obd_device *disk_obd, 
               int count, struct llog_logid *logid, struct llog_operations *op)
{
        int rc = 0;
        struct llog_obd_ctxt *ctxt;
        ENTRY;

        if (index < 0 || index >= LLOG_MAX_CTXTS)
                RETURN(-EFAULT);

        OBD_ALLOC(ctxt, sizeof(*ctxt));
        if (!ctxt)
                RETURN(-ENOMEM);

        obd->obd_llog_ctxt[index] = ctxt;
        ctxt->loc_obd = obd;
        ctxt->loc_exp = class_export_get(disk_obd->obd_self_export);
        ctxt->loc_idx = index;
        ctxt->loc_logops = op;
        sema_init(&ctxt->loc_sem, 1);

        if (op->lop_setup)
                rc = op->lop_setup(obd, index, disk_obd, count, logid);
        if (ctxt && rc) 
                OBD_FREE(ctxt, sizeof(*ctxt));

        RETURN(rc);
}
EXPORT_SYMBOL(llog_setup);

int llog_cleanup(struct llog_obd_ctxt *ctxt)
{
        int rc = 0;
        ENTRY;

        LASSERT(ctxt);

        if (CTXTP(ctxt, cleanup))
                rc = CTXTP(ctxt, cleanup)(ctxt);

        ctxt->loc_obd->obd_llog_ctxt[ctxt->loc_idx] = NULL;
        class_export_put(ctxt->loc_exp);
        ctxt->loc_exp = NULL;
        OBD_FREE(ctxt, sizeof(*ctxt));

        RETURN(rc);
}
EXPORT_SYMBOL(llog_cleanup);

int llog_add(struct llog_obd_ctxt *ctxt,
                 struct llog_rec_hdr *rec, struct lov_stripe_md *lsm,
                 struct llog_cookie *logcookies, int numcookies)
{
        int rc;
        ENTRY;

        LASSERT(ctxt);
        CTXT_CHECK_OP(ctxt, add, -EOPNOTSUPP);

        rc = CTXTP(ctxt, add)(ctxt, rec, lsm, logcookies, numcookies);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_add);

int llog_cancel(struct llog_obd_ctxt *ctxt, struct lov_stripe_md *lsm,
                int count, struct llog_cookie *cookies, int flags)
{
        int rc;
        ENTRY;

        LASSERT(ctxt);
        CTXT_CHECK_OP(ctxt, cancel, -EOPNOTSUPP);
        rc = CTXTP(ctxt, cancel)(ctxt, lsm, count, cookies, flags);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_cancel);


/* lop_setup method for filter/osc */
// XXX how to set exports
int llog_obd_origin_setup(struct obd_device *obd, int index, struct obd_device *disk_obd,
                          int count, struct llog_logid *logid)
{
        struct llog_obd_ctxt *ctxt;
        struct llog_handle *handle;
        struct obd_run_ctxt saved;
        int rc;
        ENTRY;

        if (count == 0)
                RETURN(0);

        LASSERT(count == 1);
        
        LASSERT(obd->obd_llog_ctxt[index]);
        ctxt = obd->obd_llog_ctxt[index];

        if (logid->lgl_oid)
                rc = llog_create(ctxt, &handle, logid, NULL);
        else {
                rc = llog_create(ctxt, &handle, NULL, NULL);
                if (!rc) 
                        *logid = handle->lgh_id;
        }
        if (rc) 
                GOTO(out, rc);

        ctxt->loc_handle = handle;
        push_ctxt(&saved, &disk_obd->obd_ctxt, NULL);
        rc = llog_init_handle(handle,  LLOG_F_IS_CAT, NULL);
        pop_ctxt(&saved, &disk_obd->obd_ctxt, NULL);
 out:
        if (ctxt && rc) {
                obd->obd_llog_ctxt[index] = NULL;
                OBD_FREE(ctxt, sizeof(*ctxt));
        }
        RETURN(rc);
}
EXPORT_SYMBOL(llog_obd_origin_setup);

int llog_obd_origin_cleanup(struct llog_obd_ctxt *ctxt)
{
        if (!ctxt)
                return 0;

        if (ctxt->loc_handle)
                llog_cat_put(ctxt->loc_handle);
        
        return 0;
}
EXPORT_SYMBOL(llog_obd_origin_cleanup);


/* add for obdfilter/sz and mds/unlink */
int llog_obd_origin_add(struct llog_obd_ctxt *ctxt,
                        struct llog_rec_hdr *rec, struct lov_stripe_md *lsm,
                        struct llog_cookie *logcookies, int numcookies)
{
        struct llog_handle *cathandle;
        int rc;
        ENTRY;

        cathandle = ctxt->loc_handle;
        LASSERT(cathandle != NULL);
        rc = llog_cat_add_rec(cathandle, rec, logcookies, NULL);
        if (rc != 1)
                CERROR("write one catalog record failed: %d\n", rc);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_obd_origin_add);

int llog_cat_initialize(struct obd_device *obd, int count)
{
        struct llog_logid *idarray;
        int size = sizeof(*idarray) * count;
        char name[32] = "CATLIST";
        int rc;
        ENTRY;

        OBD_ALLOC(idarray, size);
        if (!idarray)
                RETURN(-ENOMEM);

        memset(idarray, 0, size);

        rc = llog_get_cat_list(obd, obd, name, count, idarray);
        if (rc) {
                CERROR("rc: %d\n", rc);
                GOTO(out, rc);
        }

        rc = obd_llog_init(obd, obd, count, idarray);
        if (rc) {
                CERROR("rc: %d\n", rc);
                GOTO(out, rc);
        }

        rc = llog_put_cat_list(obd, obd, name, count, idarray);
        if (rc) {
                CERROR("rc: %d\n", rc);
                GOTO(out, rc);
        }
                        
 out:
        OBD_FREE(idarray, size);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_initialize);
 
int obd_llog_init(struct obd_device *obd, struct obd_device *disk_obd,
                  int count, struct llog_logid *logid)
{
        int rc;
        ENTRY;
        OBD_CHECK_OP(obd, llog_init, 0);
        OBD_COUNTER_INCREMENT(obd, llog_init);

        rc = OBP(obd, llog_init)(obd, disk_obd, count, logid);
        RETURN(rc);
}
EXPORT_SYMBOL(obd_llog_init);

int obd_llog_finish(struct obd_device *obd, int count)
{
        int rc;
        ENTRY;
        OBD_CHECK_OP(obd, llog_finish, 0);
        OBD_COUNTER_INCREMENT(obd, llog_finish);

        rc = OBP(obd, llog_finish)(obd, count);
        RETURN(rc);
}
EXPORT_SYMBOL(obd_llog_finish);
