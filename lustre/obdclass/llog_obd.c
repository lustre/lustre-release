
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

int obd_llog_setup(struct obd_device *obd, struct obd_device *disk_obd,
                   int index, int count, struct llog_logid *logid)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, llog_setup);
        OBD_COUNTER_INCREMENT(obd, llog_setup);

        rc = OBP(obd, llog_setup)(obd, disk_obd, index, count, logid);
        RETURN(rc);
}
EXPORT_SYMBOL(obd_llog_setup);

int obd_llog_cleanup(struct obd_device *obd)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, llog_cleanup);
        OBD_COUNTER_INCREMENT(obd, llog_cleanup);

        rc = OBP(obd, llog_cleanup)(obd);
        RETURN(rc);
}
EXPORT_SYMBOL(obd_llog_cleanup);

int obd_llog_origin_add(struct obd_export *exp,
                        int index,
                        struct llog_rec_hdr *rec, struct lov_stripe_md *lsm,
                        struct llog_cookie *logcookies, int numcookies)
{
        int rc;
        ENTRY;

        EXP_CHECK_OP(exp, llog_origin_add);
        OBD_COUNTER_INCREMENT(exp->exp_obd, llog_origin_add);

        rc = OBP(exp->exp_obd, llog_origin_add)
                (exp, index, rec, lsm, logcookies, numcookies);
        RETURN(rc);
}
EXPORT_SYMBOL(obd_llog_origin_add);

int obd_llog_repl_cancel(struct obd_device *obd, struct lov_stripe_md *lsm,
                          int count, struct llog_cookie *cookies, int flags)
{
        int rc;
        ENTRY;

        OBD_CHECK_OP(obd, llog_repl_cancel);
        OBD_COUNTER_INCREMENT(obd, llog_repl_cancel);

        rc = OBP(obd, llog_repl_cancel)(obd, lsm, count, cookies, flags);
        RETURN(rc);
}
EXPORT_SYMBOL(obd_llog_repl_cancel);

/* now some implementations of these stubs useful on the OSC and OBDFILTER */
int llog_obd_setup(struct obd_device *obd, struct obd_device *disk_obd,
                   int index, int count, struct llog_logid *logid)
{
        struct llog_obd_ctxt *ctxt;
        struct llog_handle *handle;
        struct obd_run_ctxt saved;
        int rc;

        LASSERT(count == 1);
        
        if (index == 0) {
                OBD_ALLOC(ctxt, sizeof(*ctxt));
                if (!ctxt)
                        RETURN(-ENOMEM);
                
                if (disk_obd->obd_llog_ctxt) {
                        CERROR("llog_ctxt already allocated\n");
                        LBUG();
                }
                disk_obd->obd_llog_ctxt = ctxt;
                sema_init(&disk_obd->obd_llog_ctxt->loc_sem, 1);
        } else 
                ctxt = disk_obd->obd_llog_ctxt;

        if (index < 0 || index >= LLOG_OBD_MAX_HANDLES) { 
                CERROR("llog_ctxt index out of range\n");
                LBUG();
        }

        if (logid->lgl_oid)
                rc = llog_create(disk_obd, &handle, logid, NULL);
        else {
                rc = llog_create(disk_obd, &handle, NULL, NULL);
                if (!rc) 
                        *logid = handle->lgh_id;
        }
        if (rc) 
                GOTO(out, rc);

        disk_obd->obd_llog_ctxt->loc_handles[index] = handle;
        push_ctxt(&saved, &disk_obd->obd_ctxt, NULL);
        rc = llog_init_handle(handle,  LLOG_F_IS_CAT, NULL);
        pop_ctxt(&saved, &disk_obd->obd_ctxt, NULL);
 out:
        if (ctxt && rc) 
                OBD_FREE(ctxt, sizeof(*ctxt));
        RETURN(rc);
}
EXPORT_SYMBOL(llog_obd_setup);

int llog_obd_cleanup(struct obd_device *obd)
{
        int i;
        struct llog_obd_ctxt *ctxt = obd->obd_llog_ctxt;

        if (!ctxt)
                return 0;

        if (ctxt->loc_imp) {
                //class_destroy_import(ctxt->loc_imp);
                ctxt->loc_imp = NULL;
        }

        for (i=0 ; i < LLOG_OBD_MAX_HANDLES ;i++ )
                if (obd->obd_llog_ctxt->loc_handles[i])
                        llog_cat_put(obd->obd_llog_ctxt->loc_handles[i]);
        
        OBD_FREE(obd->obd_llog_ctxt, sizeof(*obd->obd_llog_ctxt));
        obd->obd_llog_ctxt = NULL;
        return 0;
}
EXPORT_SYMBOL(llog_obd_cleanup);

int llog_obd_origin_add(struct obd_export *exp,
                    int index,
                    struct llog_rec_hdr *rec, struct lov_stripe_md *lsm,
                    struct llog_cookie *logcookies, int numcookies)
{
        struct llog_handle *cathandle;
        struct obd_export *export = exp->exp_obd->obd_log_exp;
        int rc;
        ENTRY;

        if (index < 0 || index >= LLOG_OBD_MAX_HANDLES) {
                LBUG();
                RETURN(-EINVAL);
        }

        //cathandle = exp->exp_obd->obd_llog_ctxt->loc_handles[index];
        cathandle = export->exp_obd->obd_llog_ctxt->loc_handles[index];
        LASSERT(cathandle != NULL);
        rc = llog_cat_add_rec(cathandle, rec, logcookies, NULL);
        if (rc != 1)
                CERROR("write one catalog record failed: %d\n", rc);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_obd_origin_add);

/* initialize the local storage obd for the logs */
int llog_initialize(struct obd_device *obd)
{
        struct obd_export *exp;
        ENTRY;

        if (obd->obd_log_exp)
                RETURN(0);

        exp = class_new_export(obd);
        if (exp == NULL)
                RETURN(-ENOMEM);
        memcpy(&exp->exp_client_uuid, &obd->obd_uuid, 
               sizeof(exp->exp_client_uuid));
        obd->obd_log_exp = exp;
        class_export_put(exp);

        obd->obd_logops = &llog_lvfs_ops;
        RETURN(0);
}
EXPORT_SYMBOL(llog_initialize);

/* disconnect the local storage obd for the logs */
int llog_disconnect(struct obd_device *obd)
{
        struct obd_export *exp;
        ENTRY;

        LASSERT(obd->obd_log_exp);
        exp = obd->obd_log_exp;

        class_handle_unhash(&exp->exp_handle);
        spin_lock(&exp->exp_obd->obd_dev_lock);
        list_del_init(&exp->exp_obd_chain);
        exp->exp_obd->obd_num_exports--;
        spin_unlock(&exp->exp_obd->obd_dev_lock);
        OBD_FREE(exp, sizeof(*exp));
        if (obd->obd_set_up) {
                atomic_dec(&obd->obd_refcount);
                wake_up(&obd->obd_refcount_waitq);
        }

        obd->obd_log_exp = NULL;
        obd->obd_logops = NULL;
        RETURN(0);
}
EXPORT_SYMBOL(llog_disconnect);

int llog_cat_initialize(struct obd_device *obd, int count)
{
        int rc, i;
        char name[32];
        struct llog_logid *idarray;
        int size = sizeof(*idarray) * count;
        ENTRY;

        LASSERT(obd->obd_log_exp);

        OBD_ALLOC(idarray, size);
        if (!idarray)
                RETURN(-ENOMEM);

        for (i = 0; i < LLOG_OBD_MAX_HANDLES; i++) {
                sprintf(name, "CATLIST-%d", i);
                memset(idarray, 0, size);
                rc = llog_get_cat_list(obd, obd, name, count, idarray);
                if (rc) {
                        CERROR("rc: %d\n", rc);
                        GOTO(out, rc);
                }
                rc = obd_llog_setup(obd, obd, i, count, idarray);
                if (rc) {
                        CERROR("rc: %d\n", rc);
                        GOTO(out, rc);
                }
                rc = llog_put_cat_list(obd, obd, name, count, idarray);
                if (rc) {
                        CERROR("rc: %d\n", rc);
                        GOTO(out, rc);
                }
        }
                        
 out:
        OBD_FREE(idarray, size);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_cat_initialize);
