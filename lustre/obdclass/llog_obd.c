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

int obd_llog_open(struct obd_device *obd, struct obd_device *disk_obd,
                  int index, int named, int flags, struct obd_uuid *log_uuid)
{
        int rc;
        ENTRY;

        

        RETURN(rc);
}
EXPORT_SYMBOL(obd_llog_open);

int obd_log_add(struct obd_export *exp, struct llog_handle *cathandle,
                struct llog_rec_hdr *rec, void *buf, 
                struct llog_cookie *logcookies, int numcookies)
{
        struct obd_device *obd = class_exp2obd(exp->exp_obd->obd_log_exp);
        struct obd_run_ctxt saved;
        int rc;
        ENTRY;

        LASSERT(cathandle != NULL);
        push_ctxt(&saved, &obd->obd_ctxt, NULL); 
        rc = llog_cat_add_rec(cathandle, rec, logcookies, buf);
        if (rc != 1)
                CERROR("write one catalog record failed: %d\n", rc);
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);

        RETURN(rc);
}
EXPORT_SYMBOL(obd_log_add);

int obd_log_cancel(struct obd_export *exp, struct llog_handle *cathandle,
                   void *buf, int count, struct llog_cookie *cookies, int flags)
{
        struct obd_device *obd = class_exp2obd(exp->exp_obd->obd_log_exp);
        struct obd_run_ctxt saved;
        int rc;
        ENTRY;

        LASSERT(cathandle != NULL);
        push_ctxt(&saved, &obd->obd_ctxt, NULL); 
        rc = llog_cat_cancel_records(cathandle, count, cookies);
        if (rc)
                CERROR("cancel %d catalog record failed: %d\n", count, rc);
        pop_ctxt(&saved, &obd->obd_ctxt, NULL);

        RETURN(rc);
}
EXPORT_SYMBOL(obd_log_cancel);
