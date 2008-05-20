#ifndef __LLOG_INTERNAL_H__
#define __LLOG_INTERNAL_H__

#include <lustre_log.h>

struct llog_process_info {
        struct llog_handle *lpi_loghandle;
        llog_cb_t           lpi_cb;
        void               *lpi_cbdata;
        void               *lpi_catdata;
        int                 lpi_rc;
        struct completion   lpi_completion;
};

int llog_put_cat_list(struct obd_device *obd, struct obd_device *disk_obd,
                      char *name, int count, struct llog_catid *idarray);
int llog_cat_id2handle(struct llog_handle *cathandle, struct llog_handle **res,
                       struct llog_logid *logid);
int class_config_dump_handler(struct llog_handle * handle,
                              struct llog_rec_hdr *rec, void *data);
#endif
