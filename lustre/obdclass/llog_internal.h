#ifndef __LLOG_INTERNAL_H__
#define __LLOG_INTERNAL_H__

int llog_get_cat_list(struct obd_device *obd, struct obd_device *disk_obd, 
                      char *name, int count, struct llog_logid *idarray);
int llog_put_cat_list(struct obd_device *obd, struct obd_device *disk_obd, 
                      char *name, int count, struct llog_logid *);
struct llog_ctxt* push_llog_ioctl_ctxt(struct obd_device *obd, 
                                       struct obd_run_ctxt *saved);
void pop_llog_ioctl_ctxt(struct obd_device *obd, struct obd_run_ctxt *saved,
                         struct llog_ctxt *ctxt);
int llog_ioctl(struct llog_ctxt *ctxt, int cmd, 
               struct obd_ioctl_data *data, void *arg, int len);
int llog_cat_id2handle(struct llog_handle *cathandle, struct llog_handle **res,
                       struct llog_logid *logid);
#endif
