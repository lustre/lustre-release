#ifndef __LLOG_INTERNAL_H__
#define __LLOG_INTERNAL_H__

int llog_get_cat_list(struct obd_device *obd, struct obd_device *disk_obd, 
                      char *name, int count, struct llog_logid *idarray);
int llog_put_cat_list(struct obd_device *obd, struct obd_device *disk_obd, 
                      char *name, int count, struct llog_logid *);
#endif
