/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _MGS_INTERNAL_H
#define _MGS_INTERNAL_H

#include <linux/lustre_mgs.h>

#define MGS_SERVICE_WATCHDOG_TIMEOUT (obd_timeout * 1000)

extern struct lvfs_callback_ops mgs_lvfs_ops;

int mgs_init_db_list(struct obd_device *obd);
int mgs_cleanup_db_list(struct obd_device *obd);
int mgs_set_next_index(struct obd_device *obd, struct mgmt_target_info *mti);
int mgs_write_log_target(struct obd_device *obd, struct mgmt_target_info *mti);

#endif
