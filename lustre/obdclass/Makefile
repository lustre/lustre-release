# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#

obj-m += obdclass.o

obdclass-objs := llog.o llog_cat.o llog_obd.o llog_swab.o
obdclass-objs += class_obd.o genops.o hash.o
obdclass-objs += lprocfs_status.o lprocfs_counters.o
obdclass-objs += lustre_handles.o lustre_peer.o
obdclass-objs += statfs_pack.o obdo.o obd_config.o obd_mount.o obd_sysfs.o
obdclass-objs += lu_object.o cl_object.o cl_page.o cl_lock.o cl_io.o
obdclass-objs += linkea.o upcall_cache.o
obdclass-objs += kernelcomm.o jobid.o
obdclass-objs += integrity.o obd_cksum.o
obdclass-objs += lu_tgt_descs.o lu_tgt_pool.o
obdclass-objs += range_lock.o
obdclass-objs += page_pools.o

ifdef CONFIG_LUSTRE_FS_SERVER
obdclass-objs += dt_object.o
obdclass-objs += idmap.o
obdclass-objs += llog_ioctl.o
obdclass-objs += llog_osd.o
obdclass-objs += local_storage.o
obdclass-objs += lprocfs_jobstats.o
obdclass-objs += lprocfs_status_server.o
obdclass-objs += lu_ucred.o
obdclass-objs += md_attrs.o
obdclass-objs += obdo_server.o
obdclass-objs += scrub.o
obdclass-objs += upcall_cache_internal.o
endif

