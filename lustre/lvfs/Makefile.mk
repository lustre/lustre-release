include $(src)/../portals/Kernelenv

obj-y += lvfs.o fsfilt_ext3.o fsfilt_smfs.o
lvfs-objs := fsfilt.o lvfs_common.o llog_lvfs.o lvfs_linux.o 
lvfs-objs += llog.o llog_cat.o 
