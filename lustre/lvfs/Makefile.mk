include $(src)/../portals/Kernelenv

obj-y += lvfs.o fsfilt_ext3.o 
lvfs-objs := fsfilt.o  lvfs_common.o  lvfs_linux.o 
