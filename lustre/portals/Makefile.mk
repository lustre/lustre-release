include $(obj)/Kernelenv

# The ordering of these determines the order that each subsystem's 
# module_init() functions are called in.  if these are changed make sure
# they reflect the dependencies between each subsystem's _init functions.
obj-y += libcfs/
obj-y += portals/
obj-y += router/
obj-y += knals/
obj-y += tests/
