include $(src)/portals/Kernelenv

# for scripts/version_tag.pl
LINUX = @LINUX@

obj-y += portals/
obj-y += obdclass/
obj-y += obdecho/
obj-y += mds/
obj-y += lib/
