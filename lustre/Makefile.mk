include $(src)/portals/Kernelenv

# for scripts/version_tag.pl
LINUX = @LINUX@

obj-y += portals/
obj-y += obdclass/
obj-y += ldlm/
#obj-y += lib/
#obj-y += mds/
obj-y += obdecho/
obj-y += ptlrpc/

# portals needs to be before utils/, which pulls in ptlctl objects
obj-m += utils/
