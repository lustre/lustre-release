include $(src)/portals/Kernelenv

# for scripts/version_tag.pl
LINUX = @LINUX@

obj-y += portals/
# obdclass has to come before anything that does class_register..
obj-y += obdclass/
obj-y += lib/
obj-y += ptlrpc/
obj-y += ldlm/
#obj-y += mds/
obj-y += obdecho/
obj-y += osc/
obj-y += ost/

# portals needs to be before utils/, which pulls in ptlctl objects
obj-m += utils/
