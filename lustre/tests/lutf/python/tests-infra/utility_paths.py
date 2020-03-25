import os, time, logging
from lutf_common_def import get_lustre_base_path
from lutf_cmd import lutf_exec_local_cmd

base_lustre = ''
LNETCTL = ''
LCTL = ''
LUSTRE_RMMOD = ''
MKFS = ''

def get_lnetctl():
	return LNETCTL
def get_lctl():
	return LCTL
def get_mkfs():
	return MKFS
def get_lustre_rmmod():
	return LUSTRE_RMMOD

def set_default_paths():
	global base_lustre
	global LNETCTL
	global LCTL
	global LUSTRE_RMMOD
	global MKFS

	paths_set = False
	base_lustre = get_lustre_base_path()

	if base_lustre:
		LNETCTL = os.path.join(base_lustre, 'lnet', 'utils', 'lnetctl')
		LCTL = os.path.join(base_lustre, 'lustre', 'utils', 'lctl')
		LUSTRE_RMMOD = os.path.join(base_lustre, 'lustre', 'scripts', 'lustre_rmmod')
		MKFS = os.path.join(base_lustre, 'lustre', 'utils', 'mkfs.lustre')
		# the assumption is that if we're working from the home directory
		# then if one utility is present all of them are present. We don't
		# support a hybrid environment, where some lustre utilities are
		# from the build directory and others are installed
		if os.path.isfile(LNETCTL):
			paths_set = True

	if not paths_set:
		LNETCTL = os.path.join(os.path.sep, 'usr', 'sbin', 'lnetctl')
		LCTL = os.path.join(os.path.sep, 'usr', 'sbin', 'lctl')
		LUSTRE_RMMOD = os.path.join(os.path.sep, 'usr', 'sbin', 'lustre_rmmod')
		MKFS = os.path.join(os.path.sep, 'usr', 'sbin', 'mkfs.lustre')


MODPROBE = os.path.join(os.path.sep, 'usr', 'sbin', 'modprobe')
INSMOD = os.path.join(os.path.sep, 'usr', 'sbin', 'insmod')
LSMOD = os.path.join(os.path.sep, 'usr', 'sbin', 'lsmod')
RMMOD = os.path.join(os.path.sep, 'usr', 'sbin', 'rmmod')
MOUNT = os.path.join(os.path.sep, 'usr', 'bin', 'mount')
UMOUNT = os.path.join(os.path.sep, 'usr', 'bin', 'umount')
CAT = os.path.join(os.path.sep, 'usr', 'bin', 'cat')
MAN = os.path.join(os.path.sep, 'usr', 'bin', 'man')

set_default_paths()

lmodules=[
'libcfs/libcfs/libcfs.ko',
'lnet/klnds/socklnd/ksocklnd.ko',
'lnet/lnet/lnet.ko',
'lnet/selftest/lnet_selftest.ko',
'lustre/obdclass/obdclass.ko',
'lustre/ptlrpc/ptlrpc.ko',
'lustre/fld/fld.ko',
'lustre/fid/fid.ko',
'lustre/obdclass/llog_test.ko',
'lustre/ptlrpc/gss/ptlrpc_gss.ko',
'lustre/obdecho/obdecho.ko',
'lustre/mgc/mgc.ko',
'lustre/red/red.ko',
'lustre/tests/kernel/kinode.ko',
'lustre/ost/ost.ko',
'lustre/mgs/mgs.ko',
'lustre/lfsck/lfsck.ko',
'lustre/quota/lquota.ko',
'lustre/mdt/mdt.ko',
'lustre/mdd/mdd.ko',
'lustre/ofd/ofd.ko',
'lustre/osp/osp.ko',
'lustre/lod/lod.ko',
'lustre/lov/lov.ko',
'lustre/osc/osc.ko',
'lustre/mdc/mdc.ko',
'lustre/lmv/lmv.ko',
'lustre/llite/lustre.ko',
'ldiskfs/ldiskfs.ko',
'lustre/osd-ldiskfs/osd_ldiskfs.ko',
]

lnetmodules=['libcfs/libcfs/libcfs.ko',
'lnet/lnet/lnet.ko',
'lnet/klnds/socklnd/ksocklnd.ko',
'lnet/selftest/lnet_selftest.ko']

def load_lnet(modparams = {}):
	global base_lustre
	global LNETCTL
	global LCTL
	global LUSTRE_RMMOD
	global MKFS

	set_default_paths()

	logging.critical("utility_paths::load_lnet")

	modules = lutf_exec_local_cmd(LSMOD)
	if modules and len(modules) >= 2:
		logging.critical(str(modules[0]) + "\nrc = "+ str(modules[1]))

	if not base_lustre or \
	   not os.path.isfile(os.path.join(base_lustre, 'lnet', 'lnet', 'lnet.ko')):
		lutf_exec_local_cmd(MODPROBE + ' lnet')
		# configure lnet. No extra module parameters loaded
		lutf_exec_local_cmd(LNETCTL + " lnet configure")
		return

	for module in lnetmodules:
		m = os.path.basename(module)
		if m in list(modparams.keys()):
			cmd = INSMOD + ' ' + os.path.join(base_lustre, module)
			for k, v in modparams[m].items():
				cmd += ' '+k+ '='+str(v)
		else:
			cmd = INSMOD + ' ' + os.path.join(base_lustre, module)
		rc = lutf_exec_local_cmd(cmd, exception=False)

	# configure lnet. No extra module parameters loaded
	rc = lutf_exec_local_cmd(LNETCTL + " net show")
	if rc:
		logging.critical(str(rc[0].decode('utf-8')))
	lutf_exec_local_cmd(LNETCTL + " lnet configure")
	lutf_exec_local_cmd(LNETCTL + " net del --net tcp", exception=False)
	rc = lutf_exec_local_cmd(LNETCTL + " net show")
	if rc:
		logging.critical(str(rc[0].decode('utf-8')))

def load_lustre(modparams = {}):
	global base_lustre
	global LNETCTL
	global LCTL
	global LUSTRE_RMMOD
	global MKFS

	set_default_paths()

	logging.critical("utility_paths::load_lustre")

	if not base_lustre or \
	   not os.path.isfile(os.path.join(base_lustre, 'lustre', 'llite', 'lustre.ko')):
		lutf_exec_local_cmd(MODPROBE + ' lustre', exception=False)
		return

	lutf_exec_local_cmd('modprobe crc_t10dif')
	lutf_exec_local_cmd('insmod /lib/modules/3.10.0-1062.9.1.el7.x86_64/kernel/fs/jbd2/jbd2.ko.xz', exception=False)
	lutf_exec_local_cmd('insmod /lib/modules/3.10.0-1062.9.1.el7.x86_64/kernel/fs/mbcache.ko.xz', exception=False)
	for module in lmodules:
		m = os.path.basename(module)
		if m in list(modparams.keys()):
			cmd = INSMOD + ' ' + os.path.join(base_lustre, module)
			for k, v in modparams[m].items():
				cmd += ' '+k+ '='+str(v)
		else:
			cmd = INSMOD + ' ' + os.path.join(base_lustre, module)
		lutf_exec_local_cmd(cmd, exception=False)

def lustre_rmmod():
	global base_lustre
	global LNETCTL
	global LCTL
	global LUSTRE_RMMOD
	global MKFS

	logging.critical("utility_paths::lustre_rmmod()")
	set_default_paths()

	logging.critical("lustre_rmmod::" + LUSTRE_RMMOD)
	lutf_exec_local_cmd(LUSTRE_RMMOD, exception=False)
	logging.critical("lustre_rmmod::" + RMMOD + " lnet_selftest")
	lutf_exec_local_cmd(RMMOD + " lnet_selftest", exception=False)
	logging.critical("lustre_rmmod::" + LNETCTL + " lnet unconfigure")
	lutf_exec_local_cmd(LNETCTL + " lnet unconfigure", exception=False)
	try:
		rc = lutf_exec_local_cmd(LUSTRE_RMMOD)
	except:
		rc = [None, -1]
		pass
	i = 0
	while rc[1] != 0 and i < 5:
		time.sleep(1)
		try:
			rc = lutf_exec_local_cmd(LUSTRE_RMMOD)
		except:
			rc = [None, -1]
			pass
		i += 1
	if rc[1] != 0:
		return False
	return True;

