import clutf_global
from lutf_exception import LUTFError, LutfDumper
import logging, os, yaml, shutil

LUSTRE_BASE_PATH = ''
LUTF_STATUS_STRING = 'LUTF STATUS: '
LUTF_STATUS_SUCCESS = 'Success'
LUTF_STATUS_FAILURE = 'Failure'
LUTF_STATUS_IGNORE = 'Ignore'
LUTF_CODE_STRING = 'LUTF CODE: '
MASTER_PORT = 8494
MASTER_DAEMON_PORT = 8495
AGENT_DAEMON_PORT = 8094
LUTF_SCRIPT_PATHS = ['src/',
		     'python/',
		     'python/tests-infra',
		     'python/infra',
		     'python/config',
		     'python/tests/']
MIN_IFS_NUM_DEFAULT = 3

def get_rpc_rsp_base():
	return {'rpc': {'dst': None, 'src': None, 'type': 'results', 'rc': None}}

def get_rpc_req_base():
	return {'rpc': {'src': None, 'dst': None, 'type': None, 'script': None,
			'class': None, 'method': None, 'function': None,
			'parameters': {'args': None, 'kwargs': None}}}

global_class_db = {}

def add_to_class_db(instance, class_id):
	if class_id in global_class_db:
		raise LUTFError("Duplicate class_id. Contention in timing")
	logging.debug("created instance for %s with id %f" % (type(instance).__name__, class_id))
	global_class_db[class_id] = instance

def get_class_from_db(class_id):
	if class_id in global_class_db:
		return global_class_db[class_id]
	logging.debug("Request for class not in the database %f" % class_id)

def del_entry_from_class_db(class_id):
	if class_id in global_class_db:
		instance = global_class_db[class_id]
		logging.debug("destroyed instance for %s with id %f" % (type(instance).__name__, class_id))
		del(global_class_db[class_id])

def dump_class_db():
	for k, v in global_class_db.items():
		logging.debug("id = %f, name = %s" % (k, type(v).__name__))

def populate_rpc_req(src, dst, req_type, script, cname,
		     mname, fname, class_id, *args, **kwargs):
	rpc = get_rpc_req_base()
	rpc['rpc']['src'] = src
	rpc['rpc']['dst'] = dst
	rpc['rpc']['type'] = req_type
	rpc['rpc']['script'] = script
	rpc['rpc']['class'] = cname
	rpc['rpc']['method'] = mname
	rpc['rpc']['function'] = fname
	rpc['rpc']['class_id'] = class_id
	rpc['rpc']['parameters']['args'] = args
	rpc['rpc']['parameters']['kwargs'] = kwargs
	return rpc

def populate_rpc_rsp(src, dst, rc, exception=None):
	rpc = get_rpc_rsp_base()
	rpc['rpc']['src'] = src
	rpc['rpc']['dst'] = dst
	if exception:
		rpc['rpc']['type'] = 'exception'
		rpc['rpc']['exception'] = exception
	else:
		rpc['rpc']['type'] = 'response'
	rpc['rpc']['rc'] = rc
	return rpc

GLOBAL_PREF_DEF = {'editor': shutil.which('vim'), 'loglevel': 'debug',
		   'halt_on_exception': False, 'remote copy': False,
		   'RPC timeout': 300, 'num_intfs': MIN_IFS_NUM_DEFAULT,
		   'cmd verbosity': True}

global_pref = GLOBAL_PREF_DEF

global_pref_file = os.path.join(clutf_global.get_lutf_tmp_dir(), 'lutf_pref.yaml')

def set_editor(editor):
	'''
	Set the text base editor to use for editing scripts
	'''
	global global_pref
	if shutil.which(editor):
		global_pref['editor'] = shutil.which(editor)
	else:
		logging.critical("%s is not found" % (str(editor)))
	save_pref()

def set_halt_on_exception(exc):
	'''
	Set halt_on_exception.
		True for raising exception and halting test progress
		False for continuing test progress
	'''
	global global_pref

	if type(exc) is not bool:
		logging.critical("Must be True or False")
		global_pref['halt_on_exception'] = False
		return
	global_pref['halt_on_exception'] = exc
	save_pref()

def set_rpc_timeout(timeout):
	'''
	Set the RPC timeout in seconds.
	That's the timeout to wait for the operation to complete on the remote end.
	'''
	global global_pref
	global_pref['RPC timeout'] = timeout
	save_pref()

def get_rpc_timeout():
	'''
	Get the RPC timeout in seconds.
	That's the timeout to wait for the operation to complete on the remote end.
	'''
	global global_pref
	return global_pref['RPC timeout']

def set_lustre_base_path(path):
	global LUSTRE_BASE_PATH
	LUSTRE_BASE_PATH = path

def get_lustre_base_path():
	global LUSTRE_BASE_PATH
	return LUSTRE_BASE_PATH

def set_script_remote_cp(enable):
	'''
	set the remote copy feature
	If True then scripts will be remote copied to the agent prior to execution
	'''
	global global_pref
	global_pref['remote copy'] = enable
	save_pref()

def set_logging_level(level):
	'''
	Set Python log level. One of: critical, debug, error, fatal
	'''
	global global_pref

	try:
		log_level = getattr(logging, level.upper())
		logging.getLogger('').setLevel(log_level)
		global_pref['loglevel'] = level
	except:
		logging.critical("Log level must be one of: critical, debug, error, fatal")
	save_pref()

def set_cmd_verbosity(value):
	'''
	Set the shell command verbosity to either on or off. If on, then
	all the shell commands will be written to the debug logging.
	'''
	global global_pref
	if value.upper() == 'ON':
		global_pref['cmd verbosity'] = True
	else:
		global_pref['cmd verbosity'] = False
	save_pref()

def is_cmd_verbosity():
	'''
	True if command verbosity is set, False otherwise.
	'''
	global global_pref
	return global_pref['cmd verbosity']

def load_pref():
	'''
	Load the LUTF preferences.
		editor - the editor of choice to use for editing scripts
		halt_on_exception - True to throw an exception on first error
				    False to continue running scripts
		log_level - Python log level. One of: critical, debug, error, fatal
	'''
	global GLOBAL_PREF_DEF
	global global_pref
	global global_pref_file

	if os.path.isfile(global_pref_file):
		with open(global_pref_file, 'r') as f:
			global_pref = yaml.load(f, Loader=yaml.FullLoader)
			if not global_pref:
				global_pref = GLOBAL_PREF_DEF
			else:
				#compare with the default and fill in any entries
				#which might not be there.
				for k, v in GLOBAL_PREF_DEF.items():
					if not k in global_pref:
						global_pref[k] = v
		save_pref()
	return global_pref

def save_pref():
	'''
	Save the LUTF preferences.
		editor - the editor of choice to use for editing scripts
		halt_on_exception - True to throw an exception on first error
				    False to continue running scripts
		log_level - Python log level. One of: critical, debug, error, fatal
	'''
	global global_pref
	global global_pref_file

	with open(global_pref_file, 'w') as f:
		f.write(yaml.dump(global_pref, Dumper=LutfDumper, indent=2, sort_keys=False))

def dump_pref():
	global global_pref
	print(yaml.dump(global_pref, Dumper=LutfDumper, indent=2, sort_keys=True))


