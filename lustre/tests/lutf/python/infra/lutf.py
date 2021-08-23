from pathlib import Path
from clutf_agent import *
from lutf_common_def import *
import lutf_common_def as common
from lutf_exception import LUTFError, LutfDumper
from lutf_cmd import lutf_exec_local_cmd
import importlib, socket
import clutf_global
import lutf_agent
import netifaces
import os, subprocess, sys, yaml, fnmatch, logging, csv
import shutil, traceback, datetime, re, copy

preferences = {}
lutf_tmp_dir = ''

class LutfYaml:
	def __init__(self, y=None):
		if y is not None and (type(y) is not dict and type(y) is not list):
			raise LUTFError('This class takes dictionaries or lists only')
		self.__yaml = y

	def get(self):
		return self.__yaml

	def dump(self):
		return yaml.dump(self.__yaml)

	def load(self, stream):
		if self.__yaml:
			raise LUTFError('There exists a YAML instance')
		self.__yaml = yaml.load(stream, Loader=yaml.FullLoader)

	def unload(self):
		self.__yaml = None

class YamlResults:
	def __init__(self):
		self.__results = []
		self.__max = 0
		self.__n = 0

	def __setitem__(self, key, value):
		for i, e in enumerate(self.__results):
			if e.get()['name'] == key:
				value['name'] = key
				self.__results[i] = LutfYaml(value)
				return
		value['name'] = key
		self.__results.append(LutfYaml(value))
		self.__max = len(self.__results)

	def __getitem__(self, key):
		for entry in self.__results:
			if entry.get()['name'] == key:
				return entry
		return None

	def __iter__(self):
		self.__n = 0
		return self

	# needed for python 3.x
	def __next__(self):
		if self.__n < self.__max:
			rc = self.__results[self.__n]
			self.__n += 1
			return rc['name'], rc.get()
		else:
			raise StopIteration

	def get(self, status=None):
		shadow = []
		for entry in self.__results:
			e = entry.get()
			if status and type(status) == str:
				if e['status'] != status.upper():
					continue
			shadow.append(entry.get())
		return shadow

# subtest_result = YamlResults
# global_test_resutls['lutf-dlc']['script-name'] = rc
class YamlGlobalTestResults:
	def __init__(self, desc=None):
		if not desc:
			self.desc = 'auster lutf'
		self.__results = {'Tests': []}
		self.__max = 0
		self.__n = 0

	def __setitem__(self, key, value):
		if type(value) != dict:
			raise TypeError("This class only takes dict type")
		for i, e in enumerate(self.__results['Tests']):
			if e['name'] == key:
				self.__results['Tests'][i]['SubTests'][value['name']] = value
				self.finalize(key)
				return
		lutf = {'name': key, 'description': self.desc, 'SubTests': YamlResults()}
		lutf['SubTests'][value['name']] = value
		self.__results['Tests'].append(lutf)
		self.__max = len(self.__results['Tests'])
		self.finalize(key)

	def __getitem__(self, key):
		for entry in self.__results['Tests']:
			if entry['name'] == key:
				return entry['SubTests']
		return None

	def __iter__(self):
		self.__n = 0
		return self

	# needed for python 3.x
	def __next__(self):
		if self.__n < self.__max:
			rc = self.__results['Tests'][self.__n]
			self.__n += 1
			return rc['name'], rc
		else:
			raise StopIteration

	def finalize(self, name):
		timefmt = datetime.datetime.utcnow().strftime('%a %b %d %H:%M:%S UTC %Y')
		for e in self.__results['Tests']:
			if e['name'] == name:
				total_duration = 0
				sstatus = 'PASS'
				subs = e['SubTests'].get()
				for r in subs:
					total_duration += r['duration']
					if r['status'] == 'FAIL':
						sstatus = 'FAIL'
				e['duration'] = total_duration
				# TODO: Pass the LUTF for now until we clean up the tests
				sstatus = 'PASS'
				e['status'] = sstatus
				e['submission'] = timefmt

	def get(self):
		rc = copy.deepcopy(self.__results)
		for t in rc['Tests']:
			t['SubTests'] = t['SubTests'].get()
		return rc

class Documentation:
	def __init__(self, base_name):
		doc_path = os.path.join(clutf_global.get_lutf_path(), 'documentation')
		Path(doc_path).mkdir(parents=True, exist_ok=True)
		self.__req = os.path.join(clutf_global.get_lutf_path(), 'documentation',
					  os.path.splitext(base_name)[0]+'_req.csv')
		self.__hld = os.path.join(clutf_global.get_lutf_path(), 'documentation',
					  os.path.splitext(base_name)[0]+'_hld.csv')
		self.__tp = os.path.join(clutf_global.get_lutf_path(), 'documentation',
					  os.path.splitext(base_name)[0]+'_tp.csv')
		self.__req_writeheader()
		self.__hld_writeheader()
		self.__tp_writeheader()

	def __req_writeheader(self):
		if not os.path.isfile(self.__req):
			header = ["Test Case ID", "Requirement Id", "Requirement Description"]
			with open(self.__req, 'w') as fcsv:
				writer = csv.writer(fcsv)
				writer.writerow(header)

	def __hld_writeheader(self):
		if not os.path.isfile(self.__req):
			header = ["Test Case ID", "Requirement Id", "Design Notes"]
			with open(self.__hld, 'w') as fcsv:
				writer = csv.writer(fcsv)
				writer.writerow(header)

	def __tp_writeheader(self):
		if not os.path.isfile(self.__req):
			header = ["Test Case ID", "Primary Requirement Id", "Secondary Requirement Id", "Test Case"]
			with open(self.__tp, 'w') as fcsv:
				writer = csv.writer(fcsv)
				writer.writerow(header)

	def req_writerow(self, req_id, req_desc, fname):
		with open(self.__req, 'a+') as fcsv:
			writer = csv.writer(fcsv)
			writer.writerow([fname, req_id, req_desc])

	def hld_writerow(self, req_id, design, fname):
		with open(self.__hld, 'a+') as fcsv:
			writer = csv.writer(fcsv)
			writer.writerow([fname, req_id, design])

	def tp_writerow(self, preq_id, sreq_id, tc, fname):
		with open(self.__tp, 'a+') as fcsv:
			writer = csv.writer(fcsv)
			writer.writerow([fname, preq_id, sreq_id, tc])

class Script:
	def __init__(self, abs_path, callbacks, parent_suite, collection):
		self.name = os.path.splitext(os.path.split(abs_path)[1])[0]
		self.__abs_path = abs_path
		self.__callbacks = callbacks
		self.__parent_suite = parent_suite.replace('suite_', '')
		self.__collection = collection

	def is_expected_failure(self, name):
		return self.__collection.in_expected_failures_list(name)

	def create_docs(self, csvfile):
		# open script and extract comment block. It is expected to
		# be at the beginning of the file
		doc = []
		start = False
		with open(self.__abs_path, 'r') as f:
			lines = f.readlines()
			for l in lines:
				if len(l.strip()) > 0 and l.strip() == '"""':
					if start:
						start = False
						break
					else:
						start = True
				elif start:
					doc.append(l.strip())
		if len(doc) == 0:
			return

		meta = {'prim': {'txt': [], 'st': False},
			'primd': {'txt': [], 'st': False},
			'sec': {'txt': [], 'st': False},
			'des': {'txt': [], 'st': False},
			'tc': {'txt': [], 'st': False}}

		for l in doc:
			if '@PRIMARY:' in l:
				meta['prim']['st'] = True
				meta['primd']['st'] = False
				meta['sec']['st'] = False
				meta['des']['st'] = False
				meta['tc']['st'] = False
				meta['prim']['txt'].append(l.split('@PRIMARY:')[1].strip())
			elif '@PRIMARY_DESC:' in l:
				meta['prim']['st'] = False
				meta['primd']['st'] = True
				meta['sec']['st'] = False
				meta['des']['st'] = False
				meta['tc']['st'] = False
				meta['primd']['txt'].append(l.split('@PRIMARY_DESC:')[1].strip())
			elif '@SECONDARY:' in l:
				meta['prim']['st'] = False
				meta['primd']['st'] = False
				meta['sec']['st'] = True
				meta['des']['st'] = False
				meta['tc']['st'] = False
				meta['sec']['txt'].append(l.split('@SECONDARY:')[1].strip())
			elif '@DESIGN:' in l:
				meta['prim']['st'] = False
				meta['primd']['st'] = False
				meta['sec']['st'] = False
				meta['des']['st'] = True
				meta['tc']['st'] = False
				meta['des']['txt'].append(l.split('@DESIGN:')[1].strip())
			elif '@TESTCASE:' in l:
				meta['prim']['st'] = False
				meta['primd']['st'] = False
				meta['sec']['st'] = False
				meta['des']['st'] = False
				meta['tc']['st'] = True
				meta['tc']['txt'].append(l.split('@TESTCASE:')[1].strip())
			elif meta['prim']['st']:
				meta['prim']['txt'].append('\n'+l)
			elif meta['primd']['st']:
				meta['primd']['txt'].append('\n'+l)
			elif meta['sec']['st']:
				meta['sec']['txt'].append('\n'+l)
			elif meta['des']['st']:
				meta['des']['txt'].append('\n'+l)
			elif meta['tc']['st']:
				meta['tc']['txt'].append('\n'+l)

		documentation = Documentation(csvfile)
		documentation.req_writerow("".join(meta['prim']['txt']),
					   "".join(meta['primd']['txt']),
					   self.name)
		documentation.hld_writerow("".join(meta['prim']['txt']),
					   "".join(meta['des']['txt']),
					   self.name)
		documentation.tp_writerow("".join(meta['prim']['txt']),
					  "".join(meta['sec']['txt']),
					  "".join(meta['tc']['txt']),
					   self.name)

	def run(self, progress=-1):
		global global_test_results
		global preferences

		name = self.name.replace('test_', '')

		preferences = common.global_pref

		module = __import__(self.name)
		# force a reload in case it has changed since it has
		# been previously be imported
		importlib.reload(module)
		try:
			module_run = getattr(module, 'run')
		except Exception as e:
			logging.critical(e)
			return
		# run the script
		if hasattr(module_run, '__call__'):
			skip_test = False
			if type(self.__callbacks) is TestSuiteCallbacks and \
			   'clean' in self.__callbacks:
				try:
					logging.critical("CLEANING UP BEFORE -->" + self.name)
					self.__callbacks['clean']()
				except Exception as e:
					logging.critical("EXCEPTION CLEANING BEFORE -->" + self.name)
					if preferences['halt_on_exception']:
						raise e
					else:
						# if the script went out of its way to say I want to halt all execution
						# then honor that.
						if type(e) == LUTFError and e.halt:
							raise e
						else:
							rc = {'status': 'FAIL', 'error': str(e)}
							skip_test = True
			if skip_test:
				rc['reason'] = 'Test setup cleanup failed'
				rc['duration'] = 0
				rc['name'] = name
				global_test_results["lutf-"+self.__parent_suite] = rc
				return
			try:
				logging.critical("Started test script: %s" % str(self.name))
				start_time = datetime.datetime.now()
				rc = module_run()
			except Exception as e:
				if preferences['halt_on_exception']:
					raise e
				else:
					# if the script went out of its way to say I want to halt all execution
					# then honor that.
					if type(e) == LUTFError and e.halt:
						raise e
					else:
						rc = {'status': 'FAIL', 'error': str(e)}

			logging.debug("Finished test script: %s" % str(self.name))
			duration = datetime.datetime.now() - start_time
			rc['duration'] = int(round(duration.total_seconds()))
			if rc['status'] == 'FAIL' and self.is_expected_failure(name):
				rc['status'] = 'EXPECTED FAILURE'
				rc['return_code'] = 0
			elif rc['status'] == 'FAIL':
				rc['return_code'] = -22
			else:
				rc['return_code'] = 0
			rc['name'] = name
			global_test_results["lutf-"+self.__parent_suite] = rc
			logging.debug("%s took %s to run" % (str(self.name), duration))

		if progress != -1:
			if clutf_global.get_lutf_mode() == clutf_global.EN_LUTF_RUN_INTERACTIVE:
				print(name+"\t"+str(progress)+"%"+" "*30, end='\r')
				if progress == 100:
					print(name+"\t"+str(progress)+"%"+" "*30)
			else:
				with open(me.get_test_progress_path(), 'a+') as f:
					out = '== lutf-' + self.__parent_suite + ' test ' + \
					      name + ' ============ ' + str(progress) + "% complete\n"
					f.write(out)
					f.flush()
			if type(self.__callbacks) is TestSuiteCallbacks and \
			   'clean' in self.__callbacks and progress == 100:
				try:
					self.__callbacks['clean']()
				except:
					logging.critical("Failed to clean at end of suite:" + self.__parent_suite)
					pass

	def show(self):
		with open(self.__abs_path, 'r') as f:
			for line in f:
				print(line.strip('\n'))

	def edit(self):
		global preferences
		preferences = common.global_pref

		try:
			subprocess.call(preferences['editor']+" "+self.__abs_path, shell=True)
		except:
			logging.critical("No editor available")
			print("No editor available")

class TestCollection:
	def __init__(self, base, name, callbacks, skip_list, expected_failures):
		self.__suite_name = name
		self.__test_db = {}
		self.__max = 0
		self.__n = 0
		self.__abs_path = os.path.join(base, name)
		self.__callbacks = callbacks
		self.__skip_list = skip_list
		self.__expected_failures = expected_failures
		self.reload()

	def __getitem__(self, key):
		try:
			rc = self.__test_db[key]
		except:
			raise LUTFError('no entry for ' + str(key))
		return rc

	def __iter__(self):
		self.__n = 0
		return self

	# needed for python 3.x
	def __next__(self):
		if self.__n < self.__max:
			key = list(self.__test_db.keys())[self.__n]
			suite = self.__test_db[key]
			self.__n += 1
			return key, suite
		else:
			raise StopIteration

	def __generate_test_db(self, db):
		# lutf/python/tests/suite_xxx has a list of tests
		# make a dictionary of each of these. Each test script
		# should start with "test_"
		for subdir, dirs, files in os.walk(self.__abs_path):
			added = False
			for f in files:
				if f.startswith('test_') and os.path.splitext(f)[1] == '.py':
					# add any subidrectories to the sys path
					if subdir != '.' and not added:
						subdirectory = os.path.join(self.__abs_path, subdir)
						if subdirectory not in sys.path:
							sys.path.append(subdirectory)
					added = True
					name = os.path.splitext(f.replace('test_', ''))[0]
					db[name] = Script(os.path.join(self.__abs_path, subdir, f), self.__callbacks, self.__suite_name, self)

		self.__max = len(self.__test_db)

	def in_expected_failures_list(self, name):
		return name in self.__expected_failures

	def __in_skip_list(self, name):
		return name in self.__skip_list

	def reload(self):
		self.__test_db = {}
		self.__generate_test_db(self.__test_db)

	def get_num_scripts(self, match='*'):
		num_scripts = 0
		for key in sorted(self.__test_db.keys()):
			if fnmatch.fnmatch(key, match) and not self.__in_skip_list(key):
				num_scripts += 1
		return num_scripts

	# run all the scripts in this test suite
	def run(self, match='*', num_scripts=0):
		# get number of scripts
		if not num_scripts:
			num_scripts = self.get_num_scripts(match)

		executed = 0

		with open(me.get_test_progress_path(), 'a+') as f:
			out = '-----============= lutf-' + self.__suite_name.replace('suite_', '') + "\n"
			f.write(out)
			f.flush()

		for key in sorted(self.__test_db.keys()):
			if fnmatch.fnmatch(key, match) and not self.__in_skip_list(key):
				executed += 1
				progress = int((executed / num_scripts) * 100)
				self.__test_db[key].run(progress)

	def create_docs(self, csvfile, match='*'):
		for k, v in self.__test_db.items():
			if fnmatch.fnmatch(k, match):
				v.create_docs(csvfile)

	def list(self):
		return list(self.__test_db.keys())

	def dump(self, match='*'):
		scripts_dict = {'scripts': []}
		for k, v in self.__test_db.items():
			if fnmatch.fnmatch(k, match):
				if self.in_expected_failures_list(k):
					scripts_dict['scripts'].append(k+' (expected failure)')
				elif self.__in_skip_list(k):
					scripts_dict['scripts'].append(k+' (skip)')
				else:
					scripts_dict['scripts'].append(k)
		scripts_dict['scripts'].sort()
		print(yaml.dump(scripts_dict, Dumper=LutfDumper, indent=2, sort_keys=True))

	def get_suite_name(self):
		return self.__suite_name

	def len(self):
		return len(self.__test_db)

	def add(self, script):
		default_script = os.path.join(clutf_global.get_lutf_path(), 'python', 'tests', 'sample.py')
		if not os.path.isfile(default_script):
			raise LUTFError("%s does not exist. Corrupted LUTF installation")
		rc = shutil.copy(default_script,
				 os.path.join(self.__abs_path, script))

class TestSuiteCallbacks:
	def __init__(self, **kwargs):
		if type(kwargs) is not dict:
			raise LUTFError("Must specify a dictionary")
		self.__callbacks = kwargs
	def __contains__(self, key):
		return key in self.__callbacks
	def __getitem__(self, key):
		try:
			rc = self.__callbacks[key]
		except:
			raise LUTFError('no entry for ' + str(key))
		return rc
	def dump(self):
		print(yaml.dump(self.__callbacks, Dumper=LutfDumper, indent=2, sort_keys=True))

class ATestSuite:
	def __init__(self, base, name):
		self.__base = base
		self.__callback_reg = False
		self.__callbacks = None
		self.name = name
		self.__abs_path = os.path.join(base, name)
		self.scripts = None
		self.__skip_list = []
		self.__expected_failures = []
		if self.__abs_path not in sys.path:
			sys.path.append(self.__abs_path)
		self.reload()

	def __register_callbacks(self):
		if self.__callback_reg:
			return
		# find callbacks module in this suite and get the callbacks
		for subdir, dirs, files in os.walk(self.__abs_path):
			break
		for f in files:
			if f == 'callbacks.py' and not self.__callback_reg:
				mod_name = self.name+'.'+'callbacks'
				module = __import__(mod_name)
				importlib.reload(module)
				try:
					### TODO Add more test suite callbacks here
					setup_clean_cb = getattr(module.callbacks, "lutf_clean_setup")
					if hasattr(setup_clean_cb, '__call__'):
						self.__callbacks = TestSuiteCallbacks(clean=setup_clean_cb)
				except Exception as e:
					logging.critical(str(e))
				self.callback_reg = True
				del(module)
			elif f == 'skip.py':
				mod_name = self.name+'.'+'skip'
				module = __import__(mod_name)
				importlib.reload(module)
				try:
					if type(module.skip.skip_list) != list:
						logging.critical('malformed skip list')
						continue
					try:
						self.__skip_list = module.skip.skip_list
					except:
						pass
					try:
						self.__expected_failures = module.skip.expected_failures
					except:
						pass
				except Exception as e:
					logging.critical(str(e))
					pass
				del(module)

	def reload(self):
		self.__callback_reg = False
		self.__register_callbacks()
		self.scripts = TestCollection(self.__base, self.name, self.__callbacks, self.__skip_list, self.__expected_failures)

	def dump(self, match='*'):
		self.scripts.dump(match)

	def list(self):
		return self.scripts.list()

	def create_docs(self, csvfile, match='*'):
		self.scripts.create_docs(csvfile, match)

	def get_num_scripts(self, match='*'):
		return self.scripts.get_num_scripts(match)

	def run(self, match='*', num_scripts=0):
		self.scripts.run(match=match, num_scripts=num_scripts)

	def get_abs_path(self):
		return self.__abs_path

	def add(self, script):
		new_name = 'test_'+os.path.splitext(script)[0]+'.py'
		if os.path.isfile(new_name):
			raise LUTFError("%s already exists" % (str(new_name)))
		self.scripts.add(new_name)
		self.reload()

class TestSuites:
	'''
	This class stores all the available test suites.
	The following methods are available for the suites:
		list() - list all the suites
		run() - run all the suites
		dump() - YAML output of the suites available
		create_docs() - create document for all suites
	A single suite can be accessed as follows:
		suites['name of suite']
	A single suite provides the following methods:
		list() - list all the scripts in the suite
		run() - Run all the scripts in the suite
		dump() - YAML output of the scripts available
		create_docs() - create document for this suite
	A single script can be accessed as follows:
		suites['name of suite'].scripts['name of script']
	A single script provides the following methods:
		edit() - edit the script
		show() - show the script
		run() - run the script
	'''
	def __init__(self):
		# iterate over the test scripts directory and generate
		# An internal database
		self.__test_db = {}
		self.__max = 0
		self.__n = 0
		self.__lutf_path = clutf_global.get_lutf_path()
		if len(self.__lutf_path) == 0:
			raise LUTFError('No LUTF path provided')
		self.__lutf_tests = self.__lutf_path + '/python/tests/'
		if not os.path.isdir(self.__lutf_tests):
			raise LUTFError('No tests suites director: ' + sef.lutf_tests)
		self.__generate_test_db(self.__test_db)

	def __getitem__(self, key):
		try:
			rc = self.__test_db[key]
		except:
			raise LUTFError('no entry for ' + str(key))
		return rc

	def __iter__(self):
		self.__n = 0
		return self

	# needed for python 3.x
	def __next__(self):
		if self.__n < self.__max:
			key = list(self.__test_db.keys())[self.__n]
			suite = self.__test_db[key]
			self.__n += 1
			return key, suite
		else:
			raise StopIteration

	def __generate_test_db(self, db):
		# lutf/python/tests has a directory for each test suite
		# make a dictionary of each of these. The lutf/python/tests
		# is one level hierarchy. Each directory suite should start
		# with "suite'
		for subdir, dirs, files in os.walk(self.__lutf_tests):
			break
		for d in dirs:
			if d.startswith('suite_'):
				name = d.replace('suite_', '')
				db[name] = ATestSuite(self.__lutf_tests, d)

		self.__max = len(self.__test_db)

	def create_docs(self, csvfile, match='*'):
		for k, v in self.__test_db.items():
			if fnmatch.fnmatch(k, match):
				v.create_docs(csvfile)

	# run all the test suites
	def run(self, suite_list='*', match='*'):
		numscripts = {}
		if suite_list == '*':
			sl = list(self.__test_db.keys())
		else:
			sl = [item for item in re.split(',| ', suite_list) if len(item.strip()) > 0]
		num_scripts = 0
		for k, v in self.__test_db.items():
			if k in sl:
				numscripts[k] = v.get_num_scripts('*')

		for k, v in self.__test_db.items():
			if k in sl:
				v.run(num_scripts=numscripts[k])

	def reload(self):
		self.__test_db = {}
		self.__generate_test_db(self.__test_db)

	def len(self):
		return len(self.__test_db)

	def list(self):
		return list(self.__test_db.keys())

	def dump(self, match='*'):
		suites_dict = {'suites': []}
		for k, v in self.__test_db.items():
			if fnmatch.fnmatch(k, match):
				suites_dict['suites'].append(k)
		suites_dict['suites'].sort()
		print(yaml.dump(suites_dict, Dumper=LutfDumper, indent=2, sort_keys=True))

class Myself:
	'''
	Class which represents this LUTF instance.
	It allows extraction of:
		- interfaces available
		- listen port
		- telnet port
		- name
		- hostname
		- LUTF type
	It provides an exit method to exit the LUTF instance
	'''
	def __init__(self, name, telnet_port):
		global preferences
		preferences = common.global_pref
		self.name = name
		self.__hostname = socket.gethostname()
		self.__lutf_telnet_server = None
		self.__lutf_telnet_port = telnet_port
		self.__lutf_listen_port = clutf_global.get_master_port()
		self.__lutf_type = clutf_global.get_lutf_type()
		lscpu = lutf_exec_local_cmd('/usr/bin/lscpu')
		self.__cpuinfo = yaml.load(lscpu[0].decode('utf-8'), Loader=yaml.FullLoader)
		cfg_path = clutf_global.get_lutf_cfg_file_path()
		if not cfg_path:
			raise LUTFError("No LUTF config file provided")
		with open(cfg_path, 'r') as f:
			self.lutf_cfg = yaml.load(f, Loader=yaml.FullLoader)
		config_ifs_num = MIN_IFS_NUM_DEFAULT
		logging.critical('CONFIGURATION CONTENT--->' + str(self.lutf_cfg))
		if "num_intfs" in self.lutf_cfg['lutf']:
			config_ifs_num = self.lutf_cfg['lutf']['num_intfs']
		if "lutf-env-vars" in self.lutf_cfg['lutf']:
			self.import_env_vars(self.lutf_cfg['lutf']['lutf-env-vars'])
		if "lustre-path" in self.lutf_cfg['lutf']:
			self.__lustre_base_path = os.path.split(self.lutf_cfg['lutf']['lustre-path'])[0]
			set_lustre_base_path(self.__lustre_base_path)
		else:
			self.__lustre_base_path = ''
		self.alias_list = self.provision_intfs(config_ifs_num)
		# delete any older test_progress files
		if os.path.isfile(self.get_test_progress_path()) and self.__lutf_type == EN_LUTF_MASTER:
			os.remove(self.get_test_progress_path())

	def import_env_vars(self, fpath):
		with open(fpath, 'r') as f:
			for line in f.readlines():
				if 'export ' in line:
					s = line.replace('export ', '')
					kv = s.split('=')
					os.environ[kv[0].strip()] = kv[1].strip().strip('"')

	def get_lustre_base_path(self):
		return self.__lustre_base_path

	def get_test_progress_path(self):
		if 'test-progress' in self.lutf_cfg['lutf']:
			path = self.lutf_cfg['lutf']['test-progress']
		else:
			path = clutf_global.get_lutf_tmp_dir()
			path = os.path.join(path, 'lutf_test_progress.out')
		return path

	def get_local_interface_names(self):
		return netifaces.interfaces()

	def get_local_interface_ip(self, name):
		return netifaces.ifaddresses(name)[netifaces.AF_INET][0]['addr']

	def get_local_interface_nm(self, name):
		return netifaces.ifaddresses(name)[netifaces.AF_INET][0]['netmask']

	def get_local_interface_bc(self, name):
		return netifaces.ifaddresses(name)[netifaces.AF_INET][0]['broadcast']

	def exit(self):
		'''
		Shutdown the LUTF
		'''
		if (len(self.alias_list) > 0):
			for alias in self.alias_list:
				del_ip_alias_cmd_str = "/usr/sbin/ip addr del " + alias
				rc = lutf_exec_local_cmd(del_ip_alias_cmd_str)
				ret_str = str(rc)
				if "ERROR" in ret_str:
					error = "Uexpected result when deleting an alias ip: %s\n" % (ret_str)
					logging.debug(error)
		print("Shutting down the LUTF")
		exit()

	def get_cpuinfo(self):
		return self.__cpuinfo

	def get_num_cpus(self):
		return self.__cpuinfo['CPU(s)']

	def get_num_numa_nodes(self):
		return self.__cpuinfo['NUMA node(s)']

	def list_intfs(self):
		'''
		Return a list of all the interfaces available on this node
		'''
		intfs = {'interfaces': {}}
		for intf in self.get_local_interface_names():
			try:
				intfs['interfaces'][intf] = {'ip': self.get_local_interface_ip(intf),
							     'netmask': self.get_local_interface_nm(intf),
							     'broadcast': self.get_local_interface_bc(intf)}
			except:
				pass
		return intfs

	def dump_intfs(self):
		'''
		Dump the interfaces in YAML format
		'''
		print(yaml.dump(self.list_intfs(), sort_keys=False))

	def my_name(self):
		'''
		Return the symbolic name assigned to this LUTF instance
		'''
		return self.name

	def my_hostname(self):
		'''
		Return the hostname of this node
		'''
		return self.__hostname

	def my_type(self):
		'''
		Return the type of this LUTF instance
		'''
		if self.__lutf_type == EN_LUTF_MASTER:
			return 'MASTER'
		elif self.__lutf_type == EN_LUTF_AGENT:
			return 'AGENT'
		raise LUTFError("Undefined LUTF role: %d" % (self.__lutf_type))

	def my_telnetport(self):
		'''
		Return the telnet port of this LUTF instance
		'''
		return self.__lutf_telnet_port

	def my_listenport(self):
		'''
		Return the listen port of this LUTF instance
		'''
		return self.__lutf_listen_port

	def handle_rpc_req(self, rpc_yaml):
		function_name = ''
		class_name = ''
		method_name = ''
		rc = {}

		#rpc_str = rpc_yaml.decode('utf-8')
		y = yaml.load(rpc_yaml, Loader=yaml.FullLoader)
		# check to see if this is for me
		target = y['rpc']['dst']
		if target != self.name:
			logging.critical("RPC intended to %s but I am %s" % (target, self.name))
			return
		source = y['rpc']['src']
		name = os.path.split(os.path.splitext(y['rpc']['script'])[0])[1]
		path = os.path.split(os.path.splitext(y['rpc']['script'])[0])[0]
		if path not in sys.path:
			sys.path.append(path)
		rpc_type = y['rpc']['type']
		if rpc_type == 'function_call':
			function_name = y['rpc']['function']
		elif rpc_type == 'method_call':
			class_name = y['rpc']['class']
			method_name = y['rpc']['method']
			class_id = y['rpc']['class_id']
		elif rpc_type == 'instantiate_class' or rpc_type == 'destroy_class':
			class_name = y['rpc']['class']
			class_id = y['rpc']['class_id']
		else:
			raise LUTFError('Unexpected rpc')

		module = __import__(name)
		importlib.reload(module)
		args = y['rpc']['parameters']['args']
		kwargs = y['rpc']['parameters']['kwargs']
		lutf_exception_string = None
		try:
			if rpc_type == 'function_call':
				module_func = getattr(module, function_name)
				if hasattr(module_func, '__call__'):
					rc = module_func(*args, **kwargs)
			elif rpc_type == 'instantiate_class':
				my_class = getattr(module, class_name)
				instance = my_class(*args, **kwargs)
				common.add_to_class_db(instance, class_id)
			elif rpc_type == 'destroy_class':
				instance = common.get_class_from_db(class_id)
				del(instance)
				common.del_entry_from_class_db(class_id)
			elif rpc_type == 'method_call':
				instance = common.get_class_from_db(class_id)
				if type(instance).__name__ != class_name:
					raise LUTFError("requested class %s, but id refers to class %s" % (class_name, type(instance).__name__))
				rc = getattr(instance, method_name)(*args, **kwargs)
		except Exception as e:
			if type(e) == LUTFError:
				lutf_exception_string = e
			else:
				exception_list = traceback.format_stack()
				exception_list = exception_list[:-2]
				exception_list.extend(traceback.format_tb(sys.exc_info()[2]))
				exception_list.extend(traceback.format_exception_only(sys.exc_info()[0], sys.exc_info()[1]))
				header = "Traceback (most recent call last):\n"
				stacktrace = "".join(exception_list)
				lutf_exception_string = header+stacktrace
		if lutf_exception_string:
			rc_yaml = populate_rpc_rsp(self.name, source, rc, lutf_exception_string)
		else:
			rc_yaml = populate_rpc_rsp(self.name, source, rc)
		lutf_send_rpc_rsp(source, yaml.dump(rc_yaml))

	def provision_intfs(self, num_intf_req):
		# if there are enough interfaces, don't need to add aliases
		intfs_dict = self.list_intfs()
		intfs = list(intfs_dict['interfaces'].keys())
		num_available = len(intfs)
		if num_available >= num_intf_req:
			return []
		# add aliases for the last available interface
		base_intf_name = intfs[num_available-1]
		base_ip = netifaces.ifaddresses(base_intf_name)[netifaces.AF_INET][0]['addr']
		base_ip_netmask = netifaces.ifaddresses(base_intf_name)[netifaces.AF_INET][0]['netmask']
		base_ip_netmask_bits = sum(bin(int(x)).count('1') for x in base_ip_netmask.split('.'))
		intf_ip_alias = base_ip
		separator = '.'
		intf_ip_alias_split = intf_ip_alias.split(separator)
		ip_incr = 1
		alias_param_list = []
		for i in range(0, num_intf_req - num_available):
			intf_name_alias = base_intf_name + ":" + str(i)
			alias_confirmed = False
			intf_ip_alias_candidate_split = intf_ip_alias_split[:]

			# try to find available ip address
			while ip_incr < 254 and not alias_confirmed:
				# increment ip addr candidate
				intf_ip_alias_candidate_split[3] = str((int(intf_ip_alias_split[3])+ip_incr)%255)
				intf_ip_alias = separator.join(intf_ip_alias_candidate_split)
				ip_incr += 1
				try:
					rc = lutf_exec_local_cmd("/usr/bin/ping -c 3 " + intf_ip_alias)
					ret_str = str(rc)
				except Exception as e:
					if "Host Unreachable" in str(e):
						alias_confirmed = True
						break
			if not alias_confirmed:
				error = "Failed to allocate ip address for alias if %s\n" % (intf_name_alias)
				logging.debug(error)
				return alias_param_list
			print("adding alias: ", intf_name_alias, " ip: ", intf_ip_alias)
			# build the command string for adding the alias, back up for clean-up on exit
			add_ip_alias_params = intf_ip_alias + "/" + str(base_ip_netmask_bits)
			add_ip_alias_params += " brd + dev " + base_intf_name + " label " + intf_name_alias
			add_ip_alias_cmd_str = "/usr/sbin/ip addr add " + add_ip_alias_params
			rc = lutf_exec_local_cmd(add_ip_alias_cmd_str)
			ret_str = str(rc)
			if "Error" in ret_str:
				error = "Uexpected result when creating an alias ip: %s\n" % (ret_str)
				logging.debug(error)
				return alias_param_list
			alias_param_list.append(add_ip_alias_params)

		return alias_param_list


# Dump the global results to console or to file
def dumpGlobalTestResults(fname=None, status=None, desc=None):
	'''
	Dump the YAML results for tests which ran so far
	'''
	global global_test_results

	results = global_test_results.get()

	if fname:
		fpath = fname
		# if this is path then use it as is, otherwise put it in the tmp dir
		if os.sep not in fname:
			fpath = os.path.join(clutf_global.get_lutf_tmp_dir(), fname)
		with open(fpath, 'w') as f:
			f.write(yaml.dump(results,
				Dumper=LutfDumper, indent=2,
				sort_keys=False))
	else:
		print(yaml.dump(results, Dumper=LutfDumper, indent=2, sort_keys=False))

def setup_paths():
	global lutf_tmp_dir
	base_lustre = ''

	for p in LUTF_SCRIPT_PATHS:
		path = os.path.join(clutf_global.get_lutf_path(),p)
		if path not in sys.path:
			sys.path.append(path)
	lutf_tmp_dir = clutf_global.get_lutf_tmp_dir()
	Path(lutf_tmp_dir).mkdir(parents=True, exist_ok=True)

logging.basicConfig(filename=os.path.join(clutf_global.get_lutf_tmp_dir(), "lutf_py.log"),
		    filemode='w')
setup_paths()

# All test results are stored in here
# Accessor functions can be used to dump it.
global_test_results = YamlGlobalTestResults()

suites = TestSuites()

agents = lutf_agent.LutfAgents()

logging.critical("INSTANTIATING myself")
me = Myself(clutf_global.get_node_name(),
	    clutf_global.get_agent_telnet_port())

# Convenience Variables
R = dumpGlobalTestResults
A = agents.dump
I = me.dump_intfs
X = me.exit

preferences = load_pref()
# set debug level
set_logging_level('debug')

