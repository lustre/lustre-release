import os, shlex, yaml, subprocess, random
from lutf_cmd import lutf_exec_local_cmd
from lutf_exception import LUTFError
from lutf_basetest import BaseTest
from utility_paths import LCTL

LNET_TRACE_MSG_SEND = "(.+?):(.+?):(.+?):(.+?):(.+?):(.+?):(.+?):\((.+?):(.+?):(.+?)\) TRACE: (.+?)\((.+?):(.+?)\) -> (.+?)\((.+?):(.+?)\) (.+?) : (.+?) try# (.+?)"
LNET_TRACE_MSG_RECV = "(.+?):(.+?):(.+?):(.+?):(.+?):(.+?):(.+?):\((.+?):(.+?):(.+?)\) TRACE: (.+?)\((.+?)\) <- (.+?) : (.+?) - (.+?)"

class LustreLog(BaseTest):
	'''
	This class provides methods to easily access the lustre kernel log
	If the log buffer overflows the start mark could be lost
	Its is suggested to keep logging running for the shortest
	period possible to avoid log over flows.
	'''
	def __init__(self, script=os.path.abspath(__file__),
		     target=None):
		super().__init__(script, target=target)
		self.__started = False
		self.__mark_unique = str(random.getrandbits(32))
		self.__start_mark = ''
		self.__end_mark = ''
		self.__daemon_logfile = ''
		self.level = self.get_level()

	def __set(self):
		lutf_exec_local_cmd(LCTL + ' set_param debug='+'"'+' '.join(self.level)+'"')

	def get_level(self):
		levels = lutf_exec_local_cmd(LCTL + ' get_param debug')
		levels = levels[0].decode('utf-8').replace('debug=', '')
		levels = levels.split()
		return levels

	def set_level(self, level):
		'''
		set lustre kernel log level
		'''
		self.level = []
		self.level.append(level)
		self.__set()
		self.level = self.get_level()

	def add_level(self, level):
		'''
		adds to the existing lustre log level
		'''
		if not level in self.level:
			self.level.append(level)
			self.__set()
			self.level = self.get_level()

	def sub_level(self, level):
		'''
		removes a log level
		'''
		if not level in self.level:
			return
		self.level.remove(level)
		self.set_level(self.level)
		self.level = self.get_level()

	def start(self):
		'''
		Start logging and mark the log with a unique marker.
		'''
		if self.__started:
			LUTFError("Logging already started")
		self.__start_mark = 'LUTF-START-'+self.__mark_unique
		lutf_exec_local_cmd(LCTL + ' mark '+self.__start_mark)
		self.__started = True

	def stop(self, logfile=None):
		'''
		Stops logging and marks the end of the log with a unique marker.
		'''
		if not self.__started:
			LUTFError("Logging did not start")
		if len(self.__start_mark) == 0:
			LUTFError("Logging corrupted")
		self.__end_mark = 'LUTF-END-'+self.__mark_unique
		lutf_exec_local_cmd(LCTL + ' mark '+self.__end_mark)
		self.__started = False
		if logfile:
			lutf_exec_local_cmd(LCTL + ' dk '+logfile)
			return None

	def get_log(self):
		rc = lutf_exec_local_cmd(LCTL + ' dk')
		output = rc[0].decode('utf-8')
		# parse into a list
		lines = output.split('\n')
		parsed = []
		start = False
		for l in lines:
			if self.__start_mark in l:
				start = True
			if self.__end_mark in l:
				start = False
			if start:
				parsed.append(l)
		return parsed

	def extract(self, search, parsed):
		extracted = []
		for l in parsed:
			if search in l:
				extracted.append(l)
		return extracted

	def start_daemon(self, logfile, size):
		'''
		Start the debug daemon and mark the beginning of the logs with a
		unique marker
		'''
		if self.__started:
			LUTFError("Logging already started")
		lutf_exec_local_cmd(LCTL + ' debug_daemon start '+logfile+' '+str(size))
		self.__daemon_logfile = logfile
		self.__mark = 'LUTF-'+str(random.getrandbits(32))
		lutf_exec_local_cmd(LCTL + ' mark '+self.__mark)
		self.__started = True

	def stop_daemon(self):
		'''
		Stop the debug daemon and mark the beginning of the logs with a
		unique marker
		'''
		if not self.__started:
			LUTFError("Logging did not start")
		if len(self.__mark) == 0:
			LUTFError("Logging corrupted")
		if len(self.__daemon_logfile) == 0:
			LUTFError("Daemon log file is not set")
		lutf_exec_local_cmd(LCTL + ' mark '+self.__mark)
		lutf_exec_local_cmd(LCTL + ' debug_daemon stop')
		lutf_exec_local_cmd(LCTL + ' debug_file '+self.__daemon_logfile+' '+self.__daemon_logfile+'.log')
		self.__mark = ''
		self.__started = False

