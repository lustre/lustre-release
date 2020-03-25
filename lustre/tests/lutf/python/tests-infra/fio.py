import os, yaml, random, sys, re, csv, signal, pathlib, shutil
from lutf_basetest import BaseTest, lutfrc
from lutf_exception import LUTFError
import selftest_template as st
from clutf_global import *
from lutf_cmd import lutf_exec_local_cmd
import threading, logging

fiocfg=['[global]\n',
	'ioengine=%s\n',
	'rw=%s\n',
	'blocksize=%s\n',
	'iodepth=1\n',
	'direct=%d\n',
	'size=%s\n',
	'numjobs=%d\n',
	'group_reporting\n',
	'thread\n',
	'time_based=1\n',
	'runtime=%d\n']

fiocpu=['[md%d]\n',
	'directory=%s\n',
	'filename_format=f.$jobnum.$filenum\n']

fiogpu=['[md%d]\n',
	'directory=%s\n',
	'filename_format=f.$jobnum.$filenum\n',
	'gpu_dev_id=%d\n']

class FioTraffic(BaseTest):
	def __init__(self, script=None, target=None, exception=True):
		super().__init__(script, target)
		self.__exception = exception
		self.__fio_cmd = shutil.which('fio')
		self.__fio_cfg = None
		self.__csv_file = None
		self.__csv_writer = None
		self.__fieldnames = ['load', 'file name', 'operation', 'file size', 'block size', 'num jobs',
			'duration', 'BW', 'IO', 'cpu usr', 'cpu sys', 'cpu ctx/job', 'cpu ctx',
			'cpu majf', 'cpu minf']
		self.__data = {}
		self.__traffic_thread = None

	# Takes a configuration dictionary
	def load(self, directory, ioengine='sync', rw='write', blocksize='1M', direct=0, size='512M', numjobs=4, runtime=30, gpu=None, cfg={}):
		global fiocfg
		global fiocpu
		global fiogpu
		lfiocfg = fiocfg

		if not self.__fio_cmd:
			if self.__exception:
				raise LUTFError("fio not available on this machine")
			return False, "fio not available on this machine"

		if 'csv' in cfg:
			self.__csv_file = open(cfg['csv'], 'w')
			self.__csv_writer = csv.DictWriter(csvfile, fieldnames=self.__fieldnames)
			self.__csv_writer.writeheader()

		load = 'CPU'
		if gpu:
			load = 'GPU'
			lfiocfg.append('mem=cudamalloc\n')
			if len(gpu) != numjobs:
				if self.__exception:
					raise LUTFError("Mismatched configuration: gpu %d numjobs %d" % (gpu, numjobs))
				return False, "Mismatched configuration: gpu %d numjobs %d" % (gpu, numjobs)
			fileblk = fiogpu
		else:
			fileblk = fiocpu

		self.__fio_cfg = ''.join(lfiocfg) % (ioengine, rw, blocksize, direct, size, numjobs, runtime)

		for i in range(0, numjobs):
			subdir = os.path.join(directory, 'md'+str(i))
			pathlib.Path(subdir).mkdir(parents=True, exist_ok=True)
			if gpu:
				self.__fio_cfg += ''.join(fileblk) % (i, subdir, gpu[i])
			else:
				self.__fio_cfg += ''.join(fileblk) % (i, subdir)

		self.__data['load'] = load
		self.__data['operation'] = rw
		self.__data['filesize'] = size
		self.__data['blocksize'] = blocksize
		self.__data['numjobs'] = numjobs
		self.__data['duration'] = runtime

	def start(self):
		if not self.__fio_cfg:
			if self.__exception:
				raise LUTFError("Failed to run traffic. No configuration")
			else:
				return False, self.__fio_cfg

		rc = self.__run_fio()

		if self.__csv_writer:
			self.__record(rc)

	def stop(self):
		if not self.__traffic_thread:
			logging.debug("No traffic running to stop")
			return
		self.__traffic_thread.join()
		self.__traffic_thread = None
		return

	def __record(self, rc):
		if self.__data['operation'] == 'write':
			m = re.search('WRITE: bw=(.+?) \((.+?)\), (.+?)-(.+?) \((.+?)-(.+?)\), io=(.+?) \((.+?)\), run=(.+?)-(.+?)msec',
				rc[0].decode("utf-8"))
		else:
			m = re.search('READ: bw=(.+?) \((.+?)\), (.+?)-(.+?) \((.+?)-(.+?)\), io=(.+?) \((.+?)\), run=(.+?)-(.+?)msec',
				rc[0].decode("utf-8"))
		# get the cpu information
		# cpu          : usr=0.02%, sys=8.27%, ctx=161380, majf=0, minf=382
		m1 = re.search("cpu(.+?): usr=(.+?), sys=(.+?), ctx=(.+?), majf=(.+?), minf=(.+?)", rc[0].decode("utf-8"))

		ctx_switches = int(int(m1[4]) / self.__data['numjobs'])
		self.__csv_writer.writerow({'load': self.__data['load'], 'operation': self.__data['operation'],
				     'file size': self.__data['filesize'], 'block size': self.__data['blocksize'],
				     'num jobs': self.__data['numjobs'], 'duration': self.__data['duration'],
				     'BW': m[2], 'IO': m[8], 'cpu usr': m1[2], 'cpu sys': m1[3], 'cpu ctx/job': str(ctx_switches),
			             'cpu ctx': m1[4], 'cpu majf': m1[5], 'cpu minf': m1[6]})

	def __run_traffic(self, cmd):
		return lutf_exec_local_cmd(cmd)

	def __run_fio(self):
		if self.__traffic_thread:
			logging.debug("Traffic is already running")
			return

		cmd_fmt = "%s %s"

		local_path = get_lutf_tmp_dir()
		pathlib.Path(local_path).mkdir(parents=True, exist_ok=True)

		fname = os.path.join(local_path, "lutf_fio_"+str(random.getrandbits(32)) + '.cfg')

		f = open(fname, 'w')
		f.write(self.__fio_cfg)
		f.close()

		cmd = cmd_fmt % (self.__fio_cmd, fname)

		self.__traffic_thread = threading.Thread(target=self.__run_traffic, args=(cmd,))
		self.__traffic_thread.start()

	def unload(self):
		if self.__csv_file:
			self.__csv_file.close()
		self.stop()

