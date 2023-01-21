"""
lutf_start.py is a script intended to be run from the lutf.sh
It relies on a set of environment variables to be set. If they
are not set the script will exit:

*_HOST: nodes to run the LUTF on. They must be unique (optional)
ONLY: A script to run (optional)
SUITE: A suite to run (optional)
LUTF_SHELL: If specified it'll run the python interpreter (optional)
MASTER_PORT: The port on which the master will listen
TELNET_PORT: The port on which a telnet session can be established to the agent
LUSTRE: The path to the lustre tests directory
PYTHONPATH: The path where the python scripts and libraries are located
LUTFPATH: Path to the lutf directory

Purpose:
--------
start an instance of the LUTF on the master and the agents
"""

import os, re, yaml, paramiko, copy
import shlex, subprocess, time
from pathlib import Path
from lutf_exception import LutfDumper
from lutf_paramiko import lutf_exec_remote_cmd, lutf_put_file, lutf_get_file

cfg_yaml = {'lutf': {'shell': True, 'agent': False, 'telnet-port': -1,
		'master-address': None, 'master-port': -1, 'node-name': None,
		'master-name': None, 'lutf-path': None, 'py-path': None, 'lustre-path': None,
		'suite': None, 'suite-list': None, 'script': None, 'pattern': None,
		'agent-list': None, 'results': None, 'always_except': None,
		'num_intfs': 3, 'lutf-env-vars': None, 'test-progress': None,
		'tmp-dir': '/tmp/lutf/'}}

class LUTF:
	def __init__(self):
		self.nodes = {}
		self.__collect_nodes()
		self.__cfg_yaml = {}

	def __collect_nodes(self):
		for k in os.environ:
			if '_HOST' in k or 'CLIENTS' in k:
				hosts = re.split(',| ', os.environ[k])
				hosts = [x for x in hosts if x]
				i = 0
				for h in hosts:
					if len(h) > 0:
						if h in list(self.nodes.values()):
							print("Duplicate host: %s. LUTF expects unique hosts: %s. Skipping" \
								% (h, str(list(self.nodes.values()))))
							continue
						if i > 0:
							self.nodes[k+str(i)] = h
						else:
							self.nodes[k] = h
						i += 1

	def __exec_local_cmd(self, cmd):
		args = shlex.split(cmd)
		out = subprocess.Popen(args, stderr=subprocess.STDOUT,
			stdout=subprocess.PIPE)
		t = out.communicate()[0],out.returncode
		print(cmd+"\n"+"rc = "+str(t[1])+"\n"+t[0].decode("utf-8"))
		return int(t[1])

	def __stop_lutf(self, key, host):
		# make sure you kill any other instances of the LUTF
		if host != os.environ['HOSTNAME']:
			lutf_exec_remote_cmd("pkill -9 lutf", host)

	def __install_deps_on_hosts(self, host):
		installbin = os.environ.get('INSTALLBIN', 'yum')
		pip = os.environ.get('PIPBIN', 'pip3')

		print("%s: %s install -y python3" % (host, installbin))
		lutf_exec_remote_cmd(installbin+" install -y python3", host, ignore_err=True)
		print("%s: %s install paramiko" % (host, pip))
		lutf_exec_remote_cmd(pip+" install paramiko", host, ignore_err=True)
		print("%s: %s install netifaces" % (host, pip))
		lutf_exec_remote_cmd(pip+" install netifaces", host, ignore_err=True)
		print("%s: %s install pyyaml" % (host, pip))
		lutf_exec_remote_cmd(pip+" install pyyaml", host, ignore_err=True)
		print("%s: %s install psutil" % (host, pip))
		lutf_exec_remote_cmd(pip+" install psutil", host, ignore_err=True)

	def __start_lutf(self, key, host, mname, master, agent_list=[], agent=True):
		self.__cfg_yaml = copy.deepcopy(cfg_yaml)

		self.__cfg_yaml['lutf']['shell'] = os.environ.get('LUTF_SHELL', 'batch')

		# agent will always run in daemon mode
		if (agent):
			self.__cfg_yaml['lutf']['shell'] = 'daemon'

		self.__cfg_yaml['lutf']['agent'] = agent
		self.__cfg_yaml['lutf']['telnet-port'] = int(os.environ['TELNET_PORT'])
		self.__cfg_yaml['lutf']['master-address'] = master
		self.__cfg_yaml['lutf']['master-port'] = int(os.environ['MASTER_PORT'])
		self.__cfg_yaml['lutf']['node-name'] = key
		self.__cfg_yaml['lutf']['master-name'] = mname
		self.__cfg_yaml['lutf']['lutf-path'] = os.environ['LUTFPATH']
		self.__cfg_yaml['lutf']['py-path'] = os.environ['PYTHONPATH']

		try:
			sl = re.split(',| ', os.environ['SUITE'])
			if len(sl) == 0:
				raise ValueError
			if len(sl) == 1:
				self.__cfg_yaml['lutf']['suite'] = os.environ['SUITE']
				del(self.__cfg_yaml['lutf']['suite-list'])
			else:
				self.__cfg_yaml['lutf']['suite-list'] = os.environ['SUITE']
				del(self.__cfg_yaml['lutf']['suite'])
		except:
			if 'suite' in self.__cfg_yaml['lutf']:
				del(self.__cfg_yaml['lutf']['suite'])

		self.__check_env_var('lustre-path', 'LUSTRE')
		self.__check_env_var('script', 'ONLY')
		self.__check_env_var('pattern')
		self.__check_env_var('results')
		self.__check_env_var('always_except')
		self.__check_env_var('num_intfs')
		self.__check_env_var('lutf-env-vars')
		self.__check_env_var('test-progress', 'LUTF_TEST_PROGRESS')

		if os.environ.get('LUTF_TMP_DIR') is not None:
			cfg['lutf']['tmp-dir'] = os.environ.get('LUTF_TMP_DIR')

		if len(agent_list) > 0:
			self.__cfg_yaml['lutf']['agent-list'] = agent_list
		else:
			if 'agent-list' in self.__cfg_yaml['lutf']:
				del(self.__cfg_yaml['lutf']['agent-list'])

		lutf_bin = 'lutf'
		cfg_name = host+'.yaml'
		lutf_cfg_path = os.path.join(self.__cfg_yaml['lutf']['tmp-dir'], 'config')
		Path(lutf_cfg_path).mkdir(parents=True, exist_ok=True)
		lutf_cfg = os.path.join(lutf_cfg_path, cfg_name)
		# write the config file
		with open(lutf_cfg, 'w') as f:
			f.write(yaml.dump(self.__cfg_yaml, Dumper=LutfDumper, indent=4))
		# copy it over to the remote
		if host != os.environ['HOSTNAME']:
			lutf_exec_remote_cmd("mkdir -p " + lutf_cfg_path, host)
			lutf_put_file(host, lutf_cfg, lutf_cfg)

		cmd = ''

		#setup the library path on the remote node
		if 'LD_LIBRARY_PATH' in os.environ and host != os.environ['HOSTNAME']:
			cmd = "LD_LIBRARY_PATH="+os.environ['LD_LIBRARY_PATH']

		if 'PATH' in os.environ and host != os.environ['HOSTNAME']:
			cmd += " PATH="+os.environ['PATH']

		if 'PYTHONPATH' in os.environ and host != os.environ['HOSTNAME']:
			cmd += " PYTHONPATH="+os.environ['PYTHONPATH']

		# start the LUTF on the remote
		if cmd:
			cmd += ' '
		cmd += lutf_bin+" --config "+lutf_cfg

		# make sure you kill any other instances of the LUTF
		rc = 0
		if host != os.environ['HOSTNAME']:
			lutf_exec_remote_cmd("pkill -9 lutf", host)
			time.sleep(1)
			print("%s: %s" % (host, cmd))
			try:
				lutf_exec_remote_cmd(cmd, host)
			except Exception as e:
				print(e)
				rc = -22
		else:
			time.sleep(1)
			print("%s: %s" % (host, cmd))
			try:
				rc = self.__exec_local_cmd(cmd)
			except Exception as e:
				print(e)
				rc = -22

		return rc

	def __check_env_var(self, var_name, env_var_name=None):
		if env_var_name is None:
			env_var_name = var_name.upper().replace('-', '_')

		if os.environ.get(env_var_name) is not None:
			self.__cfg_yaml['lutf'][var_name] = os.environ.get(env_var_name)
		else:
			if var_name in self.__cfg_yaml['lutf']:
				del(self.__cfg_yaml['lutf'][var_name])

	def __collect_lutf_logs(self, host):
		if host != os.environ['HOSTNAME']:
			rfname = "lutf."+host+".tar.gz"
			tmp_dir = self.__cfg_yaml['lutf']['tmp-dir']
			rfpath = os.path.join(os.sep, 'tmp', rfname)
			if tmp_dir[-1] == os.sep:
				landing_dir = os.path.split(tmp_dir[:-1])[0]
				tar_dir = os.path.split(tmp_dir[:-1])[1]
			else:
				landing_dir = os.path.split(tmp_dir)[0]
				tar_dir = os.path.split(tmp_dir)[1]
			cmd = "tar -czf "+rfpath+" -C "+landing_dir+" "+tar_dir
			lutf_exec_remote_cmd(cmd, host, ignore_err=True);
			lutf_get_file(host, rfpath, os.path.join(tmp_dir, rfname))

	def check_environment(self):
		needed_vars = ['LUTFPATH','PYTHONPATH','TELNET_PORT', 'MASTER_PORT',
				'HOSTNAME', 'LD_LIBRARY_PATH', 'PATH', 'LUSTRE']

		for var in needed_vars:
			try:
				os.environ[var]
			except KeyError:
				print("Missing ", var, " environment variable\n")
				return -22

		return 0

	def run(self):
		master = ''
		mname = ''

		if not os.environ['HOSTNAME'] in list(self.nodes.values()):
			i = 1
			for k in list(self.nodes.keys()):
				if 'CLIENTS' in k:
					i += 1
			key = "CLIENTS"+str(i)
			self.nodes[key] =  os.environ['HOSTNAME']

		agent_list = list(self.nodes.keys())
		if len(agent_list) == 0:
			raise ValueError("no LUTF nodes defined")

		master = os.environ['HOSTNAME']
		mname = agent_list[list(self.nodes.values()).index(os.environ['HOSTNAME'])]

		rc = 0
		for k, v in self.nodes.items():
			if v != master:
				rc = self.__start_lutf(k, v, mname, master)

		if rc == 0:
			# run master locally
			agent_list.remove(mname)
			rc = self.__start_lutf(mname, master, mname, master, agent_list=agent_list, agent=False)
			if self.__cfg_yaml['lutf']['shell'] == 'batch':
				for k, v in self.nodes.items():
					self.__stop_lutf(k, v)

		# collect all the logs
		for k, v in self.nodes.items():
			if v != master:
				self.__collect_lutf_logs(v);

		return rc

if __name__ == '__main__':
	lutf = LUTF()

	rc = lutf.check_environment()
	if (rc != 0):
		exit(rc)

	rc = lutf.run()
	exit(rc)
