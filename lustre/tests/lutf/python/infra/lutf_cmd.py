import os, shlex, subprocess, threading, ctypes, time, logging
from lutf_exception import LUTFError
import lutf_common_def

def exec_cmd(cmd, exception=True):
	if lutf_common_def.is_cmd_verbosity():
		logging.critical("executing -> " + cmd)
	args = shlex.split(cmd)
	try:
		out = subprocess.Popen(args, stderr=subprocess.STDOUT,
			stdout=subprocess.PIPE)
	except Exception as e:
		logging.critical("Failed to execute cmd: " + cmd)
		logging.critical(e)
		return [None, -1]
	t = out.communicate()[0],out.returncode
	if t[1] != 0 and exception:
		raise LUTFError(cmd+"\n"+"rc = "+str(t[1])+"\n"+t[0].decode("utf-8"))
	elif t[1] != 0:
		logging.critical("Failed to execute cmd: " + cmd + " with rc = " + str(t[1]))
	return t

class LutfCmd(threading.Thread):
	def __init__(self, name, cmd, exception=False):
		threading.Thread.__init__(self)
		self.name = name
		self.cmd = cmd
		self.thread_id = threading.get_ident()
		self.rc = None
		self.exception = exception

	def run(self):
		self.rc = exec_cmd(self.cmd, exception=self.exception)

	def raise_exception(self):
		res = ctypes.pythonapi.PyThreadState_SetAsyncExc(self.thread_id,
				ctypes.py_object(SystemExit))
		if res > 1:
			ctypes.pythonapi.PyThreadState_SetAsyncExc(self.thread_id, 0)

def lutf_exec_local_cmd(cmd, expire=0, exception=True):
	if expire <= 0 or not type(expire) == int:
		return exec_cmd(cmd, exception=exception)
	cmd_thrd = LutfCmd('lutf_cmd', cmd, exception=exception)
	cmd_thrd.start()
	time.sleep(expire)
	if cmd_thrd.isAlive():
		cmd_thrd.raise_exception()
	if not cmd_thrd.rc:
		raise StopIteration(cmd+"\nExpired")
	return cmd_thrd.rc
