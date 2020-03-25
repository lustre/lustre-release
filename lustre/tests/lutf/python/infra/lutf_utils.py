import random, os, threading

class LutfThread(threading.Thread):
	def __init__(self, name, function, exception=False, *args, **kwargs):
		threading.Thread.__init__(self)
		self.name = name
		self.thread_id = threading.get_ident()
		self.rc = None
		self.exception = exception
		self.args = args
		self.kwargs = kwargs
		self.function = function

	def run(self):
		self.rc = self.function(*self.args, **self.kwargs)

	def raise_exception(self):
		res = ctypes.pythonapi.PyThreadState_SetAsyncExc(self.thread_id,
				ctypes.py_object(SystemExit))
		if res > 1:
			ctypes.pythonapi.PyThreadState_SetAsyncExc(self.thread_id, 0)

def generate_random_int_array(size, minimum=1, maximum=3000):
	return random.sample(range(minimum, maximum), size)

def generate_random_bytes(size):
	return os.urandom(size)
