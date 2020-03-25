import lutf_agent
import clutf_global
import paramiko, logging, time
from lutf_exception import LUTFError
from lutf_paramiko import lutf_put_file
from lutf_common_def import load_pref

LUTF_TEST_PASS = 0
LUTF_TEST_FAIL = -1
LUTF_TEST_SKIP = -2

class BaseTest(object):
	# TODO the idea of the *args and **kwargs in the __init__ method is for subclasses
	# to pass all their arguments to the super() class. Then the superclass can then pass
	# that to the remote, so the remote class can be instantiated appropriately
	def __init__(self, script, target=None, *args, **kwargs):
		self.__remote = False
		# if a target is specified other than me then we're going
		# to execute on that target
		if target and target != clutf_global.get_node_name():
			agents = lutf_agent.LutfAgents()
			if target not in agents.keys():
				raise LUTFError("%s not a known agent" % target)
			self.__script = script
			self.__remote = True
			self.__target = target
			self.__class_id = time.time()
			agent = agents[self.__target]
			pref = load_pref()
			if pref['remote copy']:
				logging.debug("Putting script %s on %s:%s" % (self.__script, agent.get_hostname(), agent.get_ip()))
				lutf_put_file(agent.get_ip(), self.__script, self.__script)
			# tell the remote to instantiate the class and keep it around
			agent = agents[self.__target]
			agent.send_rpc('instantiate_class', clutf_global.get_node_name(),
				       self.__script, type(self).__name__, '__init__', '',
				       self.__class_id, *args, **kwargs)

	def __getattribute__(self, name):
		attr = object.__getattribute__(self, name)
		if hasattr(attr, '__call__'):
			def newfunc(*args, **kwargs):
				if self.__remote:
					# execute on the remote defined by:
					#     self.target
					#     attr.__name__ = name of method
					#     type(self).__name__ = name of class
					agents = lutf_agent.LutfAgents()
					if self.__target not in agents.keys():
						raise LUTFError("%s not a known agent: %s" % (self.__target, str(agents.keys())))
					agent = agents[self.__target]
					result = agent.send_rpc('method_call',
								clutf_global.get_node_name(),
								self.__script,
								type(self).__name__,
								attr.__name__, '',
								self.__class_id,
								*args, **kwargs)
				else:
					result = attr(*args, **kwargs)
				return result
			return newfunc
		else:
			return attr

	def __del__(self):
		try:
			# signal to the remote that the class is being destroyed
			if self.__remote:
				agents = lutf_agent.LutfAgents()
				if self.__target not in agents.keys():
					raise LUTFError("%s not a known agent" % target)
				agent = agents[self.__target]
				agent.send_rpc('destroy_class', clutf_global.get_node_name(),
					self.__script, type(self).__name__, '__del__', '',
					self.__class_id)
		except:
			pass

def lutfrc(error, *args, **kwargs):
	rc = {}
	if error == -1:
		rc['status'] = 'FAIL'
	elif error == -2:
		rc['status'] = 'SKIP'
	else:
		rc['status'] = 'PASS'
	if len(args):
		rc['args'] = list(args)
	if len(kwargs):
		rc['kwargs'] = kwargs
	return rc


