import code
import telnetsrvlib
import socketserver
import logging
import sys
import threading
from lutf import me, suites, agents, global_test_results

g_tns = None

class TNS(socketserver.ThreadingMixIn, socketserver.TCPServer):
	allow_reuse_address = True

class TNH(telnetsrvlib.TelnetHandler):
	def __init__(self, request, client_address, server):
		self.DOECHO = False
		self.interact = False
		self.console = None
		self.old_stdout = None
		self.more = False
		self.PROMPT = "lutf### "
		telnetsrvlib.TelnetHandler.__init__(self, request, client_address, server)

	# Overide the handler to work with the interactive console that
	# we will create
	def handle(self):
		"The actual service to which the user has connected."
		username = None
		password = None
		if self.authCallback:
			if self.authNeedUser:
				if self.DOECHO:
					self.write("Username: ")
				username = self.readline()
			if self.authNeedPass:
				if self.DOECHO:
					self.write("Password: ")
				password = self.readline(echo=False)
				if self.DOECHO:
					self.write("\n")
			try:
				self.authCallback(username, password)
			except:
				return
		while self.RUNSHELL:
			if self.DOECHO:
				self.write(self.PROMPT)
			if self.interact != True:
				cmdlist = [item.strip() for item in self.readline().split()]
				idx = 0
				while idx < (len(cmdlist) - 1):
					if cmdlist[idx][0] in ["'", '"']:
						cmdlist[idx] = cmdlist[idx] + " " + cmdlist.pop(idx+1)
						if cmdlist[idx][0] != cmdlist[idx][-1]:
							continue
						cmdlist[idx] = cmdlist[idx][1:-1]
					idx = idx + 1
				if cmdlist:
					cmd = cmdlist[0].upper()
					params = cmdlist[1:]
					if cmd in self.COMMANDS:
						try:
							self.COMMANDS[cmd](params)
						except:
							(t, p, tb) = sys.exc_info()
							if self.handleException(t, p, tb):
								break
					else:
						self.write("Unknown command '%s'\n" % cmd)
			else:
				try:
					try:
						line = self.raw_input(self.PROMPT)
						logging.debug(line)
						#self.write(line)
						encoding = getattr(sys.stdin, "encoding", None)
						#logging.debug(encoding)
						if encoding and not isinstance(line, str):
							line = line.decode(encoding)
					except EOFError:
						self.write("\n")
						break
					else:
						if (not self.more and (line == "logout" or line == "quit" or line == "exit")):
							self.interact = False
							self.PROMPT = "lutf### "
							sys.stdout = self.old_stdout
						else:
							self.more = self.console.push(line)
							if self.more:
								self.PROMPT = "lutf... "
							else:
								self.PROMPT = "lutf>>> "
				except KeyboardInterrupt:
					self.write("\nKeyboardInterrupt\n")
					self.console.resetbuffer()
					self.more = 0
		logging.debug("Exiting handler")
	def raw_input(self, prompt=""):
		#self.write(prompt)
		return self.readline()
	def cmdECHO(self, params):
		""" [<arg> ...]
		Echo parameters
		Echo command line parameters back to user, one per line.
		"""
		self.writeline("Parameters:")
		for item in params:
			self.writeline("\t%s" % item)
	def cmdINTERACT(self, params):
		"""
		Enter python interactive mode
		The main LUTF program should've set the globals properly
		"""
		self.interact = True
		vars = globals().copy()
		vars.update(locals())
		self.console = code.InteractiveConsole(vars)
		self.console.raw_input = self.raw_input
		self.console.write = self.write
		self.PROMPT = "lutf>>> "
		self.old_stdout = sys.stdout
		sys.stdout = self
		#logging.debug("cmdINTERACT complete")

	def cmdSHUTDOWN(self, params):
		"""
		Shutdown the LUTF Daemon
		"""
		global g_tns
		g_tns.stop()
		self.RUNSHELL = False
		self.writeline("Goodbye")

#class TNS1(socketserver.TCPServer):
#	allow_reuse_address = True

#class TNH1(telnetsrvlib.TelnetHandler):
#	def __init__(self, request, client_address, server):
#		print "calling TNH1.constructore"
#		telnetsrvlib.TelnetHandler.__init__(self, request, client_address, server)
#	def cmdECHO(self, params):
#		""" [<arg> ...]
#		Echo parameters
#		Echo command line parameters back to user, one per line.
#		"""
#		self.writeline("Parameters:")
#		for item in params:
#			self.writeline("\t%s" % item)

class LutfTelnetServer:
	def __init__(self, telnet_port):
		self.__telnet_port = telnet_port
		self.__tns = None

	def run(self):
		global g_tns
		logging.getLogger('').setLevel(logging.CRITICAL)
		self.__tns = TNS(("0.0.0.0", self.__telnet_port), TNH)
		g_tns = self
		self.__tns.serve_forever()

	def stop(self):
		self.__tns.shutdown()
