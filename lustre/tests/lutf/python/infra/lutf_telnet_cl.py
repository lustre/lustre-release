import telnetlib
import socket
import select
import sys

# TODO: need to fix the echo issue

class Interactive_remote (telnetlib.Telnet):
    """Creates an interactive remote session.

       Takes the following parameters:
         host: string of hostname or IP address, ex: "localhost" or "127.0.0.1"
         port: port to use to connect to the hose
         timeout (optional): timeout before failure.

    """
    def __init__(self, host, port, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        telnetlib.Telnet.__init__(self, None, 0, timeout)
        try:
            self.open(host, port, timeout)
        except IOError as e:
            print('*** Unable to open Connection: ', e.errno, ':', e.strerror, ' Please try later ***')
            return
        self.write(telnetlib.IAC + telnetlib.DONT + telnetlib.ECHO)
        self.interact()

    def echo_off(self):
        """Turn off echo on the server end.  This tells the server to not echo
           what the client sends to it.

        """
        self.write(telnetlib.IAC + telnetlib.DONT + telnetlib.ECHO)

    def setup_conn(self):
	# setup echo
	self.write_raw(telnetlib.IAC + telnetlib.DO + telnetlib.ECHO)
        # suppress go ahead
	self.write_raw(telnetlib.IAC + telnetlib.DO + telnetlib.SGA)
	self.write_raw(telnetlib.IAC + telnetlib.WILL + telnetlib.SGA)
	# setup a new environment
	self.write_raw(telnetlib.IAC + telnetlib.WILL + telnetlib.NEW_ENVIRON)
	# setup terminal type to xterm
	self.write_raw(telnetlib.IAC + telnetlib.WILL + telnetlib.TTYPE)
	self.write_raw(telnetlib.IAC + telnetlib.SB + telnetlib.TTYPE + chr(0) + "XTERM" + telnetlib.IAC + telnetlib.SE)

    def write_raw(self, buffer):
        self.msg("send %r", buffer)
        self.sock.sendall(buffer)

    def write(self, buffer):
        """Write a string to the socket, doubling any IAC characters.

        Can block if the connection is blocked.  May raise
        socket.error if the connection is closed.

        """
        if telnetlib.IAC in buffer:
            buffer = buffer.replace(telnetlib.IAC, telnetlib.IAC+telnetlib.IAC)
	else:
	    self.send_buf = buffer.replace('\n', '\r\n')
        self.msg("send %r", buffer)
        self.sock.sendall(buffer)

    def read(self):
	    #TODO: need to see how to get the timeouts workign properly
	    rfd, wfd, xfd = select.select([self], [], [], 0)
	    if self in rfd:
		try:
			text = self.read_eager()
		except EOFError:
			print('*** Connection closed by remote host ***')
		except IOError as e:
			print('*** Connection closed: ', e.errno, ':', e.strerror, ' ***')
		return text

    def wait_for(self, wait_text):
	rc_text = ''
        while 1:
            rfd, wfd, xfd = select.select([self, sys.stdin], [], [])
            if self in rfd:
                try:
                    text = self.read_eager()
                except EOFError:
                    print('*** Connection closed by remote host ***')
                    break
                except IOError as e:
                    print('*** Connection closed: ', e.errno, ':', e.strerror, ' ***')
                    break
                if text:
		    rc_text += text
		    if (len(wait_text) > 0) and (wait_text.find(text) == 0):
			wait_text = wait_text.replace(text, '')
			if (len(wait_text) == 0):
				break
		    elif (len(self.send_buf) > 0) and (wait_text in text):
			    break
	return rc_text


    def interact(self):
        """Enter interactive mode with the remote end

        """
        self.shutdown = False
        while (not self.shutdown):
            rfd, wfd, xfd = select.select([self, sys.stdin], [], [])
            if self in rfd:
                try:
                    text = self.read_eager()
                except EOFError:
                    print('*** Connection closed by remote host ***')
                    break
                except IOError as e:
                    print('*** Connection closed: ', e.errno, ':', e.strerror, ' ***')
                    break
                if text:
		    if (len(self.send_buf) > 0) and (self.send_buf.find(text) == 0):
			self.send_buf = self.send_buf.replace(text, '')
			continue
		    elif (len(self.send_buf) > 0) and (self.send_buf in text):
			    text = text.replace(self.send_buf, '', 1)
			    self.send_buf = ''
		    sys.stdout.write(text)
		    sys.stdout.flush()
            if sys.stdin in rfd:
                line = sys.stdin.readline()
                if ((line.find("exit") > -1) or (line.find("quit") > -1)) and (line.__len__() == 5):
                   self.shutdown = True
                if not line:
                    break
                self.write(line)
        self.close()

class telnet_cl(Interactive_remote):
    """Creates a none interactive remote session.  It can be turned into an
       interactive session by invoking the interact() method.

       Takes the following parameters:
         host: string of hostname or IP address, ex: "localhost" or "127.0.0.1"
         port: port to use to connect to the hose
         timeout (optional): timeout before failure.

    """
    def __init__(self, host, port,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        telnetlib.Telnet.__init__(self, None, 0, timeout)
        try:
            self.open(host, port, timeout)
        except IOError as e:
            print('*** Unable to open Connection: ', e.errno, ':', e.strerror, ' Please try later ***')
            return
	self.set_option_negotiation_callback(self.handle_option)
	self.send_buf = ''

    def read_all(self):
	    text = ""
	    t = self.read()
	    while t != None:
		text += t
		t = self.read()
	    return text

    def handle_option(self, sock, cmd, opt):
	# ignore any options
	self.sock = sock
	self.cmd = cmd
	self.opt = opt
	#if ((cmd == telnetlib.WILL) and (opt == telnetlib.ECHO)):
	#	self.write_raw(telnetlib.IAC + telnetlib.DONT + telnetlib.ECHO)
