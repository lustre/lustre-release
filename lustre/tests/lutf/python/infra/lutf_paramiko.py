import paramiko, logging

def lutf_get_file(target, rfile, sfile):
	ssh = paramiko.SSHClient()
	ssh.load_system_host_keys()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(hostname=target, timeout=3, banner_timeout=3, username='root')
	sftp = ssh.open_sftp()

	logging.debug("Commencing get %s -> %s" % (rfile, sfile))
	sftp.get(rfile, sfile)

	sftp.close()
	ssh.close()

def lutf_put_file(target, sfile, rfile):
	ssh = paramiko.SSHClient()
	ssh.load_system_host_keys()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(hostname=target, timeout=3, banner_timeout=3, username='root')
	sftp = ssh.open_sftp()

	logging.debug("Commencing put %s -> %s" % (sfile, rfile))
	sftp.put(sfile, rfile)

	sftp.close()
	ssh.close()

def lutf_exec_remote_cmd(cmd, host, ignore_err=False):
	ssh = paramiko.SSHClient()
	ssh.load_system_host_keys()
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	ssh.connect(hostname=host, timeout=3, banner_timeout=3, username='root')
	stdin, stdout, stderr = ssh.exec_command(cmd)

	error = False
	rc = ''
	for line in stderr.read().splitlines():
		if error:
			rc += '\n'
		error = True
		rc += host+': '+line.decode("utf-8")
	if error and not ignore_err:
		raise ValueError("(%s) Failed to execute: %s: %s" % (host, cmd, rc))
	ssh.close()
	return rc

