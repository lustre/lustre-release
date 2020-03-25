import lutf_agent
from lutf_basetest import BaseTest
from lutf_paramiko import *
from clutf_global import *
from clutf_agent import *
from lutf import me
from lutf_exception import LUTFError
import os, random, tempfile, shutil, pathlib

class LutfDir(BaseTest):
	def __init__(self, dname, script=os.path.abspath(__file__),
		     target=None):
		self.dname = dname
		super().__init__(script, target, self.dname)

	def listdir(self):
		return os.listdir(self.dname)

class LutfFile(BaseTest):
	def __init__(self, fname, script=os.path.abspath(__file__),
		     full_path=False, target=None):
		if not full_path:
			self.fname = os.path.join(os.getcwd(), fname)
		else:
			self.fname = fname
		super().__init__(script, target, self.fname, full_path=full_path)
		self.file_handle = None

	def open(self, mode):
		self.file_handle = open(self.fname, mode)

	def write(self, data):
		if not self.file_handle or self.file_handle.closed:
			raise LUTFError("%s not opened" % self.fname)
		self.file_handle.write(data)

	def get_full_path(self):
		return self.fname

	def readlines(self):
		lines = self.file_handle.readlines()
		return lines

	def read(self):
		data = self.file_handle.read()
		return data

	def isclosed(self):
		if self.file_handle:
			return self.file_handle.closed
		return True

	def close(self):
		if self.file_handle and not self.file_handle.closed:
			self.file_handle.close()

	def remove(self):
		if self.file_handle and not self.file_handle.closed:
			self.file_handle.close()
			os.remove(self.fname)
		else:
			os.remove(self.fname)
		self.fname = ''
		self.file_handle = None

	def find_replace_file(self, fname, search, replace, getline=False):
		count = 0
		found_line = None
		if not self.isclosed():
			raise LUTFError("Can not perform operation on file. Close it first")

		# if no replace is provided then just count the instances of the
		# search string
		if not replace:
			with open(fname) as old_file:
				for line in old_file:
					if search in line:
						if not found_line:
							found_line = line
						count += 1
			if getline:
				return count, found_line
			return count

		fh, abs_path = tempfile.mkstemp()
		with os.fdopen(fh,'w') as new_file:
			with open(fname) as old_file:
				for line in old_file:
					if search in line:
						if not found_line:
							found_line = line
						new_file.write(replace)
						count += 1
					else:
						new_file.write(line)
		#Copy the file permissions from the old file to the new file
		shutil.copymode(fname, abs_path)
		#Remove original file
		os.remove(fname)
		#Move new file
		shutil.move(abs_path, fname)

		if getline:
			return count, found_line
		return count

	def find_replace_global(self, directory, search, replace, getline=False):
		count = 0
		lines = []
		for filename in os.listdir(directory):
			fpath = os.path.join(directory, filename)
			if getline:
				c, line = self.find_replace_file(fpath, search, replace, getline)
				if c >= 1:
					lines.append(line)
				count += c
			else:
				count += self.find_replace_file(fpath, search, replace, getline)
		if getline:
			return count, lines
		return count

	def find_replace(self, search, replace):
		count = 0
		if os.path.isdir(self.fname):
			count = self.find_replace_global(self.fname, search, replace)
		elif os.path.isfile(self.fname):
			count = self.find_replace_file(self.fname, search, replace)
		return count

	def find(self, search):
		count = 0
		if os.path.isdir(self.fname):
			count = self.find_replace_global(self.fname, search, None)
		elif os.path.isfile(self.fname):
			count = self.find_replace_file(self.fname, search, None)
		return count

	def get(self, search):
		count = 0
		if os.path.isdir(self.fname):
			count, line = self.find_replace_global(self.fname, search, None, getline=True)
		elif os.path.isfile(self.fname):
			count, line = self.find_replace_file(self.fname, search, None, getline=True)
		return count, line

