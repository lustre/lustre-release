import os
import sys

def writeSwigI(block, ommit_list, swigI, function_ommit=[]):
	# create a new block with the updated info
	new_block = []
	prev_line = ''
	brace = 0
	function_ommitting = False
	for line in block:
		skip = False
		if function_ommitting:
			if '{' in line:
				brace += 1
			if '}' in line:
				brace -= 1
			if brace == 0:
				function_ommitting = False
			continue
		for ommit in function_ommit:
			if ommit in line:
				# we found the function. We'll not be too smart and we'll
				# assume that if there is a beginning it'll be in the line
				# before.
				if prev_line != '':
					new_block = new_block[:len(new_block)-1]
				function_ommitting = True;
				if '{' in line:
					brace += 1
				skip = True
				break
		if skip:
			continue
		for ommit in ommit_list:
			if line.startswith(ommit):
				skip = True
				break
		if skip:
			continue
		new_block.append(line)
		prev_line = line
	for line in new_block:
		# remove __user flag, since swig can't understand
		# it
		newline = line
		if "#define __user" in newline:
			newline = line.replace('__user', '__lutf_user')
		elif "#ifndef __user" in newline:
			newline = line.replace('__user', '__lutf_user')
		else:
			newline = line.replace('__user', '')
		swigI.write(newline)

# set up the paths to all the files that need to be swigified
netconfig_path = sys.argv[1] + '/lnet/utils/lnetconfig/liblnetconfig.h'
cyaml_path = sys.argv[1] + '/lnet/utils/lnetconfig/cyaml.h'
lib_dlc_path = sys.argv[1] + '/lnet/include/uapi/linux/lnet/lnet-dlc.h'
string_path = sys.argv[1] + '/libcfs/include/libcfs/util/string.h'
nidstr_path = sys.argv[1] + '/lnet/include/uapi/linux/lnet/nidstr.h'
limits_path = '/usr/include/limits.h'
typemap_path = sys.argv[1] + '/lustre/tests/lutf/swig_templates/typemap.template'
lutf_missing_def = sys.argv[1] + '/lustre/tests/lutf/swig_templates/lutf_missing_definitions.h'
lutf_extra_defs = sys.argv[1] + '/lustre/tests/lutf/swig_templates/liblnetconfig.template'
swig_intf_path = sys.argv[1] + '/lustre/tests/lutf/src/liblnetconfig.i'

# open these files
i_netconfig = open(netconfig_path)
i_cyaml = open(cyaml_path)
i_lib_dlc = open(lib_dlc_path)
i_string = open(string_path)
i_nidstr = open(nidstr_path)
i_limits = open(limits_path)
i_typemap = open(typemap_path)
i_lutf_missing_def = open(lutf_missing_def)

# open the swig interface output file
o_swig_intf = open(swig_intf_path, 'w')

# read the files
l_netconfig = i_netconfig.readlines()
l_cyaml = i_cyaml.readlines()
l_lib_dlc = i_lib_dlc.readlines()
l_string = i_string.readlines()
l_nidstr = i_nidstr.readlines()
l_limits = i_limits.readlines()
l_typemap = i_typemap.readlines()
l_lutf_missing_def = i_lutf_missing_def.readlines()

# identify all the lines that I'd like to remove from the swig interface
# file.
netconfig_ommit_list = ['/*', ' *', '#ifndef LIB_LNET_CONFIG_API_H', '#define LIB_LNET_CONFIG_API_H',
			'struct cYAML;', '#endif']
cyaml_ommit_list = ['/*', ' *', '#ifndef CYAML_H', '#define CYAML_H', '#endif']
generic_ommit_list = ['/*', ' *', '__printf(3, 4)']

# write the swig interface file
o_swig_intf.write('%module lnetconfig\n')
o_swig_intf.write('%{\n')

o_swig_intf.write("#include \"libcfs/util/ioctl.h\"\n")
o_swig_intf.write("#include \"libcfs/util/string.h\"\n")

writeSwigI(l_lutf_missing_def, [], o_swig_intf)
writeSwigI(l_cyaml, cyaml_ommit_list, o_swig_intf)
writeSwigI(l_netconfig, netconfig_ommit_list, o_swig_intf)
writeSwigI(l_lib_dlc, generic_ommit_list, o_swig_intf)
o_swig_intf.write('PyObject *lutf_parse_nidlist(char *str, int len, int max_nids);\n')
o_swig_intf.write('char *lutf_nid2str(unsigned long nid);\n')

o_swig_intf.write('%}\n')

for line in l_typemap:
	o_swig_intf.write(line)

# handle the typdefs that are declared in
# /usr/include/asm-generic/int-ll64.h
# It appears that SWIG has a problem with __signed__ keyword
o_swig_intf.write("typedef char __s8;\n")
o_swig_intf.write("typedef unsigned char __u8;\n")

o_swig_intf.write("typedef short __s16;\n")
o_swig_intf.write("typedef unsigned short __u16;\n")

o_swig_intf.write("typedef int __s32;\n")
o_swig_intf.write("typedef unsigned int __u32;\n")

o_swig_intf.write("typedef long long __s64;\n")
o_swig_intf.write("typedef unsigned long long __u64;\n")


o_swig_intf.write('PyObject *lutf_parse_nidlist(char *str, int len, int max_nids);\n')
o_swig_intf.write('char *lutf_nid2str(unsigned long nid);\n')
writeSwigI(l_limits, [], o_swig_intf)
writeSwigI(l_cyaml, cyaml_ommit_list, o_swig_intf)
writeSwigI(l_netconfig, netconfig_ommit_list, o_swig_intf)
writeSwigI(l_lib_dlc, generic_ommit_list, o_swig_intf)
function_ommit = ['int vscnprintf(char *buf, size_t bufsz, const char *format, va_list args)',
	          'static inline int scnprintf(char *buf, size_t bufsz, const char *format, ...)']
writeSwigI(l_string, generic_ommit_list, o_swig_intf, function_ommit=function_ommit)
writeSwigI(l_nidstr, generic_ommit_list, o_swig_intf)

with open(lutf_extra_defs, 'r') as f:
	for line in f:
		o_swig_intf.write(line)
o_swig_intf.close()
