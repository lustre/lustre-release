import sys
import os

intf = open(sys.argv[2], 'r')
contents = intf.readlines()
intf.close()

idx = 0
for c in contents:
	idx += 1
	if "%}" in c:
		break

#typemap_path = sys.argv[1] + '/lustre/tests/lutf/swig_templates/typemap.template'
typemap_path = os.path.join(sys.argv[1], 'typemap.template')
i_typemap = open(typemap_path)
l_typemap = i_typemap.readlines()
i_typemap.close()

j = 0
for i in range(idx, idx + len(l_typemap)):
	contents.insert(i, l_typemap[j])
	j += 1

new_i_file = os.path.splitext(sys.argv[2])[0]+'.i'

intf = open(new_i_file, 'w')
contents = "".join(contents)
intf.write(contents)
intf.close()

