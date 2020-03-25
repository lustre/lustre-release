SUBDIRS = src
DIST_SUBDIRS = src

nobase_noinst_DATA = swig_templates/lutf_missing_definitions.h
nobase_noinst_DATA += swig_templates/typemap.template
nobase_noinst_DATA += swig_templates/liblnetconfig.template
nobase_noinst_DATA += swig_templates/generate_lutf_swig_i.py
nobase_noinst_DATA += swig_templates/generate_lnetconfig_swig_i.py
nobase_noinst_DATA += src/lutf_agent.swg
nobase_noinst_DATA += src/lutf_global.swg
nobase_noinst_DATA += src/liblutf_connect.c
nobase_noinst_DATA += src/liblutf_agent.c
nobase_noinst_DATA += src/liblutf_global.c
EXTRA_DIST=$(nobase_noinst_DATA)

noinst_testdir = $(libdir)/lustre/tests/lutf
nobase_noinst_test_DATA = $(nobase_noinst_DATA)
