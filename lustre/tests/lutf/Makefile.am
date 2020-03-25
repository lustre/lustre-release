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
nobase_noinst_SCRIPTS = $(wildcard python/config/*.py)
nobase_noinst_SCRIPTS += $(wildcard python/config/lutf_start.sh)
nobase_noinst_SCRIPTS += $(wildcard python/infra/*.py)
nobase_noinst_SCRIPTS += $(wildcard python/tests/*.py)
nobase_noinst_SCRIPTS += $(wildcard python/tests-infra/*.py)
EXTRA_DIST=$(nobase_noinst_DATA) $(nobase_noinst_SCRIPTS)

noinst_testdir = $(libdir)/lustre/tests/lutf
nobase_noinst_test_DATA = $(nobase_noinst_DATA)
nobase_noinst_test_SCRIPTS = $(nobase_noinst_SCRIPTS)
