# Administration utilities Makefile

PYTHON_BIN=python$(PYTHON_VERSION)
SWIG_COMPFLAGS=-g -Wall -fPIC -c
SWIG_FLAGS=-D__x86_64__
SWIG_INCLUDES=-I/usr/include -I/usr/include/linux -I/usr/include/c++/4.4.4/tr1 -I/usr/include/c++/4.4.4/cstdbool
DLC_SWIG_FLAGS=-D__x86_64__  -D__arch_lib__ -D_LARGEFILE64_SOURCE=1
DLC_SWIG_INCLUDES=-I/usr/include -I/usr/include/asm -I/usr/include/linux -I/usr/lib64/gcc/i686-pc-mingw32/4.4.6/include/
DLC_SWIG_INCLUDES+=-I$(top_builddir)/lnet/utils/lnetconfig -I$(top_builddir)/lnet/utils -I$(top_builddir)/lnet/include -I$(top_builddir)/libcfs/include  -I$(top_builddir)/lnet/include/uapi/
DLC_INCLUDES=-I/usr/include -I$(top_builddir)/lnet/utils/lnetconfig -I$(top_builddir)/lnet/utils -I$(top_builddir)/lnet/include -I$(top_builddir)/libcfs/include -I$(top_builddir)/lnet/include/uapi/

LIBCFS= $(top_builddir)/libcfs/libcfs/.libs/libcfs.a
LIBLNETCONFIG=-L$(top_builddir)/lnet/utils/lnetconfig/.libs/
LIBLUTF=-L$(top_builddir)/lustre/tests/lutf/src/

LUTF_AGENT_I=$(top_builddir)/lustre/tests/lutf/src/lutf_agent.i
LUTF_AGENT_SWG=$(top_builddir)/lustre/tests/lutf/src/lutf_agent.swg
LUTF_GLOBAL_I=$(top_builddir)/lustre/tests/lutf/src/lutf_global.i
LUTF_GLOBAL_SWG=$(top_builddir)/lustre/tests/lutf/src/lutf_global.swg
LNETCONFIG_I=$(top_builddir)/lustre/tests/lutf/src/liblnetconfig.i
GEN_SWIG_TEMPLATES=$(top_builddir)/lustre/tests/lutf/swig_templates
UPDATE_LUTF_SWIG_INTF=$(GEN_SWIG_TEMPLATES)/generate_lutf_swig_i.py
GEN_SWIG_INTF_PY=$(GEN_SWIG_TEMPLATES)/generate_lnetconfig_swig_i.py
LIBLNETCONFIG_WRAP_I=$(top_builddir)/lustre/tests/lutf/src/liblnetconfig_wrap.c
LIBLNETCONFIG_WRAP_OBJ=$(top_builddir)/lustre/tests/lutf/src/liblnetconfig_wrap.o
LIBLUTF_AGENT_C=$(top_builddir)/lustre/tests/lutf/src/liblutf_agent.c
LIBLUTF_AGENT_OBJ=$(top_builddir)/lustre/tests/lutf/src/liblutf_agent.o
LIBLUTF_CONNECT_C=$(top_builddir)/lustre/tests/lutf/src/liblutf_connect.c
LIBLUTF_CONNECT_OBJ=$(top_builddir)/lustre/tests/lutf/src/liblutf_connect.o
LIBLUTF_GLOBAL_C=$(top_builddir)/lustre/tests/lutf/src/liblutf_global.c
LIBLUTF_GLOBAL_OBJ=$(top_builddir)/lustre/tests/lutf/src/liblutf_global.o

CYAML_SRC=$(top_builddir)/lnet/utils/lnetconfig/cyaml.c
CYAML_OBJ=$(top_builddir)/lustre/tests/lutf/src/cyaml.o

clean-local:
	rm -Rf *.so *_wrap.c *.py *.i

noinst_PROGRAMS = lutf

# LUTF sources
lutf_SOURCES = lutf.c lutf_listener.c lutf_python.c
lutf_SOURCES += lutf_global.h lutf_agent.h lutf_common.h lutf.h lutf_listener.h
lutf_SOURCES += lutf_message.h lutf_python.h
lutf_CPPFLAGS := $(PYTHON_CPPFLAGS)
lutf_LDADD := $(top_builddir)/lnet/utils/lnetconfig/liblnetconfig.la \
		$(LIBCFS) $(LIBREADLINE) $(LIBEFENCE) -lyaml -lm -llutf_agent -llutf_connect -llutf_global $(PYTHON_EXTRA_LIBS)
lutf_LDFLAGS := $(PYTHON_LIBS) -L$(top_builddir)/lustre/tests/lutf/src

# 1. generate the lutf_agent_wrap.c and py files
# 2. build the lutf_agent plugin
# 3. generate the DLC plugin
lutf_DEPENDENCIES := _clutf_agent.so _clutf_global.so dlc_glue

update_swig_intf :
	echo "updating lutf_agent.i"
	$(PYTHON_BIN) $(UPDATE_LUTF_SWIG_INTF) $(GEN_SWIG_TEMPLATES) $(LUTF_AGENT_SWG)
	echo "updating lutf_global.i"
	$(PYTHON_BIN) $(UPDATE_LUTF_SWIG_INTF) $(GEN_SWIG_TEMPLATES) $(LUTF_GLOBAL_SWG)

lutf_agent_wrap.c : update_swig_intf
	echo "generating lutf_agent_warp.c"
	$(SWIG) -python -includeall $(SWIG_FLAGS) $(SWIG_INCLUDES) $(LUTF_AGENT_I)
	echo "building lutf_agent_wrap.c"
	$(CC) $(SWIG_COMPFLAGS) $(PYTHON_CPPFLAGS) $@

_clutf_agent.so : liblutf_agent.so liblutf_connect.so update_swig_intf
	echo "linking _clutf_agent.so"
	$(CC) -shared lutf_agent_wrap.o -o $@ $(LIBLUTF) -llutf_agent -llutf_connect

liblutf_agent.so : lutf_agent_wrap.c
	echo "building liblutf_agent.c"
	$(CC) $(SWIG_COMPFLAGS) $(PYTHON_CPPFLAGS) $(DLC_INCLUDES) $(CYAML_SRC) $(LIBLUTF_AGENT_C)
	echo "linking liblutf_agent.so"
	$(CC) -shared $(LIBLUTF_AGENT_OBJ) $(CYAML_OBJ) -o $@

lutf_global_wrap.c : update_swig_intf
	echo "generating lutf_global_warp.c"
	$(SWIG) -python -includeall $(SWIG_FLAGS) $(SWIG_INCLUDES) $(LUTF_GLOBAL_I)
	echo "building lutf_global_wrap.c"
	$(CC) $(SWIG_COMPFLAGS) $(PYTHON_CPPFLAGS) $(DLC_INCLUDES) $@

_clutf_global.so : liblutf_global.so
	echo "linking _clutf_global.so"
	$(CC) -shared lutf_global_wrap.o -o $@ $(LIBLUTF) -llutf_global

liblutf_global.so : lutf_global_wrap.c
	echo "building liblutf_global.c"
	$(CC) $(SWIG_COMPFLAGS) $(PYTHON_CPPFLAGS) $(LIBLUTF_GLOBAL_C)
	echo "linking liblutf_global.so"
	$(CC) -shared $(LIBLUTF_GLOBAL_OBJ) -o $@

liblutf_connect.so :
	echo "building liblutf_connect.c"
	$(CC) $(SWIG_COMPFLAGS) $(PYTHON_CPPFLAGS) $(LIBLUTF_CONNECT_C)
	echo "linking liblutf_connect.so"
	$(CC) -shared $(LIBLUTF_CONNECT_OBJ) -o $@

dlc_glue:
	echo "generating liblnetconfig.i"
	$(PYTHON_BIN) $(GEN_SWIG_INTF_PY) $(top_builddir)
	echo "generating liblndconfig_wrap.c"
	$(SWIG) -python $(DLC_SWIG_FLAGS) $(DLC_SWIG_INCLUDES) $(LNETCONFIG_I)
	echo "building liblnetconfig_wrap.c"
	$(CC) $(SWIG_COMPFLAGS) $(PYTHON_CPPFLAGS) $(DLC_INCLUDES) $(LIBLNETCONFIG_WRAP_I) $(CYAML_SRC)
	echo "linking _lnetconfig.so"
	$(CC) $(LIBLNETCONFIG) -lyaml -llnetconfig -Wl,--whole-archive $(LIBCFS) $(CYAML_OBJ) -Wl,--no-whole-archive -shared -o _lnetconfig.so $(LIBLNETCONFIG_WRAP_OBJ) $(PYTHON_EXTRA_LIBS) $(PYTHON_LIBS)

install-exec-local:
	$(mkinstalldirs) $(DESTDIR)$(libdir)
	mkdir -p $(DESTDIR)$(libdir)/lustre/tests/lutf/
	cp .libs/lutf  $(DESTDIR)$(libdir)/lustre/tests/lutf/
	cp _lnetconfig.so $(DESTDIR)$(libdir)/lustre/tests/lutf/
	cp _clutf_global.so $(DESTDIR)$(libdir)/lustre/tests/lutf/
	cp liblutf_global.so $(DESTDIR)$(libdir)/lustre/tests/lutf/
	cp liblutf_connect.so $(DESTDIR)$(libdir)/lustre/tests/lutf/
	cp _clutf_agent.so $(DESTDIR)$(libdir)/lustre/tests/lutf/
	cp liblutf_agent.so $(DESTDIR)$(libdir)/lustre/tests/lutf/
	cp *.py $(DESTDIR)$(libdir)/lustre/tests/lutf/

