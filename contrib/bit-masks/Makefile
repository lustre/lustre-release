
top_builddir = ../..
src   = lustre_dlm_flags.def lustre_dlm_flags.tpl
targ  = lustre_dlm_flags.h
cropt = -nostartfiles -shared -rdynamic -fPIC

default : $(targ)
all     : $(targ) flags crash

$(targ) : $(src)
	@set -x ; \
	if autogen --version >/dev/null 2>&1 ; then \
		autogen -DTESTING=1 lustre_dlm_flags.def ; \
		rm -f $(top_builddir)/lustre/include/$@ ; \
		sed '/It has been AutoGen-ed/s/-ed.*/-ed/;s/ *$$//' \
			$@ > $(top_builddir)/lustre/include/$@ ; \
	else cp $(top_builddir)/lustre/include/$@ . ; fi

install : $(targ) install.sh
	DESTDIR="$(DESTDIR)" ./install.sh

clean :
	rm -f *~ *flags.[hc] ag-log*

clobber :
	git clean -f -x -d .

flags : lustre_dlm_flags
lustre_dlm_flags : $(targ)
	$(CC) -o $@ -g3 -O0 -DLDLM_FLAGS_PROGRAM=1 lustre_dlm_flags.c

crash : lustre-crash-ext.so
lustre-crash-ext.so : $(targ)
	$(CC) -g3 -O0 $(cropt) -o $@ lustre_dlm_flags.c

.PHONY : crash flags
