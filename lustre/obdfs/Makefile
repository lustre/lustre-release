#
# Makefile 1.00 Peter Braam <braam@cs.cmu.edu>
#

include ../config.mk

MODDIR = $(PREFIX)/lib/modules/$(UTS_RELEASE)

ifndef CFLAGS
# Don't remove "-O2" or bad things will happen!
KFLAGS = -O2 -Wall -Wstrict-prototypes -Winline -pipe -I../obd
endif

CPPFLAGS = $(PCDEBUG) -D__KERNEL__ -DMODULE -I../include \
	   -I. -I$(LINUX)/include $(SMPFLAG)
COFLAGS = -kv

CFLAGS= $(KFLAGS) $(MFLAG)

SRCS=sysctl.c super.c
OBJS=$(SRCS:%.c=%.o)

MODULES = obdfs.o

all:	../.prereq.ok kcheck $(MODULES) 

showvar:
	@echo CFLAGS $(CFLAGS)
	@echo CPPFLAGS $(CPPFLAGS)
	@echo MODDIR $(MODDIR)
	@echo UTS_RELEASE $(UTS_RELEASE)
	@echo SRCS $(SRCS)
	@echo OBJS $(OBJS)

clean:
	rm -f core core.* *.o *.d .*.o *.s *.a *~ .depend .depfiles/*.d

MODDIR = $(PREFIX)/lib/modules/$(UTS_RELEASE)

install: $(MODULES) ../.prereq.ok kcheck
	-mkdir -p $(MODDIR)/fs
	install -o root -g root -m 644 $(MODULES) $(MODDIR)/fs/

# Stuff to automatically maintain dependency files

.c.o:
	$(CC) -MD $(CFLAGS) $(CPPFLAGS) -c $<
	@mkdir -p .depfiles ; mv $*.d .depfiles

kcheck:
	@. ../config.out ; \
	if [ "$$CHECK" != "" ] ; then \
	    if [ "`cksum < $$CHECK`" != "$$CKSUM" ] ; then \
		/bin/echo -n "Kernel configuration has changed." ; \
		/bin/echo "  Please re-run 'make config'." ; \
		exit 1 ; \
	    fi ; \
	fi

obdfs.o: $(OBJS)
	$(LD) -m "`ld --help | awk '/supported emulations/ {print $$4}'`" -r -o $@ $(OBJS)

-include $(SRCS:%.c=.depfiles/%.d)
