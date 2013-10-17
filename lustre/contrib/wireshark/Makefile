# Makefile to create the Lustre/LNet plugins for Wireshark.
# It is intended to be used by script `wsbuild´ that will buil
# a RPM for wireshark and a separate RPM for the Lustre/LNet plugins.
#
# All configuration should be performed with help of shell script
# `wsconfigs.sh' (see can-edit sections).
#
# When using as a stand-alone makefile, set the macros WS_HOME,
# PLUGIN_DIR and PLUGIN_COMPILE_FLAGS to the values associated with
# your wireshark installation.
# Alternatively modify `wsconfigs.sh´ accordingly to your wireshar
# installation, source wsconfigs.sh and build with help of:
#
#      make -e -f Makefile
#

#
# Minimum Wireshark Version - This should match the README file.
#
MIN_WIRESHARK_VERSION=1.6.8

# Installation directory of the Wireshark source code
#    Note: Leave the macro undefined when using the wsbuild script.
#
# WS_HOME =
WS_HOME = 

# Installation directory for the (compiled) Wireshark plugins
#    Change the value of the following macro to the installation directory
#    of the Wireshark plugins for your installation 
#
#    Note: When using the cbuild script leave the macro undefined
#    (default: /usr/lib/wireshark/plugins/$(WS_VERSION))
#
#    For non-root and  non-rpmbuilds you might want to set the value to
#        ${HOME}/.wireshark/plugins
PLUGIN_DIR =

CFLAGS = -DINET6 -D_U_=__attribute__\(\(unused\)\) -Wall -Wpointer-arith -g \
	-DXTHREADS -D_REENTRANT -DXUSE_MTSAFE_API -fPIC -DPIC

ifdef WS_HOME
#INCS = $(shell echo "-I${WS_HOME} `./wsconfig.sh --libs --cflags glib-2.0`")
INCS := $(shell echo "-I${WS_HOME} $(PLUGIN_COMPILE_FLAGS)") -DHAVE_CONFIG_H 

else
INCS := $(shell ./wsconfig.sh --libs --cflags wireshark) \
	$(shell ./wsconfig.sh --libs --cflags glib-2.0) \
	-I../../include \
	$(shell echo "$(PLUGIN_COMPILE_FLAGS)") -DHAVE_CONFIG_H
WS_VERSION := $(shell ./wsconfig.sh --modversion wireshark)
LIBDIR := $(shell ./wsconfig.sh --variable=libdir wireshark)
CHECK=./wsconfig.sh --atleast-version=${MIN_WIRESHARK_VERSION} wireshark
endif

CFLAGS += $(INCS)

SRCS_LNET = packet-lnet.c
SRCS_LUSTRE = packet-lustre.c

CC   = gcc

OBJS_LNET := $(foreach src, $(SRCS_LNET), $(src:.c=.o))
OBJS_LUSTRE := $(foreach src, $(SRCS_LUSTRE), $(src:.c=.o))

PLUGINS=lnet.so lustre.so

ifeq (${CHECK},)
       CHECK=true
endif

ifneq ($(shell id -u), 0)
  ifndef DESTDIR
    PLUGIN_DIR = ${HOME}/.wireshark/plugins
  endif
endif

ifndef PLUGIN_DIR
  ifndef WS_VERSION
    ifndef WS_HOME
      $(error "WS_HOME not defined")
    endif
    WS_CONFIG=$(WS_HOME)/config.h
    WS_VERSION:=$(shell sed "s/^.define[[:space:]]*VERSION[[:space:]]*\"\(.*\)\"/\1/p;d" ${WS_CONFIG})
  endif
  ifeq (${LIBDIR},)
    ifeq ($(shell if [ -r /etc/SuSE-release ] ; then echo 0; else echo 1; fi ), 0)
      LIBDIR=/usr/lib64
    else
      LIBDIR=/usr/lib
    endif
  endif
  PLUGIN_DIR = $(DESTDIR)$(LIBDIR)/wireshark/plugins/$(WS_VERSION)
endif


all: check $(PLUGINS) lustre_dlm_flags_wshark.c

lustre_dlm_flags_wshark.c :
	cd ../../../contrib/bit-masks ; \
	make
	test -f lustre_dlm_flags_wshark.c

check:
	@if ! ${CHECK}; then\
		echo "Wireshark must be at least version ${MIN_WIRESHARK_VERSION} (installed ${WS_VERSION})";\
		false; \
	fi

lustre.so: $(OBJS_LUSTRE)
	$(CC) -shared $(OBJS_LUSTRE) -o $@

lnet.so: $(OBJS_LNET)
	$(CC) -shared $(OBJS_LNET) -o $@

install: all
	mkdir -p $(PLUGIN_DIR)
	install $(PLUGINS) $(PLUGIN_DIR)/

help:
	@echo "Includes:    "$(INCS)
	@echo "Install Dir: "$(PLUGIN_DIR)

clean:
	rm -f $(PLUGINS) $(OBJS_LNET) $(OBJS_LUSTRE)

extraclean: clean
	(cd $(PLUGIN_DIR)/; rm -f $(PLUGINS))

.PHONEY: check help install extraclean clean all
