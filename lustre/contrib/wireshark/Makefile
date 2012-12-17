# Modify to point to your Wireshark and glib include directories
#INCS = -I$(HOME)/wireshark-1.6.8 `pkg-config --libs --cflags glib-2.0`
INCS = `pkg-config --libs --cflags wireshark`

SRCS_LNET = packet-lnet.c
SRCS_LUSTRE = packet-lustre.c

CC   = gcc

OBJS_LNET = $(foreach src, $(SRCS_LNET), $(src:.c=.o))
OBJS_LUSTRE = $(foreach src, $(SRCS_LUSTRE), $(src:.c=.o))

PLUGINS=lnet.so lustre.so

ifeq ($(shell id -u), 0)
WS_CONFIG=$(shell pkg-config --variable=includedir wireshark)/wireshark/config.h
WS_VERSION:=$(shell sed "s/^.define VERSION //p;d" ${WS_CONFIG})
PLUGIN_DIR = /usr/local/lib/wireshark/plugins/$(WS_VERSION)
else
PLUGIN_DIR = ${HOME}/.wireshark/plugins
endif

CFLAGS = -DHAVE_CONFIG_H $(INCS) -DINET6 -D_U_=__attribute__\(\(unused\)\) -Wall -Wpointer-arith -g -DXTHREADS -D_REENTRANT -DXUSE_MTSAFE_API -fPIC -DPIC

all: $(PLUGINS)

lustre.so: $(OBJS_LUSTRE)
	$(CC) -shared $(OBJS_LUSTRE) -o $@

lnet.so: $(OBJS_LNET)
	$(CC) -shared $(OBJS_LNET) -o $@

install: $(PLUGINS)
	mkdir -p $(PLUGIN_DIR)
	install $(PLUGINS) $(PLUGIN_DIR)/

clean:
	rm -f $(PLUGINS) $(OBJS_LNET) $(OBJS_LUSTRE)

extraclean: clean
	(cd $(PLUGIN_DIR)/; rm -f $(PLUGINS))
