# Modify to point to your Wireshark and glib include directories
INCS = -I$(HOME)/wireshark-1.6.8 `pkg-config --libs --cflags glib-2.0`

SRCS_LNET = packet-lnet.c
SRCS_LUSTRE = packet-lustre.c

CC   = gcc

OBJS_LNET = $(foreach src, $(SRCS_LNET), $(src:.c=.o))
OBJS_LUSTRE = $(foreach src, $(SRCS_LUSTRE), $(src:.c=.o))

PLUGIN_NAME1 = lnet
PLUGIN_NAME2 = lustre
PLUGIN_DIR  = /usr/local/lib/wireshark/plugins/1.6.8
PLUGIN1     = $(PLUGIN_DIR)/$(PLUGIN_NAME1).so
PLUGIN2     = $(PLUGIN_DIR)/$(PLUGIN_NAME2).so

CFLAGS = -DHAVE_CONFIG_H $(INCS) -DINET6 -D_U_=__attribute__\(\(unused\)\) -Wall -Wpointer-arith -g -DXTHREADS -D_REENTRANT -DXUSE_MTSAFE_API -fPIC -DPIC

$(PLUGIN1) : $(OBJS_LNET) $(OBJS_LUSTRE)
	mkdir -p $(PLUGIN_DIR)
	$(CC) -shared $(OBJS_LNET) -o $@
	$(CC) -shared $(OBJS_LUSTRE) -o $(PLUGIN2)

$(PLUGIN2) : $(OBJS_LUSTRE)
	mkdir -p $(PLUGIN_DIR)
	$(CC) -shared $(OBJS_LUSTRE) -o $@

%.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(PLUGIN1) $(OBJS_LNET)
	rm -f $(PLUGIN2) $(OBJS_LUSTRE)
