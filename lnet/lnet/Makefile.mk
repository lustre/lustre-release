include $(src)/../Kernelenv

obj-y += portals.o
portals-objs    := 	lib-eq.o lib-init.o lib-md.o lib-me.o \
			lib-move.o lib-msg.o lib-ni.o lib-pid.o \
			api-errno.o api-ni.o api-wrap.o \
			module.o
