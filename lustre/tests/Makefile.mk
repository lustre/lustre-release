include $(src)/../portals/Kernelenv

HOSTCFLAGS += -Iinclude -D_LARGEFILE64_SOURCE

OURPTLCTL := $(addprefix $(src)/../portals/utils/, $(PTLCTLOBJS))
OURPTLCTLNOPARSER := $(addprefix $(src)/../portals/utils/, \
			$(filter-out parser.o,$(PTLCTLOBJS)))

host-progs := openunlink testreq truncate directio openme writeme open_delay \
	 	munlink tchmod toexcl fsx test_brw openclose createdestroy \
		stat createmany statmany multifstat createtest mlink \
		opendirunlink opendevunlink unlinkmany fchdir_test \
		checkstat wantedi statone runas openfile \
		mcreate mkdirmany

always := $(host-progs) 


tchmod-objs  := tchmod.o
toexcl-objs  := toexcl.o
testreq-objs  := testreq.o
mcreate-objs  := mcreate.o
munlink-objs  := munlink.o
mlink-objs  := mlink.o
truncate-objs  := truncate.o
directio-objs  := directio.o
openunlink-objs  := openunlink.o
openme-objs  := openme.o
writeme-objs  := writeme.o
fsx-objs  := fsx.o
test_brw-objs  := test_brw.o
openclose-objs  := openclose.o
createdestroy-objs  := createdestroy.o
stat-objs  := stat.o
createmany-objs  := createmany.o
statmany-objs  := statmany.o
unlinkmany-objs  := unlinkmany.o
statone-objs  := statone.o
mkdirmany-objs  := mkdirmany.o
multifstat-objs  := multifstat.o
checkstat-objs  := checkstat.o
runas-objs  := runas.o
openfile-objs  := openfile.o
wantedi-objs  := wantedi.o
createtest-objs  := createtest.o
open_delay-objs  := open_delay.o
opendirunlink-objs :=opendirunlink.o
opendevunlink-objs :=opendirunlink.o
fchdir_test-objs :=fchdir_test.o

