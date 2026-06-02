# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# openZFS OSD related configuration
#

#
# Supported configure options.  When no options are specified support
# for ZFS OSDs will be autodetected assuming server support is enabled.
# If the ZFS OSD cannot be built support for it is disabled and a
# warning is issued but the configure process is allowed to continue.
#
# --without-zfs   - Disable zfs support.
# --with-zfs=no
#
# --with-zfs      - Enable zfs support and attempt to autodetect the zfs
# --with-zfs=yes    headers in one of the following places.  Because zfs
#                   support was explicitly required if the headers cannot
#                   be located it is treated as a fatal error.
#
#                       * /var/lib/dkms/zfs/${VERSION}/source
#                       * /usr/src/zfs-${VERSION}/${LINUXRELEASE}
#                       * /usr/src/zfs-${VERSION}
#                       * ../zfs/
#                       * $LINUX/zfs
#
# --with-zfs-devel=path
#                 - User provided directory where zfs development headers
#                   are located. This option is typically used when user
#                   uses rpm2cpio to unpack src rpm.
#                   Assumes layout of:
#                     ${zfs-devel-path}/usr/include/libzfs
#                     ${zfs-devel-path}/usr/include/libspl
#                     ${zfs-devel-path}/lib64/libzfs.so.* or
#                     ${zfs-devel-path}/lib/libzfs.so.*
#
# --with-zfs=path - Enable zfs support and use the zfs headers in the
#                   provided path.  No autodetection is performed and
#                   if no headers are found this is a fatal error.
#
# --with-zfs-obj  - When zfs support is enabled the object directory
#                   will be based on the --with-zfs directory.  If this
#                   is detected incorrectly it can be explicitly
#                   specified using this option.
#

#
# LB_ZFS
#
AC_DEFUN([LB_ZFS], [
	AC_ARG_WITH([zfs-obj],
		AS_HELP_STRING([--with-zfs-obj=PATH],
		[Path to zfs build objects]),
		[zfsobj="$withval"])

	#
	# The existence of zfs.release[.in] is used to identify a valid
	# source directory.  In order of preference:
	#
	zfsver=$(ls -1 /usr/src/ | grep ^zfs- | cut -f2 -d'-' |
		 sort -V | head -n1)
	zfsdkms="/var/lib/dkms/zfs/${zfsver}"
	zfssrc1="/usr/src/zfs-${zfsver}/${LINUXRELEASE}"
	zfssrc2="/usr/src/zfs-${zfsver}"
	zfssrc3="../zfs/"
	zfssrc4="$LINUX/zfs"

	AC_MSG_CHECKING([zfs source directory])
	AS_IF([test -z "${zfssrc}"], [
		AS_IF([test -e "${zfsdkms}/source/zfs.release.in"], [
			zfssrc=${zfsdkms}/source
		], [test -e "${zfssrc1}/zfs.release.in"], [
			zfssrc=${zfssrc1}
		], [test -e "${zfssrc2}/zfs.release.in"], [
			zfssrc=${zfssrc2}
		], [test -e "${zfssrc3}/zfs.release.in"], [
			zfssrc=$(readlink -f "${zfssrc3}")
		], [test -e "${zfssrc4}/zfs.release.in"], [
			zfssrc=${zfssrc4}
		], [
			zfssrc="[Not found]"
		])
	])
	AC_MSG_RESULT([$zfssrc])

	AS_IF([test ! -e "$zfssrc/zfs.release.in" &&
	    test ! -e "$zfssrc/zfs.release"], [
		enable_zfs=no
	])

	#
	# The existence of the zfs_config.h is used to identify a valid
	# zfs object directory.  In many cases the object and source
	# directory are the same, however the objects may also reside
	# is a subdirectory named after the kernel version.  When
	# weak modules are used, the kernel version may not be the
	# same as the LINUXRELEASE against which we are building lustre.
	#
	AC_MSG_CHECKING([zfs build directory])
	AS_IF([test -z "$zfsobj"], [
		last_zfs_obj_dir=$(ls -d ${zfssrc}/[[0-9]]*/ 2> /dev/null | tail -n 1 | sed 's|/$||')
		AS_IF([test "${zfssrc}" = "${zfsdkms}/source"], [
			AS_IF([test -e "${zfsdkms}/${LINUXRELEASE}/${target_cpu}/zfs_config.h"], [
				zfsobj=${zfsdkms}/${LINUXRELEASE}/${target_cpu}
			], [
				zfsobj="[Not found]"
			])
		], [test -e "${zfssrc}/${LINUXRELEASE}/zfs_config.h"], [
			zfsobj="${zfssrc}/${LINUXRELEASE}"
		], [test -e "${zfssrc}/zfs_config.h"], [
			zfsobj="${zfssrc}"
		], [test -e "${last_zfs_obj_dir}/zfs_config.h"], [
			zfsobj="${last_zfs_obj_dir}"
		], [
			zfsobj="[Not found]"
		])
	])

	AC_MSG_RESULT([$zfsobj])
	AS_IF([test ! -e "$zfsobj/zfs_config.h"], [
		enable_zfs=no
	])

	#
	# Verify the source version using SPL_META_VERSION in spl_config.h
	#
	AS_IF([test x$enable_zfs = xyes], [
		AC_MSG_CHECKING([zfs source version])
		AS_IF([grep -F -q ZFS_META_VERSION $zfsobj/zfs_config.h], [
			zfsver=$((echo "#include <zfs_config.h>";
			    echo "zfsver=ZFS_META_VERSION-ZFS_META_RELEASE") |
			    cpp -I $zfsobj |
			    grep "^zfsver=" | tr -d \" | cut -d= -f2)
		],[
			zfsver="[Not found]"
			enable_zfs=no
		])
		AC_MSG_RESULT([$zfsver])
	])

	#
	# Verify the modules systems exist by the expect name.
	#
	AS_IF([test x$enable_zfs = xyes], [
		AC_MSG_CHECKING([zfs file name for module symbols])
		AS_IF([test -r $zfsobj/$SYMVERFILE], [
			zfssym=$SYMVERFILE
			EXTRA_SYMBOLS="$EXTRA_SYMBOLS $zfsobj/$SYMVERFILE"
		], [test -r $zfsobj/module/$SYMVERFILE], [
			zfssym=$SYMVERFILE
			EXTRA_SYMBOLS="$EXTRA_SYMBOLS $zfsobj/module/$SYMVERFILE"
		], [
			zfssym="[Not found]"
			enable_zfs=no
		])
		AC_MSG_RESULT([$zfssym])
	])

	AS_IF([test x$enable_zfs = xyes], [
		ZFS=${zfssrc}
		ZFS_OBJ=${zfsobj}
		ZFS_VERSION=${zfsver}

		AC_SUBST(ZFS)
		AC_SUBST(ZFS_OBJ)
		AC_SUBST(ZFS_VERSION)
		AC_SUBST(EXTRA_SYMBOLS)
	])

]) # LB_ZFS

#
# LB_ZFS_DEVEL
#
AC_DEFUN([LB_ZFS_DEVEL], [
	AC_ARG_WITH([zfs-devel],
		[AS_HELP_STRING([--with-zfs-devel=PATH],
		[Path to zfs development headers])],
		[zfsdevel="$withval"])

	AC_MSG_CHECKING([user provided zfs devel headers])
	AS_IF([test ! -z "${zfsdevel}"], [
		AS_IF([test -d "${zfsdevel}/usr/include/libspl" && test -d "${zfsdevel}/usr/include/libzfs"], [
			zfsinc="-I $zfsdevel/usr/include/libspl -I $zfsdevel/usr/include/libzfs"
			zfslib="-L$zfsdevel/usr/lib64 -L$zfsdevel/usr/lib -L$zfsdevel/lib64 -L$zfsdevel/lib"
		], [
			AC_MSG_ERROR([Path to development headers directory does not exist])
		])
	])
	AC_MSG_RESULT([$zfsinc])
]) # LB_ZFS_DEVEL

#
# LB_ZFS_USER
#
AC_DEFUN([LB_ZFS_USER], [
	#
	# Detect user space zfs development headers.
	#
	AC_MSG_CHECKING([zfs devel headers])
	AS_IF([test -z "${zfsinc}"], [
        	AS_IF([test -e "${zfssrc}/include/libzfs.h" && test -e "${zfssrc}/lib/libspl/include"], [
			zfsinc="-I $zfssrc/lib/libspl/include -I $zfssrc/lib/libspl/include/os/linux -I $zfssrc/include"
			zfslib="-L$zfssrc/.libs/ -L$zfssrc/lib/libzfs/.libs/ -L$zfssrc/lib/libnvpair/.libs/ -L$zfssrc/lib/libzpool/.libs/"
		], [test -d /usr/include/libzfs && test -d /usr/include/libspl], [
			zfsinc="-I/usr/include/libspl -I /usr/include/libzfs"
			zfslib=""
		], [
			zfsinc="[Not Found]"
			zfslib=""
			enable_zfs=no
		])
	])
	AC_MSG_RESULT([$zfsinc])

	ZFS_LIBZFS_INCLUDE=${zfsinc}
	ZFS_LIBZFS_LDFLAGS=${zfslib}
	ZFS_LIBZFS_LIBS="-lzfs -lnvpair -lzpool"
	AC_SUBST(ZFS_LIBZFS_INCLUDE)
	AC_SUBST(ZFS_LIBZFS_LDFLAGS)
	AC_SUBST(ZFS_LIBZFS_LIBS)
]) # LB_ZFS_USER

AC_DEFUN([LZ_KABI_ZFS], [
	#
	## LZ_ZFS_NVLIST_CONST_INTERFACES
	#
	# ZFS 2.2.0 nvpair now returns and expects constant args
	#
	AC_DEFUN([LZ_SRC_ZFS_NVLIST_CONST_INTERFACES], [
		LB2_LINUX_TEST_SRC([zfs_nvpair_const], [
			#include <sys/nvpair.h>
		],[
			nvpair_t *nvp = NULL;
			nvlist_t *nvl = NULL;
			const char *name = nvpair_name(nvp);
			nvlist_lookup_string(nvl, name, &name);
			nvlist_lookup_nvlist(nvl, name, &nvl);
		],[-Werror],[],[])
	])
	AC_DEFUN([LZ_ZFS_NVLIST_CONST_INTERFACES], [
		LB2_MSG_LINUX_TEST_RESULT([if ZFS nvlist interfaces require const],
		    [zfs_nvpair_const], [
			AC_DEFINE(HAVE_ZFS_NVLIST_CONST_INTERFACES, 1,
			    [ZFS nvlist interfaces require const])
		])
	]) # LZ_ZFS_NVLIST_CONST_INTERFACES

	#
	## LZ_ZFS_ARC_PRUNE_FUNC_UINT64
	#
	# ZFS 2.2.1 arc_prune_func_t now uses uint64_t for the
	# first parameter
	#
	AC_DEFUN([LZ_SRC_ZFS_ARC_PRUNE_FUNC_UINT64], [
		LB2_LINUX_TEST_SRC([zfs_arc_prune_func_uint64], [
			#include <sys/arc.h>
			static void arc_prune_func(uint64_t bytes, void *priv) {}
		],[
			arc_prune_t *arc_p __attribute__ ((unused)) =
				arc_add_prune_callback(arc_prune_func, NULL);
		],[-Werror],[],[])
	])
	AC_DEFUN([LZ_ZFS_ARC_PRUNE_FUNC_UINT64], [
		LB2_MSG_LINUX_TEST_RESULT([if ZFS arc_prune_func_t uses uint64_t],
		    [zfs_arc_prune_func_uint64], [
			AC_DEFINE(HAVE_ZFS_ARC_PRUNE_FUNC_UINT64, 1,
				[ZFS arc_prune_func_t uses uint64_t])
		])
	]) # LZ_ZFS_ARC_PRUNE_FUNC_UINT64

	#
	## LZ_DMU_BUF_WILL_FILL_3ARGS
	#
	# ZFS 2.2.3:
	#   Adds a boolean_t to dmu_buf_will_fill() and dmu_buf_fill_done()
	#
	# introduced in zfs commit 9b1677fb5a0824b5f4b425c0ee950aaecf252029
	#   dmu: Allow buffer fills to fail
	#
	AC_DEFUN([LZ_SRC_DMU_BUF_WILL_FILL_3ARGS], [
		LB2_LINUX_TEST_SRC([dmu_buf_will_fill_3args], [
			#include <sys/dbuf.h>
		],[
			dmu_buf_t *db = NULL;
			dmu_tx_t *tx = NULL;
			dmu_buf_will_fill(db, tx, B_TRUE);
		],[-Werror],[],[])
	])
	AC_DEFUN([LZ_DMU_BUF_WILL_FILL_3ARGS], [
		LB2_MSG_LINUX_TEST_RESULT([if dmu_buf_will_fill() has 3 args],
		    [dmu_buf_will_fill_3args], [
			AC_DEFINE(HAVE_DMU_BUF_WILL_FILL_3ARGS, 1,
				 [dmu_buf_will_fill() has 3 args])
			AC_DEFINE(LL_BFILL, [, B_FALSE], [buf bool arg])
		],[
			AC_DEFINE(LL_BFILL, [], [buf bool arg])
		])
	]) # LZ_DMU_BUF_WILL_FILL_3ARGS

	AC_DEFUN([LZ_KABI_ZFS_TESTS], [
		LZ_SRC_ZFS_NVLIST_CONST_INTERFACES
		LZ_SRC_ZFS_ARC_PRUNE_FUNC_UINT64
		LZ_SRC_DMU_BUF_WILL_FILL_3ARGS
	])
	AC_DEFUN([LZ_KABI_ZFS_CHECKS], [
		LZ_ZFS_NVLIST_CONST_INTERFACES
		LZ_ZFS_ARC_PRUNE_FUNC_UINT64
		LZ_DMU_BUF_WILL_FILL_3ARGS
	])
])

#
# LB_CONFIG_ZFS
#
AC_DEFUN([LB_CONFIG_ZFS], [
	AC_ARG_WITH([zfs],
		[AS_HELP_STRING([--with-zfs=PATH], [Path to zfs source])],
		[
			AS_IF([test x$withval = xno], [
				enable_zfs=no
				require_zfs=no
			], [test x$withval = xyes], [
				enable_zfs=yes
				require_zfs=yes
			], [
				enable_zfs=yes
				require_zfs=yes
				zfssrc="$withval"
			])
		], [
			AS_IF([test x$enable_server != xno], [
				require_zfs=no
				enable_zfs=yes
			], [
				require_zfs=no
				enable_zfs=no
			])
		])

	AC_MSG_CHECKING([whether to enable zfs])
	AC_MSG_RESULT([$enable_zfs])

	AS_IF([test x$enable_zfs = xyes], [
		AS_IF([test x$enable_modules = xyes], [
			LB_ZFS
		])
		LB_ZFS_DEVEL
		LB_ZFS_USER

		#
		# Define zfs source code version
		#
		ZFS_MAJOR=$(echo $zfsver | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\1/'])
		ZFS_MINOR=$(echo $zfsver | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\2/'])
		ZFS_PATCH=$(echo $zfsver | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\3/'])
		ZFS_FIX=$(echo $zfsver   | sed -re ['s/([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?.*/\5/'])
		AS_IF([test -z "$ZFS_FIX"], [ZFS_FIX="0"])

		AC_DEFINE_UNQUOTED([ZFS_MAJOR], [$ZFS_MAJOR], [zfs major version])
		AC_DEFINE_UNQUOTED([ZFS_MINOR], [$ZFS_MINOR], [zfs minor version])
		AC_DEFINE_UNQUOTED([ZFS_PATCH], [$ZFS_PATCH], [zfs patch version])
		AC_DEFINE_UNQUOTED([ZFS_FIX],   [$ZFS_FIX],   [zfs fix version])

		#
		# enable_zfs will be set to no in LB_ZFS if one of more
		# of the build requirements is not met.
		#
		AS_IF([test x$enable_zfs = xyes], [
			AC_DEFINE(HAVE_ZFS_OSD, 1, Enable zfs osd)
		],[
			AS_IF([test x$require_zfs = xyes], [
				AC_MSG_ERROR([

Required zfs osd cannot be built due to missing zfs development headers.

Support for zfs can be enabled by downloading the required packages for your
distribution.  See http://zfsonlinux.org/ to determine is zfs is supported by
your distribution.
				])
			], [
				AC_MSG_WARN([

Disabling optional zfs osd due to missing development headers.

Support for zfs can be enabled by downloading the required packages for your
distribution.  See http://zfsonlinux.org/ to determine is zfs is supported by
your distribution.
				])
			])
		])
	])
	AS_IF([test "x$enable_zfs" = xyes], [
		AC_SUBST(ENABLE_ZFS, yes)
	], [
		AC_SUBST(ENABLE_ZFS, no)
	])
	AM_CONDITIONAL(ZFS_ENABLED, [test "x$enable_zfs" = xyes])

	#
	# For all versions Lustre supports, SPL is bundled with ZFS.
	#
	# FIXME: The substitutions below are kept empty for the
	# build infrastructure that still references them. They
	# should be removed eventually.
	#
	AC_SUBST(SPL, [])
	AC_SUBST(SPL_OBJ, [])
	AM_CONDITIONAL(SPL_ENABLED, [false])
]) # LB_CONFIG_ZFS

AC_DEFUN([LZ_ZFS_KABI_SERIAL], [
	AC_DEFINE(_KERNEL, 1, [Tell ZFS we are kernel space code])
	LB_CHECK_COMPILE([if zfs defines dsl_pool_config_enter/exit],
	dsl_pool_config_enter, [
		#include <sys/dsl_pool.h>
	],[
		dsl_pool_config_enter(NULL, FTAG);
	],[
		AC_DEFINE(HAVE_DSL_POOL_CONFIG, 1,
			[Have dsl_pool_config_enter/exit in ZFS])
	],[
		AC_MSG_ERROR([dsl_pool_config_enter/exit do not exist])
	])
	LB_CHECK_COMPILE([if zfs defines zio_buf_alloc/free],
	zio_buf_alloc, [
		#include <sys/zio.h>
	],[
		void *ptr = zio_buf_alloc(1024);

		(void)ptr;
	],[
		AC_DEFINE(HAVE_ZIO_BUF_ALLOC, 1,
			[Have zio_buf_alloc/free in ZFS])
	],[
		AC_MSG_ERROR([zio_buf_alloc/free do not exist])
	])
	LB_CHECK_COMPILE([if zfs defines spa_maxblocksize],
	spa_maxblocksize, [
		#include <sys/spa.h>
	],[
		spa_t *spa = NULL;
		int size = spa_maxblocksize(spa);

		(void)size;
	],[
		AC_DEFINE(HAVE_SPA_MAXBLOCKSIZE, 1,
			[Have spa_maxblocksize in ZFS])
	],[
		AC_MSG_ERROR([spa_maxblocksize does not exist])
	])
	LB_CHECK_COMPILE([if zfs defines spa_get_min_alloc_range],
	spa_get_min_alloc_range, [
		#include <sys/spa.h>
	],[
		spa_t *spa = NULL;
		uint64_t min_alloc, max_alloc;

		spa_get_min_alloc_range(spa, &min_alloc, &max_alloc);

		(void)spa;
	],[
		AC_DEFINE(HAVE_SPA_GET_MIN_ALLOC_RANGE, 1,
			[Have spa_get_min_alloc_range in ZFS])
	])
	LB_CHECK_COMPILE([if zfs defines vdev_op_min_alloc],
	vdev_op_min_alloc, [
		#include <sys/vdev_impl.h>
		vdev_ops_t vdev_test_ops = {
			.vdev_op_min_alloc = NULL,
		};
	],[
	],[
		AC_DEFINE(HAVE_VDEV_OP_MIN_ALLOC, 1,
			[Have vdev_op_min_alloc in ZFS])
	])
	#
	# ZFS exports dmu_offet_next
	#
	AC_CACHE_CHECK([if ZFS exports 'dmu_offset_next'],
	[lb_cv_dmu_offset_next], [
	lb_cv_dmu_offset_next="no"
	AS_IF([grep -q -E "EXPORT_SYMBOL.*\(dmu_offset_next\)" "$zfssrc/module/zfs/dmu.c" 2>/dev/null],
		[lb_cv_dmu_offset_next="yes"])
	])
	AS_IF([test "x$lb_cv_dmu_offset_next" = "xyes"], [
		AC_DEFINE(HAVE_DMU_OFFSET_NEXT, 1,
			[Have dmu_offset_next() exported])
	])
	#
	# zfs-2.3.99-237-gf69631992
	# dmu_tx: rename dmu_tx_assign() flags from TXG_* to DMU_TX_*
	# DMU_TX_WAIT define removed and changed to enum
	#
	LB_CHECK_COMPILE([if ZFS has 'DMU_TX_WAIT'],
	dmu_tx_wait_enum, [
		#include <sys/zap.h>
		#include <sys/dnode.h>
		#include <sys/dmu.h>
	],[
		int flag = DMU_TX_WAIT;
		(void) flag;
	],[
		AC_DEFINE([HAVE_DMU_TX_WAIT], 1,
			  [DMU_TX_WAIT exists and define or enum])
	], [
		AC_DEFINE([DMU_TX_WAIT], [TXG_WAIT],
			  [DMU_TX_WAIT does not exist as define or enum])
	])
	#
	# ZFS 2.4
	#
	LB_CHECK_COMPILE([if ZFS has 'dmu_write_by_dnode_flags'],
	dmu_write_by_dnode_flags, [
		#include <sys/zap.h>
		#include <sys/dnode.h>
		#include <sys/dmu.h>
	],[
		dnode_t *dn = NULL;
		dmu_flags_t flags = 0;
		dmu_write_by_dnode(dn, 0, 0, NULL, NULL, flags);
	],[
		AC_DEFINE([HAVE_DMU_WRITE_BY_DNODE_WITH_FLAGS_ARG], 1,
			  [Have dmu_write_by_dnode() with flags in ZFS])
		AC_DEFINE([ll_dmu_write_by_dnode(dn, off, sz, buf, tx, f)],
			  [dmu_write_by_dnode((dn), (off), (sz), (buf), (tx), (f))],
			  [dmu_write_by_dnode has flags])
	], [
		AC_DEFINE([HAVE_DMU_WRITE_BY_DNODE_WITHOUT_FLAGS], 1,
			  [Have dmu_write_by_dnode without flags arg])
		AC_DEFINE([ll_dmu_write_by_dnode(dn, off, sz, buf, tx, f)],
			  [dmu_write_by_dnode((dn), (off), (sz), (buf), (tx))],
			  [dmu_write_by_dnode does not have flags arg])
	])

	LB_CHECK_COMPILE([if ZFS has 'dmu_assign_arcbuf_by_dbuf' with flags],
	dmu_assign_arcbuf_by_dbuf_flags, [
		#include <sys/zap.h>
		#include <sys/dnode.h>
		#include <sys/arc.h>
		#include <sys/dmu.h>
	],[
		dmu_buf_t *h = NULL;
		uint64_t off = 0;
		arc_buf_t *buf = NULL;
		dmu_tx_t *tx = NULL;
		dmu_flags_t flags = 0;
		(void)dmu_assign_arcbuf_by_dbuf(h, off, buf, tx, flags);
	],[
		AC_DEFINE([HAVE_DMU_ASSIGN_ARCBUF_BY_DBUF_WITH_FLAGS], 1,
			  [Have dmu_assign_arcbuf_by_dbuf() with flags])
		AC_DEFINE([ll_dmu_assign_arcbuf_by_dbuf(h, off, buf, tx, f)],
			  [dmu_assign_arcbuf_by_dbuf((h), (off), (buf), (tx), (f))],
			  [dmu_assign_arcbuf_by_dbuf has flags])
	], [
		AC_DEFINE([HAVE_DMU_ASSIGN_ARCBUF_BY_DBUF_WITHOUT_FLAGS], 1,
			  [Have dmu_assign_arcbuf_by_dbuf() does not have flags])
		AC_DEFINE([ll_dmu_assign_arcbuf_by_dbuf(h, off, buf, tx, f)],
			  [dmu_assign_arcbuf_by_dbuf((h), (off), (buf), (tx))],
			  [dmu_assign_arcbuf_by_dbuf does not have flags arg])
	])
	#
	# zfs-2.4.0 commit 5847626175
	# Pass flags to dmu_buf_hold_array_by_bonus()
	#
	# <  zfs-2.4.0, No flags arg:
	# 	dmu_buf_hold_array_by_bonus() has 7 args
	#
	# >= zfs-2.4.0, Added dmu_flags_t arg:
	# 	dmu_buf_hold_array_by_bonus() has 8 args
	LB_CHECK_COMPILE([if ZFS has 'dmu_buf_hold_array_by_bonus has flags'],
	dmu_write_hold_flags, [
		#include <sys/zap.h>
		#include <sys/dnode.h>
		#include <sys/dmu.h>
	],[
		dmu_buf_t *h = NULL;
		dmu_buf_t ***dbpp = NULL;
		int numbufsp = 0;
		(void) dmu_buf_hold_array_by_bonus(h, 0, 0, true, NULL, &numbufsp, dbpp, 0);
	],[
		AC_DEFINE([HAVE_DMU_HOLD_ARRAY_BY_BONUS_FLAGS], 1,
			  [dmu_buf_hold_array_by_bonus has flags])
		AC_DEFINE([ll_dmu_buf_hold_array_by_bonus(db, offset, len, read, tag, numbufsp, dbpp, flags)],
			  [dmu_buf_hold_array_by_bonus((db), (offset), (len), (read), (tag), (numbufsp), (dbpp), (flags))],
			  [dmu_buf_hold_array_by_bonus has 8 args])
	],[
		AC_DEFINE([HAVE_DMU_HOLD_ARRAY_BY_BONUS_NOFLAGS], 1,
			  [dmu_buf_hold_array_by_bonus has no flags])
		AC_DEFINE([ll_dmu_buf_hold_array_by_bonus(db, offset, len, read, tag, numbufsp, dbpp, flags)],
			  [dmu_buf_hold_array_by_bonus((db), (offset), (len), (read), (tag), (numbufsp), (dbpp))],
			  [dmu_buf_hold_array_by_bonus has 7 args])
	])
])
