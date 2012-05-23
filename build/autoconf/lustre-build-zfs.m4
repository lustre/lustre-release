#
# LB_PATH_SPL
#
# --with-spl      - Enable spl support and attempt to autodetect the spl
# --with-spl=yes    headers in one of the following places in this order:
#                   * ./spl
#                   * /usr/src/spl-*/$LINUXRELEASE
#                   * ../spl
#
# --with-spl=path - Enable spl support and use the spl headers in the
#                   provided path.  No autodetection is performed.
#
# --with-spl-obj  - When spl support is enabled the object directory
#                   will be based on the --with-spl directory.  If this
#                   is detected incorrectly it can be explicitly
#                   specified using this option.
#
# NOTE: As with all external packages spl is expected to already be
# configured and built.  However, if the spl tree is located in-tree
# (./spl) then it will be configured and built recursively as part of
# the lustre build system.
#
AC_DEFUN([LB_PATH_SPL],
[
AC_ARG_WITH([spl],
	AC_HELP_STRING([--with-spl=path], [set path to spl sources]),
	[],[
		if test x$enable_server = xyes && test x$enable_dist = xno; then
			with_spl='yes'
		else
			with_spl='no'
		fi
	])

case x$with_spl in
	xno)
		AC_MSG_ERROR([spl must be enabled when building zfs.])
		;;
	xyes)
		SPL_DIR=

		# Check ./spl
		spl_src=$PWD/spl
		if test -e "$spl_src"; then
			SPL_DIR=$(readlink -f $spl_src)
		else
			# Check /usr/src/spl-*/$LINUXRELEASE
			spl_src=$(ls -1d /usr/src/spl-*/$LINUXRELEASE \
			          2>/dev/null | tail -1)
			if test -e "$spl_src"; then
				SPL_DIR=$(readlink -f $spl_src)
			else
				# Check ../spl
				spl_src=$PWD/../spl
				if test -e "$spl_src"; then
					SPL_DIR=$(readlink -f $spl_src)
				else
					# Fatal spl required for zfs builds
					AC_MSG_ERROR([Could not locate spl.])
				fi
			fi
		fi

		;;
	*)
		SPL_DIR=$(readlink -f $with_spl)
		with_spl='yes'
		;;
esac

AC_ARG_WITH([spl-obj],
	AC_HELP_STRING([--with-spl-obj=path], [set path to spl objects]),
	[
		if test x$with_spl = xyes; then
			SPL_OBJ="$withval"
		fi
	],[
		if test x$with_spl = xyes; then
			SPL_OBJ=$SPL_DIR
		fi
	])

AC_MSG_CHECKING([spl source directory])
AC_MSG_RESULT([$SPL_DIR])
AC_SUBST(SPL_DIR)

AC_MSG_CHECKING([spl object directory])
AC_MSG_RESULT([$SPL_OBJ])
AC_SUBST(SPL_OBJ)

LB_SPL_SYMVERS
LB_SPL_RELEASE
])

#
# LB_SPL_BUILD
#
# Optionally configure/make the spl sources.  If the sources are
# determined to reside in-tree this feature will automatically be
# enabled.  If the sources are not in-tree it will be disabled.
# Use --enable-spl-build or --disable-spl-build if you need to
# override this behavior.
#
AC_DEFUN([LB_SPL_BUILD],
[
AC_ARG_ENABLE([spl-build],
	AC_HELP_STRING([--enable-spl-build], [enable spl configure/make]),
	[], [
		SPL_DIR_INTREE=$(readlink -f $PWD/spl)
		if test x$SPL_DIR = x$SPL_DIR_INTREE; then
			enable_spl_build='yes'
		else
			enable_spl_build='no'
		fi
	])

AC_MSG_CHECKING([whether to build spl])
if test x$enable_spl_build = xyes; then
	AC_MSG_RESULT([$enable_spl_build])

	LB_CHECK_FILE([$SPL_DIR/module/spl/spl-generic.c], [], [
		AC_MSG_ERROR([Complete spl source must exist when building.])])

	LB_CHECK_FILE([$SPL_DIR/configure], [], [
		AC_MSG_ERROR([Complete spl source must exist when building.])])

	SPL_SUBDIR="$SPL_DIR"
	AC_SUBST(SPL_SUBDIR)
	AC_CONFIG_SUBDIRS("spl")
else
	enable_spl_build='no'
	AC_MSG_RESULT([$enable_spl_build])
fi
])

#
# LB_SPL_SYMVERS
#
AC_DEFUN([LB_SPL_SYMVERS],
[
AC_MSG_CHECKING([spl module symbols])
if test -r $SPL_OBJ/Module.symvers; then
	SPL_SYMBOLS=Module.symvers
elif test -r $SPL_OBJ/Modules.symvers; then
	SPL_SYMBOLS=Modules.symvers
elif test -r $SPL_OBJ/module/Module.symvers; then
	SPL_SYMBOLS=Module.symvers
elif test -r $SPL_OBJ/module/Modules.symvers; then
	SPL_SYMBOLS=Modules.symvers
else
	SPL_SYMBOLS=$SYMVERFILE
fi

AC_MSG_RESULT([$SPL_SYMBOLS])
AC_SUBST(SPL_SYMBOLS)
])

#
# LB_SPL_RELEASE
#
AC_DEFUN([LB_SPL_RELEASE],
[
AC_MSG_CHECKING([spl source release])
if test -r $SPL_OBJ/spl_config.h; then
	tmp_flags="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="-I$SPL_DIR $EXTRA_KCFLAGS"
	LB_LINUX_TRY_MAKE([
		#include <$SPL_OBJ/spl_config.h>
	],[
		char *SPL_RELEASE;
		SPL_RELEASE=SPL_META_VERSION;
	],[
		$makerule LUSTRE_KERNEL_TEST=conftest.i
	],[
		test -s build/conftest.i
	],[
		eval $(grep "SPL_RELEASE=" build/conftest.i)
	],[
		AC_MSG_RESULT([unknown])
		AC_MSG_ERROR([Could not preprocess test program.])
	])
	EXTRA_KCFLAGS="$tmp_flags"
	rm build/conftest.i
elif test -r $SPL_DIR/META; then
	SPL_RELEASE=$(awk '/Version/ { print [$]2 }' $SPL_DIR/META)
else
	AC_MSG_RESULT([unknown])
	AC_MSG_ERROR([Could not locate spl_config.h or META to check release.])
fi

if test x$SPL_RELEASE = x; then
	AC_MSG_RESULT([unknown])
	AC_MSG_ERROR([Could not determine spl release.])
fi

AC_MSG_RESULT([$SPL_RELEASE])
AC_SUBST(SPL_RELEASE)
])


#
# LB_PATH_ZFS
#
# --without-zfs   - Disable zfs support.
# --with-zfs=no
#
# --with-zfs      - Enable zfs support and attempt to autodetect the zfs
# --with-zfs=yes    headers in one of the following places in this order:
#                   * ./zfs
#                   * /usr/src/zfs-*/$LINUXRELEASE
#                   * ../zfs
#
# --with-zfs=path - Enable zfs support and use the zfs headers in the
#                   provided path.  No autodetection is performed.
#
# --with-zfs-obj  - When zfs support is enabled the object directory
#                   will be based on the --with-zfs directory.  If this
#                   is detected incorrectly it can be explicitly
#                   specified using this option.
#
# NOTE: As with all external packages zfs is expected to already be
# configured and built.  However, if the zfs tree is located in-tree
# (./zfs) then it will be configured and built recursively as part of
# the lustre build system.
#
AC_DEFUN([LB_PATH_ZFS],
[
AC_ARG_WITH([zfs],
	AC_HELP_STRING([--with-zfs=path], [set path to zfs sources]),
	[],[
		if test x$enable_server = xyes && test x$enable_dist = xno; then
			with_zfs='yes'
		else
			with_zfs='no'
		fi
	])

case x$with_zfs in
	xno)
		ZFS_DIR=
		;;
	xyes)
		ZFS_DIR=

		# Check ./zfs
		zfs_src=$PWD/zfs
		if test -e "$zfs_src"; then
			ZFS_DIR=$(readlink -f $zfs_src)
		else
			# Check /usr/src/zfs-*/$LINUXRELEASE
			zfs_src=$(ls -1d /usr/src/zfs-*/$LINUXRELEASE \
				2>/dev/null|tail -1)
			if test -e "$zfs_src"; then
				ZFS_DIR=$(readlink -f $zfs_src)
			else
				# Check ../zfs
				zfs_src=$PWD/../zfs
				if test -e "$zfs_src"; then
					ZFS_DIR=$(readlink -f $zfs_src)
				else
					# Disable zfs failed to detect sources
					with_zfs='no'
				fi
			fi
		fi

		;;
	*)
		ZFS_DIR=$(readlink -f $with_zfs)
		with_zfs='yes'
		;;
esac

AC_MSG_CHECKING([whether to enable zfs])
AC_MSG_RESULT([$with_zfs])

AC_ARG_WITH([zfs-obj],
	AC_HELP_STRING([--with-zfs-obj=path], [set path to zfs objects]),
	[
		if test x$with_zfs = xyes; then
			ZFS_OBJ="$withval"
		fi
	],[
		if test x$with_zfs = xyes; then
			ZFS_OBJ=$ZFS_DIR
		fi
	])

if test x$with_zfs = xyes; then
	LB_ZFS_DEFINE_OPTIONS

	AC_MSG_CHECKING([zfs source directory])
	AC_MSG_RESULT([$ZFS_DIR])
	AC_SUBST(ZFS_DIR)

	AC_MSG_CHECKING([zfs object directory])
	AC_MSG_RESULT([$ZFS_OBJ])
	AC_SUBST(ZFS_OBJ)

	LB_ZFS_SYMVERS
	LB_ZFS_RELEASE

	LB_PATH_SPL

	LB_SPL_BUILD
	LB_ZFS_BUILD

fi

AM_CONDITIONAL(SPL_BUILD, test x$enable_spl_build = xyes)
AM_CONDITIONAL(ZFS_BUILD, test x$enable_zfs_build = xyes)
AM_CONDITIONAL(ZFS_ENABLED, test x$with_zfs = xyes)
])

#
# LB_ZFS_BUILD
#
# Optionally configure/make the zfs sources.  If the sources are
# determined to reside in-tree this feature will automatically be
# enabled.  If the sources are not in-tree it will be disabled.
# Use --enable-zfs-build or --disable-zfs-build if you need to
# override this behavior.
#
AC_DEFUN([LB_ZFS_BUILD],
[
AC_ARG_ENABLE([zfs-build],
	AC_HELP_STRING([--enable-zfs-build], [enable zfs configure/make]),
	[], [
		ZFS_DIR_INTREE=$(readlink -f $PWD/zfs)
		if test x$ZFS_DIR = x$ZFS_DIR_INTREE; then
			enable_zfs_build='yes'
		else
			enable_zfs_build='no'
		fi
	])

AC_MSG_CHECKING([whether to build zfs])
if test x$enable_zfs_build = xyes; then
	AC_MSG_RESULT([$enable_zfs_build])

	LB_CHECK_FILE([$ZFS_DIR/module/zfs/dmu.c], [], [
		AC_MSG_ERROR([Complete zfs sources must exist when building.])])

	LB_CHECK_FILE([$ZFS_DIR/configure], [], [
		AC_MSG_ERROR([Complete zfs sources must exist when building.])])

	ZFS_SUBDIR="$ZFS_DIR"
	AC_SUBST(ZFS_SUBDIR)
	AC_CONFIG_SUBDIRS("zfs")

	ac_configure_args="$ac_configure_args --with-spl=$SPL_DIR"
	ac_configure_args="$ac_configure_args --with-spl-obj=$SPL_OBJ"
else
	enable_zfs_build='no'
	AC_MSG_RESULT([$enable_zfs_build])
fi
])

#
# LB_ZFS_SYMVERS
#
AC_DEFUN([LB_ZFS_SYMVERS],
[
AC_MSG_CHECKING([zfs module symbols])
if test -r $ZFS_OBJ/Module.symvers; then
	ZFS_SYMBOLS=Module.symvers
elif test -r $ZFS_OBJ/Modules.symvers; then
	ZFS_SYMBOLS=Modules.symvers
elif test -r $ZFS_OBJ/module/Module.symvers; then
	ZFS_SYMBOLS=Module.symvers
elif test -r $ZFS_OBJ/module/Modules.symvers; then
	ZFS_SYMBOLS=Modules.symvers
else
	ZFS_SYMBOLS=$SYMVERFILE
fi

AC_MSG_RESULT([$ZFS_SYMBOLS])
AC_SUBST(ZFS_SYMBOLS)
])

#
# LB_ZFS_RELEASE
#
AC_DEFUN([LB_ZFS_RELEASE],
[
AC_MSG_CHECKING([zfs source release])
if test -r $ZFS_OBJ/zfs_config.h; then
	tmp_flags="$EXTRA_KCFLAGS"
	EXTRA_KCFLAGS="-I$ZFS_DIR $EXTRA_KCFLAGS"
	LB_LINUX_TRY_MAKE([
		#include <$ZFS_OBJ/zfs_config.h>
	],[
		char *ZFS_RELEASE;
		ZFS_RELEASE=ZFS_META_VERSION;
	],[
		$makerule LUSTRE_KERNEL_TEST=conftest.i
	],[
		test -s build/conftest.i
	],[
		eval $(grep "ZFS_RELEASE=" build/conftest.i)
	],[
		AC_MSG_RESULT([unknown])
		AC_MSG_ERROR([Could not preprocess test program.])
	])
	EXTRA_KCFLAGS="$tmp_flags"
	rm build/conftest.i
elif test -r $ZFS_DIR/META; then
	ZFS_RELEASE=$(awk '/Version/ { print [$]2 }' $ZFS_DIR/META)
else
	AC_MSG_RESULT([unknown])
	AC_MSG_ERROR([Could not locate zfs_config.h or META to check release.])
fi

if test x$ZFS_RELEASE = x; then
	AC_MSG_RESULT([unknown])
	AC_MSG_ERROR([Could not determine zfs release.])
fi

AC_MSG_RESULT([$ZFS_RELEASE])
AC_SUBST(ZFS_RELEASE)
])

#
# LB_ZFS_DEFINE_OPTIONS
#
AC_DEFUN([LB_ZFS_DEFINE_OPTIONS],
[
AC_DEFINE(HAVE_ZFS_OSD, 1, Enable zfs osd)
])
