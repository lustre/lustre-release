AC_PREFIX_DEFAULT([])
if test "x$prefix" = xNONE || test "x$prefix" = x; then
  usrprefix=/usr
else
  usrprefix='${prefix}'
fi
AC_SUBST(usrprefix)

AC_ARG_ENABLE(rtscts-myrinet, [ --enable-rtscts-myrinet enable rtscts over myrinet support])
AM_CONDITIONAL(RTSCTS_MYRINET, test "$enable_rtscts_myrinet" = yes)


CPLANT_ARCH=${target_cpu}
case ${CPLANT_ARCH} in
alpha*)
  RTSCTSLIB_CFLAGS='-O4 -mno-fp-regs'
  RTSCTSLIB_DEFS=-Ddec_linux
  ;;
i*86)
  RTSCTSLIB_CFLAGS=-O4
  RTSCTSLIB_DEFS=-Dintel_linux
  ;;
#*)
#  AC_MSG_ERROR([Unrecognized architecture '$CPLANT_ARCH' for rtscts])
#  ;;
esac
AC_SUBST(CPLANT_ARCH)
AC_SUBST(RTSCTSLIB_CFLAGS)
AC_SUBST(RTSCTSLIB_DEFS)

AC_MSG_CHECKING(if kernel has CPU affinity support)
if test "$target_cpu" != ia64 ; then
  enable_affinity_temp="-DCPU_AFFINITY=1"
  AC_MSG_RESULT(yes)
else
  enable_affinity_temp=""
  AC_MSG_RESULT(no)
fi
AC_MSG_CHECKING(if kernel has zero-copy TCP support)
ZCCD="`grep -c zccd $LINUX/include/linux/skbuff.h`"
if test "$ZCCD" != 0 ; then
  enable_zerocopy_temp="-DSOCKNAL_ZC=1"
  AC_MSG_RESULT(yes)
else
  enable_zerocopy_temp=""
  AC_MSG_RESULT(no)
fi

AC_ARG_ENABLE(zerocopy, [  --enable-zerocopy enable socknal zerocopy],enable_zerocopy="-DSOCKNAL_ZC=1", enable_zercopy=$enable_zerocopy_temp)

AC_ARG_ENABLE(affinity, [  --enable-affinity enable process/irq affinity],enable_affinity="-DCPU_AFFINITY=1", enable_affinity=$enable_affinity_temp)
#####################################

AC_MSG_CHECKING(if quadrics kernel headers are present)
if test -d $LINUX/drivers/net/qsnet ; then
  AC_MSG_RESULT(yes)
  QSWNAL="qswnal"
  with_quadrics="-I$LINUX/drivers/net/qsnet/include"
  :
elif test -d $LINUX/drivers/qsnet1 ; then
  AC_MSG_RESULT(yes)
  QSWNAL="qswnal"
  with_quadrics="-I$LINUX/drivers/qsnet1/include -DPROPRIETARY_ELAN"
  :
elif test -d $LINUX/drivers/quadrics ; then
  AC_MSG_RESULT(yes)
  QSWNAL="qswnal"
  with_quadrics="-I$LINUX/drivers/quadrics/include -DPROPRIETARY_ELAN"
  :
#elif test -d /usr/include/elan3 ; then
#  AC_MSG_RESULT(yes)
#  QSWNAL="qswnal"
#  with_quadrics=""
#  :
else
  AC_MSG_RESULT(no)
  QSWNAL=""
  with_quadrics=""
  :
fi
AC_SUBST(with_quadrics)
AC_SUBST(QSWNAL)

# R. Read 5/02
GMNAL=""
echo "checking with-gm=" ${with_gm}
if test "${with_gm+set}" = set; then
  if test "${with_gm}" = yes; then
    with_gm="-I/usr/local/gm/include"
  else
    with_gm=-I"$with_gm/include"
  fi
  GMNAL="gmnal"
else
# default case - no GM
  with_gm=""
fi
AC_SUBST(with_gm)
AC_SUBST(GMNAL)


def_scamac=/opt/scali/include
AC_ARG_WITH(scamac, [  --with-scamac=[yes/no/path] Path to ScaMAC includes (default=/opt/scali/include)], with_scamac=$withval, with_scamac=$def_scamac)
AC_MSG_CHECKING(if ScaMAC headers are present)
if test "$with_scamac" = yes; then
  with_scamac=$def_scamac
fi
if test "$with_scamac" != no -a -f ${with_scamac}/scamac.h; then
  AC_MSG_RESULT(yes)
  SCIMACNAL="scimacnal"
  with_scamac="-I${with_scamac} -I${with_scamac}/icm"
else
  AC_MSG_RESULT(no)
  SCIMACNAL=""
  with_scamac=""
fi
AC_SUBST(with_scamac)
AC_SUBST(SCIMACNAL)
