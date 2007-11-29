
AC_INIT([Lustre], [LUSTRE_VERSION], [https://bugzilla.lustre.org/], [lustre])
sinclude(lustre/autoconf/lustre-version.ac)

# Overridden in LB_PATH_LDISKFS on certain branches
AM_CONDITIONAL(LDISKFS_ENABLED, false)

LB_CHECK_VERSION

LC_CONFIG_SRCDIR

AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE
# AM_MAINTAINER_MODE

AC_PROG_CC

LB_CONFIGURE
