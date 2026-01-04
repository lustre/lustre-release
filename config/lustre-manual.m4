# SPDX-License-Identifier: GPL-2.0

#
# This file is part of Lustre, http://www.lustre.org/
#
# config/lustre-manual.m4
#
# Configure options for building the Lustre Operations Manual
#

#
# LB_CONFIG_MANUAL
#
# Check for --with-manual and required dependencies
#
AC_DEFUN([LB_CONFIG_MANUAL], [
AC_MSG_CHECKING([whether to build Lustre manual])
AC_ARG_WITH([manual],
	AS_HELP_STRING([--with-manual],
		[build Lustre Operations Manual (requires DocBook toolchain and pandoc)]),
	[], [with_manual="no"])
AC_MSG_RESULT([$with_manual])

AS_IF([test "x$with_manual" = xyes], [
	# Check for xmllint (XML validation)
	AC_PATH_PROG([XMLLINT], [xmllint])
	AS_IF([test -z "$XMLLINT"], [
		AC_MSG_ERROR([xmllint is required for building the manual. Install libxml2-utils (Debian/Ubuntu) or libxml2 (RHEL/CentOS).])
	])

	# Check for xsltproc (XSLT processing)
	AC_PATH_PROG([XSLTPROC], [xsltproc])
	AS_IF([test -z "$XSLTPROC"], [
		AC_MSG_ERROR([xsltproc is required for building the manual. Install xsltproc (Debian/Ubuntu) or libxslt (RHEL/CentOS).])
	])

	# Check for fop (PDF generation)
	AC_PATH_PROG([FOP], [fop])
	AS_IF([test -z "$FOP"], [
		AC_MSG_ERROR([fop is required for building the manual PDF. Install fop package.])
	])

	# Check for pandoc (Markdown generation)
	AC_PATH_PROG([PANDOC], [pandoc])
	AS_IF([test -z "$PANDOC"], [
		AC_MSG_ERROR([pandoc is required for building the manual Markdown output. Install pandoc package.])
	])

	# Check for DocBook 5 RNG schema
	AC_MSG_CHECKING([for DocBook 5 RNG schema])
	DOCBOOK_RNG=""
	for rng_path in \
		/usr/share/xml/docbook/schema/rng/5.0/docbookxi.rng \
		/usr/share/xml/docbook5/schema/rng/5.0/docbookxi.rng \
		/usr/local/opt/docbook/docbook/xml/5.0/rng/docbookxi.rng \
		/opt/local/share/xml/docbook/5.0/rng/docbookxi.rng; do
		AS_IF([test -f "$rng_path"], [
			DOCBOOK_RNG="$rng_path"
			break
		])
	done
	AS_IF([test -z "$DOCBOOK_RNG"], [
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([DocBook 5 RNG schema not found. Install docbook5-xml (Debian/Ubuntu) or docbook5-schemas (RHEL/CentOS).])
	], [
		AC_MSG_RESULT([$DOCBOOK_RNG])
	])
	AC_SUBST(DOCBOOK_RNG)

	# Check for DocBook XSL-NS stylesheets
	AC_MSG_CHECKING([for DocBook XSL-NS stylesheets])
	DOCBOOK_XSL=""
	for xsl_path in \
		/usr/share/xml/docbook/stylesheet/docbook-xsl-ns \
		/usr/share/sgml/docbook/xsl-ns-stylesheets-1.75.2 \
		/usr/share/sgml/docbook/xsl-ns-stylesheets \
		/usr/share/xml/docbook/stylesheet/nwalsh5/current \
		/usr/local/opt/docbook-xsl/docbook-xsl \
		/opt/local/share/xsl/docbook-xsl \
		/opt/local/share/xsl/docbook-xsl-nons; do
		AS_IF([test -d "$xsl_path"], [
			DOCBOOK_XSL="$xsl_path"
			break
		])
	done
	AS_IF([test -z "$DOCBOOK_XSL"], [
		AC_MSG_RESULT([not found])
		AC_MSG_ERROR([DocBook XSL-NS stylesheets not found. Install docbook-xsl-ns (Debian/Ubuntu) or docbook-style-xsl (RHEL/CentOS).])
	], [
		AC_MSG_RESULT([$DOCBOOK_XSL])
	])
	AC_SUBST(DOCBOOK_XSL)

	MANUAL_SUBDIR="docs/manual"
], [
	MANUAL_SUBDIR=""
])

AC_SUBST(MANUAL_SUBDIR)
AM_CONDITIONAL([BUILD_MANUAL], [test "x$with_manual" = xyes])
]) # LB_CONFIG_MANUAL
