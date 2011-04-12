dnl -*- mode: m4; -*-

AC_PREREQ(2.60)

define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [12])
define([PACKAGE_VERSION_FIX], [1])
define([PACKAGE_SUFFIX], [-svn])

AC_INIT([opensc],[PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign 1.10)

OPENSC_VERSION_MAJOR="PACKAGE_VERSION_MAJOR"
OPENSC_VERSION_MINOR="PACKAGE_VERSION_MINOR"
OPENSC_VERSION_FIX="PACKAGE_VERSION_FIX"

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:                      REVISION++)
#   (Oldest interface removed:          OLDEST++)
#   (Interfaces added:                  CURRENT++, REVISION=0)
OPENSC_LT_CURRENT="3"
OPENSC_LT_OLDEST="3"
OPENSC_LT_REVISION="0"
OPENSC_LT_AGE="0"
OPENSC_LT_AGE="$((${OPENSC_LT_CURRENT}-${OPENSC_LT_OLDEST}))"

AC_CONFIG_SRCDIR([src/libopensc/sc.c])

AC_CANONICAL_HOST
AC_PROG_CC
PKG_PROG_PKG_CONFIG
AC_C_BIGENDIAN

AC_ARG_WITH(
	[cygwin-native],
	[AS_HELP_STRING([--with-cygwin-native],[compile native win32])],
	,
	[with_cygwin_native="no"]
)

dnl Check for some target-specific stuff
test -z "${WIN32}" && WIN32="no"
test -z "${CYGWIN}" && CYGWIN="no"
case "${host}" in
	*-*-solaris*)
		CPPFLAGS="${CPPFLAGS} -I/usr/local/include"
		LDFLAGS="${LDFLAGS} -L/usr/local/lib -R/usr/local/lib"
	;;
	*-mingw*|*-winnt*)
		WIN32="yes"
		CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
		WIN_LIBPREFIX="lib"
	;;
	*-cygwin*)
		AC_MSG_CHECKING([cygwin mode to use])
		CYGWIN="yes"
		if test "${with_cygwin_native}" = "yes"; then
			AC_MSG_RESULT([Using native win32])
			CPPFLAGS="${CPPFLAGS} -DWIN32_LEAN_AND_MEAN"
			CFLAGS="${CFLAGS} -mno-cygwin"
			WIN32="yes"
		else
			AC_MSG_RESULT([Using cygwin])
			CPPFLAGS="${CPPFLAGS} -DCRYPTOKI_FORCE_WIN32"
			WIN_LIBPREFIX="cyg"
			AC_DEFINE([USE_CYGWIN], [1], [Define if you are on Cygwin])
		fi
	;;
esac

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--enable-strict],[enable strict compile mode @<:@disabled@:>@])],
	,
	[enable_strict="no"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic],[enable pedantic compile mode @<:@disabled@:>@])],
	,
	[enable_pedantic="no"]
)

AC_ARG_ENABLE(
	[zlib],
	[AS_HELP_STRING([--enable-zlib],[enable zlib linkage @<:@detect@:>@])],
	,
	[enable_zlib="detect"]
)

AC_ARG_ENABLE(
	[readline],
	[AS_HELP_STRING([--enable-readline],[enable readline linkage @<:@detect@:>@])],
	,
	[enable_readline="detect"]
)

AC_ARG_ENABLE(
	[openssl],
	[AS_HELP_STRING([--enable-openssl],[enable openssl linkage @<:@detect@:>@])],
	,
	[enable_openssl="detect"]
)

AC_ARG_ENABLE(
	[openct],
	[AS_HELP_STRING([--enable-openct],[enable openct linkage @<:@disabled@:>@])],
	,
	[enable_openct="no"]
)

AC_ARG_ENABLE(
	[pcsc],
	[AS_HELP_STRING([--disable-pcsc],[disable pcsc support @<:@enabled@:>@])],
	,
	[enable_pcsc="yes"]
)

AC_ARG_ENABLE(
	[ctapi],
	[AS_HELP_STRING([--enable-ctapi],[enable CT-API support @<:@disabled@:>@])],
	,
	[enable_ctapi="no"]
)

AC_ARG_ENABLE(
	[minidriver],
	[AS_HELP_STRING([--enable-minidriver],[enable minidriver on Windows @<:@disabled@:>@])],
	,
	[enable_minidriver="no"]
)

AC_ARG_ENABLE(
	[man],
	[AS_HELP_STRING([--disable-man],[disable installation of manuals @<:@enabled for none Windows@:>@])],
	,
	[enable_man="detect"]
)

AC_ARG_ENABLE(
	[doc],
	[AS_HELP_STRING([--enable-doc],[enable installation of documents @<:@disabled@:>@])],
	,
	[enable_doc="no"]
)

AC_ARG_WITH(
	[xsl-stylesheetsdir],
	[AS_HELP_STRING([--with-xsl-stylesheetsdir=PATH],[docbook xsl-stylesheets for svn build @<:@detect@:>@])],
	[xslstylesheetsdir="${withval}"],
	[xslstylesheetsdir="detect"]
)

AC_ARG_WITH(
	[pcsc-provider],
	[AS_HELP_STRING([--with-pcsc-provider=PATH],[Path to system pcsc provider @<:@system default@:>@])],
	,
	[with_pcsc_provider="detect"]
)
dnl ./configure check
reader_count=""
for rdriver in "${enable_pcsc}" "${enable_openct}" "${enable_ctapi}"; do
	test "${rdriver}" = "yes" && reader_count="${reader_count}x"
done
if test "${reader_count}" != "x"; then
	AC_MSG_ERROR([Only one of --enable-pcsc, --enable-openct, --enable-ctapi can be specified!])
fi
	 
dnl Checks for programs.
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P
AC_PROG_SED
AC_PROG_MAKE_SET

dnl Add libtool support.
ifdef(
	[LT_INIT],
	[
		LT_INIT([win32-dll])
		LT_LANG([Windows Resource])
	],
	[
		AC_LIBTOOL_WIN32_DLL
		AC_LIBTOOL_RC
		AC_PROG_LIBTOOL
	]
)

dnl These required for svn checkout
AC_ARG_VAR([SVN], [subversion utility])
AC_ARG_VAR([XSLTPROC], [xsltproc utility])
AC_CHECK_PROGS([SVN],[svn])
AC_CHECK_PROGS([XSLTPROC],[xsltproc])

AC_MSG_CHECKING([xsl-stylesheets])
if test "${xslstylesheetsdir}" = "detect"; then
	xslstylesheetsdir="no"
	for f in \
		/usr/share/xml/docbook/stylesheet/nwalsh \
		/usr/share/xml/docbook/stylesheet/nwalsh/current \
		/opt/local/share/xsl/docbook-xsl \
		/sw/share/xml/xsl/docbook-xsl \
		/usr/share/sgml/docbook/*; do

		test -e "${f}/html/docbook.xsl" && xslstylesheetsdir="${f}"
	done
elif test "${xslstylesheetsdir}" != "no"; then
	test -e "${xslstylesheetsdir}/html/docbook.xsl" || AC_MSG_ERROR([invalid])
fi
AC_MSG_RESULT([${xslstylesheetsdir}])

dnl C Compiler features
AC_C_INLINE

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_HEADER_ASSERT
AC_CHECK_HEADERS([ \
	errno.h fcntl.h malloc.h stdlib.h \
	inttypes.h string.h strings.h \
	sys/time.h unistd.h getopt.h sys/mman.h
])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([ \
	getpass gettimeofday memset mkdir \
	strdup strerror getopt_long getopt_long_only \
	strlcpy strlcat
])
AC_CHECK_SIZEOF(void *)
if test "${ac_cv_sizeof_void_p}" = 8; then
	LIBRARY_BITNESS="64"
else
	LIBRARY_BITNESS="32"
fi

dnl See if socket() is found from libsocket
AC_CHECK_LIB(
	[socket],
	[socket],
	[
		LIBS="${LIBS} -lsocket"
		AC_CHECK_LIB(
			[resolv],
			[res_query],
			[LIBS="${LIBS} -lresolv"]
		)
	]
)

dnl check for libltdl. If libltdl is not found, native dlopen/LoadLibrary is used
AC_ARG_VAR([LTLIB_CFLAGS], [C compiler flags for libltdl])
AC_ARG_VAR([LTLIB_LIBS], [linker flags for libltdl])
if test -z "${LTLIB_LIBS}"; then
	AC_CHECK_LIB(
		[ltdl],
		[lt_dlopen],
		[LTLIB_LIBS="-lltdl"]
	)
fi

saved_CFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} ${LTLIB_CFLAGS}"
AC_CHECK_HEADERS([ltdl.h])
CFLAGS="${saved_CFLAGS}"

if test "${WIN32}" = "no"; then
	dnl Special check for pthread support.
	ACX_PTHREAD(
		[AC_DEFINE(
			[HAVE_PTHREAD],
			[1],
			[Define if you have POSIX threads libraries and header files.]
		)],
		[AC_MSG_ERROR([POSIX thread support required])]
	)
	CC="${PTHREAD_CC}"
fi

if test "${enable_minidriver}" = "yes"; then
	dnl win32 special test for minidriver
	AC_CHECK_HEADER(
		[cardmod.h],
		,
		[AC_MSG_ERROR([cardmod.h is not found and required for minidriver])]
	)
	AC_DEFINE([ENABLE_MINIDRIVER], [1], [Enable minidriver support])
fi

AC_ARG_VAR([ZLIB_CFLAGS], [C compiler flags for zlib])
AC_ARG_VAR([ZLIB_LIBS], [linker flags for zlib])
if test -z "${ZLIB_LIBS}"; then
	AC_CHECK_LIB(
		[z],
		[inflate],
		[ZLIB_LIBS="-lz"]
	)
fi
saved_CFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} ${ZLIB_CFLAGS}"
AC_CHECK_HEADERS([zlib.h])
CFLAGS="${saved_CFLAGS}"
test -n "${ZLIB_LIBS}" -a "${ac_cv_header_zlib_h}" = "yes" && have_zlib="yes"

case "${enable_zlib}" in
	no)
		have_zlib="no"
	;;
	detect)
		if test "${have_zlib}" = "yes"; then
			enable_zlib="yes"
		else
			enable_zlib="no"
		fi
	;;
esac

if test "${enable_zlib}" = "yes"; then
	if test "${have_zlib}" = "yes"; then
		AC_DEFINE([ENABLE_ZLIB], [1], [Use zlib libraries and header files])
	else
		AC_MSG_ERROR([zlib linkage required, but no zlib was found])
	fi
fi

AC_ARG_VAR([READLINE_CFLAGS], [C compiler flags for readline])
AC_ARG_VAR([READLINE_LIBS], [linker flags for readline])
if test -z "${READLINE_LIBS}"; then
	for l in "" -lncurses -ltermcap; do
		unset ac_cv_lib_readline_readline
		AC_CHECK_LIB(
			[readline],
			[readline],
			[READLINE_LIBS="-lreadline ${l}"],
			,
			["${l}"]
		)
		test -n "${READLINE_LIBS}" && break;
	done
fi
saved_CFLAGS="${CFLAGS}"
CFLAGS="${CFLAGS} ${READLINE_CFLAGS}"
AC_CHECK_HEADERS([readline/readline.h])
CFLAGS="${saved_CFLAGS}"
test -n "${READLINE_LIBS}" -a "${ac_cv_header_readline_readline_h}" = "yes" && have_readline="yes"

case "${enable_readline}" in
	no)
		have_readline="no"
	;;
	detect)
		if test "${have_readline}" = "yes"; then
			enable_readline="yes"
		else
			enable_readline="no"
		fi
	;;
esac

if test "${enable_readline}" = "yes"; then
	if test "${have_readline}" = "yes"; then
		AC_DEFINE([ENABLE_READLINE], [1], [Use readline libraries and header files])
	else
		AC_MSG_ERROR([readline linkage required, but no readline was found])
	fi
fi

PKG_CHECK_MODULES(
	[OPENSSL],
	[libcrypto >= 0.9.7],
	[have_openssl="yes"],
	[PKG_CHECK_MODULES(
		[OPENSSL],
		[openssl >= 0.9.7],
		[have_openssl="yes"],
		[AC_CHECK_LIB(
			[crypto],
			[RSA_version],
			[
				have_openssl="yes"
				OPENSSL_LIBS="-lcrypto"
			],
			[have_openssl="no"]
		)]
	)]
)

case "${enable_openssl}" in
	no)
		have_openssl="no"
	;;
	detect)
		if test "${have_openssl}" = "yes"; then
			enable_openssl="yes"
		else
			enable_openssl="no"
		fi
	;;
esac

if test "${enable_openssl}" = "yes"; then
	if test "${have_openssl}" = "yes"; then
		AC_DEFINE([ENABLE_OPENSSL], [1], [Have OpenSSL libraries and header files])
	else
		AC_MSG_ERROR([OpenSSL linkage required, but no OpenSSL was found])
	fi
fi

if test "${enable_openct}" = "yes"; then
	PKG_CHECK_MODULES(
		[OPENCT],
		[libopenct],
		[AC_DEFINE([ENABLE_OPENCT], [1], [Have OpenCT libraries and header files])],
		[AC_MSG_ERROR([openct requested but not available])]
	)
fi

if test "${enable_ctapi}" = "yes"; then
	AC_DEFINE([ENABLE_CTAPI], [1], [Enable CT-API support])
fi

if test "${enable_pcsc}" = "yes"; then
	if test "${WIN32}" != "yes"; then
		PKG_CHECK_EXISTS(
			[libpcsclite],
			[PKG_CHECK_MODULES([PCSC], [libpcsclite])]
		)
		if test -z "${PCSC_CFLAGS}"; then
			case "${host}" in
				*-*-darwin*)
					PCSC_CFLAGS="-I/System/Library/Frameworks/PCSC.framework/Headers"
				;;
				*)
					PCSC_CFLAGS="-I/usr/include/PCSC"
				;;
			esac
		fi
	fi

	saved_CFLAGS="${CFLAGS}"
	CFLAGS="${CFLAGS} ${PCSC_CFLAGS}"
	# We must cope with mingw32 that does not have winscard.h mingw64 has it.
	AC_CHECK_HEADERS([winscard.h],,[test "${WIN32}" != "yes" && AC_MSG_ERROR([winscard.h is required for pcsc])])
	CFLAGS="${saved_CFLAGS}"

	if test "${with_pcsc_provider}" = "detect"; then
		case "${host}" in
			*-*-darwin*)
				DEFAULT_PCSC_PROVIDER="/System/Library/Frameworks/PCSC.framework/PCSC"
			;;
			*-mingw*|*-winnt*|*-cygwin*)
				DEFAULT_PCSC_PROVIDER="winscard.dll"
			;;
			*)
				DEFAULT_PCSC_PROVIDER="libpcsclite.so.1"
			;;
		esac
	else
		DEFAULT_PCSC_PROVIDER="${with_pcsc_provider}"
	fi
	AC_DEFINE_UNQUOTED([DEFAULT_PCSC_PROVIDER], ["${DEFAULT_PCSC_PROVIDER}"], [Default PC/SC provider])
	AC_DEFINE([ENABLE_PCSC], [1], [Define if PC/SC is to be enabled])
fi

if test "${enable_man}" = "detect"; then
	if test "${WIN32}" = "yes"; then
		enable_man="no"
	elif test -n "${XSLTPROC}" -a "${xslstylesheetsdir}" != "no"; then
		enable_man="yes"
	else
		enable_man="no"
	fi
fi

if test "${enable_man}" = "yes" -o "${enable_doc}" = "yes"; then
	AC_MSG_CHECKING([XSLTPROC requirement])
	test -n "${XSLTPROC}" || AC_MSG_ERROR([Missing XSLTPROC svn build with man or doc])
	test "${xslstylesheetsdir}" != "no" || AC_MSG_ERROR([Missing xslstylesheetsdir])
	AC_MSG_RESULT([ok])
fi

OPENSC_FEATURES=""
if test "${enable_zlib}" = "yes"; then
	OPENSC_FEATURES="${OPENSC_FEATURES} zlib"
	OPTIONAL_ZLIB_CFLAGS="${ZLIB_CFLAGS}"
	OPTIONAL_ZLIB_LIBS="${ZLIB_LIBS}"
fi
if test "${enable_readline}" = "yes"; then
	OPENSC_FEATURES="${OPENSC_FEATURES} readline"
	OPTIONAL_READLINE_CFLAGS="${READLINE_CFLAGS}"
	OPTIONAL_READLINE_LIBS="${READLINE_LIBS}"
fi
if test "${enable_openssl}" = "yes"; then
	OPENSC_FEATURES="${OPENSC_FEATURES} openssl"
	OPTIONAL_OPENSSL_CFLAGS="${OPENSSL_CFLAGS}"
	OPTIONAL_OPENSSL_LIBS="${OPENSSL_LIBS}"
fi
if test "${enable_openct}" = "yes"; then
	OPENSC_FEATURES="${OPENSC_FEATURES} openct"
	OPTIONAL_OPENCT_CFLAGS="${OPENCT_CFLAGS}"
	OPTIONAL_OPENCT_LIBS="${OPENCT_LIBS}"
fi
if test "${enable_pcsc}" = "yes"; then
	OPENSC_FEATURES="${OPENSC_FEATURES} pcsc(${DEFAULT_PCSC_PROVIDER})"
	OPTIONAL_PCSC_CFLAGS="${PCSC_CFLAGS}"
fi
if test "${enable_ctapi}" = "yes"; then
	OPENSC_FEATURES="${OPENSC_FEATURES} ctapi"
fi

AC_DEFINE_UNQUOTED([OPENSC_VERSION_MAJOR], [${OPENSC_VERSION_MAJOR}], [OpenSC version major component])
AC_DEFINE_UNQUOTED([OPENSC_VERSION_MINOR], [${OPENSC_VERSION_MINOR}], [OpenSC version minor component])
AC_DEFINE_UNQUOTED([OPENSC_VERSION_FIX], [${OPENSC_VERSION_FIX}], [OpenSC version fix component])
AC_DEFINE_UNQUOTED([OPENSC_FEATURES], ["${OPENSC_FEATURES}"], [Enabled OpenSC features])

pkcs11dir="\$(libdir)/pkcs11"

AC_SUBST([pkcs11dir])
AC_SUBST([xslstylesheetsdir])
AC_SUBST([OPENSC_VERSION_MAJOR])
AC_SUBST([OPENSC_VERSION_MINOR])
AC_SUBST([OPENSC_VERSION_FIX])
AC_SUBST([OPENSC_LT_CURRENT])
AC_SUBST([OPENSC_LT_REVISION])
AC_SUBST([OPENSC_LT_AGE])
AC_SUBST([OPENSC_LT_OLDEST])
AC_SUBST([WIN_LIBPREFIX])
AC_SUBST([DEFAULT_PCSC_PROVIDER])
AC_SUBST([OPTIONAL_ZLIB_CFLAGS])
AC_SUBST([OPTIONAL_ZLIB_LIBS])
AC_SUBST([OPTIONAL_READLINE_CFLAGS])
AC_SUBST([OPTIONAL_READLINE_LIBS])
AC_SUBST([OPTIONAL_OPENSSL_CFLAGS])
AC_SUBST([OPTIONAL_OPENSSL_LIBS])
AC_SUBST([OPTIONAL_OPENCT_CFLAGS])
AC_SUBST([OPTIONAL_OPENCT_LIBS])
AC_SUBST([OPTIONAL_PCSC_CFLAGS])
AC_SUBST([LIBRARY_BITNESS])

AM_CONDITIONAL([ENABLE_MAN], [test "${enable_man}" = "yes"])
AM_CONDITIONAL([ENABLE_ZLIB], [test "${enable_zlib}" = "yes"])
AM_CONDITIONAL([ENABLE_READLINE], [test "${enable_readline}" = "yes"])
AM_CONDITIONAL([ENABLE_OPENSSL], [test "${enable_openssl}" = "yes"])
AM_CONDITIONAL([ENABLE_OPENCT], [test "${enable_openct}" = "yes"])
AM_CONDITIONAL([ENABLE_DOC], [test "${enable_doc}" = "yes"])
AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])
AM_CONDITIONAL([CYGWIN], [test "${CYGWIN}" = "yes"])
AM_CONDITIONAL([ENABLE_MINIDRIVER], [test "${enable_minidriver}" = "yes"])

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes";
	CFLAGS="${CFLAGS} -pedantic"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="${CFLAGS} -Wall -Wextra"
fi
if test "$GCC" = "yes"; then
	# This should be resolved not ignored.
	CFLAGS="-fno-strict-aliasing ${CFLAGS}"
fi

AC_CONFIG_FILES([
	Makefile
	doc/Makefile
	etc/Makefile
	src/Makefile
	src/common/Makefile
	src/libopensc/Makefile
	src/libopensc/libopensc.pc
	src/pkcs11/Makefile
	src/pkcs15init/Makefile
	src/scconf/Makefile
	src/tests/Makefile
	src/tests/regression/Makefile
	src/tools/Makefile
	src/minidriver/Makefile
	src/minidriver/opensc-minidriver.inf
	win32/Makefile
	win32/versioninfo.rc
	win32/winconfig.h
	win32/OpenSC.iss
	win32/OpenSC.wxs
])
AC_OUTPUT

cat <<EOF

OpenSC has been configured with the following options:


Version:                 ${PACKAGE_VERSION}
User binaries:           $(eval eval eval echo "${bindir}")
Configuration files:     $(eval eval eval echo "${sysconfdir}")
XSL stylesheets:         ${xslstylesheetsdir}

man support:             ${enable_man}
doc support:             ${enable_doc}
zlib support:            ${enable_zlib}
readline support:        ${enable_readline}
OpenSSL support:         ${enable_openssl}
PC/SC support:           ${enable_pcsc}
OpenCT support:          ${enable_openct}
CT-API support:          ${enable_ctapi}
minidriver support:      ${enable_minidriver}

PC/SC default provider:  ${DEFAULT_PCSC_PROVIDER}

Host:                    ${host}
Compiler:                ${CC}
Preprocessor flags:      ${CPPFLAGS}
Compiler flags:          ${CFLAGS}
Linker flags:            ${LDFLAGS}
Libraries:               ${LIBS}

LTLIB_CFLAGS:            ${LTLIB_CFLAGS}
LTLIB_LIBS:              ${LTLIB_LIBS}
READLINE_CFLAGS:         ${READLINE_CFLAGS}
READLINE_LIBS:           ${READLINE_LIBS}
ZLIB_CFLAGS:             ${ZLIB_CFLAGS}
ZLIB_LIBS:               ${ZLIB_LIBS}
OPENSSL_CFLAGS:          ${OPENSSL_CFLAGS}
OPENSSL_LIBS:            ${OPENSSL_LIBS}
OPENCT_CFLAGS:           ${OPENCT_CFLAGS}
OPENCT_LIBS:             ${OPENCT_LIBS}
PCSC_CFLAGS:             ${PCSC_CFLAGS}

EOF

