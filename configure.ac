dnl -*- mode: m4; -*-

AC_PREREQ(2.68)

define([PRODUCT_NAME], [OpenSC])
define([PRODUCT_TARNAME], [opensc])
define([PRODUCT_BUGREPORT], [https://github.com/OpenSC/OpenSC/issues])
define([PRODUCT_URL], [https://github.com/OpenSC/OpenSC])
define([PACKAGE_VERSION_MAJOR], [0])
define([PACKAGE_VERSION_MINOR], [21])
define([PACKAGE_VERSION_FIX], [0])
define([PACKAGE_SUFFIX], [])

define([VS_FF_LEGAL_COPYRIGHT], [OpenSC Project])
define([VS_FF_LEGAL_COMPANY_NAME], [OpenSC Project])
define([VS_FF_LEGAL_COMPANY_URL], [https://github.com/OpenSC])
define([VS_FF_COMMENTS], [Provided under the terms of the GNU Lesser General Public License (LGPLv2.1+).])
define([VS_FF_PRODUCT_NAME], [OpenSC smartcard framework])
define([VS_FF_PRODUCT_UPDATES], [https://github.com/OpenSC/OpenSC/releases])
define([VS_FF_PRODUCT_URL], [https://github.com/OpenSC/OpenSC])

m4_sinclude(version.m4.ci)

m4_define([openssl_minimum_version], [1.0.1])

AC_INIT([PRODUCT_NAME],[PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR.PACKAGE_VERSION_FIX[]PACKAGE_SUFFIX],[PRODUCT_BUGREPORT],[PRODUCT_TARNAME],[PRODUCT_URL])
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign 1.10 [subdir-objects])

OPENSC_VERSION_MAJOR="PACKAGE_VERSION_MAJOR"
OPENSC_VERSION_MINOR="PACKAGE_VERSION_MINOR"
OPENSC_VERSION_FIX="PACKAGE_VERSION_FIX"

OPENSC_VS_FF_LEGAL_COPYRIGHT="VS_FF_LEGAL_COPYRIGHT"
OPENSC_VS_FF_COMPANY_NAME="VS_FF_LEGAL_COMPANY_NAME"
OPENSC_VS_FF_COMPANY_URL="VS_FF_LEGAL_COMPANY_URL"
OPENSC_VS_FF_COMMENTS="VS_FF_COMMENTS"
OPENSC_VS_FF_PRODUCT_NAME="VS_FF_PRODUCT_NAME"
OPENSC_VS_FF_PRODUCT_UPDATES="VS_FF_PRODUCT_UPDATES"
OPENSC_VS_FF_PRODUCT_URL="VS_FF_PRODUCT_URL"

# LT Version numbers, remember to change them just *before* a release.
#   (Code changed:                      REVISION++)
#   (Oldest interface changed/removed:  OLDEST++)
#   (Interfaces added:                  CURRENT++, REVISION=0)
OPENSC_LT_CURRENT="7"
OPENSC_LT_OLDEST="7"
OPENSC_LT_REVISION="0"
OPENSC_LT_AGE="0"
OPENSC_LT_AGE="$((${OPENSC_LT_CURRENT}-${OPENSC_LT_OLDEST}))"

AC_CONFIG_SRCDIR([src/libopensc/sc.c])

# silent build by default
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CANONICAL_HOST
AC_PROG_CC
# AC_PROG_CXX is needed to built the win32 custom action. Indeed dutil.h use [extern "C"] definition which fails on pure c compiler
AC_PROG_CXX
AC_PROG_OBJC
PKG_PROG_PKG_CONFIG
AC_C_BIGENDIAN

AC_ARG_ENABLE(
	[optimization],
	[AS_HELP_STRING([--disable-optimization],[disable compile optimization @<:@enabled@:>@])],
	,
	[enable_optimization="yes"]
)

AC_ARG_WITH(
	[cygwin-native],
	[AS_HELP_STRING([--with-cygwin-native],[compile native win32])],
	,
	[with_cygwin_native="no"]
)

if test "${enable_optimization}" = "no"; then
	CFLAGS="${CFLAGS} -O0 -g"
fi

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
			WIN_LIBPREFIX="cyg"
			AC_DEFINE([USE_CYGWIN], [1], [Define if you are on Cygwin])
		fi
	;;
esac

case "${host}" in
	*-mingw*|*-winnt*|*-cygwin*)
		DEBUG_FILE="%TEMP%\\\opensc-debug.log"
		PROFILE_DIR_DEFAULT="obtained from windows registers"
		PROFILE_DIR="\"\""
	;;
	*)
		DEBUG_FILE="/tmp/opensc-debug.log"
		PROFILE_DIR="\$(pkgdatadir)"
		PROFILE_DIR_DEFAULT="\$(pkgdatadir)"
	;;
esac

case "${host}" in
	*-mingw*)
		CPPFLAGS="${CPPFLAGS} -D__USE_MINGW_ANSI_STDIO=1"
	;;
esac

AX_CODE_COVERAGE()

AX_CHECK_COMPILE_FLAG([-Wunknown-warning-option], [have_unknown_warning_option="yes"], [have_unknown_warning_option="no"], [-Werror])
AM_CONDITIONAL([HAVE_UNKNOWN_WARNING_OPTION], [test "${have_unknown_warning_option}" = "yes"])

AC_ARG_ENABLE(
	[fuzzing],
	[AS_HELP_STRING([--enable-fuzzing],[enable compile of fuzzing tests @<:@disabled@:>@, note that CFLAGS and FUZZING_LIBS should be set accordingly, e.g. to something like CFLAGS="-fsanitize=address,fuzzer" FUZZING_LIBS="-fsanitize=fuzzer"])],
	,
	[enable_fuzzing="no"]
)

AC_ARG_VAR([FUZZING_LIBS], [linker flags for fuzzing])

AC_ARG_ENABLE(
	[strict],
	[AS_HELP_STRING([--disable-strict],[disable strict compile mode @<:@enabled@:>@])],
	,
	[enable_strict="yes"]
)

AC_ARG_ENABLE(
	[pedantic],
	[AS_HELP_STRING([--enable-pedantic],[enable pedantic compile mode @<:@disabled@:>@])],
	,
	[enable_pedantic="no"]
)

AC_ARG_ENABLE(
	[thread_locking],
	[AS_HELP_STRING([--disable-thread-locking],[disable OS thread locking @<:@enabled@:>@])],
	,
	[enable_thread_locking="yes"]
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
	[AS_HELP_STRING([--enable-openssl],[enable OpenSSL linkage @<:@detect@:>@])],
	,
	[enable_openssl="detect"]
)

AC_ARG_ENABLE([openssl-secure-malloc],
    [AS_HELP_STRING([--openssl-secure-malloc=<SIZE_IN_BYTES>],
        [Enable OpenSSL secure memory by specifying its size in bytes, must be a power of 2 @<:@disabled@:>@])],
    [], [enable_openssl_secure_malloc=no])
AS_IF([test $enable_openssl_secure_malloc != no],
	[AC_DEFINE_UNQUOTED([OPENSSL_SECURE_MALLOC_SIZE],[$enable_openssl_secure_malloc],[Size of OpenSSL secure memory in bytes, must be a power of 2])])

AC_ARG_ENABLE(
	[openpace],
	[AS_HELP_STRING([--enable-openpace],[enable OpenPACE linkage @<:@detect@:>@])],
	,
	[enable_openpace="detect"]
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
	[cryptotokenkit],
	[AS_HELP_STRING([--disable-cryptotokenkit],[disable CryptoTokenKit support @<:@enabled@:>@])],
	,
	[enable_cryptotokenkit="no"]
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
	[sm],
	[AS_HELP_STRING([--disable-sm],[disable secure messaging support and SM modules @<:@enabled@:>@])],
	,
	[enable_sm="yes"]
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

AC_ARG_ENABLE(
	[dnie-ui],
	[AS_HELP_STRING([--enable-dnie-ui],[enable use of external user interface program to request DNIe pin@<:@disabled@:>@])],
	,
	[enable_dnie_ui="no"]
)

AC_ARG_ENABLE(
	[notify],
	[AS_HELP_STRING([--enable-notify],[enable notifications @<:@detect@:>@])],
	,
	[enable_notify="detect"]
)

AC_ARG_ENABLE(
	[autostart-items],
	[AS_HELP_STRING([--enable-autostart-items],[enable autostart items @<:@enabled@:>@])],
	,
	[enable_autostart="yes"]
)

AC_ARG_ENABLE(
	[cmocka],
	[AS_HELP_STRING([--enable-cmocka],[Build tests in src/tests/p11test directory @<:@detect@:>@])],
	,
	[enable_cmocka="detect"]
)

AC_ARG_WITH(
	[xsl-stylesheetsdir],
	[AS_HELP_STRING([--with-xsl-stylesheetsdir=PATH],[docbook xsl-stylesheets for svn build @<:@detect@:>@])],
	[xslstylesheetsdir="${withval}"],
	[xslstylesheetsdir="detect"]
)

AC_ARG_WITH(
	[completiondir],
	[AS_HELP_STRING([--with-completiondir=PATH],[Directory of Bash completion @<:@detect@:>@])],
	[completiondir="${withval}"],
	[completiondir="detect"]
)

AC_ARG_WITH(
	[pcsc-provider],
	[AS_HELP_STRING([--with-pcsc-provider=PATH],[Path to system pcsc provider @<:@system default@:>@])],
	,
	[with_pcsc_provider="detect"]
)

AC_ARG_WITH(
	[pkcs11-provider],
	[AS_HELP_STRING([--with-pkcs11-provider=PATH],[Path to the default PKCS11 provider @<:@default=OpenSC@:>@])],
	,
	[with_pkcs11_provider="detect"]
)

dnl ./configure check
reader_count=""
for rdriver in "${enable_pcsc}" "${enable_cryptotokenkit}" "${enable_openct}" "${enable_ctapi}"; do
	test "${rdriver}" = "yes" && reader_count="${reader_count}x"
done
if test "${reader_count}" != "x"; then
	AC_MSG_ERROR([Only one of --enable-pcsc, --enable-cryptotokenkit, --enable-openct, --enable-ctapi can be specified!])
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

dnl These required for repository checkout
AC_ARG_VAR([XSLTPROC], [xsltproc utility])
AC_ARG_VAR([git], [git])
AC_CHECK_PROGS([XSLTPROC],[xsltproc])
AC_CHECK_PROGS([GIT],[git])

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

AC_MSG_CHECKING([git checkout])
GIT_CHECKOUT="no"
if test -n "${GIT}" -a -d "${srcdir}/.git"; then
	GIT_CHECKOUT="yes"
fi
AC_MSG_RESULT([${GIT_CHECKOUT}])

if test "${GIT_CHECKOUT}" = "yes"; then
	REVISION_DESCRIPTION="$(${GIT} describe || echo '<version not available>' )"
	if test "${REVISION_DESCRIPTION}" = "<version not available>"; then
		REVISION_DESCRIPTION="$(${GIT} describe --tags || echo '<version not available>')"
	fi

	HASH_COMMIT_DATE="$(${GIT} log -1 --pretty=format:'rev: %h, commit-time: %ci')"
	GIT_TAG_COMMIT="$(${GIT} rev-list --tags --no-walk --max-count=1)"

	OPENSC_SCM_REVISION="OpenSC-${REVISION_DESCRIPTION}, ${HASH_COMMIT_DATE}"
	OPENSC_VERSION_REVISION="$(${GIT} rev-list ${GIT_TAG_COMMIT}..HEAD --count || echo 0)"
else
	OPENSC_SCM_REVISION="No Git revision info available"
	OPENSC_VERSION_REVISION="0"
fi

dnl C Compiler features
AC_C_INLINE

dnl Checks for header files.
AC_HEADER_SYS_WAIT
AC_HEADER_ASSERT
AC_CHECK_HEADERS([ \
	errno.h fcntl.h stdlib.h \
	inttypes.h string.h strings.h \
	sys/time.h unistd.h sys/mman.h \
	sys/endian.h endian.h
])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_SIZE_T

dnl Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_STAT
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([ \
	getpass gettimeofday getline memset mkdir \
	strdup strerror memset_s explicit_bzero \
	strnlen sigaction
])

# Do not check for strlcpy and strlcat in Linux because it is not implemented
# and autotools can not detect it in AC_CHECK_DECLS because build does not fail
# in this test.
# https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=22192
case "${host_os}" in
	linux*)
		;;
	*)
		AC_CHECK_DECLS([strlcpy, strlcat], [], [], [[#include <string.h>]])
		;;
esac

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

if test "${WIN32}" = "no"; then
	dnl dl support
	AC_SEARCH_LIBS([dlopen], [dl dld], [], [
		AC_MSG_ERROR([unable to find the dlopen() function])
	])

	dnl Special check for pthread support.
	AX_PTHREAD(
		[AC_DEFINE(
			[HAVE_PTHREAD],
			[1],
			[Define if you have POSIX threads libraries and header files.]
		)],
		[AC_MSG_ERROR([POSIX thread support required])]
	)
	CC="${PTHREAD_CC}"
fi

if test "${enable_thread_locking}" = "yes"; then
	OPENSC_PKCS11_PTHREAD_CFLAGS="${PTHREAD_CFLAGS} -DPKCS11_THREAD_LOCKING"
else
	OPENSC_PKCS11_PTHREAD_CFLAGS=""
fi
AC_SUBST(OPENSC_PKCS11_PTHREAD_CFLAGS)

if test "${enable_minidriver}" = "yes"; then
	dnl win32 special test for minidriver
	AC_CHECK_HEADER(
		[cardmod.h],
		,
		[AC_MSG_ERROR([cardmod.h from CNG is required for minidriver])],
		[#if defined(__MINGW32__)
#include "${srcdir}/src/minidriver/cardmod-mingw-compat.h"
#endif
	])

	AC_DEFINE([ENABLE_MINIDRIVER], [1], [Enable minidriver support])
fi

if test "${enable_dnie_ui}" = "yes"; then
	AC_DEFINE([ENABLE_DNIE_UI], [1], [Enable the use of external user interface program to request DNIe user pin])

	case "${host}" in
		*-*-darwin*)
			LDFLAGS="${LDFLAGS} -framework Carbon"
		;;
	esac
	case "${host}" in
		*-apple-*)
			LDFLAGS="${LDFLAGS} -framework CoreFoundation"
		;;
	esac
fi

case "${host}" in
	*-*-darwin*)
			have_notify="yes"
		;;
	*)
			PKG_CHECK_MODULES( [GIO2], [gio-2.0],
							  [ have_notify="yes"
								have_gio2="yes" ],
							  [ have_notify="no"
								have_gio2="no" ])
			saved_CFLAGS="${CFLAGS}"
			CFLAGS="${CFLAGS} ${GIO2_CFLAGS}"
			AC_CHECK_HEADERS(gio/gio.h, [],
							 [ AC_MSG_WARN([glib2 headers not found])
							   have_notify="no"
							   have_gio2="no" ])
			CFLAGS="${saved_CFLAGS}"
			saved_LIBS="$LIBS"
			LIBS="$LIBS  ${GIO2_LIBS}"
			AC_MSG_CHECKING([for g_application_send_notification])
			AC_TRY_LINK_FUNC(g_application_send_notification, [ AC_MSG_RESULT([yes]) ],
							 [ AC_MSG_WARN([Cannot link against glib2])
							   have_notify="no"
							   have_gio2="no"  ])
			LIBS="$saved_LIBS"
		;;
esac

case "${enable_notify}" in
	no)
		have_notify="no"
	;;
	detect)
		if test "${have_notify}" = "yes"; then
			enable_notify="yes"
		else
			enable_notify="no"
		fi
	;;
esac

if test "${enable_notify}" = "yes"; then
	if test "${have_notify}" = "yes"; then
		AC_DEFINE([ENABLE_NOTIFY], [1], [Use notification libraries and header files])
		if test "${have_gio2}" = "yes"; then
			AC_DEFINE([ENABLE_GIO2], [1], [Use glib2 libraries and header files])
			OPTIONAL_NOTIFY_CFLAGS="${GIO2_CFLAGS}"
			OPTIONAL_NOTIFY_LIBS="${GIO2_LIBS}"
		fi
	else
		AC_MSG_ERROR([notification linkage required, but no notification provider was found])
	fi
fi

have_cmocka="yes"
PKG_CHECK_MODULES([CMOCKA], [cmocka >= 1.0.1],,[have_cmocka="no"])
AC_CHECK_HEADER([setjmp.h])
AC_CHECK_HEADER([cmocka.h],, [have_cmocka="no"],
[#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
])

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
	[libcrypto >= openssl_minimum_version],
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
)

case "${enable_openssl}" in
	no)
		have_openssl="no"
	;;
	detect)
		saved_CFLAGS="${CFLAGS}"
		CFLAGS="${CFLAGS} ${OPENSSL_CFLAGS}"
		AC_CHECK_HEADERS([openssl/crypto.h],,[have_openssl="no"])
		CFLAGS="${saved_CFLAGS}"
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
else
	OPENSSL_CFLAGS=""
	OPENSSL_LIBS=""
fi

if test "${enable_cmocka}" = "detect"; then
	if test "${have_cmocka}" = "yes" -a "${have_openssl}" = "yes"; then
		enable_cmocka="yes"
	else
		enable_cmocka="no"
	fi
fi

if test "${enable_cmocka}" = "yes"; then
	if test "${have_cmocka}" != "yes"; then
		AC_MSG_ERROR([Tests required, but cmocka is not available])
	fi
fi



PKG_CHECK_EXISTS([libeac], [PKG_CHECK_MODULES([OPENPACE], [libeac >= 0.9])],
                 [AC_MSG_WARN([libeac not found by pkg-config])])

saved_CPPFLAGS="$CPPFLAGS"
saved_LIBS="$LIBS"
CPPFLAGS="$CPPFLAGS $OPENPACE_CFLAGS"
LIBS="$LDFLAGS $OPENPACE_LIBS"

have_openpace="yes"
AC_CHECK_HEADERS(eac/eac.h, [],
                 [ AC_MSG_WARN([OpenPACE headers not found])
                 have_openpace="no" ])
AC_MSG_CHECKING([for EAC_CTX_init_pace])
AC_TRY_LINK_FUNC(EAC_CTX_init_pace, [ AC_MSG_RESULT([yes]) ],
                 [ AC_MSG_WARN([Cannot link against libeac])
                 have_openpace="no" ])

CPPFLAGS="$saved_CPPFLAGS"
LIBS="$saved_LIBS"


AC_ARG_ENABLE(cvcdir,
              AS_HELP_STRING([--enable-cvcdir=DIR],
                             [directory containing CV certificates (default is determined by libeac)]),
                             [cvcdir="${enableval}"],
                             [cvcdir=false])
if test "${cvcdir}" = false ; then
    cvcdir="`$PKG_CONFIG libeac --variable=cvcdir`"
fi
if test "${cvcdir}" = "" ; then
	case "${host}" in
		*-mingw*|*-winnt*|*-cygwin*)
			cvcdir="%PROGRAMFILES%\\\OpenSC Project\\\OpenSC\\\cvc"
			;;
		*)
			AC_MSG_WARN([use --enable-cvcdir=DIR])
			;;
	esac
fi
CVCDIR="${cvcdir}"
AC_SUBST(CVCDIR)
AC_DEFINE_UNQUOTED([CVCDIR], ["${CVCDIR}"], [CVC directory])

AC_ARG_ENABLE(x509dir,
              AS_HELP_STRING([--enable-x509dir=DIR],
                             [directory containing X.509 certificates (default is determined by libeac)]),
                             [x509dir="${enableval}"],
                             [x509dir=false])
if test "${x509dir}" = false ; then
    x509dir="`$PKG_CONFIG libeac --variable=x509dir`"
fi
if test -z "${x509dir}"
then
    x509dir="`$PKG_CONFIG libeac --variable=x509dir`"
fi
if test -z "${x509dir}"
then
	case "${host}" in
		*-mingw*|*-winnt*|*-cygwin*)
			x509dir="%PROGRAMFILES%\\\OpenSC Project\\\OpenSC\\\x509"
			;;
		*)
			AC_MSG_WARN([use --enable-x509dir=DIR])
			;;
	esac
fi
X509DIR="${x509dir}"
AC_SUBST(X509DIR)
AC_DEFINE_UNQUOTED([X509DIR], ["${X509DIR}"], [CVC directory])

case "${enable_openpace}" in
	no)
		have_openpace="no"
	;;
	detect)
		if test "${have_openpace}" = "yes"; then
			enable_openpace="yes"
		else
			enable_openpace="no"
		fi
	;;
esac

if test "${enable_openpace}" = "yes"; then
	if test "${have_openpace}" = "yes"; then
		AC_DEFINE([ENABLE_OPENPACE], [1], [Use OpenPACE libraries and header files])
	else
		AC_MSG_ERROR([OpenPACE linkage required, but no OpenPACE was found])
	fi
else
	OPENPACE_CFLAGS=""
	OPENPACE_LIBS=""
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
			[PKG_CHECK_MODULES([PCSC], [libpcsclite >= 1.8.22],
				[AC_DEFINE([PCSCLITE_GOOD], [1], [Sufficient version of PCSC-Lite with all the required features])],
				[:]
			)]
		)
		if test -z "${PCSC_CFLAGS}"; then
			case "${host}" in
				*-*-darwin*)
					# Locate the latest SDK.
					SDK_PATH=$(xcrun --sdk macosx --show-sdk-path)
					PCSC_CFLAGS="-I$SDK_PATH/System/Library/Frameworks/PCSC.framework/Versions/Current/Headers"
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
	AC_CHECK_HEADERS([pcsclite.h])
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

if test "${enable_cryptotokenkit}" = "yes"; then
	if test -z "${CRYPTOTOKENKIT_CFLAGS}"; then
		case "${host}" in
			*-apple-*)
				CRYPTOTOKENKIT_CFLAGS="-framework CryptoTokenKit -framework Foundation"
				LDFLAGS="${LDFLAGS} -framework CryptoTokenKit -framework Foundation"
			;;
			*)
				AC_MSG_ERROR([CryptoTokenKit only supported on Darwin])
			;;
		esac
	fi
	AC_DEFINE([ENABLE_CRYPTOTOKENKIT], [1], [Define if CryptoTokenKit is to be enabled])
fi

if test "${completiondir}" = "detect"; then
	echo completion ${completiondir}
	PKG_CHECK_MODULES([BASH_COMPLETION], [bash-completion >= 2.0],
		[completiondir="`pkg-config --variable=completionsdir bash-completion`"],
		[completiondir="${sysconfdir}/bash_completion.d"])
fi
AC_SUBST([completiondir])


AC_SUBST(DYN_LIB_EXT)
AC_SUBST(LIBDIR)
AC_SUBST(LIB_PRE)
case "${host}" in
	*-mingw*|*-winnt*|*-cygwin*)
		DYN_LIB_EXT=".dll"
		LIBDIR=""
		LIB_PRE=""
		;;
	*)
		DYN_LIB_EXT=".so"
		LIBDIR="\$(libdir)/"
		LIB_PRE="lib"
		;;
esac

if test "${enable_sm}" = "yes"; then
	AC_DEFINE([ENABLE_SM], [1], [Enable secure messaging support])

	DEFAULT_SM_MODULE="${LIB_PRE}smm-local${DYN_LIB_EXT}"
	case "${host}" in
		*-mingw*|*-winnt*|*-cygwin*)
			DEFAULT_SM_MODULE_PATH="%PROGRAMFILES%\\\OpenSC Project\\\OpenSC\\\tools"
		;;
		*)
			DEFAULT_SM_MODULE_PATH="${libdir}"
		;;
	esac
fi

if test "${with_pkcs11_provider}" = "detect"; then
	if test "${WIN32}" != "yes"; then
		DEFAULT_PKCS11_PROVIDER="${libdir}/opensc-pkcs11${DYN_LIB_EXT}"
		DEFAULT_ONEPIN_PKCS11_PROVIDER="${libdir}/onepin-opensc-pkcs11${DYN_LIB_EXT}"
	else
		DEFAULT_PKCS11_PROVIDER="%PROGRAMFILES%\\\OpenSC Project\\\OpenSC\\\pkcs11\\\opensc-pkcs11.dll"
		DEFAULT_ONEPIN_PKCS11_PROVIDER="%PROGRAMFILES%\\\OpenSC Project\\\OpenSC\\\pkcs11\\\onepin-opensc-pkcs11.dll"
	fi
else
	DEFAULT_PKCS11_PROVIDER="${with_pkcs11_provider}"
	DEFAULT_ONEPIN_PKCS11_PROVIDER="${with_pkcs11_provider}"
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
	test -n "${XSLTPROC}" || AC_MSG_ERROR([Missing XSLTPROC])
	test "${xslstylesheetsdir}" != "no" || AC_MSG_ERROR([Missing xslstylesheetsdir])
	AC_MSG_RESULT([ok])
fi

AC_ARG_VAR([GENGETOPT],
           [absolute path to gengetopt used for command line parsing of npa-tool])
AC_PATH_PROG(GENGETOPT, gengetopt, not found)
AC_ARG_VAR([CLANGTIDY],
           [absolute path to clang-tidy used for static code analysis])
AC_PATH_PROG(CLANGTIDY, clang-tidy, not found)
TIDY_CHECKS="-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling"

AX_FUNC_GETOPT_LONG
#AH_BOTTOM([#include "common/compat_getopt.h"])

OPENSC_FEATURES=""
if test "${enable_thread_locking}" = "yes"; then
	OPENSC_FEATURES="${OPENSC_FEATURES} locking"
fi
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
if test "${enable_cryptotokenkit}" = "yes"; then
	OPTIONAL_CRYPTOTOKENKIT_CFLAGS="${CRYPTOTOKENKIT_CFLAGS}"
fi
if test "${enable_ctapi}" = "yes"; then
	OPENSC_FEATURES="${OPENSC_FEATURES} ctapi"
fi

if test "${enable_minidriver}" = "yes"; then
	AC_MSG_CHECKING([WiX SDK])
	AC_CHECK_HEADERS([wcautil.h],[enable_minidriver_ca="yes"],[enable_minidriver_ca="no"])
	if test "${enable_minidriver_ca}" = "yes"; then
		AC_MSG_RESULT([found, minidriver setup custom action will be built])
	else
		AC_MSG_RESULT([not found, minidriver setup custom action will be skipped])
	fi
else
	enable_minidriver_ca="no"
fi

AC_DEFINE_UNQUOTED([OPENSC_VERSION_MAJOR], [${OPENSC_VERSION_MAJOR}], [OpenSC version major component])
AC_DEFINE_UNQUOTED([OPENSC_VERSION_MINOR], [${OPENSC_VERSION_MINOR}], [OpenSC version minor component])
AC_DEFINE_UNQUOTED([OPENSC_VERSION_FIX], [${OPENSC_VERSION_FIX}], [OpenSC version fix component])
AC_DEFINE_UNQUOTED([OPENSC_VERSION_REVISION], [${OPENSC_VERSION_REVISION}], [OpenSC file version revision])
AC_DEFINE_UNQUOTED([OPENSC_SCM_REVISION], ["${OPENSC_SCM_REVISION}"], [OpenSC version Git describe revision])
AC_DEFINE_UNQUOTED([OPENSC_FEATURES], ["${OPENSC_FEATURES}"], [Enabled OpenSC features])

AC_DEFINE_UNQUOTED([OPENSC_VS_FF_LEGAL_COPYRIGHT], ["${OPENSC_VS_FF_LEGAL_COPYRIGHT}"], [OpenSC version-info LegalCopyright value])
AC_DEFINE_UNQUOTED([OPENSC_VS_FF_COMPANY_NAME], ["${OPENSC_VS_FF_COMPANY_NAME}"], [OpenSC version-info CompanyName value])
AC_DEFINE_UNQUOTED([OPENSC_VS_FF_COMMENTS], ["${OPENSC_VS_FF_COMMENTS}"], [OpenSC version-info Comments])
AC_DEFINE_UNQUOTED([OPENSC_VS_FF_PRODUCT_NAME], ["${OPENSC_VS_FF_PRODUCT_NAME}"], [OpenSC version-info ProductName])
AC_DEFINE_UNQUOTED([OPENSC_VS_FF_PRODUCT_UPDATES], ["${OPENSC_VS_FF_PRODUCT_UPDATES}"], [OpenSC version-info UpdateURL])
AC_DEFINE_UNQUOTED([OPENSC_VS_FF_PRODUCT_URL], ["${OPENSC_VS_FF_PRODUCT_URL}"], [OpenSC version-info ProductURL])
AC_DEFINE_UNQUOTED([OPENSC_VS_FF_COMPANY_URL], ["${OPENSC_VS_FF_COMPANY_URL}"], [OpenSC version-info UpdateURL])

pkcs11dir="\$(libdir)/pkcs11"

AC_SUBST([pkcs11dir])
AC_SUBST([xslstylesheetsdir])
AC_SUBST([OPENSC_VERSION_MAJOR])
AC_SUBST([OPENSC_VERSION_MINOR])
AC_SUBST([OPENSC_VERSION_FIX])
AC_SUBST([OPENSC_VERSION_REVISION])
AC_SUBST([OPENSC_SCM_REVISION])
AC_SUBST([OPENSC_VS_FF_LEGAL_COPYRIGHT])
AC_SUBST([OPENSC_VS_FF_COMPANY_NAME])
AC_SUBST([OPENSC_VS_FF_COMMENTS])
AC_SUBST([OPENSC_VS_FF_PRODUCT_NAME])
AC_SUBST([OPENSC_VS_FF_PRODUCT_UPDATES])
AC_SUBST([OPENSC_VS_FF_PRODUCT_URL])
AC_SUBST([OPENSC_VS_FF_COMPANY_URL])
AC_SUBST([OPENSC_LT_CURRENT])
AC_SUBST([OPENSC_LT_REVISION])
AC_SUBST([OPENSC_LT_AGE])
AC_SUBST([OPENSC_LT_OLDEST])
AC_SUBST([WIN_LIBPREFIX])
AC_SUBST([DEFAULT_PCSC_PROVIDER])
AC_SUBST([DEFAULT_PKCS11_PROVIDER])
AC_SUBST([DEFAULT_ONEPIN_PKCS11_PROVIDER])
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
AC_SUBST([DEFAULT_SM_MODULE])
AC_SUBST([DEFAULT_SM_MODULE_PATH])
AC_SUBST([DEBUG_FILE])
AC_SUBST([PROFILE_DIR])
AC_SUBST([PROFILE_DIR_DEFAULT])
AC_SUBST([OPTIONAL_NOTIFY_CFLAGS])
AC_SUBST([OPTIONAL_NOTIFY_LIBS])
AC_SUBST([TIDY_CHECKS])

AM_CONDITIONAL([ENABLE_MAN], [test "${enable_man}" = "yes"])
AM_CONDITIONAL([ENABLE_THREAD_LOCKING], [test "${enable_thread_locking}" = "yes"])
AM_CONDITIONAL([ENABLE_ZLIB], [test "${enable_zlib}" = "yes"])
AM_CONDITIONAL([ENABLE_READLINE], [test "${enable_readline}" = "yes"])
AM_CONDITIONAL([ENABLE_OPENSSL], [test "${enable_openssl}" = "yes"])
AM_CONDITIONAL([ENABLE_OPENPACE], [test "${enable_openpace}" = "yes"])
AM_CONDITIONAL([ENABLE_CRYPTOTOKENKIT], [test "${enable_cryptotokenkit}" = "yes"])
AM_CONDITIONAL([ENABLE_OPENCT], [test "${enable_openct}" = "yes"])
AM_CONDITIONAL([ENABLE_DOC], [test "${enable_doc}" = "yes"])
AM_CONDITIONAL([WIN32], [test "${WIN32}" = "yes"])
AM_CONDITIONAL([CYGWIN], [test "${CYGWIN}" = "yes"])
AM_CONDITIONAL([ENABLE_MINIDRIVER], [test "${enable_minidriver}" = "yes"])
AM_CONDITIONAL([ENABLE_MINIDRIVER_SETUP_CUSTOMACTION], [test "${enable_minidriver_ca}" = "yes"])
AM_CONDITIONAL([ENABLE_SM], [test "${enable_sm}" = "yes"])
AM_CONDITIONAL([ENABLE_DNIE_UI], [test "${enable_dnie_ui}" = "yes"])
AM_CONDITIONAL([ENABLE_NPATOOL], [test "${ENABLE_NPATOOL}" = "yes"])
AM_CONDITIONAL([ENABLE_AUTOSTART], [test "${enable_autostart}" = "yes"])
AM_CONDITIONAL([ENABLE_CMOCKA], [test "${enable_cmocka}" = "yes"])
AM_CONDITIONAL([GIT_CHECKOUT], [test "${GIT_CHECKOUT}" = "yes"])
AM_CONDITIONAL([ENABLE_FUZZING], [test "${enable_fuzzing}" = "yes"])
AM_CONDITIONAL([ENABLE_SHARED], [test "${enable_shared}" = "yes"])
AS_IF([test "${enable_shared}" = "yes"], [AC_DEFINE([ENABLE_SHARED], [1], [Enable shared libraries])])

if test "${enable_pedantic}" = "yes"; then
	enable_strict="yes";
	CFLAGS="-pedantic ${CFLAGS}"
fi
if test "${enable_strict}" = "yes"; then
	CFLAGS="-Wall -Wextra -Wno-unused-parameter -Werror -Wstrict-aliasing=2 ${CFLAGS}"
fi

AC_CONFIG_FILES([
	Makefile
	doc/Makefile
	doc/tools/Makefile
	doc/files/Makefile
	etc/Makefile
	tests/Makefile
	src/Makefile
	src/common/Makefile
	src/ui/Makefile
	src/libopensc/Makefile
	src/sm/Makefile
	src/pkcs11/Makefile
	src/pkcs11/versioninfo-pkcs11.rc
	src/pkcs11/versioninfo-pkcs11-spy.rc
	src/pkcs11/opensc-pkcs11.pc
	src/pkcs15init/Makefile
	src/scconf/Makefile
	src/tests/Makefile
	src/tests/regression/Makefile
	src/tests/p11test/Makefile
	src/tests/fuzzing/Makefile
	src/tests/unittests/Makefile
	src/tools/Makefile
	src/tools/versioninfo-tools.rc
	src/tools/versioninfo-opensc-notify.rc
	src/smm/Makefile
	src/minidriver/Makefile
	src/minidriver/versioninfo-minidriver.rc
	src/minidriver/opensc-minidriver.inf
	win32/Makefile
	win32/versioninfo.rc
	win32/versioninfo-customactions.rc
	win32/winconfig.h
	win32/OpenSC.iss
	win32/OpenSC.wxs
	MacOSX/Makefile
	MacOSX/build-package
	MacOSX/Distribution.xml
	MacOSX/resources/Welcome.html
])

AC_OUTPUT

cat <<EOF

OpenSC has been configured with the following options:


Version:                 ${PACKAGE_VERSION}
Version fix:             ${OPENSC_VERSION_FIX}
Version revision:        ${OPENSC_VERSION_REVISION}
Git revision:            ${OPENSC_SCM_REVISION}

Copyright:               ${OPENSC_VS_FF_LEGAL_COPYRIGHT}
Company:                 ${OPENSC_VS_FF_COMPANY_NAME}
Company URL:             ${OPENSC_VS_FF_COMPANY_URL}
Comments:                ${OPENSC_VS_FF_COMMENTS}
Product name:            ${OPENSC_VS_FF_PRODUCT_NAME}
Product updates:         ${OPENSC_VS_FF_PRODUCT_UPDATES}
Product URL:             ${OPENSC_VS_FF_PRODUCT_URL}

User binaries:           $(eval eval eval echo "${bindir}")
Configuration files:     $(eval eval eval echo "${sysconfdir}")
Bash completion:         ${completiondir}
XSL stylesheets:         ${xslstylesheetsdir}

man support:             ${enable_man}
doc support:             ${enable_doc}
thread locking support:  ${enable_thread_locking}
zlib support:            ${enable_zlib}
readline support:        ${enable_readline}
OpenSSL support:         ${enable_openssl}
OpenSSL secure memory:   ${enable_openssl_secure_malloc}
PC/SC support:           ${enable_pcsc}
CryptoTokenKit support:  ${enable_cryptotokenkit}
OpenCT support:          ${enable_openct}
CT-API support:          ${enable_ctapi}
minidriver support:      ${enable_minidriver}
SM support:              ${enable_sm}
SM default module:       ${DEFAULT_SM_MODULE}
SM default path:         $(eval eval eval echo "${DEFAULT_SM_MODULE_PATH}")
DNIe UI support:         ${enable_dnie_ui}
Notification support:    ${enable_notify}
Code coverage:           ${enable_code_coverage}

PC/SC default provider:  ${DEFAULT_PCSC_PROVIDER}
PKCS11 default provider: $(eval eval eval echo "${DEFAULT_PKCS11_PROVIDER}")
PKCS11 onepin provider:  $(eval eval eval echo "${DEFAULT_ONEPIN_PKCS11_PROVIDER}")

Host:                    ${host}
Compiler:                ${CC}
Preprocessor flags:      ${CPPFLAGS}
Compiler flags:          ${CFLAGS}
Linker flags:            ${LDFLAGS}
Libraries:               ${LIBS}

READLINE_CFLAGS:         ${READLINE_CFLAGS}
READLINE_LIBS:           ${READLINE_LIBS}
ZLIB_CFLAGS:             ${ZLIB_CFLAGS}
ZLIB_LIBS:               ${ZLIB_LIBS}
OPENSSL_CFLAGS:          ${OPENSSL_CFLAGS}
OPENSSL_LIBS:            ${OPENSSL_LIBS}
OPENPACE_CFLAGS:         ${OPENPACE_CFLAGS}
OPENPACE_LIBS:           ${OPENPACE_LIBS}
OPENCT_CFLAGS:           ${OPENCT_CFLAGS}
OPENCT_LIBS:             ${OPENCT_LIBS}
PCSC_CFLAGS:             ${PCSC_CFLAGS}
CRYPTOTOKENKIT_CFLAGS:   ${CRYPTOTOKENKIT_CFLAGS}
GIO2_CFLAGS:             ${GIO2_CFLAGS}
GIO2_LIBS:               ${GIO2_LIBS}
FUZZING_LIBS:            ${FUZZING_LIBS}

EOF

