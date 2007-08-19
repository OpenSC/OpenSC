dnl Autoconf macros for libassuan
dnl       Copyright (C) 2002, 2003 Free Software Foundation, Inc.
dnl
dnl This file is free software; as a special exception the author gives
dnl unlimited permission to copy and/or distribute it, with or without
dnl modifications, as long as this notice is preserved.
dnl
dnl This file is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
dnl implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

dnl
dnl Common code used for libassuan detection [internal]
dnl Returns ok set to yes or no.
dnl
AC_DEFUN([_AM_PATH_LIBASSUAN_COMMON],
[ AC_ARG_WITH(libassuan-prefix,
              AC_HELP_STRING([--with-libassuan-prefix=PFX],
                             [prefix where LIBASSUAN is installed (optional)]),
     libassuan_config_prefix="$withval", libassuan_config_prefix="")
  if test x$libassuan_config_prefix != x ; then
    libassuan_config_args="$libassuan_config_args --prefix=$libassuan_config_prefix"
    if test x${LIBASSUAN_CONFIG+set} != xset ; then
      LIBASSUAN_CONFIG=$libassuan_config_prefix/bin/libassuan-config
    fi
  fi
  AC_PATH_PROG(LIBASSUAN_CONFIG, libassuan-config, no)

  tmp=ifelse([$1], ,1:0.9.2,$1)
  if echo "$tmp" | grep ':' >/dev/null 2>/dev/null ; then
    req_libassuan_api=`echo "$tmp"     | sed 's/\(.*\):\(.*\)/\1/'`
    min_libassuan_version=`echo "$tmp" | sed 's/\(.*\):\(.*\)/\2/'`
  else
    req_libassuan_api=0
    min_libassuan_version="$tmp"
  fi

  if test "$LIBASSUAN_CONFIG" != "no" ; then
    libassuan_version=`$LIBASSUAN_CONFIG --version`
  fi
  libassuan_version_major=`echo $libassuan_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
  libassuan_version_minor=`echo $libassuan_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
  libassuan_version_micro=`echo $libassuan_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`

  AC_MSG_CHECKING(for LIBASSUAN ifelse([$2], ,,[$2 ])- version >= $min_libassuan_version)
  ok=no
  if test "$LIBASSUAN_CONFIG" != "no" ; then
    ifelse([$2], ,,[if `$LIBASSUAN_CONFIG --thread=$2 2> /dev/null` ; then])
    req_major=`echo $min_libassuan_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\1/'`
    req_minor=`echo $min_libassuan_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\2/'`
    req_micro=`echo $min_libassuan_version | \
               sed 's/\([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\)/\3/'`
    if test "$libassuan_version_major" -gt "$req_major"; then
        ok=yes
    else 
        if test "$libassuan_version_major" -eq "$req_major"; then
            if test "$libassuan_version_minor" -gt "$req_minor"; then
               ok=yes
            else
               if test "$libassuan_version_minor" -eq "$req_minor"; then
                   if test "$libassuan_version_micro" -ge "$req_micro"; then
                     ok=yes
                   fi
               fi
            fi
        fi
    fi
    ifelse([$2], ,,[fi])
  fi

  if test $ok = yes; then
    AC_MSG_RESULT(yes)
  else
    AC_MSG_RESULT(no)
  fi

  if test $ok = yes; then
    if test "$req_libassuan_api" -gt 0 ; then
      tmp=`$LIBASSUAN_CONFIG --api-version 2>/dev/null || echo 0`
      if test "$tmp" -gt 0 ; then
        AC_MSG_CHECKING([LIBASSUAN ifelse([$2], ,,[$2 ])API version])
        if test "$req_libassuan_api" -eq "$tmp" ; then
          AC_MSG_RESULT(okay)
        else
          ok=no
          AC_MSG_RESULT([does not match.  want=$req_libassuan_api got=$tmp.])
        fi
      fi
    fi
  fi

])



dnl AM_PATH_LIBASSUAN([MINIMUM-VERSION,
dnl                   [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libassuan and define LIBASSUAN_CFLAGS and LIBASSUAN_LIBS
dnl
AC_DEFUN([AM_PATH_LIBASSUAN],
[ _AM_PATH_LIBASSUAN_COMMON($1)
  if test $ok = yes; then
    LIBASSUAN_CFLAGS=`$LIBASSUAN_CONFIG $libassuan_config_args --cflags`
    LIBASSUAN_LIBS=`$LIBASSUAN_CONFIG $libassuan_config_args --libs`
    ifelse([$2], , :, [$2])
  else
    LIBASSUAN_CFLAGS=""
    LIBASSUAN_LIBS=""
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBASSUAN_CFLAGS)
  AC_SUBST(LIBASSUAN_LIBS)
])


dnl AM_PATH_LIBASSUAN_PTH([MINIMUM-VERSION,
dnl                      [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libassuan and define LIBASSUAN_PTH_CFLAGS and LIBASSUAN_PTH_LIBS
dnl
AC_DEFUN([AM_PATH_LIBASSUAN_PTH],
[ _AM_PATH_LIBASSUAN_COMMON($1,pth)
  if test $ok = yes; then
    LIBASSUAN_PTH_CFLAGS=`$LIBASSUAN_CONFIG $libassuan_config_args --thread=pth --cflags`
    LIBASSUAN_PTH_LIBS=`$LIBASSUAN_CONFIG $libassuan_config_args --thread=pth --libs`
    ifelse([$2], , :, [$2])
  else
    LIBASSUAN_PTH_CFLAGS=""
    LIBASSUAN_PTH_LIBS=""
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBASSUAN_PTH_CFLAGS)
  AC_SUBST(LIBASSUAN_PTH_LIBS)
])


dnl AM_PATH_LIBASSUAN_PTHREAD([MINIMUM-VERSION,
dnl                           [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for libassuan and define LIBASSUAN_PTHREAD_CFLAGS 
dnl                           and LIBASSUAN_PTHREAD_LIBS
dnl
AC_DEFUN([AM_PATH_LIBASSUAN_PTHREAD],
[ _AM_PATH_LIBASSUAN_COMMON($1,pthread)
  if test $ok = yes; then
    LIBASSUAN_PTHREAD_CFLAGS=`$LIBASSUAN_CONFIG $libassuan_config_args --thread=pthread --cflags`
    LIBASSUAN_PTHREAD_LIBS=`$LIBASSUAN_CONFIG $libassuan_config_args --thread=pthread --libs`
    ifelse([$2], , :, [$2])
  else
    LIBASSUAN_PTHREAD_CFLAGS=""
    LIBASSUAN_PTHREAD_LIBS=""
    ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LIBASSUAN_PTHREAD_CFLAGS)
  AC_SUBST(LIBASSUAN_PTHREAD_LIBS)
])

