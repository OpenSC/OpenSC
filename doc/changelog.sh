#!/bin/sh

# based on svn2cl.sh # Copyright (C) 2005 Arthur de Jong.

set -e

SRCDIR=.

if test -n "$1"
then
	SRCDIR="$1"
fi

test -f "$SRCDIR"/`basename $0`

if ! test -w "$SRCDIR"
then
	exit 0
fi

rm -rf "$SRCDIR"/ChangeLog
cd "$SRCDIR"/..

svn --verbose --xml log | \
  xsltproc --nonet --stringparam linelen 75 \
           --stringparam groupbyday no \
           --stringparam include-rev no \
           doc/svn2cl.xsl - > doc/ChangeLog
