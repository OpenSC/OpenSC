#!/bin/bash

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

cd "$SRCDIR"

rm -rf html
xsltproc --nonet --xinclude -o html/api.html api/html.xsl api/api.xml
xsltproc --nonet --xinclude -o ../man/ api/man.xsl api/api.xml
xsltproc --nonet --xinclude -o html/tools.html api/html.xsl tools/tools.xml
xsltproc --nonet --xinclude -o ../man/ api/man.xsl tools/tools.xml
