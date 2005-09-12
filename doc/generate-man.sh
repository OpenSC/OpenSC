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

xsltproc --xinclude -o html/api.html api/html.xsl api/api.xml
xsltproc --xinclude -o ../man/ api/man.xsl api/api.xml
xsltproc --xinclude -o html/tools.html api/html.xsl tools/tools.xml
xsltproc --xinclude -o ../man/ api/man.xsl tools/api.xml
