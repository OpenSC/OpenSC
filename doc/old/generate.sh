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

	xsltproc -o "$SRCDIR"/opensc.html "$SRCDIR"/opensc.xsl "$SRCDIR/"opensc.xml
	tidy -im -utf8 -xml "$SRCDIR"/opensc.html || true
	xsltproc -o "$SRCDIR"/opensc-es.html "$SRCDIR"/opensc.xsl "$SRCDIR"/opensc-es.xml
	tidy -im -utf8 -xml "$SRCDIR"/opensc-es.html || true
