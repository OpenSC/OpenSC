#!/bin/bash

set -e

export SERVER=http://www.opensc-project.org
export WIKI=opensc/wiki
export XSL=export-wiki.xsl

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

rm -rf "$SRCDIR"/*.html "$SRCDIR"/*.css

wget -nv $SERVER/$WIKI/TitleIndex -O "$SRCDIR"/TitleIndex.tmp

grep "\"/$WIKI/[^\"]*\"" "$SRCDIR"/TitleIndex.tmp \
        |sed -e "s#.*\"/$WIKI/\([^\"]*\)\".*#\1#g" \
	> "$SRCDIR"/WikiWords.tmp
sed -e /^Trac/d -e /^Wiki/d -e /^TitleIndex/d -e /^RecentChanges/d \
	-e /^CamelCase/d -e /^SandBox/d -i "$SRCDIR"/WikiWords.tmp

for A in WikiStart `cat "$SRCDIR"/WikiWords.tmp`
do
	F=`echo $A|sed -e 's/\//_/g'`
	wget -nv $SERVER/$WIKI/$A  -O "$SRCDIR"/$F.tmp
	xsltproc --nonet --output "$SRCDIR"/$F.html "$SRCDIR"/$XSL "$SRCDIR"/$F.tmp
	sed -e "s#<a href=\"/$WIKI/\([^\"]*\)\"#<a href=\"\1.html\"#g" \
		-i "$SRCDIR"/$F.html
done

mv "$SRCDIR"/WikiStart.html "$SRCDIR"/index.html

wget -nv http://www.opensc-project.org/trac/css/trac.css \
	-O "$SRCDIR"/trac.css

rm "$SRCDIR"/*.tmp
