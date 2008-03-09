#!/bin/sh

set -e

test -z "$XSLTPROC" && XSLTPROC="xsltproc"
test -z "$WGET" && WGET="wget"
test -z "$WGET_OPTS" && WGET_OPTS="$WGET_OPTS"
test -z "$SED" && SED="sed"
test -z "$TR" && TR="tr"

test -z "$SERVER" && SERVER="http://www.opensc-project.org"
test -z "$PROJECT" && PROJECT="opensc"

SRCDIR=.
OUTDIR=.
test -n "$1" && SRCDIR="$1"
test -n "$2" &&	OUTDIR="$2"

WIKI="$PROJECT/wiki"
XSL="$SRCDIR/export-wiki.xsl"

test -f "$SRCDIR"/`basename $0`

test -e "$OUTDIR" && rm -fr "$OUTDIR"

mkdir "$OUTDIR" || exit 1

$WGET $WGET_OPTS $SERVER/$WIKI/TitleIndex -O "$OUTDIR"/TitleIndex.tmp

$SED -e "s#</li>#</li>\n#g" < "$OUTDIR"/TitleIndex.tmp \
	| grep "\"/$WIKI/[^\"]*\"" \
        |$SED -e "s#.*\"/$WIKI/\([^\"]*\)\".*#\1#g" \
	> "$OUTDIR"/WikiWords.tmp
$SED -e /^Trac/d -e /^Wiki/d -e /^TitleIndex/d -e /^RecentChanges/d \
	-e /^CamelCase/d -e /^SandBox/d -i "$OUTDIR"/WikiWords.tmp

for A in WikiStart `cat "$OUTDIR"/WikiWords.tmp`
do
	F=`echo $A|$SED -e 's/\//_/g'`
	$WGET $WGET_OPTS $SERVER/$WIKI/$A  -O "$OUTDIR"/$F.tmp
	$XSLTPROC --nonet --output "$OUTDIR"/$F.html "$XSL" "$OUTDIR"/$F.tmp
	$SED -e "s#<a href=\"/$WIKI/\([^\"]*\)\"#<a href=\"\1.html\"#g" \
		-i "$OUTDIR"/$F.html
done

mv "$OUTDIR"/WikiStart.html "$OUTDIR"/index.html

$WGET $WGET_OPTS http://www.opensc-project.org/trac/css/trac.css \
	-O "$OUTDIR"/trac.css

cat "$OUTDIR"/*.html |grep "<img src=\"/$PROJECT/attachment/wiki" \
	|$SED -e 's/.*<img src="\/'$PROJECT'\/attachment\/wiki\/\([^"]*\)?format=raw".*/\1/g' \
	|sort -u |while read A
do
	B="`echo $A |$TR / _`"
	$WGET $WGET_OPTS "$SERVER/$PROJECT/attachment/wiki/$A?format=raw" -O "$OUTDIR"/$B
	for C in "${OUTDIR}"/*.html
	do
		$SED -e 's#\/'$PROJECT'\/attachment\/wiki\/'$A'?format=raw#'$B'#g' -i "$C"
	done
done

for A in "${OUTDIR}"/*.html
do
	$SED -e 's#href="/'$PROJECT'/wiki/\([^"]*\)"#href="\1.html"#g' \
		-i $A
done

rm "$OUTDIR"/*.tmp
exit 0
