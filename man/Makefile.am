# Process this file with automake to create Makefile.in

man1_MANS = $(shell ls *.1)
man3_MANS = $(shell ls *.3)
man5_MANS = $(shell ls *.5)

MAINTAINERCLEANFILES = Makefile.in $(man1_MANS) $(man3_MANS) $(man5_MANS)

EXTRA_DIST =  $(man1_MANS) $(man3_MANS) $(man5_MANS)
