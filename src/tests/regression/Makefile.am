MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

dist_check_DATA = \
	crypt0001 crypt0002 crypt0003 crypt0004 crypt0005 crypt0006 crypt0007 \
	init0001 init0002 init0003 init0004 init0005 init0006 \
	init0007 init0008 init0009 init0010 init0011 init0012 \
	pin0001 pin0002 \
	README test.p12 bintest
dist_check_SCRIPTS = erase functions run-all 

# remove log files from regression tests
clean-local:
	-rm -rf out failed
