MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_TESTS_ENVIRONMENT = \
	SOURCE_PATH='$(top_srcdir)'; \
	export SOURCE_PATH; \
	BUILD_PATH='$(top_builddir)'; \
	export BUILD_PATH;

dist_noinst_SCRIPTS = common.sh \
                      test-manpage.sh \
                      test-duplicate-symbols.sh \
                      test-fuzzing.sh \
                      test-pkcs11-tool-test.sh \
                      test-pkcs11-tool-test-threads.sh \
                      test-pkcs11-tool-sign-verify.sh \
                      test-pkcs11-tool-allowed-mechanisms.sh

.NOTPARALLEL:
TESTS = \
        test-manpage.sh \
        test-duplicate-symbols.sh \
        test-pkcs11-tool-sign-verify.sh \
        test-pkcs11-tool-test.sh \
        test-pkcs11-tool-test-threads.sh \
        test-pkcs11-tool-allowed-mechanisms.sh
XFAIL_TESTS = \
        test-pkcs11-tool-test-threads.sh \
        test-pkcs11-tool-test.sh
