MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

@VALGRIND_CHECK_RULES@
#VALGRIND_SUPPRESSIONS_FILES = opensc.supp
#EXTRA_DIST = opensc.supp
VALGRIND_FLAGS = --num-callers=30 -q --keep-debuginfo=yes --gen-suppressions=all
# Do not run the bash scripts under valgrind
TEST_EXTENSIONS = .sh
LOG_COMPILER = $(LOG_VALGRIND)

# This pushes the valgrind command to the test environment
# the LD_PRELOAD is to avoid false positive leaks from pcsclite
AM_TESTS_ENVIRONMENT = \
	SOURCE_PATH='$(top_srcdir)'; \
	export SOURCE_PATH; \
	BUILD_PATH='$(top_builddir)'; \
	export BUILD_PATH; \
	VALGRIND='$(LOG_VALGRIND)'; \
	LD_PRELOAD='/usr/lib/x86_64-linux-gnu/libpcsclite.so.1';

dist_noinst_SCRIPTS = common.sh \
                      test-manpage.sh \
                      test-duplicate-symbols.sh \
                      test-fuzzing.sh \
                      test-pkcs11-tool-test.sh \
                      test-pkcs11-tool-test-threads.sh \
                      test-pkcs11-tool-sign-verify.sh \
                      test-pkcs11-tool-allowed-mechanisms.sh \
                      test-pkcs11-tool-sym-crypt-test.sh \
                      test-pkcs11-tool-unwrap-wrap-test.sh \
                      test-pkcs11-tool-import.sh

.NOTPARALLEL:
TESTS = \
        test-manpage.sh \
        test-duplicate-symbols.sh \
        test-pkcs11-tool-sign-verify.sh \
        test-pkcs11-tool-test.sh \
        test-pkcs11-tool-test-threads.sh \
        test-pkcs11-tool-allowed-mechanisms.sh \
        test-pkcs11-tool-sym-crypt-test.sh \
        test-pkcs11-tool-unwrap-wrap-test.sh \
        test-pkcs11-tool-import.sh
XFAIL_TESTS = \
        test-pkcs11-tool-test-threads.sh \
        test-pkcs11-tool-test.sh
