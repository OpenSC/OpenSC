MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST = softhsm_ref.json

TEST_EXTENSIONS = .sh
# This pushes the valgrind command to the test environment
AM_TESTS_ENVIRONMENT = \
	SOURCE_PATH='$(top_srcdir)'; \
	export SOURCE_PATH; \
	BUILD_PATH='$(top_builddir)'; \
	export BUILD_PATH;

@VALGRIND_CHECK_RULES@
if VALGRIND_ENABLED
VALGRIND_SUPPRESSIONS_FILES = $(srcdir)/opensc.supp
EXTRA_DIST += opensc.supp
VALGRIND_FLAGS = --num-callers=30 -q --keep-debuginfo=yes --gen-suppressions=all
# Do not run the bash scripts under valgrind
LOG_COMPILER = $(LOG_VALGRIND)
# the LD_PRELOAD is to avoid false positive leaks from pcsclite
AM_TESTS_ENVIRONMENT += \
	VALGRIND='$(LOG_VALGRIND)'; \
	LD_PRELOAD='/usr/lib/x86_64-linux-gnu/libpcsclite.so.1';
endif

dist_noinst_SCRIPTS = common.sh \
                      test-manpage.sh \
                      test-duplicate-symbols.sh \
                      test-fuzzing.sh \
                      test-p11test.sh \
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
        test-pkcs11-tool-test.sh \
        test-pkcs11-tool-test-threads.sh \
        test-pkcs11-tool-allowed-mechanisms.sh \
        test-pkcs11-tool-sym-crypt-test.sh
if ENABLE_OPENSSL
TESTS += \
        test-pkcs11-tool-sign-verify.sh \
        test-pkcs11-tool-unwrap-wrap-test.sh \
        test-pkcs11-tool-import.sh
if ENABLE_TESTS
if ENABLE_SHARED
TESTS += test-p11test.sh
endif
endif
endif
XFAIL_TESTS = \
        test-pkcs11-tool-test-threads.sh \
        test-pkcs11-tool-test.sh
