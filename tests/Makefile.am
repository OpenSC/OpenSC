MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

dist_noinst_SCRIPTS = common.sh \
                      test-manpage.sh \
                      test-fuzzing.sh \
                      test-pkcs11-tool-test.sh \
                      test-pkcs11-tool-test-threads.sh \
                      test-pkcs11-tool-sign-verify.sh \
                      test-pkcs11-tool-allowed-mechanisms.sh

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
