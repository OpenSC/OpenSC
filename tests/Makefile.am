MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

dist_noinst_SCRIPTS = test-manpage.sh \
                      test-fuzzing.sh \
                      test-pkcs11-tool-test.sh \
                      test-pkcs11-tool-sign-verify.sh

TESTS = \
	test-manpage.sh \
        test-pkcs11-tool-sign-verify.sh \
        test-pkcs11-tool-test.sh \
        test-pkcs11-tool-allowed-mechanisms.sh
XFAIL_TESTS = \
        test-pkcs11-tool-test.sh \
        test-pkcs11-tool-allowed-mechanisms.sh
