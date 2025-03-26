if conf.get('ENABLE_OPENSSL')
    executable('p11test',
        tests_targets,
        include_directories: core_inc,
        sources: files(
            'p11test.c',
            'p11test_case_common.c',
            'p11test_case_ec_derive.c',
            'p11test_case_ec_sign.c',
            'p11test_case_interface.c',
            'p11test_case_mechs.c',
            'p11test_case_multipart.c',
            'p11test_case_pss_oaep.c',
            'p11test_case_readonly.c',
            'p11test_case_secret.c',
            'p11test_case_usage.c',
            'p11test_case_wait.c',
            'p11test_case_wrap.c',
            'p11test_helpers.c',
            'p11test_loader.c',
        ),
        link_with: libcompat,
        dependencies: [
            depcmocka,
            depopenssl
        ]
    )
endif
