libtest = static_library('common',
    include_directories: core_inc,
    sources: files('sc-test.c'),
    link_with: libopensc
)

tests_targets = []
if host_machine.system() == 'windows' or host_machine.system() == 'cygwin'
    tests_targets += modwindows.compile_resources(
        configure_file(
            configuration: conf_aux,
            input: meson.project_source_root() / 'win32' / 'versioninfo.rc.in',
            output: 'versioninfo.rc'
        )
    )
endif


executable('base64',
    tests_targets,
    include_directories: core_inc,
    sources: files('base64.c'),
    link_with: [
        libopensc,
        libtest
    ]
)

executable('lottery',
    tests_targets,
    include_directories: core_inc,
    sources: files('lottery.c'),
    link_with: [
        libopensc,
        libtest
    ]
)

executable('p15dump',
    tests_targets,
    include_directories: core_inc,
    sources: files(
        'p15dump.c',
        'print.c'
    ),
    link_with: [
        libopensc,
        libtest
    ]
)

executable('pintest',
    tests_targets,
    include_directories: core_inc,
    sources: files(
        'pintest.c',
        'print.c'
    ),
    link_with: [
        libcompat,
        libopensc,
        libtest
    ]
)

executable('prngtest',
    tests_targets,
    include_directories: core_inc,
    sources: files('prngtest.c'),
    link_with: [
        libopensc,
        libtest
    ]
)

#################################################
# Unit tests
#################################################
ut_asn1 = executable('asn1',
    include_directories: core_inc,
    sources: files('unittests' / 'asn1.c'),
    link_with: [
        libopensc,
        libopensc_libraries
    ],
    dependencies: [
        depcmocka,
        libopensc_dependencies
    ]
)
test('asn1', ut_asn1)

ut_cachedir = executable('cachedir',
    include_directories: core_inc,
    sources: files('unittests' / 'cachedir.c'),
    link_with: libopensc,
    dependencies: depcmocka
)
test('cachedir', ut_cachedir)

ut_check_macro_reference_loop = executable('check_macro_reference_loop',
    include_directories: core_inc,
    sources: files('unittests' / 'check_macro_reference_loop.c'),
    link_with: [
        libopensc,
        libopensc_libraries
    ],
    dependencies: [
        depcmocka,
        libopensc_dependencies
    ]
)
test('check_macro_reference_loop', ut_check_macro_reference_loop)

ut_decode_ecdsa_signature = executable('decode_ecdsa_signature',
    include_directories: core_inc,
    sources: files('unittests' / 'decode_ecdsa_signature.c'),
    link_with: [
        libopensc,
        libopensc_libraries
    ],
    dependencies: [
        depcmocka,
        libopensc_dependencies
    ]
)
test('decode_ecdsa_signature', ut_decode_ecdsa_signature)

ut_hextobin = executable('hextobin',
    include_directories: core_inc,
    sources: files('unittests' / 'hextobin.c'),
    link_with: libopensc,
    dependencies: depcmocka
)
test('hextobin', ut_hextobin)

ut_openpgp_tool = executable('openpgp-tool',
    include_directories: core_inc,
    sources: files(
        'unittests' / 'openpgp-tool.c',
        '../tools/openpgp-tool-helpers.c'
    ),
    link_with: [
        libopensc,
        libopensc_libraries
    ],
    dependencies: [
        depcmocka,
        libopensc_dependencies
    ]
)
test('openpgp-tool', ut_openpgp_tool)

ut_pkcs15filter = executable('pkcs15filter',
    include_directories: core_inc,
    sources: files('unittests' / 'pkcs15-emulator-filter.c'),
    link_with: [
        libopensc,
        libopensc_libraries
    ],
    dependencies: [
        depcmocka,
        libopensc_dependencies
    ]
)
test('pkcs15filter', ut_pkcs15filter)

ut_simpletlv = executable('simpletlv',
    include_directories: core_inc,
    sources: files('unittests' / 'simpletlv.c'),
    link_with: [
        libopensc,
        libopensc_libraries
    ],
    dependencies: [
        depcmocka,
        libopensc_dependencies
    ]
)
test('simpletlv', ut_simpletlv)

ut_strip_pkcs1_2_padding = executable('strip_pkcs1_2_padding',
    include_directories: core_inc,
    sources: files('unittests' / 'strip_pkcs1_2_padding.c'),
    link_with: [
        libopensc,
        libopensc_libraries
    ],
    dependencies: [
        depcmocka,
        libopensc_dependencies
    ]
)
test('strip_pkcs1_2_padding', ut_strip_pkcs1_2_padding)

if conf.get('ENABLE_OPENSSL')
    ut_sm = executable('sm',
        include_directories: core_inc,
        sources: files('unittests' / 'sm.c'),
        link_with: [
            libopensc,
            libopensc_libraries,
            libsm
        ],
        dependencies: [
            depcmocka,
            libopensc_dependencies
        ]
    )
    test('sm', ut_sm)
endif

if conf.get('ENABLE_ZLIB')
    ut_compression = executable('compression',
        include_directories: core_inc,
        sources: files('unittests' / 'compression.c'),
        link_with: [
            libopensc,
            libopensc_libraries
        ],
        dependencies: [
            depcmocka,
            libopensc_dependencies
        ]
    )
    test('compression', ut_compression)
endif

#################################################
# p11test
#################################################
if conf.get('ENABLE_OPENSSL')
    executable('p11test',
        tests_targets,
        include_directories: core_inc,
        sources: files(
            'p11test' / 'p11test.c',
            'p11test' / 'p11test_case_common.c',
            'p11test' / 'p11test_case_ec_derive.c',
            'p11test' / 'p11test_case_ec_sign.c',
            'p11test' / 'p11test_case_interface.c',
            'p11test' / 'p11test_case_mechs.c',
            'p11test' / 'p11test_case_multipart.c',
            'p11test' / 'p11test_case_pss_oaep.c',
            'p11test' / 'p11test_case_readonly.c',
            'p11test' / 'p11test_case_secret.c',
            'p11test' / 'p11test_case_usage.c',
            'p11test' / 'p11test_case_wait.c',
            'p11test' / 'p11test_case_wrap.c',
            'p11test' / 'p11test_helpers.c',
            'p11test' / 'p11test_loader.c',
        ),
        dependencies: [
            depcmocka,
            depopenssl
        ]
    )
endif

#################################################
# Fuzzing tests
#################################################
fuzzer_main = get_option('fuzzing_libs') == ''? files('fuzzing' / 'fuzzer.c') : ''

fuzzers = {
    'fuzz_asn1_print':     files('fuzzing' / 'fuzz_asn1_print.c'),
    'fuzz_asn1_sig_value': files('fuzzing' / 'fuzz_asn1_sig_value.c'),
    'fuzz_card':           files(
        'fuzzing' / 'fuzz_card.c',
        'fuzzing' / 'fuzzer_reader.c'
    ),
    'fuzz_pkcs15_crypt':   files(
        'fuzzing' / 'fuzz_pkcs15_crypt.c',
        'fuzzing' / 'fuzzer_reader.c',
        'fuzzing' / 'fuzzer_tool.c',
        '..' / 'tools' / 'util.c'
    ),
    'fuzz_pkcs15_decode':  files(
        'fuzzing' / 'fuzz_pkcs15_decode.c',
        'fuzzing' / 'fuzzer_reader.c'
    ),
    'fuzz_pkcs15_encode':  files(
        'fuzzing' / 'fuzz_pkcs15_encode.c',
        'fuzzing' / 'fuzzer_reader.c'
    ),
    'fuzz_pkcs15_reader':  files(
        'fuzzing' / 'fuzz_pkcs15_reader.c',
        'fuzzing' / 'fuzzer_reader.c'
    ),
    'fuzz_pkcs15_tool':    files(
        'fuzzing' / 'fuzz_pkcs15_tool.c',
        'fuzzing' / 'fuzzer_reader.c',
        'fuzzing' / 'fuzzer_tool.c',
        '..' / 'pkcs11' / 'pkcs11-display.c',
        '..' / 'tools' / 'util.c'
    ),
    'fuzz_pkcs15init':     files(
        'fuzzing' / 'fuzz_pkcs15init.c',
        'fuzzing' / 'fuzzer_reader.c'
    ),
    'fuzz_scconf_parse_string': files('fuzzing' / 'fuzz_scconf_parse_string.c')
}
if conf.get('ENABLE_OPENSSL')
    fuzzers += {
        'fuzz_piv_tool': files(
            'fuzzing' / 'fuzz_piv_tool.c',
            'fuzzing' / 'fuzzer_reader.c',
            'fuzzing' / 'fuzzer_tool.c',
            '..' / 'tools' / 'util.c'
        )
    }
endif

foreach fuzzer, sources : fuzzers
    executable(fuzzer,
        include_directories: core_inc,
        sources: [
            sources,
            fuzzer_main
        ],
        link_with: [
            libopensc,
            libopensc_libraries
        ],
        link_args: get_option('fuzzing_libs'),
        dependencies: libopensc_dependencies
    )
endforeach

if get_option('components').contains('pkcs11')
    executable('fuzz_pkcs11',
        include_directories: core_inc,
        sources: [
            files(
                'fuzzing' / 'fuzz_pkcs11.c',
                'fuzzing' / 'fuzzer_reader.c',
                'fuzzing' / 'fuzzer_tool.c'
            ),
            fuzzer_main
        ],
        link_with: [
            libpkcs11,
            libpkcs11_libraries
        ],
        link_args: get_option('fuzzing_libs'),
        dependencies: libpkcs11_dependencies
    )
endif
