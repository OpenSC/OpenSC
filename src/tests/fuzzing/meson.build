fuzzer_main = get_option('fuzzing_libs') == ''? files('fuzzer.c') : ''

fuzzers = {
    'fuzz_asn1_print':     files('fuzz_asn1_print.c'),
    'fuzz_asn1_sig_value': files('fuzz_asn1_sig_value.c'),

    'fuzz_card':           files('fuzz_card.c',
                                 'fuzzer_reader.c'),

    'fuzz_pkcs15_crypt':   files('fuzz_pkcs15_crypt.c',
                                 'fuzzer_reader.c',
                                 'fuzzer_tool.c',
                                 '../../tools/util.c'),

    'fuzz_pkcs15_decode':  files('fuzz_pkcs15_decode.c',
                                 'fuzzer_reader.c'),

    'fuzz_pkcs15_encode':  files('fuzz_pkcs15_encode.c',
                                 'fuzzer_reader.c'),

    'fuzz_pkcs15_reader':  files('fuzz_pkcs15_reader.c',
                                 'fuzzer_reader.c'),

    'fuzz_pkcs15_tool':    files('fuzz_pkcs15_tool.c',
                                 'fuzzer_reader.c',
                                 'fuzzer_tool.c',
                                 '../../pkcs11/pkcs11-display.c',
                                 '../../tools/util.c'),

    'fuzz_pkcs15init':     files('fuzz_pkcs15init.c',
                                 'fuzzer_reader.c'),

    'fuzz_scconf_parse_string': files('fuzz_scconf_parse_string.c')
}
if conf.get('ENABLE_OPENSSL')
    fuzzers += {
        'fuzz_piv_tool': files('fuzz_piv_tool.c',
                               'fuzzer_reader.c',
                               'fuzzer_tool.c',
                               '../../tools/util.c')
    }
endif

foreach fuzzer, sources : fuzzers
    executable(fuzzer,
        tests_targets,
        include_directories: core_inc,
        sources: [
            sources,
            fuzzer_main
        ],
        link_with: libopensc_static,
        link_args: get_option('fuzzing_libs')
    )
endforeach

if get_option('components').contains('pkcs11')
    executable('fuzz_pkcs11',
        tests_targets,
        include_directories: core_inc,
        sources: [
            files(
                'fuzz_pkcs11.c',
                'fuzzer_reader.c',
                'fuzzer_tool.c'
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
