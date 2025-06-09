foreach name, sources : {
    'asn1':                  files('asn1.c'),
    'cachedir':              files('cachedir.c'),
    'check_macro_reference_loop': files('check_macro_reference_loop.c'),
    'decode_ecdsa_signature': files('decode_ecdsa_signature.c'),
    'hextobin':              files('hextobin.c'),
    'openpgp-tool':          files('openpgp-tool.c', '../../tools/openpgp-tool-helpers.c'),
    'pkcs15filter':          files('pkcs15-emulator-filter.c'),
    'simpletlv':             files('simpletlv.c'),
    'strip_pkcs1_2_padding': files('strip_pkcs1_2_padding.c'),
}

ut = executable(name,
    tests_targets,
    include_directories: core_inc,
    sources: sources,
    link_with: libopensc_static,
    dependencies: depcmocka
)
test(name, ut)
endforeach

if conf.get('ENABLE_OPENSSL')
    ut_sm = executable('sm',
        tests_targets,
        include_directories: core_inc,
        sources: files('sm.c'),
        link_with: [
            libopensc_static,
            libsm
        ],
        dependencies: depcmocka
    )
    test('sm', ut_sm)
endif

if conf.get('ENABLE_ZLIB')
    ut_compression = executable('compression',
        tests_targets,
        include_directories: core_inc,
        sources: files('compression.c'),
        link_with: libopensc_static,
        dependencies: depcmocka
    )
    test('compression', ut_compression)
endif
