executable('opensc-tool', 'opensc-tool.c', 'util.c',
    include_directories: core_inc,
    link_with: [opensc_lib, scconf_lib],
    install: true,
)

executable('opensc-explorer', 'opensc-explorer.c', 'util.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    dependencies: [readline_dep],
    install: true,
)

executable('opensc-asn1', 'opensc-asn1.c', 'fread_to_eof.c', 'opensc-asn1-cmdline.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
)

executable('pkcs15-tool', 'pkcs15-tool.c', 'util.c', '../pkcs11/pkcs11-display.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    dependencies: [openssl_dep],
    install: true,
)

executable('pkcs15-crypt', 'pkcs15-crypt.c', 'util.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    dependencies: [openssl_dep],
    install: true,
)

executable('pkcs11-tool', 'pkcs11-tool.c', 'util.c',
    include_directories: core_inc,
    link_with: [opensc_lib, pkcs11_lib, pkcs11_mod],
    dependencies: [openssl_dep],
    install: true,
)

executable('pkcs11-register', 'pkcs11-register.c', 'fread_to_eof.c', 'pkcs11-register-cmdline.c',
    include_directories: core_inc,
    link_with: [pkcs11_lib, scdl_lib],
    dependencies: [openssl_dep],
    install: true,
)

executable('cardos-tool', 'cardos-tool.c', 'util.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    dependencies: [openssl_dep],
    install: true,
)

executable('eidenv', 'eidenv.c',  'util.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    dependencies: [],
    install: true,
)

executable('openpgp-tool', 'openpgp-tool.c',  'util.c', 'openpgp-tool-helpers.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    dependencies: [],
    install: true,
)

executable('iasecc-tool', 'iasecc-tool.c',  'util.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    dependencies: [],
    install: true,
)

executable('egk-tool', 'egk-tool.c',  'util.c', 'egk-tool-cmdline.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    dependencies: [zlib_dep],
    install: true,
)

executable('goid-tool', 'goid-tool.c',  'util.c', 'goid-tool-cmdline.c', 'fread_to_eof.c',
    include_directories: core_inc,
    link_with: [opensc_lib],
    dependencies: [openssl_dep, openpace_dep],
    install: true,
)

if openssl_dep.found()
    executable('cryptoflex-tool', 'cryptoflex-tool.c', 'util.c',
        include_directories: core_inc,
        link_with: [opensc_lib],
        dependencies: [openssl_dep],
        install: true,
    )

    executable('pkcs15-init', 'pkcs15-init.c', 'util.c',
        include_directories: core_inc,
        link_with: [opensc_lib],
        dependencies: [openssl_dep],
        install: true,
    )

    executable('netkey-tool', 'netkey-tool.c',
        include_directories: core_inc,
        link_with: [opensc_lib],
        dependencies: [openssl_dep],
        install: true,
    )

    executable('piv-tool', 'piv-tool.c', 'util.c',
        include_directories: core_inc,
        link_with: [opensc_lib],
        dependencies: openssl_dep,
        install: true,
    )

    executable('westcos-tool', 'westcos-tool.c', 'util.c',
        include_directories: core_inc,
        link_with: [opensc_lib],
        dependencies: openssl_dep,
        install: true,
    )

    executable('sc-hsm-tool', 'sc-hsm-tool.c', 'util.c', 'fread_to_eof.c',
        include_directories: core_inc,
        link_with: [opensc_lib],
        dependencies: openssl_dep,
        install: true,
    )

    executable('dnie-tool', 'dnie-tool.c', 'util.c',
        include_directories: core_inc,
        link_with: [opensc_lib],
        dependencies: openssl_dep,
        install: true,
    )

    executable('gids-tool', 'gids-tool.c', 'util.c',
        include_directories: core_inc,
        link_with: [opensc_lib],
        dependencies: openssl_dep,
        install: true,
    )
endif

if openpace_dep.found()
    executable('npa-tool', 'npa-tool.c', 'fread_to_eof.c', 'util.c', 'npa-tool-cmdline.c',
        include_directories: core_inc,
        link_with: [opensc_lib],
        dependencies: [openssl_dep, openpace_dep],
    )

    executable('sceac-example.c', 'sceac-example.c',
        include_directories: core_inc,
        link_with: [opensc_lib],
        dependencies: [openssl_dep, openpace_dep],
    )
endif
