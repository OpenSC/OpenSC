sources = [
    'cardos-tool.1.xml',
    'dnie-tool.1.xml',
    'dtrust-tool.1.xml',
    'egk-tool.1.xml',
    'eidenv.1.xml',
    'goid-tool.1.xml',
    'iasecc-tool.1.xml',
    'openpgp-tool.1.xml',
    'opensc-asn1.1.xml',
    'opensc-explorer.1.xml',
    'opensc-tool.1.xml',
    'pkcs11-register.1.xml',
    'pkcs11-tool.1.xml',
    'pkcs15-crypt.1.xml',
    'pkcs15-tool.1.xml'
]

if conf.get('ENABLE_OPENSSL')
    sources += [
        'cryptoflex-tool.1.xml',
        'gids-tool.1.xml',
        'netkey-tool.1.xml',
        'piv-tool.1.xml',
        'pkcs15-init.1.xml',
        'sc-hsm-tool.1.xml',
        'westcos-tool.1.xml'
    ]

    if conf.get('ENABLE_OPENPACE')
        sources += [
            'npa-tool.1.xml'
        ]
    endif
endif

if conf.get('ENABLE_NOTIFY')
    sources += [
        'opensc-notify.1.xml'
    ]
endif

if progxsltproc.found() and stylesheets_path != ''
    foreach xml : sources
        custom_target(
            command: [progxsltproc,
                '--nonet',
                '--path', meson.project_source_root() / 'doc' + ':' + stylesheets_path / 'manpages',
                '--xinclude',
                '-o', '@OUTPUT@',
                'man.xsl',
                '@INPUT@'
            ],
            input: xml,
            output: modfs.replace_suffix(xml, ''),
            build_by_default: get_option('man'),
            install: get_option('man'),
            install_dir: get_option('mandir') / 'man1'
        )
    endforeach

    custom_target(
        command: [progxsltproc,
            '--nonet',
            '--path', meson.project_source_root() / 'doc' + ':' + stylesheets_path / 'html',
            '--xinclude',
            '-o', '@OUTPUT@',
            'html.xsl',
            '@INPUT@'
        ],
        input: 'tools.xml',
        output: 'tools.html',
        depend_files: sources,
        build_by_default: get_option('doc'),
        install: get_option('doc'),
        install_dir: absolute_docdir
    )
endif

if bash_completion_path != ''
    foreach xml : sources
        custom_target(
            command: ['generate_completion.sh', '@INPUT0@', '@INPUT1@', '@OUTPUT@'],
            input: ['completion-template', xml],
            output: modfs.replace_suffix(modfs.replace_suffix(xml, ''), ''),
            build_by_default: get_option('bash_completion'),
            install: get_option('bash_completion'),
            install_dir: bash_completion_path
        )
    endforeach
endif

unset_variable('sources')
