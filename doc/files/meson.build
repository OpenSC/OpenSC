if progxsltproc.found() and stylesheets_path != ''
    xml1 = configure_file(
        configuration: {
            'sysconfdir': absolute_sysconfdir,
            'docdir': absolute_docdir,
            'libdir': absolute_libdir / '',
            'DYN_LIB_EXT': '.' + extension_of_libraries,
            'DEFAULT_PCSC_PROVIDER': conf.get_unquoted('DEFAULT_PCSC_PROVIDER'),
            'PROFILE_DIR_DEFAULT': host_machine.system() == 'windows'? 'obtained from windows registers' : absolute_pkgdir,
            'DEFAULT_SM_MODULE': conf.get_unquoted('DEFAULT_SM_MODULE')
        },
        input: 'opensc.conf.5.xml.in',
        output: 'opensc.conf.5.xml'
    )

    custom_target(
        command: [progxsltproc,
            '--nonet',
            '--path', meson.project_source_root() / 'doc' + ':' + stylesheets_path / 'manpages',
            '--xinclude',
            '-o', '@OUTPUT@',
            'man.xsl',
            '@INPUT@'
        ],
        input: xml1,
        output: modfs.stem(xml1),
        build_by_default: get_option('man'),
        install: get_option('man'),
        install_dir: get_option('mandir') / 'man5'
    )

    xml2 = configure_file(
        configuration: {'pkgdatadir': absolute_pkgdir},
        input: 'pkcs15-profile.5.xml.in',
        output: 'pkcs15-profile.5.xml'
    )

    custom_target(
        command: [progxsltproc,
            '--nonet',
            '--path', meson.project_source_root() / 'doc' + ':' + stylesheets_path / 'manpages',
            '--xinclude',
            '-o', '@OUTPUT@',
            'man.xsl',
            '@INPUT@'
        ],
        input: xml2,
        output: modfs.stem(xml2),
        build_by_default: get_option('man'),
        install: get_option('man'),
        install_dir: get_option('mandir') / 'man5'
    )

    custom_target(
        command: [progxsltproc,
            '--nonet',
            '--path', meson.current_build_dir() + ':' +
                      meson.project_source_root() / 'doc' + ':' +
                      stylesheets_path / 'html',
            '--xinclude',
            '-o', '@OUTPUT@',
            'html.xsl',
            '@INPUT@'
        ],
        input: 'files.xml',
        output: 'files.html',
        depend_files: [xml1, xml2],
        build_by_default: get_option('doc'),
        install: get_option('doc'),
        install_dir: absolute_docdir
    )

    unset_variable('xml1')
    unset_variable('xml2')
endif
