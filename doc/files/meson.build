if progxsltproc.found() and stylesheets_path != ''
    opensc_conf_5_xml = configure_file(
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
        input: opensc_conf_5_xml,
        output: modfs.stem(opensc_conf_5_xml),
        build_by_default: get_option('man'),
        install: get_option('man'),
        install_dir: get_option('mandir') / 'man5'
    )

    pkcs15_profile_5_xml = configure_file(
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
        input: pkcs15_profile_5_xml,
        output: modfs.stem(pkcs15_profile_5_xml),
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
        depend_files: [opensc_conf_5_xml, pkcs15_profile_5_xml],
        build_by_default: get_option('doc'),
        install: get_option('doc'),
        install_dir: absolute_docdir
    )

    unset_variable('opensc_conf_5_xml')
    unset_variable('pkcs15_profile_5_xml')
endif
