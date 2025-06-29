conf_tools = configuration_data()
conf_tools.set('bindir', absolute_bindir)
conf_tools.set('CVCDIR', conf.get_unquoted('CVCDIR'))
conf_tools.set('X509DIR', conf.get_unquoted('X509DIR'))
conf_tools.set('PACKAGE_NAME', conf.get_unquoted('PACKAGE_NAME'))
conf_tools.set('PACKAGE_VERSION', conf.get_unquoted('PACKAGE_VERSION'))
conf_tools.set('PACKAGE_BUGREPORT', conf.get_unquoted('PACKAGE_BUGREPORT'))
conf_tools.set('PACKAGE_TARNAME', conf.get_unquoted('PACKAGE_TARNAME'))
conf_tools.set('PACKAGE_URL', conf.get_unquoted('PACKAGE_URL'))
conf_tools.set('PACKAGE_SUMMARY', conf.get_unquoted('PACKAGE_SUMMARY'))
conf_tools.set('DEFAULT_PKCS11_PROVIDER', conf.get_unquoted('DEFAULT_PKCS11_PROVIDER'))
conf_tools.set('PKCS11_REGISTER_SKIP_FIREFOX', conf.get('PKCS11_REGISTER_SKIP_FIREFOX'))
conf_tools.set('VDFORMAT', conf.get('ENABLE_ZLIB')? 'XML' : 'GZIP')

tools_targets = []
if host_machine.system() == 'windows' or host_machine.system() == 'cygwin'
    tools_targets += modwindows.compile_resources(
        'tools.rc',
        include_directories: core_inc,
        depend_files: 'tools.manifest'
    )
endif

tools_args = meson.get_compiler('c').get_supported_arguments(
    '-Wno-unknown-warning-option'
)

gengetopt = generator(proggengetopt,
    arguments: [
        '--input=@INPUT@',
        '--set-version=' + meson.project_version(),
        '--output-dir=@BUILD_DIR@',
        '--file-name=@BASENAME@-cmdline'
    ],
    output: ['@BASENAME@-cmdline.h', '@BASENAME@-cmdline.c']
)

libtool = static_library('tool',
    include_directories: core_inc,
    sources: files(
        'fread_to_eof.c',
        'util.c'
    ),
    link_with: [
        libcompat,
        get_option('static_components').contains('tools')? libopensc_static : libopensc
    ]
)


foreach name, sources : {
    'dnie-tool':   files('dnie-tool.c'),
    'dtrust-tool': files('dtrust-tool.c'),
    'eidenv':      files('eidenv.c'),
    'iasecc-tool': files('iasecc-tool.c')
}

executable(name,
    tools_targets,
    include_directories: core_inc,
    sources: sources,
    link_with: libtool,
    install: true
)
endforeach


foreach name, sources : {
    'cardos-tool':   files('cardos-tool.c'),
    'openpgp-tool':  files('openpgp-tool.c', 'openpgp-tool-helpers.c'),
    'pkcs15-crypt':  files('pkcs15-crypt.c'),
    'pkcs15-tool':   files('pkcs15-tool.c', '../pkcs11/pkcs11-display.c')
}

executable(name,
    tools_targets,
    include_directories: core_inc,
    sources: sources,
    link_with: libtool,
    dependencies: depopenssl,
    install: true
)
endforeach


executable('egk-tool',
    gengetopt.process(
        configure_file(
            configuration: conf_tools,
            input: 'egk-tool.ggo.in',
            output: 'egk-tool.ggo'
    )),
    tools_targets,
    c_args: tools_args,
    include_directories: core_inc,
    sources: files('egk-tool.c'),
    link_with: libtool,
    dependencies: depzlib,
    install: true
)

executable('goid-tool',
    gengetopt.process(
        configure_file(
            configuration: conf_tools,
            input: 'goid-tool.ggo.in',
            output: 'goid-tool.ggo'
    )),
    tools_targets,
    c_args: tools_args,
    include_directories: core_inc,
    sources: files('goid-tool.c'),
    link_with: [
        libsmeac,
        libtool
    ],
    dependencies: depopenpace,
    install: true
)

executable('opensc-asn1',
    gengetopt.process(
        configure_file(
            configuration: conf_tools,
            input: 'opensc-asn1.ggo.in',
            output: 'opensc-asn1.ggo'
    )),
    tools_targets,
    c_args: tools_args,
    include_directories: core_inc,
    sources: files('opensc-asn1.c'),
    link_with: libtool,
    install: true
)

executable('opensc-explorer',
    tools_targets,
    include_directories: core_inc,
    sources: files('opensc-explorer.c'),
    link_with: libtool,
    dependencies: [
        depopenssl,
        depreadline
    ],
    install: true
)

executable('opensc-tool',
    tools_targets,
    include_directories: core_inc,
    sources: files('opensc-tool.c'),
    link_with: [
        libscconf,
        libtool
    ],
    install: true
)

executable('pkcs11-register',
    gengetopt.process(
        configure_file(
            configuration: conf_tools,
            input: 'pkcs11-register.ggo.in',
            output: 'pkcs11-register.ggo'
    )),
    tools_targets,
    c_args: tools_args,
    include_directories: core_inc,
    sources: files('pkcs11-register.c'),
    link_with: [
        libpkcs11_common,
        libtool
    ],
    install: true
)


pkcs11_tool_libraries = [
    libpkcs11_common,
    libtool
]
if conf.get('ENABLE_PKCS11') and not conf.get('HAVE_P11KIT') and not conf.get('ENABLE_SHARED')
    pkcs11_tool_libraries += libpkcs11
endif

executable('pkcs11-tool',
    tools_targets,
    include_directories: core_inc,
    sources: files('pkcs11-tool.c'),
    link_with: pkcs11_tool_libraries,
    dependencies: [
        depopenssl,
        depthreads
    ],
    install: true
)


if conf.get('ENABLE_OPENSSL')
    foreach name, sources : {
        'cryptoflex-tool': files('cryptoflex-tool.c'),
        'gids-tool':       files('gids-tool.c'),
        'netkey-tool':     files('netkey-tool.c'),
        'piv-tool':        files('piv-tool.c'),
        'pkcs15-init':     files('pkcs15-init.c'),
        'sc-hsm-tool':     files('sc-hsm-tool.c'),
        'westcos-tool':    files('westcos-tool.c')
    }

    executable(name,
        tools_targets,
        include_directories: core_inc,
        sources: sources,
        link_with: libtool,
        dependencies: depopenssl,
        install: true
    )
    endforeach


    if conf.get('ENABLE_OPENPACE')
        executable('npa-tool',
            gengetopt.process(
                configure_file(
                    configuration: conf_tools,
                    input: 'npa-tool.ggo.in',
                    output: 'npa-tool.ggo'
            )),
            tools_targets,
            c_args: tools_args,
            include_directories: core_inc,
            sources: files('npa-tool.c'),
            link_with: [
                libsmeac,
                libtool
            ],
            dependencies: [
                depopenpace,
                depopenssl
            ],
            install: true
        )
    endif
endif


if conf.get('ENABLE_NOTIFY')
    opensc_notify_targets = []
    if host_machine.system() == 'windows' or host_machine.system() == 'cygwin'
        opensc_notify_targets += modwindows.compile_resources(
            'opensc-notify.rc',
            include_directories: core_inc,
            depend_files: [
                '../../win32/DDORes.dll_14_2302.ico',
                'tools.manifest'
            ]
        )
    endif

    executable('opensc-notify',
        gengetopt.process(
            configure_file(
                configuration: conf_tools,
                input: 'opensc-notify.ggo.in',
                output: 'opensc-notify.ggo'
        )),
        opensc_notify_targets,
        c_args: tools_args,
        include_directories: core_inc,
        sources: files('opensc-notify.c'),
        link_with: libtool,
        dependencies: depthreads,
        win_subsystem: 'windows',
        install: true
    )

    if host_machine.system() == 'linux'
        configure_file(
            configuration: {'bindir': absolute_bindir},
            input: 'org.opensc.notify.desktop.in',
            output: 'org.opensc.notify.desktop',
            install: true,
            install_dir: get_option('datadir') / 'applications'
        )
    endif
endif


if get_option('autostart')
    configure_file(
        configuration: {'bindir': absolute_bindir},
        input: 'pkcs11-register.desktop.in',
        output: 'pkcs11-register.desktop',
        install: true,
        install_dir: get_option('sysconfdir') / 'xdg' / 'autostart'
    )
endif


executable('sceac-example',
    include_directories: core_inc,
    sources: files('sceac-example.c'),
    link_with: [
        libsmeac,
        libtool
    ],
    build_by_default: false
)
