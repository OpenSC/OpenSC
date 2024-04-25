libutil = static_library('util',
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
conf_tools.set('PKCS11_REGISTER_SKIP_FIREFOX', conf.get_unquoted('PKCS11_REGISTER_SKIP_FIREFOX'))
conf_tools.set('VDFORMAT', conf.get('ENABLE_ZLIB')? 'XML' : 'GZIP')

tools_args = meson.get_compiler('c').get_supported_arguments(
    '-Wno-unknown-warning-option'
)

tools_targets = []
if host_machine.system() == 'windows' or host_machine.system() == 'cygwin'
    tools_targets += modwindows.compile_resources(
        configure_file(
            configuration: conf_aux,
            input: 'tools.rc.in',
            output: 'tools.rc'
        ),
        depend_files: 'tools.manifest'
    )
endif


executable('cardos-tool',
    tools_targets,
    include_directories: core_inc,
    sources: files('cardos-tool.c'),
    link_with: [
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libutil
    ],
    dependencies: depopenssl,
    install: true
)


executable('dnie-tool',
    tools_targets,
    include_directories: core_inc,
    sources: files('dnie-tool.c'),
    link_with: [
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libutil
    ],
    install: true
)


executable('dtrust-tool',
    tools_targets,
    include_directories: core_inc,
    sources: files('dtrust-tool.c'),
    link_with: [
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libutil
    ],
    install: true
)


egk_tool_target = custom_target(
    command:[proggengetopt,
        '--input=@INPUT@',
        '--set-version=' + meson.project_version(),
        '--output-dir=@OUTDIR@',
        '--file-name=egk-tool-cmdline'
    ],
    input: configure_file(
        configuration: conf_tools,
        input: 'egk-tool.ggo.in',
        output: 'egk-tool.ggo'
    ),
    output: ['egk-tool-cmdline.h', 'egk-tool-cmdline.c']
)

executable('egk-tool',
    tools_targets,
    egk_tool_target,
    c_args: tools_args,
    include_directories: core_inc,
    sources: files('egk-tool.c'),
    link_with: [
        libcompat,
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libutil
    ],
    dependencies: depzlib,
    install: true
)


executable('eidenv',
    tools_targets,
    include_directories: core_inc,
    sources: files('eidenv.c'),
    link_with: [
        libcompat,
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libutil
    ],
    install: true
)


goid_tool_target = custom_target(
    command:[proggengetopt,
        '--input=@INPUT@',
        '--set-version=' + meson.project_version(),
        '--output-dir=@OUTDIR@',
        '--file-name=goid-tool-cmdline'
    ],
    input: configure_file(
        configuration: conf_tools,
        input: 'goid-tool.ggo.in',
        output: 'goid-tool.ggo'
    ),
    output: ['goid-tool-cmdline.h', 'goid-tool-cmdline.c']
)

executable('goid-tool',
    tools_targets,
    goid_tool_target,
    c_args: tools_args,
    include_directories: core_inc,
    sources: files('goid-tool.c'),
    link_with: [
        libcompat,
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libsmeac,
        libutil
    ],
    dependencies: depopenpace,
    install: true
)


executable('iasecc-tool',
    tools_targets,
    include_directories: core_inc,
    sources: files('iasecc-tool.c'),
    link_with: [
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libutil
    ],
    install: true
)


executable('openpgp-tool',
    tools_targets,
    include_directories: core_inc,
    sources: files(
        'openpgp-tool.c',
        'openpgp-tool-helpers.c'
    ),
    link_with: [
        libcompat,
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libutil
    ],
    dependencies: depopenssl,
    install: true
)


opensc_asn1_target = custom_target(
    command:[proggengetopt,
        '--input=@INPUT@',
        '--set-version=' + meson.project_version(),
        '--output-dir=@OUTDIR@',
        '--file-name=opensc-asn1-cmdline'
    ],
    input: configure_file(
        configuration: conf_tools,
        input: 'opensc-asn1.ggo.in',
        output: 'opensc-asn1.ggo'
    ),
    output: ['opensc-asn1-cmdline.h', 'opensc-asn1-cmdline.c']
)

executable('opensc-asn1',
    tools_targets,
    opensc_asn1_target,
    c_args: tools_args,
    include_directories: core_inc,
    sources: files('opensc-asn1.c'),
    link_with: [
        libcompat,
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libutil
    ],
    install: true
)


executable('opensc-explorer',
    tools_targets,
    include_directories: core_inc,
    sources: files('opensc-explorer.c'),
    link_with: [
        libcompat,
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libutil
    ],
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
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libscconf,
        libutil
    ],
    install: true
)


pkcs11_register_target = custom_target(
    command:[proggengetopt,
        '--input=@INPUT@',
        '--set-version=' + meson.project_version(),
        '--output-dir=@OUTDIR@',
        '--file-name=pkcs11-register-cmdline'
    ],
    input: configure_file(
        configuration: conf_tools,
        input: 'pkcs11-register.ggo.in',
        output: 'pkcs11-register.ggo'
    ),
    output: ['pkcs11-register-cmdline.h', 'pkcs11-register-cmdline.c']
)

executable('pkcs11-register',
    tools_targets,
    pkcs11_register_target,
    c_args: tools_args,
    include_directories: core_inc,
    sources: files('pkcs11-register.c'),
    link_with: [
        libcompat,
        libpkcs11_common,
        libutil
    ],
    install: true
)


pkcs11_tool_libraries = [
    libcompat,
    get_option('static_components').contains('tools')? libopensc_static : libopensc,
    libpkcs11_common,
    libutil
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


executable('pkcs15-crypt',
    tools_targets,
    include_directories: core_inc,
    sources: files('pkcs15-crypt.c'),
    link_with: [
        libcompat,
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libutil
    ],
    dependencies: depopenssl,
    install: true
)


executable('pkcs15-tool',
    tools_targets,
    include_directories: core_inc,
    sources: files(
        'pkcs15-tool.c',
        '../pkcs11/pkcs11-display.c'
    ),
    link_with: [
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libutil
    ],
    dependencies: depopenssl,
    install: true
)


if conf.get('ENABLE_OPENSSL')
    executable('cryptoflex-tool',
        tools_targets,
        include_directories: core_inc,
        sources: files('cryptoflex-tool.c'),
        link_with: [
            libcompat,
            get_option('static_components').contains('tools')? libopensc_static : libopensc,
            libutil
        ],
        dependencies: depopenssl,
        install: true
    )


    executable('gids-tool',
        tools_targets,
        include_directories: core_inc,
        sources: files('gids-tool.c'),
        link_with: [
            get_option('static_components').contains('tools')? libopensc_static : libopensc,
            libutil
        ],
        dependencies: depopenssl,
        install: true
    )


    executable('netkey-tool',
        tools_targets,
        include_directories: core_inc,
        sources: files('netkey-tool.c'),
        link_with: [
            libcompat,
            get_option('static_components').contains('tools')? libopensc_static : libopensc
        ],
        dependencies: depopenssl,
        install: true
    )


    executable('piv-tool',
        tools_targets,
        include_directories: core_inc,
        sources: files('piv-tool.c'),
        link_with: [
            get_option('static_components').contains('tools')? libopensc_static : libopensc,
            libutil
        ],
        dependencies: depopenssl,
        install: true
    )


    executable('pkcs15-init',
        tools_targets,
        include_directories: core_inc,
        sources: files('pkcs15-init.c'),
        link_with: [
            libcompat,
            get_option('static_components').contains('tools')? libopensc_static : libopensc,
            libpkcs15init,
            libutil
        ],
        dependencies: depopenssl,
        install: true
    )


    executable('sc-hsm-tool',
        tools_targets,
        include_directories: core_inc,
        sources: files('sc-hsm-tool.c'),
        link_with: [
            get_option('static_components').contains('tools')? libopensc_static : libopensc,
            libutil
        ],
        dependencies: depopenssl,
        install: true
    )


    executable('westcos-tool',
        tools_targets,
        include_directories: core_inc,
        sources: files('westcos-tool.c'),
        link_with: [
            get_option('static_components').contains('tools')? libopensc_static : libopensc,
            libutil
        ],
        dependencies: depopenssl,
        install: true
    )


    if conf.get('ENABLE_OPENPACE')
        npa_tool_target = custom_target(
            command:[proggengetopt,
                '--input=@INPUT@',
                '--set-version=' + meson.project_version(),
                '--output-dir=@OUTDIR@',
                '--file-name=npa-tool-cmdline'
            ],
            input: configure_file(
                configuration: conf_tools,
                input: 'npa-tool.ggo.in',
                output: 'npa-tool.ggo'
            ),
            output: ['npa-tool-cmdline.h', 'npa-tool-cmdline.c']
        )

        executable('npa-tool',
            tools_targets,
            npa_tool_target,
            c_args: tools_args,
            include_directories: core_inc,
            sources: files('npa-tool.c'),
            link_with: [
                libcompat,
                get_option('static_components').contains('tools')? libopensc_static : libopensc,
                libsmeac,
                libutil
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
    opensc_notify_targets += custom_target(
        command:[proggengetopt,
            '--input=@INPUT@',
            '--set-version=' + meson.project_version(),
            '--output-dir=@OUTDIR@',
            '--file-name=opensc-notify-cmdline'
        ],
        input: configure_file(
            configuration: conf_tools,
            input: 'opensc-notify.ggo.in',
            output: 'opensc-notify.ggo'
        ),
        output: ['opensc-notify-cmdline.h', 'opensc-notify-cmdline.c']
    )

    if host_machine.system() == 'windows' or host_machine.system() == 'cygwin'
        opensc_notify_targets += modwindows.compile_resources(
            configure_file(
                configuration: conf_aux,
                input: 'opensc-notify.rc.in',
                output: 'opensc-notify.rc'
            ),
            depend_files: [
                meson.project_source_root() / 'win32' / 'DDORes.dll_14_2302.ico',
                'tools.manifest'
            ]
        )
    endif

    executable('opensc-notify',
        opensc_notify_targets,
        c_args: tools_args,
        include_directories: core_inc,
        sources: files('opensc-notify.c'),
        link_with: [
            libcompat,
            get_option('static_components').contains('tools')? libopensc_static : libopensc
        ],
        dependencies: depthreads,
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
        get_option('static_components').contains('tools')? libopensc_static : libopensc,
        libsmeac
    ],
    build_by_default: false
)
