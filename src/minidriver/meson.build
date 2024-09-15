if host_machine.system() != 'windows'
    error('The minidriver is intended for Windows only. Please remove it from the "components" option.')
endif

libminidriver = shared_library('opensc-minidriver',
    modwindows.compile_resources(
        configure_file(
            configuration: conf_aux,
            input: 'versioninfo-minidriver.rc.in',
            output: 'versioninfo-minidriver.rc'
        ),
        depend_files: meson.project_source_root() / 'win32' / 'DDORes.dll_14_2302.ico'
    ),
    include_directories: core_inc,
    sources: files('minidriver.c'),
    link_with: [
        libcompat,
        libnotify,
        libopensc,
        libpkcs15init,
        libstrings
    ],
    dependencies: [
        depopenpace,
        depopenssl
    ],
    vs_module_defs: configure_file(
        configuration: {'EXPORTS': modfs.read('minidriver.exports')},
        input: 'minidriver.def.in',
        output: 'minidriver.def'
    ),
    install: true
)

configure_file(
    configuration: {
        'OPENSC_VERSION_MAJOR': conf.get('OPENSC_VERSION_MAJOR'),
        'OPENSC_VERSION_MINOR': conf.get('OPENSC_VERSION_MINOR'),
        'OPENSC_VERSION_FIX':   conf.get('OPENSC_VERSION_FIX')
    },
    input: 'opensc-minidriver.inf.in',
    output: 'opensc-minidriver.inf'
)
