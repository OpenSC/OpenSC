libpkcs11_sources = files(
    'debug.c',
    'framework-pkcs15.c',
    'framework-pkcs15init.c',
    'mechanism.c',
    'misc.c',
    'openssl.c',
    'pkcs11-display.c',
    'pkcs11-global.c',
    'pkcs11-object.c',
    'pkcs11-session.c',
    'slot.c'
)

libpkcs11_libraries = [
    libcompat,
    get_option('static_components').contains('pkcs11')? libopensc_static : libopensc
]

libpkcs11_dependencies = [
    depopenpace,
    depopenssl,
    depthreads
]

libpkcs11_targets = []
if host_machine.system() == 'windows' or host_machine.system() == 'cygwin'
    libpkcs11_targets += modwindows.compile_resources(
        'pkcs11.rc',
        include_directories: core_inc,
        depend_files: 'opensc-pkcs11.dll.manifest'
    )
endif

libpkcs11_vs_defs = configure_file(
    configuration: {'EXPORTS': modfs.read('pkcs11.exports')},
    input: 'pkcs11.def.in',
    output: 'pkcs11.def'
)


libpkcs11spy_sources = files(
    'pkcs11-display.c',
    'pkcs11-spy.c'
)

libpkcs11spy_libraries = [
    libpkcs11_common
]

libpkcs11spy_dependencies = [
    depopenssl,
    depthreads
]

libpkcs11spy_targets = []
if host_machine.system() == 'windows' or host_machine.system() == 'cygwin'
    libpkcs11spy_targets += modwindows.compile_resources(
        'pkcs11-spy.rc'
    )
endif


if depp11kit.found()
    libpkcs11 = shared_library('opensc-pkcs11',
        libpkcs11_targets,
        name_prefix: '',
        include_directories: core_inc,
        sources: libpkcs11_sources,
        link_with: libpkcs11_libraries,
        dependencies: libpkcs11_dependencies,
        vs_module_defs: libpkcs11_vs_defs,
        install: true,
        install_dir: p11kit_modules_path
    )

    libpkcs11spy = shared_library('pkcs11-spy',
        libpkcs11spy_targets,
        name_prefix: '',
        include_directories: core_inc,
        sources: libpkcs11spy_sources,
        link_with: libpkcs11spy_libraries,
        dependencies: libpkcs11spy_dependencies,
        install: true,
        install_dir: p11kit_modules_path
    )

    configure_file(
        configuration: {'EXTENSION': extension_of_libraries},
        input: 'opensc.module.in',
        output: 'opensc.module',
        install: true,
        install_dir: p11kit_configs_path
    )

    if host_machine.system() != 'windows'
        install_symlink('onepin-opensc-pkcs11.' + extension_of_libraries,
            install_dir: p11kit_modules_path,
            pointing_to: 'opensc-pkcs11.' + extension_of_libraries
        )
    endif
else
    libpkcs11 = library('opensc-pkcs11',
        libpkcs11_targets,
        include_directories: core_inc,
        sources: libpkcs11_sources,
        link_with: libpkcs11_libraries,
        dependencies: libpkcs11_dependencies,
        vs_module_defs: libpkcs11_vs_defs,
        install: true
    )

    libpkcs11spy = library('pkcs11-spy',
        libpkcs11spy_targets,
        include_directories: core_inc,
        sources: libpkcs11spy_sources,
        link_with: libpkcs11spy_libraries,
        dependencies: libpkcs11spy_dependencies,
        install: true
    )

    modpkgconfig.generate(
        libpkcs11,
        name: 'OpenSC smartcard framework',
        version: meson.project_version(),
        description: 'OpenSC PKCS#11 module',
        url: 'https://github.com/OpenSC/OpenSC',
        filebase: 'opensc-pkcs11'
    )

    if host_machine.system() != 'windows'
        extension = get_option('default_library') == 'static'? 'a' : extension_of_libraries

        install_symlink('onepin-opensc-pkcs11.' + extension,
            install_dir: get_option('libdir'),
            pointing_to: prefix_of_libraries + 'opensc-pkcs11.' + extension
        )

        if prefix_of_libraries != ''
            install_symlink('opensc-pkcs11.' + extension,
                install_dir: get_option('libdir'),
                pointing_to: prefix_of_libraries + 'opensc-pkcs11.' + extension
            )
        endif

        unset_variable('extension')
    endif
endif
