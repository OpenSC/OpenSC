if conf.get('ENABLE_OPENSSL')
    libsmm_targets = []
    if host_machine.system() == 'windows' or host_machine.system() == 'cygwin'
        libsmm_targets += modwindows.compile_resources(
            'smm-local.rc',
            include_directories: core_inc,
            depend_files: 'smm-local.dll.manifest'
        )
    endif

    libsmm = library('smm-local',
        libsmm_targets,
        version: '11.0.2',
        include_directories: core_inc,
        sources: files(
            'sm-card-authentic.c',
            'sm-card-iasecc.c',
            'sm-cwa14890.c',
            'sm-global-platform.c',
            'smm-local.c'
        ),
        link_with: [
            get_option('static_components').contains('sm')? libopensc_static : libopensc,
            libsm
        ],
        dependencies: depopenssl,
        vs_module_defs: configure_file(
            configuration: {'EXPORTS': modfs.read('smm-local.exports')},
            input: 'smm-local.def.in',
            output: 'smm-local.def'
        ),
        install: true
    )
endif
