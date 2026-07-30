if conf.get('ENABLE_OPENSSL')
    libsmm_targets = []
    if host_machine.system() == 'windows' or host_machine.system() == 'cygwin'
        libsmm_targets += modwindows.compile_resources(
            'smm-local.rc',
            include_directories: core_inc
        )
    endif

    libsmm = shared_module('smm-local',
        libsmm_targets,
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
            input: '../../win32/template.def.in',
            output: 'smm-local.def'
        ),
        install: true
    )
endif
