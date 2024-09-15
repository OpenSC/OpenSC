if conf.get('ENABLE_OPENSSL')
    libsmm = library('smm-local',
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
            libopensc,
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
