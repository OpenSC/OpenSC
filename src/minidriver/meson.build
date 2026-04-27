if host_machine.system() != 'windows'
    error('The minidriver is intended for Windows only. Please remove it from the "components" option.')
endif

libminidriver = shared_module('opensc-minidriver',
    modwindows.compile_resources(
        'versioninfo-minidriver.rc',
        include_directories: core_inc,
        depend_files: '../../win32/DDORes.dll_14_2302.ico'
    ),
    include_directories: core_inc,
    sources: files('minidriver.c'),
    link_with: [
        libcompat,
        get_option('static_components').contains('minidriver')? libopensc_static : libopensc
    ],
    dependencies: [
        depcpdk,
        depopenpace,
        depopenssl
    ],
    vs_module_defs: configure_file(
        configuration: {'EXPORTS': modfs.read('opensc-minidriver.exports')},
        input: '../../win32/template.def.in',
        output: 'minidriver.def'
    ),
    install: true
)

configure_file(
    configuration: conf_aux,
    input: 'opensc-minidriver.inf.in',
    output: 'opensc-minidriver.inf'
)
