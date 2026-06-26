install_data(
    'opensc.conf',
    install_dir: get_option('sysconfdir')
)

if conf.get('ENABLE_OPENPACE')
    install_data(
        'DESRCACC100001',
        'DESCHSMCVCA00001',
        install_dir: conf.get_unquoted('CVCDIR')
    )
endif

if get_option('doc')
    conf_etc = configuration_data()
    conf_etc.set('LIBDIR', absolute_libdir / '')
    conf_etc.set('DEFAULT_PCSC_PROVIDER', conf.get_unquoted('DEFAULT_PCSC_PROVIDER'))
    conf_etc.set('DEFAULT_SM_MODULE', conf.get_unquoted('DEFAULT_SM_MODULE'))
    conf_etc.set('DEFAULT_SM_MODULE_PATH', conf.get_unquoted('DEFAULT_SM_MODULE_PATH'))
    conf_etc.set('DYN_LIB_EXT', '.' + extension_of_libraries)
    conf_etc.set('LIB_PRE', prefix_of_libraries)

    if host_machine.system() == 'windows'
        conf_etc.set('DEBUG_FILE', '%TEMP%\\opensc-debug.log')
        conf_etc.set('PROFILE_DIR_DEFAULT', 'obtained from windows registers')
        conf_etc.set('PROFILE_DIR', '')
    else
        conf_etc.set('DEBUG_FILE', '/tmp/opensc-debug.log')
        conf_etc.set('PROFILE_DIR_DEFAULT', absolute_pkgdir)
        conf_etc.set('PROFILE_DIR', absolute_pkgdir)
    endif

    configure_file(
        configuration: conf_etc,
        input: 'opensc.conf.example.in',
        output: 'opensc.conf',
        install: true,
        install_dir: absolute_docdir
    )
endif
