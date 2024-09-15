project('openpace', 'c',
        version: '1.1.3',
        meson_version : '>= 0.57.0'
       )

modfs = import('fs')
modexternalproject = import('unstable-external_project')

absolute_sysconfdir = (modfs.is_absolute(get_option('sysconfdir'))? '' : get_option('prefix')) / get_option('sysconfdir')

cv_certificates_path = get_option('cv_certificates_path')
if cv_certificates_path == ''
    cv_certificates_path = absolute_sysconfdir / 'eac' / 'cvc'
endif

x509_certificates_path = get_option('x509_certificates_path')
if x509_certificates_path == ''
    x509_certificates_path = absolute_sysconfdir / 'eac' / 'x509'
endif

depopenpace = modexternalproject.add_project('configure',
    configure_options: [
        '--enable-static',
        '--enable-cvcdir=' + cv_certificates_path,
        '--enable-x509dir=' + x509_certificates_path,
        '--disable-shared',
        '--disable-python',
        '--disable-java',
        '--disable-ruby',
        '--disable-go',
        '--with-pic'
    ]
).dependency('eac')

meson.override_dependency('libeac', declare_dependency(
    dependencies: depopenpace,
    variables: {
        'cvcdir': cv_certificates_path,
        'x509dir': x509_certificates_path
    }
))

