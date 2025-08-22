project('openpace', 'c',
        version: '1.1.3',
        license: 'GPL-3.0-only',
        default_options: 'c_winlibs=ws2_32.lib',
        meson_version: '>= 1.3.0'
       )

absolute_sysconfdir = get_option('prefix') / get_option('sysconfdir')

conf = configuration_data()

cv_certificates_path = get_option('cv_certificates_path')
if cv_certificates_path == ''
    cv_certificates_path = absolute_sysconfdir / 'eac' / 'cvc'
endif
conf.set_quoted('CVCDIR', cv_certificates_path)

x509_certificates_path = get_option('x509_certificates_path')
if x509_certificates_path == ''
    x509_certificates_path = absolute_sysconfdir / 'eac' / 'x509'
endif
conf.set_quoted('X509DIR', x509_certificates_path)

depopenssl = dependency('openssl', version: '>= 1.1.1', default_options: 'default_library=static')
if depopenssl.type_name() == 'internal'
    conf.set10('HAVE_DECL_OPENSSL_ZALLOC', true)
    conf.set('HAVE_EC_KEY_METHOD', true)
    conf.set('HAVE_EVP_PKEY_DUP', true)
    conf.set('HAVE_RSA_GET0_KEY', true)
    conf.set('HAVE_RSA_SET0_KEY', true)
    conf.set('HAVE_DH_GET0_KEY', true)
    conf.set('HAVE_DH_SET0_KEY', true)
    conf.set('HAVE_DH_GET0_PQG', true)
    conf.set('HAVE_DH_SET0_PQG', true)
    conf.set('HAVE_ECDSA_SIG_GET0', true)
    conf.set('HAVE_ECDSA_SIG_SET0', true)
    conf.set('HAVE_EC_POINT_GET_AFFINE_COORDINATES', true)
    conf.set('HAVE_EC_POINT_SET_AFFINE_COORDINATES', true)
    conf.set('HAVE_ASN1_STRING_GET0_DATA', true)
else
    conf.set10('HAVE_DECL_OPENSSL_ZALLOC',
        meson.get_compiler('c').has_define('OPENSSL_zalloc', prefix: '#include <openssl/crypto.h>', dependencies: depopenssl) or
        meson.get_compiler('c').has_function('OPENSSL_zalloc', prefix: '#include <openssl/crypto.h>', dependencies: depopenssl)
    )
    conf.set('HAVE_EC_KEY_METHOD',
        meson.get_compiler('c').has_function('EC_KEY_get_default_method', prefix: '#include <openssl/ec.h>', dependencies: depopenssl)
    )
    conf.set('HAVE_EVP_PKEY_DUP',
        meson.get_compiler('c').has_function('EVP_PKEY_dup', prefix: '#include <openssl/evp.h>', dependencies: depopenssl)
    )
    conf.set('HAVE_RSA_GET0_KEY',
        meson.get_compiler('c').has_function('RSA_get0_key', prefix: '#include <openssl/rsa.h>', dependencies: depopenssl)
    )
    conf.set('HAVE_RSA_SET0_KEY',
        meson.get_compiler('c').has_function('RSA_set0_key', prefix: '#include <openssl/rsa.h>', dependencies: depopenssl)
    )
    conf.set('HAVE_DH_GET0_KEY',
        meson.get_compiler('c').has_function('DH_get0_key', prefix: '#include <openssl/dh.h>', dependencies: depopenssl)
    )
    conf.set('HAVE_DH_SET0_KEY',
        meson.get_compiler('c').has_function('DH_set0_key', prefix: '#include <openssl/dh.h>', dependencies: depopenssl)
    )
    conf.set('HAVE_DH_GET0_PQG',
        meson.get_compiler('c').has_function('DH_get0_pqg', prefix: '#include <openssl/dh.h>', dependencies: depopenssl)
    )
    conf.set('HAVE_DH_SET0_PQG',
        meson.get_compiler('c').has_function('DH_set0_pqg', prefix: '#include <openssl/dh.h>', dependencies: depopenssl)
    )
    conf.set('HAVE_ECDSA_SIG_GET0',
        meson.get_compiler('c').has_function('ECDSA_SIG_get0', prefix: '#include <openssl/ecdsa.h>', dependencies: depopenssl)
    )
    conf.set('HAVE_ECDSA_SIG_SET0',
        meson.get_compiler('c').has_function('ECDSA_SIG_set0', prefix: '#include <openssl/ecdsa.h>', dependencies: depopenssl)
    )
    conf.set('HAVE_EC_POINT_GET_AFFINE_COORDINATES',
        meson.get_compiler('c').has_function('EC_POINT_get_affine_coordinates', prefix: '#include <openssl/ec.h>', dependencies: depopenssl)
    )
    conf.set('HAVE_EC_POINT_SET_AFFINE_COORDINATES',
        meson.get_compiler('c').has_function('EC_POINT_set_affine_coordinates', prefix: '#include <openssl/ec.h>', dependencies: depopenssl)
    )
    conf.set('HAVE_ASN1_STRING_GET0_DATA',
        meson.get_compiler('c').has_function('ASN1_STRING_get0_data', prefix: '#include <openssl/asn1.h>', dependencies: depopenssl)
    )
endif

if host_machine.system() == 'windows'
    conf.set('WIN32_LEAN_AND_MEAN', true)
endif

configure_file(
    output: 'config.h',
    configuration: conf
)
add_project_arguments('-DHAVE_CONFIG_H', language: 'c')

libeac = library('eac',
    include_directories: ['.', 'src'],
    sources: files(
        'src' / 'ca_lib.c',
        'src' / 'cv_cert.c',
        'src' / 'cvc_lookup.c',
        'src' / 'eac.c',
        'src' / 'eac_asn1.c',
        'src' / 'eac_ca.c',
        'src' / 'eac_dh.c',
        'src' / 'eac_ecdh.c',
        'src' / 'eac_kdf.c',
        'src' / 'eac_lib.c',
        'src' / 'eac_print.c',
        'src' / 'eac_util.c',
        'src' / 'misc.c',
        'src' / 'objects.c',
        'src' / 'pace.c',
        'src' / 'pace_lib.c',
        'src' / 'pace_mappings.c',
        'src' / 'ri.c',
        'src' / 'ri_lib.c',
        'src' / 'ssl_compat.c',
        'src' / 'ta.c',
        'src' / 'ta_lib.c',
        'src' / 'x509_lookup.c'
    ),
    dependencies: depopenssl
)

depeac = declare_dependency(
    include_directories: 'src',
    link_with: libeac,
    dependencies: depopenssl,
    variables: {
        'cvcdir': cv_certificates_path,
        'x509dir': x509_certificates_path
    }
)

