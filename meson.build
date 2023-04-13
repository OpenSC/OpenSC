project('opensc', 'c',
    version: '0.23.165'
)

cc = meson.get_compiler('c')
cdata = configuration_data()
check_headers = [
    'dlfcn.h',
    'fcntl.h',
    'getopt.h',
    'pcsclite.h',
    'strings.h',
    'string.h',
    'sys/endian.h',
    'sys/mman.h',
    'sys/stat.h',
    'sys/time.h',
    'sys/types.h',
    'sys/wait.h',
    'unistd.h',
    'wcautil.h',
    'winscard.h',
    'stdint.h',
]

add_project_arguments('-DHAVE_CONFIG_H', language: 'c')

foreach h : check_headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

check_functions = [
#   check token ['HAVE_DECL_STRLCAT']
#   check token ['HAVE_DECL_STRLCPY']
#   check token ['HAVE_DOPRNT']
#   check token ['HAVE_EAC_OBJ_NID2OBJ']
#   check token ['HAVE_EXPLICIT_BZERO']
    ['HAVE_GETLINE', 'getline', '#include<stdio.h>'],
    ['HAVE_GETOPT_LONG', 'getopt_long', '#include<getopt.h>'],
#   check token ['HAVE_GETPASS']
    ['HAVE_GETTIMEOFDAY', 'gettimeofday', '#include<sys/time.h>'],
    ['HAVE_MEMSET', 'memset', '#include<string.h>'],
#   check token ['HAVE_MEMSET_S']
#   check token ['HAVE_MKDIR']
    ['HAVE_PTHREAD', 'pthread_create', '#include<pthread.h>'],
#   check token ['HAVE_PTHREAD_PRIO_INHERIT']
    ['HAVE_SIGACTION', 'sigaction', '#include<signal.h>'],
#   check token ['HAVE_STAT_EMPTY_STRING_BUG']
    ['HAVE_STRDUP', 'strdup', '#include<string.h>'],
    ['HAVE_STRERROR', 'strerror', '#include<string.h>'],
#   check token ['HAVE_STRNLEN']
#   check token ['HAVE_VPRINTF']
]

foreach f : check_functions
  if cc.has_function(f.get(1), prefix : f.get(2))
    cdata.set(f.get(0), 1)
  endif
endforeach

cdata.set_quoted('SC_PKCS15_PROFILE_DIRECTORY', get_option('prefix') / get_option('datadir') / 'opensc')
cdata.set('SIZEOF_VOID_P', cc.sizeof('void*'))

thread_dep = dependency('threads')
zlib_dep = dependency('zlib', required: false)
openssl_dep = dependency('openssl', required: false)
readline_dep = dependency('readline', required: false)

cdata.set10('ENABLE_READLINE', readline_dep.found())
cdata.set('HAVE_READLINE_READLINE_H', readline_dep.found())
cdata.set10('ENABLE_ZLIB', zlib_dep.found())
cdata.set('HAVE_ZLIB_H', zlib_dep.found())
cdata.set10('ENABLE_OPENSSL', openssl_dep.found())
cdata.set('HAVE_OPENSSL_CRYPTO_H', openssl_dep.found())

version_str = meson.project_version()
varr = version_str.split('.')
cdata.set('OPENSC_VERSION_FIX', 0)
cdata.set('OPENSC_VERSION_MAJOR', varr[0])
cdata.set('OPENSC_VERSION_MINOR', varr[1])
cdata.set('OPENSC_VERSION_REVISION', varr[2])
cdata.set_quoted('OPENSC_VS_FF_COMPANY_NAME', 'OpenSC Project')
cdata.set_quoted('OPENSC_VS_FF_PRODUCT_NAME', 'OpenSC smartcard framework')
cdata.set_quoted('OPENSC_SCM_REVISION', 'FIXME')
cdata.set_quoted('OPENSC_FEATURES', 'FIXME')
cdata.set_quoted('DEFAULT_PKCS11_PROVIDER', get_option('prefix') / 'lib/opensc-pkcs11.so')
cdata.set_quoted('DEFAULT_ONEPIN_PKCS11_PROVIDER', get_option('prefix') / 'lib/onepin-opensc-pkcs11.so')

cdata.set_quoted('VERSION', version_str)
cdata.set_quoted('PACKAGE', 'opensc')
cdata.set_quoted('PACKAGE_BUGREPORT', 'https://github.com/OpenSC/OpenSC/issues')
cdata.set_quoted('PACKAGE_NAME', 'OpenSC')
cdata.set_quoted('PACKAGE_STRING', 'OpenSC ' + version_str)
cdata.set_quoted('PACKAGE_URL', 'https://github.com/OpenSC/OpenSC')
cdata.set_quoted('PACKAGE_VERSION', version_str)
cdata.set_quoted('OPENSC_CONF_PATH', get_option('sysconfdir') / 'opensc.conf')

configure_file(input : 'configheader.in',
  output : 'config.h',
  configuration : cdata)

core_inc = include_directories('.', 'src')

subdir('src')
