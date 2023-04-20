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
    ['HAVE_STRERROR', 'strerror', '#include<string.h>'],
    ['HAVE_BUILTIN_OVERFLOW', '__builtin_uadd_overflow', ''],
]

foreach f : check_functions
  if cc.has_function(f.get(1), prefix : f.get(2))
    cdata.set(f.get(0), 1)
  endif
endforeach

cdata.set_quoted('SC_PKCS15_PROFILE_DIRECTORY', get_option('prefix') / get_option('datadir') / 'opensc')
cdata.set('SIZEOF_VOID_P', cc.sizeof('void*'))

thread_dep = dependency('threads', required: false)
zlib_dep = dependency('zlib', required: false)
openssl_dep = dependency('openssl', required: false)
readline_dep = dependency('readline', required: false)
dl_dep = cc.find_library('dl', required : false)
openpace_dep = dependency('libeac', required: false)

cdata.set('ENABLE_READLINE', readline_dep.found())
cdata.set('ENABLE_ZLIB', zlib_dep.found())
cdata.set('HAVE_ZLIB_H', zlib_dep.found())
cdata.set('ENABLE_OPENSSL', openssl_dep.found())
cdata.set('HAVE_OPENSSL_CRYPTO_H', openssl_dep.found())
cdata.set('ENABLE_OPENPACE', openpace_dep.found())
if openpace_dep.found()
  x509dir = get_option('x509dir')
  if x509dir == ''
    x509dir = openpace_dep.get_pkgconfig_variable('x509dir')
  endif
  if x509dir == '' and host_machine.system() == 'windows'
    x509dir='%PROGRAMFILES%\\OpenSC Project\\OpenSC\\x509'
  endif
  cdata.set_quoted('X509DIR', x509dir)

  cvcdir = get_option('x509dir')
  if cvcdir == ''
    cvcdir = openpace_dep.get_pkgconfig_variable('cvcdir')
  endif
  if cvcdir == '' and host_machine.system() == 'windows'
    cvcdir='%PROGRAMFILES%\\OpenSC Project\\OpenSC\\cvc'
  endif
  cdata.set_quoted('CVCDIR', cvcdir)
endif
cdata.set('ENABLE_SM', get_option('sm'))
if get_option('sm')
  if host_machine.system() == 'windows'
    cdata.set_quoted('DEFAULT_SM_MODULE_PATH', '%PROGRAMFILES%\\OpenSC Project\\OpenSC\\tools')
    cdata.set_quoted('DEFAULT_SM_MODULE', 'smm-local.dll')
  else
    cdata.set_quoted('DEFAULT_SM_MODULE_PATH', get_option('prefix')/get_option('libdir'))
    cdata.set_quoted('DEFAULT_SM_MODULE', 'libsmm-local.so')
  endif
endif

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
if host_machine.system() == 'windows'
  cdata.set_quoted('DEFAULT_PKCS11_PROVIDER', '%PROGRAMFILES%\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll')
  cdata.set_quoted('DEFAULT_ONEPIN_PKCS11_PROVIDER', '%PROGRAMFILES%\\OpenSC Project\\OpenSC\\pkcs11\\onepin-opensc-pkcs11.dll')
else
  # how to replace DYN_LIB_EXT ?
  cdata.set_quoted('DEFAULT_PKCS11_PROVIDER', get_option('prefix') / get_option('libdir') / 'opensc-pkcs11.so')
  cdata.set_quoted('DEFAULT_ONEPIN_PKCS11_PROVIDER', get_option('prefix') / get_option('libdir') / 'onepin-opensc-pkcs11.so')
endif

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
