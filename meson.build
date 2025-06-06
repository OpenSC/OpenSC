project('opensc', 'c',
        version: '0.26.1',
        license: 'LGPLv2.1+',
        default_options: [
            'b_ndebug=if-release',
            'c_winlibs=advapi32.lib, bcrypt.lib, crypt32.lib, comctl32.lib, gdi32.lib, rpcrt4.lib, shell32.lib, shlwapi.lib, user32.lib, winmm.lib, ws2_32.lib',
            'cpp_winlibs=advapi32.lib, msi.lib, shell32.lib, user32.lib, version.lib'
        ],
        meson_version: '>= 0.64'
       )

modpkgconfig = import('pkgconfig')
modfs        = import('fs')
modwindows   = import('windows')

all_languages = ['c']
if host_machine.system() == 'windows'
    add_languages('cpp', native: false)
    all_languages += 'cpp'
elif host_machine.system() == 'darwin'
    add_languages('objc', native: false)
    all_languages += 'objc'
endif

prefix_of_libraries = 'lib'
if host_machine.system() == 'cygwin'
    prefix_of_libraries = 'cyg'
elif meson.get_compiler('c').get_id() == 'msvc'
    prefix_of_libraries = ''
endif

extension_of_libraries = 'so'
if host_machine.system() == 'windows'
    extension_of_libraries = 'dll'
elif host_machine.system() == 'darwin'
    extension_of_libraries = 'dylib'
endif

absolute_bindir =     get_option('prefix') / get_option('bindir')
absolute_libdir =     get_option('prefix') / get_option('libdir')
absolute_sysconfdir = get_option('prefix') / get_option('sysconfdir')
absolute_datadir =    get_option('prefix') / get_option('datadir')

absolute_pkgdir = absolute_datadir / 'opensc'
absolute_docdir = absolute_datadir / 'doc' / 'opensc'

#################################################
# Dependencies and configuration
#################################################
conf = configuration_data()
conf.set_quoted('PACKAGE_NAME', 'OpenSC')
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set_quoted('PACKAGE_BUGREPORT', 'https://github.com/OpenSC/OpenSC/issues')
conf.set_quoted('PACKAGE_TARNAME', 'opensc')
conf.set_quoted('PACKAGE_URL', 'https://github.com/OpenSC/OpenSC')
conf.set_quoted('PACKAGE_SUMMARY', '')

conf.set_quoted('OPENSC_VS_FF_COMPANY_NAME', 'OpenSC project')
conf.set_quoted('OPENSC_VS_FF_COMPANY_URL', 'https://github.com/OpenSC')
conf.set_quoted('OPENSC_VS_FF_PRODUCT_NAME', 'OpenSC smartcard framework')
conf.set_quoted('OPENSC_VS_FF_PRODUCT_UPDATES', 'https://github.com/OpenSC/OpenSC/releases')
conf.set_quoted('OPENSC_VS_FF_PRODUCT_URL', 'https://github.com/OpenSC/OpenSC')
conf.set_quoted('OPENSC_VS_FF_COMMENTS', 'Provided under the terms of the GNU Lesser General Public License (LGPLv2.1+).')
conf.set_quoted('OPENSC_VS_FF_LEGAL_COMPANY_NAME', 'OpenSC project')
conf.set_quoted('OPENSC_VS_FF_LEGAL_COMPANY_URL', 'https://github.com/OpenSC')
conf.set_quoted('OPENSC_VS_FF_LEGAL_COPYRIGHT', 'OpenSC Project')

conf.set_quoted('OPENSC_CONF_PATH', absolute_sysconfdir / 'opensc.conf')
conf.set_quoted('DEFAULT_SM_MODULE', prefix_of_libraries + 'smm-local.' + extension_of_libraries)

project_version = meson.project_version().split('.')
conf.set('OPENSC_VERSION_MAJOR', project_version[0])
conf.set('OPENSC_VERSION_MINOR', project_version[1])
conf.set('OPENSC_VERSION_FIX',   project_version[2])
conf.set('OPENSC_VERSION_REVISION', '0')
conf.set_quoted('OPENSC_SCM_REVISION', meson.project_version())

if host_machine.system() == 'windows'
    conf.set_quoted('DEFAULT_PCSC_PROVIDER', 'winscard.dll')
    conf.set_quoted('SC_PKCS15_PROFILE_DIRECTORY', 'C:\\\\Program Files\\\\OpenSC Project\\\\OpenSC\\\\profiles')
    conf.set_quoted('DEFAULT_SM_MODULE_PATH', '%PROGRAMFILES%\\\\OpenSC Project\\\\OpenSC\\\\sm')
    conf.set('PKCS11_REGISTER_SKIP_FIREFOX', 'on')
    conf.set('WIN32_LEAN_AND_MEAN', true)

elif host_machine.system() == 'darwin'
    conf.set_quoted('DEFAULT_PCSC_PROVIDER', '/System/Library/Frameworks/PCSC.framework/PCSC')
    conf.set_quoted('SC_PKCS15_PROFILE_DIRECTORY', absolute_pkgdir)
    conf.set_quoted('DEFAULT_SM_MODULE_PATH', absolute_libdir)
    conf.set('PKCS11_REGISTER_SKIP_FIREFOX', 'on')

else
    conf.set_quoted('DEFAULT_PCSC_PROVIDER', 'libpcsclite.so.1')
    conf.set_quoted('SC_PKCS15_PROFILE_DIRECTORY', absolute_pkgdir)
    conf.set_quoted('DEFAULT_SM_MODULE_PATH', absolute_libdir)
    conf.set('PKCS11_REGISTER_SKIP_FIREFOX', 'off')
endif

if meson.get_compiler('c').get_id() == 'msvc'
    conf.set('PATH_MAX', 'FILENAME_MAX')
    conf.set('strncasecmp', 'strnicmp')
    conf.set('strcasecmp', 'stricmp')
    conf.set('S_IRUSR', 'S_IREAD')
    conf.set('S_IWUSR', 'S_IWRITE')
endif

conf.set('ENABLE_SHARED', get_option('default_library') != 'static')
conf.set('ENABLE_PKCS11',     get_option('components').contains('pkcs11'))
conf.set('ENABLE_MINIDRIVER', get_option('components').contains('minidriver'))
conf.set('ENABLE_SM',         get_option('components').contains('sm'))

conf.set('ENABLE_PCSC', false)
conf.set('ENABLE_CRYPTOTOKENKIT', false)
conf.set('ENABLE_OPENCT', false)
conf.set('ENABLE_CTAPI', false)
conf.set('HAVE_WINSCARD_H', false)
conf.set('HAVE_PCSCLITE_H', false)

if get_option('driver') == 'pcsc'
    conf.set('ENABLE_PCSC', true)
    if host_machine.system() == 'windows'
        deppcsc = meson.get_compiler('c').find_library('winscard')
        conf.set('HAVE_WINSCARD_H', meson.get_compiler('c').has_header('winscard.h'))
    else
        deppcsc = dependency('libpcsclite', version: '>= 1.8.22')
        conf.set('HAVE_WINSCARD_H', meson.get_compiler('c').has_header('winscard.h', dependencies: deppcsc))
        conf.set('HAVE_PCSCLITE_H', meson.get_compiler('c').has_header('pcsclite.h', dependencies: deppcsc))
    endif
elif get_option('driver') == 'crypttokenkit'
    conf.set('ENABLE_CRYPTOTOKENKIT', true)
    depcryptotokenkit = dependency('appleframeworks', modules: 'CryptoTokenKit')

elif get_option('driver') == 'openct'
    conf.set('ENABLE_OPENCT', true)
    depopenct = dependency('openct')

elif get_option('driver') == 'ctapi'
    conf.set('ENABLE_CTAPI', true)

else
    error('The option "driver" has unknown value')
endif

depopenpace = dependency('libeac', version: '>= 0.9', required: get_option('openpace'), default_options: 'default_library=static')
conf.set('ENABLE_OPENPACE', depopenpace.found())
if depopenpace.found()
    conf.set_quoted('CVCDIR', depopenpace.get_variable('cvcdir'))
    conf.set_quoted('X509DIR', depopenpace.get_variable('x509dir'))
else
    conf.set_quoted('CVCDIR', '')
    conf.set_quoted('X509DIR', '')
endif

depopenssl = dependency('openssl', version: '>= 1.1.1', required: get_option('openssl'), default_options: 'default_library=static')
conf.set('ENABLE_OPENSSL', depopenssl.found())
if depopenssl.found() and get_option('openssl_secure_malloc') != 0
    conf.set('OPENSSL_SECURE_MALLOC_SIZE', get_option('openssl_secure_malloc'))
endif

depreadline = dependency('readline', required: get_option('readline'))
conf.set('ENABLE_READLINE', depreadline.found())

depzlib = dependency('zlib', required: get_option('zlib'), default_options: 'default_library=static')
conf.set('ENABLE_ZLIB', depzlib.found())

can_enable_piv_sm = get_option('components').contains('sm') and depopenssl.found()
if get_option('piv_sm').enabled()
    if not can_enable_piv_sm
        error('The "piv_sm" option requires OpenSSL and -Dcomponents=sm')
    endif
    conf.set('ENABLE_PIV_SM', true)
elif get_option('piv_sm').auto()
    conf.set('ENABLE_PIV_SM', can_enable_piv_sm)
else
    conf.set('ENABLE_PIV_SM', false)
endif
unset_variable('can_enable_piv_sm')

depcorefoundation = dependency('appleframeworks', modules: 'CoreFoundation', required: get_option('dnie_ui'))
conf.set('ENABLE_DNIE_UI', depcorefoundation.found())

depgio2 = dependency('gio-2.0', required: false, default_options: 'default_library=static')
conf.set('ENABLE_GIO2', depgio2.found())

conf.set('ENABLE_NOTIFY', get_option('notify'))
conf.set('PKCS11_THREAD_LOCKING', get_option('thread_locking'))

depthreads = dependency('threads', required: false)
depdl = dependency('dl', required: false)

conf.set_quoted('DEFAULT_PKCS11_PROVIDER', '')
if get_option('components').contains('pkcs11')
    depp11kit = dependency('p11-kit-1', required: get_option('p11kit'))
    conf.set('HAVE_P11KIT', depp11kit.found())
    if depp11kit.found()
        p11kit_modules_path = depp11kit.get_variable('p11_module_path')
        p11kit_configs_path = depp11kit.get_variable('p11_module_configs')

        conf.set_quoted('DEFAULT_PKCS11_PROVIDER', p11kit_modules_path / 'opensc-pkcs11.' + extension_of_libraries)
    else
        if get_option('default_library') != 'static'
            if host_machine.system() == 'windows'
                conf.set_quoted('DEFAULT_PKCS11_PROVIDER', '%PROGRAMFILES%\\\\OpenSC Project\\\\OpenSC\\\\pkcs11\\\\opensc-pkcs11.dll')
            else
                conf.set_quoted('DEFAULT_PKCS11_PROVIDER', absolute_libdir / prefix_of_libraries + 'opensc-pkcs11.' + extension_of_libraries)
            endif
        endif
    endif
endif
conf.set('DEFAULT_ONEPIN_PKCS11_PROVIDER', conf.get('DEFAULT_PKCS11_PROVIDER'))

conf.set('HAVE_INTTYPES_H',       meson.get_compiler('c').has_header('inttypes.h'))
conf.set('HAVE_STRING_H',         meson.get_compiler('c').has_header('string.h'))
conf.set('HAVE_STRINGS_H',        meson.get_compiler('c').has_header('strings.h'))
conf.set('HAVE_SYS_TIME_H',       meson.get_compiler('c').has_header('sys' / 'time.h'))
conf.set('HAVE_SYS_MMAN_H',       meson.get_compiler('c').has_header('sys' / 'mman.h'))
conf.set('HAVE_SYS_ENDIAN_H',     meson.get_compiler('c').has_header('sys' / 'endian.h'))
conf.set('HAVE_UNISTD_H',         meson.get_compiler('c').has_header('unistd.h'))
conf.set('HAVE_ENDIAN_H',         meson.get_compiler('c').has_header('endian.h'))
conf.set('HAVE_PTHREAD',          meson.get_compiler('c').has_header('pthread.h'))

conf.set('HAVE_GETPASS',          meson.get_compiler('c').has_function('getpass'))
conf.set('HAVE_GETTIMEOFDAY',     meson.get_compiler('c').has_function('gettimeofday'))
conf.set('HAVE_GETLINE',          meson.get_compiler('c').has_function('getline'))
conf.set('HAVE_MEMSET_S',         meson.get_compiler('c').has_function('memset_s'))
conf.set('HAVE_EXPLICIT_BZERO',   meson.get_compiler('c').has_function('explicit_bzero'))
conf.set('HAVE_STRNLEN',          meson.get_compiler('c').has_function('strnlen'))
conf.set('HAVE_SIGACTION',        meson.get_compiler('c').has_function('sigaction'))
conf.set('HAVE_BUILTIN_OVERFLOW', meson.get_compiler('c').has_function('__builtin_uadd_overflow'))

opensc_features = ''
opensc_features += conf.get('PKCS11_THREAD_LOCKING')? ' locking'  : ''
opensc_features += conf.get('ENABLE_OPENPACE')?       ' openpace' : ''
opensc_features += conf.get('ENABLE_OPENSSL')?        ' openssl'  : ''
opensc_features += conf.get('ENABLE_READLINE')?       ' readline' : ''
opensc_features += conf.get('ENABLE_ZLIB')?           ' zlib'     : ''
opensc_features += conf.get('ENABLE_PCSC')?           ' pcsc(@0@)'.format(conf.get_unquoted('DEFAULT_PCSC_PROVIDER')) : ''
opensc_features += conf.get('ENABLE_CRYPTOTOKENKIT')? ' cryptotokenkit' : ''
opensc_features += conf.get('ENABLE_OPENCT')?         ' openct' : ''
opensc_features += conf.get('ENABLE_CTAPI')?          ' ctapi' : ''
conf.set_quoted('OPENSC_FEATURES', opensc_features.strip())
unset_variable('opensc_features')

if get_option('components').contains('tools')
    proggengetopt = find_program('gengetopt')
endif

if get_option('components').contains('minidriver')
    cpdk_path = get_option('cpdk_path')
    if cpdk_path == ''
        foreach path : [
            'C:/Program Files/Windows Kits/10/Cryptographic Provider Development Kit',
            'C:/Program Files (x86)/Windows Kits/10/Cryptographic Provider Development Kit' ]

            if modfs.is_dir(path / 'Include')
                cpdk_path = path
                break
            endif
        endforeach
        if cpdk_path == ''
            error('Cryptographic Provider Development Kit is not found. Please set the path in the "cpdk_path" option.')
        endif
    else
        if not modfs.is_dir(cpdk_path / 'Include')
            error('The directory @0@ does not exist'.format(cpdk_path / 'Include'))
        endif
    endif

    depcpdk = declare_dependency(
        include_directories: cpdk_path / 'Include'
    )
endif

if get_option('tests')
    depcmocka = dependency('cmocka', version: '>= 1.0.1')
endif

conf.set('QUOTE_HELPER(x)', '#x')
conf.set('QUOTE(x)', 'QUOTE_HELPER(x)')

configure_file(
    output: 'config.h',
    configuration: conf
)
add_project_arguments('-DHAVE_CONFIG_H', language: all_languages)

# Additional configuration for non-C files
conf_aux = configuration_data()
conf_aux.set('PROJECT_SOURCE_ROOT', meson.project_source_root())
conf_aux.set('PROJECT_BUILD_ROOT', meson.project_build_root())

conf_aux.set('PACKAGE_NAME',      conf.get_unquoted('PACKAGE_NAME'))
conf_aux.set('PACKAGE_VERSION',   conf.get_unquoted('PACKAGE_VERSION'))
conf_aux.set('PACKAGE_BUGREPORT', conf.get_unquoted('PACKAGE_BUGREPORT'))
conf_aux.set('PACKAGE_TARNAME',   conf.get_unquoted('PACKAGE_TARNAME'))
conf_aux.set('PACKAGE_URL',       conf.get_unquoted('PACKAGE_URL'))
conf_aux.set('PACKAGE_SUMMARY',   conf.get_unquoted('PACKAGE_SUMMARY'))

conf_aux.set('OPENSC_VS_FF_COMPANY_NAME',       conf.get_unquoted('OPENSC_VS_FF_COMPANY_NAME'))
conf_aux.set('OPENSC_VS_FF_COMPANY_URL',        conf.get_unquoted('OPENSC_VS_FF_COMPANY_URL'))
conf_aux.set('OPENSC_VS_FF_PRODUCT_NAME',       conf.get_unquoted('OPENSC_VS_FF_PRODUCT_NAME'))
conf_aux.set('OPENSC_VS_FF_PRODUCT_UPDATES',    conf.get_unquoted('OPENSC_VS_FF_PRODUCT_UPDATES'))
conf_aux.set('OPENSC_VS_FF_PRODUCT_URL',        conf.get_unquoted('OPENSC_VS_FF_PRODUCT_URL'))
conf_aux.set('OPENSC_VS_FF_COMMENTS',           conf.get_unquoted('OPENSC_VS_FF_COMMENTS'))
conf_aux.set('OPENSC_VS_FF_LEGAL_COMPANY_NAME', conf.get_unquoted('OPENSC_VS_FF_LEGAL_COMPANY_NAME'))
conf_aux.set('OPENSC_VS_FF_LEGAL_COMPANY_URL',  conf.get_unquoted('OPENSC_VS_FF_LEGAL_COMPANY_URL'))
conf_aux.set('OPENSC_VS_FF_LEGAL_COPYRIGHT',    conf.get_unquoted('OPENSC_VS_FF_LEGAL_COPYRIGHT'))

conf_aux.set('OPENSC_VERSION_MAJOR', project_version[0])
conf_aux.set('OPENSC_VERSION_MINOR', project_version[1])
conf_aux.set('OPENSC_VERSION_FIX',   project_version[2])

conf_aux.set('OPENSC_VERSION_REVISION', conf.get('OPENSC_VERSION_REVISION'))

if not meson.get_compiler('c').has_header('getopt.h')
    getopt_target = modfs.copyfile('src' / 'common' / 'compat_getopt.h', 'getopt.h')
endif

#################################################
# Build targets
#################################################
core_inc = include_directories('.', 'src')

subdir('src' / 'common')
subdir('src' / 'scconf')
subdir('src' / 'ui')
subdir('src' / 'pkcs15init')
subdir('src' / 'sm')
subdir('src' / 'libopensc')

if get_option('components').contains('pkcs11')
    subdir('src' / 'pkcs11')
endif

if get_option('components').contains('tools')
    subdir('src' / 'tools')
endif

if get_option('components').contains('minidriver')
    subdir('src' / 'minidriver')
endif

if get_option('components').contains('sm')
    subdir('src' / 'smm')
endif

subdir('etc')

if get_option('tests')
    subdir('src' / 'tests')
endif

if host_machine.system() == 'windows'
    subdir('win32')
endif

if host_machine.system() == 'darwin'
    subdir('MacOSX')
endif

#################################################
# Documentation and completion files
#################################################
progxsltproc = find_program('xsltproc', required: false)
if progxsltproc.found()
    stylesheets_path = get_option('xsl_stylesheets_path')
    if stylesheets_path == ''
        foreach path : [
            '/usr/share/xml/docbook/stylesheet/nwalsh',
            '/usr/share/xml/docbook/stylesheet/nwalsh/current',
            '/opt/local/share/xsl/docbook-xsl',
            '/sw/share/xml/xsl/docbook-xsl' ]

            if modfs.exists(path / 'html' / 'docbook.xsl')
                stylesheets_path = path
                break
            endif
        endforeach
    else
        if not modfs.exists(stylesheets_path / 'html' / 'docbook.xsl')
            error('The file @0@ does not exist'.format(stylesheets_path / 'html' / 'docbook.xsl'))
        endif
    endif
endif

bash_completion_path = get_option('bash_completion_path')
if bash_completion_path == ''
    depbashcompletion = dependency('bash-completion', version: '>= 2.0', required: false)
    if depbashcompletion.found()
        bash_completion_path = depbashcompletion.get_variable('completionsdir')
    endif
endif

subdir('doc' / 'files')

if get_option('components').contains('tools')
    subdir('doc' / 'tools')
endif

install_data('NEWS', install_dir: absolute_docdir)
