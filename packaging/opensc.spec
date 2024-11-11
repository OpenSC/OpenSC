Name:           opensc
Version:        0.1.0
Release:        1%{?dist}
Summary:        Smart card library and applications

License:        LGPL-2.1-or-later AND BSD-3-Clause
URL:            https://github.com/OpenSC/OpenSC/wiki
Source0:        opensc-0.1.0.tar.gz
Source1:        opensc.module

BuildRequires:  make
BuildRequires:  pcsc-lite-devel
BuildRequires:  readline-devel
BuildRequires:  openssl-devel
BuildRequires:  /usr/bin/xsltproc
BuildRequires:  docbook-style-xsl
BuildRequires:  autoconf automake libtool gcc
BuildRequires:  bash-completion
BuildRequires:  zlib-ng-devel
# For tests
BuildRequires:  libcmocka-devel
BuildRequires:  vim-common
BuildRequires:  softhsm
BuildRequires:  openssl
Requires:       pcsc-lite-libs%{?_isa}
Requires:       pcsc-lite
Obsoletes:      mozilla-opensc-signer < 0.12.0
Obsoletes:      opensc-devel < 0.12.0
Obsoletes:      coolkey <= 1.1.0-36
# The simclist is bundled in upstream
Provides:       bundled(simclist) = 1.5

%description
OpenSC provides a set of libraries and utilities to work with smart cards. Its
main focus is on cards that support cryptographic operations, and facilitate
their use in security applications such as authentication, mail encryption and
digital signatures. OpenSC implements the PKCS#11 API so applications
supporting this API (such as Mozilla Firefox and Thunderbird) can use it. On
the card OpenSC implements the PKCS#15 standard and aims to be compatible with
every software/card that does so, too.


%prep
%setup -q

# The test-pkcs11-tool-allowed-mechanisms already works in Fedora
XFAIL_TESTS="test-pkcs11-tool-test-threads.sh test-pkcs11-tool-test.sh"

# In FIPS mode, OpenSSL doesn't allow RSA-PKCS, this is hardcoded into OpenSSL
# and we cannot influence it. Hence, the test is expected to fail in FIPS mode.
if [[ -f "/proc/sys/crypto/fips_enabled" && $(cat /proc/sys/crypto/fips_enabled) == "1" ]]; then
	XFAIL_TESTS+=" test-pkcs11-tool-unwrap-wrap-test.sh test-p11test.sh"
fi

sed -i -e "/XFAIL_TESTS/,$ {
  s/XFAIL_TESTS.*/XFAIL_TESTS=$XFAIL_TESTS/
  q
}" tests/Makefile.am


cp -p src/pkcs15init/README ./README.pkcs15init
cp -p src/scconf/README.scconf .
# No {_libdir} here to avoid multilib conflicts; it's just an example
sed -i -e 's|/usr/local/towitoko/lib/|/usr/lib/ctapi/|' etc/opensc.conf.example.in


%build
autoreconf -fvi
%ifarch %{ix86}
sed -i -e 's/opensc.conf/opensc-%{_arch}.conf/g' src/libopensc/Makefile.in
%endif
sed -i -e 's|"/lib /usr/lib\b|"/%{_lib} %{_libdir}|' configure # lib64 rpaths
%set_build_flags
CFLAGS="$CFLAGS -Wstrict-aliasing=2 -Wno-deprecated-declarations"
%configure --disable-static \
  --disable-autostart-items \
  --disable-notify \
  --disable-assert \
  --enable-pcsc \
  --enable-cmocka \
  --enable-sm
%make_build


%check
make check || (cat tests/*.log src/tests/unittests/*.log && exit 1)


%install
%make_install
install -Dpm 644 %{SOURCE1} $RPM_BUILD_ROOT%{_datadir}/p11-kit/modules/opensc.module

%ifarch %{ix86}
# To avoid multilib issues, move these files on 32b intel architectures
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/opensc.conf
install -Dpm 644 etc/opensc.conf $RPM_BUILD_ROOT%{_sysconfdir}/opensc-%{_arch}.conf
rm -f $RPM_BUILD_ROOT%{_mandir}/man5/opensc.conf.5
install -Dpm 644 doc/files/opensc.conf.5 $RPM_BUILD_ROOT%{_mandir}/man5/opensc-%{_arch}.conf.5
# use NEWS file timestamp as reference for configuration file
touch -r NEWS $RPM_BUILD_ROOT%{_sysconfdir}/opensc-%{_arch}.conf
touch -r NEWS $RPM_BUILD_ROOT%{_mandir}/man5/opensc-%{_arch}.conf.5
%else
# For backward compatibility, symlink the old location to the new files
ln -s %{_sysconfdir}/opensc.conf $RPM_BUILD_ROOT%{_sysconfdir}/opensc-%{_arch}.conf
%endif

find $RPM_BUILD_ROOT%{_libdir} -type f -name "*.la" | xargs rm

rm -rf $RPM_BUILD_ROOT%{_datadir}/doc/opensc

# Upstream considers libopensc API internal and no longer ships
# public headers and pkgconfig files.
# Remove the symlink as nothing is supposed to link against libopensc.
rm -f $RPM_BUILD_ROOT%{_libdir}/libopensc.so
# remove the .pc file so we do not confuse users #1673139
rm -f $RPM_BUILD_ROOT%{_libdir}/pkgconfig/*.pc
rm -f $RPM_BUILD_ROOT%{_libdir}/libsmm-local.so

# the npa-tool builds to nothing since we do not have OpenPACE library
rm -rf %{buildroot}%{_bindir}/npa-tool
rm -rf %{buildroot}%{_mandir}/man1/npa-tool.1*

# the pkcs11-register is not applicable to Fedora/RHEL where we use p11-kit
rm -rf %{buildroot}%{_bindir}/pkcs11-register
rm -rf %{buildroot}%{_mandir}/man1/pkcs11-register.1*

# Remove the notification files
rm %{buildroot}%{_datadir}/applications/org.opensc.notify.desktop
rm %{buildroot}%{_mandir}/man1/opensc-notify.1*


%files
%doc COPYING NEWS README*

%{_datadir}/bash-completion/*

%ifarch %{ix86}
%{_mandir}/man5/opensc-%{_arch}.conf.5*
%else
%config(noreplace) %{_sysconfdir}/opensc.conf
%{_mandir}/man5/opensc.conf.5*
%endif

%config(noreplace) %{_sysconfdir}/opensc-%{_arch}.conf
# Co-owned with p11-kit so it is not hard dependency
%dir %{_datadir}/p11-kit
%dir %{_datadir}/p11-kit/modules
%{_datadir}/p11-kit/modules/opensc.module
%{_bindir}/cardos-tool
%{_bindir}/cryptoflex-tool
%{_bindir}/eidenv
%{_bindir}/iasecc-tool
%{_bindir}/gids-tool
%{_bindir}/netkey-tool
%{_bindir}/openpgp-tool
%{_bindir}/opensc-explorer
%{_bindir}/opensc-tool
%{_bindir}/opensc-asn1
%{_bindir}/piv-tool
%{_bindir}/pkcs11-tool
%{_bindir}/pkcs15-crypt
%{_bindir}/pkcs15-init
%{_bindir}/pkcs15-tool
%{_bindir}/sc-hsm-tool
%{_bindir}/dnie-tool
%{_bindir}/westcos-tool
%{_bindir}/egk-tool
%{_bindir}/goid-tool
%{_bindir}/dtrust-tool
%{_libdir}/lib*.so.*
%{_libdir}/opensc-pkcs11.so
%{_libdir}/pkcs11-spy.so
%{_libdir}/onepin-opensc-pkcs11.so
%dir %{_libdir}/pkcs11
%{_libdir}/pkcs11/opensc-pkcs11.so
%{_libdir}/pkcs11/onepin-opensc-pkcs11.so
%{_libdir}/pkcs11/pkcs11-spy.so
%{_datadir}/opensc/
%{_mandir}/man1/cardos-tool.1*
%{_mandir}/man1/cryptoflex-tool.1*
%{_mandir}/man1/eidenv.1*
%{_mandir}/man1/gids-tool.1*
%{_mandir}/man1/goid-tool.1*
%{_mandir}/man1/iasecc-tool.1*
%{_mandir}/man1/netkey-tool.1*
%{_mandir}/man1/openpgp-tool.1*
%{_mandir}/man1/opensc-explorer.*
%{_mandir}/man1/opensc-tool.1*
%{_mandir}/man1/opensc-asn1.1*
%{_mandir}/man1/piv-tool.1*
%{_mandir}/man1/pkcs11-tool.1*
%{_mandir}/man1/pkcs15-crypt.1*
%{_mandir}/man1/pkcs15-init.1*
%{_mandir}/man1/pkcs15-tool.1*
%{_mandir}/man1/sc-hsm-tool.1*
%{_mandir}/man1/westcos-tool.1*
%{_mandir}/man1/dnie-tool.1*
%{_mandir}/man1/egk-tool.1*
%{_mandir}/man1/dtrust-tool.1*
%{_mandir}/man5/pkcs15-profile.5*
