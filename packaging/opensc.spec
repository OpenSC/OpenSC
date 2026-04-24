Name:           opensc
Version:        0.27.1
Release:        %autorelease
Summary:        Smart card library and applications

License:        LGPL-2.1-or-later AND BSD-3-Clause
URL:            https://github.com/OpenSC/OpenSC/wiki
Source0:        https://github.com/OpenSC/OpenSC/releases/download/%{version}/%{name}-%{version}.tar.xz

BuildRequires:  make
BuildRequires:  pcsc-lite-devel
BuildRequires:  readline-devel
BuildRequires:  openssl-devel
BuildRequires:  /usr/bin/xsltproc
BuildRequires:  docbook-style-xsl
BuildRequires:  meson gcc
%if 0%{?fedora} || 0%{?rhel} > 10
BuildRequires:  bash-completion-devel
%else
BuildRequires:  bash-completion
%endif
BuildRequires:  zlib-ng-compat-devel
BuildRequires:  p11-kit-devel
# For tests
BuildRequires:  libcmocka-devel
BuildRequires:  vim-common
%if ! 0%{?rhel}
BuildRequires:  openpace-devel
%endif
BuildRequires:  softhsm
BuildRequires:  openssl
Requires:       %{name}-libs = %{version}-%{release}
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

%package        libs
Requires:       pcsc-lite-libs%{?_isa}
Summary:        OpenSC libraries

%description    libs
OpenSC libraries.


%prep
%setup -q -n opensc-%{version}

XFAIL_TESTS="test-pkcs11-tool-test-threads.sh test-pkcs11-tool-test.sh"

# In FIPS mode, OpenSSL doesn't allow RSA-PKCS, this is hardcoded into OpenSSL
# and we cannot influence it. Hence, the test is expected to fail in FIPS mode.
if [[ -f "/proc/sys/crypto/fips_enabled" && $(cat /proc/sys/crypto/fips_enabled) == "1" ]]; then
	XFAIL_TESTS+=" test-pkcs11-tool-unwrap-wrap-test.sh"
fi

sed -i -e "/XFAIL_TESTS/,$ {
  s/XFAIL_TESTS.*/XFAIL_TESTS=$XFAIL_TESTS/
  q
}" tests/Makefile.am

cp -p src/pkcs15init/README ./README.pkcs15init
cp -p src/scconf/README.scconf .
# No {_libdir} here to avoid multilib conflicts; it's just an example
sed -i -e 's|/usr/local/towitoko/lib/|/usr/lib/ctapi/|' etc/opensc.conf.example.in

%conf
%meson -Dopenssl=enabled \
%if ! 0%{?rhel}
        -Dopenpace=enabled \
%else
       -Dopenpace=disabled \
%endif
       -Ddnie_ui=disabled \
       -Ddriver=pcsc \
       -Dautostart=false \
       -Dnotify=false

%build
%meson_build

%check
%meson_test

%install
%meson_install

rm -rf $RPM_BUILD_ROOT%{_datadir}/doc/opensc

# Upstream considers libopensc API internal and no longer ships
# public headers and pkgconfig files.
# Remove the symlink as nothing is supposed to link against libopensc.
rm $RPM_BUILD_ROOT%{_libdir}/libopensc.so
rm $RPM_BUILD_ROOT%{_libdir}/libsmm-local.so

%files
%doc COPYING NEWS README*

%{_datadir}/bash-completion/*


%{_bindir}/cardos-tool
%{_bindir}/cryptoflex-tool
%{_bindir}/eidenv
%{_bindir}/iasecc-tool
%{_bindir}/gids-tool
%{_bindir}/netkey-tool
%if ! 0%{?rhel}
%{_bindir}/npa-tool
%endif
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
%{_bindir}/lteid-tool
%{_datadir}/opensc/
%{_mandir}/man1/cardos-tool.1*
%{_mandir}/man1/cryptoflex-tool.1*
%{_mandir}/man1/eidenv.1*
%{_mandir}/man1/gids-tool.1*
%{_mandir}/man1/goid-tool.1*
%{_mandir}/man1/iasecc-tool.1*
%{_mandir}/man1/netkey-tool.1*
%if ! 0%{?rhel}
%{_mandir}/man1/npa-tool.1*
%endif
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
%{_mandir}/man1/lteid-tool.1*
%{_mandir}/man5/pkcs15-profile.5*

%files libs
%config(noreplace) %{_sysconfdir}/opensc.conf
%{_mandir}/man5/opensc.conf.5*

# Co-owned with p11-kit so it is not hard dependency
%dir %{_datadir}/p11-kit
%dir %{_datadir}/p11-kit/modules
%{_datadir}/p11-kit/modules/opensc.module
%dir %{_libdir}/pkcs11
%{_libdir}/pkcs11/opensc-pkcs11.so
%{_libdir}/pkcs11/onepin-opensc-pkcs11.so
%{_libdir}/pkcs11/pkcs11-spy.so

# For OpenPACE
%if ! 0%{?rhel}
%config(noreplace) %{_sysconfdir}/eac/cvc/DESCHSMCVCA00001
%config(noreplace) %{_sysconfdir}/eac/cvc/DESRCACC100001
%endif

%changelog
%autochangelog
