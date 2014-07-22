%define ver      XXX-LUSTRE-PLUGIN-VERSION-XXX
%define rel      2
%define prefix   /usr

Summary:        Lustre plugins for wireshark
Name:           XXX-LUSTRE-PLUGIN-RPM-NAME-XXX
Version:        %ver
Release:        %rel
License:        GPL
Group:          Networking/Utilities
Source:         %{name}-%{version}.tar.bz2
URL:            https://wiki.hpdd.intel.com/
BuildRoot:      %{_tmpdir}/lustre-wireshark-%{PACKAGE_VERSION}-root
Requires:       wireshark >= 1.6.8
BuildRequires:	wireshark-devel

%description
Plugins for wireshark to enable monitoring of Lustre/LNet network traffic.

%prep
%setup
make -e -f Makefile all > make-plugins.log 2>&1

%install
rm -rf \${RPM_BUILD_ROOT}
make DESTDIR=\${RPM_BUILD_ROOT} -e -f Makefile install

%clean
rm -rf \${RPM_BUILD_ROOT}

%files
%defattr(-, root, root)
%doc README
%{_libdir}/wireshark/plugins/*/*.so

%changelog
