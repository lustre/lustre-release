# obd.spec
%define version 0.005
%define kversion 2.4.9
%define aclevel ac10
%define izolevel 2
Release: 0
%define extraversion -%{aclevel}
%define kuname %{kversion}%{extraversion}
%define knamever %{kversion}_%{aclevel}
%define bdir $RPM_BUILD_DIR/obd-%{version}-%{knamever}

Summary: Object-Based Disk storage drivers for Linux %{kuname}
Name: obd
Version: %{version}
Requires: kernel-intermezzo = %{knamever}_%{izolevel}
Copyright: GPL
Group: Development/Kernel
BuildRoot: /var/tmp/obd-%{version}-root

#
# Sources
Source0: ftp://ftp.lustre.com/pub/lustre/obd-%{version}.tar.gz

%description
Object-Based Disk storage drivers for Linux %{kuname}.

%prep
%setup

%build
rm -rf $RPM_BUILD_ROOT

# Set an explicit path to our Linux tree, if we can.
enable=
linuxdir=/usr/src/linux-%{kuname}
test -d $linuxdir && enable=--enable-linuxdir=$linuxdir
./configure $enable
make

%install
make install PREFIX=$RPM_BUILD_ROOT

%files
/lib/modules/%{kuname}/fs/obd*.o
/usr/bin/obdcontrol
%doc COPYING FDL
%doc doc/API.txt doc/OBD-HOWTO.sgml doc/obdspec.sgml
%doc doc/OLVM.txt doc/figs doc/notes.txt doc/obdtrace_demo.txt

%post
depmod -ae || exit 0

%postun
depmod -ae || exit 0

%clean
#rm -rf $RPM_BUILD_ROOT

# end of file
