# obd.spec
%define version 0.007
%define kversion 2.4.9
%define aclevel ac10
%define izolevel 2
Release: 0
%define extraversion -%{aclevel}
%define kuname %{kversion}%{extraversion}
%define knamever %{kversion}_%{aclevel}
%define bdir $RPM_BUILD_DIR/obd-%{version}-%{knamever}

Summary: Object-Based Disk utility programs
Name: lustre
Version: %{version}
Copyright: GPL
Group: Utilities/System
Requires: lustre-modules, perl-Storable, perl-Term-ReadLine-Gnu
BuildRoot: /var/tmp/obd-%{version}-root
Source: ftp://ftp.lustre.com/pub/lustre/obd-%{version}.tar.gz

%description
Object-Based Disk utilities and demonstration scripts.

%package -n lustre-modules
Summary: Object-Based Disk storage drivers for Linux %{kuname}
Group: Development/Kernel
#Requires: kernel-intermezzo = %{knamever}_%{izolevel}

%description -n lustre-modules
Object-Based Disk storage drivers for Linux %{kuname}.

%package -n lustre-source
Summary: Object-Based Disk storage driver source
Group: Development/Kernel

%description -n lustre-source
Object-Based Disk storage driver source.

%prep
%setup -n obd-%{version}

%build
rm -rf $RPM_BUILD_ROOT

# Create the pristine source directory.
mkdir -p $RPM_BUILD_ROOT/usr/src/obd-%{version}
tar -cf - . | (cd $RPM_BUILD_ROOT/usr/src/obd-%{version} && tar -xvBpf -)

# Set an explicit path to our Linux tree, if we can.
enable=
linuxdir=/usr/src/linux-%{kuname}
test -d $linuxdir && enable=--enable-linuxdir=$linuxdir
./configure $enable
make

%install
make install prefix=$RPM_BUILD_ROOT

%files
%attr(-, root, root) %doc COPYING FDL
%attr(-, root, root) %doc doc/API.txt doc/OBD-HOWTO.sgml doc/obdspec.sgml
%attr(-, root, root) %doc doc/OLVM.txt doc/figs doc/notes.txt
%attr(-, root, root) %doc doc/obdtrace_demo.txt
%attr(-, root, root) /usr/bin/obdcontrol

%files -n lustre-modules
%attr(-, root, root) %doc COPYING
%attr(-, root, root) /lib/modules/%{kuname}/fs/obd*.o

%files -n lustre-source
%attr(-, root, root) /usr/src/obd-%{version}

%post
depmod -ae || exit 0

%postun
depmod -ae || exit 0

%clean
#rm -rf $RPM_BUILD_ROOT

# end of file
