# These four variables will all be replaced automatically by lbuild-uml
# please do not add any extra whitespace
%define tag 0305061924
%define uml_location /usr/src/uml-b_open
%define kernel_version 2.4.20
%define uml_version kernel-2
%define patch_version -8
%define lustre_source /home/build/build/lustre-b_open
%define lustre_version 16

Summary: Lustre UML kernel package
Name: lum
Version: %{kernel_version}_uml_lustre%{lustre_version}
Release: %{tag}
License: GPL
Group: System
URL: http://www.lustre.org/pub/lustre/
Source0: linux-%{kernel_version}%{patch_version}.tar.gz
Source1: uml-config
Patch0: one-big-patch
BuildRoot: %{_tmppath}/%{kernel_version}-%{patch_version}-buildroot
%define __spec_install_post /usr/lib/rpm/brp-compress || :

%description
A user mode kernel package for Lustre development.

%prep
%setup -q -n linux-%{kernel_version}%{patch_version}
%patch0 -p1
cp -fv /usr/src/redhat/SOURCES/uml-config .config
ln -s ../kernel/tt/include/ptrace-tt.h arch/um/sys-i386
#cd %{lustre_source}/kernel_patches
#eval `./prepare_tree.sh -t $RPM_BUILD_DIR/linux -s rh-2.4.18-18` && cd $RPM_BUILD_DIR/linux && pushpatch 1000

%build
make distclean
cp -fv /usr/src/redhat/SOURCES/uml-config .config
make  oldconfig ARCH=um
make  dep ARCH=um
make  linux modules ARCH=um
make  clean

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{uml_location}
#mkdir -p $RPM_BUILD_ROOT
#mkdir -p %{uml_location}
#mkdir -p $RPM_BUILD_ROOT/linux-%{kernel_version}-uml-lustre-%{tag}
cd ..
cp -Rp linux-%{kernel_version}%{patch_version} $RPM_BUILD_ROOT/%{uml_location}/linux-%{kernel_version}-uml-lustre-%{tag}
ln -s linux-%{kernel_version}-uml-lustre-%{tag} $RPM_BUILD_ROOT/%{uml_location}/uml-%{kernel_version}

#find linux-%{kernel_version}%{patch_version} -maxdepth 1 -exec cp -a {} $RPM_BUILD_ROOT/%{uml_location} \; 
#cp -a linux-%{kernel_version}%{patch_version} $RPM_BUILD_ROOT/%{uml_location}

#find $RPM_BUILD_ROOT/%{uml_location} -type f > /tmp/kernel-rpm_tmp.list
#sed -e "s,$RPM_BUILD_ROOT,,g" /tmp/kernel-rpm_tmp.list  > /tmp/kernel-rpm.list
#rm -rf /tmp/kernel-rpm_tmp.list
%clean
rm -rf $RPM_BUILD_ROOT

#%files -f /tmp/kernel-rpm.list
%files
%defattr(-,root,root,-)
%{uml_location}/uml-%{kernel_version}
%{uml_location}/linux-%{kernel_version}-uml-lustre-%{tag}/
%doc


%changelog
* Thu Aug 01 2002 Phil Schwan <phil@clusterfs.com>
- Abstract uml_location, uml_version, and kernel_version
* Fri Jul 19 2002 Peter J. Braam <braam@clusterfs.com> 
- Initial build.
