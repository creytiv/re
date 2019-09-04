%define name     re
%define ver      0.6.1
%define rel      1

Summary: Generic library for real-time communications with async IO support
Name: %name
Version: %ver
Release: %rel
License: BSD
Group: Applications/Devel
Source0: file://%{name}-%{version}.tar.gz
URL: http://www.creytiv.com/
Vendor: Creytiv
Packager: Alfred E. Heggestad <aeh@db.org>
BuildRoot: /var/tmp/%{name}-build-root

%description
Generic library for real-time communications with async IO support

%package devel
Summary:	libre development files
Group:		Development/Libraries
Requires:	%{name} = %{version}

%description devel
libre development files.

%prep
%setup

%build
make RELEASE=1

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install \
%ifarch x86_64
	LIBDIR=/usr/lib64
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%defattr(644,root,root,755)
%attr(755,root,root) %{_libdir}/libre*.so*

%files devel
%defattr(644,root,root,755)
%{_includedir}/re/*.h
/usr/share/re/re.mk
%{_libdir}/libre*.a
%{_libdir}/pkgconfig/libre.pc

%changelog
* Fri Nov 5 2010 Alfred E. Heggestad <aeh@db.org> -
- Initial build.
