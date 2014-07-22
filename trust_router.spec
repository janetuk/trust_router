Name:           trust_router
Version:        1.3
Release:        1%{?dist}
Summary:        Moonshot Trust Router

Group:          System Environment/Libraries
License:        BSD
URL:            http://www.project-moonshot.org/
Source0:        %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  krb5-devel 
BuildRequires: jansson-devel >= 2.4
BuildRequires: sqlite-devel, openssl-devel
Requires:       moonshot-gss-eap

%description
The trust router provides a mechanism for discovering the topology of
trust graphs in a topology and establishing temporary identities
between them.


%package        devel
Summary:        Development files for %{name}
Group:          Development/Libraries
Requires:       %{name}-libs = %{version}-%{release}

%description    devel
The %{name}-devel package contains libraries and header files for
developing applications that use %{name}-libs.

%package libs
Summary: Libraries needed by %{Name}

%description libs
This package includes libraries needed by the %{Name} package or
packages that wish trust_router functionality.




%prep
%setup -q


%build
%configure --disable-static
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'


%clean
rm -rf $RPM_BUILD_ROOT


%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%doc README
%{_bindir}/*

%files libs
%defattr(-,root,root,-)
%{_libdir}/*.so.*

%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/*.so



