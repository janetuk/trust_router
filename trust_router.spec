%global optflags %{optflags} -Wno-parentheses
Name:           trust_router
Version:        3.0.2
Release:        1%{?dist}
Summary:        Moonshot Trust Router

Group:          System Environment/Libraries
License:        BSD
URL:            http://www.project-moonshot.org/
Source0:        %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf, automake, m4, libtool
BuildRequires:  krb5-devel, glib2-devel
BuildRequires: jansson-devel >= 2.4
BuildRequires: sqlite-devel, openssl-devel, libtalloc-devel, libevent-devel
%{?el7:BuildRequires: systemd}
Requires:       moonshot-gss-eap >= 0.9.3, sqlite

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
autoreconf -f -i

%build
%configure --disable-static
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'

# Install config files
install -D -m 755 redhat/init $RPM_BUILD_ROOT/%{_initrddir}/trust_router
install -D -m 640 redhat/organizations.cfg $RPM_BUILD_ROOT/%{_sysconfdir}/trust_router/organizations.cfg
install -D -m 640 redhat/default-internal.cfg $RPM_BUILD_ROOT/%{_sysconfdir}/trust_router/conf.d/default/internal.cfg
install -D -m 640 redhat/tr-test-internal.cfg $RPM_BUILD_ROOT/%{_sysconfdir}/trust_router/conf.d/tr-test/internal.cfg
install -D -m 640 redhat/sysconfig $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/trust_router
install -D -m 640 redhat/sysconfig.tids $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/tids
install -D -m 755 redhat/tids.init $RPM_BUILD_ROOT/%{_initrddir}/tids

# Link shared config
ln -s ../../organizations.cfg $RPM_BUILD_ROOT/%{_sysconfdir}/trust_router/conf.d/default/organizations.cfg
ln -s ../../organizations.cfg $RPM_BUILD_ROOT/%{_sysconfdir}/trust_router/conf.d/tr-test/organizations.cfg

# Install wrapper scripts
install -D -m 755 redhat/tidc-wrapper $RPM_BUILD_ROOT/%{_bindir}/tidc-wrapper
install -D -m 755 redhat/tids-wrapper $RPM_BUILD_ROOT/%{_bindir}/tids-wrapper
install -D -m 755 redhat/trust_router-wrapper $RPM_BUILD_ROOT/%{_bindir}/trust_router-wrapper

# As we're building an RPM, we don't need the init scripts etc. in /usr/share
rm -rf $RPM_BUILD_ROOT/%{_datadir}/trust_router/redhat


%clean
rm -rf $RPM_BUILD_ROOT


%pre
getent group trustrouter > /dev/null || groupadd -r trustrouter
getent passwd trustrouter > /dev/null || useradd -r -g trustrouter -d /var/lib/trust_router -s /sbin/nologin -c "GSS-EAP Trust Router service account" trustrouter
exit 0


%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig

%post
# Data directory
tr_home=/var/lib/trust_router
tr_schema=${tr_home}/.schema_1.5.2
test -d ${tr_home} ||mkdir ${tr_home}
chown trustrouter:trustrouter ${tr_home}
test -e $tr_schema || rm -f $tr_home/keys
sqlite3 </usr/share/trust_router/schema.sql ${tr_home}/keys
touch $tr_schema
chown trustrouter:trustrouter ${tr_home}/keys
chmod 660 ${tr_home}/keys

# Log Directory
test -d /var/log/trust_router ||mkdir /var/log/trust_router
chown root:trustrouter /var/log/trust_router
chmod 770 /var/log/trust_router



%files
%defattr(-,root,root,-)
%doc README
#%{_bindir}/tidc
#%{_bindir}/tidc-wrapper
#%{_bindir}/tids
#%{_bindir}/tids-wrapper
#%{_bindir}/trust_router
#%{_bindir}/trust_router-wrapper
%{_bindir}/*
%{_datadir}/trust_router/schema.sql

%{_initrddir}/tids
%{_initrddir}/trust_router

%{?el7:%{_unitdir}/tids.service}

%config(noreplace) %{_sysconfdir}/sysconfig/tids
%config(noreplace) %{_sysconfdir}/sysconfig/trust_router

%dir %attr(755,root,trustrouter) %{_sysconfdir}/trust_router
%dir %attr(755,root,trustrouter) %{_sysconfdir}/trust_router/conf.d/
%dir %attr(755,root,trustrouter) %{_sysconfdir}/trust_router/conf.d/default
%dir %attr(755,root,trustrouter) %{_sysconfdir}/trust_router/conf.d/tr-test

%attr(640,root,trustrouter) %config(noreplace) %{_sysconfdir}/trust_router/organizations.cfg
%attr(640,root,trustrouter) %config(noreplace) %{_sysconfdir}/trust_router/conf.d/default/internal.cfg
%attr(640,root,trustrouter) %config(noreplace) %{_sysconfdir}/trust_router/conf.d/tr-test/internal.cfg
%attr(640,root,trustrouter) %config(noreplace) %{_sysconfdir}/trust_router/conf.d/default/organizations.cfg
%attr(640,root,trustrouter) %config(noreplace) %{_sysconfdir}/trust_router/conf.d/tr-test/organizations.cfg

%files libs
%defattr(-,root,root,-)
%{_libdir}/*.so.*

%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/*.so
