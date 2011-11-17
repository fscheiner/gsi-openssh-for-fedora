# gsissh is openssh with support for GSI authentication
# This gsissh specfile is based on the openssh specfile

# Do we want SELinux & Audit
%global WITH_SELINUX 1

# OpenSSH privilege separation requires a user & group ID
%global sshd_uid    74
%global sshd_gid    74

# Build position-independent executables (requires toolchain support)?
%global pie 1

# Do we want kerberos5 support (1=yes 0=no)
# It is not possible to support kerberos5 and GSI at the same time
%global kerberos5 0

# Do we want GSI support (1=yes 0=no)
%global gsi 1

# Do we want LDAP support
%global ldap 1

# Do we want libedit support
%global libedit 1

# Do we want NSS tokens support
%global nss 1

# Whether or not /sbin/nologin exists.
%global nologin 1

Summary: An implementation of the SSH protocol with GSI authentication
Name: gsi-openssh
Version: 5.3p1
Release: 3%{?dist}
Provides: gsissh = %{version}-%{release}
Obsoletes: gsissh < 5.3p1-3
URL: http://www.openssh.com/portable.html
#Source0: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz
#Source1: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz.asc
# This package differs from the upstream OpenSSH tarball in that
# the ACSS cipher is removed by running openssh-nukeacss.sh in
# the unpacked source directory.
Source0: openssh-%{version}-noacss.tar.bz2
Source1: openssh-nukeacss.sh
Source2: gsisshd.old.pam
Source3: gsisshd.init
Source7: gsisshd.sysconfig
Source99: README.sshd-and-gsisshd
Patch0: openssh-5.2p1-redhat.patch
Patch2: openssh-5.3p1-skip-initial.patch
Patch4: openssh-5.2p1-vendor.patch
Patch5: openssh-5.3p1-engine.patch
Patch12: openssh-5.2p1-selinux.patch
Patch13: openssh-5.3p1-mls.patch
Patch18: openssh-5.0p1-pam_selinux.patch
Patch19: openssh-5.2p1-sesftp.patch
Patch22: openssh-3.9p1-askpass-keep-above.patch
Patch24: openssh-4.3p1-fromto-remote.patch
Patch27: openssh-5.1p1-log-in-chroot.patch
Patch30: openssh-4.0p1-exit-deadlock.patch
Patch35: openssh-5.1p1-askpass-progress.patch
Patch38: openssh-4.3p2-askpass-grab-info.patch
Patch39: openssh-4.3p2-no-v6only.patch
Patch44: openssh-5.2p1-allow-ip-opts.patch
Patch49: openssh-4.3p2-gssapi-canohost.patch
Patch51: openssh-5.3p1-nss-keys.patch
Patch55: openssh-5.1p1-cloexec.patch
Patch62: openssh-5.1p1-scp-manpage.patch
Patch65: openssh-5.3p1-fips.patch
Patch69: openssh-5.3p1-selabel.patch
Patch71: openssh-5.2p1-edns.patch
Patch73: openssh-5.3p1-gsskex.patch
Patch74: openssh-5.3p1-randclean.patch
Patch75: openssh-5.3p1-strictalias.patch
Patch76: openssh-5.3p1-595935.patch
Patch77: openssh-5.3p1-x11.patch
Patch78: openssh-5.3p1-authorized-keys-command.patch
Patch79: openssh-5.3p1-stderr.patch
Patch80: openssh-5.3p1-audit.patch
Patch81: openssh-5.3p1-biguid.patch
Patch82: openssh-5.3p1-kuserok.patch
Patch83: openssh-5.3p1-sftp_umask.patch
Patch84: openssh-5.3p1-clientloop.patch
Patch85: openssh-5.3p1-ldap.patch
Patch86: openssh-5.3p1-keycat.patch
Patch87: openssh-5.3p1-sftp-chroot.patch
Patch88: openssh-5.3p1-entropy.patch
Patch89: openssh-5.3p1-multiple-sighup.patch

# This is the patch that adds GSI support
# Based on http://grid.ncsa.illinois.edu/ssh/dl/patch/openssh-5.3p1.patch
Patch98: openssh-5.3p1-gsissh.patch

# The gsissh server has problems with blocked signals in threaded globus libs
# This patch from OSG resolves these problems
Patch99: openssh-5.3p1-unblock-signals.patch

License: BSD
Group: Applications/Internet
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
%if %{nologin}
Requires: /sbin/nologin
%endif

Requires: initscripts >= 5.20

BuildRequires: autoconf, automake, perl, zlib-devel
BuildRequires: audit-libs-devel >= 2.0.5
BuildRequires: util-linux, groff, man
BuildRequires: pam-devel
BuildRequires: tcp_wrappers-devel
BuildRequires: fipscheck-devel
BuildRequires: openssl-devel >= 0.9.8j
%if %{ldap}
BuildRequires: openldap-devel
%endif

%if %{kerberos5}
BuildRequires: krb5-devel
%endif

%if %{gsi}
BuildRequires: globus-gss-assist-devel
BuildRequires: globus-usage-devel
%endif

%if %{libedit}
BuildRequires: libedit-devel ncurses-devel
%endif

%if %{nss}
BuildRequires: nss-devel
%endif

%if %{WITH_SELINUX}
Requires: libselinux >= 1.27.7
BuildRequires: libselinux-devel >= 1.27.7
Requires: audit-libs >= 1.0.8
BuildRequires: audit-libs >= 1.0.8
%endif

BuildRequires: xauth

%package clients
Summary: SSH client applications with GSI authentication
Requires: %{name} = %{version}-%{release}
Provides: gsissh-clients = %{version}-%{release}
Obsoletes: gsissh-clients < 5.3p1-3
Group: Applications/Internet

%package server
Summary: SSH server daemon with GSI authentication
Provides: gsissh-server = %{version}-%{release}
Obsoletes: gsissh-server < 5.3p1-3
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires(post): chkconfig >= 0.9, /sbin/service
Requires(pre): /usr/sbin/useradd
Requires: pam >= 1.0.1-3

%description
SSH (Secure SHell) is a program for logging into and executing
commands on a remote machine. SSH is intended to replace rlogin and
rsh, and to provide secure encrypted communications between two
untrusted hosts over an insecure network. X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's version of the last free version of SSH, bringing
it up to date in terms of security and features.

This version of OpenSSH has been modified to support GSI authentication.

This package includes the core files necessary for both the gsissh
client and server. To make this package useful, you should also
install gsi-openssh-clients, gsi-openssh-server, or both.

%description clients
OpenSSH is a free version of SSH (Secure SHell), a program for logging
into and executing commands on a remote machine. This package includes
the clients necessary to make encrypted connections to SSH servers.

This version of OpenSSH has been modified to support GSI authentication.

%description server
OpenSSH is a free version of SSH (Secure SHell), a program for logging
into and executing commands on a remote machine. This package contains
the secure shell daemon (sshd). The sshd daemon allows SSH clients to
securely connect to your SSH server.

This version of OpenSSH has been modified to support GSI authentication.

%prep
%setup -q -n openssh-%{version}
%patch0 -p1 -b .redhat
%patch2 -p1 -b .skip-initial
%patch4 -p1 -b .vendor
%patch5 -p1 -b .engine

%if %{WITH_SELINUX}
#SELinux
%patch12 -p1 -b .selinux
%patch13 -p1 -b .mls
%patch18 -p1 -b .pam_selinux
%patch19 -p1 -b .sesftp
%endif

%patch22 -p1 -b .keep-above
%patch24 -p1 -b .fromto-remote
%patch27 -p1 -b .log-chroot
%patch30 -p1 -b .exit-deadlock
%patch35 -p1 -b .progress
%patch38 -p1 -b .grab-info
%patch39 -p1 -b .no-v6only
%patch44 -p1 -b .ip-opts
%patch49 -p1 -b .canohost
%patch51 -p1 -b .nss-keys
%patch55 -p1 -b .cloexec
%patch62 -p1 -b .manpage
%patch65 -p1 -b .fips
%patch69 -p1 -b .selabel
%patch71 -p1 -b .edns
%patch73 -p1 -b .gsskex
%patch74 -p1 -b .randclean
%patch75 -p1 -b .strictalias
%patch76 -p1 -b .bz595935
%patch77 -p1 -b .x11
%patch78 -p1 -b .akc
%patch79 -p1 -b .stderr
%patch80 -p1 -b .audit
%patch81 -p1 -b .biguid
%patch82 -p1 -b .kuserok
%patch83 -p1 -b .sftp-umask
%patch84 -p1 -b .clientloop
%if %{ldap}
%patch85 -p1 -b .ldap
%endif
%patch86 -p1 -b .keycat
%patch87 -p1 -b .sftp-chroot
%patch88 -p1 -b .entropy
%patch89 -p1 -b .multiple-sighhup
%patch98 -p1 -b .gsi
%patch99 -p1 -b .signals

sed 's/sshd.pid/gsisshd.pid/' -i pathnames.h
sed 's!$(piddir)/sshd.pid!$(piddir)/gsisshd.pid!' -i Makefile.in

cp -p %{SOURCE99} .

autoreconf

%build
CFLAGS="$RPM_OPT_FLAGS"; export CFLAGS
%if %{pie}
%ifarch s390 s390x sparc sparcv9 sparc64
CFLAGS="$CFLAGS -fPIC"
%else
CFLAGS="$CFLAGS -fpic"
%endif
export CFLAGS
LDFLAGS="$LDFLAGS -pie"; export LDFLAGS
LDFLAGS="$LDFLAGS -Wl,-z,relro -Wl,-z,now"; export LDFLAGS
%endif
%if %{kerberos5}
if test -r /etc/profile.d/krb5-devel.sh ; then
	source /etc/profile.d/krb5-devel.sh
fi
krb5_prefix=`krb5-config --prefix`
if test "$krb5_prefix" != "%{_prefix}" ; then
	CPPFLAGS="$CPPFLAGS -I${krb5_prefix}/include -I${krb5_prefix}/include/gssapi"; export CPPFLAGS
	CFLAGS="$CFLAGS -I${krb5_prefix}/include -I${krb5_prefix}/include/gssapi"
	LDFLAGS="$LDFLAGS -L${krb5_prefix}/%{_lib}"; export LDFLAGS
else
	krb5_prefix=
	CPPFLAGS="-I%{_includedir}/gssapi"; export CPPFLAGS
	CFLAGS="$CFLAGS -I%{_includedir}/gssapi"
fi
%endif

%configure \
	--sysconfdir=%{_sysconfdir}/gsissh \
	--libexecdir=%{_libexecdir}/gsissh \
	--datadir=%{_datadir}/gsissh \
	--with-tcp-wrappers \
	--with-default-path=/usr/local/bin:/bin:/usr/bin \
	--with-superuser-path=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin \
	--with-privsep-path=%{_var}/empty/gsisshd \
	--enable-vendor-patchlevel="FC-%{version}-%{release}" \
	--disable-strip \
	--without-zlib-version-check \
	--with-ssl-engine \
	--with-authorized-keys-command \
%if %{ldap}
	--with-ldap \
%endif
%if %{nss}
	--with-nss \
%endif
	--with-pam \
%if %{WITH_SELINUX}
	--with-selinux --with-audit=linux \
%endif
%if %{kerberos5}
	--with-kerberos5${krb5_prefix:+=${krb5_prefix}} \
%else
	--without-kerberos5 \
%endif
%if %{gsi}
	--with-gsi \
%else
	--without-gsi \
%endif
%if %{libedit}
	--with-libedit
%else
	--without-libedit
%endif

make SSH_PROGRAM=%{_bindir}/gsissh \
     ASKPASS_PROGRAM=%{_libexecdir}/openssh/ssh-askpass

# Add generation of HMAC checksums of the final stripped binaries
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    fipshmac $RPM_BUILD_ROOT%{_bindir}/gsissh \
    fipshmac $RPM_BUILD_ROOT%{_sbindir}/gsisshd \
%{nil}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p -m755 $RPM_BUILD_ROOT%{_sysconfdir}/gsissh
mkdir -p -m755 $RPM_BUILD_ROOT%{_libexecdir}/gsissh
mkdir -p -m755 $RPM_BUILD_ROOT%{_var}/empty/gsisshd
make install DESTDIR=$RPM_BUILD_ROOT
%if %{ldap}
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/gsissh/ldap.conf
%endif

install -d $RPM_BUILD_ROOT/etc/pam.d/
install -d $RPM_BUILD_ROOT/etc/sysconfig/
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -d $RPM_BUILD_ROOT%{_libexecdir}/gsissh
install -m644 %{SOURCE2} $RPM_BUILD_ROOT/etc/pam.d/gsisshd
install -m755 %{SOURCE3} $RPM_BUILD_ROOT/etc/rc.d/init.d/gsisshd
install -m644 %{SOURCE7} $RPM_BUILD_ROOT/etc/sysconfig/gsisshd

rm $RPM_BUILD_ROOT%{_bindir}/ssh-add
rm $RPM_BUILD_ROOT%{_bindir}/ssh-agent
rm $RPM_BUILD_ROOT%{_bindir}/ssh-keyscan
rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ssh-keycat
rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ssh-ldap-helper
rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ssh-ldap-wrapper
rm $RPM_BUILD_ROOT%{_mandir}/man1/ssh-add.1*
rm $RPM_BUILD_ROOT%{_mandir}/man1/ssh-agent.1*
rm $RPM_BUILD_ROOT%{_mandir}/man1/ssh-keyscan.1*
rm $RPM_BUILD_ROOT%{_mandir}/man5/ssh-ldap.conf.5*
rm $RPM_BUILD_ROOT%{_mandir}/man8/ssh-ldap-helper.8*
rm $RPM_BUILD_ROOT%{_datadir}/gsissh/Ssh.bin

for f in $RPM_BUILD_ROOT%{_bindir}/* \
	 $RPM_BUILD_ROOT%{_sbindir}/* \
	 $RPM_BUILD_ROOT%{_mandir}/man*/* ; do
    mv $f `dirname $f`/gsi`basename $f`
done
ln -sf gsissh $RPM_BUILD_ROOT%{_bindir}/gsislogin
ln -sf gsissh.1 $RPM_BUILD_ROOT%{_mandir}/man1/gsislogin.1

perl -pi -e "s|$RPM_BUILD_ROOT||g" $RPM_BUILD_ROOT%{_mandir}/man*/*

rm -f README.nss.nss-keys
%if ! %{nss}
rm -f README.nss
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%pre server
getent group sshd >/dev/null || groupadd -g %{sshd_uid} -r sshd || :
%if %{nologin}
getent passwd sshd >/dev/null || \
  useradd -c "Privilege-separated SSH" -u %{sshd_uid} -g sshd \
  -s /sbin/nologin -r -d /var/empty/sshd sshd 2> /dev/null || :
%else
getent passwd sshd >/dev/null || \
  useradd -c "Privilege-separated SSH" -u %{sshd_uid} -g sshd \
  -s /dev/null -r -d /var/empty/sshd sshd 2> /dev/null || :
%endif

%post server
/sbin/chkconfig --add gsisshd

%postun server
/sbin/service gsisshd condrestart > /dev/null 2>&1 || :

%preun server
if [ "$1" = 0 ]
then
	/sbin/service gsisshd stop > /dev/null 2>&1 || :
	/sbin/chkconfig --del gsisshd
fi

%files
%defattr(-,root,root)
%doc CREDITS ChangeLog INSTALL LICENCE LICENSE.globus_usage OVERVIEW PROTOCOL* README* TODO WARNING*
%attr(0755,root,root) %dir %{_sysconfdir}/gsissh
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/gsissh/moduli
%attr(0755,root,root) %{_bindir}/gsissh-keygen
%attr(0644,root,root) %{_mandir}/man1/gsissh-keygen.1*
%attr(0755,root,root) %dir %{_libexecdir}/gsissh
%attr(4755,root,root) %{_libexecdir}/gsissh/ssh-keysign
%attr(0644,root,root) %{_mandir}/man8/gsissh-keysign.8*

%files clients
%defattr(-,root,root)
%attr(0755,root,root) %{_bindir}/gsissh
%attr(0644,root,root) %{_bindir}/.gsissh.hmac
%attr(0644,root,root) %{_mandir}/man1/gsissh.1*
%attr(0755,root,root) %{_bindir}/gsiscp
%attr(0644,root,root) %{_mandir}/man1/gsiscp.1*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/gsissh/ssh_config
%attr(0755,root,root) %{_bindir}/gsislogin
%attr(0644,root,root) %{_mandir}/man1/gsislogin.1*
%attr(0644,root,root) %{_mandir}/man5/gsissh_config.5*
%attr(0755,root,root) %{_bindir}/gsisftp
%attr(0644,root,root) %{_mandir}/man1/gsisftp.1*

%files server
%defattr(-,root,root)
%dir %attr(0711,root,root) %{_var}/empty/gsisshd
%attr(0755,root,root) %{_sbindir}/gsisshd
%attr(0644,root,root) %{_sbindir}/.gsisshd.hmac
%attr(0755,root,root) %{_libexecdir}/gsissh/sftp-server
%attr(0644,root,root) %{_mandir}/man5/gsisshd_config.5*
%attr(0644,root,root) %{_mandir}/man5/gsimoduli.5*
%attr(0644,root,root) %{_mandir}/man8/gsisshd.8*
%attr(0644,root,root) %{_mandir}/man8/gsisftp-server.8*
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/gsissh/sshd_config
%attr(0644,root,root) %config(noreplace) /etc/pam.d/gsisshd
%attr(0755,root,root) /etc/rc.d/init.d/gsisshd
%attr(0640,root,root) %config(noreplace) /etc/sysconfig/gsisshd

%changelog
* Thu Oct 06 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-3
- Change package name gsissh → gsi-openssh
- Based on openssh-5.3p1-52.el6_1.2

* Wed Aug 10 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-2
- Add patch from OSG to resolve threading problems in the server
- Based on openssh-5.3p1-52.el6_1.2

* Tue Mar 08 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-1
- Initial packaging
- Based on openssh-5.3p1-20.el6_0.3
