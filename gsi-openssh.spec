# gsi-openssh is openssh with support for GSI authentication
# This gsi-openssh specfile is based on the openssh specfile

# Do we want SELinux & Audit
%if 0%{?!noselinux:1}
%global WITH_SELINUX 1
%else
%global WITH_SELINUX 0
%endif

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

# Do we want libedit support
%global libedit 1

# Do we want LDAP support
%global ldap 1

# Do we want NSS tokens support
# NSS support is broken from 5.4p1
%global nss 0

# Whether or not /sbin/nologin exists.
%global nologin 1

%global openssh_ver 5.8p2
%global openssh_rel 3

Summary: An implementation of the SSH protocol with GSI authentication
Name: gsi-openssh
Version: %{openssh_ver}
Release: %{openssh_rel}%{?dist}
Provides: gsissh = %{version}-%{release}
Obsoletes: gsissh < 5.8p2-2
URL: http://www.openssh.com/portable.html
#Source0: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz
#Source1: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz.asc
# This package differs from the upstream OpenSSH tarball in that
# the ACSS cipher is removed by running openssh-nukeacss.sh in
# the unpacked source directory.
Source0: openssh-%{version}-noacss.tar.bz2
Source1: openssh-nukeacss.sh
Source2: gsisshd.pam
Source7: gsisshd.sysconfig
Source8: gsisshd-keygen.service
Source11: gsisshd.service
Source13: gsisshd-keygen
Source99: README.sshd-and-gsisshd

Patch0: openssh-5.6p1-redhat.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1872
Patch100: openssh-5.8p1-fingerprint.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1879
Patch200: openssh-5.8p1-exit.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1894
Patch300: openssh-5.8p1-getaddrinfo.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1402
Patch8: openssh-5.8p1-audit0.patch
Patch1: openssh-5.8p1-audit1.patch
Patch2: openssh-5.8p1-audit2.patch
Patch3: openssh-5.8p1-audit3.patch
Patch4: openssh-5.8p1-audit4.patch
Patch5: openssh-5.8p1-audit5.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1889
Patch6: openssh-5.8p1-packet.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1890 (WONTFIX) need integration to prng helper
Patch7: openssh-5.8p1-entropy.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1640 (WONTFIX)
Patch9: openssh-5.8p1-vendor.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1663
Patch20: openssh-5.8p1-authorized-keys-command.patch
#?-- unwanted child :(
Patch21: openssh-5.8p1-ldap.patch
# #-mail-conf
# Patch22: openssh-5.8p1-selinux.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1641 (WONTFIX)
Patch23: openssh-5.8p1-selinux-role.patch
#?
Patch24: openssh-5.8p1-mls.patch
# #https://bugzilla.mindrot.org/show_bug.cgi?id=1614
# Patch25: openssh-5.6p1-selabel.patch
#was https://bugzilla.mindrot.org/show_bug.cgi?id=1637
#?
Patch26: openssh-5.8p1-sftpcontext.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1668
Patch30: openssh-5.6p1-keygen.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1644
Patch31: openssh-5.2p1-allow-ip-opts.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1701
Patch32: openssh-5.8p1-randclean.patch
# #https://bugzilla.mindrot.org/show_bug.cgi?id=1636
# Patch33: openssh-5.1p1-log-in-chroot.patch
#http://cvsweb.netbsd.org/cgi-bin/cvsweb.cgi/src/crypto/dist/ssh/Attic/sftp-glob.c.diff?r1=1.13&r2=1.13.12.1&f=h
Patch35: openssh-5.8p1-glob.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1891
Patch36: openssh-5.8p1-pwchange.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1893
Patch37: openssh-5.8p1-keyperm.patch
#?
Patch50: openssh-5.8p1-fips.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1789
Patch51: openssh-5.5p1-x11.patch
#?
Patch52: openssh-5.6p1-exit-deadlock.patch
#?
Patch53: openssh-5.1p1-askpass-progress.patch
#?
Patch54: openssh-4.3p2-askpass-grab-info.patch
#?
Patch56: openssh-5.2p1-edns.patch
#?
Patch57: openssh-5.1p1-scp-manpage.patch
#?
Patch58: openssh-5.8p1-keycat.patch
#http://www.sxw.org.uk/computing/patches/openssh.html
Patch60: openssh-5.8p1-gsskex.patch
#?
Patch61: openssh-5.8p1-gssapi-canohost.patch
#?
Patch62: openssh-5.8p1-localdomain.patch
#http://www.mail-archive.com/kerberos@mit.edu/msg17591.html
Patch63: openssh-5.8p2-force_krb.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1780
Patch64: openssh-5.8p2-kuserok.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1329 (WONTFIX)
Patch65: openssh-5.8p2-remove-stale-control-socket.patch
#?
Patch66: openssh-5.8p2-ipv6man.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1919
Patch67: openssh-5.8p2-unconfined.patch
#?
Patch69: openssh-5.8p2-askpass-ld.patch
#https://bugzilla.redhat.com/show_bug.cgi?id=739989
Patch70: openssh-5.8p2-copy-id-restorecon.patch
#---
#https://bugzilla.mindrot.org/show_bug.cgi?id=1604
# sctp
#https://bugzilla.mindrot.org/show_bug.cgi?id=1873 => https://bugzilla.redhat.com/show_bug.cgi?id=668993

# This is the patch that adds GSI support
# Based on http://grid.ncsa.illinois.edu/ssh/dl/patch/openssh-5.8p2.patch
Patch98: openssh-5.8p2-gsissh.patch

# The gsissh server has problems with blocked signals in threaded globus libs
# This patch from OSG resolves these problems
Patch99: openssh-5.8p2-unblock-signals.patch

License: BSD
Group: Applications/Internet
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
%if %{nologin}
Requires: /sbin/nologin
%endif

Requires: initscripts >= 5.20

%if %{ldap}
BuildRequires: openldap-devel
%endif
BuildRequires: autoconf, automake, perl, zlib-devel
BuildRequires: audit-libs-devel >= 2.0.5
BuildRequires: util-linux, groff
BuildRequires: pam-devel
BuildRequires: tcp_wrappers-devel
BuildRequires: fipscheck-devel >= 1.3.0
BuildRequires: openssl-devel >= 0.9.8j

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
Provides: gsissh-clients = %{version}-%{release}
Obsoletes: gsissh-clients < 5.8p2-2
Group: Applications/Internet
Requires: %{name} = %{version}-%{release}
Requires: fipscheck-lib%{_isa} >= 1.3.0

%package server
Summary: SSH server daemon with GSI authentication
Provides: gsissh-server = %{version}-%{release}
Obsoletes: gsissh-server < 5.8p2-2
Group: System Environment/Daemons
Requires: %{name} = %{version}-%{release}
Requires(pre): /usr/sbin/useradd
Requires: pam >= 1.0.1-3
Requires: fipscheck-lib%{_isa} >= 1.3.0
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units
# This is actually needed for the %triggerun script but Requires(triggerun)
# is not valid.  We can use %post because this particular %triggerun script
# should fire just after this package is installed.
Requires(post): systemd-sysv

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
%patch100 -p1 -b .fingerprint
%patch200 -p1 -b .exit
%patch300 -p1 -b .getaddrinfo
%patch8 -p1 -b .audit0
%patch1 -p1 -b .audit1
%patch2 -p1 -b .audit2
%patch3 -p1 -b .audit3
%patch4 -p1 -b .audit4
%patch5 -p1 -b .audit5
%patch6 -p1 -b .packet
%patch7 -p1 -b .entropy
%patch9 -p1 -b .vendor
%patch20 -p1 -b .akc
%if %{ldap}
%patch21 -p1 -b .ldap
%endif
%if %{WITH_SELINUX}
#SELinux
# %patch22 -p1 -b .selinux
%patch23 -p1 -b .role
%patch24 -p1 -b .mls
%patch26 -p1 -b .sftpcontext
%endif
%patch30 -p1 -b .keygen
%patch31 -p1 -b .ip-opts
%patch32 -p1 -b .randclean
%patch35 -p1 -b .glob
%patch36 -p1 -b .pwchange
%patch37 -p1 -b .keyperm

%patch50 -p1 -b .fips
%patch51 -p1 -b .x11
%patch52 -p1 -b .exit-deadlock
%patch53 -p1 -b .progress
%patch54 -p1 -b .grab-info
%patch56 -p1 -b .edns
%patch57 -p1 -b .manpage
%patch58 -p1 -b .keycat
%patch60 -p1 -b .gsskex
%patch61 -p1 -b .canohost
%patch62 -p1 -b .localdomain
%patch63 -p1 -b .force_krb
%patch64 -p1 -b .kuserok
%patch65 -p1 -b .remove_stale
%patch66 -p1 -b .ipv6man
%patch67 -p1 -b .unconfined
%patch69 -p1 -b .askpass-ld
%patch70 -p1 -b .restorecon
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
LDFLAGS="$LDFLAGS -pie -z relro -z now"

export CFLAGS
export LDFLAGS

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
%if %{nss}
	--with-nss \
%endif
%if %{ldap}
	--with-ldap \
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
    fipshmac -d $RPM_BUILD_ROOT%{_libdir}/fipscheck $RPM_BUILD_ROOT%{_bindir}/gsissh $RPM_BUILD_ROOT%{_sbindir}/gsisshd \
%{nil}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p -m755 $RPM_BUILD_ROOT%{_sysconfdir}/gsissh
mkdir -p -m755 $RPM_BUILD_ROOT%{_libexecdir}/gsissh
mkdir -p -m755 $RPM_BUILD_ROOT%{_var}/empty/gsisshd
make install DESTDIR=$RPM_BUILD_ROOT
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/gsissh/ldap.conf

install -d $RPM_BUILD_ROOT/etc/pam.d/
install -d $RPM_BUILD_ROOT/etc/sysconfig/
install -d $RPM_BUILD_ROOT%{_libexecdir}/gsissh
install -d $RPM_BUILD_ROOT%{_libdir}/fipscheck
install -m644 %{SOURCE2} $RPM_BUILD_ROOT/etc/pam.d/gsisshd
install -m644 %{SOURCE7} $RPM_BUILD_ROOT/etc/sysconfig/gsisshd
install -m755 %{SOURCE13} $RPM_BUILD_ROOT/%{_sbindir}/sshd-keygen
install -d -m755 $RPM_BUILD_ROOT/%{_unitdir}
install -m644 %{SOURCE8} $RPM_BUILD_ROOT/%{_unitdir}/gsisshd-keygen.service
install -m644 %{SOURCE11} $RPM_BUILD_ROOT/%{_unitdir}/gsisshd.service

rm $RPM_BUILD_ROOT%{_bindir}/ssh-add
rm $RPM_BUILD_ROOT%{_bindir}/ssh-agent
rm $RPM_BUILD_ROOT%{_bindir}/ssh-keyscan
rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ssh-ldap-helper
rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ssh-ldap-wrapper
rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ssh-keycat
rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ssh-pkcs11-helper
rm $RPM_BUILD_ROOT%{_mandir}/man1/ssh-add.1*
rm $RPM_BUILD_ROOT%{_mandir}/man1/ssh-agent.1*
rm $RPM_BUILD_ROOT%{_mandir}/man1/ssh-keyscan.1*
rm $RPM_BUILD_ROOT%{_mandir}/man5/ssh-ldap.conf.5*
rm $RPM_BUILD_ROOT%{_mandir}/man8/ssh-ldap-helper.8*
rm $RPM_BUILD_ROOT%{_mandir}/man8/ssh-pkcs11-helper.8*

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

%pre
getent group ssh_keys >/dev/null || groupadd -r ssh_keys || :

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

%postun server
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
    /bin/systemctl try-restart gsisshd.service >/dev/null 2>&1 || :
    /bin/systemctl try-restart gsisshd-keygen.service >/dev/null 2>&1 || :
fi

%preun server
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
    /bin/systemctl --no-reload disable gsisshd.service > /dev/null 2>&1 || :
    /bin/systemctl --no-reload disable gsisshd-keygen.service > /dev/null 2>&1 || :
    /bin/systemctl stop gsisshd.service > /dev/null 2>&1 || :
    /bin/systemctl stop gsisshd-keygen.service > /dev/null 2>&1 || :
fi

%triggerun server -- gsi-openssh-server < 5.8p2-1
/usr/bin/systemd-sysv-convert --save gsisshd >/dev/null 2>&1 || :
/sbin/chkconfig --del gsisshd >/dev/null 2>&1 || :
/bin/systemctl try-restart gsisshd.service >/dev/null 2>&1 || :
# This one was never a service, so we don't simply restart it
/bin/systemctl is-active -q gsisshd.service && /bin/systemctl start gsisshd-keygen.service >/dev/null 2>&1 || :

%files
%defattr(-,root,root)
%doc CREDITS ChangeLog INSTALL LICENCE LICENSE.globus_usage OVERVIEW PROTOCOL* README README.platform README.privsep README.tun README.dns README.sshd-and-gsisshd TODO WARNING*
%attr(0755,root,root) %dir %{_sysconfdir}/gsissh
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/gsissh/moduli
%attr(0755,root,root) %{_bindir}/gsissh-keygen
%attr(0644,root,root) %{_mandir}/man1/gsissh-keygen.1*
%attr(0755,root,root) %dir %{_libexecdir}/gsissh
%attr(2755,root,ssh_keys) %{_libexecdir}/gsissh/ssh-keysign
%attr(0644,root,root) %{_mandir}/man8/gsissh-keysign.8*

%files clients
%defattr(-,root,root)
%attr(0755,root,root) %{_bindir}/gsissh
%attr(0644,root,root) %{_libdir}/fipscheck/gsissh.hmac
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
%attr(0755,root,root) %{_sbindir}/gsisshd-keygen
%attr(0644,root,root) %{_libdir}/fipscheck/gsisshd.hmac
%attr(0755,root,root) %{_libexecdir}/gsissh/sftp-server
%attr(0644,root,root) %{_mandir}/man5/gsisshd_config.5*
%attr(0644,root,root) %{_mandir}/man5/gsimoduli.5*
%attr(0644,root,root) %{_mandir}/man8/gsisshd.8*
%attr(0644,root,root) %{_mandir}/man8/gsisftp-server.8*
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/gsissh/sshd_config
%attr(0644,root,root) %config(noreplace) /etc/pam.d/gsisshd
%attr(0640,root,root) %config(noreplace) /etc/sysconfig/gsisshd
%attr(0644,root,root) %{_unitdir}/gsisshd-keygen.service
%attr(0644,root,root) %{_unitdir}/gsisshd.service

%changelog
* Sun Nov 27 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.8p2-3
- Based on openssh-5.8p2-22.fc16

* Thu Oct 06 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.8p2-2
- Change package name gsissh → gsi-openssh
- Based on openssh-5.8p2-16.fc16.1

* Wed Aug 10 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.8p2-1
- Add patch from OSG to resolve threading problems in the server
- Based on openssh-5.8p2-16.fc16.1

* Sat Mar 05 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.8p1-1
- Initial packaging
- Based on openssh-5.8p1-14.fc16.1
