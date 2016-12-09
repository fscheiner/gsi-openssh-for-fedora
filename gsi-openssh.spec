# gsi-openssh is openssh with support for GSI authentication
# This gsi-openssh specfile is based on the openssh specfile

# Do we want SELinux & Audit
%if 0%{?!noselinux:1}
%global WITH_SELINUX 1
%else
%global WITH_SELINUX 0
%endif

%global _hardened_build 1

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

%global openssh_ver 7.3p1
%global openssh_rel 4

Summary: An implementation of the SSH protocol with GSI authentication
Name: gsi-openssh
Version: %{openssh_ver}
Release: %{openssh_rel}%{?dist}
Provides: gsissh = %{version}-%{release}
Obsoletes: gsissh < 5.8p2-2
URL: http://www.openssh.com/portable.html
Source0: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz
Source2: gsisshd.pam
Source7: gsisshd.sysconfig
Source9: gsisshd@.service
Source10: gsisshd.socket
Source11: gsisshd.service
Source12: gsisshd-keygen@.service
Source13: gsisshd-keygen
Source14: gsisshd.tmpfiles
Source15: gsisshd-keygen.target
Source99: README.sshd-and-gsisshd

#https://bugzilla.mindrot.org/show_bug.cgi?id=2581
Patch100: openssh-6.7p1-coverity.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1894
#https://bugzilla.redhat.com/show_bug.cgi?id=735889
#Patch102: openssh-5.8p1-getaddrinfo.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1889
Patch103: openssh-5.8p1-packet.patch
# OpenSSL 1.1.0 compatibility
Patch104: openssh-7.3p1-openssl-1.1.0.patch

#https://bugzilla.mindrot.org/show_bug.cgi?id=1402
# https://bugzilla.redhat.com/show_bug.cgi?id=1171248
# record pfs= field in CRYPTO_SESSION audit event
Patch200: openssh-7.2p1-audit.patch
# Audit race condition in forked child (#1310684)
Patch201: openssh-7.1p2-audit-race-condition.patch

#https://bugzilla.mindrot.org/show_bug.cgi?id=1641 (WONTFIX)
Patch400: openssh-6.6p1-role-mls.patch
#https://bugzilla.redhat.com/show_bug.cgi?id=781634
Patch404: openssh-6.6p1-privsep-selinux.patch

#?-- unwanted child :(
Patch501: openssh-6.7p1-ldap.patch
#?
Patch502: openssh-6.6p1-keycat.patch

#https://bugzilla.mindrot.org/show_bug.cgi?id=1644
Patch601: openssh-6.6p1-allow-ip-opts.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1893 (WONTFIX)
Patch604: openssh-6.6p1-keyperm.patch
#(drop?) https://bugzilla.mindrot.org/show_bug.cgi?id=1925
Patch606: openssh-5.9p1-ipv6man.patch
#?
Patch607: openssh-5.8p2-sigpipe.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1789
Patch609: openssh-7.2p2-x11.patch

#?
Patch700: openssh-7.2p1-fips.patch
#?
Patch702: openssh-5.1p1-askpass-progress.patch
#https://bugzilla.redhat.com/show_bug.cgi?id=198332
Patch703: openssh-4.3p2-askpass-grab-info.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1635 (WONTFIX)
Patch707: openssh-6.6p1-redhat.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1890 (WONTFIX) need integration to prng helper which is discontinued :)
Patch708: openssh-6.6p1-entropy.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1640 (WONTFIX)
Patch709: openssh-6.2p1-vendor.patch
# warn users for unsupported UsePAM=no (#757545)
Patch711: openssh-7.2p2-UsePAM-UseLogin-warning.patch
# make aes-ctr ciphers use EVP engines such as AES-NI from OpenSSL
Patch712: openssh-6.3p1-ctr-evp-fast.patch
# add cavs test binary for the aes-ctr
Patch713: openssh-6.6p1-ctr-cavstest.patch
# add SSH KDF CAVS test driver
Patch714: openssh-6.7p1-kdf-cavs.patch

#http://www.sxw.org.uk/computing/patches/openssh.html
#changed cache storage type - #848228
Patch800: openssh-7.2p1-gsskex.patch
#http://www.mail-archive.com/kerberos@mit.edu/msg17591.html
Patch801: openssh-6.6p1-force_krb.patch
# add new option GSSAPIEnablek5users and disable using ~/.k5users by default (#1169843)
# CVE-2014-9278
Patch802: openssh-6.6p1-GSSAPIEnablek5users.patch
# Documentation about GSSAPI
# from https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=765655
Patch803: openssh-7.1p1-gssapi-documentation.patch
# use default_ccache_name from /etc/krb5.conf (#991186)
Patch804: openssh-6.3p1-krb5-use-default_ccache_name.patch
# Respect k5login_directory option in krk5.conf (#1328243)
Patch805: openssh-7.2p2-k5login_directory.patch

Patch900: openssh-6.1p1-gssapi-canohost.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1780
Patch901: openssh-6.6p1-kuserok.patch
# Use tty allocation for a remote scp (#985650)
Patch906: openssh-6.4p1-fromto-remote.patch
# privsep_preauth: use SELinux context from selinux-policy (#1008580)
Patch916: openssh-6.6.1p1-selinux-contexts.patch
# use different values for DH for Cisco servers (#1026430)
Patch917: openssh-6.6.1p1-cisco-dh-keys.patch
# log via monitor in chroots without /dev/log
Patch918: openssh-6.6.1p1-log-in-chroot.patch
# scp file into non-existing directory (#1142223)
Patch919: openssh-6.6.1p1-scp-non-existing-directory.patch
# Config parser shouldn't accept ip/port syntax (#1130733)
Patch920: openssh-6.6.1p1-ip-port-config-parser.patch
# restore tcp wrappers support, based on Debian patch
# https://lists.mindrot.org/pipermail/openssh-unix-dev/2014-April/032497.html
Patch921: openssh-6.7p1-debian-restore-tcp-wrappers.patch
# apply upstream patch and make sshd -T more consistent (#1187521)
Patch922: openssh-6.8p1-sshdT-output.patch
# Add sftp option to force mode of created files (#1191055)
Patch926: openssh-6.7p1-sftp-force-permission.patch
# Memory problems
# https://bugzilla.mindrot.org/show_bug.cgi?id=2401
Patch928: openssh-6.8p1-memory-problems.patch
# Restore compatible default (#89216)
Patch929: openssh-6.9p1-permit-root-login.patch
# Add GSSAPIKexAlgorithms option for server and client application
Patch932: openssh-7.0p1-gssKexAlgorithms.patch
# Possibility to validate legacy systems by more fingerprints (#1249626)(#2439)
Patch933: openssh-7.0p1-show-more-fingerprints.patch
# make s390 use /dev/ crypto devices -- ignore closefrom
Patch939: openssh-7.2p2-s390-closefrom.patch
# expose more information to PAM
# https://github.com/openssh/openssh-portable/pull/47
Patch940: openssh-7.2p2-expose-pam.patch
# Rework SELinux context handling with chroot (#1357860)
Patch942: openssh-7.2p2-chroot-capabilities.patch
# Null dereference in newkeys code (#1380297)
Patch943: openssh-7.3p1-null-deref.patch
# Move MAX_DISPLAYS to a configuration option (#1341302)
Patch944: openssh-7.3p1-x11-max-displays.patch

# This is the patch that adds GSI support
# Based on http://grid.ncsa.illinois.edu/ssh/dl/patch/openssh-7.0p1.patch
Patch98: openssh-7.3p1-gsissh.patch

License: BSD
Group: Applications/Internet
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: /sbin/nologin
Obsoletes: %{name}-clients-fips, %{name}-server-fips

%if %{ldap}
BuildRequires: openldap-devel
%endif
BuildRequires: autoconf, automake, perl, perl-generators, zlib-devel
BuildRequires: audit-libs-devel >= 2.0.5
BuildRequires: util-linux, groff
BuildRequires: pam-devel
BuildRequires: tcp_wrappers-devel
BuildRequires: fipscheck-devel >= 1.3.0
BuildRequires: openssl-devel >= 0.9.8j
BuildRequires: libcap-ng-devel

%if %{kerberos5}
BuildRequires: krb5-devel
%endif

%if %{gsi}
BuildRequires: globus-gss-assist-devel >= 8
BuildRequires: globus-gssapi-gsi-devel >= 10
BuildRequires: globus-common-devel >= 14
BuildRequires: globus-usage-devel >= 3
%endif

%if %{libedit}
BuildRequires: libedit-devel ncurses-devel
%endif

%if %{WITH_SELINUX}
Requires: libselinux >= 2.3-5
BuildRequires: libselinux-devel >= 2.3-5
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
Recommends: crypto-policies

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

# investigate %patch102 -p1 -b .getaddrinfo
%patch103 -p1 -b .packet

%patch400 -p1 -b .role-mls
%patch404 -p1 -b .privsep-selinux

%if %{ldap}
%patch501 -p1 -b .ldap
%endif
%patch502 -p1 -b .keycat

%patch601 -p1 -b .ip-opts
%patch604 -p1 -b .keyperm
%patch606 -p1 -b .ipv6man
%patch607 -p1 -b .sigpipe
%patch609 -p1 -b .x11

%patch702 -p1 -b .progress
%patch703 -p1 -b .grab-info
%patch707 -p1 -b .redhat
%patch708 -p1 -b .entropy
%patch709 -p1 -b .vendor
%patch711 -p1 -b .log-usepam-no
%patch712 -p1 -b .evp-ctr
%patch713 -p1 -b .ctr-cavs
%patch714 -p1 -b .kdf-cavs

%patch800 -p1 -b .gsskex
%patch801 -p1 -b .force_krb
%patch803 -p1 -b .gss-docs
%patch804 -p1 -b .ccache_name
%patch805 -p1 -b .k5login

%patch900 -p1 -b .canohost
%patch901 -p1 -b .kuserok
%patch906 -p1 -b .fromto-remote
%patch916 -p1 -b .contexts
#%patch917 -p1 -b .cisco-dh # investigate
%patch918 -p1 -b .log-in-chroot
%patch919 -p1 -b .scp
%patch920 -p1 -b .config
%patch802 -p1 -b .GSSAPIEnablek5users
%patch921 -p1 -b .tcp_wrappers
%patch922 -p1 -b .sshdt
%patch926 -p1 -b .sftp-force-mode
%patch928 -p1 -b .memory
%patch929 -p1 -b .root-login
%patch932 -p1 -b .gsskexalg
%patch933 -p1 -b .fingerprint
%patch939 -p1 -b .s390-dev
%patch940 -p1 -b .expose-pam
%patch942 -p1 -b .chroot-cap
%patch943 -p1 -b .deref
%patch944 -p1 -b .x11max

%patch200 -p1 -b .audit
%patch201 -p1 -b .audit-race
%patch700 -p1 -b .fips

%patch100 -p1 -b .coverity
%patch104 -p1 -b .openssl

%patch98 -p1 -b .gsi

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
	--with-default-path=/usr/local/bin:/usr/bin \
	--with-superuser-path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin \
	--with-privsep-path=%{_var}/empty/gsisshd \
	--enable-vendor-patchlevel="FC-%{openssh_ver}-%{openssh_rel}" \
	--disable-strip \
	--without-zlib-version-check \
	--with-ssl-engine \
	--with-ipaddr-display \
	--with-pie=no \
%if %{ldap}
	--with-ldap \
%endif
	--with-pam \
%if %{WITH_SELINUX}
	--with-selinux --with-audit=linux \
%ifnarch ppc
	--with-sandbox=seccomp_filter \
%else
	--with-sandbox=rlimit \
%endif
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
%global __spec_install_post \
    %%{?__debug_package:%%{__debug_install_post}} \
    %%{__arch_install_post} \
    %%{__os_install_post} \
    fipshmac -d $RPM_BUILD_ROOT%{_libdir}/fipscheck $RPM_BUILD_ROOT%{_bindir}/gsissh $RPM_BUILD_ROOT%{_sbindir}/gsisshd \
%{nil}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p -m755 $RPM_BUILD_ROOT%{_sysconfdir}/gsissh
mkdir -p -m755 $RPM_BUILD_ROOT%{_sysconfdir}/gsissh/ssh_config.d
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
install -m644 ssh_config_redhat $RPM_BUILD_ROOT/etc/gsissh/ssh_config.d/05-redhat.conf
install -d -m755 $RPM_BUILD_ROOT/%{_unitdir}
install -m644 %{SOURCE9} $RPM_BUILD_ROOT/%{_unitdir}/gsisshd@.service
install -m644 %{SOURCE10} $RPM_BUILD_ROOT/%{_unitdir}/gsisshd.socket
install -m644 %{SOURCE11} $RPM_BUILD_ROOT/%{_unitdir}/gsisshd.service
install -m644 %{SOURCE12} $RPM_BUILD_ROOT/%{_unitdir}/gsisshd-keygen@.service
install -m644 %{SOURCE15} $RPM_BUILD_ROOT/%{_unitdir}/gsisshd-keygen.target
install -m755 %{SOURCE13} $RPM_BUILD_ROOT/%{_libexecdir}/gsissh/sshd-keygen
install -m644 -D %{SOURCE14} $RPM_BUILD_ROOT%{_tmpfilesdir}/gsissh.conf

rm $RPM_BUILD_ROOT%{_bindir}/ssh-add
rm $RPM_BUILD_ROOT%{_bindir}/ssh-agent
rm $RPM_BUILD_ROOT%{_bindir}/ssh-keyscan
rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ctr-cavstest
rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ssh-cavs
rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ssh-cavs_driver.pl
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

perl -pi -e "s|$RPM_BUILD_ROOT||g" $RPM_BUILD_ROOT%{_mandir}/man*/*

%clean
rm -rf $RPM_BUILD_ROOT

%pre
getent group ssh_keys >/dev/null || groupadd -r ssh_keys || :

%pre server
getent group sshd >/dev/null || groupadd -g %{sshd_uid} -r sshd || :
getent passwd sshd >/dev/null || \
  useradd -c "Privilege-separated SSH" -u %{sshd_uid} -g sshd \
  -s /sbin/nologin -r -d /var/empty/sshd sshd 2> /dev/null || :

%post server
%systemd_post gsisshd.service gsisshd.socket

%preun server
%systemd_preun gsisshd.service gsisshd.socket

%postun server
%systemd_postun_with_restart gsisshd.service

%files
%license LICENCE LICENSE.globus_usage
%doc CREDITS ChangeLog INSTALL OVERVIEW PROTOCOL* README README.platform README.privsep README.tun README.dns README.sshd-and-gsisshd TODO
%attr(0755,root,root) %dir %{_sysconfdir}/gsissh
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/gsissh/moduli
%attr(0755,root,root) %{_bindir}/gsissh-keygen
%attr(0644,root,root) %{_mandir}/man1/gsissh-keygen.1*
%attr(0755,root,root) %dir %{_libexecdir}/gsissh
%attr(2755,root,ssh_keys) %{_libexecdir}/gsissh/ssh-keysign
%attr(0644,root,root) %{_mandir}/man8/gsissh-keysign.8*

%files clients
%attr(0755,root,root) %{_bindir}/gsissh
%attr(0644,root,root) %{_libdir}/fipscheck/gsissh.hmac
%attr(0644,root,root) %{_mandir}/man1/gsissh.1*
%attr(0755,root,root) %{_bindir}/gsiscp
%attr(0644,root,root) %{_mandir}/man1/gsiscp.1*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/gsissh/ssh_config
%dir %attr(0755,root,root) %{_sysconfdir}/gsissh/ssh_config.d/
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/gsissh/ssh_config.d/05-redhat.conf
%attr(0644,root,root) %{_mandir}/man5/gsissh_config.5*
%attr(0755,root,root) %{_bindir}/gsisftp
%attr(0644,root,root) %{_mandir}/man1/gsisftp.1*

%files server
%dir %attr(0711,root,root) %{_var}/empty/gsisshd
%attr(0755,root,root) %{_sbindir}/gsisshd
%attr(0644,root,root) %{_libdir}/fipscheck/gsisshd.hmac
%attr(0755,root,root) %{_libexecdir}/gsissh/sftp-server
%attr(0755,root,root) %{_libexecdir}/gsissh/sshd-keygen
%attr(0644,root,root) %{_mandir}/man5/gsisshd_config.5*
%attr(0644,root,root) %{_mandir}/man5/gsimoduli.5*
%attr(0644,root,root) %{_mandir}/man8/gsisshd.8*
%attr(0644,root,root) %{_mandir}/man8/gsisftp-server.8*
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/gsissh/sshd_config
%attr(0644,root,root) %config(noreplace) /etc/pam.d/gsisshd
%attr(0640,root,root) %config(noreplace) /etc/sysconfig/gsisshd
%attr(0644,root,root) %{_unitdir}/gsisshd.service
%attr(0644,root,root) %{_unitdir}/gsisshd@.service
%attr(0644,root,root) %{_unitdir}/gsisshd.socket
%attr(0644,root,root) %{_unitdir}/gsisshd-keygen@.service
%attr(0644,root,root) %{_unitdir}/gsisshd-keygen.target
%attr(0644,root,root) %{_tmpfilesdir}/gsissh.conf

%changelog
* Fri Dec 09 2016 Mattias Ellert <mattias.ellert@physics.uu.se> - 7.3p1-4
- Based on openssh-7.3p1-7.fc25

* Wed Nov 02 2016 Mattias Ellert <mattias.ellert@physics.uu.se> - 7.3p1-3
- Based on openssh-7.3p1-5.fc26

* Thu Oct 20 2016 Mattias Ellert <mattias.ellert@physics.uu.se> - 7.3p1-2
- Based on openssh-7.3p1-4.fc25

* Mon Aug 15 2016 Mattias Ellert <mattias.ellert@physics.uu.se> - 7.3p1-1
- Based on openssh-7.3p1-3.fc25

* Mon Jul 18 2016 Mattias Ellert <mattias.ellert@physics.uu.se> - 7.2p2-6
- Based on openssh-7.2p2-10.fc24

* Sun Jul 03 2016 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.2p2-5
- Based on openssh-7.2p2-9.fc24

* Sun Jun 26 2016 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.2p2-4
- Based on openssh-7.2p2-8.fc24

* Thu May 12 2016 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.2p2-3
- Based on openssh-7.2p2-5.fc24

* Sat Apr 16 2016 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.2p2-2
- Based on openssh-7.2p2-4.fc24

* Sat Apr 16 2016 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.2p2-1
- Based on openssh-7.2p2-2.fc23

* Fri Mar 04 2016 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.2p1-1
- Based on openssh-7.2p1-2.fc23

* Wed Mar 02 2016 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.1p2-4
- Based on openssh-7.1p2-4.fc23

* Wed Feb 03 2016 Fedora Release Engineering <releng@fedoraproject.org> - 7.1p2-3.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Mon Feb 01 2016 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.1p2-3
- Based on openssh-7.1p2-3.fc23

* Fri Jan 29 2016 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.1p2-2
- Based on openssh-7.1p2-2.fc23

* Tue Jan 19 2016 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.1p2-1
- Based on openssh-7.1p2-1.fc23

* Thu Oct 08 2015 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.1p1-2
- Based on openssh-7.1p1-3.fc23

* Mon Aug 24 2015 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.1p1-1
- Based on openssh-7.1p1-1.fc23

* Fri Aug 14 2015 Mattias Ellert <mattias.ellert@fysast.uu.se> - 7.0p1-1
- Based on openssh-7.0p1-1.fc23

* Wed Jul 29 2015 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.9p1-3
- Based on openssh-6.9p1-4.fc22

* Mon Jul 27 2015 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.9p1-2
- Based on openssh-6.9p1-3.fc22

* Sun Jul 05 2015 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.9p1-1
- Based on openssh-6.9p1-1.fc22

* Wed Jun 17 2015 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 6.8p1-2.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_23_Mass_Rebuild

* Tue Apr 21 2015 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.8p1-2
- Based on openssh-6.8p1-5.fc22

* Mon Apr 13 2015 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.8p1-1
- Based on openssh-6.8p1-4.fc22

* Mon Apr 13 2015 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.6.1p1-5
- Based on openssh-6.6.1p1-12.fc21

* Thu Jan 15 2015 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.6.1p1-4
- Based on openssh-6.6.1p1-11.1.fc21

* Mon Nov 24 2014 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.6.1p1-3
- Based on openssh-6.6.1p1-8.fc21

* Wed Oct 22 2014 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.6.1p1-2
- Based on openssh-6.6.1p1-5.fc21

* Sat Aug 16 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 6.6.1p1-1.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Wed Jul 16 2014 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.6.1p1-1
- Based on openssh-6.6.1p1-2.fc21

* Thu Jul 10 2014 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.4p1-3
- Based on openssh-6.4p1-4.fc20

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 6.4p1-2.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Wed Dec 11 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.4p1-2
- Based on openssh-6.4p1-3.fc20

* Tue Nov 26 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.4p1-1
- Based on openssh-6.4p1-2.fc20

* Mon Oct 21 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.3p1-2
- Add obsoletes for -fips packages

* Tue Oct 15 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.3p1-1
- Based on openssh-6.3p1-1.fc20

* Wed Oct 02 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.2p2-3
- Based on openssh-6.2p2-8.fc20

* Fri Aug 23 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.2p2-2
- Based on openssh-6.2p2-5.fc19

* Sat Aug 03 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 6.2p2-1.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_20_Mass_Rebuild

* Mon Jun 24 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.2p2-1
- Based on openssh-6.2p2-3.fc19

* Fri Apr 26 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.2p1-3
- Based on openssh-6.2p1-4.fc19

* Wed Apr 17 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.2p1-2
- Based on openssh-6.2p1-3.fc19

* Wed Apr 10 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.2p1-1
- Based on openssh-6.2p1-2.fc19

* Sat Apr 06 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.1p1-5
- Based on openssh-6.1p1-7.fc19
- Security fix for vulnerability
    http://grid.ncsa.illinois.edu/ssh/pamuserchange-2013-01.adv
    https://wiki.egi.eu/wiki/SVG:Advisory-SVG-2013-5168

* Tue Feb 26 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.1p1-4
- Based on openssh-6.1p1-6.fc18

* Thu Feb 14 2013 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 6.1p1-3.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_19_Mass_Rebuild

* Mon Dec 10 2012 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.1p1-3
- Based on openssh-6.1p1-4.fc18

* Thu Nov 01 2012 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.1p1-2
- Based on openssh-6.1p1-2.fc18

* Tue Sep 18 2012 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.1p1-1
- Based on openssh-6.1p1-1.fc18

* Mon Aug 13 2012 Mattias Ellert <mattias.ellert@fysast.uu.se> - 6.0p1-1
- Based on openssh-6.0p1-1.fc18

* Mon Aug 13 2012 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9p1-7
- Based on openssh-5.9p1-26.fc17

* Thu Jul 19 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 5.9p1-6.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Fri May 11 2012 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9p1-6
- Based on openssh-5.9p1-22.fc17

* Wed Feb 08 2012 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9p1-5
- Based on openssh-5.9p1-19.fc17

* Sun Jan 22 2012 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9p1-4
- Drop openssh-5.8p2-unblock-signals.patch - not needed for GT >= 5.2
- Based on openssh-5.9p1-16.fc17

* Fri Jan 13 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 5.9p1-3.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Sun Nov 27 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9p1-3
- Based on openssh-5.9p1-13.fc17

* Thu Nov 17 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9p1-2
- Based on openssh-5.9p1-11.fc17

* Thu Oct 06 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.9p1-1
- Initial packaging
- Based on openssh-5.9p1-7.fc17
