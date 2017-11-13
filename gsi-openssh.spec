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

# Do we want LDAP support
%global ldap 1

# Do we want libedit support
%global libedit 1

# Do we want NSS tokens support
%global nss 1

# Whether or not /sbin/nologin exists.
%global nologin 1

%global openssh_ver 5.3p1
%global openssh_rel 17

Summary: An implementation of the SSH protocol with GSI authentication
Name: gsi-openssh
Version: %{openssh_ver}
Release: %{openssh_rel}%{?dist}
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
Patch19: openssh-5.3p1-sesftp.patch
Patch22: openssh-3.9p1-askpass-keep-above.patch
Patch24: openssh-4.3p1-fromto-remote.patch
Patch27: openssh-5.1p1-log-in-chroot.patch
Patch30: openssh-4.0p1-exit-deadlock.patch
Patch35: openssh-5.1p1-askpass-progress.patch
Patch38: openssh-4.3p2-askpass-grab-info.patch
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
Patch90: openssh-5.3p1-ipv6man.patch
Patch91: openssh-5.3p1-manerr.patch
Patch92: openssh-5.3p1-askpass-ld.patch
# make aes-ctr ciphers use EVP engines such as AES-NI from OpenSSL
Patch93: openssh-5.3p1-ctr-evp-fast.patch
# adjust Linux out-of-memory killer (#744236)
Patch94: openssh-5.3p1-linux-oomkiller.patch
# add RequiredAuthentications (#657378)
Patch95: openssh-5.3p1-required-authentications.patch
# run privsep slave process as the users SELinux context (#798241)
Patch96: openssh-5.3p1-selinux-privsep.patch
# don't escape backslah in a banner (#809619)
Patch97: openssh-5.3p1-noslash.patch
# prevent post-auth resource exhaustion (#809938)
Patch98: openssh-5.3p1-prevent-post-auth-resource-exhaustion.patch
# use IPV6_V6ONLY also for channels (#732955)
Patch99: openssh-5.3p1-v6only.patch
# Add a 'netcat mode' (ssh -W) (#860809)
Patch100: openssh-5.3p1-netcat-mode.patch
# change the bad key permissions error message (#880575)
Patch101: openssh-5.3p1-880575.patch
# fix a race condition in ssh-agent (#896561)
Patch102: openssh-5.3p1-ssh-agent-fix-race.patch
# backport support for PKCS11 from openssh-5.4p1 (#908038)
# https://bugzilla.mindrot.org/show_bug.cgi?id=1371
Patch103: openssh-5.3p1-pkcs11-support.patch
# add a KexAlgorithms knob to the client and server configuration (#951704)
Patch104: openssh-5.3p1-KexAlgorithms.patch
# Add HMAC-SHA2 algorithm support (#969565)
Patch105: openssh-5.3p1-hmac-sha2.patch
# Fix man page typos (#896547)
Patch106: openssh-5.3p1-fix-manpage-typos.patch
# Add support for certificate key types for users and hosts (#906872)
Patch107: openssh-5.3p1-ssh-certificates.patch
# Apply RFC3454 stringprep to banners when possible (#955792)
Patch108: openssh-5.3p1-utf8-banner-message.patch
# Abort non-subsystem sessions to forced internal sftp-server (#993509)
Patch109: openssh-5.3p1-drop-internal-sftp-connections.patch
# Do ssh_gssapi_krb5_storecreds() twice - before and after pam sesssion (#974096)
Patch110: openssh-5.3p1-gssapi-with-poly-tmp.patch
# Change default of MaxStartups to 10:30:100 (#908707)
Patch111: openssh-5.3p1-change-max-startups.patch
# FIPS mode - adjust the key echange DH groups and ssh-keygen according to SP800-131A (#993580)
Patch120: openssh-5.3p1-FIPS-mode-SP800-131A.patch
# ECDSA and ECDH support (#1028335)
Patch121: openssh-5.3p1-ecdsa-ecdh.patch
# fix segfault in GSSAPI key exchange in FIPS mode
Patch122: openssh-5.3p1-gsskex-fips.patch
# log fipscheck verification message into syslog authpriv (#1020803)
Patch123: openssh-5.3p1-fips-syslog.patch
# Prevents a server from skipping SSHFP lookup and forcing a new-hostkey
# dialog by offering only certificate keys. (#1081338)
Patch124: openssh-5.3p1-CVE-2014-2653.patch
# ignore environment variables with embedded '=' or '\0' characters (#1077843)
Patch125: openssh-5.3p1-ignore-bad-env-var.patch
# backport ControlPersist option (#953088)
Patch126: openssh-5.3p1-ControlPersist.patch
# log when a client requests an interactive session and only sftp is allowed (#997377)
Patch127: openssh-5.3p1-log-sftp-only-connections.patch
# don't try to load RSA1 host key in FIPS mode (#1009959)
Patch128: openssh-5.3p1-fips-dont-load-rsa1-keys.patch
# restore Linux oom_adj setting when handling SIGHUP to maintain behaviour over restart (#1010429)
Patch129: openssh-5.3p1-restore-oom-after-restart.patch
# ssh-keygen -V - relative-specified certificate expiry time should be relative to current time (#1022459)
Patch130: openssh-5.3p1-ssh-keygen-V-fix.patch
# look for x11 forward sockets with AI_ADDRCONFIG flag getaddrinfo (#1027197)
Patch131: openssh-5.3p1-x11-getaddrinfo.patch
# fix openssh-5.3p1-x11.patch for non-linux platforms (#1100913)
Patch132: openssh-5.3p1-x11-for-non-linux-platforms.patch
# fix several coverity issue (#876544)
Patch133: openssh-5.3p1-fix-several-coverity-issues.patch
# skip requesting smartcard PIN when removing keys from agent (#1042519)
Patch134: openssh-5.3p1-skip-pin-for-ssh-add-e.patch
# fix race in backported ControlPersist patch (#953088)
Patch135: openssh-5.3p1-ControlPersist-avoid-race-between-bind-and-listen.patch
# ignore SIGPIPE in ssh-keyscan (#1108836)
Patch136: openssh-5.3p1-sigpipe.patch
# Ignore SIGXFSZ in postauth monitor child (#1133906)
Patch137: openssh-5.3p1-ignore-SIGXFSZ.patch
# Fix ControlPersist option with ProxyCommand (#1160487)
Patch138: openssh-5.3p1-ControlPersist-fix-ProxyCommand.patch
# Fix ssh-keygen with error : gethostname: File name too long (#1161454)
Patch139: openssh-5.3p1-NI_MAXHOST.patch
# set a client's address right after a connection is set (#1161449)
Patch140: openssh-5.3p1-set_remote_ipaddr.patch
# fix printing of extensions in v01 certificates (#1093869)
Patch141: openssh-5.3p1-fix-printing-of-extensions.patch
# don't close fds for internal sftp sessions (#1085710)
Patch142: openssh-5.3p1-dont-close-fds-for-internal-sftp.patch
# fix config parsing elements in quotes (#1134938)
Patch143: openssh-5.3p1-fix-config-parsing-quotes.patch
# fix ssh-copy-id on non-sh remote shells (#1135521)
Patch144: openssh-5.3p1-fix-ssh-copy-id-on-non-sh-shell.patch
# Backport wildcard functionality for PermitOpen in sshd_config file (#1159055)
Patch145: openssh-5.3p1-backport-permit-open-wildcard.patch
# Add sftp option to force mode of created files (#1191055)
Patch146: openssh-5.3p1-sftp-force-permission.patch
# Fix sshd -T does not show all (default) options, inconsistency (#1109251)
Patch147: openssh-5.3p1-test-mode-all-values.patch
# Missing options in man ssh (#1197763)
Patch148: openssh-5.3p1-man-ssh-missing-options.patch
# SSH2_MSG_DISCONNECT for user initiated disconnect does not follow RFC 4253
Patch149: openssh-5.3p1-ssh2-mgs-disconnect.patch
# ssh-agent segfaults when removing CAC credentials (#1253612)
Patch150: openssh-5.3p1-nss-keys-fix.patch
# Add GSSAPIKexAlgorithms option for both server and client application (#1253060)
Patch151: openssh-5.3p1-gssKexAlgorithms.patch
# Backport Match LocalAddress and LocalPort (#1211673)
Patch153: openssh-5.3p1-match-localaddress-localport.patch
# Backport security patches from openssh-6.9 and 7.0 (#1281468)
#  CVE-2015-5352: XSECURITY restrictions bypass under certain conditions
#  CVE-2015-5600: MaxAuthTries limit bypass via duplicates in KbdInteractiveDevices
#  CVE-2015-6563: Privilege separation weakness related to PAM support
#  CVE-2015-6564: Use-after-free bug related to PAM support
Patch154: openssh-5.3p1-security7.patch
# Fix weakness of agent locking (ssh-add -x) to password guessing (#1281468)
Patch155: openssh-5.3p1-agent-locking.patch
# Clarity of Match block (#1219820)
Patch156: openssh-5.3p1-man-match.patch
# Clarity of TERM variable in AcceptEnv and SendEnv (#1285003)
Patch157: openssh-5.3p1-man-TERM.patch
# Clarity of AllowGroups and similar documentation (#1284997)
Patch158: openssh-5.3p1-man-allowGroups.patch
# CVE-2016-1908: Prevent fallback of untrusted X11 to trusted (#1299048)
Patch159: openssh-5.3p1-fallback-x11-untrusted.patch
# CVE-2016-3115: missing sanitisation of input for X11 forwarding (#1316829)
Patch161: openssh-5.3p1-CVE-2016-3115.patch
# ssh-copy-id: SunOS does not understand ~ (#1327547)
Patch162: openssh-5.3p1-ssh-copy-id-tilde.patch
# Relax bits needed for hmac-sha2-512 and gss-group1-sha1- (#1353359)
Patch163: openssh-5.3p1-relax-bits-needed.patch
# close ControlPersist background process stderr when not in debug mode (#1335539)
Patch164: openssh-5.3p1-ControlPersist-stderr.patch
# "The agent has no identities." in ~/.ssh/authorized_keys (#1353410)
Patch165: openssh-5.3p1-ssh-copy-id-agent.patch
# Remove RC4 cipher and questionable MACs from the default proposal (#1373836)
Patch166: openssh-5.3p1-deprecate-insecure-algorithms.patch
# Prevent infinite loop when Ctrl+Z pressed at password prompt (#1218424)
Patch167: openssh-5.3p1-prevent-infinite-loop.patch
# make s390 use /dev/ crypto devices -- ignore closefrom (#1397547)
Patch168: openssh-5.3p1-s390-closefrom.patch
# CVE-2015-8325: privilege escalation via user's PAM environment and UseLogin=yes
Patch169: openssh-5.3p1-CVE-2015-8325.patch
# CVE-2016-6210: User enumeration via covert timing channel
Patch170: openssh-5.3p1-CVE-2016-6210.patch

# This is the patch that adds GSI support
# Based on http://grid.ncsa.illinois.edu/ssh/dl/patch/openssh-5.3p1.patch
Patch200: openssh-5.3p1-gsissh.patch

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
BuildRequires: globus-gss-assist-devel >= 8
BuildRequires: globus-gssapi-gsi-devel >= 12.12
BuildRequires: globus-common-devel >= 14
BuildRequires: globus-usage-devel >= 3
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
%patch90 -p1 -b .ipv6man
%patch91 -p1 -b .manerr
%patch92 -p1 -b .askpass-ld
%patch93 -p1 -b .evp-ctr
%patch94 -p1 -b .oom-killer
%patch95 -p1 -b .required-authentication
%patch96 -p1 -b .privsep
%patch97 -p1 -b .noslash
%patch98 -p1 -b .postauth-exhaustion
%patch99 -p1 -b .v6only
%patch100 -p1 -b .netcat
%patch101 -p1 -b .key-perm-message
%patch102 -p1 -b .fix-race
%patch103 -p1 -b .pkcs11
%patch104 -p1 -b .KexAlgorithms
%patch105 -p1 -b .hmac-sha2
%patch106 -p1 -b .man
%patch107 -p1 -b .certificates
%patch108 -p1 -b .utf8-banner
%patch109 -p1 -b .drop-internal-sftp
%patch110 -p1 -b .gssapi-poly-tmp
%patch111 -p1 -b .max-startups
%patch120 -p1 -b .SP800-131A
%patch121 -p1 -b .ecdsa-ecdh
%patch122 -p1 -b .gsskex-fips
%patch123 -p1 -b .fips-syslog
%patch124 -p1 -b .CVE-2014-2653
%patch125 -p1 -b .bad-env-var
%patch126 -p1 -b .ControlPersist
%patch127 -p1 -b .997377
%patch128 -p1 -b .1009959
%patch129 -p1 -b .1010429
%patch130 -p1 -b .1022459
%patch131 -p1 -b .1027197
%patch132 -p1 -b .1100913
%patch133 -p1 -b .876544
%patch134 -p1 -b .1042519
%patch135 -p1 -b .ControlPersist-race
%patch136 -p1 -b .sigpipe
%patch137 -p1 -b .SIGXFSZ
%patch138 -p1 -b .ControlPersist-ProxyCommand
%patch139 -p1 -b .1161454
%patch140 -p1 -b .unknown
%patch141 -p1 -b .certs
%patch142 -p1 -b .1085710
%patch143 -p1 -b .config-quotes
%patch144 -p1 -b .ssh-copy-id
%patch145 -p1 -b .permitopen
%patch146 -p1 -b .sftp-force-mode
%patch147 -p1 -b .sshd-t
%patch148 -p1 -b .man-ssh
%patch149 -p1 -b .ssh2-msg-disconnect
%patch150 -p1 -b .cac
%patch151 -p1 -b .gsskex-algs
%patch153 -p1 -b .localaddress
%patch154 -p1 -b .security7
%patch155 -p1 -b .agent-locking
%patch156 -p1 -b .match
%patch157 -p1 -b .TERM
%patch158 -p1 -b .allowGroups
%patch159 -p1 -b .untrusted
%patch161 -p1 -b .xauth
%patch162 -p1 -b .tilde
%patch163 -p1 -b .relax-dh
%patch164 -p1 -b .ControlPersist-stderr
%patch165 -p1 -b .ssh-copy-id-agent
%patch166 -p1 -b .insecure
%patch167 -p1 -b .infinite
%patch168 -p1 -b .s390
%patch169 -p1 -b .use-login
%patch170 -p1 -b .user-enumeration

%patch200 -p1 -b .gsi

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
rm $RPM_BUILD_ROOT%{_libexecdir}/gsissh/ssh-pkcs11-helper
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
%doc CREDITS ChangeLog INSTALL LICENCE LICENSE.globus_usage OVERVIEW PROTOCOL PROTOCOL.agent PROTOCOL.certkeys README* TODO WARNING*
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
* Mon Nov 13 2017 Mattias Ellert <mattias.ellert@physics.uu.se> - 5.3p1-17
- Based on openssh-5.3p1-123.el6_9

* Mon Jul 31 2017 Mattias Ellert <mattias.ellert@physics.uu.se> - 5.3p1-16
- Update GSI patch with more openssl 1.1.0 fixes from Globus

* Tue Mar 21 2017 Mattias Ellert <mattias.ellert@physics.uu.se> - 5.3p1-15
- Based on openssh-5.3p1-122.el6

* Thu Dec 15 2016 Mattias Ellert <mattias.ellert@physics.uu.se> - 5.3p1-14
- Adding mechanism OID negotiation with the introduction of micv2 OID

* Sun Jun 26 2016 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-13
- Based on openssh-5.3p1-118.1.el6_8

* Tue Jan 19 2016 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-12
- Based on openssh-5.3p1-112.el6_7

* Wed Oct 22 2014 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-11
- Based on openssh-5.3p1-104.el6

* Tue Nov 26 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-10
- Based on openssh-5.3p1-94.el6

* Sat Apr 06 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-9
- Security fix for vulnerability
    http://grid.ncsa.illinois.edu/ssh/pamuserchange-2013-01.adv
    https://wiki.egi.eu/wiki/SVG:Advisory-SVG-2013-5168

* Tue Feb 26 2013 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-8
- Based on openssh-5.3p1-84.1.el6

* Tue Dec 11 2012 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-7
- Based on openssh-5.3p1-81.el6_3

* Tue Aug 14 2012 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-6
- Based on openssh-5.3p1-81.el6

* Wed Feb 08 2012 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-5
- Based on openssh-5.3p1-70.el6_2.2

* Sun Jan 22 2012 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-4
- Drop openssh-5.3p1-unblock-signals.patch - not needed with GT >= 5.2
- Based on openssh-5.3p1-70.el6

* Thu Oct 06 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-3
- Change package name gsissh → gsi-openssh
- Based on openssh-5.3p1-52.el6_1.2

* Wed Aug 10 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-2
- Add patch from OSG to resolve threading problems in the server
- Based on openssh-5.3p1-52.el6_1.2

* Tue Mar 08 2011 Mattias Ellert <mattias.ellert@fysast.uu.se> - 5.3p1-1
- Initial packaging
- Based on openssh-5.3p1-20.el6_0.3
