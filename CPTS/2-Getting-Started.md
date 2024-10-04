# Introduction 

## Infosec Overview
[Information security](https://en.wikipedia.org/wiki/Information_security) (infosec) is a vast field. The field has grown and evolved greatly in the last few years. It offers many specializations, including but not limited to:
- Network and infrastructure security
- Application security
- Security testing
- Systems auditing
- Business continuity planning
- Digital forensics
- Incident detection and response

In a nutshell, infosec is the practice of protecting data from unauthorized access, changes, unlawful use, disruption, etc
+ Infosec professionals also take actions to reduce the overall impact of any such incident

Data can be electronic or physical and tangible (e.g., design blueprints) or intangible (knowledge)
+ A common phrase that will come up many times in our infosec career is protecting the "confidentiality, integrity, and availability of data," or the `CIA triad`

### Risk Management Process
Data protection must focus on efficient yet effective policy implementation without negatively affecting an organization's business operations and productivity
+ To achieve this, organizations must follow a process called the `risk management process`
+ This process involves the following five steps:

| Step                   | Explanation                                                                                                                                                                               |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Identifying the Risk` | Identifying risks the business is exposed to, such as legal, environmental, market, regulatory, and other types of risks.                                                                 |
| `Analyze the Risk`     | Analyzing the risks to determine their impact and probability. The risks should be mapped to the organization's various policies, procedures, and business processes.                     |
| `Evaluate the Risk`    | Evaluating, ranking, and prioritizing risks. Then, the organization must decide to accept (unavoidable), avoid (change plans), control (mitigate), or transfer risk (insure).             |
| `Dealing with Risk`    | Eliminating or containing the risks as best as possible. This is handled by interfacing directly with the stakeholders for the system or process that the risk is associated with.        |
| `Monitoring Risk`      | All risks must be constantly monitored. Risks should be constantly monitored for any situational changes that could change their impact score, `i.e., from low to medium or high impact`. |
As mentioned previously, the core tenet of infosec is information assurance, or maintaining the `CIA` of data and making sure that it is not compromised in any way, shape, or form when an incident occurs
+ An incident could be a natural disaster, system malfunction, or security incident

### Red Team vs. Blue Team
In infosec, we usually hear the terms `red team` and `blue team`
+ In the simplest terms, the `red team` plays the attackers' role, while the `blue team` plays the defenders' part

Red teamers usually play an adversary role in breaking into the organization to identify any potential weaknesses real attackers may utilize to break the organization's defenses
+ The most common task on the red teaming side is penetration testing, social engineering, and other similar offensive techniques

On the other hand, the blue team makes up the majority of infosec jobs
+ It is responsible for strengthening the organization's defenses by analyzing the risks, coming up with policies, responding to threats and incidents, and effectively using security tools and other similar tasks

### Role of Penetration Testers
A security assessor (network penetration tester, web application penetration tester, red teamer, etc.) helps an organization identify risks in its external and internal networks
+ These risks may include network or web application vulnerabilities, sensitive data exposure, misconfigurations, or issues that could lead to reputational harm
+ A good tester can work with a client to identify risks to their organization, provide information on how to reproduce these risks, and guidance on either mitigating or remediating the issues identified during testing

Assessments can take many forms, from a white-box penetration test against all in-scope systems and applications to identify as many vulnerabilities as possible, to a phishing assessment to assess the risk or employee's security awareness, to a targeted red team assessment built around a scenario to emulate a real-world threat actor

We must understand the bigger picture of the risks an organization faces and its environment to evaluate and rate vulnerabilities discovered during testing accurately
+ A deep understanding of the risk management process is critical for anyone starting in information security

This module will focus on how to get started in infosec and penetration testing from a hands-on perspective, specifically selecting and navigating a pentest distro, learning about common technologies and essential tools, learning the levels and the basics of penetration testing, cracking our first box on HTB, how to find and ask for help most effectively, common potential issues, and how to navigate the Hack the Box platform

While this module uses the Hack The Box platform and purposefully vulnerable machines as examples, the fundamental skills showcased apply to any environment

# Setup

## Getting Started with a Pentest Distro 
Anyone looking to start a technical path in information security must become comfortable with a wide range of technologies and operating systems
+ As penetration testers, we must understand how to set up, maintain, and secure both Linux and Windows attack machines
+ Depending on the client environment or scope of the assessment, we may be using a Linux or Windows VM on our machine, our base operating system, a cloud Linux box, a VM installed within the client's environment, or even perform testing directly from a client-owned workstation to simulate an insider threat (assume breach scenario)

### Choosing a Distro 
There are many Linux distributions (distros) for penetration testing
+ There are quite a few Debian-based pre-existing distros preloaded with many tools that we need to perform our assessments
+ Many of these tools are rarely required, and no distro contains every tool that we need to perform our assessments
+ As we learn and progress in our careers, we will gravitate to specific tools and have a list of "must-haves" to add to a new distro
+ As we progress, we may even prefer to fully customize our own pentesting VM from a Debian or Ubuntu base image, but building a fully custom VM is outside this module's scope

The choice of a distro is individual, and, as mentioned, we can even choose to create and maintain our own from scratch
+ There are countless Linux distros out there that serve various purposes, some explicitly customized for penetration testing, others geared towards web application penetration testing, forensics, etc

This section will cover setting up and working with [Parrot OS](https://www.parrotsec.org/)
+ This distro is used for the Pwnbox that we will see throughout Academy, customized to practice and solve exercises throughout the various modules we will encounter

It is important to note that each penetration test or security assessment must be performed from a freshly installed VM to avoid including security-relevant details from another client environment in our reports by accident or retaining client-sensitive data for significant lengths of time
+ For this reason, we must have the ability to quickly stand up a new pentest machine and have processes in place (automation, scripts, detailed procedures, etc.) for quickly setting up our distro(s) of choice for each assessment we perform

### Setting up a Pentest Distro 
There are many ways to set up our local pentest distro
+ We can install it as our base operating system (though not recommended), configure our workstation to dual boot (time-consuming to switch back and forth between operating systems), or install using virtualization

There are quite a few options available to us: [Hyper-V](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/about/) on Windows, as virtual machines on [bare metal hypervisors](https://www.vmware.com/topics/bare-metal-hypervisor) such as [Proxmox](https://proxmox.com/en/) or [VMware ESXi](https://www.vmware.com/products/esxi-and-esx.html) or using free hypervisors such as [VirtualBox](https://www.virtualbox.org), or [VMware Workstation Player](https://www.vmware.com/products/workstation-player.html), which can be installed and used as hypervisors on Windows and Linux operating systems
+ Another option is [VMware Workstation](https://www.vmware.com/products/workstation-pro.html), which requires a paid license but offers many more features than the free options.

A `hypervisor` is software that allows us to create and run virtual machines (VMs).
+ It will enable us to use our host computer (desktop or laptop) to run multiple VMs by virtually sharing memory and processing resources.  
VMs on a hypervisor run isolated from the primary operating system, which offers a layer of isolation and protection between our production network and vulnerable networks, such as Hack The Box, or when connecting to client environments from a VM (though VM breakout vulnerabilities do arise from time to time).

Depending on the amount of resources our host system has (i.e., RAM), we can usually run a few VMs at once
+ It is often helpful to stand up a VM during an assessment to test out an exploit or attempt to recreate a target application and stand-up machines in a lab environment to test out the latest tools, exploits, and techniques
+ Everyone working in a technical information security role should be comfortable working with one or more hypervisors and building virtual machines competently for both work and practice

To be successful, we must continuously work to hone our craft
+ A great way is by setting up a home lab to attempt to reproduce vulnerabilities, set up vulnerable applications and services, see the effects of remediation recommendations, and have a safe place to practice new attack techniques/exploits
+ We can build our lab on an old laptop or desktop but preferably using a server to install a bare-metal hypervisor

For our purposes, we will be using a modified version of Parrot Security (Pwnbox), available [here](https://www.parrotsec.org/download/) to build a local virtual machine
+ We can choose two formats:
	- `Optical disc image (ISO)`
	- `Open Virtual Appliance (OVA)`

#### ISO
The `ISO` file is essentially just a CD-ROM that can be mounted within our hypervisor of choice to build the VM by installing the operating system ourselves
+ An `ISO` gives us more room for customization, e.g., keyboard layout, locale, desktop environment switch, custom partitioning, etc., and therefore a more granular approach when setting up our attack VM

#### OVA
The `OVA` file is a pre-built virtual appliance that contains an `OVF` XML file that specifies the VM hardware settings and a `VMDK`, which is the virtual disk that the operating system is installed on
+ An `OVA` is pre-built and therefore can be rapidly deployed to get up and running quicker.

Once up and running, we can begin exploring the operating system, becoming familiar with the tools, and performing any desired customizations
+ The Parrot Linux team maintains a variety of helpful documentation:
	- [What is Parrot?](https://www.parrotsec.org/docs/introduction/what-is-parrot)
	- [Installation](https://www.parrotsec.org/docs/installation/)
	- [Configuration](https://www.parrotsec.org/docs/configuration/parrot-software-management)

### Practicing with Parrot
We will encounter Parrot Linux throughout Academy
+ The in-browser version, or Pwnbox, is available in any module sections which require interaction with a target host in our lab environment
+ Click the `Start Instance` button below and start becoming familiar with the Pwnbox
+ All interactive Module sections can be completed from our own VM after either spawning a Docker image or spawning a target host or multiple hosts and downloading a VPN key
+ Using the Pwnbox is not a requirement but is useful because all Academy work can be completed within our browser without requiring any virtualization software or additional resources to run a virtual machine

Docker instances can be accessed without requiring a separate VPN connection
+ Specific hosts (i.e., Active Directory targets) require VPN access if not accessed from the Pwnbox
+ If this is the case, a button will appear to download a VPN key after spawning the target
+ We will begin working with target hosts later in this module

## Staying Organized
Whether we are performing client assessments, playing CTFs, taking a course in Academy or elsewhere, or playing HTB boxes/labs, organization is always crucial
+ It is essential to prioritize clear and accurate documentation from the very beginning
+ This skill will benefit us no matter what path we take in information security or even other career paths
### Folder Structure 
When attacking a single box, lab, or client environment, we should have a clear folder structure on our attack machine to save data such as: scoping information, enumeration data, evidence of exploitation attempts, sensitive data such as credentials, and other data obtained during recon, exploitation, and post-exploitation
+ A sample folder structure may look like follows:

```shell-session
nsoqui@htb[/htb]$ tree Projects/

Projects/
└── Acme Company
    ├── EPT
    │   ├── evidence
    │   │   ├── credentials
    │   │   ├── data
    │   │   └── screenshots
    │   ├── logs
    │   ├── scans
    │   ├── scope
    │   └── tools
    └── IPT
        ├── evidence
        │   ├── credentials
        │   ├── data
        │   └── screenshots
        ├── logs
        ├── scans
        ├── scope
        └── tools
```

+ Here we have a folder for the client `Acme Company` with two assessments, Internal Penetration Test (IPT) and External Penetration Test (EPT).
+ Under each folder, we have subfolders for saving scan data, any relevant tools, logging output, scoping information (i.e., lists of IPs/networks to feed to our scanning tools), and an evidence folder that may contain any credentials retrieved during the assessment, any relevant data retrieved as well as screenshots

It is a personal preference, but some folks create a folder for each target host and save screenshots within it
+ Others organize their notes by host or network and save screenshots directly into the note-taking tool
+ Experiment with folder structures and see what works best for you to stay organized and work most efficiently

### Note Taking Tools 
Productivity and organization are very important
+ A very technical but unorganized penetration tester will have a difficult time succeeding in this industry
+ Various tools can be used for organization and note-taking
+ Selecting a note-taking tool is very individual
+ Some of us may not need a feature that another person requires based on their workflow. 
	+ Some great options to explore include:

| [Cherrytree](https://www.giuspen.com/cherrytree)     | [Visual Studio Code](https://code.visualstudio.com) | [Evernote](https://evernote.com)            |
| ---------------------------------------------------- | --------------------------------------------------- | ------------------------------------------- |
| [Notion](https://www.notion.so)                      | [GitBook](https://www.gitbook.com)                  | [Sublime Text](https://www.sublimetext.com) |
| [Notepad++](https://notepad-plus-plus.org/downloads) |                                                     |                                             |

Some of these are more focused on note-taking, while others such as Notion and GitBook have richer features that can be used to create Wiki-type pages, cheat sheets, and more
+ It is important to make sure that any client data is only stored locally and not synced to the cloud if using one of these tools on real-world assessments

### Other Tools and Tips
Every infosec professional should maintain a knowledge base
+ This can be in the format of your choosing (though the tools above are recommended)
+ This knowledge base should contain quick reference guides for setup tasks that we perform on most assessments and cheat sheets for common commands that we use for each phase of an assessment

As we complete boxes, labs, assessments, training courses, etc., we should be aggregating every payload, command, tip as we never know when one may come in handy
+ Having them accessible will increase our overall efficiency and productivity
+ Each HTB Academy Module has a cheat sheet of relevant commands showcased within the Module sections, which you can download and keep for future reference

We should also maintain checklists, report templates for various assessment types, and build a findings/vulnerability database
+ This database can take the form of a spreadsheet or something more complex and include a finding title, description, impact, remediation advice, and references
+ Having these findings already written will save us considerable time and re-work during the reporting phase as the bulk of the findings will be written already and likely only require some customization to the target environment

### Moving On
Try out various note-taking tools and develop the folder structure that works for you and matches your methodology
+ Start early, so this becomes a habit
+ The Nibbles walkthrough later in this Module is an excellent opportunity to practice our documentation
+ Also, this Module contains many commands that are useful to add to our common commands cheat sheet

## Connecting Using VPN
A [virtual private network (VPN)](https://en.wikipedia.org/wiki/Virtual_private_network) allows us to connect to a private (internal) network and access hosts and resources as if we were directly connected to the target private network
+ It is a secured communications channel over shared public networks to connect to a private network (i.e., an employee remotely connecting to their company's corporate network from their home).
+ VPNs provide a degree of privacy and security by encrypting communications over the channel to prevent eavesdropping and access to data traversing the channel

At a high-level, VPN works by routing our connecting device's internet connection through the target VPN's private server instead of our internet service provider (ISP)
+ When connected to a VPN, data originates from the VPN server rather than our computer and will appear to originate from a public IP address other than our own.

There are two main types of remote access VPNs: client-based VPN and SSL VPN. SSL VPN uses the web browser as the VPN client
+ The connection is established between the browser and an SSL VPN gateway can be configured to only allow access to web-based applications such as email and intranet sites, or even the internal network but without the need for the end user to install or use any specialized software
+ Client-based VPN requires the use of client software to establish the VPN connection
+ Once connected, the user's host will work mostly as if it were connected directly to the company network and will be able to access any resources (applications, hosts, subnets, etc.) allowed by the server configuration
+ Some corporate VPNs will provide employees with full access to the internal corporate network, while others will place users on a specific segment reserved for remote workers

### Why Use a VPN?
We can use a VPN service such as `NordVPN` or `Private Internet Access` and connect to a VPN server in another part of our country or another region of the world to obscure our browsing traffic or disguise our public IP address
+ This can provide us with some level of security and privacy
+ Still, since we are connecting to a company's server, there is always the chance that data is being logged or the VPN service is not following security best practices or the security features that they advertise
+ Using a VPN service comes with the risk that the provider is not doing what they are saying and are logging all data
+ Usage of a VPN service **does not** guarantee anonymity or privacy but is useful for bypassing certain network/firewall restrictions or when connected to a possible hostile network (i.e., a public airport wireless network).
+ A VPN service should never be used with the thought that it will protect us from the consequences of performing nefarious activities

### Connecting to HTB VPN
HTB and other services offering purposefully vulnerable VMs/networks require players to connect to the target network via a VPN to access the private lab network
+ Hosts within HTB networks cannot connect directly out to the internet
+ When connected to HTB VPN (or any penetration testing/hacking-focused lab), we should always consider the network to be "hostile."

We should only connect from a virtual machine, disallow password authentication if SSH is enabled on our attacking VM, lockdown any web servers, and not leave sensitive information on our attack VM (i.e., do not play HTB or other vulnerable networks with the same VM that we use to perform client assessments).
+ When connecting to a VPN (either within HTB Academy or the main HTB platform), we connect using the following command

```shell-session
sudo openvpn user.ovpn
```
+ Output:
```shell-session
Thu Dec 10 18:42:41 2020 OpenVPN 2.4.9 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on Apr 21 2020
Thu Dec 10 18:42:41 2020 library versions: OpenSSL 1.1.1g  21 Apr 2020, LZO 2.10
Thu Dec 10 18:42:41 2020 Outgoing Control Channel Authentication: Using 256 bit message hash 'SHA256' for HMAC authentication
Thu Dec 10 18:42:41 2020 Incoming Control Channel Authentication: Using 256 bit message hash 'SHA256' for HMAC authentication
Thu Dec 10 18:42:41 2020 TCP/UDP: Preserving recently used remote address: [AF_INET]
Thu Dec 10 18:42:41 2020 Socket Buffers: R=[212992->212992] S=[212992->212992]
Thu Dec 10 18:42:41 2020 UDP link local: (not bound)
<SNIP>
Thu Dec 10 18:42:41 2020 Initialization Sequence Completed
```
+ The last line `Initialization Sequence Completed` tells us that we successfully connected to the VPN

Where `sudo` tells our host to run the command as the elevated root user, `openvpn` is the VPN client, and the `user.ovpn` file is the VPN key that we download from either the Academy module section or the main HTB platform
+ If we type `ifconfig` in another terminal window, we will see a `tun` adapter if we successfully connected to the VPN:
```shell-session
nsoqui@htb[/htb]$ ifconfig

<SNIP>

tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.x.2  netmask 255.255.254.0  destination 10.10.x.2
        inet6 dead:beef:1::2000  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::d82f:301a:a94a:8723  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen
``````

Typing `netstat -rn` will show us the networks accessible via the VPN.
```shell-session
Kernel IP routing table
Destination     Gateway         Genmask         Flags   MSS Window  irtt Iface
0.0.0.0         192.168.1.2     0.0.0.0         UG        0 0          0 eth0
10.10.14.0      0.0.0.0         255.255.254.0   U         0 0          0 tun0
10.129.0.0      10.10.14.1      255.255.0.0     UG        0 0          0 tun0
192.168.1.0     0.0.0.0         255.255.255.0   U         0 0          0 eth0
```

#### Help with VPN
If this is your first time using a VPN, the following resources on the Hack The Box support portal will be helpful:
- [Introduction to Lab Access](https://help.hackthebox.com/en/articles/5185687-gs-introduction-to-lab-access)
- [Connection Troubleshooting](https://help.hackthebox.com/en/articles/5185536-t-connection-troubleshooting)

# Pentesting Basics 

## Common Terms
Penetration testing/hacking is an enormous field
+ We will encounter countless technologies throughout our careers
+ Here are some of the most common terms and technologies that we will come across repeatedly and must have a firm grasp of
+ This is not an exhaustive list but is enough to get started with fundamental Modules and easy HTB boxes

### What is a Shell?
`Shell` is a very common term that we will hear again and again during our journey
+ It has a few meanings. On a Linux system, the shell is a program that takes input from the user via the keyboard and passes these commands to the operating system to perform a specific function
+ In the early days of computing, the shell was the only interface available for interacting with systems
+ Since then, many more operating system types and versions have emerged along with the graphic user interface (GUI) to complement command-line interfaces (shell), such as the Linux terminal, Windows command-line (cmd.exe), and Windows PowerShell

Most Linux systems use a program called [Bash (Bourne Again Shell)](https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html) as a shell program to interact with the operating system
+ Bash is an enhanced version of [sh](https://man7.org/linux/man-pages/man1/sh.1p.html), the Unix systems' original shell program
+ Aside from `bash` there are also other shells, including but not limited to [Zsh](https://en.wikipedia.org/wiki/Z_shell), [Tcsh](https://en.wikipedia.org/wiki/Tcsh), [Ksh](https://en.wikipedia.org/wiki/KornShell), [Fish shell](https://en.wikipedia.org/wiki/Fish_(Unix_shell)), etc.

We will often read about or hear others talking about "getting a shell" on a box (system).
+ This means that the target host has been exploited, and we have obtained shell-level access (typically `bash` or `sh`) and can run commands interactively as if we are sitting logged in to the host
+ A shell may be obtained by exploiting a web application or network/service vulnerability or obtaining credentials and logging into the target host remotely

There are three main types of shell connections:

|**Shell Type**|**Description**|
|---|---|
|`Reverse shell`|Initiates a connection back to a "listener" on our attack box.|
|`Bind shell`|"Binds" to a specific port on the target host and waits for a connection from our attack box.|
|`Web shell`|Runs operating system commands via the web browser, typically not interactive or semi-interactive. It can also be used to run single commands (i.e., leveraging a file upload vulnerability and uploading a `PHP` script to run a single command.|
Each type of shell has its use case, and the same way there are many ways to obtain a shell, the helper program that we use to get a shell can be written in many languages (`Python`, `Perl`, `Go`, `Bash`, `Java`, `awk`, `PHP`, etc.).
+ These can be small scripts or larger, more complex programs to facilitate a connection from the target host back to our attacking system and obtain "shell" access
+ Shell access will be discussed in-depth in a later section.

### What is a Port?
A [port](https://en.wikipedia.org/wiki/Port_(computer_networking)) can be thought of as a window or door on a house (the house being a remote system), if a window or door is left open or not locked correctly, we can often gain unauthorized access to a home
+ This is similar in computing
+ Ports are virtual points where network connections begin and end
+ They are software-based and managed by the host operating system
+ Ports are associated with a specific process or service and allow computers to differentiate between different traffic types (SSH traffic flows to a different port than web requests to access a website even though the access requests are sent over the same network connection)

Each port is assigned a number, and many are standardized across all network-connected devices (though a service can be configured to run on a non-standard port).
+ For example, `HTTP` messages (website traffic) typically go to port `80`, while `HTTPS` messages go to port `443` unless configured otherwise
+ We will encounter web applications running on non-standard ports but typically find them on ports 80 and 443
+ Port numbers allow us to access specific services or applications running on target devices
+ At a very high level, ports help computers understand how to handle the various types of data they receive

There are two categories of ports, [Transmission Control Protocol (TCP)](https://en.wikipedia.org/wiki/Transmission_Control_Protocol), and [User Datagram Protocol (UDP)](https://en.wikipedia.org/wiki/User_Datagram_Protocol).

`TCP` is connection-oriented, meaning that a connection between a client and a server must be established before data can be sent
+ The server must be in a listening state awaiting connection requests from clients

`UDP` utilizes a connectionless communication model
+ There is no "handshake" and therefore introduces a certain amount of unreliability since there is no guarantee of data delivery
+ `UDP` is useful when error correction/checking is either not needed or is handled by the application itself
+ `UDP` is suitable for applications that run time-sensitive tasks since dropping packets is faster than waiting for delayed packets due to retransmission, as is the case with `TCP` and can significantly affect a real-time system
+ There are `65,535` `TCP` ports and `65,535` different `UDP` ports, each denoted by a number. Some of the most well-known `TCP` and `UDP` ports are listed below:

|Port(s)|Protocol|
|---|---|
|`20`/`21` (TCP)|`FTP`|
|`22` (TCP)|`SSH`|
|`23` (TCP)|`Telnet`|
|`25` (TCP)|`SMTP`|
|`80` (TCP)|`HTTP`|
|`161` (TCP/UDP)|`SNMP`|
|`389` (TCP/UDP)|`LDAP`|
|`443` (TCP)|`SSL`/`TLS` (`HTTPS`)|
|`445` (TCP)|`SMB`|
|`3389` (TCP)|`RDP`|

As information security professionals, we must be able to quickly recall large amounts of information on a wide variety of topics
+ It is essential for us, especially as pentesters, to have a firm grasp of many `TCP` and `UDP` ports and be able to recognize them from just their number quickly (i.e., know that port `21` is `FTP`, port `80` is `HTTP`, port `88` is `Kerberos`) without having to look it up
+ This will come with practice and repetition and eventually become second nature as we attack more boxes, labs, and real-world networks and help us work more efficiently and better prioritize our enumeration efforts and attacks.

Guides such as [this](https://www.stationx.net/common-ports-cheat-sheet/) and [this](https://web.archive.org/web/20240315102711/https://packetlife.net/media/library/23/common-ports.pdf) are great resources for learning standard and less common TCP and UDP ports.
+ Challenge yourself to memorize as many of these as possible and do some research about each of the protocols listed in the table above
+ This is a great [reference](https://nullsec.us/top-1-000-tcp-and-udp-ports-nmap-default/) on the top 1,000 `TCP` and `UDP` ports from `nmap` along with the top 100 services scanned by `nmap`

### What is a Web Server
A web server is an application that runs on the back-end server, which handles all of the `HTTP` traffic from the client-side browser, routes it to the requests destination pages, and finally responds to the client-side browser
+ Web servers usually run on TCP ports `80` or `443`, and are responsible for connecting end-users to various parts of the web application, in addition to handling their various responses

As web applications tend to be open for public interaction and facing the internet, they may lead to the back-end server being compromised if they suffer from any vulnerabilities
+ Web applications can provide a vast attack surface, making them a high-value target for attackers and pentesters

Many types of vulnerabilities can affect web applications
+ We will often hear about/see references to the [OWASP Top 10](https://owasp.org/www-project-top-ten/)
+ This is a standardized list of the top 10 web application vulnerabilities maintained by the Open Web Application Security Project (OWASP).
+ This list is considered the top 10 most dangerous vulnerabilities and is not an exhaustive list of all possible web application vulnerabilities
+ Web application security assessment methodologies are often based around the OWASP top 10 as a starting point for the top categories of flaws that an assessor should be checking for

The current OWASP Top 10 list is:

|Number|Category|Description|
|---|---|---|
|1.|[Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)|Restrictions are not appropriately implemented to prevent users from accessing other users accounts, viewing sensitive data, accessing unauthorized functionality, modifying data, etc.|
|2.|[Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)|Failures related to cryptography which often leads to sensitive data exposure or system compromise.|
|3.|[Injection](https://owasp.org/Top10/A03_2021-Injection/)|User-supplied data is not validated, filtered, or sanitized by the application. Some examples of injections are SQL injection, command injection, LDAP injection, etc.|
|4.|[Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)|These issues happen when the application is not designed with security in mind.|
|5.|[Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)|Missing appropriate security hardening across any part of the application stack, insecure default configurations, open cloud storage, verbose error messages which disclose too much information.|
|6.|[Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)|Using components (both client-side and server-side) that are vulnerable, unsupported, or out of date.|
|7.|[Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)|Authentication-related attacks that target user's identity, authentication, and session management.|
|8.|[Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)|Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs).|
|9.|[Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)|This category is to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected..|
|10.|[Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)|SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL).|
It is essential to become familiar with each of these categories and the various vulnerabilities that fit each
+ Web application vulnerabilities will be covered in-depth in later modules
+ To learn more about web applications, check out the [Introduction to Web Applications](https://academy.hackthebox.com/module/details/75) module

## Basic Tools
Tools such as `SSH`, `Netcat`, `Tmux`, and `Vim` are essential and are used daily by most information security professionals
+ Although these tools are not intended to be penetration testing tools, they are critical to the penetration testing process, so we must master them

### Using SSH 
[Secure Shell (SSH)](https://en.wikipedia.org/wiki/SSH_(Secure_Shell)) is a network protocol that runs on port `22` by default and provides users such as system administrators a secure way to access a computer remotely
+ SSH can be configured with password authentication or passwordless using [public-key authentication](https://serverpilot.io/docs/how-to-use-ssh-public-key-authentication/) using an SSH public/private key pair
+ SSH can be used to remotely access systems on the same network, over the internet, facilitate connections to resources in other networks using port forwarding/proxying, and upload/download files to and from remote systems

SSH uses a client-server model, connecting a user running an SSH client application such as `OpenSSH` to an SSH server
+ While attacking a box or during a real-world assessment, we often obtain cleartext credentials or an SSH private key that can be leveraged to connect directly to a system via SSH
+ An SSH connection is typically much more stable than a reverse shell connection and can often be used as a "jump host" to enumerate and attack other hosts in the network, transfer tools, set up persistence, etc
+ If we obtain a set of credentials, we can use SSH to login remotely to the server by using the username `@` the remote server IP, as follows:
```shell-session
ssh Bob@10.10.10.10
```

It is also possible to read local private keys on a compromised system or add our public key to gain SSH access to a specific user, as we'll discuss in a later section
+ As we can see, SSH is an excellent tool for securely connecting to a remote machine
+ It also provides a way for mapping local ports on the remote machine to our localhost, which can become handy at times

### Using Netcat
[Netcat](https://linux.die.net/man/1/nc), `ncat`, or `nc`, is an excellent network utility for interacting with TCP/UDP ports
+ It can be used for many things during a pentest
+ Its primary usage is for connecting to shells, which we'll discuss later in this module
+ In addition to that, `netcat` can be used to connect to any listening port and interact with the service running on that port
+ For example, `SSH` is programmed to handle connections over port 22 to send all data and keys
+ We can connect to TCP port 22 with `netcat`:
```shell-session
netcat 10.10.10.10 22
```

As we can see, port 22 sent us its banner, stating that `SSH` is running on it
+ This technique is called `Banner Grabbing`, and can help identify what service is running on a particular port
+ `Netcat` comes pre-installed in most Linux distributions
+ We can also download a copy for Windows machines from this [link](https://nmap.org/download.html)
+ There's another Windows alternative to `netcat` coded in PowerShell called [PowerCat](https://github.com/besimorhino/powercat)
+ `Netcat` can also be used to transfer files between machines, as we'll discuss later

Another similar network utility is [socat](https://linux.die.net/man/1/socat), which has a few features that `netcat` does not support, like forwarding ports and connecting to serial devices
+ `Socat` can also be used to [upgrade a shell to a fully interactive TTY](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat)
+ We will see a few examples of this in a later section
+ `Socat` is a very handy utility that should be a part of every penetration tester's toolkit

A [standalone binary](https://github.com/andrew-d/static-binaries) of `Socat` can be transferred to a system after obtaining remote code execution to get a more stable reverse shell connection

### Using Tmux
Terminal multiplexers, like `tmux` or `Screen`, are great utilities for expanding a standard Linux terminal's features, like having multiple windows within one terminal and jumping between them
+ Let's see some examples of using `tmux`, which is the more common of the two
+ If `tmux` is not present on our Linux system, we can install it with the following command:
```shell-session
sudo apt install tmux -y
```

Once we have `tmux`, we can start it by entering `tmux` as our command:
+ The default key to input `tmux` commands prefix is `[CTRL + B]`. In order to open a new window in `tmux`, we can hit the prefix 'i.e. `[CTRL + B]`' and then hit `C`:

We can switch between panes by hitting the prefix and then the `left` or `right` arrows for horizontal switching or the `up` or `down` arrows for vertical switching
+ The commands above cover some basic `tmux` usage
+ It is a powerful tool and can be used for many things, including logging, which is very important during any technical engagement
+ This [cheatsheet](https://tmuxcheatsheet.com) is a very handy reference. Also, this [Introduction to tmux](https://www.youtube.com/watch?v=Lqehvpe_djs) video by `ippsec` is worth your time

### Using Vim 
[Vim](https://linuxcommand.org/lc3_man_pages/vim1.html) is a great text editor that can be used for writing code or editing text files on Linux systems
+ One of the great benefits of using `Vim` is that it relies entirely on the keyboard, so you do not have to use the mouse, which (once we get the hold of it) will significantly increase your productivity and efficiency in writing/editing code
+ We usually find `Vim` or `Vi` installed on compromised Linux systems, so learning how to use it allows us to edit files even on remote systems
+ `Vim` also has many other features, like extensions and plugins, which can significantly extend its usage and make for a great code editor

| `x`  | Cut character  |
| ---- | -------------- |
| `dw` | Cut word       |
| `dd` | Cut full line  |
| `yw` | Copy word      |
| `yy` | Copy full line |
| `p`  | Paste          |
If we want to save a file or quit `Vim`, we have to press`:` to go into `command mode`
+ Once we do, we will see any commands we type at the bottom of the vim window

There are many commands available to us. The following are some of them:

|Command|Description|
|---|---|
|`:1`|Go to line number 1.|
|`:w`|Write the file, save|
|`:q`|Quit|
|`:q!`|Quit without saving|
|`:wq`|Write and quit|

`Vim` is a very powerful tool and has many other commands and features. This [cheatsheet](https://vimsheet.com) is an excellent resource for further unlocking the power of `Vim`

## Service Scanning 
TODO