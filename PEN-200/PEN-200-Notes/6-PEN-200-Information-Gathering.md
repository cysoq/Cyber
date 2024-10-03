# Information Gathering 

## Penetration Testing Lifecycle 
To keep a company's security posture as tightly controlled as possible, we should conduct penetration testing on a regular cadence and after every time there's a significant shift in the target's IT architecture.

A typical penetration test comprises the following stages:
- Defining the Scope
- Information Gathering
- Vulnerability Detection
- Initial Foothold
- Privilege Escalation
- Lateral Movement
- Reporting/Analysis
- Lessons Learned/Remediation

### Scope
The scope of a penetration test engagement defines which **IP ranges**, **hosts**, and **applications** should be test subjects during the engagement, as compared to out-of-scope items that should not be tested

### Information Gathering Layout 
Once we have agreed with the client on the engagement's scope and time frame, we can proceed to the second step, information gathering. During this step, we aim to collect as much data about the target as possible
+ To begin information gathering, we typically perform reconnaissance to retrieve details about the target organization's infrastructure, assets, and personnel
+ This can be done either passively or actively
	+ While the former technique aims to retrieve the target's information with almost no direct interaction, the latter probes the infrastructure directly
	+ Active information gathering reveals a bigger footprint, so it is often preferred to avoid exposure by gathering information passively

It's important to note that information gathering (also known as enumeration) does not end after our initial reconnaissance
+ We'll need to continue collecting data as the penetration test progresses, building our knowledge of the target's attack surface as we discover new information by gaining a foothold or moving laterally

## Passive Information Gathering 
Passive Information Gathering, also known as _Open-source Intelligence_ (OSINT) is the process of collecting openly-available information about a target, generally without any direct interaction with that target

Two different schools of thought about what constitutes "passive" in this context:
+ In the strictest interpretation, we _never_ communicate with the target directly. For example, we could rely on third parties for information, but we wouldn't access any of the target's systems or servers. Using this approach maintains a high level of secrecy about our actions and intentions, but can also be cumbersome and may limit our results
+ In a looser interpretation, we might interact with the target, but only as a normal internet user would. For example, if the target's website allows us to register for an account, we could do that. However, we would not test the website for vulnerabilities during this phase

There are a variety of resources and tools we can use to gather information, and the process is cyclical rather than linear
+ In other words, the "next step" of any stage of the process depends on what we find during the previous steps, creating "cycles" of processes
+ Since each tool or resource can generate any number of varied results, it can be hard to define a standardized process
+ The ultimate goal of passive information gathering is to obtain information that clarifies or expands an attack surface, helps us conduct a successful phishing campaign, or supplements other penetration testing steps such as password guessing, which can ultimately lead to account compromise

### Whois Enumeration 
Whois is a TCP service, tool, and type of database that can provide information about a **domain name**, such as the name server and registrar 
+ This information is often public since registrars charge a fee for private registration 
+ Port 43 is used for WHOIS queries

Can gather basic information about a domain name by executing a standard **forward search** with the domain name and IP address of the Ubuntu WHOIS server as an argument of the host `-h` parameter 
+ Usage: `whois <DOMAIN> -h <WHOIS_IP>`
	+ Example: `whois megacorpone.com -h 192.168.50.251`

Not all of the data will be useful, but can discover valuable information such as *who registered the domain name*, which can be cross-referenced with the company directory 
+ Additionally can find the **name servers**, which are a component of DNS that should be added to our notes 

With an IP address, can perform a **reverse lookup** to gather more information 
+ Usage: `whois <IP> -h <WHOIS_IP>`
	+ Example: `whois 38.100.193.70 -h 192.168.50.251` 
+ A reverse lookup can give more information about who is hosting the IP, which should be noted

### Google Hacking 
"Google Hacking" was popularized by Johnny Long in 2001, through several talks and the popular book (Google Hacking for Penetration Testers), he outlined how search engines like google can be used to uncover critical information, vulnerabilities, and misconfigured websites

This technique uses clever strings and *operators* for creative refinement of search queries, most of which work with a variety of search engines 
+ The process is iterative, beginning with a broad search, then narrowed using operators to sift out irrelevant or uninteresting results 

#### Operators 

| Operator   | Usage                                                                                                                                                                                                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `site`     | limits searches to a single domain, can use the operator to gather a rough idea of an organizations web presence. Example: `site:megacorpone.com`                                                                                                                         |
| `filetype` | Limits search results to a specified file type. Example: `site:megacorpone.com filetype:txt`, which can effectively find robots.txt files                                                                                                                                 |
| `ext`      | Can discern which programming languages might be used on a web site, searches like `ext:php`, `ext:xml`, and `ext:py` will find indexed PHP Pages, XML, and Python pages, respectively                                                                                    |
| `-`        | Can be used to exclude particular items from a search, narrow the results. Example: `site:megacorpone.com -filetype:html` will find non-HTML pages in that domain                                                                                                         |
| `intitle`  | Can be used to find specified strings in the title on the page. Example: `intitle:"index of" "parent directory"` can be searched to find pages that contain "index of" in the title and the words "parent directory" on the page. This will find directory listing pages. |
+ Mastery of these operators, combined with a keen sense of deduction, are key skills for effective search engine "hacking"

#### robots.txt file
This file instructs web crawlers, such as a Google search engine crawler, to allow or disallow specific resources 
+ It can reveal pages and resources that are otherwise hidden from regular searches, despite being listed allowed by the policy

#### Directory listing pages 
Pages that list the file contents of the directories without index pages
+ Misconfigurations like this can reveal interesting files and sensitive information

#### Google Hacking Database 
Contains multitudes of creative searches that demonstrate the power of leveraging combined operators: https://www.exploit-db.com/google-hacking-database
+ Can also experiment with google dorks through the **DorkSearch** portal which provides a pre-built subset of queries and a builder tool to facilitate the search: https://dorksearch.com/
	+ Also has a Dork query AI 

### Netcraft 
Netcraft is an Internet service company, based in England, that offers a free web portal that performs various information gather functions such as discovering which **technologies** are running on a given website, and **finding which other hosts** share the same IP netblock 
+ Considered a passive technique, since there is no direct interaction 

Can use Netcraft's **DNS search page** to gather information about a domain: https://searchdns.netcraft.com
+ For each server found, can view a "site report" that provides additional information and history about the server
+ Te start of the report will cover registration information, further down there will be "site technology" entries 
+ This list of **subdomains** and **technologies** will prove useful as we move onto active information gathering and exploitation 
	+ Can find subdomains just by searching the known domain in the DNS search
	+ For example, searching `megacorpone.com` returns `www.megacorpone.com` and `intranet.megacorpone.com`

### Open-Source Code
There are various online tools and resources we can use to passively gather information. This includes open-source projects and online code repositories such as GitHub, GitHub Gist, GitLab, and SourceForge
+ Code stored online can provide a glimpse into the programming languages and frameworks use by an organization 
+ On rare occasions, developers have accidentally committed sensitive data and credentials to public repos 
+ Can search these platforms using the google hacking search operators

GitHub's search is flexible, can search a user or organizations repos
+ Will need an account to search across all public repos 
+ Can search a targets repo for specific file names using the `path:` operator
	+ `path:*users*` will search for any files with the word "users" in the name 
	+ Can potentially find username and password hashes via this method 

The manual approach works best on small repos, for larger repos should user automation tools for searching such as <mark style="background: #D2B3FFA6;">Gitrob</mark> and <mark style="background: #D2B3FFA6;">Gitleaks</mark> 
+ Most of these tools require an access token to use the source code-hosting providers API 
+ Can use theses tools to search for AWS access key IDS in a file for example, which can allow unlimited access to the same AWS account and lead to a compromise of any cloud service managed by this identity 

Tools that search through source code for secrets, like <mark style="background: #D2B3FFA6;">Gitrob</mark> or <mark style="background: #D2B3FFA6;">Gitleaks</mark>, generally rely on _regular expressions_ or _entropy_-based detections to identify potentially useful information. Entropy-based detection attempts to find strings that are randomly generated. The idea is that a long string of random characters and numbers is probably a password. No matter how a tool searches for secrets, no tool is perfect and they will miss things that a manual inspection might find

### Shodan 
Shodan is a search engine that crawls devices connected to the internet, including the servers that run websites, and devices like routers and IoT devices 
+ Google search engine is for web server content, Shodan searches Internet-connected devices, interacts with them, and displays information about them 
+ Will gather information passively, and will list the IPs, services, and banner information 
+ Will get a snapshot of the targets internal footprint, and will be able to drill down by clicking specific *Top Ports* or *Top Products* 
+ With these results can determine information like service application version, and get a summary of the host 
	+ Can review the ports, services, and technologies used by the server on this page
	+ Shodan will also reveal if there are any published vulnerabilities for any of the identified services or technologies running on the same host

Can use Shodan operators to do detailed searches 
+ `hostname` can be used to isolate specific hostnames 
	+ For example `hostname:megacorpone.com`

### Security Headers and SSL/TLS 
There are several other specialty websites that we can use to gather information about a website or domain's security posture
+ Some of these will blur the line between passive and active information gathering 

Security Headers, https://securityheaders.com/, will analyze HTTP response headers and provide basic analysis of the target site's security posture 
+ Can use this to get an idea of an organizations coding and security practices based on the results 
+ Can see missing defensive headers such as `Content-Security-Policy` and `X-Frame-Options` 
+ These missing headers are not necessarily vulnerabilities in and of themselves, but they could indicate web developers or server admins that are not familiar with _server hardening_
	+ **Server hardening** is the overall process of securing a server via configuration. This includes processes such as disabling unneeded services, removing unused services or user accounts, rotating default passwords, setting appropriate server headers, and so forth. We don't need to know all the ins and outs of configuring every type of server, but understanding the concepts and what to search for can help us determine how best to approach a potential target

Another scanning tool we can use is the _SSL Server Test_ from Qualys SSL Labs, https://www.ssllabs.com/ssltest/, this tool analyzes a server's SSL/TLS configuration and compares it against current best practices
+ It will also identify some SSL/TLS related vulnerabilities such as Poodle or Heart bleed
+ Indication that a server supports TLS versions such as 1.0 and 1.1, which are deemed legacy as they implement insecure cipher suites, ultimately suggests that our target is not applying current best practices for SSL/TLS hardening
	+ Disabling the _TLS_DHE_RSA_WITH_AES_256_CBC_SHA_ suite has been recommended for several years, due to multiple vulnerabilities both on AES Cipher Block Chaining mode and the SHA1 algorithm
## Active Information Gathering 
Will move beyond passive information gathering and explore techniques that involve direct interaction with target services
+ However, in some cases during a penetration test, we won't have the luxury of running our favorite Kali Linux tool
+ In an _assumed breach_ scenario such as this, we are typically given a Windows-based workstation by the client and must use what's available on Windows
	+ When "Living off the Land", we can leverage several pre-installed and trusted Windows binaries to perform post-compromise analysis
	+ These binaries are shortened as _LOLBins_ or, more recently, _LOLBAS_ to include Binaries, Scripts and Libraries

### DNS Enumeration 
The Domain Name System (DNS) is a distributed database responsible for translating user-friendly domain names into IP addresses 
+ It is one of the most critical systems on the internet 
+ This is facilitated by a hierarchical structure that is divided into several zones, starting with the top-level root zone 

Each domain can use different types of DNS records. Some of the most common types of DNS records include:
- **NS**: Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
- **A**: Also known as a host record, the "_a record_" contains the IPv4 address of a hostname (such as www.megacorpone.com).
- **AAAA**: Also known as a quad A host record, the "_aaaa record_" contains the IPv6 address of a hostname (such as www.megacorpone.com).
- **MX**: Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.
- **PTR**: Pointer Records are used in reverse lookup zones and can find the records associated with an IP address.
- **CNAME**: Canonical Name Records are used to create aliases for other host records.
- **TXT**: Text records can contain any arbitrary data and be used for various purposes, such as domain ownership verification.

#### DNS enumeration with host command, and bash one-liners 
Due to the wealth of information in DNS, it is a lucrative target for active information gathering 
+ The <mark style="background: #D2B3FFA6;">host</mark> command can find the IP address of a domain 
+ Usage: `host <DOMAIN>`
	+ Example: `host www.megacorpone.com` 
+ My default, the host command searches for an A record, but can also query other fields such as MX or TXT, by specifying the record type in our query using the `-t` option 
	+ Usage: `host -t <RECORD_TYPE> <DOMAIN>`
	+ Example for mx record: `host -t mx megacorpone.com`
		+ Each server has a different **priority** (10, 20, 50, 60) and the server with the **lowest priority number will be used first** to forward mail addressed to the megacorpone.com domain
	+ Example for txt records: `host -t txt megacorpone.com` 
		+ Will return various entries 
+ Can use the host command to see if various **domains and subdomains exist** 
	+ `host idontexist.megacorpone.com` for example will return not found or found 
##### DNS forward lookup brute-forcing
Can automate the effort of DNS domain enumeration by developing DNS brute-forcing techniques to speed up our research
+ By using a wordlist containing common hostnames, we can attempt to guess DNS records and check the response for valid hostnames

Can automate the forward DNS-lookup of common hostnames using the <mark style="background: #D2B3FFA6;">host</mark> *forward lookup* command in a Bash one-liner
+ Will build a list of possible hostnames:
``` Markdown
kali@kali:~$ cat list.txt
www
ftp
mail
owa
proxy
router
```
+ Can now use the bash one-liner to attempt to resolve each hostname: 
``` bash
for ip in $(cat list.txt); do host $ip.megacorpone.com; done
```
+ Example output:
```
www.megacorpone.com has address 149.56.244.87
Host ftp.megacorpone.com not found: 3(NXDOMAIN)
mail.megacorpone.com has address 51.222.169.212
Host owa.megacorpone.com not found: 3(NXDOMAIN)
Host proxy.megacorpone.com not found: 3(NXDOMAIN)
router.megacorpone.com has address 51.222.169.214
```
+ Using this simplified wordlist, we discovered entries for "www", "mail", and "router". The hostnames "ftp", "owa", and "proxy", however, were not found
+ Much more comprehensive wordlists are available as part of the SecLists project
	+ These wordlists can be installed to the **/usr/share/seclists** directory using the **sudo apt install seclists** command

##### DNS reverse lookup brute-forcing
Can scan the approximate range (For example, above shows that the valid hostnames are in the 51.222.169.X range), with *reverse lookups* 
+ Will use a bash one liner to loop through IP addresses 51.222.169.200 through 51.222.169.254, and will filter out results (using grep -v) by showing only entries that do not contain "not found"
``` Bash
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```
+ Example output: 
```
...
208.169.222.51.in-addr.arpa domain name pointer admin.megacorpone.com.
209.169.222.51.in-addr.arpa domain name pointer beta.megacorpone.com.
210.169.222.51.in-addr.arpa domain name pointer fs1.megacorpone.com.
211.169.222.51.in-addr.arpa domain name pointer intranet.megacorpone.com.
212.169.222.51.in-addr.arpa domain name pointer mail.megacorpone.com.
213.169.222.51.in-addr.arpa domain name pointer mail2.megacorpone.com.
214.169.222.51.in-addr.arpa domain name pointer router.megacorpone.com.
215.169.222.51.in-addr.arpa domain name pointer siem.megacorpone.com.
216.169.222.51.in-addr.arpa domain name pointer snmp.megacorpone.com.
217.169.222.51.in-addr.arpa domain name pointer syslog.megacorpone.com.
218.169.222.51.in-addr.arpa domain name pointer support.megacorpone.com.
219.169.222.51.in-addr.arpa domain name pointer test.megacorpone.com.
220.169.222.51.in-addr.arpa domain name pointer vpn.megacorpone.com.
...
```
+ In this example: We have successfully managed to resolve a number of IP addresses to valid hosts using reverse DNS lookups
+ If we were performing an assessment, we could further extrapolate these results, and might scan for "mail2", "router", etc., and reverse-lookup positive results
	+ These types of scans are often cyclical; we expand our search based on any information we receive at every round

#### DNS enumeration with Kali Linux 
There are several tools for this, notably _DNSRecon_ and _DNSenum_

##### DNSRecon
DNSRecon is an advanced DNS enumeration script written in Python
+ Can run <mark style="background: #D2B3FFA6;">dnsrecon</mark> against a domain using the `-d` option and `-t` to specify the type of enumeration where `std` is a standard scan
+ Usage: `dnsrecon -d <DOMAIN> -t <SCAN_TYPE>`
	+ Example: `dnsrecon -d megacorpone.com -t std` 
	+ Example output:
```
[*] std: Performing General Enumeration against: megacorpone.com...
[-] DNSSEC is not configured for megacorpone.com
[*] 	 SOA ns1.megacorpone.com 51.79.37.18
[*] 	 NS ns1.megacorpone.com 51.79.37.18
[*] 	 NS ns3.megacorpone.com 66.70.207.180
[*] 	 NS ns2.megacorpone.com 51.222.39.63
[*] 	 MX mail.megacorpone.com 51.222.169.212
[*] 	 MX spool.mail.gandi.net 217.70.178.1
[*] 	 MX fb.mail.gandi.net 217.70.178.217
[*] 	 MX fb.mail.gandi.net 217.70.178.216
[*] 	 MX fb.mail.gandi.net 217.70.178.215
[*] 	 MX mail2.megacorpone.com 51.222.169.213
[*] 	 TXT megacorpone.com Try Harder
[*] 	 TXT megacorpone.com google-site-verification=U7B_b0HNeBtY4qYGQZNsEYXfCJ32hMNV3GtC0wWq5pA
[*] Enumerating SRV Records
[+] 0 Records Found
```
+ Based on the output above, we have managed to perform a successful DNS scan on the main record types against the megacorpone.com domain

Can **bruteforce with a wordlist** using `-D` option to specify a file name containing potential subdomain strings, and the `-t` option specified as `brt` for bruteforce 
+ Usage: `dnsrecon -d <DOMAIN> -D <WORDLIST_PATH> -t brt`
	+ Example: `dnsrecon -d megacorpone.com -D ~/list.txt -t brt`
	+ Example output: 
```
[*] Using the dictionary file: /home/kali/list.txt (provided by user)
[*] brt: Performing host and subdomain brute force against megacorpone.com...
[+] 	 A www.megacorpone.com 149.56.244.87
[+] 	 A mail.megacorpone.com 51.222.169.212
[+] 	 A router.megacorpone.com 51.222.169.214
[+] 3 Records Found
```
+ Where the list used is as follows:
```
kali@kali:~$ cat list.txt 
www
ftp
mail
owa
proxy
router
```
+ The brute force attempt has finished, and we have *managed to resolve a few hostnames*

##### DNSEnum
DNSEnum is another popular DNS enumeration tool that can be used to further automate DNS enumeration of the megacorpone.com domain, and can be ran simply with the <mark style="background: #D2B3FFA6;">dnsenum</mark> command followed by the domain 
+ Usage: `dnsenum <DOMAIN>`
	+ Example: `dnsenum megacorpone.com`
	+ Example output:
``` 
...
dnsenum VERSION:1.2.6

-----   megacorpone.com   -----

...

Brute forcing with /usr/share/dnsenum/dns.txt:
_______________________________________________

admin.megacorpone.com.                   5        IN    A        51.222.169.208
beta.megacorpone.com.                    5        IN    A        51.222.169.209
fs1.megacorpone.com.                     5        IN    A        51.222.169.210
intranet.megacorpone.com.                5        IN    A        51.222.169.211
mail.megacorpone.com.                    5        IN    A        51.222.169.212
mail2.megacorpone.com.                   5        IN    A        51.222.169.213
ns1.megacorpone.com.                     5        IN    A        51.79.37.18
ns2.megacorpone.com.                     5        IN    A        51.222.39.63
ns3.megacorpone.com.                     5        IN    A        66.70.207.180
router.megacorpone.com.                  5        IN    A        51.222.169.214
siem.megacorpone.com.                    5        IN    A        51.222.169.215
snmp.megacorpone.com.                    5        IN    A        51.222.169.216
syslog.megacorpone.com.                  5        IN    A        51.222.169.217
test.megacorpone.com.                    5        IN    A        51.222.169.219
vpn.megacorpone.com.                     5        IN    A        51.222.169.220
www.megacorpone.com.                     5        IN    A        149.56.244.87
www2.megacorpone.com.                    5        IN    A        149.56.244.87


megacorpone.com class C netranges:
___________________________________

 51.79.37.0/24
 51.222.39.0/24
 51.222.169.0/24
 66.70.207.0/24
 149.56.244.0/24


Performing reverse lookup on 1280 ip addresses:
________________________________________________

18.37.79.51.in-addr.arpa.                86400    IN    PTR      ns1.megacorpone.com.
...
```

Have now discovered several previously-unknown hosts as a result of our extensive DNS enumeration
+ Information gathering has a cyclic pattern, so we'll need to perform all the other passive and active enumeration tasks on this new subset of hosts to disclose any new potential details

#### DNS enumeration with Windows 
Although not in the LOLBAS listing, <mark style="background: #D2B3FFA6;">nslookup</mark> is another great utility for Windows DNS enumeration and still used during 'Living off the Land' scenarios
+ Applications that can provide unintended code execution are normally listed under the **LOLBAS** project

With a Windows 11 client, can run a simple query to resolve the **A record** for a host 
+ Usage: `nslookup <DOMAIN>`
	+ Example: `nslookup mail.megacorptwo.com`
	+ Example output:
```
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  192.168.50.151

Name:    mail.megacorptwo.com
Address:  192.168.50.154
```
+ queried the default DNS server (192.168.50.151) to resolve the IP address of mail.megacorptwo.com, which the DNS server then answered with "192.168.50.154"

<mark style="background: #D2B3FFA6;">nslookup</mark> can perform more granular queries. For instance, we can query a given DNS record type using the `-type` switch 
+ Usage: `nslookup -type=<RECORD_TYPE> <DOMAIN> <DNS_IP>`
	+ Example for txt record type: `nslookup -type=TXT info.megacorptwo.com 192.168.50.151`
	+ Example output:
```
Server:  UnKnown
Address:  192.168.50.151

info.megacorptwo.com    text =

        "greetings from the TXT record body"
```
+ We are specifically querying the 192.168.50.151 DNS server for any TXT record related to the info.megacorptwo.com host

The <mark style="background: #D2B3FFA6;">nslookup</mark> utility is as versatile as the Linux <mark style="background: #D2B3FFA6;">host</mark> command and the queries can also be further automated through <mark style="background: #ADCCFFA6;">PowerShell</mark> or <mark style="background: #D2B3FFA6;">Batch</mark> scripting

### TCP/UDP Port Scanning Theory 
Port scanning is the process of inspecting TCP or UDP ports on a remote machine with the intention of detecting what services are running on the target and what potential attack vectors may exist
+ **Note**: port scanning is not representative of traditional user activity and could be considered illegal in some jurisdictions. Therefore, it _should not be performed outside the labs_ without direct, written permission from the target network owner

It is essential to understand the implications of port scanning, as well as the impact that specific port scans can have
+ Due to the amount of traffic some scans can generate, along with their intrusive nature, running port scans blindly can have adverse effects on target systems or the client network such as overloading servers and network links or triggering an IDS/IPS
+ Running the wrong scan could result in downtime for the customer

Using a proper port scanning methodology can significantly improve our efficiency as penetration testers while also limiting many of the risks
+ Depending on the scope of the engagement, instead of running a full port scan against the target network, we can start by only scanning for ports 80 and 443.
+ With a list of possible web servers, we can run a full port scan against these servers in the background while performing other enumeration
+ Once the full port scan is complete, we can further narrow our scans to probe for more and more information with each subsequent scan
+ Port scanning should be understood as a dynamic process that is unique to each engagement
	+ The results of one scan determine the type and scope of the next scan

We'll begin our exploration of port scanning with a simple TCP and UDP port scan using <mark style="background: #D2B3FFA6;">Netcat</mark>
+ It should be noted that <mark style="background: #D2B3FFA6;">Netcat</mark> is **not** a port scanner, but it can be used as such in a rudimentary way to showcase how a typical port scanner works
+ Since Netcat is already present on many systems, we can repurpose some of its functionality to mimic a basic port scan when we are not in need of a fully-featured port scanner

#### TCP scanning techniques
+ The simplest TCP port scanning technique, usually called CONNECT scanning, relies on the three-way TCP handshake mechanism
+ This mechanism is designed so that two hosts attempting to communicate can negotiate the parameters of the network TCP socket connection before transmitting any data
	+ In basic terms, a host sends a TCP _SYN_ packet to a server on a destination port
	+ If  the destination port is open, the server responds with a _SYN-ACK_ packet and the client host sends an _ACK_ packet to complete the handshake
	+ If the handshake completes successfully, the port is considered open

We can demonstrate this by running a TCP Netcat port scan on ports with the <mark style="background: #D2B3FFA6;">nc</mark> command, `-n` will use numeric IPs with no DNS lookups, `-vv` will show the output as extra verbose, `-w` indicates the connection timeout in seconds, and `-z` specifies zero-I/O mode which sends no data and is used for scanning
+ Usage: `nc -nvv -w <TIMEOUT_TIME> -z <IP> <PORT_RANGE>`
	+ Example: `nc -nvv -w 1 -z 192.168.50.152 3388-3390`
	+ Example output:
```
(UNKNOWN) [192.168.50.152] 3390 (?) : Connection refused
(UNKNOWN) [192.168.50.152] 3389 (ms-wbt-server) open
(UNKNOWN) [192.168.50.152] 3388 (?) : Connection refused
 sent 0, rcvd 0
```
+ This output indicates that port 3389 is open, while connections on port 3388 and 3390 have been refused 

See <mark style="background: #D2B3FFA6;">Wireshark</mark> capture of the scan:
![[Screenshot 2023-08-01 at 2.47.51 PM.png]]
+ Netcat sent several TCP SYN packets to ports 3390, 3389, and 3388 on packets 1, 3, and 7, respectively
	+ Due to a variety of factors, including timing issues, the packets may appear out of order in Wireshark
+ We'll observe that the server sent a *TCP SYN-ACK* packet from port 3389 on packet 4, indicating that the port is open
+ The other ports did not reply with a similar SYN-ACK packet, and actively rejected the connection attempt via a _RST-ACK_ packet
+ Finally, on packet 6, Netcat closed this connection by sending a _FIN-ACK_ packet

#### UDP scanning techniques
Since UDP is stateless and does not involve a three-way handshake, the mechanism behind UDP port scanning is different from TCP

Can run a UDP <mark style="background: #D2B3FFA6;">Netcat</mark> port scan similarly to the TCP scan, but will use the `-u` option which indicates a UDP scan 
+ Usage: `nc -nvv -u -z -w <TIMEOUT_TIME> <IP> <PORT_RANGE>`
	+ Example: `nc -nv -u -z -w 1 192.168.50.149 120-123`
	+ Example output:
```
(UNKNOWN) [192.168.50.149] 123 (ntp) open
```

From the Wireshark capture, we will notice the UDP scan uses a different mechanism than a TCP scan:
![[Screenshot 2023-08-01 at 2.53.47 PM.png]]
+ An empty UDP packet is sent to a specific port (packets 2, 3, 5, and 7)
+ If the destination UDP port is open, the packet will be passed to the application layer
+ The response received will depend on how the application is programmed to respond to empty packets
+ In this example, the application sends no response
+ However, if the destination UDP port is closed, the target should respond with an ICMP port unreachable (as shown in packets 5, 7, and 9), sent by the UDP/IP stack of the target machine

Most UDP scanners tend to use the standard "ICMP port unreachable" message to infer the status of a target port
+ However, this method can be completely unreliable when the target port is filtered by a firewall
+ In fact, in these cases the scanner will report the target port as open because of the absence of the ICMP message

UDP scanning can be **problematic** for several reasons
1. UDP scanning is often unreliable, as firewalls and routers may drop ICMP packets. This can lead to false positives and ports showing as open when they are, in fact, closed
2. Second, many port scanners do not scan all available ports, and usually have a pre-set list of "interesting ports" that are scanned. This means open UDP ports can go unnoticed. Using a protocol-specific UDP port scanner may help to obtain more accurate results
3. Finally, penetration testers often forget to scan for open UDP ports, instead focusing on the "more exciting" TCP ports. Although UDP scanning can be unreliable, there are plenty of attack vectors lurking behind open UDP ports. A TCP scan also generates much more traffic than a UDP scan, due to overhead and packet retransmissions

### Port Scanning with Nmap 
Nmap (written by Gordon Lyon, aka Fyodor) is one of the most popular, versatile, and robust port scanners available
+ It has been actively developed for over two decades, and offers numerous features beyond port scanning 

A lot of Nmap scans need to be run using **sudo** 
+ This is because quite a few Nmap scans require access to raw sockets, which requires root privileges 
+ Raw sockets allow for surgical manipulation of TCP and UDP packets 
+ Without raw sockets, Nmap is limited to crafting packets using the standard Berkeley socket API 

Should understand the **footprint** that each Nmap scan leaves on the wire and the scanned hosts 
+ A default Nmap TCP scan will scan the 1000 most popular ports on a given machine 
+ Cab examine the amount of traffic sent by this type of scan
	+ Can monitor the amount of traffic sent to a target host using *iptables* 
#### Iptables
![[Pasted image 20230802143342.png]]
+ See that the chains in the **tables** are organized, where the **filter** will primarily be used as firewall functionality, which servers our purposes 
+ **Chains** are the rules that process packet types, in the filter table:
	+ input is incoming traffic
	+ output is outgoing traffic
	+ and forward is traffic being forwarded 
+ **Rules** are tested from the first rule in the chain, to the last rule
	+ With out a default rule, all packets are accepted 
+ **Targets** are set in these rules, and these refer to what is going to happen to that packet, it can be one of the following:
	+ Accept: Allow packet to travel and be processed
	+ Reject: Will drop and send feed back to the sender that it was dropped 
	+ Drop: Dropped, as if there was no packet at all

<mark style="background: #D2B3FFA6;">iptables</mark> commands can be found on the man page, but the basics are as follows:
+ `iptables -L` to list the default table (filter) chains 
+ Can change the default rule of a chain with: `iptables --policy <CHAIN> <TARGET>`
	+ Setting default incoming traffic to be dropped example: `iptables --policy INPUT DROP`
+ Specify IP based rules: `iptables -I <CHAIN> -s <SOURCE_IP> -d <DESTINATION_IP> <TARGET>`
	+ Dropping all incoming traffic from 10.0.0.1 example: `iptables -I INPUT -s 10.0.0.1 -j DROP`
+ `iptables -L --line-numbers` to see the chains rules by line number 
+ Can delete a rule number via: `iptables -D <CHAIN> <RULE_NUMBER>`
+ Specify port based rules: `iptables -I <CHAIN> -p <TCP/UDP> --dport <DESTINATION_PORT> --sport <SOURCE_PORT> -j <TARGET>`
	+ Can combine port rules with ip rules for very specific firewall rules 
+ Save rules with `sudo /sbin/iptables-save`
+ Flush rules with `iptables -F`
+ `sudo iptables -Z` to zero the packet and byte counters of the rules 
+ `sudo iptables -vn -L` to see statistics of the chain rules 

#### Iptables nmap traffic testing 
Will use several *iptables* options 
+ Can use the `-I` option to insert a new rule into a given chain at the top, which will include both the **INPUT** and **OUTPUT** chain, followed by the rule model. 
+ Can specify the `-d` option for the destination IP, and the `-j` option to **ACCEPT** the traffic 
+ `-Z` option can be used to zero the packet and byte counters in all chains 
+ All put together:
```
kali@kali:~$ sudo iptables -I INPUT 1 -s 192.168.50.149 -j ACCEPT
kali@kali:~$ sudo iptables -I OUTPUT 1 -d 192.168.50.149 -j ACCEPT
kali@kali:~$ sudo iptables -Z
```

Can now generate some traffic using <mark style="background: #FFB86CA6;">nmap</mark>:
```
nmap 192.168.50.149
```
+ Can review some **iptables** statistics to get a clearer idea of how much traffic our scan generated. We can use the `-v` option to add some verbosity to our output, `-n` to enable numeric output, and `-L` to list the rules present in all chains:
```
kali@kali:~$ sudo iptables -vn -L
Chain INPUT (policy ACCEPT 1270 packets, 115K bytes)
 pkts bytes target     prot opt in     out     source               destination
 1196 47972 ACCEPT     all  --  *      *       192.168.50.149      0.0.0.0/0

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 1264 packets, 143K bytes)
 pkts bytes target     prot opt in     out     source               destination
 1218 72640 ACCEPT     all  --  *      *       0.0.0.0/0            192.168.50.149
```
+ According to the output, this default 1000-port scan generated around **72 KB** of traffic

Using a nmap scan that scans all TCP port via the `-p` option will generate even more traffic:
```
nmap -p 1-65535 192.168.50.149
```
+ See traffic generated with iptables 
```
kali@kali:~$ sudo iptables -vn -L
Chain INPUT (policy ACCEPT 67996 packets, 6253K bytes)
 pkts bytes target     prot opt in     out     source               destination
68724 2749K ACCEPT     all  --  *      *       192.168.50.149      0.0.0.0/0

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 67923 packets, 7606K bytes)
 pkts bytes target     prot opt in     out     source               destination
68807 4127K ACCEPT     all  --  *      *       0.0.0.0/0            192.168.50.149
```
+ generated about **4 MB** of traffic - a significantly higher amount
+ However, this full port scan has discovered more ports than the default TCP scan found

Our results imply that a full Nmap scan of a class C network (254 hosts) would result in sending over 1000 MB of traffic to the network. 
+ Ideally, a full TCP and UDP port scan of every single target machine would provide the most accurate information about exposed network services. However, we clearly need to balance any traffic restrictions (such as a slow uplink) with discovering additional open ports and services via a more exhaustive scan. 
+ This is especially true for larger networks, such as a class A or B network assessment.
+ **Note**: There are modern port scanners like **MASSCAN** and **RustScan** that, although faster than Nmap, generate a substantial amount of concurrent traffic. Nmap, on the other hand, imposes some traffic rate limiting that results in less bandwidth congestion and more covert behavior.

#### Nmap scanning techniques 

##### Stealth/SYN scan
The most popular Nmap scanning technique is **SYN**, or "**stealth**" scanning
+ There are many benefits of the SYN scan, and it is the default scan option used when no scan option is specified with correct **sudo** permission (Because it requires raw socket privileges)
	+ Can still be specified with the `-sS` option

SYN scanning is a TCP port scanning method that sends SYN packets to various ports on a target machine without completing a TCP handshake 
+ If a TCP port is open, a SYN-ACK should be sent back from the target machine, which informs us it is open 
+ The port scanner does not send the final ACK to complete the three-way handshake 
+ Because the three way handshake is not completed, the information is not passed to the application layer, so it could not appear in any application logs 
+ A SYN scan is also faster an more efficient because fewer packets are sent/recieved 
+ **Note**: the term "stealth" refers to the fact that, in the past, firewalls would fail to log incomplete TCP connections. 
	+ This is no longer the case with modern firewalls and although the stealth moniker has stuck around, it could be misleading

Example:
```
sudo nmap -sS 192.168.50.149
```
##### TCP Connect Scan
As the name suggests, performs a full TCP connection
+ Defaults to this when **sudo** is not used to provide raw socket privileges 
	+ Can be specified with the `-sT` option

TCP Connect scan will use the Berkeley socket API to perform the three-way handshake, and does not require elevated privileges 
+ Nmap has to wait for the connection to complete before the API returns the status of the connections, which makes it take much longer then the SYN scan 

Example:
```
nmap -sT 192.168.50.149
```
+ Output:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-09 06:44 EST
Nmap scan report for 192.168.50.149
Host is up (0.11s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
...
```
+ Can see even from this scan the there are a few open services 
+ Many of these services are only active on Windows-based hosts, especially Domain Controllers 
	+ Can already infer the underlying OS and role of the target host 

##### UDP Scan
When performing a UDP scan, Nmap will use a combination of two different methods to determine if a port is open or closed
+ For most ports, it will use the standard "ICMP port unreachable" method described earlier by sending an empty packet to a given port
+ However, for common ports, such as port 161, which is used by SNMP, it will send a protocol-specific SNMP packet in an attempt to get a response from an application bound to that port
+ To perform a UDP scan, we'll use the `-sU` option, with **sudo** required to access raw sockets

Example:
```
sudo nmap -sU 192.168.50.149
```

##### Combination Scan 
The UDP scan (`-sU`) can also be used in conjunction with a TCP SYN scan (`-sS`) to build a more complete picture of our target

Example:
```
sudo nmap -sU -sS 192.168.50.149
```
+ Output:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-09 08:16 EST
Nmap scan report for 192.168.50.149
Host is up (0.10s latency).
Not shown: 989 closed tcp ports (reset), 977 closed udp ports (port-unreach)
PORT      STATE         SERVICE
53/tcp    open          domain
88/tcp    open          kerberos-sec
135/tcp   open          msrpc
139/tcp   open          netbios-ssn
389/tcp   open          ldap
445/tcp   open          microsoft-ds
464/tcp   open          kpasswd5
593/tcp   open          http-rpc-epmap
636/tcp   open          ldapssl
3268/tcp  open          globalcatLDAP
3269/tcp  open          globalcatLDAPssl
53/udp    open          domain
123/udp   open          ntp
389/udp   open          ldap
...
```
+ The joint TCP and UDP scan revealed additional open UDP ports, further disclosing which services are running on the target host

##### Network Sweeping 
Can extend what we have learned from a single host and apply it to a full network range, and quickly find which hosts are up
+ To deal with large volumes of hosts, or conserve network traffic, can attempt to probe targets using network sweeping techniques, where it begins with broad scams, then use more specific scans agains hosts of interests 
+ Will perform a network sweep with the `-sn` option 

The host discovery process consists of more than just sending an ICMP echo request. Nmap also sends a **TCP SYN** packet to port 443, a **TCP ACK** packet to port 80, and an **ICMP** timestamp request to verify whether a host is available

Example:
```
nmap -sn 192.168.50.1-253
```
+ Output:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-10 03:19 EST
Nmap scan report for 192.168.50.6
Host is up (0.12s latency).
Nmap scan report for 192.168.50.8
Host is up (0.12s latency).
...
Nmap done: 254 IP addresses (13 hosts up) scanned in 3.74 seconds
```

Using grep on a standard nmap output can be cumbersome
+ Can use the Nmap's "greppable" output paramater `-oG` to save the results in a more manageable format 
+ Example
```
kali@kali:~$ nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-10 03:21 EST
Initiating Ping Scan at 03:21
...
Read data files from: /usr/bin/../share/nmap
Nmap done: 254 IP addresses (13 hosts up) scanned in 3.74 seconds
...

kali@kali:~$ grep Up ping-sweep.txt | cut -d " " -f 2
192.168.50.6
192.168.50.8
192.168.50.9
...
```

##### Port Specific  Sweeping 
Sweep for specific TCP or UDP ports across the network, probing for common services and ports in an attempt to locate systems that may be useful or have known vulnerabilities
+ This scan tends to be more accurate than a ping sweep
+ Will use the `-p` option for **specific ports** during the sweeps 

Example (For finding web services):
```
nmap -p 80 192.168.50.1-253 -oG web-sweep.txt
```
+ Output:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-10 03:50 EST
Nmap scan report for 192.168.50.6
Host is up (0.11s latency).

PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for 192.168.50.8
Host is up (0.11s latency).

PORT   STATE  SERVICE
80/tcp closed http
...

kali@kali:~$ grep open web-sweep.txt | cut -d" " -f2
192.168.50.6
192.168.50.20
192.168.50.21
```

Can prob specially from a **short list of common ports**, with the `--top-ports` argument
+ `--top-ports=20` will look for the top 20 ports 
+ The top 20 <mark style="background: #FFB86CA6;">nmap</mark> ports are determined using the `/usr/share/nmap/nmap-services` file, which uses a simple format of three whitespace-separated columns
	+ The first is the name of the service, the second contains the port number and protocol, and the third is the "port frequency"
	+ Everything after the third column is ignored, but is typically used for comments as shown by the use of the pound sign (#). The port frequency is based on how often the port was found open during periodic research scans of the internet

##### Aggressive Scan
Enable OS version detection, script scanning, and traceroute with `-A`
1. OS detection: Nmap attempts to identify the operating system of the target by analyzing the responses from various network probes.
2. Version detection: Nmap tries to determine the versions of the services running on open ports, providing more detailed information about the software versions in use.
3. Script scanning: Nmap runs a selection of default scripts from the Nmap Scripting Engine (NSE). These scripts are designed to perform additional tests and gather more information about the target, such as vulnerability checks, service enumeration, etc.

##### OS fingerprinting
This feature attempts to guess the target's operating system by inspecting returned packets
+ This works because operating systems often use slightly different implementations of the TCP/IP stack (such as varying default TTL values and TCP window sizes), and these slight variances create a fingerprint that Nmap can often identify
+ can be enabled with the `-O` option

By default, Nmap will display the detected OS only if the retrieved fingerprint is very accurate
+ If there is not an exact match, but still want to get a **rough idea** of the target os, can include:
	+ `--osscan-guess` option (to force a guess)

Example:
```
sudo nmap -O 192.168.50.14 --osscan-guess
```
+ Output:
```
...
Running (JUST GUESSING): Microsoft Windows 2008|2012|2016|7|Vista (88%)
OS CPE: cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista::sp1:home_premium
Aggressive OS guesses: Microsoft Windows Server 2008 SP1 or Windows Server 2008 R2 (88%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (88%), Microsoft Windows Server 2012 R2 (88%), Microsoft Windows Server 2012 (87%), Microsoft Windows Server 2016 (87%), Microsoft Windows 7 (86%), Microsoft Windows Vista Home Premium SP1 (85%), Microsoft Windows 7 Professional (85%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
...
```
+ The response suggests that the underlying operating system of this target is either Windows 2008 R2, 2012, 2016, Vista, or Windows 7
+ **Note** that OS Fingerprinting is not always 100% accurate, often due to network devices like **firewalls** or **proxies** that rewrite packet headers in between the communication

##### Service Scan
If we want to run a plain service nmap scan we can do it by providing only the `-sV` parameter
+ Will do Service identification, vulnerability assessment, and fingerprinting 
+ Banner grabbing significantly impacts the amount of traffic used as well as the speed of our scan. We should always be mindful of the options we use with <mark style="background: #FFB86CA6;">nmap</mark> and how they affect our scans
+ Banners can be modified by system administrators and intentionally set to fake service names to mislead potential attackers
##### Scan Output 
+ **Normal** Output (`-oN`): This option writes the output in normal human-readable format to the specified file
+ **XML** Output (`-oX`): The XML output option saves the scan results in XML format
+ **Grepable** Output (`-oG`): This option writes the output in a grepable format, which is useful for further processing with tools like grep or scripting
+ **All Output Formats** (`-oA`): This option saves results in all formats: normal, XML, and grepable. It generates three files with the given base name and appropriate extensions (.nmap, .xml, .gnmap)

Can use <mark style="background: #D2B3FFA6;">xsltproc</mark> to convert a XML file to a HTML file, which can be viewed nicely 
+ Usage: `xsltproc <XML_NMAP_FILE> -o <HTML_NMAP_FILE>`
+ Open in fire fox with `firefox <HTML_NMAP_FILE>`
#### Nmap Scripting Engine (NSE)
Can use the **NSE** to launch user-created scripts in order to automate various scanning tasks
+ These scripts perform a broad range of functions including DNS enumeration, brute force attacks, and even vulnerability identification
+ NSE scripts are located in the `/usr/share/nmap/scripts` directory
	+ The _http-headers_ script, for example, attempts to connect to the HTTP service on a target system and determine the supported headers

To view more information about a script, we can use the `--script-help` option, which displays a description of the script and a URL where we can find more in-depth information, such as the script arguments and usage examples
+ Example: `nmap --script-help http-headers`
	+ Example Usage: `nmap --script http-headers 192.168.50.6`
#### Powershell Scanning from Windows host 
If we are conducting initial network enumeration from a Windows laptop with no internet access, we are prevented from installing any extra tools that might help us, like the Windows Nmap version
+ In such a limited scenario, we are forced to pursue the 'living off the land' strategy
+ There are a few helpful built-in <mark style="background: #ADCCFFA6;">PowerShell</mark> functions we can use

The `Test-NetConnection` function checks if an IP responds to ICMP and whether a specified TCP port on the target host is open
+ For instance, from the **Windows 11** client, we can verify if the SMB port 445 is open on a domain controller as follows:
	+ `Test-NetConnection -Port 445 192.168.50.151`
	+ Output:
```
ComputerName     : 192.168.50.151
RemoteAddress    : 192.168.50.151
RemotePort       : 445
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.50.152
TcpTestSucceeded : True
```
+ The returned value in the _TcpTestSucceeded_ parameter indicates that port 445 is open

We can further script the whole process in order to scan the first 1024 ports on the Domain Controller with the PowerShell one-liner shown below:
+ To do so we need to instantiate a _TcpClient_ Socket object as _Test-NetConnection_ send additional traffic that is non needed for our purposes
``` PowerShell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null
```
+ We start by piping the first 1024 integer into a for-loop which assigns the incremental integer value to the `$_` 
+ Then, we create a _Net.Sockets.TcpClient_ object and perform a TCP connection against the target IP on that specific port, and if the connection is successful, it prompts a log message that includes the open TCP port
+ Note that this method is very slow
### SMB Enumeration 
Server Message Block (SMB) protocol has had a bad security track record, due to its complex implementation and open nature 
+ SMB started with unauthenticated null sessions in Windows 2000 and XP 
+ Also had a plethora of SMB bugs and vulnerabilities over the years
+ SMB protocol has been updated and improved in parallel with Windows releases 

**NetBIOS** service listens on TCP port *139*, as well as several UDP ports 
+ Keep in mind **SMB** (TCP port 445) and NetBIOS are two separate protocols 
+ NetBIOS is an independent session layer protocol and service that allows computers on a local network to communicate with each other 

Modern implementations of **SMB** can work without **NetBIOS** 
+ NetBIOS over TCP (**NBT**) is required for backward compatibility and these are often enabled together 
+ This means the enumeration of these two services often go hand-in-hand 

These services can be scanned with tools like <mark style="background: #FFB86CA6;">nmap</mark>, using the following:
```
nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
```
+ Output:
```
kali@kali:~$ cat smb.txt
# Nmap 7.92 scan initiated Thu Mar 17 06:03:12 2022 as: nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
# Ports scanned: TCP(2;139,445) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 192.168.50.1 ()	Status: Down
...
Host: 192.168.50.21 ()	Status: Up
Host: 192.168.50.21 ()	Ports: 139/closed/tcp//netbios-ssn///, 445/closed/tcp//microsoft-ds///
...
Host: 192.168.50.217 ()	Status: Up
Host: 192.168.50.217 ()	Ports: 139/closed/tcp//netbios-ssn///, 445/closed/tcp//microsoft-ds///
# Nmap done at Thu Mar 17 06:03:18 2022 -- 254 IP addresses (15 hosts up) scanned in 6.17 seconds
```
+ Saving the output into a text file, it reveals hosts with ports 139 and 445 open

#### NetBIOS scanning with nbtscan 
There are other, more specialized tools for specifically identifying NetBIOS information, such as <mark style="background: #D2B3FFA6;">nbtscan</mark>
+ Can use this to query the NetBIOS name service for valid NetBIOS names, specifying the originating UDP port as 137 with the `-r` option:
```
sudo nbtscan -r 192.168.50.0/24
```
+ Output:
```
Doing NBT name scan for addresses from 192.168.50.0/24

IP address       NetBIOS Name     Server    User             MAC address
------------------------------------------------------------------------------
192.168.50.124   SAMBA            <server>  SAMBA            00:00:00:00:00:00
192.168.50.134   SAMBAWEB         <server>  SAMBAWEB         00:00:00:00:00:00
...
```
+ This scan revealed two NetBIOS names belong to two hosts 
+ This can further improve the context of the scanned hosts, as NetBIOS names are ofter very descriptive about the role of the host within the organization 
+ This data can feed our information-gathering cycle by leading to further disclosures

#### Nmap NSE script scanning 
Nmap also offers many useful NSE scripts that we can use to discover and enumerate SMB services
+ We'll find these scripts in the `/usr/share/nmap/scripts` directory
+ To show smb scripts: `ls -1 /usr/share/nmap/scripts/smb*`
	+ There are several interesting Nmap SMB NSE scripts that perform various tasks such as OS discovery and enumeration via SMB
	+ The **SMB discovery script** works only if SMBv1 is enabled on the target, which is not the default case on modern versions of Windows. However, plenty of legacy systems are still running SMBv1, and we have enabled this specific version on the Windows host to simulate such a scenario

The _smb-os-discovery_ module on the Windows 11 client for example:
```
nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152
```
+ Output:
```
...
PORT    STATE SERVICE      REASON
139/tcp open  netbios-ssn  syn-ack
445/tcp open  microsoft-ds syn-ack

Host script results:
| smb-os-discovery:
|   OS: Windows 10 Pro 22000 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: client01
|   NetBIOS computer name: CLIENT01\x00
|   Domain name: megacorptwo.com
|   Forest name: megacorptwo.com
|   FQDN: client01.megacorptwo.com
|_  System time: 2022-03-17T11:54:20-07:00
...
```
+ This particular script identified a potential match for the host operating system; however, we know it's inaccurate as the target host is running Windows 11 instead of the reported Windows 10
+ As mentioned earlier, any Nmap service and OS enumeration output should be taken with *grain of* salt, as none of the algorithms are perfect
+ Unlike Nmap's OS fingerprinting options we explored earlier, OS enumeration via NSE scripting provides extra information, such as the domain and other details related to Active Directory Domain Services
	+ This approach will also likely go unnoticed, as it produces less traffic that can also blend into normal enterprise network activity

#### SMB enumerating with Windows 
One useful tool for **enumerating SMB shares** within Windows environments is <mark style="background: #D2B3FFA6;">net view</mark>
+ It lists domains, resources, and computers belonging to a given host
+ As an example, connected to the client01 VM, we can list all the shares running on dc01:
```
net view \\dc01 /all
```
+ Output:
```
Shared resources at \\dc01

Share name  Type  Used as  Comment

-------------------------------------------------------------------------------
ADMIN$      Disk           Remote Admin
C$          Disk           Default share
IPC$        IPC            Remote IPC
NETLOGON    Disk           Logon server share
SYSVOL      Disk           Logon server share
The command completed successfully.
```
+ providing the `/all` keyword, we can list the **administrative shares** ending with the **dollar sign**

#### enum4linux Enumeration 
Can use <mark style="background: #D2B3FFA6;">enum4linux</mark> to enumerate SMB for various things using various methods 
+ `enum4linx -a <IP>` option will use all of its simple methods available, this will show a good spread of various enumerated information 
+ With a valid user can do more user enumeration with the `-U` option and share enumeration for that user with the `-S` option 
	+ `enum4linux -u <USER> -p <PASSWORD> -U <IP>` and `enum4linux -u <USER> -p <PASSWORD> -S <IP>`

### SMTP Enumeration 
Can gather information about a host or network from vulnerable mail servers
+ The Simple Mail Transport Protocol (**SMTP**) supports several interesting commands such as _VRFY_ and _EXPN_:
	+ A **VRFY** request asks the server to verify an email address
	+ **EXPN** asks the server for the membership of a mailing list
+ These can often be abused to verify existing users on a mail server, which is useful information during a penetration test
#### Netcat SMTP Enumeration
Example with netcat (using `nc -nv <IP> <PORT>` for basic port connection):
```
nc -nv 192.168.50.8 25
```
+ Interaction:
```
(UNKNOWN) [192.168.50.8] 25 (smtp) open
220 mail ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
VRFY idontexist
550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local recipient table
```
+ Observed how the success and error messages differ
+ The SMTP server readily verifies that the user exists, This procedure can be used to help guess valid usernames in an automated fashion

#### Python SMTP Enumeration
Next, let's consider the following Python script, which opens a TCP socket, connects to the SMTP server, and issues a VRFY command for a given username:
``` Python
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
        print("Usage: vrfy.py <username> <target_ip>")
        sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))

# Receive the banner
banner = s.recv(1024)

print(banner)

# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)

print(result)

# Close the socket
s.close()
```
+ We can run the script by providing the username to be tested as a first argument and the target IP as a second argument:
``` 
kali@kali:~/Desktop$ python3 smtp.py root 192.168.50.8
b'220 mail ESMTP Postfix (Ubuntu)\r\n'
b'252 2.0.0 root\r\n'


kali@kali:~/Desktop$ python3 smtp.py johndoe 192.168.50.8
b'220 mail ESMTP Postfix (Ubuntu)\r\n'
b'550 5.1.1 <johndoe>: Recipient address rejected: User unknown in local recipient table\r\n'
```

#### SMTP Enumeration with Windows
Can obtain SMTP information about our target from the Windows 11 client, as we did previously using <mark style="background: #ADCCFFA6;">PowerShell</mark> `Test-NetConnection`
+ Usage: `Test-NetConnection -Port 25 <IP>`

Can not fully interact without the telnet client on Microsoft:
+ Enable Telnet client with: `dism /online /Enable-Feature /FeatureName:TelnetClient`
	+ **Note**: Installing Telnet requires administrative privileges, which could present challenges if we are running as a low-privilege user
		+ However, we could grab the **Telnet binary** located on another development machine of ours at `c:\windows\system32\telnet.exe` and transfer it to the Windows machine we are testing from
+ Once we have enabled Telnet on the testing machine, we can connect to the target machine and perform enumeration as we did from Kali:
```
telnet <IP> 25
```
+ Example output:
```
220 mail ESMTP Postfix (Ubuntu)
VRFY goofy
550 5.1.1 <goofy>: Recipient address rejected: User unknown in local recipient table
VRFY root
252 2.0.0 root
```

### SNMP Enumeration
Over the years, we have often found that the _Simple Network Management Protocol_ (SNMP) is not well-understood by many network administrators
+ This often results in SNMP misconfigurations, which can result in significant information leaks
+ Runs on UDP port 161

SNMP is based on **UDP**, a simple, *stateless* protocol, so it is susceptible to IP **spoofing** and **reply attacks** 
+ Additionally, the commonly used SNMP protocols 1, 2, and 2c offer no traffic encryption
	+ Meaning that SNMP information and credentials can be easily intercepted over a local network
+ Traditional SNMP protocols also have weak authentication schemes and are commonly left configured with default public and private community strings
+ Because all of the above applies to a protocol that is, by definition, meant to "Manage the Network," SNMP is another usefull enumeration protocols

Until recently, SNMPv3, which provides authentication and encryption, has been shipped to support only **DES-56**, proven to be a *weak* encryption scheme that can be easily brute-forced. A more recent SNMPv3 implementation supports the **AES-256** encryption scheme

#### SNMP Management Information Base (MIB) 
The SNMP _Management Information Base_ (MIB) is a database containing information usually related to network management
+ The database is organized like a tree, with **branches** that represent different organizations or network functions 
+ The **leaves** of the tree (endpoints) correspond to specific variable values that can be accessed and probed by an external user 
+ Information about the MIB tree can be seen on the IBM Knowledge Center: https://www.ibm.com/docs/en/aix/7.1?topic=management-information-base

See Windows SNMP MIB values:

|                        |                  |
| ---------------------- | ---------------- |
| 1.3.6.1.2.1.25.1.6.0   | System Processes |
| 1.3.6.1.2.1.25.4.2.1.2 | Running Programs |
| 1.3.6.1.2.1.25.4.2.1.4 | Processes Path   |
| 1.3.6.1.2.1.25.2.3.1.4 | Storage Units    |
| 1.3.6.1.2.1.25.6.3.1.2 | Software Name    |
| 1.3.6.1.4.1.77.1.2.25  | User Accounts    |
| 1.3.6.1.2.1.6.13.1.3   | TCP Local Ports  |

#### SNMP scan with Nmap
To scan for open SNMP ports, we can run **nmap**, using the `-sU` option to perform UDP scanning and the `--open` option to limit the output and display only open ports
```
sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
```
+ Output:
```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-14 06:02 EDT
Nmap scan report for 192.168.50.151
Host is up (0.10s latency).

PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
...
```

#### SNMP community screen bruteforce with Nmap
```
sudo nmap -sU -p161 --script snmp-brute <IP> --script-args snmp-brute.communitiesdb=<COMMUNITY-STRING-LIST>
```

#### SNMP Enumeration Tools 

##### onesixtyone
Tool such as _onesixtyone_, which will attempt a brute force attack against a list of IP addresses
+ Will have to build text files containing community strings and the IP address we wish to scan: 
```
kali@kali:~$ echo public > community
kali@kali:~$ echo private >> community
kali@kali:~$ echo manager >> community

kali@kali:~$ for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
```
+ Command with lists created:
```
onesixtyone -c community -i ips
```
+ output: 
```
Scanning 254 hosts, 3 communities
192.168.50.151 [public] Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
...
```
+ Once a SNMP service is found, can start querying for specific MIB data that might be interesting 
##### snmpwalk
Can probe and query SNMP values using a tool such as _snmpwalk_, provided we know the SNMP read-only community string, which in most cases is "public"
+ Can use the MIB values in the above table for Windows to attempt to enumerate their corresponding values 

The following command enumerates the entire MIB tree using the `-c` option to specify the community string, and `-v` to specify the SNMP version number as well as the `-t` option to specific the timeout period, in this case as 10 
+ Usage: `snmpwalk -c <COMMUNITY_STRING> -v<VERSION_NUMBER> -t <TIMEOUT> <IP>`
	+ **Note**: Should use the `-Og` option translate an Hex Numbers into strings 
	+ Example: `snmpwalk -c public -v1 -t 10 192.168.50.151`
	+ Example output:
```
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.3
iso.3.6.1.2.1.1.3.0 = Timeticks: (78235) 0:13:02.35
iso.3.6.1.2.1.1.4.0 = STRING: "admin@megacorptwo.com"
iso.3.6.1.2.1.1.5.0 = STRING: "dc01.megacorptwo.com"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 79
iso.3.6.1.2.1.2.1.0 = INTEGER: 24
...
```
+ Can use the output to obtain target email addresses 
	+ This information can be used to craft a social engineering attack

Can also parse a specific branch of the MIB called OID (**object identifiers**):

The following command enumerates the **Windows users** on a machine
+ Usage: `snmpwalk -c <COMMUNITY_STRING> -v<VERSION_NUMBER> <IP> 1.3.6.1.4.1.77.1.2.25`
	+ Example: `snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25`
	+ Example output:
```
iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.6.107.114.98.116.103.116 = STRING: "krbtgt"
iso.3.6.1.4.1.77.1.2.25.1.1.7.115.116.117.100.101.110.116 = STRING: "student"
iso.3.6.1.4.1.77.1.2.25.1.1.13.65.100.109.105.110.105.115.116.114.97.116.111.114 = STRING: "Administrator"
```

The following command enumerates all the **currently running processes**:
+ Usage: `snmpwalk -c <COMMUNITY_STRING> -v<VERSION_NUMBER> <IP> 1.3.6.1.2.1.25.4.2.1.2`
	+ Example: `snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2`
	+ Example output: 
```
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "System Idle Process"
iso.3.6.1.2.1.25.4.2.1.2.4 = STRING: "System"
iso.3.6.1.2.1.25.4.2.1.2.88 = STRING: "Registry"
iso.3.6.1.2.1.25.4.2.1.2.260 = STRING: "smss.exe"
iso.3.6.1.2.1.25.4.2.1.2.316 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.372 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.472 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.476 = STRING: "wininit.exe"
iso.3.6.1.2.1.25.4.2.1.2.484 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.540 = STRING: "winlogon.exe"
iso.3.6.1.2.1.25.4.2.1.2.616 = STRING: "services.exe"
iso.3.6.1.2.1.25.4.2.1.2.632 = STRING: "lsass.exe"
iso.3.6.1.2.1.25.4.2.1.2.680 = STRING: "svchost.exe"
...
```
+ The command returned an array of strings, each one containing the name of the running process. This information could be valuable as it might reveal vulnerable applications, or even indicate which kind of **anti-virus** is running on the target

Query all the **software that is installed on the machine**:
+ Usage: `snmpwalk -c <COMMUNITY_STRING> -v<VERSION_NUMBER> <IP> 1.3.6.1.2.1.25.6.3.1.2`
	+ Example: `snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.6.3.1.2`
	+ Example output:
```
iso.3.6.1.2.1.25.6.3.1.2.1 = STRING: "Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.2 = STRING: "VMware Tools"
iso.3.6.1.2.1.25.6.3.1.2.3 = STRING: "Microsoft Visual C++ 2019 X64 Additional Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.4 = STRING: "Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.27.290"
iso.3.6.1.2.1.25.6.3.1.2.5 = STRING: "Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.27.290"
iso.3.6.1.2.1.25.6.3.1.2.6 = STRING: "Microsoft Visual C++ 2019 X86 Additional Runtime - 14.27.29016"
iso.3.6.1.2.1.25.6.3.1.2.7 = STRING: "Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.27.29016"
...
```
+ When combined with the running process list we obtained earlier, this information can become extremely valuable for cross-checking the exact software version a process is running on the target host

Another SNMP enumeration technique is to list all the **current TCP listening ports**:
+ Usage: `snmpwalk -c <COMMUNITY_STRING> -v<VERSION_NUMBER> <IP> 1.3.6.1.2.1.6.13.1.3`
	+ Example: `snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3`
	+ Example output:
```
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.88.0.0.0.0.0 = INTEGER: 88
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.135.0.0.0.0.0 = INTEGER: 135
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.389.0.0.0.0.0 = INTEGER: 389
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.445.0.0.0.0.0 = INTEGER: 445
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.464.0.0.0.0.0 = INTEGER: 464
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.593.0.0.0.0.0 = INTEGER: 593
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.636.0.0.0.0.0 = INTEGER: 636
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3268.0.0.0.0.0 = INTEGER: 3268
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3269.0.0.0.0.0 = INTEGER: 3269
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5357.0.0.0.0.0 = INTEGER: 5357
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5985.0.0.0.0.0 = INTEGER: 5985
...
```
+ The integer value from the output above represents the current listening TCP ports on the target. This information can be extremely useful as it can disclose ports that are listening only locally and thus reveal a new service that had been previously unknown