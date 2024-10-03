# General Course Overview 

Module exercises are implemented that allow us to use the same remote UP and port multiple times 
+ On the Module Exercise VMs that require an SSH connection, we suggest issuing the SSH command with a couple of extra options as follows:
```
ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@192.168.50.52
```
+ The _UserKnownHostsFile=/dev/null_ and _StrictHostKeyChecking=no_ options have been added to prevent the **known-hosts** file on our local Kali machine from being corrupted

Discord, our community chat platform, can be accessed via the Profile drop-down at the upper right hand corner of the OffSec Learning Portal
## Lab Environment 
combination of the following components:
- Your Kali Linux VM
- The OffSec Learning Portal
- A lab containing deployable target machines
- A VPN connection between your Kali VM and the lab

Connect to the VPN via:
```
sudo openvpn pen200.ovpn
```
+ Once opened, will have a TUN0 network interface, with an IP address as follows: 

`192.168.119.X`, where `X` is some value between 1 and 255. Every time we reconnect to the VPN, we might get assigned a different value for `X`.
+ In addition, all lab machines within the PWK environment will have addresses that follow the format `192.168.X.Y`, where `X` is the same value as the third octet of our TUN0 address, and `Y` is the specific octet associated with the machine.

## How to Approach the Course
Penetration testing - and information security in general - is fundamentally about *reasoning under uncertainty*
+ Penetration testing is closer to poker than chess, you don't know what your opponent knows, and you have to make predictions based on incomplete data 
+ The only reason why hacking a machine takes any time at all is because there are things about it that we don't know
	+ In a majority of cases, if we knew everything there was to know about a -specific target ahead of time, then we would already know the precise few commands or lines of code necessary to compromise it

Can think of this course as teaching two sets of different skills at the same time:
+ one relating to *penetration testing technique*, and one relating to *methodology*, *approach*, and *attitude*.

PWK contains seven learning modalities:
1. Learning Modules
2. Demonstration Module Exercises
3. Application Module Exercises
4. Capstone Module Exercises
5. The Assembling the Pieces Module
6. Challenge Labs (type one)
7. Challenge Labs (type two)

### Learning Module
the text-based Learning Modules all cover specific penetration testing concepts, techniques, and skills. They are each approximately between 30 and 50 pages in length, and they are accompanied by videos that go over the same concepts in a visual and interactive manner. They are logically ordered in a way that allows for progressively building on top of previously learned skills
+ we encourage you to start the relevant lab machines and follow along by typing the commands and clicking around in the same manner as demonstrated. This helps you internalize the material

### Demonstration Module 
This type of exercise asks the learner to either input some factual, knowledge based answer to the question, or to obtain a randomized flag by copying the exact some commands and input shown in the course material
+ The amount of uncertainty here is still very low, because the learner can obtain the solution directly by reading or watching the Module

### Applied Module Exercises
Here we start to slowly increase the amount of uncertainty. Instead of the learner needing to copy _exactly_ the same steps, the learner now must apply their skills in novel but limited scenarios

### Capstone Module Exercises
While demonstration and application exercises are constrained to specific Learning Units, Capstone Exercises have a wider scope. In particular they encompass the entire Module. This increases the amount of uncertainty present, because the learner may not know which techniques or concepts from the module are specifically required to complete the exercise

### Assembling the Pieces
There are 20 Modules in PWK (aside from this introduction and the final module) and for each of them the learner will go through the process of:
1. Reading and watching the Module and preferably following along
2. Completing the Demonstration exercises by copying the input
3. Working through the Application exercises by using specific techniques
4. Attacking machines from start to finish via the Capstone Exercises

At this point, learners will be just about ready for the Challenge Labs. The Assembling the Pieces Module represents a bridge between the Modules and the Labs. It provides a full walkthrough of a small penetration test and allows the learner to follow along with all demonstrated steps. In a sense, this Module is the equivalent of a demonstration exercise for the entire set of Challenge Labs.

### Challenge Labs 1-3
There are two types of Challenge Labs. The first three are called _scenarios_. Each scenario consists of a set of networked machines and a short background story that puts those machines in context. Your goal is to obtain access to a Domain Administrator account on an Active Directory domain, and compromise as many machines on the network as possible.

In the same way that Capstone Exercises test the learner on the material of multiple Learning Units, so too do these scenarios test the learner on the material of multiple Learning Modules. The uncertainty here is high, because you will not know which machines are vulnerable to what types of attacks. In addition, each of the three Challenge Labs progressively increase in complexity due to additional machines, subnetworks, and attack vectors.

Further, you will not know that any _specific_ machine is directly vulnerable in the first place. Some machines will be dependent on information, credentials, or capabilities that will be found on other machines. And some machines may not even be (intentionally) exploitable until after the Domain Controller is compromised.

All machines contain either a **local.txt** file, a **proof.txt** file, or both. The contents of these files are randomized hashes that can be submitted to the OLP to log each compromise. Just like the Module exercise flags, the contents of these files will change on every revert of the machine. We'll discuss more details related to these scenarios in the final Module of PWK.

### Challenge Labs 4-6
The second type of Challenge Lab consists of an OSCP-like experience. They are each composed of six OSCP machines. The intention of these Challenges is to provide a mock-exam experience that closely reflects a similar level of difficulty to that of the actual OSCP exam.

Each challenge contains three machines that are connected via Active Directory, and three standalone machines that do not have any dependencies or intranet connections. All the standalone machines have a **local.txt** and a **proof.txt**.

While the Challenge Labs have no point values, on the exam the standalone machines would be worth 20 points each for a total of 60 points. The Active Directory set is worth 40 points all together, and the entire domain must be compromised to achieve any points for it at all.

All the intended attack vectors for these machines are taught in the PEN-200 Modules, or are leveraged in the first three Challenge Labs. However, the specific requirements to trigger the vulnerabilities may differ from the exact scenarios and techniques demonstrated in the course material. You are expected to be able to take the demonstrated exploitation techniques and modify them for the specific environment.

Also included with your initial purchase of the PWK course is an attempt at the _OSCP certification exam_[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/penetration-testing-with-kali-linux-general-course-information/how-to-approach-the-course/challenge-labs-4-6#fn1) itself. The exam is optional, so it is up to you to decide whether or not you would like to tackle it.

To schedule your OSCP exam, go to your exam scheduling calendar. The calendar can be located in the OffSec Learning Portal under the course exam page. Here you will find your exam expiry date, as well as schedule the exam for your preferred date and time.

Keep in mind that you won't be able to select a start time if the exam labs are full for that time period so we encourage you to schedule your exam as soon as possible.

## Summary of modules

### Optional Ramp-up Modules
We begin with three optional Modules from our Fundamentals series. These Modules are included in PWK for those learners who desire a softer start to their PWK learning journey.

_Introduction to Cybersecurity_ provides a broad survey on the current state of the world of Cybersecurity. It covers how Cybersecurity is practiced as a discipline and what kinds of threats and threat actors exist. It also covers security principles, controls and strategies, Cybersecurity laws, regulations and frameworks, and career opportunities within the industry.

_Effective Learning Strategies_ is a practical introduction to learning theory that explains OffSec's unique approach to teaching. This module begins with an overview of how learning happens and then explores the construction of OffSec materials. The second half of the module is immediately applicable for learners and includes tactics, strategies, and specific, practical steps.

Finally, we continue with a Module on _Report Writing for Penetration Testers_. This Module provides a framework, some advice, and some tips on writing notes as you progress through a penetration test. It also covers how you might think about writing a penetration testing report. The OSCP exam requires each learner to submit a report of their exam penetration test, so it is recommend to practice your note taking and report writing skills as you proceed with the Module exercises and Challenge Lab machines.

### Enumeration and Information Gathering 
We then dive into PWK proper, starting with one of the most important aspects of penetration testing: _Information Gathering_. Often called by its synonym _enumeration_, the vast majority of one's time during a penetration test is spent on information gathering of one form or another. However, this Module is specifically about how to approach a network at the very outset of an engagement.

We extend our information gathering toolkit by exploring the concept of _Vulnerability Scanning_.[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/penetration-testing-with-kali-linux-general-course-information/summary-of-pwk-learning-modules/enumeration-and-information-gathering#fn1) Vulnerability scanning offers us several techniques to narrow our scope within a particular network. It helps us identify machines that are especially likely to be vulnerable. Attack vectors on such machines are often colloquially called _low-hanging fruit_, as the imagery of reaching up to take the easy pieces of fruit off a tree is particularly powerful.

### Web Application and Client Side Attacks 
_Perimeter attacks_. By perimeter attacks, we mean methods of infiltration that can be reliably done from the internet. In other words, attacks that can be initiated without any sort of access to an organization's internal network.

We begin with an extensive exploration of Web Application attacks. There are two primary reasons for starting here. The first is that Web vulnerabilities are among the most common attacks vectors available to us, since modern web apps usually allow users to submit data to them. The second is that web applications are inherently visual and therefore provide us with a nice interface for understanding why our attacks work in the way that they do

_Introduction to Web Applications_ begins by covering a methodology, a toolset, and an enumeration framework related to web applications that will help us throughout the course. It then covers our first vulnerability class: _Cross-Site Scripting_ (XSS).[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/penetration-testing-with-kali-linux-general-course-information/summary-of-pwk-learning-modules/web-application-and-client-side-attacks#fn1) XSS is an excellent vulnerability to start with because it targets the _user_ of a web application as opposed to the server running it. Since the vast majority of our regular day-to-day usage of web applications is as normal users, XSS can be unusually intuitive, compared to other types of attacks.

We continue our exploration of web application attacks in _Common Web Application Attacks_, where we survey four different kinds of vulnerabilities. _Directory Traversal_[2](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/penetration-testing-with-kali-linux-general-course-information/summary-of-pwk-learning-modules/web-application-and-client-side-attacks#fn2) provides us with an example of how we can obtain access to information that we're not supposed to. _File Inclusion_ shows us what can happen when certain configurations are not set up judiciously by a web administrator. _File Upload Vulnerabilities_[3](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/penetration-testing-with-kali-linux-general-course-information/summary-of-pwk-learning-modules/web-application-and-client-side-attacks#fn3) demonstrate how we can take advantage of the ability to upload our own files to a web server. Finally, _Command Injection_[4](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/penetration-testing-with-kali-linux-general-course-information/summary-of-pwk-learning-modules/web-application-and-client-side-attacks#fn4) allows us to run code of our choice on the web server itself

Our examination of web-based attacks concludes with a dedicated Module on _SQL Injection_, otherwise known as _SQLi_.[5](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/penetration-testing-with-kali-linux-general-course-information/summary-of-pwk-learning-modules/web-application-and-client-side-attacks#fn5) This vulnerability class is particularly important not only because of how common it is, but because it teaches us how weaknesses can arise in a system due to multiple components interacting with each other in complex ways. In the case of SQLi, a web server and a database need to both be set up in precise ways so that we as attackers cannot abuse them

_Client-Side Attacks_ are another very common external class of attacks. They generally deal with methods of taking advantage of human users of computer systems. In this Module, we'll learn how to perform reconnaissance on a system, attack users of common programs like Microsoft Office, and even how to abuse Microsoft Library Files

### Other Perimeter Attacks 
It is relatively common to encounter various types of external-facing services on a penetration test that are vulnerable to different kinds of attacks. However, as penetration testers we will rarely have time to write our own exploits from scratch in the middle of an engagement.

Luckily, there are several ways in which we can benefit from the experience of the information security community. _Locating Public Exploits_ will portray several different means of working with exploits that are available on Kali Linux and _on the internet_.[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/penetration-testing-with-kali-linux-general-course-information/summary-of-pwk-learning-modules/other-perimeter-attacks#fn1) Then, _Fixing Exploits_ will help us adapt these exploits to suit our specific needs

We then explore the very surface of a very exciting subject: _Anti Virus Evasion_. While _Anti Virus_ (AV) evasion isn't itself a perimeter attack, having some knowledge of how to avoid AV will be helpful since most modern day enterprises do deploy AV solutions

Finally, we complete our review of perimeter attacks with an analysis of cryptography and _Password Attacks_. Weak or predictable passwords are extremely common in most organizations. This Module covers how to attack network services and how to obtain and crack various kinds of credentials

### Privilege Escalation and Lateral Movement 
Once we obtain access to a machine, we suddenly have a whole set of new actions and activities open to us. We may want to increase our _privileges_[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/penetration-testing-with-kali-linux-general-course-information/summary-of-pwk-learning-modules/privilege-escalation-and-lateral-movement#fn1) on the machines so that we can fully control it, or we might want to use it to gain access to other machines on the network

_Windows Privilege Escalation_ demonstrates how after compromising a Windows target, we can use our new legitimate permissions to become an Administrator. We will learn how to gather information, exploit various types of services, and attack different Windows components

Then, _Linux Privilege Escalation_ goes through the same process with Linux targets and obtaining root level permissions. It reinforces the methodology learned in the previous Module and covers Linux-specific techniques

Escalating permissions is instrumentally important on an engagement because doing so gives us more access. But as penetration testers, we always want to ask ourselves what the biggest impact our attacks can have on the network to provide the most value for our clients. Sometimes, it can be even more effective to gain access to another machine owned by the organization. When we move from one machine to another on the same network, we call this _pivoting_,[2](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/penetration-testing-with-kali-linux-general-course-information/summary-of-pwk-learning-modules/privilege-escalation-and-lateral-movement#fn2) and when we move into another subnetwork we call this _tunneling_.[3](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/penetration-testing-with-kali-linux-general-course-information/summary-of-pwk-learning-modules/privilege-escalation-and-lateral-movement#fn3) _Port Redirection and SSH Tunneling_ covers the basics of these persistence skills, while _Tunneling through Deep Packet Inspection_ showcases a particular technique that can be used to evade a common network-layer defense

We wrap up this portion of the course with an exploration of _The Metasploit Framework_ (MSF).[4](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/penetration-testing-with-kali-linux-general-course-information/summary-of-pwk-learning-modules/privilege-escalation-and-lateral-movement#fn4) MSF is a powerful set of tools that help us automate many of the enumeration and exploitation steps we've learned so far

### Active Directory 
_Active Directory_[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/penetration-testing-with-kali-linux-general-course-information/summary-of-pwk-learning-modules/active-directory#fn1) is one of the most complex and important technologies for us to learn as penetration testers because it is ubiquitous in today's enterprise environment. PWK dedicates three Modules to this area: _Active Directory Introduction and Enumeration_ paints a picture of how to think specifically about Windows machines in the context of an Active Directory domain. We will learn how to gather information and set ourselves up to more thoroughly compromise a network.

Then, _Attacking Active Directory Authentication_ provides us with several techniques to increase our presence within the network by attacking or bypassing authentication protocols. Finally, _Lateral Movement in Active Directory_ helps us understand how to apply many of the pivoting concepts we've previously learned in complex AD environments

### Challenge Lab Preparation 
The final two PWK Modules represent a bridge between the text, video, and exercise based learning modalities and the Challenge Labs themselves. By this point the learner will have completed over 300 exercises, including the compromise of approximately 25 machines. Now it's time to put it all together. In _Assembling the Pieces_, we walk the learner through a simulated penetration test of five machines. Techniques from _Information Gathering_ all the way through _Lateral Movement in Active Directory_ are required to successfully compromise the domain. Learners will be able to follow along and see exactly how we think about targeting a new environment from start to finish.

Finally, _Trying Harder: The Challenge Labs_ provides a set of instructions and some further detail on the Challenge Labs. We highly recommend completing all the Modules including _Assembling the Pieces_ before beginning with the Challenge Labs!

# Introduction to Cybersecurity 

## The Practice of Cybersecurity 

### Challenges in Cybersecurity 
Cybersecurity is a unique discipline, no longer a niche area of software engineering or system administration. There are a few distinct characteristics of cybersecurity that distinguish it from other technical fields 

Security involves **malicious** and **intelligent** actors (opponents)
+ Dealing with them requires a different approach, discipline and mindset compared to facing accidental problems
+ Whether simulating an attack or defending against one, we need to consider the perspective and potential actions of our opponent, and try to anticipate what they might go 
+ The opponents are human beings with **agency**, they can reason, predict, judge, analyze, conjecture, and deliberate. They can also feel emotions like happiness, sorrow, greed, feat, triumph, and guilt 
+ Both attackers and defenders can leverage the motions of their human opponent

An important aspect of security **involves reasoning under uncertainty** 
+ We have deductive skills, by are not omniscient, can not determine everything or remember infinite facts 
+ Need to make assumptions and estimate probabilities, sometimes implicitly and sometimes explicitly 

Understanding Cybersecurity necessitates learning more about how we think as human agents, and how to solve problems 
+ Need to adopt and nurture specific mindsets that will help us as we learn and apply skills 

### A Word on Mindsets
Should understand your own mind and that of your adversary, we tend to think of a mindset as a set of beliefs the inform out personal perspective on something 
+ Should have a growth mindset, that encourages the belief that mental ability is flexible and adaptable, and that one can grow their capacity to learn over time 
+ Another mindset is the **security mindset**, proposed by Bruce Schneier, which is the mindset that encourages a constant question of how one can attack a system 
+ In Offsec, they encourage the **Try Harder mindset**, which represent the following perspectives in a moment of failure:
	+ If my attack or defense fails, it represents a truth about my current skills/processes/configurations/approach as much as it is a truth about the system
	+ If my attack or defense fails, this allows me to learn something new, change my approach, and do something differently
+ Those two perspectives help provide someone with the mental fortitude to make mistakes and learn from them 

### On Emulating the Minds of our Opponents 
The more we learn about a would be attacker, the more we can think **like an attacker** 
+ A pentest is where the penetration tester takes the role of an attacker to understand the systems vulnerabilities and exposed weaknesses 
+ Leveraging the skill-sets and mindsets of an attacker allows to to better answer questions like "How might an attacker gain access?", "What can they do with that access?", and "What are the worst possible outcomes from an attacker?"

## Threats and Threat Actors 

### The Evolution of Attack and Defense 
Cybersecurity contains multiples agents, one defending an asset and one attacking an asset
+ The subsist on the persistence of the other 
+ They become more skilled and sophisticated because of the efforts (or imagined efforts) of their counterpart

### Risks, Threats, Vulnerabilities, and Exploits 

#### Risk 
Risk is to consider two axes: the probability that a negative event will occur, and the impact on something we value if such an event happens 
+ This allows use to conceptualize risk via four quadrants:
1. Low probability, low impact events 
2. Low probability, high impact events 
3. High probability, low impact events 
4. High probability, high impact events 

Should examine the questions "How likely is it that a particular attack might happen?" and "What would be the worst possible outcome if the attack occurs?"

#### Threat 
When we can attribute a specific risk to a particular cause, we're describing a _threat_
+ In cybersecurity, a threat is something that poses risk to an asset we care about protecting
+ Not all threats are human; if our network depends on the local electricity grid, a severe lightning storm could be a threat to ongoing system operations
+  person or group of people embodying a threat is known as a _threat actor_ a term signifying agency, motivation, and intelligence

#### Vulnerability 
For a threat to become an actual risk, the target being threatened must be _vulnerable_ in some manner
+ A vulnerability is a flaw that allows a threat to cause harm
+ Flaws aren't always vulnerabilities if they don't pose any risk of damage

For example: in December 2021  vulnerability was discovered in the _Apache Log4J_ library, a popular Java-based logging library
+ This vulnerability could lead to arbitrary code execution by taking advantage of a _JNDI Java toolkit_ feature which, by default, allowed for download requests to enrich logging
+ If a valid Java file was downloaded, this program would be executed by the server. This means that if user-supplied input (such as a username or HTTP header) was improperly sanitized before being logged, it was possible to make the server download a malicious Java file that would allow a remote, unauthorized user to execute commands on the server
+ Due to the popularity of the Log4j library, this vulnerability was given the highest possible rating under the _Common Vulnerability Scoring System_ (CVSS) used to score vulnerabilities: 10.0 Critical
+ This rating led to a frenzied aftermath including vendors, companies, and individuals scrambling to identify and patch vulnerable systems as well as search for indications of compromise
+ Additional Log4J vulnerabilities were discovered soon after, exacerbating matters
+ This vulnerability could have been **prevented** by ensuring that user-supplied data is properly _sanitized_
+ The issue could have been **mitigated** by ensuring that potentially dangerous features (such as allowing web-requests and code execution) were disabled by default


#### Exploits 
In computer programs, vulnerabilities occur when someone who interacts with the program can achieve specific objectives that are unintended by the programmer
+ When these objectives provide the user with access or privileges that they aren't supposed to have, and when they are pursued deliberately and maliciously, the user's actions become an _exploit_
+ The word _exploit_ in cybersecurity can be used as both a noun and as a verb. As a noun, an exploit is a procedure for abusing a particular vulnerability. As a verb, to exploit a vulnerability is to perform the procedure that reliably abuses it

#### Attack Surface 
describes all the points of contact on our system or network that _could_ be vulnerable to exploitation
+ Defenders attempt to reduce their attack surfaces as much as possible

#### Attack Vector 
is a specific vulnerability and exploitation combination that can further a threat actor's objectives
+ Attackers try to probe a given attack surface to locate promising attack vectors

### Threat Actor Classification 
Cybersecurity professionals are chiefly interested in threat actors since typically, most threats that our systems, networks, and enterprises are vulnerable to are human
+ Some key attributes of cybercrime compared to physical crime include its relative anonymity, the ability to execute attacks at a distance, and (typically) a lack of physical danger and monetary cost

There are a wide variety of threat actors
+ Different people and groups have various levels of technical sophistication, different resources, personal motivations, and a variety of legal and moral systems guiding their behavior
+ While we cannot list out every kind of threat actor, there are several high-level classifications to keep in mind

**Individual Malicious Actors**: On the most superficial level, anyone attempting to do something that they are not supposed to do fits into this category
+ In cybersecurity, malicious actors can explore _digital_ tactics that are unintended by developers, such as authenticating to restricted services, stealing credentials, and defacing websites
+ _Paige Thompson_ was an example of an individual attacker that can cause extreme amounts of damage and loss 
	+ In July 2019, Thompson was arrested for exploiting a router which had unnecessarily high privileges to download the private information of 100 million people from Capital One
	+ This attack lead to the loss of personal information including SSNs, account numbers, addresses, phone numbers, email addresses, etc
	+ This attack was partly enabled by a misconfigured _Web Application Firewall_ (WAF) that had excessive permissions allowing it to list and read files
	+ The attack could have been _prevented_ by applying the principle of least privilege and verifying correct configuration of the WAF
	+ Since the attacker posted about their actions on social media, another mitigation could have been social media monitoring

**Malicious Groups**: When individuals band together to form groups, they often become stronger than their individual group members
+ This can be even more true online because the ability to communicate instantly and at vast distances enables people to achieve goals that would have been impossible without such powerful communication tools
+ For example, the ability to quickly coordinate on who-does-what over a instant messaging services is just as valuable to malicious cyber groups as it is to modern businesses
+ they are often considered to be one of the more dangerous threat actors
+ For example: Over the span of a number of months, the _"Lapsus$"_ group performed a number of attacks on a wide range of companies, stealing proprietary information and engaging in extortion
	+ These attacks resulted in a loss of corporate data - including proprietary data such as source code, schematics, and other documentation
	+ The attacks further resulted in the public exposure of data, and financial losses for companies that submitted to extortion
+ Individuals within a group can bring their own specialties to the table that people working alone wouldn't be able to leverage
+ In addition, they can launch many different types of attacks at targets at a volume and velocity that an individual wouldn't be able to
+ There's a common truism in the cybersecurity industry that the attacker only needs to succeed once, while the defender must succeed every time
+ The efficacy of groups of attackers highlights this asymmetry
+ Should be focusing on security best practices such as MFA, access control, and network segmentation

**Insider Threats**: Perhaps one of the most dangerous types of threat actor, an insider threat is anyone who already has privileged access to a system and can abuse their privileges to attack
+ Often, insider threats are individuals or groups of employees or ex-employees of an enterprise that become motivated to harm it in some capacity
+ Insider threats can be so treacherous because they are usually assumed to have a certain level of trust
+ That trust can be exploited to gain further access to resources, or these actors may simply have access to internal knowledge that isn't meant to be public
+ At the beginning of the COVID-19 pandemic, Christopher Dobbins, who had just been fired as Vice President of a medical packaging company, used a fake account that he had created during his employment to access company systems and change/delete data that was critical to the company's distribution of medical supplies
	+ This delayed delivery of critical medical supplies at a crucial stage of the pandemic and the disruption of the company's broader shipment operations
	+ The attack was enabled by a fake account created by a vice-president, who may have had access to more permissions than what might be considered best practice for a VP of Finance
	+ This attack likely could have been prevented by applying the _principle of least privilege_

**Nation States**: Although international cyber politics, cyber war, and digital intelligence are vast subjects and significantly beyond the scope of this Module, we should recognize that some of the most proficient, resourceful, and well-financed operators of cyber attacks exist at the nation-state level within many different countries across the globe
+ Since 2009, North Korean threat actors, usually grouped under the name _Lazarus_, have engaged in a number of different attacks ranging from data theft (Sony, 2014), to ransomware (WannaCry, 2017) to financial theft targeting banks (Bangladesh Bank, 2016) and cryptocurrencies - notably, the 2022 Axie Infinity attack. These attacks have resulted in the loss and leak of corporate data, including proprietary data (Sony) and financial losses for companies that paid a ransom
+ An information assurance firm called _NCC Group_ suggests the following steps to prevent or mitigate attacks from the Lazarus group: network segmentation, patching and updating internet facing resources, ensuring the correct implementation of MFA, monitoring for anomalous user behavior (example: multiple, concurrent sessions from different locations), ensuring sufficient logging, and log analysis

### Recent Cybersecurity Breaches
**Social Engineering**: Social Engineering represents a broad class of attacks where an attacker persuades or manipulates human victims to provide them with information or access that they shouldn't have.
+ In July 2021, attackers used a social engineering technique called _spearphishing_ to _gain access to_ an internal _Twitter_ tool that allowed them to reset the passwords of a number of high-profile accounts
+ They used these accounts to tweet promotions of a Bitcoin scam
+ The impacts of this attack included financial losses for specific Twitter users, data exposure for a number of high-profile accounts, and repetitional damage to Twitter itself
+ The attack began with phone spearphishing and social engineering, which allowed attackers to obtain employee credentials and access to Twitter's internal network
+ This could have been prevented had employees been better equipped to recognize social engineering and spearphishing attacks
+ Additional protections that could have prevented or mitigated this attack include limiting access to sensitive internal tools using the principle of least privilege and increased monitoring for anomalous user activity

**Phishing**: Phishing is a more general class of attack relative to spearphishing. While spearphishing attacks are targeted to specific individuals, phishing is usually done in broad sweeps. Phishing strategy is usually to try to send a malicious communication to as many people as possible, inreasing the likelihood of a victim clicking a link or otherwise doing something that would compromise security
+ In September 2021, a subsidiary of Toyota acknowledged that they had fallen prey to a Business Email Compromise _(BEC)_ phishing scam
+ The scam resulted in a transfer of ¥ 4 billion (JPY), equivalent to roughly 37 million USD, to the scammer's account
+ This attack occurred because an employee was persuaded to change account information associated with a series of payments
+ The United States Federal Bureau of Investigation _(FBI)_ recommends these and other steps be taken to prevent BEC
	- Verify the legitimacy of any request for payment, purchase or changes to account information or payment policies in person.
	- If this is not possible, verify legitimacy over the phone.
	- Be wary of requests that indicate urgency.
	- Carefully inspect email addresses and URLs in email communications.
	- Do not open email attachments from people that you do not know.
	- Carefully inspect the email address of the sender before responding.

**Ransomware**: Ransomware is a type of malware that infects computer systems and then locks a legitimate user from accessing it properly. Often, users are contacted by the attacker and asked for a ransom in order to unlock their machine or documents
+ In May 2021, a ransomware _incident_ occurred at Colonial Pipeline, a major American oil company
+ The attack lead to the disruption of fuel distribution for multiple days
+ This attack resulted in a loss of corporate data, the halting of fuel distribution, millions of dollars in ransomware payments, increased fuel prices, and fuel shortage fears
+ In this attack, hackers gained access to Colonial Pipeline's network with a single compromised password
+ This attack could have been prevented or at least made less likely by ensuring that MFA was enabled on all internet-facing resources, as well as by prohibiting password reuse

**Credential Abuse**: Credential Abuse can occur when an attacker acquires legitimate credentials, allowing them to log into machines or services that they otherwise would not be able to. Often, attackers are able to guess user passwords because they are predictable or weak.
+ In _December 2020_, a series of malicious updates had been discovered in the SolarWinds Orion platform, an infrastructure monitoring and management tool
+ These malicious updates allowed malware to be installed on the environment of any SolarWinds customer that installed this update and led to the compromise of a number of these customers, including universities, US government agencies, and other major organizations
+ As a supply-chain attack, this attack affected approximately 18,000 SolarWinds customers and led to the breach of a subset of customers including government agencies and other major companies
+ According to former SolarWinds CEO Kevin Thompson, this attack resulted from a _weak password_ that was accidentally exposed publicly on Github
+ This attack could have been prevented by ensuring that passwords are sufficiently strong and by monitoring the internet for leaked secrets
+ CISA has also stated that this attack could have been mitigated by blocking outbound internet traffic from SolarWinds Orion servers

**Authentication Bypass**: While Credential Abuse allows attackers to log in to services by legitimate means, Authentication Bypasses can allow attackers to ignore or step-around intended authentication protocols
+ Similar to the above SolarWinds attack, on _July 2 2021_ an attack was detected that took advantage of a vulnerability in software vendor Kaseya's VSA remote management tool
+ Attackers were able to bypass the authentication system of the remote tool to eventually push REvil ransomware from compromised customer Virtual System Administrator (VSA) servers to endpoints via a malicious update
+ Since this attack targeted a number of _Managed Service Providers_ (MSPs), its potential scope encompassed not only the MSP customers of Kaseya, but also the customers of those MSPs
+ According to _Brian Krebs_, this vulnerability had been known about for at least three months before this ransomware incident
+ This attack could have been prevented by prioritizing and fixing known vulnerabilities in an urgent and timely manner

## The CIA Triad
- **Confidentiality**: Can actors who should not have access to the system or information access the system or information?
- **Integrity**: Can the data or the system be modified in some way that is not intended?
- **Availability**: Are the data or the system accessible when and how they are intended to be?
	- A common attack against availability is _denial of service_

### Microsoft Integrity recommendations  
In their advisory, Microsoft recommended that potential targets take the following steps to protect themselves: enable MFA to mitigate potentially compromised credentials, enable _Controlled Folder Access_ (CFA) in Microsoft Defender to prevent MBR/VBR tampering, use provided IoCs to search for potential breaches, review and validate authentication activity for all remote access, and investigate other anomalous activity. More information about the technical details of the attack has been published by _CrowdStrike_.[4](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/introduction-to-cybersecurity/the-cia-triad/integrity#fn4). Put simply, integrity is important for an enterprise to protect because other businesses and consumers need to be able to trust the information held by the enterprise.

## Security Principles, Controls, and Strategies

### Security Principles 
During this Learning Unit, we'll begin to explore a few _security_ _principles_ we might encounter throughout our OffSec Learning Journey

_The Principle of Least Privilege_ expresses the idea that each part within a system should only be granted the lowest possible privileges needed to achieve its task. Whether referring to users on a machine or lines of code in a program, correctly adhering to this discipline can greatly narrow the attack surface

The _Zero Trust_ security model takes the Principle of Least Privilege and carries it to its ultimate conclusion. This model advocates for removing all implicit trust of networks and has a goal of protecting access to resources, often with granular authorization processes for every resource request.

_Open Security_, a somewhat counter-intuitive principle, states that the security of a system should not depend on its _secrecy_. In other words, even if an attacker knows exactly how the system's security is implemented, the attacker should still be thwarted. This isn't to say that _nothing_ should be secret. Credentials are a clear case where the security of a password depends on its secrecy. However, we'd want our system to be secure _even if_ the attacker knows there is a password, and even if they know the cryptographic algorithm behind it.

_Defense in Depth_ advocates for adding defenses to as many layers of a system as possible, so that if one is bypassed, another may still prevent full infiltration. An example of defense in depth outside the context of cybersecurity would be a garage that requires entering an electronic code, using a key on a bolted door lock, then finally disabling a voice-activated internal alarm system to open the garage.

### Security Controls and Strategies 
To meet the ideals of concepts such as least privilege, open security, and defense-in-depth, we need to implement _Security Strategies_. These can include interventions like:
- 24/7 vigilance
- Threat modelling
- Table top discussions
- Continuous training on tactics, processes, and procedures
- Continuous automated patching
- Continuous supply chain verification
- Inventory of all assets within the organization 
- Secure coding and design
- Daily log reviews
- Multiple layers of well-implemented _Security Controls_

### Shift-Left Security
One of the best ways to avoid extra costs and impacts to availability is to design an entire system so that security is built into the service architecture, rather than requiring many additional software layers
+ In order to design systems with built-in security, the idea of _shift-left security_ can improve efficiency
+ The idea of shift-left security is to consider security engineering from the outset when designing a product or system, rather than attempt to bake it in after the product has been built

Most applications do not have security built in and instead rely on platform-level security controls surrounding the services
+ This can work well; however, it can result in security being weaker or easier to bypass. For example, if a specific technology (for example, Kubernetes modules) are providing all of the security services, then someone that controls that technology (in this case, a Kubernetes administrator) could remove or tamper with it and bypass security for all services

However, we once again need to consider business impact. In particular, shifting left can potentially cause slower production times because developers will need to explicitly think about security in addition to the product specifications
+  An organization therefore will need to decide what trade-offs they can make in their particular circumstance

### Administrative Segmentation 
It may seem okay to have an administrator bypass security controls based on their role and functional needs. Shouldn't we trust our administrators? However, when a threat is internal or otherwise able to obtain valid administrative credentials, our security posture becomes weaker
+ In order to defeat internal threats and threats that have acquired valid credentials or authentication capability, we must segment controls so that no single authority can bypass all controls
+ In order to accomplish this, we may need to split controls between application teams and administrators, or split access for administration between multiple administrators, as with _Shamir's Secret Sharing_ (SSS)

With SSS, we might design a system so that three different administrator authorizations are required to authorize any one administrative root access
+ Shamir's secret sharing scheme enables a system to split access authorization requirements between multiple systems or persons
+ With this in place, we can design a system so that no one person has the root credentials

### Threat Modelling and Threat Intelligence 
After we've completed an inventory for both systems and software and we understand our organization's requirements, we're ready to begin researching potential threats. Security teams research (or leverage vendor research about) threats to different industries and software
+ We can use this information in our _Threat Modelling_. Threat modelling describes taking data from real-world adversaries and evaluating those attack patterns and techniques against our people, processes, systems, and software. It is important to consider how the compromise of one system in our network might impact others
+ _Threat Intelligence_ is data that has been refined in the _context_ of the organization: actionable information that an organization has gathered via threat modelling about a valid threat to that organization's success. Information isn't considered threat intelligence unless it results in an _action item_ for the organization. The existence of an exploit is not threat intelligence; however, it _is_ potentially useful information that might lead to threat intelligence
	+ An example of threat intelligence occurs when a relevant adversary's attack patterns are learned, _and_ those attack patterns could defeat the current controls in the organization, _and_ when that adversary is a potential threat to the organization
	+ The difference between security information and threat intelligence is often that security information has only been studied out of context for the specific organization
	+ When real threat intelligence is gathered, an organization can take informed action to improve their processes, procedures, tactics, and 

### Table-Top Tactics 
After concerning threat intelligence or other important information is received, enterprises may benefit from immediately scheduling a _cross organization_ discussion
+ One type of discussion is known as a _table-top_, which brings together engineers, stakeholders, and security professionals to discuss how the organization might react to various types of disasters and attacks
+ Conducting regular table-tops to evaluate different systems and environments is a great way to ensure that all teams know the _Tactics, Techniques, and Procedures_ (TTPs) for handling various scenarios
+ Often organizations don't build out proper TTPs, resulting in longer incident response times

Table-top discussions help organizations raise cross-team awareness, helping teams understand weaknesses and gaps in controls so they can better plan for such scenarios in their tactics, procedures, and systems designs
+ Having engineers and specialists involved in table-tops might help other teams find solutions to security issues, or vice-versa

Table-top security sessions are part of _Business Continuity Planning_ (BCP)
+ BCP also includes many other aspects such as live drill responses to situations like ransomware and supply-chain compromise
+ BCP extends outside of cybersecurity emergencies to include processes and procedures for natural disasters and gun violence
+ Routine table-top sessions and continuous gathering of relevant intelligence provides a proactive effort for mitigating future issues as well as rehearsing tactics, processes, and procedures

### Continuous Patching and Supply Chain Validation
Another defensive technique known as _continuous automated patching_ is accomplished by pulling the upstream source code and applying it to the lowest development environment
+ Next, the change is tested, and only moved to production if it is successful
+ We can leverage cloud provider infrastructure to more easily spin up complete replicas of environments for testing these changes
+ Rather than continuously running a full patch test environment, we can create one with relative ease using our cloud provider, run the relevant tests, then delete it
+ The primary risk of this approach is supply chain compromise

_Continuous supply chain validation_ occurs when people and systems validate that the software and hardware received from vendors is the expected material and that it hasn't been tampered with, as well as ensuring output software and materials are verifiable by customers and business partners
+ Continuous supply chain validation is difficult, and sometimes requires more than software checks, such as physical inspections of equipment ordered
+ On the software side of supply chain security, we can use deeper testing and inspection techniques to evaluate upstream data more closely
+ We might opt to increase the security testing duration to attempt to detect sleeper malware implanted in upstream sources
+ _Sleeper malware_ is software that is inactive while on a a system for a period of time, potentially weeks, before it starts taking action

Utilizing a _software bill of materials_ (SBOM) as a way to track dependencies automatically in the application build process greatly helps us evaluate supply chain tampering
+ If we identify the software dependencies, create an SBOM with them, and package the container and SBOM together in a cryptographically-verifiable way, then we can verify the container's SBOM signature before loading it into to production
+ This kind of process presents additional challenges for adversaries

### Encryption 
Beyond tracking software, many organizations likely want to leverage _encryption_. Encryption often protects us from adversaries more than any other type of control. While using encryption doesn't solve all problems, well-integrated encryption at multiple layers of controls creates a stronger security posture
+ Keeping this in mind, there _are_ some caveats to consider when it comes to encryption
+ Encrypting all our data won't be useful if we can't decrypt it and restore it when required
+ We must also consider some types of data that we won't want to decrypt as the information is to be used only ephemerally
+ One example of ephemeral encryption is _TLS_, in which nobody but the server and the client of that specific interaction can decrypt the information (not even the administrators), and the decryption keys only exist in memory for a brief time before being discarded

Decryption keys in such a scenario are never on disk and never sent across the network
+ This type of privacy is commonly used when sending secrets or _Personal Identifiable Information_ (PII) across the wire
+ Any required tracing and auditing data can be output from the applications rather than intercepted, and the secrets and PII can be excluded, encrypted, or scrubbed
+ PII can include names, addresses, phone numbers, email addresses, SSNs, and other information that can be used to track down or spy on an individual person

Along with ensuring we can encrypt data, we should ensure that only the minimum required persons or systems can decrypt said data
+ We also probably want backups that are encrypted with different keys
+ In general, we don't want to re-use encryption keys for different uses, as each key should only have one purpose
+ A file encryption key might encrypt millions of files, but that key should be used for only that purpose, and not, for example, signing or TLS

Although using encryption and backups are great practices, we also should implement protocols for routinely restoring from backups to ensure that we know how, and that the process works for every component
+ In some cases, we don't need to back up detailed log data; however, most compliance and auditing standards require historic logs
+ Some specifications may even require that systems are in place to query for and delete specific historic log records

### Logging and Chaos Testing 
Being able to access granular data quickly is of great benefit to an organization
+ Well-engineered logging is one of the most important security aspects of application design
+ With consistent, easy to process, and sufficiently-detailed logging, an operations team can more quickly respond to problems, meaning incidents can be detected and resolved faster

The last control we'll explore is _Chaos Testing_. Chaos testing is a type of BCP or _disaster recovery_ (DR)[2](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/introduction-to-cybersecurity/security-principles,-controls,-and-strategies/logging-and-chaos-testing#fn2) practice that is often handled via automation
+ For example, we might leverage a virtual machine that has valid administrative credentials in the production network to cause intentional disasters from within
+ Chaos engineering includes a variety of different approaches, such as having red teams create chaos in the organization to test how well the organization is able to handle it, scheduling programmed machine shutdowns at various intervals, or having authenticated malicious platform API commands sent in
+ The goal is to truly test our controls during messy and unpredictable situations
+ If a production system and organization can handle chaos with relative grace, then it is an indication that it will be robust and resilient to security threats


## Cybersecurity Laws, Regulations, Standards, and Frameworks 

### Laws and Regulations
Different countries and jurisdictions all have their own, so most of the items we'll discuss here are centered on the United States; however, some are applicable globally as well. 
+ As a security professional, it's _always_ important to understand exactly which laws and regulations one might be subject to

#### HIPPA
The _Health Insurance Portability and Accountability Act_ of 1996 (HIPAA) is a United States federal law regulating health care coverage and the privacy of patient health information
+ Included in this law was a requirement to create of a set of standards for protecting patient health information, known as _Protected Health Information_ (PHI)
+ The standards that regulate how PHI can be used and disclosed are established by the _Privacy Rule_
+ This rule sets limits on what information can be shared without a patient's consent and grants patients a number of additional rights over their information, such as the right to obtain a copy of their health records
+ Another rule known as the _Security Rule_ outlines how electronic PHI (e-PHI) must be protected, It describes three classes of safeguards that must be in place
	+ administrative (having a designated security official, a security management process, periodic assessments, etc.)
	+ physical (facility access control, device security)
	+ technical (access control, transmission security, audit abilities, etc.)
+ These rules also include provisions for enforcement and monetary penalties for non-compliance
+ Importantly, HIPAA also requires that covered entities (healthcare providers, health plans, business associates, etc.) provide _notification_ in the event that a PHI breach occurs

#### FERPA
The _Family Educational Rights and Privacy Act_ of 1974 (FERPA), is a United States federal law regulating the privacy of learners' education records
+ This law sets limits upon the disclosure and use of these records without parents' or learners' consent
+ Some instances where schools are permitted to disclose these records are school transfers, cases of health or safety emergency, and compliance with a judicial order
+ FERPA also grants parents and learners over the age of 18 a number of rights over this information
+ These rights include the right to inspect these records, the right to request modification to inaccurate or misleading records, and more
+ Schools that fail to comply with these laws risk losing access to federal funding

#### GLBA 
The _Gramm-Leach-Bliley Act_ (GLBA), enacted by the United States Congress in 1999, establishes a number of requirements that financial institutions must follow to protect consumers' financial information
+ This law requires that institutions describe how they use and share information and allow individuals to opt out in certain cases
+ Like other cybersecurity laws, GLBA requires that financial institutions ensure the confidentiality and integrity of customer financial information by anticipating threats to security and taking steps to protect against unauthorized access
+ In addition, financial institutions must also describe the steps that they are taking to achieve this

#### GDPR
The _General Data Protection Regulation_ (GDPR) is a law adopted by the _European Union_ in 2016 that regulates data privacy and security
+ It applies to the private sector and most public sector entities that collect and process personal data
+ It provides individuals with a wide set of rights over their data including the well-known "right to be forgotten" and other rights related to notifications of data breaches and portability of data between providers
+ GDPR outlines a strict legal baseline for processing personal data
+ For example, personal data may be processed only if the _data subject_ has given consent, to comply with legal obligations, to perform certain tasks in the public interest, or for other "legitimate interests"
+ For businesses that process data on a large scale or for whom data processing is a core operation, a data protection officer - who is responsible for overseeing data protection - must be appointed
+ GDPR also establishes an independent supervisory authority to audit and enforce compliance with these regulations and administer punishment for non-compliance
+ The fines for violating these regulations are very high: a maximum of 20 million Euros or 4% of revenue (whichever is higher), plus any additional damages that individuals may seek
+ One unique aspect of GDPR is that it applies to any entity collecting or processing data related to people in the European Union, _regardless of that entity's location_
+ At the time of its adoption, it was considered the most strict data privacy law in the world and has since become a model for a number of laws and regulations enacted around the globe

#### Key disclosure laws
laws that compel the disclosure of cryptographic keys or passwords under specific conditions
+ This is typically done as part of a criminal investigation when seeking evidence of a suspected crime
+ A number of countries have adopted key disclosure laws requiring disclosure under varying conditions
+ For instance, Part III of the United Kingdom's _Regulation of Investigatory Powers Act_ 2000 (RIPA) grants authorities the power to force suspects to disclose decryption keys or decrypt data
	+ Failure to comply is punishable by a maximum of two years in prison or five years if a matter of national securiy or child indecency is involved

#### CCPA
The _California Consumer Privacy Act_ of 2018 (CCPA) is a Californian law granting residents of the state certain privacy rights concerning personal information held by for-profit businesses
+ One of these rights is the "right to know", which requires business to to disclose to consumers, upon request, what personal information has been collected, used, and sold about them, and why
+ The "right to opt-out" also allows consumers to request that their personal information not be sold, something that must, with few exceptions, be approved
+ Another right is the "right to delete", which allows consumers to request that businesses delete collected personal information
	+ In this case, however, there are a number of exceptions that allow business to decline these requests

### Standards and Frameworks

#### PCI DSS
The _Payment Card Industry Data Security Standard_ (PCI DSS) is an information security standard, first published in 2004, for organizations handling customer payment data for a number of major credit card companies
+ It is managed by the Payment Card Industry Standards Council and it's purpose is to ensure that payment data is properly secured in order to reduce the risk of credit card fraud
+ As with other frameworks, PCI DSS consists of a number of requirements, compliance with which must be assessed annually
+ Most of these requirements resemble other industry best practices regarding network and system security, access control, vulnerability management, monitoring, etc
	+ For example, Requirement 2 prohibits the use of vendor-supplied defaults for system passwords and other security-related parameters
+ Other requirements are credit-card specific formulations of other familiar best practices
	+ For example, Requirement 3 outlines what types of credit card data can be stored and how it must be protected

#### CIS Top 18
The _Center for Internet Security_ (CIS) Critical Security Controls, also known as _CIS Controls_, are a set of 18 (previously 20) recommended controls intended to increase an organization's security posture
+ While not themselves laws or regulations, these controls pertain to a number of areas that regulations are concerned with, including data protection, access control management, continuous vulnerability management, malware detection, and more
+ These controls are divided into a number of safeguards (previously known as sub-controls), which, in turn, are grouped into three _implementation groups_ intended to help prioritize safeguard implementation
+ IG1 consists of controls that are considered the minimum standard for information security meant to protect against the most common attacks and should be implemented by every organization
	+ They are typically implemented by small businesses with limited IT expertise that manage data of low sensitivity
+ IG2 is composed of additional safeguards that are meant to apply to more complex organizations, typically those with multiple departments and staff dedicated to managing IT infrastructure with more sensitive customer and proprietary data
+ IG3, which consists of all safeguards, is typically implemented by organizations with dedicated cybersecurity experts managing sensitive data that may be subject to oversight

#### NIST Cybersecurity Framework
The _National Institute for Standards and Technology_ (NIST) _Cybersecurity Framework_ is a collection of standards and practices designed to help organizations understand and reduce cybersecurity risk
+ It was originally developed to help protect critical infrastructure; however, it has been subsequently adopted by a wide array of organizations
+ The NIST framework consists of three _components_: Core, Implementation Tiers, and Profiles
	+ Framework Core is a set of cybersecurity activities and outcomes
		+ It is divided into five high-level functions that encompass a number of categories (for example, Asset Management and Risk Assessment)
		+ These categories, in turn, include subcategories that consist of statements describing the outcome of improved security and which are aligned with Information References
		+ These references go into deeper detail about possible technical implementations. For example, Subcategory ID.BE-1 (Function: Identify, Category: Business Environment) states "The organization's role in the supply chain is identified and communicated
	+ The Framework Implementation Tiers specify the degree to which an organization's Cybersecurity practices satisfy the outcome described by the subcategories of the Framework Core
		+ There are four such Tiers: partial (the least degree), risk informed, repeatable, and adaptive
	+ Framework Profiles refer to the relationship between the present implementation of an organization's cybersecurity activities (Current Profile) and their desired outcome (Target Profile), which is determined by the organization's business objectives, requirements, controls and risk appetite
		+ The comparison of these profiles can help the organization perform a gap analysis, as well as understand and prioritize the work required to fill it

#### ATT3CK and D3FEND
The MITRE organization has tabulated and organized a framework for cataloging how groups of attackers work together to infiltrate systems and achieve their goals
+ This framework, called the _MITRE ATT3CK_ framework, is constantly updated to reflect the latest TTPs (tactics, techniques, and procedures) used by malicious groups across the globe

More recently, MITRE released a mirrored framework from the _defensive_ perspective
+  ATT3CK is meant to catalog and categorize the various ways that threat actors operate in the real world, D3FEND portrays a set of best practices, actions, and methodologies employed by defenders to prevent, detect, mitigate, and react to attacks

#### Cyber Kill Chain 
A methodology developed by Lockheed Martin to help defenders identify and defend against cyber attacks
+ It outlines seven stages of the attack lifecycle: reconnaissance, weaponization, delivery, exploitation, installation, command and control, and actions on objectives
+ In the reconnaissance phase, an attacker identifies a target and enumerates potential weaknesses through which it may be exploited
+ Weaponization is the process by which an attack method is used to exploit this weakness it identified
+ This attack is launched in the delivery phase and, in the exploitation phase, the payload is executed on the target system
+ This leads to the installation stage in which malware is installed on the system
+ This malware is used to execute further commands in the command and control phase
+ In the actions on objectives phase, the attacker performs the actions required to achieve their ultimate goals, which may be data theft, modification, destruction, etc

#### FedRAMP
The _Federal Risk and Authorization Management Program_ (FedRAMP) is a United States program that provides a standardized security framework for cloud services used by the federal government
+ Whereas previously, a cloud service may have been required to obtain different authorizations for different federal agencies, FedRAMP allows a cloud service to obtain a single authorization for all government agencies
+ Its goal is to accelerate the government's adoption of cloud services while also ensuring that these services are secure
+ The controls are based off of NIST SP 800-53 Revision 4 and enhanced by a number of additional controls that pertain specifically to cloud computing

## Cybersecurity Career Opportunities

### Attack 
**Network Penetration Tester**: A Network Penetration Tester is responsible for discovering and exploiting vulnerabilities that exist in a targeted network. This career may be a good choice for someone who has a strong understanding of networking and systems and enjoys finding ways of subverting their security measures. This role also benefits from clear technical writing abilities. To learn such skills, we suggest reviewing OffSec's PEN courses at the 100, 200, and 300 levels.

**Web Application Testers**: A Web Application Tester is responsible for testing web applications for security weaknesses. A good candidate for this role likely has a strong knowledge of web application vulnerabilities, enjoys testing them, and enjoys subverting the security measures that they employ. The skills required to become a Web Application Tester are covered in the WEB track at the 100, 200, and 300 levels. These Modules teach the basics of how web applications work as well black-box and white-box approaches to web application testing.

**Cloud Penetration Tester**: A Cloud Penetration Tester is responsible for performing penetration testing on cloud infrastructure. This might be a good career path for someone who has knowledge and experience in cloud infrastructure and penetration testing. As with other penetration testing positions, you may enjoy this role if you have fun probing infrastructure for weaknesses and figuring out ways to exploit them. CLD-100 teaches learners how to test, attack, and exploit cloud technologies.

**Exploit Developer**: An Exploit Developer is responsible for discovering and developing exploits for software vulnerabilities. Someone looking to become an Exploit Developer might enjoy reverse engineering applications to determine how they work, reading low-level code, and bypassing security mitigations. The EXP-301 course offers more information about Windows binary exploitation, while EXP-312 explores macOS logical exploitation.

**Vulnerability Researcher**:A Vulnerability Researcher is responsible for researching new software vulnerabilities and exploitation techniques, determining their impact, developing Proofs of Concept (PoCs), and communicating their findings to different stakeholders. A person may wish to be a Vulnerability Researcher if they enjoy reverse engineering and researching new and emerging vulnerabilities and techniques. You can follow EXP-301 and EXP-312 to learn how to reverse engineer and develop exploits for Windows and macOS software, respectively.

### Defend
**SOC Analyst**: A SOC Analyst is responsible for monitoring, triaging and, when necessary, escalating security alerts that arise from within monitored networks. Someone may be a good fit for this position if they enjoy investigating and gathering information surrounding suspicious activity. To prepare, we recommend following the SOC track at the 100 and 200 levels in the OffSec library. SOC Modules will explore the techniques attackers use to infiltrate networks and those that analysts use to discover this activity.

**Malware Analyst**: A Malware Analyst is responsible for analyzing suspected or confirmed malware samples in order to determine how they work and, ultimately, what their purpose is. Someone might enjoy this role if they have a basic understanding of networking and like analyzing suspicious samples and reverse engineering.

The OffSec library contains a number of resources that can help learners learn these skills. For example, EXP-301 teaches reverse engineering and some basics of the Windows API. PEN courses at the 200 and 300 levels describe how attackers craft malicious documents and payloads as well as the techniques that they use to evade antivirus and other detection mechanisms. Finally, the 100-level library contains Modules that can help to learn the basics of networking.

**Digital Forensics Analyst**: A Digital Forensics Analyst is responsible for investigating Cybersecurity incidents by gathering and analyzing evidence of intrusions and recovering data. Someone who enjoys this role likely has a strong understanding of how systems and networks operate and is interested in investigating how intrusions occur, then assembling evidence into a complete story. To begin learning these skills, we recommend reviewing the SOC track at the 100 and 200 levels. SOC-200 shows some of the specific ways attackers operate and how to search for evidence of their attacks.

**Incident Responder**: An Incident Responder is responsible for reacting to cybersecurity events. This includes identifying the cause and scope of an incident and recommending measures to contain, eliminate, and recover from it. Someone may be a good fit for this role if they have a strong technical background and enjoy working in a fast-paced environment and performing root cause analysis. This role also benefits from strong cross-functional communication skills. Starting with the SOC track at the 100 and 200 level will help learners prepare for this career. SOC-200 in particular shows some of the ways attackers operate and how to search for evidence of their attacks.

**Threat Hunter**: A Threat Hunter is responsible for proactively searching networks and systems for Indicators of Compromise (IOCs) using the most up-to-date threat intelligence. This role could be a good choice for someone who enjoys following the most recent cybersecurity feeds and searching for malicious activity that may have evaded existing defenses. There are a number of resources in the OffSec library that can help to prepare for this position. For example, the SOC track at the 100 and 200 levels teaches about common techniques used by attackers and how to search for and identify them. The PEN-300 course is helpful to learn about the ways that attackers bypass existing defenses.

### Build
**Cloud Engineer**: A Cloud Engineer is responsible for building and maintaining the cloud infrastructure. This role encompasses a number of more specialized positions, including Cloud Architect, and, with the usual exception of that position, typically involves the implementation of the cloud architecture as outlined by the company's cloud-computing strategy. This career may be a good fit for someone who enjoys programming and building infrastructure, and has experience with cloud service providers and other cloud-related technologies.

**Cloud Architect**: A Cloud Architect is responsible for designing and overseeing the implementation of a cloud-computing strategy aligned with the business's goals and needs. Individuals with a deep, cutting-edge understanding of cloud computing who enjoy developing high-level business strategy and excel at communicating technical concepts across business areas may enjoy this role.

OffSec's CLD-100 offers more information about important cloud concepts and technologies. It teaches learners how to build clouds safely and secure these technologies.

**Developer**: A Software Developer is responsible for writing computer programs which, depending on the precise role, may range from core operating system components to desktop, mobile and web applications. Someone who enjoys designing elegant and efficient programmatic solutions to problems may enjoy this role. Depending on the type of software development, the OffSec Library contains a considerable number of resources to help learners understand attack vectors and create secure software. A general understanding of software vulnerabilities is available in the PEN-200 course, while information about web development can be found in OffSec's WEB courses at the 200 and 300 level. Those who may be programming in memory-unsafe languages such as C may be interested in the EXP-301 and EXP-312 courses.

**DevSecOps**: DevSecOps (an abbreviation for Development, Security and Operations) is an approach to software development that integrates security into all stages of the software development lifecycle, rather than postponing it to the end. A DevSecOps Engineer[5](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/introduction-to-cybersecurity/career-opportunities-in-cybersecurity/cybersecurity-career-opportunities-build#fn5) is responsible for automating security testing and other security-related processes. This role might be a good fit for someone who has an understanding of Continuous Integration / Continuous Development (CI/CD) pipeline and tools, an interest in security testing automation, and the ability to work in a fast-paced environment.

The OffSec Library contains a considerable number of resources that can help learners with software development, including understanding the different attack vectors to automate testing for and the types of automation testing tools available. This information can be found in the WEB and PEN courses at the 200 and 300 level. CLD-100 also provides details about Docker and Kubernetes: two essential tools for DevSecOps.

**Site Reliability Engineer**: A Site Reliability Engineer is responsible for ensuring and improving the availability and performance of software systems. A person may wish to be a Site Reliability Engineer if they have software development experience and are interested in using automation to monitor for, alert, and respond to reliability-related issues. learners can learn about containers and Kubernetes, some of the key technologies used to support SRE, by following CLD-100 in the OffSec library.

**System Hardener (System Administrator)**: A System Hardener is responsible for configuring systems to reduce their security risk. This involves changing insecure default configurations, removing unused programs, ensuring firewalls are appropriately restrictive, etc. A person may seek out this career if they have experience with system administration, are familiar with attack techniques, and enjoy making systems and the data they store more secure. Many of the skills required for this position are covered in the PEN track at the 100, 200 and 300 levels. PEN-100, for instance, explores some of the basics of networking and system administration. PEN-200 describes some of the common techniques that attackers use. PEN-300 teaches more advanced techniques that attackers use to bypass defenses.

# Effective Learning Strategies 

## Learning Theory 

### What We Know and What We Don't
First, learning is not entirely dependent on the learner. The teacher, the material, the education format, and a variety of other factors affect success more than a learner's raw capability
+ External events and circumstances can drastically affect a learner's performance

Second, as new educational studies are constantly released, it's clear there's still much to be discovered about the mechanics of our memory. This includes research suggesting that the notion of learning modes (or learning styles) is more of a myth than previously thought

### Memory Mechanisms and Dual Coding
Can improve memory by doing the following:
1. Improve the quality of information we take in
2. Improve the way or mode in which we receive information
3. Improve our practice of retrieving information

- _Improve the quality of information we take in:_ At a basic level, we expect our training material to be accurate. We might need explanatory paragraphs (like this one), written in a simple, easy-to-understand manner. This responsibility generally falls to the instructor or training provider.
- _Improve the way or mode in which we receive information:_ This could include multiple approaches. Information might be more easily retained if presented in multiple formats, such as videos or images. This might also comprise, for example, a safe, distraction-free environment for the learner.
- _Improve our practice of retrieving information:_ This may seem like merely exam practice at first, but there's more to it than that. A learner who reads a paragraph about how to create a file and then follows along to create a file independently is working on memory retrieval.

Taking in the same information via a secondary method, for example, reading an explanation and then watching a video about the same Module, is called _Dual Coding_
+ The basic principle behind Dual Coding is that repeatedly studying the same information through different means improves retention

### The Forgetting Curve and Cognitive Load
Two of the most common problems we encounter when trying to learn something (or create a memory) are "too long ago" or "too much information at once"
+ Forgetting information happens as soon as you learn it, with one experiment allowing 100% memory after reading source, 58% after 20 minutes, and 23% after a day. called this decline _The Forgetting Curve_

The second problem, which we've referred to as "too much information at once", is usually referred to as _Cognitive Load_
+ At some point, if more and more information keeps coming in, there simply isn't enough space for everything to stay organized
+ To remedy this, instructors may try reducing what is called "extraneous load."
+ These are extra pieces of new information that aren't important or necessary
+ Need to reduce extraneous load in the physical learning space itself as well

## Unique Challenges to Learning Technical Skills 

### Digital vs. Print Materials 
Findings are that smaller screens may make learning more difficult and that individuals who read books tend to understand the information more fully
+ Sometimes screen reading can cause visual or sensory fatigue
+ Learners learning in a digital context have easy access to a number of tools, including the ability to quickly and easily reference additional materials (for example, looking up the definition of a new vocabulary word)
+ On the other hand, sometimes the act of reading forces one into a distraction-free environment that allows for deeper focus

The second, and perhaps the more important thing to note here, has to do with a concept known as _Contextual Learning_
+ This concept suggests that even on an intuitive level, we know that it's easier to learn how to build a house on a construction site
+ When the training material is presented in the same context as the skill that we're trying to learn, our brain has to do less translation work and can accept the new information more readily

### Expecting the Unexpected
There is another unique challenge that we will face in learning cyber security. This field is consistently focused on trying to prepare for situations we can't possibly predict
+ We might learn about _Enterprise Network Architecture_, which examines the way a business organizes servers, workstations, and devices on a network
	+ Unfortunately, as in-depth as that Module might go, it's unlikely to cover the exact network architecture that we'll encounter in some future scenario
+ In another Module, we might thoroughly and perfectly understand a specific attack vector, and we might even be able to execute it in the lab environment, but that doesn't mean we will encounter that exact vector in all future environments

We also must take into account that the entire field of cyber security is constantly evolving
+ New vulnerabilities are discovered all the time, a network that is secure today may not be secure in six months
+ A learner needs to be able to exceed their initial training in order to remain effective in the field

In this way, learning about cyber security is similar to learning _transversal skills_ like leadership, communication, and teamwork
+ There is no simple, straightforward standard operating procedure for building better teamwork just as there is no simple, straightforward standard operating procedure for exploit development
+ Instead, we need to focus on understanding methods, techniques, and the purpose behind certain actions

The best approach to this problem is not to learn a series of steps we can follow to make that network secure today, then learn a _new_ set of steps in six months
+ The solution is to learn the methodology and the purpose behind each security step
+ When new risks arise, we'll apply the same methodology, adapting and evolving along with the changing threat landscape

### Challenges of Remote Asynchronous Learning 
There is one more aspect of this particular type of learning that we will want to take into consideration--the fact that this is a _remote_ learning environment

We must also consider that some online learning is _asynchronous_, meaning the instructor may not be present in a Zoom call or classroom to deliver a lecture, instruction, or to answer questions
+ Instead, the learner can participate in the class at whatever hour or pace works best for them

learners in a remote, asynchronous learning environment should be aware of two things:
1. The advantages that come from the peer support, community, and camaraderie of other learners in a traditional classroom setting is no longer a guarantee.
2. The pace and timing of the course is largely the learner's responsibility.

## OffSec Training Methodology 

### The Demonstration Method 
using the _Demonstration Method_ means showing (or acting out) what one hopes the learner will be able to accomplish
+ An instructor using the demonstration method will follow the exact steps that a learner should follow, including the resulting output of running the command

For example:
``` Shell
kali@kali:~$ ls *.txt
oldfilename.txt

kali@kali:~$ mv oldfilename.txt newfilename.txt
 
kali@kali:~$ ls *.txt
newfilename.txt
```
+ Before showing the code block, we would first lay out our plan and detail any new or interesting commands we're planning on running

After the code listing, we would explain our results
+ In this case, we listed the **.txt** files and only had one, named **oldfilename.txt**
+ We then ran our renaming command and received no output, as expected
+ Finally, we checked our results by running **ls .txt** again, This time, the output shows the only **.txt** file in the directory is **newfilename.txt**
+ Could take further steps to ensure this file contains the same contents as earlier, and that only the filename has changed

While it may seem unnecessary to include these extra items, this sort of demonstration and description begins to expose the thought process that a learner will need to learn
+ Sometimes the material will take what feels like a longer route in order to show both the new skill and a useful context
+ It may also actively expose and discuss the instructor's "mistakes" and redirections
+ Demonstrating a thought process in this manner is called _modeling_, and was developed as a way to teach _critical thinking skills_

### Learning by Doing
Doing something helps us learn it. There is an absolute wealth of research to support learning by doing as a method that increases memory retention and improves the overall educational experience of a learner

We know this method works well for learners, and OffSec has applied it in several ways.
1. The Training Materials
2. The Module Exercises
3. The Challenge Labs
4. Proving Grounds

The *training materials* themselves will always trend toward focusing on scenarios that we can follow along with. There are times when we need to discuss a bit of theory so that we have enough background to go deeper, but in general, if the material can demonstrate working through a problem, then the expectation is that the learner should be able to follow along. Often a _virtual machine_ (VM) is specifically built in order to accommodate this.

The _Module Exercises_ themselves will often involve working with a VM as well. This is the approach as often as is reasonably possible, but with some Modules (this one, for example) that are more theoretical, exercises are presented in a more standard question-and-answer format.

The OffSec Library also contains _Challenge Labs_, which take the exercises one step further. A Challenge Lab is, essentially, an environment of additional practice exercises specifically created to help learners prepare for an exam (which, perhaps as expected, is also hands-on). We highly recommend that learners take advantage of this additional opportunity.

Finally, we leverage *assessments and exams*. These are exercises and networked lab environments specifically for proving the skills we've learned. Since a real world environment will not give us a clear indication for which vulnerabilities might be present on a system, we don't create a 1:1 link between a course Module and an assessment (for example, we don't advertise whether or not a machine is vulnerable to privilege escalation).

### Facing Difficulty 
There is a common expression that "practice makes perfect". That may be true, but it begs the question, what makes for ideal practice?
+ Studies demonstrate that struggle is not only important to the learning experience, but it's actually more important than mere repetition for creating the neural pathways that help us learn new skills
+ Put simply, we feel that memorizing syntax is less important than being familiar with challenges and comfortable with a bit of struggle as a necessary character trait for someone in the field of information security

Getting stuck isn't fun, but we believe that being comfortable in a situation where we might not have all of the information and working through the problem is critical to success in the field of cyber security
+ The goal is to help you practice getting stuck enough that you become quite comfortable with recovering

### Contextual Learning and Interleaving
Whenever possible, OffSec's learning materials will present a new skill as part of a realistic scenario
+ This can be difficult with more basic skills, like the command used to rename a file, but as we move deeper and deeper into the materials, we will find ourselves working through hands-on scenarios that are as representative of the real world as possible

Learners may also find that when information is presented in context, they are actually learning several things at once
+ For example, if we are learning about how an attack method might be both executed and detected at the same time, our brain can make more connections to help us learn effectively. This method is called _interleaving_

## Case Study: chmod -x chmod 

### What is Executable Permission?
Every file on a Linux machine has a number of additional properties associated with it 
+ These include when the file was created, what user created it, which users have permissions to read that file, and even the name of the file itself

File permissions are particularly important. They indicate whether or not we are allowed to either read, write, or execute a particular file
+ We might think of the word _write_ in this context as our ability to make certain changes to a file. This could, for example, be set to not allow us to write to a file, which might keep that file from being accidentally deleted
+ The permissions might also be set to not allow us to read a file that has information in it that we shouldn't be allowed to view

These are called the _file permissions_ and they pertain to a few different types of users who might be on this computer: the file owner, the user ownership group, and anyone else
+ These different classes of users can be given (or denied) permission for each of the three actions above: read, write, and execute

We'll **touch** a file (**newfilename.txt**), which will create it and automatically make us the owner. Then we'll use the listing command **ls** to gather information about the file, providing the **-l** parameter that will produce a long listing including the file permissions
```
kali@kali:~$ touch newfilename.txt

kali@kali:~$ ls -l newfilename.txt
-rw-r--r-- 1 kali kali 0 Jun  6 12:31 newfilename.txt
```
+ The touch command produced no output. This is normal
+ The output of the ls command includes information about the permissions as indicated by the letters _rwx_, where the "r" is for read, the "w" is for write, and the "x" is for execute
+ A dash (-) indicates that the user class doesn't have the corresponding permissions. In this case, we have permission to read and write to our new file, but there is no "x" character in the output, meaning no class has permission to execute
+ As the owner of a particular file, we were granted read and write permissions by default when we created it, but we aren't granted executable permissions
	+ In other words, if **newfilename.txt** was a program, we would not be able to execute it
	+ This is a small but useful security feature that prevents us from accidentally running something we might not want to

Let's say we have a simple program that will give us a complete list of employee names
+ This program is a Python script we've created named **find_employee_names.py**
```
kali@kali:~$ ./find_employee_names.py
zsh: permission denied: ./find_employee_names.py

kali@kali:~$ ls -l find_employee_names.py
-rw-r--r-- 1 kali kali 206 Jun  7 12:31 find_employee_names.py
```
+ The **./** part of the command simply instructs the system where to find the file
+ The "zsh: permission denied" error message indicates that for some reason, we're not able to execute (or run) our script
+ there's no "x" character in the **ls** output, which means that we don't have permission to execute

Let's change the executable permission for this file and give ourselves permission to execute the file (put another way, to run it as a program). We can use **chmod +x** to add the executable permission to our script file. Let's do so and try running the script again
```
kali@kali:~$ chmod +x find_employee_names.py

kali@kali:~$ ls -l find_employee_names.py
-rwxr-xr-x 1 kali kali 206 Jun  7 12:31 find_employee_names.py

kali@kali:~$  ./find_employee_names.py
R. Jones
R. Diggs
G. Grice
C. Smith
C. Woods
D. Coles
J. Hunter
L. Hawkins
E. Turner
D. Hill
```
+ This time, the **ls** output contains the "x" character, indicating that executable permission is allowed for all three user classes

Now change it back so that we no longer have permission to execute the file. To add the permission, we used **chmod +x**, so this time, we will use **chmod -x**.
```
kali@kali:~$ chmod -x find_employee_names.py

kali@kali:~$ ./find_employee_names.py
zsh: permission denied: ./find_employee_names.py
```

### Going Deeper: Encountering a Strange Problem
We'll consider the fact that the chmod command itself is just a file
+ It follows the same rules as other files on the system, including the same rules about permissions. It exists in a slightly different location (in the **/usr/bin/** directory) as our script, but the only reason we are able to run the _chmod +x find_employee_names.py_ command at all is because the **chmod** file has its permissions set to allow us to run it as a program
+ Now, let's ask ourselves an interesting question: since chmod is the tool that allows us to set permissions, what would we do if we did not have permission to execute it?

Thankfully, it is not easy to accidentally remove our executable permission for this file. Despite this, we've done so on our system
```
kali@kali:~$ ./find_employee_names.py
zsh: permission denied: ./find_employee_names.py

kali@kali:~$ chmod +x find_employee_names.py
zsh: permission denied: chmod
```

We could try running **chmod** on the chmod file, but we will run into the same problem. Let's run it on **/usr/bin/chmod**, since this is the specific location of the file
```
kali@kali:~$ chmod +x /usr/bin/chmod
zsh: permission denied: chmod
```
+ Once again our permission is denied, but we're not stuck yet

### One Potential Solution
There are a number of ways to fix our chmod problem. The simplest solutions involve finding a "clean" version of the chmod file and replacing it 
+ The more complicated solutions include running one binary in the context of another binary that has the correct permissions. Let's explore one particularly interesting solution

We need to do what our chmod file can do, but we also need permission to do it. To put this another way, our end goal is a file that can do what chmod can do, but that has the permissions of another file, such as **ls**
+ We'll start by making a copy of a file that we know has the permission set we need. Since we checked the ls command earlier, let's copy that file into a new file named **chmodfix**
```
kali@kali:~$ cp /usr/bin/ls chmodfix

kali@kali:~$ ls -l chmodfix
-rwxr-xr-x 1 kali kali 147176 Jun  8 08:16 chmodfix
```
+ Our new **chmodfix** file has the same permissions as the file we copied. This is a promising start
+ The new **chmodfix** file is a perfect copy of **ls**. It can be run in the same way as ls, can use the same options, and so on. In other words, anywhere we would have used ls, we can use this instead. Let's try running it on itself

Since the only thing that seems to be "broken" with our **chmod** file is the permissions (as far as we know, the contents of the file itself are fine), let's try to copy only the contents of the file and not the permissions. In other words, we only need the contents of the file - not the entire thing
+ Since we know that cp will copy the entire file, we can't use that approach
+ The _cat_ command is often used to show the contents of a file, so we will use that. Instead of just sending the contents of the file to display in the terminal window, we can use the ">" character to send them into our **chmodfix** file
+ First, we'll run **ls -l** so that we can easily confirm whether or not the file contents change
```
kali@kali:~$ ls -l chmodfix
-rwxr-xr-x 1 kali kali 147176 Jun  8 08:20 chmodfix

kali@kali:~$ cat /usr/bin/chmod > chmodfix

kali@kali:~$ ls -l chmodfix
-rwxr-xr-x 1 kali kali 64448 Jun  8 08:21 chmodfix
```
+ We previously examined the _-rwxr-xr-x_ portion of the output
+ We'll also notice a number, "147176" in the case of the first command, in the output
	+ This number indicates the size of the file. After we run the **cat** command, we'll observe that the file name and the permissions are still the same as before, but the file size is now "64448". This output indicates that the contents of the file have changed, but the permissions remained intact

Let's return to the beginning and try to run **chmodfix +x** on our script
```
kali@kali:~$ ./chmodfix +x find_employee_names.py

kali@kali:~$ ./find_employee_names.py    
R. Jones
R. Diggs
G. Grice
C. Smith
C. Woods
D. Coles
J. Hunter
L. Hawkins
E. Turner
D. Hill
```
+ We were able to restore our permission to execute our script and run it

Let's try and run the **chmodfix** command on the original **chmod** file to fix things
```
kali@kali:~$ ./chmodfix +x /usr/bin/chmod
./chmodfix: changing permissions of '/usr/bin/chmod': Operation not permitted
```

Right now we are trying to run this command as the _kali_ user. Let's try running the command again, but this time as a Super User. To do this, we'll use the **sudo** command,[2](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/effective-learning-strategies/case-study-chmod-x-chmod/one-potential-solution#fn2) followed by our original command. The system will prompt us for our password
```
kali@kali:~$ sudo ./chmodfix +x /usr/bin/chmod
[sudo] password for kali: 
```

### Analyzing this Approach
Although we covered an admittedly simple section from our written training, let's take a moment to examine how we taught this material. We'll highlight a few things in particular:
1. Using the demonstration method
2. Learning by doing
3. The skill, not the tool
4. Interleaving
5. Expecting the unexpected

_The demonstration method_ is used specifically in the tone and voice of the example covered, but also in the series of actions that we follow. We don't skip steps, including verifying whether our solutions worked.

Notably, we encounter a "problem" (not being able to execute our script) almost immediately, which represents the real-world, day-to-day experience of learners after the course has ended. Research also supports problem solving as a very effective learning strategy both for engagement and retention

This problem-solving approach is used throughout Modules very intentionally. One way learners can take advantage of this is by trying to predict outcomes

_Learning by doing_ is an area where learners can take learning into their own hands and accelerate their own growth. The best way to do this is to follow along
+ Normally, a Module will include at least one virtual machine that is specifically set up to allow learners to follow the accompanying text. In this case, we would have used a Linux machine with our **find_employee_names.py** script on it 

## Tactics and Common Methods
Next, we need to think about strategy and tactics. Consider the following quote from Sun Tzu:
+ Strategy without tactics is the slowest route to victory. Tactics without strategy is the noise before defeat. – Sun Tzu

In the most basic sense, we can think of _strategy_ as being a long-term vision, while _tactics_ are the short-term, immediate actions that we take
+ Strategy is the map, and tactics are the steps

For learners in a formal school structure, the strategy and tactics of study are often built into the school structure itself. A learner's schedule and the Modules of study, and even how that learner will approach the learning material, are all dictated by the school district or the instructor
+ In the absence of that rigid school structure, a common mistake of adult learners is to approach their studies casually, without thinking about either tactics or strategy
+ We might know, for example, that it's important to "take notes", but what exactly should we be writing down? And what should we do with those notes

### Cornell Notes
There are many different note taking systems. Let's briefly examine one called _Cornell Notes_
+ was developed by a Cornell University Professor named Walter Pauk in the 1950s. This method involves using a pen and paper, which helps with dual encoding
+ The first step is to divide the page into three areas. These are the _cue_ (on the left hand side of the page), the _notes_ (the large area on the right hand side of the page), and the _summary_ (several lines of space at the bottom of the page)

The cue might be questions we have about the text or key words or phrases. To illustrate an example, let's discuss a Module like password hashing
+ This Module might have key terms to learn such as _one-way encryption_, _salting_, and _cracking passwords_. We might also have a question, for example, "Are some hashing methods better than others?"
+ The notes section for that page should be directly related to the items in the cue section. For example, near where we've written one-way encryption, we might write a long form definition of what is meant by this term
+ Finally, we will complete the summary section as we review our notes. To continue the example, we might write "hashing a password = additional protection. Interested in more about cracking." The content here does not need to necessarily be directly related to the material

### Retrieval Practice
_Retrieval Practice_ is, as the name suggests, the practice of determining whether or not information can be recalled
+ Can think of this simply as quizzing yourself
+ This practice can take many forms, including covering our notes and trying to recall what was written, or creating challenges or flashcards

Let's discuss flashcards first. The _Leitner System_ is named for German scientist Sebastian Leitner and involves making flashcards as a method to review and repeat learning
+ Both the act of creating and then practicing with flashcards can be incredibly useful. A flashcard is a small paper card that has a question or term on one side and then the answer or definition on the other side
+ Practice involves reading the question and guessing the answer
+ There are a multitude of applications that can help create flashcards, but consider the benefits of taking small index cards and a pen or pencil and creating your own. The act of writing down the information and creating our own flashcards is dual coding at its best

This method can be used in a number of different ways, but often takes full advantage of Spaced Practice as well as shuffling the cards and reviewing different cards on different days
+ The Leitner System is not incredibly useful for learning methodologies and problem-solving skills, but can be helpful when trying to memorize things, like a particular tool's syntax

Creating actual challenges can be difficult. Learners have a few options here. The most obvious is to complete the included challenges for every Module. Whenever possible, these challenges do not simply repeat the information or the methods included in the Module, but ask the learner to go just one step further. Another option is to to return to a completed hands-on exercise and repeat it. Finally, some courses include challenge labs, which are virtual machines that allow for a more hands-on retrieval practice or self-testing

### Spaced Practice 
Many learners have had the experience of "cramming," or staying up late to study and try to memorize a lot of information on the night before a big exam
+ Any learner who has tried this method can attest to how ineffective it can be, especially just a few days after the exam has concluded. _Spaced practice_ is the opposite of this style of study
+ Spaced practice has to do with the timing and duration of our study time. It is recommended to spread out the study time over days and weeks rather than do it all at once
+ Long, "cramming"-style study sessions actually take more time, often come at the expense of sleep, and (because they overwhelm our cognitive load) are significantly less effective

The exact duration and space between study sessions will be different for each individual. Taking breaks and walking away from the computer screen for five or ten minutes can be very helpful. Take a nap or get some sleep. Do an activity that has nothing to do with your studies at all to space practice

### The SQ3R Method
Has learners follow a pattern of study activities - survey, question, read, recite, review
+ We will detail the SQ3R method here, but it is notably very similar to the the _PQ4R method_, which is useful for reading comprehension. learners who find the following tactic useful may want to check out the PQ4R method as well

A learner begins by surveying the Module, or reviewing a high level outline, scanning through the material that might be covered during the study session. In particular, it would be important to review any highlighted text, diagrams, and headings
+  the case of our current Module, a learner might encounter the various headings and subheadings: Learning Theory, Unique Challenges to Learning Technical Skills, Offsec Training Methodology, and so on. They might then review the subheadings

Next, they will create, preferably in writing, a list of questions that they hope to have answered via the material. This may or may not reflect what the material will actually cover, but should be based largely on the survey. This is a very important step, as learners will return to the questions repeatedly

Next, the learner reads the material one section at a time. If there are videos or other activities for this section, they can also complete those

Next, the learner returns to their list of questions for that smaller section. They should try and recite the questions back from memory and determine if they're now able to answer them

Finally, in the review, a learner returns to all of the smaller sections from a larger Module or chapter to check whether or not the questions have been answered and they can recall the answers

For learners who have been taught that note taking is simply "writing down things that seem important", the SQ3R method represents an alternative that is much more effective

### The Feynman Technique
The _Feynman Technique_[1](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/effective-learning-strategies/tactics-and-common-methods/the-feynman-technique#fn1) takes its name from Richard Feynman, a Nobel-prize winning physicist with a unique gift for explaining complex Modules in everyday terms. The technique that bears his name has four simple steps:
1. Learn a Module
2. Explain it to a beginner
3. Identify gaps
4. Return to study

What makes this method of study unique is Step 2. Many descriptions of this technique use the example of explaining the Module to a child who is unfamiliar with it. If we don't have access to a child (or a child who is willing to listen to an explanation about, for example, network scripting), this technique can still be useful
+ In the act of explaining things to children, we change our language to make things more simple
+ In the act of explaining things to children, we change our language to make things more simple. For example, when discussing a Brute Force Attack[2](https://portal.offsec.com/courses/pen-200/books-and-videos/modal/modules/effective-learning-strategies/tactics-and-common-methods/the-feynman-technique#fn2) with another professional, we might quickly devolve into a discussion on the massive computational power needed to crack a certain key. While explaining it to a child, we could simply say "it's a way to keep guessing lots and lots of passwords until, hopefully, one of them works."

The explanation itself isn't as important as the work the brain has to do to wrestle with the concepts and make them understandable outside of jargon. Similarly, when it's very difficult for us to break something down in this manner, that may be a sign that we don't understand it very well yet ourselves. All of this work helps us increase our own understanding

## Advice and Suggestions on Exams

### Dealing with Stress
OffSec certifications are earned, not given. We use this language intentionally. Having a certification from OffSec is a significant accomplishment. You can't fake your way to the finish line or guess your way to a passing score
+ For some individuals, this means that the exam and the weeks and months leading up to it can become a very stressful time

A great deal has been written on dealing with stress in general, but we'll focus in particular on high-stakes exam stress
+ Since this exam is extremely well known and notoriously stress-inducing, there are a number of excellent resources about how to manage the experience. Let's review a few of the common themes.
	1. Take Care of Yourself
	2. Schedule and Plan Your Study
	3. Have a Growth Mindset

First and foremost, any learner can't be expected to perform as well if they are feeling too hungry, tired, or sick to keep pressing on
+ Managing stress can begin with simply being aware of what's happening with our physiological bodies. Lack of sleep and poor diet can put us at a disadvantage before we even start
+ Positivity and optimism are also important factors
+ Making sure that we have things to look forward to - whether that is a study break or time with friends - can really help to fuel us when we're feeling discouraged with our studies

Second, creating a plan for ourselves is critical

Third, a _growth mindset_ can be extremely powerful
+ Essentially, the growth mindset has to do with the belief in one's own potential
+ If a learner believes they have the potential to conquer a challenge, they will have a huge head start. Alternatively, if a learner assumes they will fail, it's not likely that they will accidentally succeed
+ Try Harder mindset to describe resilience and persistence, The growth mindset might be better described as the "Not Yet Mindset."
+ A learner who encounters some particularly difficult material in preparing for a tough, stressful exam is likely to feel as if they can't do the exercise or can't understand the concepts
	+ If it ends there, the emotional impact of this sort of self-awareness can be devastating. Consider, on the other hand, that same learner with a Not Yet Mindset who thinks, for example, "I can't do the exercise _yet_", or "I can't understand the concepts _yet_."

### Knowing When You're Ready 
The quickest answer to this question then, is "it depends on the individual." Rather than leave it there, however, let's take a closer look at one specific piece of data that shows us a certain group of learners who have a clear advantage on the exam
+ The following chart focuses on the OSCP certification. It shows a direct correlation between preparedness (working on more PEN-200 lab machines) and succeeding in the exam
+ Perhaps not surprisingly, the more time spent preparing for the exam, the more likely a learner is to be successful. Unfortunately there is no shortcut here. As the saying goes, "preparation makes passing."

| OSCP Pass Rate | # of PEN-200 (PWK) Lab Machines Compromised |
| -------------- | --------------------------------- |
| 28%            | Bellow 11                         |
| 40%            | 11-20                             |
| 52%            | 21-30                             |
| 54%            | 31-40                             |
| 67%            | 41-50                             |
| 74%            | 51-60                             |
| 85%            | 61-70                             |

### Practical Advice for Exam Takers
In general, we would advise two tactics for exam takers:
1. Prepare for the exam
2. Understand the exam

Each exam covers the content from the course, so it follows that reading the course materials, watching any videos, and doing exercises will all be incredibly helpful. Using effective learning strategies will also give learners an advantage.

Second, we recommend understanding the exam. The OffSec help site provides detailed descriptions of each exam, including what exam takers can expect and useful tips about how to approach enumeration tasks or submit proof that you were able to perform the required tasks

In addition to this particular resource, there are webinars, searchable blog posts, and YouTube videos of former learners reviewing their exam experiences
+ Heading into the exam with a clear understanding about what exactly it entails will not only reduce stress, but also improve performance

## Practical Steps 

### Creating a Long Term Strategy 
Choosing a particular focus, Course, or Learning Path is a critical first step to creating a long term strategy
+ Having specific goals will help guide your decisions in terms of how much, when, and what Modules you choose to study

It's entirely possible that a few weeks into this plan you will need to adjust it or change it, and that's fine. In fact, the best plans often need to be adjusted over time. The alternative - having no plan at all - would mean studying in an ad hoc manner, picking up (and putting down) materials whenever convenient

Planning can also greatly reduce stress levels
+ planning helps us to create an idea of what will happen rather than allowing it to happen to us. This helps with feeling more in control of a situation and reduces anxiety

Unfortunately, the saying, "failing to plan is planning to fail" is often true, and we can sometimes set ourselves up for a very emotionally taxing and stressful failure

### Use Time Allotment Strategies
One of the most impactful strategies is distributing study time over multiple sessions instead of cramming as much studying as possible into long sessions
+ This strategy, called Spaced Practice, requires looking at a calendar, finding reasonable time slots, and sticking to a schedule. In addition to avoiding "marathon" sessions whenever possible, there are a few things to consider when choosing the best times to schedule studying

Some research has suggested that before sleep might be a great time to study
+ The danger here is that it is quite easy to push back the bedtime to continue studying
+ Intuitively, we might think that we are being more productive by staying up later and studying more, but a lack of sleep can negatively impact our brain's ability to retain information
+ Planning study time also means planning an end to the studying
+ If sleep is important for studying, a learner might correctly assume that exercise is as well
+ Intense physical activity increases blood to flow to the brain, and fires neurons in the hippocampus (the center for memory)
+ In addition to generally improving brain health, exercising either before or after studying can be highly beneficial to improving memory and recall

### Narrowing our Focus 
Now that we know to schedule study time on our calendar, let's consider how to organize our physical space
+ To that end, we need to address a significant problem: multitasking
	+ Study after study has shown the negative impact that multitasking has on learning, job performance, and even brain health in general. Sometimes we feel like we can accomplish more by doing more things at once, but this simply isn't true
+ Creating a productive study space isn't just about only doing one thing at a time, but it's also about minimizing extra noise
+ Even though listening to music may not seem like much of a distraction at the time, processing this background noise still takes up a finite amount of mental space
+ Studies show that in general, listening to music - especially fast music with lyrics - while studying gets in the way of learning
	+ However, there is some additional research that suggests certain types of music (slow, instrumental music, in particular), may be actually helpful to some
+ In cases where it is actually helpful, it's entirely possible that music is blocking out other, even more distracting sounds (a learner in a coffee shop may find it easier to focus with headphones that cancel out the surrounding conversations, for example)
+ It's also reasonable to do what we can to make the study space one that we feel comfortable in and one that we enjoy spending time in
+ More to the point, interruptions caused by phone alerts, text messages, emails, and individuals who might need our attention are another form of multitasking 
	+ Small habits, like putting your phone in airplane mode or choosing a relatively isolated place for study, can help sharpen focus

### Pick a Strategy
As with choosing a time and a location, it's okay to change strategies mid-stream
+ It's also okay to come up with and iteratively improve on a pattern that works individually

In the case of OffSec materials, some learners may want to read first, then watch the videos, or vice versa
+ Some learners may want to preview the challenge exercises before reading the material
+ Others may want to follow along with the text on a local or virtual machine, moving one command at a time

No matter which strategy we select, it's important to have a plan in place and actively think about it. It's very difficult to assess whether or not a strategy is successful without recognizing what that strategy actually is

### Find a Community of Co-Learners
There are numerous benefits to studying as part of a community of learners, not least of which is the opportunity to develop an entirely new set of soft skills
+ Group work is often used by educators as a way to encourage learners to learn the social skills required in a collaborative environment
+ Even if one hopes to work as a sole-proprietor and not have any co-workers, the tools learned when working as part of a group can be immensely helpful to one's professional career
+ In addition to social skills, there's a major benefit to being responsible for explaining ideas to co-learners who might be struggling. This is at the core of the *Feynman Technique* that we reviewed earlier
+ Finally, there is something to be said for the camaraderie and the sheer enjoyment of being part of a group of co-learners, sharing the ups and downs of a course
	+ A German proverb, "_Geteiltes Leid ist halbes Leid_", roughly translated means "A problem that is shared is half of a problem."

OffSec learners may want to reach out to local information security groups or coworkers to create their own study cohort. The OffSec Discord server also provides a way to collaborate and learn together with other learners across the globe
+ Discord participants also have access to course alumni, OffSec learner Mentors, and staff

### Study Your Own Studies
Let's wrap up this Module by examining our responsibility not just for learning, but the assessment of that strategy
+ Since many of the details of how a "classroom" is constructed is up to you (the learner), you are also responsible for assessing and improving on that strategy

While this might sound like a lot, let's review an easy and effective approach: at the end of a study session, take just 10 seconds to think about how well it went
+ It's a very small thing, but it can make a huge difference
+ To understand how, we'll look at the two most obvious and extreme outcomes of a study session

If the study session was particularly difficult, this moment of self-reflection might lead you to think about some of the content that made it difficult
+ Generally speaking, we want to ask why it was difficult. The easy answer here might be "that SQL Injection is just tough!" but the difficulty of the material is at least somewhat out of our hands (though this might indicate a need to spend the next study session reviewing some more foundational materials)

Here is a list of potential questions to ask about the study session:
1. What time did I start the study session?
2. How long was the study session?
3. Did I get interrupted (if so, how did that happen)?
4. What did I do just before I started studying?
5. What did I eat or drink before I started studying?
6. What was my study location like? Was it quiet or busy?
7. What did I do during the study session specifically?

The opposite scenario. Let's say that we finish a study session and we feel great about how it went. Again, it might be easy to say, "That went really well because I'm fascinated by SQL Injection," but we should think beyond the content itself.
+ In this case, the answers to these questions may reveal keys to future successful study sessions
+ Let's say we studied for one hour in the morning after a light breakfast at the dining room table with a cup of coffee, using our own version of the Feynman Technique
+ If that led to a successful session, it's worth making a note of this and then planning the next study session to recreate as much of the scenario as possible

# Report Writing for Penetration Testers 

## Understanding Note-Taking

### Penetration Testing Deliverables
A penetration test or red team exercise is difficult to script in advance
+ This is because the tester cannot consistently anticipate exactly what kind of machines or networks the client will want to be tested
+ **Note**: Even though the outcome of our assessment is ofter unpredictable, is is often recommended to define a detailed _scope_ during the preliminary meetings with the customer
	+ This process is especially very helpful when prioritizing business critical targets within large networks

While the general execution plan for a penetration test will often follow a particular model, most pentests tend to follow the maxim "no plan survives first contact with the enemy"
+ This means that any specific activities we might expect to perform during the engagement might not actually happen, since the reality of the testing environment is almost certainly different than our initial ideas and hypotheses about it
+ It's therefore difficult to report on penetration tests using pre-populated forms

As such, instead of preparing a report in advance, the penetration test is executed and notes are taken as it proceeds to ensure that there is a detailed record of what was done
+ the penetration test can be repeated if it becomes necessary to demonstrate that an issue is real
+ the penetration test can be repeated after remediation to confirm that an issue has been fixed
+ if there's a system failure during the period of the penetration test, the client and tester can determine if the testing was the cause of the failure

During a penetration test, some activities may not be permitted
+ have to be very clear about the _Rules of Engagement_ (RoE), under which testing is done 
+ When conducting red team testing, a person will often be assigned the role of "referee" to ensure that the rules of engagement are observed
+ There may be constraints placed on testing such as not carrying out denial of service attacks, or not engaging in social engineering
+ Furthermore, the testing work may be in response to the client's regulatory compliance requirements and may need to follow a specific methodology such as the OWASP Penetration Testing Execution Standard: https://owasp.org/www-project-web-security-testing-guide/latest/3-The_OWASP_Testing_Framework/1-Penetration_Testing_Methodologies

### Note Portability 
Portability of penetration testing notes means being able to pass those notes on to others
+ Writing notes that are concise and coherent is an integral part of successful note-taking, and enables the notes to be used not only by ourselves but also by others
+ Additionally, concise notes can be quickly adapted for technical reporting
+ The need for portability is particularly emphasized when a penetration tester has to leave an engagement because of sickness, illness, or other issues
+ Having a shared understanding of how notes should be taken is especially important for large penetration testing teams, where individuals need to be able to understand the details of other team members' engagements at will

### The General Structure of Penetration Testing Notes
We need to take a structured approach to note-taking that is both concise and precise, here are some principles that often useful to consider:
- Rather than taking a few general notes assuming that we'll remember how to perform certain actions next time, we should record exactly what we did.
- This means that every command that we type, every line of code that we modify, and even anywhere we click in the GUI should be recorded so that we can reproduce our actions.
- Even if we've taken a lot of notes, if looking at them later doesn't help us remember exactly what happened during the assessment, then they won't be particularly useful to us.
- The notes need to be structured and sufficiently detailed to remove any ambiguity.
- To write a convincing and substantiated technical report later, we need to provide sufficient technical details within our notes.
- If the notes are not written coherently, it will be difficult for someone else to repeat the test and get the same results.

A note-taking structure that starts broad and drills down into each section is an easy and expandable method of taking notes
+ The top-down approach guides us to start with the broadest activity, and then narrow down our focus and expand the level of detail until we have everything we need to replicate exactly what happened

Let's now look at an example of the notes we might take for a web vulnerability we discovered:
- **Application Name**: This is important in a multi-application test, and a good habit to get into. The application names also lends itself to building a natural folder and file structure quite nicely.
- **URL**: This is the exact URL that would be used to locate the vulnerability that we've detected.
- **Request Type**: This represents both the type of request (i.e: GET, POST, OPTIONS, etc) that was made, as well as any manual changes we made to it. For example, we might intercept a POST request message and change the username or password before forwarding it on.
- **Issue Detail**: This is the overview of the vulnerability that will be triggered by our actions. For example, we may point to a CVE describing the vulnerability if one exists, and/or explain the impact we observe. We may categorize the impact as denial of service, remote code execution, privilege escalation, and so on.
- **Proof of Concept Payload**: This is a string or code block that will trigger the vulnerability. This is the most important part of the note, as it is what will drive the issue home and allow it to be replicated. It should list all of the necessary preconditions, and provide the exact code or commands that would need to be used to perform the triggers the vulnerability again.

Let’s get more specific and review an example of testing for a _Cross-Site Scripting_ (XSS) vulnerability. The target we tested has a web page aptly named **XSSBlog.html**:
``` Markdown
Testing for Cross-Site Scripting 

Testing Target: 192.168.1.52 
Application:    XSSBlog
Date Started:   31 March 2022

1.  Navigated to the application
    http://192.168.1.52/XSSBlog.html
    Result: Blog page displayed as expected
    
2.  Entered our standard XSS test data: 
    You will rejoice to hear that no disaster has accompanied the
    commencement of an enterprise which you have regarded with such
    evil forebodings.<script>alert("Your computer is infected!");</script> 
    I arrived here yesterday, and my first task is to assure my dear
    sister of my welfare and increasing confidence in the success of
    my undertaking. 

3.  Clicked Submit to post the blog entry.
    Result: Blog entry appeared to save correctly.

4.  Navigated to read the blog post
    http://192.168.1.52/XSSRead.php
    Result: The blog started to display and then the expected alert popped up.

5.  Test indicated the site is vulnerable to XSS.

PoC payload: <script>alert(‘Your computer is infected!’)</script>
```
+ We now have a simple, fast, and expandable way to take coherent and comprehensive notes that another tester can follow
+ It's worth repeating that the notes are not themselves the report we will deliver to the client, but they will be invaluable when we attempt to put our report together later

### Choosing the Right Note-Taking Tool
To decide on the right tool for a particular engagement, it is important to understand some requirements
+ In many cases we want to keep all information local to the computer rather than uploading it anywhere else, so certain tools are precluded from being used
+ By the same token, if an engagement is source-code heavy then a tool that does not allow for code blocks to be inserted is not going to be appropriate

While a comprehensive list of desirable properties to keep in mind is nearly impossible to enumerate, some of the more important items to remember are:
- **Screenshots**: If a lot of screenshots are necessary, consider a tool that allows for inline screenshot insertion.
- **Code blocks**: Code blocks need formatting to be properly and quickly understood.
- **Portability**: Something that can be used cross-OS, or easily transferred to another place should be high on the list of priorities.
- **Directory Structure**: In an engagement with multiple domains or applications, keeping a coherent structure is necessary. While manually setting up a structure is allowed, a tool that can do this automatically makes things easier. 

_Sublime_ is a pretty standard text editor that adds lots of useful features and functionality. One of the most important features it provides is flexible syntax highlighting. Syntax highlighting allows us to place code blocks into a file, and those code blocks will be highlighted according to the programming language's specific syntax rules. However, this often comes with limitations. Highlighting two languages is not possible with one file. In an engagement with a single code type, this is not a problem, but for others, we may prefer to use different options. Additionally, it's not currently possible to inline screenshots at the time of writing.

Another tool we can consider is _CherryTree_. This tool comes as standard in Kali. It contains many of the features that are necessary for note-taking. It uses an SQLite database to store the notes we take, and these can be exported as HTML, PDF, plain text, or as a CherryTree document. CherryTree comes with a lot of built-in formatting, and provides a tree structure to store documents, which it calls "nodes" and "subnodes".

_Obsidian_ markdown editor, which contains all the features that we need for note-taking. We can install Obsidian as a snap application or in its Flatpak application form. It also comes as an AppImage, meaning that all we need to do is copy it into our system, mark it as executable, and run it.
+ Obsidian stores information in a _Vault_, which is a folder on our system. We can create both markdown files and folders within the Vault. Obsidian's features include a live preview of markdown text, in-line image placement, code blocks, and a multitude of add-ons such as a community-built CSS extension
+ An Obsidian vault can be relocated to another computer and opened from the Welcome menu. Markdown files can simply be dropped into the Vault folders, which will automatically be recognized by Obsidian
+ The use of markdown means that we can provide syntax and formatting that is easily copied to most report generation tools, and a PDF can be generated straight from Obsidian itself

### Taking Screenshots
A good screenshot can explain the issue being discussed at a glance and in more detail than a textual description
+ Screenshots are particularly useful to help present a technically complex or detail-heavy section of a report
+ As the saying goes, a picture is worth 1000 words. Conversely, a bad screenshot can obfuscate and draw attention away from what the issue is
+ For example, it's more effective to show a screenshot of an alert box popping up from an XSS payload than to describe it in words. However, it's more difficult to use a screenshot to describe exactly what's happening when we use something like a buffer overflow payload

We can use screenshots to supplement our note-taking or to include them in our report to illustrate the steps we took, which will help another tester reproduce the issues
+ However, we need to be conscious of the audience. While a penetration tester may consider an alert window to demonstrate XSS as perfectly self-explanatory, developers unfamiliar with the vulnerability may not understand its true cause or impact
+ It's good practice to always support a screenshot with text

There are several pitfalls we should avoid when using screenshots
+ Must ensure there isn't more than one concept illustrated in each screenshot
+ Must ensure the impact is framed properly in the screenshot
+ The caption for the screenshot shouldn't be overly long

To recap, a good screenshot has the following characteristics:
- is legible
- contains some visual indication that it applies to the client
- contains the material that is being described
- supports the description of the material
- properly frames the material being described

On the other hand, a bad screenshot is one that:
- is illegible
- is generic rather than client-specific
- contains obfuscated or irrelevant information
- is improperly framed

Under the screenshot, we include a caption. A caption is not meant to provide additional context for the picture. A caption is there to describe the picture in a few words. Any additional context that is necessary can be provided in a separate paragraph. In most cases, eight to ten words is an appropriate maximum for a caption.

### Tools to Take Screenshots
Can take screenshots using native operating system capabilities
+ Windows, Linux, and macOS all provide tools to take screenshots, can also use special-purpose tools

For **Windows**, the PrintScreen key allows us to take a copy of the full screen, and _Alt/PrtSc_ takes a screenshot of the currently active window. This can then be pasted into a Paint, Word, or PowerPoint document and manipulated as required. We'll often want to crop the image to remove any unwanted material, and we can do that in these applications
+ We can also invoke the Windows _Snipping Tool_ by pressing the Windows key together with Shift/S.

**MacOS** provides the capability to take a screenshot using the keyboard Shift/Command combination with the numeric keys 3, 4, or 5 key. To select and save the entire screen, we can use F+B+3. To highlight and select a specific area on the screen, we can simply use F+B+4 or F+B+5.

We can take a screenshot in **Linux** using the PrintScreen key. This will capture and save the entire screen to the user’s **Images/ directory**. B+PrintScreen will allow for area highlighting and selection. In Kali Linux, we can also use the _Screenshot_ tool which is installed by default and comes with many options such as choosing the active window, selecting a region, adding a delay before taking the actual screenshot, etc

_Flameshot_ is an OS-agnostic, open-source, feature-rich screen-capturing tool. It comes with both a command-line and GUI interface and has integrated drawing tools to add highlights, pixelation, text, and other modifications to the captured image

## Writing Effective Technical Penetration Testing Reports

### Purpose of Technical Report 
As vendors of a penetration testing service, we want to provide our clients with as much value as possible
+ Reports are the mechanism by which value is delivered and the main artifact that enables the client to take forward action
+ Our ability to find twenty vulnerabilities in a web application won’t make a business impact if we can't provide a presentation of both the vulnerabilities and our recommendations on potential remediation
+ Without a clear direction forward, the client is not getting full value for their time and money

To properly prepare a report for the client, we must understand two things:
1. The purpose of the report
2. How we can deliver the information we've collected in a way that the audience can understand

When a client pays for a penetration testing engagement, it is often (mis)understood that they are "just" paying for an ethical hacker to legally attack their infrastructure to find and exploit weaknesses
+ While that may be technically necessary to deliver the required results, it is not the fundamental purpose of the engagement
+ There are even some cases in which clients would prefer not to have their infrastructure attacked at all

So, what is the point of a company engaging a penetration tester?
+ The end goal is for the client to be presented with a path forward that outlines and highlights all the flaws that are currently present in their systems within the scope of the engagement, ways to fix those flaws in an immediate sense, and strategic goals that will prevent those vulnerabilities from appearing in the future
+ This output is often provided in the form of a penetration testing report. As far as the client is concerned, the report is (usually) the only deliverable of the engagement that truly matters

We might wonder how we ought to report on the parts of our engagement where we haven't found any vulnerabilities
+ In many cases where we don't find vulnerabilities, we should avoid including too many technical details on what we did in the report
+ A simple statement that no vulnerabilities have been found is often sufficient
+ We should ensure that we don't confuse the client with the technical details of our attempts, as this will undermine the value of the issues we did actually find It's the tester’s job to present that information in a way that is easy to understand and act upon
+ That said, some clients may prefer verbose and deep technical reports even on non-issues, which leads to another consideration: the **audience**

The client receiving the report is an expert in their own specific industry
+ They will often (though not always) be aware of the security concerns of that industry and will expect us to have done our homework to also be aware of them
+ this means having a deep understanding of what would cause concern to the client in the event of an attack. In other words, understanding their key business goals and objectives
+ This is another reason why being clear on the Rules of Engagement is so important, because it gives us a window into the client's core concerns

All issues discovered in the course of testing should be documented but we will want to highlight any issues we find that would affect these key areas
+ Examples of client-specific key areas of concern could include **HIPAA**, which is a framework that governs medical data in the US, and **PCI**, which is a framework that governs credit card and payment processing
+ As we begin to record our findings, we'll need to keep in mind the situation under which the vulnerability may be exploited and its potential impact
	+ A clear text HTTP login on the internet is considered extremely unsafe. On an internal network, while still unsafe, it is less concerning given that more steps must be accomplished to properly exploit it

As report writers, we must present useful, accurate, and actionable information to the client without inserting our own biases

### Tailor the Content 
We must deliver skill-appropriate content for all the readers of our report
+ It may be read by **executives**, the **heads of security**, and by **technical members of the security team**
+ This means we want to not only provide a simple overview of the issues for the executives, but we will also want to provide sufficient technical detail for the more technical readers

We can do this by splitting up content into an appropriate structure of sections and subsections
+ The number of audiences we have for a particular engagement depends heavily on our relationship with the client, their size, budget, and maturity

#### Management level 
we'll consider an engagement for which we have only two target audiences. The first, and arguably the more important, is the **management level**
+ This is often the level at which many external engagement contracts are signed and where the value of investing in the testing needs to be highlighted
+ Depending on the business, this may be C-level functions (CISO, CSO, CFO, etc), or department heads of IT or security
+ However, most executives and upper-level directors will not necessarily have the technical ability to follow a detailed technical explanation
	+ We should provide them with a section that highlights the outcome and impact of the engagement in a way that accurately reports on the vulnerabilities found while not being overloaded with technical details

#### Technical level
The second audience we will consider is made up of the **technical staff** who have the technical knowledge to understand the report and implement the remediations outlined for the vulnerabilities that have been identified
+ This audience must be provided with enough technical detail to enable them to understand what is wrong, what the impact of each finding is, and how they can be fixed
+ In addition, this audience greatly benefits when we can provide advice on how to prevent similar types of issues from occurring in the future

### Executive Summary 
The first section of the report should be an **Executive Summary**
+ This enables senior management to understand the scope and outcomes of the testing at a sufficient level to understand the value of the test, and to approve remediation

#### Executive Summary Snapshot
We start with the quick bite-sized pieces of information that provide the big picture (Snapshot Executive Summary), and follow that up with the full Executive Summary

##### Breakdown
The Executive Summary Snapshot can generally be broken down as follows:
1. The Executive Summary should start with **outlining the scope of the engagement**, having a clear scope agreed upon in advance of the testing defines the bounds of what will be covered
2. We then **want to be very clear as to what exactly was tested and whether anything was dropped from the scope**
	+ Timing issues, such as insufficient testing time due to finding too many vulnerabilities to adequately report on, should be included to ensure that the scope statement for any subsequent test is appropriate
	+ Including the scope statement in the report protects the penetration tester from any suggestion of not having completed the required testing
	+ It also gives the client a more accurate model of what is practical given the budget and time constraints that were initially set
3. Want to include the **time frame of the test**. This includes the length of time spent on testing, the dates, and potentially the testing hours as well
4. Refer to the **Rules of Engagement** and reference the **referee report** if a referee was part of the testing team
	+ If denial of service testing was allowed, or social engineering was encouraged, that should be noted here. If we followed a specific testing methodology, we should also indicate that here
5. Include supporting infrastructure and accounts
	+ Using the example of a web application, if we were given user accounts by the client, include them here along with the IP addresses that the attacks came from (i.e our testing machines)
	+ We should also note any accounts that we created so the client can confirm they have been removed. 

##### Example 
``` Markdown
Executive Summary:

- Scope: https://kali.org/login.php
- Timeframe: Jan 3 - 5, 2022
- OWASP/PCI Testing methodology was used
- Social engineering and DoS testing were not in scope
- No testing accounts were given; testing was black box from an external IP address
- All tests were run from 192.168.1.2"
```

#### Long-form Executive Summary
This is a written summary of the testing that provides a high-level overview of each step of the engagement and establishes severity, context, and a "worst-case scenario" for the key findings from the testing
+ It's important not to undersell or oversell the vulnerabilities
+ We want the client's mental model of their security posture to be accurate
	+ For example, if we've found an SQL injection that enables credit card details to be stolen, then that represents a very different severity than if we've found an authentication bypass on a system hosting public data. We would certainly emphasize the former in the Executive Summary, but we may not highlight the latter in this section

We should make note of any trends that were observed in the testing to provide strategic advice. The executive doesn't need to be given the full technical details in this section, and technical staff will be able to find them as each vulnerability will be expanded upon in later sections of the report
+ What we can do, however, is to describe the trends we've identified and validate our concerns with summaries of one or two of the more important related findings

To highlight trends, we want to group findings with similar vulnerabilities
+ Many vulnerabilities of the same type generally show a failure in that particular area
+ For example, if we find stored and reflected XSS, along with SQL injection and file upload vulnerabilities, then user input is clearly not being properly sanitized across the board
+ This must be fixed at a systemic level. This section is an appropriate place to inform the client of a systemic failure, and we can recommend the necessary process changes as the remediation. In this example, we may encourage the client to provide proper security training for their developers

It is useful to mention things that the client has done well
+ This is especially true because while management may be paying for the engagement, our working relationship is often with the technical security teams
+ We want to make sure that they are not personally looked down upon. Even those penetration tests that find severe vulnerabilities will likely also identify one or two areas that were hardened
+ Including those areas will soften the impact on people, and make the client more accepting of the report as a whole

##### Breakdown
The Long-form Executive Summary can generally be broken down as follows:
1. Include a few sentences **describing the engagement**
2. Add several sentences that talk about some effective hardening we observed
	+ Careful language should be used here
	+ We do not say something like "It was _impossible_ to upload malicious files", because we cannot make absolute claims without absolute evidence
	+ We must be careful to make sure our language does not preclude the possibility that _we_ were simply unable to find a flaw that does actually exist and remains undetected
3. Introduce a discussion of the vulnerabilities discovered
	+ Several paragraphs of this type may be required, depending on the number and kind of vulnerabilities we found. Use as many as necessary to illustrate the trends, but try not to make up trends where they don't exist
4. Finally the Executive Summary should conclude with an engagement wrap-up

##### Example
Describing the Engagement
```
- "The Client hired OffSec to conduct a penetration test of
their kali.org web application in October of 2025. The test was conducted
from a remote IP between the hours of 9 AM and 5 PM, with no users
provided by the Client."
```

Identifying positives 
```
- "The application had many forms of hardening in place. First, OffSec was unable to upload malicious files due to the strong filtering
in place. OffSec was also unable to brute force user accounts
because of the robust lockout policy in place. Finally, the strong
password policy made trivial password attacks unlikely to succeed.
This points to a commendable culture of user account protections."
```

Explaining a vulnerability
```
- "However, there were still areas of concern within the application.
OffSec was able to inject arbitrary JavaScript into the browser of
an unwitting victim that would then be run in the context of that
victim. In conjuction with the username enumeration on the login
field, there seems to be a trend of unsanitized user input compounded
by verbose error messages being returned to the user. This can lead
to some impactful issues, such as password or session stealing. It is
recommended that all input and error messages that are returned to the
user be sanitized and made generic to prevent this class of issue from
cropping up."
```

Concise conclusion 
```
"These vulnerabilities and their remediations are described in more
detail below. Should any questions arise, OffSec is happy
to provide further advice and remediation help."
```

#### Remedition 
We should mention here that not all penetration testers will offer remediation advice, and not all clients will expect it. That said, we believe that the most effective relationships are those between clients and vendors that do work on that level together

### Testing Environment Considerations

The first section of the full report should detail any issues that affected the testing
+ This is usually a fairly small section
+ At times, there are mistakes or extenuating circumstances that occur during an engagement
+ While those directly involved will already be aware of them, we should document them in the report to demonstrate that we've been transparent

It is our job as penetration testers and consultants to inform the client of all circumstances and limitations that affected the engagement
+ This is done so that they can improve on the next iteration of testing and get the most value for the money they are paying
+ It is important to note that not every issue needs to be highlighted, and regardless of the circumstances of the test, we need to ensure the report is professional

We'll consider three potential states with regard to extenuating circumstances 
- **Positive Outcome**: "There were no limitations or extenuating circumstances in the engagement. The time allocated was sufficient to thoroughly test the environment."
- **Neutral Outcome**: "There were no credentials allocated to the tester in the first two days of the test. However, the attack surface was much smaller than anticipated. Therefore, this did not have an impact on the overall test. OffSec recommends that communication of credentials occurs immediately before the engagement begins for future contracts, so that we can provide as much testing as possible within the allotted time."
- **Negative Outcome**: "There was not enough time allocated to this engagement to conduct a thorough review of the application, and the scope became much larger than expected. It is recommended that more time is allocated to future engagements to provide more comprehensive coverage."

The considerations we raise in this section will allow both us and the client to learn from mistakes or successes on this test and apply them to future engagements

### Technical Summary 
Should be a list of all of the key findings in the report, written out with a summary and recommendation for a technical person, like a security architect, to learn at a glance what needs to be done

This section should group findings into common areas. For example, all weak account password issues that have been identified would be grouped, regardless of the testing timeline. An example of the structure of this section might be:
- User and Privilege Management
- Architecture
- Authorization
- Patch Management
- Integrity and Signatures
- Authentication
- Access Control
- Audit, Log Management and Monitoring
- Traffic and Data Encryption
- Security Misconfigurations

An example of a technical summary for Patch Management is as follows:
``` Markdown
4. Patch Management

Windows and Ubuntu operating systems that are not up to date were
identified. These are shown to be vulnerable to publicly-available
exploits and could result in malicious execution of code, theft
of sensitive information, or cause denial of services which may
impact the infrastructure. Using outdated applications increases the
possibility of an intruder gaining unauthorized access by exploiting
known vulnerabilities. Patch management ought to be improved and
updates should be applied in conjunction with change management.
```
+ The section should finish with a risk heat map based on vulnerability severity adjusted as appropriate to the client's context, and as agreed upon with a client security risk representative if possible

### Technical Findings and Recommendation 
The Technical Findings and Remediation section is where we include the full technical details relating to our penetration test, and what we consider to be the appropriate steps required to address the findings
+ While this is a technical section, we should not assume the audience is made up of penetration testers

Not everyone, even those who work within the technologies that were being tested, will fully understand the nuances of the vulnerabilities
+ While a deep technical dive into the root causes of an exploit is not always necessary, a broad overview of how it was able to take place should usually be provided
+ It is better to assume less background knowledge on behalf of the audience and give too much information, rather than the opposite

This section is often presented in tabular form and provides full details of the findings
+ A finding might cover one vulnerability that has been identified, or may cover multiple vulnerabilities of the same type

It's important to note that there might be a need for an **attack narrative**
+ This narrative describes, in story format, exactly what happened during the test
+ This is typically done for a simulated threat engagement, but is also useful at times to describe the more complex exploitation steps required for a regular penetration test
+ If it is necessary, then writing out the attack path step-by-step, with appropriate screenshots, is generally sufficient
+ An extended narrative could be placed in an Appendix and referenced from the findings table

#### Entry Examples 

| REF | RISK | ISSUE DESCRIPTION AND IMPLICATIONS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | RECOMMENDATIONS                                                                                                                                                                                                                                                       |
| --- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | H    | Account, Password, and Privilege Management is inadequate. Account management is the process of provisioning new accounts and removing accounts that are no longer required. The following issues were identified by performing an analysis of 122,624 user accounts post-compromise: 722 user accounts were configured to never expire; 23,142 users had never logged in; 6 users were members of the domain administrator group; default initial passwords were in use for 968 accounts.                                                                                                                                                                                                                                                                                                                                                            | All accounts should have passwords that are enforced by a strict policy. All accounts with weak passwords should be forced to change them. All accounts should be set to expire automatically. Accounts no longer required should be removed.                         |
| 2   | H    | Information enumerated through an anonymous SMB session. An anonymous SMB session connection was made, and the information gained was then used to gain unauthorized user access as detailed in Appendix E.9.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | To prevent information gathering via anonymous SMB sessions: Access to TCP ports 139 and 445 should be restricted based on roles and requirements. Enumeration of SAM accounts should be disabled using the Local Security Policy > Local Policies > Security Options |
| 3   | M    | Malicious JavaScript code can be run to silently carry out malicious activity. A form of this is reflected cross-site scripting (XSS), which occurs when a web application accepts user input with embedded active code and then outputs it into a webpage that is subsequently displayed to a user. This will cause attacker-injected code to be executed on the user's web browser. XSS attacks can be used to achieve outcomes such as unauthorized access and credential theft, which can in some cases result in reputational and financial damage as a result of bad publicity or fines. As shown in Appendix E.8, the [client] application is vulnerable to an XSS vulnerability because the username value is displayed on the screen login attempt fails. A proof-of-concept using a maliciously crafted username is provided in Appendix E. | Treat all user input as potentially tainted, and perform proper sanitization through special character filtering. Adequately encode all user-controlled output when rendering to a page. Do not include the username in the error message of the application login.   |

It's important to understand that what we identify as the severity of an issue based on its vulnerability score not its context-specific business risk
+ It only represents technical severity, even if we adjust it based on likelihood
+ We can reflect this in our findings as technical severity, or we can work with the client's risk team to gain an understanding of the appropriate level of business risk by including consideration of the unique business impact to the client

We can start our findings description with a sentence or two describing what the vulnerability is, why it is dangerous, and what an attacker can accomplish with it
+ This can be written in such a way to provide insight into the immediate impact of an attack
+ We then describe some of the technical details about the vulnerability
+ There is often no need to go into overwhelming detail; simply explain at a basic level what the vulnerability is and how to exploit it
+ The intention is to describe a complex exploit in a way that most technical audiences can understand

We also need to include evidence to prove the vulnerability identified is exploitable, along with any further relevant information
+ If this is simple, it can be included inline as per the first entry above. Otherwise, it can be documented in an appendix as shown in the second entry

Once the details of the vulnerability have been explained, we can describe the specific finding that we have identified in the system or application
+ We will use the notes that we took during testing and the screenshots that support them to provide a detailed account
+ Although this is more than a few sentences, we'll want to summarize it in the table and reference an appendix for the full description

It's good practice to use our notes and screenshots to walk the reader through how we achieved the result step-by-step
+ The screenshots should contain a short explanation of what it shows, we should not rely on the screenshot to speak for itself
+ We should present the impact of the vulnerability in a way that frames its severity for the client in an appropriate manner, and is directly relevant to the business or application

The remediation advice should be detailed enough to enable system and application administrators to implement it without ambiguity
+ The remediation should be clear, concise, and thorough
+ It should be sufficient to remove the vulnerability in a manner acceptable to the client and relevant to the application
+ Presenting remediation that is excessive, unacceptably costly, or culturally inappropriate (e.g. not allowing remote logins for a remote working environment) will lead to the fix never being implemented. A strong understanding of the needs of the client is necessary here

There are several other important **items to keep in mind**
+ *First*, broad solutions should be avoided, in favor of things that drill down into the specifics of the application and the business
+ *Second*, theoretical solutions are not effective in combating a vulnerability. Make sure that any solution given has a concrete and practical implementation
+ *Finally*, do not layer multiple steps into one proposed solution. Each distinct step should be its own solution

The Technical Findings and Recommendations section will likely be the major part of the report and the time and effort invested in writing it should reflect its importance
+ In describing the findings, we will present the means of replicating them, either in the body of the report or in an appendix
	+ We need to show exactly where the application was affected, and how to trigger the vulnerability
	+ A full set of steps to replicate the finding should be documented with screenshots
	+ This includes steps that we take for granted (such as running with administrative privileges), as these may not be obvious to the reader

The details should be separated into two sections:
1. The affected URL/endpoint
2. A method of triggering the vulnerability

If multiple areas are affected by the vulnerability, we should include a reference to each area
+ If there is a large number of similar issues, then it's often acceptable to provide samples with a caveat that these are not the only areas where the issue occurs. In the latter case, we would recommend a systemic remediation

### Appendices, Further Information, and References
The final part of the report is the _Appendices_ section
+ Things that go here typically do not fit anywhere else in the report, or are too lengthy or detailed to include inline
+ This includes long lists of compromised users or affected areas, large proof-of-concept code blocks, expanded methodology or technical write-ups, etc 
+  A good rule to follow is if it's necessary for the report but would break the flow of the page, put it in an appendix

We may wish to include a _Further Information_ section
+ In this section, we'd include things that may not be necessary for the main write-up but could reasonably provide value for the client
+ Examples would include articles that describe the vulnerability in more depth, standards for the remediation recommendation for the client to follow, and other methods of exploitation
+ If there is nothing that can add enough value, there is no reason to necessarily include this section

_References_ can be a useful way to provide more insight for the client in areas not directly relevant to the testing we carried out
+ When providing references, we need to ensure we only use the most authoritative sources, and we should also ensure that we cite them properly