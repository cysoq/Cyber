# Active Directory Introduction and Enumeration
_Active Directory Domain Services_, often referred to as Active Directory (AD), is a service that allows system administrators to update and manage operating systems, applications, users, and data access on a large scale 
+ Active Directory is installed with a standard configuration, however, system administrators often customize it to fit the needs of the organization

From a penetration tester's perspective, Active Directory is very interesting as it typically contain a wealth of information
+ If we successfully compromise certain objects within the domain, we may be able to take full control over the organization's infrastructure

In this Learning Module, we will focus on the enumeration aspect of Active Directory
+ The information we will gather throughout the Module will have a direct impact on the various attacks we will do in the upcoming _Attacking Active Directory Authentication_ and _Lateral Movement in Active Directory_ Modules

## Active Directory - Introduction 
While Active Directory itself is a service, it also acts as a management layer
+ AD contains critical information about the environment, storing information about users, groups, and computers, each referred to as _objects_
+ Permissions set on each object dictate the privileges that object has within the domain

Configuring and maintaining an instance of Active Directory can be daunting for administrators, especially since the wealth of contained information often creates a large attack surface

The first step in configuring an instance of AD is to create a domain name such as _corp.com_ in which _corp_ is often the name of the organization itself
+ Within this domain, administrators can add various types of objects that are associated with the organization such as computers, users, and group objects
+ **NOTE**: An AD environment has a critical dependency on the _Domain Name System_ (DNS) service.
	+ As such, a typical domain controller will also host a DNS server that is authoritative for a given domain

To ease the management of various objects and assist with management, system administrators often organize these objects into _Organizational Units_ (OUs)

OUs are comparable to file system folders in that they are containers used to store objects within the domain
+ Computer objects represent actual servers and workstations that are domain-joined (part of the domain), and user objects represent accounts that can be used to log in to the domain-joined computers
+ In addition, all AD objects contain attributes, which will vary depending on the type of object
+ For example, a user object may include attributes such as first name, last name, username, phone number, etc

AD relies on several components and communication services
+ For example, when a user attempts to log in to the domain, a request is sent to a _Domain Controller_ (DC), which checks whether or not the user is allowed to log in to the domain
+ One or more DCs act as the hub and core of the domain, storing all OUs, objects, and their attributes
+ Since the DC is such a central domain component, we'll pay close attention to it as we enumerate AD

Objects can be assigned to AD groups so that administrators can manage those object as a single unit
+ For example, users in a group could be given access to a file server share or given administrative access to various clients in the domain
+ Attackers often target high-privileged groups

Members of _Domain Admins_ are among the most privileged objects in the domain
+ If an attacker compromises a member of this group (often referred to as _domain administrators_), they essentially gain complete control over the domain

This attack vector could extend beyond a single domain since an AD instance can host more than one domain in a _domain tree_ or multiple domain trees in a _domain forest_
+ While there is a Domain Admins group for each domain in the forest, members of the _Enterprise Admins_ group are granted full control over all the domains in the forest and have Administrator privilege on all DCs
+ This is obviously a high-value target for an attacker

We will leverage these and other concepts in this Module as we focus on the extremely important aspect of AD enumeration
+ This important discipline can improve our success during the attack phase
+ We will leverage a variety of tools to manually enumerate AD, most of which rely on the _Lightweight Directory Access Protocol_ (LDAP)
+ Once we've introduced foundational techniques, we will leverage automation to perform enumeration at scale

### Enumeration - Defining our Goals
Before we begin, let's discuss the scenario and define our goals

In this scenario, we'll enumerate the _corp.com_ domain
+ We've obtained user credentials to a domain user through a successful phishing attack
+ Alternatively, the target organization may have provided us with user credentials so that we can perform penetration testing based on an _assumed breach_
+ This would speed up the process for us and also give the organization insight into how easily attackers can move within their environment once they have gained initial access

The user we have access to is _stephanie_ who has remote desktop permissions on a Windows 11 machine that is a part of the domain
+ This user is not a local administrator on the machine, which is something we may need to take into consideration as we move along

During a real-world assessment, the organization may also define the scope and goals of the penetration test
+ In our case however, we are restricted to the _corp.com_ domain with the PWK labs. 
+ Our goal will be to enumerate the full domain, including finding possible ways to achieve the highest privilege possible (domain administrator in this case)

In this Module, we will perform the enumeration from one client machine with the low privileged _stephanie_ domain user
+ However, once we start performing attacks and we are able to gain access to additional users and computers, we may have to repeat parts of the enumeration process from the new standpoint
+ This perspective shift (or _pivot_) is critical during the enumeration process considering the complexity of permissions across the domain
+ Each pivot may give us an opportunity to advance our attack

For example, if we gain access to another low-privileged user account that seems to have the same access as _stephanie_, we shouldn't simply dismiss it
+ Instead, we should always repeat our enumeration with that new account since administrators often grant individual users increased permissions based on their unique role in the organization
+ This persistent "rinse and repeat" process is the key to successful enumeration and works extremely well, especially in large organizations

## Active Directory - Manual Enumeration
There are many ways to enumerate AD and a wide variety of tools we can use
+ In this Learning Unit, we will start enumerating the domain using tools that are already installed in Windows
+ We will start with the "low-hanging fruit", the information we can gather quickly and easily
+ Eventually, we will leverage more robust techniques such as invoking .NET classes using PowerShell to communicate with AD via LDAP

### Active Directory - Enumeration Using Legacy Windows Tools
Since we are starting in an _assumed breach_ scenario and we have credentials for _stephanie_, we will use those credentials to authenticate to the domain via a Windows 11 machine (CLIENT75)
+ We'll use the _Remote Desktop Protocol_ (RDP) with _xfreerdp_ to connect to the client and log in to the domain
+ We'll supply the user name with **/u**, the domain name with **/d** and enter the password, which in this case is _`LegmanTeamBenzoin!!`_:
```
xfreerdp /u:stephanie /d:corp.com /v:192.168.50.75
```

AD contains so much information that it can be hard to determine where to start enumerating
+ But since every AD installation fundamentally contains users and groups, we'll start there

To start gathering user information, we will use _net.exe_, which is installed by default on all Windows operating systems
+ More specifically, we will use the **net user** sub-command
+ While we can use this tool to enumerate local accounts on the machine, we'll instead use **/domain** to print out the users in the domain
+ Usage:
```
net user /domain
```
+ Example:
```
C:\Users\stephanie>net user /domain
The request will be processed at a domain controller for domain corp.com.

User accounts for \\DC1.corp.com

-------------------------------------------------------------------------------
Administrator            dave                     Guest
iis_service              jeff                     jeffadmin
jen                      krbtgt                   pete
stephanie
The command completed successfully.
```

The output from this command will vary depending on the size of the organization
+ Armed with a list of users, we can now query information about individual users

Administrators often have a tendency to add prefixes or suffixes to usernames that identify accounts by their function
+ Based on the output in Listing 2, we should check out the _jeffadmin_ user because it might be an administrative account
+ Let's inspect the user with **net.exe** and the **/domain** flag:
```
net user <USER> /domain
```
+ Example: 
```
C:\Users\stephanie>net user jeffadmin /domain
The request will be processed at a domain controller for domain corp.com.

User name                    jeffadmin
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            9/2/2022 4:26:48 PM
Password expires             Never
Password changeable          9/3/2022 4:26:48 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   9/20/2022 1:36:09 AM

Logon hours allowed          All

Local Group Memberships      *Administrators
Global Group memberships     *Domain Users         *Domain Admins
The command completed successfully.
```
+ According to the output, _jeffadmin_ is a part of the _Domain Admins_ group, which is something we should take note of
+ If we manage to compromise this account, we'll essentially elevate ourselves to domain administrator

We can also use **net.exe** to enumerate groups in the domain with **net group**:
+ Usage:
```
net group /domain
```
+ Example:
```
The request will be processed at a domain controller for domain corp.com.

Group Accounts for \\DC1.corp.com

-------------------------------------------------------------------------------
*Cloneable Domain Controllers
*Debug
*Development Department
*DnsUpdateProxy
*Domain Admins
*Domain Computers
*Domain Controllers
*Domain Guests
*Domain Users
*Enterprise Admins
*Enterprise Key Admins
*Enterprise Read-only Domain Controllers
*Group Policy Creator Owners
*Key Admins
*Management Department
*Protected Users
*Read-only Domain Controllers
*Sales Department
*Schema Admins
The command completed successfully.
```

The output includes a long list of groups in the domain
+ Some of these are installed by default, see defaults here: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups
+ Others, like those highlighted above, are custom groups created by the administrator
+ Let's enumerate a custom group first

We'll again use **net.exe** to enumerate the group members, this time focusing on the _Sales Department_ group
+ Usage:
```
net group <GROUP-NAME> /domain
```
+ Example:
```
PS C:\Tools> net group "Sales Department" /domain
The request will be processed at a domain controller for domain corp.com.

Group name     Sales Department
Comment

Members

-------------------------------------------------------------------------------
pete                     stephanie
The command completed successfully.
```
+ This reveals that _pete_ and _stephanie_ are members of the _Sales Department_ group

Although this doesn't seem to reveal much, each small piece of information gained through enumeration is potentially valuable
+ In a real-world assessment, we might enumerate each group, cataloging the results
+ This will require good organization, which we'll discuss later, but we'll move on for now as we have more flexible alternatives to net.exe to discuss in the next section

### Enumerating Active Directory using PowerShell and .NET Classes
There are several tools we can use to enumerate Active Directory. PowerShell cmdlets like _Get-ADUser_ work well but they are only installed by default on domain controllers as part of the _Remote Server Administration Tools_ (RSAT)
+ RSAT is very rarely present on clients in a domain and we must have administrative privileges to install them
+ While we can, in principle, import the DLL required for enumeration ourselves, we will look into other options

We'll develop a tool that requires only basic privileges and is flexible enough to use in real-world engagements
+ We will mimic the queries that occur as part of AD's regular operation
+ This will help us understand the basic concepts used in the pre-built tools we'll use later

Specifically, we'll use PowerShell and .NET classes to create a script that enumerates the domain
+ Although PowerShell development can seem complex, we'll take it one step at a time

In order to enumerate AD, we first need to understand how to communicate with the service
+ Before we start building our script, let's discuss some theory

AD enumeration relies on **LDAP**
+ When a domain machine searches for an object, like a printer, or when we query user or group objects, LDAP is used as the communication channel for the query
+ In other words, LDAP is the protocol used to communicate with Active Directory
+ LDAP is not exclusive to AD, other directory services use it as well

LDAP communication with AD is not always straight-forward, but we'll leverage an _Active Directory Services Interface_ (ADSI) (a set of interfaces built on _COM_) as an LDAP provider

According to Microsoft's documentation, we need a specific LDAP _ADsPath_ in order to communicate with the AD service
+ The LDAP path's prototype looks like this:
```
LDAP://HostName[:PortNumber][/DistinguishedName]
```
+ We need three parameters for a full LDAP path: _HostName_, _PortNumber_, and a _DistinguishedName_

Let's take a moment to break this down
+ The _Hostname_ can be a computer name, IP address or a domain name
+ In our case, we are working with the _corp.com_ domain, so we could simply add that to our LDAP path and likely obtain information
+ Note that a domain may have multiple DCs, so setting the domain name could potentially resolve to the IP address of any DC in the domain

While this would likely still return valid information, it might not be the most optimal enumeration approach
+ In fact, to make our enumeration as accurate as possible, we should look for the DC that holds the most updated information
+ This is known as the _Primary Domain Controller_ (PDC)
+ There can be only one PDC in a domain
+ To find the PDC, we need to find the DC holding the _PdcRoleOwner_ property
	+ We'll eventually use PowerShell and a specific .NET class to find this

The _PortNumber_ for the LDAP connection is optional as per Microsoft's documentation
+ In our case we will not add the port number since it will automatically choose the port based on whether or not we are using an SSL connection
+ However, it is worth noting that if we come across a domain in the future using non-default ports, we may need to manually add this to the script

Lastly, a _DistinguishedName_ (DN) is a part of the LDAP path
+ A DN is a name that uniquely identifies an object in AD, including the domain itself
+ If we aren't familiar with LDAP, this may be somewhat confusing so let's go into a bit more detail

In order for LDAP to function, objects in AD (or other directory services) must be formatted according to a specific naming standard
+ To show an example of a DN, we can use our _stephanie_ domain user
+ We know that _stephanie_ is a user object within the _corp.com_ domain
+ With this, the DN may (although we cannot be sure yet) look something like this:
```
CN=Stephanie,CN=Users,DC=corp,DC=com
```

The Listing above shows a few new references we haven't seen earlier in this Module, such as _CN_ and _DC_
+ The CN is known as the _Common Name_, which specifies the identifier of an object in the domain
+ While we normally refer to "DC" as the Domain Controller in AD terms, "DC" means _Domain Component_ when we are referring to a Distinguished Name
	+ The _Domain Component_ represents the top of an LDAP tree and in this case we refer to it as the Distinguished Name of the domain itself

When reading a DN, we start with the Domain Component objects on the right side and move to the left
+ In the example above, we have four components, starting with two components named _DC=corp,DC=com_
+ The Domain Component objects as mentioned above represent the top of an LDAP tree following the required naming standard
+ Continuing through the DN, _CN=Users_ represents the Common Name for the container where the user object is stored (also known as the parent container)
+ Finally, all the way to the left, _CN=Stephanie_ represents the Common Name for the user object itself, which is also lowest in the hierarchy

In our case for the LDAP path, we are interested in the Domain Component object, which is _DC=corp,DC=com_
+ If we added _CN=Users_ to our LDAP path, we would restrict ourselves by only being able to search objects within that given container

Let's begin writing our script by obtaining the required hostname for the PDC
+ In the Microsoft .NET classes related to AD, we find the _System.DirectoryServices.ActiveDirectory_ namespace
+ While there are a few classes to choose from here, we'll focus on the _Domain Class_
+ It specifically contains a reference to the _PdcRoleOwner_ in the properties, which is exactly what we need
+ By checking the methods, we find a method called _GetCurrentDomain()_, which will return the domain object for the current user, in this case _stephanie_

To invoke the _Domain Class_ and the _GetCurrentDomain_ method, we'll run the following command in PowerShell:
```
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```
+ Example output:
```
Forest                  : corp.com
DomainControllers       : {DC1.corp.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner        : DC1.corp.com
RidRoleOwner            : DC1.corp.com
InfrastructureRoleOwner : DC1.corp.com
Name                  	: corp.com
```

The output reveals the _PdcRoleOwner_ property, which in this case is _DC1.corp.com_
+ While we can certainly add this hostname directly into our script as part of the LDAP path, we want to automate the process so we can also use this script in future engagements

Let's do this one step at a time
+ First, we'll create a variable that will store the domain object, then we will print the variable so we can verify that it still works within our script
+ The first part of our script is listed below:
```
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Print the variable
$domainObj
```

In order to run the script, we must bypass the execution policy, which was designed to keep us from accidentally running PowerShell scripts
+ Will do this with **`powershell -ep bypass`**
```
PS C:\Users\stephanie> .\enumeration.ps1

Forest                  : corp.com
DomainControllers       : {DC1.corp.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : DC1.corp.com
RidRoleOwner            : DC1.corp.com
InfrastructureRoleOwner : DC1.corp.com
Name                    : corp.com
```

Our _domainObj_ variable now holds the information about the domain object
+ Although this print statement isn't required, it's a nice way to verify that our command and the variable worked as intended

Since the hostname in the _PdcRoleOwner_ property is required for our LDAP path, we can extract the name directly from the domain object
+ In case we need more information from the domain object later in our script, we will keep the _`$domainObj`_ for the time being and create a new variable called _`$PDC`_, which will extract the value from the _PdcRoleOwner_ property held in our _$domainObj_ variable:
```
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Store the PdcRoleOwner name to the $PDC variable
$PDC = $domainObj.PdcRoleOwner.Name

# Print the $PDC variable
$PDC
```

Now let's run the script again and inspect the output:
```
PS C:\Users\stephanie> .\enumeration.ps1
DC1.corp.com
```
+ In this case we have dynamically extracted the PDC from the _PdcRoleOwner_ property by using the Domain Class

While we can also get the DN for the domain via the domain object, it does not follow the naming standard required by LDAP
+ In our example, we know that the base domain is _corp.com_ and the DN would in fact be _DC=corp,DC=com_
+ In this instance, we could grab _corp.com_ from the _Name_ property in the domain object and tell PowerShell to break it up and add the required _DC=_ parameter
+ However, there is an easier way of doing it, which will also make sure we are obtaining the correct DN

We can use ADSI (Active Directory Services Interface) directly in PowerShell to retrieve the DN
+ We'll use two single quotes to indicate that the search starts at the top of the AD hierarchy:
```
([adsi]'').distinguishedName
```
+ Example output:
```
DC=corp,DC=com
```

This returns the DN in the proper format for the LDAP path
+ Now we can add a new variable in our script that will store the DN for the domain
+ To make sure the script still works, we'll add a _print_ statement and print the contents of our new variable:
```
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Store the PdcRoleOwner name to the $PDC variable
$PDC = $domainObj.PdcRoleOwner.Name

# Store the Distinguished Name variable into the $DN variable
$DN = ([adsi]'').distinguishedName

# Print the $DN variable
$DN
```

At this point, we are dynamically obtaining the Hostname and the DN with our script
+ Now we must assemble the pieces to build the full LDAP path
+ To do this, we'll add a new _`$LDAP`_ variable to our script that will contain the _`$PDC`_ and _`$DN`_ variables, prefixed with `LDAP://`

The final script generates the LDAP shown below
+ Note that in order to clean it up, we have removed the comments
+ Will also run the PowerShell bypass first:
```
powershell -ep bypass
```
+ Since we only needed the _PdcRoleOwner_ property's name value from the domain object, we add that directly in our _`$PDC`_ variable on the first line, limiting the amount of code required:
``` PowerShell
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```

Let's run the script.
```
PS C:\Users\stephanie> .\enumeration.ps1
LDAP://DC1.corp.com/DC=corp,DC=com
```
+ We have successfully used .NET classes and ADSI to dynamically obtain the full LDAP path required for our enumeration
+ Also, our script is dynamic, so we can easily reuse it in real-world engagements

### Adding Search Functionality to our Script
So far, our script builds the required LDAP path
+ Now we can build in search functionality

To do this, we will use two .NET classes that are located in the _System.DirectoryServices_ namespace, more specifically the _DirectoryEntry_ and _DirectorySearcher_ classes
+ Let's discuss these before we implement them

The _DirectoryEntry_ class encapsulates an object in the AD service hierarchy
+ In our case, we want to search from the very top of the AD hierarchy, so we will provide the obtained LDAP path to the _DirectoryEntry_ class
+ One thing to note with _DirectoryEntry_ is that we can pass it credentials to authenticate to the domain
+ However, since we are already logged in, there is no need to do that here

The _DirectorySearcher_ class performs queries against AD using LDAP
+ When creating an instance of _DirectorySearcher_, we must specify the AD service we want to query in the form of the _SearchRoot_ property
+ According to Microsoft's documentation, this property indicates where the search begins in the AD hierarchy
+ Since the _DirectoryEntry_ class encapsulates the LDAP path that points to the top of the hierarchy, we will pass that as a variable to _DirectorySearcher_

The _DirectorySearcher_ documentation lists _FindAll()_, which returns a collection of all the entries found in AD
+ Let's implement these two classes into our script
+ The code below shows the relevant part of the script:
``` powershell
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()
```
+ As indicated above, we have added the _`$direntry`_ variable, which is encapsulating our obtained LDAP path
+ The _`$dirsearcher`_ variable contains the _`$direntry`_ variable and uses the information as the _SearchRoot_, pointing to the top of the hierarchy where _DirectorySearcher_ will run the _FindAll()_ method

Now since we start the search at the top and aren't filtering the results, it will generate a lot of output. However, let's run it:
```
PS C:\Users\stephanie> .\enumeration.ps1

Path
----
LDAP://DC1.corp.com/DC=corp,DC=com
LDAP://DC1.corp.com/CN=Users,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Computers,DC=corp,DC=com
LDAP://DC1.corp.com/OU=Domain Controllers,DC=corp,DC=com
LDAP://DC1.corp.com/CN=System,DC=corp,DC=com
LDAP://DC1.corp.com/CN=LostAndFound,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Infrastructure,DC=corp,DC=com
LDAP://DC1.corp.com/CN=ForeignSecurityPrincipals,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Program Data,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Microsoft,CN=Program Data,DC=corp,DC=com
LDAP://DC1.corp.com/CN=NTDS Quotas,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Managed Service Accounts,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Keys,DC=corp,DC=com
LDAP://DC1.corp.com/CN=WinsockServices,CN=System,DC=corp,DC=com
LDAP://DC1.corp.com/CN=RpcServices,CN=System,DC=corp,DC=com
LDAP://DC1.corp.com/CN=FileLinks,CN=System,DC=corp,DC=com
LDAP://DC1.corp.com/CN=VolumeTable,CN=FileLinks,CN=System,DC=corp,DC=com
LDAP://DC1.corp.com/CN=ObjectMoveTable,CN=FileLinks,CN=System,DC=corp,DC=com
...
```

As shown in the truncated output above, the script does indeed generate a lot of text
+ In fact, we are receiving all objects in the entire domain
+ This does at least prove that the script is working as expected

Filtering the output is rather simple, and there are several ways to do so
+ One way is to set up a filter that will sift through the _samAccountType_ attribute, which is an attribute applied to all user, computer, and group objects
+ The official documentation reveals different values of the _samAccountType_ attribute, but we'll start with 0x30000000 (decimal 805306368), which will enumerate all **users** in the domain
+ To implement the filter in our script, we can simply add the filter to the **`$dirsearcher.filter`** as shown below
```
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$dirsearcher.FindAll()
```

Running our script displays all user objects in the domain:
```
PS C:\Users\stephanie> .\enumeration.ps1

Path                                                         Properties
----                                                         ----------
LDAP://DC1.corp.com/CN=Administrator,CN=Users,DC=corp,DC=com {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=Guest,CN=Users,DC=corp,DC=com         {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=krbtgt,CN=Users,DC=corp,DC=com        {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=dave,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, usnchanged...}
LDAP://DC1.corp.com/CN=stephanie,CN=Users,DC=corp,DC=com     {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=jeff,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=jeffadmin,CN=Users,DC=corp,DC=com     {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=iis_service,CN=Users,DC=corp,DC=com   {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=pete,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=jen,CN=Users,DC=corp,DC=com           {logoncount, codepage, objectcategory, dscorepropagatio
```

This is great information to have, but we need to develop it a little further
+ When enumerating AD, we are very interested in the _attributes_ of each object, which are stored in the _Properties_ field

Knowing this, we can store the results we receive from our search in a new variable
+ We'll iterate through each object and print each property on its own line via a nested loop as shown below:
``` PowerShell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}
```
+ This complete script will search through AD and filter the results based on the _samAccountType_ of our choosing, then place the results into the new _`$result`_ variable
+ It will then further filter the results based on two _foreach_ loops
+ The first loop will extract the objects stored in _`$result`_ and place them into the _`$obj`_ variable
+ The second loop will extract all the properties for each object and store the information in the _`$prop`_ variable
+ The script will then print _`$prop`_ and present the output in the terminal

While the _Write-Host_ command is not required for the script to function, it does print a line between each object
+ This helps make the output somewhat easier to read

The script will output lots of information, which can be overwhelming depending on the existing number of domain users
+ The Listing below shows a partial view of _jeffadmin_'s attributes:
```
PS C:\Users\stephanie> .\enumeration.ps1
...
logoncount                     {173}
codepage                       {0}
objectcategory                 {CN=Person,CN=Schema,CN=Configuration,DC=corp,DC=com}
dscorepropagationdata          {9/3/2022 6:25:58 AM, 9/2/2022 11:26:49 PM, 1/1/1601 12:00:00 AM}
usnchanged                     {52775}
instancetype                   {4}
name                           {jeffadmin}
badpasswordtime                {133086594569025897}
pwdlastset                     {133066348088894042}
objectclass                    {top, person, organizationalPerson, user}
badpwdcount                    {0}
samaccounttype                 {805306368}
lastlogontimestamp             {133080434621989766}
usncreated                     {12821}
objectguid                     {14 171 173 158 0 247 44 76 161 53 112 209 139 172 33 163}
memberof                       {CN=Domain Admins,CN=Users,DC=corp,DC=com, CN=Administrators,CN=Builtin,DC=corp,DC=com}
whencreated                    {9/2/2022 11:26:48 PM}
adspath                        {LDAP://DC1.corp.com/CN=jeffadmin,CN=Users,DC=corp,DC=com}
useraccountcontrol             {66048}
cn                             {jeffadmin}
countrycode                    {0}
primarygroupid                 {513}
whenchanged                    {9/19/2022 6:44:22 AM}
lockouttime                    {0}
lastlogon                      {133088312288347545}
distinguishedname              {CN=jeffadmin,CN=Users,DC=corp,DC=com}
admincount                     {1}
samaccountname                 {jeffadmin}
objectsid                      {1 5 0 0 0 0 0 5 21 0 0 0 30 221 116 118 49 27 70 39 209 101 53 106 82 4 0 0}
lastlogoff                     {0}
accountexpires                 {9223372036854775807}
...
```

We can filter based on any property of any object type
+ In the example below, we have made two changes
+ First, we have changed the filter to use the _name_ property to only show information for _jeffadmin_
+ Additionally, we have added _.memberof_ to the _`$prop`_ variable to only display the groups _jeffadmin_ is a member of:
``` PowerShell
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="name=jeffadmin"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop.memberof
    }

    Write-Host "-------------------------------"
}
```
+ Output:
```
PS C:\Users\stephanie> .\enumeration.ps1
CN=Domain Admins,CN=Users,DC=corp,DC=com
CN=Administrators,CN=Builtin,DC=corp,DC=com
```

This confirms that _jeffadmin_ is indeed a member of the _Domain Admins_ group
+ We can use this script to enumerate any object available to us in AD
+ However, in the current state, this would require us to make further edits to the script itself based on what we wish to enumerate

Instead, we can make the script more flexible, allowing us to add the required parameters via the command line
+ For example, we could have the script accept the _samAccountType_ we wish to enumerate as a command line argument
+ There are many ways we can accomplish this
+ One way is to simply encapsulate the current functionality of the script into an actual function. 
+ An example of this is shown below:
``` PowerShell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}
```

At the very top, we declare the function itself with the name of our choosing, in this case _LDAPSearch_
+ It then dynamically obtains the required LDAP path connection string and adds it to the _`$DirectoryEntry`_ variable
+ Finally, the search is run and the output is added into an array, which is displayed in our terminal depending on our needs

To use the function, let's import it to memory:
```
Import-Module .\function.ps1
```

Within PowerShell, we can now use the **LDAPSearch** command (our declared function name) to obtain information from AD
+ To repeat parts of the user enumeration we did earlier, we can again filter on the specific _samAccountType_
```
PS C:\Users\stephanie> LDAPSearch -LDAPQuery "(samAccountType=805306368)"

Path                                                         Properties
----                                                         ----------
LDAP://DC1.corp.com/CN=Administrator,CN=Users,DC=corp,DC=com {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=Guest,CN=Users,DC=corp,DC=com         {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=krbtgt,CN=Users,DC=corp,DC=com        {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=dave,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, usnchanged...}
LDAP://DC1.corp.com/CN=stephanie,CN=Users,DC=corp,DC=com     {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=jeff,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=jeffadmin,CN=Users,DC=corp,DC=com     {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=iis_service,CN=Users,DC=corp,DC=com   {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=pete,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, dscorepropagatio...
LDAP://DC1.corp.com/CN=jen,CN=Users,DC=corp,DC=com           {logoncount, codepage, objectcategory, dscorepropagatio
```

We can also search directly for an _Object Class_, which is a component of AD that defines the object type
+ Let's use **objectClass=group** in this case to list all the groups in the domain:
```
PS C:\Users\stephanie> LDAPSearch -LDAPQuery "(objectclass=group)"

...                                                                                 ----------
LDAP://DC1.corp.com/CN=Read-only Domain Controllers,CN=Users,DC=corp,DC=com            {usnchanged, distinguishedname, grouptype, whencreated...}
LDAP://DC1.corp.com/CN=Enterprise Read-only Domain Controllers,CN=Users,DC=corp,DC=com {iscriticalsystemobject, usnchanged, distinguishedname, grouptype...}
LDAP://DC1.corp.com/CN=Cloneable Domain Controllers,CN=Users,DC=corp,DC=com            {iscriticalsystemobject, usnchanged, distinguishedname, grouptype...}
LDAP://DC1.corp.com/CN=Protected Users,CN=Users,DC=corp,DC=com                         {iscriticalsystemobject, usnchanged, distinguishedname, grouptype...}
LDAP://DC1.corp.com/CN=Key Admins,CN=Users,DC=corp,DC=com                              {iscriticalsystemobject, usnchanged, distinguishedname, grouptype...}
LDAP://DC1.corp.com/CN=Enterprise Key Admins,CN=Users,DC=corp,DC=com                   {iscriticalsystemobject, usnchanged, distinguishedname, grouptype...}
LDAP://DC1.corp.com/CN=DnsAdmins,CN=Users,DC=corp,DC=com                               {usnchanged, distinguishedname, grouptype, whencreated...}
LDAP://DC1.corp.com/CN=DnsUpdateProxy,CN=Users,DC=corp,DC=com                          {usnchanged, distinguishedname, grouptype, whencreated...}
LDAP://DC1.corp.com/CN=Sales Department,DC=corp,DC=com                                 {usnchanged, distinguishedname, grouptype, whencreated...}
LDAP://DC1.corp.com/CN=Management Department,DC=corp,DC=com                            {usnchanged, distinguishedname, grouptype, whencreated...}
LDAP://DC1.corp.com/CN=Development Department,DC=corp,DC=com                           {usnchanged, distinguishedname, grouptype, whencreated...}
LDAP://DC1.corp.com/CN=Debug,CN=Users,DC=corp,DC=com                                   {usnchanged, distinguishedname, grouptype, whencreated...}
```

Our script enumerates more groups than `net.exe` including _Print Operators_, _IIS_IUSRS_, and others
+ This is because it enumerates all AD objects including _Domain Local_ groups (not just global groups)

In order to print properties and attributes for objects, we'll need to implement the loops we discussed earlier
+ For now, let's do this directly from the PowerShell command

To enumerate every group available in the domain and also display the user members, we can pipe the output into a new variable and use a _foreach_ loop that will print each property for a group
+ This allows us to select specific attributes we are interested in
+ For example, let's focus on the _CN_ and _member_ attributes:

``` Powershell
PS C:\Users\stephanie\Desktop> foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {
>> $group.properties | select {$_.cn}, {$_.member}
>> }
```

Even though this environment is somewhat small, we still received a lot of output
+ Let's focus on the three groups we noticed earlier in our enumeration with `net.exe`:
```
...
Sales Department              {CN=Development Department,DC=corp,DC=com, CN=pete,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
Management Department         CN=jen,CN=Users,DC=corp,DC=com
Development Department        {CN=Management Department,DC=corp,DC=com, CN=pete,CN=Users,DC=corp,DC=com, CN=dave,CN=Users,DC=corp,DC=com}
...
```

According to our search, we have expanded the properties for each object, in this case the _group_ objects, and we printed the _member_ attribute for each group
+ Above reveals something unexpected
+ Earlier when we enumerated the _Sales Department_ group with net.exe, we only found two users in it: _pete_ and _stephanie_
+ In this case however, it appears that _Development Department_ is also a member

Since the output can be somewhat difficult to read, let's once again search for the groups, but this time specify the _Sales Department_ in the query and pipe it into a variable in our PowerShell command line:
``` PowerShell
PS C:\Users\stephanie> $sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
```

Now that we only have one object in our variable, we can simply print the _member_ attribute directly:
```
PS C:\Users\stephanie\Desktop> $sales.properties.member
CN=Development Department,DC=corp,DC=com
CN=pete,CN=Users,DC=corp,DC=com
CN=stephanie,CN=Users,DC=corp,DC=com
PS C:\Users\stephanie\Desktop>
```
+ The _Development Department_ is indeed a member of the _Sales Department_ group as indicated
+ This is something we missed earlier with `net.exe`

This is a group within a group, known as a _nested group_
+ Nested groups are relatively common in AD and scales well, allowing flexibility and dynamic membership customization of even the largest AD implementations

The `net.exe` tool missed this because it only lists _user_ objects, not group objects
+ In addition, `net.exe `can not display specific attributes
+ This emphasizes the benefit of custom tools

Now that we know the _Development Department_ is a member of the _Sales Department_, let's enumerate it:
```
PS C:\Users\stephanie> $group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"

PS C:\Users\stephanie> $group.properties.member
CN=Management Department,DC=corp,DC=com
CN=pete,CN=Users,DC=corp,DC=com
CN=dave,CN=Users,DC=corp,DC=com
```

Based on the output above, we have another case of a nested group since _Management Department_ is a member of _Development Department_
+ Lets check this group as well:
```
PS C:\Users\stephanie\Desktop> $group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Management Department*))"

PS C:\Users\stephanie\Desktop> $group.properties.member
CN=jen,CN=Users,DC=corp,DC=com
```

Finally, after searching through multiple groups, it appears we found the end
+ According to the output in Listing 35, _jen_ is the sole member of the _Management Department_ group
+ Although we saw _jen_ as a member of the _Management Department_ group earlier, we obtained additional information about the group memberships in this case by enumerating the groups one-by-one

An additional thing to note here is that while it appears that _jen_ is only a part of the _Management Department_ group, she is also an indirect member of the _Sales Department_ and _Development Department_ groups, since groups typically inherit each other
+ This is normal behavior in AD; however, if misconfigured, users may end up with more privileges than they were intended to have
+ This might allow attackers to take advantage of the misconfiguration to further expand their reach inside the compromised domain

This concludes the journey with our PowerShell script that invokes .NET classes to run queries against AD via LDAP
+ As we have verified, this approach is much more powerful than running tools such as net.exe and provides a wealth of enumeration options

While this script can surely be developed further by adding additional options and functions, this may require more research on PowerShell scripting, which is outside the scope of this Module
+ With a basic understanding of LDAP and how we can use it to communicate with AD using PowerShell, we'll shift our focus in the next section to a pre-developed script that will speed up our process

### AD Enumeration with PowerView
So far we have only scratched the surface of Active Directory enumeration by mostly focusing on users and groups
+ While the tools we have used so far have given us a good start and an understanding of how we can communicate with AD and obtain information, other researchers have created more elaborate tools for the same purpose

One popular option is the _PowerView_ PowerShell script, which includes many functions to improve the effectiveness of our enumeration
+ As a way of introducing PowerView, let's walk through parts of our enumeration steps from the previous section
+ PowerView is already installed in the **`C:\Tools`** folder on CLIENT75. To use it, we'll first import it to memory
```
Import-Module .\PowerView.ps1
```

With PowerView imported, we can start exploring various commands that are available
+ See a list of available commands: https://powersploit.readthedocs.io/en/latest/Recon/

Let's start by running **Get-NetDomain**, which will give us basic information about the domain (which we used _GetCurrentDomain_ for previously):
```
Get-NetDomain
```
+ Example output:
```
Forest                  : corp.com
DomainControllers       : {DC1.corp.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : DC1.corp.com
RidRoleOwner            : DC1.corp.com
InfrastructureRoleOwner : DC1.corp.com
Name                    : corp.com
```

Much like the script we created earlier, PowerView is also using .NET classes to obtain the required LDAP path and uses it to communicate with AD
+ Now let's get a list of all users in the domain with **Get-NetUser**:
```
Get-NetUser
```
+ Example output:
```
logoncount             : 113
iscriticalsystemobject : True
description            : Built-in account for administering the computer/domain
distinguishedname      : CN=Administrator,CN=Users,DC=corp,DC=com
objectclass            : {top, person, organizationalPerson, user}
lastlogontimestamp     : 9/13/2022 1:03:47 AM
name                   : Administrator
objectsid              : S-1-5-21-1987370270-658905905-1781884369-500
samaccountname         : Administrator
admincount             : 1
codepage               : 0
samaccounttype         : USER_OBJECT
accountexpires         : NEVER
cn                     : Administrator
whenchanged            : 9/13/2022 8:03:47 AM
instancetype           : 4
usncreated             : 8196
objectguid             : e5591000-080d-44c4-89c8-b06574a14d85
lastlogoff             : 12/31/1600 4:00:00 PM
objectcategory         : CN=Person,CN=Schema,CN=Configuration,DC=corp,DC=com
dscorepropagationdata  : {9/2/2022 11:25:58 PM, 9/2/2022 11:25:58 PM, 9/2/2022 11:10:49 PM, 1/1/1601 6:12:16 PM}
memberof               : {CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=com, CN=Domain Admins,CN=Users,DC=corp,DC=com, CN=Enterprise
                         Admins,CN=Users,DC=corp,DC=com, CN=Schema Admins,CN=Users,DC=corp,DC=com...}
lastlogon              : 9/14/2022 2:37:15 AM
...
```

Get-NetUser automatically enumerates all attributes on the user objects
+ This presents a lot of information, which can be difficult to digest

In the script we created earlier, we used loops to print certain attributes based on the information obtained
+ obtained. However, with PowerView we can simply pipe the output into **select**, where we can choose the attributes we are interested in

Above reveals that the _cn_ attribute holds the username of the user
+ Let's pipe the output into **select** and choose the **cn** attribute
```
PS C:\Tools> Get-NetUser | select cn

cn
--
Administrator
Guest
krbtgt
dave
stephanie
jeff
jeffadmin
iis_service
pete
jen
```
+ This produced a cleaned-up list of users in the domain

When enumerating AD, there are many interesting attributes to search for
+ For example, if a user is dormant (they have not changed their password or logged in recently) we will cause less interference and draw less attention if we take over that account during the engagement
+ In addition, if a user hasn't changed their password since a recent password policy change, their password may be weaker than the current policy
+ This might make it more vulnerable to password attacks

This is something we can easily investigate
+ Let's run **Get-NetUser** again, this time piping the output into **select** and extracting these attributes
```
Get-NetUser | select cn,pwdlastset,lastlogon
```
+ Example output:
```
cn            pwdlastset            lastlogon
--            ----------            ---------
Administrator 8/16/2022 5:27:22 PM  9/14/2022 2:37:15 AM
Guest         12/31/1600 4:00:00 PM 12/31/1600 4:00:00 PM
krbtgt        9/2/2022 4:10:48 PM   12/31/1600 4:00:00 PM
dave          9/7/2022 9:54:57 AM   9/14/2022 2:57:28 AM
stephanie     9/2/2022 4:23:38 PM   12/31/1600 4:00:00 PM
jeff          9/2/2022 4:27:20 PM   9/14/2022 2:54:55 AM
jeffadmin     9/2/2022 4:26:48 PM   9/14/2022 2:26:37 AM
iis_service   9/7/2022 5:38:43 AM   9/14/2022 2:35:55 AM
pete          9/6/2022 12:41:54 PM  9/13/2022 8:37:09 AM
jen           9/6/2022 12:43:01 PM  9/13/2022 8:36:55 AM
```
+ We have a nice list which shows us when the users last changed their password, as well as when they last logged in to the domain

Similarly, we can use **Get-NetGroup** to enumerate groups:
```
Get-NetGroup | select cn
```
+ Example output:
```
cn
--
...
Key Admins
Enterprise Key Admins
DnsAdmins
DnsUpdateProxy
Sales Department
Management Department
Development Department
Debug
```

Enumerating specific groups with PowerView is easy. Although we will not go through the process of unraveling nested groups in this case, let's investigate the **Sales Department** using **Get-NetGroup** and pipe the output into **select member**
```
PS C:\Tools> Get-NetGroup "Sales Department" | select member

member
------
{CN=Development Department,DC=corp,DC=com, CN=pete,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
```
+ Now that we have essentially recreated the functionality of our previous script, we're ready to explore more attributes and enumeration techniques

## Manual Enumeration - Expanding our Repertoire 
Now that we are familiar with LDAP and we have a few tools in our toolkit, let's further explore the domain
+ Our goal is to use all this information to create a _domain map_
+ While we don't necessarily need to draw a map ourselves, it is a good idea to try visualizing how the domain is configured and understand the relationship between objects
+ Visualizing the environment can make it easier to find potential attack vectors

### Enumerating Operating Systems
In a typical penetration test, we use various recon tools in order to detect which operating system a client or server is using
+ We can, however, enumerate this from Active Directory

Let's use the **Get-NetComputer** PowerView command to enumerate the computer objects in the domain:
```
Get-NetComputer
```
+ Example output:
```
pwdlastset                    : 10/2/2022 10:19:40 PM
logoncount                    : 319
msds-generationid             : {89, 27, 90, 188...}
serverreferencebl             : CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=com
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=DC1,OU=Domain Controllers,DC=corp,DC=com
objectclass                   : {top, person, organizationalPerson, user...}
lastlogontimestamp            : 10/13/2022 11:37:06 AM
name                          : DC1
objectsid                     : S-1-5-21-1987370270-658905905-1781884369-1000
samaccountname                : DC1$
localpolicyflags              : 0
codepage                      : 0
samaccounttype                : MACHINE_ACCOUNT
whenchanged                   : 10/13/2022 6:37:06 PM
accountexpires                : NEVER
countrycode                   : 0
operatingsystem               : Windows Server 2022 Standard
instancetype                  : 4
msdfsr-computerreferencebl    : CN=DC1,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,DC=corp,DC=com
objectguid                    : 8db9e06d-068f-41bc-945d-221622bca952
operatingsystemversion        : 10.0 (20348)
lastlogoff                    : 12/31/1600 4:00:00 PM
objectcategory                : CN=Computer,CN=Schema,CN=Configuration,DC=corp,DC=com
dscorepropagationdata         : {9/2/2022 11:10:48 PM, 1/1/1601 12:00:01 AM}
serviceprincipalname          : {TERMSRV/DC1, TERMSRV/DC1.corp.com, Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/DC1.corp.com, ldap/DC1.corp.com/ForestDnsZones.corp.com...}
usncreated                    : 12293
lastlogon                     : 10/18/2022 3:37:56 AM
badpwdcount                   : 0
cn                            : DC1
useraccountcontrol            : SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
whencreated                   : 9/2/2022 11:10:48 PM
primarygroupid                : 516
iscriticalsystemobject        : True
msds-supportedencryptiontypes : 28
usnchanged                    : 178663
ridsetreferences              : CN=RID Set,CN=DC1,OU=Domain Controllers,DC=corp,DC=com
dnshostname                   : DC1.corp.com
```

There are many interesting attributes, but for now we'll search for the operating system and hostnames
+ Let's pipe the output into **select** and clean up our list:
```
Get-NetComputer | select operatingsystem,dnshostname
```
+ Example output:
```
operatingsystem              dnshostname
---------------              -----------
Windows Server 2022 Standard DC1.corp.com
Windows Server 2022 Standard web04.corp.com
Windows Server 2022 Standard FILES04.corp.com
Windows 11 Pro               client74.corp.com
Windows 11 Pro               client75.corp.com
Windows 10 Pro               CLIENT76.corp.com
```

The output reveals a total of six computers in this domain, three of which are servers, including one DC
+ It's a good idea to grab this information early in the assessment to determine the relative age of the systems and to locate potentially weak targets
+ According to the information we've gathered so far, the machine with the oldest OS appears to be running Windows 10
+ Additionally, it appears we are dealing with a web server and a file server that will require our attention at some point as well
+ So far in our enumeration we have obtained a nice list of all objects in the domain as well as their attributes

### Getting an Overview - Permissions and Logged on Users
Now that we have a clear list of computers, users, and groups in the domain, we will continue our enumeration and focus on the relationships between as many objects as possible
+ These relationships often play a key role during an attack, and our goal is to build a _map_ of the domain to find potential attack vectors

For example, when a user logs in to the domain, their credentials are cached in memory on the computer they logged in from
+ If we are able to steal those credentials, we may be able to use them to authenticate as the domain user and may even escalate our domain privileges
+ However, during an AD assessment, we may not always want to escalate our privileges right away

Instead, it's important to establish a good foothold, and our goal at the very least should be to maintain our access
+ If we are able to compromise other users that have the same permissions as the user we already have access to, this allows us to maintain our foothold
+ If , for example, the password is reset for the user we originally obtained access to, or the system administrators notice suspicious activity and disable the account, we would still have access to the domain via other users we compromised

When the time comes to escalate our privileges, we don't necessarily need to immediately escalate to _Domain Admins_ because there may be other accounts that have higher privileges than a regular domain user, even if they aren't necessarily a part of the _Domain Admins_ group
+ _Service Accounts_, which we will discuss later, are a good example of this
+ Although they may not always have the highest privilege possible, they may have more permissions than a regular domain user, such as local administrator privileges on specific servers

In addition, an organization's most sensitive and important data may be stored in locations that do not require domain administrator privileges, such as a database or a file server
+ This means that obtaining domain administrator privileges should not always be the end goal during an assessment since we may be able to reach the "crown jewels" for an organization via other users in the domain

When an attacker or penetration tester improves access through multiple higher-level accounts to reach a goal, it is known as a _chained compromise_
+ In order to find possible attack paths, we'll need to learn more about our initial user and see what else we have access to in the domain
+ We also need to find out where other users are logged in
+ Let's dig into that now

PowerView's _Find-LocalAdminAccess_ command scans the network in an attempt to determine if our current user has administrative permissions on any computers in the domain
+ The command relies on the _OpenServiceW function_, which will connect to the _Service Control Manager_ (SCM) on the target machines
+ The SCM essentially maintains a database of installed services and drivers on Windows computers
+ PowerView will attempt to open this database with the _SC_MANAGER_ALL_ACCESS_ access right, which require administrative privileges, and if the connection is successful, PowerView will deem that our current user has administrative privileges on the target machine

Let's run **Find-LocalAdminAccess** against _corp.com_
+ While the command supports parameters such as _Computername_ and _Credentials_, we will run it without parameters in this case since we are interested in enumerating all computers, and we are already logged in as _stephanie_
+ In other words, we are _spraying_ the environment to find possible local administrative access on computers under the current user context
+ Depending on the size of the environment, it may take a few minutes for `Find-LocalAdminAccess` to finish:
```
Find-LocalAdminAccess
```
+ Example output:
```
client74.corp.com
```

This reveals that _stephanie_ has administrative privileges on CLIENT74
+ While it may be tempting to log in to CLIENT74 and check permissions right away, this is a good opportunity to zoom out and generalize

Penetration testing can lead us in many different directions and while we should definitely follow up on the many different paths based on our interactions, we should stick to our schedule/plan most of the time to keep a disciplined approach
+ Let's continue by trying to visualize how computers and users are connected together
+ The first step in this process will be to obtain information such as *which user is logged in to which computer*

Historically, the two most reliable Windows APIs that could (and still may) help us achieve these goals are _NetWkstaUserEnum_ and _NetSessionEnum_
+ The former requires administrative privileges, while the latter does not
+ However, Windows has undergone changes over the last couple of years, possibly making the discovery of logged in user enumeration more difficult for us

PowerView's **Get-NetSession** command uses the _NetWkstaUserEnum_ and _NetSessionEnum_ APIs under the hood
+ Let's try running it against some of the machines in the domain and see if we can find any logged in users:
```
Get-NetSession -ComputerName <COMPUTER_NAME>
```
+ Example:
```
PS C:\Tools> Get-NetSession -ComputerName files04

PS C:\Tools> Get-NetSession -ComputerName web04
```
+ Above, we are not receiving any output
+ A simple explanation would be that there are no users logged in on the machines

However, to make sure we aren't receiving any error messages, let's add the **-Verbose** flag
```
Get-NetSession -ComputerName <COMPUTER_NAME> -Verbose
```
+ Example:
```
PS C:\Tools> Get-NetSession -ComputerName files04 -Verbose
VERBOSE: [Get-NetSession] Error: Access is denied

PS C:\Tools> Get-NetSession -ComputerName web04 -Verbose
VERBOSE: [Get-NetSession] Error: Access is denied
```
+ Unfortunately, it appears that _NetSessionEnum_ does not work in this case and returns an "Access is denied" error message
+ This most likely means that we are not allowed to run the query, and based on the error message, it may have something to do with privileges

Since we may have administrative privileges on CLIENT74 with _stephanie_, let's run **Get-NetSession** against that machine and inspect the output there as well:
```
PS C:\Tools> Get-NetSession -ComputerName client74

CName        : \\192.168.50.75
UserName     : stephanie
Time         : 8
IdleTime     : 0
ComputerName : client74
```
+ We did receive some more information this time
+ However, looking closer at the output, the IP address in _CName_ (192.168.50.75) does not match the IP address for CLIENT74
+ In fact, it matches the IP address for our current machine, which is CLIENT75
+ Since we haven't spawned any sessions to CLIENT74, something appears to be off in this case as well

In a real world engagement, or even in the Challenge Labs, we might accept that enumerating sessions with PowerView does not work and try to use a different tool
+ However, let's use this as a learning opportunity and take a deeper dive into the _NetSessionEnum_ API and try to figure out exactly why it does not work in our case

According to the documentation for _NetSessionEnum_, there are five possible query levels: 0,1,2,10,502
+ Level 0 only returns the name of the computer establishing the session
+ Levels 1 and 2 return more information but require administrative privileges
+ This leaves us with Levels 10 and 502
	+ Both should return information such as the name of the computer and name of the user establishing the connection
	+ By default, PowerView uses query level 10 with _NetSessionEnum_, which should give us the information we are interested in

The permissions required to enumerate sessions with _NetSessionEnum_ are defined in the **SrvsvcSessionInfo** registry key, which is located in the **`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity`** hive
+ We'll use the Windows 11 machine we are currently logged in on to check the permissions
+ Although it may have different permissions than the other machines in the environment, it may give us an idea of what is going on

In order to view the permissions, we'll use the PowerShell **Get-Acl** cmdlet
+ This command will essentially retrieve the permissions for the object we define with the **-Path** flag and print them in our PowerShell prompt:
```
Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
```
+ Output:
```

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : BUILTIN\Users Allow  ReadKey
         BUILTIN\Administrators Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         CREATOR OWNER Allow  FullControl
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681 Allow  ReadKey
```
+ Above reveals the groups and users that have either _FullControl_ or _ReadKey_, meaning they can all read the **SrvsvcSessionInfo** key itself

However, the _BUILTIN_ group, _NT AUTHORITY_ group, _CREATOR OWNER_ and _APPLICATION PACKAGE AUTHORITY_ are defined by the system, and do not allow _NetSessionEnum_ to enumerate this registry key from a remote standpoint
+ The long string in the end of the output is, according to Microsoft's documentation, a _capability SID_
+ In fact, the documentation refers to the exact SID in our output

A capability SID is an _unforgeable_ token of authority that grants a Windows component or a Universal Windows Application access to various resources
+ However, it will not give us remote access to the registry key of interest

In older Windows versions (which Microsoft does not specify), _Authenticated Users_ were allowed to access the registry hive and obtain information from the **SrvsvcSessionInfo** key
+ However, following the _least privilege_ principle, regular domain users should not be able to acquire this information within the domain, which is likely part of the reason the permissions for the registry hive changed as well
+ In this case, due to permissions, we can be certain that _NetSessionEnum_ will not be able to obtain this type of information on default Windows 11

Now let's get a better sense of the operating system versions in use
+ We can do this with **Net-GetComputer**, this time including the **operatingsystemversion** attribute:
```
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
```
+ Example output:
```
dnshostname       operatingsystem              operatingsystemversion
-----------       ---------------              ----------------------
DC1.corp.com      Windows Server 2022 Standard 10.0 (20348)
web04.corp.com    Windows Server 2022 Standard 10.0 (20348)
FILES04.corp.com  Windows Server 2022 Standard 10.0 (20348)
client74.corp.com Windows 11 Pro               10.0 (22000)
client75.corp.com Windows 11 Pro               10.0 (22000)
CLIENT76.corp.com Windows 10 Pro               10.0 (16299)
```
+ As we discovered earlier, Windows 10 is the oldest operating system in the environment, and based on the output above, it runs version 16299, otherwise known as build 1709

While the documentation from Microsoft is not clear when they made a change to the **`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity`** registry hive, it appears to be around the release of this exact build
+ It also seems to affect all Windows Server operating systems since Windows Server 2019 build 1809
+ This creates an issue for us since we won't be able to use PowerView to build the domain map we had in mind

Even though _NetSessionEnum_ does not work in this case, we should still keep it in our toolkit since it's not uncommon to find older systems in real-world environments
+ Fortunately there are other tools we can use, such as the _PsLoggedOn_ application from the _SysInternals Suite_
+ The documentation states that PsLoggedOn will enumerate the registry keys under **HKEY_USERS** to retrieve the _security identifiers_ (SID) of logged-in users and convert the SIDs to usernames
+ PsLoggedOn will also use the _NetSessionEnum_ API to see who is logged on to the computer via resource shares

One limitation, however, is that PsLoggedOn relies on the _Remote Registry_ service in order to scan the associated key
+ The Remote Registry service has not been enabled by default on Windows workstations since Windows 8, but system administrators may enable it for various administrative tasks, for backwards compatibility, or for installing monitoring/deployment tools, scripts, agents, etc

It is also enabled by default on later Windows Server Operating Systems such as Server 2012 R2, 2016 (1607), 2019 (1809), and Server 2022 (21H2)
+ If it is enabled, the service will stop after ten minutes of inactivity to save resources, but it will re-enable (with an _automatic trigger_) once we connect with PsLoggedOn

With the theory out of the way for now, let's try to run PsLoggedOn against the computers we attempted to enumerate earlier, starting with FILES04 and WEB04
+ PsLoggedOn is located in **`C:\Tools\PSTools`** on CLIENT75
+ To use it, we'll simply run it with the target hostname:
```
.\PsLoggedon.exe \\<HOSTNAME>
```
+ Example:
```
PS C:\Tools\PSTools> .\PsLoggedon.exe \\files04

PsLoggedon v1.35 - See who's logged on
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Users logged on locally:
     <unknown time>             CORP\jeff
Unable to query resource logons
```
+ In this case, we discover that _jeff_ is logged in on FILES04 with his domain user account
+ This is great information, which suggests another potential attack vector
+ We'll make a note in our documentation

Will enumerate WEB04 as well:
```
PsLoggedon v1.35 - See who's logged on
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

No one is logged on locally.
Unable to query resource logons
```
+ According to the output, there are no users logged in on WEB04
+ This may be a false positive since we cannot know for sure that the **Remote Registry** service is running, but we didn't receive any error messages, which suggests the output is accurate
+ For now, we will simply have to trust our enumeration and accept that no users are logged in on the specific server

As we discovered earlier in this section, it appears that we have administrative privileges on CLIENT74 via _stephanie_, so this is a machine of high interest, and we should enumerate possible sessions there as well
+ For educational purposes, we have enabled the Remote Registry service on CLIENT74
```
PS C:\Tools\PSTools> .\PsLoggedon.exe \\client74

PsLoggedon v1.35 - See who's logged on
Copyright (C) 2000-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

Users logged on locally:
     <unknown time>             CORP\jeffadmin

Users logged on via resource shares:
     10/5/2022 1:33:32 AM       CORP\stephanie
```
+ It appears _jeffadmin_ has an open session on CLIENT74, and the output reveals some very interesting pieces of information
+ If our enumeration is accurate and we in fact have administrative privileges on CLIENT74, we should be able to log in there and possibly steal _jeffadmin_'s credentials!
+ It would be very tempting to try this immediately, but it's best practice to stay the course and continue our enumeration
+ After all, our goal is not to get a quick win, but rather to provide a thorough analysis

Another interesting thing to note in the output is that _stephanie_ is logged on via resource shares
+ This is shown because PsLoggedOn also uses the _NetSessionEnum_ API, which in this case requires a logon in order to work
+ This may also explain why we saw a logon earlier for _stephanie_ while using PowerView

This concludes the enumeration of our compromised user, including the enumeration of active sessions within the domain
+ Based on the information we have gathered, we have a very interesting attack path that may lead us all the way to domain administrator if pursued

### Enumeration Through Service Principal Names
So far, we have obtained quite a bit of information, and we are starting to see how things are connected together within the domain
+ To wrap up our discussion of user enumeration, we'll shift our focus to _Service Accounts_, which may also be members of high-privileged groups

Applications must be executed in the context of an operating system user
+ If a user launches an application, that user account defines the context
+ However, services launched by the system itself run in the context of a _Service Account_

In other words, isolated applications can use a set of predefined service accounts, such as _LocalSystem_, _LocalService_, and _NetworkService_
+ For more complex applications, a domain user account may be used to provide the needed context while still maintaining access to resources inside the domain

When applications like _Exchange_, MS SQL, or _Internet Information Services_ (IIS) are integrated into AD, a unique service instance identifier known as _Service Principal Name_ (SPN) associates a service to a specific service account in Active Directory
+ Managed Service Accounts, introduced with Windows Server 2008 R2, were designed for complex applications, which require tighter integration with Active Directory
+ Larger applications like MS SQL and Microsoft Exchange often required server redundancy when running to guarantee availability, but Managed Service Accounts did not support this
+ To remedy this, Group Managed Service Accounts were introduced with Windows Server 2012, but this requires that domain controllers run Windows Server 2012 or higher
+ Because of this, some organizations may still rely on basic Service Accounts

We can obtain the IP address and port number of applications running on servers integrated with AD by simply enumerating all SPNs in the domain, meaning we don't need to run a broad port scan
+ Since the information is registered and stored in AD, it is present on the domain controller
+ To obtain the data, we will again query the DC, this time searching for specific SPNs

To enumerate SPNs (Service Principle Names) in the domain, we have multiple options
+ In this case, we'll use **setspn.exe**, which is installed on Windows by default
+ We'll use **-L** to run against both servers and clients in the domain:
```
setspn -L
```
+ While we could iterate through the list of domain users, we previously discovered the _iis_service_ user, will start with that one:
```
c:\Tools>setspn -L iis_service
Registered ServicePrincipalNames for CN=iis_service,CN=Users,DC=corp,DC=com:
        HTTP/web04.corp.com
        HTTP/web04
        HTTP/web04.corp.com:80
```
+ Above an SPN is linked to the _iis_service_ account

Another way of enumerating SPNs is to let PowerView enumerate all the accounts in the domain
+ To obtain a clear list of SPNs, we can pipe the output into **select** and choose the **samaccountname** and **serviceprincipalname** attributes:
```
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```
+ Usage:
```
PS C:\Tools> Get-NetUser -SPN | select samaccountname,serviceprincipalname

samaccountname serviceprincipalname
-------------- --------------------
krbtgt         kadmin/changepw
iis_service    {HTTP/web04.corp.com, HTTP/web04, HTTP/web04.corp.com:80}
```

While we will explore the _krbtgt_ account in upcoming AD-related Modules, for now, we'll continue to focus on _iis service_
+ The _serviceprincipalname_ of this account is set to "`HTTP/web04.corp.com`, `HTTP/web04`, `HTTP/web04.corp.com:80`", which is indicative of a web server

Let's attempt to resolve **web04.corp.com** with **nslookup**:
```
PS C:\Tools\> nslookup.exe web04.corp.com
Server:  UnKnown
Address:  192.168.50.70

Name:    web04.corp.com
Address:  192.168.50.72
```

From the result, it's clear that the hostname resolves to an internal IP address
+ If we browse this to this IP, we find a website that requires a login:
![[Pasted image 20231230203606.png]]

Since these types of accounts are used to run services, we can assume that they have more privileges than regular domain user accounts
+ For now, we'll simply document that _iis_service_ has a linked SPN, which will be valuable for us in the upcoming AD-related Modules

### Enumerating Object Permissions
In this section, we will enumerate specific permissions that are associated with Active Directory objects
+ Although the technical details of those permissions are complex and out of scope of this Module, it's important that we discuss the basic principles before we start enumeration

In short, an object in AD may have a set of permissions applied to it with multiple _Access Control Entries_ (ACE)
+ These ACEs make up the _Access Control List_ (ACL)
+ Each ACE defines whether access to the specific object is allowed or denied

As a very basic example, let's say a domain user attempts to access a domain share (which is also an object)
+ The targeted object, in this case the share, will then go through a validation check based on the ACL to determine if the user has permissions to the share
+ This ACL validation involves two main steps:
	+ In an attempt to access the share, the user will send an _access token_, which consists of the user identity and permissions
	+ The target object will then validate the token against the list of permissions (the ACL)
	+ If the ACL allows the user to access the share, access is granted, otherwise the request is denied

AD includes a wealth of permission types that can be used to configure an ACE
+ However, from an attacker's standpoint, we are mainly interested in a few key permission types
+ Here's a list of the most interesting ones along with a description of the permissions they provide:
```
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group
```

The Microsoft documentation lists other permissions and describes each in more detail
+ See documentation: https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks

We can use **Get-ObjectAcl** to enumerate ACEs with PowerView
+ To get started, let's enumerate our own user to determine which ACEs are applied to it 
+ We can do this by filtering on **-Identity**:
```
Get-ObjectAcl -Identity <USER>
```
+ Example:
```
PS C:\Tools> Get-ObjectAcl -Identity stephanie

...
ObjectDN               : CN=stephanie,CN=Users,DC=corp,DC=com
ObjectSID              : S-1-5-21-1987370270-658905905-1781884369-1104
ActiveDirectoryRights  : ReadProperty
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 4c164200-20c0-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 16
SecurityIdentifier     : S-1-5-21-1987370270-658905905-1781884369-553
AceType                : AccessAllowedObject
AceFlags               : None
IsInherited            : False
InheritanceFlags       : None
PropagationFlags       : None
AuditFlags             : None
...
```

The amount of output may seem overwhelming since we enumerated every ACE that grants or denies some sort of permission to _stephanie_
+ While there are many properties that seem potentially useful, we are primarily interested in those highlighted in the truncated output of the listing above

The output lists two _Security Identifiers_ (SID), unique values that represent an object in AD
+ The first (located in the highlighted _ObjectSID_ property) contains the value `S-1-5-21-1987370270-658905905-1781884369-1104`, which is difficult to read
+ In order to make sense of the SID, we can use PowerView's **Convert-SidToName** command to convert it to an actual domain object name:
```
Convert-SidToName <SID>
```
+ Example:
```
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
CORP\stephanie
```

The conversion reveals that the SID in the _ObjectSID_ property belongs to the _stephanie_ user we are currently using
+ The _ActiveDirectoryRights_ property describes the type of permission applied to the object
+ In order to find out who has the _ReadProperty_ permission in this case, we need to convert the _SecurityIdentifier_ value

Let's use PowerView to convert it into a name we can read:
```
PS C:\Tools> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
CORP\RAS and IAS Servers
```
+ According to PowerView, the SID in the _SecurityIdentifier_ property belongs to a default AD group named _RAS and IAS Servers_

Taking this information together, the _RAS and IAS Servers_ group has _ReadProperty_ access rights to our user
+ While this is a common configuration in AD and likely won't give us an attack vector, we have used the example to make sense of the information we have obtained

In short, we are interested in the _ActiveDirectoryRights_ and _SecurityIdentifier_ for each object we enumerate going forward

The highest access permission we can have on an object is _GenericAll_
+ Although there are many other interesting ones as discussed previously in this section, we will use GenericAll as an example in this case

We can continue to use **Get-ObjectAcl** and select only the properties we are interested in, namely _ActiveDirectoryRights_ and _SecurityIdentifier_
+ While the _ObjectSID_ is nice to have, we don't need it when we are enumerating specific objects in AD since it will only contain the SID for the object we are in fact enumerating

Although we should enumerate all objects the domain, let's start with the _Management Department_ group for now
+ We will check if any users have GenericAll permissions

To generate clean and manageable output, we'll use the PowerShell **-eq** flag to filter the **ActiveDirectoryRights** property, only displaying the values that equal **GenericAll**
+ We'll then pipe the results into **select**, only displaying the **SecurityIdentifier** and **ActiveDirectoryRights** properties:
```
Get-ObjectAcl -Identity <OBJECT> | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```
+ Example:
```
PS C:\Tools> Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

SecurityIdentifier                            ActiveDirectoryRights
------------------                            ---------------------
S-1-5-21-1987370270-658905905-1781884369-512             GenericAll
S-1-5-21-1987370270-658905905-1781884369-1104            GenericAll
S-1-5-32-548                                             GenericAll
S-1-5-18                                                 GenericAll
S-1-5-21-1987370270-658905905-1781884369-519             GenericAll
```

In this case, we have a total of five objects that have the GenericAll permission on the _Management Department_ object
+ To make sense of this, let's convert all the SIDs into actual names:
```
PS C:\Tools> "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
CORP\Domain Admins
CORP\stephanie
BUILTIN\Account Operators
Local System
CORP\Enterprise Admins
```

The first SID belongs to the _Domain Admins_ group and the GenericAll permission comes as no surprise since _Domain Admins_ have the highest privilege possible in the domain
+ What's interesting, however, is to find _stephanie_ in this list
+ Typically, a regular domain user should not have GenericAll permissions on other objects in AD, so this may be a misconfiguration

This finding is significant and indicates that _stephanie_ is a powerful account
+ When we enumerated the _Management Group_, we discovered that _jen_ was its only member
+ As an experiment to show the power of misconfigured object permissions, let's try to use our permissions as _stephanie_ to add ourselves to this group with net.exe:
```
net group <GROUP> <USER> /add /domain
```
+ Example:
```
PS C:\Tools> net group "Management Department" stephanie /add /domain
The request will be processed at a domain controller for domain corp.com.

The command completed successfully.
```

Based on the output, we should now be a member of the group
+ We can verify this with **Get-NetGroup**
```
PS C:\Tools> Get-NetGroup "Management Department" | select member

member
------
{CN=jen,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
```
+ This reveals that _jen_ is no longer the sole member of the group and that we have successfully added our _stephanie_ user in there as well

Now that we have abused the GenericAll permission, let's use it to clean up after ourselves by removing our user from the group:
```
net group <GROUP> <USER> /del /domain
```
+ Example:
```
PS C:\Tools> net group "Management Department" stephanie /del /domain
The request will be processed at a domain controller for domain corp.com.

The command completed successfully.
```

Once again we can use PowerView to verify that _jen_ is the sole member of the group:
```
PS C:\Tools> Get-NetGroup "Management Department" | select member

member
------
CN=jen,CN=Users,DC=corp,DC=com
```
+ the cleanup was successful

From a system administrator perspective, managing permissions in Active Directory can be a tough task, especially in complex environments
+ Weak permissions such as the one we saw here are often the go-to vectors for attackers since it can often help us escalate our privileges within the domain

In this particular case, we enumerated the _Management Group_ object specifically and leveraged _stephanie's_ GenericAll to add our own user to the group
+ Although it didn't grant us additional domain privileges, this exercise demonstrated the process of discovering and abusing the vast array of permissions that we can leverage in real-world engagements

### Enumerating Domain Shares
To wrap up our manual enumeration discussion, we'll shift our focus to domain shares
+ Domain shares often contain critical information about the environment, which we can use to our advantage

We'll use PowerView's **Find-DomainShare** function to find the shares in the domain
+ We could also add the _`-CheckShareAccess`_ flag to display shares only available to us
+ However, we'll skip this flag for now to return a full list, including shares we may target later
+ Note that it may take a few moments for PowerView to find the shares and list them:
```
Find-DomainShare
```
+ Example:
```
Name           Type Remark                 ComputerName
----           ---- ------                 ------------
ADMIN$   2147483648 Remote Admin           DC1.corp.com
C$       2147483648 Default share          DC1.corp.com
IPC$     2147483651 Remote IPC             DC1.corp.com
NETLOGON          0 Logon server share     DC1.corp.com
SYSVOL            0 Logon server share     DC1.corp.com
ADMIN$   2147483648 Remote Admin           web04.corp.com
backup            0                        web04.corp.com
C$       2147483648 Default share          web04.corp.com
IPC$     2147483651 Remote IPC             web04.corp.com
ADMIN$   2147483648 Remote Admin           FILES04.corp.com
C                 0                        FILES04.corp.com
C$       2147483648 Default share          FILES04.corp.com
docshare          0 Documentation purposes FILES04.corp.com
IPC$     2147483651 Remote IPC             FILES04.corp.com
Tools             0                        FILES04.corp.com
Users             0                        FILES04.corp.com
Windows           0                        FILES04.corp.com
ADMIN$   2147483648 Remote Admin           client74.corp.com
C$       2147483648 Default share          client74.corp.com
IPC$     2147483651 Remote IPC             client74.corp.com
ADMIN$   2147483648 Remote Admin           client75.corp.com
C$       2147483648 Default share          client75.corp.com
IPC$     2147483651 Remote IPC             client75.corp.com
sharing           0                        client75.corp.com
```
+ Above reveals shares from three different servers and a few clients.
+ Although some of these are default domain shares, we should investigate each of them in search of interesting information

In this instance, we'll first focus on **SYSVOL**, as it may include files and folders that reside on the domain controller itself
+ This particular share is typically used for various domain policies and scripts
+ By default, the **SYSVOL** folder is mapped to **`%SystemRoot%\SYSVOL\Sysvol\domain-name`** on the domain controller and every domain user has access to it:
```
PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\

    Directory: \\dc1.corp.com\sysvol\corp.com

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/21/2022   1:11 AM                Policies
d-----          9/2/2022   4:08 PM                scripts
```

During an assessment, we should investigate every folder we discover in search of interesting items
+ For now, let's examine the **Policies** folder:
```
PS C:\Tools> ls \\dc1.corp.com\sysvol\corp.com\Policies\

    Directory: \\dc1.corp.com\sysvol\corp.com\Policies

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/21/2022   1:13 AM                oldpolicy
d-----          9/2/2022   4:08 PM                {31B2F340-016D-11D2-945F-00C04FB984F9}
d-----          9/2/2022   4:08 PM                {6AC1786C-016F-11D2-945F-00C04fB984F9}
```

All the folders are potentially interesting, but we'll explore **oldpolicy** first. Within it, shown above, we find a file named **old-policy-backup.xml**:
```
PS C:\Tools> cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups   clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User   clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}"
          name="Administrator (built-in)"
          image="2"
          changed="2012-05-03 11:45:20"
          uid="{253F4D90-150A-4EFB-BCC8-6E894A9105F7}">
    <Properties
          action="U"
          newName=""
          fullName="admin"
          description="Change local admin"
          cpassword="+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
          changeLogon="0"
          noChange="0"
          neverExpires="0"
          acctDisabled="0"
          userName="Administrator (built-in)"
          expires="2016-02-10" />
  </User>
</Groups>
```
+ Due to the naming of the folder and the name of the file itself, it appears that this is an older domain policy file
+ This is a common artifact on domain shares as system administrators often forget them when implementing new policies
+ In this particular case, the XML file describes an old policy (helpful for learning more about the current policies) and an encrypted password for the local built-in Administrator account
+ The encrypted password could be extremely valuable for us

Historically, system administrators often changed local workstation passwords through _Group Policy Preferences_ (GPP)
+ However, even though GPP-stored passwords are encrypted with AES-256, the private key for the encryption has been posted on _MSDN_
+ We can use this key to decrypt these encrypted passwords
+ In this case, we'll use the **gpp-decrypt** ruby script in Kali Linux that decrypts a given GPP encrypted string:
```
gpp-decrypt "<PASSWORD>"
```
+ Example:
```
kali@kali:~$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
P@$$w0rd
```
+ Above we successfully decrypted the password and we will make a note of this in our documentation

Let's check out **docshare** on **FILES04.corp.com** (which is not a default share):
```
PS C:\Tools> ls \\FILES04\docshare

    Directory: \\FILES04\docshare

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/21/2022   2:02 AM                docs
```

Farther in the folder structure, we find a **do-not-share** folder that contains **start-email.txt**:
```
PS C:\Tools> ls \\FILES04\docshare\docs\do-not-share

    Directory: \\FILES04\docshare\docs\do-not-share

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/21/2022   2:02 AM           1142 start-email.txt
```

Although this is a very strange name for a folder that is in fact shared, let's check out the content of the file:
```
PS C:\Tools> cat \\FILES04\docshare\docs\do-not-share\start-email.txt
Hi Jeff,

We are excited to have you on the team here in Corp. As Pete mentioned, we have been without a system administrator
since Dennis left, and we are very happy to have you on board.

Pete mentioned that you had some issues logging in to your Corp account, so I'm sending this email to you on your personal address.

The username I'm sure you already know, but here you have the brand new auto generated password as well: HenchmanPutridBonbon11

As you may be aware, we are taking security more seriously now after the previous breach, so please change the password at first login.

Best Regards
Stephanie

...............

Hey Stephanie,

Thank you for the warm welcome. I heard about the previous breach and that Dennis left the company.

Fortunately he gave me a great deal of documentation to go through, although in paper format. I'm in the
process of digitalizing the documentation so we can all share the knowledge. For now, you can find it in
the shared folder on the file server.

Thank you for reminding me to change the password, I will do so at the earliest convenience.

Best regards
Jeff
```

According to the text in this file, _jeff_ stored an email with a possible cleartext password: _`HenchmanPutridBonbon11`_
+ Although the password may have been changed, we will make a note of it in our documentation
+ Between this password and the password we discovered earlier, we're building a rough profile of the password policy used for both users and computers in the organization
+ We could use this to create specific wordlists that we can use for password guessing and brute force, if needed

## Active Directory - Automated Enumeration
Our manual enumeration can be relatively time consuming and can generate a wealth of information that can be difficult to organize
+ Although it is important to understand the concepts of manual enumeration, we can also leverage automated tools to speed up the enumeration process and quickly reveal possible attack paths, especially in large environments
+ Manual and automated tools each have their merits, and most professionals leverage a combination of the two in real-world engagements

Some automated tools, like _PingCastle_, generate gorgeous reports although most require paid licenses for commercial use
+ In our case, we will focus on _BloodHound_, an excellent free tool that's extremely useful for analyzing AD environments
+ It's worth noting that automated tools generate a great deal of network traffic and many administrators will likely recognize a spike in traffic as we run these tools

### Collecting Data with SharpHound
We'll use BloodHound in the next section to analyze, organize and present the data, and the companion data collection tool, _SharpHound_ to collect the data
+ SharpHound is written in C# and uses Windows API functions and LDAP namespace functions similar to those we used manually in the previous sections
+ For example, SharpHound will attempt to use _NetWkstaUserEnum_ and _NetSessionEnum_ to enumerate logged-on sessions, just as we did earlier
+ It will also run queries against the Remote Registry service, which we also leveraged earlier
+ **NOTE**: It's often best to combine automatic and manual enumeration techniques when assessing Active Directory. Even though we could theoretically gather the same information with a manual approach, graphical relationships often reveal otherwise unnoticed attack paths

Let's get <mark style="background: #D2B3FFA6;">SharpHound</mark> up and running
+ SharpHound is available in a few different formats
+ We can compile it ourselves, use an already compiled executable, or use it as a PowerShell script
+ In our case, we will use the PowerShell script that is located in **`C:\Tools`** on `CLIENT75`
+ First, let's open a PowerShell window and import the script to memory:
```
Import-Module .\Sharphound.ps1
```

With SharpHound imported, we can now start collecting domain data
+ However, in order to run SharpHound, we must first run **`Invoke-BloodHound`**:
```
Invoke-BloodHound
```
+ This is not intuitive since we're only running SharpHound at this stage
+ Let's invoke **Get-Help** to learn more about this command:
```
PS C:\Tools> Get-Help Invoke-BloodHound

NAME
    Invoke-BloodHound

SYNOPSIS
    Runs the BloodHound C# Ingestor using reflection. The assembly is stored in this file.


SYNTAX
    Invoke-BloodHound [-CollectionMethod <String[]>] [-Domain <String>] [-SearchForest] [-Stealth] [-LdapFilter <String>] [-DistinguishedName
    <String>] [-ComputerFile <String>] [-OutputDirectory <String>] [-OutputPrefix <String>] [-CacheName <String>] [-MemCache] [-RebuildCache]
    [-RandomFilenames] [-ZipFilename <String>] [-NoZip] [-ZipPassword <String>] [-TrackComputerCalls] [-PrettyPrint] [-LdapUsername <String>]
    [-LdapPassword <String>] [-DomainController <String>] [-LdapPort <Int32>] [-SecureLdap] [-DisableCertVerification] [-DisableSigning]
    [-SkipPortCheck] [-PortCheckTimeout <Int32>] [-SkipPasswordCheck] [-ExcludeDCs] [-Throttle <Int32>] [-Jitter <Int32>] [-Threads <Int32>]
    [-SkipRegistryLoggedOn] [-OverrideUsername <String>] [-RealDNSName <String>] [-CollectAllProperties] [-Loop] [-LoopDuration <String>]
    [-LoopInterval <String>] [-StatusInterval <Int32>] [-Verbosity <Int32>] [-Help] [-Version] [<CommonParameters>]


DESCRIPTION
    Using reflection and assembly.load, load the compiled BloodHound C# ingestor into memory
    and run it without touching disk. Parameters are converted to the equivalent CLI arguments
    for the SharpHound executable and passed in via reflection. The appropriate function
    calls are made in order to ensure that assembly dependencies are loaded properly.


RELATED LINKS

REMARKS
    To see the examples, type: "get-help Invoke-BloodHound -examples".
    For more information, type: "get-help Invoke-BloodHound -detailed".
    For technical information, type: "get-help Invoke-BloodHound -full".
```

We'll begin with the **-CollectionMethod**, which describes the various collection methods
+ In our case, we'll attempt to gather **All** data, which will perform all collection methods except for local group policies
+ By default, SharpHound will gather the data in JSON files and automatically zip them for us
+ This makes it easy for us to transfer the file to Kali Linux later
+ We'll save this output file on our desktop, with a "corp audit" prefix as shown below:
```
Invoke-BloodHound -CollectionMethod All -OutputDirectory . -OutputPrefix "<PREFIX_STRING>"
```

Note that the data collection may take a few moments to finish, depending on the size of the environment we are enumerating
+ Let's examine SharpHound's output:
```
2022-10-12T09:20:22.3688459-07:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2022-10-12T09:20:22.5909898-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-10-12T09:20:22.6383624-07:00|INFORMATION|Initializing SharpHound at 9:20 AM on 10/12/2022
2022-10-12T09:20:22.9661022-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2022-10-12T09:20:23.3881009-07:00|INFORMATION|Beginning LDAP search for corp.com
2022-10-12T09:20:23.4975127-07:00|INFORMATION|Producer has finished, closing LDAP channel
2022-10-12T09:20:23.4975127-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2022-10-12T09:20:53.6398934-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 96 MB RAM
2022-10-12T09:21:13.6762695-07:00|INFORMATION|Consumers finished, closing output channel
2022-10-12T09:21:13.7396906-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2022-10-12T09:21:13.8983935-07:00|INFORMATION|Status: 106 objects finished (+106 2.12)/s -- Using 104 MB RAM
2022-10-12T09:21:13.8983935-07:00|INFORMATION|Enumeration finished in 00:00:50.5065909
2022-10-12T09:21:14.0094454-07:00|INFORMATION|Saving cache with stats: 66 ID to type mappings.
 68 name to SID mappings.
 2 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2022-10-12T09:21:14.0255279-07:00|INFORMATION|SharpHound Enumeration Completed at 9:21 AM on 10/12/2022! Happy Graphing!
```
+ Based on the output above, we scanned a total of 106 objects
+ This will obviously vary based on how many objects and sessions exist in the domain

In this case, SharpHound essentially took a snapshot of the domain from the _stephanie_ user, and we should be able to analyze everything the user account has access to
+ The collected data is stored in the zip file located on our Desktop:
```
PS C:\Tools> ls C:\Users\stephanie\Desktop\

    Directory: C:\Users\stephanie\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         9/27/2022  11:00 PM          12680 corp audit_20220927230019_BloodHound.zip
-a----         9/27/2022  11:00 PM           9734 MTk2MmZkNjItY2IyNC00MWMzLTk5YzMtM2E1ZDcwYThkMzRl.bin
```
+ We'll use this file in the next section as we analyze the data with BloodHound
+ Sharphound created the **bin** cache file to speed up data collection
+ This is not needed for our analysis and we can safely delete it 

One thing to note is that SharpHound also supports _looping_, which means that the collector will run cyclical queries of our choosing over a period of time
+ While the collection method we used above created a _snapshot_ over the domain, running it in a loop may gather additional data as the environment changes
+ The cache file speeds up the process
+ For example, if a user logged on after we collected a snapshot, we would have missed it in our analysis
+ We will not use the looping functionality, but we recommend experimenting with it in the training labs and inspecting the results in <mark style="background: #D2B3FFA6;">BloodHound</mark>

### Analysing Data using BloodHound
In this section, we will analyze the domain data using BloodHound in Kali Linux, but it should be noted that we could install the application and required dependencies on Windows-based systems as well
+ In order to use BloodHound, we need to start the _Neo4j_ service, which is installed by default
+ Note that when Bloodhound is installed with _APT_, the Neo4j service is automatically installed as well

Neo4j is essentially an open source graph database (NoSQL) that creates nodes, edges, and properties instead of simple rows and columns
+ This facilitates the visual representation of our collected data
+ Let's go ahead and start the Neo4j service:
```
sudo neo4j start
```
+ Output 
```
kali@kali:~$ sudo neo4j start
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /usr/share/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /usr/share/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /usr/share/neo4j/run
Starting Neo4j.
Started neo4j (pid:334819). It is available at http://localhost:7474
There may be a short delay until the server is ready.
```

As indicated in the output, the Neo4j service is now running and it should be available via the web interface at `http://localhost:7474`
+ Let's browse this location and authenticate using the default credentials (_neo4j_ as both username and password):
![[Pasted image 20240102155641.png]]

After authenticating with the default credentials, we are prompted for a password change:
![[Pasted image 20240102155654.png]]
+ In this case, we can choose any password we'd like; however, we must remember it since we'll also use it to authenticate to the database later

Once we have changed the password, we can authenticate to the database and run our own queries against it
+ However, since we haven't imported any data yet there isn't much we can do and we'd rather allow BloodHound to run the queries for us

With Neo4j running, it's time to start BloodHound as well
+ We can do this directly from the terminal:
```
bloodhound
```

Once we start BloodHound, we are met with an authentication window, asking us to log in to the Neo4j Database:
![[Pasted image 20240102155748.png]]
+ As indicated by the green check mark in the first column, BloodHound has automatically detected that we have the Neo4j database running
+ In order to log in, we use the _neo4j_ username and the password we created earlier

Since we haven't imported data yet, we don't have any visual representation of the domain at this point
+ In order to import the data, we must first transfer the zip file from our Windows machine to our Kali Linux machine
+ We can then use the _Upload Data_ function on the right side of the GUI to upload the zip file, or drag-and-drop it into BloodHound's main window
+ Either way, the progress bar indicates the upload progress:
![[Pasted image 20240102155847.png]]
+ Once the upload is finished, we can close the _Upload Progress_ window

Now it's time to start analyzing the data
+ Let's first get an idea about how much data the database really contains
+ To do this, let's click the _More Info_ tab at the top-left
+ This presents the _Database Info_ as shown below:
![[Pasted image 20240102155930.png]]

Our small environment doesn't contain much
+ But in some cases, especially in a larger environment, the database may take some time to update
+ In these cases, we can use the _Refresh Database Stats_ button to present an updated view

Looking at the information, we have discovered four total sessions in the domain, which have been enumerated (using _NetSessionEnum_ and _PsLoggedOn_ techniques we used earlier)
+ Additionally, we have discovered a wealth of ACLs, a total of 10 users, 57 groups, and more

We'll explain the _Node Info_ later, as there isn't much here at this point
+ For now, we are mostly interested in the _Analysis_ button
+ When we click it, we are presented with various pre-built analysis options:
![[Pasted image 20240102160025.png]]

There are many pre-built analytics queries to experiment with here, and we will not be able to cover all of them in this Module
+ However, to get started, let's use _Find all Domain Admins_ under _Domain Information_
+ This presents the graph shown below:
![[Pasted image 20240102160050.png]]

Each of the circle icons are known as _nodes_, and we can drag them to move them in the interface
+ In this case the three nodes are connected and BloodHound placed them far apart from each other, so we can simply move them closer to each other to keep everything nice and clean

In order to see what the two nodes on the left represent, we can hover over them with the mouse pointer, or we can toggle the information by pressing the control button
+ While toggling on and off the information for each node may be preferred for some analysis, we can also tell BloodHound to show this information by default by clicking _Settings_ on the right side of the interface and setting _Node Label Display_ to _Always Display_:
![[Pasted image 20240102160131.png]]

Based on this view, the _Domain Admins_ for the domain are indeed _jeffadmin_ and the _administrator_ account itself
+ As shown in Figure below, BloodHound shows an edge in the form of a line between the user objects and the _Domain Admins_ group, indicating the relationship, which in this case tells us that the particular users are a member of the given group:
![[Pasted image 20240102160156.png]]

Although BloodHound is capable of deep analysis, much of its functionality is out of scope for this Module
+ For now, we'll focus on the _Shortest Paths_ shown in the _Analysis_ tab
+ One of the strengths of BloodHound is its ability to automatically attempt to find the shortest path possible to reach our goal, whether that goal is to take over a particular computer, user, or group

Let's start with the _Find Shortest Paths to Domain Admins_ as it provides a nice overview and doesn't require any parameters
+ The query is listed towards the bottom of the _Analysis_ tab:
![[Pasted image 20240102160240.png]]

This reveals the true power of BloodHound
+ We can analyze this graph to determine our best attack approach
+ In this case, the graph will reveal a few things we didn't catch in our earlier enumeration

For example,let's focus on the relationship between _stephanie_ and CLIENT74, which we saw in our earlier enumeration
+ To get more information, we can hover the mouse over the string that indicates the connection between the node to see what kind of connection it really is:
![[Pasted image 20240102160313.png]]
+ The small pop-up says _AdminTo_, and this indicates that _stephanie_ indeed has administrative privileges on CLIENT74

If we right-click the line between the nodes and click _? Help_, BloodHound will show additional information:
![[Pasted image 20240102160333.png]]

As indicated in the information above, _stephanie_ has administrative privileges on CLIENT74 and has several ways to obtain code execution on it 
+ **NOTE**: In the _? Help_ menu BloodHound also offers information in the _Abuse_ tab, which will tell us more about the possible attack we can take on the given path. It also contains _Opsec_ information as what to look out for when it comes to being detected, as well as references to the information displayed.

After further reading of Figure {@fig:ad_enum_bh_DA_short}, and after further inspection of the graph, we discover the connection _jeffadmin_ has to CLIENT74
+ This means that the credentials for _jeffadmin_ may be cached on the machine, which could be fatal for the organization
+ If we are able to take advantage of the given attack path and steal the credentials for _jeffadmin_, we should be able to log in as him and become domain administrator through his _Domain Admins_ membership

This plays directly into the second _Shortest Path_ we'd like to show for this Module, namely the _Shortest Paths to Domain Admins from Owned Principals_
+ If we run this query against _corp.com_ without configuring BloodHound, we receive a "NO DATA RETURNED FROM QUERY" message

However, the _Owned Principals_ plays a big role here, and refers to the objects we are currently in control of in the domain
+ In order to analyze, we can mark any object we'd like as _owned_ in BloodHound, even if we haven't obtained access to them
+ Sometimes it is a good idea to think in the lines of "what if" when it comes to AD assessments
+ In this case however, we will leave the imagination on the side and focus on the objects we in fact have control over

The only object we know for a fact we have control over is the _stephanie_ user, and we have partial control over CLIENT75, since that is where we are logged in
+ We do not have administrative privileges, so we may need to think about doing privilege escalation on the machine later, but for now, let's say that we have control over it 

In order for us to obtain an _owned principal_ in BloodHound, we will run a search (top left), right click the object that shows in the middle of the screen, and click _Mark User as Owned_
+ A principal marked as _owned_ is shown in BloodHound with a skull icon next to the node itself
![[Pasted image 20240102160608.png]]

One thing to note here is that if we click the icon for the object we are searching, it will be placed into the _Node Info_ button where we can read more about the object itself
+ We'll repeat the process for CLIENT75 as well, however in this case we click _Mark Computer as Owned_, and we end up having two _owned principals_
+ Now that we informed BloodHound about our owned principals, we can run the _Shortest Paths to Domain Admins from Owned Principals_ query:
+ NOTE: It's a good idea to mark every object we have access to as _owned_ to improve our visibility into more potential attack vectors. There may be a short path to our goals that hinges on ownership of a particular object:
![[Pasted image 20240102160649.png]]
+ Note that we have rearranged the nodes in the Figure above to clarify our potential attack path

Let's read this by starting with the left-hand node, which is CLIENT75
+ As expected, _stephanie_ has a session there
+ The _stephanie_ user should be able to connect to CLIENT74, where _jeffadmin_ has a session
+ _jeffadmin_ is a part of the _Domain Admins_ group, so if we are able to take control of his account by either impersonating him or stealing the credentials on CLIENT74, we will be domain administrators

BloodHound comes with a wealth of functions and options we cannot fully cover in this Module
+ While we focused mostly on shortest paths, we highly recommend getting accustomed to the other BloodHound pre-built queries within the Challenge Labs

In this particular domain, we were able to enumerate most of the information using manual methods first, but in a large-scale production environment with thousands of users and computers, the information may be difficult to digest
+ Although the queries from SharpHound generate noise in the network and will likely be caught by security analysts, it is a tool worth running if the situation allows it, since it gives a nice visual overview of the environment at run time

Change a password using AD with:
```
net user <USER> <PASSWORD> /domain
```

Can then start a powershell session with the user:
```
runas /user:<AD>\<USER> "powershell -ep bypass"
```
+ Might need to add: `/netonly` 
